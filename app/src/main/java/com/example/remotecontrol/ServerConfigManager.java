package com.example.remotecontrol;

import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * ServerConfigManager - Server-Driven Configuration Management
 *
 * यह class server से JSON configuration fetch करती है और locally cache करती है।
 * Features:
 * - HTTP/HTTPS JSON config fetching (background thread)
 * - Local in-memory cache with configurable TTL
 * - Automatic periodic refresh (background scheduler)
 * - Config change notifications (listener pattern)
 * - Default fallback values (network unavailable होने पर)
 *
 * Config keys supported:
 *   heartbeat_interval     - Socket heartbeat interval (ms)
 *   photo_compression      - Photo quality (0-100) and max resolution
 *   auto_upload_interval   - Batch photo upload frequency (ms)
 *   enabled_commands       - JSON array of allowed command names
 *   encryption_enabled     - TLS/SSL toggle (boolean)
 *   logging_level          - Log verbosity (VERBOSE/DEBUG/INFO/WARN/ERROR)
 *   signing_secret         - HMAC signing secret (sensitive)
 */
public class ServerConfigManager {

    private static final String TAG = "ServerConfigManager";

    // ─── Default configuration values (fallback when server unreachable) ─────
    private static final long   DEFAULT_HEARTBEAT_INTERVAL_MS = 30_000L;   // 30 seconds
    private static final int    DEFAULT_PHOTO_QUALITY         = 80;        // 80% JPEG quality
    private static final int    DEFAULT_MAX_PHOTO_WIDTH       = 1280;
    private static final int    DEFAULT_MAX_PHOTO_HEIGHT      = 720;
    private static final long   DEFAULT_AUTO_UPLOAD_INTERVAL_MS = 300_000L; // 5 minutes
    private static final boolean DEFAULT_ENCRYPTION_ENABLED   = true;
    private static final String DEFAULT_LOGGING_LEVEL         = "INFO";
    private static final long   DEFAULT_CACHE_TTL_MS          = 300_000L;  // 5 minutes

    // Singleton
    private static volatile ServerConfigManager instance;

    // ─── Configuration URL ────────────────────────────────────────────────────
    private volatile String configUrl = "";

    // ─── Cached config and TTL management ────────────────────────────────────
    private volatile JSONObject cachedConfig = null;
    private volatile long cacheTimestamp = 0L;
    private volatile long cacheTtlMs = DEFAULT_CACHE_TTL_MS;

    // ─── Background refresh scheduler ────────────────────────────────────────
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor();
    private ScheduledFuture<?> refreshTask = null;

    // ─── Config change listeners ──────────────────────────────────────────────
    private final List<ConfigChangeListener> listeners = new ArrayList<>();

    /**
     * Private constructor - singleton
     */
    private ServerConfigManager() {}

    /**
     * getInstance() - thread-safe singleton accessor
     */
    public static ServerConfigManager getInstance() {
        if (instance == null) {
            synchronized (ServerConfigManager.class) {
                if (instance == null) {
                    instance = new ServerConfigManager();
                }
            }
        }
        return instance;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Initialization
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * init() - config URL set करें और initial fetch schedule करें
     *
     * @param configUrl  Full URL to the server's JSON config endpoint
     * @param ttlMs      Cache validity duration in milliseconds
     */
    public synchronized void init(String configUrl, long ttlMs) {
        this.configUrl = configUrl != null ? configUrl : "";
        this.cacheTtlMs = ttlMs > 0 ? ttlMs : DEFAULT_CACHE_TTL_MS;
        Log.d(TAG, "ServerConfigManager initialized with URL: " + configUrl);

        // Immediately fetch config in background
        fetchConfigAsync();

        // Auto-refresh हर cacheTtlMs interval पर
        scheduleAutoRefresh();
    }

    /**
     * scheduleAutoRefresh() - periodic background config refresh
     */
    private synchronized void scheduleAutoRefresh() {
        // Previous task cancel करें
        if (refreshTask != null && !refreshTask.isDone()) {
            refreshTask.cancel(false);
        }
        refreshTask = scheduler.scheduleAtFixedRate(
                this::fetchConfigAsync,
                cacheTtlMs,       // initial delay
                cacheTtlMs,       // period
                TimeUnit.MILLISECONDS
        );
        Log.d(TAG, "Auto-refresh scheduled every " + cacheTtlMs + "ms");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Config Fetching
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * fetchConfigAsync() - background thread में server से config fetch करें
     */
    private void fetchConfigAsync() {
        scheduler.execute(() -> {
            try {
                JSONObject freshConfig = fetchFromServer();
                if (freshConfig != null) {
                    updateCache(freshConfig);
                }
            } catch (Exception e) {
                Log.e(TAG, "Background config fetch failed", e);
            }
        });
    }

    /**
     * fetchFromServer() - HTTP GET से JSON config fetch करता है
     *
     * @return Parsed JSONObject या null on failure
     */
    private JSONObject fetchFromServer() {
        if (configUrl.isEmpty()) {
            Log.w(TAG, "Config URL not set, skipping fetch");
            return null;
        }

        HttpURLConnection conn = null;
        try {
            URL url = new URL(configUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(10_000);   // 10 second connect timeout
            conn.setReadTimeout(15_000);      // 15 second read timeout
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("User-Agent", "RemoteControl-Android/1.0");

            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "Config fetch returned HTTP " + responseCode);
                return null;
            }

            // Response body read करें
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            reader.close();

            String jsonStr = sb.toString().trim();
            Log.d(TAG, "Config fetched successfully (" + jsonStr.length() + " chars)");
            return new JSONObject(jsonStr);

        } catch (java.net.MalformedURLException e) {
            Log.e(TAG, "Invalid config URL: " + configUrl, e);
        } catch (java.net.SocketTimeoutException e) {
            Log.w(TAG, "Config fetch timed out");
        } catch (Exception e) {
            Log.e(TAG, "Config fetch error", e);
        } finally {
            if (conn != null) conn.disconnect();
        }
        return null;
    }

    /**
     * updateCache() - नया config cache में store करें और listeners notify करें
     */
    private synchronized void updateCache(JSONObject newConfig) {
        JSONObject oldConfig = this.cachedConfig;
        this.cachedConfig = newConfig;
        this.cacheTimestamp = System.currentTimeMillis();
        Log.d(TAG, "Config cache updated");

        // Notify all registered listeners
        for (ConfigChangeListener listener : listeners) {
            try {
                listener.onConfigChanged(oldConfig, newConfig);
            } catch (Exception e) {
                Log.e(TAG, "Listener notification failed", e);
            }
        }
    }

    /**
     * isCacheValid() - cache अभी भी fresh है?
     */
    private boolean isCacheValid() {
        return cachedConfig != null
                && (System.currentTimeMillis() - cacheTimestamp) < cacheTtlMs;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Config Accessors
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * getRawConfig() - raw JSONObject return करें (null if not yet fetched)
     */
    public JSONObject getRawConfig() {
        return cachedConfig;
    }

    /**
     * getHeartbeatIntervalMs() - Socket heartbeat interval in milliseconds
     * Server config key: "heartbeat_interval"
     */
    public long getHeartbeatIntervalMs() {
        if (isCacheValid()) {
            return cachedConfig.optLong("heartbeat_interval",
                    DEFAULT_HEARTBEAT_INTERVAL_MS);
        }
        return DEFAULT_HEARTBEAT_INTERVAL_MS;
    }

    /**
     * getPhotoQuality() - JPEG compression quality (0-100)
     * Server config key: "photo_compression.quality"
     */
    public int getPhotoQuality() {
        if (isCacheValid()) {
            JSONObject photoConfig = cachedConfig.optJSONObject("photo_compression");
            if (photoConfig != null) {
                return photoConfig.optInt("quality", DEFAULT_PHOTO_QUALITY);
            }
        }
        return DEFAULT_PHOTO_QUALITY;
    }

    /**
     * getMaxPhotoWidth() - Maximum photo width in pixels
     * Server config key: "photo_compression.max_width"
     */
    public int getMaxPhotoWidth() {
        if (isCacheValid()) {
            JSONObject photoConfig = cachedConfig.optJSONObject("photo_compression");
            if (photoConfig != null) {
                return photoConfig.optInt("max_width", DEFAULT_MAX_PHOTO_WIDTH);
            }
        }
        return DEFAULT_MAX_PHOTO_WIDTH;
    }

    /**
     * getMaxPhotoHeight() - Maximum photo height in pixels
     * Server config key: "photo_compression.max_height"
     */
    public int getMaxPhotoHeight() {
        if (isCacheValid()) {
            JSONObject photoConfig = cachedConfig.optJSONObject("photo_compression");
            if (photoConfig != null) {
                return photoConfig.optInt("max_height", DEFAULT_MAX_PHOTO_HEIGHT);
            }
        }
        return DEFAULT_MAX_PHOTO_HEIGHT;
    }

    /**
     * getAutoUploadIntervalMs() - Batch photo upload frequency in milliseconds
     * Server config key: "auto_upload_interval"
     */
    public long getAutoUploadIntervalMs() {
        if (isCacheValid()) {
            return cachedConfig.optLong("auto_upload_interval",
                    DEFAULT_AUTO_UPLOAD_INTERVAL_MS);
        }
        return DEFAULT_AUTO_UPLOAD_INTERVAL_MS;
    }

    /**
     * getEnabledCommands() - Server द्वारा allowed commands की list
     * Server config key: "enabled_commands" (JSON array of strings)
     *
     * @return List of enabled command names, empty = all allowed
     */
    public List<String> getEnabledCommands() {
        List<String> commands = new ArrayList<>();
        if (isCacheValid()) {
            JSONArray arr = cachedConfig.optJSONArray("enabled_commands");
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    String cmd = arr.optString(i, "").trim();
                    if (!cmd.isEmpty()) commands.add(cmd);
                }
            }
        }
        return commands;
    }

    /**
     * isEncryptionEnabled() - TLS/SSL encryption toggle
     * Server config key: "encryption_enabled"
     */
    public boolean isEncryptionEnabled() {
        if (isCacheValid()) {
            return cachedConfig.optBoolean("encryption_enabled",
                    DEFAULT_ENCRYPTION_ENABLED);
        }
        return DEFAULT_ENCRYPTION_ENABLED;
    }

    /**
     * getLoggingLevel() - Server-driven log verbosity
     * Server config key: "logging_level" (VERBOSE/DEBUG/INFO/WARN/ERROR)
     */
    public String getLoggingLevel() {
        if (isCacheValid()) {
            return cachedConfig.optString("logging_level", DEFAULT_LOGGING_LEVEL);
        }
        return DEFAULT_LOGGING_LEVEL;
    }

    /**
     * getSigningSecret() - HMAC signing secret (sensitive - handle carefully)
     * Server config key: "signing_secret"
     */
    public String getSigningSecret() {
        if (isCacheValid()) {
            return cachedConfig.optString("signing_secret", "");
        }
        return "";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Listener Management
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * addConfigChangeListener() - config update notifications के लिए listener register करें
     */
    public synchronized void addConfigChangeListener(ConfigChangeListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    /**
     * removeConfigChangeListener() - listener unregister करें (memory leak prevention)
     */
    public synchronized void removeConfigChangeListener(ConfigChangeListener listener) {
        listeners.remove(listener);
    }

    /**
     * forceRefresh() - Manual cache invalidation और तत्काल refresh
     * (debug/testing के लिए useful)
     */
    public void forceRefresh() {
        Log.d(TAG, "Force refresh requested");
        fetchConfigAsync();
    }

    /**
     * shutdown() - Background scheduler cleanup (app destroy पर call करें)
     */
    public void shutdown() {
        if (refreshTask != null) refreshTask.cancel(false);
        scheduler.shutdownNow();
        Log.d(TAG, "ServerConfigManager shutdown");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Listener Interface
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * ConfigChangeListener - config update notification callback
     */
    public interface ConfigChangeListener {
        /**
         * @param oldConfig  Previous config (null if first fetch)
         * @param newConfig  New config fetched from server
         */
        void onConfigChanged(JSONObject oldConfig, JSONObject newConfig);
    }
}
