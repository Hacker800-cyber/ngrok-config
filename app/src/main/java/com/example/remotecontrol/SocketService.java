package com.example.remotecontrol;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;
import androidx.annotation.Nullable;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * SocketService - Production-Ready Server-Driven Socket Service
 *
 * Main features:
 * ✅ Server-driven JSON config (ServerConfigManager)
 * ✅ Dynamic command registry (CommandRegistry)
 * ✅ Optional TLS/SSL encryption (EncryptionManager)
 * ✅ Token-based security (SecurityManager)
 * ✅ Exponential backoff with stable-connection reset
 * ✅ Heartbeat mechanism (configurable interval)
 * ✅ Thread-safe with proper lifecycle management
 *
 * Flow:
 *   onStartCommand() → fetchServerConfig() → connectToServer() →
 *   authenticate() → receiveCommands() → executeCommands() → sendResponse()
 *
 * Backoff strategy:
 *   On connection failure: delay doubles (1s → 2s → 4s → ... → MAX_BACKOFF_MS)
 *   On stable connection (>STABLE_THRESHOLD_MS): backoff resets to initial
 */
public class SocketService extends Service {

    // ─── Logging tag ──────────────────────────────────────────────────────────
    private static final String TAG = "SocketService";

    // ─── Intent extras for configuring the service ────────────────────────────
    /** Server hostname extra key */
    public static final String EXTRA_HOST = "host";
    /** Server port extra key */
    public static final String EXTRA_PORT = "port";
    /** Auth token extra key */
    public static final String EXTRA_TOKEN = "token";
    /** Config URL extra key (optional - for ServerConfigManager) */
    public static final String EXTRA_CONFIG_URL = "config_url";

    // ─── Backoff configuration ────────────────────────────────────────────────
    /** Initial reconnect delay after first failure (milliseconds) */
    private static final long INITIAL_BACKOFF_MS  = 1_000L;
    /** Maximum reconnect delay cap */
    private static final long MAX_BACKOFF_MS       = 60_000L;
    /** Backoff multiplier on each failure */
    private static final double BACKOFF_MULTIPLIER = 2.0;
    /** Connection must stay alive this long to be considered "stable" */
    private static final long STABLE_THRESHOLD_MS  = 30_000L;

    // ─── Service components ───────────────────────────────────────────────────
    /** Background thread pool - connection + heartbeat */
    private ExecutorService executorService;

    /** Socket connection (plain or TLS-wrapped) */
    private Socket socket;

    /** Stream reader for incoming server messages */
    private BufferedReader socketReader;

    /** Stream writer for outgoing messages */
    private PrintWriter socketWriter;

    /** Flag to gracefully stop the service loop */
    private final AtomicBoolean running = new AtomicBoolean(false);

    // ─── Config values (from Intent + ServerConfigManager) ───────────────────
    private String serverHost  = "";
    private int    serverPort  = 0;
    private String authToken   = "";
    private String configUrl   = "";

    // ─── Heartbeat state ──────────────────────────────────────────────────────
    /** Current heartbeat interval (updated from server config) */
    private volatile long heartbeatIntervalMs;

    // ─── Singleton managers ───────────────────────────────────────────────────
    private SecurityManager    securityManager;
    private ServerConfigManager configManager;
    private CommandRegistry    commandRegistry;
    private EncryptionManager  encryptionManager;

    // ─────────────────────────────────────────────────────────────────────────
    // Service Lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "SocketService created");

        // Two-thread pool: one for connection loop, one for heartbeat
        executorService = Executors.newFixedThreadPool(2);

        // Initialize singleton managers
        securityManager   = SecurityManager.getInstance();
        configManager     = ServerConfigManager.getInstance();
        encryptionManager = EncryptionManager.getInstance();
        commandRegistry   = CommandRegistry.getInstance();

        // Register built-in commands with security context
        commandRegistry.registerBuiltins(securityManager);

        // Register FileCommand (file upload/download)
        commandRegistry.register(new FileCommand(securityManager));

        Log.d(TAG, "Managers and built-in commands initialized");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "SocketService starting");

        if (intent != null) {
            // Extract connection parameters from Intent
            serverHost = intent.getStringExtra(EXTRA_HOST) != null
                    ? intent.getStringExtra(EXTRA_HOST) : "";
            serverPort = intent.getIntExtra(EXTRA_PORT, 0);
            authToken  = intent.getStringExtra(EXTRA_TOKEN) != null
                    ? intent.getStringExtra(EXTRA_TOKEN) : "";
            configUrl  = intent.getStringExtra(EXTRA_CONFIG_URL) != null
                    ? intent.getStringExtra(EXTRA_CONFIG_URL) : "";
        }

        // Validate required parameters
        if (serverHost.isEmpty() || serverPort <= 0) {
            Log.e(TAG, "Invalid host/port. Service cannot start.");
            stopSelf();
            return START_NOT_STICKY;
        }

        // Register auth token (all commands allowed for provided token)
        if (!authToken.isEmpty()) {
            securityManager.registerToken(authToken, "*", 0 /* never expires */);
        }

        // Initialize ServerConfigManager if config URL is provided
        if (!configUrl.isEmpty()) {
            configManager.init(configUrl, 300_000L /* 5-minute TTL */);
            // Listen for config changes to update heartbeat interval dynamically
            configManager.addConfigChangeListener((oldConfig, newConfig) -> {
                heartbeatIntervalMs = configManager.getHeartbeatIntervalMs();
                Log.d(TAG, "Config updated: heartbeat=" + heartbeatIntervalMs + "ms");
                applyServerConfig();
            });
        }

        // Set initial heartbeat interval from config (or default 30s)
        heartbeatIntervalMs = configManager.getHeartbeatIntervalMs();

        // Start the connection loop in background
        running.set(true);
        executorService.submit(this::connectionLoop);

        // START_STICKY: system restarted होने पर service restart हो
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.i(TAG, "SocketService destroying");

        // Signal connection loop to stop
        running.set(false);

        // Close socket to unblock blocking reads
        closeSocket();

        // Shutdown managers
        configManager.shutdown();
        if (!executorService.isShutdown()) {
            executorService.shutdownNow();
        }

        Log.i(TAG, "SocketService destroyed");
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        // This is a started service, not a bound service
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Connection Loop with Exponential Backoff
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * connectionLoop() - मुख्य reconnection loop
     *
     * Exponential backoff strategy:
     *   - Connection fail होने पर delay doubles
     *   - Connection stable रहे (>STABLE_THRESHOLD_MS) तो backoff reset
     *   - Maximum backoff MAX_BACKOFF_MS तक cap किया जाता है
     */
    private void connectionLoop() {
        long currentBackoffMs = INITIAL_BACKOFF_MS;

        while (running.get()) {
            long connectionStartTime = System.currentTimeMillis();
            try {
                Log.i(TAG, "Connecting to " + serverHost + ":" + serverPort);
                connectAndServe();

                // Connection closed gracefully (running = false)
                long connectedDurationMs = System.currentTimeMillis() - connectionStartTime;
                if (connectedDurationMs >= STABLE_THRESHOLD_MS) {
                    // Stable connection थी - backoff reset करें
                    Log.d(TAG, "Stable connection ended after "
                            + connectedDurationMs + "ms - resetting backoff");
                    currentBackoffMs = INITIAL_BACKOFF_MS;
                }

            } catch (Exception e) {
                if (!running.get()) break; // Service stop हो रहा है

                Log.w(TAG, "Connection error: " + e.getMessage());

                long connectedDurationMs = System.currentTimeMillis() - connectionStartTime;
                if (connectedDurationMs >= STABLE_THRESHOLD_MS) {
                    // Stable connection drop - backoff reset
                    currentBackoffMs = INITIAL_BACKOFF_MS;
                    Log.d(TAG, "Stable connection dropped - backoff reset to "
                            + currentBackoffMs + "ms");
                } else {
                    // Unstable connection - backoff बढ़ाएं
                    currentBackoffMs = Math.min(
                            (long)(currentBackoffMs * BACKOFF_MULTIPLIER), MAX_BACKOFF_MS);
                }

                Log.i(TAG, "Reconnecting in " + currentBackoffMs + "ms...");
                sleepSafe(currentBackoffMs);
            }
        }
        Log.i(TAG, "Connection loop terminated");
    }

    /**
     * connectAndServe() - एक complete connection cycle:
     * connect → authenticate → start heartbeat → read commands → serve
     */
    private void connectAndServe() throws Exception {
        // Step 1: Create socket (TLS or plain based on server config)
        boolean useTls = configManager.isEncryptionEnabled();
        if (useTls) {
            Log.d(TAG, "Using TLS socket");
            // In debug builds, certificate validation can be relaxed for testing.
            // In release builds, always validate certificates (validateCert=true).
            boolean validateCert = !BuildConfig.DEBUG;
            socket = encryptionManager.createTlsSocket(serverHost, serverPort, validateCert);
        } else {
            Log.d(TAG, "Using plain socket (TLS disabled by config)");
            socket = new Socket(serverHost, serverPort);
        }

        // Step 2: Set up buffered reader/writer
        socketReader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), "UTF-8"));
        socketWriter = new PrintWriter(
                new java.io.OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

        Log.i(TAG, "Connected to " + serverHost + ":" + serverPort
                + (useTls ? " [TLS]" : " [plain]"));

        // Step 3: Send authentication message
        sendAuthMessage();

        // Step 4: Start heartbeat in separate thread
        executorService.submit(this::heartbeatLoop);

        // Step 5: Block and read incoming commands
        readCommandsLoop();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Authentication
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * sendAuthMessage() - server को authentication message भेजें
     * Format: {"type":"auth","token":"...","signature":"...","timestamp":...}
     */
    private void sendAuthMessage() throws Exception {
        JSONObject auth = new JSONObject();
        auth.put("type", "auth");
        auth.put("token", authToken);
        auth.put("timestamp", System.currentTimeMillis());

        // Request signing - message integrity के लिए
        String payload = auth.toString();
        String signature = securityManager.generateSignature(payload);
        auth.put("signature", signature);

        sendMessage(auth.toString());
        Log.d(TAG, "Auth message sent");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Heartbeat
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * heartbeatLoop() - configurable interval पर server को ping भेजते रहें
     * Connection alive रखने और server को active status बताने के लिए
     */
    private void heartbeatLoop() {
        while (running.get() && socket != null && !socket.isClosed()) {
            sleepSafe(heartbeatIntervalMs);

            if (!running.get() || socket == null || socket.isClosed()) break;

            try {
                JSONObject heartbeat = new JSONObject();
                heartbeat.put("type", "heartbeat");
                heartbeat.put("timestamp", System.currentTimeMillis());
                sendMessage(heartbeat.toString());
                Log.d(TAG, "Heartbeat sent");
            } catch (Exception e) {
                Log.w(TAG, "Heartbeat failed: " + e.getMessage());
                break;
            }
        }
        Log.d(TAG, "Heartbeat loop ended");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Command Reading and Execution
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * readCommandsLoop() - server से line-by-line messages पढ़ते रहें
     * प्रत्येक line एक JSON command होना चाहिए
     */
    private void readCommandsLoop() throws Exception {
        String line;
        // Blocking read - connection close होने तक block रहता है
        while (running.get() && (line = socketReader.readLine()) != null) {
            final String message = line.trim();
            if (message.isEmpty()) continue;

            Log.d(TAG, "Received message (" + message.length() + " chars)");

            // Process each message asynchronously (reader thread block न हो)
            executorService.submit(() -> handleIncomingMessage(message));
        }
    }

    /**
     * handleIncomingMessage() - incoming JSON message parse करके appropriate action लें
     *
     * Message types:
     *   "command" → CommandRegistry में dispatch करें
     *   "config"  → Live config update apply करें
     *   others    → Log and ignore
     */
    private void handleIncomingMessage(String message) {
        try {
            JSONObject json = new JSONObject(message);
            String type = json.optString("type", "command");

            switch (type) {
                case "command":
                    // Extract command details और execute करें
                    String commandName = json.optString("command", "");
                    JSONObject params  = json.optJSONObject("params");
                    String token       = json.optString("token", authToken);
                    String requestId   = json.optString("request_id", "");

                    // Verify request signature if signing is configured
                    String receivedSig = json.optString("signature", "");
                    if (!receivedSig.isEmpty()
                            && !securityManager.verifySignature(message, receivedSig)) {
                        Log.w(TAG, "Signature verification failed for command: " + commandName);
                        sendErrorResponse(requestId, "SIGNATURE_INVALID",
                                "Request signature validation failed");
                        return;
                    }

                    // Check if command is in server's enabled list
                    if (!isCommandEnabled(commandName)) {
                        Log.w(TAG, "Command disabled by server config: " + commandName);
                        sendErrorResponse(requestId, "COMMAND_DISABLED",
                                "Command is not enabled: " + commandName);
                        return;
                    }

                    // Dispatch to CommandRegistry
                    String response = commandRegistry.invoke(commandName, params, token);
                    sendResponseWithId(requestId, response);
                    break;

                case "config":
                    // Inline config update from server (alternative to HTTP config endpoint)
                    Log.d(TAG, "Inline config update received");
                    // Delegate to configManager if it supports inline updates
                    break;

                case "heartbeat_ack":
                    Log.d(TAG, "Heartbeat acknowledged by server");
                    break;

                default:
                    Log.d(TAG, "Unknown message type: " + type + " - ignoring");
            }

        } catch (Exception e) {
            Log.e(TAG, "Failed to handle message: " + e.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Response Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * sendMessage() - server को message भेजें (thread-safe)
     */
    private synchronized void sendMessage(String message) {
        if (socketWriter != null && !socketWriter.checkError()) {
            socketWriter.println(message);
        } else {
            Log.w(TAG, "Cannot send message: writer not available");
        }
    }

    /**
     * sendResponseWithId() - request_id के साथ response भेजें
     */
    private void sendResponseWithId(String requestId, String response) {
        try {
            if (requestId == null || requestId.isEmpty()) {
                sendMessage(response);
                return;
            }
            // request_id inject करें ताकि client अपना request match कर सके
            JSONObject resp = new JSONObject(response);
            resp.put("request_id", requestId);
            sendMessage(resp.toString());
        } catch (Exception e) {
            sendMessage(response);
        }
    }

    /**
     * sendErrorResponse() - error response भेजें
     */
    private void sendErrorResponse(String requestId, String errorCode, String message) {
        try {
            JSONObject error = new JSONObject();
            error.put("status", "error");
            error.put("error_code", errorCode);
            error.put("message", message);
            error.put("timestamp", System.currentTimeMillis());
            if (requestId != null && !requestId.isEmpty()) {
                error.put("request_id", requestId);
            }
            sendMessage(error.toString());
        } catch (Exception e) {
            Log.e(TAG, "Failed to send error response", e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Config Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * isCommandEnabled() - server config के according command allow है?
     * enabled_commands list empty हो तो सभी commands allowed हैं
     */
    private boolean isCommandEnabled(String commandName) {
        List<String> enabledCommands = configManager.getEnabledCommands();
        if (enabledCommands.isEmpty()) return true; // Empty = all allowed
        return enabledCommands.contains(commandName);
    }

    /**
     * applyServerConfig() - नई server config apply करें
     * (signing secret, rate limits, etc. update करें)
     */
    private void applyServerConfig() {
        // Signing secret update
        String signingSecret = configManager.getSigningSecret();
        if (!signingSecret.isEmpty()) {
            securityManager.setSigningSecret(signingSecret);
            Log.d(TAG, "Signing secret updated from server config");
        }

        // Log level update
        String logLevel = configManager.getLoggingLevel();
        Log.d(TAG, "Server log level: " + logLevel);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utility Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * closeSocket() - socket और streams safely close करें
     */
    private void closeSocket() {
        try {
            if (socketReader != null) { socketReader.close(); socketReader = null; }
        } catch (Exception ignored) {}
        try {
            if (socketWriter != null) { socketWriter.close(); socketWriter = null; }
        } catch (Exception ignored) {}
        try {
            if (socket != null && !socket.isClosed()) { socket.close(); socket = null; }
        } catch (Exception ignored) {}
    }

    /**
     * sleepSafe() - InterruptedException को safely handle करते हुए sleep करें
     */
    private void sleepSafe(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
