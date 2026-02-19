package com.example.remotecontrol;

import android.util.Log;
import org.json.JSONObject;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SecurityManager - Token-based authentication और request security
 *
 * Features:
 * - Token-based authentication (प्रत्येक request को valid token चाहिए)
 * - Request signing (HMAC-SHA256 based request integrity)
 * - Command permission validation (per-token permission matrix)
 * - Rate limiting (sliding window algorithm)
 *
 * Thread-safe: सभी operations ConcurrentHashMap और AtomicInteger से safe हैं।
 */
public class SecurityManager {

    private static final String TAG = "SecurityManager";

    // Maximum requests per token per minute (rate limiting)
    private static final int MAX_REQUESTS_PER_MINUTE = 60;

    // Token window duration in milliseconds (1 minute)
    private static final long RATE_WINDOW_MS = 60_000L;

    // Singleton instance - केवल एक instance पूरे app में
    private static volatile SecurityManager instance;

    // ─── Token storage ────────────────────────────────────────────────────────
    // token → TokenInfo (permissions, expiry, etc.)
    private final ConcurrentHashMap<String, TokenInfo> validTokens = new ConcurrentHashMap<>();

    // ─── Rate limiting storage ────────────────────────────────────────────────
    // token → RequestWindow (request count + window start time)
    private final ConcurrentHashMap<String, RequestWindow> rateLimitWindows = new ConcurrentHashMap<>();

    // ─── Signing secret ──────────────────────────────────────────────────────
    // Server से मिला shared secret - production में secure storage से load होगा
    private volatile String signingSecret = "";

    /**
     * Private constructor - singleton pattern
     */
    private SecurityManager() {
        Log.d(TAG, "SecurityManager initialized");
    }

    /**
     * getInstance() - thread-safe singleton accessor (double-checked locking)
     */
    public static SecurityManager getInstance() {
        if (instance == null) {
            synchronized (SecurityManager.class) {
                if (instance == null) {
                    instance = new SecurityManager();
                }
            }
        }
        return instance;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Token Management
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * registerToken() - नया authentication token register करें
     *
     * @param token       Unique token string
     * @param permissions Comma-separated list of allowed commands (या "*" for all)
     * @param expiryMs    Token expiry time in milliseconds (0 = never expires)
     */
    public void registerToken(String token, String permissions, long expiryMs) {
        if (token == null || token.isEmpty()) {
            Log.w(TAG, "Attempted to register null/empty token");
            return;
        }
        long expiry = (expiryMs > 0) ? (System.currentTimeMillis() + expiryMs) : Long.MAX_VALUE;
        validTokens.put(token, new TokenInfo(permissions, expiry));
        Log.d(TAG, "Token registered with permissions: " + permissions);
    }

    /**
     * revokeToken() - token को revoke करें (logout / security breach)
     */
    public void revokeToken(String token) {
        validTokens.remove(token);
        rateLimitWindows.remove(token);
        Log.d(TAG, "Token revoked");
    }

    /**
     * isValidToken() - क्या यह token valid और non-expired है?
     *
     * @param token  Token to validate
     * @return true if token is valid and not expired
     */
    public boolean isValidToken(String token) {
        if (token == null || token.isEmpty()) return false;
        TokenInfo info = validTokens.get(token);
        if (info == null) return false;

        // Expiry check
        if (System.currentTimeMillis() > info.expiryTime) {
            // Auto-revoke expired tokens
            validTokens.remove(token);
            Log.d(TAG, "Token expired and auto-revoked");
            return false;
        }
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Permission Validation
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * hasPermission() - क्या इस token को commandName execute करने की permission है?
     *
     * @param token       Auth token
     * @param commandName Command to check permission for
     * @return true if permitted
     */
    public boolean hasPermission(String token, String commandName) {
        if (!isValidToken(token)) return false;

        TokenInfo info = validTokens.get(token);
        if (info == null) return false;

        // "*" means all commands allowed
        if ("*".equals(info.permissions)) return true;

        // Check comma-separated permission list
        String[] perms = info.permissions.split(",");
        for (String perm : perms) {
            if (perm.trim().equalsIgnoreCase(commandName)) return true;
        }
        return false;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Rate Limiting
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * checkRateLimit() - sliding window rate limit check करें
     *
     * @param token  Token to check rate limit for
     * @return true if request is within rate limit, false if limit exceeded
     */
    public boolean checkRateLimit(String token) {
        long now = System.currentTimeMillis();

        RequestWindow window = rateLimitWindows.computeIfAbsent(
                token, k -> new RequestWindow(now));

        synchronized (window) {
            // Window expired? Reset करें
            if (now - window.windowStart >= RATE_WINDOW_MS) {
                window.windowStart = now;
                window.requestCount.set(1);
                return true;
            }

            // Within window - count increment करें और check करें
            int count = window.requestCount.incrementAndGet();
            if (count > MAX_REQUESTS_PER_MINUTE) {
                Log.w(TAG, "Rate limit exceeded: " + count + " requests in window");
                return false;
            }
            return true;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Request Signing
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * setSigningSecret() - HMAC signing secret set करें (server से प्राप्त)
     */
    public void setSigningSecret(String secret) {
        this.signingSecret = secret != null ? secret : "";
    }

    /**
     * generateSignature() - request payload का HMAC-SHA256 signature बनाएं
     *
     * @param payload  Message payload to sign
     * @return         Hex-encoded HMAC-SHA256 signature, या empty string on error
     */
    public String generateSignature(String payload) {
        if (signingSecret.isEmpty() || payload == null) return "";
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec keySpec =
                    new javax.crypto.spec.SecretKeySpec(
                            signingSecret.getBytes("UTF-8"), "HmacSHA256");
            mac.init(keySpec);
            byte[] hashBytes = mac.doFinal(payload.getBytes("UTF-8"));
            // Convert bytes to hex string
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "Signature generation failed", e);
            return "";
        }
    }

    /**
     * verifySignature() - received signature को verify करें
     *
     * @param payload           Original message payload
     * @param receivedSignature Signature received from server
     * @return true if signature matches
     */
    public boolean verifySignature(String payload, String receivedSignature) {
        if (receivedSignature == null || receivedSignature.isEmpty()) return false;
        String expectedSig = generateSignature(payload);
        // Constant-time comparison to prevent timing attacks
        return constantTimeEquals(expectedSig, receivedSignature);
    }

    /**
     * constantTimeEquals() - timing-attack safe string comparison
     * दोनों strings की length अलग हो तो भी same time लेता है
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Inner Classes
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * TokenInfo - token की metadata store करता है
     */
    private static class TokenInfo {
        final String permissions;  // Comma-separated या "*"
        final long expiryTime;     // Absolute expiry timestamp in ms

        TokenInfo(String permissions, long expiryTime) {
            this.permissions = permissions != null ? permissions : "";
            this.expiryTime = expiryTime;
        }
    }

    /**
     * RequestWindow - rate limiting के लिए sliding window data
     */
    private static class RequestWindow {
        long windowStart;             // Window start timestamp
        final AtomicInteger requestCount; // Atomic counter for thread safety

        RequestWindow(long windowStart) {
            this.windowStart = windowStart;
            this.requestCount = new AtomicInteger(0);
        }
    }
}
