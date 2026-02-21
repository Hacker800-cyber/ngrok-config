package com.example.remotecontrol;

import android.util.Log;
import org.json.JSONObject;

/**
 * CommandBase - सभी commands के लिए abstract base class
 *
 * यह class सभी command implementations के लिए:
 * - Standard error handling (एकसमान error handling)
 * - Response formatting (JSON response format)
 * - Logging integration (built-in logging)
 * - Thread-safe execution pattern
 * प्रदान करती है।
 */
public abstract class CommandBase {

    // Tag for Android logcat logging
    protected static final String TAG = "CommandBase";

    // Command name identifier - subclass में set होगा
    protected final String commandName;

    // SecurityManager reference for permission validation
    protected final SecurityManager securityManager;

    /**
     * Constructor - command name और security manager inject करते हैं
     *
     * @param commandName  इस command का unique identifier
     * @param securityManager permission validation के लिए
     */
    public CommandBase(String commandName, SecurityManager securityManager) {
        this.commandName = commandName;
        this.securityManager = securityManager;
    }

    /**
     * execute() - मुख्य entry point जो subclass की doExecute() call करता है।
     * Security check, error handling और response formatting यहाँ होती है।
     *
     * @param params  Command parameters (JSON object)
     * @param token   Auth token for permission check
     * @return        JSON formatted response string
     */
    public final String execute(JSONObject params, String token) {
        try {
            // Step 1: Permission validation - क्या यह token इस command को execute कर सकता है?
            if (securityManager != null && !securityManager.hasPermission(token, commandName)) {
                Log.w(TAG, "Permission denied for command: " + commandName);
                return buildErrorResponse("PERMISSION_DENIED",
                        "Token does not have permission for command: " + commandName);
            }

            // Step 2: Rate limiting check - बहुत तेज़ requests को block करें
            if (securityManager != null && !securityManager.checkRateLimit(token)) {
                Log.w(TAG, "Rate limit exceeded for token on command: " + commandName);
                return buildErrorResponse("RATE_LIMIT_EXCEEDED",
                        "Too many requests. Please wait before retrying.");
            }

            // Step 3: Actual command execution - subclass में implement होगा
            Log.d(TAG, "Executing command: " + commandName);
            String result = doExecute(params);

            // Step 4: Success response wrap करें
            return buildSuccessResponse(result);

        } catch (SecurityException se) {
            // Security-related errors
            Log.e(TAG, "Security error in command " + commandName + ": " + se.getMessage());
            return buildErrorResponse("SECURITY_ERROR", se.getMessage());

        } catch (IllegalArgumentException iae) {
            // Invalid parameter errors
            Log.e(TAG, "Invalid params for command " + commandName + ": " + iae.getMessage());
            return buildErrorResponse("INVALID_PARAMS", iae.getMessage());

        } catch (Exception e) {
            // Generic unexpected errors
            Log.e(TAG, "Unexpected error in command " + commandName, e);
            return buildErrorResponse("INTERNAL_ERROR",
                    "Command execution failed: " + e.getMessage());
        }
    }

    /**
     * doExecute() - subclass में implement करना अनिवार्य है।
     * यह actual command logic contain करता है।
     *
     * @param params  Command parameters
     * @return        Raw result string (success response में wrap होगा)
     * @throws Exception  Any exception will be caught by execute()
     */
    protected abstract String doExecute(JSONObject params) throws Exception;

    /**
     * getCommandName() - command का name return करता है
     */
    public String getCommandName() {
        return commandName;
    }

    /**
     * buildSuccessResponse() - standard JSON success response बनाता है
     *
     * Format: {"status":"success","command":"...","result":"...","timestamp":...}
     */
    protected String buildSuccessResponse(String result) {
        try {
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("command", commandName);
            response.put("result", result);
            response.put("timestamp", System.currentTimeMillis());
            return response.toString();
        } catch (Exception e) {
            // Fallback if JSON building fails
            return "{\"status\":\"success\",\"command\":\"" + commandName
                    + "\",\"result\":\"" + result + "\"}";
        }
    }

    /**
     * buildErrorResponse() - standard JSON error response बनाता है
     *
     * Format: {"status":"error","command":"...","error_code":"...","message":"...","timestamp":...}
     */
    protected String buildErrorResponse(String errorCode, String message) {
        try {
            JSONObject response = new JSONObject();
            response.put("status", "error");
            response.put("command", commandName);
            response.put("error_code", errorCode);
            response.put("message", message != null ? message : "Unknown error");
            response.put("timestamp", System.currentTimeMillis());
            return response.toString();
        } catch (Exception e) {
            return "{\"status\":\"error\",\"error_code\":\"" + errorCode + "\"}";
        }
    }

    /**
     * logInfo() - INFO level logging with command context
     */
    protected void logInfo(String message) {
        Log.i(TAG, "[" + commandName + "] " + message);
    }

    /**
     * logError() - ERROR level logging with command context
     */
    protected void logError(String message, Throwable t) {
        Log.e(TAG, "[" + commandName + "] " + message, t);
    }

    /**
     * logDebug() - DEBUG level logging with command context
     */
    protected void logDebug(String message) {
        Log.d(TAG, "[" + commandName + "] " + message);
    }
}
