package com.example.remotecontrol;

import android.util.Log;
import org.json.JSONObject;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CommandRegistry - Dynamic Command Handler Registration System
 *
 * यह class एक central registry है जहाँ:
 * - Commands runtime पर register/unregister हो सकते हैं (server-driven)
 * - Custom CommandBase subclasses inject की जा सकती हैं
 * - Thread-safe invocation guaranteed है (ConcurrentHashMap)
 * - Built-in commands automatically registered होते हैं
 *
 * Usage:
 *   CommandRegistry registry = CommandRegistry.getInstance();
 *   registry.register(new MyCustomCommand(securityMgr));
 *   String response = registry.invoke("my_command", params, token);
 */
public class CommandRegistry {

    private static final String TAG = "CommandRegistry";

    // Singleton instance
    private static volatile CommandRegistry instance;

    // command name → CommandBase implementation
    // ConcurrentHashMap - thread-safe read/write without explicit locks
    private final ConcurrentHashMap<String, CommandBase> registry = new ConcurrentHashMap<>();

    /**
     * Private constructor - built-in commands यहाँ register होते हैं
     */
    private CommandRegistry() {
        Log.d(TAG, "CommandRegistry initialized");
        // Built-in commands अलग से registerBuiltins() से register करें
        // ताकि SecurityManager inject हो सके
    }

    /**
     * getInstance() - thread-safe singleton accessor
     */
    public static CommandRegistry getInstance() {
        if (instance == null) {
            synchronized (CommandRegistry.class) {
                if (instance == null) {
                    instance = new CommandRegistry();
                }
            }
        }
        return instance;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Registration API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * register() - नया command handler register करें
     * Existing handler हो तो replace हो जाएगा (hot-swap support)
     *
     * @param command  CommandBase subclass instance
     */
    public void register(CommandBase command) {
        if (command == null) {
            Log.w(TAG, "Attempted to register null command");
            return;
        }
        String name = command.getCommandName();
        registry.put(name, command);
        Log.d(TAG, "Command registered: " + name);
    }

    /**
     * unregister() - command को registry से हटाएं
     * (server config में command disable होने पर call होगा)
     *
     * @param commandName  Command name to remove
     */
    public void unregister(String commandName) {
        if (commandName == null) return;
        CommandBase removed = registry.remove(commandName);
        if (removed != null) {
            Log.d(TAG, "Command unregistered: " + commandName);
        }
    }

    /**
     * isRegistered() - क्या यह command available है?
     */
    public boolean isRegistered(String commandName) {
        return commandName != null && registry.containsKey(commandName);
    }

    /**
     * getRegisteredCommands() - सभी registered command names की snapshot
     * (debugging/logging के लिए)
     */
    public String[] getRegisteredCommands() {
        return registry.keySet().toArray(new String[0]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Invocation API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * invoke() - command को execute करें
     *
     * @param commandName  Command to execute
     * @param params       JSON parameters for the command
     * @param token        Auth token (SecurityManager को pass होगा)
     * @return             JSON response string from CommandBase.execute()
     */
    public String invoke(String commandName, JSONObject params, String token) {
        if (commandName == null || commandName.isEmpty()) {
            return buildErrorJson("INVALID_COMMAND", "Command name is null or empty");
        }

        CommandBase command = registry.get(commandName);
        if (command == null) {
            Log.w(TAG, "Unknown command requested: " + commandName);
            return buildErrorJson("UNKNOWN_COMMAND",
                    "Command not found in registry: " + commandName);
        }

        Log.d(TAG, "Invoking command: " + commandName);
        return command.execute(params != null ? params : new JSONObject(), token);
    }

    /**
     * invoke() - convenience overload with raw JSON string params
     */
    public String invoke(String commandName, String paramsJson, String token) {
        JSONObject params = new JSONObject();
        if (paramsJson != null && !paramsJson.isEmpty()) {
            try {
                params = new JSONObject(paramsJson);
            } catch (Exception e) {
                Log.w(TAG, "Failed to parse params JSON: " + paramsJson);
                return buildErrorJson("INVALID_PARAMS", "Params is not valid JSON");
            }
        }
        return invoke(commandName, params, token);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Built-in Commands Registration
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * registerBuiltins() - SecurityManager inject करके built-in commands register करें.
     * App startup पर call करें।
     *
     * Built-in commands:
     *   - "ping"          → connectivity check
     *   - "get_info"      → system info
     *   - "log_level"     → server-driven log level control
     *   - "list_commands" → available commands list
     */
    public void registerBuiltins(SecurityManager securityManager) {
        // ── ping command ──────────────────────────────────────────────────────
        register(new CommandBase("ping", securityManager) {
            @Override
            protected String doExecute(JSONObject params) {
                return "pong:" + System.currentTimeMillis();
            }
        });

        // ── get_info command ─────────────────────────────────────────────────
        // Device और app की basic system info return करता है
        register(new CommandBase("get_info", securityManager) {
            @Override
            protected String doExecute(JSONObject params) throws Exception {
                JSONObject info = new JSONObject();
                info.put("android_version", android.os.Build.VERSION.RELEASE);
                info.put("device_model", android.os.Build.MODEL);
                info.put("manufacturer", android.os.Build.MANUFACTURER);
                info.put("sdk_int", android.os.Build.VERSION.SDK_INT);
                info.put("timestamp", System.currentTimeMillis());
                return info.toString();
            }
        });

        // ── log_level command ────────────────────────────────────────────────
        // Server द्वारा log verbosity control (future: pass to ServerConfigManager)
        register(new CommandBase("log_level", securityManager) {
            @Override
            protected String doExecute(JSONObject params) throws Exception {
                String level = params.optString("level", "INFO");
                // Validate allowed levels
                if (!level.matches("VERBOSE|DEBUG|INFO|WARN|ERROR")) {
                    throw new IllegalArgumentException("Invalid log level: " + level);
                }
                Log.i(TAG, "Log level change requested: " + level);
                return "Log level set to: " + level;
            }
        });

        // ── list_commands command ────────────────────────────────────────────
        // Available commands enumerate करता है (admin/debug use)
        register(new CommandBase("list_commands", securityManager) {
            @Override
            protected String doExecute(JSONObject params) throws Exception {
                String[] commands = getRegisteredCommands();
                org.json.JSONArray arr = new org.json.JSONArray();
                for (String cmd : commands) {
                    arr.put(cmd);
                }
                JSONObject result = new JSONObject();
                result.put("commands", arr);
                result.put("count", commands.length);
                return result.toString();
            }
        });

        Log.d(TAG, "Built-in commands registered: ping, get_info, log_level, list_commands");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * buildErrorJson() - lightweight JSON error response (CommandBase के बिना)
     */
    private String buildErrorJson(String code, String message) {
        return "{\"status\":\"error\",\"error_code\":\"" + code
                + "\",\"message\":\"" + message
                + "\",\"timestamp\":" + System.currentTimeMillis() + "}";
    }
}
