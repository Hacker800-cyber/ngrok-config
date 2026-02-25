package com.example.remotecontrol;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

/**
 * BootReceiver - Device Boot पर SocketService Auto-Start
 *
 * यह BroadcastReceiver BOOT_COMPLETED event handle करता है:
 * - BOOT_COMPLETED: Device reboot के बाद SocketService restart
 *
 * BOOT_COMPLETED एक "protected broadcast" है जो केवल Android system
 * send कर सकता है - third-party apps यह broadcast नहीं भेज सकतीं।
 *
 * Required manifest permissions:
 *   android.permission.RECEIVE_BOOT_COMPLETED
 */
public class BootReceiver extends BroadcastReceiver {

    private static final String TAG = "BootReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null) return;

        // Verify this is the expected system boot broadcast.
        // ACTION_BOOT_COMPLETED is a protected broadcast - only the Android system
        // can send it, so no further sender verification is required.
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            Log.w(TAG, "Ignoring unexpected action: " + intent.getAction());
            return;
        }

        Log.i(TAG, "BOOT_COMPLETED received - starting SocketService");
        startSocketService(context);
    }

    /**
     * startSocketService() - SocketService को foreground service के रूप में start करें
     *
     * Android 8.0+ (API 26+) पर background से service start करने के लिए
     * startForegroundService() use करना ज़रूरी है।
     */
    private void startSocketService(Context context) {
        try {
            Intent serviceIntent = new Intent(context, SocketService.class);

            // Note: Production में ये values secure storage (e.g., EncryptedSharedPreferences)
            // से load होनी चाहिए, hardcode नहीं करनी चाहिए।
            // यहाँ blank defaults हैं - app अपनी storage से populate करे।
            serviceIntent.putExtra(SocketService.EXTRA_HOST, "");
            serviceIntent.putExtra(SocketService.EXTRA_PORT, 0);
            serviceIntent.putExtra(SocketService.EXTRA_TOKEN, "");

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                // Android 8.0+ के लिए foreground service required है
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }

            Log.d(TAG, "SocketService start requested");

        } catch (Exception e) {
            Log.e(TAG, "Failed to start SocketService from BootReceiver", e);
        }
    }
}
