package com.example.remotecontrol;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

/**
 * BootReceiver - Device Boot/Update पर SocketService Auto-Start
 *
 * यह BroadcastReceiver दो events handle करता है:
 * 1. BOOT_COMPLETED   - Device reboot के बाद SocketService restart
 * 2. MY_PACKAGE_REPLACED - App update के बाद service restart
 *
 * Required manifest permissions:
 *   android.permission.RECEIVE_BOOT_COMPLETED
 *
 * AndroidManifest.xml में declare होना ज़रूरी है:
 *   <receiver android:name=".BootReceiver" android:exported="true">
 *     <intent-filter>
 *       <action android:name="android.intent.action.BOOT_COMPLETED"/>
 *     </intent-filter>
 *   </receiver>
 */
public class BootReceiver extends BroadcastReceiver {

    private static final String TAG = "BootReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null) return;

        String action = intent.getAction();
        Log.i(TAG, "Received broadcast: " + action);

        // Handle boot complete और package replace events
        if (Intent.ACTION_BOOT_COMPLETED.equals(action)
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {

            Log.i(TAG, "Starting SocketService after: " + action);
            startSocketService(context);
        }
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
