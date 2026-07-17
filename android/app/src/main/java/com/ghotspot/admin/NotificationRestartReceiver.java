package com.ghotspot.admin;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.SystemClock;

public class NotificationRestartReceiver extends BroadcastReceiver {
    private static final String ACTION_START_NOTIFICATION_SERVICE = "com.ghotspot.admin.START_NOTIFICATION_SERVICE";
    private static final int RESTART_REQUEST_CODE = 3001;
    private static final long PUSH_FALLBACK_INTERVAL_MS = 6L * 60L * 60L * 1000L;

    @Override
    public void onReceive(Context context, Intent intent) {
        startNotificationService(context);
    }

    static void schedule(Context context, long delayMs) {
        if (!hasRegisteredDevice(context)) return;
        Intent intent = new Intent(context, NotificationRestartReceiver.class);
        intent.setAction(ACTION_START_NOTIFICATION_SERVICE);
        PendingIntent pendingIntent = PendingIntent.getBroadcast(
            context,
            RESTART_REQUEST_CODE,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        if (alarmManager == null) return;
        long triggerAt = SystemClock.elapsedRealtime() + Math.max(1000, delayMs);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            alarmManager.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pendingIntent);
        } else {
            alarmManager.set(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pendingIntent);
        }
    }

    static void scheduleFallback(Context context) {
        schedule(context, PUSH_FALLBACK_INTERVAL_MS);
    }

    static void cancel(Context context) {
        Intent intent = new Intent(context, NotificationRestartReceiver.class);
        intent.setAction(ACTION_START_NOTIFICATION_SERVICE);
        PendingIntent pendingIntent = PendingIntent.getBroadcast(
            context,
            RESTART_REQUEST_CODE,
            intent,
            PendingIntent.FLAG_NO_CREATE | PendingIntent.FLAG_IMMUTABLE
        );
        if (pendingIntent == null) return;
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        if (alarmManager != null) alarmManager.cancel(pendingIntent);
        pendingIntent.cancel();
    }

    static void startNotificationService(Context context) {
        if (!hasRegisteredDevice(context)) return;
        Intent service = new Intent(context, NotificationPollService.class);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(service);
            } else {
                context.startService(service);
            }
        } catch (Exception ignored) {
            schedule(context, 15000);
        }
    }

    private static boolean hasRegisteredDevice(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(GHotspotPrefs.NAME, Context.MODE_PRIVATE);
        return !prefs.getString(GHotspotPrefs.BASE_URL, "").isEmpty() &&
            !prefs.getString(GHotspotPrefs.DEVICE_TOKEN, "").isEmpty();
    }
}
