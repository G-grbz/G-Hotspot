package com.ghotspot.admin;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class NotificationPollService extends Service {
    static final String CHANNEL_ALERTS = "g_hotspot_alerts";
    static final String CHANNEL_PROGRESS = "g_hotspot_approval_progress";
    static final String CHANNEL_SERVICE = "g_hotspot_service";
    static final String EXTRA_NOTIFICATION_ID = "notification_id";
    static final String EXTRA_REQUEST_ID = "request_id";
    static final String EXTRA_ACTION = "approval_action";
    static final String EXTRA_NOTIFICATION_TITLE = "notification_title";

    private static final int SERVICE_NOTIFICATION_ID = 1001;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private SharedPreferences prefs;
    private boolean polling;
    private boolean pushMode;

    private final Runnable pollRunnable = new Runnable() {
        @Override
        public void run() {
            pollOnce();
            handler.postDelayed(this, pollIntervalMs());
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        prefs = getSharedPreferences(GHotspotPrefs.NAME, MODE_PRIVATE);
        ensureChannels(this);
        startForeground(SERVICE_NOTIFICATION_ID, serviceNotification());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        handler.removeCallbacks(pollRunnable);
        handler.post(pollRunnable);
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        handler.removeCallbacks(pollRunnable);
        if (pushMode || prefs.getBoolean(GHotspotPrefs.PUSH_ENABLED, false)) {
            NotificationRestartReceiver.scheduleFallback(this);
        } else {
            NotificationRestartReceiver.schedule(this, pollIntervalMs());
        }
        executor.shutdownNow();
        super.onDestroy();
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        if (prefs.getBoolean(GHotspotPrefs.PUSH_ENABLED, false)) {
            NotificationRestartReceiver.scheduleFallback(this);
        } else {
            NotificationRestartReceiver.schedule(this, 2000);
        }
        super.onTaskRemoved(rootIntent);
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void pollOnce() {
        if (polling) return;
        String baseUrl = prefs.getString(GHotspotPrefs.BASE_URL, "");
        String token = prefs.getString(GHotspotPrefs.DEVICE_TOKEN, "");
        if (baseUrl.isEmpty() || token.isEmpty()) {
            NotificationRestartReceiver.cancel(this);
            stopSelf();
            return;
        }
        polling = true;
        executor.submit(() -> {
            PowerManager.WakeLock wakeLock = acquirePollWakeLock();
            try {
                long since = prefs.getLong(GHotspotPrefs.LAST_SEEN_AT, 0);
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                JSONObject response = GHotspotHttp.getJson(
                    baseUrl + "/api/android/notifications?since=" + since + "&limit=50",
                    headers
                );
                prefs.edit()
                    .putInt(GHotspotPrefs.POLL_INTERVAL_SECONDS, response.optInt("pollIntervalSeconds", 20))
                    .putBoolean(GHotspotPrefs.PUSH_ENABLED, response.optBoolean("pushEnabled", false))
                    .apply();
                JSONArray rows = response.optJSONArray("notifications");
                long lastSeen = since;
                if (rows != null) {
                    for (int index = 0; index < rows.length(); index += 1) {
                        JSONObject row = rows.getJSONObject(index);
                        showAlert(this, row);
                        markDelivered(baseUrl, token, row.optString("id", ""));
                        lastSeen = Math.max(lastSeen, row.optLong("createdAt", lastSeen));
                    }
                }
                if (lastSeen > since) {
                    prefs.edit().putLong(GHotspotPrefs.LAST_SEEN_AT, lastSeen).apply();
                }
                if (response.optBoolean("pushEnabled", false)) {
                    pushMode = true;
                    handler.removeCallbacks(pollRunnable);
                    NotificationRestartReceiver.scheduleFallback(this);
                    stopSelf();
                }
            } catch (Exception ignored) {
            } finally {
                polling = false;
                if (pushMode) {
                    NotificationRestartReceiver.scheduleFallback(this);
                } else {
                    NotificationRestartReceiver.schedule(this, pollIntervalMs());
                }
                releaseWakeLock(wakeLock);
            }
        });
    }

    static void showAlert(Context context, JSONObject row) {
        ensureChannels(context);
        String type = row.optString("type", "system");
        JSONObject payload = row.optJSONObject("payload");
        String requestId = payload == null ? "" : payload.optString("requestId", "");
        int notificationId = Math.abs(row.optString("id", String.valueOf(System.nanoTime())).hashCode());
        String title = row.optString("title", "G-Hotspot");
        String body = row.optString("body", "");
        if ("admin-approval".equals(type) && NotificationActionReceiver.isRequestInFlight(requestId)) return;

        Intent open = new Intent(context, MainActivity.class);
        PendingIntent contentIntent = PendingIntent.getActivity(
            context,
            notificationId,
            open,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Notification.Builder builder = new Notification.Builder(context, CHANNEL_ALERTS)
            .setSmallIcon(com.ghotspot.admin.R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(new Notification.BigTextStyle().bigText(body))
            .setContentIntent(contentIntent)
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_ALARM)
            .setDefaults(Notification.DEFAULT_ALL)
            .setPriority(Notification.PRIORITY_HIGH)
            .setVisibility(Notification.VISIBILITY_PUBLIC);

        if ("admin-approval".equals(type) && !requestId.isEmpty()) {
            builder.addAction(action(context, actionLabel(row, "approve", context.getString(R.string.action_approve)), "approve", requestId, notificationId, title));
            builder.addAction(action(context, actionLabel(row, "reject", context.getString(R.string.action_reject)), "reject", requestId, notificationId, title));
        }

        NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        manager.notify(notificationId, builder.build());
    }

    private static String actionLabel(JSONObject row, String id, String fallback) {
        JSONArray actions = row.optJSONArray("actions");
        if (actions == null) return fallback;
        for (int index = 0; index < actions.length(); index += 1) {
            JSONObject action = actions.optJSONObject(index);
            if (action != null && id.equals(action.optString("id"))) {
                String label = action.optString("label", "");
                if (!label.isEmpty()) return label;
            }
        }
        return fallback;
    }

    private static Notification.Action action(Context context, String label, String action, String requestId, int notificationId, String title) {
        Intent intent = new Intent(context, NotificationActionReceiver.class);
        intent.putExtra(EXTRA_ACTION, action);
        intent.putExtra(EXTRA_REQUEST_ID, requestId);
        intent.putExtra(EXTRA_NOTIFICATION_ID, notificationId);
        intent.putExtra(EXTRA_NOTIFICATION_TITLE, title);
        PendingIntent pendingIntent = PendingIntent.getBroadcast(
            context,
            (requestId + action).hashCode(),
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );
        return new Notification.Action.Builder(
            com.ghotspot.admin.R.drawable.ic_notification,
            label,
            pendingIntent
        ).build();
    }

    private void markDelivered(String baseUrl, String token, String notificationId) {
        if (notificationId.isEmpty()) return;
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            GHotspotHttp.postJson(
                baseUrl + "/api/android/notifications/" + notificationId + "/delivered",
                headers,
                new JSONObject()
            );
        } catch (Exception ignored) {
        }
    }

    static void markDeliveredAsync(Context context, String notificationId) {
        if (notificationId == null || notificationId.isEmpty()) return;
        Context appContext = context.getApplicationContext();
        new Thread(() -> {
            SharedPreferences prefs = appContext.getSharedPreferences(GHotspotPrefs.NAME, Context.MODE_PRIVATE);
            String baseUrl = prefs.getString(GHotspotPrefs.BASE_URL, "");
            String token = prefs.getString(GHotspotPrefs.DEVICE_TOKEN, "");
            if (baseUrl.isEmpty() || token.isEmpty()) return;
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                GHotspotHttp.postJson(
                    baseUrl + "/api/android/notifications/" + notificationId + "/delivered",
                    headers,
                    new JSONObject()
                );
            } catch (Exception ignored) {
            }
        }, "g-hotspot-delivered").start();
    }

    private long pollIntervalMs() {
        int seconds = prefs.getInt(GHotspotPrefs.POLL_INTERVAL_SECONDS, 20);
        return Math.max(5, Math.min(300, seconds)) * 1000L;
    }

    private Notification serviceNotification() {
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent contentIntent = PendingIntent.getActivity(
            this,
            1,
            open,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );
        return new Notification.Builder(this, CHANNEL_SERVICE)
            .setSmallIcon(com.ghotspot.admin.R.drawable.ic_notification)
            .setContentTitle(getString(R.string.service_notification_title))
            .setContentText(getString(R.string.service_notification_body))
            .setContentIntent(contentIntent)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setOngoing(true)
            .setPriority(Notification.PRIORITY_LOW)
            .setShowWhen(false)
            .build();
    }

    private PowerManager.WakeLock acquirePollWakeLock() {
        try {
            PowerManager powerManager = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (powerManager == null) return null;
            PowerManager.WakeLock wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "g-hotspot:notification-poll"
            );
            wakeLock.setReferenceCounted(false);
            wakeLock.acquire(Math.max(30000L, pollIntervalMs() + 10000L));
            return wakeLock;
        } catch (Exception ignored) {
            return null;
        }
    }

    private void releaseWakeLock(PowerManager.WakeLock wakeLock) {
        if (wakeLock == null) return;
        try {
            if (wakeLock.isHeld()) wakeLock.release();
        } catch (Exception ignored) {
        }
    }

    static void ensureChannels(Context context) {
        NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        manager.createNotificationChannel(new NotificationChannel(
            CHANNEL_ALERTS,
            context.getString(R.string.notification_channel_alerts),
            NotificationManager.IMPORTANCE_HIGH
        ));
        NotificationChannel progressChannel = new NotificationChannel(
            CHANNEL_PROGRESS,
            context.getString(R.string.notification_channel_progress),
            NotificationManager.IMPORTANCE_LOW
        );
        progressChannel.setSound(null, null);
        progressChannel.enableVibration(false);
        progressChannel.setShowBadge(false);
        manager.createNotificationChannel(progressChannel);
        manager.createNotificationChannel(new NotificationChannel(
            CHANNEL_SERVICE,
            context.getString(R.string.notification_channel_service),
            NotificationManager.IMPORTANCE_LOW
        ));
    }
}
