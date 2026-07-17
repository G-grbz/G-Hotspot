package com.ghotspot.admin;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.widget.Toast;

import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class NotificationActionReceiver extends BroadcastReceiver {
    private static final Set<String> IN_FLIGHT_REQUESTS = ConcurrentHashMap.newKeySet();

    static boolean isRequestInFlight(String requestId) {
        return requestId != null && !requestId.isEmpty() && IN_FLIGHT_REQUESTS.contains(requestId);
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        int sourceNotificationId = intent.getIntExtra(NotificationPollService.EXTRA_NOTIFICATION_ID, 0);
        String requestId = intent.getStringExtra(NotificationPollService.EXTRA_REQUEST_ID);
        String action = intent.getStringExtra(NotificationPollService.EXTRA_ACTION);
        String requestKey = requestId == null || requestId.isEmpty()
            ? sourceNotificationId + ":" + String.valueOf(action)
            : requestId;
        if (!IN_FLIGHT_REQUESTS.add(requestKey)) return;

        PendingResult pendingResult = goAsync();
        try {
            showProcessing(context, sourceNotificationId, action, intent.getStringExtra(NotificationPollService.EXTRA_NOTIFICATION_TITLE));
            new Thread(() -> {
                String message = context.getString(R.string.decision_sent);
                boolean success = false;
                try {
                    SharedPreferences prefs = context.getSharedPreferences(GHotspotPrefs.NAME, Context.MODE_PRIVATE);
                    String baseUrl = prefs.getString(GHotspotPrefs.BASE_URL, "");
                    String token = prefs.getString(GHotspotPrefs.DEVICE_TOKEN, "");
                    if (baseUrl == null || baseUrl.isEmpty() || token == null || token.isEmpty() ||
                        requestId == null || requestId.isEmpty() || action == null || action.isEmpty()) {
                        throw new IllegalStateException(context.getString(R.string.missing_registration));
                    }
                    Map<String, String> headers = new HashMap<>();
                    headers.put("Authorization", "Bearer " + token);
                    JSONObject body = new JSONObject();
                    body.put("message", "");
                    JSONObject response = GHotspotHttp.postJson(
                        baseUrl + "/api/android/admin-approval/requests/" + requestId + "/" + action,
                        headers,
                        body
                    );
                    success = response.optBoolean("ok", false);
                    message = success
                        ? ("approve".equals(action) ? context.getString(R.string.request_approved) : context.getString(R.string.request_rejected))
                        : response.optString("message", context.getString(R.string.decision_failed));
                } catch (Exception error) {
                    message = error.getMessage() == null ? context.getString(R.string.decision_failed) : error.getMessage();
                } finally {
                    try {
                        showResult(context, sourceNotificationId, success, message);
                    } finally {
                        IN_FLIGHT_REQUESTS.remove(requestKey);
                        pendingResult.finish();
                    }
                }
            }, "g-hotspot-action").start();
        } catch (RuntimeException error) {
            try {
                showResult(context, sourceNotificationId, false, context.getString(R.string.decision_failed));
            } finally {
                IN_FLIGHT_REQUESTS.remove(requestKey);
                pendingResult.finish();
            }
        }
    }

    private void showProcessing(Context context, int sourceNotificationId, String action, String title) {
        if (sourceNotificationId == 0) return;
        NotificationPollService.ensureChannels(context);
        NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null) return;
        String message = context.getString(
            "approve".equals(action) ? R.string.decision_approving : R.string.decision_rejecting
        );
        Notification notification = new Notification.Builder(context, NotificationPollService.CHANNEL_PROGRESS)
            .setSmallIcon(com.ghotspot.admin.R.drawable.ic_notification)
            .setContentTitle(title == null || title.isEmpty() ? "G-Hotspot" : title)
            .setContentText(message)
            .setStyle(new Notification.BigTextStyle().bigText(message))
            .setProgress(0, 0, true)
            .setCategory(Notification.CATEGORY_PROGRESS)
            .setPriority(Notification.PRIORITY_LOW)
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .setShowWhen(false)
            .build();
        manager.cancel(sourceNotificationId);
        manager.notify(sourceNotificationId, notification);
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show();
    }

    private void showResult(Context context, int sourceNotificationId, boolean success, String message) {
        NotificationPollService.ensureChannels(context);
        NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null) return;
        if (sourceNotificationId != 0) manager.cancel(sourceNotificationId);
        Intent open = new Intent(context, MainActivity.class);
        PendingIntent contentIntent = PendingIntent.getActivity(
            context,
            2001,
            open,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );
        Notification notification = new Notification.Builder(context, NotificationPollService.CHANNEL_ALERTS)
            .setSmallIcon(com.ghotspot.admin.R.drawable.ic_notification)
            .setContentTitle(success ? "G-Hotspot" : context.getString(R.string.ghotspot_error))
            .setContentText(message)
            .setStyle(new Notification.BigTextStyle().bigText(message))
            .setContentIntent(contentIntent)
            .setAutoCancel(true)
            .build();
        manager.notify(Math.abs((message + System.currentTimeMillis()).hashCode()), notification);
    }
}
