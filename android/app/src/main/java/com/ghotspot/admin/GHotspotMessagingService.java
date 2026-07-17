package com.ghotspot.admin;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;

import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;

import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

public class GHotspotMessagingService extends FirebaseMessagingService {
    @Override
    public void onNewToken(String token) {
        super.onNewToken(token);
        saveAndRegisterToken(this, token);
    }

    @Override
    public void onMessageReceived(RemoteMessage message) {
        super.onMessageReceived(message);
        String raw = message.getData().get("notification");
        if (raw == null || raw.isEmpty()) return;
        try {
            JSONObject notification = new JSONObject(raw);
            NotificationPollService.showAlert(this, notification);
            getSharedPreferences(GHotspotPrefs.NAME, MODE_PRIVATE)
                .edit()
                .putBoolean(GHotspotPrefs.PUSH_ENABLED, true)
                .apply();
            NotificationPollService.markDeliveredAsync(
                this,
                notification.optString("id", "")
            );
        } catch (Exception ignored) {
        }
    }

    @Override
    public void onDeletedMessages() {
        super.onDeletedMessages();
        NotificationRestartReceiver.startNotificationService(this);
    }

    static void syncToken(Context context) {
        try {
            FirebaseMessaging.getInstance().getToken().addOnCompleteListener(task -> {
                if (task.isSuccessful() && task.getResult() != null) {
                    saveAndRegisterToken(context, task.getResult());
                }
            });
        } catch (Exception ignored) {
            context.getSharedPreferences(GHotspotPrefs.NAME, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(GHotspotPrefs.PUSH_ENABLED, false)
                .apply();
        }
    }

    private static void saveAndRegisterToken(Context context, String fcmToken) {
        if (fcmToken == null || fcmToken.trim().isEmpty()) return;
        Context appContext = context.getApplicationContext();
        SharedPreferences prefs = appContext.getSharedPreferences(GHotspotPrefs.NAME, Context.MODE_PRIVATE);
        prefs.edit().putString(GHotspotPrefs.FCM_TOKEN, fcmToken).apply();
        String baseUrl = prefs.getString(GHotspotPrefs.BASE_URL, "");
        String deviceToken = prefs.getString(GHotspotPrefs.DEVICE_TOKEN, "");
        if (baseUrl.isEmpty() || deviceToken.isEmpty()) return;

        new Thread(() -> {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + deviceToken);
                JSONObject body = new JSONObject();
                body.put("fcmToken", fcmToken);
                JSONObject response = GHotspotHttp.postJson(
                    baseUrl + "/api/android/push-token",
                    headers,
                    body
                );
                boolean enabled = response.optBoolean("pushEnabled", false);
                prefs.edit().putBoolean(GHotspotPrefs.PUSH_ENABLED, enabled).apply();
                if (enabled) {
                    appContext.stopService(new Intent(appContext, NotificationPollService.class));
                    NotificationRestartReceiver.scheduleFallback(appContext);
                } else {
                    startPollService(appContext);
                }
            } catch (Exception ignored) {
                prefs.edit().putBoolean(GHotspotPrefs.PUSH_ENABLED, false).apply();
                startPollService(appContext);
            }
        }, "g-hotspot-fcm-register").start();
    }

    private static void startPollService(Context context) {
        Intent service = new Intent(context, NotificationPollService.class);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(service);
            } else {
                context.startService(service);
            }
        } catch (Exception ignored) {
        }
    }
}
