package com.ghotspot.admin;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.DownloadManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.view.Gravity;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import com.google.mlkit.vision.barcode.common.Barcode;
import com.google.mlkit.vision.codescanner.GmsBarcodeScanner;
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions;
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private static final int QR_SCAN_REQUEST = 4801;
    private static final int DOWNLOAD_PERMISSION_REQUEST = 4802;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private SharedPreferences prefs;
    private WebView webView;
    private EditText serverUrlInput;
    private EditText pairingCodeInput;
    private boolean pairingStatusPending;
    private boolean waitingForApproval;
    private boolean adminSessionPending;
    private boolean apkDownloadPending;
    private Runnable adminSessionRetryRunnable;
    private final Runnable batteryOptimizationRunnable = this::requestBatteryOptimizationExemptionIfNeeded;

    private final Runnable pairingStatusRunnable = new Runnable() {
        @Override
        public void run() {
            checkPairingStatus();
            handler.postDelayed(this, 5000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences(GHotspotPrefs.NAME, MODE_PRIVATE);
        requestNotificationPermission();
        configureSystemBars();
        if (handlePairingIntent(getIntent())) return;
        String baseUrl = prefs.getString(GHotspotPrefs.BASE_URL, "");
        String token = prefs.getString(GHotspotPrefs.DEVICE_TOKEN, "");
        if (baseUrl.isEmpty() || token.isEmpty()) {
            showSetup();
        } else {
            showAdmin(baseUrl);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handlePairingIntent(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        String baseUrl = prefs.getString(GHotspotPrefs.BASE_URL, "");
        String token = prefs.getString(GHotspotPrefs.DEVICE_TOKEN, "");
        if (!token.isEmpty()) {
            GHotspotMessagingService.syncToken(this);
            startNotificationService();
            handler.removeCallbacks(batteryOptimizationRunnable);
            handler.postDelayed(batteryOptimizationRunnable, 5000);
        }
        if (waitingForApproval) {
            handler.removeCallbacks(pairingStatusRunnable);
            handler.post(pairingStatusRunnable);
        } else if (webView != null && !baseUrl.isEmpty() && !token.isEmpty()) {
            ensureAdminSessionThenLoad(baseUrl, true);
        }
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(pairingStatusRunnable);
        handler.removeCallbacks(batteryOptimizationRunnable);
        clearAdminSessionRetry();
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    private void showSetup() {
        clearAdminSessionRetry();
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setPadding(dp(24), dp(24), dp(24), dp(24));
        root.setFitsSystemWindows(true);
        root.setBackgroundColor(Color.WHITE);

        webView = null;
        TextView title = new TextView(this);
        title.setText(getString(R.string.app_name));
        title.setTextSize(24);
        title.setTextColor(Color.rgb(17, 24, 39));
        title.setGravity(Gravity.CENTER);
        root.addView(title, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        EditText input = new EditText(this);
        waitingForApproval = false;
        input.setHint(getString(R.string.server_hint));
        input.setSingleLine(true);
        input.setText(prefs.getString(GHotspotPrefs.BASE_URL, ""));
        serverUrlInput = input;
        LinearLayout.LayoutParams inputParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        );
        inputParams.setMargins(0, dp(22), 0, dp(12));
        root.addView(input, inputParams);

        pairingCodeInput = new EditText(this);
        pairingCodeInput.setHint(getString(R.string.pairing_code_hint));
        pairingCodeInput.setSingleLine(true);
        root.addView(pairingCodeInput, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        Button scan = new Button(this);
        scan.setText(getString(R.string.scan_qr));
        root.addView(scan, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ));
        scan.setOnClickListener(view -> scanPairingQr());

        Button save = new Button(this);
        save.setText(getString(R.string.pair_device));
        root.addView(save, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ));
        save.setOnClickListener(view -> {
            String normalized = normalizeBaseUrl(input.getText().toString());
            if (normalized.isEmpty()) {
                Toast.makeText(this, getString(R.string.enter_server), Toast.LENGTH_SHORT).show();
                return;
            }
            String code = pairingCodeInput.getText().toString().trim();
            if (code.isEmpty()) {
                Toast.makeText(this, getString(R.string.enter_pairing_code), Toast.LENGTH_SHORT).show();
                return;
            }
            claimPairingCode(normalized, code);
        });

        setContentView(root);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != QR_SCAN_REQUEST || resultCode != RESULT_OK || data == null) return;
        String result = data.getStringExtra("SCAN_RESULT");
        if (result == null || result.trim().isEmpty()) return;
        applyPairingScanResult(result);
    }

    private void showAdmin(String baseUrl) {
        clearAdminSessionRetry();
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.WHITE);
        root.setFitsSystemWindows(true);

        LinearLayout toolbar = new LinearLayout(this);
        toolbar.setGravity(Gravity.CENTER_VERTICAL);
        toolbar.setPadding(dp(8), 0, dp(8), 0);
        toolbar.setBackgroundColor(Color.WHITE);

        TextView label = new TextView(this);
        label.setText(Uri.parse(baseUrl).getHost());
        label.setTextColor(Color.rgb(55, 65, 81));
        toolbar.addView(label, new LinearLayout.LayoutParams(0, dp(48), 1));

        Button server = new Button(this);
        waitingForApproval = false;
        server.setText(getString(R.string.server));
        server.setOnClickListener(view -> showSetup());
        toolbar.addView(server, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        Button reload = new Button(this);
        reload.setText(getString(R.string.reload));
        reload.setOnClickListener(view -> webView.reload());
        toolbar.addView(reload, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        root.addView(toolbar, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(52)
        ));

        webView = new WebView(this);
        configureWebView(webView);
        root.addView(webView, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            0,
            1
        ));
        setContentView(root);
        showPanelLoading(baseUrl);
        ensureAdminSessionThenLoad(baseUrl, false);
    }

    private void configureWebView(WebView target) {
        WebSettings settings = target.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(target, true);
        target.addJavascriptInterface(new AdminSessionBridge(), "GHotspotAndroid");
        target.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                CookieManager.getInstance().flush();
                detectAdminLoginScreen(view, url);
            }
        });
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != DOWNLOAD_PERMISSION_REQUEST || !apkDownloadPending) return;
        apkDownloadPending = false;
        if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            enqueueApkDownload();
        } else {
            Toast.makeText(this, getString(R.string.apk_download_permission_denied), Toast.LENGTH_LONG).show();
        }
    }

    private void claimPairingCode(String baseUrl, String code) {
        executor.submit(() -> {
            try {
                JSONObject body = new JSONObject();
                body.put("code", code);
                body.put("name", deviceName());
                body.put("appVersion", appVersion());
                body.put("platformVersion", "Android " + Build.VERSION.RELEASE + " API " + Build.VERSION.SDK_INT);
                body.put("fcmToken", prefs.getString(GHotspotPrefs.FCM_TOKEN, ""));

                JSONObject response = GHotspotHttp.postJson(
                    baseUrl + "/api/android/pairing/claim",
                    new HashMap<>(),
                    body
                );
                String nextToken = response.optString("token", "");
                if (!nextToken.isEmpty()) {
                    prefs.edit()
                        .putString(GHotspotPrefs.BASE_URL, baseUrl)
                        .putString(GHotspotPrefs.DEVICE_TOKEN, nextToken)
                        .putInt(GHotspotPrefs.POLL_INTERVAL_SECONDS, response.optInt("pollIntervalSeconds", 20))
                        .putBoolean(GHotspotPrefs.PUSH_ENABLED, response.optBoolean("pushEnabled", false))
                        .putLong(GHotspotPrefs.LAST_SEEN_AT, 0)
                        .apply();
                    runOnUiThread(this::showWaitingForApproval);
                }
            } catch (Exception error) {
                runOnUiThread(() -> Toast.makeText(this, error.getMessage(), Toast.LENGTH_LONG).show());
            }
        });
    }

    private void showWaitingForApproval() {
        clearAdminSessionRetry();
        webView = null;
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setPadding(dp(24), dp(24), dp(24), dp(24));
        root.setFitsSystemWindows(true);
        root.setBackgroundColor(Color.WHITE);

        TextView title = new TextView(this);
        waitingForApproval = true;
        title.setText(getString(R.string.waiting_for_approval));
        title.setTextSize(22);
        title.setGravity(Gravity.CENTER);
        root.addView(title, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        TextView body = new TextView(this);
        body.setText(getString(R.string.approve_device_message));
        body.setGravity(Gravity.CENTER);
        body.setPadding(0, dp(12), 0, dp(12));
        root.addView(body, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        Button change = new Button(this);
        change.setText(getString(R.string.change_server));
        change.setOnClickListener(view -> {
            prefs.edit().remove(GHotspotPrefs.DEVICE_TOKEN).apply();
            showSetup();
        });
        root.addView(change, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        setContentView(root);
        handler.removeCallbacks(pairingStatusRunnable);
        handler.post(pairingStatusRunnable);
    }

    private void checkPairingStatus() {
        if (pairingStatusPending) return;
        String baseUrl = prefs.getString(GHotspotPrefs.BASE_URL, "");
        String token = prefs.getString(GHotspotPrefs.DEVICE_TOKEN, "");
        if (baseUrl.isEmpty() || token.isEmpty()) return;
        pairingStatusPending = true;
        executor.submit(() -> {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                JSONObject response = GHotspotHttp.getJson(baseUrl + "/api/android/pairing/status", headers);
                JSONObject device = response.optJSONObject("device");
                if (device != null && "approved".equals(device.optString("status"))) {
                    handler.removeCallbacks(pairingStatusRunnable);
                    GHotspotMessagingService.syncToken(this);
                    runOnUiThread(() -> showAdmin(baseUrl));
                }
            } catch (Exception ignored) {
            } finally {
                pairingStatusPending = false;
            }
        });
    }

    private void showPanelLoading(String baseUrl) {
        if (webView == null) return;
        String html = "<!doctype html><html><head><meta charset=\"utf-8\">" +
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
            "<style>body{margin:0;min-height:100vh;display:grid;place-items:center;" +
            "font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#374151;background:#fff}" +
            "div{text-align:center;font-size:15px}</style></head><body><div>" +
            getString(R.string.loading_panel) +
            "</div></body></html>";
        webView.loadDataWithBaseURL(baseUrl, html, "text/html", "UTF-8", null);
    }

    private void ensureAdminSessionThenLoad(String baseUrl, boolean refreshExisting) {
        if (adminSessionPending) return;
        clearAdminSessionRetry();
        String token = prefs.getString(GHotspotPrefs.DEVICE_TOKEN, "");
        if (token.isEmpty()) {
            showSetup();
            return;
        }
        adminSessionPending = true;
        if (refreshExisting) showPanelLoading(baseUrl);
        executor.submit(() -> {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                JSONObject response = GHotspotHttp.postJson(
                    baseUrl + "/api/android/admin-session",
                    headers,
                    new JSONObject()
                );
                JSONObject session = response.optJSONObject("session");
                if (session == null) throw new IllegalStateException(getString(R.string.admin_session_failed));
                String cookie = session.optString("cookieName", "gh_admin") + "=" +
                    session.optString("token", "") +
                    "; Path=/; Max-Age=" + session.optInt("maxAge", 43200) +
                    "; SameSite=Strict";
                CookieManager.getInstance().setCookie(baseUrl, cookie);
                CookieManager.getInstance().flush();
                runOnUiThread(() -> {
                    startNotificationService();
                    waitingForApproval = false;
                    if (webView != null) webView.loadUrl(baseUrl + "/admin");
                });
            } catch (Exception error) {
                runOnUiThread(() -> {
                    String message = String.valueOf(error.getMessage());
                    if (message.contains("approval")) {
                        showWaitingForApproval();
                    } else if (isPermanentRegistrationError(message)) {
                        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
                        showSetup();
                    } else {
                        showPanelLoading(baseUrl);
                        scheduleAdminSessionRetry(baseUrl);
                    }
                });
            } finally {
                adminSessionPending = false;
            }
        });
    }

    private void detectAdminLoginScreen(WebView view, String url) {
        if (!isAdminPanelUrl(url) || Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) return;
        handler.postDelayed(() -> {
            if (view != webView) return;
            view.evaluateJavascript(
                "(function(){var login=document.getElementById('loginScreen');" +
                    "return !!(login && !login.classList.contains('hidden'));})()",
                value -> {
                    if ("true".equals(value)) {
                        String baseUrl = prefs.getString(GHotspotPrefs.BASE_URL, "");
                        if (!baseUrl.isEmpty()) ensureAdminSessionThenLoad(baseUrl, true);
                    }
                }
            );
        }, 700);
    }

    private boolean isAdminPanelUrl(String url) {
        if (url == null) return false;
        try {
            Uri uri = Uri.parse(url);
            String path = uri.getPath();
            return "/admin".equals(path) || "/admin/".equals(path) || path == null || path.isEmpty();
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean isPermanentRegistrationError(String message) {
        String normalized = String.valueOf(message).toLowerCase();
        return normalized.contains("token") ||
            normalized.contains("registered") ||
            normalized.contains("unauthorized") ||
            normalized.contains("not found");
    }

    private void scheduleAdminSessionRetry(String baseUrl) {
        clearAdminSessionRetry();
        adminSessionRetryRunnable = () -> ensureAdminSessionThenLoad(baseUrl, true);
        handler.postDelayed(adminSessionRetryRunnable, 2500);
    }

    private void clearAdminSessionRetry() {
        if (adminSessionRetryRunnable != null) {
            handler.removeCallbacks(adminSessionRetryRunnable);
            adminSessionRetryRunnable = null;
        }
    }

    private final class AdminSessionBridge {
        @JavascriptInterface
        public void refreshAdminSession() {
            handler.post(() -> {
                String baseUrl = prefs.getString(GHotspotPrefs.BASE_URL, "");
                if (!baseUrl.isEmpty() && webView != null) {
                    ensureAdminSessionThenLoad(baseUrl, true);
                }
            });
        }

        @JavascriptInterface
        public void downloadAndroidApk() {
            handler.post(MainActivity.this::requestApkDownload);
        }
    }

    private void requestApkDownload() {
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P &&
            checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            apkDownloadPending = true;
            requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, DOWNLOAD_PERMISSION_REQUEST);
            return;
        }
        enqueueApkDownload();
    }

    private void enqueueApkDownload() {
        String baseUrl = prefs.getString(GHotspotPrefs.BASE_URL, "");
        if (baseUrl.isEmpty()) {
            Toast.makeText(this, getString(R.string.apk_download_failed), Toast.LENGTH_LONG).show();
            return;
        }
        try {
            Uri uri = Uri.parse(baseUrl + "/api/admin/android/app-build/apk");
            String version = appVersion();
            String fileName = "g-hotspot-" + version + "-" + System.currentTimeMillis() + ".apk";
            DownloadManager.Request request = new DownloadManager.Request(uri)
                .setTitle("G-Hotspot " + version)
                .setDescription(getString(R.string.apk_download_description))
                .setMimeType("application/vnd.android.package-archive")
                .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
                .setAllowedOverMetered(true)
                .setAllowedOverRoaming(true)
                .setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, fileName);
            String cookie = CookieManager.getInstance().getCookie(baseUrl);
            if (cookie != null && !cookie.isEmpty()) request.addRequestHeader("Cookie", cookie);
            if (webView != null) {
                String userAgent = webView.getSettings().getUserAgentString();
                if (userAgent != null && !userAgent.isEmpty()) request.addRequestHeader("User-Agent", userAgent);
            }
            DownloadManager manager = (DownloadManager) getSystemService(Context.DOWNLOAD_SERVICE);
            if (manager == null) throw new IllegalStateException("DownloadManager unavailable");
            manager.enqueue(request);
            Toast.makeText(this, getString(R.string.apk_download_started), Toast.LENGTH_LONG).show();
        } catch (Exception error) {
            Toast.makeText(this, getString(R.string.apk_download_failed), Toast.LENGTH_LONG).show();
        }
    }

    private void startNotificationService() {
        if (prefs.getBoolean(GHotspotPrefs.PUSH_ENABLED, false)) {
            NotificationRestartReceiver.scheduleFallback(this);
            return;
        }
        Intent intent = new Intent(this, NotificationPollService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 100);
        }
    }

    private void requestBatteryOptimizationExemptionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return;
        if (prefs.getBoolean(GHotspotPrefs.PUSH_ENABLED, false)) return;
        PowerManager powerManager = (PowerManager) getSystemService(Context.POWER_SERVICE);
        if (powerManager == null || powerManager.isIgnoringBatteryOptimizations(getPackageName())) return;

        long now = System.currentTimeMillis();
        long lastPromptAt = prefs.getLong(GHotspotPrefs.BATTERY_OPTIMIZATION_PROMPT_LAST_AT, 0);
        if (now - lastPromptAt < 24L * 60L * 60L * 1000L) return;
        prefs.edit().putLong(GHotspotPrefs.BATTERY_OPTIMIZATION_PROMPT_LAST_AT, now).apply();

        new AlertDialog.Builder(this)
            .setTitle(getString(R.string.battery_optimization_title))
            .setMessage(getString(R.string.battery_optimization_message))
            .setPositiveButton(getString(R.string.battery_optimization_open), (dialog, which) -> openBatteryOptimizationSettings())
            .setNegativeButton(android.R.string.cancel, null)
            .show();
    }

    private void openBatteryOptimizationSettings() {
        try {
            Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
            intent.setData(Uri.parse("package:" + getPackageName()));
            startActivity(intent);
        } catch (Exception error) {
            try {
                Intent fallback = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                fallback.setData(Uri.parse("package:" + getPackageName()));
                startActivity(fallback);
            } catch (Exception ignored) {
            }
        }
    }

    private void configureSystemBars() {
        getWindow().setStatusBarColor(Color.WHITE);
        getWindow().setNavigationBarColor(Color.WHITE);
        if (Build.VERSION.SDK_INT >= 30) {
            getWindow().setDecorFitsSystemWindows(true);
        }
    }

    private void scanPairingQr() {
        try {
            GmsBarcodeScannerOptions options = new GmsBarcodeScannerOptions.Builder()
                .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                .enableAutoZoom()
                .build();
            GmsBarcodeScanner scanner = GmsBarcodeScanning.getClient(this, options);
            scanner.startScan()
                .addOnSuccessListener(barcode -> {
                    String rawValue = barcode.getRawValue();
                    if (rawValue == null || rawValue.trim().isEmpty()) {
                        Toast.makeText(this, getString(R.string.qr_result_empty), Toast.LENGTH_LONG).show();
                        return;
                    }
                    applyPairingScanResult(rawValue);
                })
                .addOnFailureListener(error -> scanPairingQrWithExternalIntent())
                .addOnCanceledListener(() -> {});
        } catch (Exception error) {
            scanPairingQrWithExternalIntent();
        }
    }

    private void scanPairingQrWithExternalIntent() {
        try {
            Intent intent = new Intent("com.google.zxing.client.android.SCAN");
            intent.putExtra("SCAN_MODE", "QR_CODE_MODE");
            if (intent.resolveActivity(getPackageManager()) == null) {
                Toast.makeText(this, getString(R.string.qr_scanner_unavailable), Toast.LENGTH_LONG).show();
                return;
            }
            startActivityForResult(intent, QR_SCAN_REQUEST);
        } catch (Exception error) {
            Toast.makeText(this, getString(R.string.qr_scanner_unavailable), Toast.LENGTH_LONG).show();
        }
    }

    private boolean handlePairingIntent(Intent intent) {
        Uri data = intent == null ? null : intent.getData();
        if (!isPairingUri(data)) return false;
        return applyPairingUri(data, true);
    }

    private void applyPairingScanResult(String result) {
        String text = result == null ? "" : result.trim();
        if (text.isEmpty()) return;
        Uri uri = Uri.parse(text);
        if (isPairingUri(uri) && applyPairingUri(uri, true)) return;
        String code = pairingCodeFromText(text);
        if (!code.isEmpty() && pairingCodeInput != null) pairingCodeInput.setText(code);
    }

    private boolean applyPairingUri(Uri uri, boolean autoClaim) {
        if (!isPairingUri(uri)) return false;
        String server = normalizeBaseUrl(uri.getQueryParameter("server"));
        String code = normalizePairingCode(uri.getQueryParameter("code"));
        if (!server.isEmpty()) {
            prefs.edit().putString(GHotspotPrefs.BASE_URL, server).apply();
        }
        showSetup();
        if (!server.isEmpty() && serverUrlInput != null) serverUrlInput.setText(server);
        if (!code.isEmpty() && pairingCodeInput != null) pairingCodeInput.setText(code);
        if (autoClaim && !server.isEmpty() && !code.isEmpty()) {
            claimPairingCode(server, code);
        }
        return true;
    }

    private boolean isPairingUri(Uri uri) {
        return uri != null &&
            "ghotspot".equalsIgnoreCase(uri.getScheme()) &&
            "pair".equalsIgnoreCase(uri.getHost());
    }

    private String pairingCodeFromText(String text) {
        try {
            Uri uri = Uri.parse(text);
            String code = uri.getQueryParameter("code");
            if (code != null) return normalizePairingCode(code);
        } catch (Exception ignored) {
        }
        int queryIndex = text.indexOf("code=");
        if (queryIndex >= 0) {
            return normalizePairingCode(Uri.decode(text.substring(queryIndex + 5).split("&", 2)[0]));
        }
        return normalizePairingCode(text);
    }

    private String normalizeBaseUrl(String input) {
        String value = input == null ? "" : input.trim();
        if (value.isEmpty()) return "";
        if (!value.startsWith("http://") && !value.startsWith("https://")) {
            value = "http://" + value;
        }
        while (value.endsWith("/")) value = value.substring(0, value.length() - 1);
        try {
            Uri uri = Uri.parse(value);
            if (uri.getHost() == null || uri.getHost().isEmpty()) return "";
            return value;
        } catch (Exception error) {
            return "";
        }
    }

    private String normalizePairingCode(String input) {
        return input == null ? "" : input.toUpperCase().replaceAll("[^A-Z0-9]", "");
    }

    private String deviceName() {
        return (Build.MANUFACTURER + " " + Build.MODEL).trim();
    }

    private String appVersion() {
        try {
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), 0);
            return info.versionName;
        } catch (Exception ignored) {
            return "1.1.0";
        }
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }
}
