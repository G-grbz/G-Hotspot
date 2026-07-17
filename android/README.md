# G-Hotspot Android Admin

This helper app opens the G-Hotspot admin panel in a WebView and registers the
phone as an Android notification device through the G-Hotspot pairing flow.

## Build

For instant locked-screen delivery, first register an Android app with package
name `com.ghotspot.admin` in Firebase and place the downloaded configuration at:

```text
android/app/google-services.json
```

The build still succeeds without this file, but then the app uses the polling
fallback and Android may delay notifications during Doze.

```sh
JAVA_HOME=/usr/lib/jvm/java-17-openjdk ANDROID_USER_HOME="$PWD/app/.android" GRADLE_USER_HOME=/tmp/g-hotspot-gradle gradle --no-daemon :app:assembleDebug
```

The debug APK is written to:

```text
android/app/build/outputs/apk/debug/g-hotspot.apk
```

The same flow is available in the admin panel under **Settings > Android
notifications**. Uploading a `google-services.json` there validates that it is
an Android Firebase configuration for `com.ghotspot.admin`, replaces the
project's `android/app/google-services.json`, and invalidates the previous APK.
The **Build APK** action runs Gradle on the server and exposes the resulting APK
for authenticated download when the build succeeds.

The server needs Java 17, a `gradle` executable on `PATH`, and an Android SDK.
The builder reads `ANDROID_HOME` or `ANDROID_SDK_ROOT` and also detects common
SDK installation locations automatically. Panel builds run from an isolated
temporary workspace, while the local debug signing key is retained under
`android/app/.android`. Keep this directory to install later panel builds over
the existing app; it is excluded from Git and must remain private. When
G-Hotspot is run through the
hardened example systemd unit, keep its `android/app` `ReadWritePaths` entry so
the service can update the configuration and publish the finished APK.

## Runtime

1. Enable `NOTIFICATION_ANDROID_ENABLED` in G-Hotspot notification settings.
2. In the admin panel, open notification settings and generate an Android
   pairing code.
3. Install the APK on the Android phone.
4. Enter the G-Hotspot server address, for example `http://192.168.1.10:3000`.
5. Scan the pairing QR code or enter the pairing code manually. QR scanning uses
   Google Play services Code Scanner when available, then falls back to an
   installed ZXing-compatible scanner app.
6. Approve the pending Android device from any G-Hotspot admin panel.
7. Allow Android notifications when prompted.

After approval, the app opens `/admin` directly by creating an Android device
admin session with `/api/android/admin-session`. The persisted Android device
token is enough to recreate the admin session after G-Hotspot restarts, so the
app should not ask for the admin password again unless the device is disabled.

Admin approval notifications include `Approve` and `Reject` actions. These call
the same server decision path as the web admin panel.

The app validates HTTPS certificates against both Android's system trust store
and certificates deliberately installed in the user's credential store. This
supports private G-Hotspot certificate authorities without disabling certificate
chain, hostname, or expiry validation.

## Instant push setup

1. In Firebase Console, create or select a project and add the Android app
   `com.ghotspot.admin`.
2. Download `google-services.json` to `android/app/google-services.json` and
   rebuild/reinstall the APK.
3. In Firebase project settings, create a service-account private key and place
   its JSON file on the G-Hotspot server outside the web/public directories.
4. Set `ANDROID_FCM_SERVICE_ACCOUNT_FILE` to that absolute server path, or enter
   the path in the admin notification settings, then restart G-Hotspot.
5. Open the Android app once after updating so its Firebase registration token
   is synchronized with the server.

The server sends time-sensitive, user-visible alerts as high-priority FCM data
messages. The app renders the complete notification directly from that payload,
without a follow-up network request. This allows FCM to wake the app in Doze
while avoiding a permanent app-owned network connection.

When Firebase push is active, the foreground polling service stops and only a
six-hour recovery check remains. If Firebase is not configured or token
registration fails, the previous foreground polling behavior remains available
as a compatibility fallback. Android still blocks all delivery after the user
explicitly uses system-level Force stop until the app is opened again.

The admin panel generates QR images with the `qrencode` command when it is
available on the G-Hotspot host. If it is missing, the one-time pairing code is
still shown for manual entry.
