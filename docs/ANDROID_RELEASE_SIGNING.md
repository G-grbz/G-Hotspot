# Android Release Signing

G-Hotspot GitHub releases can publish a signed Android APK together with the source
archive, checksums, SBOM and GitHub artifact attestations. The private signing key is
never committed to the repository.

## 1. Create the long-lived signing key once

Create the key on a trusted workstation and keep the resulting file private. The
command prompts for the keystore password instead of placing it in shell history.

```bash
keytool -genkeypair -v \
  -keystore g-hotspot-release.p12 \
  -storetype PKCS12 \
  -alias ghotspot \
  -keyalg RSA \
  -keysize 4096 \
  -validity 10000
```

For PKCS12, use the same value for the key password and keystore password if the
local JDK does not support separate passwords. Back up `g-hotspot-release.p12` in at
least one offline, access-controlled location. Losing this key means future APKs
cannot update installations signed with it.

If older G-Hotspot APKs were installed with a local/debug signing key, a new
release-signed APK cannot update those installations in place. They must be
uninstalled/reinstalled once when migrating to the permanent release key. Android
requires updates to be signed by the same application signing identity.

## 2. Encode the keystore for GitHub Actions

Linux:

```bash
base64 -w 0 g-hotspot-release.p12 > g-hotspot-release.p12.b64
```

Portable alternative:

```bash
base64 < g-hotspot-release.p12 | tr -d '\n' > g-hotspot-release.p12.b64
```

Do not commit either file. Repository `.gitignore` rules exclude common Android
signing file extensions, but the key should preferably be generated outside the
repository checkout.

## 3. Configure repository Actions secrets

In GitHub, open **Settings → Secrets and variables → Actions** and create:

```text
ANDROID_RELEASE_KEYSTORE_BASE64
ANDROID_RELEASE_KEYSTORE_PASSWORD
ANDROID_RELEASE_KEY_ALIAS
ANDROID_RELEASE_KEY_PASSWORD
```

Values:

- `ANDROID_RELEASE_KEYSTORE_BASE64`: the single-line contents of
  `g-hotspot-release.p12.b64`.
- `ANDROID_RELEASE_KEYSTORE_PASSWORD`: the keystore password.
- `ANDROID_RELEASE_KEY_ALIAS`: `ghotspot` when the example command above is used.
- `ANDROID_RELEASE_KEY_PASSWORD`: the private-key password; for the PKCS12 example
  this is normally the same as the keystore password.

The release workflow intentionally fails before publishing when any required signing
secret is missing or the key/alias/password combination cannot be opened.

## 4. Optional Firebase configuration

For Firebase Cloud Messaging in the GitHub-built APK, encode the Android Firebase
configuration and add one more Actions secret:

```bash
base64 -w 0 android/app/google-services.json > google-services.json.b64
```

```text
ANDROID_GOOGLE_SERVICES_JSON_BASE64
```

This secret is optional. If absent, the Android APK still builds and retains the
polling fallback. Never put the Firebase **service-account private key** in this
secret or in the APK; that credential belongs only on the G-Hotspot server.

## 5. Release flow

After CI is green, push the matching version tag. For version `1.3.0`:

```bash
git tag -a v1.3.0 -m "G-Hotspot v1.3.0"
git push origin v1.3.0
```

The release workflow builds and publishes:

```text
G-Hotspot-v1.3.0.zip
G-Hotspot-v1.3.0-android.apk
G-Hotspot-v1.3.0-android-signing-cert.txt
G-Hotspot-v1.3.0.sbom.cdx.json
SHA256SUMS
```

It aligns the APK before signing, verifies the final signature, includes the APK and
certificate information in `SHA256SUMS`, and subjects the release artifacts to GitHub
build-provenance attestation.

Users can verify the release APK provenance with:

```bash
gh attestation verify G-Hotspot-v1.3.0-android.apk --repo G-grbz/G-Hotspot
```

and verify downloaded release checksums with:

```bash
sha256sum -c SHA256SUMS
```
