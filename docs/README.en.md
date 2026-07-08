# G-Hotspot English Documentation

G-Hotspot is a Node.js verification and session-management service for OPNsense Captive Portal. G-Hotspot handles guest verification, then grants internet access through the OPNsense Captive Portal Session API.

This document covers installation, production setup, OPNsense API privileges, Kea DHCP, 5651/syslog logging, Turkish NVİ identity verification and WhatsApp Cloud API configuration.

## Table of Contents

- [Status and live-test note](#status-and-live-test-note)
- [Features](#features)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Base configuration](#base-configuration)
- [Admin panel](#admin-panel)
- [Verification methods](#verification-methods)
- [OPNsense production setup](#opnsense-production-setup)
- [OPNsense API user and required privileges](#opnsense-api-user-and-required-privileges)
- [Kea DHCP integration](#kea-dhcp-integration)
- [Traffic Shaper, speed limits and quotas](#traffic-shaper-speed-limits-and-quotas)
- [5651 / Syslog evidence chain](#5651--syslog-evidence-chain)
- [Notifications](#notifications)
- [Security and privacy](#security-and-privacy)
- [Testing and troubleshooting](#testing-and-troubleshooting)

## Status and live-test note

Current repository state:

- Application version: `1.0.0`
- Required Node.js version: `>=24.0.0`
- Database: built-in Node.js `node:sqlite`
- Default gateway mode: `mock`
- Production gateway mode: `opnsense-api`
- License: AGPL-3.0-only
- No external runtime npm dependency.

Live-test status:

- 5651/syslog logging and the KamuSM RFC3161 timestamp flow have been live-tested with a real KamuSM account.
- Generic RFC3161 and API-key TSA providers commonly used for US/EU deployments have not been live-tested with real provider accounts.
- Turkish T.C. identity verification has not been live-tested with a real NVİ KPSv2 account.
- WhatsApp OTP delivery has not been live-tested with a real Meta WhatsApp Cloud API production account and approved template.

Validate these features in your own environment before production use. Do not present the 5651/syslog feature as a legal compliance guarantee without live end-to-end testing and review by the people responsible for your legal, privacy, security and evidence-retention processes. Generate a sample evidence package (`.log`, `.log.tsq`, `.log.tsr`) and have it reviewed by the legal/privacy/security/evidence-retention teams or advisors responsible for your jurisdiction and organization.

## Features

- Single-use or multi-use voucher codes.
- E-mail OTP through SMTP.
- WhatsApp OTP through Meta WhatsApp Cloud API.
- SMS OTP through Netgsm, İleti Merkezi, Twilio or a custom HTTP provider.
- Telegram OTP through a Telegram bot. Bots cannot message a phone number directly; the user opens the bot and shares their own Telegram contact.
- Turkish T.C. identity verification through NVİ KPSv2.
- Optional SMS OTP after successful NVİ verification.
- Manual admin approval workflow.
- Turkish and English portal/admin UI.
- Runtime settings through the admin panel.
- Voucher generation, inventory, disable flow and CSV export.
- Active sessions, verification history, traffic counters and CSV reports.
- OPNsense Captive Portal Session API integration.
- OPNsense Kea DHCPv4 lease/reservation synchronization.
- Per-user download/upload speed limits through OPNsense Traffic Shaper.
- Method-specific daily, weekly or monthly quota profiles.
- 5651/syslog-oriented tamper-evident logging with a hash chain.
- Daily `.log`, `.log.tsq` and `.log.tsr` files for completed days.
- Clock, NTP, timezone, service start/stop integrity events.
- System notifications by e-mail, SMS and Telegram.

## Requirements

Development or test:

- Node.js 24 or newer.
- Linux, macOS or another environment supported by Node.js 24.
- `GATEWAY_MODE=mock` for testing without OPNsense.

Production:

- OPNsense Captive Portal.
- A dedicated, restricted OPNsense API user.
- Kea DHCPv4. Managed DHCP lease/reservation synchronization works with Kea DHCP.
- Static IP address for the G-Hotspot host.
- Guest network access to the G-Hotspot IP and port before captive portal authentication.
- HTTPS reverse proxy or a valid TLS certificate in production.
- OPNsense remote syslog forwarding if syslog logging is enabled.
- TSA credentials/API key and outbound access if syslog timestamping is enabled.
- NVİ KPSv2 username/password if Turkish identity verification is enabled.
- Meta WhatsApp Business setup, approved Authentication template, Phone Number ID and access token if WhatsApp verification is enabled.

Check Node.js:

```bash
node --version
```

Manjaro example:

```bash
sudo pacman -S nodejs npm
```

## Quick start

```bash
npm start
```

Portal:

```text
http://localhost:8080
```

Admin panel:

```text
http://localhost:8080/admin
```

Health check:

```bash
curl http://127.0.0.1:8080/health
```

`npm start` creates `data/system.db` on first run and serves `/install` until
the administrator account, application secret and gateway mode are configured.
If `.env` already exists, it is not overwritten and its values are imported into
`system.db` for backward compatibility. After import, runtime configuration is
read from `system.db`; `.env` is not loaded as a live settings source.

## Base configuration

Main settings live in `data/system.db` and can be changed from the installer or
admin settings panel. See [`.env.example`](../.env.example) as a legacy/import
reference.

Minimum application settings:

```dotenv
APP_NAME=G-Hotspot
HOST=
PORT=
APP_SECRET=replace-with-at-least-32-random-characters
DATABASE_PATH=./data/hotspot.db
PUBLIC_BASE_URL=
DEFAULT_LANGUAGE=en
SESSION_MINUTES=720
```

When `HOST` or `PUBLIC_BASE_URL` is empty, G-Hotspot detects the server IPv4
address automatically. When `PORT` is empty, it uses `8080`.

Admin:

```dotenv
ADMIN_USERNAME=admin
ADMIN_PASSWORD=long-unique-password
ADMIN_SESSION_HOURS=12
```

Gateway:

```dotenv
GATEWAY_MODE=mock
```

`mock` mode lets you test the portal without touching OPNsense. It does not open real internet access.

For OPNsense:

```dotenv
GATEWAY_MODE=opnsense-api
OPNSENSE_BASE_URL=https://192.168.1.1
OPNSENSE_ZONE_ID=0
OPNSENSE_API_KEY=api-key
OPNSENSE_API_SECRET=api-secret
OPNSENSE_TLS_REJECT_UNAUTHORIZED=true
```

Duration units:

- Retry interval: `minutes`, `hours`, `days`, `months`, `years`, `unlimited`
- Reverification and access duration: `hours`, `days`, `months`, `years`, `unlimited`

Example:

```dotenv
EMAIL_IP_RETRY_INTERVAL_VALUE=2
EMAIL_IP_RETRY_INTERVAL_UNIT=hours
EMAIL_REVERIFY_DURATION_VALUE=24
EMAIL_REVERIFY_DURATION_UNIT=hours
EMAIL_ACCESS_DURATION_VALUE=24
EMAIL_ACCESS_DURATION_UNIT=hours
```

In this example, the same IP can request a new e-mail code every two hours. The same e-mail address cannot verify again for 24 hours. Successful verification grants 24 hours of internet access.

## Admin panel

Admin panel:

```text
http://HOST:PORT/admin
```

Main panel areas:

- Dashboard: active sessions, traffic, voucher and verification summaries.
- Sessions: IP, MAC, method, start/end time and traffic counters.
- Verifications: OTP and verification history.
- Admin approval: pending access requests.
- Vouchers: single or bulk voucher generation.
- Logs: unified activity records.
- Syslog/5651: hash chain, storage status, export and timestamp status.
- Settings: application, OPNsense, syslog, e-mail, WhatsApp, SMS, Telegram, NVİ and notifications.

Secret fields are not sent back to the browser. Leaving a secret field blank keeps the current value.

These process-level settings require a restart after changes:

- `HOST`
- `PORT`
- `DATABASE_PATH`
- `APP_SECRET`

## Verification methods

### Voucher

Voucher codes are not stored in clear text. The full code is visible only when generated.

```bash
npm run voucher -- create --count=5 --minutes=720 --uses=1 --label=Guest
npm run voucher -- create --count=1 --minutes=120 --expires-days=7
npm run voucher -- list
npm run voucher -- disable --id=VOUCHER_UUID
```

Portal voucher attempts are rate-limited to 10 attempts per IP per 15 minutes.

### E-mail OTP

```dotenv
EMAIL_ENABLED=true
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_STARTTLS=true
SMTP_USER=hotspot@example.com
SMTP_PASS=app-password
```

If `SMTP_HOST` or `SMTP_USER` is empty, e-mail verification is disabled. The sender address is taken from `SMTP_USER` for safety.

Code validity: 5 minutes. Incorrect code attempt limit: 5.

### SMS OTP

Supported providers:

- `netgsm`
- `iletimerkezi`
- `twilio`
- `custom`

Base settings:

```dotenv
SMS_ENABLED=true
SMS_PROVIDER=netgsm
SMS_SENDER=GHotspot
SMS_OTP_MINUTES=5
SMS_MESSAGE_TEMPLATE={appName} access code: {code}. The code is valid for {minutes} minutes.
```

Custom HTTP service variables:

```text
{phone} {code} {message} {sender} {appName} {minutes}
```

Custom provider example:

```dotenv
SMS_PROVIDER=custom
CUSTOM_SMS_URL=https://sms.example.com/send
CUSTOM_SMS_METHOD=POST
CUSTOM_SMS_AUTHORIZATION=Bearer secret-token
CUSTOM_SMS_HEADERS_JSON={"x-source":"g-hotspot"}
CUSTOM_SMS_BODY_TEMPLATE={"to":"{phone}","sender":"{sender}","message":"{message}","code":"{code}"}
CUSTOM_SMS_SUCCESS_PATH=data.success
```

### WhatsApp OTP

WhatsApp delivery uses Meta WhatsApp Cloud API. The user receives a 6-digit code in WhatsApp and enters it in the portal.

Live-test status: not live-tested with a real Meta production account and approved template. Test with your own Meta application before production use.

Meta-side setup:

1. Create an OTP template in the `Authentication` category in WhatsApp Manager.
2. Use a template name such as `hotspot_otp`.
3. Choose the template language that matches your portal language.
4. If the template includes a copy/code button, keep `WHATSAPP_TEMPLATE_BUTTON=true`.
5. Wait for Meta approval.
6. Copy `Phone Number ID` from the API Setup screen.
7. In production, use a permanent System User access token with `whatsapp_business_messaging`, not a temporary token.

`.env`:

```dotenv
WHATSAPP_ENABLED=true
WHATSAPP_BUSINESS_NUMBER=905551112233
WHATSAPP_PHONE_NUMBER_ID=meta-phone-number-id
WHATSAPP_ACCESS_TOKEN=meta-system-user-access-token
WHATSAPP_TEMPLATE_NAME=hotspot_otp
WHATSAPP_TEMPLATE_LANGUAGE=tr
WHATSAPP_TEMPLATE_BUTTON=true
META_GRAPH_API_VERSION=v22.0
META_GRAPH_BASE_URL=https://graph.facebook.com
```

WhatsApp is considered disabled if any of these values are empty:

```text
WHATSAPP_PHONE_NUMBER_ID
WHATSAPP_ACCESS_TOKEN
WHATSAPP_TEMPLATE_NAME
```

If you are using a Meta test number, add the recipient phone number to the allowed recipient list in the Meta API Setup screen.

WhatsApp code validity: 10 minutes. Incorrect code attempt limit: 5.

Webhook is optional. Code verification does not depend on the webhook. Use it only if you want delivery/read status events:

```dotenv
WHATSAPP_VERIFY_TOKEN=long-random-value
META_APP_SECRET=meta-app-secret
PUBLIC_BASE_URL=https://hotspot.example.com
```

Webhook URL:

```text
https://hotspot.example.com/webhooks/whatsapp
```

If `META_APP_SECRET` is set, incoming `X-Hub-Signature-256` signatures are verified.

### Telegram OTP

Telegram bots cannot message a phone number directly. The flow is:

1. The user selects Telegram verification in the portal.
2. The portal redirects the user to the Telegram bot.
3. The user shares their own Telegram contact with the bot.
4. The bot sends an OTP.
5. The user enters the code in the portal.

```dotenv
TELEGRAM_ENABLED=true
TELEGRAM_BOT_USERNAME=GHotspotBot
TELEGRAM_MODE=webhook
TELEGRAM_BOT_TOKEN=bot-token
TELEGRAM_WEBHOOK_SECRET=long-random-value
TELEGRAM_OTP_MINUTES=5
```

`TELEGRAM_MODE=polling` can be useful for local tests. Webhook mode is recommended for production.

### Turkish T.C. identity verification, NVİ KPSv2

NVİ verification checks the user's Turkish T.C. identity number, first name, last name and birth year through KPSv2.

Live-test status: not live-tested with a real NVİ KPSv2 account. Test with your own NVİ credentials before production use.

Important details:

- The old public `KPSPublic.asmx` service is not used.
- KPSv2 username/password must be obtained from NVİ.
- If `NVI_SEND_SMS_CODE=false`, successful NVİ verification opens access immediately.
- If `NVI_SEND_SMS_CODE=true`, successful NVİ verification is followed by SMS OTP to the user's phone.
- SMS-backed NVİ requires `SMS_ENABLED=true` and a configured SMS provider.

```dotenv
NVI_ENABLED=true
NVI_SEND_SMS_CODE=false
NVI_ACCESS_DURATION_VALUE=24
NVI_ACCESS_DURATION_UNIT=hours
NVI_USERNAME=kps-username
NVI_PASSWORD=kps-password
```

NVİ with SMS code:

```dotenv
NVI_SEND_SMS_CODE=true
SMS_ENABLED=true
SMS_PROVIDER=netgsm
```

Incorrect SMS code attempt limit: 5.

### Admin approval

Admin approval lets the guest submit their full name and optional contact information. An administrator approves or rejects the request from the admin panel.

```dotenv
ADMIN_APPROVAL_ENABLED=true
ADMIN_APPROVAL_REQUEST_TTL_MINUTES=1440
ADMIN_APPROVAL_ACCESS_DURATION_VALUE=24
ADMIN_APPROVAL_ACCESS_DURATION_UNIT=hours
ADMIN_APPROVAL_APPROVE_TEXT=Your internet access request was approved.
ADMIN_APPROVAL_REJECT_TEXT=Your internet access request was rejected.
```

Approval results can be sent to the user by e-mail or SMS.

## OPNsense production setup

Recommended layout:

```text
Guest VLAN/WiFi
  -> OPNsense Captive Portal
  -> G-Hotspot HTTP/HTTPS portal
  -> OPNsense Captive Portal Session API
```

OPNsense-side checklist:

1. Create a Captive Portal zone for the guest VLAN or WiFi.
2. Assign a static IP address to the G-Hotspot host.
3. Add the G-Hotspot IP and port to the captive portal allowed addresses/list.
4. Make sure guests can reach G-Hotspot before authentication.
5. Create a separate low-privilege OPNsense API user.
6. Generate API key/secret.
7. Select `opnsense-api` on `/install` or in the admin settings panel.
8. Use Kea DHCP, or disable Kea synchronization.

OPNsense captive portal template:

- Open `Create template` in the admin panel.
- Set the HTML language, page title, redirect URL/port and visible text.
- Download the generated ZIP with `Download ZIP`.
- Upload the ZIP file to the OPNsense captive portal template field.

Single zone:

```dotenv
OPNSENSE_ZONE_ID=0
```

Multiple zones:

```dotenv
OPNSENSE_ZONE_MAP="172.16.2.0/24=0; 172.16.3.0/24=1"
```

Client IPs that do not match the map fall back to `OPNSENSE_ZONE_ID`.

Behind a reverse proxy:

```dotenv
TRUST_PROXY=true
PUBLIC_BASE_URL=https://hotspot.example.com
```

`TRUST_PROXY=true` trusts `X-Forwarded-For`. Do not enable it if G-Hotspot is directly exposed.

First test with a self-signed OPNsense certificate:

```dotenv
OPNSENSE_TLS_REJECT_UNAUTHORIZED=false
```

Use a valid certificate for permanent production setup.

## OPNsense API user and required privileges

Do not grant full administrator privileges to the OPNsense API user. Create a separate user and assign only the effective privileges required by the endpoints being used.

Menu paths and privilege names may vary depending on the OPNsense version. The relevant section is generally located at:

```text
System -> Access -> Users -> Edit user -> Effective Privileges
```

API areas used by G-Hotspot:

| Feature                                     | Endpoint examples                                                                        | Privilege to select under OPNsense `Effective Privileges` |
| ------------------------------------------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Open captive portal access                  | `POST /api/captiveportal/session/connect/{zoneId}`                                       | **Services: Captive Portal**                              |
| List captive portal sessions                | `GET /api/captiveportal/session/list/{zoneId}`                                           | **Services: Captive Portal**                              |
| Disconnect a captive portal session         | `POST /api/captiveportal/session/disconnect/{zoneId}`                                    | **Services: Captive Portal**                              |
| Read the ARP table                          | `GET /api/diagnostics/interface/get_arp`                                                 | **Diagnostics: ARP Table**                                |
| Read DHCP leases                            | `/api/kea/leases4/search`, `/api/kea/leases/search`, and fallback DHCPv4 lease endpoints | **Services: DHCP: Kea (v4)**                              |
| Read Kea subnets, options, and reservations | `/api/kea/dhcpv4/searchSubnet`, `searchOption`, `searchReservation`                      | **Services: DHCP: Kea (v4)**                              |
| Write Kea reservations                      | `addReservation`, `setReservation`, `delReservation`                                     | **Services: DHCP: Kea (v4)**                              |
| Write Kea options                           | `addOption`                                                                              | **Services: DHCP: Kea (v4)**                              |
| Reconfigure the Kea service                 | `/api/kea/service/reconfigure`                                                           | **Services: DHCP: Kea (v4)**                              |
| Read Traffic Shaper pipes and rules         | `/api/trafficshaper/settings/search_pipes`, `/api/trafficshaper/settings/search_rules`   | **Firewall: Shaper**                                      |
| Write Traffic Shaper pipes and rules        | `add_pipe`, `set_pipe`, `del_pipe`, `add_rule`, `set_rule`, `del_rule`                   | **Firewall: Shaper**                                      |
| Reconfigure the Traffic Shaper service      | `/api/trafficshaper/service/reconfigure`                                                 | **Firewall: Shaper**                                      |
| Network and interface discovery             | `/api/interfaces/overview/export`, `/api/interfaces/overview/search`                     | **Status: Interfaces**                                    |
| Network connection and port diagnostics     | Related Netstat API operations                                                           | **Diagnostics: Netstat**                                  |

## Required Privileges for OPNsense 26.1.11

For the API user created for G-Hotspot, select the following entries under `Effective Privileges`:

* **Diagnostics: ARP Table**
* **Diagnostics: Netstat**
* **Firewall: Shaper**
* **Services: Captive Portal**
* **Services: DHCP: Kea (v4)**
* **Status: Interfaces**

The **Firewall: Shaper** privilege is mandatory when per-user or per-device speed limits are enabled. Without this privilege, OPNsense will generally return an `HTTP 403 Forbidden` response, and speed limit rules cannot be created or updated.

When Kea DHCP synchronization is enabled, the **Services: DHCP: Kea (v4)** privilege is required. This privilege is used to read DHCP lease records, manage reservations and options, and reconfigure the Kea service.

Without the Kea privilege, internet access through the captive portal will generally continue to work. However, DHCP reservation creation, lease duration synchronization, and related DHCP operations will be skipped, and a warning will be written to the G-Hotspot logs.

Without the **Diagnostics: ARP Table** privilege or permission to read Kea DHCP leases, IP-to-MAC address mapping and device ownership protection may not work correctly. In this case, G-Hotspot may be unable to reliably verify the MAC address of the connected device.

The **Status: Interfaces** and **Diagnostics: Netstat** privileges are used for network interface discovery, connection status checks, and diagnosing gateway-related issues.

## Kea DHCP integration

G-Hotspot can create OPNsense Kea DHCPv4 reservations so DHCP lease lifetime follows the access duration.

Default:

```dotenv
OPNSENSE_KEA_LEASE_SYNC_ENABLED=true
```

This feature:

- Resolves the verified client's IP and MAC from OPNsense ARP/DHCP lease data.
- Finds the Kea DHCPv4 subnet containing the client IP.
- Creates or reuses DHCP option 51 for the required lease time.
- Creates or updates a Kea DHCP reservation with description `G-Hotspot access <authorizationId>`.
- Reconfigures Kea when the reservation changes.
- Can remove managed reservations when sessions end.

Limits:

- This integration is for Kea DHCPv4.
- Legacy ISC DHCP reservation management is not targeted.
- If the client IP is outside Kea subnets, you will see `No OPNsense Kea DHCPv4 subnet contains <ip>`.
- If the client MAC cannot be found through OPNsense ARP/DHCP lease sources, synchronization can be skipped.

If you do not use Kea or do not want to grant Kea API privileges:

```dotenv
OPNSENSE_KEA_LEASE_SYNC_ENABLED=false
```

## Traffic Shaper, speed limits and quotas

Legacy global settings:

```dotenv
DOWNLOAD_SPEED_LIMIT_MBPS=0
UPLOAD_SPEED_LIMIT_MBPS=0
OPNSENSE_SHAPER_INTERFACE=wan
OPNSENSE_SHAPER_NETWORK=any
```

`0` means unlimited.

Method-specific speed and quota profiles:

```dotenv
VOUCHER_DOWNLOAD_SPEED_LIMIT_MBPS=20
VOUCHER_UPLOAD_SPEED_LIMIT_MBPS=5
VOUCHER_QUOTA_PERIOD=daily
VOUCHER_DOWNLOAD_QUOTA_GB=10
VOUCHER_UPLOAD_QUOTA_GB=2
```

Supported prefixes:

- `VOUCHER`
- `ADMIN_APPROVAL`
- `NVI`
- `EMAIL`
- `WHATSAPP`
- `TELEGRAM`
- `SMS`

Quota periods:

- `daily`
- `weekly`
- `monthly`

Traffic Shaper behavior:

- The app creates its managed pipes/rules with `G-Hotspot managed ...` descriptions.
- Download uses a `dst-ip` mask and upload uses a `src-ip` mask.
- This makes limits apply per user/IP.
- OPNsense Traffic Shaper is reconfigured after changes.
- If shaper application fails, the verification method is not automatically treated as failed; the error is logged.

## 5651 / Syslog evidence chain

This feature creates 5651/syslog-oriented records, builds a hash chain and can obtain TSA/RFC3161 timestamps for completed local days.

Live-test status: the KamuSM RFC3161 timestamp flow has been live-tested with a real KamuSM account. Generic RFC3161 and API-key TSA modes, including US/EU providers, have not been live-tested with real provider accounts. Run live end-to-end testing with your selected provider before using it for evidence workflows.

Legal responsibility and compliance note: this feature produces technical hash-chain, export and timestamp files; it does not guarantee legal sufficiency for any country or sector. Before production use, create sample `.log`, `.log.tsq` and `.log.tsr` files and have that package reviewed by your legal counsel, privacy/data-protection team, security team or evidence-retention advisor under the laws of Turkey, the EU, the US or any other jurisdiction where you operate.

Base behavior:

- Each traffic record includes the previous record hash.
- System events are stored in a separate hash chain.
- If a record is changed, the chain breaks and the change can be detected.
- This is tamper-evident, not tamper-proof.
- Protection against physical deletion or disk tampering depends on your external archive, WORM storage, backup and operational controls.

Base settings:

```dotenv
SYSLOG_ENABLED=true
SYSLOG_NETWORKS=172.16.2.0/24,172.16.3.0/24
SYSLOG_TIME_ZONE=Europe/Istanbul
SYSLOG_RETENTION_DAYS=730
SYSLOG_EXPORT_DIR=./data/syslog
SYSLOG_RECEIVER_ENABLED=true
SYSLOG_RECEIVER_HOST=0.0.0.0
SYSLOG_RECEIVER_PORT=5514
```

`SYSLOG_NETWORKS` accepts:

- `any`
- single IP
- CIDR
- comma-separated list
- IPv4 start-end range

Configure OPNsense to forward firewall/filterlog records to G-Hotspot as remote syslog. Use `SYSLOG_RECEIVER_PORT`.

The default port is `5514`, so root is not required. If you change it to `514`, Linux requires root or `CAP_NET_BIND_SERVICE`.

Captured traffic fields include:

- client IP
- client MAC when available
- subscriber/authorization data
- source IP/port
- destination IP/port
- protocol
- service type
- byte counters
- raw source JSON/line
- creation time
- previous hash and record hash

### Storage guard

When syslog is enabled, G-Hotspot checks that log storage is writable before granting a new portal session.

```dotenv
SYSLOG_STORAGE_ALERT_PERCENT=85
SYSLOG_STORAGE_BLOCK_PERCENT=99
```

- At the alert threshold, the admin panel shows a warning and a system event is recorded.
- At the block threshold, new portal sessions are rejected.
- Existing sessions are not directly disconnected.

`SYSLOG_RETENTION_DAYS` is policy metadata. Do not rely on automatic deletion; plan your archive and cleanup process separately.

### Syslog timestamping

```dotenv
SYSLOG_TIMESTAMP_MODE=kamusm
SYSLOG_KAMUSM_USER=kamusm-user
SYSLOG_KAMUSM_PASSWORD=kamusm-password
SYSLOG_KAMUSM_URL=http://zd.kamusm.gov.tr
SYSLOG_KAMUSM_TIMEOUT_SECONDS=60
```

`SYSLOG_TIMESTAMP_MODE` accepts:

- `disabled`: does not create timestamp tokens.
- `kamusm`: keeps the existing KamuSM behavior; it sends the RFC3161 request to KamuSM TSA with HTTP Basic username/password.
- `rfc3161`: standard RFC3161 HTTP TSA flow commonly used by international providers, including US/EU deployments.
- `api-key`: RFC3161 request with a configurable API key HTTP header.

RFC3161 example:

```dotenv
SYSLOG_TIMESTAMP_MODE=rfc3161
SYSLOG_TIMESTAMP_URL=https://tsa.example.com
SYSLOG_TIMESTAMP_HEADERS_JSON=
SYSLOG_TIMESTAMP_CERT_REQUEST=true
SYSLOG_TIMESTAMP_TIMEOUT_SECONDS=60
```

API key example:

```dotenv
SYSLOG_TIMESTAMP_MODE=api-key
SYSLOG_TIMESTAMP_API_URL=https://tsa.example.com
SYSLOG_TIMESTAMP_API_KEY=provider-api-key
SYSLOG_TIMESTAMP_API_KEY_HEADER=Authorization
SYSLOG_TIMESTAMP_API_KEY_PREFIX=Bearer
SYSLOG_TIMESTAMP_API_TIMEOUT_SECONDS=60
```

Legal sufficiency depends on the jurisdiction, the provider's TSA certificate/profile and the organization's policy; these settings provide the technical timestamp token workflow.

Example files for each completed local day:

```text
2026-06-27.log      Daily raw log
2026-06-27.log.tsq  RFC3161 timestamp query
2026-06-27.log.tsr  Timestamp response/token
```

The app creates an RFC3161 timestamp query from the SHA-256 digest of the `.log` file, sends it to the selected TSA endpoint and stores the returned token as `.log.tsr`.

OpenSSL verification example:

```bash
openssl ts -verify \
  -queryfile 2026-06-27.log.tsq \
  -in 2026-06-27.log.tsr \
  -CAfile provider-tsa-ca.pem
```

### Clock, NTP and service events

```dotenv
SYSLOG_HEALTH_CHECK_INTERVAL_SECONDS=60
SYSLOG_CLOCK_SKEW_ALERT_SECONDS=120
SYSLOG_NTP_CHECK_ENABLED=true
```

Example recorded events:

- `clock_moved_backward`
- `clock_jumped_forward`
- `ntp_sync_lost`
- `ntp_sync_restored`
- `timezone_changed`
- `system_boot_detected`
- `syslog_receiver_started`
- `syslog_receiver_stopped`
- `syslog_auto_exporter_started`
- `syslog_auto_exporter_stopped`

`timedatectl` is recommended on Linux for NTP checks. Set
`SYSLOG_NTP_CHECK_ENABLED=false` if `timedatectl`, systemd or DBus is not
available on the host.

## Notifications

System notifications can be sent by e-mail, SMS and Telegram.

Example:

```dotenv
NOTIFICATION_EMAIL_ENABLED=true
NOTIFICATION_EMAIL_RECIPIENTS=admin@example.com
NOTIFICATION_EMAIL_REPEAT_FREQUENCY=state-change

NOTIFICATION_SMS_ENABLED=true
NOTIFICATION_SMS_RECIPIENTS=905551112233
NOTIFICATION_SMS_REPEAT_FREQUENCY=state-change

NOTIFICATION_TELEGRAM_ENABLED=true
NOTIFICATION_TELEGRAM_RECIPIENTS=123456789
NOTIFICATION_TELEGRAM_REPEAT_FREQUENCY=state-change
```

Supported repeat frequencies:

- `state-change`
- `hourly`
- `daily`
- `monthly`

Notification events include:

- syslog storage warning
- syslog timestamp success/failure
- system startup
- OPNsense access failure
- user verified
- access expired
- admin login
- failed admin login attempt
- admin approval result

## systemd example

The repository includes [systemd/g-hotspot.service.example](../systemd/g-hotspot.service.example).

User service example:

```ini
[Unit]
Description=G-Hotspot captive portal service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/USER/g-hotspot
ExecStart=/usr/bin/node src/server.js
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/USER/g-hotspot/data

[Install]
WantedBy=default.target
```

Install:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/g-hotspot.service.example ~/.config/systemd/user/g-hotspot.service
systemctl --user daemon-reload
systemctl --user enable --now g-hotspot
journalctl --user -u g-hotspot -f
```

If you run it as a system service, adjust the user, directory permissions and `ReadWritePaths` for your deployment.

## Security and privacy

- Do not commit `data/system.db` or legacy `.env` files.
- `APP_SECRET` must be at least 32 random, unique characters.
- Use a long, unique admin password.
- Do not give the OPNsense API user full admin privileges.
- Use HTTPS in production.
- Use `TRUST_PROXY=true` only behind a trusted reverse proxy.
- Use `OPNSENSE_TLS_REJECT_UNAUTHORIZED=false` only for initial testing.
- Use `META_APP_SECRET` for Meta webhook signature verification.
- Do not share provider tokens or SMS/SMTP passwords.
- Verification identities, IP addresses, MAC addresses, session records and logs can contain personal data.
- Confirm your local privacy, consent, notice and retention requirements.
- Replace `PORTAL_TERMS_MARKDOWN`, `PORTAL_POLICY_MARKDOWN` and `PORTAL_PRIVACY_MARKDOWN` with your organization's texts.

## Testing and checks

Code checks:

```bash
npm run check
npm test
```

Health check:

```bash
curl http://127.0.0.1:8080/health
```

Gateway test approach:

- First test portal flows with `GATEWAY_MODE=mock`.
- Then switch to `opnsense-api` in an OPNsense test VLAN.
- Verify captive portal connect/list/disconnect operations.
- Verify Kea DHCP reservation creation.
- Verify Traffic Shaper pipe/rule creation.
- Verify syslog file writing and storage guard behavior.
- Test WhatsApp and NVİ against real external accounts separately; verify KamuSM with your own account/network, and live-test RFC3161/API-key TSA providers end-to-end with your selected provider account.

## Troubleshooting

`OPNsense API returned HTTP 403`

- The API user's effective privileges are incomplete.
- For Traffic Shaper, check the `Firewall: Shaper` privilege specifically.

`No OPNsense Kea DHCPv4 subnet contains <ip>`

- The client IP is not inside a Kea DHCPv4 subnet.
- OPNsense Kea DHCP may not be enabled.
- The API user may be missing Kea subnet read privileges.

`Kea DHCP lease lifetime could not be synchronized`

- Kea API privileges are missing.
- Client MAC address could not be resolved from ARP/DHCP lease sources.
- You can disable this feature with `OPNSENSE_KEA_LEASE_SYNC_ENABLED=false`.

`WhatsApp Cloud API rejected the message`

- Template may not be approved.
- Template language may be wrong.
- Phone Number ID may be wrong.
- Access token may be missing privileges or expired.
- In Meta test mode, the recipient number may not be in the allowed recipient list.

`NVI verification could not be completed`

- KPSv2 username/password may be wrong.
- Network access to NVİ may be unavailable.
- System clock may be wrong.
- Your KPSv2 account may not be authorized for this service.

`Syslog storage is ... full`

- The disk for `SYSLOG_EXPORT_DIR` is full.
- New sessions are rejected at the block threshold.
- Move logs to a safe archive and free disk space.

`Timestamp failed`

- In KamuSM mode, username/password may be wrong.
- In RFC3161/API-key mode, TSA URL, API key or additional header settings may be wrong.
- `SYSLOG_KAMUSM_URL`, `SYSLOG_TIMESTAMP_URL` or `SYSLOG_TIMESTAMP_API_URL` network access may be wrong.
- Organization firewall may block the TSA endpoint.
- The KamuSM flow has been live-tested with a real KamuSM account; for RFC3161/API-key providers, live verification depends on your provider account, so test end-to-end with your own account.

## Main files

- [../README.md](../README.md): GitHub entry document.
- [../.env.example](../.env.example): full configuration example.
- [../src/server.js](../src/server.js): HTTP portal and webhook server.
- [../src/services/opnsense.js](../src/services/opnsense.js): OPNsense API, Kea and shaper integration.
- [../src/services/opnsenseTemplate.js](../src/services/opnsenseTemplate.js): OPNsense captive portal template ZIP generation.
- [../src/services/law5651.js](../src/services/law5651.js): 5651/syslog and timestamping.
- [../src/services/nvi.js](../src/services/nvi.js): NVİ KPSv2 client.
- [../src/services/whatsapp.js](../src/services/whatsapp.js): WhatsApp Cloud API client.
- [../opnsense-template/index.html](../opnsense-template/index.html): OPNsense captive portal redirect template example.
