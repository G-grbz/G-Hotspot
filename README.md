# G-Hotspot

G-Hotspot is a lightweight Node.js captive portal companion for OPNsense. It provides voucher, e-mail OTP, WhatsApp OTP, SMS OTP, Telegram OTP, T.C. identity verification and admin approval flows, then opens the verified client session through the OPNsense Captive Portal Session API.

Türkçe: G-Hotspot, OPNsense captive portal için hazırlanmış hafif bir Node.js doğrulama servisidir. Voucher, e-posta OTP, WhatsApp OTP, SMS OTP, Telegram OTP, T.C. kimlik doğrulama ve yönetici onayı akışlarını sunar; doğrulanan istemciye OPNsense Captive Portal Session API üzerinden internet erişimi açar.

---

## Screenshots

### Portal / Login Page

![G-Hotspot Portal Login Page](docs/images/portal-login.png)

### Admin Dashboard

![G-Hotspot Admin Dashboard](docs/images/admin-dashboard.png)

---

## Documentation

* [Türkçe ayrıntılı dokümantasyon](docs/README.tr.md)
* [English detailed documentation](docs/README.en.md)
* [Docs index](docs/README.md)

## Current Status

* Version: `1.0.0`
* Runtime: Node.js `>=24.0.0`
* Database: built-in `node:sqlite`
* License: AGPL-3.0-only
* Default gateway mode: `mock`
* Production gateway mode: `opnsense-api`

Important validation note:

* 5651/syslog logging and the KamuSM RFC3161 timestamp flow have been live-tested with a real KamuSM account. Generic RFC3161 and API-key TSA providers commonly used for US/EU deployments, T.C. identity verification through NVİ KPSv2 and WhatsApp Cloud API delivery are implemented and covered by local tests/mocks where applicable, but they have not been live-tested against real external production services in this repository state. Validate these flows in your own OPNsense, Kea DHCP, KamuSM or selected TSA provider, NVİ and Meta environments before using them for production or legal evidence processes. Before relying on the 5651/syslog output, generate a sample evidence package (`.log`, `.log.tsq`, `.log.tsr`) and have it reviewed by the legal, privacy, security and evidence-retention teams or advisors responsible for your jurisdiction and organization.

Önemli doğrulama notu:

* 5651/syslog loglama ve KamuSM RFC3161 zaman damgası akışı gerçek KamuSM hesabıyla canlı test edilmiştir. ABD/AB dağıtımlarında yaygın kullanılan genel RFC3161 ve API-key TSA sağlayıcıları, NVİ KPSv2 ile T.C. kimlik doğrulaması ve WhatsApp Cloud API gönderimi kod seviyesinde uygulanmıştır ve uygun yerlerde yerel test/mock kapsamı vardır; ancak bu repo durumunda gerçek dış üretim servisleriyle canlı test edilmemiştir. Üretim veya hukuki delil süreçlerinden önce kendi OPNsense, Kea DHCP, KamuSM veya seçtiğiniz TSA sağlayıcı, NVİ ve Meta ortamınızda doğrulama yapın. 5651/syslog çıktısına güvenmeden önce örnek bir delil paketi (`.log`, `.log.tsq`, `.log.tsr`) üretin ve bulunduğunuz ülke ile kurumunuzdan sorumlu hukuk, KVKK/gizlilik, bilgi güvenliği ve delil saklama ekiplerine veya danışmanlarına inceletin.

## Feature Summary

* Voucher access with one-time or multi-use codes.
* E-mail OTP with SMTP.
* WhatsApp OTP through Meta WhatsApp Cloud API authentication templates.
* SMS OTP through Netgsm, İleti Merkezi, Twilio or a custom HTTP provider.
* Telegram OTP using a Telegram bot contact-share flow.
* T.C. identity verification through NVİ KPSv2, optionally followed by SMS OTP.
* Admin approval workflow for guest access requests.
* Turkish and English portal/admin UI.
* Admin dashboard, voucher management, session list, CSV exports and activity logs.
* OPNsense Captive Portal Session API integration.
* OPNsense Kea DHCP lease/reservation synchronization.
* OPNsense Traffic Shaper based per-user speed limits and quota profiles.
* 5651/syslog-oriented tamper-evident logging with hash chain and optional KamuSM RFC3161 daily timestamp files.
* System notifications by e-mail, SMS and Telegram.

## Quick Start

```bash
npm start
```

Portal:

```text
http://localhost:8080
```

Admin panel:

```text
http://SERVER_IP:8080/admin
```

Run checks:

```bash
npm test
npm run check
curl http://SERVER_IP:8080/health
```

`npm start` creates `data/system.db` on first run and opens the web installer at
`/install` until the administrator account, application secret and gateway mode
are configured. Existing `.env` files are not overwritten and are imported into
`system.db` for backward compatibility. After import, runtime configuration is
read from `system.db`; `.env` is not loaded as a live settings source.

## Production Notes

* Keep `data/system.db` private. It contains `APP_SECRET`, admin password, OPNsense API credentials and provider secrets.
* Use `GATEWAY_MODE=mock` only for development. It does not open real internet access.
* Use `GATEWAY_MODE=opnsense-api` with an OPNsense API user that has only the required effective privileges.
* Kea DHCP is required for the managed DHCP lease/reservation synchronization feature. Disable `OPNSENSE_KEA_LEASE_SYNC_ENABLED` if your OPNsense DHCP setup is not Kea-compatible.
* Put the portal and provider webhooks behind HTTPS in production.
* Do not treat the 5651/syslog feature as a legal compliance guarantee without live testing and legal/process review.

## License and Attribution

G-Hotspot is licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`). Keep the `LICENSE` and `NOTICE` files with all copies and
modified versions. Original project attribution: Gökhan GÜRBÜZ, GitHub
username `G-grbz`, https://github.com/G-grbz. The portal, administration
panel and `/api/v1/about` endpoint expose the project attribution for
operators and users.

## Türkçe Kısa Kurulum

```bash
npm start
```

İlk `npm start` çalıştırması `data/system.db` dosyasını hazırlar. Tarayıcıdan
`http://SERVER_IP:8080/install` adresini açıp mock veya OPNsense API modunu,
yönetici kullanıcı adını, yönetici şifresini ve uygulama anahtarını belirleyin.
Mevcut `.env` dosyaları geriye uyumluluk için ilk açılışta `system.db` içine
aktarılır. Importtan sonra çalışma zamanı ayarları `system.db` üzerinden
okunur; `.env` canlı ayar kaynağı olarak yüklenmez.

Ayrıntılı üretim kurulumu, OPNsense API izinleri, Kea DHCP, 5651/syslog, NVİ ve WhatsApp ayarları için [Türkçe dokümantasyona](docs/README.tr.md) bakın.

## English Quick Setup

```bash
npm start
```

The first `npm start` prepares `data/system.db`. Open
`http://SERVER_IP:8080/install` and choose mock or OPNsense API mode, then set
the administrator username, administrator password and application secret.
Existing `.env` files are imported into `system.db` for backward compatibility.
After import, runtime configuration is read from `system.db`; `.env` is not
loaded as a live settings source.

For production setup, OPNsense API permissions, Kea DHCP, 5651/syslog, NVİ and WhatsApp configuration, read the [English documentation](docs/README.en.md).
