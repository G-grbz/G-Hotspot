# G-Hotspot Türkçe Dokümantasyon

G-Hotspot, OPNsense Captive Portal için Node.js ile yazılmış bir doğrulama ve oturum yönetimi servisidir. Kullanıcı doğrulamasını G-Hotspot yapar, internet erişimini ise OPNsense Captive Portal Session API üzerinden açar.

Bu doküman GitHub için teknik kurulum, üretim notları, OPNsense API yetkileri, Kea DHCP, 5651/syslog, NVİ ve WhatsApp ayrıntılarını içerir.

## İçindekiler

- [Durum ve canlı test notu](#durum-ve-canlı-test-notu)
- [Özellikler](#özellikler)
- [Gereksinimler](#gereksinimler)
- [Hızlı başlangıç](#hızlı-başlangıç)
- [Temel yapılandırma](#temel-yapılandırma)
- [Yönetim paneli](#yönetim-paneli)
- [Doğrulama yöntemleri](#doğrulama-yöntemleri)
- [OPNsense üretim kurulumu](#opnsense-üretim-kurulumu)
- [OPNsense API kullanıcısı ve gerekli izinler](#opnsense-api-kullanıcısı-ve-gerekli-izinler)
- [Kea DHCP entegrasyonu](#kea-dhcp-entegrasyonu)
- [Traffic Shaper, hız limiti ve kota](#traffic-shaper-hız-limiti-ve-kota)
- [5651 / Syslog delil zinciri](#5651--syslog-delil-zinciri)
- [Bildirimler](#bildirimler)
- [Güvenlik ve gizlilik](#güvenlik-ve-gizlilik)
- [Test ve sorun giderme](#test-ve-sorun-giderme)

## Durum ve canlı test notu

Bu repodaki mevcut durum için net sınırlar:

- Uygulama sürümü: `1.1.0`
- Node.js gereksinimi: `>=24.0.0`
- Veritabanı: Node.js yerleşik `node:sqlite`
- Varsayılan gateway modu: `mock`
- Üretim gateway modu: `opnsense-api`
- Lisans: G-Hotspot Noncommercial Source-Available License 1.0
- Harici runtime npm bağımlılığı yoktur.

Canlı test durumu:

- 5651/syslog loglama ve KamuSM RFC3161 zaman damgası akışı gerçek KamuSM hesabıyla canlı test edildi.
- ABD/AB dağıtımlarında yaygın kullanılan genel RFC3161 ve API-key TSA sağlayıcıları gerçek sağlayıcı hesaplarıyla canlı doğrulanmadı.
- T.C. kimlik doğrulama akışı gerçek NVİ KPSv2 hesabıyla canlı doğrulanmadı.
- WhatsApp OTP akışı gerçek Meta WhatsApp Cloud API üretim hesabı ve onaylı şablonla canlı doğrulanmadı.

Bu nedenle bu özellikler üretimde kullanılmadan önce kendi ortamınızda test edilmelidir. Özellikle 5651/syslog çıktıları hukuki delil süreci için tek başına garanti olarak sunulmamalıdır. Örnek bir delil paketi (`.log`, `.log.tsq`, `.log.tsr`) üretip bulunduğunuz ülke ve kurumunuz için geçerli hukuk, KVKK/gizlilik, bilgi güvenliği ve delil saklama süreçlerinden sorumlu ekip veya danışmanlarla doğrulayın.

## Özellikler

- Tek kullanımlık veya çok kullanımlık voucher kodları.
- SMTP ile e-posta OTP.
- Meta WhatsApp Cloud API ile WhatsApp OTP.
- Netgsm, İleti Merkezi, Twilio veya özel HTTP servis ile SMS OTP.
- Telegram bot ile Telegram OTP. Bot telefon numarasına doğrudan mesaj atamaz; kullanıcı botu açıp kendi Telegram iletişimini paylaşır.
- NVİ KPSv2 ile T.C. kimlik numarası, ad, soyad ve doğum yılı doğrulaması.
- NVİ doğrulamasından sonra isteğe bağlı SMS OTP.
- Yönetici onayı ile manuel erişim açma.
- Türkçe ve İngilizce portal/yönetim paneli.
- Yönetim panelinden ayar yönetimi.
- Voucher üretimi, listeleme, devre dışı bırakma ve CSV dışa aktarma.
- Aktif oturum, doğrulama geçmişi, trafik sayaçları ve CSV raporları.
- OPNsense Captive Portal Session API entegrasyonu.
- OPNsense Kea DHCPv4 lease/reservation senkronizasyonu.
- OPNsense Traffic Shaper ile kişi başı indirme/yükleme hız limiti.
- Yöntem bazlı günlük/haftalık/aylık kota profilleri.
- 5651/syslog odaklı hash zincirli, değişiklik fark ettiren loglama.
- Tamamlanan günler için `.log`, `.log.tsq` ve `.log.tsr` dosyaları.
- Saat, NTP, timezone, servis başlangıç/duruş gibi bütünlük olayları.
- E-posta, SMS ve Telegram sistem bildirimleri.

## Gereksinimler

Geliştirme veya test:

- Node.js 24 veya daha yeni bir sürüm.
- Linux, macOS veya Node.js 24 destekleyen başka bir ortam.
- OPNsense olmadan test için `GATEWAY_MODE=mock`.

Üretim:

- OPNsense Captive Portal.
- OPNsense API anahtarı olan ayrı ve kısıtlı bir API kullanıcısı.
- Kea DHCPv4. Yönetilen DHCP lease/reservation senkronizasyonu Kea DHCP ile çalışır.
- G-Hotspot makinesi için sabit IP.
- Misafir ağından G-Hotspot IP ve portuna captive portal öncesi erişim izni.
- Üretimde HTTPS reverse proxy veya doğrudan geçerli TLS sertifikası.
- Syslog kullanılacaksa OPNsense remote syslog yönlendirmesi.
- Syslog zaman damgası kullanılacaksa TSA kullanıcı adı/API key ve dış ağa erişim.
- NVİ kullanılacaksa KPSv2 kullanıcı adı/şifre.
- WhatsApp kullanılacaksa Meta WhatsApp Business, onaylı Authentication template, Phone Number ID ve access token.

Node.js kontrolü:

```bash
node --version
```

Manjaro örneği:

```bash
sudo pacman -S nodejs npm
```

## Hızlı başlangıç

```bash
npm start
```

Portal:

```text
http://localhost:8080
```

Yönetim paneli:

```text
http://localhost:8080/admin
```

Sağlık kontrolü:

```bash
curl http://127.0.0.1:8080/health
```

`npm start` ilk çalıştırmada `data/system.db` dosyasını oluşturur ve yönetici
hesabı, uygulama anahtarı ve ağ geçidi modu ayarlanana kadar `/install`
sayfasını sunar. `.env` zaten varsa üzerine yazılmaz ve değerleri geriye
uyumluluk için `system.db` içine aktarılır. Importtan sonra çalışma zamanı
ayarları `system.db` üzerinden okunur; `.env` canlı ayar kaynağı olarak
yüklenmez.

## Temel yapılandırma

Ana ayarlar `data/system.db` içindedir ve kurulum ekranı veya yönetim panelinden
değiştirilebilir. [`.env.example`](../.env.example) dosyası eski kurulumlar ve
içe aktarma için referans olarak tutulur.

Minimum uygulama ayarları:

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

`HOST` veya `PUBLIC_BASE_URL` boş bırakılırsa G-Hotspot sunucunun IPv4
adresini otomatik tespit eder. `PORT` boş bırakılırsa `8080` kullanılır.

Yönetici:

```dotenv
ADMIN_USERNAME=admin
ADMIN_PASSWORD=uzun-ve-benzersiz-bir-parola
ADMIN_SESSION_HOURS=12
```

Gateway:

```dotenv
GATEWAY_MODE=mock
```

`mock` mod, OPNsense'e dokunmadan portal akışlarını test eder. Gerçek internet erişimi açmaz.

OPNsense için:

```dotenv
GATEWAY_MODE=opnsense-api
OPNSENSE_BASE_URL=https://192.168.1.1
OPNSENSE_ZONE_ID=0
OPNSENSE_API_KEY=api-key
OPNSENSE_API_SECRET=api-secret
OPNSENSE_TLS_REJECT_UNAUTHORIZED=true
```

Süre birimleri:

- Retry interval için: `minutes`, `hours`, `days`, `months`, `years`, `unlimited`
- Yeniden doğrulama ve erişim süresi için: `hours`, `days`, `months`, `years`, `unlimited`

Örnek:

```dotenv
EMAIL_IP_RETRY_INTERVAL_VALUE=2
EMAIL_IP_RETRY_INTERVAL_UNIT=hours
EMAIL_REVERIFY_DURATION_VALUE=24
EMAIL_REVERIFY_DURATION_UNIT=hours
EMAIL_ACCESS_DURATION_VALUE=24
EMAIL_ACCESS_DURATION_UNIT=hours
```

Bu örnekte aynı IP iki saatte bir yeni e-posta kodu isteyebilir. Aynı e-posta adresi 24 saat içinde tekrar doğrulanamaz. Başarılı doğrulamada internet 24 saat açık kalır.

## Yönetim paneli

Yönetim paneli:

```text
http://HOST:PORT/admin
```

Panelden yönetilebilen ana alanlar:

- Dashboard: aktif oturum, trafik, voucher, doğrulama özetleri.
- Sessions: IP, MAC, yöntem, başlangıç/bitiş, trafik sayaçları.
- Verifications: OTP ve doğrulama geçmişi.
- Admin approval: bekleyen kullanıcı onay istekleri.
- Vouchers: tekli veya toplu voucher üretimi.
- Logs: birleşik aktivite kayıtları.
- Syslog/5651: hash zinciri, storage durumu, export ve timestamp durumu.
- Settings: uygulama, OPNsense, syslog, e-posta, WhatsApp, SMS, Telegram, NVİ ve bildirim ayarları.

Gizli alanlar tarayıcıya geri gönderilmez. Secret alanları boş bırakılırsa mevcut değer korunur.

Şu ayarlar süreç seviyesindedir ve değişiklikten sonra yeniden başlatma gerekir:

- `HOST`
- `PORT`
- `DATABASE_PATH`
- `APP_SECRET`

## Doğrulama yöntemleri

### Voucher

Voucher kodları veritabanında açık metin tutulmaz. Kodun açık hali yalnızca üretildiği anda görünür.

```bash
npm run voucher -- create --count=5 --minutes=720 --uses=1 --label=Misafir
npm run voucher -- create --count=1 --minutes=120 --expires-days=7
npm run voucher -- list
npm run voucher -- disable --id=VOUCHER_UUID
```

Portal tarafında voucher denemeleri IP başına 15 dakikada 10 deneme ile sınırlandırılır.

### E-posta OTP

```dotenv
EMAIL_ENABLED=true
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_STARTTLS=true
SMTP_USER=hotspot@example.com
SMTP_PASS=uygulama-parolasi
```

`SMTP_HOST` veya `SMTP_USER` boşsa e-posta yöntemi devre dışı kalır. Gönderen adresi güvenlik için `SMTP_USER` değerinden alınır.

Kod geçerlilik süresi: 5 dakika. Yanlış kod deneme limiti: 5.

### SMS OTP

Desteklenen sağlayıcılar:

- `netgsm`
- `iletimerkezi`
- `twilio`
- `custom`

Temel ayarlar:

```dotenv
SMS_ENABLED=true
SMS_PROVIDER=netgsm
SMS_SENDER=GHotspot
SMS_OTP_MINUTES=5
SMS_MESSAGE_TEMPLATE={appName} access code: {code}. The code is valid for {minutes} minutes.
```

Özel HTTP servis değişkenleri:

```text
{phone} {code} {message} {sender} {appName} {minutes}
```

Özel servis örneği:

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

WhatsApp gönderimi Meta WhatsApp Cloud API ile yapılır. Kullanıcı WhatsApp'ta aldığı 6 haneli kodu portala girer.

Canlı test durumu: gerçek Meta üretim hesabı ve onaylı şablonla canlı test edilmedi. Üretime almadan önce kendi Meta uygulamanızda test edin.

Meta tarafında:

1. WhatsApp Manager içinde `Authentication` kategorisinde OTP şablonu oluşturun.
2. Şablon adını örneğin `hotspot_otp` yapın.
3. Portal dilinizle uyumlu template language seçin.
4. Kopyalama/kod düğmesi kullanıyorsanız `WHATSAPP_TEMPLATE_BUTTON=true` bırakın.
5. Şablonun Meta tarafından onaylanmasını bekleyin.
6. API Setup ekranından `Phone Number ID` alın.
7. Üretimde geçici token yerine `whatsapp_business_messaging` yetkili kalıcı System User access token kullanın.

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

Şu üç alan boşsa WhatsApp yöntemi kapalı kabul edilir:

```text
WHATSAPP_PHONE_NUMBER_ID
WHATSAPP_ACCESS_TOKEN
WHATSAPP_TEMPLATE_NAME
```

Meta test numarası kullanıyorsanız alıcı numarayı Meta API Setup ekranındaki izin verilen alıcı listesine ekleyin.

WhatsApp kod geçerlilik süresi: 10 dakika. Yanlış kod deneme limiti: 5.

Webhook isteğe bağlıdır. Kod doğrulaması webhook'a bağlı değildir. Teslim/okundu durumları için:

```dotenv
WHATSAPP_VERIFY_TOKEN=uzun-rastgele-bir-deger
META_APP_SECRET=meta-uygulama-secret
PUBLIC_BASE_URL=https://hotspot.example.com
```

Webhook adresi:

```text
https://hotspot.example.com/webhooks/whatsapp
```

`META_APP_SECRET` ayarlanırsa gelen `X-Hub-Signature-256` imzası doğrulanır.

### Telegram OTP

Telegram botlar telefon numarasına doğrudan mesaj atamaz. Akış şu şekildedir:

1. Kullanıcı portalda Telegram doğrulamasını seçer.
2. Portal kullanıcıyı Telegram botuna yönlendirir.
3. Kullanıcı botta kendi Telegram iletişimini paylaşır.
4. Bot OTP gönderir.
5. Kullanıcı kodu portala girer.

```dotenv
TELEGRAM_ENABLED=true
TELEGRAM_BOT_USERNAME=GHotspotBot
TELEGRAM_MODE=webhook
TELEGRAM_BOT_TOKEN=bot-token
TELEGRAM_WEBHOOK_SECRET=uzun-rastgele-deger
TELEGRAM_OTP_MINUTES=5
```

`TELEGRAM_MODE=polling` yerel testlerde kullanılabilir. Üretimde webhook önerilir.

### T.C. kimlik doğrulaması, NVİ KPSv2

NVİ doğrulaması kullanıcının T.C. kimlik numarası, ad, soyad ve doğum yılı bilgisini KPSv2 ile doğrular.

Canlı test durumu: gerçek NVİ KPSv2 hesabıyla canlı test edilmedi. Üretime almadan önce NVİ hesabınızla test edin.

Önemli noktalar:

- Eski public `KPSPublic.asmx` servisi kullanılmaz.
- KPSv2 erişimi için NVİ Genel Müdürlüğü'nden kullanıcı adı/şifre alınmalıdır.
- `NVI_SEND_SMS_CODE=false` ise NVİ sorgusu başarılı olduğunda erişim doğrudan açılır.
- `NVI_SEND_SMS_CODE=true` ise NVİ başarılı olduktan sonra kullanıcının telefonuna SMS OTP gönderilir.
- SMS OTP'li NVİ akışı için `SMS_ENABLED=true` ve SMS sağlayıcı ayarları gerekir.

```dotenv
NVI_ENABLED=true
NVI_SEND_SMS_CODE=false
NVI_ACCESS_DURATION_VALUE=24
NVI_ACCESS_DURATION_UNIT=hours
NVI_USERNAME=kps-kullanici-adi
NVI_PASSWORD=kps-sifre
```

SMS kodlu NVİ:

```dotenv
NVI_SEND_SMS_CODE=true
SMS_ENABLED=true
SMS_PROVIDER=netgsm
```

Yanlış SMS kod deneme limiti: 5.

### Yönetici onayı

Yönetici onayı, kullanıcının ad soyad ve isteğe bağlı iletişim bilgisiyle erişim talebi oluşturmasını sağlar. Yönetici panelden onaylarsa erişim açılır.

```dotenv
ADMIN_APPROVAL_ENABLED=true
ADMIN_APPROVAL_REQUEST_TTL_MINUTES=1440
ADMIN_APPROVAL_ACCESS_DURATION_VALUE=24
ADMIN_APPROVAL_ACCESS_DURATION_UNIT=hours
ADMIN_APPROVAL_APPROVE_TEXT=Your internet access request was approved.
ADMIN_APPROVAL_REJECT_TEXT=Your internet access request was rejected.
```

Onay sonucu e-posta veya SMS ile kullanıcıya bildirilebilir.

## OPNsense üretim kurulumu

Önerilen yerleşim:

```text
Guest VLAN/WiFi
  -> OPNsense Captive Portal
  -> G-Hotspot HTTP/HTTPS portal
  -> OPNsense Captive Portal Session API
```

OPNsense tarafında yapılacaklar:

1. Misafir VLAN veya WiFi için Captive Portal zone oluşturun.
2. G-Hotspot makinesine sabit IP verin.
3. Captive Portal allowed addresses/listesine G-Hotspot IP ve portunu ekleyin.
4. Misafirler doğrulama öncesinde G-Hotspot'a ulaşabilmelidir.
5. OPNsense API için ayrı, düşük yetkili kullanıcı oluşturun.
6. API key/secret üretin.
7. `/install` ekranında veya yönetim paneli ayarlarında `opnsense-api` modunu seçin.
8. Kea DHCP kullanın veya Kea sync'i kapatın.

OPNsense captive portal şablonu:

- Admin panelde `Template oluştur` sekmesini açın.
- HTML dili, sayfa başlığı, yönlendirme URL/portu ve ekranda görünen metinleri doldurun.
- `Download ZIP` ile oluşan ZIP dosyasını indirin.
- ZIP dosyasını OPNsense captive portal template alanına yükleyin.

Tek zone:

```dotenv
OPNSENSE_ZONE_ID=0
```

Birden fazla zone:

```dotenv
OPNSENSE_ZONE_MAP="172.16.2.0/24=0; 172.16.3.0/24=1"
```

Eşleşmeyen istemci IP'leri `OPNSENSE_ZONE_ID` değerine düşer.

Reverse proxy kullanıyorsanız:

```dotenv
TRUST_PROXY=true
PUBLIC_BASE_URL=https://hotspot.example.com
```

`TRUST_PROXY=true`, `X-Forwarded-For` başlığını güvenilir kabul eder. G-Hotspot doğrudan internete açıksa etkinleştirmeyin.

Self-signed OPNsense sertifikasıyla ilk test:

```dotenv
OPNSENSE_TLS_REJECT_UNAUTHORIZED=false
```

Kalıcı kurulumda geçerli sertifika önerilir.

## OPNsense API kullanıcısı ve gerekli izinler

OPNsense API kullanıcısına tam yönetici yetkisi vermeyin. Ayrı kullanıcı açın, yalnızca kullanılan endpoint'lerin effective privilege izinlerini verin.

OPNsense sürümüne göre menü ve privilege isimleri değişebilir. Kontrol edilecek yer genellikle:

```text
System -> Access -> Users -> Edit user -> Effective Privileges
```

G-Hotspot tarafından kullanılan API alanları:

| Özellik                                       | Endpoint örnekleri                                                                        | OPNsense `Effective Privileges` alanında seçilecek izin |
| --------------------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Captive portal erişim açma                    | `POST /api/captiveportal/session/connect/{zoneId}`                                        | **Services: Captive Portal**                            |
| Captive portal oturum listeleme               | `GET /api/captiveportal/session/list/{zoneId}`                                            | **Services: Captive Portal**                            |
| Captive portal oturum kesme                   | `POST /api/captiveportal/session/disconnect/{zoneId}`                                     | **Services: Captive Portal**                            |
| ARP tablosunu okuma                           | `GET /api/diagnostics/interface/get_arp`                                                  | **Diagnostics: ARP Table**                              |
| DHCP lease okuma                              | `/api/kea/leases4/search`, `/api/kea/leases/search` ve fallback DHCPv4 lease endpointleri | **Services: DHCP: Kea (v4)**                            |
| Kea subnet, option ve reservation okuma       | `/api/kea/dhcpv4/searchSubnet`, `searchOption`, `searchReservation`                       | **Services: DHCP: Kea (v4)**                            |
| Kea reservation yazma                         | `addReservation`, `setReservation`, `delReservation`                                      | **Services: DHCP: Kea (v4)**                            |
| Kea option yazma                              | `addOption`                                                                               | **Services: DHCP: Kea (v4)**                            |
| Kea servisini yeniden yapılandırma            | `/api/kea/service/reconfigure`                                                            | **Services: DHCP: Kea (v4)**                            |
| Traffic Shaper pipe ve kural okuma            | `/api/trafficshaper/settings/search_pipes`, `/api/trafficshaper/settings/search_rules`    | **Firewall: Shaper**                                    |
| Traffic Shaper pipe ve kural yazma            | `add_pipe`, `set_pipe`, `del_pipe`, `add_rule`, `set_rule`, `del_rule`                    | **Firewall: Shaper**                                    |
| Traffic Shaper servisini yeniden yapılandırma | `/api/trafficshaper/service/reconfigure`                                                  | **Firewall: Shaper**                                    |
| Ağ ve arayüz keşfi                            | `/api/interfaces/overview/export`, `/api/interfaces/overview/search`                      | **Status: Interfaces**                                  |
| Ağ bağlantısı ve port teşhisi                 | İlgili Netstat API işlemleri                                                              | **Diagnostics: Netstat**                                |

## OPNsense 26.1.11 versiyonu için seçilmesi gereken yetkiler

OPNsense üzerinde G-Hotspot için oluşturulan API kullanıcısının `Effective Privileges` alanında aşağıdaki izinler seçilmelidir:

* **Diagnostics: ARP Table**
* **Diagnostics: Netstat**
* **Firewall: Shaper**
* **Services: Captive Portal**
* **Services: DHCP: Kea (v4)**
* **Status: Interfaces**

Özellikle kullanıcı veya cihaz bazlı hız limiti kullanılacaksa **Firewall: Shaper** yetkisi zorunludur. Bu yetki bulunmadığında OPNsense genellikle `HTTP 403 Forbidden` yanıtı döndürür ve hız limiti kuralları oluşturulamaz ya da güncellenemez.

Kea DHCP senkronizasyonu etkinse **Services: DHCP: Kea (v4)** yetkisi gerekir. Bu izin, DHCP lease kayıtlarının okunması, reservation ve option işlemlerinin yapılması ve Kea servisinin yeniden yapılandırılması için kullanılır.

Kea yetkisi bulunmadığında captive portal üzerinden internet erişimi çoğu durumda açılmaya devam eder. Ancak DHCP reservation oluşturma, lease süresi senkronizasyonu ve ilgili DHCP işlemleri atlanır; durum G-Hotspot loglarına uyarı olarak yazılır.

**Diagnostics: ARP Table** veya Kea DHCP lease okuma yetkisi bulunmadığında IP–MAC eşleştirmesi ve cihaz sahipliği koruması eksik çalışabilir. Bu durumda G-Hotspot, bağlanan cihazın MAC adresini güvenilir şekilde doğrulayamayabilir.

**Status: Interfaces** ve **Diagnostics: Netstat**  yetkileri; ağ arayüzlerinin keşfedilmesi, bağlantı durumunun kontrol edilmesi ve gateway kaynaklı sorunların teşhis edilmesi için kullanılır.

## Kea DHCP entegrasyonu

G-Hotspot, DHCP lease süresini erişim süresiyle uyumlu tutmak için OPNsense Kea DHCPv4 rezervasyonları oluşturabilir.

Varsayılan:

```dotenv
OPNSENSE_KEA_LEASE_SYNC_ENABLED=true
```

Bu özellik şunları yapar:

- Doğrulanan istemcinin IP ve MAC adresini OPNsense ARP/DHCP lease bilgilerinden bulur.
- İstemci IP'sinin hangi Kea DHCPv4 subnet içinde olduğunu arar.
- Erişim süresine karşılık gelen DHCP option 51 lease-time option'ı oluşturur veya mevcut olanı kullanır.
- `G-Hotspot access <authorizationId>` açıklamasıyla Kea DHCP reservation oluşturur/günceller.
- Reservation değiştiyse Kea servisini reconfigure eder.
- Oturum kapatıldığında yönetilen reservation'ı silebilir.

Sınırlar:

- Bu entegrasyon Kea DHCPv4 içindir.
- Eski ISC DHCP reservation yönetimi hedeflenmez.
- İstemci IP'si Kea subnet içinde değilse `No OPNsense Kea DHCPv4 subnet contains <ip>` hatası alınır.
- İstemci MAC adresi OPNsense ARP/DHCP lease kaynaklarından bulunamazsa sync atlanabilir.

Kea kullanmıyorsanız veya API yetkisi vermek istemiyorsanız:

```dotenv
OPNSENSE_KEA_LEASE_SYNC_ENABLED=false
```

## Traffic Shaper, hız limiti ve kota

Global eski ayarlar:

```dotenv
DOWNLOAD_SPEED_LIMIT_MBPS=0
UPLOAD_SPEED_LIMIT_MBPS=0
OPNSENSE_SHAPER_INTERFACE=wan
OPNSENSE_SHAPER_NETWORK=any
```

`0` sınırsız anlamına gelir.

Yöntem bazlı hız ve kota profilleri:

```dotenv
VOUCHER_DOWNLOAD_SPEED_LIMIT_MBPS=20
VOUCHER_UPLOAD_SPEED_LIMIT_MBPS=5
VOUCHER_QUOTA_PERIOD=daily
VOUCHER_DOWNLOAD_QUOTA_GB=10
VOUCHER_UPLOAD_QUOTA_GB=2
```

Desteklenen prefix'ler:

- `VOUCHER`
- `ADMIN_APPROVAL`
- `NVI`
- `EMAIL`
- `WHATSAPP`
- `TELEGRAM`
- `SMS`

Kota periyotları:

- `daily`
- `weekly`
- `monthly`

Traffic Shaper davranışı:

- Uygulama kendi yönettiği pipe/rule kayıtlarını `G-Hotspot managed ...` açıklamasıyla oluşturur.
- Download yönünde `dst-ip`, upload yönünde `src-ip` maskesi kullanılır.
- Böylece limit kişi/IP başına uygulanır.
- Değişiklikten sonra OPNsense Traffic Shaper reconfigure edilir.
- Shaper uygulanamazsa doğrulama yöntemi otomatik olarak başarısız sayılmaz; hata loglanır.

## 5651 / Syslog delil zinciri

Bu özellik 5651/syslog odaklı kayıt üretir, hash zinciri kurar ve tamamlanan günler için isteğe bağlı TSA/RFC3161 zaman damgası alır.

Canlı test durumu: KamuSM RFC3161 zaman damgası akışı gerçek KamuSM hesabıyla canlı test edildi. Genel RFC3161 ve API-key TSA modları, ABD/AB sağlayıcıları dahil, gerçek sağlayıcı hesaplarıyla canlı doğrulanmadı. Hukuki delil süreci için kullanmadan önce seçtiğiniz sağlayıcıyla canlı uçtan uca test yapın.

Hukuki sorumluluk ve uygunluk notu: Bu özellik teknik olarak hash zinciri, export ve zaman damgası dosyaları üretir; herhangi bir ülke veya sektör için hukuki yeterlilik garantisi vermez. Üretime geçmeden önce örnek `.log`, `.log.tsq` ve `.log.tsr` dosyaları oluşturun; bu paketi Türkiye, AB, ABD veya faaliyet gösterdiğiniz diğer ülke mevzuatına göre kendi hukuk biriminize, KVKK/gizlilik sorumlularınıza, bilgi güvenliği ekibinize veya delil saklama danışmanınıza inceletin.

Temel davranış:

- Her trafik kaydı önceki kaydın hash'ini içerir.
- Sistem olayları ayrı bir hash zincirinde tutulur.
- Kayıt değişirse zincir kırılır ve değişiklik fark edilebilir.
- Bu model tamper-evident çalışır; fiziksel silme veya disk müdahalesini tek başına imkansız yapmaz.
- Eski kayıtların WORM, harici imzalı arşiv veya bağımsız log sunucusuyla korunması kurumsal süreçlerinize bağlıdır.

Temel ayarlar:

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

`SYSLOG_NETWORKS` değerleri:

- `any`
- tek IP
- CIDR
- virgülle ayrılmış liste
- IPv4 başlangıç-bitiş aralığı

OPNsense tarafında firewall/filterlog kayıtlarını G-Hotspot'a remote syslog olarak gönderin. Port olarak `SYSLOG_RECEIVER_PORT` değerini kullanın.

Varsayılan port `5514` olduğu için root yetkisi gerekmez. Portu `514` yaparsanız Linux'ta root veya `CAP_NET_BIND_SERVICE` gerekir.

Kaydedilen trafik alanları:

- istemci IP
- mümkünse istemci MAC
- subscriber/authorization bilgisi
- kaynak IP/port
- hedef IP/port
- protokol
- servis tipi
- byte sayaçları
- ham kaynak JSON/satır bilgisi
- oluşturma zamanı
- önceki hash ve kayıt hash'i

### Storage guard

Syslog açıkken yeni portal oturumu verilmeden önce log depolamasının yazılabilir olduğu kontrol edilir.

```dotenv
SYSLOG_STORAGE_ALERT_PERCENT=85
SYSLOG_STORAGE_BLOCK_PERCENT=99
```

- Alert eşiği aşılırsa yönetim panelinde uyarı ve sistem olayı oluşur.
- Block eşiği aşılırsa yeni portal oturumları reddedilir.
- Mevcut oturumlar doğrudan kesilmez.

`SYSLOG_RETENTION_DAYS` politika bilgisidir. Eski kayıtların otomatik silinmesine güvenmeyin; arşiv/temizlik sürecinizi ayrıca planlayın.

### Syslog zaman damgası

```dotenv
SYSLOG_TIMESTAMP_MODE=kamusm
SYSLOG_KAMUSM_USER=kamusm-kullanici
SYSLOG_KAMUSM_PASSWORD=kamusm-sifre
SYSLOG_KAMUSM_URL=http://zd.kamusm.gov.tr
SYSLOG_KAMUSM_TIMEOUT_SECONDS=60
```

`SYSLOG_TIMESTAMP_MODE` şu değerleri alır:

- `disabled`: zaman damgası üretmez.
- `kamusm`: mevcut KamuSM davranışını korur; RFC3161 isteğini KamuSM TSA servisine HTTP Basic kullanıcı adı/şifreyle gönderir.
- `rfc3161`: ABD/AB dahil birçok uluslararası TSA sağlayıcısında kullanılan standart RFC3161 HTTP akışıdır.
- `api-key`: RFC3161 isteğini API key header'ı ile isteyen sağlayıcılar içindir.

RFC3161 örneği:

```dotenv
SYSLOG_TIMESTAMP_MODE=rfc3161
SYSLOG_TIMESTAMP_URL=https://tsa.example.com
SYSLOG_TIMESTAMP_HEADERS_JSON=
SYSLOG_TIMESTAMP_CERT_REQUEST=true
SYSLOG_TIMESTAMP_TIMEOUT_SECONDS=60
```

API key örneği:

```dotenv
SYSLOG_TIMESTAMP_MODE=api-key
SYSLOG_TIMESTAMP_API_URL=https://tsa.example.com
SYSLOG_TIMESTAMP_API_KEY=provider-api-key
SYSLOG_TIMESTAMP_API_KEY_HEADER=Authorization
SYSLOG_TIMESTAMP_API_KEY_PREFIX=Bearer
SYSLOG_TIMESTAMP_API_TIMEOUT_SECONDS=60
```

Hukuki yeterlilik ülkeye, sağlayıcının TSA sertifika/profiline ve kurum politikasına bağlıdır; bu ayarlar teknik timestamp token üretimini sağlar.

Her tamamlanan yerel gün için export dizininde örnek dosyalar:

```text
2026-06-27.log      Günlük ham log
2026-06-27.log.tsq  RFC3161 timestamp query
2026-06-27.log.tsr  Timestamp response/token
```

Uygulama `.log` dosyasının SHA-256 özetinden RFC3161 timestamp query üretir, seçili TSA servisine gönderir ve dönen token'ı `.log.tsr` olarak saklar.

OpenSSL doğrulama örneği:

```bash
openssl ts -verify \
  -queryfile 2026-06-27.log.tsq \
  -in 2026-06-27.log.tsr \
  -CAfile provider-tsa-ca.pem
```

### Saat, NTP ve servis olayları

```dotenv
SYSLOG_HEALTH_CHECK_INTERVAL_SECONDS=60
SYSLOG_CLOCK_SKEW_ALERT_SECONDS=120
SYSLOG_NTP_CHECK_ENABLED=true
```

Kaydedilen olay örnekleri:

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

NTP kontrolü için Linux sistemde `timedatectl` bulunması önerilir.
`timedatectl`, systemd veya DBus host üzerinde kullanılamıyorsa
`SYSLOG_NTP_CHECK_ENABLED=false` olarak ayarlayın.

## Bildirimler

Sistem bildirimleri e-posta, SMS ve Telegram ile gönderilebilir.

Örnek:

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

Desteklenen tekrar frekansları:

- `state-change`
- `hourly`
- `daily`
- `monthly`

Bildirim olayları:

- syslog storage uyarısı
- syslog zaman damgası başarı/hata
- sistem başlangıcı
- OPNsense erişim hatası
- kullanıcı doğrulandı
- erişim süresi bitti
- admin giriş yaptı
- başarısız admin giriş denemesi
- admin approval sonucu

## systemd örneği

Repoda [systemd/g-hotspot.service.example](../systemd/g-hotspot.service.example) dosyası vardır.

Kullanıcı servisi örneği:

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
ReadWritePaths=/home/USER/g-hotspot/data /home/USER/g-hotspot/android/app

[Install]
WantedBy=default.target
```

Kurulum:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/g-hotspot.service.example ~/.config/systemd/user/g-hotspot.service
systemctl --user daemon-reload
systemctl --user enable --now g-hotspot
journalctl --user -u g-hotspot -f
```

Sistem servisi olarak çalıştıracaksanız kullanıcı, dizin izinleri ve `ReadWritePaths` değerlerini kendi kurulumunuza göre düzenleyin. Android APK üretme özelliği için servis kullanıcısının proje dizinindeki `android/app` yoluna yazabilmesi gerekir; Gradle çalışma dosyaları sistemin geçici dizininde oluşturulur. Üretici özel debug imza anahtarını `android/app/.android` altında kalıcı tutar; sonraki APK dosyalarının kurulu uygulamayı güncelleyebilmesi için bu dizini koruyun.

## Güvenlik ve gizlilik

- `data/system.db` veya eski `.env` dosyalarını repoya koymayın.
- `APP_SECRET` en az 32 karakter, rastgele ve benzersiz olmalıdır.
- Admin parolası uzun ve benzersiz olmalıdır.
- OPNsense API kullanıcısına tam admin yetkisi vermeyin.
- Üretimde HTTPS kullanın.
- `TRUST_PROXY=true` sadece güvenilir reverse proxy arkasında kullanılmalıdır.
- `OPNSENSE_TLS_REJECT_UNAUTHORIZED=false` sadece ilk testte kullanılmalıdır.
- Meta webhook için `META_APP_SECRET` kullanın.
- Provider tokenlarını ve SMS/SMTP şifrelerini paylaşmayın.
- Doğrulama kimlikleri, IP, MAC, oturum ve log kayıtları kişisel veri içerebilir.
- KVKK, açık rıza, aydınlatma metni ve saklama süresi süreçlerini kurumunuzla doğrulayın.
- `PORTAL_TERMS_MARKDOWN`, `PORTAL_POLICY_MARKDOWN` ve `PORTAL_PRIVACY_MARKDOWN` metinlerini kendi kurum metinlerinizle değiştirin.

## Test ve kontrol

Kod kontrolleri:

```bash
npm run check
npm test
```

Sağlık kontrolü:

```bash
curl http://127.0.0.1:8080/health
```

Gateway testleri:

- Önce `GATEWAY_MODE=mock` ile portal akışını test edin.
- Sonra OPNsense test VLAN'ında `opnsense-api` moduna geçin.
- Captive portal connect/list/disconnect işlemlerini kontrol edin.
- Kea DHCP reservation oluşuyor mu kontrol edin.
- Traffic Shaper pipe/rule kayıtlarını kontrol edin.
- Syslog dosya yazımı ve storage guard davranışını test edin.
- WhatsApp ve NVİ gibi dış servisleri gerçek hesaplarla ayrıca test edin; KamuSM için kendi hesabınız/kurum ağınızda doğrulama yapın, RFC3161/API-key TSA sağlayıcılarını ise seçtiğiniz sağlayıcı hesabıyla canlı uçtan uca test edin.

## Sorun giderme

`OPNsense API returned HTTP 403`

- API kullanıcısının effective privilege izinleri eksik.
- Traffic Shaper için özellikle `Firewall: Shaper` iznini kontrol edin.

`No OPNsense Kea DHCPv4 subnet contains <ip>`

- İstemci IP'si Kea DHCPv4 subnetleri içinde değil.
- OPNsense Kea DHCP etkin olmayabilir.
- API kullanıcısının Kea subnet okuma izni eksik olabilir.

`Kea DHCP lease lifetime could not be synchronized`

- Kea API yetkileri eksik.
- İstemci MAC adresi ARP/DHCP lease kaynaklarından bulunamadı.
- `OPNSENSE_KEA_LEASE_SYNC_ENABLED=false` yaparak bu özelliği kapatabilirsiniz.

`WhatsApp Cloud API rejected the message`

- Template onaylanmamış olabilir.
- Template language yanlış olabilir.
- Phone Number ID yanlış olabilir.
- Access token yetkisi eksik veya süresi bitmiş olabilir.
- Meta test modunda alıcı numara izinli listeye eklenmemiş olabilir.

`NVI verification could not be completed`

- KPSv2 kullanıcı adı/şifre yanlış olabilir.
- NVİ servisine ağ erişimi yoktur.
- Sistem saati hatalı olabilir.
- KPSv2 hesabınız bu servis için yetkili olmayabilir.

`Syslog storage is ... full`

- `SYSLOG_EXPORT_DIR` diski doludur.
- Yeni oturumlar block eşiğinde reddedilir.
- Logları güvenli arşive taşıyıp disk alanını boşaltın.

`Timestamp failed`

- KamuSM modunda kullanıcı adı/şifre hatalı olabilir.
- RFC3161/API-key modunda TSA URL, API key veya ek header ayarları hatalı olabilir.
- `SYSLOG_KAMUSM_URL`, `SYSLOG_TIMESTAMP_URL` veya `SYSLOG_TIMESTAMP_API_URL` ağ erişimi sorunlu olabilir.
- Kurum firewall'u TSA servisine çıkışı engelliyor olabilir.
- KamuSM akışı gerçek KamuSM hesabıyla canlı test edildi; RFC3161/API-key sağlayıcıları için canlı doğrulama sağlayıcı hesabınıza bağlı olduğu için kendi hesabınızla uçtan uca test gereklidir.

## Ana dosyalar

- [../README.md](../README.md): GitHub giriş dokümanı.
- [../.env.example](../.env.example): tüm yapılandırma örneği.
- [../src/server.js](../src/server.js): HTTP portal ve webhook sunucusu.
- [../src/services/opnsense.js](../src/services/opnsense.js): OPNsense API, Kea ve shaper entegrasyonu.
- [../src/services/opnsenseTemplate.js](../src/services/opnsenseTemplate.js): OPNsense captive portal template ZIP üretimi.
- [../src/services/law5651.js](../src/services/law5651.js): 5651/syslog ve zaman damgası.
- [../src/services/nvi.js](../src/services/nvi.js): NVİ KPSv2 istemcisi.
- [../src/services/whatsapp.js](../src/services/whatsapp.js): WhatsApp Cloud API istemcisi.
- [../opnsense-template/index.html](../opnsense-template/index.html): OPNsense captive portal yönlendirme şablonu örneği.
