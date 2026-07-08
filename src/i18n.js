import { normalizeLanguage as normalizeSupportedLanguage } from './lib/languages.js';

const messages = {
  en: {
    emailSubject: '{appName} verification code',
    emailText: 'Your {appName} internet access verification code is: {code}\n\nThis code is valid for {minutes} minutes.',
    emailIntro: 'Your internet access verification code:',
    codeValidity: 'This code is valid for {minutes} minutes.',
    telegramContactRequest: '{appName}: Tap the button below to share the phone number linked to this Telegram account. Entering the phone number manually will not trigger a verification code.',
    telegramContactButton: 'Share my Telegram phone number',
    telegramOtpText: '{appName} Telegram verification code: {code}. This code is valid for {minutes} minutes. Enter it in the Telegram verification code field on the hotspot portal.',
    telegramExpiredStartAgain: '{appName}: This verification request has expired. Please restart the process from the hotspot portal.',
    telegramStartFromPortalFirst: '{appName}: Please start the Telegram verification process from the hotspot portal first.',
    telegramDoNotTypePhone: '{appName}: Do not enter the phone number manually. Tap "Share my Telegram phone number" so Telegram can verify that the number belongs to your account.',
    telegramShareOwnPhone: '{appName}: Please share the phone number linked to your own Telegram account.',
    telegramNoPendingVerification: '{appName}: No pending hotspot verification request was found for this Telegram phone number.',
    systemNotification: '{appName} system notification',
    syslogStorageStatusFailed: 'Unable to check the syslog storage status: {error}',
    syslogStorageFull: 'Syslog storage is {usage}% full.',
    syslogStorageBlockedPortal: 'Syslog storage is {usage}% full; new verification requests cannot be processed.',
    syslogStorageRecovered: 'Syslog storage usage has returned to {usage}%.',
    syslogKamusmTimestampSucceeded: 'A KamuSM timestamp was successfully created for {file}.',
    syslogKamusmTimestampFailed: 'Failed to create a KamuSM timestamp for {file}: {error}',
    syslogTimestampSucceeded: 'A timestamp was successfully created for {file}.',
    syslogTimestampFailed: 'Failed to create a timestamp for {file}: {error}',
    systemStartupDetected: 'System startup detected.',
    opnsenseConnectionLost: 'OPNsense connection lost: {error}',
    userVerifiedNotification: '{method} user verified: {identity} ({clientIp}).',
    accessExpiredNotification: '{method} access expired: {identity} ({clientIp}).',
    adminLoginNotification: 'Administrator {adminUser} signed in from {clientIp}.',
    adminLoginFailedNotification: 'Failed administrator sign-in attempt for {adminUser} from {clientIp}: {error}'
  },

  tr: {
    emailSubject: '{appName} doğrulama kodu',
    emailText: '{appName} internet erişim doğrulama kodunuz: {code}\n\nBu kod {minutes} dakika boyunca geçerlidir.',
    emailIntro: 'İnternet erişim doğrulama kodunuz:',
    codeValidity: 'Bu kod {minutes} dakika boyunca geçerlidir.',
    telegramContactRequest: '{appName}: Bu Telegram hesabına bağlı telefon numarasını paylaşmak için aşağıdaki butona dokunun. Telefon numarasını elle girmeniz durumunda doğrulama kodu gönderilmez.',
    telegramContactButton: 'Telegram telefon numaramı paylaş',
    telegramOtpText: '{appName} Telegram doğrulama kodunuz: {code}. Bu kod {minutes} dakika boyunca geçerlidir. Kodu hotspot portalındaki Telegram doğrulama kodu alanına girin.',
    telegramExpiredStartAgain: '{appName}: Bu doğrulama isteğinin süresi doldu. Lütfen işlemi hotspot portalından yeniden başlatın.',
    telegramStartFromPortalFirst: '{appName}: Lütfen Telegram doğrulama işlemini önce hotspot portalından başlatın.',
    telegramDoNotTypePhone: '{appName}: Telefon numaranızı elle girmeyin. Telegram\'ın numaranın hesabınıza ait olduğunu doğrulayabilmesi için "Telegram telefon numaramı paylaş" butonuna dokunun.',
    telegramShareOwnPhone: '{appName}: Lütfen kendi Telegram hesabınıza bağlı telefon numarasını paylaşın.',
    telegramNoPendingVerification: '{appName}: Bu Telegram telefon numarasıyla eşleşen bekleyen bir hotspot doğrulama isteği bulunamadı.',
    systemNotification: '{appName} sistem bildirimi',
    syslogStorageStatusFailed: 'Syslog depolama durumu kontrol edilemedi: {error}',
    syslogStorageFull: 'Syslog depolama alanı %{usage} oranında dolu.',
    syslogStorageBlockedPortal: 'Syslog depolama alanı %{usage} oranında dolu; yeni doğrulama işlemleri yapılamaz.',
    syslogStorageRecovered: 'Syslog depolama kullanımı %{usage} seviyesine geriledi.',
    syslogKamusmTimestampSucceeded: '{file} için KamuSM zaman damgası başarıyla oluşturuldu.',
    syslogKamusmTimestampFailed: '{file} için KamuSM zaman damgası oluşturulamadı: {error}',
    syslogTimestampSucceeded: '{file} için zaman damgası başarıyla oluşturuldu.',
    syslogTimestampFailed: '{file} için zaman damgası oluşturulamadı: {error}',
    systemStartupDetected: 'Sistem başlangıcı algılandı.',
    opnsenseConnectionLost: 'OPNsense bağlantısı kesildi: {error}',
    userVerifiedNotification: '{method} kullanıcısı doğrulandı: {identity} ({clientIp}).',
    accessExpiredNotification: '{method} erişim süresi doldu: {identity} ({clientIp}).',
    adminLoginNotification: '{adminUser} yöneticisi {clientIp} adresinden oturum açtı.',
    adminLoginFailedNotification: '{adminUser} yöneticisi için {clientIp} adresinden başarısız giriş denemesi: {error}'
  }
};

export function normalizeLanguage(value, fallback = 'en') {
  return normalizeSupportedLanguage(value, fallback);
}

export function requestLanguage(request, value, fallback = 'en') {
  return normalizeLanguage(value || request.headers['accept-language'], fallback);
}

export function translate(language, key, variables = {}) {
  const template = messages[normalizeLanguage(language)]?.[key] || messages.en[key] || key;
  return template.replace(/\{(\w+)\}/g, (match, name) =>
    Object.hasOwn(variables, name) ? String(variables[name]) : match
  );
}
