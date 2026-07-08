import test from 'node:test';
import assert from 'node:assert/strict';
import {
  markdownToSafeHtml, renderAdminApprovalNotificationTemplate,
  renderSystemNotificationTemplate, shouldNotifySystemEvent
} from '../src/services/notifications.js';

const event = {
  eventType: 'syslog_storage_warning_threshold_reached',
  severity: 'warning',
  message: 'Syslog storage is 64.84% full.',
  detail: {
    usagePercent: 64.84,
    alertPercent: 40,
    blockPercent: 99,
    freeBytes: 10 * 1024 * 1024
  }
};

test('system notification templates replace syslog storage placeholders', () => {
  const rendered = renderSystemNotificationTemplate([
    '{systemNotification}',
    'System notification',
    '{message}',
    'Type: {type}',
    'Severity: {warning}',
    'Storage usage: {usage}%',
    'Warning threshold: {w-threshold}%',
    'Block threshold: {b-threshold}%',
    'Free disk: {freeDisk}'
  ].join('\n'), { appName: 'G-Hotspot', defaultLanguage: 'tr' }, event);

  assert.equal(rendered, [
    'G-Hotspot sistem bildirimi',
    'System notification',
    'Syslog depolama alanı %64.84 oranında dolu.',
    'Type: syslog_storage_warning_threshold_reached',
    'Severity: warning',
    'Storage usage: 64.84%',
    'Warning threshold: 40%',
    'Block threshold: 99%',
    'Free disk: 10 MB'
  ].join('\n'));
  assert.doesNotMatch(rendered, /Directory:/u);
});

test('notification markdown keeps underscored event names readable', () => {
  const html = markdownToSafeHtml('Type: syslog_storage_warning_threshold_reached');
  assert.equal(html, '<p>Type: syslog_storage_warning_threshold_reached</p>');
});

test('system notification templates omit lines whose placeholders are empty', () => {
  const template = [
    '{systemNotification}',
    '',
    'Uygulama adi: {appName}',
    '',
    '{message}',
    '',
    'onem: {severity}',
    '',
    'ip adresi: {clientIp}',
    'mac adresi: {clientMac}',
    'Dogrulama yontemi: {method}',
    'Kullanici kimligi: {identity}',
    'Yonetici kullanici adi: {adminUser}',
    'hata: {error}',
    'erisim sonlanma tarihi: {expiresAt}'
  ].join('\n');

  const startup = renderSystemNotificationTemplate(template, {
    appName: 'G-Hotspot',
    defaultLanguage: 'tr'
  }, {
    eventType: 'system_startup',
    severity: 'info',
    detail: {}
  });

  assert.equal(startup, [
    'G-Hotspot sistem bildirimi',
    '',
    'Uygulama adi: G-Hotspot',
    '',
    'Sistem başlangıcı algılandı.',
    '',
    'onem: info'
  ].join('\n'));
  assert.doesNotMatch(startup, /mac adresi:|Dogrulama yontemi:|Yonetici kullanici adi:/u);

  const adminLogin = renderSystemNotificationTemplate(template, {
    appName: 'G-Hotspot',
    defaultLanguage: 'tr'
  }, {
    eventType: 'admin_login_succeeded',
    severity: 'info',
    detail: {
      adminUser: 'GkhnG',
      clientIp: '46.197.35.246'
    }
  });

  assert.match(adminLogin, /ip adresi: 46\.197\.35\.246/u);
  assert.match(adminLogin, /Yonetici kullanici adi: GkhnG/u);
  assert.doesNotMatch(adminLogin, /mac adresi:|Dogrulama yontemi:|hata:|erisim sonlanma tarihi:/u);

  const failedAdminLogin = renderSystemNotificationTemplate(template, {
    appName: 'G-Hotspot',
    defaultLanguage: 'tr'
  }, {
    eventType: 'admin_login_failed',
    severity: 'warning',
    detail: {
      adminUser: 'admin',
      clientIp: '46.197.35.247',
      error: 'invalid_credentials'
    }
  });

  assert.match(failedAdminLogin, /ip adresi: 46\.197\.35\.247/u);
  assert.match(failedAdminLogin, /Yonetici kullanici adi: admin/u);
  assert.match(failedAdminLogin, /hata: invalid_credentials/u);
});

test('system notification templates remove empty comma-separated placeholder segments', () => {
  const rendered = renderSystemNotificationTemplate(
    '{appName}, {message}, {clientIp}, {clientMac}, {method}, {identity}',
    { appName: 'G-Hotspot', defaultLanguage: 'tr' },
    {
      eventType: 'system_startup',
      severity: 'info',
      detail: {}
    }
  );

  assert.equal(rendered, 'G-Hotspot, Sistem başlangıcı algılandı.');
});

test('admin approval notification templates replace decision placeholders', () => {
  const rendered = renderAdminApprovalNotificationTemplate(
    '{fullName}|{contact}|{decisionText}|{decisionAt}|{validity}|{validUntil}|{status}',
    {
      appName: 'G-Hotspot',
      defaultLanguage: 'en',
      adminApproval: { accessDuration: { value: 2, unit: 'hours' } }
    },
    {
      full_name: 'Ada Lovelace',
      contact: 'ada@example.com',
      contact_type: 'email',
      status: 'approved',
      access_expires_at: Date.UTC(2026, 0, 1, 14, 0, 0)
    },
    {
      status: 'approved',
      message: 'Approved by reception.',
      decidedAt: Date.UTC(2026, 0, 1, 12, 0, 0),
      expiresAt: Date.UTC(2026, 0, 1, 14, 0, 0)
    }
  );

  assert.match(rendered, /^Ada Lovelace\|ada@example\.com\|Approved by reception\./u);
  assert.match(rendered, /\|2 hours\|/u);
  assert.match(rendered, /\|approved$/u);
});

test('KamuSM timestamp notifications can be enabled per result', () => {
  const success = { eventType: 'syslog_kamusm_timestamp_succeeded' };
  const failure = { eventType: 'syslog_kamusm_timestamp_failed' };
  const genericSuccess = { eventType: 'syslog_timestamp_succeeded' };
  const genericFailure = { eventType: 'syslog_timestamp_failed' };

  assert.equal(shouldNotifySystemEvent({ notifications: {} }, success), true);
  assert.equal(shouldNotifySystemEvent({ notifications: {} }, failure), true);
  assert.equal(shouldNotifySystemEvent({ notifications: {} }, genericSuccess), true);
  assert.equal(shouldNotifySystemEvent({ notifications: {} }, genericFailure), true);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      syslogKamusmSuccessEnabled: false,
      syslogKamusmFailureEnabled: true
    }
  }, success), false);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      syslogKamusmSuccessEnabled: false,
      syslogKamusmFailureEnabled: true
    }
  }, genericSuccess), false);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      syslogKamusmSuccessEnabled: false,
      syslogKamusmFailureEnabled: true
    }
  }, failure), true);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      syslogKamusmSuccessEnabled: false,
      syslogKamusmFailureEnabled: true
    }
  }, genericFailure), true);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      emailSyslogKamusmSuccessEnabled: false,
      smsSyslogKamusmSuccessEnabled: true
    }
  }, success, 'email'), false);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      emailSyslogKamusmSuccessEnabled: false,
      smsSyslogKamusmSuccessEnabled: true
    }
  }, success, 'sms'), true);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      emailSyslogKamusmSuccessEnabled: false,
      smsSyslogKamusmSuccessEnabled: true
    }
  }, success), true);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      emailSyslogKamusmSuccessEnabled: false,
      smsSyslogKamusmSuccessEnabled: false
    }
  }, success), false);
});

test('system activity notifications are channel-specific', () => {
  const verified = {
    eventType: 'user_verified',
    detail: {
      method: 'voucher',
      identity: 'LOBBY-001',
      clientIp: '172.16.2.44'
    }
  };
  assert.equal(shouldNotifySystemEvent({ notifications: {} }, verified), false);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      emailUserVerifiedEnabled: true,
      smsUserVerifiedEnabled: false
    }
  }, verified, 'email'), true);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      emailUserVerifiedEnabled: true,
      smsUserVerifiedEnabled: false
    }
  }, verified, 'sms'), false);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      emailUserVerifiedEnabled: false,
      smsUserVerifiedEnabled: false,
      telegramUserVerifiedEnabled: true
    }
  }, verified, 'telegram'), true);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      emailUserVerifiedEnabled: false,
      smsUserVerifiedEnabled: false,
      telegramUserVerifiedEnabled: true
    }
  }, verified), true);
  assert.equal(renderSystemNotificationTemplate(
    '{message} | {method} | {identity} | {clientIp}',
    { appName: 'G-Hotspot', defaultLanguage: 'tr' },
    verified
  ), 'voucher kullanıcısı doğrulandı: LOBBY-001 (172.16.2.44). | voucher | LOBBY-001 | 172.16.2.44');

  const failedLogin = {
    eventType: 'admin_login_failed',
    detail: {
      adminUser: 'admin',
      clientIp: '172.16.2.55',
      error: 'invalid_credentials'
    }
  };
  assert.equal(shouldNotifySystemEvent({ notifications: {} }, failedLogin), false);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      emailAdminLoginFailedEnabled: true,
      smsAdminLoginFailedEnabled: false
    }
  }, failedLogin, 'email'), true);
  assert.equal(shouldNotifySystemEvent({
    notifications: {
      emailAdminLoginFailedEnabled: true,
      smsAdminLoginFailedEnabled: false
    }
  }, failedLogin, 'sms'), false);
});
