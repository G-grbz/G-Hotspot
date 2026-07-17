import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { config, reloadConfig } from '../src/config.js';
import { getSettings, installOpnsenseGateway, saveSettings } from '../src/settings.js';
import { quotaProfileForMethod } from '../src/services/quotas.js';

test('settings surface automatic server address instead of bundled env defaults', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-settings-'));
  const envPath = path.join(directory, '.env');
  fs.writeFileSync(envPath, [
    'HOST=0.0.0.0',
    'PORT=8080',
    'PUBLIC_BASE_URL=http://192.168.1.50:8080',
    ''
  ].join('\n'));
  try {
    const settings = getSettings(envPath);
    assert.notEqual(settings.values.HOST, '0.0.0.0');
    assert.match(settings.values.HOST, /^\d{1,3}(?:\.\d{1,3}){3}$/u);
    assert.equal(settings.values.PORT, '8080');
    assert.equal(settings.values.PUBLIC_BASE_URL, `http://${settings.values.HOST}:8080`);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('installer rejects the disabled pfSense gateway mode', () => {
  assert.throws(
    () => installOpnsenseGateway({ GATEWAY_MODE: 'pfsense-api' }),
    /GATEWAY_MODE must be mock or opnsense-api/u
  );
});

test('settings mask secrets and persist runtime-safe changes', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-settings-'));
  const envPath = path.join(directory, '.env');
  fs.writeFileSync(envPath, [
    'APP_NAME=Before',
    'WHATSAPP_ACCESS_TOKEN=secret-token',
    'DEFAULT_LANGUAGE=en',
    ''
  ].join('\n'));
  const originalAppName = process.env.APP_NAME;
  try {
    const before = getSettings(envPath);
    assert.equal(before.values.WHATSAPP_ACCESS_TOKEN, '');
    assert.equal(before.configured.WHATSAPP_ACCESS_TOKEN, true);
    assert.equal(before.values.ALLOWED_COUNTRY_CODES, '');
    assert.equal(before.values.EMAIL_ENABLED, 'true');
    assert.equal(before.values.EMAIL_ACCESS_DURATION_VALUE, '24');
    assert.equal(before.values.EMAIL_ACCESS_DURATION_UNIT, 'hours');
    assert.equal(before.values.EMAIL_IP_RETRY_INTERVAL_VALUE, '1');
    assert.equal(before.values.EMAIL_IP_RETRY_INTERVAL_UNIT, 'minutes');
    assert.equal(before.values.EMAIL_REVERIFY_DURATION_VALUE, '24');
    assert.equal(before.values.EMAIL_REVERIFY_DURATION_UNIT, 'hours');
    assert.equal(before.values.TELEGRAM_ENABLED, 'false');
    assert.equal(before.values.TELEGRAM_ACCESS_DURATION_VALUE, '24');
    assert.equal(before.values.TELEGRAM_ACCESS_DURATION_UNIT, 'hours');
    assert.equal(before.values.TELEGRAM_BOT_TOKEN, '');
    assert.equal(before.configured.TELEGRAM_BOT_TOKEN, false);
    assert.equal(before.values.OPNSENSE_ZONE_MAP, '');
    assert.equal(before.values.OPNSENSE_SYNC_INTERVAL_SECONDS, '10');
    assert.equal(before.values.OPNSENSE_KEA_LEASE_SYNC_ENABLED, 'true');
    assert.equal(before.values.OPNSENSE_COOKIE_IP_MOVE_ENABLED, 'true');
    assert.equal(before.values.OPNSENSE_SESSION_COOKIE_REQUIRED, 'false');
    assert.equal(before.values.OPNSENSE_SHAPER_INTERFACE, 'wan');
    assert.equal(before.values.OPNSENSE_SHAPER_NETWORK, 'any');
    assert.equal(before.values.VOUCHER_DOWNLOAD_SPEED_LIMIT_MBPS, '0');
    assert.equal(before.values.VOUCHER_UPLOAD_SPEED_LIMIT_MBPS, '0');
    assert.equal(before.values.VOUCHER_QUOTA_PERIOD, 'daily');
    assert.equal(before.values.VOUCHER_DOWNLOAD_QUOTA_GB, '0');
    assert.equal(before.values.VOUCHER_UPLOAD_QUOTA_GB, '0');
    assert.equal(before.values.SMS_DOWNLOAD_SPEED_LIMIT_MBPS, '0');
    assert.equal(before.values.SMS_UPLOAD_SPEED_LIMIT_MBPS, '0');
    assert.equal(before.values.SMS_QUOTA_PERIOD, 'daily');
    assert.equal(before.values.SMS_DOWNLOAD_QUOTA_GB, '0');
    assert.equal(before.values.SMS_UPLOAD_QUOTA_GB, '0');
    assert.equal(before.values.NVI_ENABLED, 'false');
    assert.equal(before.values.NVI_SEND_SMS_CODE, 'false');
    assert.equal(before.values.NVI_ACCESS_DURATION_VALUE, '24');
    assert.equal(before.values.NVI_ACCESS_DURATION_UNIT, 'hours');
    assert.equal(before.values.NVI_IP_RETRY_INTERVAL_VALUE, '1');
    assert.equal(before.values.NVI_IP_RETRY_INTERVAL_UNIT, 'minutes');
    assert.equal(before.values.NVI_REVERIFY_DURATION_VALUE, '24');
    assert.equal(before.values.NVI_REVERIFY_DURATION_UNIT, 'hours');
    assert.equal(before.values.NVI_USERNAME, '');
    assert.equal(before.values.NVI_PASSWORD, '');
    assert.equal(before.configured.NVI_PASSWORD, false);
    assert.equal(before.values.NVI_DOWNLOAD_SPEED_LIMIT_MBPS, '0');
    assert.equal(before.values.NVI_QUOTA_PERIOD, 'daily');
    assert.equal(before.values.NVI_DOWNLOAD_QUOTA_GB, '0');
    assert.equal(Boolean(before.values.SYSLOG_TIME_ZONE), true);
    assert.equal(before.values.SYSLOG_TIMESTAMP_MODE, 'disabled');
    assert.equal(before.values.SYSLOG_KAMUSM_USER, '');
    assert.equal(before.values.SYSLOG_KAMUSM_PASSWORD, '');
    assert.equal(before.configured.SYSLOG_KAMUSM_PASSWORD, false);
    assert.equal(before.values.SYSLOG_KAMUSM_URL, 'http://zd.kamusm.gov.tr');
    assert.equal(before.values.SYSLOG_KAMUSM_TIMEOUT_SECONDS, '60');
    assert.equal(before.values.SYSLOG_TIMESTAMP_URL, '');
    assert.equal(before.values.SYSLOG_TIMESTAMP_HEADERS_JSON, '');
    assert.equal(before.values.SYSLOG_TIMESTAMP_CERT_REQUEST, 'true');
    assert.equal(before.values.SYSLOG_TIMESTAMP_TIMEOUT_SECONDS, '60');
    assert.equal(before.values.SYSLOG_TIMESTAMP_API_URL, '');
    assert.equal(before.values.SYSLOG_TIMESTAMP_API_KEY, '');
    assert.equal(before.configured.SYSLOG_TIMESTAMP_API_KEY, false);
    assert.equal(before.values.SYSLOG_TIMESTAMP_API_KEY_HEADER, 'Authorization');
    assert.equal(before.values.SYSLOG_TIMESTAMP_API_KEY_PREFIX, 'Bearer');
    assert.equal(before.values.SYSLOG_TIMESTAMP_API_TIMEOUT_SECONDS, '60');
    assert.equal(before.values.SYSLOG_EXPORT_ZIP_ENABLED, 'false');
    assert.equal(before.values.SYSLOG_EXPORT_DELETE_SOURCE_AFTER_ZIP, 'false');
    assert.equal(Object.hasOwn(before.values, 'SYSLOG_KAMUSM_TIMESTAMP_ENABLED'), false);
    assert.equal(Object.hasOwn(before.values, 'SYSLOG_SIGNATURE_TIMEOUT_SECONDS'), false);
    assert.equal(Object.hasOwn(before.values, 'SYSLOG_BACKUP_READONLY'), false);
    assert.equal(Object.hasOwn(before.values, 'SYSLOG_REMOTE_MIRROR_ENABLED'), false);
    assert.equal(before.values.NOTIFICATION_EMAIL_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_SMS_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_EMAIL_REPEAT_FREQUENCY, 'state-change');
    assert.equal(before.values.NOTIFICATION_EMAIL_STARTUP_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_SMS_REPEAT_FREQUENCY, 'state-change');
    assert.equal(before.values.NOTIFICATION_SMS_STARTUP_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_REPEAT_FREQUENCY, 'state-change');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_STARTUP_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_EMAIL_SYSLOG_STORAGE_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_EMAIL_SYSLOG_KAMUSM_SUCCESS_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_EMAIL_SYSLOG_KAMUSM_FAILURE_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_EMAIL_ADMIN_APPROVAL_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_EMAIL_SYSTEM_STARTUP_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_EMAIL_OPNSENSE_DOWN_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_EMAIL_USER_VERIFIED_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_EMAIL_ACCESS_EXPIRED_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_EMAIL_ADMIN_LOGIN_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_EMAIL_ADMIN_LOGIN_FAILED_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_SMS_SYSLOG_STORAGE_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_SMS_SYSLOG_KAMUSM_SUCCESS_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_SMS_SYSLOG_KAMUSM_FAILURE_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_SMS_ADMIN_APPROVAL_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_SMS_SYSTEM_STARTUP_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_SMS_OPNSENSE_DOWN_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_SMS_USER_VERIFIED_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_SMS_ACCESS_EXPIRED_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_SMS_ADMIN_LOGIN_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_SMS_ADMIN_LOGIN_FAILED_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_SYSLOG_STORAGE_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_SYSLOG_KAMUSM_SUCCESS_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_SYSLOG_KAMUSM_FAILURE_ENABLED, 'true');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_SYSTEM_STARTUP_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_OPNSENSE_DOWN_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_USER_VERIFIED_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_ACCESS_EXPIRED_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_ADMIN_LOGIN_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_ADMIN_LOGIN_FAILED_ENABLED, 'false');
    assert.equal(before.values.NOTIFICATION_EMAIL_RECIPIENTS, '');
    assert.equal(before.values.NOTIFICATION_SMS_RECIPIENTS, '');
    assert.equal(before.values.NOTIFICATION_TELEGRAM_RECIPIENTS, '');
    assert.match(before.values.NOTIFICATION_SYSLOG_EMAIL_TEMPLATE_MARKDOWN, /^\{systemNotification\}/u);
    assert.match(before.values.NOTIFICATION_SYSLOG_EMAIL_TEMPLATE_MARKDOWN, /Storage usage: \{storageUsage\}%/u);
    assert.doesNotMatch(before.values.NOTIFICATION_SYSLOG_EMAIL_TEMPLATE_MARKDOWN, /Directory:/u);
    assert.equal(before.values.NOTIFICATION_SYSLOG_SMS_TEMPLATE, '{appName}: {message}');
    assert.equal(before.values.NOTIFICATION_SYSLOG_TELEGRAM_TEMPLATE, '{appName}: {message}');
    assert.equal(before.values.NOTIFICATION_SYSTEM_EMAIL_TEMPLATE_MARKDOWN, '{systemNotification}\n\n{message}');
    assert.equal(before.values.NOTIFICATION_SYSTEM_SMS_TEMPLATE, '{appName}: {message}');
    assert.equal(before.values.NOTIFICATION_SYSTEM_TELEGRAM_TEMPLATE, '{appName}: {message}');
    const generalGroup = before.schema.find(group => group.id === 'general');
    const syslogGroup = before.schema.find(group => group.id === 'syslog');
    const opnsenseGroup = before.schema.find(group => group.id === 'opnsense');
    const gatewayModeField = opnsenseGroup.fields.find(field => field.key === 'GATEWAY_MODE');
    const quotasGroup = before.schema.find(group => group.id === 'quotas');
    const notificationGroup = before.schema.find(group => group.id === 'notifications');
    const androidNotificationGroup = before.schema.find(group => group.id === 'android-notifications');
    const adminApprovalGroup = before.schema.find(group => group.id === 'admin-approval');
    const nviGroup = before.schema.find(group => group.id === 'nvi');
    assert.equal(Boolean(quotasGroup), true);
    assert.equal(Boolean(notificationGroup), true);
    assert.equal(Boolean(androidNotificationGroup), true);
    assert.equal(Boolean(adminApprovalGroup), true);
    assert.equal(Boolean(nviGroup), true);
    assert.deepEqual(gatewayModeField.options, ['mock', 'opnsense-api']);
    assert.equal(generalGroup.fields.some(field => field.key === 'ALLOWED_COUNTRY_CODES'), true);
    assert.equal(opnsenseGroup.fields.some(field => field.key === 'OPNSENSE_COOKIE_IP_MOVE_ENABLED'), true);
    assert.equal(opnsenseGroup.fields.some(field => field.key === 'OPNSENSE_SESSION_COOKIE_REQUIRED'), true);
    assert.equal(opnsenseGroup.fields.some(field => field.key === 'OPNSENSE_SHAPER_NETWORK'), false);
    assert.equal(quotasGroup.fields.some(field => field.key === 'OPNSENSE_SHAPER_NETWORK'), true);
    assert.equal(quotasGroup.fields.some(field => field.key === 'EMAIL_DOWNLOAD_SPEED_LIMIT_MBPS'), true);
    assert.equal(quotasGroup.fields.some(field => field.key === 'NVI_DOWNLOAD_QUOTA_GB'), true);
    assert.equal(quotasGroup.fields.some(field => field.key === 'SMS_DOWNLOAD_QUOTA_GB'), true);
    assert.equal(syslogGroup.fields.some(field => field.key === 'SYSLOG_STORAGE_ALERT_PERCENT'), true);
    assert.equal(syslogGroup.fields.some(field => field.key === 'SYSLOG_STORAGE_BLOCK_PERCENT'), true);
    assert.equal(syslogGroup.fields.some(field => field.key === 'SYSLOG_EXPORT_ZIP_ENABLED'), true);
    assert.equal(syslogGroup.fields.some(field => field.key === 'SYSLOG_EXPORT_DELETE_SOURCE_AFTER_ZIP'), true);
    assert.equal(syslogGroup.fields.some(field => field.key === 'SYSLOG_TIMESTAMP_MODE'), true);
    assert.equal(syslogGroup.fields.some(field => field.key === 'SYSLOG_TIMESTAMP_API_KEY'), true);
    assert.equal(syslogGroup.fields.some(field => field.key === 'SYSLOG_KAMUSM_TIMESTAMP_ENABLED'), false);
    assert.equal(notificationGroup.fields.some(field => field.key === 'SYSLOG_STORAGE_ALERT_PERCENT'), false);
    assert.equal(notificationGroup.fields.some(field => field.key === 'NOTIFICATION_EMAIL_ADMIN_APPROVAL_ENABLED'), false);
    assert.equal(notificationGroup.fields.some(field => field.key === 'NOTIFICATION_SMS_ADMIN_APPROVAL_ENABLED'), false);
    assert.equal(notificationGroup.fields.some(field => field.key === 'NOTIFICATION_TELEGRAM_ENABLED'), true);
    assert.equal(notificationGroup.fields.some(field => field.key === 'NOTIFICATION_TELEGRAM_SYSLOG_STORAGE_ENABLED'), true);
    assert.equal(notificationGroup.fields.some(field => field.key === 'NOTIFICATION_ANDROID_ENABLED'), false);
    assert.equal(notificationGroup.fields.some(field => field.key === 'NOTIFICATION_ANDROID_ADMIN_APPROVAL_ENABLED'), false);
    assert.equal(androidNotificationGroup.fields.some(field => field.key === 'NOTIFICATION_ANDROID_ENABLED'), true);
    assert.equal(androidNotificationGroup.fields.some(field => field.key === 'ANDROID_FCM_SERVICE_ACCOUNT_FILE'), true);
    assert.equal(androidNotificationGroup.fields.some(field => field.key === 'NOTIFICATION_ANDROID_ADMIN_APPROVAL_ENABLED'), true);
    assert.equal(adminApprovalGroup.fields.some(field => field.key === 'NOTIFICATION_EMAIL_ADMIN_APPROVAL_ENABLED'), true);
    assert.equal(adminApprovalGroup.fields.some(field => field.key === 'NOTIFICATION_SMS_ADMIN_APPROVAL_ENABLED'), true);
    assert.equal(adminApprovalGroup.fields.some(field => field.key === 'NOTIFICATION_ANDROID_ADMIN_APPROVAL_ENABLED'), false);
    assert.equal(nviGroup.fields.some(field => field.key === 'NVI_SEND_SMS_CODE'), true);
    assert.equal(nviGroup.fields.some(field => field.key === 'NVI_IP_RETRY_INTERVAL_VALUE'), true);
    assert.equal(nviGroup.fields.some(field => field.key === 'NVI_REVERIFY_DURATION_VALUE'), true);
    assert.equal(nviGroup.fields.some(field => field.key === 'NVI_ACCESS_DURATION_VALUE'), true);
    assert.equal(nviGroup.fields.some(field => field.key === 'NVI_USERNAME'), true);
    assert.equal(nviGroup.fields.some(field => field.key === 'NVI_PASSWORD'), true);
    assert.equal(nviGroup.fields.some(field => field.key === 'NVI_SERVICE_URL'), false);
    assert.equal(nviGroup.fields.some(field => field.key === 'NVI_SOAP_METHOD'), false);
    assert.equal(before.values.PORTAL_TITLE_TEXT, '');
    assert.equal(before.values.PORTAL_NETWORK_LABEL_TEXT, 'GUEST NETWORK');
    assert.equal(
      before.values.PORTAL_VERIFICATION_PROMPT_TEXT,
      'Choose a verification method to open internet access.'
    );
    assert.equal(before.values.PORTAL_PRIMARY_COLOR, '#5340CC');
    assert.equal(before.values.PORTAL_CARD_IMAGE_OPACITY, '100');
    assert.equal(before.values.PORTAL_BODY_IMAGE_ANIMATION_ENABLED, 'false');
    assert.equal(
      before.values.PORTAL_TERMS_TEXT,
      'By continuing, you accept the terms of use for this guest network.'
    );
    assert.match(before.values.PORTAL_TERMS_MARKDOWN, /^## Terms of Use/u);
    assert.match(before.values.PORTAL_POLICY_MARKDOWN, /^## Safe Internet Policy/u);
    assert.match(before.values.PORTAL_PRIVACY_MARKDOWN, /^## Privacy Notice/u);

    const result = saveSettings({
      APP_NAME: 'After',
      DEFAULT_LANGUAGE: 'tr',
      ALLOWED_COUNTRY_CODES: '90\n33\n1',
      PORTAL_TITLE_TEXT: 'Otel WiFi Girişi',
      PORTAL_NETWORK_LABEL_TEXT: 'OTEL MİSAFİR AĞI',
      PORTAL_VERIFICATION_PROMPT_TEXT: 'İnternete bağlanmak için size uygun yöntemi seçin.',
      PORTAL_TERMS_TEXT: 'Devam ederek kullanım koşullarını kabul edersiniz. Kullanım Koşulları İçin Tıklayın',
      PORTAL_TERMS_MARKDOWN: '## Kullanım Koşulları\n\n- Ağ kurallarına uyun.',
      PORTAL_POLICY_MARKDOWN: '## Güvenli İnternet Politikası\n\n- Güvenli kullanım kurallarına uyun.',
      PORTAL_PRIVACY_MARKDOWN: '## Kişisel Veri Aydınlatma Metni\n\n- Kişisel veri işleme amaçlarını okuyun.',
      PORTAL_BODY_IMAGE_ANIMATION_ENABLED: true,
      WHATSAPP_ACCESS_TOKEN: ''
    }, envPath);
    assert.equal(result.restartRequired, false);
    const content = fs.readFileSync(envPath, 'utf8');
    assert.match(content, /^APP_NAME=After$/mu);
    assert.match(content, /^DEFAULT_LANGUAGE=tr$/mu);
    assert.match(content, /^ALLOWED_COUNTRY_CODES="90\\n33\\n1"$/mu);
    assert.match(content, /^PORTAL_BODY_IMAGE_ANIMATION_ENABLED=true$/mu);
    assert.equal(
      getSettings(envPath).values.PORTAL_TITLE_TEXT,
      'Otel WiFi Girişi'
    );
    assert.equal(
      getSettings(envPath).values.PORTAL_NETWORK_LABEL_TEXT,
      'OTEL MİSAFİR AĞI'
    );
    assert.equal(
      getSettings(envPath).values.PORTAL_VERIFICATION_PROMPT_TEXT,
      'İnternete bağlanmak için size uygun yöntemi seçin.'
    );
    assert.equal(
      getSettings(envPath).values.PORTAL_TERMS_TEXT,
      'Devam ederek kullanım koşullarını kabul edersiniz. Kullanım Koşulları İçin Tıklayın'
    );
    assert.equal(
      getSettings(envPath).values.PORTAL_TERMS_MARKDOWN,
      '## Kullanım Koşulları\n\n- Ağ kurallarına uyun.'
    );
    assert.equal(
      getSettings(envPath).values.PORTAL_POLICY_MARKDOWN,
      '## Güvenli İnternet Politikası\n\n- Güvenli kullanım kurallarına uyun.'
    );
    assert.equal(
      getSettings(envPath).values.PORTAL_PRIVACY_MARKDOWN,
      '## Kişisel Veri Aydınlatma Metni\n\n- Kişisel veri işleme amaçlarını okuyun.'
    );
    assert.equal(getSettings(envPath).values.PORTAL_BODY_IMAGE_ANIMATION_ENABLED, 'true');
    saveSettings({
      PORTAL_TITLE_TEXT: '',
      PORTAL_NETWORK_LABEL_TEXT: '',
      PORTAL_VERIFICATION_PROMPT_TEXT: ''
    }, envPath);
    assert.equal(getSettings(envPath).values.PORTAL_TITLE_TEXT, '');
    assert.equal(getSettings(envPath).values.PORTAL_NETWORK_LABEL_TEXT, '');
    assert.equal(getSettings(envPath).values.PORTAL_VERIFICATION_PROMPT_TEXT, '');
    assert.match(content, /^WHATSAPP_ACCESS_TOKEN=secret-token$/mu);

    assert.throws(() => saveSettings({ SMS_PROVIDER: 'invalid-provider' }, envPath),
      /SMS_PROVIDER must be/u);
    assert.doesNotMatch(fs.readFileSync(envPath, 'utf8'), /invalid-provider/u);
    assert.throws(() => saveSettings({ PORTAL_PRIMARY_COLOR: 'red' }, envPath),
      /PORTAL_PRIMARY_COLOR must be a six-digit hex color/u);
    assert.doesNotMatch(fs.readFileSync(envPath, 'utf8'), /PORTAL_PRIMARY_COLOR=red/u);
    assert.throws(() => saveSettings({ OPNSENSE_ZONE_MAP: '172.16.3.0/24:1' }, envPath),
      /OPNSENSE_ZONE_MAP entries must use network=zoneId/u);
    assert.doesNotMatch(fs.readFileSync(envPath, 'utf8'), /172\.16\.3\.0\/24:1/u);
    assert.throws(() => saveSettings({ ALLOWED_COUNTRY_CODES: '999' }, envPath),
      /ALLOWED_COUNTRY_CODES contains an unknown country code/u);
    assert.doesNotMatch(fs.readFileSync(envPath, 'utf8'), /999/u);
    assert.throws(() => saveSettings({ SYSLOG_TIME_ZONE: 'Mars/Olympus' }, envPath),
      /SYSLOG_TIME_ZONE must be a valid IANA time zone/u);
    assert.doesNotMatch(fs.readFileSync(envPath, 'utf8'), /Mars\/Olympus/u);
  } finally {
    if (originalAppName == null) delete process.env.APP_NAME;
    else process.env.APP_NAME = originalAppName;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('runtime portal header texts can be disabled with empty values', () => {
  const originalTitle = process.env.PORTAL_TITLE_TEXT;
  const originalNetworkLabel = process.env.PORTAL_NETWORK_LABEL_TEXT;
  const originalVerificationPrompt = process.env.PORTAL_VERIFICATION_PROMPT_TEXT;
  try {
    delete process.env.PORTAL_TITLE_TEXT;
    delete process.env.PORTAL_NETWORK_LABEL_TEXT;
    delete process.env.PORTAL_VERIFICATION_PROMPT_TEXT;
    reloadConfig();
    assert.equal(config.portal.titleText, '');
    assert.equal(config.portal.networkLabelText, 'GUEST NETWORK');
    assert.equal(
      config.portal.verificationPromptText,
      'Choose a verification method to open internet access.'
    );

    process.env.PORTAL_TITLE_TEXT = 'Custom Portal Title';
    process.env.PORTAL_NETWORK_LABEL_TEXT = '';
    process.env.PORTAL_VERIFICATION_PROMPT_TEXT = '';
    reloadConfig();
    assert.equal(config.portal.titleText, 'Custom Portal Title');
    assert.equal(config.portal.networkLabelText, '');
    assert.equal(config.portal.verificationPromptText, '');

    process.env.PORTAL_TITLE_TEXT = '';
    reloadConfig();
    assert.equal(config.portal.titleText, '');
  } finally {
    if (originalTitle == null) delete process.env.PORTAL_TITLE_TEXT;
    else process.env.PORTAL_TITLE_TEXT = originalTitle;
    if (originalNetworkLabel == null) delete process.env.PORTAL_NETWORK_LABEL_TEXT;
    else process.env.PORTAL_NETWORK_LABEL_TEXT = originalNetworkLabel;
    if (originalVerificationPrompt == null) delete process.env.PORTAL_VERIFICATION_PROMPT_TEXT;
    else process.env.PORTAL_VERIFICATION_PROMPT_TEXT = originalVerificationPrompt;
    reloadConfig();
  }
});

test('SMTP from address follows SMTP username', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-settings-'));
  const envPath = path.join(directory, '.env');
  fs.writeFileSync(envPath, [
    'SMTP_USER=owner@example.com',
    'SMTP_FROM=spoof@example.net',
    ''
  ].join('\n'));
  const originalSmtpUser = process.env.SMTP_USER;
  const originalSmtpFrom = process.env.SMTP_FROM;
  try {
    const before = getSettings(envPath);
    assert.equal(before.values.SMTP_USER, 'owner@example.com');
    assert.equal(before.values.SMTP_FROM, 'owner@example.com');

    saveSettings({ SMTP_FROM: 'attacker@example.net' }, envPath);
    let content = fs.readFileSync(envPath, 'utf8');
    assert.match(content, /^SMTP_FROM=owner@example.com$/mu);
    assert.doesNotMatch(content, /attacker@example.net/u);

    saveSettings({
      SMTP_USER: 'new-owner@example.com',
      SMTP_FROM: 'attacker@example.net'
    }, envPath);
    content = fs.readFileSync(envPath, 'utf8');
    assert.match(content, /^SMTP_USER=new-owner@example.com$/mu);
    assert.match(content, /^SMTP_FROM=new-owner@example.com$/mu);
    assert.equal(getSettings(envPath).values.SMTP_FROM, 'new-owner@example.com');
  } finally {
    if (originalSmtpUser == null) delete process.env.SMTP_USER;
    else process.env.SMTP_USER = originalSmtpUser;
    if (originalSmtpFrom == null) delete process.env.SMTP_FROM;
    else process.env.SMTP_FROM = originalSmtpFrom;
    reloadConfig();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('runtime SMTP sender ignores SMTP_FROM and uses SMTP username', () => {
  const originalSmtpHost = process.env.SMTP_HOST;
  const originalSmtpUser = process.env.SMTP_USER;
  const originalSmtpFrom = process.env.SMTP_FROM;
  try {
    process.env.SMTP_HOST = 'smtp.example.com';
    process.env.SMTP_USER = 'owner@example.com';
    process.env.SMTP_FROM = 'spoof@example.net';
    reloadConfig();
    assert.equal(config.smtp.user, 'owner@example.com');
    assert.equal(config.smtp.from, 'owner@example.com');
    assert.equal(config.smtp.configured, true);

    delete process.env.SMTP_USER;
    reloadConfig();
    assert.equal(config.smtp.configured, false);
    assert.equal(config.smtp.enabled, false);
    assert.equal(config.smtp.from, '');
  } finally {
    if (originalSmtpHost == null) delete process.env.SMTP_HOST;
    else process.env.SMTP_HOST = originalSmtpHost;
    if (originalSmtpUser == null) delete process.env.SMTP_USER;
    else process.env.SMTP_USER = originalSmtpUser;
    if (originalSmtpFrom == null) delete process.env.SMTP_FROM;
    else process.env.SMTP_FROM = originalSmtpFrom;
    reloadConfig();
  }
});

test('saving settings removes duplicate environment entries', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-settings-'));
  const envPath = path.join(directory, '.env');
  fs.writeFileSync(envPath, [
    'OPNSENSE_SHAPER_NETWORK="172.16.2.10 - 172.16.2.90"',
    '',
    '# duplicate managed value',
    'OPNSENSE_SHAPER_NETWORK=172.16.2.0/24',
    ''
  ].join('\n'));
  try {
    saveSettings({
      OPNSENSE_SHAPER_NETWORK: '192.168.50.1 - 192.168.50.100'
    }, envPath);
    const content = fs.readFileSync(envPath, 'utf8');
    assert.equal(
      content.match(/^OPNSENSE_SHAPER_NETWORK=/gmu)?.length,
      1
    );
    assert.equal(
      getSettings(envPath).values.OPNSENSE_SHAPER_NETWORK,
      '192.168.50.1 - 192.168.50.100'
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('runtime NVI access uses T.C. identity quota profile', () => {
  const originalValues = {
    NVI_DOWNLOAD_SPEED_LIMIT_MBPS: process.env.NVI_DOWNLOAD_SPEED_LIMIT_MBPS,
    NVI_UPLOAD_SPEED_LIMIT_MBPS: process.env.NVI_UPLOAD_SPEED_LIMIT_MBPS,
    NVI_QUOTA_PERIOD: process.env.NVI_QUOTA_PERIOD,
    NVI_DOWNLOAD_QUOTA_GB: process.env.NVI_DOWNLOAD_QUOTA_GB,
    NVI_UPLOAD_QUOTA_GB: process.env.NVI_UPLOAD_QUOTA_GB
  };
  try {
    process.env.NVI_DOWNLOAD_SPEED_LIMIT_MBPS = '25';
    process.env.NVI_UPLOAD_SPEED_LIMIT_MBPS = '5';
    process.env.NVI_QUOTA_PERIOD = 'monthly';
    process.env.NVI_DOWNLOAD_QUOTA_GB = '20';
    process.env.NVI_UPLOAD_QUOTA_GB = '3';
    reloadConfig();
    assert.deepEqual(quotaProfileForMethod(config, 'nvi'), {
      downloadSpeedMbps: 25,
      uploadSpeedMbps: 5,
      quotaPeriod: 'monthly',
      downloadQuotaGb: 20,
      uploadQuotaGb: 3
    });
  } finally {
    for (const [key, value] of Object.entries(originalValues)) {
      if (value == null) delete process.env[key];
      else process.env[key] = value;
    }
    reloadConfig();
  }
});
