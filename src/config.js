import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { envBoolean, envInteger } from './lib/env.js';
import { normalizeLanguage } from './lib/languages.js';
import { isSystemInstalled, loadSystemSettingsIntoEnv } from './system.js';
import {
  automaticListenHost,
  automaticListenPort,
  automaticPublicBaseUrl,
  ipv4InNetworkList,
  normalizeNetworkList
} from './lib/network.js';
import { COUNTRY_CALLING_CODES, isKnownCountryCode, normalizeCountryCode } from './lib/security.js';
import { QUOTA_METHODS, QUOTA_PERIODS } from './services/quotas.js';

loadSystemSettingsIntoEnv();

const ACCESS_DURATION_UNITS = new Set(['hours', 'days', 'months', 'years', 'unlimited']);
const RETRY_INTERVAL_UNITS = new Set(['minutes', ...ACCESS_DURATION_UNITS]);
const TELEGRAM_MODES = new Set(['webhook', 'polling']);
const GATEWAY_MODES = [
  'mock',
  'opnsense-api'
  // TODO(pfSense): Re-enable 'pfsense-api' after the adapter and login flow are completed.
  // 'pfsense-api'
];
const NOTIFICATION_FREQUENCIES = ['state-change', 'hourly', 'daily', 'monthly'];
const SYSLOG_AUTO_EXPORT_INTERVALS = ['1h', '6h', '12h', '24h', 'daily'];
const SYSLOG_TIMESTAMP_MODES = ['disabled', 'kamusm', 'rfc3161', 'api-key'];
const TRAFFIC_LOG_RETENTION_OPTIONS_MINUTES = [15, 30, 45, 60];
const TEMPORARY_APP_SECRET = randomBytes(48).toString('base64url');
export const DEFAULT_PORTAL_TERMS_TEXT =
  'By continuing, you accept the terms of use for this guest network.';
export const DEFAULT_PORTAL_NETWORK_LABEL_TEXT = 'GUEST NETWORK';
export const DEFAULT_PORTAL_VERIFICATION_PROMPT_TEXT =
  'Choose a verification method to open internet access.';
export const DEFAULT_PORTAL_TERMS_MARKDOWN = [
  '## Terms of Use',
  '',
  'By using this guest network, you agree to use the internet connection lawfully and responsibly.',
  '',
  '- Do not attempt to access systems or data without authorization.',
  '- Do not disrupt network service for other users.',
  '- The network owner may limit, monitor, or terminate access when necessary.'
].join('\n');
export const DEFAULT_PORTAL_POLICY_MARKDOWN = [
  '## Safe Internet Policy',
  '',
  'This guest network is provided with safety controls intended to keep internet access lawful and appropriate.',
  '',
  '- Do not use the connection for illegal, harmful, abusive, or disruptive activity.',
  '- Some websites, content categories, or services may be restricted by network policy.',
  '- Contact the network administrator if you believe access has been blocked incorrectly.'
].join('\n');
export const DEFAULT_PORTAL_PRIVACY_MARKDOWN = [
  '## Privacy Notice',
  '',
  'Personal data shared during verification is processed for guest network access, security, logging, and legal compliance purposes.',
  '',
  '- Verification details may include contact information, device address, IP address, access time, and session records.',
  '- Records are retained only for operational, security, and legal requirements.',
  '- Contact the network administrator for privacy requests related to this guest network.'
].join('\n');
export const DEFAULT_SYSLOG_NOTIFICATION_EMAIL_MARKDOWN = [
  '{systemNotification}',
  '',
  '{message}',
  '',
  'Type: {eventType}',
  'Severity: {severity}',
  'Log file: {logFile}',
  'Timestamp token: {timestampToken}',
  'Storage usage: {storageUsage}%'
].join('\n');
export const DEFAULT_SYSLOG_NOTIFICATION_SMS_TEMPLATE =
  '{appName}: {message}';
export const DEFAULT_SYSLOG_NOTIFICATION_TELEGRAM_TEMPLATE =
  DEFAULT_SYSLOG_NOTIFICATION_SMS_TEMPLATE;
export const DEFAULT_SYSTEM_NOTIFICATION_EMAIL_MARKDOWN = [
  '{systemNotification}',
  '',
  '{message}'
].join('\n');
export const DEFAULT_SYSTEM_NOTIFICATION_SMS_TEMPLATE =
  '{appName}: {message}';
export const DEFAULT_SYSTEM_NOTIFICATION_TELEGRAM_TEMPLATE =
  DEFAULT_SYSTEM_NOTIFICATION_SMS_TEMPLATE;
export const DEFAULT_ADMIN_APPROVAL_NOTIFICATION_EMAIL_MARKDOWN = [
  '{appName} admin approval result',
  '',
  '{decisionText}',
  '',
  'Decision time: {decisionAt}',
  'Validity: {validity}',
  'Valid until: {validUntil}'
].join('\n');
export const DEFAULT_ADMIN_APPROVAL_NOTIFICATION_SMS_TEMPLATE =
  '{appName}: {decisionText} Decision time: {decisionAt}. Validity: {validity}.';

function envText(name, fallback) {
  return Object.hasOwn(process.env, name) ? process.env[name] : fallback;
}

export function systemTimeZone() {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
}

function normalizeTimeZone(value, fallback = systemTimeZone()) {
  const timeZone = String(value || fallback || 'UTC').trim();
  try {
    new Intl.DateTimeFormat('en-US', { timeZone }).format(new Date());
    return timeZone;
  } catch {
    throw new Error(`${value ? 'SYSLOG_TIME_ZONE' : 'System time zone'} must be a valid IANA time zone`);
  }
}

function envAlias(name, legacyName, fallback = '') {
  const value = process.env[name] ?? (legacyName ? process.env[legacyName] : undefined);
  return value == null || value === '' ? fallback : value;
}

function envAliasPreserveEmpty(name, legacyName, fallback = '') {
  const value = process.env[name] ?? (legacyName ? process.env[legacyName] : undefined);
  return value == null ? fallback : value;
}

function normalizeTrafficLogRetentionMinutes(value, fallback = 60) {
  const parsed = Math.trunc(Number(value));
  const minutes = Number.isFinite(parsed) ? parsed : fallback;
  if (minutes <= TRAFFIC_LOG_RETENTION_OPTIONS_MINUTES[0]) return TRAFFIC_LOG_RETENTION_OPTIONS_MINUTES[0];
  return TRAFFIC_LOG_RETENTION_OPTIONS_MINUTES.find(option => minutes <= option) ||
    TRAFFIC_LOG_RETENTION_OPTIONS_MINUTES.at(-1);
}

function trafficLogRetentionMinutesEnv() {
  if (process.env.TRAFFIC_LOGS_RETENTION_MINUTES != null && process.env.TRAFFIC_LOGS_RETENTION_MINUTES !== '') {
    return normalizeTrafficLogRetentionMinutes(process.env.TRAFFIC_LOGS_RETENTION_MINUTES);
  }
  if (process.env.TRAFFIC_LOGS_RETENTION_DAYS != null && process.env.TRAFFIC_LOGS_RETENTION_DAYS !== '') {
    return normalizeTrafficLogRetentionMinutes(Number.parseInt(process.env.TRAFFIC_LOGS_RETENTION_DAYS, 10) * 24 * 60);
  }
  return 60;
}

function envBooleanAlias(name, legacyName, fallback = false) {
  const value = process.env[name] ?? (legacyName ? process.env[legacyName] : undefined);
  if (value == null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function envIntegerAlias(name, legacyName, fallback, { min, max } = {}) {
  const raw = process.env[name] ?? (legacyName ? process.env[legacyName] : undefined);
  const value = raw == null || raw === '' ? fallback : Number.parseInt(raw, 10);
  if (!Number.isInteger(value)) throw new Error(`${name} must be an integer`);
  if (min != null && value < min) throw new Error(`${name} must be >= ${min}`);
  if (max != null && value > max) throw new Error(`${name} must be <= ${max}`);
  return value;
}

function envOptionAlias(name, legacyName, fallback, allowed) {
  const value = String(envAlias(name, legacyName, fallback) || fallback).trim().toLowerCase();
  if (!allowed.includes(value)) throw new Error(`${name} must be one of: ${allowed.join(', ')}`);
  return value;
}

function envJsonObjectAlias(name, legacyName, fallback = '') {
  const value = envAlias(name, legacyName, fallback);
  if (!String(value || '').trim()) return value;
  const parsed = JSON.parse(value);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${name} must be a JSON object`);
  }
  return value;
}

function syslogAutoExportInterval(value) {
  const raw = String(value || 'daily').trim().toLowerCase();
  const aliases = {
    '1': '1h',
    '60': '1h',
    hour: '1h',
    hourly: '1h',
    '1h': '1h',
    '6': '6h',
    '360': '6h',
    '6h': '6h',
    '12': '12h',
    '720': '12h',
    '12h': '12h',
    '24': '24h',
    '1440': '24h',
    '24h': '24h',
    day: 'daily',
    daily: 'daily'
  };
  const normalized = aliases[raw] || raw;
  if (!SYSLOG_AUTO_EXPORT_INTERVALS.includes(normalized)) {
    throw new Error(`SYSLOG_AUTO_EXPORT_INTERVAL must be one of: ${SYSLOG_AUTO_EXPORT_INTERVALS.join(', ')}`);
  }
  return normalized;
}

function syslogAutoExportIntervalMinutes(value) {
  if (value === 'daily') return 1440;
  return Number(value.replace(/h$/u, '')) * 60;
}

function envIntegerWithLegacy(name, legacyName, fallback, options = {}) {
  const raw = process.env[name] ?? (legacyName ? process.env[legacyName] : undefined);
  const value = raw == null || raw === '' ? fallback : Number.parseInt(raw, 10);
  if (!Number.isInteger(value)) throw new Error(`${name} must be an integer`);
  if (options.min != null && value < options.min) throw new Error(`${name} must be >= ${options.min}`);
  if (options.max != null && value > options.max) throw new Error(`${name} must be <= ${options.max}`);
  return value;
}

function stringList(value) {
  return String(value || '')
    .split(/[\n;,]+/u)
    .map(item => item.trim())
    .filter(Boolean);
}

function countryCodeList(value) {
  return [...new Set(stringList(value).map(normalizeCountryCode).filter(Boolean))].map(code => {
    if (!isKnownCountryCode(code)) {
      throw new Error(`ALLOWED_COUNTRY_CODES contains an unknown country code: ${code}`);
    }
    return code;
  });
}

function durationSetting(
  name,
  fallbackValue = 24,
  fallbackUnit = 'hours',
  allowedUnits = ACCESS_DURATION_UNITS
) {
  const unit = process.env[`${name}_UNIT`] || fallbackUnit;
  if (!allowedUnits.has(unit)) {
    throw new Error(`${name}_UNIT must be one of: ${[...allowedUnits].join(', ')}`);
  }
  return {
    value: envInteger(`${name}_VALUE`, fallbackValue, { min: 1, max: 1000 }),
    unit
  };
}

function accessDuration(prefix, fallbackValue = 24, fallbackUnit = 'hours') {
  return durationSetting(`${prefix}_ACCESS_DURATION`, fallbackValue, fallbackUnit);
}

function verificationLimits(prefix) {
  return {
    ipRetryInterval: durationSetting(
      `${prefix}_IP_RETRY_INTERVAL`,
      1,
      'minutes',
      RETRY_INTERVAL_UNITS
    ),
    reverifyDuration: durationSetting(`${prefix}_REVERIFY_DURATION`)
  };
}

function bandwidthProfiles(legacyDownloadSpeedMbps, legacyUploadSpeedMbps) {
  return Object.fromEntries(QUOTA_METHODS.map(({ method, prefix }) => [method, {
    downloadSpeedMbps: envIntegerWithLegacy(
      `${prefix}_DOWNLOAD_SPEED_LIMIT_MBPS`,
      'DOWNLOAD_SPEED_LIMIT_MBPS',
      legacyDownloadSpeedMbps,
      { min: 0, max: 100000 }
    ),
    uploadSpeedMbps: envIntegerWithLegacy(
      `${prefix}_UPLOAD_SPEED_LIMIT_MBPS`,
      'UPLOAD_SPEED_LIMIT_MBPS',
      legacyUploadSpeedMbps,
      { min: 0, max: 100000 }
    ),
    quotaPeriod: envOptionAlias(`${prefix}_QUOTA_PERIOD`, null, 'daily', QUOTA_PERIODS),
    downloadQuotaGb: envInteger(`${prefix}_DOWNLOAD_QUOTA_GB`, 0, { min: 0, max: 1000000 }),
    uploadQuotaGb: envInteger(`${prefix}_UPLOAD_QUOTA_GB`, 0, { min: 0, max: 1000000 })
  }]));
}

function envColor(name, fallback) {
  const value = process.env[name] || fallback;
  if (!/^#[0-9a-f]{6}$/iu.test(value)) throw new Error(`${name} must be a six-digit hex color`);
  return value.toUpperCase();
}

function parseGatewayZoneMap(value) {
  const text = String(value || '').trim();
  if (!text) return [];
  return text
    .split(/[;,\n]+/u)
    .map(entry => entry.trim())
    .filter(Boolean)
    .map(entry => {
      const match = entry.match(/^(.+?)\s*=\s*(\d{1,2})$/u);
      if (!match) {
        throw new Error('OPNSENSE_ZONE_MAP entries must use network=zoneId, for example 172.16.3.0/24=1');
      }
      const network = normalizeNetworkList(match[1]);
      try {
        ipv4InNetworkList('0.0.0.0', network);
      } catch (error) {
        throw new Error(`OPNSENSE_ZONE_MAP contains an invalid network "${match[1].trim()}": ${error.message}`);
      }
      const zoneId = Number(match[2]);
      if (!Number.isInteger(zoneId) || zoneId < 0 || zoneId > 19) {
        throw new Error('OPNSENSE_ZONE_MAP zone IDs must be between 0 and 19');
      }
      return { network, zoneId };
    });
}

function gatewayBoolean(name, fallback = false) {
  const value = process.env[name] ?? '';
  if (value == null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function gatewayInteger(name, fallback, options = {}) {
  const raw = process.env[name] ?? '';
  const value = raw == null || raw === '' ? fallback : Number.parseInt(raw, 10);
  if (!Number.isInteger(value)) throw new Error(`${name} must be an integer`);
  if (options.min != null && value < options.min) throw new Error(`${name} must be >= ${options.min}`);
  if (options.max != null && value > options.max) throw new Error(`${name} must be <= ${options.max}`);
  return value;
}

function buildConfig() {
  const installed = isSystemInstalled();
  const configuredAppSecret = process.env.APP_SECRET ?? '';
  const appSecret = configuredAppSecret.length >= 32
    ? configuredAppSecret
    : (installed ? configuredAppSecret : TEMPORARY_APP_SECRET);
  if (installed && appSecret.length < 32) {
    throw new Error('APP_SECRET must contain at least 32 characters. Run the install page or update system.db.');
  }

  const gatewayMode = process.env.GATEWAY_MODE || 'mock';
  if (!GATEWAY_MODES.includes(gatewayMode)) {
    throw new Error(`GATEWAY_MODE must be one of: ${GATEWAY_MODES.join(', ')}`);
  }

  const smsProvider = process.env.SMS_PROVIDER || 'netgsm';
  if (!['netgsm', 'iletimerkezi', 'twilio', 'custom'].includes(smsProvider)) {
    throw new Error('SMS_PROVIDER must be netgsm, iletimerkezi, twilio or custom');
  }
  const telegramMode = process.env.TELEGRAM_MODE || 'webhook';
  if (!TELEGRAM_MODES.has(telegramMode)) {
    throw new Error('TELEGRAM_MODE must be webhook or polling');
  }
  const legacyNotificationFrequency = String(process.env.NOTIFICATION_REPEAT_FREQUENCY || '').trim().toLowerCase();
  const legacyStartupNotification = legacyNotificationFrequency === 'startup';
  const legacyRepeatFrequency = legacyStartupNotification
    ? 'state-change'
    : legacyNotificationFrequency || 'state-change';

  const databasePath = path.resolve(process.env.DATABASE_PATH || './data/hotspot.db');
  const smtpUser = process.env.SMTP_USER || '';
  const smtpConfigured = Boolean(process.env.SMTP_HOST && smtpUser);
  const legacyDownloadSpeedMbps = envInteger('DOWNLOAD_SPEED_LIMIT_MBPS', 0, { min: 0, max: 100000 });
  const legacyUploadSpeedMbps = envInteger('UPLOAD_SPEED_LIMIT_MBPS', 0, { min: 0, max: 100000 });
  const gatewayNetworkFallback = process.env.OPNSENSE_SHAPER_NETWORK || 'any';
  const gatewayShaperInterface = process.env.OPNSENSE_SHAPER_INTERFACE || 'wan';
  const gatewayBaseUrl = (process.env.OPNSENSE_BASE_URL || '').replace(/\/$/, '');
  // TODO(pfSense): Restore OPNSENSE_CAPTIVE_PORTAL_URL when pfSense support resumes.
  const defaultCountryCode = normalizeCountryCode(process.env.DEFAULT_COUNTRY_CODE || '90') || '90';
  if (!COUNTRY_CALLING_CODES.includes(defaultCountryCode)) {
    throw new Error(`DEFAULT_COUNTRY_CODE must be a known country code: ${defaultCountryCode}`);
  }
  const legacyKamusmTimestampEnabled = envBooleanAlias(
    'SYSLOG_KAMUSM_TIMESTAMP_ENABLED',
    'LOG5651_KAMUSM_TIMESTAMP_ENABLED',
    false
  );
  const syslogTimestampMode = envOptionAlias(
    'SYSLOG_TIMESTAMP_MODE',
    'LOG5651_TIMESTAMP_MODE',
    legacyKamusmTimestampEnabled ? 'kamusm' : 'disabled',
    SYSLOG_TIMESTAMP_MODES
  );
  const result = {
    appName: process.env.APP_NAME || 'G-Hotspot',
    installRequired: !installed,
    host: automaticListenHost(process.env.HOST),
    port: automaticListenPort(process.env.PORT),
    appSecret,
    databasePath,
    publicBaseUrl: automaticPublicBaseUrl({
      publicBaseUrl: process.env.PUBLIC_BASE_URL,
      host: process.env.HOST,
      port: process.env.PORT
    }),
    trustProxy: envBoolean('TRUST_PROXY', false),
    defaultCountryCode,
    allowedCountryCodes: countryCodeList(process.env.ALLOWED_COUNTRY_CODES),
    defaultLanguage: normalizeLanguage(process.env.DEFAULT_LANGUAGE, 'en'),
    sessionMinutes: envInteger('SESSION_MINUTES', 720, { min: 1, max: 10080 }),
    portal: {
      titleText: envText('PORTAL_TITLE_TEXT', ''),
      networkLabelText: envText('PORTAL_NETWORK_LABEL_TEXT', DEFAULT_PORTAL_NETWORK_LABEL_TEXT),
      verificationPromptText: envText(
        'PORTAL_VERIFICATION_PROMPT_TEXT',
        DEFAULT_PORTAL_VERIFICATION_PROMPT_TEXT
      ),
      termsText: process.env.PORTAL_TERMS_TEXT || DEFAULT_PORTAL_TERMS_TEXT,
      termsMarkdown: process.env.PORTAL_TERMS_MARKDOWN || DEFAULT_PORTAL_TERMS_MARKDOWN,
      policyMarkdown: process.env.PORTAL_POLICY_MARKDOWN || DEFAULT_PORTAL_POLICY_MARKDOWN,
      privacyMarkdown: process.env.PORTAL_PRIVACY_MARKDOWN || DEFAULT_PORTAL_PRIVACY_MARKDOWN
    },
    appearance: {
      primaryColor: envColor('PORTAL_PRIMARY_COLOR', '#5340CC'),
      primaryHoverColor: envColor('PORTAL_PRIMARY_HOVER_COLOR', '#4530B0'),
      headingColor: envColor('PORTAL_HEADING_COLOR', '#1A1523'),
      textColor: envColor('PORTAL_TEXT_COLOR', '#374151'),
      mutedColor: envColor('PORTAL_MUTED_COLOR', '#6B7280'),
      buttonTextColor: envColor('PORTAL_BUTTON_TEXT_COLOR', '#FFFFFF'),
      inputBackgroundColor: envColor('PORTAL_INPUT_BACKGROUND_COLOR', '#FAFAFA'),
      inputBorderColor: envColor('PORTAL_INPUT_BORDER_COLOR', '#E5E1F8'),
      inputTextColor: envColor('PORTAL_INPUT_TEXT_COLOR', '#1A1523'),
      bodyBackgroundColor: envColor('PORTAL_BODY_BACKGROUND_COLOR', '#F0EEF9'),
      bodyBackgroundOpacity: envInteger('PORTAL_BODY_BACKGROUND_OPACITY', 100, { min: 0, max: 100 }),
      bodyImageOpacity: envInteger('PORTAL_BODY_IMAGE_OPACITY', 100, { min: 0, max: 100 }),
      bodyImageBlur: envInteger('PORTAL_BODY_IMAGE_BLUR', 0, { min: 0, max: 40 }),
      bodyImageAnimationEnabled: envBoolean('PORTAL_BODY_IMAGE_ANIMATION_ENABLED', false),
      cardBackgroundColor: envColor('PORTAL_CARD_BACKGROUND_COLOR', '#FFFFFF'),
      cardBackgroundOpacity: envInteger('PORTAL_CARD_BACKGROUND_OPACITY', 100, { min: 0, max: 100 }),
      cardBorderWidth: envInteger('PORTAL_CARD_BORDER_WIDTH', 1, { min: 0, max: 20 }),
      cardBorderColor: envColor('PORTAL_CARD_BORDER_COLOR', '#000000'),
      cardBorderOpacity: envInteger('PORTAL_CARD_BORDER_OPACITY', 7, { min: 0, max: 100 }),
      cardBorderRadius: envInteger('PORTAL_CARD_BORDER_RADIUS', 18, { min: 0, max: 80 }),
      cardShadowOffsetX: envInteger('PORTAL_CARD_SHADOW_OFFSET_X', 0, { min: -80, max: 80 }),
      cardShadowOffsetY: envInteger('PORTAL_CARD_SHADOW_OFFSET_Y', 4, { min: -80, max: 80 }),
      cardShadowBlur: envInteger('PORTAL_CARD_SHADOW_BLUR', 24, { min: 0, max: 160 }),
      cardShadowSpread: envInteger('PORTAL_CARD_SHADOW_SPREAD', 0, { min: -80, max: 80 }),
      cardShadowColor: envColor('PORTAL_CARD_SHADOW_COLOR', '#6366F1'),
      cardShadowOpacity: envInteger('PORTAL_CARD_SHADOW_OPACITY', 10, { min: 0, max: 100 }),
      cardImageOpacity: envInteger('PORTAL_CARD_IMAGE_OPACITY', 100, { min: 0, max: 100 }),
      cardImageBlur: envInteger('PORTAL_CARD_IMAGE_BLUR', 0, { min: 0, max: 40 }),
      cardBackdropBlur: envInteger('PORTAL_CARD_BACKDROP_BLUR', 0, { min: 0, max: 40 })
    },
    voucher: {
      enabled: envBoolean('VOUCHER_ENABLED', true)
    },
    adminApproval: {
      enabled: envBoolean('ADMIN_APPROVAL_ENABLED', false),
      accessDuration: accessDuration('ADMIN_APPROVAL'),
      limits: verificationLimits('ADMIN_APPROVAL'),
      requestTtlMinutes: envInteger('ADMIN_APPROVAL_REQUEST_TTL_MINUTES', 1440, { min: 1, max: 10080 }),
      approveText: process.env.ADMIN_APPROVAL_APPROVE_TEXT ||
        'Your internet access request was approved.',
      rejectText: process.env.ADMIN_APPROVAL_REJECT_TEXT ||
        'Your internet access request was rejected.'
    },
    nvi: {
      enabled: envBoolean('NVI_ENABLED', false),
      sendSmsCode: envBoolean('NVI_SEND_SMS_CODE', false),
      accessDuration: accessDuration('NVI'),
      limits: verificationLimits('NVI'),
      username: process.env.NVI_USERNAME || '',
      password: process.env.NVI_PASSWORD || '',
      timeoutSeconds: envInteger('NVI_TIMEOUT_SECONDS', 30, { min: 3, max: 60 })
    },
    admin: {
      enabled: installed && Boolean(process.env.ADMIN_PASSWORD),
      username: process.env.ADMIN_USERNAME || 'admin',
      password: process.env.ADMIN_PASSWORD || '',
      sessionHours: envInteger('ADMIN_SESSION_HOURS', 12, { min: 1, max: 168 })
    },
    gateway: {
      mode: gatewayMode,
      baseUrl: gatewayBaseUrl,
      captivePortalUrl: '',
      zoneId: envInteger('OPNSENSE_ZONE_ID', 0, { min: 0, max: 19 }),
      zoneMap: parseGatewayZoneMap(process.env.OPNSENSE_ZONE_MAP),
      apiKey: process.env.OPNSENSE_API_KEY || '',
      apiSecret: process.env.OPNSENSE_API_SECRET || '',
      tlsRejectUnauthorized: gatewayBoolean('OPNSENSE_TLS_REJECT_UNAUTHORIZED', true),
      syncEnabled: gatewayBoolean('OPNSENSE_SYNC_ENABLED', true),
      syncIntervalSeconds: gatewayInteger('OPNSENSE_SYNC_INTERVAL_SECONDS', 10, { min: 5, max: 3600 }),
      keaLeaseSyncEnabled: gatewayBoolean('OPNSENSE_KEA_LEASE_SYNC_ENABLED', true),
      dhcpLeaseSyncEnabled: gatewayBoolean('OPNSENSE_KEA_LEASE_SYNC_ENABLED', true),
      cookieIpMoveEnabled: gatewayBoolean('OPNSENSE_COOKIE_IP_MOVE_ENABLED', true),
      sessionCookieRequired: gatewayBoolean('OPNSENSE_SESSION_COOKIE_REQUIRED', false),
      shaperInterface: gatewayShaperInterface,
      shaperNetwork: gatewayNetworkFallback,
      downloadSpeedMbps: legacyDownloadSpeedMbps,
      uploadSpeedMbps: legacyUploadSpeedMbps,
      bandwidthProfiles: bandwidthProfiles(legacyDownloadSpeedMbps, legacyUploadSpeedMbps)
    },
    law5651: {
      enabled: envBooleanAlias('SYSLOG_ENABLED', 'LOG5651_ENABLED', false),
      networks: normalizeNetworkList(
        envAlias('SYSLOG_NETWORKS', 'LOG5651_NETWORKS', gatewayNetworkFallback)
      ),
      timeZone: normalizeTimeZone(envAlias('SYSLOG_TIME_ZONE', 'LOG5651_TIME_ZONE', '')),
      retentionDays: envIntegerAlias('SYSLOG_RETENTION_DAYS', 'LOG5651_RETENTION_DAYS', 730, { min: 1, max: 1000 }),
      exportDirectory: path.resolve(
        envAlias('SYSLOG_EXPORT_DIR', 'LOG5651_EXPORT_DIR', path.join(path.dirname(databasePath), 'syslog'))
      ),
      exportZipEnabled: envBooleanAlias('SYSLOG_EXPORT_ZIP_ENABLED', 'LOG5651_EXPORT_ZIP_ENABLED', false),
      exportDeleteSourceAfterZip: envBooleanAlias(
        'SYSLOG_EXPORT_DELETE_SOURCE_AFTER_ZIP',
        'LOG5651_EXPORT_DELETE_SOURCE_AFTER_ZIP',
        false
      ),
      storageAlertPercent: envIntegerAlias('SYSLOG_STORAGE_ALERT_PERCENT', 'LOG5651_STORAGE_ALERT_PERCENT', 85, { min: 1, max: 100 }),
      storageBlockPercent: envIntegerAlias('SYSLOG_STORAGE_BLOCK_PERCENT', 'LOG5651_STORAGE_BLOCK_PERCENT', 99, { min: 1, max: 100 }),
      timestampMode: syslogTimestampMode,
      kamusmTimestampEnabled: syslogTimestampMode === 'kamusm',
      kamusmUser: envAlias('SYSLOG_KAMUSM_USER', 'LOG5651_KAMUSM_USER', ''),
      kamusmPassword: envAlias('SYSLOG_KAMUSM_PASSWORD', 'LOG5651_KAMUSM_PASSWORD', ''),
      kamusmUrl: envAlias('SYSLOG_KAMUSM_URL', 'LOG5651_KAMUSM_URL', 'http://zd.kamusm.gov.tr'),
      kamusmTimeoutSeconds: envIntegerAlias('SYSLOG_KAMUSM_TIMEOUT_SECONDS', 'LOG5651_KAMUSM_TIMEOUT_SECONDS', 60, { min: 5, max: 300 }),
      timestampCommand: '',
      timestampUrl: envAlias('SYSLOG_TIMESTAMP_URL', 'LOG5651_TIMESTAMP_URL', ''),
      timestampHeadersJson: envJsonObjectAlias('SYSLOG_TIMESTAMP_HEADERS_JSON', 'LOG5651_TIMESTAMP_HEADERS_JSON', ''),
      timestampCertRequest: envBooleanAlias('SYSLOG_TIMESTAMP_CERT_REQUEST', 'LOG5651_TIMESTAMP_CERT_REQUEST', true),
      timestampTimeoutSeconds: envIntegerAlias('SYSLOG_TIMESTAMP_TIMEOUT_SECONDS', 'LOG5651_TIMESTAMP_TIMEOUT_SECONDS', 60, { min: 5, max: 300 }),
      timestampApiUrl: envAlias('SYSLOG_TIMESTAMP_API_URL', 'LOG5651_TIMESTAMP_API_URL', ''),
      timestampApiKey: envAlias('SYSLOG_TIMESTAMP_API_KEY', 'LOG5651_TIMESTAMP_API_KEY', ''),
      timestampApiKeyHeader: envAlias('SYSLOG_TIMESTAMP_API_KEY_HEADER', 'LOG5651_TIMESTAMP_API_KEY_HEADER', 'Authorization'),
      timestampApiKeyPrefix: envAliasPreserveEmpty('SYSLOG_TIMESTAMP_API_KEY_PREFIX', 'LOG5651_TIMESTAMP_API_KEY_PREFIX', 'Bearer'),
      timestampApiTimeoutSeconds: envIntegerAlias('SYSLOG_TIMESTAMP_API_TIMEOUT_SECONDS', 'LOG5651_TIMESTAMP_API_TIMEOUT_SECONDS', 60, { min: 5, max: 300 }),
      archiveSigningKey: appSecret,
      signatureCommand: '',
      signatureTimeoutSeconds: 60,
      backupEnabled: false,
      backupDirectories: [],
      backupReadonly: false,
      backupImmutableCommand: '',
      backupWormRequired: false,
      autoExportEnabled: true,
      autoExportInterval: syslogAutoExportInterval(envAlias(
        'SYSLOG_AUTO_EXPORT_INTERVAL',
        'LOG5651_AUTO_EXPORT_INTERVAL',
        'daily'
      )),
      autoExportIntervalMinutes: 1440,
      syslogEnabled: envBooleanAlias('SYSLOG_RECEIVER_ENABLED', 'LOG5651_SYSLOG_ENABLED', false),
      syslogHost: envAlias('SYSLOG_RECEIVER_HOST', 'LOG5651_SYSLOG_HOST', '0.0.0.0'),
      syslogPort: envIntegerAlias('SYSLOG_RECEIVER_PORT', 'LOG5651_SYSLOG_PORT', 5514, { min: 1, max: 65535 }),
      remoteMirrorEnabled: false,
      remoteMirrorHost: '',
      remoteMirrorPort: 514,
      remoteMirrorProtocol: 'udp',
      healthCheckIntervalSeconds: envIntegerAlias('SYSLOG_HEALTH_CHECK_INTERVAL_SECONDS', 'LOG5651_HEALTH_CHECK_INTERVAL_SECONDS', 60, { min: 10, max: 3600 }),
      clockSkewAlertSeconds: envIntegerAlias('SYSLOG_CLOCK_SKEW_ALERT_SECONDS', 'LOG5651_CLOCK_SKEW_ALERT_SECONDS', 120, { min: 1, max: 86400 }),
      ntpCheckEnabled: envBooleanAlias('SYSLOG_NTP_CHECK_ENABLED', 'LOG5651_NTP_CHECK_ENABLED', true)
    },
    trafficLogs: {
      enabled: envBoolean('TRAFFIC_LOGS_ENABLED', true),
      retentionMinutes: trafficLogRetentionMinutesEnv(),
      resolveDomains: envBoolean('TRAFFIC_LOGS_RESOLVE_DOMAINS', true),
      liveRefreshSeconds: envInteger('TRAFFIC_LOGS_LIVE_REFRESH_SECONDS', 5, { min: 2, max: 60 }),
      logDirectory: path.resolve(path.dirname(databasePath), 'traffic-records')
    },
    notifications: {
      emailEnabled: envBoolean('NOTIFICATION_EMAIL_ENABLED', true),
      emailRecipients: process.env.NOTIFICATION_EMAIL_RECIPIENTS || '',
      emailRepeatFrequency: envOptionAlias(
        'NOTIFICATION_EMAIL_REPEAT_FREQUENCY',
        null,
        legacyRepeatFrequency,
        NOTIFICATION_FREQUENCIES
      ),
      emailStartupEnabled: envBoolean('NOTIFICATION_EMAIL_STARTUP_ENABLED', legacyStartupNotification),
      smsEnabled: envBoolean('NOTIFICATION_SMS_ENABLED', true),
      smsRecipients: process.env.NOTIFICATION_SMS_RECIPIENTS || '',
      smsRepeatFrequency: envOptionAlias(
        'NOTIFICATION_SMS_REPEAT_FREQUENCY',
        null,
        legacyRepeatFrequency,
        NOTIFICATION_FREQUENCIES
      ),
      smsStartupEnabled: envBoolean('NOTIFICATION_SMS_STARTUP_ENABLED', legacyStartupNotification),
      telegramEnabled: envBoolean('NOTIFICATION_TELEGRAM_ENABLED', true),
      telegramRecipients: process.env.NOTIFICATION_TELEGRAM_RECIPIENTS || '',
      telegramRepeatFrequency: envOptionAlias(
        'NOTIFICATION_TELEGRAM_REPEAT_FREQUENCY',
        null,
        legacyRepeatFrequency,
        NOTIFICATION_FREQUENCIES
      ),
      telegramStartupEnabled: envBoolean('NOTIFICATION_TELEGRAM_STARTUP_ENABLED', legacyStartupNotification),
      androidEnabled: envBoolean('NOTIFICATION_ANDROID_ENABLED', false),
      androidRepeatFrequency: envOptionAlias(
        'NOTIFICATION_ANDROID_REPEAT_FREQUENCY',
        null,
        legacyRepeatFrequency,
        NOTIFICATION_FREQUENCIES
      ),
      androidStartupEnabled: envBoolean('NOTIFICATION_ANDROID_STARTUP_ENABLED', legacyStartupNotification),
      androidPollIntervalSeconds: envInteger('ANDROID_APP_POLL_INTERVAL_SECONDS', 20, { min: 5, max: 300 }),
      androidFcmServiceAccountFile: envText('ANDROID_FCM_SERVICE_ACCOUNT_FILE', '').trim(),
      syslogEmailTemplateMarkdown: process.env.NOTIFICATION_SYSLOG_EMAIL_TEMPLATE_MARKDOWN ||
        DEFAULT_SYSLOG_NOTIFICATION_EMAIL_MARKDOWN,
      syslogSmsTemplate: process.env.NOTIFICATION_SYSLOG_SMS_TEMPLATE ||
        DEFAULT_SYSLOG_NOTIFICATION_SMS_TEMPLATE,
      syslogTelegramTemplate: process.env.NOTIFICATION_SYSLOG_TELEGRAM_TEMPLATE ||
        DEFAULT_SYSLOG_NOTIFICATION_TELEGRAM_TEMPLATE,
      systemEmailTemplateMarkdown: process.env.NOTIFICATION_SYSTEM_EMAIL_TEMPLATE_MARKDOWN ||
        DEFAULT_SYSTEM_NOTIFICATION_EMAIL_MARKDOWN,
      systemSmsTemplate: process.env.NOTIFICATION_SYSTEM_SMS_TEMPLATE ||
        DEFAULT_SYSTEM_NOTIFICATION_SMS_TEMPLATE,
      systemTelegramTemplate: process.env.NOTIFICATION_SYSTEM_TELEGRAM_TEMPLATE ||
        DEFAULT_SYSTEM_NOTIFICATION_TELEGRAM_TEMPLATE,
      emailSyslogStorageEnabled: envBooleanAlias(
        'NOTIFICATION_EMAIL_SYSLOG_STORAGE_ENABLED',
        'NOTIFICATION_SYSLOG_STORAGE_ENABLED',
        true
      ),
      smsSyslogStorageEnabled: envBooleanAlias(
        'NOTIFICATION_SMS_SYSLOG_STORAGE_ENABLED',
        'NOTIFICATION_SYSLOG_STORAGE_ENABLED',
        true
      ),
      telegramSyslogStorageEnabled: envBooleanAlias(
        'NOTIFICATION_TELEGRAM_SYSLOG_STORAGE_ENABLED',
        'NOTIFICATION_SYSLOG_STORAGE_ENABLED',
        true
      ),
      androidSyslogStorageEnabled: envBooleanAlias(
        'NOTIFICATION_ANDROID_SYSLOG_STORAGE_ENABLED',
        'NOTIFICATION_SYSLOG_STORAGE_ENABLED',
        true
      ),
      emailSyslogKamusmSuccessEnabled: envBooleanAlias(
        'NOTIFICATION_EMAIL_SYSLOG_KAMUSM_SUCCESS_ENABLED',
        'NOTIFICATION_SYSLOG_KAMUSM_SUCCESS_ENABLED',
        true
      ),
      smsSyslogKamusmSuccessEnabled: envBooleanAlias(
        'NOTIFICATION_SMS_SYSLOG_KAMUSM_SUCCESS_ENABLED',
        'NOTIFICATION_SYSLOG_KAMUSM_SUCCESS_ENABLED',
        true
      ),
      telegramSyslogKamusmSuccessEnabled: envBooleanAlias(
        'NOTIFICATION_TELEGRAM_SYSLOG_KAMUSM_SUCCESS_ENABLED',
        'NOTIFICATION_SYSLOG_KAMUSM_SUCCESS_ENABLED',
        true
      ),
      androidSyslogKamusmSuccessEnabled: envBooleanAlias(
        'NOTIFICATION_ANDROID_SYSLOG_KAMUSM_SUCCESS_ENABLED',
        'NOTIFICATION_SYSLOG_KAMUSM_SUCCESS_ENABLED',
        true
      ),
      emailSyslogKamusmFailureEnabled: envBooleanAlias(
        'NOTIFICATION_EMAIL_SYSLOG_KAMUSM_FAILURE_ENABLED',
        'NOTIFICATION_SYSLOG_KAMUSM_FAILURE_ENABLED',
        true
      ),
      smsSyslogKamusmFailureEnabled: envBooleanAlias(
        'NOTIFICATION_SMS_SYSLOG_KAMUSM_FAILURE_ENABLED',
        'NOTIFICATION_SYSLOG_KAMUSM_FAILURE_ENABLED',
        true
      ),
      telegramSyslogKamusmFailureEnabled: envBooleanAlias(
        'NOTIFICATION_TELEGRAM_SYSLOG_KAMUSM_FAILURE_ENABLED',
        'NOTIFICATION_SYSLOG_KAMUSM_FAILURE_ENABLED',
        true
      ),
      androidSyslogKamusmFailureEnabled: envBooleanAlias(
        'NOTIFICATION_ANDROID_SYSLOG_KAMUSM_FAILURE_ENABLED',
        'NOTIFICATION_SYSLOG_KAMUSM_FAILURE_ENABLED',
        true
      ),
      emailAdminApprovalEnabled: envBooleanAlias(
        'NOTIFICATION_EMAIL_ADMIN_APPROVAL_ENABLED',
        'NOTIFICATION_ADMIN_APPROVAL_ENABLED',
        true
      ),
      smsAdminApprovalEnabled: envBooleanAlias(
        'NOTIFICATION_SMS_ADMIN_APPROVAL_ENABLED',
        'NOTIFICATION_ADMIN_APPROVAL_ENABLED',
        true
      ),
      androidAdminApprovalEnabled: envBooleanAlias(
        'NOTIFICATION_ANDROID_ADMIN_APPROVAL_ENABLED',
        'NOTIFICATION_ADMIN_APPROVAL_ENABLED',
        true
      ),
      emailSystemStartupEnabled: envBoolean('NOTIFICATION_EMAIL_SYSTEM_STARTUP_ENABLED', false),
      smsSystemStartupEnabled: envBoolean('NOTIFICATION_SMS_SYSTEM_STARTUP_ENABLED', false),
      telegramSystemStartupEnabled: envBoolean('NOTIFICATION_TELEGRAM_SYSTEM_STARTUP_ENABLED', false),
      androidSystemStartupEnabled: envBoolean('NOTIFICATION_ANDROID_SYSTEM_STARTUP_ENABLED', false),
      emailOpnsenseDownEnabled: envBoolean('NOTIFICATION_EMAIL_OPNSENSE_DOWN_ENABLED', false),
      smsOpnsenseDownEnabled: envBoolean('NOTIFICATION_SMS_OPNSENSE_DOWN_ENABLED', false),
      telegramOpnsenseDownEnabled: envBoolean('NOTIFICATION_TELEGRAM_OPNSENSE_DOWN_ENABLED', false),
      androidOpnsenseDownEnabled: envBoolean('NOTIFICATION_ANDROID_OPNSENSE_DOWN_ENABLED', false),
      emailUserVerifiedEnabled: envBoolean('NOTIFICATION_EMAIL_USER_VERIFIED_ENABLED', false),
      smsUserVerifiedEnabled: envBoolean('NOTIFICATION_SMS_USER_VERIFIED_ENABLED', false),
      telegramUserVerifiedEnabled: envBoolean('NOTIFICATION_TELEGRAM_USER_VERIFIED_ENABLED', false),
      androidUserVerifiedEnabled: envBoolean('NOTIFICATION_ANDROID_USER_VERIFIED_ENABLED', false),
      emailAccessExpiredEnabled: envBoolean('NOTIFICATION_EMAIL_ACCESS_EXPIRED_ENABLED', false),
      smsAccessExpiredEnabled: envBoolean('NOTIFICATION_SMS_ACCESS_EXPIRED_ENABLED', false),
      telegramAccessExpiredEnabled: envBoolean('NOTIFICATION_TELEGRAM_ACCESS_EXPIRED_ENABLED', false),
      androidAccessExpiredEnabled: envBoolean('NOTIFICATION_ANDROID_ACCESS_EXPIRED_ENABLED', false),
      emailAdminLoginEnabled: envBoolean('NOTIFICATION_EMAIL_ADMIN_LOGIN_ENABLED', false),
      smsAdminLoginEnabled: envBoolean('NOTIFICATION_SMS_ADMIN_LOGIN_ENABLED', false),
      telegramAdminLoginEnabled: envBoolean('NOTIFICATION_TELEGRAM_ADMIN_LOGIN_ENABLED', false),
      androidAdminLoginEnabled: envBoolean('NOTIFICATION_ANDROID_ADMIN_LOGIN_ENABLED', false),
      emailAdminLoginFailedEnabled: envBoolean('NOTIFICATION_EMAIL_ADMIN_LOGIN_FAILED_ENABLED', false),
      smsAdminLoginFailedEnabled: envBoolean('NOTIFICATION_SMS_ADMIN_LOGIN_FAILED_ENABLED', false),
      telegramAdminLoginFailedEnabled: envBoolean('NOTIFICATION_TELEGRAM_ADMIN_LOGIN_FAILED_ENABLED', false),
      androidAdminLoginFailedEnabled: envBoolean('NOTIFICATION_ANDROID_ADMIN_LOGIN_FAILED_ENABLED', false),
      syslogStorageEnabled: envBoolean('NOTIFICATION_SYSLOG_STORAGE_ENABLED', true),
      syslogKamusmSuccessEnabled: envBoolean('NOTIFICATION_SYSLOG_KAMUSM_SUCCESS_ENABLED', true),
      syslogKamusmFailureEnabled: envBoolean('NOTIFICATION_SYSLOG_KAMUSM_FAILURE_ENABLED', true),
      adminApprovalEnabled: envBoolean('NOTIFICATION_ADMIN_APPROVAL_ENABLED', true),
      adminApprovalEmailTemplateMarkdown: process.env.NOTIFICATION_ADMIN_APPROVAL_EMAIL_TEMPLATE_MARKDOWN ||
        DEFAULT_ADMIN_APPROVAL_NOTIFICATION_EMAIL_MARKDOWN,
      adminApprovalSmsTemplate: process.env.NOTIFICATION_ADMIN_APPROVAL_SMS_TEMPLATE ||
        DEFAULT_ADMIN_APPROVAL_NOTIFICATION_SMS_TEMPLATE
    },
    smtp: {
      enabled: envBoolean('EMAIL_ENABLED', true) && smtpConfigured,
      configured: smtpConfigured,
      accessDuration: accessDuration('EMAIL'),
      limits: verificationLimits('EMAIL'),
      host: process.env.SMTP_HOST || '',
      port: envInteger('SMTP_PORT', 587, { min: 1, max: 65535 }),
      secure: envBoolean('SMTP_SECURE', false),
      starttls: envBoolean('SMTP_STARTTLS', true),
      user: smtpUser,
      pass: process.env.SMTP_PASS || '',
      from: smtpUser
    },
    whatsapp: {
      enabled: envBoolean('WHATSAPP_ENABLED', true) && Boolean(
        process.env.WHATSAPP_PHONE_NUMBER_ID &&
        process.env.WHATSAPP_ACCESS_TOKEN &&
        process.env.WHATSAPP_TEMPLATE_NAME
      ),
      configured: Boolean(
        process.env.WHATSAPP_PHONE_NUMBER_ID &&
        process.env.WHATSAPP_ACCESS_TOKEN &&
        process.env.WHATSAPP_TEMPLATE_NAME
      ),
      accessDuration: accessDuration('WHATSAPP'),
      limits: verificationLimits('WHATSAPP'),
      businessNumber: (process.env.WHATSAPP_BUSINESS_NUMBER || '').replace(/\D/g, ''),
      phoneNumberId: process.env.WHATSAPP_PHONE_NUMBER_ID || '',
      accessToken: process.env.WHATSAPP_ACCESS_TOKEN || '',
      templateName: process.env.WHATSAPP_TEMPLATE_NAME || '',
      templateLanguage: process.env.WHATSAPP_TEMPLATE_LANGUAGE || 'en',
      templateButton: envBoolean('WHATSAPP_TEMPLATE_BUTTON', true),
      graphApiVersion: process.env.META_GRAPH_API_VERSION || 'v22.0',
      graphBaseUrl: process.env.META_GRAPH_BASE_URL || 'https://graph.facebook.com',
      verifyToken: process.env.WHATSAPP_VERIFY_TOKEN || '',
      metaAppSecret: process.env.META_APP_SECRET || ''
    },
    telegram: {
      enabled: envBoolean('TELEGRAM_ENABLED', false) && Boolean(
        process.env.TELEGRAM_BOT_TOKEN &&
        process.env.TELEGRAM_BOT_USERNAME
      ),
      configured: Boolean(
        process.env.TELEGRAM_BOT_TOKEN &&
        process.env.TELEGRAM_BOT_USERNAME
      ),
      accessDuration: accessDuration('TELEGRAM'),
      limits: verificationLimits('TELEGRAM'),
      mode: telegramMode,
      botToken: process.env.TELEGRAM_BOT_TOKEN || '',
      botUsername: String(process.env.TELEGRAM_BOT_USERNAME || '').replace(/^@/u, ''),
      webhookSecret: process.env.TELEGRAM_WEBHOOK_SECRET || '',
      botApiBaseUrl: (process.env.TELEGRAM_BOT_API_BASE_URL || 'https://api.telegram.org').replace(/\/$/, ''),
      otpMinutes: envInteger('TELEGRAM_OTP_MINUTES', 5, { min: 1, max: 30 }),
      template: process.env.TELEGRAM_MESSAGE_TEMPLATE ||
        '{appName} Telegram access code: {code}. The code is valid for {minutes} minutes.'
    },
    sms: {
      enabled: envBoolean('SMS_ENABLED', false),
      accessDuration: accessDuration('SMS'),
      limits: verificationLimits('SMS'),
      provider: smsProvider,
      sender: process.env.SMS_SENDER || configAppName(process.env.APP_NAME),
      template: process.env.SMS_MESSAGE_TEMPLATE ||
        '{appName} access code: {code}. The code is valid for {minutes} minutes.',
      otpMinutes: envInteger('SMS_OTP_MINUTES', 5, { min: 1, max: 30 }),
      netgsm: {
        usercode: process.env.NETGSM_USERCODE || '',
        password: process.env.NETGSM_PASSWORD || '',
        header: process.env.NETGSM_HEADER || ''
      },
      iletimerkezi: {
        apiKey: process.env.ILETIMERKEZI_API_KEY || '',
        apiSecret: process.env.ILETIMERKEZI_API_SECRET || '',
        sender: process.env.ILETIMERKEZI_SENDER || ''
      },
      twilio: {
        accountSid: process.env.TWILIO_ACCOUNT_SID || '',
        authToken: process.env.TWILIO_AUTH_TOKEN || '',
        from: process.env.TWILIO_FROM || ''
      },
      custom: {
        url: process.env.CUSTOM_SMS_URL || '',
        method: (process.env.CUSTOM_SMS_METHOD || 'POST').toUpperCase(),
        authorization: process.env.CUSTOM_SMS_AUTHORIZATION || '',
        headersJson: process.env.CUSTOM_SMS_HEADERS_JSON || '{}',
        bodyTemplate: process.env.CUSTOM_SMS_BODY_TEMPLATE ||
          '{"to":"{phone}","sender":"{sender}","message":"{message}","code":"{code}"}',
        successPath: process.env.CUSTOM_SMS_SUCCESS_PATH || ''
      }
    }
  };

  result.syslog = result.law5651;
  result.law5651.autoExportIntervalMinutes = syslogAutoExportIntervalMinutes(result.law5651.autoExportInterval);

  if (result.law5651.timestampMode === 'kamusm') {
    if (!String(result.law5651.kamusmUser || '').trim()) {
      throw new Error('SYSLOG_KAMUSM_USER is required when KamuSM timestamping is enabled');
    }
    if (!String(result.law5651.kamusmPassword || '').trim()) {
      throw new Error('SYSLOG_KAMUSM_PASSWORD is required when KamuSM timestamping is enabled');
    }
  }
  if (result.law5651.timestampMode === 'rfc3161' && !String(result.law5651.timestampUrl || '').trim()) {
    throw new Error('SYSLOG_TIMESTAMP_URL is required when RFC3161 timestamping is enabled');
  }
  if (result.law5651.timestampMode === 'api-key') {
    if (!String(result.law5651.timestampApiUrl || '').trim()) {
      throw new Error('SYSLOG_TIMESTAMP_API_URL is required when API key timestamping is enabled');
    }
    if (!String(result.law5651.timestampApiKey || '').trim()) {
      throw new Error('SYSLOG_TIMESTAMP_API_KEY is required when API key timestamping is enabled');
    }
    if (!String(result.law5651.timestampApiKeyHeader || '').trim()) {
      throw new Error('SYSLOG_TIMESTAMP_API_KEY_HEADER is required when API key timestamping is enabled');
    }
  }

  if (result.sms.enabled) {
    const required = {
      netgsm: [result.sms.netgsm.usercode, result.sms.netgsm.password, result.sms.netgsm.header || result.sms.sender],
      iletimerkezi: [
        result.sms.iletimerkezi.apiKey,
        result.sms.iletimerkezi.apiSecret,
        result.sms.iletimerkezi.sender || result.sms.sender
      ],
      twilio: [result.sms.twilio.accountSid, result.sms.twilio.authToken, result.sms.twilio.from],
      custom: [result.sms.custom.url, result.sms.custom.bodyTemplate]
    }[result.sms.provider];
    if (required.some(value => !String(value || '').trim())) {
      throw new Error(`SMS_PROVIDER ${result.sms.provider} is enabled but its settings are incomplete`);
    }
  }
  if (result.smtp.enabled && result.smtp.secure && result.smtp.starttls) {
    throw new Error('SMTP_SECURE and SMTP_STARTTLS cannot both be enabled');
  }
  return result;
}

function configAppName(value) {
  return String(value || 'GHotspot').replace(/[^A-Za-z0-9]/g, '').slice(0, 11) || 'GHotspot';
}

function replaceObject(target, source) {
  for (const key of Object.keys(target)) {
    if (!(key in source)) delete target[key];
  }
  for (const [key, value] of Object.entries(source)) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      if (!target[key] || typeof target[key] !== 'object') target[key] = {};
      replaceObject(target[key], value);
    } else target[key] = value;
  }
}

export const config = buildConfig();

export function reloadConfig({ preserveKeys = [], loadSystem = false } = {}) {
  if (loadSystem) loadSystemSettingsIntoEnv({ preserveKeys });
  const next = buildConfig();
  replaceObject(config, next);
  if (!config.installRequired &&
      config.gateway.mode === 'opnsense-api' &&
      (!config.gateway.baseUrl || !config.gateway.apiKey || !config.gateway.apiSecret)) {
    throw new Error('Gateway API mode requires OPNSENSE_BASE_URL, OPNSENSE_API_KEY and OPNSENSE_API_SECRET');
  }
  return config;
}

reloadConfig({ loadSystem: true });
