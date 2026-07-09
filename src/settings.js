import fs from 'node:fs';
import path from 'node:path';
import { readEnvFile, updateEnvFile } from './lib/env.js';
import { availableLanguageCodes } from './lib/languages.js';
import { automaticListenHost, automaticListenPort, automaticPublicBaseUrl } from './lib/network.js';
import { generateSecret } from './lib/security.js';
import {
  DEFAULT_ADMIN_APPROVAL_NOTIFICATION_EMAIL_MARKDOWN,
  DEFAULT_ADMIN_APPROVAL_NOTIFICATION_SMS_TEMPLATE,
  DEFAULT_PORTAL_NETWORK_LABEL_TEXT,
  DEFAULT_PORTAL_POLICY_MARKDOWN,
  DEFAULT_PORTAL_PRIVACY_MARKDOWN,
  DEFAULT_PORTAL_TERMS_MARKDOWN,
  DEFAULT_PORTAL_TERMS_TEXT,
  DEFAULT_PORTAL_VERIFICATION_PROMPT_TEXT,
  DEFAULT_SYSTEM_NOTIFICATION_EMAIL_MARKDOWN,
  DEFAULT_SYSTEM_NOTIFICATION_SMS_TEMPLATE,
  DEFAULT_SYSTEM_NOTIFICATION_TELEGRAM_TEMPLATE,
  DEFAULT_SYSLOG_NOTIFICATION_EMAIL_MARKDOWN,
  DEFAULT_SYSLOG_NOTIFICATION_SMS_TEMPLATE,
  DEFAULT_SYSLOG_NOTIFICATION_TELEGRAM_TEMPLATE,
  reloadConfig,
  systemTimeZone
} from './config.js';
import {
  isSystemInstalled,
  loadSystemSettingsIntoEnv,
  markSystemInstalled,
  readSystemMeta,
  readSystemSettings,
  replaceSystemMeta,
  replaceSystemSettings,
  writeSystemSettings
} from './system.js';
import { QUOTA_METHODS, QUOTA_PERIODS } from './services/quotas.js';

const field = (key, label, options = {}) => ({ key, label, type: 'text', ...options });

function timeZoneOptions() {
  const values = typeof Intl.supportedValuesOf === 'function'
    ? Intl.supportedValuesOf('timeZone')
    : [];
  return [...new Set(['UTC', systemTimeZone(), ...values])].filter(Boolean).sort();
}

const legacySettingKeys = new Map([
  ['SYSLOG_ENABLED', 'LOG5651_ENABLED'],
  ['SYSLOG_NETWORKS', 'LOG5651_NETWORKS'],
  ['SYSLOG_TIME_ZONE', 'LOG5651_TIME_ZONE'],
  ['SYSLOG_RETENTION_DAYS', 'LOG5651_RETENTION_DAYS'],
  ['SYSLOG_EXPORT_DIR', 'LOG5651_EXPORT_DIR'],
  ['SYSLOG_AUTO_EXPORT_INTERVAL', 'LOG5651_AUTO_EXPORT_INTERVAL'],
  ['SYSLOG_STORAGE_ALERT_PERCENT', 'LOG5651_STORAGE_ALERT_PERCENT'],
  ['SYSLOG_STORAGE_BLOCK_PERCENT', 'LOG5651_STORAGE_BLOCK_PERCENT'],
  ['SYSLOG_TIMESTAMP_MODE', 'LOG5651_TIMESTAMP_MODE'],
  ['SYSLOG_TIMESTAMP_URL', 'LOG5651_TIMESTAMP_URL'],
  ['SYSLOG_TIMESTAMP_HEADERS_JSON', 'LOG5651_TIMESTAMP_HEADERS_JSON'],
  ['SYSLOG_TIMESTAMP_CERT_REQUEST', 'LOG5651_TIMESTAMP_CERT_REQUEST'],
  ['SYSLOG_TIMESTAMP_TIMEOUT_SECONDS', 'LOG5651_TIMESTAMP_TIMEOUT_SECONDS'],
  ['SYSLOG_TIMESTAMP_API_URL', 'LOG5651_TIMESTAMP_API_URL'],
  ['SYSLOG_TIMESTAMP_API_KEY', 'LOG5651_TIMESTAMP_API_KEY'],
  ['SYSLOG_TIMESTAMP_API_KEY_HEADER', 'LOG5651_TIMESTAMP_API_KEY_HEADER'],
  ['SYSLOG_TIMESTAMP_API_KEY_PREFIX', 'LOG5651_TIMESTAMP_API_KEY_PREFIX'],
  ['SYSLOG_TIMESTAMP_API_TIMEOUT_SECONDS', 'LOG5651_TIMESTAMP_API_TIMEOUT_SECONDS'],
  ['SYSLOG_KAMUSM_TIMESTAMP_ENABLED', 'LOG5651_KAMUSM_TIMESTAMP_ENABLED'],
  ['SYSLOG_KAMUSM_USER', 'LOG5651_KAMUSM_USER'],
  ['SYSLOG_KAMUSM_PASSWORD', 'LOG5651_KAMUSM_PASSWORD'],
  ['SYSLOG_KAMUSM_URL', 'LOG5651_KAMUSM_URL'],
  ['SYSLOG_KAMUSM_TIMEOUT_SECONDS', 'LOG5651_KAMUSM_TIMEOUT_SECONDS'],
  ['SYSLOG_RECEIVER_ENABLED', 'LOG5651_SYSLOG_ENABLED'],
  ['SYSLOG_RECEIVER_HOST', 'LOG5651_SYSLOG_HOST'],
  ['SYSLOG_RECEIVER_PORT', 'LOG5651_SYSLOG_PORT'],
  ['SYSLOG_HEALTH_CHECK_INTERVAL_SECONDS', 'LOG5651_HEALTH_CHECK_INTERVAL_SECONDS'],
  ['SYSLOG_CLOCK_SKEW_ALERT_SECONDS', 'LOG5651_CLOCK_SKEW_ALERT_SECONDS'],
  ['SYSLOG_NTP_CHECK_ENABLED', 'LOG5651_NTP_CHECK_ENABLED'],
  ['NOTIFICATION_EMAIL_SYSLOG_STORAGE_ENABLED', 'NOTIFICATION_SYSLOG_STORAGE_ENABLED'],
  ['NOTIFICATION_SMS_SYSLOG_STORAGE_ENABLED', 'NOTIFICATION_SYSLOG_STORAGE_ENABLED'],
  ['NOTIFICATION_EMAIL_SYSLOG_KAMUSM_SUCCESS_ENABLED', 'NOTIFICATION_SYSLOG_KAMUSM_SUCCESS_ENABLED'],
  ['NOTIFICATION_SMS_SYSLOG_KAMUSM_SUCCESS_ENABLED', 'NOTIFICATION_SYSLOG_KAMUSM_SUCCESS_ENABLED'],
  ['NOTIFICATION_EMAIL_SYSLOG_KAMUSM_FAILURE_ENABLED', 'NOTIFICATION_SYSLOG_KAMUSM_FAILURE_ENABLED'],
  ['NOTIFICATION_SMS_SYSLOG_KAMUSM_FAILURE_ENABLED', 'NOTIFICATION_SYSLOG_KAMUSM_FAILURE_ENABLED'],
  ['NOTIFICATION_EMAIL_ADMIN_APPROVAL_ENABLED', 'NOTIFICATION_ADMIN_APPROVAL_ENABLED'],
  ['NOTIFICATION_SMS_ADMIN_APPROVAL_ENABLED', 'NOTIFICATION_ADMIN_APPROVAL_ENABLED'],
  ...QUOTA_METHODS.flatMap(({ prefix }) => [
    [`${prefix}_DOWNLOAD_SPEED_LIMIT_MBPS`, 'DOWNLOAD_SPEED_LIMIT_MBPS'],
    [`${prefix}_UPLOAD_SPEED_LIMIT_MBPS`, 'UPLOAD_SPEED_LIMIT_MBPS']
  ])
]);

const quotaSectionLabels = {
  voucher: 'Voucher',
  'admin-approval': 'Admin approval',
  nvi: 'T.C. Identity',
  email: 'Email',
  whatsapp: 'WhatsApp',
  telegram: 'Telegram',
  sms: 'SMS'
};

function quotaFields() {
  const fields = [
    field('OPNSENSE_SHAPER_INTERFACE', 'Traffic shaper interface', {
      defaultValue: 'wan',
      placeholder: 'wan',
      section: 'OPNsense traffic shaper'
    }),
    field('OPNSENSE_SHAPER_NETWORK', 'Guest network or CIDR', {
      defaultValue: 'any',
      placeholder: '172.16.2.100 - 172.16.2.254',
      warning: 'Accepts an IP, CIDR, comma-separated list or start-end IPv4 range.'
    })
  ];
  for (const { method, prefix } of QUOTA_METHODS) {
    const section = quotaSectionLabels[method] || method;
    fields.push(
      field(`${prefix}_DOWNLOAD_SPEED_LIMIT_MBPS`, 'Download speed limit per user (Mbps)', {
        type: 'number',
        min: 0,
        max: 100000,
        defaultValue: '0',
        section,
        warning: 'Set to 0 for unlimited speed. The API user needs the "Firewall: Shaper" privilege.'
      }),
      field(`${prefix}_UPLOAD_SPEED_LIMIT_MBPS`, 'Upload speed limit per user (Mbps)', {
        type: 'number',
        min: 0,
        max: 100000,
        defaultValue: '0',
        warning: 'Set to 0 for unlimited speed. The API user needs the "Firewall: Shaper" privilege.'
      }),
      field(`${prefix}_QUOTA_PERIOD`, 'AKN period', {
        type: 'select',
        options: QUOTA_PERIODS,
        defaultValue: 'daily'
      }),
      field(`${prefix}_DOWNLOAD_QUOTA_GB`, 'Download AKN quota (GB)', {
        type: 'number',
        min: 0,
        max: 1000000,
        defaultValue: '0',
        warning: 'Set to 0 for unlimited usage. When the quota is reached, the current internet session is disconnected until the next period.'
      }),
      field(`${prefix}_UPLOAD_QUOTA_GB`, 'Upload AKN quota (GB)', {
        type: 'number',
        min: 0,
        max: 1000000,
        defaultValue: '0',
        warning: 'Set to 0 for unlimited usage. Daily, weekly and monthly periods use the Syslog time zone.'
      })
    );
  }
  return fields;
}

export const settingsSchema = [
  {
    id: 'general',
    label: 'General',
    description: 'Application identity, runtime network and session defaults.',
    fields: [
      field('APP_NAME', 'Application name', { section: 'Application' }),
      field('DEFAULT_LANGUAGE', 'Default language', { type: 'select', options: availableLanguageCodes() }),
      field('PUBLIC_BASE_URL', 'Public base URL', { placeholder: 'https://hotspot.example.com' }),
      field('DEFAULT_COUNTRY_CODE', 'Default country code', { placeholder: '90' }),
      field('ALLOWED_COUNTRY_CODES', 'Allowed country codes', {
        type: 'textarea',
        placeholder: '90\n33\n1',
        warning: 'Leave empty to allow all country codes. Use one country code per line, comma or semicolon.'
      }),
      field('SESSION_MINUTES', 'Default session duration (minutes)', { type: 'number', min: 1, max: 10080 }),
      field('TRUST_PROXY', 'Trust reverse proxy headers', { type: 'boolean' }),
      field('HOST', 'Listen host', { restartRequired: true, section: 'Runtime service' }),
      field('PORT', 'Listen port', { type: 'number', min: 1, max: 65535, restartRequired: true }),
      field('DATABASE_PATH', 'Database path', { restartRequired: true }),
      field('APP_SECRET', 'Application secret', {
        type: 'secret',
        restartRequired: true,
        warning: 'Changing this invalidates existing voucher hashes and active admin sessions.'
      })
    ]
  },
  {
    id: 'appearance',
    label: 'Appearance',
    description: 'Verification screen text, colors and images.',
    fields: [
      field('PORTAL_NETWORK_LABEL_TEXT', 'Network label', {
        defaultValue: DEFAULT_PORTAL_NETWORK_LABEL_TEXT,
        section: 'Verification screen text',
        warning: 'Shown above the application name on the verification screen.'
      }),
      field('PORTAL_TITLE_TEXT', 'Portal title', {
        warning: 'Overrides the H1 title on the verification screen. Leave empty to show the application name.'
      }),
      field('PORTAL_VERIFICATION_PROMPT_TEXT', 'Verification prompt', {
        type: 'textarea',
        defaultValue: DEFAULT_PORTAL_VERIFICATION_PROMPT_TEXT,
        warning: 'Shown under the title on the verification screen.'
      }),
      field('PORTAL_TERMS_TEXT', 'Terms notice markdown', {
        type: 'textarea',
        defaultValue: DEFAULT_PORTAL_TERMS_TEXT,
        section: 'Terms of use',
        warning: 'Markdown is shown on the verification screen. Links to terms, policy, or privacy open the related modal.'
      }),
      field('PORTAL_TERMS_MARKDOWN', 'Terms content markdown', {
        type: 'textarea',
        defaultValue: DEFAULT_PORTAL_TERMS_MARKDOWN,
        warning: 'Markdown is shown in the terms modal.'
      }),
      field('PORTAL_POLICY_MARKDOWN', 'Safe internet policy markdown', {
        type: 'textarea',
        defaultValue: DEFAULT_PORTAL_POLICY_MARKDOWN,
        warning: 'Markdown is shown in the safe internet policy modal.'
      }),
      field('PORTAL_PRIVACY_MARKDOWN', 'Privacy notice markdown', {
        type: 'textarea',
        defaultValue: DEFAULT_PORTAL_PRIVACY_MARKDOWN,
        warning: 'Markdown is shown in the privacy notice modal.'
      }),
      field('PORTAL_PRIMARY_COLOR', 'Primary color', {
        type: 'color', defaultValue: '#5340CC', section: 'Verification screen colors'
      }),
      field('PORTAL_PRIMARY_HOVER_COLOR', 'Primary hover color', { type: 'color', defaultValue: '#4530B0' }),
      field('PORTAL_HEADING_COLOR', 'Heading color', { type: 'color', defaultValue: '#1A1523' }),
      field('PORTAL_TEXT_COLOR', 'Text color', { type: 'color', defaultValue: '#374151' }),
      field('PORTAL_MUTED_COLOR', 'Muted text color', { type: 'color', defaultValue: '#6B7280' }),
      field('PORTAL_BUTTON_TEXT_COLOR', 'Button text color', { type: 'color', defaultValue: '#FFFFFF' }),
      field('PORTAL_INPUT_BACKGROUND_COLOR', 'Input background color', { type: 'color', defaultValue: '#FAFAFA' }),
      field('PORTAL_INPUT_BORDER_COLOR', 'Input border color', { type: 'color', defaultValue: '#E5E1F8' }),
      field('PORTAL_INPUT_TEXT_COLOR', 'Input text color', { type: 'color', defaultValue: '#1A1523' }),
      field('PORTAL_BODY_BACKGROUND_COLOR', 'Body background color', {
        type: 'color', defaultValue: '#F0EEF9', section: 'Body appearance'
      }),
      field('PORTAL_BODY_BACKGROUND_OPACITY', 'Body color opacity', {
        type: 'range', min: 0, max: 100, defaultValue: '100', suffix: '%'
      }),
      field('PORTAL_BODY_IMAGE_OPACITY', 'Body image opacity', {
        type: 'range', min: 0, max: 100, defaultValue: '100', suffix: '%'
      }),
      field('PORTAL_BODY_IMAGE_BLUR', 'Body image blur', {
        type: 'range', min: 0, max: 40, defaultValue: '0', suffix: 'px'
      }),
      field('PORTAL_BODY_IMAGE_ANIMATION_ENABLED', 'Cinematic backdrop motion', {
        type: 'boolean',
        defaultValue: 'false',
        warning: 'Animates only the full-screen verification backdrop image; the card background remains static.'
      }),
      field('PORTAL_CARD_BACKGROUND_COLOR', 'Card background color', {
        type: 'color', defaultValue: '#FFFFFF', section: 'Card appearance'
      }),
      field('PORTAL_CARD_BACKGROUND_OPACITY', 'Card color opacity', {
        type: 'range', min: 0, max: 100, defaultValue: '100', suffix: '%'
      }),
      field('PORTAL_CARD_BORDER_WIDTH', 'Card border width', {
        type: 'range', min: 0, max: 20, defaultValue: '1', suffix: 'px'
      }),
      field('PORTAL_CARD_BORDER_COLOR', 'Card border color', { type: 'color', defaultValue: '#000000' }),
      field('PORTAL_CARD_BORDER_OPACITY', 'Card border opacity', {
        type: 'range', min: 0, max: 100, defaultValue: '7', suffix: '%'
      }),
      field('PORTAL_CARD_BORDER_RADIUS', 'Card corner radius', {
        type: 'range', min: 0, max: 80, defaultValue: '18', suffix: 'px'
      }),
      field('PORTAL_CARD_SHADOW_OFFSET_X', 'Card shadow horizontal offset', {
        type: 'range', min: -80, max: 80, defaultValue: '0', suffix: 'px'
      }),
      field('PORTAL_CARD_SHADOW_OFFSET_Y', 'Card shadow vertical offset', {
        type: 'range', min: -80, max: 80, defaultValue: '4', suffix: 'px'
      }),
      field('PORTAL_CARD_SHADOW_BLUR', 'Card shadow blur', {
        type: 'range', min: 0, max: 160, defaultValue: '24', suffix: 'px'
      }),
      field('PORTAL_CARD_SHADOW_SPREAD', 'Card shadow spread', {
        type: 'range', min: -80, max: 80, defaultValue: '0', suffix: 'px'
      }),
      field('PORTAL_CARD_SHADOW_COLOR', 'Card shadow color', { type: 'color', defaultValue: '#6366F1' }),
      field('PORTAL_CARD_SHADOW_OPACITY', 'Card shadow opacity', {
        type: 'range', min: 0, max: 100, defaultValue: '10', suffix: '%'
      }),
      field('PORTAL_CARD_IMAGE_OPACITY', 'Card image opacity', {
        type: 'range', min: 0, max: 100, defaultValue: '100', suffix: '%'
      }),
      field('PORTAL_CARD_IMAGE_BLUR', 'Card image blur', {
        type: 'range', min: 0, max: 40, defaultValue: '0', suffix: 'px'
      }),
      field('PORTAL_CARD_BACKDROP_BLUR', 'Card backdrop blur', {
        type: 'range', min: 0, max: 40, defaultValue: '0', suffix: 'px'
      })
    ]
  },
  {
    id: 'admin',
    label: 'Admin',
    description: 'Administrator credentials and session lifetime.',
    fields: [
      field('ADMIN_USERNAME', 'Username'),
      field('ADMIN_PASSWORD', 'Password', { type: 'secret' }),
      field('ADMIN_SESSION_HOURS', 'Session lifetime (hours)', { type: 'number', min: 1, max: 168 })
    ]
  },
  {
    id: 'opnsense',
    label: 'OPNsense',
    description: 'Captive Portal Session API connection.',
    fields: [
      field('GATEWAY_MODE', 'Gateway mode', { type: 'select', options: ['mock', 'opnsense-api'] }),
      field('OPNSENSE_BASE_URL', 'Base URL'),
      field('OPNSENSE_ZONE_ID', 'Zone ID', { type: 'number', min: 0, max: 19 }),
      field('OPNSENSE_ZONE_MAP', 'Client network zone map', {
        type: 'textarea',
        section: 'Captive portal zones',
        placeholder: '172.16.2.0/24=0\n172.16.3.0/24=1',
        warning: 'Optional. Match client IPs to different captive portal zone IDs; falls back to Zone ID.'
      }),
      field('OPNSENSE_API_KEY', 'API key', { type: 'secret' }),
      field('OPNSENSE_API_SECRET', 'API secret', { type: 'secret' }),
      field('OPNSENSE_TLS_REJECT_UNAUTHORIZED', 'Verify TLS certificate', { type: 'boolean' }),
      field('OPNSENSE_SYNC_ENABLED', 'Enable automatic session synchronization', {
        type: 'boolean',
        defaultValue: 'true',
        section: 'Session synchronization',
        warning: 'Disable this if OPNsense becomes unstable; manual Sync OPNsense remains available.'
      }),
      field('OPNSENSE_SYNC_INTERVAL_SECONDS', 'Synchronization interval in seconds', {
        type: 'number',
        min: 5,
        max: 3600,
        defaultValue: '10',
        section: 'Session synchronization',
        warning: 'Lower values close stale IP sessions faster but call the OPNsense API more often.'
      }),
      field('OPNSENSE_KEA_LEASE_SYNC_ENABLED', 'Align Kea DHCP lease lifetime with access duration', {
        type: 'boolean',
        defaultValue: 'true',
        section: 'Session synchronization',
        warning: 'Creates G-Hotspot managed Kea DHCPv4 reservations with DHCP lease-time option 51.'
      }),
      field('OPNSENSE_COOKIE_IP_MOVE_ENABLED', 'Move verified cookie session after IP changes', {
        type: 'boolean',
        defaultValue: 'true',
        warning: 'When a verified browser keeps its session cookie, access can follow the device to its new IP address.'
      }),
      field('OPNSENSE_SESSION_COOKIE_REQUIRED', 'Require session cookie for verified devices', {
        type: 'boolean',
        defaultValue: 'false',
        warning: 'When enabled, devices without a valid session cookie must verify again even if their IP has an active session. To access session details later at xx:port/session, users should complete verification in a regular browser and then open the session page from that same browser. Otherwise, access can still be moved with the verification cookie, but session details will not be available from a browser that does not have that cookie.'
      })
    ]
  },
  {
    id: 'quotas',
    label: 'Kotalar',
    description: 'Bandwidth and AKN usage limits for each verification method.',
    fields: quotaFields()
  },
  {
    id: 'syslog',
    label: 'Syslog',
    description: 'Structured traffic records for selected OPNsense networks.',
    fields: [
      field('SYSLOG_ENABLED', 'Enable syslog logging', {
        type: 'boolean',
        defaultValue: 'false',
        warning: 'Records are appended with timestamps and hash-chain integrity metadata.'
      }),
      field('SYSLOG_NETWORKS', 'Logged OPNsense networks', {
        type: 'textarea',
        defaultValue: 'any',
        placeholder: '172.16.2.0/24, 10.10.10.20 - 10.10.10.80',
        warning: 'Accepts any, IP, CIDR, comma-separated list or start-end IPv4 range.'
      }),
      field('SYSLOG_TIME_ZONE', 'Export time zone', {
        type: 'select',
        options: timeZoneOptions(),
        defaultValue: systemTimeZone(),
        warning: 'Daily log file names and displayed export times use this time zone; hash-chain storage remains timezone-independent.'
      }),
      field('SYSLOG_RETENTION_DAYS', 'Retention period (days)', {
        type: 'number',
        min: 1,
        max: 1000,
        defaultValue: '730',
        warning: 'Syslog traffic retention must stay within the applicable legal retention window.'
      }),
      field('SYSLOG_EXPORT_DIR', 'Log directory', {
        defaultValue: './data/syslog',
        warning: 'Automatic export files are written here as .log files; timestamp tokens use the matching .tsr extension.'
      }),
      field('SYSLOG_AUTO_EXPORT_INTERVAL', 'Automatic export interval', {
        type: 'select',
        options: ['1h', '6h', '12h', '24h', 'daily'],
        defaultValue: 'daily',
        section: 'Automatic export',
        warning: 'Syslog exports are created automatically when syslog logging is enabled. Daily exports run at 23:59:59 in the export time zone. If timestamping is enabled, the same export schedule is timestamped.'
      }),
      field('SYSLOG_STORAGE_ALERT_PERCENT', 'Storage warning threshold (%)', {
        type: 'number',
        min: 1,
        max: 100,
        defaultValue: '85',
        section: 'Syslog storage fullness',
        warning: 'Administrators are warned when the filesystem that stores syslog data reaches this usage.'
      }),
      field('SYSLOG_STORAGE_BLOCK_PERCENT', 'Storage block threshold (%)', {
        type: 'number',
        min: 1,
        max: 100,
        defaultValue: '99',
        warning: 'New portal sessions are refused when syslog storage reaches this usage.'
      }),
      field('SYSLOG_RECEIVER_ENABLED', 'Enable OPNsense firewall syslog receiver', {
        type: 'boolean',
        defaultValue: 'false',
        restartRequired: true,
        section: 'OPNsense firewall flow logs',
        warning: 'Required for logging non-captive-portal devices on the selected networks.'
      }),
      field('SYSLOG_RECEIVER_HOST', 'Syslog listen host', {
        defaultValue: '0.0.0.0',
        restartRequired: true
      }),
      field('SYSLOG_RECEIVER_PORT', 'Syslog listen port', {
        type: 'number',
        min: 1,
        max: 65535,
        defaultValue: '5514',
        restartRequired: true,
        warning: 'Configure OPNsense remote syslog/firewall log target to this host and port.'
      }),
      field('SYSLOG_HEALTH_CHECK_INTERVAL_SECONDS', 'Health check interval (seconds)', {
        type: 'number',
        min: 10,
        max: 3600,
        defaultValue: '60',
        section: 'Time and service guard'
      }),
      field('SYSLOG_CLOCK_SKEW_ALERT_SECONDS', 'Clock jump alert threshold (seconds)', {
        type: 'number',
        min: 1,
        max: 86400,
        defaultValue: '120'
      }),
      field('SYSLOG_NTP_CHECK_ENABLED', 'Monitor NTP synchronization', {
        type: 'boolean',
        defaultValue: 'true',
        warning: 'Uses timedatectl when available and records lost/restored synchronization events.'
      }),
      field('SYSLOG_TIMESTAMP_MODE', 'Timestamp provider', {
        type: 'select',
        options: ['disabled', 'kamusm', 'rfc3161', 'api-key'],
        defaultValue: 'disabled',
        section: 'Syslog timestamp',
        warning: 'Choose KamuSM for the existing Turkey flow, generic RFC3161 TSA for EU/US-style providers, or API key mode for RFC3161 services protected by an HTTP key. When disabling timestamping, you can stamp currently unexported records first; exports created while timestamping is disabled stay unsigned.'
      }),
      field('SYSLOG_KAMUSM_USER', 'KamuSM username', {
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'kamusm' }
      }),
      field('SYSLOG_KAMUSM_PASSWORD', 'KamuSM password', {
        type: 'secret',
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'kamusm' }
      }),
      field('SYSLOG_KAMUSM_URL', 'KamuSM TSA URL', {
        defaultValue: 'http://zd.kamusm.gov.tr',
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'kamusm' }
      }),
      field('SYSLOG_KAMUSM_TIMEOUT_SECONDS', 'KamuSM timeout (seconds)', {
        type: 'number',
        min: 5,
        max: 300,
        defaultValue: '60',
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'kamusm' }
      }),
      field('SYSLOG_TIMESTAMP_URL', 'RFC3161 TSA URL', {
        placeholder: 'https://tsa.example.com',
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'rfc3161' },
        warning: 'Posts an RFC3161 timestamp query and stores the returned timestamp reply as .tsr.'
      }),
      field('SYSLOG_TIMESTAMP_HEADERS_JSON', 'RFC3161 extra headers (JSON)', {
        type: 'textarea',
        defaultValue: '',
        placeholder: '{"Authorization":"Bearer token"}',
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'rfc3161' },
        warning: 'Optional HTTP headers for providers that require account-specific headers.'
      }),
      field('SYSLOG_TIMESTAMP_CERT_REQUEST', 'Request TSA certificate in token', {
        type: 'boolean',
        defaultValue: 'true',
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'rfc3161' }
      }),
      field('SYSLOG_TIMESTAMP_TIMEOUT_SECONDS', 'RFC3161 timeout (seconds)', {
        type: 'number',
        min: 5,
        max: 300,
        defaultValue: '60',
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'rfc3161' }
      }),
      field('SYSLOG_TIMESTAMP_API_URL', 'API key TSA URL', {
        placeholder: 'https://tsa.example.com',
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'api-key' },
        warning: 'Posts an RFC3161 timestamp query with the configured API key header.'
      }),
      field('SYSLOG_TIMESTAMP_API_KEY', 'Timestamp API key', {
        type: 'secret',
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'api-key' }
      }),
      field('SYSLOG_TIMESTAMP_API_KEY_HEADER', 'API key header', {
        defaultValue: 'Authorization',
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'api-key' }
      }),
      field('SYSLOG_TIMESTAMP_API_KEY_PREFIX', 'API key value prefix', {
        defaultValue: 'Bearer',
        placeholder: 'Bearer',
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'api-key' },
        warning: 'Leave empty when the provider expects the raw API key value.'
      }),
      field('SYSLOG_TIMESTAMP_API_TIMEOUT_SECONDS', 'API key TSA timeout (seconds)', {
        type: 'number',
        min: 5,
        max: 300,
        defaultValue: '60',
        visibleWhenValue: { key: 'SYSLOG_TIMESTAMP_MODE', value: 'api-key' }
      })
    ]
  },
  {
    id: 'notifications',
    label: 'Notification settings',
    description: 'System alert delivery channels and alert subscriptions.',
    fields: [
      field('NOTIFICATION_EMAIL_ENABLED', 'Send by email', {
        type: 'boolean',
        defaultValue: 'true',
        section: 'Delivery channels',
        warning: 'Uses the configured SMTP settings.'
      }),
      field('NOTIFICATION_EMAIL_RECIPIENTS', 'Notification email recipients', {
        type: 'textarea',
        placeholder: 'admin@example.com\nnoc@example.com',
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED',
        warning: 'One email address per line, comma or semicolon.'
      }),
      field('NOTIFICATION_EMAIL_REPEAT_FREQUENCY', 'Email notification frequency', {
        type: 'select',
        options: ['state-change', 'hourly', 'daily', 'monthly'],
        defaultValue: 'state-change',
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED',
        warning: 'Threshold changes are sent immediately; this controls repeated email reminders while an alert remains active.'
      }),
      field('NOTIFICATION_EMAIL_STARTUP_ENABLED', 'Send email on every system startup', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED',
        warning: 'If an alert is already active when the service starts, an email reminder is sent once.'
      }),
      field('NOTIFICATION_SMS_ENABLED', 'Send by SMS', {
        type: 'boolean',
        defaultValue: 'true',
        warning: 'Uses the configured SMS provider settings.'
      }),
      field('NOTIFICATION_SMS_RECIPIENTS', 'Notification SMS recipients', {
        type: 'textarea',
        placeholder: '5xx xxx xx xx\n0xxx xxx xx xx',
        visibleWhen: 'NOTIFICATION_SMS_ENABLED',
        warning: 'One phone number per line, comma or semicolon.'
      }),
      field('NOTIFICATION_SMS_REPEAT_FREQUENCY', 'SMS notification frequency', {
        type: 'select',
        options: ['state-change', 'hourly', 'daily', 'monthly'],
        defaultValue: 'state-change',
        visibleWhen: 'NOTIFICATION_SMS_ENABLED',
        warning: 'Threshold changes are sent immediately; this controls repeated SMS reminders while an alert remains active.'
      }),
      field('NOTIFICATION_SMS_STARTUP_ENABLED', 'Send SMS on every system startup', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_SMS_ENABLED',
        warning: 'If an alert is already active when the service starts, an SMS reminder is sent once.'
      }),
      field('NOTIFICATION_TELEGRAM_ENABLED', 'Send by Telegram', {
        type: 'boolean',
        defaultValue: 'true',
        visibleWhen: 'TELEGRAM_ENABLED',
        warning: 'Uses the configured Telegram bot settings.'
      }),
      field('NOTIFICATION_TELEGRAM_RECIPIENTS', 'Notification Telegram recipients', {
        type: 'textarea',
        placeholder: '123456789\n-1001234567890',
        visibleWhen: 'TELEGRAM_ENABLED',
        visibleWhenAny: ['NOTIFICATION_TELEGRAM_ENABLED'],
        warning: 'One Telegram chat ID per line, comma or semicolon.'
      }),
      field('NOTIFICATION_TELEGRAM_REPEAT_FREQUENCY', 'Telegram notification frequency', {
        type: 'select',
        options: ['state-change', 'hourly', 'daily', 'monthly'],
        defaultValue: 'state-change',
        visibleWhen: 'TELEGRAM_ENABLED',
        visibleWhenAny: ['NOTIFICATION_TELEGRAM_ENABLED'],
        warning: 'Threshold changes are sent immediately; this controls repeated Telegram reminders while an alert remains active.'
      }),
      field('NOTIFICATION_TELEGRAM_STARTUP_ENABLED', 'Send Telegram on every system startup', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'TELEGRAM_ENABLED',
        visibleWhenAny: ['NOTIFICATION_TELEGRAM_ENABLED'],
        warning: 'If an alert is already active when the service starts, a Telegram reminder is sent once.'
      }),
      field('NOTIFICATION_EMAIL_SYSLOG_STORAGE_ENABLED', 'Syslog storage fullness alerts', {
        type: 'boolean',
        defaultValue: 'true',
        section: 'Alert types',
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED'
      }),
      field('NOTIFICATION_EMAIL_SYSLOG_KAMUSM_SUCCESS_ENABLED', 'Timestamp success notifications', {
        type: 'boolean',
        defaultValue: 'true',
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED'
      }),
      field('NOTIFICATION_EMAIL_SYSLOG_KAMUSM_FAILURE_ENABLED', 'Timestamp failure notifications', {
        type: 'boolean',
        defaultValue: 'true',
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED'
      }),
      field('NOTIFICATION_EMAIL_SYSTEM_STARTUP_ENABLED', 'System startup', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED'
      }),
      field('NOTIFICATION_EMAIL_OPNSENSE_DOWN_ENABLED', 'OPNsense outage', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED'
      }),
      field('NOTIFICATION_EMAIL_USER_VERIFIED_ENABLED', 'User verified', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED'
      }),
      field('NOTIFICATION_EMAIL_ACCESS_EXPIRED_ENABLED', 'Access expired', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED'
      }),
      field('NOTIFICATION_EMAIL_ADMIN_LOGIN_ENABLED', 'Admin sign-in', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED'
      }),
      field('NOTIFICATION_EMAIL_ADMIN_LOGIN_FAILED_ENABLED', 'Failed admin sign-in attempt', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED'
      }),
      field('NOTIFICATION_SMS_SYSLOG_STORAGE_ENABLED', 'Syslog storage fullness alerts', {
        type: 'boolean',
        defaultValue: 'true',
        visibleWhen: 'NOTIFICATION_SMS_ENABLED'
      }),
      field('NOTIFICATION_SMS_SYSLOG_KAMUSM_SUCCESS_ENABLED', 'Timestamp success notifications', {
        type: 'boolean',
        defaultValue: 'true',
        visibleWhen: 'NOTIFICATION_SMS_ENABLED'
      }),
      field('NOTIFICATION_SMS_SYSLOG_KAMUSM_FAILURE_ENABLED', 'Timestamp failure notifications', {
        type: 'boolean',
        defaultValue: 'true',
        visibleWhen: 'NOTIFICATION_SMS_ENABLED'
      }),
      field('NOTIFICATION_SMS_SYSTEM_STARTUP_ENABLED', 'System startup', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_SMS_ENABLED'
      }),
      field('NOTIFICATION_SMS_OPNSENSE_DOWN_ENABLED', 'OPNsense outage', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_SMS_ENABLED'
      }),
      field('NOTIFICATION_SMS_USER_VERIFIED_ENABLED', 'User verified', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_SMS_ENABLED'
      }),
      field('NOTIFICATION_SMS_ACCESS_EXPIRED_ENABLED', 'Access expired', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_SMS_ENABLED'
      }),
      field('NOTIFICATION_SMS_ADMIN_LOGIN_ENABLED', 'Admin sign-in', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_SMS_ENABLED'
      }),
      field('NOTIFICATION_SMS_ADMIN_LOGIN_FAILED_ENABLED', 'Failed admin sign-in attempt', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_SMS_ENABLED'
      }),
      field('NOTIFICATION_TELEGRAM_SYSLOG_STORAGE_ENABLED', 'Syslog storage fullness alerts', {
        type: 'boolean',
        defaultValue: 'true',
        visibleWhen: 'NOTIFICATION_TELEGRAM_ENABLED'
      }),
      field('NOTIFICATION_TELEGRAM_SYSLOG_KAMUSM_SUCCESS_ENABLED', 'Timestamp success notifications', {
        type: 'boolean',
        defaultValue: 'true',
        visibleWhen: 'NOTIFICATION_TELEGRAM_ENABLED'
      }),
      field('NOTIFICATION_TELEGRAM_SYSLOG_KAMUSM_FAILURE_ENABLED', 'Timestamp failure notifications', {
        type: 'boolean',
        defaultValue: 'true',
        visibleWhen: 'NOTIFICATION_TELEGRAM_ENABLED'
      }),
      field('NOTIFICATION_TELEGRAM_SYSTEM_STARTUP_ENABLED', 'System startup', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_TELEGRAM_ENABLED'
      }),
      field('NOTIFICATION_TELEGRAM_OPNSENSE_DOWN_ENABLED', 'OPNsense outage', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_TELEGRAM_ENABLED'
      }),
      field('NOTIFICATION_TELEGRAM_USER_VERIFIED_ENABLED', 'User verified', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_TELEGRAM_ENABLED'
      }),
      field('NOTIFICATION_TELEGRAM_ACCESS_EXPIRED_ENABLED', 'Access expired', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_TELEGRAM_ENABLED'
      }),
      field('NOTIFICATION_TELEGRAM_ADMIN_LOGIN_ENABLED', 'Admin sign-in', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_TELEGRAM_ENABLED'
      }),
      field('NOTIFICATION_TELEGRAM_ADMIN_LOGIN_FAILED_ENABLED', 'Failed admin sign-in attempt', {
        type: 'boolean',
        defaultValue: 'false',
        visibleWhen: 'NOTIFICATION_TELEGRAM_ENABLED'
      }),
      field('NOTIFICATION_SYSLOG_EMAIL_TEMPLATE_MARKDOWN', 'Syslog email template markdown', {
        type: 'textarea',
        defaultValue: DEFAULT_SYSLOG_NOTIFICATION_EMAIL_MARKDOWN,
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED',
        visibleWhenAny: [
          'NOTIFICATION_EMAIL_SYSLOG_STORAGE_ENABLED',
          'NOTIFICATION_EMAIL_SYSLOG_KAMUSM_SUCCESS_ENABLED',
          'NOTIFICATION_EMAIL_SYSLOG_KAMUSM_FAILURE_ENABLED'
        ],
        warning: 'Available placeholders: {appName}, {systemNotification}, {message}, {eventType}, {severity}, {storageUsage}, {warningThreshold}, {blockThreshold}, {freeDisk}, {logFile}, {timestampToken}.'
      }),
      field('NOTIFICATION_SYSTEM_EMAIL_TEMPLATE_MARKDOWN', 'System event email template markdown', {
        type: 'textarea',
        defaultValue: DEFAULT_SYSTEM_NOTIFICATION_EMAIL_MARKDOWN,
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED',
        visibleWhenAny: [
          'NOTIFICATION_EMAIL_SYSTEM_STARTUP_ENABLED',
          'NOTIFICATION_EMAIL_OPNSENSE_DOWN_ENABLED',
          'NOTIFICATION_EMAIL_USER_VERIFIED_ENABLED',
          'NOTIFICATION_EMAIL_ACCESS_EXPIRED_ENABLED',
          'NOTIFICATION_EMAIL_ADMIN_LOGIN_ENABLED',
          'NOTIFICATION_EMAIL_ADMIN_LOGIN_FAILED_ENABLED'
        ],
        warning: 'Available placeholders: {appName}, {systemNotification}, {message}, {eventType}, {severity}, {clientIp}, {clientMac}, {method}, {identity}, {adminUser}, {error}, {expiresAt}.'
      }),
      field('NOTIFICATION_ADMIN_APPROVAL_EMAIL_TEMPLATE_MARKDOWN', 'Admin approval email template markdown', {
        type: 'textarea',
        defaultValue: DEFAULT_ADMIN_APPROVAL_NOTIFICATION_EMAIL_MARKDOWN,
        visibleWhen: 'NOTIFICATION_EMAIL_ENABLED',
        visibleWhenAny: ['NOTIFICATION_EMAIL_ADMIN_APPROVAL_ENABLED'],
        warning: 'Available placeholders: {appName}, {fullName}, {contact}, {decisionText}, {decisionAt}, {validity}, {validUntil}, {status}.'
      }),
      field('NOTIFICATION_SYSLOG_SMS_TEMPLATE', 'Syslog SMS template', {
        type: 'textarea',
        defaultValue: DEFAULT_SYSLOG_NOTIFICATION_SMS_TEMPLATE,
        visibleWhen: 'NOTIFICATION_SMS_ENABLED',
        visibleWhenAny: [
          'NOTIFICATION_SMS_SYSLOG_STORAGE_ENABLED',
          'NOTIFICATION_SMS_SYSLOG_KAMUSM_SUCCESS_ENABLED',
          'NOTIFICATION_SMS_SYSLOG_KAMUSM_FAILURE_ENABLED'
        ],
        warning: 'Available placeholders: {appName}, {systemNotification}, {message}, {eventType}, {severity}, {storageUsage}, {warningThreshold}, {blockThreshold}, {freeDisk}, {logFile}, {timestampToken}.'
      }),
      field('NOTIFICATION_SYSLOG_TELEGRAM_TEMPLATE', 'Syslog Telegram template', {
        type: 'textarea',
        defaultValue: DEFAULT_SYSLOG_NOTIFICATION_TELEGRAM_TEMPLATE,
        visibleWhen: 'TELEGRAM_ENABLED',
        visibleWhenAny: [
          'NOTIFICATION_TELEGRAM_SYSLOG_STORAGE_ENABLED',
          'NOTIFICATION_TELEGRAM_SYSLOG_KAMUSM_SUCCESS_ENABLED',
          'NOTIFICATION_TELEGRAM_SYSLOG_KAMUSM_FAILURE_ENABLED'
        ],
        warning: 'Available placeholders: {appName}, {systemNotification}, {message}, {eventType}, {severity}, {storageUsage}, {warningThreshold}, {blockThreshold}, {freeDisk}, {logFile}, {timestampToken}.'
      }),
      field('NOTIFICATION_SYSTEM_SMS_TEMPLATE', 'System event SMS template', {
        type: 'textarea',
        defaultValue: DEFAULT_SYSTEM_NOTIFICATION_SMS_TEMPLATE,
        visibleWhen: 'NOTIFICATION_SMS_ENABLED',
        visibleWhenAny: [
          'NOTIFICATION_SMS_SYSTEM_STARTUP_ENABLED',
          'NOTIFICATION_SMS_OPNSENSE_DOWN_ENABLED',
          'NOTIFICATION_SMS_USER_VERIFIED_ENABLED',
          'NOTIFICATION_SMS_ACCESS_EXPIRED_ENABLED',
          'NOTIFICATION_SMS_ADMIN_LOGIN_ENABLED',
          'NOTIFICATION_SMS_ADMIN_LOGIN_FAILED_ENABLED'
        ],
        warning: 'Available placeholders: {appName}, {systemNotification}, {message}, {eventType}, {severity}, {clientIp}, {clientMac}, {method}, {identity}, {adminUser}, {error}, {expiresAt}.'
      }),
      field('NOTIFICATION_SYSTEM_TELEGRAM_TEMPLATE', 'System event Telegram template', {
        type: 'textarea',
        defaultValue: DEFAULT_SYSTEM_NOTIFICATION_TELEGRAM_TEMPLATE,
        visibleWhen: 'TELEGRAM_ENABLED',
        visibleWhenAny: [
          'NOTIFICATION_TELEGRAM_SYSTEM_STARTUP_ENABLED',
          'NOTIFICATION_TELEGRAM_OPNSENSE_DOWN_ENABLED',
          'NOTIFICATION_TELEGRAM_USER_VERIFIED_ENABLED',
          'NOTIFICATION_TELEGRAM_ACCESS_EXPIRED_ENABLED',
          'NOTIFICATION_TELEGRAM_ADMIN_LOGIN_ENABLED',
          'NOTIFICATION_TELEGRAM_ADMIN_LOGIN_FAILED_ENABLED'
        ],
        warning: 'Available placeholders: {appName}, {systemNotification}, {message}, {eventType}, {severity}, {clientIp}, {clientMac}, {method}, {identity}, {adminUser}, {error}, {expiresAt}.'
      }),
      field('NOTIFICATION_ADMIN_APPROVAL_SMS_TEMPLATE', 'Admin approval SMS template', {
        type: 'textarea',
        defaultValue: DEFAULT_ADMIN_APPROVAL_NOTIFICATION_SMS_TEMPLATE,
        visibleWhen: 'NOTIFICATION_SMS_ENABLED',
        visibleWhenAny: ['NOTIFICATION_SMS_ADMIN_APPROVAL_ENABLED'],
        warning: 'Available placeholders: {appName}, {fullName}, {contact}, {decisionText}, {decisionAt}, {validity}, {validUntil}, {status}.'
      })
    ]
  },
  {
    id: 'voucher',
    label: 'Voucher',
    description: 'Voucher access method availability.',
    fields: [
      field('VOUCHER_ENABLED', 'Enable voucher verification', { type: 'boolean', defaultValue: 'true' })
    ]
  },
  {
    id: 'admin-approval',
    label: 'Admin approval',
    description: 'Guest requests that must be approved or rejected by an administrator.',
    fields: [
      field('ADMIN_APPROVAL_ENABLED', 'Enable admin approval verification', {
        type: 'boolean',
        defaultValue: 'false'
      }),
      field('NOTIFICATION_EMAIL_ADMIN_APPROVAL_ENABLED', 'Email approval result notifications', {
        type: 'boolean',
        defaultValue: 'true',
        section: 'Notification settings',
        warning: 'Sends one approval or rejection result to the contact entered by the guest, when the matching delivery channel is active.'
      }),
      field('NOTIFICATION_SMS_ADMIN_APPROVAL_ENABLED', 'SMS approval result notifications', {
        type: 'boolean',
        defaultValue: 'true',
        warning: 'Sends one approval or rejection result to the contact entered by the guest, when the matching delivery channel is active.'
      }),
      field('ADMIN_APPROVAL_IP_RETRY_INTERVAL_VALUE', 'Same IP can create a new request after', {
        type: 'number', min: 1, max: 1000, defaultValue: '1',
        durationPair: 'admin-approval-ip-retry', durationRole: 'value',
        section: 'Request rules'
      }),
      field('ADMIN_APPROVAL_IP_RETRY_INTERVAL_UNIT', 'Time unit', {
        type: 'select',
        options: ['minutes', 'hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'minutes',
        durationPair: 'admin-approval-ip-retry',
        durationRole: 'unit',
        warning: 'After a guest creates an admin approval request from an IP, that IP must wait this long before creating another request.'
      }),
      field('ADMIN_APPROVAL_REVERIFY_DURATION_VALUE', 'Same guest can request again after', {
        type: 'number', min: 1, max: 1000, defaultValue: '24',
        durationPair: 'admin-approval-reverify', durationRole: 'value'
      }),
      field('ADMIN_APPROVAL_REVERIFY_DURATION_UNIT', 'Time unit', {
        type: 'select',
        options: ['hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'hours',
        durationPair: 'admin-approval-reverify',
        durationRole: 'unit',
        warning: 'This controls when the same name/contact identity can receive access again. Unlimited means it can be approved only once.'
      }),
      field('ADMIN_APPROVAL_REQUEST_TTL_MINUTES', 'Request waits for approval for (minutes)', {
        type: 'number',
        min: 1,
        max: 10080,
        defaultValue: '1440'
      }),
      field('ADMIN_APPROVAL_ACCESS_DURATION_VALUE', 'Internet stays open for', {
        type: 'number', min: 1, max: 1000, defaultValue: '24',
        durationPair: 'admin-approval', durationRole: 'value', section: 'Internet access'
      }),
      field('ADMIN_APPROVAL_ACCESS_DURATION_UNIT', 'Time unit', {
        type: 'select',
        options: ['hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'hours',
        durationPair: 'admin-approval',
        durationRole: 'unit'
      }),
      field('ADMIN_APPROVAL_APPROVE_TEXT', 'Default approval text', {
        type: 'textarea',
        defaultValue: 'Your internet access request was approved.',
        section: 'Decision messages'
      }),
      field('ADMIN_APPROVAL_REJECT_TEXT', 'Default rejection text', {
        type: 'textarea',
        defaultValue: 'Your internet access request was rejected.'
      })
    ]
  },
  {
    id: 'nvi',
    label: 'T.C. Kimlik',
    description: 'NVİ KPSv2 T.C. kimlik doğrulaması.',
    fields: [
      field('NVI_ENABLED', 'Enable T.C. identity verification', { type: 'boolean', defaultValue: 'false' }),
      field('NVI_SEND_SMS_CODE', 'Send code by SMS after NVI verification', {
        type: 'boolean',
        defaultValue: 'false',
        warning: 'When enabled, successful NVI lookup sends an SMS code to the phone number entered by the guest. When disabled, successful NVI lookup grants access directly.'
      }),
      field('NVI_IP_RETRY_INTERVAL_VALUE', 'Same IP can request a new verification after', {
        type: 'number', min: 1, max: 1000, defaultValue: '1',
        durationPair: 'nvi-ip-retry', durationRole: 'value',
        section: 'Request rules'
      }),
      field('NVI_IP_RETRY_INTERVAL_UNIT', 'Time unit', {
        type: 'select',
        options: ['minutes', 'hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'minutes',
        durationPair: 'nvi-ip-retry',
        durationRole: 'unit',
        warning: 'After an NVI verification request from an IP, that IP must wait this long before requesting another verification.'
      }),
      field('NVI_REVERIFY_DURATION_VALUE', 'Same T.C. identity can verify again after', {
        type: 'number', min: 1, max: 1000, defaultValue: '24',
        durationPair: 'nvi-reverify', durationRole: 'value'
      }),
      field('NVI_REVERIFY_DURATION_UNIT', 'Time unit', {
        type: 'select',
        options: ['hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'hours',
        durationPair: 'nvi-reverify',
        durationRole: 'unit',
        warning: 'This controls when the same T.C. identity can get access again. Unlimited means it can be verified only once.'
      }),
      field('NVI_ACCESS_DURATION_VALUE', 'Internet stays open for', {
        type: 'number', min: 1, max: 1000, defaultValue: '24',
        durationPair: 'nvi', durationRole: 'value', section: 'Internet access'
      }),
      field('NVI_ACCESS_DURATION_UNIT', 'Time unit', {
        type: 'select',
        options: ['hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'hours',
        durationPair: 'nvi',
        durationRole: 'unit'
      }),
      field('NVI_USERNAME', 'KPSv2 username', { section: 'KPSv2 credentials' }),
      field('NVI_PASSWORD', 'KPSv2 password', { type: 'secret' })
    ]
  },
  {
    id: 'email',
    label: 'Email',
    description: 'SMTP configuration for email OTP delivery.',
    fields: [
      field('EMAIL_ENABLED', 'Enable email verification', { type: 'boolean', defaultValue: 'true' }),
      field('EMAIL_IP_RETRY_INTERVAL_VALUE', 'Same IP can request a new code after', {
        type: 'number', min: 1, max: 1000, defaultValue: '1',
        durationPair: 'email-ip-retry', durationRole: 'value',
        section: 'Code request rules'
      }),
      field('EMAIL_IP_RETRY_INTERVAL_UNIT', 'Time unit', {
        type: 'select',
        options: ['minutes', 'hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'minutes',
        durationPair: 'email-ip-retry',
        durationRole: 'unit',
        warning: 'After an email code is sent from an IP, that IP must wait this long before requesting another code.'
      }),
      field('EMAIL_REVERIFY_DURATION_VALUE', 'Same email can verify again after', {
        type: 'number', min: 1, max: 1000, defaultValue: '24',
        durationPair: 'email-reverify', durationRole: 'value'
      }),
      field('EMAIL_REVERIFY_DURATION_UNIT', 'Time unit', {
        type: 'select',
        options: ['hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'hours',
        durationPair: 'email-reverify',
        durationRole: 'unit',
        warning: 'This controls when the same email address can get access again. Unlimited means it can be verified only once.'
      }),
      field('EMAIL_ACCESS_DURATION_VALUE', 'Internet stays open for', {
        type: 'number', min: 1, max: 1000, defaultValue: '24',
        durationPair: 'email', durationRole: 'value', section: 'Internet access'
      }),
      field('EMAIL_ACCESS_DURATION_UNIT', 'Time unit', {
        type: 'select',
        options: ['hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'hours',
        durationPair: 'email',
        durationRole: 'unit'
      }),
      field('SMTP_HOST', 'SMTP host', { section: 'SMTP delivery' }),
      field('SMTP_PORT', 'SMTP port', { type: 'number', min: 1, max: 65535 }),
      field('SMTP_SECURE', 'Use implicit TLS (usually port 465)', { type: 'boolean' }),
      field('SMTP_STARTTLS', 'Use STARTTLS (usually port 587)', { type: 'boolean' }),
      field('SMTP_USER', 'SMTP username'),
      field('SMTP_PASS', 'SMTP password', { type: 'secret' }),
      field('SMTP_FROM', 'From address', {
        readOnly: true,
        derivedFrom: 'SMTP_USER',
        warning: 'This value is locked to the SMTP username.'
      })
    ]
  },
  {
    id: 'whatsapp',
    label: 'WhatsApp',
    description: 'Meta WhatsApp Cloud API and optional webhook settings.',
    fields: [
      field('WHATSAPP_ENABLED', 'Enable WhatsApp verification', { type: 'boolean', defaultValue: 'true' }),
      field('WHATSAPP_IP_RETRY_INTERVAL_VALUE', 'Same IP can request a new code after', {
        type: 'number', min: 1, max: 1000, defaultValue: '1',
        durationPair: 'whatsapp-ip-retry', durationRole: 'value',
        section: 'Code request rules'
      }),
      field('WHATSAPP_IP_RETRY_INTERVAL_UNIT', 'Time unit', {
        type: 'select',
        options: ['minutes', 'hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'minutes',
        durationPair: 'whatsapp-ip-retry',
        durationRole: 'unit',
        warning: 'After a WhatsApp code is sent from an IP, that IP must wait this long before requesting another code.'
      }),
      field('WHATSAPP_REVERIFY_DURATION_VALUE', 'Same phone can verify again after', {
        type: 'number', min: 1, max: 1000, defaultValue: '24',
        durationPair: 'whatsapp-reverify', durationRole: 'value'
      }),
      field('WHATSAPP_REVERIFY_DURATION_UNIT', 'Time unit', {
        type: 'select',
        options: ['hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'hours',
        durationPair: 'whatsapp-reverify',
        durationRole: 'unit',
        warning: 'This controls when the same phone number can get access again. Unlimited means it can be verified only once.'
      }),
      field('WHATSAPP_ACCESS_DURATION_VALUE', 'Internet stays open for', {
        type: 'number', min: 1, max: 1000, defaultValue: '24',
        durationPair: 'whatsapp', durationRole: 'value', section: 'Internet access'
      }),
      field('WHATSAPP_ACCESS_DURATION_UNIT', 'Time unit', {
        type: 'select',
        options: ['hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'hours',
        durationPair: 'whatsapp',
        durationRole: 'unit'
      }),
      field('WHATSAPP_BUSINESS_NUMBER', 'Business number', { section: 'WhatsApp delivery' }),
      field('WHATSAPP_PHONE_NUMBER_ID', 'Phone Number ID'),
      field('WHATSAPP_ACCESS_TOKEN', 'Access token', { type: 'secret' }),
      field('WHATSAPP_TEMPLATE_NAME', 'Authentication template name'),
      field('WHATSAPP_TEMPLATE_LANGUAGE', 'Template language'),
      field('WHATSAPP_TEMPLATE_BUTTON', 'Template has copy-code button', { type: 'boolean' }),
      field('META_GRAPH_API_VERSION', 'Graph API version'),
      field('META_GRAPH_BASE_URL', 'Graph API base URL'),
      field('WHATSAPP_VERIFY_TOKEN', 'Webhook verify token', { type: 'secret' }),
      field('META_APP_SECRET', 'Meta app secret', { type: 'secret' })
    ]
  },
  {
    id: 'telegram',
    label: 'Telegram',
    description: 'Telegram bot verification using the phone number registered to the user account.',
    fields: [
      field('TELEGRAM_ENABLED', 'Enable Telegram verification', { type: 'boolean', defaultValue: 'false' }),
      field('TELEGRAM_IP_RETRY_INTERVAL_VALUE', 'Same IP can request a new code after', {
        type: 'number', min: 1, max: 1000, defaultValue: '1',
        durationPair: 'telegram-ip-retry', durationRole: 'value',
        section: 'Code request rules'
      }),
      field('TELEGRAM_IP_RETRY_INTERVAL_UNIT', 'Time unit', {
        type: 'select',
        options: ['minutes', 'hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'minutes',
        durationPair: 'telegram-ip-retry',
        durationRole: 'unit',
        warning: 'After a Telegram code is requested from an IP, that IP must wait this long before requesting another code.'
      }),
      field('TELEGRAM_REVERIFY_DURATION_VALUE', 'Same phone can verify again after', {
        type: 'number', min: 1, max: 1000, defaultValue: '24',
        durationPair: 'telegram-reverify', durationRole: 'value'
      }),
      field('TELEGRAM_REVERIFY_DURATION_UNIT', 'Time unit', {
        type: 'select',
        options: ['hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'hours',
        durationPair: 'telegram-reverify',
        durationRole: 'unit',
        warning: 'This controls when the same phone number can get access again. Unlimited means it can be verified only once.'
      }),
      field('TELEGRAM_ACCESS_DURATION_VALUE', 'Internet stays open for', {
        type: 'number', min: 1, max: 1000, defaultValue: '24',
        durationPair: 'telegram', durationRole: 'value', section: 'Internet access'
      }),
      field('TELEGRAM_ACCESS_DURATION_UNIT', 'Time unit', {
        type: 'select',
        options: ['hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'hours',
        durationPair: 'telegram',
        durationRole: 'unit'
      }),
      field('TELEGRAM_BOT_USERNAME', 'Bot username', {
        section: 'Telegram bot',
        placeholder: 'GHotspotBot'
      }),
      field('TELEGRAM_MODE', 'Delivery mode', {
        type: 'select',
        options: ['webhook', 'polling'],
        defaultValue: 'webhook'
      }),
      field('TELEGRAM_BOT_TOKEN', 'Bot token', { type: 'secret' }),
      field('TELEGRAM_WEBHOOK_SECRET', 'Webhook secret token', { type: 'secret' }),
      field('TELEGRAM_BOT_API_BASE_URL', 'Bot API base URL', {
        defaultValue: 'https://api.telegram.org'
      }),
      field('TELEGRAM_OTP_MINUTES', 'OTP validity (minutes)', { type: 'number', min: 1, max: 30 }),
      field('TELEGRAM_MESSAGE_TEMPLATE', 'Message template', {
        type: 'textarea',
        placeholder: '{appName} Telegram access code: {code}. The code is valid for {minutes} minutes.'
      })
    ]
  },
  {
    id: 'sms',
    label: 'SMS',
    description: 'Choose a provider and configure SMS OTP delivery.',
    fields: [
      field('SMS_ENABLED', 'Enable SMS OTP', { type: 'boolean' }),
      field('SMS_IP_RETRY_INTERVAL_VALUE', 'Same IP can request a new code after', {
        type: 'number', min: 1, max: 1000, defaultValue: '1',
        durationPair: 'sms-ip-retry', durationRole: 'value',
        section: 'Code request rules'
      }),
      field('SMS_IP_RETRY_INTERVAL_UNIT', 'Time unit', {
        type: 'select',
        options: ['minutes', 'hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'minutes',
        durationPair: 'sms-ip-retry',
        durationRole: 'unit',
        warning: 'After an SMS code is sent from an IP, that IP must wait this long before requesting another code.'
      }),
      field('SMS_REVERIFY_DURATION_VALUE', 'Same phone can verify again after', {
        type: 'number', min: 1, max: 1000, defaultValue: '24',
        durationPair: 'sms-reverify', durationRole: 'value'
      }),
      field('SMS_REVERIFY_DURATION_UNIT', 'Time unit', {
        type: 'select',
        options: ['hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'hours',
        durationPair: 'sms-reverify',
        durationRole: 'unit',
        warning: 'This controls when the same phone number can get access again. Unlimited means it can be verified only once.'
      }),
      field('SMS_ACCESS_DURATION_VALUE', 'Internet stays open for', {
        type: 'number', min: 1, max: 1000, defaultValue: '24',
        durationPair: 'sms', durationRole: 'value', section: 'Internet access'
      }),
      field('SMS_ACCESS_DURATION_UNIT', 'Time unit', {
        type: 'select',
        options: ['hours', 'days', 'months', 'years', 'unlimited'],
        defaultValue: 'hours',
        durationPair: 'sms',
        durationRole: 'unit'
      }),
      field('SMS_PROVIDER', 'Provider', {
        type: 'select',
        options: ['netgsm', 'iletimerkezi', 'twilio', 'custom'],
        section: 'SMS delivery'
      }),
      field('SMS_SENDER', 'Default sender'),
      field('SMS_OTP_MINUTES', 'OTP validity (minutes)', { type: 'number', min: 1, max: 30 }),
      field('SMS_MESSAGE_TEMPLATE', 'Message template', {
        type: 'textarea',
        placeholder: '{appName} access code: {code}. The code is valid for {minutes} minutes.'
      }),
      field('NETGSM_USERCODE', 'Netgsm user code', { provider: 'netgsm' }),
      field('NETGSM_PASSWORD', 'Netgsm password', { type: 'secret', provider: 'netgsm' }),
      field('NETGSM_HEADER', 'Netgsm message header', { provider: 'netgsm' }),
      field('ILETIMERKEZI_API_KEY', 'İleti Merkezi API key', { provider: 'iletimerkezi' }),
      field('ILETIMERKEZI_API_SECRET', 'İleti Merkezi API secret', { type: 'secret', provider: 'iletimerkezi' }),
      field('ILETIMERKEZI_SENDER', 'İleti Merkezi sender', { provider: 'iletimerkezi' }),
      field('TWILIO_ACCOUNT_SID', 'Twilio Account SID', { provider: 'twilio' }),
      field('TWILIO_AUTH_TOKEN', 'Twilio auth token', { type: 'secret', provider: 'twilio' }),
      field('TWILIO_FROM', 'Twilio sender number', { provider: 'twilio' }),
      field('CUSTOM_SMS_URL', 'Custom service URL', { provider: 'custom' }),
      field('CUSTOM_SMS_METHOD', 'HTTP method', {
        type: 'select', options: ['POST', 'PUT', 'PATCH'], provider: 'custom'
      }),
      field('CUSTOM_SMS_AUTHORIZATION', 'Authorization header', { type: 'secret', provider: 'custom' }),
      field('CUSTOM_SMS_HEADERS_JSON', 'Additional headers (JSON)', { type: 'textarea', provider: 'custom' }),
      field('CUSTOM_SMS_BODY_TEMPLATE', 'JSON body template', {
        type: 'textarea',
        provider: 'custom',
        placeholder: '{"to":"{phone}","message":"{message}","code":"{code}"}'
      }),
      field('CUSTOM_SMS_SUCCESS_PATH', 'Success JSON path', {
        provider: 'custom',
        placeholder: 'data.success'
      })
    ]
  }
];

const schemaFields = settingsSchema.flatMap(group => group.fields);
const allowedKeys = new Set(schemaFields.map(item => item.key));
const secretKeys = new Set(schemaFields.filter(item => item.type === 'secret').map(item => item.key));
const restartKeys = new Set(schemaFields.filter(item => item.restartRequired).map(item => item.key));
const installVerificationGroupIds = new Set([
  'voucher',
  'admin-approval',
  'nvi',
  'email',
  'whatsapp',
  'telegram',
  'sms'
]);
const installOptionalSettingKeys = new Set([
  'OPNSENSE_ZONE_MAP',
  ...settingsSchema
    .filter(group => installVerificationGroupIds.has(group.id))
    .flatMap(group => group.fields.map(item => item.key))
]);
const installSettingKeys = new Set([
  'APP_NAME',
  'DATABASE_PATH',
  'APP_SECRET',
  'DEFAULT_LANGUAGE',
  'ADMIN_USERNAME',
  'ADMIN_PASSWORD',
  'ADMIN_SESSION_HOURS',
  'GATEWAY_MODE',
  'OPNSENSE_BASE_URL',
  'OPNSENSE_ZONE_ID',
  'OPNSENSE_API_KEY',
  'OPNSENSE_API_SECRET',
  'OPNSENSE_TLS_REJECT_UNAUTHORIZED',
  ...installOptionalSettingKeys
]);
const trafficLogFields = [
  field('TRAFFIC_LOGS_ENABLED', 'Enable operational traffic logs', {
    type: 'boolean',
    defaultValue: 'true'
  }),
  field('TRAFFIC_LOGS_RETENTION_DAYS', 'Retention period (days)', {
    type: 'number',
    min: 1,
    max: 365,
    defaultValue: '30'
  }),
  field('TRAFFIC_LOGS_RESOLVE_DOMAINS', 'Resolve destination domains', {
    type: 'boolean',
    defaultValue: 'true'
  }),
  field('TRAFFIC_LOGS_LIVE_REFRESH_SECONDS', 'Live refresh interval (seconds)', {
    type: 'number',
    min: 2,
    max: 60,
    defaultValue: '5'
  })
];

function trafficLogField(key) {
  return trafficLogFields.find(item => item.key === key);
}

function booleanSetting(value, fallback) {
  if (typeof value === 'boolean') return value;
  if (value == null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function integerSetting(value, fallback, { min, max } = {}) {
  const parsed = Number.parseInt(value, 10);
  const number = Number.isInteger(parsed) ? parsed : fallback;
  return Math.min(max, Math.max(min, number));
}

function trafficLogPublicValues(values, includeProcessEnv) {
  const output = {};
  for (const field of trafficLogFields) {
    output[field.key] = values[field.key] ??
      (includeProcessEnv ? process.env[field.key] : undefined) ??
      field.defaultValue ??
      '';
  }
  return output;
}

function runtimeSettingValue(key, values, includeProcessEnv) {
  const source = values[key] ?? (includeProcessEnv ? process.env[key] : undefined);
  if (key === 'HOST') return automaticListenHost(source);
  if (key === 'PORT') return String(automaticListenPort(source));
  if (key === 'PUBLIC_BASE_URL') {
    return automaticPublicBaseUrl({
      publicBaseUrl: source,
      host: values.HOST ?? (includeProcessEnv ? process.env.HOST : undefined),
      port: values.PORT ?? (includeProcessEnv ? process.env.PORT : undefined)
    });
  }
  if (key === 'SYSLOG_TIMESTAMP_MODE') {
    const configured = String(source || '').trim().toLowerCase();
    if (configured) return configured;
    const legacyEnabled = values.SYSLOG_KAMUSM_TIMESTAMP_ENABLED ??
      values.LOG5651_KAMUSM_TIMESTAMP_ENABLED ??
      (includeProcessEnv ? process.env.SYSLOG_KAMUSM_TIMESTAMP_ENABLED : undefined) ??
      (includeProcessEnv ? process.env.LOG5651_KAMUSM_TIMESTAMP_ENABLED : undefined);
    if (['1', 'true', 'yes', 'on'].includes(String(legacyEnabled || '').toLowerCase())) return 'kamusm';
    return null;
  }
  return null;
}

function settingsSource(envPath) {
  if (typeof envPath === 'string') {
    return {
      values: readEnvFile(envPath),
      includeProcessEnv: path.resolve(envPath) === path.resolve('.env')
    };
  }
  return {
    values: readSystemSettings(),
    includeProcessEnv: true
  };
}

function collectSettingsChanges(input) {
  const changes = {};
  for (const [key, value] of Object.entries(input || {})) {
    if (!allowedKeys.has(key)) continue;
    if (secretKeys.has(key) && String(value ?? '') === '') continue;
    changes[key] = typeof value === 'boolean' ? String(value) : String(value ?? '');
  }
  return changes;
}

function withSmtpFrom(changes, input, values, includeProcessEnv) {
  if (!Object.hasOwn(input || {}, 'SMTP_USER') && !Object.hasOwn(input || {}, 'SMTP_FROM')) return changes;
  changes.SMTP_FROM = changes.SMTP_USER ??
    values.SMTP_USER ??
    (includeProcessEnv ? process.env.SMTP_USER : undefined) ??
    '';
  return changes;
}

function processSnapshot(keys) {
  const previous = new Map();
  for (const key of keys) previous.set(key, process.env[key]);
  return previous;
}

function restoreProcessSnapshot(previous) {
  for (const [key, value] of previous) {
    if (value == null) delete process.env[key];
    else process.env[key] = value;
  }
}

function changedRestartKeys(changes) {
  return Object.keys(changes).filter(key => restartKeys.has(key));
}

function saveSystemChanges(changes, { restartAware = false } = {}) {
  const keys = Object.keys(changes);
  const restartChanged = restartAware ? changedRestartKeys(changes) : [];
  const previousSettings = readSystemSettings();
  const previousProcessValues = processSnapshot(keys);
  try {
    writeSystemSettings(changes);
    loadSystemSettingsIntoEnv({ importEnv: false });
    reloadConfig();
    if (restartChanged.length) {
      restoreProcessSnapshot(new Map(restartChanged.map(key => [key, previousProcessValues.get(key)])));
      loadSystemSettingsIntoEnv({ preserveKeys: restartChanged, importEnv: false });
      reloadConfig();
    }
  } catch (error) {
    replaceSystemSettings(previousSettings);
    loadSystemSettingsIntoEnv({ importEnv: false });
    restoreProcessSnapshot(previousProcessValues);
    reloadConfig();
    throw error;
  }
  return { saved: keys, restartRequired: restartChanged.length > 0 };
}

function saveEnvSettings(input, envPath) {
  const source = settingsSource(envPath);
  const changes = withSmtpFrom(
    collectSettingsChanges(input),
    input,
    source.values,
    source.includeProcessEnv
  );
  const restartRequired = Object.keys(changes).some(key => restartKeys.has(key));
  const previousProcessValues = processSnapshot(Object.keys(changes));
  const previousFile = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : null;
  try {
    updateEnvFile(changes, envPath);
    reloadConfig();
    for (const key of Object.keys(changes)) {
      if (!restartKeys.has(key)) continue;
      const value = previousProcessValues.get(key);
      if (value == null) delete process.env[key];
      else process.env[key] = value;
    }
    reloadConfig();
  } catch (error) {
    if (previousFile == null) fs.rmSync(envPath, { force: true });
    else fs.writeFileSync(envPath, previousFile, { mode: 0o600 });
    restoreProcessSnapshot(previousProcessValues);
    reloadConfig();
    throw error;
  }
  return { saved: Object.keys(changes), restartRequired };
}

export function getSettings(envPath = null) {
  const { values, includeProcessEnv } = settingsSource(envPath);
  const publicValues = {};
  const configured = {};
  for (const key of allowedKeys) {
    const legacyKey = legacySettingKeys.get(key);
    if (secretKeys.has(key)) {
      publicValues[key] = '';
      configured[key] = Boolean(
        values[key] ||
        (legacyKey ? values[legacyKey] : '') ||
        (includeProcessEnv && process.env[key]) ||
        (includeProcessEnv && legacyKey && process.env[legacyKey])
      );
    } else {
      const schemaField = schemaFields.find(item => item.key === key);
      publicValues[key] = runtimeSettingValue(key, values, includeProcessEnv) ??
        values[key] ??
        (legacyKey ? values[legacyKey] : undefined) ??
        (includeProcessEnv ? process.env[key] : undefined) ??
        (includeProcessEnv && legacyKey ? process.env[legacyKey] : undefined) ??
        schemaField?.defaultValue ??
        '';
    }
  }
  publicValues.SMTP_FROM = publicValues.SMTP_USER || '';
  return { schema: settingsSchema, values: publicValues, configured };
}

export function saveSettings(input, envPath = null) {
  if (typeof envPath === 'string') return saveEnvSettings(input, envPath);
  const source = settingsSource(null);
  const changes = withSmtpFrom(
    collectSettingsChanges(input),
    input,
    source.values,
    source.includeProcessEnv
  );
  return saveSystemChanges(changes, { restartAware: true });
}

export function getTrafficLogSettings(envPath = null) {
  const { values, includeProcessEnv } = settingsSource(envPath);
  return {
    schema: trafficLogFields,
    values: trafficLogPublicValues(values, includeProcessEnv)
  };
}

function collectTrafficLogChanges(input) {
  const changes = {};
  const enabledField = trafficLogField('TRAFFIC_LOGS_ENABLED');
  const retentionField = trafficLogField('TRAFFIC_LOGS_RETENTION_DAYS');
  const resolveField = trafficLogField('TRAFFIC_LOGS_RESOLVE_DOMAINS');
  const refreshField = trafficLogField('TRAFFIC_LOGS_LIVE_REFRESH_SECONDS');
  if (Object.hasOwn(input || {}, 'TRAFFIC_LOGS_ENABLED')) {
    changes.TRAFFIC_LOGS_ENABLED = String(booleanSetting(input.TRAFFIC_LOGS_ENABLED, enabledField.defaultValue === 'true'));
  }
  if (Object.hasOwn(input || {}, 'TRAFFIC_LOGS_RETENTION_DAYS')) {
    changes.TRAFFIC_LOGS_RETENTION_DAYS = String(integerSetting(
      input.TRAFFIC_LOGS_RETENTION_DAYS,
      Number(retentionField.defaultValue),
      { min: retentionField.min, max: retentionField.max }
    ));
  }
  if (Object.hasOwn(input || {}, 'TRAFFIC_LOGS_RESOLVE_DOMAINS')) {
    changes.TRAFFIC_LOGS_RESOLVE_DOMAINS = String(booleanSetting(
      input.TRAFFIC_LOGS_RESOLVE_DOMAINS,
      resolveField.defaultValue === 'true'
    ));
  }
  if (Object.hasOwn(input || {}, 'TRAFFIC_LOGS_LIVE_REFRESH_SECONDS')) {
    changes.TRAFFIC_LOGS_LIVE_REFRESH_SECONDS = String(integerSetting(
      input.TRAFFIC_LOGS_LIVE_REFRESH_SECONDS,
      Number(refreshField.defaultValue),
      { min: refreshField.min, max: refreshField.max }
    ));
  }
  return changes;
}

export function saveTrafficLogSettings(input, envPath = null) {
  const changes = collectTrafficLogChanges(input);
  if (typeof envPath !== 'string') return saveSystemChanges(changes);

  const previousProcessValues = processSnapshot(Object.keys(changes));
  const previousFile = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : null;
  try {
    updateEnvFile(changes, envPath);
    reloadConfig();
  } catch (error) {
    if (previousFile == null) fs.rmSync(envPath, { force: true });
    else fs.writeFileSync(envPath, previousFile, { mode: 0o600 });
    restoreProcessSnapshot(previousProcessValues);
    reloadConfig();
    throw error;
  }
  return { saved: Object.keys(changes), restartRequired: false };
}

function normalizedInstallLanguage(value) {
  const language = String(value || '').trim().toLowerCase().split(/[-_,;]/u)[0];
  return availableLanguageCodes().includes(language) ? language : 'en';
}

function normalizedGatewayMode(value) {
  const mode = String(value || 'mock').trim().toLowerCase().replace(/_/gu, '-');
  if (!['mock', 'opnsense-api'].includes(mode)) {
    throw new Error('GATEWAY_MODE must be mock or opnsense-api');
  }
  return mode;
}

function requiredInstallText(value, label) {
  const text = String(value || '').trim();
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function installInteger(value, fallback, { min, max, label }) {
  const number = Number.parseInt(value == null || value === '' ? fallback : value, 10);
  if (!Number.isInteger(number) || number < min || number > max) {
    throw new Error(`${label} must be between ${min} and ${max}`);
  }
  return String(number);
}

function installBoolean(value, fallback) {
  return String(booleanSetting(value, fallback));
}

function installUrl(value) {
  const text = requiredInstallText(value, 'OPNsense base URL').replace(/\/+$/u, '');
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error('OPNsense base URL must be a valid URL');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('OPNsense base URL must start with http:// or https://');
  }
  return text;
}

export function generateInstallSecret() {
  return generateSecret(48);
}

export function getInstallStatus() {
  return {
    installed: isSystemInstalled(),
    appName: process.env.APP_NAME || 'G-Hotspot',
    defaultLanguage: normalizedInstallLanguage(process.env.DEFAULT_LANGUAGE || 'en'),
    gatewayMode: process.env.GATEWAY_MODE || 'mock'
  };
}

export function installOpnsenseGateway(input = {}) {
  const source = input.settings && typeof input.settings === 'object' ? input.settings : input;
  const mode = normalizedGatewayMode(source.GATEWAY_MODE);
  if (mode !== 'opnsense-api') throw new Error('GATEWAY_MODE must be opnsense-api');
  return {
    mode,
    baseUrl: installUrl(source.OPNSENSE_BASE_URL),
    zoneId: installInteger(source.OPNSENSE_ZONE_ID, 0, {
      min: 0,
      max: 19,
      label: 'OPNsense zone ID'
    }),
    zoneMap: [],
    apiKey: requiredInstallText(source.OPNSENSE_API_KEY, 'OPNsense API key'),
    apiSecret: requiredInstallText(source.OPNSENSE_API_SECRET, 'OPNsense API secret'),
    tlsRejectUnauthorized: booleanSetting(source.OPNSENSE_TLS_REJECT_UNAUTHORIZED, true)
  };
}

export function completeInstallation(input = {}) {
  if (isSystemInstalled()) throw new Error('System is already installed');
  const source = input.settings && typeof input.settings === 'object' ? input.settings : input;
  const mode = normalizedGatewayMode(source.GATEWAY_MODE);
  const appSecret = requiredInstallText(source.APP_SECRET, 'Application secret');
  if (appSecret.length < 32) throw new Error('Application secret must contain at least 32 characters');

  const changes = {
    APP_NAME: String(source.APP_NAME || 'G-Hotspot').trim() || 'G-Hotspot',
    DATABASE_PATH: String(source.DATABASE_PATH || './data/hotspot.db').trim() || './data/hotspot.db',
    APP_SECRET: appSecret,
    DEFAULT_LANGUAGE: normalizedInstallLanguage(source.DEFAULT_LANGUAGE),
    ADMIN_USERNAME: requiredInstallText(source.ADMIN_USERNAME || 'admin', 'Admin username'),
    ADMIN_PASSWORD: requiredInstallText(source.ADMIN_PASSWORD, 'Admin password'),
    ADMIN_SESSION_HOURS: installInteger(source.ADMIN_SESSION_HOURS, 12, {
      min: 1,
      max: 168,
      label: 'Admin session lifetime'
    }),
    GATEWAY_MODE: mode,
    OPNSENSE_ZONE_ID: installInteger(source.OPNSENSE_ZONE_ID, 0, {
      min: 0,
      max: 19,
      label: 'OPNsense zone ID'
    }),
    OPNSENSE_TLS_REJECT_UNAUTHORIZED: installBoolean(source.OPNSENSE_TLS_REJECT_UNAUTHORIZED, true)
  };

  if (mode === 'opnsense-api') {
    changes.OPNSENSE_BASE_URL = installUrl(source.OPNSENSE_BASE_URL);
    changes.OPNSENSE_API_KEY = requiredInstallText(source.OPNSENSE_API_KEY, 'OPNsense API key');
    changes.OPNSENSE_API_SECRET = requiredInstallText(source.OPNSENSE_API_SECRET, 'OPNsense API secret');
  } else {
    for (const key of ['OPNSENSE_BASE_URL', 'OPNSENSE_API_KEY', 'OPNSENSE_API_SECRET']) {
      if (source[key] != null) changes[key] = String(source[key] || '').trim();
    }
  }

  const previousSettings = readSystemSettings();
  const optionalChanges = Object.fromEntries(
    Object.entries(collectSettingsChanges(source)).filter(([key]) => installOptionalSettingKeys.has(key))
  );
  Object.assign(changes, withSmtpFrom(
    optionalChanges,
    source,
    previousSettings,
    true
  ));

  const saved = Object.fromEntries(
    Object.entries(changes).filter(([key]) => installSettingKeys.has(key))
  );
  const previousMeta = readSystemMeta();
  const previousProcessValues = processSnapshot(Object.keys(saved));
  try {
    writeSystemSettings(saved);
    markSystemInstalled();
    loadSystemSettingsIntoEnv({ importEnv: false });
    reloadConfig();
  } catch (error) {
    replaceSystemSettings(previousSettings);
    replaceSystemMeta(previousMeta);
    loadSystemSettingsIntoEnv({ importEnv: false });
    restoreProcessSnapshot(previousProcessValues);
    reloadConfig();
    throw error;
  }

  return {
    installed: true,
    saved: Object.keys(saved),
    appName: process.env.APP_NAME || 'G-Hotspot',
    defaultLanguage: process.env.DEFAULT_LANGUAGE || 'en',
    gatewayMode: process.env.GATEWAY_MODE || 'mock'
  };
}
