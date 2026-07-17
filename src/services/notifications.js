import { isValidEmail, isValidPhone, normalizeEmail, normalizePhone } from '../lib/security.js';
import { translate } from '../i18n.js';
import { sendMail } from './smtp.js';
import { sendSmsMessage } from './sms.js';
import { sendTelegramText } from './telegram.js';

const SYSLOG_STORAGE_EVENTS = new Set([
  'syslog_storage_status_failed',
  'syslog_storage_warning_threshold_reached',
  'syslog_storage_block_threshold_reached',
  'syslog_storage_blocked_portal',
  'syslog_storage_recovered'
]);
const SYSLOG_TIMESTAMP_EVENTS = new Set([
  'syslog_kamusm_timestamp_succeeded',
  'syslog_kamusm_timestamp_failed',
  'syslog_timestamp_succeeded',
  'syslog_timestamp_failed'
]);
const DEFAULT_ENABLED_NOTIFICATION_SETTINGS = new Set([
  'SyslogStorage',
  'SyslogKamusmSuccess',
  'SyslogKamusmFailure',
  'AdminApproval'
]);
const SYSTEM_NOTIFICATION_CHANNELS = ['email', 'sms', 'telegram', 'android'];
const ADMIN_APPROVAL_NOTIFICATION_CHANNELS = ['email', 'sms'];
const DEFAULT_SYSLOG_EMAIL_TEMPLATE = [
  '{appName} system notification',
  '',
  '{message}',
  '',
  'Type: {eventType}',
  'Severity: {severity}',
  'Log file: {logFile}',
  'Timestamp token: {timestampToken}',
  'Storage usage: {storageUsage}%'
].join('\n');
const DEFAULT_SYSLOG_SMS_TEMPLATE = '{appName}: {message}';
const DEFAULT_SYSLOG_TELEGRAM_TEMPLATE = DEFAULT_SYSLOG_SMS_TEMPLATE;
const DEFAULT_SYSTEM_EVENT_EMAIL_TEMPLATE = [
  '{systemNotification}',
  '',
  '{message}'
].join('\n');
const DEFAULT_SYSTEM_EVENT_SMS_TEMPLATE = '{appName}: {message}';
const DEFAULT_SYSTEM_EVENT_TELEGRAM_TEMPLATE = DEFAULT_SYSTEM_EVENT_SMS_TEMPLATE;
const DEFAULT_ADMIN_APPROVAL_EMAIL_TEMPLATE = [
  '{appName} admin approval result',
  '',
  '{decisionText}',
  '',
  'Decision time: {decisionAt}',
  'Validity: {validity}',
  'Valid until: {validUntil}'
].join('\n');
const DEFAULT_ADMIN_APPROVAL_SMS_TEMPLATE =
  '{appName}: {decisionText} Decision time: {decisionAt}. Validity: {validity}.';

function recipients(value) {
  return String(value || '')
    .split(/[\n;,]+/u)
    .map(item => item.trim())
    .filter(Boolean);
}

function eventType(event) {
  return String(event?.eventType || event?.event_type || '');
}

function eventSeverity(event) {
  return String(event?.severity || 'info');
}

function eventMessage(event) {
  return String(event?.message || eventType(event) || 'System notification');
}

function eventDetail(event) {
  const detail = event?.detail ?? event?.detail_json ?? null;
  if (!detail || typeof detail === 'object') return detail || {};
  try {
    return JSON.parse(detail);
  } catch {
    return {};
  }
}

function storageDetail(detail) {
  const storage = detail.storage || detail;
  return {
    directory: storage.directory || '',
    usagePercent: storage.usagePercent ?? '',
    alertPercent: storage.alertPercent ?? '',
    blockPercent: storage.blockPercent ?? '',
    freeBytes: storage.freeBytes ?? ''
  };
}

function formatBytes(value) {
  const bytes = Math.max(0, Number(value) || 0);
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const amount = bytes / 1024 ** index;
  return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
}

function basename(value) {
  return String(value || '').split(/[\\/]/u).filter(Boolean).at(-1) || '';
}

function isSyslogNotificationEvent(event) {
  const type = eventType(event);
  return SYSLOG_STORAGE_EVENTS.has(type) || SYSLOG_TIMESTAMP_EVENTS.has(type);
}

function notificationSubject(config, event) {
  const severity = eventSeverity(event).toUpperCase();
  return `${config.appName || 'G-Hotspot'} ${severity}: ${localizedEventMessage(config, event)}`.slice(0, 180);
}

function templateVariables(config, event) {
  const detail = eventDetail(event);
  const storage = storageDetail(detail);
  const severity = eventSeverity(event);
  const variables = {
    appName: config.appName || 'G-Hotspot',
    systemNotification: translate(config.defaultLanguage || 'en', 'systemNotification', {
      appName: config.appName || 'G-Hotspot'
    }),
    message: localizedEventMessage(config, event),
    eventType: eventType(event),
    type: eventType(event),
    severity,
    warning: severity,
    storageUsage: storage.usagePercent,
    usage: storage.usagePercent,
    warningThreshold: storage.alertPercent,
    'w-threshold': storage.alertPercent,
    alertThreshold: storage.alertPercent,
    blockThreshold: storage.blockPercent,
    'b-threshold': storage.blockPercent,
    freeBytes: storage.freeBytes,
    freeDisk: storage.freeBytes === '' ? '' : formatBytes(storage.freeBytes),
    free: storage.freeBytes === '' ? '' : formatBytes(storage.freeBytes),
    logFile: basename(detail.filePath),
    filePath: detail.filePath || '',
    timestampToken: basename(detail.timestampTokenPath),
    timestampTokenPath: detail.timestampTokenPath || '',
    timestampRequest: basename(detail.timestampRequestPath),
    timestampRequestPath: detail.timestampRequestPath || '',
    recordCount: detail.recordCount ?? '',
    periodStart: detail.periodStartAt ?? '',
    periodEnd: detail.periodEndAt ?? '',
    authorizationId: detail.authorizationId || '',
    method: detail.method || '',
    identity: detail.identity || '',
    clientIp: detail.clientIp || '',
    clientMac: detail.clientMac || '',
    adminUser: detail.adminUser || '',
    error: detail.error || '',
    gatewayMode: detail.gatewayMode || '',
    gatewayBaseUrl: detail.gatewayBaseUrl || '',
    expiresAt: detail.expiresAt ? formatDateTime(config, detail.expiresAt) : ''
  };
  return variables;
}

function localizedEventMessage(config, event) {
  const language = config.defaultLanguage || 'en';
  const detail = eventDetail(event);
  const storage = storageDetail(detail);
  const usage = storage.usagePercent === '' ? '' : storage.usagePercent;
  if (eventType(event) === 'syslog_storage_status_failed') {
    return translate(language, 'syslogStorageStatusFailed', {
      error: detail.error || storage.error || eventMessage(event)
    });
  }
  if (['syslog_storage_warning_threshold_reached', 'syslog_storage_block_threshold_reached'].includes(eventType(event))) {
    return translate(language, 'syslogStorageFull', { usage });
  }
  if (eventType(event) === 'syslog_storage_blocked_portal') {
    return translate(language, 'syslogStorageBlockedPortal', { usage: storage.usagePercent || detail.storage?.usagePercent || '' });
  }
  if (eventType(event) === 'syslog_storage_recovered') {
    return translate(language, 'syslogStorageRecovered', { usage });
  }
  if (eventType(event) === 'syslog_kamusm_timestamp_succeeded') {
    return translate(language, 'syslogKamusmTimestampSucceeded', {
      file: basename(detail.filePath) || eventMessage(event)
    });
  }
  if (eventType(event) === 'syslog_kamusm_timestamp_failed') {
    return translate(language, 'syslogKamusmTimestampFailed', {
      file: basename(detail.filePath) || '',
      error: detail.timestampError || eventMessage(event)
    });
  }
  if (eventType(event) === 'syslog_timestamp_succeeded') {
    return translate(language, 'syslogTimestampSucceeded', {
      file: basename(detail.filePath) || eventMessage(event)
    });
  }
  if (eventType(event) === 'syslog_timestamp_failed') {
    return translate(language, 'syslogTimestampFailed', {
      file: basename(detail.filePath) || '',
      error: detail.timestampError || eventMessage(event)
    });
  }
  if (['system_boot_detected', 'system_boot_observed', 'system_startup'].includes(eventType(event))) {
    return translate(language, 'systemStartupDetected');
  }
  if (eventType(event) === 'opnsense_connection_lost') {
    return translate(language, 'opnsenseConnectionLost', {
      error: detail.error || eventMessage(event)
    });
  }
  if (eventType(event) === 'user_verified') {
    return translate(language, 'userVerifiedNotification', {
      method: detail.method || '',
      identity: detail.identity || '',
      clientIp: detail.clientIp || ''
    });
  }
  if (eventType(event) === 'access_expired') {
    return translate(language, 'accessExpiredNotification', {
      method: detail.method || '',
      identity: detail.identity || '',
      clientIp: detail.clientIp || ''
    });
  }
  if (eventType(event) === 'admin_login_succeeded') {
    return translate(language, 'adminLoginNotification', {
      adminUser: detail.adminUser || '',
      clientIp: detail.clientIp || ''
    });
  }
  if (eventType(event) === 'admin_login_failed') {
    return translate(language, 'adminLoginFailedNotification', {
      adminUser: detail.adminUser || '',
      clientIp: detail.clientIp || '',
      error: detail.error || eventMessage(event)
    });
  }
  if (eventMessage(event) === 'System notification') {
    return translate(language, 'systemNotification', { appName: config.appName || 'G-Hotspot' });
  }
  return eventMessage(event);
}

function locale(config) {
  return config.defaultLanguage || 'en';
}

function formatDateTime(config, value) {
  if (!value) return '';
  const date = new Date(Number(value));
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat(locale(config), {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: config.law5651?.timeZone || config.syslog?.timeZone || undefined
  }).format(date);
}

function durationParts(duration = {}) {
  return {
    value: Math.max(1, Number(duration.value) || 1),
    unit: String(duration.unit || 'hours')
  };
}

function formatDuration(config, duration = {}) {
  const { value, unit } = durationParts(duration);
  if (unit === 'unlimited') return locale(config) === 'tr' ? 'Suresiz' : 'Unlimited';
  const labels = locale(config) === 'tr'
    ? { minutes: 'dakika', hours: 'saat', days: 'gun', months: 'ay', years: 'yil' }
    : { minutes: 'minute', hours: 'hour', days: 'day', months: 'month', years: 'year' };
  const label = labels[unit] || unit;
  if (locale(config) === 'tr') return `${value} ${label}`;
  return `${value} ${label}${value === 1 ? '' : 's'}`;
}

const TEMPLATE_PLACEHOLDER_PATTERN = /\{([A-Za-z][A-Za-z0-9-]*)\}/g;

function templatePlaceholderNames(text, variables) {
  return [...String(text || '').matchAll(TEMPLATE_PLACEHOLDER_PATTERN)]
    .map(match => match[1])
    .filter(key => Object.hasOwn(variables, key));
}

function templateValueIsEmpty(variables, key) {
  return String(variables[key] ?? '').trim() === '';
}

function replaceTemplatePlaceholders(text, variables) {
  return String(text || '').replace(TEMPLATE_PLACEHOLDER_PATTERN, (match, key) =>
    Object.hasOwn(variables, key) ? String(variables[key] ?? '') : match
  );
}

function removeEmptyTemplateSegments(line, variables) {
  const names = templatePlaceholderNames(line, variables);
  if (names.length && names.every(key => templateValueIsEmpty(variables, key))) return '';
  const pruned = String(line).includes(',')
    ? String(line).split(',')
      .map(segment => segment.trim())
      .filter(segment => {
        const segmentNames = templatePlaceholderNames(segment, variables);
        return !segmentNames.length || segmentNames.some(key => !templateValueIsEmpty(variables, key));
      })
      .join(', ')
    : String(line);
  return replaceTemplatePlaceholders(pruned, variables)
    .replace(/\s*[\[(]\s*[\])]/gu, '')
    .replace(/\s+,/gu, ',')
    .replace(/,\s*([.!?;:])/gu, '$1')
    .replace(/,\s*$/gu, '')
    .replace(/\s{2,}/gu, ' ')
    .trimEnd();
}

function renderNotificationTemplate(template, variables) {
  return String(template || '')
    .replace(/\r\n?/gu, '\n')
    .split('\n')
    .map(line => removeEmptyTemplateSegments(line, variables))
    .filter((line, index, lines) => line || (lines[index - 1] && lines[index + 1]))
    .join('\n')
    .replace(/\n{3,}/gu, '\n\n')
    .trim();
}

function adminApprovalTemplateVariables(config, request, decision = {}) {
  const status = String(decision.status || request.status || '');
  const approved = status === 'approved';
  const decisionAt = Number(decision.decidedAt || request.decided_at || Date.now());
  const validUntil = approved
    ? Number(decision.expiresAt || request.access_expires_at || 0)
    : 0;
  const validity = approved
    ? formatDuration(config, config.adminApproval?.accessDuration)
    : (locale(config) === 'tr' ? 'Erisim verilmedi' : 'No access granted');
  return {
    appName: config.appName || 'G-Hotspot',
    fullName: request.full_name || request.fullName || '',
    contact: request.contact || '',
    decisionText: decision.message || request.decision_message || '',
    decisionAt: formatDateTime(config, decisionAt),
    validity,
    validUntil: validUntil ? formatDateTime(config, validUntil) : '-',
    status,
    statusText: approved
      ? (locale(config) === 'tr' ? 'Onaylandi' : 'Approved')
      : (locale(config) === 'tr' ? 'Reddedildi' : 'Rejected')
  };
}

export function renderAdminApprovalNotificationTemplate(template, config, request, decision = {}) {
  const variables = adminApprovalTemplateVariables(config, request, decision);
  return renderNotificationTemplate(template, variables);
}

export function renderSystemNotificationTemplate(template, config, event) {
  const variables = templateVariables(config, event);
  return renderNotificationTemplate(template, variables);
}

function renderInlineMarkdown(value) {
  return escapeHtml(value)
    .replace(/`([^`]+)`/gu, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/gu, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/gu, '<em>$1</em>');
}

export function markdownToSafeHtml(markdown) {
  const lines = String(markdown || '').replace(/\r\n?/gu, '\n').split('\n');
  const blocks = [];
  let paragraph = [];
  let list = [];
  const flushParagraph = () => {
    if (!paragraph.length) return;
    blocks.push(`<p>${paragraph.map(renderInlineMarkdown).join('<br>')}</p>`);
    paragraph = [];
  };
  const flushList = () => {
    if (!list.length) return;
    blocks.push(`<ul>${list.map(item => `<li>${renderInlineMarkdown(item)}</li>`).join('')}</ul>`);
    list = [];
  };
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      flushParagraph();
      flushList();
      continue;
    }
    const heading = trimmed.match(/^(#{1,3})\s+(.+)$/u);
    if (heading) {
      flushParagraph();
      flushList();
      const level = heading[1].length;
      blocks.push(`<h${level}>${renderInlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }
    const bullet = trimmed.match(/^[-*]\s+(.+)$/u);
    if (bullet) {
      flushParagraph();
      list.push(bullet[1]);
      continue;
    }
    flushList();
    paragraph.push(trimmed);
  }
  flushParagraph();
  flushList();
  return blocks.join('') || '<p></p>';
}

function systemNotificationSetting(event) {
  const type = eventType(event);
  if (SYSLOG_STORAGE_EVENTS.has(type)) {
    return 'SyslogStorage';
  }
  if (type === 'syslog_kamusm_timestamp_succeeded' || type === 'syslog_timestamp_succeeded') {
    return 'SyslogKamusmSuccess';
  }
  if (type === 'syslog_kamusm_timestamp_failed' || type === 'syslog_timestamp_failed') {
    return 'SyslogKamusmFailure';
  }
  if (SYSLOG_TIMESTAMP_EVENTS.has(type)) return 'SyslogKamusm';
  if (type === 'system_startup') return 'SystemStartup';
  if (type === 'opnsense_connection_lost') return 'OpnsenseDown';
  if (type === 'user_verified') return 'UserVerified';
  if (type === 'access_expired') return 'AccessExpired';
  if (type === 'admin_login_succeeded') return 'AdminLogin';
  if (type === 'admin_login_failed') return 'AdminLoginFailed';
  return '';
}

function notificationSettingEnabled(notifications, setting, channel = null, availableChannels = SYSTEM_NOTIFICATION_CHANNELS) {
  if (!setting) return false;
  const legacyKey = `${setting.charAt(0).toLowerCase()}${setting.slice(1)}Enabled`;
  if (channel) {
    const channelKey = `${channel}${setting}Enabled`;
    if (Object.hasOwn(notifications, channelKey)) return notifications[channelKey] !== false;
    if (Object.hasOwn(notifications, legacyKey)) return notifications[legacyKey] !== false;
    return DEFAULT_ENABLED_NOTIFICATION_SETTINGS.has(setting);
  }
  if (
    availableChannels.some(item => Object.hasOwn(notifications, `${item}${setting}Enabled`))
  ) {
    return availableChannels.some(item =>
      Object.hasOwn(notifications, `${item}${setting}Enabled`) &&
      notificationSettingEnabled(notifications, setting, item, availableChannels)
    );
  }
  if (Object.hasOwn(notifications, legacyKey)) return notifications[legacyKey] !== false;
  return availableChannels.some(item => notificationSettingEnabled(notifications, setting, item, availableChannels));
}

function adminApprovalNotificationEnabled(notifications, channel = null) {
  return notificationSettingEnabled(notifications, 'AdminApproval', channel, ADMIN_APPROVAL_NOTIFICATION_CHANNELS);
}

export function shouldNotifySystemEvent(config, event, channel = null) {
  const notifications = config.notifications || {};
  const setting = systemNotificationSetting(event);
  if (setting === 'SyslogKamusm') return true;
  if (!setting) return false;
  return notificationSettingEnabled(notifications, setting, channel);
}

function enabledSystemNotificationChannels(config, event, channels) {
  return [...new Set(channels || SYSTEM_NOTIFICATION_CHANNELS)]
    .filter(channel => shouldNotifySystemEvent(config, event, channel));
}

function adminApprovalDisabledResult(notifications) {
  if (!adminApprovalNotificationEnabled(notifications)) {
    return { sent: 0, skipped: true, reason: 'disabled' };
  }
  return false;
}

export async function sendAdminApprovalNotification(config, request, decision = {}, { logger = console } = {}) {
  const notifications = config.notifications || {};
  const disabled = adminApprovalDisabledResult(notifications);
  if (disabled) return disabled;

  const contactType = String(request.contact_type || request.contactType || 'none');
  const contact = String(request.contact || '').trim();
  if (!contact || contactType === 'none') {
    return { sent: 0, skipped: true, reason: 'no_contact' };
  }

  const tasks = [];
  if (
    contactType === 'email' &&
    adminApprovalNotificationEnabled(notifications, 'email') &&
    notifications.emailEnabled &&
    config.smtp?.enabled
  ) {
    const to = normalizeEmail(contact);
    if (isValidEmail(to)) {
      const text = renderAdminApprovalNotificationTemplate(
        notifications.adminApprovalEmailTemplateMarkdown || DEFAULT_ADMIN_APPROVAL_EMAIL_TEMPLATE,
        config,
        request,
        decision
      );
      const html = `<div style="font-family:system-ui,sans-serif;max-width:620px;margin:auto">
        ${markdownToSafeHtml(text)}
      </div>`;
      tasks.push(sendMail(config.smtp, {
        to,
        subject: `${config.appName || 'G-Hotspot'} admin approval ${decision.status || request.status}`,
        text,
        html
      }));
    } else {
      logger.warn?.(`Admin approval email contact is invalid: ${contact}`);
    }
  }

  if (
    contactType === 'phone' &&
    adminApprovalNotificationEnabled(notifications, 'sms') &&
    notifications.smsEnabled &&
    config.sms?.enabled
  ) {
    const phone = normalizePhone(contact, config.defaultCountryCode);
    if (isValidPhone(phone)) {
      const message = renderAdminApprovalNotificationTemplate(
        notifications.adminApprovalSmsTemplate || DEFAULT_ADMIN_APPROVAL_SMS_TEMPLATE,
        config,
        request,
        decision
      ).slice(0, 480);
      tasks.push(sendSmsMessage(config.sms, { phone, message, appName: config.appName }));
    } else {
      logger.warn?.(`Admin approval phone contact is invalid: ${contact}`);
    }
  }

  if (!tasks.length) return { sent: 0, skipped: true, reason: 'no_matching_channel' };
  const results = await Promise.allSettled(tasks);
  const failed = results.filter(item => item.status === 'rejected');
  for (const failure of failed) {
    logger.warn?.(`Admin approval notification delivery failed: ${failure.reason?.message || failure.reason}`);
  }
  return {
    sent: results.length - failed.length,
    failed: failed.length
  };
}

export async function sendSystemNotification(config, event, {
  logger = console,
  channels = null,
  androidNotifier = null
} = {}) {
  const channelSet = new Set(enabledSystemNotificationChannels(config, event, channels));
  if (!channelSet.size) {
    return { sent: 0, skipped: true, reason: 'disabled' };
  }

  const notifications = config.notifications || {};
  const tasks = [];

  if (channelSet.has('email') && notifications.emailEnabled && config.smtp?.enabled) {
    const subject = notificationSubject(config, event);
    const template = isSyslogNotificationEvent(event)
      ? (notifications.syslogEmailTemplateMarkdown || DEFAULT_SYSLOG_EMAIL_TEMPLATE)
      : (notifications.systemEmailTemplateMarkdown || DEFAULT_SYSTEM_EVENT_EMAIL_TEMPLATE);
    const text = renderSystemNotificationTemplate(
      template,
      config,
      event
    );
    const html = `<div style="font-family:system-ui,sans-serif;max-width:620px;margin:auto">
      ${markdownToSafeHtml(text)}
    </div>`;
    for (const raw of recipients(notifications.emailRecipients)) {
      const to = normalizeEmail(raw);
      if (!isValidEmail(to)) {
        logger.warn?.(`System notification email recipient is invalid: ${raw}`);
        continue;
      }
      tasks.push(sendMail(config.smtp, { to, subject, text, html }));
    }
  }

  if (channelSet.has('sms') && notifications.smsEnabled && config.sms?.enabled) {
    const template = isSyslogNotificationEvent(event)
      ? (notifications.syslogSmsTemplate || DEFAULT_SYSLOG_SMS_TEMPLATE)
      : (notifications.systemSmsTemplate || DEFAULT_SYSTEM_EVENT_SMS_TEMPLATE);
    const message = renderSystemNotificationTemplate(
      template,
      config,
      event
    ).slice(0, 480);
    for (const raw of recipients(notifications.smsRecipients)) {
      const phone = normalizePhone(raw, config.defaultCountryCode);
      if (!isValidPhone(phone)) {
        logger.warn?.(`System notification SMS recipient is invalid: ${raw}`);
        continue;
      }
      tasks.push(sendSmsMessage(config.sms, { phone, message, appName: config.appName }));
    }
  }

  if (channelSet.has('telegram') && notifications.telegramEnabled && config.telegram?.enabled) {
    const template = isSyslogNotificationEvent(event)
      ? (notifications.syslogTelegramTemplate || DEFAULT_SYSLOG_TELEGRAM_TEMPLATE)
      : (notifications.systemTelegramTemplate || DEFAULT_SYSTEM_EVENT_TELEGRAM_TEMPLATE);
    const text = renderSystemNotificationTemplate(
      template,
      config,
      event
    ).slice(0, 3900);
    for (const chatId of recipients(notifications.telegramRecipients)) {
      tasks.push(sendTelegramText(config.telegram, { chatId, text }));
    }
  }

  if (channelSet.has('android') && notifications.androidEnabled && typeof androidNotifier === 'function') {
    const template = isSyslogNotificationEvent(event)
      ? (notifications.syslogAndroidTemplate || notifications.syslogTelegramTemplate || DEFAULT_SYSLOG_TELEGRAM_TEMPLATE)
      : (notifications.systemAndroidTemplate || notifications.systemTelegramTemplate || DEFAULT_SYSTEM_EVENT_TELEGRAM_TEMPLATE);
    const body = renderSystemNotificationTemplate(
      template,
      config,
      event
    ).slice(0, 1000);
    tasks.push(Promise.resolve(androidNotifier({
      title: notificationSubject(config, event),
      body,
      event
    })));
  }

  if (!tasks.length) return { sent: 0, skipped: true, reason: 'no_recipients_or_channels' };
  const results = await Promise.allSettled(tasks);
  const failed = results.filter(item => item.status === 'rejected');
  for (const failure of failed) {
    logger.warn?.(`System notification delivery failed: ${failure.reason?.message || failure.reason}`);
  }
  return {
    sent: results.length - failed.length,
    failed: failed.length
  };
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}
