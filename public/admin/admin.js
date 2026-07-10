const state = {
  csrfToken: '',
  user: '',
  appName: 'G-Hotspot',
  gatewayMode: '',
  currentView: 'dashboard',
  createdVouchers: [],
  settings: null,
  settingsGroup: 'general',
  notificationTemplateKey: '',
  sessionRows: [],
  sessionColumns: null,
  pendingSessionActions: {},
  trafficPeriod: 'daily',
  topSitesHours: 6,
  topBandwidthHours: 6,
  trafficLogSettings: null,
  trafficLogRows: [],
  trafficLogLivePaused: false,
  lastTrafficLogRefreshAt: 0,
  opnsenseTemplateDefaults: null,
  about: null,
  releaseInfo: null,
  gatewayInterfaces: null,
  gatewayNetworks: null,
  adminApprovalRefreshPending: false,
  pendingAdminApprovalDecisions: {},
  lastAdminApprovalRefreshAt: 0
};

let adminPublicIpLookupPromise = null;
let releaseCheckPromise = null;
const buttonBusyHtml = new WeakMap();

const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const i18n = window.GH_I18N;
const t = (text, variables) => i18n.t(text, variables);
const DEFAULT_TERMS_TEXT = 'By continuing, you accept the terms of use for this guest network.';
const DEFAULT_NETWORK_LABEL_TEXT = 'GUEST NETWORK';
const DEFAULT_VERIFICATION_PROMPT_TEXT = 'Choose a verification method to open internet access.';
const APP_VERSION = '1.0.0';
const ADMIN_PUBLIC_IP_LOOKUP_URL = 'https://api.ipify.org?format=json';
const SESSION_COLUMNS_STORAGE_KEY = 'gh_admin_session_columns';
const SIDEBAR_MINI_STORAGE_KEY = 'gh_admin_sidebar_mini';
const THEME_STORAGE_KEY = 'gh_admin_theme';
const DASHBOARD_FILTERS_STORAGE_KEY = 'gh_admin_dashboard_filters';
const OPNSENSE_TEMPLATE_STORAGE_KEY = 'gh_admin_opnsense_template';
const RELEASE_POPUP_STORAGE_KEY = 'gh_admin_release_popup_seen';
const DASHBOARD_TRAFFIC_PERIODS = new Set(['hourly', '6h', '12h', 'daily', 'weekly', 'monthly']);
const DASHBOARD_HOUR_RANGES = new Set([1, 6, 12, 24]);
let resetSettingsScrollOnRender = false;
const TRAFFIC_LOG_STREAM_ICONS = {
  pause: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/></svg>',
  play: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14l11-7-11-7Z"/></svg>'
};
const MB = 1024 * 1024;
const APPEARANCE_ASSET_FALLBACK_LIMITS = {
  logo: 2 * MB,
  'card-background': 20 * MB,
  'body-background': 20 * MB
};
const APPEARANCE_UPLOAD_CHUNK_BYTES = 768 * 1024;
const NOTIFICATION_ALERT_TYPE_GROUPS = [
  {
    label: 'Email alert types',
    visibleWhen: 'NOTIFICATION_EMAIL_ENABLED',
    keys: [
      'NOTIFICATION_EMAIL_SYSLOG_STORAGE_ENABLED',
      'NOTIFICATION_EMAIL_SYSLOG_KAMUSM_SUCCESS_ENABLED',
      'NOTIFICATION_EMAIL_SYSLOG_KAMUSM_FAILURE_ENABLED',
      'NOTIFICATION_EMAIL_SYSTEM_STARTUP_ENABLED',
      'NOTIFICATION_EMAIL_OPNSENSE_DOWN_ENABLED',
      'NOTIFICATION_EMAIL_USER_VERIFIED_ENABLED',
      'NOTIFICATION_EMAIL_ACCESS_EXPIRED_ENABLED',
      'NOTIFICATION_EMAIL_ADMIN_LOGIN_ENABLED',
      'NOTIFICATION_EMAIL_ADMIN_LOGIN_FAILED_ENABLED'
    ]
  },
  {
    label: 'SMS alert types',
    visibleWhen: 'NOTIFICATION_SMS_ENABLED',
    keys: [
      'NOTIFICATION_SMS_SYSLOG_STORAGE_ENABLED',
      'NOTIFICATION_SMS_SYSLOG_KAMUSM_SUCCESS_ENABLED',
      'NOTIFICATION_SMS_SYSLOG_KAMUSM_FAILURE_ENABLED',
      'NOTIFICATION_SMS_SYSTEM_STARTUP_ENABLED',
      'NOTIFICATION_SMS_OPNSENSE_DOWN_ENABLED',
      'NOTIFICATION_SMS_USER_VERIFIED_ENABLED',
      'NOTIFICATION_SMS_ACCESS_EXPIRED_ENABLED',
      'NOTIFICATION_SMS_ADMIN_LOGIN_ENABLED',
      'NOTIFICATION_SMS_ADMIN_LOGIN_FAILED_ENABLED'
    ]
  },
  {
    label: 'Telegram alert types',
    visibleWhen: 'NOTIFICATION_TELEGRAM_ENABLED',
    visibleWhenAll: ['TELEGRAM_ENABLED'],
    keys: [
      'NOTIFICATION_TELEGRAM_SYSLOG_STORAGE_ENABLED',
      'NOTIFICATION_TELEGRAM_SYSLOG_KAMUSM_SUCCESS_ENABLED',
      'NOTIFICATION_TELEGRAM_SYSLOG_KAMUSM_FAILURE_ENABLED',
      'NOTIFICATION_TELEGRAM_SYSTEM_STARTUP_ENABLED',
      'NOTIFICATION_TELEGRAM_OPNSENSE_DOWN_ENABLED',
      'NOTIFICATION_TELEGRAM_USER_VERIFIED_ENABLED',
      'NOTIFICATION_TELEGRAM_ACCESS_EXPIRED_ENABLED',
      'NOTIFICATION_TELEGRAM_ADMIN_LOGIN_ENABLED',
      'NOTIFICATION_TELEGRAM_ADMIN_LOGIN_FAILED_ENABLED'
    ]
  }
];
const NOTIFICATION_TEMPLATE_PLACEHOLDERS = {
  syslog: [
    ['appName', 'Configured application name.', 'G-Hotspot'],
    ['systemNotification', 'Localized system notification title.', 'G-Hotspot system notification'],
    ['message', 'Human-readable event message.', 'Syslog storage is 85% full.'],
    ['eventType', 'Internal event code for diagnostics.', 'syslog_storage_warning_threshold_reached'],
    ['severity', 'Event severity.', 'warning'],
    ['storageUsage', 'Current syslog storage usage percentage.', '85'],
    ['warningThreshold', 'Configured warning threshold percentage.', '80'],
    ['blockThreshold', 'Configured block threshold percentage.', '95'],
    ['freeDisk', 'Formatted free disk space.', '12 GB'],
    ['logFile', 'Daily log file name.', '2026-06-30.log'],
    ['timestampToken', 'Timestamp token file name.', '2026-06-30.log.tsr']
  ],
  system: [
    ['appName', 'Configured application name.', 'G-Hotspot'],
    ['systemNotification', 'Localized system notification title.', 'G-Hotspot system notification'],
    ['message', 'Human-readable event message.', 'Administrator GkhnG signed in from 203.0.113.10.'],
    ['eventType', 'Internal event code for diagnostics.', 'admin_login_succeeded'],
    ['severity', 'Event severity.', 'info'],
    ['clientIp', 'Client or administrator source IP address.', '203.0.113.10'],
    ['clientMac', 'Client MAC address when known.', 'AA:BB:CC:DD:EE:FF'],
    ['method', 'Verification method.', 'voucher'],
    ['identity', 'User identity or voucher id.', 'LOBBY-001'],
    ['adminUser', 'Administrator username.', 'GkhnG'],
    ['error', 'Failure reason when available.', 'OPNsense API request timed out'],
    ['expiresAt', 'Access expiration time.', 'Jun 30, 2026 14:30']
  ],
  adminApproval: [
    ['appName', 'Configured application name.', 'G-Hotspot'],
    ['fullName', 'Guest full name.', 'Ada Lovelace'],
    ['contact', 'Guest contact address or phone.', 'ada@example.com'],
    ['decisionText', 'Approval or rejection message.', 'Your request was approved.'],
    ['decisionAt', 'Decision time.', 'Jun 30, 2026 14:30'],
    ['validity', 'Granted access duration.', '2 hours'],
    ['validUntil', 'Access expiration time.', 'Jun 30, 2026 16:30'],
    ['status', 'Decision status.', 'approved']
  ]
};

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function safeTooltipAccent(value) {
  const color = String(value || '').trim();
  return /^#[0-9a-f]{3,8}$/iu.test(color) ? color : '#6366f1';
}

function dashboardTooltipAttributes({ title, accent, rows = [], foot = '' }) {
  const attributes = [
    'data-dashboard-tooltip',
    `data-tooltip-title="${escapeHtml(title)}"`,
    `data-tooltip-accent="${escapeHtml(safeTooltipAccent(accent))}"`
  ];
  rows.slice(0, 3).forEach((row, index) => {
    const position = index + 1;
    attributes.push(`data-tooltip-label-${position}="${escapeHtml(row.label)}"`);
    attributes.push(`data-tooltip-value-${position}="${escapeHtml(row.value)}"`);
  });
  if (foot) attributes.push(`data-tooltip-foot="${escapeHtml(foot)}"`);
  return attributes.join(' ');
}

function dashboardTooltipElement() {
  let tooltip = $('#dashboardTooltip');
  if (!tooltip) {
    tooltip = document.createElement('div');
    tooltip.id = 'dashboardTooltip';
    tooltip.className = 'dashboard-tooltip hidden';
    tooltip.setAttribute('aria-hidden', 'true');
    document.body.append(tooltip);
  }
  return tooltip;
}

function dashboardTooltipRows(target) {
  return [1, 2, 3].map(index => {
    const label = target.getAttribute(`data-tooltip-label-${index}`);
    const value = target.getAttribute(`data-tooltip-value-${index}`);
    return label && value ? { label, value } : null;
  }).filter(Boolean);
}

function positionDashboardTooltip(event) {
  const tooltip = $('#dashboardTooltip');
  if (!tooltip || tooltip.classList.contains('hidden')) return;
  const margin = 12;
  const gap = 18;
  const width = tooltip.offsetWidth;
  const height = tooltip.offsetHeight;
  let left = event.clientX + gap;
  let top = event.clientY - height - gap;
  if (left + width + margin > window.innerWidth) left = event.clientX - width - gap;
  if (left < margin) left = margin;
  if (top < margin) top = event.clientY + gap;
  if (top + height + margin > window.innerHeight) top = window.innerHeight - height - margin;
  tooltip.style.left = `${Math.round(left)}px`;
  tooltip.style.top = `${Math.round(Math.max(margin, top))}px`;
}

function showDashboardTooltip(target, event) {
  const tooltip = dashboardTooltipElement();
  const rows = dashboardTooltipRows(target);
  const title = target.getAttribute('data-tooltip-title') || '';
  const foot = target.getAttribute('data-tooltip-foot') || '';
  const accent = safeTooltipAccent(target.getAttribute('data-tooltip-accent'));
  tooltip.style.setProperty('--tooltip-accent', accent);
  tooltip.innerHTML = `
    <div class="dashboard-tooltip__head"><span></span><strong>${escapeHtml(title)}</strong></div>
    <div class="dashboard-tooltip__metrics">
      ${rows.map(row => `<div><span>${escapeHtml(row.label)}</span><strong>${escapeHtml(row.value)}</strong></div>`).join('')}
    </div>
    ${foot ? `<div class="dashboard-tooltip__foot">${escapeHtml(foot)}</div>` : ''}
  `;
  tooltip.classList.remove('hidden');
  positionDashboardTooltip(event);
}

function hideDashboardTooltip() {
  $('#dashboardTooltip')?.classList.add('hidden');
}

function api(path, options = {}) {
  return fetch(path, {
    ...options,
    headers: {
      ...(options.body ? { 'content-type': 'application/json' } : {}),
      ...(state.csrfToken ? { 'x-csrf-token': state.csrfToken } : {}),
      ...(options.headers || {})
    }
  }).then(async response => {
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401 && path !== '/api/admin/login') {
      showLogin();
      throw new Error(t('Your administrator session has expired.'));
    }
    if (!response.ok) {
      const message = payload.error === 'appearance_asset_too_large' && payload.maxBytes
        ? t('Image is too large. Maximum size is {maxSize}.', { maxSize: formatBytes(payload.maxBytes) })
        : t(payload.message || `HTTP ${response.status}`);
      throw new Error(message);
    }
    return payload;
  });
}

function publicNotificationIp(value) {
  const ip = String(value || '').trim();
  if (!ip) return '';
  const ipv4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u);
  if (ipv4) {
    const parts = ipv4.slice(1).map(Number);
    if (parts.some(part => part < 0 || part > 255)) return '';
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return '';
    return ip;
  }
  if (!/^[0-9a-f:]+$/iu.test(ip) || !ip.includes(':')) return '';
  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80:')) return '';
  return ip;
}

function lookupAdminPublicIp() {
  if (adminPublicIpLookupPromise) return adminPublicIpLookupPromise;
  adminPublicIpLookupPromise = (async () => {
    const controller = window.AbortController ? new AbortController() : null;
    const timeout = controller ? setTimeout(() => controller.abort(), 1400) : null;
    try {
      const response = await fetch(ADMIN_PUBLIC_IP_LOOKUP_URL, {
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        ...(controller ? { signal: controller.signal } : {})
      });
      if (!response.ok) return '';
      const payload = await response.json().catch(() => ({}));
      return publicNotificationIp(payload.ip);
    } catch {
      return '';
    } finally {
      if (timeout) clearTimeout(timeout);
    }
  })();
  return adminPublicIpLookupPromise;
}

function toast(message, type = 'success') {
  const element = document.createElement('div');
  element.className = `toast ${type}`;
  element.textContent = message;
  $('#toastRegion').append(element);
  setTimeout(() => element.remove(), 3800);
}

function setButtonBusy(button, busy, busyLabel = 'Processing…') {
  if (!button) return;
  button.disabled = busy;
  if (busy) {
    if (!buttonBusyHtml.has(button)) buttonBusyHtml.set(button, button.innerHTML);
    button.setAttribute('aria-busy', 'true');
    button.innerHTML = `<span class="button-spinner" aria-hidden="true"></span><span>${escapeHtml(t(busyLabel))}</span>`;
  } else {
    button.removeAttribute('aria-busy');
    if (buttonBusyHtml.has(button)) {
      button.innerHTML = buttonBusyHtml.get(button);
      buttonBusyHtml.delete(button);
    }
  }
}

function setPlainText(target, value) {
  const element = typeof target === 'string' ? $(target) : target;
  if (!element) return;
  const text = String(value ?? '');
  element.dataset.i18nSource = text;
  element.textContent = text;
}

function setSafeHtml(target, html) {
  const element = typeof target === 'string' ? $(target) : target;
  if (!element) return;
  element.innerHTML = html;
}

function portalPreviewDocumentName(value) {
  const raw = String(value || '').trim();
  if (!raw || raw.startsWith('//') || /^[a-z][a-z0-9+.-]*:/iu.test(raw)) return '';
  const normalized = raw
    .replace(/^[#]+/u, '')
    .replace(/^\.?\//u, '')
    .replace(/[?#].*$/u, '')
    .replace(/\/+$/u, '')
    .toLowerCase();
  return ['terms', 'policy', 'privacy'].includes(normalized) ? normalized : '';
}

function safePortalPreviewHref(value) {
  const raw = String(value || '').trim();
  if (!raw || raw.startsWith('//')) return '';
  const documentName = portalPreviewDocumentName(raw);
  if (documentName) return `#${documentName}`;
  try {
    const url = new URL(raw, location.origin);
    if (url.origin === location.origin && !/^[a-z][a-z0-9+.-]*:/iu.test(raw)) {
      return `${url.pathname}${url.search}${url.hash}`;
    }
    if (['http:', 'https:', 'mailto:', 'tel:'].includes(url.protocol)) return url.href;
  } catch {}
  return '';
}

function renderPortalPreviewBasicInlineMarkdown(value) {
  return escapeHtml(value)
    .replace(/\*\*([^*\n]+)\*\*/gu, '<strong>$1</strong>')
    .replace(/\*([^*\n]+)\*/gu, '<em>$1</em>');
}

function renderPortalPreviewInlineMarkdown(value) {
  const placeholders = [];
  const stash = html => {
    placeholders.push(html);
    return `\u0000${placeholders.length - 1}\u0000`;
  };
  let source = String(value ?? '');
  source = source.replace(/`([^`\n]+)`/gu, (match, code) =>
    stash(`<code>${escapeHtml(code)}</code>`)
  );
  source = source.replace(/\[([^\]\n]+)\]\(([^)\s]+)\)/gu, (match, label, href) => {
    const safeHref = safePortalPreviewHref(href);
    if (!safeHref) return match;
    return stash(
      `<a href="${escapeHtml(safeHref)}">${renderPortalPreviewBasicInlineMarkdown(label)}</a>`
    );
  });
  return renderPortalPreviewBasicInlineMarkdown(source)
    .replace(/\u0000(\d+)\u0000/gu, (match, index) => placeholders[Number(index)] || '');
}

function portalPreviewMarkdownToSafeHtml(markdown, emptyText = t('No terms have been configured yet.')) {
  const lines = String(markdown || '').replace(/\r\n?/gu, '\n').split('\n');
  const blocks = [];
  let paragraph = [];
  const flushParagraph = () => {
    const html = paragraph.map((item, itemIndex) => {
      const rendered = renderPortalPreviewInlineMarkdown(item.text);
      if (itemIndex >= paragraph.length - 1) return rendered;
      return `${rendered}${item.hardBreak ? '<br>' : ' '}`;
    }).join('').trim();
    if (html) blocks.push(`<p>${html}</p>`);
    paragraph = [];
  };
  let index = 0;
  while (index < lines.length) {
    const rawLine = lines[index];
    const line = rawLine.trim();
    if (!line) {
      flushParagraph();
      index += 1;
      continue;
    }
    if (/^```/u.test(line)) {
      flushParagraph();
      index += 1;
      const code = [];
      while (index < lines.length && !/^```/u.test(lines[index].trim())) {
        code.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      blocks.push(`<pre><code>${escapeHtml(code.join('\n'))}</code></pre>`);
      continue;
    }
    const heading = line.match(/^(#{1,4})\s+(.+)$/u);
    if (heading) {
      flushParagraph();
      const level = heading[1].length;
      blocks.push(`<h${level}>${renderPortalPreviewInlineMarkdown(heading[2])}</h${level}>`);
      index += 1;
      continue;
    }
    if (/^>\s?/u.test(line)) {
      flushParagraph();
      const quotes = [];
      while (index < lines.length && /^>\s?/u.test(lines[index].trim())) {
        quotes.push(renderPortalPreviewInlineMarkdown(lines[index].trim().replace(/^>\s?/u, '')));
        index += 1;
      }
      blocks.push(`<blockquote>${quotes.map(item => `<p>${item}</p>`).join('')}</blockquote>`);
      continue;
    }
    if (/^[-*]\s+/u.test(line)) {
      flushParagraph();
      const items = [];
      while (index < lines.length && /^[-*]\s+/u.test(lines[index].trim())) {
        items.push(`<li>${renderPortalPreviewInlineMarkdown(lines[index].trim().replace(/^[-*]\s+/u, ''))}</li>`);
        index += 1;
      }
      blocks.push(`<ul>${items.join('')}</ul>`);
      continue;
    }
    if (/^\d+\.\s+/u.test(line)) {
      flushParagraph();
      const items = [];
      while (index < lines.length && /^\d+\.\s+/u.test(lines[index].trim())) {
        items.push(`<li>${renderPortalPreviewInlineMarkdown(lines[index].trim().replace(/^\d+\.\s+/u, ''))}</li>`);
        index += 1;
      }
      blocks.push(`<ol>${items.join('')}</ol>`);
      continue;
    }
    paragraph.push({ text: line, hardBreak: /\s{2,}$/u.test(rawLine) });
    index += 1;
  }
  flushParagraph();
  return blocks.join('') || `<p>${escapeHtml(emptyText)}</p>`;
}

function setTranslatedText(target, source, variables) {
  const element = typeof target === 'string' ? $(target) : target;
  if (!element) return;
  element.dataset.i18nSource = source;
  element.textContent = t(source, variables);
}

function formatBytes(value) {
  const bytes = Math.max(0, Number(value) || 0);
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const amount = bytes / 1024 ** index;
  return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
}

function formatByteRate(value) {
  return `${formatBytes(value)}/s`;
}

function shortHash(value) {
  const text = String(value || '');
  return text ? `${text.slice(0, 12)}…${text.slice(-8)}` : '—';
}

function formatDate(value, withTime = true) {
  if (!value) return '—';
  const numeric = Number(value);
  const timestamp = Number.isFinite(numeric) ? numeric : Date.parse(String(value));
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat(i18n.locale, {
    day: '2-digit',
    month: 'short',
    ...(withTime ? { hour: '2-digit', minute: '2-digit' } : { year: 'numeric' })
  }).format(date);
}

function formatDuration(milliseconds) {
  const minutes = Math.max(0, Math.floor(milliseconds / 60000));
  if (minutes < 60) return i18n.language === 'tr' ? `${minutes} dk` : `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  if (hours < 24) {
    return i18n.language === 'tr'
      ? (rest ? `${hours} sa ${rest} dk` : `${hours} sa`)
      : (rest ? `${hours} hr ${rest} min` : `${hours} hr`);
  }
  const days = Math.floor(hours / 24);
  return i18n.language === 'tr' ? `${days} gün ${hours % 24} sa` : `${days} d ${hours % 24} hr`;
}

function formatDateRange(start, end) {
  if (!start || !end) return '—';
  return `${formatDate(start)} - ${formatDate(end)}`;
}

function relativeTime(value) {
  const difference = Date.now() - Number(value);
  const minutes = Math.floor(difference / 60000);
  if (minutes < 1) return t('Just now');
  if (minutes < 60) return i18n.language === 'tr' ? `${minutes} dk önce` : `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return i18n.language === 'tr' ? `${hours} sa önce` : `${hours} hr ago`;
  const days = Math.floor(hours / 24);
  return i18n.language === 'tr' ? `${days} gün önce` : `${days} d ago`;
}

function syncRelativeTime(value) {
  const difference = Date.now() - Number(value);
  const minutes = Math.floor(difference / 60000);
  if (minutes < 1) return t('Just now');
  if (minutes < 60) {
    return i18n.language === 'tr'
      ? `${minutes} ${minutes === 1 ? 'dk' : 'dakika'} önce`
      : `${minutes} ${minutes === 1 ? 'min' : 'minutes'} ago`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return i18n.language === 'tr'
      ? `${hours} saat önce`
      : `${hours} ${hours === 1 ? 'hour' : 'hours'} ago`;
  }
  const days = Math.floor(hours / 24);
  return i18n.language === 'tr'
    ? `${days} gün önce`
    : `${days} ${days === 1 ? 'day' : 'days'} ago`;
}

function dashboardDateLabel() {
  return new Intl.DateTimeFormat(i18n.locale, {
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric'
  }).format(new Date());
}

function updateWelcomeSyncStatus(lastSuccessfulSyncAt) {
  const syncLabel = lastSuccessfulSyncAt ? syncRelativeTime(lastSuccessfulSyncAt) : '—';
  setPlainText('#welcomeDate', `${dashboardDateLabel()} · ${t('Last successful sync')}: ${syncLabel}`);
}

function methodMeta(method) {
  if (method === 'admin-approval') return { label: t('Admin approval'), short: 'A', className: 'admin-approval' };
  if (method === 'nvi') return { label: t('T.C. Identity'), short: 'TC', className: 'nvi' };
  if (method === 'email') return { label: t('Email'), short: '@', className: 'email' };
  if (method === 'whatsapp') return { label: 'WhatsApp', short: 'W', className: 'whatsapp' };
  if (method === 'telegram') return { label: 'Telegram', short: 'T', className: 'telegram' };
  if (method === 'sms') return { label: 'SMS', short: 'S', className: 'sms' };
  return { label: 'Voucher', short: 'V', className: 'voucher' };
}

function authorizationIdentity(row) {
  if (row.method === 'voucher') {
    return {
      primary: row.voucher_label || t('Voucher access'),
      secondary: `${t('Code ending')} ···· ${row.voucher_hint || '—'}`
    };
  }
  return {
    primary: row.identity,
    secondary: row.method === 'email'
      ? t('Verified email')
      : row.method === 'admin-approval'
        ? t('Admin approved guest')
        : row.method === 'nvi'
          ? t('Verified T.C. identity')
          : t('Verified phone')
  };
}

function authorizationState(row) {
  if (row.status === 'failed') return { key: 'failed', label: t('Failed') };
  if (authorizationQuotaBlocked(row)) {
    return { key: 'ended', label: t('Quota exceeded') };
  }
  if (row.ended_at || Number(row.expires_at) <= Date.now()) return { key: 'ended', label: t('Ended') };
  return { key: 'active', label: t('Active') };
}

function authorizationQuotaBlocked(row) {
  return Number(row.quota_blocked_until || 0) > Date.now();
}

function sessionRemainingText(row) {
  const status = authorizationState(row);
  if (status.key !== 'active') return '—';
  if (Number(row.unlimited)) return t('No expiration');
  return formatDuration(Math.max(0, Number(row.expires_at) - Date.now()));
}

function quotaPeriodLabel(value) {
  return {
    daily: t('Daily'),
    weekly: t('Weekly'),
    monthly: t('Monthly')
  }[value] || value || '—';
}

function quotaLine(used, limit) {
  const usedBytes = Math.max(0, Number(used) || 0);
  const limitBytes = Math.max(0, Number(limit) || 0);
  if (!limitBytes) return t('Unlimited');
  const remaining = Math.max(0, limitBytes - usedBytes);
  return `${formatBytes(usedBytes)} / ${formatBytes(limitBytes)} · ${t('Remaining')}: ${formatBytes(remaining)}`;
}

function sessionQuotaCell(row) {
  const downloadLimit = Number(row.quota_download_limit_bytes || 0);
  const uploadLimit = Number(row.quota_upload_limit_bytes || 0);
  if (!downloadLimit && !uploadLimit) return `<span class="muted">${escapeHtml(t('No quota'))}</span>`;
  const blockedUntil = Number(row.quota_blocked_until || 0);
  const blocked = blockedUntil > Date.now()
    ? `<span>${escapeHtml(t('Blocked until'))}: ${escapeHtml(formatDate(blockedUntil))}</span>`
    : `<span>${escapeHtml(t('Quota resets'))}: ${escapeHtml(formatDate(row.quota_period_end_at))}</span>`;
  return `<div class="stacked">
    <strong>${escapeHtml(quotaPeriodLabel(row.quota_period))}</strong>
    <span>↓ ${escapeHtml(quotaLine(row.quota_download_bytes, downloadLimit))}</span>
    <span>↑ ${escapeHtml(quotaLine(row.quota_upload_bytes, uploadLimit))}</span>
    ${blocked}
  </div>`;
}

function sessionActionKey(action, id) {
  return `${action}:${String(id || '')}`;
}

function isSessionActionPending(action, id) {
  return Boolean(state.pendingSessionActions[sessionActionKey(action, id)]);
}

function setSessionActionPending(action, id, pending) {
  const key = sessionActionKey(action, id);
  if (pending) state.pendingSessionActions[key] = true;
  else delete state.pendingSessionActions[key];
  renderSessionsTable();
}

function sessionActionBusyContent(label = 'Processing…') {
  return `<span class="button-spinner" aria-hidden="true"></span><span>${escapeHtml(t(label))}</span>`;
}

const SESSION_COLUMNS = [
  {
    key: 'identity',
    label: 'USER / IDENTITY',
    width: 230,
    minWidth: 150,
    render(row, { identity, method }) {
      return `<div class="identity-cell"><div class="identity-icon ${method.className}">${escapeHtml(method.short)}</div><div><strong title="${escapeHtml(identity.primary)}">${escapeHtml(identity.primary)}</strong><span>${escapeHtml(identity.secondary)}</span></div></div>`;
    }
  },
  {
    key: 'connection',
    label: 'CONNECTION',
    width: 210,
    minWidth: 140,
    render(row, { method }) {
      return `<div class="stacked"><strong>${escapeHtml(row.client_ip)}</strong><span>${escapeHtml(row.client_mac || t('MAC unknown'))} · ${method.label}</span></div>`;
    }
  },
  {
    key: 'start',
    label: 'START',
    width: 180,
    minWidth: 130,
    render(row) {
      return `<div class="stacked"><strong>${formatDate(row.created_at)}</strong><span>${relativeTime(row.created_at)}</span></div>`;
    }
  },
  {
    key: 'download',
    label: 'DOWNLOAD',
    width: 120,
    minWidth: 90,
    render(row) {
      return `<strong>${formatBytes(row.download_bytes)}</strong>`;
    }
  },
  {
    key: 'upload',
    label: 'UPLOAD',
    width: 120,
    minWidth: 90,
    render(row) {
      return `<strong>${formatBytes(row.upload_bytes)}</strong>`;
    }
  },
  {
    key: 'quota',
    label: 'QUOTA',
    width: 270,
    minWidth: 170,
    render(row) {
      return sessionQuotaCell(row);
    }
  },
  {
    key: 'usageDuration',
    label: 'USAGE DURATION',
    width: 200,
    minWidth: 145,
    render(row, { end }) {
      return `<div class="stacked"><strong>${formatDuration(Math.max(0, end - Number(row.created_at)))}</strong><span>${t('Expires')}: ${formatDate(row.expires_at)}</span></div>`;
    }
  },
  {
    key: 'remainingTime',
    label: 'REMAINING TIME',
    width: 150,
    minWidth: 115,
    render(row) {
      return `<strong>${escapeHtml(sessionRemainingText(row))}</strong>`;
    }
  },
  {
    key: 'status',
    label: 'STATUS',
    width: 120,
    minWidth: 90,
    render(row, { status }) {
      if (authorizationQuotaBlocked(row)) {
        const pending = isSessionActionPending('reset-quota', row.id);
        return `<button class="status-pill status-pill-button ${status.key}" type="button" data-reset-quota="${encodeURIComponent(row.id)}" title="${escapeHtml(t(pending ? 'Processing…' : 'Reset quota'))}" ${pending ? 'disabled aria-busy="true"' : ''}>${pending ? sessionActionBusyContent() : escapeHtml(status.label)}</button>`;
      }
      return `<span class="status-pill ${status.key}">${escapeHtml(status.label)}</span>`;
    }
  },
  {
    key: 'actions',
    label: 'ACTIONS',
    width: 80,
    minWidth: 60,
    render(row, { canDisconnect }) {
      const pending = isSessionActionPending('disconnect', row.id);
      return canDisconnect
        ? `<button class="action-button danger" data-disconnect="${encodeURIComponent(row.id)}" title="${escapeHtml(t(pending ? 'Processing…' : 'Disconnect session'))}" ${pending ? 'disabled aria-busy="true"' : ''}>${pending ? '<span class="button-spinner" aria-hidden="true"></span>' : '×'}</button>`
        : '';
    }
  }
];

function sessionColumnDefaults() {
  return SESSION_COLUMNS.map(column => column.key);
}

function loadSessionColumnKeys() {
  if (state.sessionColumns) return state.sessionColumns;
  let stored = null;
  try {
    stored = JSON.parse(localStorage.getItem(SESSION_COLUMNS_STORAGE_KEY) || 'null');
  } catch {
    stored = null;
  }
  const validKeys = new Set(SESSION_COLUMNS.map(column => column.key));
  const selected = Array.isArray(stored)
    ? stored.filter(key => validKeys.has(key))
    : sessionColumnDefaults();
  state.sessionColumns = selected.length ? selected : sessionColumnDefaults();
  return state.sessionColumns;
}

function saveSessionColumnKeys(keys) {
  state.sessionColumns = keys.length ? keys : sessionColumnDefaults();
  try {
    localStorage.setItem(SESSION_COLUMNS_STORAGE_KEY, JSON.stringify(state.sessionColumns));
  } catch {}
}

function visibleSessionColumns() {
  const selected = new Set(loadSessionColumnKeys());
  return SESSION_COLUMNS.filter(column => selected.has(column.key));
}

function sessionRowContext(row) {
  const identity = authorizationIdentity(row);
  const method = methodMeta(row.method);
  const status = authorizationState(row);
  const end = row.ended_at || Math.min(Date.now(), Number(row.expires_at));
  return {
    identity,
    method,
    status,
    end,
    canDisconnect: status.key === 'active'
  };
}

function renderSessionColumnMenu() {
  const menu = $('#sessionColumnsMenu');
  if (!menu) return;
  const selected = new Set(loadSessionColumnKeys());
  menu.innerHTML = `
    <div class="session-columns-menu__title">${escapeHtml(t('Visible columns'))}</div>
    ${SESSION_COLUMNS.map(column => `
      <label class="session-column-option">
        <input type="checkbox" data-session-column="${escapeHtml(column.key)}" ${selected.has(column.key) ? 'checked' : ''}>
        <span>${escapeHtml(t(column.label))}</span>
      </label>
    `).join('')}
  `;
}

function renderSessionsTable(rows = state.sessionRows) {
  const columns = visibleSessionColumns();
  $('#sessionsTable')?.style.setProperty(
    '--session-table-min-width',
    `${Math.min(1040, Math.max(0, columns.length * 130))}px`
  );
  $('#sessionsHead').innerHTML = `<tr>${columns.map(column => `<th>${escapeHtml(t(column.label))}</th>`).join('')}</tr>`;
  $('#sessionsBody').innerHTML = rows.length ? rows.map(row => {
    const context = sessionRowContext(row);
    return `<tr>${columns.map(column => `<td>${column.render(row, context)}</td>`).join('')}</tr>`;
  }).join('') : emptyRow(columns.length);
  renderSessionColumnMenu();
}

function statusLabel(status) {
  return {
    verified: t('Verified'),
    approved: t('Approved'),
    rejected: t('Rejected'),
    pending: t('Pending'),
    processing: t('Processing'),
    failed: t('Failed'),
    expired: t('Expired')
  }[status] || status;
}

function verificationAttemptText(value) {
  const attempts = Number(value) || 0;
  const label = attempts === 1 ? t('wrong code attempt') : t('wrong code attempts');
  return `${attempts.toLocaleString(i18n.locale)} ${label}`;
}

function verificationFallbackDetail(row, method) {
  if (row.kind === 'admin-approval') {
    if (row.status === 'approved') return t('Admin approved the request and access was granted.');
    if (row.status === 'rejected') return t('Admin rejected the request.');
    if (row.status === 'pending') return t('Request is waiting for administrator review.');
    if (row.status === 'failed') return t('Admin approval access could not be granted.');
  }
  if (row.kind === 'voucher') {
    if (row.status === 'verified') return t('Voucher redeemed and access was granted.');
    if (row.status === 'failed') return t('Voucher access failed.');
  }
  if (row.status === 'verified') {
    return t('{method} verification succeeded and access was granted.', { method: method.label });
  }
  if (row.status === 'pending') {
    if (row.kind === 'telegram') {
      return t('Telegram verification is waiting for the user to share their phone number with the bot.');
    }
    return t('{method} code was sent and is waiting for the user.', { method: method.label });
  }
  if (row.status === 'processing') return t('Verification is being processed.');
  if (row.status === 'expired') return t('Verification expired before completion.');
  if (row.status === 'failed') return t('Verification failed.');
  return t('No provider detail was recorded for this older entry.');
}

function isPositiveVerificationDetail(value) {
  return /accepted|request created|authorization succeeded/iu.test(String(value || ''));
}

function verificationDetail(row, method) {
  const stored = String(row.last_error || '').trim();
  const telegramWaiting = row.kind === 'telegram' &&
    row.status === 'pending' &&
    (!stored || stored.includes('Waiting for the user to share'));
  const pendingError = row.status === 'pending' && stored && !isPositiveVerificationDetail(stored);
  const summary = {
    verified: t('Successful'),
    approved: t('Approved'),
    rejected: t('Rejected'),
    pending: pendingError ? t('Unsuccessful') : (telegramWaiting ? t('Waiting') : t('Delivery successful')),
    processing: t('Processing'),
    failed: t('Unsuccessful'),
    expired: t('Expired')
  }[row.status] || statusLabel(row.status);
  const tooltip = [
    stored || verificationFallbackDetail(row, method),
    Number(row.attempts) ? verificationAttemptText(row.attempts) : ''
  ].filter(Boolean).join('\n');
  return { summary, tooltip, key: pendingError ? 'failed' : row.status };
}

function emptyRow(columns, message = t('No records match these filters.')) {
  return `<tr class="empty-row"><td colspan="${columns}">${escapeHtml(message)}</td></tr>`;
}

function showLogin() {
  state.csrfToken = '';
  $('#loginScreen').classList.remove('hidden');
  $('#adminApp').classList.add('hidden');
  lookupAdminPublicIp();
  setTimeout(() => $('#loginPassword').focus(), 50);
}

function storedSidebarMini() {
  try {
    return localStorage.getItem(SIDEBAR_MINI_STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

function setSidebarMini(enabled, { store = false } = {}) {
  $('#adminApp')?.classList.toggle('sidebar-mini', Boolean(enabled));
  const button = $('#sidebarToggle');
  if (button) {
    const label = enabled ? t('Expand sidebar') : t('Collapse sidebar');
    $('#sidebarToggleText').textContent = enabled ? t('Expand') : t('Collapse');
    button.setAttribute('aria-label', label);
    button.setAttribute('aria-pressed', enabled ? 'true' : 'false');
    button.title = label;
  }
  if (store) {
    try {
      localStorage.setItem(SIDEBAR_MINI_STORAGE_KEY, enabled ? '1' : '0');
    } catch {}
  }
}

function storedTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY) === 'dark' ? 'dark' : 'light';
  } catch {
    return 'light';
  }
}

function setTheme(theme, { store = false } = {}) {
  const nextTheme = theme === 'dark' ? 'dark' : 'light';
  const isDark = nextTheme === 'dark';
  document.documentElement.dataset.theme = nextTheme;
  document.documentElement.style.colorScheme = nextTheme;
  document.querySelector('meta[name="color-scheme"]')?.setAttribute('content', nextTheme);

  const button = $('#themeToggle');
  if (button) {
    const label = isDark ? t('Switch to light mode') : t('Switch to dark mode');
    const text = isDark ? t('Light mode') : t('Dark mode');
    const textNode = $('#themeToggleText');
    if (textNode) textNode.textContent = text;
    button.setAttribute('aria-label', label);
    button.setAttribute('aria-pressed', isDark ? 'true' : 'false');
    button.title = label;
  }

  if (store) {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    } catch {}
  }
}

function dashboardHourRange(value, fallback = 6) {
  const hours = Number(value);
  return DASHBOARD_HOUR_RANGES.has(hours) ? hours : fallback;
}

function dashboardTrafficPeriod(value, fallback = 'daily') {
  return DASHBOARD_TRAFFIC_PERIODS.has(value) ? value : fallback;
}

function storedDashboardFilters() {
  try {
    const stored = JSON.parse(localStorage.getItem(DASHBOARD_FILTERS_STORAGE_KEY) || '{}');
    return stored && typeof stored === 'object' ? stored : {};
  } catch {
    return {};
  }
}

function saveDashboardFilters() {
  try {
    localStorage.setItem(DASHBOARD_FILTERS_STORAGE_KEY, JSON.stringify({
      trafficPeriod: dashboardTrafficPeriod(state.trafficPeriod),
      topSitesHours: dashboardHourRange(state.topSitesHours),
      topBandwidthHours: dashboardHourRange(state.topBandwidthHours)
    }));
  } catch {}
}

function applyStoredDashboardFilters() {
  const stored = storedDashboardFilters();
  state.trafficPeriod = dashboardTrafficPeriod(stored.trafficPeriod, state.trafficPeriod);
  state.topSitesHours = dashboardHourRange(stored.topSitesHours, state.topSitesHours);
  state.topBandwidthHours = dashboardHourRange(stored.topBandwidthHours, state.topBandwidthHours);
  if ($('#trafficPeriod')) $('#trafficPeriod').value = state.trafficPeriod;
  if ($('#topSitesRange')) $('#topSitesRange').value = String(state.topSitesHours);
  if ($('#topBandwidthRange')) $('#topBandwidthRange').value = String(state.topBandwidthHours);
}

function showApp(session) {
  state.csrfToken = session.csrfToken;
  state.user = session.user;
  state.appName = session.appName || state.appName;
  state.gatewayMode = session.gatewayMode || '';
  $('#loginScreen').classList.add('hidden');
  $('#adminApp').classList.remove('hidden');
  setSidebarMini(storedSidebarMini());
  setPlainText('#adminName', state.user);
  updateAdminAvatarInitial();
  setPlainText('#brandName', state.appName);
  setTranslatedText('#gatewayMode', state.gatewayMode === 'opnsense-api' ? 'API connection active' : 'Mock / test mode');
  document.title = `${state.appName} ${t('Administration')}`;
  updateWelcomeSyncStatus(null);
  i18n.translateDom();
  refreshGatewayStatus();
  refreshActiveSessionCount().catch(() => {});
  checkLatestRelease({ showDailyPopup: true }).catch(() => {});
  navigate(initialAdminView(), { replace: true });
}

function renderProjectAttribution(about = state.about || {}) {
  const targets = ['#loginProjectAttribution', '#adminProjectAttribution']
    .map(selector => $(selector))
    .filter(Boolean);
  if (!targets.length) return;
  const name = about.displayName || about.name || 'G-Hotspot';
  const author = about.author || 'Gökhan GÜRBÜZ';
  const username = about.githubUsername ? ` (${about.githubUsername})` : ' (G-grbz)';
  const versionValue = about.version || APP_VERSION;
  const version = versionValue ? ` v${versionValue}` : '';
  const license = about.license || 'G-Hotspot Noncommercial Source-Available License 1.0';
  const source = String(about.githubUrl || about.source || '').trim();
  for (const target of targets) {
    const label = document.createElement('span');
    label.textContent = `${t('Powered by')} ${name}${version} / ${author}${username} · ${license}`;
    target.replaceChildren(label);
    if (/^https?:\/\//u.test(source)) {
      const separator = document.createElement('span');
      const link = document.createElement('a');
      separator.textContent = ' · ';
      link.href = source;
      link.target = '_blank';
      link.rel = 'noreferrer';
      link.textContent = about.githubUrl ? 'GitHub' : t('Source');
      target.append(separator, link);
    }
  }
}

async function loadProjectAttribution() {
  try {
    state.about = await api('/api/v1/about');
  } catch {
    state.about = {
      displayName: 'G-Hotspot',
      version: APP_VERSION,
      license: 'LicenseRef-G-Hotspot-NC-1.0',
      author: 'Gökhan GÜRBÜZ',
      githubUsername: 'G-grbz',
      githubUrl: 'https://github.com/G-grbz',
      source: 'https://github.com/G-grbz'
    };
  }
  renderProjectAttribution();
}

function localDateKey(date = new Date()) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
}

function releaseIdentity(info = state.releaseInfo) {
  const release = info?.release || {};
  return release.id || release.tag || release.version || release.title || '';
}

function latestReleaseLabel(release = {}) {
  if (release.version) return `v${release.version}`;
  return release.tag || release.title || '—';
}

function releasePopupSeenToday(info = state.releaseInfo) {
  const key = releaseIdentity(info);
  if (!key) return true;
  try {
    const stored = JSON.parse(localStorage.getItem(RELEASE_POPUP_STORAGE_KEY) || '{}');
    return stored.releaseKey === key && stored.date === localDateKey();
  } catch {
    return false;
  }
}

function markReleasePopupSeen(info = state.releaseInfo) {
  const key = releaseIdentity(info);
  if (!key) return;
  try {
    localStorage.setItem(RELEASE_POPUP_STORAGE_KEY, JSON.stringify({
      releaseKey: key,
      date: localDateKey()
    }));
  } catch {}
}

function renderReleaseIndicator() {
  const button = $('#releaseStatusButton');
  const profile = button?.closest('.admin-profile');
  const hasUpdate = Boolean(state.releaseInfo?.updateAvailable && state.releaseInfo?.release);
  profile?.classList.toggle('has-update', hasUpdate);
  if (!button) return;
  const label = hasUpdate
    ? t('Update available: {version}', { version: latestReleaseLabel(state.releaseInfo.release) })
    : t('Check for updates');
  button.setAttribute('aria-label', label);
  button.title = label;
}

function updateAdminAvatarInitial() {
  const initial = String(state.user || 'A').trim().slice(0, 1).toUpperCase() || 'A';
  setPlainText('#adminAvatarInitial', initial);
}

function releaseInfoAlert() {
  const info = state.releaseInfo;
  if (!info?.updateAvailable || !info.release) return null;
  const latest = latestReleaseLabel(info.release);
  const current = info.currentVersion ? `v${info.currentVersion}` : '—';
  return {
    level: 'update',
    title: t('G-Hotspot update available'),
    body: t('Installed version {current}; latest release {latest}.', { current, latest }),
    buttonLabel: t('View release notes'),
    action: 'release'
  };
}

function openReleaseModal() {
  const info = state.releaseInfo;
  const release = info?.release;
  if (!info?.updateAvailable || !release) return false;
  setPlainText('#releaseModalEyebrow', t('UPDATE AVAILABLE'));
  setPlainText('#releaseModalTitle', release.title || t('G-Hotspot update available'));
  setPlainText('#releaseCurrentVersion', info.currentVersion ? `v${info.currentVersion}` : '—');
  setPlainText('#releaseLatestVersion', latestReleaseLabel(release));
  setPlainText('#releasePublishedAt', release.publishedAt ? formatDate(release.publishedAt) : '—');
  setSafeHtml(
    '#releaseNotes',
    portalPreviewMarkdownToSafeHtml(release.body, t('No release notes were published for this release.'))
  );
  const link = $('#releaseGithubLink');
  if (link) {
    link.href = release.url || `${info.repository?.url || 'https://github.com/G-grbz/G-Hotspot'}/releases`;
  }
  markReleasePopupSeen(info);
  $('#releaseModal')?.classList.remove('hidden');
  return true;
}

function closeReleaseModal() {
  $('#releaseModal')?.classList.add('hidden');
}

function maybeOpenDailyReleasePopup() {
  if (!state.releaseInfo?.updateAvailable || !state.releaseInfo?.release) return;
  if (releasePopupSeenToday(state.releaseInfo)) return;
  setTimeout(() => {
    if (!state.csrfToken || document.hidden || releasePopupSeenToday(state.releaseInfo)) return;
    openReleaseModal();
  }, 700);
}

async function checkLatestRelease({ showDailyPopup = false, refresh = false } = {}) {
  if (releaseCheckPromise) return releaseCheckPromise;
  releaseCheckPromise = (async () => {
    try {
      const suffix = refresh ? '?refresh=1' : '';
      state.releaseInfo = await api(`/api/admin/releases/latest${suffix}`);
      renderReleaseIndicator();
      refreshSystemAlerts().catch(() => {});
      if (showDailyPopup) maybeOpenDailyReleasePopup();
      return state.releaseInfo;
    } catch {
      state.releaseInfo = null;
      renderReleaseIndicator();
      return null;
    } finally {
      releaseCheckPromise = null;
    }
  })();
  return releaseCheckPromise;
}

async function openReleaseFromAvatar() {
  await checkLatestRelease({ refresh: true });
  if (openReleaseModal()) return;
  toast(t('No newer release was found.'));
}

async function refreshGatewayStatus() {
  const label = $('#gatewayMode');
  setTranslatedText(label, state.gatewayMode === 'mock' ? 'Mock / test mode' : 'Connecting…');
  if (state.gatewayMode === 'mock') return;
  try {
    const status = await api('/api/admin/gateway/status');
    setTranslatedText(label, status.connected ? 'API connection active' : 'Connection failed');
    label.title = status.error || '';
  } catch (error) {
    setTranslatedText(label, 'Connection failed');
    label.title = error.message;
  }
}

async function loadDashboard() {
  applyStoredDashboardFilters();
  const selectedPeriod = $('#trafficPeriod')?.value || state.trafficPeriod || 'daily';
  const selectedTopSitesHours = Number($('#topSitesRange')?.value || state.topSitesHours || 6);
  const selectedTopBandwidthHours = Number($('#topBandwidthRange')?.value || state.topBandwidthHours || 6);
  const data = await api(`/api/admin/dashboard?trafficPeriod=${encodeURIComponent(selectedPeriod)}&topSitesHours=${encodeURIComponent(selectedTopSitesHours)}&topBandwidthHours=${encodeURIComponent(selectedTopBandwidthHours)}`);
  const summary = data.summary;
  setPlainText('#metricActive', summary.activeSessions.toLocaleString(i18n.locale));
  setTranslatedText('#metricToday','Total connections today: {total}',{total: summary.todaySessions.toLocaleString(i18n.locale)});
  setPlainText('#metricDownload', formatBytes(summary.downloadBytes));
  setPlainText('#metricUpload', formatBytes(summary.uploadBytes));
  setPlainText('#metricVouchers', summary.usableVouchers.toLocaleString(i18n.locale));
  setPlainText('#metricRedeemed', summary.redeemedVouchers.toLocaleString(i18n.locale));
  setPlainText('#activeNavCount', summary.activeSessions > 99 ? '99+' : summary.activeSessions);
  updateWelcomeSyncStatus(data.gateway?.lastSuccessfulSyncAt);
  state.trafficPeriod = data.traffic?.period || selectedPeriod;
  state.topSitesHours = Number(data.topSites?.hours || selectedTopSitesHours || 6);
  state.topBandwidthHours = Number(data.topBandwidthClients?.hours || selectedTopBandwidthHours || 6);
  if ($('#trafficPeriod')) $('#trafficPeriod').value = state.trafficPeriod;
  if ($('#topSitesRange')) $('#topSitesRange').value = String(state.topSitesHours);
  if ($('#topBandwidthRange')) $('#topBandwidthRange').value = String(state.topBandwidthHours);
  saveDashboardFilters();
  renderSessionTrafficChart(data.daily);
  renderTrafficChart(data.traffic || data.daily);
  renderMethodDonut(data.methods);
  renderTopSitesDonut(data.topSites || {});
  renderTopBandwidthDonut(data.topBandwidthClients || {});
  renderDashboardAdminApprovals(data.adminApproval || {});
  state.lastAdminApprovalRefreshAt = Date.now();
  renderRecentSessions(data.recent);
}

function syslogStorageAlert(data) {
  const storage = data.healthRuntime?.storage || {};
  if (storage.available && storage.warning) {
    return {
      level: storage.blocking ? 'critical' : 'warning',
      title: storage.blocking ? t('Syslog storage block threshold reached') : t('Syslog storage warning'),
      body: t('Syslog storage is {usage}% full. Warning threshold: {alert}%, block threshold: {block}%.', {
        usage: storage.usagePercent,
        alert: storage.alertPercent || data.storageAlertPercent || 85,
        block: storage.blockPercent || data.storageBlockPercent || 99
      }),
      storage
    };
  }
  if (!storage.available && data.enabled) {
    return {
      level: 'critical',
      title: t('Syslog storage status unavailable'),
      body: storage.error || t('Syslog storage status could not be checked.'),
      storage
    };
  }
  return null;
}

function renderDashboardStorageAlert(alert) {
  const panel = $('#dashboardStorageAlert');
  if (!panel) return;
  if (!alert) {
    panel.classList.add('hidden');
    return;
  }
  panel.classList.toggle('critical', alert.level === 'critical');
  setPlainText('#dashboardStorageTitle', alert.title);
  setPlainText('#dashboardStorageMessage', alert.body);
  const percent = alert.storage?.available
    ? Math.max(0, Math.min(100, Number(alert.storage.usagePercent) || 0))
    : 100;
  $('#dashboardStorageBar').style.width = `${percent}%`;
  panel.classList.remove('hidden');
}

async function refreshSystemAlerts() {
  const target = $('#systemAlerts');
  if (!target || !state.csrfToken) return;
  try {
    const data = await api('/api/admin/syslog/status');
    const storageAlert = syslogStorageAlert(data);
    renderDashboardStorageAlert(storageAlert);
    const alerts = [
      releaseInfoAlert(),
      ...(state.currentView === 'dashboard' ? [] : [storageAlert])
    ].filter(Boolean);
    target.innerHTML = alerts.map(alert => `<div class="system-alert ${escapeHtml(alert.level)}">
      <div><strong>${escapeHtml(alert.title)}</strong><span>${escapeHtml(alert.body)}</span></div>
      ${alert.action === 'release'
        ? `<button class="text-button" type="button" data-open-release-update>${escapeHtml(alert.buttonLabel)}</button>`
        : `<button class="text-button" type="button" data-settings-shortcut="notifications">${escapeHtml(t('Notification settings'))}</button>`}
    </div>`).join('');
    target.classList.toggle('hidden', alerts.length === 0);
  } catch {
    renderDashboardStorageAlert(null);
    const alert = releaseInfoAlert();
    target.innerHTML = alert ? `<div class="system-alert ${escapeHtml(alert.level)}">
      <div><strong>${escapeHtml(alert.title)}</strong><span>${escapeHtml(alert.body)}</span></div>
      <button class="text-button" type="button" data-open-release-update>${escapeHtml(alert.buttonLabel)}</button>
    </div>` : '';
    target.classList.toggle('hidden', !alert);
  }
}

async function refreshActiveSessionCount() {
  const data = await api('/api/admin/sessions?state=active&limit=1');
  const count = Number(data.total || 0);
  setPlainText('#activeNavCount', count > 99 ? '99+' : count);
}

function lastSevenDays(rows) {
  const map = new Map(rows.map(row => [row.day, row]));
  const output = [];
  for (let offset = 6; offset >= 0; offset -= 1) {
    const date = new Date();
    date.setHours(12, 0, 0, 0);
    date.setDate(date.getDate() - offset);
    const key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
    output.push({
      day: key,
      label: new Intl.DateTimeFormat(i18n.locale, { weekday: 'short' }).format(date).replace('.', ''),
      sessions: Number(map.get(key)?.sessions || 0),
      traffic: Number(map.get(key)?.traffic || 0)
    });
  }
  return output;
}

function chartPath(points, valueKey, x, y) {
  return points.map((point, index) => {
    const value = Number(point[valueKey] || 0);
    return `${index ? 'L' : 'M'} ${x(index)} ${y(value)}`;
  }).join(' ');
}

function renderSessionTrafficChart(rows) {
  const points = lastSevenDays(rows || []);
  const width = 720;
  const height = 205;
  const padding = { left: 20, right: 18, top: 22, bottom: 31 };
  const plotHeight = height - padding.top - padding.bottom;
  const plotBottom = height - padding.bottom;
  const max = Math.max(4, ...points.map(point => point.sessions));
  const trafficMax = Math.max(1, ...points.map(point => Number(point.traffic || 0)));
  const x = index => padding.left + index * ((width - padding.left - padding.right) / (points.length - 1));
  const y = value => padding.top + (height - padding.top - padding.bottom) * (1 - value / max);
  const step = (width - padding.left - padding.right) / Math.max(1, points.length - 1);
  const barWidth = Math.min(42, Math.max(18, step * .34));
  const coordinates = points.map((point, index) => [x(index), y(point.sessions)]);
  const line = coordinates.map(([cx, cy], index) => `${index ? 'L' : 'M'} ${cx} ${cy}`).join(' ');
  const area = `${line} L ${coordinates.at(-1)[0]} ${height - padding.bottom} L ${coordinates[0][0]} ${height - padding.bottom} Z`;
  const grid = [0, .25, .5, .75, 1].map(fraction => {
    const gy = padding.top + fraction * (height - padding.top - padding.bottom);
    return `<line class="chart-grid-line" x1="${padding.left}" y1="${gy}" x2="${width - padding.right}" y2="${gy}"/>`;
  }).join('');
  const labels = points.map((point, index) =>
    `<text class="chart-label" x="${x(index)}" y="${height - 8}" text-anchor="middle">${escapeHtml(point.label)}</text>`
  ).join('');
  const trafficBars = points.map((point, index) => {
    const traffic = Number(point.traffic || 0);
    const barHeight = traffic ? Math.max(3, traffic / trafficMax * plotHeight * .58) : 0;
    return `<rect class="session-traffic-bar" x="${x(index) - barWidth / 2}" y="${plotBottom - barHeight}" width="${barWidth}" height="${barHeight}" rx="4"/>`;
  }).join('');
  const dots = points.map((point, index) => `
    <circle class="chart-point" cx="${x(index)}" cy="${y(point.sessions)}" r="3.5"/>
    ${point.sessions ? `<text class="chart-value" x="${x(index)}" y="${y(point.sessions) - 10}" text-anchor="middle">${point.sessions}</text>` : ''}
  `).join('');
  const hitAreas = points.map((point, index) => {
    const tooltip = dashboardTooltipAttributes({
      title: `${point.label} · ${point.day}`,
      accent: '#6366f1',
      rows: [
        { label: t('Session count'), value: Number(point.sessions || 0).toLocaleString(i18n.locale) },
        { label: t('Daily traffic'), value: formatBytes(point.traffic || 0) },
        { label: t('Period'), value: t('Last 7 days') }
      ]
    });
    return `<rect class="chart-hit-area" x="${x(index) - step / 2}" y="${padding.top}" width="${step}" height="${plotHeight}" ${tooltip}/>`;
  }).join('');
  $('#sessionTrafficChart').innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-label="${t('Connection chart for the last seven days')}">
      <defs><linearGradient id="sessionAreaGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#7566e8" stop-opacity=".24"/><stop offset="1" stop-color="#7566e8" stop-opacity=".01"/></linearGradient></defs>
      ${grid}<path class="chart-area session-chart-area" d="${area}"/>${trafficBars}<path class="chart-line session-chart-line" d="${line}"/>${dots}${labels}${hitAreas}
    </svg>`;
}

function chartPointTitle(point) {
  if (point?.startAt) return formatDate(point.startAt);
  return point?.label || point?.key || '—';
}

function compactChartLabel(point, index, total, bucket) {
  if (['5min', '30min', 'hour'].includes(bucket)) {
    const interval = total > 18 ? 3 : 2;
    return index % interval === 0 || index === total - 1 ? point.label : '';
  }
  if (total <= 10) {
    const date = new Date(point.startAt || 0);
    return new Intl.DateTimeFormat(i18n.locale, { day: '2-digit', month: 'short' }).format(date).replace('.', '');
  }
  if (index % 5 !== 0 && index !== total - 1) return '';
  const date = new Date(point.startAt || 0);
  return new Intl.DateTimeFormat(i18n.locale, { day: '2-digit', month: 'short' }).format(date).replace('.', '');
}

function trafficChartSubtitle(series) {
  if (series?.period === 'hourly') return 'Traffic for the last 1 hour';
  if (series?.period === '6h') return 'Traffic for the last 6 hours';
  if (series?.period === '12h') return 'Traffic for the last 12 hours';
  return series?.bucket === 'hour' ? 'Hourly traffic for today' : 'Daily traffic for the selected period';
}

function renderTrafficSummary(series) {
  const summary = series?.summary || {};
  const cards = [
    ['Total download', formatBytes(summary.totalDownloadBytes || 0), 'blue'],
    ['Total upload', formatBytes(summary.totalUploadBytes || 0), 'amber'],
    ['Peak bucket', summary.peakBytes ? `${formatBytes(summary.peakBytes)} · ${summary.peakLabel || '—'}` : '—', 'violet'],
    ['Live clients', `${Number(summary.liveClients || 0).toLocaleString(i18n.locale)} / ${Number(summary.liveRecords || 0).toLocaleString(i18n.locale)}`, 'green']
  ];
  $('#trafficSummary').innerHTML = cards.map(([label, value, tone]) => `
    <div class="traffic-summary-card ${escapeHtml(tone)}">
      <span>${escapeHtml(t(label))}</span>
      <strong>${escapeHtml(value)}</strong>
    </div>
  `).join('');
}

function renderTrafficChart(series) {
  if (Array.isArray(series)) {
    const points = lastSevenDays(series);
    series = {
      period: 'weekly',
      bucket: 'day',
      points: points.map(point => ({
        ...point,
        downloadBytes: Number(point.traffic || 0),
        uploadBytes: 0,
        records: Number(point.sessions || 0)
      })),
      summary: {
        totalDownloadBytes: points.reduce((sum, point) => sum + Number(point.traffic || 0), 0),
        totalUploadBytes: 0,
        peakBytes: Math.max(0, ...points.map(point => Number(point.traffic || 0))),
        peakLabel: '',
        liveClients: 0,
        liveRecords: 0
      }
    };
  }
  const points = (series?.points || []).map(point => ({
    ...point,
    downloadBytes: Number(point.downloadBytes || 0),
    uploadBytes: Number(point.uploadBytes || 0),
    records: Number(point.records || 0)
  }));
  renderTrafficSummary(series);
  setTranslatedText('#trafficChartSubtitle', trafficChartSubtitle(series));
  const width = 720;
  const height = 205;
  const padding = { left: 32, right: 18, top: 22, bottom: 33 };
  const plotHeight = height - padding.top - padding.bottom;
  const plotBottom = height - padding.bottom;
  const max = Math.max(1024, ...points.flatMap(point => [point.downloadBytes, point.uploadBytes]));
  const recordsMax = Math.max(1, ...points.map(point => Number(point.records || 0)));
  const x = index => padding.left + index * ((width - padding.left - padding.right) / (points.length - 1));
  const safeX = points.length > 1 ? x : () => width / 2;
  const y = value => padding.top + (height - padding.top - padding.bottom) * (1 - value / max);
  const step = points.length > 1
    ? (width - padding.left - padding.right) / (points.length - 1)
    : (width - padding.left - padding.right);
  const barWidth = Math.min(22, Math.max(5, step * .24));
  const downloadLine = chartPath(points, 'downloadBytes', safeX, y);
  const uploadLine = chartPath(points, 'uploadBytes', safeX, y);
  const area = points.length
    ? `${downloadLine} L ${safeX(points.length - 1)} ${height - padding.bottom} L ${safeX(0)} ${height - padding.bottom} Z`
    : '';
  const grid = [0, .25, .5, .75, 1].map(fraction => {
    const gy = padding.top + fraction * (height - padding.top - padding.bottom);
    return `<line class="chart-grid-line" x1="${padding.left}" y1="${gy}" x2="${width - padding.right}" y2="${gy}"/>`;
  }).join('');
  const axisLabels = [0, .5, 1].map(fraction => {
    const value = max * (1 - fraction);
    const gy = padding.top + fraction * (height - padding.top - padding.bottom);
    return `<text class="chart-axis-label" x="0" y="${gy + 3}">${escapeHtml(formatBytes(value))}</text>`;
  }).join('');
  const labels = points.map((point, index) => {
    const label = compactChartLabel(point, index, points.length, series?.bucket);
    return label ? `<text class="chart-label" x="${safeX(index)}" y="${height - 8}" text-anchor="middle">${escapeHtml(label)}</text>` : '';
  }).join('');
  const recordBars = points.map((point, index) => {
    const records = Number(point.records || 0);
    const barHeight = records ? Math.max(3, records / recordsMax * plotHeight * .46) : 0;
    return `<rect class="chart-record-bar" x="${safeX(index) - barWidth / 2}" y="${plotBottom - barHeight}" width="${barWidth}" height="${barHeight}" rx="3"/>`;
  }).join('');
  const dots = points.map((point, index) => `
    ${(point.downloadBytes || point.uploadBytes) ? `<circle class="chart-point download" cx="${safeX(index)}" cy="${y(point.downloadBytes)}" r="3.2"/>` : ''}
    ${point.uploadBytes ? `<circle class="chart-point upload" cx="${safeX(index)}" cy="${y(point.uploadBytes)}" r="3.2"/>` : ''}
  `).join('');
  const liveSummary = series?.summary || {};
  const hitAreas = points.map((point, index) => {
    const tooltip = dashboardTooltipAttributes({
      title: chartPointTitle(point),
      accent: '#3b82f6',
      rows: [
        { label: t('Download'), value: formatBytes(point.downloadBytes || 0) },
        { label: t('Upload'), value: formatBytes(point.uploadBytes || 0) },
        { label: t('Live records'), value: Number(point.records || 0).toLocaleString(i18n.locale) }
      ],
      foot: `${t('Live clients')}: ${Number(liveSummary.liveClients || 0).toLocaleString(i18n.locale)} · ${t('Live records')}: ${Number(liveSummary.liveRecords || 0).toLocaleString(i18n.locale)}`
    });
    return `<rect class="chart-hit-area" x="${safeX(index) - step / 2}" y="${padding.top}" width="${step}" height="${plotHeight}" ${tooltip}/>`;
  }).join('');
  $('#trafficChart').innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-label="${t('Download and upload traffic chart')}">
      <defs><linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#3b82f6" stop-opacity=".18"/><stop offset="1" stop-color="#3b82f6" stop-opacity=".01"/></linearGradient></defs>
      ${grid}${axisLabels}${area ? `<path class="chart-area" d="${area}"/>` : ''}
      ${recordBars}
      ${downloadLine ? `<path class="chart-line download-line" d="${downloadLine}"/>` : ''}
      ${uploadLine ? `<path class="chart-line upload-line" d="${uploadLine}"/>` : ''}
      ${dots}${labels}${hitAreas}
    </svg>`;
}

function renderMethodDonut(methods) {
  methods = Array.isArray(methods) ? methods : [];
  const colors = {
    email: '#6758e8',
    nvi: '#db2777',
    whatsapp: '#25a875',
    telegram: '#2aabee',
    sms: '#3b82f6',
    voucher: '#efa33a',
    'admin-approval': '#0f766e'
  };
  const total = methods.reduce((sum, item) => sum + Number(item.count), 0);
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const segments = methods.map(item => {
    const count = Number(item.count || 0);
    const meta = methodMeta(item.method);
    const color = colors[item.method] || '#aaa';
    const percentage = total ? Math.round(count / total * 100) : 0;
    const length = total ? (count / total) * circumference : 0;
    const tooltip = dashboardTooltipAttributes({
      title: meta.label,
      accent: color,
      rows: [
        { label: t('Records'), value: `${count.toLocaleString(i18n.locale)} ${t('verifications')}` },
        { label: t('Share'), value: `%${percentage}` },
        { label: t('Period'), value: t('Last 7 days') }
      ]
    });
    const element = `<circle class="donut-segment" cx="75" cy="75" r="${radius}" stroke="${color}" stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="${-offset}" ${tooltip}/>`;
    offset += length;
    return element;
  }).join('');
  $('#methodDonut').innerHTML = `
    <svg viewBox="0 0 150 150"><circle class="donut-track" cx="75" cy="75" r="${radius}"/>${segments}</svg>
    <div class="donut-center"><strong>${total.toLocaleString(i18n.locale)}</strong><span>${t('verifications')}</span></div>`;
  $('#methodLegend').innerHTML = methods.length ? methods.map(item => {
    const meta = methodMeta(item.method);
    const count = Number(item.count || 0);
    const percentage = total ? Math.round(count / total * 100) : 0;
    const tooltip = dashboardTooltipAttributes({
      title: meta.label,
      accent: colors[item.method] || '#aaa',
      rows: [
        { label: t('Records'), value: `${count.toLocaleString(i18n.locale)} ${t('verifications')}` },
        { label: t('Share'), value: `%${percentage}` },
        { label: t('Period'), value: t('Last 7 days') }
      ]
    });
    return `<span ${tooltip}><i class="legend-dot legend-${escapeHtml(item.method)}"></i>${meta.label} %${percentage}</span>`;
  }).join('') : `<span>${t('No verification data yet')}</span>`;
}

function topSitesPeriodLabel(hours) {
  const value = Number(hours || 6);
  if (value === 1) return t('Last 1 hour');
  if (value === 6) return t('Last 6 hours');
  if (value === 12) return t('Last 12 hours');
  return t('Last 24 hours');
}

const SITE_GAUGE_COLORS = [ '#6366F1', '#8B5CF6', '#EC4899', '#F59E0B', '#10B981', '#06B6D4', '#3B82F6', '#F472B6', '#F97316', '#14B8A6'];
const CLIENT_GAUGE_COLORS = [ '#6758e8', '#db2777', '#25a875', '#2aabee', '#3b82f6', '#efa33a', '#0f766e', '#10B981', '#06B6D4', '#8B5CF6'];

function gaugeColor(colors, index) {
  return colors[index % colors.length];
}

function shadeHexColor(hex, percent) {
  const num = parseInt(String(hex).replace('#', ''), 16);
  let r = (num >> 16) + percent;
  let g = ((num >> 8) & 0x00FF) + percent;
  let b = (num & 0x0000FF) + percent;
  r = Math.min(255, Math.max(0, r));
  g = Math.min(255, Math.max(0, g));
  b = Math.min(255, Math.max(0, b));
  return `#${(0x1000000 + r * 0x10000 + g * 0x100 + b).toString(16).slice(1)}`;
}

function siteGaugeLabel(row) {
  return row.label || row.clientIp || row.site || '—';
}

function siteGaugeTotalBytes(row) {
  const totalBytes = row.totalBytes ?? (Number(row.downloadBytes || 0) + Number(row.uploadBytes || 0));
  return Number(totalBytes || 0);
}

function siteGaugeMetricValue(row, metric) {
  return metric === 'bytes' ? siteGaugeTotalBytes(row) : Number(row.visits || 0);
}

function siteGaugeTooltipRows(row, metric, percentage, periodLabel) {
  if (metric === 'bytes') {
    return {
      rows: [
        { label: t('Traffic'), value: formatBytes(siteGaugeTotalBytes(row)) },
        { label: t('Download'), value: formatBytes(row.downloadBytes || 0) },
        { label: t('Upload'), value: formatBytes(row.uploadBytes || 0) }
      ],
      foot: periodLabel
    };
  }
  return {
    rows: [
      { label: t('Traffic'), value: `${Number(row.visits || 0).toLocaleString(i18n.locale)} ${t('visits')}` },
      { label: t('Share'), value: `%${percentage}` },
      { label: t('Period'), value: periodLabel }
    ],
    foot: ''
  };
}

function siteGaugeLegendDetail(row, metric, percentage) {
  if (metric === 'bytes') {
    return `${formatBytes(siteGaugeTotalBytes(row))} · ↓ ${formatBytes(row.downloadBytes || 0)} · ↑ ${formatBytes(row.uploadBytes || 0)} · ${percentage}%`;
  }
  const visits = Number(row.visits || 0);
  return `${visits.toLocaleString(i18n.locale)} ${t('visits')} · ${percentage}%`;
}

function renderSiteGauge(data, {
  subtitleSelector,
  donutSelector,
  legendSelector,
  metric = 'visits',
  emptyText = 'No site traffic yet',
  colors = SITE_GAUGE_COLORS,
  colorClassPrefix = 'site-color'
}) {
  const rows = Array.isArray(data.rows) ? data.rows : [];
  const total = rows.reduce((sum, row) => sum + siteGaugeMetricValue(row, metric), 0);
  const periodLabel = topSitesPeriodLabel(data.hours);
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const rawSegmentLengths = rows.map(row => {
    const value = siteGaugeMetricValue(row, metric);
    return total && value > 0 ? (value / total) * circumference : 0;
  });
  const visibleSegmentCount = rawSegmentLengths.filter(length => length > 0).length;
  const minSegmentLength = visibleSegmentCount > 1 ? 8 : 0;
  const minimumLengthTotal = minSegmentLength * visibleSegmentCount;
  const rawLengthTotal = rawSegmentLengths.reduce((sum, length) => sum + length, 0);
  const remainingLength = Math.max(0, circumference - minimumLengthTotal);
  const segmentLengths = rawSegmentLengths.map(length => {
    if (!length) return 0;
    if (!minSegmentLength || rawLengthTotal <= 0) return length;
    return minSegmentLength + (length / rawLengthTotal) * remainingLength;
  });
  let offset = 0;
  const segments = rows.map((row, index) => {
    const value = siteGaugeMetricValue(row, metric);
    const percentage = total ? Math.round(value / total * 100) : 0;
    const color = gaugeColor(colors, index);
    const title = `#${index + 1} ${siteGaugeLabel(row)}`;
    const tooltipRows = siteGaugeTooltipRows(row, metric, percentage, periodLabel);
    const tooltip = dashboardTooltipAttributes({
      title,
      accent: color,
      rows: tooltipRows.rows,
      foot: tooltipRows.foot
    });
    const length = segmentLengths[index] || 0;
    const element = `<circle class="donut-segment" cx="75" cy="75" r="${radius}" stroke="${color}" stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="${-offset}" ${tooltip}/>`;
    offset += length;
    return element;
  }).join('');
  setPlainText(subtitleSelector, periodLabel);
  $(donutSelector).innerHTML = `
    <svg viewBox="0 0 150 150"><circle class="donut-track" cx="75" cy="75" r="${radius}"/>${segments}</svg>
    <div class="donut-center"><strong>${metric === 'bytes' ? formatBytes(total) : total.toLocaleString(i18n.locale)}</strong><span>${metric === 'bytes' ? t('Traffic') : t('visits')}</span></div>`;
  $(legendSelector).innerHTML = rows.length ? rows.map((row, index) => {
    const value = siteGaugeMetricValue(row, metric);
    const percentage = total ? Math.round(value / total * 100) : 0;
    const precisePercentage = total ? (value / total) * 100 : 0;
    const width = value > 0 ? Math.max(10, Math.min(100, precisePercentage)) : 0;
    const color = gaugeColor(colors, index);
    const title = `#${index + 1} ${siteGaugeLabel(row)}`;
    const tooltipRows = siteGaugeTooltipRows(row, metric, percentage, periodLabel);
    const tooltip = dashboardTooltipAttributes({
      title,
      accent: color,
      rows: tooltipRows.rows,
      foot: tooltipRows.foot
    });
    return `<div class="site-legend-row ${colorClassPrefix}-${index % colors.length}" ${tooltip}>
      <span class="site-rank" aria-label="${escapeHtml(title)}">${index + 1}</span>
      <div class="site-name"><strong>${escapeHtml(siteGaugeLabel(row))}</strong><span>${escapeHtml(siteGaugeLegendDetail(row, metric, percentage))}</span></div>
       <svg class="site-bar" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true" focusable="false">
        <line class="site-bar-track" x1="0" y1="4" x2="100" y2="4" vector-effect="non-scaling-stroke"/>
        <line class="site-bar-fill" x1="0" y1="4" x2="${width}" y2="4" stroke-opacity="${width > 0 ? 1 : 0}" vector-effect="non-scaling-stroke"/>
      </svg>
    </div>`;
  }).join('') : `<div class="site-empty">${escapeHtml(t(emptyText))}</div>`;
}

function renderTopSitesDonut(data) {
  renderSiteGauge(data, {
    subtitleSelector: '#topSitesSubtitle',
    donutSelector: '#topSitesDonut',
    legendSelector: '#topSitesLegend'
  });
}

function renderTopBandwidthDonut(data) {
  renderSiteGauge(data, {
    subtitleSelector: '#topBandwidthSubtitle',
    donutSelector: '#topBandwidthDonut',
    legendSelector: '#topBandwidthLegend',
    metric: 'bytes',
    emptyText: 'No download / upload traffic yet',
    colors: CLIENT_GAUGE_COLORS,
    colorClassPrefix: 'client-color'
  });
}

function approvalContactLabel(row) {
  if (!row.contact) return t('No contact provided');
  return row.contact_type === 'phone' ? `+${row.contact}` : row.contact;
}

function approvalDecisionLabel(row) {
  if (row.status === 'pending') return t('Waiting');
  if (row.status === 'approved') return row.decision_message || t('Approved');
  if (row.status === 'rejected') return row.decision_message || t('Rejected');
  return row.last_error || statusLabel(row.status);
}

function pendingAdminApprovalDecision(requestId) {
  return state.pendingAdminApprovalDecisions[String(requestId || '')] || '';
}

function adminApprovalActionIcon(action) {
  return action === 'approve' ? '✓' : '×';
}

function renderApprovalActionButton(action, requestId, pendingAction) {
  const approve = action === 'approve';
  const busy = pendingAction === action;
  const label = busy ? t('Processing…') : t(approve ? 'Approve' : 'Reject');
  const className = approve ? 'success' : 'danger';
  const disabled = pendingAction ? ' disabled' : '';
  const busyAttr = busy ? ' aria-busy="true"' : '';
  const content = busy
    ? '<span class="button-spinner" aria-hidden="true"></span>'
    : adminApprovalActionIcon(action);
  return `<button class="action-button ${className}" type="button" data-admin-approval-action="${action}" data-admin-approval-id="${escapeHtml(requestId)}" title="${escapeHtml(label)}" aria-label="${escapeHtml(label)}"${disabled}${busyAttr}>${content}</button>`;
}

function renderApprovalActions(row) {
  if (row.status !== 'pending') return '';
  const requestId = encodeURIComponent(row.id);
  const pendingAction = pendingAdminApprovalDecision(requestId);
  return `<div class="request-actions">
    ${renderApprovalActionButton('approve', requestId, pendingAction)}
    ${renderApprovalActionButton('reject', requestId, pendingAction)}
  </div>`;
}

function syncAdminApprovalDecisionButtons(requestId) {
  const pendingAction = pendingAdminApprovalDecision(requestId);
  $$('[data-admin-approval-id]').forEach(button => {
    if (button.dataset.adminApprovalId !== requestId) return;
    const action = button.dataset.adminApprovalAction;
    const busy = pendingAction === action;
    const label = busy ? t('Processing…') : t(action === 'approve' ? 'Approve' : 'Reject');
    button.disabled = Boolean(pendingAction);
    button.title = label;
    button.setAttribute('aria-label', label);
    if (busy) button.setAttribute('aria-busy', 'true');
    else button.removeAttribute('aria-busy');
    button.innerHTML = busy
      ? '<span class="button-spinner" aria-hidden="true"></span>'
      : adminApprovalActionIcon(action);
  });
}

function setAdminApprovalDecisionPending(requestId, action, pending) {
  const key = String(requestId || '');
  if (!key) return;
  if (pending) state.pendingAdminApprovalDecisions[key] = action;
  else delete state.pendingAdminApprovalDecisions[key];
  syncAdminApprovalDecisionButtons(key);
}

function renderDashboardAdminApprovals(data) {
  const panel = $('#dashboardApprovalRequests');
  if (!panel) return;
  const requests = data.requests || [];
  const pending = Number(data.pending || 0);
  panel.classList.toggle('hidden', pending === 0);
  setPlainText('#dashboardApprovalCount', `${pending.toLocaleString(i18n.locale)} ${t('requests')}`);
  $('#dashboardApprovalList').innerHTML = requests.length ? requests.map(row => `
    <div class="approval-row">
      <div class="identity-cell">
        <div class="identity-icon admin-approval">A</div>
        <div><strong>${escapeHtml(row.full_name)}</strong><span>${escapeHtml(approvalContactLabel(row))}</span></div>
      </div>
      <div class="stacked"><strong>${escapeHtml(row.client_ip)}</strong><span>${escapeHtml(row.client_mac || t('No MAC address recorded'))}</span></div>
      <div class="log-time">${formatDate(row.created_at)}<br><span>${relativeTime(row.created_at)}</span></div>
      ${renderApprovalActions(row)}
    </div>
  `).join('') : `<div class="empty-activity">${escapeHtml(t('No pending admin approval requests.'))}</div>`;
}

async function refreshDashboardAdminApprovals() {
  if (state.adminApprovalRefreshPending) return;
  state.adminApprovalRefreshPending = true;
  state.lastAdminApprovalRefreshAt = Date.now();
  try {
    const data = await api('/api/admin/admin-approval/requests?status=pending&limit=8');
    renderDashboardAdminApprovals({
      pending: Number(data.total || 0),
      requests: data.rows || []
    });
  } finally {
    state.adminApprovalRefreshPending = false;
  }
}

function renderRecentSessions(rows) {
  $('#recentSessionsBody').innerHTML = rows.length ? rows.map(row => {
    const identity = authorizationIdentity(row);
    const method = methodMeta(row.method);
    const status = authorizationState(row);
    const end = row.ended_at || Math.min(Date.now(), Number(row.expires_at));
    return `<tr>
      <td><div class="identity-cell"><div class="identity-icon ${method.className}">${escapeHtml(method.short)}</div><div><strong>${escapeHtml(identity.primary)}</strong><span>${escapeHtml(identity.secondary)}</span></div></div></td>
      <td><span class="method-pill ${method.className}">${method.label}</span></td>
      <td><div class="stacked"><strong>${escapeHtml(row.client_ip)}</strong><span>${escapeHtml(row.client_mac || t('No MAC address recorded'))}</span></div></td>
      <td><div class="stacked"><strong>${formatBytes(Number(row.download_bytes) + Number(row.upload_bytes))}</strong><span>↓ ${formatBytes(row.download_bytes)} · ↑ ${formatBytes(row.upload_bytes)}</span></div></td>
      <td>${formatDuration(Math.max(0, end - Number(row.created_at)))}</td>
      <td><span class="status-pill ${status.key}">${status.label}</span></td>
    </tr>`;
  }).join('') : emptyRow(6, t('No connection records yet.'));
}

async function loadSessions() {
  const params = new URLSearchParams({
    search: $('#sessionSearch').value,
    method: $('#sessionMethod').value,
    state: $('#sessionState').value,
    limit: '250'
  });
  const data = await api(`/api/admin/sessions?${params}`);
  $('#sessionCount').textContent = `${data.total.toLocaleString(i18n.locale)} ${t('records')}`;
  state.sessionRows = data.rows;
  renderSessionsTable(data.rows);
  refreshActiveSessionCount().catch(() => {});
}

async function loadVerifications() {
  const params = new URLSearchParams({
    search: $('#verificationSearch').value,
    kind: $('#verificationKind').value,
    status: $('#verificationStatus').value,
    limit: '250'
  });
  const data = await api(`/api/admin/verifications?${params}`);
  $('#verificationCount').textContent = `${data.total.toLocaleString(i18n.locale)} ${t('records')}`;
  $('#verificationsBody').innerHTML = data.rows.length ? data.rows.map(row => {
    const method = methodMeta(row.kind);
    const detail = verificationDetail(row, method);
    const requestLabel = row.kind === 'voucher' ? t('Redeemed') : t('OTP valid until');
    const targetSecondary = row.kind === 'voucher'
      ? `${t('Code ending')} ···· ${row.voucher_hint || '—'}`
      : (row.verified_at ? `${t('Verified')}: ${formatDate(row.verified_at)}` : t('Not verified yet'));
    return `<tr>
      <td><div class="identity-cell"><div class="identity-icon ${method.className}">${escapeHtml(method.short)}</div><div><strong>${escapeHtml(row.target)}</strong><span>${escapeHtml(targetSecondary)}</span></div></div></td>
      <td><span class="method-pill ${method.className}">${method.label}</span></td>
      <td><div class="stacked"><strong>${escapeHtml(row.client_ip)}</strong><span>${escapeHtml(row.client_mac || t('No MAC address recorded'))}</span></div></td>
      <td><div class="stacked"><strong>${formatDate(row.created_at)}</strong><span>${requestLabel}: ${formatDate(row.expires_at)}</span>${row.access_expires_at ? `<span>${t('Access valid until')}: ${row.access_unlimited ? t('No expiration') : formatDate(row.access_expires_at)}</span>` : ''}</div></td>
      <td title="${escapeHtml(t('Counts only incorrect OTP/code entries, not send attempts.'))}">${escapeHtml(verificationAttemptText(row.attempts))}</td>
      <td><span class="status-pill ${escapeHtml(row.status)}">${escapeHtml(statusLabel(row.status))}</span></td>
      <td><span class="detail-summary ${escapeHtml(detail.key)}" title="${escapeHtml(detail.tooltip)}">${escapeHtml(detail.summary)}</span></td>
    </tr>`;
  }).join('') : emptyRow(7);
}

async function loadAdminApprovalRequests() {
  const params = new URLSearchParams({
    search: $('#adminApprovalSearch')?.value || '',
    status: $('#adminApprovalStatus')?.value || '',
    limit: '250'
  });
  const data = await api(`/api/admin/admin-approval/requests?${params}`);
  $('#adminApprovalCount').textContent = `${data.total.toLocaleString(i18n.locale)} ${t('requests')}`;
  $('#adminApprovalBody').innerHTML = data.rows.length ? data.rows.map(row => `
    <tr>
      <td><div class="identity-cell"><div class="identity-icon admin-approval">A</div><div><strong>${escapeHtml(row.full_name)}</strong><span>${escapeHtml(row.identity)}</span></div></div></td>
      <td><div class="stacked"><strong>${escapeHtml(approvalContactLabel(row))}</strong><span>${escapeHtml(row.contact_type || 'none')}</span></div></td>
      <td><div class="stacked"><strong>${escapeHtml(row.client_ip)}</strong><span>${escapeHtml(row.client_mac || t('No MAC address recorded'))}</span></div></td>
      <td><div class="stacked"><strong>${formatDate(row.created_at)}</strong><span>${t('Request valid until')}: ${formatDate(row.request_expires_at)}</span></div></td>
      <td><div class="stacked"><strong>${escapeHtml(approvalDecisionLabel(row))}</strong><span>${row.decided_at ? `${t('Decision time')}: ${formatDate(row.decided_at)}` : t('Not decided yet')}</span></div></td>
      <td><span class="status-pill ${escapeHtml(row.status)}">${escapeHtml(statusLabel(row.status))}</span></td>
      <td>${renderApprovalActions(row)}</td>
    </tr>
  `).join('') : emptyRow(7, t('No admin approval requests match these filters.'));
}

function voucherState(row) {
  if (!row.enabled) return { key: 'failed', label: t('Disabled') };
  if (row.expires_at && Number(row.expires_at) < Date.now()) return { key: 'expired', label: t('Expired') };
  if (Number(row.used_count) >= Number(row.max_uses)) return { key: 'ended', label: t('Depleted') };
  if (row.valid_from && Number(row.valid_from) > Date.now()) return { key: 'pending', label: t('Scheduled') };
  return { key: 'active', label: t('Available') };
}

async function loadVouchers() {
  const params = new URLSearchParams({
    search: $('#voucherSearch').value,
    status: $('#voucherStatus').value,
    limit: '250'
  });
  const data = await api(`/api/admin/vouchers?${params}`);
  $('#voucherCount').textContent = `${data.total.toLocaleString(i18n.locale)} voucher`;
  $('#vouchersBody').innerHTML = data.rows.length ? data.rows.map(row => {
    const status = voucherState(row);
    const ratio = Math.min(100, Math.round(Number(row.used_count) / Number(row.max_uses) * 100));
    return `<tr>
      <td><div class="identity-cell"><div class="identity-icon voucher">V</div><div><strong>••••-••••-${escapeHtml(row.code_hint)}</strong><span>${escapeHtml(row.id.slice(0, 8))}</span></div></div></td>
      <td>${escapeHtml(row.label || t('No label'))}</td>
      <td><div class="usage-bar"><progress max="100" value="${ratio}"></progress><span>${row.used_count} / ${row.max_uses} ${t('uses')}</span></div></td>
      <td>${formatDuration(Number(row.duration_minutes) * 60000)}</td>
      <td><div class="stacked"><strong>${row.expires_at ? formatDate(row.expires_at) : t('No expiration')}</strong><span>${row.valid_from ? `${t('Starts')}: ${formatDate(row.valid_from)}` : t('Valid immediately')}</span></div></td>
      <td>${formatDate(row.created_at)}</td>
      <td><span class="status-pill ${status.key}">${status.label}</span></td>
      <td><button class="action-button" data-toggle-voucher="${encodeURIComponent(row.id)}" data-enabled="${row.enabled ? '0' : '1'}" title="${row.enabled ? t('Disable') : t('Enable')}">${row.enabled ? '—' : '+'}</button></td>
    </tr>`;
  }).join('') : emptyRow(8);
}

function activityLabel(row) {
  const labels = {
    access_granted: t('Internet access granted'),
    access_failed: t('Gateway authorization failed'),
    verification_verified: t('User verified'),
    verification_pending: t('Verification request created'),
    verification_failed: t('Verification failed'),
    verification_expired: t('Verification expired'),
    admin_approval_pending: t('Admin approval request created'),
    admin_approval_approved: t('Admin approval request approved'),
    admin_approval_rejected: t('Admin approval request rejected'),
    admin_approval_expired: t('Admin approval request expired'),
    admin_approval_failed: t('Admin approval request failed'),
    admin_login: t('Administrator signed in'),
    admin_logout: t('Administrator signed out'),
    vouchers_created: t('Voucher group created'),
    voucher_enabled: t('Voucher enabled'),
    voucher_disabled: t('Voucher disabled'),
    session_disconnected: t('Session disconnected by administrator'),
    gateway_sync: t('OPNsense data synchronized'),
    settings_updated: t('Settings updated'),
    appearance_asset_uploaded: t('Appearance image uploaded'),
    appearance_asset_deleted: t('Appearance image removed'),
    traffic_logs_settings_updated: t('Traffic log settings updated'),
    smtp_test_sent: t('SMTP test email sent'),
    law5651_sync: t('Syslog synchronized'),
    law5651_export: t('Syslog export created'),
    syslog_sync: t('Syslog synchronized'),
    syslog_export: t('Syslog export created'),
    syslog_vacuum: t('Syslog database compacted'),
    opnsense_template_created: t('OPNsense template ZIP created'),
    syslog_backup_failed: t('Syslog backup failed'),
    syslog_backup_succeeded: t('Syslog backup completed'),
    syslog_backup_worm_warning: t('Syslog backup WORM warning'),
    syslog_remote_mirror_failed: t('Remote syslog mirror failed'),
    syslog_kamusm_timestamp_succeeded: t('KamuSM timestamp created'),
    syslog_kamusm_timestamp_failed: t('KamuSM timestamp failed'),
    syslog_timestamp_succeeded: t('Timestamp created'),
    syslog_timestamp_failed: t('Timestamp failed'),
    syslog_storage_warning_threshold_reached: t('Syslog storage warning'),
    syslog_storage_block_threshold_reached: t('Syslog storage block threshold reached'),
    syslog_storage_blocked_portal: t('Portal blocked by syslog storage'),
    syslog_storage_recovered: t('Syslog storage recovered'),
    ntp_sync_lost: t('NTP synchronization lost'),
    ntp_sync_restored: t('NTP synchronization restored'),
    ntp_status_unknown: t('NTP status unknown'),
    clock_moved_backward: t('System clock moved backward'),
    clock_jumped_forward: t('System clock jumped forward'),
    timezone_changed: t('Time zone changed'),
    system_boot_detected: t('System boot detected'),
    system_boot_observed: t('System boot recorded'),
    syslog_service_started: t('Syslog guard started'),
    syslog_service_stopped: t('Syslog guard stopped'),
    syslog_receiver_started: t('Syslog receiver started'),
    syslog_receiver_stopped: t('Syslog receiver stopped'),
    syslog_receiver_error: t('Syslog receiver error'),
    syslog_auto_exporter_started: t('Syslog automatic exporter started'),
    syslog_auto_exporter_stopped: t('Syslog automatic exporter stopped'),
    portal_log_write_check: t('Portal log write checked')
  };
  return labels[row.action] || row.action.replaceAll('_', ' ');
}

function activitySource(value) {
  if (['email', 'nvi', 'whatsapp', 'telegram', 'sms', 'voucher', 'admin-approval'].includes(value)) {
    return methodMeta(value).label;
  }
  return {
    admin: t('Administration panel'),
    gateway: 'OPNsense',
    voucher_batch: t('Voucher group'),
    authorization: t('Hotspot session'),
    traffic_logs: t('Traffic logs'),
    opnsense_template: t('OPNsense template'),
    settings: t('Settings'),
    law5651: 'Syslog',
    syslog: 'Syslog'
  }[value] || value || t('System');
}

async function loadLogs() {
  const params = new URLSearchParams({
    search: $('#logSearch').value,
    kind: $('#logKind').value,
    limit: '300'
  });
  const data = await api(`/api/admin/logs?${params}`);
  $('#logsList').innerHTML = data.rows.length ? data.rows.map(row => {
    const icon = row.kind === 'admin'
      ? '<path d="M12 15a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM5 21a7 7 0 0 1 14 0"/>'
      : row.kind === 'verification'
        ? '<path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V5l8-3 8 3v8Z"/><path d="m9 12 2 2 4-4"/>'
        : '<path d="M5 12h14M13 6l6 6-6 6"/>';
    return `<div class="log-row">
      <div class="log-icon ${escapeHtml(row.kind)}"><svg viewBox="0 0 24 24">${icon}</svg></div>
      <div class="log-main"><strong>${escapeHtml(activityLabel(row))}</strong><span>${escapeHtml(row.subject || t('System'))}</span></div>
      <div class="log-meta"><span>${t('Method / source')}</span><strong>${escapeHtml(activitySource(row.method))}</strong></div>
      <div class="log-meta"><span>${t('Client IP')}</span><strong>${escapeHtml(row.clientIp || '—')}</strong></div>
      <div class="log-time">${formatDate(row.createdAt)}<br><span>${relativeTime(row.createdAt)}</span></div>
    </div>`;
  }).join('') : `<div class="empty-activity">${t('No activity matches these filters.')}</div>`;
}

function trafficDirectionLabel(value) {
  return {
    incoming: t('Incoming'),
    outgoing: t('Outgoing'),
    session: t('Session'),
    flow: t('Flow')
  }[value] || value || '—';
}

function trafficEndpointLabel(ip, port = '', domain = '') {
  const address = ip || '—';
  const label = domain ? `${domain} · ${address}` : address;
  return `${label}${port ? `:${port}` : ''}`;
}

function trafficEndpointAddress(ip, port = '') {
  const address = ip || '—';
  return `${address}${port ? `:${port}` : ''}`;
}

function trafficLogRaw(row) {
  try {
    return row.raw_json ? JSON.parse(row.raw_json) : {};
  } catch {
    return {};
  }
}

function normalizeTrafficInterface(value) {
  return String(value || '').trim().toLowerCase();
}

function trafficInterfaceRoleFromText(value) {
  const text = normalizeTrafficInterface(value);
  if (!text) return '';
  if (/(^|[^a-z0-9])wan([^a-z0-9]|$)/u.test(text)) return 'wan';
  if (/(^|[^a-z0-9])lan([^a-z0-9]|$)/u.test(text)) return 'lan';
  return '';
}

function discoveredTrafficInterface(rawName) {
  const key = normalizeTrafficInterface(rawName);
  if (!key) return null;
  const interfaces = state.gatewayInterfaces?.interfaces || [];
  return interfaces.find(item => {
    const aliases = [
      item.name,
      item.label,
      item.description,
      ...(Array.isArray(item.aliases) ? item.aliases : [])
    ].map(normalizeTrafficInterface).filter(Boolean);
    return aliases.includes(key);
  }) || null;
}

function fallbackTrafficInterfaceRole(row) {
  if (row.kind === 'flow' && row.direction === 'incoming') return 'wan';
  if (row.kind === 'flow' && row.direction === 'outgoing') return 'lan';
  if (row.kind === 'session') return 'lan';
  return '';
}

function trafficInterfaceMeta(row) {
  const raw = trafficLogRaw(row);
  const interfaceName = String(raw.interface || raw.interfaceName || raw.iface || '').trim();
  const discovered = discoveredTrafficInterface(interfaceName);
  const discoveredLabel = discovered?.label || discovered?.description || discovered?.name || '';
  const role = trafficInterfaceRoleFromText(discoveredLabel) ||
    trafficInterfaceRoleFromText(discovered?.name) ||
    fallbackTrafficInterfaceRole(row);
  const label = role
    ? role.toUpperCase()
    : (discoveredLabel || interfaceName || '—').toUpperCase();
  return {
    label,
    role: role || 'unknown',
    rawName: interfaceName,
    title: interfaceName && label !== interfaceName.toUpperCase()
      ? `${label} · ${interfaceName.toUpperCase()}`
      : label
  };
}

function trafficProtocolLabel(row) {
  return String(row.protocol || '—').toUpperCase();
}

function trafficDirectionKey(value) {
  const direction = String(value || '').trim().toLowerCase();
  return ['incoming', 'outgoing', 'session', 'flow'].includes(direction)
    ? direction
    : 'unknown';
}

function trafficProtocolKey(row) {
  const protocol = String(row.protocol || '').trim().toLowerCase();
  if (protocol === 'tcp' || protocol === '6') return 'tcp';
  if (protocol === 'udp' || protocol === '17') return 'udp';
  if (
    protocol === 'icmp' ||
    protocol === 'icmpv4' ||
    protocol === 'icmpv6' ||
    protocol === '1' ||
    protocol === '58'
  ) return 'icmp';
  return 'other';
}

function trafficActionKey(row) {
  const raw = trafficLogRaw(row);
  const action = String(raw.action || '').toLowerCase();
  const serviceType = String(row.service_type || '').toLowerCase();
  if (action === 'pass' || serviceType.includes('pass')) return 'passed';
  if (action === 'block' || action === 'reject' || serviceType.includes('block') || serviceType.includes('reject')) {
    return 'blocked';
  }
  if (row.kind === 'session') return 'passed';
  return 'unknown';
}

function trafficActionLabel(row) {
  return {
    passed: t('Passed'),
    blocked: t('Blocked'),
    unknown: t('Unknown')
  }[trafficActionKey(row)];
}

function trafficIsoTimestamp(value) {
  if (!value) return '—';
  const date = new Date(Number(value));
  if (Number.isNaN(date.getTime())) return '—';
  const part = number => String(number).padStart(2, '0');
  return [
    date.getFullYear(),
    part(date.getMonth() + 1),
    part(date.getDate())
  ].join('-') + `T${part(date.getHours())}:${part(date.getMinutes())}:${part(date.getSeconds())}`;
}

function trafficEndpointCell(row, type) {
  const ip = type === 'source' ? row.source_ip : row.destination_ip;
  const port = type === 'source' ? row.source_port : row.destination_port;
  const address = ip || '—';
  const endpoint = trafficEndpointAddress(address, port || '');
  const protocolKey = trafficProtocolKey(row);
  const mac = row.client_mac && row.client_ip && ip === row.client_ip ? row.client_mac : '';
  const portTitle = port ? `${trafficProtocolLabel(row)} port ${port}` : '';

  return `<div class="traffic-endpoint-main">
    <strong title="${escapeHtml(endpoint)}">${escapeHtml(address)}</strong>
    ${port ? `<span class="traffic-endpoint-separator" aria-hidden="true">:</span><span class="traffic-port ${escapeHtml(protocolKey)}" title="${escapeHtml(portTitle)}">${escapeHtml(port)}</span>` : ''}
  </div>${mac ? `<span class="traffic-endpoint-mac" title="${escapeHtml(mac)}">${escapeHtml(mac)}</span>` : ''}`;
}

function trafficKindLabel(value) {
  return value === 'flow' ? t('Firewall flow') : t('Session snapshot');
}

function trafficLogFilterParams(extra = {}) {
  const params = new URLSearchParams({
    sourceIp: $('#trafficLogSourceIp')?.value || '',
    sourcePort: $('#trafficLogSourcePort')?.value || '',
    destinationIp: $('#trafficLogDestinationIp')?.value || '',
    destinationPort: $('#trafficLogDestinationPort')?.value || '',
    startAt: $('#trafficLogStartAt')?.value || '',
    endAt: $('#trafficLogEndAt')?.value || '',
    kind: $('#trafficLogKind')?.value || '',
    period: $('#trafficLogPeriod')?.value || 'daily',
    ...extra
  });
  return params;
}

function updateTrafficLogsExportHref() {
  const params = trafficLogFilterParams();
  $('#trafficLogsExport')?.setAttribute('href', `/api/admin/export/traffic-logs.csv?${params}`);
}

function updateTrafficLogStreamToggle() {
  const button = $('#trafficLogStreamToggleButton');
  if (!button) return;
  const paused = Boolean(state.trafficLogLivePaused);
  const label = paused ? 'Resume live traffic logs' : 'Pause live traffic logs';
  button.innerHTML = paused ? TRAFFIC_LOG_STREAM_ICONS.play : TRAFFIC_LOG_STREAM_ICONS.pause;
  button.classList.toggle('is-paused', paused);
  button.dataset.i18nAria = label;
  button.setAttribute('aria-label', t(label));
  button.setAttribute('aria-pressed', paused ? 'true' : 'false');
  button.title = t(label);
}

function setTrafficLogLivePaused(paused, { refresh = false } = {}) {
  state.trafficLogLivePaused = Boolean(paused);
  updateTrafficLogStreamToggle();
  if (!state.trafficLogLivePaused && refresh && state.currentView === 'traffic-logs') {
    loadTrafficLogs().catch(error => toast(error.message, 'error'));
  }
}

function toggleTrafficLogLiveStream() {
  const refresh = state.trafficLogLivePaused;
  setTrafficLogLivePaused(!state.trafficLogLivePaused, { refresh });
}

function renderTrafficLogSummary(data) {
  const summary = data.summary || {};
  const settings = data.settings || {};
  const liveReady = summary.liveSource === 'gateway_interface' && Number(summary.liveWindowSeconds || 0) > 0;
  const liveUnavailable = summary.liveSource === 'gateway_interface_forbidden'
    ? t('OPNsense interface API permission required')
    : t('Waiting for gateway sample');
  const liveDownload = liveReady ? formatByteRate(summary.liveDownloadBps || 0) : liveUnavailable;
  const liveUpload = liveReady ? formatByteRate(summary.liveUploadBps || 0) : liveUnavailable;
  $('#trafficLogSummary').innerHTML = [
    [t('Records'), Number(summary.records || 0).toLocaleString(i18n.locale)],
    [t('Clients'), Number(summary.clients || 0).toLocaleString(i18n.locale)],
    [t('Live download'), liveDownload],
    [t('Live upload'), liveUpload],
    [t('Retention'), `${settings.retentionDays || 30} ${t('days')}`],
    [t('Last record'), summary.lastCreatedAt ? relativeTime(summary.lastCreatedAt) : '—']
  ].map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
}

function renderTrafficLogs(rows) {
  if (!rows.length) {
    $('#trafficLogsList').innerHTML = `<div class="empty-activity">${escapeHtml(t('No traffic logs match these filters.'))}</div>`;
    return;
  }
  const columns = [
    'Interface', 'Direction', 'Time', 'Protocol', 'Source', 'Destination',
    'Domain', 'Action', 'Flow detail', 'Traffic'
  ];
  $('#trafficLogsList').innerHTML = `<div class="traffic-log-table">
    <div class="traffic-log-table-head">${columns.map(column => `<div>${escapeHtml(t(column))}</div>`).join('')}</div>
    ${rows.map(row => {
    const downloadBytes = row.effective_download_bytes ?? row.download_bytes ?? 0;
    const uploadBytes = row.effective_upload_bytes ?? row.upload_bytes ?? 0;
    const traffic = `↓ ${formatBytes(downloadBytes)} · ↑ ${formatBytes(uploadBytes)}`;
      const actionKey = trafficActionKey(row);
      const directionKey = trafficDirectionKey(row.direction || row.kind);
      const interfaceMeta = trafficInterfaceMeta(row);
      const protocolKey = trafficProtocolKey(row);
      return `<div class="traffic-log-row ${escapeHtml(row.kind)}">
      <div class="traffic-log-cell traffic-log-interface"><span class="traffic-badge traffic-interface-badge ${escapeHtml(interfaceMeta.role)}" title="${escapeHtml(interfaceMeta.title)}">${escapeHtml(interfaceMeta.label)}</span></div>
      <div class="traffic-log-cell traffic-log-direction"><span class="traffic-badge traffic-direction-badge ${escapeHtml(directionKey)}">${escapeHtml(trafficDirectionLabel(row.direction || row.kind))}</span></div>
      <div class="traffic-log-cell traffic-log-time"><strong title="${escapeHtml(trafficIsoTimestamp(row.created_at))}">${escapeHtml(trafficIsoTimestamp(row.created_at))}</strong></div>
      <div class="traffic-log-cell traffic-log-protocol"><span class="traffic-badge traffic-protocol-badge ${escapeHtml(protocolKey)}">${escapeHtml(trafficProtocolLabel(row))}</span></div>
      <div class="traffic-log-cell traffic-log-endpoint-cell">${trafficEndpointCell(row, 'source')}</div>
      <div class="traffic-log-cell traffic-log-endpoint-cell">${trafficEndpointCell(row, 'destination')}</div>
      <div class="traffic-log-cell"><strong title="${escapeHtml(row.destination_domain || '—')}">${escapeHtml(row.destination_domain || '—')}</strong></div>
      <div class="traffic-log-cell traffic-log-action ${escapeHtml(actionKey)}"><strong>${escapeHtml(trafficActionLabel(row))}</strong></div>
      <div class="traffic-log-cell traffic-log-flow"><strong>${escapeHtml(trafficKindLabel(row.kind))}</strong><span>${escapeHtml(trafficProtocolLabel(row).toLowerCase())}</span></div>
      <div class="traffic-log-cell traffic-log-usage">
        <strong title="${escapeHtml(traffic)}">${escapeHtml(traffic)}</strong>
        <span>${formatDate(row.created_at)} · ${relativeTime(row.created_at)}</span>
      </div>
    </div>`;
  }).join('')}
  </div>`;
}

async function loadTrafficLogs() {
  const params = trafficLogFilterParams({ limit: '250' });
  updateTrafficLogsExportHref();
  const data = await api(`/api/admin/traffic-logs?${params}`);
  state.lastTrafficLogRefreshAt = Date.now();
  state.trafficLogRows = data.rows || [];
  $('#trafficLogCount').textContent = `${data.total.toLocaleString(i18n.locale)} ${t('records')}`;
  renderTrafficLogSummary(data);
  renderTrafficLogs(state.trafficLogRows);
}

function setTrafficLogSettingsForm(payload) {
  const values = payload.values || {};
  const runtime = payload.runtime || {};
  $('#trafficLogsEnabled').checked = String(values.TRAFFIC_LOGS_ENABLED ?? runtime.enabled) === 'true' || runtime.enabled === true;
  $('#trafficLogsRetentionDays').value = values.TRAFFIC_LOGS_RETENTION_DAYS ?? runtime.retentionDays ?? 30;
  $('#trafficLogsResolveDomains').checked = String(values.TRAFFIC_LOGS_RESOLVE_DOMAINS ?? runtime.resolveDomains) === 'true' || runtime.resolveDomains === true;
  $('#trafficLogsLiveRefreshSeconds').value = values.TRAFFIC_LOGS_LIVE_REFRESH_SECONDS ?? runtime.liveRefreshSeconds ?? 5;
}

async function loadTrafficLogSettings() {
  state.trafficLogSettings = await api('/api/admin/traffic-logs/settings');
  setTrafficLogSettingsForm(state.trafficLogSettings);
}

async function loadTrafficLogInterfaces() {
  if (state.gatewayMode === 'mock' || state.gatewayInterfaces) return;
  try {
    state.gatewayInterfaces = await api('/api/admin/gateway/interfaces');
  } catch {
    state.gatewayInterfaces = { interfaces: [] };
  }
}

async function loadTrafficLogView() {
  updateTrafficLogStreamToggle();
  const interfaces = loadTrafficLogInterfaces()
    .then(() => {
      if (state.currentView === 'traffic-logs' && state.trafficLogRows.length) {
        renderTrafficLogs(state.trafficLogRows);
      }
    })
    .catch(() => {});
  await Promise.all([
    loadTrafficLogs(),
    loadTrafficLogSettings()
  ]);
  void interfaces;
}

function openTrafficLogSettingsModal() {
  const modal = $('#trafficLogSettingsModal');
  modal.classList.remove('hidden');
  setTimeout(() => $('#trafficLogsEnabled')?.focus(), 40);
}

function closeTrafficLogSettingsModal() {
  $('#trafficLogSettingsModal').classList.add('hidden');
  $('#trafficLogSettingsButton')?.focus();
}

async function saveTrafficLogSettings(event) {
  event.preventDefault();
  const button = $('#saveTrafficLogSettings');
  setButtonBusy(button, true, 'Saving…');
  try {
    const result = await api('/api/admin/traffic-logs/settings', {
      method: 'PUT',
      body: JSON.stringify({
        settings: {
          TRAFFIC_LOGS_ENABLED: $('#trafficLogsEnabled').checked,
          TRAFFIC_LOGS_RETENTION_DAYS: $('#trafficLogsRetentionDays').value,
          TRAFFIC_LOGS_RESOLVE_DOMAINS: $('#trafficLogsResolveDomains').checked,
          TRAFFIC_LOGS_LIVE_REFRESH_SECONDS: $('#trafficLogsLiveRefreshSeconds').value
        }
      })
    });
    state.trafficLogSettings = { ...(state.trafficLogSettings || {}), runtime: result.runtime };
    toast(t('Traffic log settings saved.'));
    closeTrafficLogSettingsModal();
    await loadTrafficLogs();
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setButtonBusy(button, false);
  }
}

function settingOptionLabel(value, field = null) {
  if (field?.key?.endsWith('_QUOTA_PERIOD')) {
    return quotaPeriodLabel(value);
  }
  return {
    en: 'English',
    tr: 'Türkçe',
    mock: 'Mock / test',
    'opnsense-api': 'OPNsense API',
    netgsm: 'Netgsm',
    iletimerkezi: 'İleti Merkezi',
    twilio: 'Twilio',
    custom: t('Create custom service'),
    webhook: 'Webhook',
    polling: 'Polling',
    hours: t('Hours'),
    days: t('Days'),
    months: t('Months'),
    years: t('Years'),
    minutes: t('Minutes'),
    unlimited: t('Unlimited'),
    disabled: t('Disabled'),
    kamusm: 'KamuSM',
    rfc3161: 'RFC3161 TSA',
    'api-key': t('API key'),
    'state-change': t('When alert changes'),
    hourly: t('Once an hour'),
    '1h': t('Every 1 hour'),
    '6h': t('Every 6 hours'),
    '12h': t('Every 12 hours'),
    '24h': t('Every 24 hours'),
    daily: t('Once a day'),
    weekly: t('Once a week'),
    monthly: t('Once a month')
  }[value] || value;
}

function settingVisibilityAttributes(field) {
  const attributes = [];
  if (field.visibleWhen) attributes.push(`data-visible-when="${escapeHtml(field.visibleWhen)}"`);
  if (field.visibleWhenValue) {
    const key = typeof field.visibleWhenValue === 'string'
      ? field.visibleWhenValue.split('=')[0]
      : field.visibleWhenValue.key;
    const value = typeof field.visibleWhenValue === 'string'
      ? field.visibleWhenValue.split('=').slice(1).join('=')
      : field.visibleWhenValue.value;
    attributes.push(`data-visible-when-value="${escapeHtml(`${key}=${value}`)}"`);
  }
  if (field.visibleWhenAll) {
    attributes.push(`data-visible-when-all="${escapeHtml(field.visibleWhenAll.join(','))}"`);
  }
  if (field.visibleWhenAny) {
    attributes.push(`data-visible-when-any="${escapeHtml(field.visibleWhenAny.join(','))}"`);
  }
  return attributes.length ? ` ${attributes.join(' ')}` : '';
}

function settingInput(field, value, configured, options = {}) {
  const id = `setting_${field.key}`;
  const provider = field.provider ? ` data-provider="${field.provider}"` : '';
  const derivedFrom = field.derivedFrom ? ` data-derived-from="${escapeHtml(field.derivedFrom)}"` : '';
  const readOnly = field.readOnly ? ' readonly aria-readonly="true"' : '';
  const full = ['textarea', 'secret'].includes(field.type) ? ' full' : '';
  const visibility = settingVisibilityAttributes(field);
  const help = field.warning
    ? `<small>${escapeHtml(t(field.warning))}</small>`
    : (field.restartRequired ? `<small>${escapeHtml(t('Requires a process restart.'))}</small>` : '');
  const networkChoices = ['OPNSENSE_SHAPER_NETWORK', 'SYSLOG_NETWORKS', 'OPNSENSE_ZONE_MAP'].includes(field.key)
    ? `<div class="syslog-network-choices opnsense-network-choices" data-opnsense-network-choices="${escapeHtml(field.key)}"></div>`
    : '';
  let control;
  if (field.type === 'boolean') {
    if (options.minimalBoolean) {
      return `<div class="setting-field setting-field--minimal-boolean"${provider}${visibility}>
        <label class="minimal-boolean-field" for="${id}">
          <input id="${id}" name="${escapeHtml(field.key)}" data-setting="${field.key}"${derivedFrom} type="checkbox" ${String(value) === 'true' ? 'checked' : ''}>
          <span>${escapeHtml(t(field.label))}</span>
        </label>
        ${help}
      </div>`;
    }
    control = `<label class="boolean-field"><input id="${id}" name="${escapeHtml(field.key)}" data-setting="${field.key}"${derivedFrom} type="checkbox" ${String(value) === 'true' ? 'checked' : ''}><span>${escapeHtml(t('Enabled'))}</span></label>`;
  } else if (field.type === 'select') {
    control = `<select id="${id}" name="${escapeHtml(field.key)}" data-setting="${field.key}"${derivedFrom}>${field.options.map(option =>
      `<option value="${escapeHtml(option)}" ${String(value) === String(option) ? 'selected' : ''}>${escapeHtml(settingOptionLabel(option, field))}</option>`
    ).join('')}</select>`;
  } else if (field.type === 'textarea') {
    control = `<textarea id="${id}" name="${escapeHtml(field.key)}" data-setting="${field.key}"${derivedFrom}${readOnly} placeholder="${escapeHtml(field.placeholder || '')}">${escapeHtml(value)}</textarea>`;
  } else if (field.type === 'range') {
    control = `<div class="range-field"><input id="${id}" name="${escapeHtml(field.key)}" data-setting="${field.key}"${derivedFrom} type="range" value="${escapeHtml(value)}" min="${field.min}" max="${field.max}"><output for="${id}">${escapeHtml(value)}${escapeHtml(field.suffix || '')}</output></div>`;
  } else {
    const type = field.type === 'secret' ? 'password' : field.type;
    const placeholder = field.type === 'secret' && configured
      ? t('Configured — leave blank to keep the current value')
      : (field.placeholder || '');
    const list = field.key === 'OPNSENSE_SHAPER_INTERFACE' ? ' list="opnsenseInterfaceChoices"' : '';
    const datalist = field.key === 'OPNSENSE_SHAPER_INTERFACE'
      ? '<datalist id="opnsenseInterfaceChoices"></datalist><small id="opnsenseInterfaceStatus"></small>'
      : '';
    control = `<input id="${id}" name="${escapeHtml(field.key)}" data-setting="${field.key}"${derivedFrom}${readOnly} type="${type}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}"${list} ${field.min != null ? `min="${field.min}"` : ''} ${field.max != null ? `max="${field.max}"` : ''}>${datalist}`;
  }
  return `<div class="setting-field${full}"${provider}${visibility}><label for="${id}">${escapeHtml(t(field.label))}</label>${control}${networkChoices}${help}</div>`;
}

function isNotificationTemplateField(group, field) {
  return group.id === 'notifications' &&
    field.type === 'textarea' &&
    field.key.startsWith('NOTIFICATION_') &&
    field.key.includes('TEMPLATE');
}

function notificationAlertTypeGroup(group, field) {
  if (group.id !== 'notifications') return null;
  return NOTIFICATION_ALERT_TYPE_GROUPS.find(item => item.keys.includes(field.key)) || null;
}

function settingFieldValue(field) {
  return state.settings.values[field.key] ?? field.defaultValue ?? '';
}

function notificationTemplateKind(key) {
  if (String(key).includes('ADMIN_APPROVAL')) return 'adminApproval';
  if (String(key).includes('SYSTEM')) return 'system';
  return 'syslog';
}

function notificationTemplateField(key) {
  return state.settings?.schema
    ?.find(group => group.id === 'notifications')
    ?.fields
    ?.find(field => field.key === key) || null;
}

function templatePlaceholderHelp(field) {
  return `<div class="template-placeholder-help">
    <button class="template-placeholder-link" type="button" data-template-placeholder-help="${escapeHtml(field.key)}">
      ${escapeHtml(t('Available placeholders'))}
    </button>
    <small>${escapeHtml(t('Click to see how each value is used in this template.'))}</small>
  </div>`;
}

function templatePlaceholderExample(kind) {
  const examples = {
    syslog: {
      template: '{appName}: {message} ({storageUsage}%)',
      result: 'G-Hotspot: Syslog storage is 85% full. (85%)'
    },
    system: {
      template: '{appName}: {message}',
      result: 'G-Hotspot: Administrator GkhnG signed in from 203.0.113.10.'
    },
    adminApproval: {
      template: '{appName}: {decisionText}',
      result: 'G-Hotspot: Your request was approved.'
    }
  };
  return examples[kind] || examples.syslog;
}

function closeTemplatePlaceholderModal() {
  $('#templatePlaceholderModal').classList.add('hidden');
}

function openTemplatePlaceholderModal(templateKey) {
  const field = notificationTemplateField(templateKey);
  const kind = notificationTemplateKind(templateKey);
  const placeholders = NOTIFICATION_TEMPLATE_PLACEHOLDERS[kind] || [];
  const example = templatePlaceholderExample(kind);
  setTranslatedText('#templatePlaceholderEyebrow', 'Available placeholders');
  setTranslatedText('#templatePlaceholderTitle', field?.label || 'Available placeholders');
  setTranslatedText(
    '#templatePlaceholderIntro',
    'Use a placeholder exactly as shown, including braces. When the notification is sent, it is replaced with the matching live value.'
  );
  setSafeHtml('#templatePlaceholderExample', `
    <div>
      <span>${escapeHtml(t('Template'))}</span>
      <code>${escapeHtml(example.template)}</code>
    </div>
    <div>
      <span>${escapeHtml(t('Sent value'))}</span>
      <strong>${escapeHtml(t(example.result))}</strong>
    </div>
  `);
  setSafeHtml('#templatePlaceholderList', `
    <div class="template-placeholder-row template-placeholder-row--head">
      <span>${escapeHtml(t('Placeholder'))}</span>
      <span>${escapeHtml(t('Meaning'))}</span>
      <span>${escapeHtml(t('Sample value'))}</span>
    </div>
    ${placeholders.map(([name, description, sample]) => `
      <div class="template-placeholder-row">
        <code>{${escapeHtml(name)}}</code>
        <span>${escapeHtml(t(description))}</span>
        <strong>${escapeHtml(t(sample))}</strong>
      </div>
    `).join('')}
  `);
  $('#templatePlaceholderModal').classList.remove('hidden');
}

function renderNotificationTemplatePicker(templateFields) {
  if (!templateFields.length) return '';
  const selectedField = templateFields.find(field => field.key === state.notificationTemplateKey) || templateFields[0];
  state.notificationTemplateKey = selectedField.key;
  const selectedId = `setting_${selectedField.key}`;
  const selectedValue = settingFieldValue(selectedField);
  const help = templatePlaceholderHelp(selectedField);
  const hiddenTemplates = templateFields
    .filter(field => field.key !== selectedField.key)
    .map(field => `<textarea id="setting_hidden_${field.key}" name="${escapeHtml(field.key)}" hidden data-setting="${field.key}">${escapeHtml(settingFieldValue(field))}</textarea>`)
    .join('');
  return `<div class="settings-section"><h3>${escapeHtml(t('Templates'))}</h3></div>
    <div class="setting-field notification-template-picker full">
      <label for="notificationTemplateSelect">${escapeHtml(t('Templates'))}</label>
      <select id="notificationTemplateSelect" name="notificationTemplateSelect" data-notification-template-select>
        ${templateFields.map(field =>
          `<option value="${escapeHtml(field.key)}" ${field.key === selectedField.key ? 'selected' : ''}>${escapeHtml(t(field.label))}</option>`
        ).join('')}
      </select>
    </div>
    ${hiddenTemplates}
    <div class="setting-field notification-template-editor full">
      <label for="${selectedId}">${escapeHtml(t(selectedField.label))}</label>
      <textarea id="${selectedId}" name="${escapeHtml(selectedField.key)}" data-setting="${selectedField.key}" placeholder="${escapeHtml(selectedField.placeholder || '')}">${escapeHtml(selectedValue)}</textarea>
      ${help}
    </div>`;
}

function renderNotificationAlertTypeGroup(alertGroup, group) {
  const fields = alertGroup.keys
    .map(key => group.fields.find(field => field.key === key))
    .filter(Boolean);

  return `
    <div
      class="settings-option-group"
      data-visible-when="${escapeHtml(alertGroup.visibleWhen)}"
      ${alertGroup.visibleWhenAll ? `data-visible-when-all="${escapeHtml(alertGroup.visibleWhenAll.join(','))}"` : ''}
    >
      <h4>${escapeHtml(t(alertGroup.label))}</h4>

      ${fields.map(field => settingInput(
        field,
        state.settings.values[field.key] ?? field.defaultValue ?? '',
        state.settings.configured[field.key],
        { minimalBoolean: true }
      )).join('')}
    </div>
  `;
}

function settingDurationInput(valueField, unitField, value, unitValue) {
  const valueId = `setting_${valueField.key}`;
  const unitId = `setting_${unitField.key}`;
  const help = unitField.warning || valueField.warning
    ? `<small>${escapeHtml(t(unitField.warning || valueField.warning))}</small>`
    : '';
  const pair = valueField.durationPair;
  const unitOptions = unitField.options.map(option =>
    `<option value="${escapeHtml(option)}" ${String(unitValue) === String(option) ? 'selected' : ''}>${escapeHtml(settingOptionLabel(option, unitField))}</option>`
  ).join('');
  return `<div class="setting-field duration-field" data-duration-field="${escapeHtml(pair)}">
    <label for="${valueId}">${escapeHtml(t(valueField.label))}</label>
    <div class="duration-control">
      <input id="${valueId}" name="${escapeHtml(valueField.key)}" class="duration-value-control" data-setting="${valueField.key}" data-duration-pair="${escapeHtml(pair)}" data-duration-role="value" type="number" value="${escapeHtml(value)}" ${valueField.min != null ? `min="${valueField.min}"` : ''} ${valueField.max != null ? `max="${valueField.max}"` : ''}>
      <select id="${unitId}" name="${escapeHtml(unitField.key)}" data-setting="${unitField.key}" data-duration-pair="${escapeHtml(pair)}" data-duration-role="unit" aria-label="${escapeHtml(t(unitField.label))}">${unitOptions}</select>
    </div>
    ${help}
  </div>`;
}

function renderSettingFields(group) {
  const notificationTemplateFields = group.fields.filter(field => isNotificationTemplateField(group, field));
  const parts = [];
  let notificationTemplatesRendered = false;
  const notificationAlertTypeGroupsRendered = new Set();
  for (const field of group.fields) {
    if (field.durationRole === 'unit') continue;
    const alertTypeGroup = notificationAlertTypeGroup(group, field);
    if (isNotificationTemplateField(group, field)) {
      if (notificationTemplatesRendered) continue;
      notificationTemplatesRendered = true;
      parts.push(renderNotificationTemplatePicker(notificationTemplateFields));
      continue;
    }
    const durationUnit = field.durationRole === 'value'
      ? group.fields.find(item => item.durationPair === field.durationPair && item.durationRole === 'unit')
      : null;
    const sectionVisibility = alertTypeGroup
      ? ' data-visible-when-any="NOTIFICATION_EMAIL_ENABLED,NOTIFICATION_SMS_ENABLED,NOTIFICATION_TELEGRAM_ENABLED"'
      : settingVisibilityAttributes(field);
    const section = field.section
      ? `<div class="settings-section"${sectionVisibility}><h3>${escapeHtml(t(field.section))}</h3></div>`
      : '';
    if (alertTypeGroup) {
    if (notificationAlertTypeGroupsRendered.size === 0) {
      const groupsHtml = NOTIFICATION_ALERT_TYPE_GROUPS
        .map(item => renderNotificationAlertTypeGroup(item, group))
        .join('');

      parts.push(`
        ${section}
        <div class="settings-option-group-wrapper">
          ${groupsHtml}
        </div>
      `);

      NOTIFICATION_ALERT_TYPE_GROUPS.forEach(item => {
        notificationAlertTypeGroupsRendered.add(item.label);
      });
    }

    continue;
  }
    if (durationUnit) {
      parts.push(`${section}${settingDurationInput(
        field,
        durationUnit,
        state.settings.values[field.key] ?? field.defaultValue ?? '',
        state.settings.values[durationUnit.key] ?? durationUnit.defaultValue ?? ''
      )}`);
      continue;
    }
    parts.push(`${section}${settingInput(
      field,
      state.settings.values[field.key] ?? field.defaultValue ?? '',
      state.settings.configured[field.key]
    )}`);
  }
  return parts.join('');
}

function collectSettingValuesFromDom() {
  const values = {};
  $$('[data-setting]').forEach(input => {
    values[input.dataset.setting] = input.type === 'checkbox' ? input.checked : input.value;
  });
  return values;
}

function syncSettingValuesFromDom() {
  if (!state.settings?.values) return;
  Object.assign(state.settings.values, collectSettingValuesFromDom());
}

function settingFieldByKey(key) {
  return state.settings?.schema
    ?.flatMap(group => group.fields)
    ?.find(field => field.key === key) || null;
}

function settingToggleValue(key) {
  const field = settingFieldByKey(key);
  if (field?.visibleWhen && !settingToggleValue(field.visibleWhen)) return false;
  if (field?.visibleWhenAll?.length && !field.visibleWhenAll.every(item => settingToggleValue(item))) return false;
  if (field?.visibleWhenAny?.length && !field.visibleWhenAny.some(item => settingToggleValue(item))) return false;
  const input = $(`[data-setting="${key}"]`);
  if (!input) return String(state.settings?.values?.[key] ?? '') === 'true';
  if (input.type === 'checkbox') return input.checked;
  return Boolean(input.value);
}

function settingCurrentValue(key) {
  const input = $(`[data-setting="${key}"]`);
  if (!input) return String(state.settings?.values?.[key] ?? '');
  if (input.type === 'checkbox') return String(input.checked);
  return String(input.value ?? '');
}

function settingValueMatches(spec) {
  const [key, ...expectedParts] = String(spec || '').split('=');
  if (!key || !expectedParts.length) return true;
  return settingCurrentValue(key) === expectedParts.join('=');
}

function updateConditionalSettings() {
  $$('[data-visible-when], [data-visible-when-any], [data-visible-when-all], [data-visible-when-value]').forEach(element => {
    let visible = true;
    if (element.dataset.visibleWhen) {
      visible = visible && settingToggleValue(element.dataset.visibleWhen);
    }
    if (element.dataset.visibleWhenValue) {
      visible = visible && settingValueMatches(element.dataset.visibleWhenValue);
    }
    if (element.dataset.visibleWhenAll) {
      const keys = element.dataset.visibleWhenAll.split(',').map(item => item.trim()).filter(Boolean);
      visible = visible && keys.every(key => settingToggleValue(key));
    }
    if (element.dataset.visibleWhenAny) {
      const keys = element.dataset.visibleWhenAny.split(',').map(item => item.trim()).filter(Boolean);
      visible = visible && keys.some(key => settingToggleValue(key));
    }
    element.classList.toggle('hidden', !visible);
  });
}

function formatAssetSize(bytes) {
  if (!bytes) return '';
  return bytes < 1024 * 1024
    ? `${Math.ceil(bytes / 1024)} KB`
    : `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function appearanceAssetMaxSize(kind) {
  return Number(state.settings?.appearanceAssets?.[kind]?.maxSize) ||
    APPEARANCE_ASSET_FALLBACK_LIMITS[kind] ||
    0;
}

function appearanceUploadId() {
  if (window.crypto?.randomUUID) return window.crypto.randomUUID();
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

async function uploadAppearanceAsset(kind, file) {
  const endpoint = `/api/admin/appearance/assets/${kind}`;
  if (file.size <= APPEARANCE_UPLOAD_CHUNK_BYTES) {
    return api(endpoint, {
      method: 'PUT',
      body: await file.arrayBuffer(),
      headers: { 'content-type': file.type || 'application/octet-stream' }
    });
  }

  const uploadId = appearanceUploadId();
  const total = Math.ceil(file.size / APPEARANCE_UPLOAD_CHUNK_BYTES);
  let result = null;
  for (let index = 0; index < total; index += 1) {
    const start = index * APPEARANCE_UPLOAD_CHUNK_BYTES;
    const chunk = file.slice(start, Math.min(file.size, start + APPEARANCE_UPLOAD_CHUNK_BYTES));
    result = await api(endpoint, {
      method: 'PUT',
      body: await chunk.arrayBuffer(),
      headers: {
        'content-type': 'application/octet-stream',
        'x-gh-upload-id': uploadId,
        'x-gh-upload-index': String(index),
        'x-gh-upload-total': String(total),
        'x-gh-upload-size': String(file.size)
      }
    });
  }
  return result;
}

function renderAppearanceAssets() {
  const assets = state.settings.appearanceAssets || {};
  const definitions = [
    ['logo', 'Portal logo', 'Shown inside the brand mark. PNG, JPEG or WebP; maximum {maxSize}.'],
    ['card-background', 'Card background image', 'Independent image behind the verification card content; maximum {maxSize}.'],
    ['body-background', 'Body background image', 'Independent full-screen background image; maximum {maxSize}.']
  ];
  return `<section class="appearance-assets">
    <div class="settings-section"><h3>${escapeHtml(t('Verification screen images'))}</h3></div>
    <div class="appearance-assets-grid">${definitions.map(([kind, label, help]) => {
      const asset = assets[kind] || {};
      const maxSize = formatBytes(appearanceAssetMaxSize(kind));
      return `<article class="appearance-asset-card">
        <div class="appearance-preview ${kind === 'logo' ? 'logo-preview' : ''}">
          ${asset.url
            ? `<img src="${escapeHtml(asset.url)}" alt="${escapeHtml(t(label))}">`
            : `<span>${escapeHtml(t('No image uploaded'))}</span>`}
        </div>
        <div class="appearance-asset-copy">
          <strong>${escapeHtml(t(label))}</strong>
          <p>${escapeHtml(t(help, { maxSize }))}</p>
          ${asset.configured ? `<small>${escapeHtml(formatAssetSize(asset.size))}</small>` : ''}
        </div>
        <div class="appearance-asset-actions">
          <label class="secondary-button file-button" for="appearance_${kind}">
            ${escapeHtml(t(asset.configured ? 'Replace image' : 'Upload image'))}
          </label>
          <input id="appearance_${kind}" name="appearance_${kind}" class="appearance-file-input" data-appearance-upload="${kind}" type="file" accept="image/png,image/jpeg,image/webp">
          ${asset.configured
            ? `<button class="action-button danger appearance-delete" type="button" data-appearance-delete="${kind}">${escapeHtml(t('Remove'))}</button>`
            : ''}
        </div>
      </article>`;
    }).join('')}</div>
  </section>`;
}

function renderPortalPreview() {
  const logo = state.settings.appearanceAssets?.logo || {};
  const networkLabel = portalPreviewOptionalDisplayValue('PORTAL_NETWORK_LABEL_TEXT', DEFAULT_NETWORK_LABEL_TEXT);
  const verificationPrompt = portalPreviewOptionalDisplayValue(
    'PORTAL_VERIFICATION_PROMPT_TEXT',
    DEFAULT_VERIFICATION_PROMPT_TEXT
  );
  const portalTitle = portalPreviewTitleValue();
  const termsText = portalPreviewDisplayValue('PORTAL_TERMS_TEXT', DEFAULT_TERMS_TEXT);
  return `<section class="portal-preview-section">
    <div class="settings-section"><h3>${escapeHtml(t('Verification screen preview'))}</h3></div>
    <div id="portalPreviewStage" class="portal-preview-stage">
      <div id="portalPreviewCard" class="portal-preview-card">
        <div class="portal-preview-brand-row">
          <div class="portal-preview-brand">
            <div class="portal-preview-brand-mark">
              ${logo.url
                ? `<img src="${escapeHtml(logo.url)}" alt="${escapeHtml(t('Portal logo'))}">`
                : '<span>G</span>'}
            </div>
            <div>
              <p id="portalPreviewNetworkLabel" class="${networkLabel ? '' : 'hidden'}">${escapeHtml(networkLabel)}</p>
              <h1 id="portalPreviewAppName">${escapeHtml(portalTitle)}</h1>
            </div>
          </div>
          <div id="portalPreviewLanguage" class="portal-preview-language">EN</div>
        </div>
        <p id="portalPreviewLead" class="portal-preview-lead ${verificationPrompt ? '' : 'hidden'}">${escapeHtml(verificationPrompt)}</p>
        <div class="portal-preview-client">${escapeHtml(t('Connected device: {ip}', { ip: '192.168.1.24' }))}</div>
        <div class="portal-preview-tabs">
          <button class="active" type="button">${escapeHtml(t('Voucher'))}</button>
          <button type="button">${escapeHtml(t('Admin approval'))}</button>
          <button type="button">${escapeHtml(t('Email'))}</button>
          <button type="button">WhatsApp</button>
          <button type="button">Telegram</button>
          <button type="button">SMS</button>
        </div>
        <div class="portal-preview-form">
          <label>${escapeHtml(t('Voucher code'))}</label>
          <div>${escapeHtml('ABCD-EFGH-JKLM')}</div>
          <button type="button">${escapeHtml(t('Open internet access'))}</button>
        </div>
        <div id="portalPreviewTerms" class="portal-preview-terms">${portalPreviewMarkdownToSafeHtml(termsText)}</div>
      </div>
    </div>
  </section>`;
}

function renderSyslogStatus(data) {
  const summary = data.summary || {};
  const lastExport = summary.lastExport || null;
  const syslog = data.syslogRuntime || {};
  const autoExport = data.autoExportRuntime || {};
  const health = data.healthRuntime || {};
  const storage = health.storage || {};
  const ntp = health.ntp || {};
  const timestampMode = data.timestampMode || (data.kamusmTimestampEnabled ? 'kamusm' : 'disabled');
  const timestampProvider = {
    kamusm: 'KamuSM',
    rfc3161: 'RFC3161 TSA',
    'api-key': t('API key')
  }[timestampMode] || t('Disabled');
  const timestampLabel = {
    disabled: t('Not configured'),
    created: t('Timestamp created'),
    failed: t('Timestamp failed'),
    'missing-token': t('Timestamp token missing')
  };
  $('#syslogStatusText').textContent = data.enabled
    ? t('Enabled for {networks}', { networks: data.networks || 'any' })
    : t('Disabled');
  $('#syslogStats').innerHTML = [
    [t('Records'), Number(summary.count || 0).toLocaleString(i18n.locale)],
    [t('System events'), Number(summary.eventCount || 0).toLocaleString(i18n.locale)],
    [t('Last syslog alert'), summary.lastAlert
      ? `${t(summary.lastAlert.eventType)} · ${formatDate(summary.lastAlert.createdAt)}`
      : '—'],
    [t('Last record'), summary.lastCreatedAt ? formatDate(summary.lastCreatedAt) : '—'],
    [t('Last hash'), shortHash(summary.lastHash)],
    [t('Timestamp provider'), timestampProvider],
    [t('Timestamp status'), data.timestampConfigured
      ? (timestampLabel[lastExport?.timestampStatus] || t('Waiting'))
      : t('Disabled')],
    [t('Timestamp credentials'), timestampMode === 'kamusm'
      ? (data.kamusmUserConfigured ? t('Configured') : '—')
      : (timestampMode === 'api-key' ? (data.timestampApiKeyConfigured ? t('Configured') : '—') : '—')],
    [t('Last timestamped log'), lastExport?.filePath ? lastExport.filePath.split(/[\\/]/u).pop() : '—'],
    [t('Last timestamp token'), lastExport?.timestampTokenPath ? lastExport.timestampTokenPath.split(/[\\/]/u).pop() : '—'],
    [t('Timestamp error'), lastExport?.timestampError || '—'],
    [t('Traffic'), `↓ ${formatBytes(summary.downloadBytes)} · ↑ ${formatBytes(summary.uploadBytes)}`],
    [t('Retention'), `${data.retentionDays} ${t('days')}`],
    [t('Storage usage'), storage.available
      ? `${storage.usagePercent}% (${t('warn at {percent}%', { percent: storage.alertPercent || data.storageAlertPercent || 85 })})`
      : (storage.error || '—')],
    [t('Portal session gate'), storage.blocking
      ? t('Blocked by syslog storage')
      : t('Accepting new sessions')],
    [t('Export time zone'), data.timeZone || 'UTC'],
    [t('Time guard'), health.enabled
      ? (health.lastCheckAt ? `${t('Checked')} ${relativeTime(health.lastCheckAt)}` : t('Enabled'))
      : t('Disabled')],
    [t('Clock drift'), `${Number(health.lastClockDriftMs || 0).toLocaleString(i18n.locale)} ms`],
    [t('NTP synchronization'), ntp.synced === true
      ? t('Synchronized')
      : ntp.synced === false
        ? t('Lost')
        : (ntp.error || '—')],
    [t('Firewall syslog'), data.syslogEnabled
      ? (syslog.listening
        ? t('Listening on udp://{host}:{port}', { host: syslog.host || data.syslogHost, port: syslog.port || data.syslogPort })
        : t('Enabled but not listening'))
      : t('Disabled')],
    [t('Syslog received'), Number(syslog.received || 0).toLocaleString(i18n.locale)],
    [t('Syslog stored'), Number(syslog.stored || 0).toLocaleString(i18n.locale)],
    [t('Syslog ignored'), Number(syslog.ignored || 0).toLocaleString(i18n.locale)],
    [t('Syslog error'), syslog.lastError || '—'],
    [t('Last syslog sample'), syslog.lastMessage || '—'],
    [t('Automatic export'), autoExport.enabled
      ? (autoExport.waitingForGateway
        ? t('Waiting for OPNsense communication')
        : settingOptionLabel(autoExport.schedule || data.autoExportInterval || 'daily'))
      : t('Disabled')],
    [t('Next automatic export'), autoExport.nextRunAt ? formatDate(autoExport.nextRunAt) : '—'],
    [t('Automatic export error'), autoExport.lastError || '—'],
    [t('Export directory'), data.exportDirectory || '—'],
    [t('Last export'), lastExport ? `${formatDate(lastExport.createdAt)} · ${shortHash(lastExport.exportHash)}` : '—'],
    [t('Last export window'), lastExport?.periodStartAt && lastExport?.periodEndAt
      ? `${lastExport.exportReason || 'manual'} · ${formatDateRange(lastExport.periodStartAt, lastExport.periodEndAt)}`
      : '—']
  ].map(([label, value]) => `<div class="syslog-stat"><span>${escapeHtml(label)}</span><strong title="${escapeHtml(value)}">${escapeHtml(value)}</strong></div>`).join('');
}

async function loadSyslogStatus() {
  const panel = $('#syslogPanel');
  if (!panel || panel.classList.contains('hidden')) return;
  const data = await api('/api/admin/syslog/status');
  renderSyslogStatus(data);
}

function appendSettingNetwork(key, network) {
  const input = $(`[data-setting="${key}"]`);
  if (!input) return;
  if (key === 'OPNSENSE_ZONE_MAP') {
    const zoneId = $('[data-setting="OPNSENSE_ZONE_ID"]')?.value || state.settings?.values?.OPNSENSE_ZONE_ID || '0';
    const lines = input.value.split(/\n/u).map(item => item.trim()).filter(Boolean);
    if (!lines.some(line => line.split('=')[0]?.trim() === network)) {
      lines.push(`${network}=${zoneId}`);
    }
    input.value = lines.join('\n');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return;
  }
  const current = input.value
    .split(',')
    .map(item => item.trim())
    .filter(Boolean)
    .filter(item => item.toLowerCase() !== 'any');
  if (!current.includes(network)) current.push(network);
  input.value = current.join(', ');
  input.dispatchEvent(new Event('input', { bubbles: true }));
}

function renderGatewayNetworkChoices(payload = {}) {
  const targets = $$('[data-opnsense-network-choices]');
  if (!targets.length) return;
  const choices = payload.choices || [];
  for (const target of targets) {
    const key = target.dataset.opnsenseNetworkChoices;
    if (!choices.length) {
      target.innerHTML = `<span>${escapeHtml(payload.error ? t(payload.error) : t('No OPNsense networks discovered.'))}</span>`;
      continue;
    }
    target.innerHTML = `<span>${escapeHtml(t('OPNsense networks'))}</span>${choices.map(choice =>
      `<button class="syslog-network-choice" type="button" data-setting-network="${escapeHtml(key)}" data-network="${escapeHtml(choice.network)}" title="${escapeHtml(choice.label)}">${escapeHtml(choice.network)}</button>`
    ).join('')}`;
  }
}

async function loadGatewayNetworks() {
  if (!$$('[data-opnsense-network-choices]').length) return;
  if (state.gatewayNetworks) {
    renderGatewayNetworkChoices(state.gatewayNetworks);
    return;
  }
  renderGatewayNetworkChoices({
    choices: [],
    error: 'Loading OPNsense networks…'
  });
  state.gatewayNetworks = await api('/api/admin/gateway/networks');
  renderGatewayNetworkChoices(state.gatewayNetworks);
}

function portalPreviewValue(key, fallback = '') {
  const input = $(`[data-setting="${key}"]`);
  const value = input
    ? (input.type === 'checkbox' ? input.checked : input.value)
    : state.settings?.values?.[key];
  return value === undefined || value === null || value === '' ? fallback : value;
}

function portalPreviewDisplayValue(key, fallback = '') {
  const value = portalPreviewValue(key, fallback);
  return value === fallback ? t(fallback) : value;
}

function portalPreviewRawValue(key) {
  const input = $(`[data-setting="${key}"]`);
  return input
    ? (input.type === 'checkbox' ? input.checked : input.value)
    : state.settings?.values?.[key];
}

function portalPreviewOptionalDisplayValue(key, fallback = '') {
  const value = portalPreviewRawValue(key);
  if (value === undefined || value === null) return t(fallback);
  const text = String(value).trim();
  return text === fallback ? t(fallback) : text;
}

function portalPreviewTitleValue() {
  return String(portalPreviewRawValue('PORTAL_TITLE_TEXT') || '').trim() ||
    portalPreviewValue('APP_NAME', state.appName || 'G-Hotspot');
}

function setOptionalPreviewText(selector, text) {
  const element = $(selector);
  if (!element) return;
  element.textContent = text;
  element.classList.toggle('hidden', !text);
}

function portalPreviewColor(key, fallback) {
  const value = String(portalPreviewValue(key, fallback)).trim();
  return /^#[0-9a-f]{6}$/iu.test(value) ? value : fallback;
}

function portalPreviewNumber(key, fallback, min = 0, max = 100) {
  const value = Number(portalPreviewValue(key, fallback));
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, value));
}

function portalPreviewBoolean(key, fallback = false) {
  const value = portalPreviewRawValue(key);
  if (typeof value === 'boolean') return value;
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function portalPreviewRgba(colorKey, opacityKey, colorFallback, opacityFallback) {
  const hex = portalPreviewColor(colorKey, colorFallback).slice(1);
  const opacity = portalPreviewNumber(opacityKey, opacityFallback, 0, 100) / 100;
  const red = Number.parseInt(hex.slice(0, 2), 16);
  const green = Number.parseInt(hex.slice(2, 4), 16);
  const blue = Number.parseInt(hex.slice(4, 6), 16);
  return `rgba(${red},${green},${blue},${opacity})`;
}

function portalPreviewAsset(kind) {
  const url = state.settings?.appearanceAssets?.[kind]?.url || '';
  return url ? `url("${String(url).replaceAll('"', '%22')}")` : 'none';
}

function updatePortalPreview() {
  const stage = $('#portalPreviewStage');
  const card = $('#portalPreviewCard');
  if (!stage || !card) return;

  stage.style.setProperty('--preview-primary', portalPreviewColor('PORTAL_PRIMARY_COLOR', '#5340CC'));
  stage.style.setProperty('--preview-primary-hover', portalPreviewColor('PORTAL_PRIMARY_HOVER_COLOR', '#4530B0'));
  stage.style.setProperty('--preview-heading', portalPreviewColor('PORTAL_HEADING_COLOR', '#1A1523'));
  stage.style.setProperty('--preview-text', portalPreviewColor('PORTAL_TEXT_COLOR', '#374151'));
  stage.style.setProperty('--preview-muted', portalPreviewColor('PORTAL_MUTED_COLOR', '#6B7280'));
  stage.style.setProperty('--preview-button-text', portalPreviewColor('PORTAL_BUTTON_TEXT_COLOR', '#FFFFFF'));
  stage.style.setProperty('--preview-input-background', portalPreviewColor('PORTAL_INPUT_BACKGROUND_COLOR', '#FAFAFA'));
  stage.style.setProperty('--preview-input-border', portalPreviewColor('PORTAL_INPUT_BORDER_COLOR', '#E5E1F8'));
  stage.style.setProperty('--preview-input-text', portalPreviewColor('PORTAL_INPUT_TEXT_COLOR', '#1A1523'));
  stage.style.setProperty('--preview-body-color', portalPreviewColor('PORTAL_BODY_BACKGROUND_COLOR', '#F0EEF9'));
  stage.style.setProperty('--preview-body-color-opacity', String(portalPreviewNumber('PORTAL_BODY_BACKGROUND_OPACITY', 100) / 100));
  stage.style.setProperty('--preview-body-image', portalPreviewAsset('body-background'));
  stage.style.setProperty('--preview-body-image-opacity', String(portalPreviewNumber('PORTAL_BODY_IMAGE_OPACITY', 100) / 100));
  stage.style.setProperty('--preview-body-image-blur', `${portalPreviewNumber('PORTAL_BODY_IMAGE_BLUR', 0, 0, 40)}px`);
  stage.style.setProperty(
    '--preview-body-image-animation',
    portalPreviewBoolean('PORTAL_BODY_IMAGE_ANIMATION_ENABLED')
      ? 'portal-preview-backdrop-cinematic 24s ease-in-out infinite alternate'
      : 'none'
  );
  stage.style.setProperty('--preview-card-color', portalPreviewColor('PORTAL_CARD_BACKGROUND_COLOR', '#FFFFFF'));
  stage.style.setProperty('--preview-card-color-opacity', String(portalPreviewNumber('PORTAL_CARD_BACKGROUND_OPACITY', 100) / 100));
  stage.style.setProperty('--preview-card-border', [
    `${portalPreviewNumber('PORTAL_CARD_BORDER_WIDTH', 1, 0, 20)}px`,
    'solid',
    portalPreviewRgba('PORTAL_CARD_BORDER_COLOR', 'PORTAL_CARD_BORDER_OPACITY', '#000000', 7)
  ].join(' '));
  stage.style.setProperty('--preview-card-radius', `${portalPreviewNumber('PORTAL_CARD_BORDER_RADIUS', 18, 0, 80)}px`);
  stage.style.setProperty('--preview-card-shadow', [
    `${portalPreviewNumber('PORTAL_CARD_SHADOW_OFFSET_X', 0, -80, 80)}px`,
    `${portalPreviewNumber('PORTAL_CARD_SHADOW_OFFSET_Y', 4, -80, 80)}px`,
    `${portalPreviewNumber('PORTAL_CARD_SHADOW_BLUR', 24, 0, 160)}px`,
    `${portalPreviewNumber('PORTAL_CARD_SHADOW_SPREAD', 0, -80, 80)}px`,
    portalPreviewRgba('PORTAL_CARD_SHADOW_COLOR', 'PORTAL_CARD_SHADOW_OPACITY', '#6366F1', 10)
  ].join(' '));
  stage.style.setProperty('--preview-card-image', portalPreviewAsset('card-background'));
  stage.style.setProperty('--preview-card-image-opacity', String(portalPreviewNumber('PORTAL_CARD_IMAGE_OPACITY', 100) / 100));
  stage.style.setProperty('--preview-card-image-blur', `${portalPreviewNumber('PORTAL_CARD_IMAGE_BLUR', 0, 0, 40)}px`);
  stage.style.setProperty('--preview-card-backdrop-blur', `${portalPreviewNumber('PORTAL_CARD_BACKDROP_BLUR', 0, 0, 40)}px`);

  setPlainText('#portalPreviewAppName', portalPreviewTitleValue());
  setOptionalPreviewText(
    '#portalPreviewNetworkLabel',
    portalPreviewOptionalDisplayValue('PORTAL_NETWORK_LABEL_TEXT', DEFAULT_NETWORK_LABEL_TEXT)
  );
  setOptionalPreviewText(
    '#portalPreviewLead',
    portalPreviewOptionalDisplayValue('PORTAL_VERIFICATION_PROMPT_TEXT', DEFAULT_VERIFICATION_PROMPT_TEXT)
  );
  setPlainText('#portalPreviewLanguage', String(portalPreviewValue('DEFAULT_LANGUAGE', 'en')).slice(0, 2).toUpperCase());
  setSafeHtml(
    '#portalPreviewTerms',
    portalPreviewMarkdownToSafeHtml(portalPreviewDisplayValue('PORTAL_TERMS_TEXT', DEFAULT_TERMS_TEXT))
  );
}

function bindPortalPreviewInputs() {
  const keys = [
    'APP_NAME',
    'DEFAULT_LANGUAGE',
    'PORTAL_TITLE_TEXT',
    'PORTAL_NETWORK_LABEL_TEXT',
    'PORTAL_VERIFICATION_PROMPT_TEXT',
    'PORTAL_TERMS_TEXT',
    'PORTAL_PRIMARY_COLOR',
    'PORTAL_PRIMARY_HOVER_COLOR',
    'PORTAL_HEADING_COLOR',
    'PORTAL_TEXT_COLOR',
    'PORTAL_MUTED_COLOR',
    'PORTAL_BUTTON_TEXT_COLOR',
    'PORTAL_INPUT_BACKGROUND_COLOR',
    'PORTAL_INPUT_BORDER_COLOR',
    'PORTAL_INPUT_TEXT_COLOR',
    'PORTAL_BODY_BACKGROUND_COLOR',
    'PORTAL_BODY_BACKGROUND_OPACITY',
    'PORTAL_BODY_IMAGE_OPACITY',
    'PORTAL_BODY_IMAGE_BLUR',
    'PORTAL_BODY_IMAGE_ANIMATION_ENABLED',
    'PORTAL_CARD_BACKGROUND_COLOR',
    'PORTAL_CARD_BACKGROUND_OPACITY',
    'PORTAL_CARD_BORDER_WIDTH',
    'PORTAL_CARD_BORDER_COLOR',
    'PORTAL_CARD_BORDER_OPACITY',
    'PORTAL_CARD_BORDER_RADIUS',
    'PORTAL_CARD_SHADOW_OFFSET_X',
    'PORTAL_CARD_SHADOW_OFFSET_Y',
    'PORTAL_CARD_SHADOW_BLUR',
    'PORTAL_CARD_SHADOW_SPREAD',
    'PORTAL_CARD_SHADOW_COLOR',
    'PORTAL_CARD_SHADOW_OPACITY',
    'PORTAL_CARD_IMAGE_OPACITY',
    'PORTAL_CARD_IMAGE_BLUR',
    'PORTAL_CARD_BACKDROP_BLUR'
  ];
  keys.forEach(key => {
    const input = $(`[data-setting="${key}"]`);
    input?.addEventListener('input', updatePortalPreview);
    input?.addEventListener('change', updatePortalPreview);
  });
  updatePortalPreview();
}

function updateProviderFields() {
  const provider = $('[data-setting="SMS_PROVIDER"]')?.value || 'netgsm';
  $$('[data-provider]').forEach(element => {
    element.classList.toggle('hidden', element.dataset.provider !== provider);
  });
}

function updateDurationFields() {
  for (const select of $$('select[data-duration-role="unit"]')) {
    const pair = select.dataset.durationPair;
    const valueField = $(`[data-duration-pair="${pair}"][data-duration-role="value"]`);
    const isUnlimited = select.value === 'unlimited';
    valueField?.classList.toggle('hidden', isUnlimited);
    select.closest('.duration-control')?.classList.toggle('duration-control--unlimited', isUnlimited);
  }
}

function syncDerivedSettings() {
  $$('[data-derived-from]').forEach(input => {
    const source = $(`[data-setting="${input.dataset.derivedFrom}"]`);
    input.value = source?.value || '';
  });
}

function bindDerivedSettings() {
  $$('[data-derived-from]').forEach(input => {
    const source = $(`[data-setting="${input.dataset.derivedFrom}"]`);
    const sync = () => {
      input.value = source?.value || '';
    };
    source?.addEventListener('input', sync);
    source?.addEventListener('change', sync);
  });
  syncDerivedSettings();
}

function renderGatewayInterfaceChoices(payload = {}) {
  const datalist = $('#opnsenseInterfaceChoices');
  const status = $('#opnsenseInterfaceStatus');
  if (!datalist || !status) return;
  const interfaces = payload.interfaces || [];
  datalist.innerHTML = interfaces.map(item => {
    const label = item.label && item.label !== item.name ? `${item.label} (${item.name})` : item.name;
    return `<option value="${escapeHtml(item.name)}" label="${escapeHtml(label)}"></option>`;
  }).join('');
  status.textContent = payload.error
    ? t(payload.error)
    : (interfaces.length
        ? t('{count} OPNsense interfaces discovered.', { count: interfaces.length })
        : t('No OPNsense interfaces discovered; manual entry is still available.'));
}

async function loadGatewayInterfaces() {
  if (!$('#opnsenseInterfaceChoices')) return;
  if (state.gatewayInterfaces) {
    renderGatewayInterfaceChoices(state.gatewayInterfaces);
    return;
  }
  renderGatewayInterfaceChoices({
    interfaces: [],
    error: 'Loading OPNsense interfaces…'
  });
  state.gatewayInterfaces = await api('/api/admin/gateway/interfaces');
  renderGatewayInterfaceChoices(state.gatewayInterfaces);
}

function storedOpnsenseTemplateValues() {
  try {
    const stored = JSON.parse(localStorage.getItem(OPNSENSE_TEMPLATE_STORAGE_KEY) || '{}');
    return stored && typeof stored === 'object' ? stored : {};
  } catch {
    return {};
  }
}

function saveOpnsenseTemplateValues(values) {
  const { targetUrl, ...storedValues } = values;
  try {
    localStorage.setItem(OPNSENSE_TEMPLATE_STORAGE_KEY, JSON.stringify(storedValues));
  } catch {}
}

function opnsenseTemplateFields() {
  return {
    lang: $('#opnsenseTemplateLang'),
    title: $('#opnsenseTemplateTitle'),
    targetUrl: $('#opnsenseTemplateTargetUrl'),
    refreshSeconds: $('#opnsenseTemplateRefreshSeconds'),
    redirectText: $('#opnsenseTemplateRedirectText'),
    linkText: $('#opnsenseTemplateLinkText'),
    noscriptText: $('#opnsenseTemplateNoscriptText')
  };
}

function opnsenseTemplateValuesFromForm() {
  const fields = opnsenseTemplateFields();
  return {
    lang: fields.lang?.value || '',
    title: fields.title?.value || '',
    targetUrl: fields.targetUrl?.value || '',
    refreshSeconds: fields.refreshSeconds?.value || '0',
    redirectText: fields.redirectText?.value || '',
    linkText: fields.linkText?.value || '',
    noscriptText: fields.noscriptText?.value || ''
  };
}

function setOpnsenseTemplateValues(values = {}) {
  const fields = opnsenseTemplateFields();
  Object.entries(fields).forEach(([key, input]) => {
    if (input) input.value = values[key] ?? '';
  });
}

function opnsenseTemplateDelay(value) {
  const seconds = Number(value);
  return Number.isFinite(seconds) ? Math.min(60, Math.max(0, Math.trunc(seconds))) : 0;
}

function opnsenseTemplateHtml(values) {
  const targetUrl = String(values.targetUrl || '').trim();
  const refreshSeconds = opnsenseTemplateDelay(values.refreshSeconds);
  return `<!doctype html>
<html lang="${escapeHtml(values.lang)}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="${refreshSeconds};url=${escapeHtml(targetUrl)}">
  <title>${escapeHtml(values.title)}</title>
</head>
<body>
<p>${escapeHtml(values.redirectText)}</p>
<p><a href="${escapeHtml(targetUrl)}">${escapeHtml(values.linkText)}</a></p>
<script>
  (function () {
    var target = ${JSON.stringify(targetUrl)};
    var query = window.location.search || '';
    var hash = window.location.hash || '';
    window.location.replace(target + query + hash);
  }());
</script>
<noscript><p>${escapeHtml(values.noscriptText)}</p></noscript>
</body>
</html>
`;
}

function safeOpnsenseTemplatePreviewUrl(value) {
  try {
    const url = new URL(String(value || '').trim());
    return ['http:', 'https:'].includes(url.protocol) ? url.toString() : '#';
  } catch {
    return '#';
  }
}

function updateOpnsenseTemplatePreview() {
  const values = opnsenseTemplateValuesFromForm();
  saveOpnsenseTemplateValues(values);
  setPlainText('#opnsenseTemplatePreviewTitle', values.title || 'Redirecting');
  setPlainText('#opnsenseTemplatePreviewText', values.redirectText || '');
  const link = $('#opnsenseTemplatePreviewLink');
  if (link) {
    link.textContent = values.linkText || values.targetUrl || '';
    link.href = safeOpnsenseTemplatePreviewUrl(values.targetUrl);
  }
  setPlainText('#opnsenseTemplateCode', opnsenseTemplateHtml(values));
}

async function loadOpnsenseTemplateBuilder() {
  const form = $('#opnsenseTemplateForm');
  if (!form) return;
  if (!state.opnsenseTemplateDefaults) {
    const data = await api('/api/admin/opnsense-template');
    state.opnsenseTemplateDefaults = data.defaults || {};
  }
  if (form.dataset.loaded !== 'true') {
    const storedValues = storedOpnsenseTemplateValues();
    setOpnsenseTemplateValues({
      ...state.opnsenseTemplateDefaults,
      ...storedValues,
      targetUrl: state.opnsenseTemplateDefaults.targetUrl || ''
    });
    form.dataset.loaded = 'true';
  }
  if (form.dataset.bound !== 'true') {
    form.addEventListener('input', updateOpnsenseTemplatePreview);
    form.addEventListener('change', updateOpnsenseTemplatePreview);
    form.dataset.bound = 'true';
  }
  updateOpnsenseTemplatePreview();
}

function resetOpnsenseTemplateBuilder() {
  setOpnsenseTemplateValues(state.opnsenseTemplateDefaults || {});
  updateOpnsenseTemplatePreview();
  toast(t('Template defaults restored.'));
}

function opnsenseTemplateDownloadFilename(response) {
  const disposition = response.headers.get('content-disposition') || '';
  const match = disposition.match(/filename\*?=(?:UTF-8''|")?([^";]+)/iu);
  return match ? decodeURIComponent(match[1].replace(/^"|"$/gu, '')) : 'opnsense-captiveportal-template.zip';
}

async function downloadOpnsenseTemplateZip(event) {
  event.preventDefault();
  const form = $('#opnsenseTemplateForm');
  if (!form.reportValidity()) return;
  const button = $('#downloadOpnsenseTemplateButton');
  setButtonBusy(button, true, 'Creating…');
  try {
    const response = await fetch('/api/admin/opnsense-template.zip', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(state.csrfToken ? { 'x-csrf-token': state.csrfToken } : {})
      },
      body: JSON.stringify({ template: opnsenseTemplateValuesFromForm() })
    });
    if (response.status === 401) {
      showLogin();
      throw new Error(t('Your administrator session has expired.'));
    }
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(t(payload.message || `HTTP ${response.status}`));
    }
    const blob = await response.blob();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = opnsenseTemplateDownloadFilename(response);
    document.body.append(link);
    link.click();
    URL.revokeObjectURL(link.href);
    link.remove();
    toast(t('OPNsense template ZIP created.'));
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setButtonBusy(button, false);
  }
}

function renderSettingsGroup() {
  const group = state.settings.schema.find(item => item.id === state.settingsGroup) || state.settings.schema[0];
  state.settingsGroup = group.id;
  syncViewLocation('settings', true);
  $$('.settings-tab').forEach(button => button.classList.toggle('active', button.dataset.settingsGroup === group.id));
  $$('.settings-tab').forEach(button => {
    if (button.dataset.settingsGroup === 'voucher') {
      button.textContent = t('Voucher Management');
    }
  });
  const isAppearance = group.id === 'appearance';
  const isVoucher = group.id === 'voucher';
  const isAdminApproval = group.id === 'admin-approval';
  $('#settingsHeader').innerHTML = `<h2>${escapeHtml(t(group.label))}</h2><p>${escapeHtml(t(group.description))}</p>`;
  $('#settingsFields').classList.toggle('settings-fields--with-preview', isAppearance);
  $('#settingsFields').innerHTML = isAppearance
    ? `<div class="settings-fields-main">${renderSettingFields(group)}${renderAppearanceAssets()}</div>${renderPortalPreview()}`
    : renderSettingFields(group);
  $('#emailTestPanel').classList.toggle('hidden', group.id !== 'email');
  $('#syslogPanel').classList.toggle('hidden', group.id !== 'syslog');
  $('#syslogVacuumButton').classList.toggle('hidden', group.id !== 'syslog');
  $('#voucherManagementPanel').classList.toggle('hidden', !isVoucher);
  $('#adminApprovalManagementPanel').classList.toggle('hidden', !isAdminApproval);
  if (isVoucher) loadVouchers().catch(error => toast(error.message, 'error'));
  if (isAdminApproval) loadAdminApprovalRequests().catch(error => toast(error.message, 'error'));
  updateProviderFields();
  updateDurationFields();
  bindDerivedSettings();
  updateConditionalSettings();
  $('[data-setting="SMS_PROVIDER"]')?.addEventListener('change', updateProviderFields);
  $$('[data-setting]').forEach(input => {
    input.addEventListener('input', updateConditionalSettings);
    input.addEventListener('change', updateConditionalSettings);
  });
  $('[data-notification-template-select]')?.addEventListener('change', event => {
    syncSettingValuesFromDom();
    state.notificationTemplateKey = event.target.value;
    renderSettingsGroup();
  });
  $$('select[data-duration-role="unit"]').forEach(select =>
    select.addEventListener('change', updateDurationFields)
  );
  $$('.range-field input').forEach(input => input.addEventListener('input', () => {
    const field = group.fields.find(item => item.key === input.dataset.setting);
    input.nextElementSibling.textContent = `${input.value}${field?.suffix || ''}`;
  }));
  bindPortalPreviewInputs();
  $$('[data-appearance-upload]').forEach(input => input.addEventListener('change', async () => {
    const file = input.files?.[0];
    if (!file) return;
    const kind = input.dataset.appearanceUpload;
    const maxSize = appearanceAssetMaxSize(kind);
    if (maxSize && file.size > maxSize) {
      toast(t('Image is too large. Maximum size is {maxSize}.', { maxSize: formatBytes(maxSize) }), 'error');
      input.value = '';
      return;
    }
    input.disabled = true;
    try {
      await uploadAppearanceAsset(kind, file);
      toast(t('Appearance image uploaded.'));
      await loadSettings();
    } catch (error) {
      toast(error.message, 'error');
      input.disabled = false;
    }
  }));
  $$('[data-appearance-delete]').forEach(button => button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      await api(`/api/admin/appearance/assets/${button.dataset.appearanceDelete}`, {
        method: 'DELETE'
      });
      toast(t('Appearance image removed.'));
      await loadSettings();
    } catch (error) {
      toast(error.message, 'error');
      button.disabled = false;
    }
  }));
  const smtpSecure = $('[data-setting="SMTP_SECURE"]');
  const smtpStartTls = $('[data-setting="SMTP_STARTTLS"]');
  smtpSecure?.addEventListener('change', () => {
    if (smtpSecure.checked && smtpStartTls) smtpStartTls.checked = false;
  });
  smtpStartTls?.addEventListener('change', () => {
    if (smtpStartTls.checked && smtpSecure) smtpSecure.checked = false;
  });
  i18n.translateDom($('#settingsHeader'));
  i18n.translateDom($('#settingsFields'));
  i18n.translateDom($('#emailTestPanel'));
  i18n.translateDom($('#syslogPanel'));
  if (['opnsense', 'quotas', 'syslog'].includes(group.id)) {
    loadGatewayNetworks().catch(error => {
      renderGatewayNetworkChoices({
        choices: [],
        error: error.message
      });
    });
  }
  if (group.id === 'syslog') {
    loadSyslogStatus().catch(error => toast(error.message, 'error'));
  }
  if (group.id === 'quotas') {
    loadGatewayInterfaces().catch(error => {
      renderGatewayInterfaceChoices({
        interfaces: [],
        error: error.message
      });
    });
  }
  if (resetSettingsScrollOnRender) {
    resetSettingsScrollOnRender = false;
    window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
    document.scrollingElement?.scrollTo?.({ top: 0, left: 0, behavior: 'auto' });
    document.querySelector('.content')?.scrollTo?.({ top: 0, left: 0, behavior: 'auto' });
    document.querySelector('[data-view-panel="settings"]')?.scrollTo?.({ top: 0, left: 0, behavior: 'auto' });
  }
}

async function testEmailSettings() {
  const button = $('#testEmailButton');
  const recipient = $('#emailTestRecipient').value.trim();
  if (!recipient) {
    toast(t('Enter a test recipient email address.'), 'error');
    $('#emailTestRecipient').focus();
    return;
  }
  setButtonBusy(button, true, 'Sending…');
  try {
    const result = await api('/api/admin/settings/test-email', {
      method: 'POST',
      body: JSON.stringify({ recipient, language: i18n.language })
    });
    toast(t('Test email sent to {recipient}.', { recipient: result.recipient }));
  } catch (error) {
    toast(t('Test email failed: {error}', { error: error.message }), 'error');
  } finally {
    setButtonBusy(button, false);
  }
}

async function syncSyslog() {
  const button = $('#syslogSyncButton');
  setButtonBusy(button, true, 'Synchronizing…');
  try {
    const result = await api('/api/admin/syslog/sync', { method: 'POST', body: '{}' });
    toast(t('{inserted} new syslog records added.', {
      inserted: result.syslog?.inserted || result.law5651?.inserted || 0
    }));
    await loadSyslogStatus();
  } catch (error) {
    toast(t('Synchronization failed: {error}', { error: error.message }), 'error');
  } finally {
    setButtonBusy(button, false);
  }
}

async function exportSyslog() {
  const button = $('#syslogExportButton');
  setButtonBusy(button, true, 'Creating…');
  try {
    const result = await api('/api/admin/syslog/export', { method: 'POST', body: '{}' });
    toast(t('Syslog export created with {count} records.', { count: result.recordCount }));
    if (['failed', 'missing-token'].includes(result.timestampStatus)) {
      toast(t('Timestamp failed: {error}', { error: result.timestampError || result.timestampStatus }), 'error');
    }
    await loadSyslogStatus();
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setButtonBusy(button, false);
  }
}

async function vacuumSyslogDatabase() {
  const confirmed = await openActionConfirmModal({
    eyebrow: 'DATABASE MAINTENANCE',
    title: 'Compact syslog database',
    message: 'This will compact the hotspot database with SQLite VACUUM. It does not normally delete records, but interrupted maintenance, disk-full errors or storage problems can risk data loss. The system creates a database backup first; still, continue only after syslog exports are complete and during a quiet maintenance window.',
    confirmLabel: 'Run VACUUM',
    danger: true
  });
  if (!confirmed) return;
  const button = $('#syslogVacuumButton');
  setButtonBusy(button, true, 'Compacting…');
  try {
    const result = await api('/api/admin/syslog/vacuum', { method: 'POST', body: '{}' });
    toast(t('Database compacted. Reclaimed {reclaimed} in {seconds}s.', {
      reclaimed: formatBytes(result.reclaimedBytes || 0),
      seconds: Math.max(0.1, Number(result.durationMs || 0) / 1000).toFixed(1)
    }));
    if (result.backupPath) {
      toast(t('Database backup saved: {file}', {
        file: String(result.backupPath).split(/[\\/]/u).pop()
      }));
    }
    await loadSyslogStatus();
  } catch (error) {
    toast(t('Database compaction failed: {error}', { error: error.message }), 'error');
  } finally {
    setButtonBusy(button, false);
  }
}

async function loadSettings() {
  state.gatewayInterfaces = null;
  state.gatewayNetworks = null;
  state.settings = await api('/api/admin/settings');
  const locationGroup = settingsGroupFromLocation();
  if (locationGroup && state.settings.schema.some(group => group.id === locationGroup)) {
    state.settingsGroup = locationGroup;
  }
  $('#settingsTabs').innerHTML = state.settings.schema.map(group =>
    `<button class="settings-tab ${group.id === state.settingsGroup ? 'active' : ''}" type="button" data-settings-group="${group.id}">${escapeHtml(t(group.label))}</button>`
  ).join('');
  $$('[data-settings-group]').forEach(button => button.addEventListener('click', () => {
    if (state.settingsGroup === button.dataset.settingsGroup) return;
    state.settingsGroup = button.dataset.settingsGroup;
    resetSettingsScrollOnRender = true;
    renderSettingsGroup();
  }));
  renderSettingsGroup();
}

async function saveSettings(event) {
  event.preventDefault();
  const button = $('#saveSettingsButton');
  syncDerivedSettings();
  const values = collectSettingValuesFromDom();
  const currentTimestampMode = String(state.settings?.values?.SYSLOG_TIMESTAMP_MODE || 'disabled').toLowerCase();
  const nextTimestampMode = String(values.SYSLOG_TIMESTAMP_MODE || currentTimestampMode || 'disabled').toLowerCase();
  let syslogTimestampStampExisting = false;
  if (currentTimestampMode !== 'disabled' && nextTimestampMode === 'disabled') {
    const timestampDisableChoice = await openActionConfirmModal({
      eyebrow: 'SYSLOG TIMESTAMP',
      title: 'Disable syslog timestamp',
      message: 'Timestamping is being disabled. Stamp current syslog records before disabling?',
      confirmLabel: 'Stamp and disable',
      confirmValue: 'stamp',
      alternateLabel: 'Disable without timestamp',
      alternateValue: 'skip',
      cancelLabel: 'Cancel disable',
      cancelValue: 'cancel',
      danger: true
    });
    if (timestampDisableChoice === 'cancel') return;
    syslogTimestampStampExisting = timestampDisableChoice === 'stamp';
  }
  setButtonBusy(button, true, 'Saving…');
  try {
    const result = await api('/api/admin/settings', {
      method: 'PUT',
      body: JSON.stringify({ settings: values, syslogTimestampStampExisting })
    });
    state.appName = result.appName;
    state.gatewayMode = result.gatewayMode;
    setPlainText('#brandName', state.appName);
    refreshGatewayStatus();
    $('#settingsRestartNotice').classList.toggle('hidden', !result.restartRequired);
    $('#settingsRestartNotice').textContent = result.restartRequired
      ? t('Some changes require a process restart.')
      : '';
    toast(t('Settings saved and applied.'));
    if (result.bandwidthWarning) {
      const message = result.bandwidthWarningCode === 'opnsense_shaper_forbidden'
        ? t('Bandwidth limits require the "Firewall: Shaper" privilege for the OPNsense API user.')
        : t('Bandwidth limits could not be applied: {error}', {
          error: result.bandwidthWarning
        });
      toast(message, 'error');
    }
    if (result.syslogTimestampWarning) {
      toast(t('Syslog timestamp warning: {error}', { error: result.syslogTimestampWarning }), 'error');
    }
    await loadSettings();
    await refreshSystemAlerts();
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setButtonBusy(button, false);
  }
}

const viewConfig = {
  dashboard: ['CONTROL CENTER', 'Dashboard', loadDashboard],
  sessions: ['USAGE MANAGEMENT', 'Sessions', loadSessions],
  verifications: ['IDENTITY VERIFICATION', 'Verifications', loadVerifications],
  logs: ['AUDIT RECORDS', 'Activity Logs', loadLogs],
  'traffic-logs': ['TRAFFIC JOURNAL', 'Traffic Logs', loadTrafficLogView],
  'opnsense-template': ['OPNSENSE TEMPLATE', 'Create template', loadOpnsenseTemplateBuilder],
  settings: ['SYSTEM CONFIGURATION', 'Settings', loadSettings]
};

function viewFromLocation() {
  let hash = window.location.hash || '';
  try {
    hash = decodeURIComponent(hash);
  } catch {
    return '';
  }
  hash = hash.replace(/^#\/?/, '').split('/')[0];
  return viewConfig[hash] ? hash : '';
}

function settingsGroupFromLocation() {
  let hash = window.location.hash || '';
  try {
    hash = decodeURIComponent(hash);
  } catch {
    return '';
  }
  const [view, group] = hash.replace(/^#\/?/, '').split('/');
  return view === 'settings' ? String(group || '').trim() : '';
}

function initialAdminView() {
  return viewFromLocation() || state.currentView || 'dashboard';
}

function syncViewLocation(view, replace = false) {
  const hash = view === 'settings' && state.settingsGroup
    ? `${view}/${state.settingsGroup}`
    : view;
  if (window.location.hash.replace(/^#\/?/, '') === hash) return;
  const url = new URL(window.location.href);
  url.hash = hash;
  history[replace ? 'replaceState' : 'pushState'](null, '', url);
}

async function navigate(view, options = {}) {
  if (!viewConfig[view]) return;
  if (view === 'settings') {
    state.settingsGroup = options.settingsGroup || settingsGroupFromLocation() || state.settingsGroup;
  }
  syncViewLocation(view, Boolean(options.replace));
  state.currentView = view;
  $$('.nav-item[data-view]').forEach(item => item.classList.toggle('active', item.dataset.view === view));
  $$('.view').forEach(panel => panel.classList.toggle('active', panel.dataset.viewPanel === view));
  setTranslatedText('#pageEyebrow', viewConfig[view][0]);
  setTranslatedText('#pageTitle', viewConfig[view][1]);
  $('#adminApp').classList.remove('sidebar-open');
  try {
    await viewConfig[view][2]();
    refreshSystemAlerts().catch(() => {});
    if (view !== 'dashboard' && view !== 'sessions') refreshActiveSessionCount().catch(() => {});
  } catch (error) {
    toast(error.message, 'error');
  }
}

function debounce(callback, delay = 280) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => callback(...args), delay);
  };
}

function openVoucherModal() {
  $('#voucherModal').classList.remove('hidden');
  $('#voucherForm').classList.remove('hidden');
  $('#voucherResult').classList.add('hidden');
  $('#voucherLabel').focus();
}

function closeVoucherModal() {
  $('#voucherModal').classList.add('hidden');
}

let adminApprovalDecisionResolver = null;
let actionConfirmResolver = null;
let actionConfirmCancelValue = false;
let actionConfirmSubmitValue = true;
let actionConfirmAlternateValue = false;

function closeAdminApprovalDecisionModal(value = null) {
  $('#adminApprovalDecisionModal').classList.add('hidden');
  const resolver = adminApprovalDecisionResolver;
  adminApprovalDecisionResolver = null;
  if (resolver) resolver(value);
}

function openAdminApprovalDecisionModal(action) {
  const approve = action === 'approve';
  const modal = $('#adminApprovalDecisionModal');
  const card = modal.querySelector('.modal-card');
  const message = $('#adminApprovalDecisionMessage');
  card.classList.toggle('reject', !approve);
  setPlainText('#adminApprovalDecisionTitle', approve ? t('Approval message') : t('Rejection message'));
  setPlainText('#adminApprovalDecisionEyebrow', approve ? t('APPROVE REQUEST') : t('REJECT REQUEST'));
  setPlainText('#adminApprovalDecisionSubmit', approve ? t('Approve') : t('Reject'));
  message.value = t(approve
    ? 'Your internet access request was approved.'
    : 'Your internet access request was rejected.');
  modal.classList.remove('hidden');
  setTimeout(() => message.focus(), 40);
  return new Promise(resolve => {
    adminApprovalDecisionResolver = resolve;
  });
}

function closeActionConfirmModal(value = actionConfirmCancelValue) {
  $('#actionConfirmModal').classList.add('hidden');
  $('#actionConfirmAlternate')?.classList.add('hidden');
  const resolver = actionConfirmResolver;
  actionConfirmResolver = null;
  if (resolver) resolver(value);
}

function openActionConfirmModal({
  eyebrow = 'SESSION ACTION',
  title = 'Confirm action',
  message = '',
  confirmLabel = 'Confirm',
  confirmValue = true,
  alternateLabel = '',
  alternateValue = false,
  cancelLabel = 'Cancel',
  cancelValue = false,
  danger = false
} = {}) {
  const modal = $('#actionConfirmModal');
  const card = modal.querySelector('.modal-card');
  const alternate = $('#actionConfirmAlternate');
  card.classList.toggle('danger', Boolean(danger));
  actionConfirmCancelValue = cancelValue;
  actionConfirmSubmitValue = confirmValue;
  actionConfirmAlternateValue = alternateValue;
  setPlainText('#actionConfirmEyebrow', t(eyebrow));
  setPlainText('#actionConfirmTitle', t(title));
  setPlainText('#actionConfirmMessage', t(message));
  setPlainText('#actionConfirmSubmit', t(confirmLabel));
  setPlainText('#actionConfirmCancel', t(cancelLabel));
  if (alternate) {
    alternate.classList.toggle('hidden', !alternateLabel);
    setPlainText(alternate, alternateLabel ? t(alternateLabel) : '');
  }
  modal.classList.remove('hidden');
  setTimeout(() => $('#actionConfirmSubmit').focus(), 40);
  return new Promise(resolve => {
    actionConfirmResolver = resolve;
  });
}

async function runSessionAction(action, id, callback) {
  if (!id || isSessionActionPending(action, id)) return;
  setSessionActionPending(action, id, true);
  try {
    await callback();
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setSessionActionPending(action, id, false);
  }
}

function voucherManagementVisible() {
  return state.currentView === 'settings' && state.settingsGroup === 'voucher';
}

async function createVouchers(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  setButtonBusy(button, true, 'Creating…');
  try {
    const expiresValue = $('#voucherExpires').value;
    const payload = await api('/api/admin/vouchers', {
      method: 'POST',
      body: JSON.stringify({
        label: $('#voucherLabel').value,
        count: Number($('#voucherCountInput').value),
        maxUses: Number($('#voucherUses').value),
        durationMinutes: Number($('#voucherDuration').value),
        expiresAt: expiresValue ? new Date(expiresValue).getTime() : null
      })
    });
    state.createdVouchers = payload.vouchers;
    $('#createdVoucherCount').textContent = payload.vouchers.length;
    $('#createdVoucherCodes').value = payload.vouchers.map(item => item.code).join('\n');
    $('#voucherForm').classList.add('hidden');
    $('#voucherResult').classList.remove('hidden');
    toast(`${payload.vouchers.length} ${t('vouchers created')}`);
    if (voucherManagementVisible()) loadVouchers();
    loadDashboard();
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setButtonBusy(button, false);
  }
}

async function copyCreatedVouchers() {
  const text = state.createdVouchers.map(item => item.code).join('\n');
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    $('#createdVoucherCodes').select();
    document.execCommand('copy');
  }
  toast(t('Voucher codes copied to the clipboard.'));
}

function downloadCreatedVouchers() {
  const rows = ['Code', ...state.createdVouchers.map(item => item.code)].join('\n');
  const blob = new Blob([`\uFEFF${rows}`], { type: 'text/csv;charset=utf-8' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `vouchers-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.append(link);
  link.click();
  URL.revokeObjectURL(link.href);
  link.remove();
}

async function syncGateway() {
  const button = $('#syncButton');
  setButtonBusy(button, true, 'Synchronizing…');
  try {
    const result = await api('/api/admin/sync', { method: 'POST', body: '{}' });
    toast(t('{received} gateway sessions read, {matched} records matched.', result));
    updateWelcomeSyncStatus(result.syncedAt);
    if (result.syslog?.enabled || result.law5651?.enabled) {
      toast(t('{inserted} new syslog records added.', {
        inserted: result.syslog?.inserted || result.law5651?.inserted || 0
      }));
    }
    refreshGatewayStatus();
    await navigate(state.currentView);
  } catch (error) {
    toast(t('Synchronization failed: {error}', { error: error.message }), 'error');
  } finally {
    setButtonBusy(button, false);
  }
}

async function login(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button');
  const notice = $('#loginNotice');
  notice.classList.add('hidden');
  setButtonBusy(button, true, 'Signing in…');
  try {
    const notificationPublicIp = await lookupAdminPublicIp();
    const session = await api('/api/admin/login', {
      method: 'POST',
      body: JSON.stringify({
        username: $('#loginUsername').value,
        password: $('#loginPassword').value,
        notificationPublicIp
      })
    });
    const config = await api('/api/admin/session');
    showApp({ ...config, ...session });
    $('#loginPassword').value = '';
  } catch (error) {
    notice.textContent = error.message;
    notice.classList.remove('hidden');
  } finally {
    setButtonBusy(button, false);
  }
}

async function logout() {
  try { await api('/api/admin/logout', { method: 'POST', body: '{}' }); } catch {}
  showLogin();
}

$('#loginForm').addEventListener('submit', login);
$('#logoutButton').addEventListener('click', logout);
$('#syncButton').addEventListener('click', syncGateway);
$('#releaseStatusButton').addEventListener('click', openReleaseFromAvatar);
$('#settingsForm').addEventListener('submit', saveSettings);
$('#testEmailButton').addEventListener('click', testEmailSettings);
$('#syslogSyncButton').addEventListener('click', syncSyslog);
$('#syslogExportButton').addEventListener('click', exportSyslog);
$('#syslogVacuumButton').addEventListener('click', vacuumSyslogDatabase);
$('#trafficLogSettingsButton').addEventListener('click', openTrafficLogSettingsModal);
$('#trafficLogStreamToggleButton').addEventListener('click', toggleTrafficLogLiveStream);
$('#trafficLogSettingsForm').addEventListener('submit', saveTrafficLogSettings);
function setAdminLanguage(language) {
  i18n.setLanguage(language, 'gh_admin_language');
}

$('#adminLanguage').addEventListener('change', event => setAdminLanguage(event.target.value));
$('#loginLanguage').addEventListener('change', event => setAdminLanguage(event.target.value));
$('#mobileMenu').addEventListener('click', () => $('#adminApp').classList.add('sidebar-open'));
$('#sidebarOverlay').addEventListener('click', () => $('#adminApp').classList.remove('sidebar-open'));
$('#sidebarToggle').addEventListener('click', () => {
  const next = !$('#adminApp').classList.contains('sidebar-mini');
  setSidebarMini(next, { store: true });
});
$('#themeToggle').addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  setTheme(next, { store: true });
});
$$('[data-view]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.view)));
$$('[data-go-view]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.goView)));
$$('[data-open-voucher]').forEach(button => button.addEventListener('click', openVoucherModal));
$$('[data-close-modal]').forEach(button => button.addEventListener('click', closeVoucherModal));
$$('[data-close-decision-modal]').forEach(button =>
  button.addEventListener('click', () => closeAdminApprovalDecisionModal(null))
);
$$('[data-close-action-confirm]').forEach(button =>
  button.addEventListener('click', () => closeActionConfirmModal())
);
$$('[data-close-template-placeholders]').forEach(button =>
  button.addEventListener('click', closeTemplatePlaceholderModal)
);
$$('[data-close-traffic-log-settings]').forEach(button =>
  button.addEventListener('click', closeTrafficLogSettingsModal)
);
$$('[data-close-release-modal]').forEach(button =>
  button.addEventListener('click', closeReleaseModal)
);
$('#voucherForm').addEventListener('submit', createVouchers);
$('#opnsenseTemplateForm').addEventListener('submit', downloadOpnsenseTemplateZip);
$('#resetOpnsenseTemplateButton').addEventListener('click', resetOpnsenseTemplateBuilder);
$('#copyVouchers').addEventListener('click', copyCreatedVouchers);
$('#downloadVouchers').addEventListener('click', downloadCreatedVouchers);
$('#adminApprovalDecisionForm').addEventListener('submit', event => {
  event.preventDefault();
  closeAdminApprovalDecisionModal($('#adminApprovalDecisionMessage').value);
});
$('#actionConfirmAlternate').addEventListener('click', () => closeActionConfirmModal(actionConfirmAlternateValue));
$('#actionConfirmSubmit').addEventListener('click', () => closeActionConfirmModal(actionConfirmSubmitValue));

$('#sessionSearch').addEventListener('input', debounce(loadSessions));
$('#sessionMethod').addEventListener('change', loadSessions);
$('#sessionState').addEventListener('change', loadSessions);
$('#verificationSearch').addEventListener('input', debounce(loadVerifications));
$('#verificationKind').addEventListener('change', loadVerifications);
$('#verificationStatus').addEventListener('change', loadVerifications);
$('#voucherSearch').addEventListener('input', debounce(loadVouchers));
$('#voucherStatus').addEventListener('change', loadVouchers);
$('#adminApprovalSearch').addEventListener('input', debounce(loadAdminApprovalRequests));
$('#adminApprovalStatus').addEventListener('change', loadAdminApprovalRequests);
$('#logSearch').addEventListener('input', debounce(loadLogs));
$('#logKind').addEventListener('change', loadLogs);
$('#trafficPeriod').addEventListener('change', () => {
  state.trafficPeriod = $('#trafficPeriod').value;
  saveDashboardFilters();
  loadDashboard().catch(error => toast(error.message, 'error'));
});
$('#topSitesRange')?.addEventListener('change', () => {
  state.topSitesHours = Number($('#topSitesRange').value || 6);
  saveDashboardFilters();
  loadDashboard().catch(error => toast(error.message, 'error'));
});
$('#topBandwidthRange')?.addEventListener('change', () => {
  state.topBandwidthHours = Number($('#topBandwidthRange').value || 6);
  saveDashboardFilters();
  loadDashboard().catch(error => toast(error.message, 'error'));
});

document.addEventListener('pointerover', event => {
  const target = event.target.closest?.('[data-dashboard-tooltip]');
  if (!target) return;
  showDashboardTooltip(target, event);
});

document.addEventListener('pointermove', event => {
  if (!event.target.closest?.('[data-dashboard-tooltip]')) return;
  positionDashboardTooltip(event);
});

document.addEventListener('pointerout', event => {
  const target = event.target.closest?.('[data-dashboard-tooltip]');
  if (!target) return;
  const nextTarget = event.relatedTarget?.closest?.('[data-dashboard-tooltip]');
  if (nextTarget === target) return;
  hideDashboardTooltip();
});

window.addEventListener('resize', hideDashboardTooltip);
window.addEventListener('scroll', hideDashboardTooltip, true);
[
  '#trafficLogSourceIp',
  '#trafficLogSourcePort',
  '#trafficLogDestinationIp',
  '#trafficLogDestinationPort'
].forEach(selector => $(selector)?.addEventListener('input', debounce(loadTrafficLogs)));
[
  '#trafficLogStartAt',
  '#trafficLogEndAt'
].forEach(selector => $(selector)?.addEventListener('change', loadTrafficLogs));
$('#trafficLogKind').addEventListener('change', loadTrafficLogs);
$('#trafficLogPeriod').addEventListener('change', loadTrafficLogs);

document.addEventListener('click', async event => {
  const settingNetwork = event.target.closest('[data-setting-network]');
  if (settingNetwork) {
    appendSettingNetwork(settingNetwork.dataset.settingNetwork, settingNetwork.dataset.network);
    return;
  }
  const columnsButton = event.target.closest('#sessionColumnsButton');
  const columnsMenu = event.target.closest('#sessionColumnsMenu');
  if (columnsButton) {
    const menu = $('#sessionColumnsMenu');
    const expanded = menu.classList.toggle('hidden') === false;
    columnsButton.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    return;
  }
  if (columnsMenu) {
    return;
  }
  $('#sessionColumnsMenu')?.classList.add('hidden');
  $('#sessionColumnsButton')?.setAttribute('aria-expanded', 'false');
  const placeholderHelp = event.target.closest('[data-template-placeholder-help]');
  if (placeholderHelp) {
    openTemplatePlaceholderModal(placeholderHelp.dataset.templatePlaceholderHelp);
    return;
  }
  const settingsShortcut = event.target.closest('[data-settings-shortcut]');
  if (settingsShortcut) {
    state.settingsGroup = settingsShortcut.dataset.settingsShortcut;
    await navigate('settings');
    return;
  }
  const releaseUpdate = event.target.closest('[data-open-release-update]');
  if (releaseUpdate) {
    openReleaseModal();
    return;
  }
  const resetQuota = event.target.closest('[data-reset-quota]');
  if (resetQuota) {
    const id = decodeURIComponent(resetQuota.dataset.resetQuota || '');
    if (isSessionActionPending('reset-quota', id)) return;
    const confirmed = await openActionConfirmModal({
      title: 'Reset quota',
      message: 'Reset this session quota? The user will be allowed to use the internet again if the access period is still active.',
      confirmLabel: 'Reset quota'
    });
    if (!confirmed) return;
    await runSessionAction('reset-quota', id, async () => {
      const result = await api(`/api/admin/sessions/${encodeURIComponent(id)}/reset-quota`, {
        method: 'POST',
        body: '{}'
      });
      if (result.gatewayError) {
        toast(t('Quota reset, but gateway access could not be restored: {error}', { error: result.gatewayError }), 'error');
      } else {
        toast(t('Quota reset.'));
      }
      await loadSessions();
      loadDashboard();
    });
    return;
  }
  const disconnect = event.target.closest('[data-disconnect]');
  if (disconnect) {
    const id = decodeURIComponent(disconnect.dataset.disconnect || '');
    if (isSessionActionPending('disconnect', id)) return;
    const confirmed = await openActionConfirmModal({
      title: 'Disconnect session',
      message: 'Disconnect this user from the internet?',
      confirmLabel: 'Disconnect session',
      danger: true
    });
    if (!confirmed) return;
    await runSessionAction('disconnect', id, async () => {
      await api(`/api/admin/sessions/${encodeURIComponent(id)}/disconnect`, { method: 'POST', body: '{}' });
      toast(t('Session disconnected.'));
      await loadSessions();
      loadDashboard();
    });
    return;
  }
  const adminApprovalAction = event.target.closest('[data-admin-approval-action]');
  if (adminApprovalAction) {
    const requestId = adminApprovalAction.dataset.adminApprovalId;
    if (adminApprovalAction.disabled || pendingAdminApprovalDecision(requestId)) return;
    const action = adminApprovalAction.dataset.adminApprovalAction;
    const message = await openAdminApprovalDecisionModal(action);
    if (message == null) return;
    setAdminApprovalDecisionPending(requestId, action, true);
    try {
      const result = await api(
        `/api/admin/admin-approval/requests/${requestId}/${action}`,
        {
          method: 'POST',
          body: JSON.stringify({ message })
        }
      );
      const notification = result.notification || {};
      if (notification.failed || notification.error) {
        toast(t('Request updated, but notification delivery failed.'), 'error');
      } else {
        toast(t(action === 'approve' ? 'Request approved.' : 'Request rejected.'));
      }
      if (state.currentView === 'dashboard') await loadDashboard();
      if (state.currentView === 'settings' && state.settingsGroup === 'admin-approval') {
        await loadAdminApprovalRequests();
      }
      await loadVerifications().catch(() => {});
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      setAdminApprovalDecisionPending(requestId, action, false);
    }
    return;
  }
  const toggle = event.target.closest('[data-toggle-voucher]');
  if (toggle) {
    toggle.disabled = true;
    try {
      const enabled = toggle.dataset.enabled === '1';
      await api(`/api/admin/vouchers/${toggle.dataset.toggleVoucher}/toggle`, {
        method: 'POST',
        body: JSON.stringify({ enabled })
      });
      toast(enabled ? t('Voucher enabled.') : t('Voucher disabled.'));
      await loadVouchers();
      loadDashboard();
    } catch (error) {
      toast(error.message, 'error');
      toggle.disabled = false;
    }
  }
});

document.addEventListener('change', event => {
  const input = event.target.closest('[data-session-column]');
  if (!input) return;
  const selected = new Set(loadSessionColumnKeys());
  if (input.checked) selected.add(input.dataset.sessionColumn);
  else selected.delete(input.dataset.sessionColumn);
  if (!selected.size) {
    input.checked = true;
    toast(t('At least one column must remain visible.'), 'error');
    return;
  }
  saveSessionColumnKeys(SESSION_COLUMNS.map(column => column.key).filter(key => selected.has(key)));
  renderSessionsTable();
});

document.addEventListener('gh:language', () => {
  $('#adminLanguage').value = i18n.language;
  $('#loginLanguage').value = i18n.language;
  setSidebarMini($('#adminApp').classList.contains('sidebar-mini'));
  i18n.translateDom();
  setTheme(document.documentElement.dataset.theme);
  updateTrafficLogStreamToggle();
  renderProjectAttribution();
  renderReleaseIndicator();
  refreshSystemAlerts().catch(() => {});
  if (state.csrfToken) navigate(state.currentView);
});

function navigateFromLocation() {
  const view = viewFromLocation();
  if (!state.csrfToken || !view) return;
  if (view !== state.currentView) {
    navigate(view, { replace: true });
    return;
  }
  if (view === 'settings') {
    const group = settingsGroupFromLocation();
    if (group && group !== state.settingsGroup && state.settings?.schema?.some(item => item.id === group)) {
      state.settingsGroup = group;
      resetSettingsScrollOnRender = true;
      renderSettingsGroup();
    }
  }
}

window.addEventListener('hashchange', navigateFromLocation);
window.addEventListener('popstate', navigateFromLocation);

document.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    closeActionConfirmModal(false);
    closeAdminApprovalDecisionModal(null);
    closeTemplatePlaceholderModal();
    closeReleaseModal();
    closeVoucherModal();
    $('#sessionColumnsMenu')?.classList.add('hidden');
    $('#sessionColumnsButton')?.setAttribute('aria-expanded', 'false');
    $('#adminApp').classList.remove('sidebar-open');
    hideDashboardTooltip();
  }
});

setInterval(() => {
  if (!state.csrfToken || document.hidden) return;
  if (state.currentView === 'dashboard') loadDashboard().catch(() => {});
  if (state.currentView === 'sessions') loadSessions().catch(() => {});
  if (state.currentView === 'traffic-logs' && !state.trafficLogLivePaused) loadTrafficLogs().catch(() => {});
  if (!['dashboard', 'sessions'].includes(state.currentView)) refreshActiveSessionCount().catch(() => {});
}, 30000);

setInterval(() => {
  if (!state.csrfToken || document.hidden || state.currentView !== 'dashboard') return;
  if (Date.now() - state.lastAdminApprovalRefreshAt < 5000) return;
  refreshDashboardAdminApprovals().catch(() => {});
}, 1000);

setInterval(() => {
  if (!state.csrfToken || document.hidden || state.currentView !== 'traffic-logs') return;
  if (state.trafficLogLivePaused) return;
  const seconds = Number(state.trafficLogSettings?.runtime?.liveRefreshSeconds || 5);
  if (Date.now() - state.lastTrafficLogRefreshAt < Math.max(2, seconds) * 1000) return;
  loadTrafficLogs().catch(() => {});
}, 1000);

setInterval(() => {
  if (!state.csrfToken || document.hidden) return;
  checkLatestRelease({ showDailyPopup: true }).catch(() => {});
}, 60 * 60 * 1000);

setTheme(storedTheme());

(async function init() {
  try {
    await i18n.ready;
    setTheme(document.documentElement.dataset.theme);
    await loadProjectAttribution();
    const session = await api('/api/admin/session');
    await i18n.setAutomaticLanguage(session.defaultLanguage || 'en', 'gh_admin_language');
    $('#adminLanguage').value = i18n.language;
    if (session.authenticated) showApp(session);
    else {
      showLogin();
      if (!session.enabled) {
        $('#loginNotice').textContent = t('The admin panel is disabled. Set ADMIN_PASSWORD in the settings file.');
        $('#loginNotice').classList.remove('hidden');
      }
    }
    i18n.reveal();
  } catch (error) {
    showLogin();
    $('#loginNotice').textContent = t('The administration service is unavailable: {error}', { error: error.message });
    $('#loginNotice').classList.remove('hidden');
    i18n.reveal();
  }
})();
