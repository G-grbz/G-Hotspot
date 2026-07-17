const i18n = window.GH_I18N;
const t = (text, variables) => i18n.t(text, variables);
let session = null;
let timer = null;
let portalConfig = null;
const DEFAULT_LOGO_URL = '/img/logo.png';
const DEFAULT_NETWORK_LABEL_TEXT = 'GUEST NETWORK';

function portalDisplayText(value, fallback) {
  if (value === undefined || value === null) return t(fallback);
  const text = String(value || '').trim();
  return text === fallback ? t(fallback) : text;
}

function setOptionalText(element, text) {
  if (!element) return;
  element.textContent = text;
  element.classList.toggle('hidden', !text);
}

function renderSessionBrandTexts(config = portalConfig) {
  if (!config) return;
  const appName = document.querySelector('#appName');
  const networkLabel = document.querySelector('#networkLabel');
  const portalTitle = String(config.portal?.titleText || '').trim();
  if (appName) appName.textContent = portalTitle || config.appName;
  setOptionalText(networkLabel, portalDisplayText(
    config.portal?.networkLabelText,
    DEFAULT_NETWORK_LABEL_TEXT
  ));
}

function setBrandLogo(config) {
  const logo = document.querySelector('#brandLogo');
  const fallback = document.querySelector('.brand-fallback');
  if (!logo || !fallback) return;

  const sources = [config.appearance?.logoUrl, DEFAULT_LOGO_URL]
    .filter((source, index, list) => source && list.indexOf(source) === index);
  let index = 0;

  function showFallback() {
    logo.onload = null;
    logo.onerror = null;
    logo.removeAttribute('src');
    logo.classList.add('hidden');
    fallback.classList.remove('hidden');
  }

  function loadNextLogo() {
    const source = sources[index];
    index += 1;
    if (!source) {
      showFallback();
      return;
    }
    logo.onload = () => {
      logo.onload = null;
      logo.onerror = null;
      logo.classList.remove('hidden');
      fallback.classList.add('hidden');
    };
    logo.onerror = loadNextLogo;
    logo.alt = `${config.appName} logo`;
    logo.src = source;
  }

  loadNextLogo();
}

function formatDate(value) {
  return new Intl.DateTimeFormat(i18n.locale, {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(new Date(Number(value)));
}

function formatBytes(value) {
  const bytes = Math.max(0, Number(value) || 0);
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const amount = bytes / 1024 ** index;
  return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
}

function formatDuration(milliseconds) {
  const minutes = Math.max(0, Math.floor(milliseconds / 60000));
  const days = Math.floor(minutes / 1440);
  const hours = Math.floor((minutes % 1440) / 60);
  const rest = minutes % 60;
  const parts = [];
  if (days) parts.push(t('{count} days', { count: days }));
  if (hours) parts.push(t('{count} hours', { count: hours }));
  if (rest || !parts.length) parts.push(t('{count} minutes', { count: rest }));
  return parts.join(' ');
}

function methodLabel(method) {
  return {
    voucher: t('Voucher'),
    'admin-approval': t('Admin approval'),
    email: t('Email'),
    whatsapp: 'WhatsApp',
    telegram: 'Telegram',
    sms: 'SMS'
  }[method] || method;
}

function quotaPeriodLabel(value) {
  return {
    daily: t('Daily'),
    weekly: t('Weekly'),
    monthly: t('Monthly')
  }[value] || value || '—';
}

function quotaBlockedUntil() {
  return Number(session?.quotaBlockedUntil || 0);
}

function isQuotaBlocked() {
  return quotaBlockedUntil() > Date.now();
}

function quotaUsageText(used, limit) {
  const limitBytes = Math.max(0, Number(limit) || 0);
  if (!limitBytes) return t('Unlimited');
  return `${formatBytes(used)} / ${formatBytes(limitBytes)}`;
}

function quotaRemainingText(used, limit) {
  const limitBytes = Math.max(0, Number(limit) || 0);
  if (!limitBytes) return '';
  return `${t('Remaining')}: ${formatBytes(Math.max(0, limitBytes - Math.max(0, Number(used) || 0)))}`;
}

function visibleDownloadBytes() {
  return Math.max(
    Number(session.downloadBytes || 0),
    Number(session.quotaDownloadLimitBytes || 0) ? Number(session.quotaDownloadBytes || 0) : 0
  );
}

function visibleUploadBytes() {
  return Math.max(
    Number(session.uploadBytes || 0),
    Number(session.quotaUploadLimitBytes || 0) ? Number(session.quotaUploadBytes || 0) : 0
  );
}

function setQuotaDetail(id, visible, value = '—', note = '') {
  const detail = document.querySelector(`#${id}Detail`);
  detail.classList.toggle('hidden', !visible);
  if (!visible) return;
  document.querySelector(`#${id}`).textContent = value;
  const noteElement = document.querySelector(`#${id}Remaining`) || document.querySelector(`#${id}Reset`);
  if (noteElement) noteElement.textContent = note;
}

function renderQuota() {
  const downloadLimit = Number(session.quotaDownloadLimitBytes || 0);
  const uploadLimit = Number(session.quotaUploadLimitBytes || 0);
  const hasQuota = Boolean(downloadLimit || uploadLimit);
  const blockedUntil = quotaBlockedUntil();
  const resetAt = blockedUntil > Date.now()
    ? blockedUntil
    : Number(session.quotaPeriodEndAt || 0);

  setQuotaDetail('quotaPeriod', hasQuota, quotaPeriodLabel(session.quotaPeriod), resetAt
    ? `${t(blockedUntil > Date.now() ? 'Blocked until' : 'Quota resets')}: ${formatDate(resetAt)}`
    : '');
  setQuotaDetail(
    'quotaDownload',
    Boolean(downloadLimit),
    quotaUsageText(session.quotaDownloadBytes, downloadLimit),
    quotaRemainingText(session.quotaDownloadBytes, downloadLimit)
  );
  setQuotaDetail(
    'quotaUpload',
    Boolean(uploadLimit),
    quotaUsageText(session.quotaUploadBytes, uploadLimit),
    quotaRemainingText(session.quotaUploadBytes, uploadLimit)
  );
}

function showNotice(message, type = 'error') {
  const notice = document.querySelector('#notice');
  notice.textContent = message;
  notice.className = `notice ${type}`;
}

function updateCountdown() {
  if (!session) return;
  if (isQuotaBlocked()) {
    const blockedUntil = quotaBlockedUntil();
    document.querySelector('#remainingText').textContent = blockedUntil
      ? t('Internet access is paused until {time}.', { time: formatDate(blockedUntil) })
      : t('Internet access is paused until the next quota period.');
    return;
  }
  const remaining = Number(session.expiresAt) - Date.now();
  document.querySelector('#remainingText').textContent = session.unlimited
    ? t('This session has no expiration.')
    : t('Time remaining: {duration}', { duration: formatDuration(remaining) });
  if (!session.unlimited && remaining <= 0) {
    clearInterval(timer);
    showNotice(t('Your session has ended. Redirecting to the login page.'), 'info');
    setTimeout(() => location.replace('/'), 1500);
  }
}

function render() {
  const quotaBlocked = isQuotaBlocked();
  document.querySelector('#sessionStatusIcon').textContent = quotaBlocked ? '!' : '✓';
  document.querySelector('#sessionStatusTitle').textContent = quotaBlocked
    ? t('Quota limit reached')
    : t('Internet access is active');
  document.querySelector('#clientIp').textContent = session.clientIp || '—';
  document.querySelector('#clientMac').textContent = session.clientMac || t('Not available');
  document.querySelector('#deviceName').textContent = session.deviceName || '';
  document.querySelector('#method').textContent = methodLabel(session.method);
  document.querySelector('#identity').textContent = session.identity || '';
  document.querySelector('#gatewayStatus').textContent =
    session.gatewayConnected ? t('Connected') : t('Disconnected');
  document.querySelector('#gatewayMode').textContent = {
    'opnsense-api': 'OPNsense API',
    // TODO(pfSense): Restore the session label when pfSense support resumes.
    // 'pfsense-api': 'pfSense API',
    mock: t('Mock / test mode')
  }[session.gatewayMode] || session.gatewayMode || t('Mock / test mode');
  document.querySelector('#startedAt').textContent = formatDate(session.createdAt);
  document.querySelector('#expiresAt').textContent =
    session.unlimited ? t('No expiration') : formatDate(session.expiresAt);
  document.querySelector('#duration').textContent = session.unlimited
    ? t('Unlimited access')
    : t('Total duration: {duration}', {
      duration: formatDuration(Number(session.expiresAt) - Number(session.createdAt))
    });
  document.querySelector('#download').textContent = formatBytes(visibleDownloadBytes());
  document.querySelector('#upload').textContent = formatBytes(visibleUploadBytes());
  renderQuota();
  const continueButton = document.querySelector('#continueButton');
  continueButton.href = session.redirectUrl || '/';
  continueButton.classList.toggle('hidden', quotaBlocked || !session.redirectUrl);
  updateCountdown();
}

async function loadSession() {
  const response = await fetch('/api/v1/session', { cache: 'no-store' });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 404 || payload.error === 'session_not_found') {
      location.replace('/');
      return false;
    }
    throw new Error(t(payload.message || 'Session not found'));
  }
  session = payload;
  render();
  return true;
}

document.querySelector('#logoutButton').addEventListener('click', async event => {
  const button = event.currentTarget;
  button.disabled = true;
  button.textContent = t('Disconnecting…');
  try {
    const response = await fetch('/api/v1/session/logout', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-session-action': 'logout'
      },
      body: '{}'
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(t(payload.message || `HTTP ${response.status}`));
    location.replace(payload.redirectUrl || '/');
  } catch (error) {
    showNotice(error.message);
    button.disabled = false;
    button.textContent = t('Log out and disconnect');
  }
});

document.querySelector('#languageSelect').addEventListener('change', event => {
  i18n.setLanguage(event.target.value);
});

document.addEventListener('gh:language', () => {
  document.querySelector('#languageSelect').value = i18n.language;
  renderSessionBrandTexts();
  if (session) render();
});

async function preloadPortalFonts() {
  if (!document.fonts?.load) return;
  const families = ['Manrope', 'Roboto Condensed', 'Satisfy'];
  const sample = 'G-Hotspot ABCÇĞİÖŞÜ abcçğıöşü 0123456789';
  await Promise.allSettled(families.map(family => document.fonts.load(`400 1em "${family}"`, sample)));
}

(async function init() {
  try {
    await i18n.ready;
    await preloadPortalFonts();
    const configResponse = await fetch('/api/v1/config', { cache: 'no-store' });
    const config = await configResponse.json();
    portalConfig = config;
    if (!i18n.hasStoredLanguage()) {
      await i18n.setLanguage(config.defaultLanguage || 'en');
    }
    window.GH_TERMS?.init({ config });
    document.querySelector('#languageSelect').value = i18n.language;
    renderSessionBrandTexts(config);
    setBrandLogo(config);
    document.title = `${t('Active session')} · ${config.appName}`;
    if (!await loadSession()) return;
    timer = setInterval(() => loadSession().catch(error => showNotice(error.message)), 30000);
    setInterval(updateCountdown, 1000);
    i18n.reveal();
  } catch (error) {
    showNotice(error.message);
    document.querySelector('#logoutButton').classList.add('hidden');
    document.querySelector('#continueButton').classList.remove('hidden');
    document.querySelector('#continueButton').href = '/';
    document.querySelector('#continueButton').textContent = t('Return to verification');
    i18n.reveal();
  }
}());
