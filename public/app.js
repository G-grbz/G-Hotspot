const state = {
  emailChallengeId: '',
  whatsappChallengeId: '',
  telegramChallengeId: '',
  smsChallengeId: '',
  nviChallengeId: '',
  adminApprovalRequestId: '',
  about: null,
  config: null
};

const params = new URLSearchParams(location.search);
const redirectUrl = params.get('redirurl') || params.get('redirect') || '';
let clientMac = normalizeMac(params.get('client_mac') || params.get('mac') || '');
const telegramChallengeParam = params.get('telegram_challenge') || '';
const notice = document.querySelector('#notice');
const i18n = window.GH_I18N;
const t = (text, variables) => i18n.t(text, variables);
const countryCodeModal = document.querySelector('#countryCodeModal');
const countryCodeList = document.querySelector('#countryCodeList');
const countryCodeSearch = document.querySelector('#countryCodeSearch');
const countryCodeEmpty = document.querySelector('#countryCodeEmpty');
const TELEGRAM_PENDING_KEY = 'gh_telegram_pending';
const ADMIN_APPROVAL_PENDING_KEY = 'gh_admin_approval_pending';
const DEFAULT_LOGO_URL = '/img/logo.png';
const DEFAULT_NETWORK_LABEL_TEXT = 'GUEST NETWORK';
const DEFAULT_VERIFICATION_PROMPT_TEXT = 'Choose a verification method to open internet access.';
const APP_VERSION = '1.0.0';
const VOUCHER_CODE_LENGTH = 12;
const COUNTRY_MODAL_CLOSE_ANIMATION_MS = 180;
const COUNTRY_POPOVER_MARGIN = 10;
let adminApprovalPollTimer = 0;
let countryCodeCloseTimer = 0;
let activeCountryCodeSelect = null;
let activeCountryCodeTrigger = null;

function normalizeMac(value) {
  const parts = String(value || '').match(/[0-9a-f]{2}/giu);
  return parts?.length === 6 ? parts.map(part => part.toUpperCase()).join(':') : '';
}

function clientInfoLabel() {
  const clientIp = state.config?.clientIp || '';
  if (clientIp && clientMac) return `${clientIp} - ${clientMac}`;
  return clientIp || clientMac;
}

function renderClientInfo() {
  const element = document.querySelector('#clientInfo');
  if (!element || !state.config) return;
  element.textContent = t('Connected device: {ip}', { ip: clientInfoLabel() });
}

function portalDisplayText(value, fallback) {
  if (value === undefined || value === null) return t(fallback);
  const text = String(value || '').trim();
  return text === fallback ? t(fallback) : text;
}

function setOptionalPortalText(element, text) {
  if (!element) return;
  element.textContent = text;
  element.classList.toggle('hidden', !text);
}

function portalTitleText() {
  const text = String(state.config?.portal?.titleText || '').trim();
  return text || state.config?.appName || 'G-Hotspot';
}

function renderPortalTexts() {
  if (!state.config) return;
  const title = document.querySelector('#appName');
  const networkLabel = document.querySelector('#networkLabel');
  const verificationPrompt = document.querySelector('#verificationPrompt');
  if (title) title.textContent = portalTitleText();
  setOptionalPortalText(networkLabel, portalDisplayText(
    state.config.portal?.networkLabelText,
    DEFAULT_NETWORK_LABEL_TEXT
  ));
  setOptionalPortalText(verificationPrompt, portalDisplayText(
    state.config.portal?.verificationPromptText,
    DEFAULT_VERIFICATION_PROMPT_TEXT
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

function renderProjectAttribution(about = state.about || {}) {
  const element = document.querySelector('#projectAttribution');
  if (!element) return;
  const name = about.displayName || about.name || 'G-Hotspot';
  const author = about.author || 'Gökhan GÜRBÜZ';
  const username = about.githubUsername ? ` (${about.githubUsername})` : ' (G-grbz)';
  const versionValue = about.version || APP_VERSION;
  const version = versionValue ? ` v${versionValue}` : '';
  const license = about.license || 'LicenseRef-G-Hotspot-NC-1.0';
  const source = String(about.githubUrl || about.source || '').trim();
  const label = document.createElement('span');
  label.textContent = `${t('Powered by')} ${name}${version} / ${author}${username} · ${license}`;
  element.replaceChildren(label);
  if (/^https?:\/\//u.test(source)) {
    const separator = document.createElement('span');
    const link = document.createElement('a');
    separator.textContent = '·';
    link.href = source;
    link.target = '_blank';
    link.rel = 'noreferrer';
    link.textContent = about.githubUrl ? 'GitHub' : t('Source');
    element.append(separator, link);
  }
}

async function loadProjectAttribution() {
  try {
    state.about = await api('/api/v1/about', { headers: {} });
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

function showNotice(message, type = 'info') {
  if (!notice) return;
  notice.textContent = message;
  notice.className = `notice ${type}`;
}

function clearNotice() {
  if (!notice) return;
  notice.textContent = '';
  notice.className = 'notice hidden';
}

function setBusy(form, busy) {
  if (!form || typeof form.querySelector !== 'function') return;
  const button = form.querySelector('button[type="submit"]');
  if (!button) return;
  button.disabled = busy;
  button.dataset.label ||= button.dataset.i18nSource || button.textContent;
  button.textContent = busy ? t('Processing…') : t(button.dataset.label);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers || {}) }
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (payload.error === 'reverification_limited' && payload.retryAt) {
      const date = new Intl.DateTimeFormat(i18n.locale, {
        dateStyle: 'medium',
        timeStyle: 'short'
      }).format(new Date(Number(payload.retryAt)));
      throw new Error(t(
        'This identity can be verified again after {date}.',
        { date }
      ));
    }
    if (payload.error === 'reverification_permanently_blocked') {
      throw new Error(t(
        'This identity has already been verified and cannot be verified again.'
      ));
    }
    if (payload.error === 'ip_request_limited' && payload.retryAt) {
      const date = new Intl.DateTimeFormat(i18n.locale, {
        dateStyle: 'medium',
        timeStyle: 'short'
      }).format(new Date(Number(payload.retryAt)));
      throw new Error(t(
        'A new verification code can be requested from this IP after {date}.',
        { date }
      ));
    }
    if (payload.error === 'ip_request_permanently_blocked') {
      throw new Error(t(
        'This IP address cannot request another verification code.'
      ));
    }
    throw new Error(t(payload.message || `HTTP ${response.status}`));
  }
  return payload;
}

function commonPayload() {
  return { redirectUrl, clientMac, language: i18n.language };
}

function digits(value, maxLength = 64) {
  return String(value || '').replace(/\D/g, '').slice(0, maxLength);
}

function normalizeCountryCode(value) {
  return digits(value, 3);
}

function phoneCountryCodes() {
  const allCodes = Array.isArray(state.config?.countryCallingCodes)
    ? state.config.countryCallingCodes.map(normalizeCountryCode).filter(Boolean)
    : [];
  const allowedCodes = Array.isArray(state.config?.allowedCountryCodes)
    ? state.config.allowedCountryCodes.map(normalizeCountryCode).filter(Boolean)
    : [];
  const source = allowedCodes.length ? allowedCodes : allCodes;
  return [...new Set(source)];
}

const CALLING_CODE_FLAGS = {
  '1': '🇺🇸 🇨🇦',
  '1242': '🇧🇸',
  '1246': '🇧🇧',
  '1264': '🇦🇮',
  '1268': '🇦🇬',
  '1284': '🇻🇬',
  '1340': '🇻🇮',
  '1345': '🇰🇾',
  '1441': '🇧🇲',
  '1473': '🇬🇩',
  '1649': '🇹🇨',
  '1658': '🇯🇲',
  '1664': '🇲🇸',
  '1670': '🇲🇵',
  '1671': '🇬🇺',
  '1684': '🇦🇸',
  '1721': '🇸🇽',
  '1758': '🇱🇨',
  '1767': '🇩🇲',
  '1784': '🇻🇨',
  '1787': '🇵🇷',
  '1809': '🇩🇴',
  '1829': '🇩🇴',
  '1849': '🇩🇴',
  '1868': '🇹🇹',
  '1869': '🇰🇳',
  '1876': '🇯🇲',
  '1939': '🇵🇷',
  '7': '🇷🇺 🇰🇿',
  '20': '🇪🇬',
  '27': '🇿🇦',
  '30': '🇬🇷',
  '31': '🇳🇱',
  '32': '🇧🇪',
  '33': '🇫🇷',
  '34': '🇪🇸',
  '36': '🇭🇺',
  '39': '🇮🇹 🇻🇦',
  '3906698': '🇻🇦',
  '40': '🇷🇴',
  '41': '🇨🇭',
  '43': '🇦🇹',
  '44': '🇬🇧',
  '441481': '🇬🇬',
  '441534': '🇯🇪',
  '441624': '🇮🇲',
  '45': '🇩🇰',
  '46': '🇸🇪',
  '47': '🇳🇴',
  '4779': '🇸🇯',
  '48': '🇵🇱',
  '49': '🇩🇪',
  '51': '🇵🇪',
  '52': '🇲🇽',
  '53': '🇨🇺',
  '54': '🇦🇷',
  '55': '🇧🇷',
  '56': '🇨🇱',
  '57': '🇨🇴',
  '58': '🇻🇪',
  '60': '🇲🇾',
  '61': '🇦🇺',
  '6189162': '🇨🇨',
  '6189164': '🇨🇽',
  '62': '🇮🇩',
  '63': '🇵🇭',
  '64': '🇳🇿',
  '65': '🇸🇬',
  '66': '🇹🇭',
  '81': '🇯🇵',
  '82': '🇰🇷',
  '84': '🇻🇳',
  '86': '🇨🇳',
  '90': '🇹🇷',
  '91': '🇮🇳',
  '92': '🇵🇰',
  '93': '🇦🇫',
  '94': '🇱🇰',
  '95': '🇲🇲',
  '98': '🇮🇷',
  '211': '🇸🇸',
  '212': '🇲🇦 🇪🇭',
  '213': '🇩🇿',
  '216': '🇹🇳',
  '218': '🇱🇾',
  '220': '🇬🇲',
  '221': '🇸🇳',
  '222': '🇲🇷',
  '223': '🇲🇱',
  '224': '🇬🇳',
  '225': '🇨🇮',
  '226': '🇧🇫',
  '227': '🇳🇪',
  '228': '🇹🇬',
  '229': '🇧🇯',
  '230': '🇲🇺',
  '231': '🇱🇷',
  '232': '🇸🇱',
  '233': '🇬🇭',
  '234': '🇳🇬',
  '235': '🇹🇩',
  '236': '🇨🇫',
  '237': '🇨🇲',
  '238': '🇨🇻',
  '239': '🇸🇹',
  '240': '🇬🇶',
  '241': '🇬🇦',
  '242': '🇨🇬',
  '243': '🇨🇩',
  '244': '🇦🇴',
  '245': '🇬🇼',
  '246': '🇮🇴',
  '247': '🇦🇨',
  '248': '🇸🇨',
  '249': '🇸🇩',
  '250': '🇷🇼',
  '251': '🇪🇹',
  '252': '🇸🇴',
  '253': '🇩🇯',
  '254': '🇰🇪',
  '255': '🇹🇿',
  '256': '🇺🇬',
  '257': '🇧🇮',
  '258': '🇲🇿',
  '260': '🇿🇲',
  '261': '🇲🇬',
  '262': '🇷🇪 🇾🇹',
  '262269': '🇾🇹',
  '262639': '🇾🇹',
  '262262': '🇷🇪',
  '262692': '🇷🇪',
  '263': '🇿🇼',
  '264': '🇳🇦',
  '265': '🇲🇼',
  '266': '🇱🇸',
  '267': '🇧🇼',
  '268': '🇸🇿',
  '269': '🇰🇲',
  '290': '🇸🇭',
  '2908': '🇹🇦',
  '291': '🇪🇷',
  '297': '🇦🇼',
  '298': '🇫🇴',
  '299': '🇬🇱',
  '350': '🇬🇮',
  '351': '🇵🇹',
  '352': '🇱🇺',
  '353': '🇮🇪',
  '354': '🇮🇸',
  '355': '🇦🇱',
  '356': '🇲🇹',
  '357': '🇨🇾',
  '358': '🇫🇮',
  '35818': '🇦🇽',
  '359': '🇧🇬',
  '370': '🇱🇹',
  '371': '🇱🇻',
  '372': '🇪🇪',
  '373': '🇲🇩',
  '374': '🇦🇲',
  '375': '🇧🇾',
  '376': '🇦🇩',
  '377': '🇲🇨',
  '378': '🇸🇲',
  '380': '🇺🇦',
  '381': '🇷🇸',
  '382': '🇲🇪',
  '383': '🇽🇰',
  '385': '🇭🇷',
  '386': '🇸🇮',
  '387': '🇧🇦',
  '389': '🇲🇰',
  '420': '🇨🇿',
  '421': '🇸🇰',
  '423': '🇱🇮',
  '500': '🇫🇰',
  '501': '🇧🇿',
  '502': '🇬🇹',
  '503': '🇸🇻',
  '504': '🇭🇳',
  '505': '🇳🇮',
  '506': '🇨🇷',
  '507': '🇵🇦',
  '508': '🇵🇲',
  '509': '🇭🇹',
  '590': '🇬🇵 🇧🇱 🇲🇫',
  '591': '🇧🇴',
  '592': '🇬🇾',
  '593': '🇪🇨',
  '594': '🇬🇫',
  '595': '🇵🇾',
  '596': '🇲🇶',
  '597': '🇸🇷',
  '598': '🇺🇾',
  '599': '🇨🇼 🇧🇶',
  '5993': '🇧🇶',
  '5994': '🇧🇶',
  '5997': '🇧🇶',
  '5999': '🇨🇼',
  '670': '🇹🇱',
  '672': '🇦🇺',
  '6723': '🇳🇫',
  '673': '🇧🇳',
  '674': '🇳🇷',
  '675': '🇵🇬',
  '676': '🇹🇴',
  '677': '🇸🇧',
  '678': '🇻🇺',
  '679': '🇫🇯',
  '680': '🇵🇼',
  '681': '🇼🇫',
  '682': '🇨🇰',
  '683': '🇳🇺',
  '685': '🇼🇸',
  '686': '🇰🇮',
  '687': '🇳🇨',
  '688': '🇹🇻',
  '689': '🇵🇫',
  '690': '🇹🇰',
  '691': '🇫🇲',
  '692': '🇲🇭',
  '850': '🇰🇵',
  '852': '🇭🇰',
  '853': '🇲🇴',
  '855': '🇰🇭',
  '856': '🇱🇦',
  '880': '🇧🇩',
  '886': '🇹🇼',
  '960': '🇲🇻',
  '961': '🇱🇧',
  '962': '🇯🇴',
  '963': '🇸🇾',
  '964': '🇮🇶',
  '965': '🇰🇼',
  '966': '🇸🇦',
  '967': '🇾🇪',
  '968': '🇴🇲',
  '970': '🇵🇸',
  '971': '🇦🇪',
  '972': '🇮🇱',
  '973': '🇧🇭',
  '974': '🇶🇦',
  '975': '🇧🇹',
  '976': '🇲🇳',
  '977': '🇳🇵',
  '992': '🇹🇯',
  '993': '🇹🇲',
  '994': '🇦🇿',
  '995': '🇬🇪',
  '996': '🇰🇬',
  '998': '🇺🇿'
};

const CALLING_CODE_REGIONS = {
  '1': ['US', 'CA', 'BS', 'BB', 'AI', 'AG', 'VG', 'VI', 'KY', 'BM', 'GD', 'TC', 'MS', 'MP', 'GU', 'AS', 'SX', 'LC', 'DM', 'VC', 'PR', 'DO', 'TT', 'KN', 'JM'],
  '7': ['RU', 'KZ'],
  '20': ['EG'],
  '27': ['ZA'],
  '30': ['GR'],
  '31': ['NL'],
  '32': ['BE'],
  '33': ['FR'],
  '34': ['ES'],
  '36': ['HU'],
  '39': ['IT', 'VA'],
  '40': ['RO'],
  '41': ['CH'],
  '43': ['AT'],
  '44': ['GB', 'GG', 'JE', 'IM'],
  '45': ['DK'],
  '46': ['SE'],
  '47': ['NO', 'SJ'],
  '48': ['PL'],
  '49': ['DE'],
  '51': ['PE'],
  '52': ['MX'],
  '53': ['CU'],
  '54': ['AR'],
  '55': ['BR'],
  '56': ['CL'],
  '57': ['CO'],
  '58': ['VE'],
  '60': ['MY'],
  '61': ['AU', 'CC', 'CX'],
  '62': ['ID'],
  '63': ['PH'],
  '64': ['NZ'],
  '65': ['SG'],
  '66': ['TH'],
  '81': ['JP'],
  '82': ['KR'],
  '84': ['VN'],
  '86': ['CN'],
  '90': ['TR'],
  '91': ['IN'],
  '92': ['PK'],
  '93': ['AF'],
  '94': ['LK'],
  '95': ['MM'],
  '98': ['IR'],
  '211': ['SS'],
  '212': ['MA', 'EH'],
  '213': ['DZ'],
  '216': ['TN'],
  '218': ['LY'],
  '220': ['GM'],
  '221': ['SN'],
  '222': ['MR'],
  '223': ['ML'],
  '224': ['GN'],
  '225': ['CI'],
  '226': ['BF'],
  '227': ['NE'],
  '228': ['TG'],
  '229': ['BJ'],
  '230': ['MU'],
  '231': ['LR'],
  '232': ['SL'],
  '233': ['GH'],
  '234': ['NG'],
  '235': ['TD'],
  '236': ['CF'],
  '237': ['CM'],
  '238': ['CV'],
  '239': ['ST'],
  '240': ['GQ'],
  '241': ['GA'],
  '242': ['CG'],
  '243': ['CD'],
  '244': ['AO'],
  '245': ['GW'],
  '246': ['IO'],
  '248': ['SC'],
  '249': ['SD'],
  '250': ['RW'],
  '251': ['ET'],
  '252': ['SO'],
  '253': ['DJ'],
  '254': ['KE'],
  '255': ['TZ'],
  '256': ['UG'],
  '257': ['BI'],
  '258': ['MZ'],
  '260': ['ZM'],
  '261': ['MG'],
  '262': ['RE', 'YT'],
  '263': ['ZW'],
  '264': ['NA'],
  '265': ['MW'],
  '266': ['LS'],
  '267': ['BW'],
  '268': ['SZ'],
  '269': ['KM'],
  '290': ['SH'],
  '291': ['ER'],
  '297': ['AW'],
  '298': ['FO'],
  '299': ['GL'],
  '350': ['GI'],
  '351': ['PT'],
  '352': ['LU'],
  '353': ['IE'],
  '354': ['IS'],
  '355': ['AL'],
  '356': ['MT'],
  '357': ['CY'],
  '358': ['FI', 'AX'],
  '359': ['BG'],
  '370': ['LT'],
  '371': ['LV'],
  '372': ['EE'],
  '373': ['MD'],
  '374': ['AM'],
  '375': ['BY'],
  '376': ['AD'],
  '377': ['MC'],
  '378': ['SM'],
  '379': ['VA'],
  '380': ['UA'],
  '381': ['RS'],
  '382': ['ME'],
  '383': ['XK'],
  '385': ['HR'],
  '386': ['SI'],
  '387': ['BA'],
  '389': ['MK'],
  '420': ['CZ'],
  '421': ['SK'],
  '423': ['LI'],
  '500': ['FK'],
  '501': ['BZ'],
  '502': ['GT'],
  '503': ['SV'],
  '504': ['HN'],
  '505': ['NI'],
  '506': ['CR'],
  '507': ['PA'],
  '508': ['PM'],
  '509': ['HT'],
  '590': ['GP', 'BL', 'MF'],
  '591': ['BO'],
  '592': ['GY'],
  '593': ['EC'],
  '594': ['GF'],
  '595': ['PY'],
  '596': ['MQ'],
  '597': ['SR'],
  '598': ['UY'],
  '599': ['CW', 'BQ'],
  '670': ['TL'],
  '672': ['NF'],
  '673': ['BN'],
  '674': ['NR'],
  '675': ['PG'],
  '676': ['TO'],
  '677': ['SB'],
  '678': ['VU'],
  '679': ['FJ'],
  '680': ['PW'],
  '681': ['WF'],
  '682': ['CK'],
  '683': ['NU'],
  '685': ['WS'],
  '686': ['KI'],
  '687': ['NC'],
  '688': ['TV'],
  '689': ['PF'],
  '690': ['TK'],
  '691': ['FM'],
  '692': ['MH'],
  '850': ['KP'],
  '852': ['HK'],
  '853': ['MO'],
  '855': ['KH'],
  '856': ['LA'],
  '880': ['BD'],
  '886': ['TW'],
  '960': ['MV'],
  '961': ['LB'],
  '962': ['JO'],
  '963': ['SY'],
  '964': ['IQ'],
  '965': ['KW'],
  '966': ['SA'],
  '967': ['YE'],
  '968': ['OM'],
  '970': ['PS'],
  '971': ['AE'],
  '972': ['IL'],
  '973': ['BH'],
  '974': ['QA'],
  '975': ['BT'],
  '976': ['MN'],
  '977': ['NP'],
  '992': ['TJ'],
  '993': ['TM'],
  '994': ['AZ'],
  '995': ['GE'],
  '996': ['KG'],
  '998': ['UZ']
};

const REGION_NAME_FALLBACKS = {
  en: {
    XK: 'Kosovo'
  },
  tr: {
    XK: 'Kosova'
  }
};

const regionDisplayNameCache = new Map();

function flagForCountryCode(value) {
  let digits = String(value ?? '').replace(/\D/g, '');

  if (digits.startsWith('00')) {
    digits = digits.slice(2);
  }
  for (let length = Math.min(7, digits.length); length > 0; length -= 1) {
    const prefix = digits.slice(0, length);
    if (CALLING_CODE_FLAGS[prefix]) {
      return CALLING_CODE_FLAGS[prefix];
    }
  }

  return '🏳️';
}

function normalizedSearchText(value) {
  return String(value || '')
    .toLocaleLowerCase(i18n.locale || undefined)
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/gu, '')
    .replace(/[ıİ]/gu, 'i');
}

function clampNumber(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function regionDisplayName(region) {
  const language = i18n.language || 'en';
  const fallback = REGION_NAME_FALLBACKS[language]?.[region] ||
    REGION_NAME_FALLBACKS.en?.[region] ||
    region;

  try {
    const locale = i18n.locale || language || 'en-US';
    if (!regionDisplayNameCache.has(locale)) {
      regionDisplayNameCache.set(locale, new Intl.DisplayNames([locale], { type: 'region' }));
    }
    const name = regionDisplayNameCache.get(locale).of(region);
    return name && name !== region ? name : fallback;
  } catch {
    return fallback;
  }
}

function countryCodeRegionNames(code) {
  return [...new Set((CALLING_CODE_REGIONS[code] || [])
    .map(region => regionDisplayName(region))
    .filter(Boolean))];
}

function countryCodeNameLabel(names) {
  if (!names.length) return t('Country code');
  if (names.length <= 3) return names.join(', ');
  return t('{countries} and {count} more', {
    countries: names.slice(0, 2).join(', '),
    count: names.length - 2
  });
}

function countryCodeItems() {
  return phoneCountryCodes().map(code => {
    const flag = flagForCountryCode(code);
    const names = countryCodeRegionNames(code);
    const label = countryCodeNameLabel(names);
    const regions = CALLING_CODE_REGIONS[code] || [];
    return {
      code,
      flag,
      label,
      searchText: normalizedSearchText([
        code,
        `+${code}`,
        flag,
        label,
        names.join(' '),
        regions.join(' ')
      ].join(' '))
    };
  });
}

function countryCodeCompactLabel(code) {
  return code ? `${flagForCountryCode(code)} +${code}` : t('Country code');
}

function ensureCountryCodeTrigger(select) {
  let trigger = select.nextElementSibling?.matches?.('[data-country-code-trigger]')
    ? select.nextElementSibling
    : null;

  if (!trigger) {
    trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'phone-country-select country-code-trigger';
    trigger.dataset.countryCodeTrigger = select.id || 'country-code';
    trigger.setAttribute('aria-haspopup', 'dialog');
    trigger.setAttribute('aria-controls', 'countryCodeModal');
    select.insertAdjacentElement('afterend', trigger);
    trigger.addEventListener('click', () => {
      if (countryCodePopoverIsOpen() && activeCountryCodeSelect === select) {
        closeCountryCodeModal();
        return;
      }
      openCountryCodeModal(select, trigger);
    });
  }

  select.classList.add('phone-country-select--native');
  select.setAttribute('aria-hidden', 'true');
  select.tabIndex = -1;
  trigger.disabled = select.disabled;
  trigger.textContent = countryCodeCompactLabel(select.value);
  trigger.setAttribute('aria-expanded', trigger === activeCountryCodeTrigger &&
    countryCodeModal &&
    !countryCodeModal.classList.contains('hidden')
    ? 'true'
    : 'false');
  trigger.setAttribute('aria-label', `${t('Country code')} ${countryCodeCompactLabel(select.value)}`);
  return trigger;
}

function syncCountryCodeControls() {
  for (const select of document.querySelectorAll('[data-country-code-select]')) {
    ensureCountryCodeTrigger(select);
  }
}

function populateCountryCodeSelects() {
  const codes = phoneCountryCodes();
  const defaultCountryCode = normalizeCountryCode(state.config?.defaultCountryCode) || codes[0] || '';
  for (const select of document.querySelectorAll('[data-country-code-select]')) {
    const current = normalizeCountryCode(select.value);
    select.replaceChildren(...codes.map(code => {
      const option = document.createElement('option');
      option.value = code;
      option.textContent = `${flagForCountryCode(code)} +${code}`;
      return option;
    }));
    select.value = codes.includes(current)
      ? current
      : (codes.includes(defaultCountryCode) ? defaultCountryCode : codes[0] || '');
    select.disabled = codes.length <= 1;
  }
  syncCountryCodeControls();
}

function renderCountryCodeOptions() {
  if (!countryCodeList || !countryCodeEmpty) return;
  const query = normalizedSearchText(countryCodeSearch?.value || '');
  const selectedCode = activeCountryCodeSelect?.value || '';
  const items = countryCodeItems().filter(item => !query || item.searchText.includes(query));

  countryCodeList.replaceChildren(...items.map(item => {
    const option = document.createElement('button');
    const flag = document.createElement('span');
    const text = document.createElement('span');
    const name = document.createElement('strong');
    const code = document.createElement('span');

    option.type = 'button';
    option.className = 'country-code-option';
    option.dataset.countryCodeOption = item.code;
    option.setAttribute('role', 'option');
    option.setAttribute('aria-selected', item.code === selectedCode ? 'true' : 'false');

    flag.className = 'country-code-option__flag';
    flag.textContent = item.flag;
    text.className = 'country-code-option__text';
    name.textContent = item.label;
    code.textContent = `+${item.code}`;

    text.append(name, code);
    option.append(flag, text);
    return option;
  }));

  countryCodeList.classList.toggle('hidden', !items.length);
  countryCodeEmpty.classList.toggle('hidden', Boolean(items.length));
}

function positionCountryCodePopover() {
  if (!countryCodeModal || !activeCountryCodeTrigger) return;
  const rect = activeCountryCodeTrigger.getBoundingClientRect();
  const viewportWidth = document.documentElement.clientWidth || window.innerWidth;
  const viewportHeight = document.documentElement.clientHeight || window.innerHeight;
  const width = Math.min(320, Math.max(220, viewportWidth - (COUNTRY_POPOVER_MARGIN * 2)));
  const left = clampNumber(
    rect.left,
    COUNTRY_POPOVER_MARGIN,
    Math.max(COUNTRY_POPOVER_MARGIN, viewportWidth - width - COUNTRY_POPOVER_MARGIN)
  );
  const belowTop = rect.bottom + 6;
  const availableBelow = viewportHeight - belowTop - COUNTRY_POPOVER_MARGIN;
  const availableAbove = rect.top - COUNTRY_POPOVER_MARGIN - 6;
  let maxHeight = Math.max(210, Math.min(320, availableBelow));
  let top = belowTop;

  if (availableBelow < 230 && availableAbove > availableBelow) {
    maxHeight = Math.max(210, Math.min(320, availableAbove));
    top = Math.max(COUNTRY_POPOVER_MARGIN, rect.top - maxHeight - 6);
  }

  countryCodeModal.style.setProperty('--country-popover-left', `${Math.round(left)}px`);
  countryCodeModal.style.setProperty('--country-popover-top', `${Math.round(top)}px`);
  countryCodeModal.style.setProperty('--country-popover-width', `${Math.round(width)}px`);
  countryCodeModal.style.setProperty('--country-popover-max-height', `${Math.round(maxHeight)}px`);
}

function openCountryCodeModal(select, trigger) {
  if (!countryCodeModal || !select || select.disabled) return;
  clearTimeout(countryCodeCloseTimer);
  activeCountryCodeSelect = select;
  activeCountryCodeTrigger = trigger || null;
  if (countryCodeSearch) countryCodeSearch.value = '';
  renderCountryCodeOptions();
  countryCodeModal.classList.remove('hidden');
  countryCodeModal.setAttribute('aria-hidden', 'false');
  positionCountryCodePopover();
  activeCountryCodeTrigger?.setAttribute('aria-expanded', 'true');
  requestAnimationFrame(() => {
    positionCountryCodePopover();
    countryCodeModal.classList.add('is-open');
    countryCodeSearch?.focus({ preventScroll: true });
  });
}

function closeCountryCodeModal({ restoreFocus = true } = {}) {
  if (!countryCodeModal || countryCodeModal.classList.contains('hidden')) return;
  clearTimeout(countryCodeCloseTimer);
  const trigger = activeCountryCodeTrigger;
  countryCodeModal.classList.remove('is-open');
  countryCodeModal.setAttribute('aria-hidden', 'true');
  trigger?.setAttribute('aria-expanded', 'false');
  activeCountryCodeSelect = null;
  activeCountryCodeTrigger = null;
  countryCodeCloseTimer = setTimeout(() => {
    countryCodeModal.classList.add('hidden');
  }, COUNTRY_MODAL_CLOSE_ANIMATION_MS);
  if (restoreFocus && trigger && document.contains(trigger)) {
    trigger.focus({ preventScroll: true });
  }
}

function selectCountryCode(code) {
  const normalized = normalizeCountryCode(code);
  if (!activeCountryCodeSelect || !normalized) return;
  activeCountryCodeSelect.value = normalized;
  activeCountryCodeSelect.dispatchEvent(new Event('change', { bubbles: true }));
  syncCountryCodeControls();
  closeCountryCodeModal();
}

function focusableCountryModalElements() {
  if (!countryCodeModal || countryCodeModal.classList.contains('hidden')) return [];
  return [...countryCodeModal.querySelectorAll([
    'button:not([disabled])',
    'input:not([disabled])',
    '[tabindex]:not([tabindex="-1"])'
  ].join(','))].filter(element =>
    element.offsetWidth || element.offsetHeight || element.getClientRects().length
  );
}

function trapCountryModalFocus(event) {
  if (!countryCodeModal || countryCodeModal.classList.contains('hidden')) return;
  const focusable = focusableCountryModalElements();
  if (!focusable.length) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function countryCodePopoverIsOpen() {
  return Boolean(countryCodeModal && !countryCodeModal.classList.contains('hidden'));
}

function phonePayload(phoneSelector, countrySelector) {
  return {
    phone: document.querySelector(phoneSelector).value,
    countryCode: document.querySelector(countrySelector).value
  };
}

function voucherText(value) {
  return String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, VOUCHER_CODE_LENGTH);
}

function formatVoucherCode(value) {
  return voucherText(value).replace(/.{4}(?=.)/gu, '$&-');
}

function voucherCaretPosition(value, rawIndex) {
  if (rawIndex <= 0) return 0;
  let seen = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== '-') seen += 1;
    if (seen >= rawIndex) return index + 1;
  }
  return value.length;
}

function formatVoucherInput(input) {
  const selectionStart = input.selectionStart ?? input.value.length;
  const rawBeforeCaret = voucherText(input.value.slice(0, selectionStart)).length;
  const formatted = formatVoucherCode(input.value);
  input.value = formatted;
  const caret = voucherCaretPosition(formatted, rawBeforeCaret);
  input.setSelectionRange(caret, caret);
}

function sessionProbePath() {
  const sessionParams = new URLSearchParams({ optional: '1' });
  if (clientMac) sessionParams.set('client_mac', clientMac);
  return `/api/v1/session?${sessionParams}`;
}

async function resolveClientMacInBackground() {
  if (clientMac) return;
  try {
    const payload = await api('/api/v1/client-mac', { headers: {} });
    const resolvedClientMac = normalizeMac(payload.clientMac);
    if (!resolvedClientMac) return;
    clientMac = resolvedClientMac;
    renderClientInfo();
  } catch {
    // MAC lookup is display-only; keep the portal usable if OPNsense is slow or unreachable.
  }
}

function success(payload) {
  clearTelegramPending();
  clearAdminApprovalPending();
  showNotice(t('Verification completed. Your internet access is now open.'), 'success');
  setTimeout(() => location.replace(payload.sessionUrl || '/session'), 150);
}

function storageGet(key) {
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function storageSet(key, value) {
  try {
    sessionStorage.setItem(key, value);
  } catch {}
}

function storageRemove(key) {
  try {
    sessionStorage.removeItem(key);
  } catch {}
}

function telegramPending() {
  try {
    const pending = JSON.parse(storageGet(TELEGRAM_PENDING_KEY) || 'null');
    if (!pending?.challengeId || Number(pending.expiresAt) <= Date.now()) {
      clearTelegramPending();
      return null;
    }
    return pending;
  } catch {
    clearTelegramPending();
    return null;
  }
}

function saveTelegramPending(payload, phone = '') {
  const pending = {
    challengeId: payload.challengeId,
    expiresAt: payload.expiresAt,
    botUrl: payload.botUrl || '',
    appUrl: payload.appUrl || '',
    startCommand: payload.startCommand || '',
    maskedPhone: payload.maskedPhone || phone || ''
  };
  storageSet(TELEGRAM_PENDING_KEY, JSON.stringify(pending));
  setTelegramChallengeUrl(pending.challengeId);
  return pending;
}

function clearTelegramPending() {
  storageRemove(TELEGRAM_PENDING_KEY);
  clearTelegramChallengeUrl();
}

function adminApprovalPending() {
  try {
    const pending = JSON.parse(storageGet(ADMIN_APPROVAL_PENDING_KEY) || 'null');
    if (!pending?.id || Number(pending.requestExpiresAt) <= Date.now()) {
      clearAdminApprovalPending();
      return null;
    }
    return pending;
  } catch {
    clearAdminApprovalPending();
    return null;
  }
}

function saveAdminApprovalPending(payload) {
  const pending = {
    id: payload.id,
    status: payload.status,
    requestExpiresAt: payload.requestExpiresAt
  };
  state.adminApprovalRequestId = pending.id;
  storageSet(ADMIN_APPROVAL_PENDING_KEY, JSON.stringify(pending));
  return pending;
}

function clearAdminApprovalPending() {
  state.adminApprovalRequestId = '';
  storageRemove(ADMIN_APPROVAL_PENDING_KEY);
  if (adminApprovalPollTimer) clearInterval(adminApprovalPollTimer);
  adminApprovalPollTimer = 0;
}

function showAdminApprovalWaiting(pending) {
  if (!pending?.id) return;
  state.adminApprovalRequestId = pending.id;
  document.querySelector('#adminApprovalForm').classList.add('hidden');
  document.querySelector('#adminApprovalWaiting').classList.remove('hidden');
}

async function checkAdminApprovalStatus({ quiet = false } = {}) {
  const requestId = state.adminApprovalRequestId || adminApprovalPending()?.id;
  if (!requestId) return false;
  const payload = await api(`/api/v1/admin-approval/status/${encodeURIComponent(requestId)}`, {
    headers: {}
  });
  if (payload.status === 'approved') {
    success(payload);
    return true;
  }
  if (['rejected', 'expired', 'failed'].includes(payload.status)) {
    clearAdminApprovalPending();
    document.querySelector('#adminApprovalWaiting').classList.add('hidden');
    document.querySelector('#adminApprovalForm').classList.remove('hidden');
    showNotice(payload.decisionMessage || payload.error || t('Admin approval request was not approved.'), 'error');
    return true;
  }
  saveAdminApprovalPending(payload);
  showAdminApprovalWaiting(payload);
  if (!quiet) showNotice(t('Your request is still waiting for administrator approval.'), 'info');
  return false;
}

function startAdminApprovalPolling() {
  if (adminApprovalPollTimer) return;
  adminApprovalPollTimer = setInterval(() => {
    checkAdminApprovalStatus({ quiet: true }).catch(() => {});
  }, 5000);
}

function restoreAdminApprovalPending() {
  const pending = adminApprovalPending();
  if (!pending) return false;
  activateMethod('admin-approval');
  showAdminApprovalWaiting(pending);
  startAdminApprovalPolling();
  showNotice(t('Your request is waiting for administrator approval.'), 'info');
  checkAdminApprovalStatus({ quiet: true }).catch(() => {});
  return true;
}

function activateMethod(method) {
  document.querySelectorAll('.tab').forEach(tab =>
    tab.classList.toggle('active', tab.dataset.tab === method)
  );
  document.querySelectorAll('.panel').forEach(panel =>
    panel.classList.toggle('active', panel.dataset.panel === method)
  );
}

function configureNviForm() {
  const smsCode = Boolean(state.config?.nviSendSmsCode);
  const phoneGroup = document.querySelector('#nviPhoneGroup');
  const phoneInput = document.querySelector('#nviPhone');
  const submitButton = document.querySelector('#nviSubmitButton');
  phoneGroup.classList.toggle('hidden', !smsCode);
  phoneInput.required = smsCode;
  submitButton.textContent = t(smsCode ? 'Verify identity and send SMS code' : 'Verify identity and connect');
}

function telegramBotName(botUrl) {
  try {
    const username = new URL(botUrl).pathname.replace(/^\/+/u, '').split('/')[0];
    return username ? `@${username}` : '';
  } catch {
    return '';
  }
}

function showTelegramVerification(pending, { focus = false } = {}) {
  if (!pending?.challengeId) return;
  state.telegramChallengeId = pending.challengeId;
  const botName = telegramBotName(pending.botUrl || '');
  const botNameElement = document.querySelector('#telegramBotName');
  botNameElement.textContent = botName ? t('Telegram bot: {bot}', { bot: botName }) : '';
  botNameElement.classList.toggle('hidden', !botName);
  document.querySelector('#telegramStartCommand').textContent = pending.startCommand || '';
  document.querySelector('#telegramManualStart').classList.toggle('hidden', !pending.startCommand);
  document.querySelector('#telegramForm').classList.add('hidden');
  document.querySelector('#telegramVerifyForm').classList.remove('hidden');
  document.querySelector('#telegramDestination').textContent =
    t('Open the Telegram bot and share the phone number registered to {phone}.', {
      phone: pending.maskedPhone || ''
    });
  if (focus) document.querySelector('#telegramCode').focus();
}

function restoreTelegramPending() {
  const pending = telegramPending();
  if (!pending) return false;
  activateMethod('telegram');
  showTelegramVerification(pending);
  showNotice(t('Telegram verification is still waiting. Enter the code sent by the bot.'), 'info');
  return true;
}

function telegramContinueUrl(challengeId) {
  const url = new URL(location.href);
  url.searchParams.set('telegram_challenge', challengeId);
  return `${url.pathname}${url.search}${url.hash}`;
}

function setTelegramChallengeUrl(challengeId) {
  if (!challengeId || !history.replaceState) return;
  history.replaceState(null, '', telegramContinueUrl(challengeId));
}

function clearTelegramChallengeUrl() {
  if (!history.replaceState || !new URLSearchParams(location.search).has('telegram_challenge')) return;
  const url = new URL(location.href);
  url.searchParams.delete('telegram_challenge');
  history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
}

async function resumeTelegramFromUrl() {
  if (!telegramChallengeParam) return false;
  const existing = telegramPending();
  if (existing?.challengeId === telegramChallengeParam) {
    activateMethod('telegram');
    showTelegramVerification(existing);
    showNotice(t('Telegram verification is still waiting. Enter the code sent by the bot.'), 'info');
    return true;
  }
  try {
    const payload = await api(`/api/v1/telegram/resume/${encodeURIComponent(telegramChallengeParam)}`, {
      headers: {}
    });
    const pending = saveTelegramPending(payload);
    activateMethod('telegram');
    showTelegramVerification(pending);
    showNotice(t('Telegram verification is still waiting. Enter the code sent by the bot.'), 'info');
    return true;
  } catch {
    clearTelegramPending();
    showNotice(t('Telegram verification expired. Start again.'), 'error');
    return false;
  }
}

async function resumeTelegramFromCurrentClient() {
  try {
    const payload = await api('/api/v1/telegram/current?optional=1', { headers: {} });
    if (!payload.challengeId) return false;
    const pending = saveTelegramPending(payload);
    activateMethod('telegram');
    showTelegramVerification(pending);
    showNotice(t('Telegram verification is still waiting. Enter the code sent by the bot.'), 'info');
    return true;
  } catch {
    return false;
  }
}

async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {}
  const textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.append(textarea);
  textarea.select();
  try {
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    textarea.remove();
  }
}

function openTelegramBot(event) {
  event.preventDefault();
  const pending = telegramPending();
  if (pending) showTelegramVerification(pending);
  const command = document.querySelector('#telegramStartCommand').textContent.trim();
  if (!command) return;
  copyText(command).then(copied => {
    showNotice(t(copied
      ? 'Telegram command copied. Open Telegram manually and send it to the bot.'
      : 'Copy this command and send it to the Telegram bot.'
    ), 'info');
  });
}

for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => {
    clearNotice();
    activateMethod(tab.dataset.tab);
  });
}

const voucherCodeInput = document.querySelector('#voucherCode');
voucherCodeInput.addEventListener('input', () => formatVoucherInput(voucherCodeInput));

const nviTcknInput = document.querySelector('#nviTckn');
const nviBirthYearInput = document.querySelector('#nviBirthYear');
nviTcknInput.addEventListener('input', () => {
  nviTcknInput.value = digits(nviTcknInput.value, 11);
});
nviBirthYearInput.addEventListener('input', () => {
  nviBirthYearInput.value = digits(nviBirthYearInput.value, 4);
});

document.querySelector('#voucherForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  clearNotice();
  setBusy(form, true);
  try {
    voucherCodeInput.value = formatVoucherCode(voucherCodeInput.value);
    const code = voucherCodeInput.value;
    success(await api('/api/v1/voucher/redeem', {
      method: 'POST', body: JSON.stringify({ code, ...commonPayload() })
    }));
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    setBusy(form, false);
  }
});

document.querySelector('#adminApprovalForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  clearNotice();
  setBusy(form, true);
  try {
    const fullName = document.querySelector('#adminApprovalFullName').value;
    const contact = document.querySelector('#adminApprovalContact').value;
    const countryCode = document.querySelector('#adminApprovalCountryCode').value;
    const payload = await api('/api/v1/admin-approval/request', {
      method: 'POST',
      body: JSON.stringify({ fullName, contact, countryCode, ...commonPayload() })
    });
    const pending = saveAdminApprovalPending(payload);
    showAdminApprovalWaiting(pending);
    startAdminApprovalPolling();
    showNotice(t('Your request is waiting for administrator approval.'), 'info');
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    setBusy(form, false);
  }
});

document.querySelector('#adminApprovalCheck').addEventListener('click', () => {
  checkAdminApprovalStatus().catch(error => showNotice(error.message, 'error'));
});

document.querySelector('#adminApprovalNew').addEventListener('click', () => {
  clearAdminApprovalPending();
  document.querySelector('#adminApprovalWaiting').classList.add('hidden');
  document.querySelector('#adminApprovalForm').classList.remove('hidden');
  clearNotice();
  document.querySelector('#adminApprovalFullName').focus();
});

document.querySelector('#emailRequestForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  clearNotice();
  setBusy(form, true);
  try {
    const email = document.querySelector('#email').value;
    const payload = await api('/api/v1/email/request', {
      method: 'POST', body: JSON.stringify({ email, ...commonPayload() })
    });
    state.emailChallengeId = payload.challengeId;
    form.classList.add('hidden');
    document.querySelector('#emailVerifyForm').classList.remove('hidden');
    showNotice(t('The verification code was sent to your email address.'), 'info');
    document.querySelector('#emailCode').focus();
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    setBusy(form, false);
  }
});

document.querySelector('#emailVerifyForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  clearNotice();
  setBusy(form, true);
  try {
    const code = document.querySelector('#emailCode').value;
    success(await api('/api/v1/email/verify', {
      method: 'POST', body: JSON.stringify({ challengeId: state.emailChallengeId, code })
    }));
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    setBusy(form, false);
  }
});

document.querySelector('#nviForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  clearNotice();
  setBusy(form, true);
  try {
    const payload = await api('/api/v1/nvi/request', {
      method: 'POST',
      body: JSON.stringify({
        tckn: document.querySelector('#nviTckn').value,
        firstName: document.querySelector('#nviFirstName').value,
        lastName: document.querySelector('#nviLastName').value,
        birthYear: document.querySelector('#nviBirthYear').value,
        ...phonePayload('#nviPhone', '#nviCountryCode'),
        ...commonPayload()
      })
    });
    if (!payload.challengeId) {
      success(payload);
      return;
    }
    state.nviChallengeId = payload.challengeId;
    form.classList.add('hidden');
    document.querySelector('#nviVerifyForm').classList.remove('hidden');
    document.querySelector('#nviDestination').textContent =
      t('NVI verification succeeded. The SMS code was sent to {phone}.', { phone: payload.maskedPhone });
    document.querySelector('#nviCode').focus();
    showNotice(t('Enter the SMS code to complete T.C. identity verification.'), 'info');
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    setBusy(form, false);
  }
});

document.querySelector('#nviVerifyForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  clearNotice();
  setBusy(form, true);
  try {
    const code = document.querySelector('#nviCode').value;
    success(await api('/api/v1/nvi/verify', {
      method: 'POST',
      body: JSON.stringify({ challengeId: state.nviChallengeId, code })
    }));
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    setBusy(form, false);
  }
});

document.querySelector('#nviResend').addEventListener('click', () => {
  document.querySelector('#nviVerifyForm').classList.add('hidden');
  document.querySelector('#nviForm').classList.remove('hidden');
  document.querySelector('#nviForm').requestSubmit();
});

document.querySelector('#nviChangeIdentity').addEventListener('click', () => {
  state.nviChallengeId = '';
  document.querySelector('#nviCode').value = '';
  document.querySelector('#nviVerifyForm').classList.add('hidden');
  document.querySelector('#nviForm').classList.remove('hidden');
  clearNotice();
  document.querySelector('#nviTckn').focus();
});

document.querySelector('#whatsappForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  clearNotice();
  setBusy(form, true);
  try {
    const payload = await api('/api/v1/whatsapp/request', {
      method: 'POST', body: JSON.stringify({ ...phonePayload('#phone', '#whatsappCountryCode'), ...commonPayload() })
    });
    state.whatsappChallengeId = payload.challengeId;
    form.classList.add('hidden');
    document.querySelector('#whatsappVerifyForm').classList.remove('hidden');
    document.querySelector('#whatsappDestination').textContent =
      t('{phone} received a WhatsApp verification code.', { phone: payload.maskedPhone });
    document.querySelector('#whatsappCode').focus();
    showNotice(t('The code was sent through WhatsApp and is valid for 10 minutes.'), 'info');
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    setBusy(form, false);
  }
});

document.querySelector('#whatsappVerifyForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  clearNotice();
  setBusy(form, true);
  try {
    const code = document.querySelector('#whatsappCode').value;
    success(await api('/api/v1/whatsapp/verify', {
      method: 'POST',
      body: JSON.stringify({ challengeId: state.whatsappChallengeId, code })
    }));
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    setBusy(form, false);
  }
});

document.querySelector('#whatsappResend').addEventListener('click', () => {
  document.querySelector('#whatsappVerifyForm').classList.add('hidden');
  document.querySelector('#whatsappForm').classList.remove('hidden');
  document.querySelector('#whatsappForm').requestSubmit();
});

document.querySelector('#whatsappChangeNumber').addEventListener('click', () => {
  state.whatsappChallengeId = '';
  document.querySelector('#whatsappCode').value = '';
  document.querySelector('#whatsappVerifyForm').classList.add('hidden');
  document.querySelector('#whatsappForm').classList.remove('hidden');
  clearNotice();
  document.querySelector('#phone').focus();
});

document.querySelector('#telegramBotLink').addEventListener('click', openTelegramBot);

document.querySelector('#telegramForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  clearNotice();
  setBusy(form, true);
  try {
    const payload = await api('/api/v1/telegram/request', {
      method: 'POST', body: JSON.stringify({ ...phonePayload('#telegramPhone', '#telegramCountryCode'), ...commonPayload() })
    });
    showTelegramVerification(saveTelegramPending(payload, payload.maskedPhone), { focus: true });
    showNotice(t('After sharing your Telegram phone number with the bot, enter the code sent in Telegram.'), 'info');
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    setBusy(form, false);
  }
});

document.querySelector('#telegramVerifyForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  clearNotice();
  setBusy(form, true);
  try {
    const code = document.querySelector('#telegramCode').value;
    const challengeId = state.telegramChallengeId || telegramPending()?.challengeId;
    if (!challengeId) throw new Error(t('Start Telegram verification again.'));
    success(await api('/api/v1/telegram/verify', {
      method: 'POST',
      body: JSON.stringify({ challengeId, code })
    }));
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    setBusy(form, false);
  }
});

document.querySelector('#telegramResend').addEventListener('click', () => {
  document.querySelector('#telegramVerifyForm').classList.add('hidden');
  document.querySelector('#telegramForm').classList.remove('hidden');
  document.querySelector('#telegramForm').requestSubmit();
});

document.querySelector('#telegramChangeNumber').addEventListener('click', () => {
  state.telegramChallengeId = '';
  clearTelegramPending();
  document.querySelector('#telegramCode').value = '';
  document.querySelector('#telegramStartCommand').textContent = '';
  document.querySelector('#telegramManualStart').classList.add('hidden');
  document.querySelector('#telegramVerifyForm').classList.add('hidden');
  document.querySelector('#telegramForm').classList.remove('hidden');
  clearNotice();
  document.querySelector('#telegramPhone').focus();
});

document.querySelector('#telegramCopyStart')?.addEventListener('click', async () => {
  const command = document.querySelector('#telegramStartCommand').textContent.trim();
  if (!command) return;
  if (await copyText(command)) {
    showNotice(t('Telegram command copied. Open Telegram manually and send it to the bot.'), 'info');
  } else {
    showNotice(t('Copy this command and send it to the Telegram bot.'), 'info');
  }
});

document.querySelector('#smsForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  clearNotice();
  setBusy(form, true);
  try {
    const payload = await api('/api/v1/sms/request', {
      method: 'POST', body: JSON.stringify({ ...phonePayload('#smsPhone', '#smsCountryCode'), ...commonPayload() })
    });
    state.smsChallengeId = payload.challengeId;
    form.classList.add('hidden');
    document.querySelector('#smsVerifyForm').classList.remove('hidden');
    document.querySelector('#smsDestination').textContent =
      t('{phone} received an SMS verification code.', { phone: payload.maskedPhone });
    document.querySelector('#smsCode').focus();
    showNotice(t('The SMS code was sent.'), 'info');
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    setBusy(form, false);
  }
});

document.querySelector('#smsVerifyForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  clearNotice();
  setBusy(form, true);
  try {
    const code = document.querySelector('#smsCode').value;
    success(await api('/api/v1/sms/verify', {
      method: 'POST',
      body: JSON.stringify({ challengeId: state.smsChallengeId, code })
    }));
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    setBusy(form, false);
  }
});

document.querySelector('#smsResend').addEventListener('click', () => {
  document.querySelector('#smsVerifyForm').classList.add('hidden');
  document.querySelector('#smsForm').classList.remove('hidden');
  document.querySelector('#smsForm').requestSubmit();
});

document.querySelector('#smsChangeNumber').addEventListener('click', () => {
  state.smsChallengeId = '';
  document.querySelector('#smsCode').value = '';
  document.querySelector('#smsVerifyForm').classList.add('hidden');
  document.querySelector('#smsForm').classList.remove('hidden');
  clearNotice();
  document.querySelector('#smsPhone').focus();
});

countryCodeSearch?.addEventListener('input', renderCountryCodeOptions);

countryCodeSearch?.addEventListener('keydown', event => {
  if (event.key === 'Enter') {
    const firstOption = countryCodeList?.querySelector('[data-country-code-option]');
    if (!firstOption) return;
    event.preventDefault();
    selectCountryCode(firstOption.dataset.countryCodeOption);
  }
  if (event.key === 'ArrowDown') {
    const firstOption = countryCodeList?.querySelector('[data-country-code-option]');
    if (!firstOption) return;
    event.preventDefault();
    firstOption.focus();
  }
});

countryCodeList?.addEventListener('click', event => {
  const option = event.target.closest?.('[data-country-code-option]');
  if (!option || !countryCodeList.contains(option)) return;
  selectCountryCode(option.dataset.countryCodeOption);
});

countryCodeList?.addEventListener('keydown', event => {
  const option = event.target.closest?.('[data-country-code-option]');
  if (!option) return;
  const options = [...countryCodeList.querySelectorAll('[data-country-code-option]')];
  const index = options.indexOf(option);
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    selectCountryCode(option.dataset.countryCodeOption);
  }
  if (event.key === 'ArrowDown') {
    event.preventDefault();
    (options[index + 1] || options[0])?.focus();
  }
  if (event.key === 'ArrowUp') {
    event.preventDefault();
    (options[index - 1] || options[options.length - 1])?.focus();
  }
});

document.querySelectorAll('[data-country-code-close]').forEach(element => {
  element.addEventListener('click', () => closeCountryCodeModal());
});

document.addEventListener('pointerdown', event => {
  if (!countryCodePopoverIsOpen()) return;
  if (countryCodeModal.contains(event.target) || activeCountryCodeTrigger?.contains(event.target)) return;
  closeCountryCodeModal({ restoreFocus: false });
});

document.addEventListener('keydown', event => {
  if (!countryCodePopoverIsOpen()) return;
  if (event.key === 'Escape') closeCountryCodeModal();
});

window.addEventListener('resize', () => {
  if (countryCodePopoverIsOpen()) positionCountryCodePopover();
});

document.addEventListener('scroll', () => {
  if (countryCodePopoverIsOpen()) positionCountryCodePopover();
}, true);

document.querySelector('#languageSelect').addEventListener('change', event => {
  i18n.setLanguage(event.target.value);
});

document.addEventListener('gh:language', () => {
  document.querySelector('#languageSelect').value = i18n.language;
  renderProjectAttribution();
  syncCountryCodeControls();
  if (countryCodeModal && !countryCodeModal.classList.contains('hidden')) {
    renderCountryCodeOptions();
  }
  configureNviForm();
  if (state.config) {
    renderPortalTexts();
    renderClientInfo();
    const pending = telegramPending();
    if (pending && !document.querySelector('#telegramVerifyForm')?.classList.contains('hidden')) {
      showTelegramVerification(pending);
    }
  }
});

(async function init() {
  try {
    await i18n.ready;
    state.config = await api('/api/v1/config', { headers: {} });
    await loadProjectAttribution();
    if (!clientMac) clientMac = normalizeMac(state.config.clientMac);
    window.GH_TERMS?.init({ config: state.config });
    await i18n.setAutomaticLanguage(state.config.defaultLanguage || 'en');
    document.querySelector('#languageSelect').value = i18n.language;
    document.querySelector('#appName').textContent = state.config.appName;
    renderPortalTexts();
    setBrandLogo(state.config);
    document.title = state.config.appName;
    renderClientInfo();
    populateCountryCodeSelects();
    configureNviForm();
    resolveClientMacInBackground();
    const enabledMethods = {
      voucher: state.config.voucherEnabled,
      'admin-approval': state.config.adminApprovalEnabled,
      email: state.config.emailEnabled,
      nvi: state.config.nviEnabled,
      whatsapp: state.config.whatsappEnabled,
      telegram: state.config.telegramEnabled,
      sms: state.config.smsEnabled
    };
    for (const [method, enabled] of Object.entries(enabledMethods)) {
      document.querySelector(`[data-tab="${method}"]`)?.classList.toggle('hidden', !enabled);
      document.querySelector(`[data-panel="${method}"]`)?.classList.toggle('method-disabled', !enabled);
    }
    const firstEnabled = Object.keys(enabledMethods).find(method => enabledMethods[method]);
    activateMethod(firstEnabled);
    if (!enabledMethods.telegram) clearTelegramPending();
    if (!enabledMethods['admin-approval']) clearAdminApprovalPending();
    if (!firstEnabled) showNotice(t('No verification method is currently available.'), 'error');

    const activeSession = await fetch(sessionProbePath(), { cache: 'no-store' });
    if (activeSession.ok) {
      const payload = await activeSession.json().catch(() => ({}));
      if (payload.active !== false) {
        location.replace('/session');
        return;
      }
    }
    const restoredTelegram = enabledMethods.telegram &&
      (await resumeTelegramFromUrl() || restoreTelegramPending() || await resumeTelegramFromCurrentClient());
    const restoredAdminApproval = !restoredTelegram &&
      enabledMethods['admin-approval'] &&
      restoreAdminApprovalPending();
    if (!restoredTelegram && !restoredAdminApproval && firstEnabled && state.config.gatewayMode === 'mock') {
      showNotice(t('Test mode is active. Verification will not open a real OPNsense session.'), 'info');
    }
    i18n.reveal();
  } catch (error) {
    showNotice(t('Portal configuration could not be loaded: {error}', { error: error.message }), 'error');
    i18n.reveal();
  }
})();
