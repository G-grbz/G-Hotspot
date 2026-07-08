import { deflateRawSync } from 'node:zlib';

export const OPNSENSE_TEMPLATE_DEFAULTS = Object.freeze({
  lang: 'en',
  title: 'Redirecting',
  refreshSeconds: 3,
  targetUrl: 'http://172.16.2.2:8080/',
  redirectText: 'Redirecting to the guest network portal…',
  linkText: 'Continue to G-Hotspot',
  noscriptText: 'JavaScript is disabled. Use the link above to continue.'
});

const CRC32_TABLE = new Uint32Array(256).map((_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});

function templateError(message, code = 'invalid_opnsense_template') {
  const error = new Error(message);
  error.code = code;
  return error;
}

function textValue(value, fallback, { max = 500, trim = true } = {}) {
  const text = String(value ?? '');
  const normalized = trim ? text.trim() : text;
  return (normalized || fallback).slice(0, max);
}

function normalizeLang(value) {
  const lang = textValue(value, OPNSENSE_TEMPLATE_DEFAULTS.lang, { max: 35 }).toLowerCase();
  if (!/^[a-z]{2,8}(?:-[a-z0-9]{1,8})*$/u.test(lang)) {
    throw templateError('Enter a valid HTML language code.', 'invalid_template_language');
  }
  return lang;
}

function normalizeRefreshSeconds(value) {
  const seconds = Number(value ?? OPNSENSE_TEMPLATE_DEFAULTS.refreshSeconds);
  if (!Number.isFinite(seconds)) {
    throw templateError('Enter a valid redirect delay.', 'invalid_template_delay');
  }
  return Math.min(60, Math.max(0, Math.trunc(seconds)));
}

function normalizeTargetUrl(value) {
  const raw = textValue(value, OPNSENSE_TEMPLATE_DEFAULTS.targetUrl, { max: 2048 });
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw templateError('Enter a valid redirect URL.', 'invalid_template_url');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw templateError('Redirect URL must start with http:// or https://.', 'invalid_template_url');
  }
  return url.toString();
}

export function normalizeOpnsenseTemplateOptions(input = {}) {
  return {
    lang: normalizeLang(input.lang),
    title: textValue(input.title, OPNSENSE_TEMPLATE_DEFAULTS.title, { max: 120 }),
    refreshSeconds: normalizeRefreshSeconds(input.refreshSeconds),
    targetUrl: normalizeTargetUrl(input.targetUrl),
    redirectText: textValue(input.redirectText, OPNSENSE_TEMPLATE_DEFAULTS.redirectText),
    linkText: textValue(input.linkText, OPNSENSE_TEMPLATE_DEFAULTS.linkText, { max: 200 }),
    noscriptText: textValue(input.noscriptText, OPNSENSE_TEMPLATE_DEFAULTS.noscriptText)
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

export function renderOpnsenseTemplateHtml(input = {}) {
  const options = normalizeOpnsenseTemplateOptions(input);
  const targetScriptValue = JSON.stringify(options.targetUrl);
  return `<!doctype html>
<html lang="${escapeHtml(options.lang)}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="${options.refreshSeconds};url=${escapeHtml(options.targetUrl)}">
  <title>${escapeHtml(options.title)}</title>
</head>
<body>
<p>${escapeHtml(options.redirectText)}</p>
<p><a href="${escapeHtml(options.targetUrl)}">${escapeHtml(options.linkText)}</a></p>
<script>
  (function () {
    var target = ${targetScriptValue};
    var query = window.location.search || '';
    var hash = window.location.hash || '';
    window.location.replace(target + query + hash);
  }());
</script>
<noscript><p>${escapeHtml(options.noscriptText)}</p></noscript>
</body>
</html>
`;
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function dosTimeDate(date = new Date()) {
  const year = Math.max(1980, date.getFullYear());
  const time =
    (date.getHours() << 11) |
    (date.getMinutes() << 5) |
    Math.floor(date.getSeconds() / 2);
  const dosDate =
    ((year - 1980) << 9) |
    ((date.getMonth() + 1) << 5) |
    date.getDate();
  return { time, date: dosDate };
}

export function createZipArchive(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  const { time, date } = dosTimeDate();

  for (const entry of entries) {
    const name = Buffer.from(String(entry.name || '').replace(/^\/+/u, ''), 'utf8');
    if (!name.length) throw templateError('ZIP entry name is required.', 'invalid_zip_entry');
    const data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(String(entry.data ?? ''), 'utf8');
    const compressed = deflateRawSync(data, { level: 9 });
    const checksum = crc32(data);

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0x0800, 6);
    localHeader.writeUInt16LE(8, 8);
    localHeader.writeUInt16LE(time, 10);
    localHeader.writeUInt16LE(date, 12);
    localHeader.writeUInt32LE(checksum, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(data.length, 22);
    localHeader.writeUInt16LE(name.length, 26);
    localHeader.writeUInt16LE(0, 28);

    localParts.push(localHeader, name, compressed);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0x0800, 8);
    centralHeader.writeUInt16LE(8, 10);
    centralHeader.writeUInt16LE(time, 12);
    centralHeader.writeUInt16LE(date, 14);
    centralHeader.writeUInt32LE(checksum, 16);
    centralHeader.writeUInt32LE(compressed.length, 20);
    centralHeader.writeUInt32LE(data.length, 24);
    centralHeader.writeUInt16LE(name.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    centralHeader.writeUInt32LE(offset, 42);
    centralParts.push(centralHeader, name);

    offset += localHeader.length + name.length + compressed.length;
  }

  const centralDirectory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralDirectory, end]);
}

export function createOpnsenseTemplateZip(input = {}) {
  const html = renderOpnsenseTemplateHtml(input);
  return {
    filename: 'opnsense-captiveportal-template.zip',
    html,
    buffer: createZipArchive([{ name: 'index.html', data: html }])
  };
}
