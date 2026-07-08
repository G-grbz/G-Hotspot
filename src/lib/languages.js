import fs from 'node:fs';
import path from 'node:path';

const FALLBACK_CODES = ['en', 'tr'];
let cachedCodes = null;

export function availableLanguageCodes() {
  if (cachedCodes) return [...cachedCodes];
  try {
    const manifestPath = path.resolve('public/i18n/languages.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const codes = Array.isArray(manifest)
      ? manifest
        .map(item => String(item?.code || '').trim().toLowerCase())
        .filter(code => /^[a-z]{2,8}$/u.test(code))
      : [];
    cachedCodes = [...new Set(codes.length ? codes : FALLBACK_CODES)];
    if (!cachedCodes.includes('en')) cachedCodes.unshift('en');
  } catch {
    cachedCodes = FALLBACK_CODES;
  }
  return [...cachedCodes];
}

export function normalizeLanguage(value, fallback = 'en') {
  const codes = availableLanguageCodes();
  const language = String(value || '').trim().toLowerCase().split(/[-_,;]/u)[0];
  const normalizedFallback = codes.includes(fallback) ? fallback : 'en';
  return codes.includes(language) ? language : normalizedFallback;
}
