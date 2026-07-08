import { createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

const VOUCHER_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
const TOKEN_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
export const COUNTRY_CALLING_CODES = Object.freeze([
  '1', '7', '20', '27', '30', '31', '32', '33', '34', '36', '39', '40', '41', '43', '44', '45',
  '46', '47', '48', '49', '51', '52', '53', '54', '55', '56', '57', '58', '60', '61', '62',
  '63', '64', '65', '66', '81', '82', '84', '86', '90', '91', '92', '93', '94', '95', '98',
  '211', '212', '213', '216', '218', '220', '221', '222', '223', '224', '225', '226', '227',
  '228', '229', '230', '231', '232', '233', '234', '235', '236', '237', '238', '239', '240',
  '241', '242', '243', '244', '245', '246', '248', '249', '250', '251', '252', '253', '254',
  '255', '256', '257', '258', '260', '261', '262', '263', '264', '265', '266', '267', '268',
  '269', '290', '291', '297', '298', '299', '350', '351', '352', '353', '354', '355', '356',
  '357', '358', '359', '370', '371', '372', '373', '374', '375', '376', '377', '378', '379',
  '380', '381', '382', '383', '385', '386', '387', '389', '420', '421', '423', '500', '501',
  '502', '503', '504', '505', '506', '507', '508', '509', '590', '591', '592', '593', '594',
  '595', '596', '597', '598', '599', '670', '672', '673', '674', '675', '676', '677', '678',
  '679', '680', '681', '682', '683', '685', '686', '687', '688', '689', '690', '691', '692',
  '850', '852', '853', '855', '856', '880', '886', '960', '961', '962', '963', '964', '965',
  '966', '967', '968', '970', '971', '972', '973', '974', '975', '976', '977', '992', '993',
  '994', '995', '996', '998'
]);

export function keyedHash(secret, value) {
  return createHmac('sha256', secret).update(String(value), 'utf8').digest('hex');
}

export function safeEqualHex(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  if (left.length !== right.length) return false;
  if (!/^[0-9a-f]+$/iu.test(left) || !/^[0-9a-f]+$/iu.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

export function generateOtp() {
  return String(randomInt(100000, 1000000));
}

export function generateToken(length = 8, alphabet = TOKEN_ALPHABET) {
  let output = '';
  for (let index = 0; index < length; index += 1) {
    output += alphabet[randomInt(0, alphabet.length)];
  }
  return output;
}

export function generateVoucherCode() {
  return `${generateToken(4, VOUCHER_ALPHABET)}-${generateToken(4, VOUCHER_ALPHABET)}-${generateToken(4, VOUCHER_ALPHABET)}`;
}

export function generateSecret(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

export function normalizeVoucher(value) {
  return String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

export function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/u.test(value) && value.length <= 254;
}

export function normalizeCountryCode(value) {
  return String(value || '').replace(/\D/g, '').slice(0, 3);
}

export function normalizePhone(value, defaultCountryCode = '90') {
  let digits = String(value || '').replace(/\D/g, '');
  if (digits.startsWith('00')) digits = digits.slice(2);
  if (digits.startsWith('0')) digits = `${defaultCountryCode}${digits.slice(1)}`;
  else if (digits.length === 10 && defaultCountryCode) digits = `${defaultCountryCode}${digits}`;
  return digits;
}

export function normalizePhoneForCountry(value, countryCode = '90') {
  const raw = String(value || '').trim();
  const code = normalizeCountryCode(countryCode);
  let digits = raw.replace(/\D/g, '');
  if (!code) return normalizePhone(raw, '');
  const hasInternationalPrefix = /^\s*(?:\+|00)/u.test(raw);
  if (digits.startsWith('00')) digits = digits.slice(2);
  if (hasInternationalPrefix) return digits.startsWith(code) ? digits : '';
  if (digits.startsWith(code) && digits.length > code.length + 4) return digits;
  if (digits.startsWith('0')) digits = digits.replace(/^0+/u, '');
  return `${code}${digits}`;
}

export function normalizeTckn(value) {
  return String(value || '').replace(/\D/g, '').slice(0, 11);
}

export function normalizeMac(value) {
  const parts = String(value || '').match(/[0-9a-f]{2}/giu);
  return parts?.length === 6 ? parts.map(part => part.toUpperCase()).join(':') : '';
}

export function isValidPhone(value) {
  return /^\d{10,15}$/u.test(value);
}

export function isValidPhoneForCountry(value, defaultCountryCode = '90') {
  const phone = String(value || '');
  const countryCode = normalizeCountryCode(defaultCountryCode);
  return isValidPhone(phone) && (!countryCode || phone.startsWith(countryCode));
}

export function isKnownCountryCode(value) {
  return COUNTRY_CALLING_CODES.includes(normalizeCountryCode(value));
}

export function isAllowedCountryCode(value, allowedCountryCodes = []) {
  const countryCode = normalizeCountryCode(value);
  const allowed = [...new Set((allowedCountryCodes || []).map(normalizeCountryCode).filter(Boolean))];
  return isKnownCountryCode(countryCode) && (allowed.length === 0 || allowed.includes(countryCode));
}

export function isValidTckn(value) {
  const digits = normalizeTckn(value);
  if (!/^[1-9]\d{10}$/u.test(digits)) return false;
  const numbers = [...digits].map(Number);
  const oddSum = numbers[0] + numbers[2] + numbers[4] + numbers[6] + numbers[8];
  const evenSum = numbers[1] + numbers[3] + numbers[5] + numbers[7];
  const tenth = ((oddSum * 7) - evenSum) % 10;
  if (tenth !== numbers[9]) return false;
  const firstTen = numbers.slice(0, 10).reduce((sum, number) => sum + number, 0);
  return firstTen % 10 === numbers[10];
}

export function sanitizeRedirectUrl(value) {
  if (!value) return '';
  try {
    const url = new URL(String(value));
    return ['http:', 'https:'].includes(url.protocol) ? url.toString() : '';
  } catch {
    return '';
  }
}

export function normalizeIp(value) {
  const text = String(value || '').trim();
  return text.startsWith('::ffff:') ? text.slice(7) : text;
}
