import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateOtp, isAllowedCountryCode, isValidEmail, isValidPhoneForCountry, isValidTckn, keyedHash,
  normalizeEmail, safeEqualHex, normalizeMac, normalizePhone, normalizePhoneForCountry, normalizeTckn,
  normalizeVoucher, sanitizeRedirectUrl
} from '../src/lib/security.js';

test('normalizers produce stable values', () => {
  assert.equal(normalizeVoucher('ab12-cd34'), 'AB12CD34');
  assert.equal(normalizeEmail('  USER@Example.COM '), 'user@example.com');
  assert.equal(normalizePhone('0532 111 22 33', '90'), '905321112233');
  assert.equal(normalizePhone('553 618 47 48', '90'), '905536184748');
  assert.equal(normalizePhoneForCountry('06 12 34 56 78', '33'), '33612345678');
  assert.equal(normalizePhoneForCountry('+1 555 123 4567', '90'), '');
  assert.equal(normalizeTckn('100 000 001 46'), '10000000146');
  assert.equal(normalizeMac('aa-bb-cc-dd-ee-ff'), 'AA:BB:CC:DD:EE:FF');
  assert.equal(normalizeMac('AA:BB:CC:DD:EE:FF'), 'AA:BB:CC:DD:EE:FF');
  assert.equal(normalizeMac('not-a-mac'), '');
});

test('phone validation follows the selected and allowed country code', () => {
  assert.equal(isValidPhoneForCountry(normalizePhone('553 618 47 48', '90'), '90'), true);
  assert.equal(isValidPhoneForCountry(normalizePhone('555 123 4567', '1'), '1'), true);
  assert.equal(isValidPhoneForCountry(normalizePhone('+1 555 123 4567', '90'), '90'), false);
  assert.equal(isValidPhoneForCountry(normalizePhone('00 1 555 123 4567', '90'), '90'), false);
  assert.equal(isAllowedCountryCode('33', ['90', '33']), true);
  assert.equal(isAllowedCountryCode('1', ['90', '33']), false);
  assert.equal(isAllowedCountryCode('1', []), true);
});

test('TCKN checksum validation', () => {
  assert.equal(isValidTckn('10000000146'), true);
  assert.equal(isValidTckn('10000000147'), false);
  assert.equal(isValidTckn('01234567890'), false);
});

test('OTP is six digits', () => {
  assert.match(generateOtp(), /^\d{6}$/u);
});

test('keyed hashes are deterministic and secret-dependent', () => {
  assert.equal(keyedHash('a', 'value'), keyedHash('a', 'value'));
  assert.notEqual(keyedHash('a', 'value'), keyedHash('b', 'value'));
  assert.equal(safeEqualHex('z'.repeat(64), 'z'.repeat(64)), false);
});

test('email and redirect validation', () => {
  assert.equal(isValidEmail('user@example.com'), true);
  assert.equal(isValidEmail('bad@'), false);
  assert.equal(sanitizeRedirectUrl('https://example.com/x'), 'https://example.com/x');
  assert.equal(sanitizeRedirectUrl('javascript:alert(1)'), '');
});
