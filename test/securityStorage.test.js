import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { hashPassword, verifyPassword, verifyPasswordAsync } from '../src/lib/security.js';
import { readSystemSettings, writeSystemSettings } from '../src/system.js';

test('admin passwords use scrypt and verify without storing plaintext', async () => {
  const encoded = hashPassword('correct horse battery staple');
  assert.match(encoded, /^scrypt\$v=1\$/u);
  assert.equal(verifyPassword('correct horse battery staple', encoded), true);
  assert.equal(verifyPassword('wrong password', encoded), false);
  assert.equal(await verifyPasswordAsync('correct horse battery staple', encoded), true);
  assert.equal(await verifyPasswordAsync('wrong password', encoded), false);
});

test('system.db encrypts secrets at rest and hashes legacy admin password writes', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-secure-store-'));
  const dbPath = path.join(directory, 'system.db');
  try {
    writeSystemSettings({
      APP_SECRET: 'app-secret-that-is-longer-than-thirty-two-characters',
      ADMIN_PASSWORD: 'a-strong-admin-password',
      SMTP_PASS: 'mail-password-secret',
      ILETIMERKEZI_API_KEY: 'provider-api-key',
      CUSTOM_SMS_HEADERS_JSON: '{"Authorization":"Bearer hidden-token"}',
      APP_NAME: 'Visible value'
    }, dbPath);

    const rawDb = new DatabaseSync(dbPath);
    const raw = Object.fromEntries(rawDb.prepare('SELECT key, value FROM settings').all().map(row => [row.key, row.value]));
    rawDb.close();

    assert.equal(Object.hasOwn(raw, 'ADMIN_PASSWORD'), false);
    assert.match(raw.ADMIN_PASSWORD_HASH, /^scrypt\$v=1\$/u);
    assert.notEqual(raw.ADMIN_PASSWORD_HASH, 'a-strong-admin-password');
    assert.match(raw.APP_SECRET, /^enc:v1:/u);
    assert.match(raw.SMTP_PASS, /^enc:v1:/u);
    assert.match(raw.ILETIMERKEZI_API_KEY, /^enc:v1:/u);
    assert.match(raw.CUSTOM_SMS_HEADERS_JSON, /^enc:v1:/u);
    assert.equal(raw.APP_NAME, 'Visible value');
    assert.equal(JSON.stringify(raw).includes('mail-password-secret'), false);
    assert.equal(JSON.stringify(raw).includes('hidden-token'), false);

    const settings = readSystemSettings(dbPath);
    assert.equal(settings.APP_SECRET, 'app-secret-that-is-longer-than-thirty-two-characters');
    assert.equal(settings.SMTP_PASS, 'mail-password-secret');
    assert.equal(settings.ILETIMERKEZI_API_KEY, 'provider-api-key');
    assert.equal(settings.CUSTOM_SMS_HEADERS_JSON, '{"Authorization":"Bearer hidden-token"}');
    assert.equal(verifyPassword('a-strong-admin-password', settings.ADMIN_PASSWORD_HASH), true);

    const keyFile = path.join(directory, '.system-key');
    assert.equal(fs.existsSync(keyFile), true);
    assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600);
    assert.equal(fs.statSync(dbPath).mode & 0o777, 0o600);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('legacy plaintext secrets are migrated and removed from SQLite storage', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-secret-migration-'));
  const dbPath = path.join(directory, 'system.db');
  const legacyPassword = 'legacy-admin-password-123';
  const legacyAppSecret = 'legacy-app-secret-that-is-definitely-long-enough';
  const legacySmtpPassword = 'legacy-mail-password';
  try {
    const legacyDb = new DatabaseSync(dbPath);
    legacyDb.exec(`
      PRAGMA journal_mode=WAL;
      CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      ) STRICT;
    `);
    const insert = legacyDb.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)');
    insert.run('ADMIN_PASSWORD', legacyPassword, Date.now());
    insert.run('APP_SECRET', legacyAppSecret, Date.now());
    insert.run('SMTP_PASS', legacySmtpPassword, Date.now());
    legacyDb.close();

    const migrated = readSystemSettings(dbPath);
    assert.equal(Object.hasOwn(migrated, 'ADMIN_PASSWORD'), false);
    assert.equal(verifyPassword(legacyPassword, migrated.ADMIN_PASSWORD_HASH), true);
    assert.equal(migrated.APP_SECRET, legacyAppSecret);
    assert.equal(migrated.SMTP_PASS, legacySmtpPassword);

    for (const name of fs.readdirSync(directory)) {
      const filePath = path.join(directory, name);
      if (!fs.statSync(filePath).isFile()) continue;
      const bytes = fs.readFileSync(filePath);
      assert.equal(bytes.includes(Buffer.from(legacyPassword)), false, `${name} still contains legacy admin password`);
      assert.equal(bytes.includes(Buffer.from(legacyAppSecret)), false, `${name} still contains legacy APP_SECRET`);
      assert.equal(bytes.includes(Buffer.from(legacySmtpPassword)), false, `${name} still contains legacy SMTP password`);
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
