import fs from 'node:fs';
import path from 'node:path';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { readEnvFile } from './lib/env.js';
import { hashPassword, isPasswordHash } from './lib/security.js';

const DEFAULT_SYSTEM_DATABASE_PATH = './data/system.db';
const INSTALL_FLAG = 'installed';
const ENCRYPTION_PREFIX = 'enc:v1:';
const MASTER_KEY_BYTES = 32;
const NON_PERSISTED_ENV_KEYS = new Set([
  'SYSTEM_ENCRYPTION_KEY',
  'SYSTEM_ENCRYPTION_KEY_FILE',
  'SYSTEM_DATABASE_PATH',
  'SETUP_TOKEN',
  'INSTALL_SETUP_TOKEN'
]);
const SECRET_SETTING_KEYS = new Set([
  'APP_SECRET',
  'OPNSENSE_API_KEY',
  'OPNSENSE_API_SECRET',
  'SYSLOG_KAMUSM_PASSWORD',
  'SYSLOG_TIMESTAMP_API_KEY',
  'SYSLOG_TIMESTAMP_HEADERS_JSON',
  'NVI_PASSWORD',
  'SMTP_PASS',
  'WHATSAPP_ACCESS_TOKEN',
  'WHATSAPP_VERIFY_TOKEN',
  'META_APP_SECRET',
  'TELEGRAM_BOT_TOKEN',
  'TELEGRAM_WEBHOOK_SECRET',
  'NETGSM_PASSWORD',
  'ILETIMERKEZI_API_KEY',
  'ILETIMERKEZI_API_SECRET',
  'TWILIO_AUTH_TOKEN',
  'CUSTOM_SMS_AUTHORIZATION',
  'CUSTOM_SMS_HEADERS_JSON'
]);

function now() {
  return Date.now();
}

function normalizeKey(value) {
  return String(value || '').trim();
}

function chmodPrivate(filePath) {
  for (const target of [filePath, `${filePath}-wal`, `${filePath}-shm`]) {
    try {
      if (fs.existsSync(target)) fs.chmodSync(target, 0o600);
    } catch {}
  }
}

function encryptionKeyFile(filePath) {
  const configured = String(process.env.SYSTEM_ENCRYPTION_KEY_FILE || '').trim();
  return configured
    ? path.resolve(configured)
    : path.join(path.dirname(path.resolve(filePath)), '.system-key');
}

function parseMasterKey(value, sourceName) {
  const text = String(value || '').trim();
  if (!text) return null;
  if (text.length < 32) throw new Error(`${sourceName} must contain at least 32 characters`);
  return createHash('sha256').update(text, 'utf8').digest();
}

function readOrCreateMasterKey(filePath) {
  const configured = parseMasterKey(process.env.SYSTEM_ENCRYPTION_KEY, 'SYSTEM_ENCRYPTION_KEY');
  if (configured) return configured;

  const keyFile = encryptionKeyFile(filePath);
  fs.mkdirSync(path.dirname(keyFile), { recursive: true });
  if (fs.existsSync(keyFile)) {
    chmodPrivate(keyFile);
    const raw = String(fs.readFileSync(keyFile, 'utf8') || '').trim();
    let decoded;
    try {
      decoded = Buffer.from(raw, 'base64url');
    } catch {
      decoded = Buffer.alloc(0);
    }
    if (decoded.length !== MASTER_KEY_BYTES) {
      throw new Error(`Invalid system encryption key file: ${keyFile}`);
    }
    return decoded;
  }

  const key = randomBytes(MASTER_KEY_BYTES);
  try {
    fs.writeFileSync(keyFile, `${key.toString('base64url')}\n`, { mode: 0o600, flag: 'wx' });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    const raw = String(fs.readFileSync(keyFile, 'utf8') || '').trim();
    const decoded = Buffer.from(raw, 'base64url');
    if (decoded.length !== MASTER_KEY_BYTES) throw new Error(`Invalid system encryption key file: ${keyFile}`);
    return decoded;
  }
  chmodPrivate(keyFile);
  return key;
}

function isEncryptedValue(value) {
  return String(value || '').startsWith(ENCRYPTION_PREFIX);
}

function encryptSettingValue(key, value, filePath) {
  const plaintext = String(value ?? '');
  if (!SECRET_SETTING_KEYS.has(key) || !plaintext || isEncryptedValue(plaintext)) return plaintext;
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', readOrCreateMasterKey(filePath), nonce);
  cipher.setAAD(Buffer.from(key, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${ENCRYPTION_PREFIX}${nonce.toString('base64url')}:${tag.toString('base64url')}:${ciphertext.toString('base64url')}`;
}

function decryptSettingValue(key, value, filePath) {
  const encoded = String(value ?? '');
  if (!isEncryptedValue(encoded)) return encoded;
  const parts = encoded.slice(ENCRYPTION_PREFIX.length).split(':');
  if (parts.length !== 3) throw new Error(`Encrypted setting ${key} has an invalid format`);
  const [nonceText, tagText, ciphertextText] = parts;
  try {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      readOrCreateMasterKey(filePath),
      Buffer.from(nonceText, 'base64url')
    );
    decipher.setAAD(Buffer.from(key, 'utf8'));
    decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
    return Buffer.concat([
      decipher.update(Buffer.from(ciphertextText, 'base64url')),
      decipher.final()
    ]).toString('utf8');
  } catch {
    throw new Error(`Could not decrypt system setting ${key}. Check SYSTEM_ENCRYPTION_KEY or the system key file.`);
  }
}

function openSystemDatabase(filePath = systemDatabasePath()) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const db = new DatabaseSync(filePath, { timeout: 5000 });
  db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON;');
  chmodPrivate(filePath);
  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT;
  `);
  const sensitiveSettingsMigrated = migrateSensitiveSettings(db, filePath);
  if (sensitiveSettingsMigrated) {
    db.exec('PRAGMA wal_checkpoint(TRUNCATE); VACUUM;');
  }
  chmodPrivate(filePath);
  return db;
}

function readRows(db, table, filePath) {
  return Object.fromEntries(
    db.prepare(`SELECT key, value FROM ${table}`).all().map(row => [
      row.key,
      table === 'settings' ? decryptSettingValue(row.key, row.value, filePath) : row.value
    ])
  );
}

function writeRows(db, table, values, filePath) {
  const statement = db.prepare(`
    INSERT INTO ${table} (key, value, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET
      value = excluded.value,
      updated_at = excluded.updated_at
  `);
  const timestamp = now();
  for (const [rawKey, rawValue] of Object.entries(values || {})) {
    let key = normalizeKey(rawKey);
    if (!key) continue;
    let value = String(rawValue ?? '');
    if (table === 'settings' && key === 'ADMIN_PASSWORD') {
      key = 'ADMIN_PASSWORD_HASH';
      value = isPasswordHash(value) ? value : hashPassword(value);
    }
    if (table === 'settings') value = encryptSettingValue(key, value, filePath);
    statement.run(key, value, timestamp);
  }
}

function migrateSensitiveSettings(db, filePath) {
  const rows = db.prepare('SELECT key, value FROM settings').all();
  if (!rows.length) return false;
  const timestamp = now();
  const update = db.prepare('UPDATE settings SET value=?, updated_at=? WHERE key=?');
  const insert = db.prepare(`
    INSERT INTO settings (key, value, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
  `);
  const remove = db.prepare('DELETE FROM settings WHERE key=?');
  const existingPasswordHash = rows.find(row => row.key === 'ADMIN_PASSWORD_HASH')?.value || '';
  let migrated = false;
  db.exec('BEGIN IMMEDIATE');
  try {
    for (const row of rows) {
      if (row.key === 'ADMIN_PASSWORD') {
        if (String(row.value || '') && !isPasswordHash(existingPasswordHash)) {
          const passwordHash = isPasswordHash(row.value) ? row.value : hashPassword(row.value);
          insert.run('ADMIN_PASSWORD_HASH', passwordHash, timestamp);
        }
        remove.run('ADMIN_PASSWORD');
        migrated = true;
        continue;
      }
      if (SECRET_SETTING_KEYS.has(row.key) && row.value && !isEncryptedValue(row.value)) {
        update.run(encryptSettingValue(row.key, row.value, filePath), timestamp, row.key);
        migrated = true;
      }
    }
    db.exec('COMMIT');
    return migrated;
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    throw error;
  }
}

export function systemDatabasePath() {
  return path.resolve(process.env.SYSTEM_DATABASE_PATH || DEFAULT_SYSTEM_DATABASE_PATH);
}

export function readSystemSettings(filePath = systemDatabasePath()) {
  const db = openSystemDatabase(filePath);
  try {
    return readRows(db, 'settings', filePath);
  } finally {
    db.close();
  }
}

export function readSystemMeta(filePath = systemDatabasePath()) {
  const db = openSystemDatabase(filePath);
  try {
    return readRows(db, 'meta', filePath);
  } finally {
    db.close();
  }
}

export function writeSystemSettings(changes, filePath = systemDatabasePath()) {
  const db = openSystemDatabase(filePath);
  try {
    db.exec('BEGIN IMMEDIATE');
    writeRows(db, 'settings', changes, filePath);
    db.exec('COMMIT');
    chmodPrivate(filePath);
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    throw error;
  } finally {
    db.close();
  }
}

export function deleteSystemSettings(keys, filePath = systemDatabasePath()) {
  const db = openSystemDatabase(filePath);
  try {
    db.exec('BEGIN IMMEDIATE');
    const statement = db.prepare('DELETE FROM settings WHERE key=?');
    for (const key of keys || []) statement.run(normalizeKey(key));
    db.exec('COMMIT');
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    throw error;
  } finally {
    db.close();
  }
}

export function replaceSystemSettings(values, filePath = systemDatabasePath()) {
  const db = openSystemDatabase(filePath);
  try {
    db.exec('BEGIN IMMEDIATE');
    db.exec('DELETE FROM settings');
    writeRows(db, 'settings', values, filePath);
    db.exec('COMMIT');
    chmodPrivate(filePath);
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    throw error;
  } finally {
    db.close();
  }
}

export function writeSystemMeta(values, filePath = systemDatabasePath()) {
  const db = openSystemDatabase(filePath);
  try {
    db.exec('BEGIN IMMEDIATE');
    writeRows(db, 'meta', values, filePath);
    db.exec('COMMIT');
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    throw error;
  } finally {
    db.close();
  }
}

export function replaceSystemMeta(values, filePath = systemDatabasePath()) {
  const db = openSystemDatabase(filePath);
  try {
    db.exec('BEGIN IMMEDIATE');
    db.exec('DELETE FROM meta');
    writeRows(db, 'meta', values, filePath);
    db.exec('COMMIT');
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    throw error;
  } finally {
    db.close();
  }
}

export function markSystemInstalled(filePath = systemDatabasePath()) {
  writeSystemMeta({ [INSTALL_FLAG]: 'true' }, filePath);
}

export function isSystemInstalled(filePath = systemDatabasePath()) {
  const settings = readSystemSettings(filePath);
  const meta = readSystemMeta(filePath);
  return meta[INSTALL_FLAG] === 'true' ||
    (String(settings.APP_SECRET || process.env.APP_SECRET || '').length >= 32 &&
      Boolean(String(settings.ADMIN_PASSWORD_HASH || settings.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD_HASH || process.env.ADMIN_PASSWORD || '').trim()));
}

export function importEnvToSystemIfNeeded({
  envPath = path.resolve('.env'),
  filePath = systemDatabasePath()
} = {}) {
  const settings = readSystemSettings(filePath);
  const meta = readSystemMeta(filePath);
  if (meta[INSTALL_FLAG] === 'true' || Object.keys(settings).length) return false;

  const envValues = readEnvFile(envPath);
  if (fs.existsSync(envPath)) {
    try { fs.chmodSync(envPath, 0o600); } catch {}
  }
  const appSecret = String(envValues.APP_SECRET || process.env.APP_SECRET || '');
  const adminPasswordHash = String(envValues.ADMIN_PASSWORD_HASH || process.env.ADMIN_PASSWORD_HASH || '');
  const adminPassword = String(envValues.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD || '');
  if (appSecret.length < 32 || (!adminPasswordHash && !adminPassword.trim())) return false;

  const values = Object.keys(envValues).length ? { ...envValues } : Object.fromEntries(
    Object.entries(process.env).filter(([key]) =>
      /^[A-Z][A-Z0-9_]*$/u.test(key) && !NON_PERSISTED_ENV_KEYS.has(key)
    )
  );
  for (const key of NON_PERSISTED_ENV_KEYS) delete values[key];
  values.ADMIN_PASSWORD_HASH = isPasswordHash(adminPasswordHash)
    ? adminPasswordHash
    : hashPassword(adminPassword);
  delete values.ADMIN_PASSWORD;
  const db = openSystemDatabase(filePath);
  try {
    db.exec('BEGIN IMMEDIATE');
    writeRows(db, 'settings', values, filePath);
    writeRows(db, 'meta', { [INSTALL_FLAG]: 'true', imported_from_env: 'true' }, filePath);
    db.exec('COMMIT');
    return true;
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    throw error;
  } finally {
    db.close();
  }
}

export function loadSystemSettingsIntoEnv({
  preserveKeys = [],
  importEnv = true,
  filePath = systemDatabasePath()
} = {}) {
  if (importEnv) importEnvToSystemIfNeeded({ filePath });
  const preserve = new Set(preserveKeys);
  const settings = readSystemSettings(filePath);
  for (const [key, value] of Object.entries(settings)) {
    if (preserve.has(key)) continue;
    process.env[key] = value;
  }
  if (settings.ADMIN_PASSWORD_HASH && !preserve.has('ADMIN_PASSWORD')) delete process.env.ADMIN_PASSWORD;
  return {
    installed: isSystemInstalled(filePath),
    settings
  };
}
