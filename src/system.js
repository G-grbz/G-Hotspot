import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { readEnvFile } from './lib/env.js';

const DEFAULT_SYSTEM_DATABASE_PATH = './data/system.db';
const INSTALL_FLAG = 'installed';

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

function openSystemDatabase(filePath = systemDatabasePath()) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const db = new DatabaseSync(filePath, { timeout: 5000 });
  db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;');
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
  return db;
}

function readRows(db, table) {
  return Object.fromEntries(
    db.prepare(`SELECT key, value FROM ${table}`).all().map(row => [row.key, row.value])
  );
}

function writeRows(db, table, values) {
  const statement = db.prepare(`
    INSERT INTO ${table} (key, value, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET
      value = excluded.value,
      updated_at = excluded.updated_at
  `);
  const timestamp = now();
  for (const [rawKey, rawValue] of Object.entries(values || {})) {
    const key = normalizeKey(rawKey);
    if (!key) continue;
    statement.run(key, String(rawValue ?? ''), timestamp);
  }
}

export function systemDatabasePath() {
  return path.resolve(process.env.SYSTEM_DATABASE_PATH || DEFAULT_SYSTEM_DATABASE_PATH);
}

export function readSystemSettings(filePath = systemDatabasePath()) {
  const db = openSystemDatabase(filePath);
  try {
    return readRows(db, 'settings');
  } finally {
    db.close();
  }
}

export function readSystemMeta(filePath = systemDatabasePath()) {
  const db = openSystemDatabase(filePath);
  try {
    return readRows(db, 'meta');
  } finally {
    db.close();
  }
}

export function writeSystemSettings(changes, filePath = systemDatabasePath()) {
  const db = openSystemDatabase(filePath);
  try {
    db.exec('BEGIN IMMEDIATE');
    writeRows(db, 'settings', changes);
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
    writeRows(db, 'settings', values);
    db.exec('COMMIT');
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
    writeRows(db, 'meta', values);
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
    writeRows(db, 'meta', values);
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
      Boolean(String(settings.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD || '').trim()));
}

export function importEnvToSystemIfNeeded({
  envPath = path.resolve('.env'),
  filePath = systemDatabasePath()
} = {}) {
  const settings = readSystemSettings(filePath);
  const meta = readSystemMeta(filePath);
  if (meta[INSTALL_FLAG] === 'true' || Object.keys(settings).length) return false;

  const envValues = readEnvFile(envPath);
  const appSecret = String(envValues.APP_SECRET || process.env.APP_SECRET || '');
  const adminPassword = String(envValues.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD || '');
  if (appSecret.length < 32 || !adminPassword.trim()) return false;

  const values = Object.keys(envValues).length ? envValues : Object.fromEntries(
    Object.entries(process.env).filter(([key]) => /^[A-Z][A-Z0-9_]*$/u.test(key))
  );
  const db = openSystemDatabase(filePath);
  try {
    db.exec('BEGIN IMMEDIATE');
    writeRows(db, 'settings', values);
    writeRows(db, 'meta', { [INSTALL_FLAG]: 'true', imported_from_env: 'true' });
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
  return {
    installed: isSystemInstalled(filePath),
    settings
  };
}
