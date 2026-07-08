import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  markSystemInstalled,
  writeSystemSettings
} from '../src/system.js';

const projectRoot = path.resolve(import.meta.dirname, '..');
const configUrl = pathToFileURL(path.join(projectRoot, 'src/config.js')).href;
let importCounter = 0;

function restoreEnv(snapshot) {
  for (const key of Object.keys(process.env)) {
    if (!Object.hasOwn(snapshot, key)) delete process.env[key];
  }
  for (const [key, value] of Object.entries(snapshot)) {
    process.env[key] = value;
  }
}

async function importConfigIn(directory) {
  const previousCwd = process.cwd();
  const previousEnv = { ...process.env };
  try {
    process.chdir(directory);
    const m = await import(`${configUrl}?case=${importCounter++}`);
    return {
      installRequired: m.config.installRequired,
      appName: m.config.appName,
      smtpConfigured: m.config.smtp.configured
    };
  } finally {
    process.chdir(previousCwd);
    restoreEnv(previousEnv);
  }
}

function createInstalledSystemDatabase(directory) {
  const dbPath = path.join(directory, 'data/system.db');
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  writeSystemSettings({
    APP_NAME: 'Database App',
    APP_SECRET: 'x'.repeat(32),
    ADMIN_PASSWORD: 'admin-password'
  }, dbPath);
  markSystemInstalled(dbPath);
}

test('installed system starts from system.db without .env', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-system-'));
  try {
    createInstalledSystemDatabase(directory);
    const config = await importConfigIn(directory);
    assert.equal(config.installRequired, false);
    assert.equal(config.appName, 'Database App');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('installed system ignores .env at runtime', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-system-'));
  try {
    createInstalledSystemDatabase(directory);
    fs.writeFileSync(path.join(directory, '.env'), [
      'SMTP_HOST=smtp.example.com',
      'SMTP_USER=owner@example.com',
      ''
    ].join('\n'));
    const config = await importConfigIn(directory);
    assert.equal(config.installRequired, false);
    assert.equal(config.appName, 'Database App');
    assert.equal(config.smtpConfigured, false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
