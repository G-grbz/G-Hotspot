import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const { port } = server.address();
  await new Promise(resolve => server.close(resolve));
  return port;
}

function requestJson(port, pathname, headers = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      hostname: '127.0.0.1',
      port,
      path: pathname,
      method: 'GET',
      headers
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let body = {};
        try { body = raw ? JSON.parse(raw) : {}; } catch {}
        resolve({ statusCode: response.statusCode, headers: response.headers, raw, body });
      });
    });
    request.once('error', reject);
    request.end();
  });
}

async function waitForServer(port, child) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode != null) throw new Error(`server exited before startup with code ${child.exitCode}`);
    try {
      const response = await requestJson(port, '/api/install/status');
      if (response.statusCode === 200) return;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('server did not start in time');
}

async function stopChild(child) {
  if (child.exitCode != null) return;
  child.kill('SIGTERM');
  await Promise.race([
    new Promise(resolve => child.once('exit', resolve)),
    new Promise(resolve => setTimeout(resolve, 2000))
  ]);
  if (child.exitCode == null) child.kill('SIGKILL');
}

test('installer enforces the admin password complexity rule before advancing', () => {
  const installHtml = fs.readFileSync(path.resolve('public/install.html'), 'utf8');
  const installJs = fs.readFileSync(path.resolve('public/install.js'), 'utf8');
  const tr = JSON.parse(fs.readFileSync(path.resolve('public/i18n/tr.json'), 'utf8'));

  assert.match(installHtml, /id="adminPassword"[^>]+minlength="8"/u);
  assert.match(installJs, /const ADMIN_PASSWORD_MIN_LENGTH = 8;/u);
  assert.match(installJs, /step === 0 && !validateAdminPassword\(\)/u);
  assert.match(installJs, /adminPasswordMeetsRequirements/u);
  assert.match(installJs, /\\p\{Lu\}/u);
  assert.equal(tr['Minimum 8 characters, including one letter, one uppercase letter, and one number.'], 'En az 8 karakter; en az bir harf, bir büyük harf ve bir rakam içermelidir.');
  assert.equal(tr['Admin password must contain at least 8 characters, including one letter, one uppercase letter, and one number.'], 'Yönetici parolası en az 8 karakter olmalı; en az bir harf, bir büyük harf ve bir rakam içermelidir.');
});

test('installer APIs allow direct localhost and require setup token for remote/proxied requests', { timeout: 15000 }, async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-install-security-'));
  const port = await freePort();
  const setupToken = 'integration-setup-token-with-enough-randomness';
  let stderr = '';
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: path.resolve('.'),
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      PORT: String(port),
      SETUP_TOKEN: setupToken,
      SYSTEM_DATABASE_PATH: path.join(directory, 'system.db'),
      DATABASE_PATH: path.join(directory, 'hotspot.db')
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });

  try {
    await waitForServer(port, child);

    const localhost = await requestJson(port, '/api/install/settings');
    assert.equal(localhost.statusCode, 200);

    const installFonts = await requestJson(port, '/fonts.css', { host: `172.16.2.2:${port}` });
    assert.equal(installFonts.statusCode, 200);
    assert.match(String(installFonts.headers['content-type'] || ''), /^text\/css/u);
    assert.match(installFonts.raw, /@font-face/u);

    const installFontFile = await requestJson(port, '/fonts/inter-latin.woff2', { host: `172.16.2.2:${port}` });
    assert.equal(installFontFile.statusCode, 200);
    assert.notEqual(String(installFontFile.headers['content-type'] || ''), 'application/json');

    const lanHttpStatus = await requestJson(port, '/api/install/status', { host: `172.16.2.2:${port}` });
    assert.equal(lanHttpStatus.statusCode, 200);
    assert.equal(lanHttpStatus.headers['cross-origin-opener-policy'], undefined);

    const remoteHost = await requestJson(port, '/api/install/settings', { host: 'setup.example.invalid' });
    assert.equal(remoteHost.statusCode, 401);
    assert.equal(remoteHost.body.error, 'setup_token_required');

    const proxiedLoopback = await requestJson(port, '/api/install/settings', {
      host: `127.0.0.1:${port}`,
      'x-forwarded-for': '198.51.100.10'
    });
    assert.equal(proxiedLoopback.statusCode, 401);

    const authorizedRemote = await requestJson(port, '/api/install/settings', {
      host: 'setup.example.invalid',
      'x-setup-token': setupToken
    });
    assert.equal(authorizedRemote.statusCode, 200);
  } finally {
    await stopChild(child);
    fs.rmSync(directory, { recursive: true, force: true });
  }

  assert.equal(stderr.includes('ReferenceError'), false, stderr);
});
