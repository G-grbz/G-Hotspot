import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  getClientIp,
  isTrustedProxyRequest,
  normalizeTrustedProxyCidrs,
  serveStatic
} from '../src/lib/http.js';

test('trusted proxy CIDRs are validated and normalized', () => {
  assert.equal(
    normalizeTrustedProxyCidrs('127.0.0.1; 10.0.0.0/8\n::1/128'),
    '127.0.0.1/32,10.0.0.0/8,::1/128'
  );
  assert.throws(() => normalizeTrustedProxyCidrs('not-an-ip'), /Invalid trusted proxy address/u);
  assert.throws(() => normalizeTrustedProxyCidrs('10.0.0.0/99'), /Invalid trusted proxy CIDR prefix/u);
});

test('forwarded client IP is accepted only from an explicitly trusted proxy', () => {
  const trusted = {
    socket: { remoteAddress: '10.20.30.40' },
    headers: { 'x-forwarded-for': '203.0.113.25, 10.20.30.40' }
  };
  assert.equal(isTrustedProxyRequest(trusted, true, '10.20.30.0/24'), true);
  assert.equal(getClientIp(trusted, true, '10.20.30.0/24'), '203.0.113.25');

  const untrusted = {
    socket: { remoteAddress: '10.20.31.40' },
    headers: { 'x-forwarded-for': '127.0.0.1' }
  };
  assert.equal(isTrustedProxyRequest(untrusted, true, '10.20.30.0/24'), false);
  assert.equal(getClientIp(untrusted, true, '10.20.30.0/24'), '10.20.31.40');
  assert.equal(getClientIp(trusted, false, '10.20.30.0/24'), '10.20.30.40');
});

test('static CSP is self-contained and grants ipify only to admin assets', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-csp-'));
  fs.mkdirSync(path.join(directory, 'admin'));
  fs.writeFileSync(path.join(directory, 'index.html'), '<!doctype html><title>portal</title>');
  fs.writeFileSync(path.join(directory, 'admin', 'index.html'), '<!doctype html><title>admin</title>');

  function responseCapture() {
    return {
      statusCode: null,
      headers: {},
      writeHead(statusCode, headers) {
        this.statusCode = statusCode;
        this.headers = headers;
      },
      end() {}
    };
  }

  try {
    const portal = responseCapture();
    assert.equal(serveStatic(portal, directory, '/'), true);
    const portalCsp = portal.headers['content-security-policy'];
    assert.match(portalCsp, /script-src 'self'/u);
    assert.match(portalCsp, /script-src-attr 'none'/u);
    assert.match(portalCsp, /object-src 'none'/u);
    assert.match(portalCsp, /connect-src 'self'/u);
    assert.doesNotMatch(portalCsp, /fonts\.googleapis|fonts\.gstatic|api\.ipify/u);

    const admin = responseCapture();
    assert.equal(serveStatic(admin, directory, '/admin/index.html'), true);
    assert.match(admin.headers['content-security-policy'], /connect-src 'self' https:\/\/api\.ipify\.org/u);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
