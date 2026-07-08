import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {
  accessExpiry,
  grantAccess,
  normalizeActiveAuthorizationDurations,
  reverificationState
} from '../src/services/access.js';
import { HotspotDatabase } from '../src/db.js';

async function waitForRequest(requests, predicate, timeoutMs = 500) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const match = requests.find(predicate);
    if (match) return match;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  return requests.find(predicate);
}

test('access durations support hours, days, months, years and unlimited', () => {
  const now = Date.UTC(2026, 0, 15, 12, 0, 0);
  assert.equal(accessExpiry({ value: 24, unit: 'hours' }, now).expiresAt,
    Date.UTC(2026, 0, 16, 12, 0, 0));
  assert.equal(accessExpiry({ value: 15, unit: 'minutes' }, now).expiresAt,
    Date.UTC(2026, 0, 15, 12, 15, 0));
  assert.equal(accessExpiry({ value: 2, unit: 'days' }, now).expiresAt,
    Date.UTC(2026, 0, 17, 12, 0, 0));
  assert.equal(accessExpiry({ value: 1, unit: 'months' }, now).expiresAt,
    Date.UTC(2026, 1, 15, 12, 0, 0));
  assert.equal(accessExpiry({ value: 1, unit: 'years' }, now).expiresAt,
    Date.UTC(2027, 0, 15, 12, 0, 0));
  assert.equal(accessExpiry({ value: 1, unit: 'unlimited' }, now).unlimited, true);
});

test('reverification limits support finite and permanent lockouts', () => {
  const verifiedAt = Date.UTC(2026, 0, 15, 12, 0, 0);
  assert.deepEqual(
    reverificationState({ value: 1, unit: 'days' }, verifiedAt, verifiedAt + 12 * 3600000),
    {
      allowed: false,
      retryAt: Date.UTC(2026, 0, 16, 12, 0, 0),
      permanent: false
    }
  );
  assert.equal(
    reverificationState({ value: 1, unit: 'days' }, verifiedAt, verifiedAt + 25 * 3600000).allowed,
    true
  );
  assert.deepEqual(
    reverificationState({ value: 1, unit: 'unlimited' }, verifiedAt, verifiedAt + 10 * 365 * 86400000),
    { allowed: false, retryAt: null, permanent: true }
  );
});

test('active authorization durations follow the current configured method duration', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-duration-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const createdAt = Date.UTC(2026, 6, 5, 10, 58, 0);
  const staleExpiresAt = createdAt + 730 * 24 * 60 * 60 * 1000;
  try {
    const authorization = db.saveAuthorization({
      method: 'admin-approval',
      identity: 'Guest User',
      clientIp: '172.16.2.103',
      clientMac: '28:16:7F:27:46:71',
      gatewayMode: 'mock',
      gatewaySessionId: 'mock-session',
      status: 'active',
      expiresAt: staleExpiresAt,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    db.db.prepare(`
      UPDATE authorizations
      SET created_at=?, expires_at=?, lease_seconds=?
      WHERE id=?
    `).run(createdAt, staleExpiresAt, 730 * 24 * 60 * 60, authorization.id);

    const result = normalizeActiveAuthorizationDurations(db, {
      adminApproval: {
        accessDuration: { value: 1, unit: 'hours' }
      }
    });
    const updated = db.getAuthorization(authorization.id);

    assert.equal(result.checked, 1);
    assert.equal(result.updated, 1);
    assert.equal(Number(updated.expires_at), createdAt + 60 * 60 * 1000);
    assert.equal(Number(updated.unlimited), 0);
    assert.equal(Number(updated.lease_seconds), 60 * 60);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('grantAccess refuses new sessions when syslog cannot be written', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-gate-'));
  try {
    const db = {
      recordLaw5651Event() {
        throw new Error('database is read-only');
      }
    };
    await assert.rejects(
      grantAccess({
        db,
        config: {
          law5651: {
            enabled: true,
            exportDirectory: directory,
            storageAlertPercent: 85,
            storageBlockPercent: 100
          },
          gateway: { mode: 'mock' }
        },
        method: 'voucher',
        identity: 'voucher-1',
        clientIp: '192.168.10.20',
        clientMac: '',
        duration: { value: 1, unit: 'hours' },
        redirectUrl: ''
      }),
      error => error.code === 'syslog_unavailable' && /not writable/u.test(error.message)
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('OPNsense access stores the DHCP or ARP owner MAC instead of the captive portal response MAC', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    requests.push({ method: request.method, url: request.url, body });
    if (request.url === '/api/captiveportal/session/connect/1') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        sessionId: 'session-1',
        ipAddress: '172.16.3.3',
        macAddress: '28:16:7f:27:46:71'
      }));
      return;
    }
    if (request.url === '/api/diagnostics/interface/get_arp') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/dhcpv4/leases/searchLease') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [
          {
            if: 'wifiap',
            address: '172.16.3.3',
            mac: '36:90:70:af:4d:b0',
            state: 'assigned'
          }
        ]
      }));
      return;
    }
    if (request.url === '/api/kea/dhcpv4/searchSubnet') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [{ uuid: 'subnet-1', subnet: '172.16.3.0/24' }] }));
      return;
    }
    if (request.url === '/api/kea/dhcpv4/searchOption') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/kea/dhcpv4/addOption') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ result: 'saved', uuid: 'option-1' }));
      return;
    }
    if (request.url === '/api/kea/dhcpv4/searchReservation') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/kea/dhcpv4/addReservation') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ result: 'saved', uuid: 'reservation-1' }));
      return;
    }
    if (request.url === '/api/kea/service/reconfigure') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ status: 'ok' }));
      return;
    }
    response.writeHead(404);
    response.end();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const result = await grantAccess({
      db,
      config: {
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          zoneMap: [{ network: '172.16.3.0/24', zoneId: 1 }],
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true,
          keaLeaseSyncEnabled: true
        }
      },
      method: 'email',
      identity: 'gkhn.gurbuz@hotmail.com',
      clientIp: '172.16.3.3',
      clientMac: '',
      duration: { value: 2, unit: 'days' },
      redirectUrl: ''
    });
    const authorization = db.getAuthorization(result.authorizationId);
    const connect = requests.find(item => item.url === '/api/captiveportal/session/connect/1');
    const leaseOption = await waitForRequest(requests, item => item.url === '/api/kea/dhcpv4/addOption');
    const reservation = await waitForRequest(requests, item => item.url === '/api/kea/dhcpv4/addReservation');
    await waitForRequest(requests, item => item.url === '/api/kea/service/reconfigure');

    assert.equal(result.clientMac, '36:90:70:AF:4D:B0');
    assert.equal(authorization.client_ip, '172.16.3.3');
    assert.equal(authorization.client_mac, '36:90:70:AF:4D:B0');
    assert.equal(authorization.gateway_session_id, '1:session-1');
    assert.deepEqual(Object.fromEntries(new URLSearchParams(connect.body)), {
      user: 'email:gkhn.gurbuz@hotmail.com',
      ip: '172.16.3.3'
    });
    assert.equal(JSON.parse(leaseOption.body).option.data, '172800');
    assert.equal(JSON.parse(reservation.body).reservation.option, 'option-1');
    assert.equal(
      JSON.parse(reservation.body).reservation.hostname,
      'gh-email-gkhn-gurbuz-hotmail-com'
    );
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('OPNsense access disconnects a conflicting authorization before granting access on a reused IP', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    requests.push({ method: request.method, url: request.url, body });
    if (request.url === '/api/captiveportal/session/connect/1') {
      const params = Object.fromEntries(new URLSearchParams(body));
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        sessionId: 'new-session',
        ipAddress: params.ip
      }));
      return;
    }
    if (request.url === '/api/captiveportal/session/disconnect/1') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ status: 'ok' }));
      return;
    }
    if (request.url === '/api/diagnostics/interface/get_arp') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/dhcpv4/leases/searchLease') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [
          { address: '172.16.3.3', mac: '28:16:7f:27:46:71', state: 'assigned' }
        ]
      }));
      return;
    }
    response.writeHead(404);
    response.end();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const existing = db.saveAuthorization({
      method: 'email',
      identity: 'guest@example.com',
      clientIp: '172.16.3.3',
      clientMac: '36:90:70:AF:4D:B0',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:old-session',
      status: 'active',
      expiresAt: Date.now() + 3600000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    const result = await grantAccess({
      db,
      config: {
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          zoneMap: [{ network: '172.16.3.0/24', zoneId: 1 }],
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true
        }
      },
      method: 'sms',
      identity: '905551112233',
      clientIp: '172.16.3.3',
      clientMac: '',
      duration: { value: 24, unit: 'hours' },
      redirectUrl: ''
    });
    const stale = db.getAuthorization(existing.id);
    const granted = db.getAuthorization(result.authorizationId);
    const connectRequests = requests.filter(item => item.url === '/api/captiveportal/session/connect/1');
    const disconnect = requests.find(item => item.url === '/api/captiveportal/session/disconnect/1');

    assert.equal(stale.client_ip, '172.16.3.3');
    assert.equal(stale.client_mac, '36:90:70:AF:4D:B0');
    assert.equal(stale.gateway_session_id, null);
    assert.equal(stale.disconnect_reason, null);
    assert.equal(stale.ended_at, null);
    assert.equal(granted.client_ip, '172.16.3.3');
    assert.equal(granted.client_mac, '28:16:7F:27:46:71');
    assert.equal(granted.gateway_session_id, '1:new-session');
    assert.deepEqual(connectRequests.map(item => Object.fromEntries(new URLSearchParams(item.body))), [
      { user: 'sms:905551112233', ip: '172.16.3.3' }
    ]);
    assert.deepEqual(Object.fromEntries(new URLSearchParams(disconnect.body)), {
      sessionId: 'old-session'
    });
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('OPNsense access resynchronizes Kea reservation when an existing authorization is reused', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    requests.push({ method: request.method, url: request.url, body });
    if (request.url === '/api/diagnostics/interface/get_arp') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/dhcpv4/leases/searchLease') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{ address: '172.16.3.2', mac: '28:16:7f:27:46:71', state: 'assigned' }]
      }));
      return;
    }
    if (request.url === '/api/captiveportal/session/connect/1') {
      const params = Object.fromEntries(new URLSearchParams(body));
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        sessionId: 'restored-session',
        ipAddress: params.ip,
        macAddress: '28:16:7F:27:46:71'
      }));
      return;
    }
    if (request.url === '/api/kea/dhcpv4/searchSubnet') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [{ uuid: 'subnet-1', subnet: '172.16.3.0/24' }] }));
      return;
    }
    if (request.url === '/api/kea/dhcpv4/searchOption') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/kea/dhcpv4/addOption') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ result: 'saved', uuid: 'option-1' }));
      return;
    }
    if (request.url === '/api/kea/dhcpv4/searchReservation') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/kea/dhcpv4/addReservation') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ result: 'saved', uuid: 'reservation-1' }));
      return;
    }
    if (request.url === '/api/kea/service/reconfigure') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ status: 'ok' }));
      return;
    }
    response.writeHead(404);
    response.end();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const authorization = db.saveAuthorization({
      method: 'voucher',
      identity: 'voucher-1',
      clientIp: '172.16.3.2',
      clientMac: '28:16:7F:27:46:71',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: null,
      status: 'active',
      expiresAt: Date.now() + 45500_000,
      leaseSeconds: 172800,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });

    const result = await grantAccess({
      db,
      config: {
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          zoneMap: [{ network: '172.16.3.0/24', zoneId: 1 }],
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true,
          keaLeaseSyncEnabled: true
        }
      },
      method: 'voucher',
      identity: 'voucher-1',
      clientIp: '172.16.3.2',
      clientMac: '',
      duration: { value: 2, unit: 'days' },
      redirectUrl: ''
    });
    const leaseOption = await waitForRequest(requests, item => item.url === '/api/kea/dhcpv4/addOption');
    const reservation = await waitForRequest(requests, item => item.url === '/api/kea/dhcpv4/addReservation');
    await waitForRequest(requests, item => item.url === '/api/kea/service/reconfigure');

    assert.equal(result.authorizationId, authorization.id);
    assert.equal(db.getAuthorization(authorization.id).gateway_session_id, '1:restored-session');
    assert.equal(JSON.parse(leaseOption.body).option.data, '172800');
    assert.equal(JSON.parse(reservation.body).reservation.ip_address, '172.16.3.2');
    assert.equal(requests.some(item => item.url === '/api/captiveportal/session/connect/1'), true);
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
