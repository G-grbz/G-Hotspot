import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {
  assertSyslogTimestampDisableAllowed,
  createAdminController,
  compareReleaseVersions,
  releaseVersion,
  publicIpCandidate
} from '../src/admin.js';
import { HotspotDatabase } from '../src/db.js';
import { quotaPeriodWindow } from '../src/services/quotas.js';

test('admin notification public IP helper ignores private addresses', () => {
  assert.equal(publicIpCandidate('172.16.2.2'), '');
  assert.equal(publicIpCandidate('192.168.1.25'), '');
  assert.equal(publicIpCandidate('10.0.0.4'), '');
  assert.equal(publicIpCandidate('203.0.113.10'), '203.0.113.10');
});

test('admin update helper reads release versions from GitHub titles', () => {
  assert.equal(releaseVersion('G-Hotspot v1.0.0'), '1.0.0');
  assert.equal(releaseVersion('release/2.4.1 notes'), '2.4.1');
  assert.equal(compareReleaseVersions('1.0.0', '0.5.3'), 1);
  assert.equal(compareReleaseVersions('1.0.0-beta.1', '1.0.0'), -1);
  assert.equal(compareReleaseVersions('1.0.0', '1.0.0'), 0);
});

test('admin blocks disabling syslog timestamping after evidence logging starts', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-admin-timestamp-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  try {
    assert.equal(assertSyslogTimestampDisableAllowed(
      { SYSLOG_TIMESTAMP_MODE: 'disabled' },
      { db, config: { syslog: { timestampMode: 'kamusm' } } }
    ), true);
    const now = Date.UTC(2026, 6, 8, 10, 0, 0);
    db.appendLaw5651Logs([{
      dedupeKey: 'admin-timestamp-disable',
      kind: 'session',
      source: 'opnsense',
      network: 'any',
      clientIp: '172.16.2.22',
      clientMac: 'aa:bb:cc:dd:ee:11',
      sourceIp: '172.16.2.22',
      destinationIp: '8.8.8.8',
      protocol: 'tcp',
      serviceType: 'internet-access',
      startedAt: now,
      createdAt: now
    }]);
    assert.throws(() => assertSyslogTimestampDisableAllowed(
      { SYSLOG_TIMESTAMP_MODE: 'disabled' },
      { db, config: { syslog: { timestampMode: 'kamusm' } } }
    ), error => error?.code === 'syslog_timestamp_disable_blocked' && error?.statusCode === 409);
    assert.equal(assertSyslogTimestampDisableAllowed(
      { SYSLOG_TIMESTAMP_MODE: 'rfc3161' },
      { db, config: { syslog: { timestampMode: 'kamusm' } } }
    ), true);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('admin expiry job disconnects expired gateway sessions', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requests.push({
      method: request.method,
      url: request.url,
      body: Buffer.concat(chunks).toString('utf8')
    });
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ status: 'ok' }));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const now = Date.UTC(2026, 5, 27, 0, 40, 0);
  try {
    const authorization = db.saveAuthorization({
      method: 'email',
      identity: 'guest@example.com',
      clientIp: '172.16.2.100',
      clientMac: '28:16:7F:27:46:71',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '3:expired-session',
      status: 'active',
      expiresAt: now - 1000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    db.saveAuthorization({
      method: 'email',
      identity: 'active@example.com',
      clientIp: '172.16.2.101',
      clientMac: '',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '3:active-session',
      status: 'active',
      expiresAt: now + 60000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });

    const admin = createAdminController({
      db,
      config: {
        appSecret: 'secret',
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true
        }
      }
    });

    const result = await admin.expireAuthorizations({ now });
    assert.equal(result.checked, 1);
    assert.equal(result.disconnected, 1);
    assert.equal(result.failed, 0);
    assert.equal(db.getAuthorization(authorization.id).disconnect_reason, 'session_expired');
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].url, '/api/captiveportal/session/disconnect/3');
    assert.deepEqual(Object.fromEntries(new URLSearchParams(requests[0].body)), {
      sessionId: 'expired-session'
    });
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('admin expiry job removes Kea reservation for an authorization ended before its access duration elapsed', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const requests = [];
  let authorizationId = '';
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requests.push({
      method: request.method,
      url: request.url,
      body: Buffer.concat(chunks).toString('utf8')
    });
    let payload = {};
    if (request.url === '/api/kea/dhcpv4/searchReservation') {
      payload = {
        rows: [{
          uuid: 'reservation-1',
          description: `G-Hotspot access ${authorizationId}`,
          ip_address: '172.16.2.100',
          hw_address: '28:16:7F:27:46:71'
        }]
      };
    } else if (request.url === '/api/kea/dhcpv4/delReservation/reservation-1') {
      payload = { result: 'deleted' };
    } else if (request.url === '/api/kea/service/reconfigure') {
      payload = { status: 'ok' };
    } else {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(payload));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const now = Date.UTC(2026, 5, 27, 0, 40, 0);
  try {
    const created = db.saveAuthorization({
      method: 'email',
      identity: 'guest@example.com',
      clientIp: '172.16.2.100',
      clientMac: '28:16:7F:27:46:71',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '3:old-session',
      status: 'active',
      expiresAt: now - 1000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    authorizationId = created.id;
    db.endAuthorization(created.id, 'session_ip_mac_mismatch');
    const admin = createAdminController({
      db,
      config: {
        appSecret: 'secret',
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true,
          keaLeaseSyncEnabled: true
        }
      }
    });

    const result = await admin.expireAuthorizations({ now });
    const authorization = db.getAuthorization(created.id);

    assert.equal(result.checked, 1);
    assert.equal(result.disconnected, 0);
    assert.equal(result.failed, 0);
    assert.ok(authorization.kea_deleted_at);
    assert.deepEqual(requests.map(item => ({ method: item.method, url: item.url })), [
      { method: 'POST', url: '/api/kea/dhcpv4/searchReservation' },
      { method: 'POST', url: '/api/kea/dhcpv4/delReservation/reservation-1' },
      { method: 'POST', url: '/api/kea/service/reconfigure' }
    ]);
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('admin sync disconnects a session when the verified IP is owned by another MAC', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    requests.push({ method: request.method, url: request.url, body });
    if (request.url === '/api/captiveportal/session/list/0') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{
          sessionId: 'old-session',
          userName: 'telegram:905536184748',
          ipAddress: '172.16.2.100',
          macAddress: '6e:8c:cf:bb:84:9b'
        }]
      }));
      return;
    }
    if (request.url === '/api/diagnostics/interface/get_arp') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [
          { ipAddress: '172.16.2.100', macAddress: '28:16:7f:27:46:71' },
          { ipAddress: '172.16.2.101', macAddress: '6e:8c:cf:bb:84:9b' }
        ]
      }));
      return;
    }
    if (request.url === '/api/captiveportal/session/connect/0') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        sessionId: 'new-session',
        ipAddress: '172.16.2.101',
        macAddress: '6E:8C:CF:BB:84:9B'
      }));
      return;
    }
    if (request.url === '/api/captiveportal/session/disconnect/0') {
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
      method: 'telegram',
      identity: '905536184748',
      clientIp: '172.16.2.100',
      clientMac: '6E:8C:CF:BB:84:9B',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: 'old-session',
      status: 'active',
      expiresAt: Date.now() + 3600000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    const admin = createAdminController({
      db,
      config: {
        appSecret: 'secret',
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true,
          keaLeaseSyncEnabled: true
        },
        syslog: { enabled: false, networks: 'any', retentionDays: 730 }
      }
    });

    const result = await admin.syncUsage();
    const updated = db.getAuthorization(authorization.id);
    const dashboard = db.dashboard();
    const connect = requests.find(item => item.url === '/api/captiveportal/session/connect/0');
    const disconnect = requests.find(item => item.url === '/api/captiveportal/session/disconnect/0');

    assert.ok(result.syncedAt);
    assert.equal(dashboard.gateway.lastSuccessfulSyncAt, result.syncedAt);
    assert.equal(result.staleIpMoved, 0);
    assert.equal(result.staleIpDisconnected, 1);
    assert.equal(updated.client_ip, '172.16.2.100');
    assert.equal(updated.gateway_session_id, null);
    assert.equal(updated.disconnect_reason, null);
    assert.equal(updated.ended_at, null);
    assert.equal(connect, undefined);
    assert.deepEqual(Object.fromEntries(new URLSearchParams(disconnect.body)), {
      sessionId: 'old-session'
    });
    assert.equal(requests.some(item => /\/api\/kea\/dhcpv4\/.*Reservation/u.test(item.url)), false);
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('admin sync disconnects a session when DHCP leases show another MAC on the verified IP', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    requests.push({ method: request.method, url: request.url, body });
    if (request.url === '/api/captiveportal/session/list/0') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/captiveportal/session/list/1') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{
          sessionId: 'old-session',
          userName: 'email:gkhn.gurbuz@hotmail.com',
          ipAddress: '172.16.3.3'
        }]
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
            address: '172.16.3.2',
            mac: 'fa:93:8f:47:d5:8b',
            hostname: 'xiaomi-13t-pro',
            state: 'assigned'
          },
          {
            if: 'wifiap',
            address: '172.16.3.3',
            mac: '28:16:7f:27:46:71',
            hostname: 'new-xiaomi',
            state: 'assigned'
          }
        ]
      }));
      return;
    }
    if (request.url === '/api/captiveportal/session/connect/1') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        sessionId: 'new-session',
        ipAddress: '172.16.3.2',
        macAddress: 'FA:93:8F:47:D5:8B'
      }));
      return;
    }
    if (request.url === '/api/captiveportal/session/disconnect/1') {
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
      method: 'email',
      identity: 'gkhn.gurbuz@hotmail.com',
      clientIp: '172.16.3.3',
      clientMac: 'FA:93:8F:47:D5:8B',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:old-session',
      status: 'active',
      expiresAt: Date.now() + 3600000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    const admin = createAdminController({
      db,
      config: {
        appSecret: 'secret',
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          zoneMap: [{ network: '172.16.3.0/24', zoneId: 1 }],
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true
        },
        syslog: { enabled: false, networks: 'any', retentionDays: 730 }
      }
    });

    const result = await admin.syncUsage();
    const updated = db.getAuthorization(authorization.id);
    const connect = requests.find(item => item.url === '/api/captiveportal/session/connect/1');
    const disconnect = requests.find(item => item.url === '/api/captiveportal/session/disconnect/1');

    assert.equal(result.staleIpMoved, 0);
    assert.equal(result.staleIpDisconnected, 1);
    assert.equal(result.dhcpLeases, 2);
    assert.equal(updated.client_ip, '172.16.3.3');
    assert.equal(updated.client_mac, 'FA:93:8F:47:D5:8B');
    assert.equal(updated.gateway_session_id, null);
    assert.equal(updated.disconnect_reason, null);
    assert.equal(updated.ended_at, null);
    assert.equal(connect, undefined);
    assert.deepEqual(Object.fromEntries(new URLSearchParams(disconnect.body)), {
      sessionId: 'old-session'
    });
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('admin sync disconnects a MAC-less session when the gateway session is on another IP', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    requests.push({ method: request.method, url: request.url, body });
    if (request.url === '/api/captiveportal/session/list/0') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/captiveportal/session/list/1') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{
          sessionId: 'old-session',
          userName: 'email:gkhn.gurbuz@hotmail.com',
          ipAddress: '172.16.2.100',
          macAddress: '28:16:7f:27:46:71'
        }]
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
          { if: 'lan', address: '172.16.2.100', mac: '28:16:7f:27:46:71', state: 'assigned' },
          { if: 'wifiap', address: '172.16.3.3', mac: '36:90:70:af:4d:b0', state: 'assigned' }
        ]
      }));
      return;
    }
    if (request.url === '/api/captiveportal/session/connect/1') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        sessionId: 'new-session',
        ipAddress: '172.16.3.3',
        macAddress: '28:16:7f:27:46:71'
      }));
      return;
    }
    if (request.url === '/api/captiveportal/session/disconnect/1') {
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
      method: 'email',
      identity: 'gkhn.gurbuz@hotmail.com',
      clientIp: '172.16.3.3',
      clientMac: '',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:old-session',
      status: 'active',
      expiresAt: Date.now() + 3600000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    const admin = createAdminController({
      db,
      config: {
        appSecret: 'secret',
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          zoneMap: [{ network: '172.16.3.0/24', zoneId: 1 }],
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true
        },
        syslog: { enabled: false, networks: 'any', retentionDays: 730 }
      }
    });

    const result = await admin.syncUsage();
    const updated = db.getAuthorization(authorization.id);
    const connect = requests.find(item => item.url === '/api/captiveportal/session/connect/1');
    const disconnect = requests.find(item => item.url === '/api/captiveportal/session/disconnect/1');

    assert.equal(result.staleIpMoved, 0);
    assert.equal(result.staleIpDisconnected, 1);
    assert.equal(updated.client_ip, '172.16.3.3');
    assert.equal(updated.client_mac, null);
    assert.equal(updated.gateway_session_id, null);
    assert.equal(updated.disconnect_reason, null);
    assert.equal(updated.ended_at, null);
    assert.equal(connect, undefined);
    assert.deepEqual(Object.fromEntries(new URLSearchParams(disconnect.body)), {
      sessionId: 'old-session'
    });
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('admin sync does not overwrite a verified MAC with a conflicting gateway row MAC', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const server = http.createServer((request, response) => {
    if (request.url === '/api/captiveportal/session/list/0') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/captiveportal/session/list/1') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{
          sessionId: 'session-1',
          userName: 'email:gkhn.gurbuz@hotmail.com',
          ipAddress: '172.16.3.3',
          macAddress: '28:16:7f:27:46:71',
          bytesIn: 2048,
          bytesOut: 4096
        }]
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
          { if: 'wifiap', address: '172.16.3.3', mac: '36:90:70:af:4d:b0', state: 'assigned' }
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
    const authorization = db.saveAuthorization({
      method: 'email',
      identity: 'gkhn.gurbuz@hotmail.com',
      clientIp: '172.16.3.3',
      clientMac: '36:90:70:AF:4D:B0',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:session-1',
      status: 'active',
      expiresAt: Date.now() + 3600000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    const admin = createAdminController({
      db,
      config: {
        appSecret: 'secret',
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          zoneMap: [{ network: '172.16.3.0/24', zoneId: 1 }],
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true
        },
        syslog: { enabled: false, networks: 'any', retentionDays: 730 }
      }
    });

    const result = await admin.syncUsage();
    const updated = db.getAuthorization(authorization.id);

    assert.equal(result.matched, 1);
    assert.equal(updated.client_ip, '172.16.3.3');
    assert.equal(updated.client_mac, '36:90:70:AF:4D:B0');
    assert.equal(updated.download_bytes, 4096);
    assert.equal(updated.upload_bytes, 2048);
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('admin sync disconnects a session when method quota is exceeded', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requests.push({
      method: request.method,
      url: request.url,
      body: Buffer.concat(chunks).toString('utf8')
    });
    if (request.url === '/api/captiveportal/session/list/0') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{
          sessionId: 'quota-session',
          userName: 'sms:905551112233',
          ipAddress: '172.16.2.44',
          macAddress: '28:16:7f:27:46:71',
          bytesIn: 1024,
          bytesOut: 2 * 1024 * 1024 * 1024
        }]
      }));
      return;
    }
    if (request.url === '/api/diagnostics/interface/get_arp') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{ ipAddress: '172.16.2.44', macAddress: '28:16:7f:27:46:71' }]
      }));
      return;
    }
    if (request.url === '/api/kea/leases4/search') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/captiveportal/session/disconnect/0') {
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
      method: 'sms',
      identity: '905551112233',
      clientIp: '172.16.2.44',
      clientMac: '28:16:7F:27:46:71',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '0:quota-session',
      status: 'active',
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    const admin = createAdminController({
      db,
      config: {
        appSecret: 'secret',
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true,
          bandwidthProfiles: {
            sms: {
              downloadSpeedMbps: 0,
              uploadSpeedMbps: 0,
              quotaPeriod: 'daily',
              downloadQuotaGb: 1,
              uploadQuotaGb: 0
            }
          }
        },
        syslog: { enabled: false, networks: 'any', retentionDays: 730, timeZone: 'UTC' }
      }
    });

    const result = await admin.syncUsage();
    const updated = db.getAuthorization(authorization.id);

    assert.equal(result.matched, 1);
    assert.equal(result.quotaDisconnected, 1);
    assert.equal(updated.ended_at, null);
    assert.equal(updated.gateway_session_id, null);
    assert.equal(updated.quota_period_key.startsWith('daily:'), true);
    assert.equal(Number(updated.quota_blocked_until) > Date.now(), true);
    assert.equal(updated.download_bytes, 2 * 1024 * 1024 * 1024);
    const disconnect = requests.find(item => item.url === '/api/captiveportal/session/disconnect/0');
    assert.equal(disconnect.method, 'POST');
    assert.deepEqual(Object.fromEntries(new URLSearchParams(disconnect.body)), {
      sessionId: 'quota-session'
    });
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('admin sync baselines reused gateway counters after quota session reverification', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  let downloadBytes = 700 * 1024 * 1024;
  let uploadBytes = 20 * 1024 * 1024;
  const server = http.createServer((request, response) => {
    if (request.url === '/api/captiveportal/session/list/0') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{
          sessionId: 'quota-session',
          userName: 'sms:905551112233',
          ipAddress: '172.16.2.44',
          macAddress: '28:16:7f:27:46:71',
          bytesIn: uploadBytes,
          bytesOut: downloadBytes
        }]
      }));
      return;
    }
    if (request.url === '/api/diagnostics/interface/get_arp') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{ ipAddress: '172.16.2.44', macAddress: '28:16:7f:27:46:71' }]
      }));
      return;
    }
    if (request.url === '/api/kea/leases4/search') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    response.writeHead(404);
    response.end();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const oldAuthorization = db.saveAuthorization({
      method: 'sms',
      identity: '905551112233',
      clientIp: '172.16.2.44',
      clientMac: '28:16:7F:27:46:71',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: 'quota-session',
      status: 'active',
      expiresAt: Date.now() - 60000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    db.endAuthorization(oldAuthorization.id, 'session_expired');

    const authorization = db.saveAuthorization({
      method: 'sms',
      identity: '905551112233',
      clientIp: '172.16.2.44',
      clientMac: '28:16:7F:27:46:71',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: 'quota-session',
      status: 'active',
      expiresAt: Date.now() + 60 * 60 * 1000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    const createdAt = Date.now();
    db.db.prepare('UPDATE authorizations SET created_at=? WHERE id=?').run(createdAt - 120000, oldAuthorization.id);
    db.db.prepare('UPDATE authorizations SET created_at=? WHERE id=?').run(createdAt, authorization.id);

    const admin = createAdminController({
      db,
      config: {
        appSecret: 'secret',
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true,
          bandwidthProfiles: {
            sms: {
              downloadSpeedMbps: 0,
              uploadSpeedMbps: 0,
              quotaPeriod: 'daily',
              downloadQuotaGb: 1,
              uploadQuotaGb: 1
            }
          }
        },
        syslog: { enabled: false, networks: 'any', retentionDays: 730, timeZone: 'UTC' }
      }
    });

    const firstSync = await admin.syncUsage();
    const firstUpdated = db.getAuthorization(authorization.id);
    const firstQuota = db.db.prepare(`
      SELECT * FROM authorization_quota_usage WHERE authorization_id=?
    `).get(authorization.id);

    assert.equal(firstSync.quotaDisconnected, 0);
    assert.equal(firstUpdated.download_bytes, 0);
    assert.equal(firstUpdated.upload_bytes, 0);
    assert.equal(firstQuota.download_bytes, 0);
    assert.equal(firstQuota.upload_bytes, 0);
    assert.equal(firstQuota.last_gateway_download_bytes, downloadBytes);
    assert.equal(firstQuota.last_gateway_upload_bytes, uploadBytes);
    assert.ok(Number(firstQuota.reset_at) > 0);

    const downloadDelta = 128 * 1024 * 1024;
    const uploadDelta = 8 * 1024 * 1024;
    downloadBytes += downloadDelta;
    uploadBytes += uploadDelta;

    const secondSync = await admin.syncUsage();
    const secondUpdated = db.getAuthorization(authorization.id);
    const secondQuota = db.db.prepare(`
      SELECT * FROM authorization_quota_usage WHERE authorization_id=?
    `).get(authorization.id);

    assert.equal(secondSync.quotaDisconnected, 0);
    assert.equal(secondUpdated.download_bytes, downloadDelta);
    assert.equal(secondUpdated.upload_bytes, uploadDelta);
    assert.equal(secondQuota.download_bytes, downloadDelta);
    assert.equal(secondQuota.upload_bytes, uploadDelta);
    assert.equal(secondQuota.last_gateway_download_bytes, downloadBytes);
    assert.equal(secondQuota.last_gateway_upload_bytes, uploadBytes);
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('admin quota reset preserves lifetime session traffic totals', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const baselineDownload = 900 * 1024 * 1024;
  const baselineUpload = 90 * 1024 * 1024;
  const resetGatewayDownload = 1200 * 1024 * 1024;
  const resetGatewayUpload = 120 * 1024 * 1024;
  const downloadDelta = 75 * 1024 * 1024;
  const uploadDelta = 9 * 1024 * 1024;
  const server = http.createServer((request, response) => {
    if (request.url === '/api/captiveportal/session/list/0') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{
          sessionId: 'quota-reset-session',
          userName: 'sms:905551112233',
          ipAddress: '172.16.2.44',
          macAddress: '28:16:7f:27:46:71',
          bytesIn: resetGatewayUpload + uploadDelta,
          bytesOut: resetGatewayDownload + downloadDelta
        }]
      }));
      return;
    }
    if (request.url === '/api/diagnostics/interface/get_arp') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{ ipAddress: '172.16.2.44', macAddress: '28:16:7f:27:46:71' }]
      }));
      return;
    }
    if (request.url === '/api/kea/leases4/search') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    response.writeHead(404);
    response.end();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const authorization = db.saveAuthorization({
      method: 'sms',
      identity: '905551112233',
      clientIp: '172.16.2.44',
      clientMac: '28:16:7F:27:46:71',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '0:quota-reset-session',
      status: 'active',
      expiresAt: Date.now() + 60 * 60 * 1000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    db.updateAuthorizationUsage(authorization.id, {
      downloadBytes: baselineDownload,
      uploadBytes: baselineUpload,
      lastSeenAt: Date.now(),
      sampledAt: Date.now()
    });
    const period = quotaPeriodWindow('daily', Date.now(), 'UTC');
    db.resetAuthorizationQuotaUsage(db.getAuthorization(authorization.id), period, {
      downloadBytes: resetGatewayDownload,
      uploadBytes: resetGatewayUpload,
      authorizationDownloadBytes: baselineDownload,
      authorizationUploadBytes: baselineUpload,
      resetAt: Date.now()
    });

    const admin = createAdminController({
      db,
      config: {
        appSecret: 'secret',
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true,
          bandwidthProfiles: {
            sms: {
              downloadSpeedMbps: 0,
              uploadSpeedMbps: 0,
              quotaPeriod: 'daily',
              downloadQuotaGb: 2,
              uploadQuotaGb: 2
            }
          }
        },
        syslog: { enabled: false, networks: 'any', retentionDays: 730, timeZone: 'UTC' }
      }
    });

    const result = await admin.syncUsage();
    const updated = db.getAuthorization(authorization.id);
    const quota = db.getAuthorizationQuotaUsage(authorization.id, period.key);

    assert.equal(result.quotaDisconnected, 0);
    assert.equal(quota.download_bytes, downloadDelta);
    assert.equal(quota.upload_bytes, uploadDelta);
    assert.equal(updated.download_bytes, baselineDownload + downloadDelta);
    assert.equal(updated.upload_bytes, baselineUpload + uploadDelta);
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('admin sync keeps the verified IP from OPNsense ipAddresses when ownership APIs are unavailable', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const server = http.createServer((request, response) => {
    if (request.url === '/api/captiveportal/session/list/0') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/captiveportal/session/list/1') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{
          sessionId: 'session-1',
          userName: 'email:gkhn.gurbuz@hotmail.com',
          ipAddress: '172.16.2.100',
          macAddress: '28:16:7f:27:46:71',
          ipAddresses: [
            '172.16.2.100',
            '172.16.2.101',
            '172.16.3.3',
            'fe80::63de:8b47:7477:bcb2'
          ],
          bytesIn: 2048,
          bytesOut: 4096
        }]
      }));
      return;
    }
    if (request.url === '/api/diagnostics/interface/get_arp' ||
        request.url === '/api/dhcpv4/leases/searchLease') {
      response.writeHead(403, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ status: 403, message: 'Forbidden' }));
      return;
    }
    if (request.url === '/api/captiveportal/session/disconnect/1') {
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
      method: 'email',
      identity: 'gkhn.gurbuz@hotmail.com',
      clientIp: '172.16.3.3',
      clientMac: '',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:session-1',
      status: 'active',
      expiresAt: Date.now() + 3600000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    const admin = createAdminController({
      db,
      config: {
        appSecret: 'secret',
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          zoneMap: [{ network: '172.16.3.0/24', zoneId: 1 }],
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true
        },
        syslog: { enabled: false, networks: 'any', retentionDays: 730 }
      }
    });

    const result = await admin.syncUsage();
    const updated = db.getAuthorization(authorization.id);

    assert.equal(result.matched, 1);
    assert.equal(result.arpEntries, 0);
    assert.equal(result.dhcpLeases, 0);
    assert.equal(updated.client_ip, '172.16.3.3');
    assert.equal(updated.client_mac, null);
    assert.equal(updated.download_bytes, 4096);
    assert.equal(updated.upload_bytes, 2048);
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('admin sync disconnects a polluted authorization instead of moving it without a browser session', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const server = http.createServer((request, response) => {
    if (request.url === '/api/captiveportal/session/list/0') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/captiveportal/session/list/1') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{
          sessionId: 'session-1',
          userName: 'email:gkhn.gurbuz@hotmail.com',
          ipAddress: '172.16.2.100',
          macAddress: '28:16:7f:27:46:71',
          ipAddresses: [
            '172.16.2.100',
            '172.16.2.101',
            '172.16.3.3',
            'fe80::63de:8b47:7477:bcb2'
          ],
          bytesIn: 2048,
          bytesOut: 4096
        }]
      }));
      return;
    }
    if (request.url === '/api/diagnostics/interface/get_arp' ||
        request.url === '/api/dhcpv4/leases/searchLease') {
      response.writeHead(403, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ status: 403, message: 'Forbidden' }));
      return;
    }
    if (request.url === '/api/captiveportal/session/disconnect/1') {
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
      method: 'email',
      identity: 'gkhn.gurbuz@hotmail.com',
      clientIp: '172.16.2.100',
      clientMac: '28:16:7F:27:46:71',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:session-1',
      status: 'active',
      expiresAt: Date.now() + 3600000,
      redirectUrl: '',
      gatewayResponse: {
        ipAddress: '172.16.3.3',
        macAddress: '28:16:7f:27:46:71',
        sessionId: 'session-1',
        gHotspotZoneId: 1
      },
      error: ''
    });
    const admin = createAdminController({
      db,
      config: {
        appSecret: 'secret',
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          zoneMap: [{ network: '172.16.3.0/24', zoneId: 1 }],
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true
        },
        syslog: { enabled: false, networks: 'any', retentionDays: 730 }
      }
    });

    const result = await admin.syncUsage();
    const updated = db.getAuthorization(authorization.id);

    assert.equal(result.matched, 1);
    assert.equal(result.staleIpDisconnected, 1);
    assert.equal(updated.client_ip, '172.16.2.100');
    assert.equal(updated.client_mac, '28:16:7F:27:46:71');
    assert.equal(updated.gateway_session_id, null);
    assert.equal(updated.disconnect_reason, null);
    assert.equal(updated.ended_at, null);
    assert.equal(updated.download_bytes, 0);
    assert.equal(updated.upload_bytes, 0);
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('admin sync disconnects a moved gateway session when the database still has the old IP', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requests.push({
      method: request.method,
      url: request.url,
      body: Buffer.concat(chunks).toString('utf8')
    });
    if (request.url === '/api/captiveportal/session/list/0') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [] }));
      return;
    }
    if (request.url === '/api/captiveportal/session/list/1') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{
          sessionId: 'new-session',
          userName: 'email:gkhn.gurbuz@hotmail.com',
          ipAddress: '172.16.3.2'
        }]
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
          { if: 'wifiap', address: '172.16.3.2', mac: 'fa:93:8f:47:d5:8b', state: 'assigned' },
          { if: 'wifiap', address: '172.16.3.3', mac: '28:16:7f:27:46:71', state: 'assigned' }
        ]
      }));
      return;
    }
    if (request.url === '/api/captiveportal/session/disconnect/1') {
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
      method: 'email',
      identity: 'gkhn.gurbuz@hotmail.com',
      clientIp: '172.16.3.3',
      clientMac: 'FA:93:8F:47:D5:8B',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:old-session',
      status: 'active',
      expiresAt: Date.now() + 3600000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    const admin = createAdminController({
      db,
      config: {
        appSecret: 'secret',
        gateway: {
          mode: 'opnsense-api',
          baseUrl: `http://127.0.0.1:${port}`,
          zoneId: 0,
          zoneMap: [{ network: '172.16.3.0/24', zoneId: 1 }],
          apiKey: 'key',
          apiSecret: 'secret',
          tlsRejectUnauthorized: true
        },
        syslog: { enabled: false, networks: 'any', retentionDays: 730 }
      }
    });

    const result = await admin.syncUsage();
    const updated = db.getAuthorization(authorization.id);

    assert.equal(result.staleIpMoved, 0);
    assert.equal(result.staleIpDisconnected, 1);
    assert.equal(updated.client_ip, '172.16.3.3');
    assert.equal(updated.gateway_session_id, null);
    assert.equal(updated.disconnect_reason, null);
    assert.equal(updated.ended_at, null);
    assert.equal(
      requests.some(item => item.url.includes('/api/captiveportal/session/connect/')),
      false
    );
    assert.equal(
      requests.some(item => item.url.includes('/api/captiveportal/session/disconnect/')),
      true
    );
  } finally {
    await new Promise(resolve => server.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
