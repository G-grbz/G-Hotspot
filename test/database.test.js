import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { HotspotDatabase, deviceOsFromUserAgent } from '../src/db.js';
import {
  appendTrafficLogFileRecords,
  cleanupTrafficLogFile,
  listTrafficLogFileRecords,
  topTrafficLogFileClients,
  topTrafficLogFileSites,
  trafficLogFileSeries,
  trafficLogRecordFromInterfaceCounters,
  trafficLogRecordFromSession
} from '../src/services/trafficLogs.js';

test('device OS can be inferred from browser user agents', () => {
  assert.equal(
    deviceOsFromUserAgent(
      'Mozilla/5.0 (Linux; Android 14; 23049PCD8G) AppleWebKit/537.36 Chrome/125.0 Mobile Safari/537.36'
    ),
    'android'
  );
  assert.equal(deviceOsFromUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)'), 'ios');
  assert.equal(deviceOsFromUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64)'), 'windows');
  assert.equal(deviceOsFromUserAgent(''), '');
});

test('syslog records are stored in a separate syslog database', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-split-'));
  const databasePath = path.join(directory, 'hotspot.db');
  const syslogPath = path.join(directory, 'syslog.db');
  const db = new HotspotDatabase(databasePath);
  const now = Date.UTC(2026, 6, 13, 10, 0, 0);
  try {
    assert.equal(db.syslogFilePath, syslogPath);
    assert.equal(fs.existsSync(syslogPath), true);
    assert.equal(
      db.db.prepare("SELECT COUNT(*) count FROM sqlite_master WHERE type='table' AND name='law5651_logs'").get().count,
      0
    );

    const result = db.appendLaw5651Logs([{
      dedupeKey: 'syslog-split-flow',
      kind: 'flow',
      source: 'opnsense-filterlog',
      clientIp: '172.16.2.120',
      sourceIp: '172.16.2.120',
      destinationIp: '8.8.8.8',
      protocol: 'udp',
      serviceType: 'firewall-pass-out',
      startedAt: now,
      downloadBytes: 42,
      uploadBytes: 12,
      createdAt: now
    }]);
    assert.equal(result.inserted, 1);
    db.recordLaw5651Event({
      eventType: 'receiver_started',
      severity: 'info',
      message: 'Receiver started',
      createdAt: now
    });
    db.setLaw5651State('checkpoint', 'ok', now);

    assert.equal(db.syslogDb.prepare('SELECT COUNT(*) count FROM law5651_logs').get().count, 1);
    assert.equal(db.syslogDb.prepare('SELECT COUNT(*) count FROM law5651_events').get().count, 1);
    assert.equal(db.getLaw5651State('checkpoint').value, 'ok');
    assert.equal(db.listActivity({ kind: 'syslog' })[0].action, 'receiver_started');
    assert.equal(db.syslogDatabaseMaintenanceStats().path, syslogPath);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('legacy law5651 tables migrate from hotspot database to syslog database', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-migrate-'));
  const databasePath = path.join(directory, 'hotspot.db');
  const legacy = new DatabaseSync(databasePath);
  const now = Date.UTC(2026, 6, 13, 11, 0, 0);
  legacy.exec(`
    CREATE TABLE law5651_logs (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
      id TEXT NOT NULL UNIQUE,
      dedupe_key TEXT NOT NULL UNIQUE,
      kind TEXT NOT NULL CHECK (kind IN ('session', 'flow')),
      source TEXT NOT NULL,
      network TEXT,
      client_ip TEXT NOT NULL,
      client_mac TEXT,
      subscriber_id TEXT,
      source_ip TEXT NOT NULL,
      source_port TEXT,
      destination_ip TEXT,
      destination_port TEXT,
      protocol TEXT,
      service_type TEXT NOT NULL,
      started_at INTEGER NOT NULL,
      ended_at INTEGER,
      download_bytes INTEGER NOT NULL DEFAULT 0,
      upload_bytes INTEGER NOT NULL DEFAULT 0,
      raw_json TEXT,
      previous_hash TEXT NOT NULL,
      record_hash TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL
    ) STRICT;
    INSERT INTO law5651_logs
      (id, dedupe_key, kind, source, client_ip, source_ip, service_type, started_at,
       download_bytes, upload_bytes, previous_hash, record_hash, created_at)
    VALUES
      ('legacy-log-1', 'legacy-dedupe-1', 'flow', 'opnsense-filterlog', '172.16.2.121',
       '172.16.2.121', 'firewall-pass-out', ${now}, 100, 20, '${'0'.repeat(64)}',
       '${'1'.repeat(64)}', ${now});

    CREATE TABLE law5651_state (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at INTEGER NOT NULL
    ) STRICT;
    INSERT INTO law5651_state(key, value, updated_at)
    VALUES ('legacy-checkpoint', 'ready', ${now});
  `);
  legacy.close();

  const db = new HotspotDatabase(databasePath);
  try {
    assert.equal(db.listLaw5651Logs().total, 1);
    assert.equal(db.getLaw5651State('legacy-checkpoint').value, 'ready');
    assert.equal(
      db.db.prepare("SELECT COUNT(*) count FROM sqlite_master WHERE type='table' AND name LIKE 'law5651_%'").get().count,
      0
    );
    assert.equal(db.syslogDb.prepare('SELECT COUNT(*) count FROM law5651_logs').get().count, 1);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('voucher can be claimed only up to max uses', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  try {
    const voucherId = db.createVoucher({
      codeHash: 'hash', codeHint: '1234', label: 'test', maxUses: 1,
      durationMinutes: 60, validFrom: null, expiresAt: null
    });
    assert.equal(db.claimVoucher('hash', Date.now(), 'ABCD').ok, true);
    assert.equal(db.listVouchers()[0].code_prefix, 'ABCD');
    assert.equal(db.saveAuthorization({
      method: 'voucher',
      identity: voucherId,
      clientIp: '192.0.2.10',
      clientMac: '',
      gatewayMode: 'mock',
      gatewaySessionId: 'voucher-session',
      status: 'active',
      expiresAt: Date.now() + 60000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    }).voucher_code_prefix, 'ABCD');
    assert.deepEqual(db.claimVoucher('hash'), { ok: false, reason: 'used' });
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('voucher authorizations are listed with verification records', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  try {
    const voucherId = db.createVoucher({
      codeHash: 'voucher-hash',
      codeHint: '7890',
      label: 'Lobby',
      maxUses: 3,
      durationMinutes: 60,
      validFrom: null,
      expiresAt: null
    });
    db.saveAuthorization({
      method: 'voucher',
      identity: voucherId,
      clientIp: '192.0.2.10',
      clientMac: 'AA:BB:CC:DD:EE:FF',
      gatewayMode: 'mock',
      gatewaySessionId: 'voucher-session',
      status: 'active',
      expiresAt: Date.now() + 60000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });

    const all = db.listChallenges({ kind: 'voucher' });
    assert.equal(all.total, 1);
    assert.equal(all.rows[0].kind, 'voucher');
    assert.equal(all.rows[0].status, 'verified');
    assert.equal(all.rows[0].target, 'Lobby');
    assert.equal(all.rows[0].voucher_hint, '7890');
    assert.equal(db.listChallenges({ kind: 'voucher', status: 'pending' }).total, 0);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('challenge state can be claimed and completed', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  try {
    const challenge = db.createChallenge({
      kind: 'email', target: 'a@example.com', secretHash: 'x', clientIp: '192.0.2.1',
      clientMac: '', redirectUrl: '', expiresAt: Date.now() + 60000, language: 'tr'
    });
    assert.equal(challenge.language, 'tr');
    assert.equal(db.claimChallenge(challenge.id), true);
    assert.equal(db.claimChallenge(challenge.id), false);
    db.setChallengeDetail(challenge.id, 'SMTP server accepted the verification code request.');
    db.appendChallengeDetail(challenge.id, 'Gateway authorization succeeded.');
    db.finishChallenge(challenge.id, true);
    const completed = db.getChallenge(challenge.id);
    assert.equal(completed.status, 'verified');
    assert.equal(
      completed.last_error,
      'SMTP server accepted the verification code request.\nGateway authorization succeeded.'
    );
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('phone-based challenges and authorizations are supported', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  try {
    const smsChallenge = db.createChallenge({
      kind: 'sms', target: '905551112233', secretHash: 'sms-hash', clientIp: '192.0.2.2',
      clientMac: '', redirectUrl: '', expiresAt: Date.now() + 60000
    });
    assert.equal(smsChallenge.kind, 'sms');
    const smsAuthorization = db.saveAuthorization({
      method: 'sms', identity: '905551112233', clientIp: '192.0.2.2', clientMac: '',
      gatewayMode: 'mock', gatewaySessionId: 'sms-session', status: 'active',
      expiresAt: Date.now() + 60000, redirectUrl: '', gatewayResponse: {}, error: ''
    });
    assert.equal(smsAuthorization.method, 'sms');

    const telegramChallenge = db.createChallenge({
      kind: 'telegram', target: '905551114455', secretHash: 'telegram-hash', clientIp: '192.0.2.5',
      clientMac: '', redirectUrl: '', expiresAt: Date.now() + 60000
    });
    assert.equal(telegramChallenge.kind, 'telegram');
    assert.equal(
      db.getPendingChallengeByTarget('telegram', '905551114455').id,
      telegramChallenge.id
    );
    assert.equal(
      db.getPendingChallengeByClient('telegram', '192.0.2.5').id,
      telegramChallenge.id
    );
    const updated = db.updateChallengeSecret(telegramChallenge.id, 'next-hash', Date.now() + 120000);
    assert.equal(updated.secret_hash, 'next-hash');
    const telegramAuthorization = db.saveAuthorization({
      method: 'telegram', identity: '905551114455', clientIp: '192.0.2.5', clientMac: '',
      gatewayMode: 'mock', gatewaySessionId: 'telegram-session', status: 'active',
      expiresAt: Date.now() + 60000, redirectUrl: '', gatewayResponse: {}, error: ''
    });
    assert.equal(telegramAuthorization.method, 'telegram');

    const nviChallenge = db.createChallenge({
      kind: 'nvi', target: '10000000146', secretHash: 'nvi-hash', clientIp: '192.0.2.6',
      clientMac: '', redirectUrl: '', expiresAt: Date.now() + 60000
    });
    assert.equal(nviChallenge.kind, 'nvi');
    const nviAuthorization = db.saveAuthorization({
      method: 'nvi', identity: '10000000146', clientIp: '192.0.2.6', clientMac: '',
      gatewayMode: 'mock', gatewaySessionId: 'nvi-session', status: 'active',
      expiresAt: Date.now() + 60000, redirectUrl: '', gatewayResponse: {}, error: ''
    });
    assert.equal(nviAuthorization.method, 'nvi');
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('dashboard groups active devices by inferred operating system', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const now = Date.now();
  const saveActiveDevice = ({ identity, clientIp, deviceName, deviceOs = '', expiresAt = now + 60000 }) => {
    const authorization = db.saveAuthorization({
      method: 'email',
      identity,
      clientIp,
      clientMac: '',
      gatewayMode: 'mock',
      gatewaySessionId: `${clientIp}-session`,
      status: 'active',
      expiresAt,
      redirectUrl: '',
      gatewayResponse: {},
      error: '',
      deviceOs
    });
    db.updateAuthorizationUsage(authorization.id, {
      downloadBytes: 0,
      uploadBytes: 0,
      lastSeenAt: now,
      sampledAt: now,
      deviceName
    });
    return authorization;
  };

  try {
    saveActiveDevice({ identity: 'win@example.com', clientIp: '192.0.2.11', deviceName: 'DESKTOP-LOBBY' });
    saveActiveDevice({ identity: 'android@example.com', clientIp: '192.0.2.12', deviceName: 'xiaomi-13t-pro' });
    saveActiveDevice({ identity: 'linux@example.com', clientIp: '192.0.2.13', deviceName: 'ubuntu-workstation' });
    saveActiveDevice({ identity: 'ios@example.com', clientIp: '192.0.2.14', deviceName: 'iPhone12' });
    saveActiveDevice({
      identity: 'voucher@example.com',
      clientIp: '192.0.2.16',
      deviceName: 'gh-voucher-acc76b7a-0799-421e-b090-c3d585907222',
      deviceOs: 'android'
    });
    saveActiveDevice({
      identity: 'expired@example.com',
      clientIp: '192.0.2.15',
      deviceName: 'MacBook-Pro',
      expiresAt: now - 1000
    });

    const distribution = db.dashboard(now).deviceOs;
    const counts = new Map(distribution.rows.map(row => [row.os, row.count]));
    assert.equal(distribution.total, 5);
    assert.equal(counts.get('windows'), 1);
    assert.equal(counts.get('android'), 2);
    assert.equal(counts.get('linux'), 1);
    assert.equal(counts.get('ios'), 1);
    assert.equal(counts.has('macos'), false);
    assert.deepEqual(
      distribution.rows.find(row => row.os === 'android').devices,
      ['xiaomi-13t-pro', '192.0.2.16']
    );
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('device OS learned for a session is reused for legacy authorizations with the same MAC', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const databasePath = path.join(directory, 'test.db');
  let db = new HotspotDatabase(databasePath);
  const now = Date.now();
  const saveAuthorization = ({ identity, clientIp, clientMac, deviceOs = '' }) => db.saveAuthorization({
    method: 'email',
    identity,
    clientIp,
    clientMac,
    gatewayMode: 'mock',
    gatewaySessionId: `${identity}-session`,
    status: 'active',
    expiresAt: now + 60000,
    redirectUrl: '',
    gatewayResponse: {},
    error: '',
    deviceOs
  });

  try {
    const legacy = saveAuthorization({
      identity: 'legacy@example.com',
      clientIp: '192.0.2.21',
      clientMac: 'AA:BB:CC:DD:EE:FF'
    });
    const known = saveAuthorization({
      identity: 'known@example.com',
      clientIp: '192.0.2.22',
      clientMac: 'AA:BB:CC:DD:EE:FF',
      deviceOs: 'android'
    });

    assert.equal(db.getAuthorization(legacy.id).device_os, null);
    assert.equal(db.rememberAuthorizationDeviceOs(known.id, 'windows'), 'android');
    assert.equal(db.getAuthorization(legacy.id).device_os, 'android');

    const learned = saveAuthorization({
      identity: 'learned@example.com',
      clientIp: '192.0.2.23',
      clientMac: '11:22:33:44:55:66'
    });
    assert.equal(db.rememberAuthorizationDeviceOs(learned.id, 'ios'), 'ios');
    assert.equal(db.getAuthorization(learned.id).device_os, 'ios');

    const migrationLegacy = saveAuthorization({
      identity: 'migration-legacy@example.com',
      clientIp: '192.0.2.24',
      clientMac: '22:33:44:55:66:77'
    });
    saveAuthorization({
      identity: 'migration-known@example.com',
      clientIp: '192.0.2.25',
      clientMac: '22:33:44:55:66:77',
      deviceOs: 'windows'
    });
    assert.equal(db.getAuthorization(migrationLegacy.id).device_os, null);

    db.close();
    db = new HotspotDatabase(databasePath);
    assert.equal(db.getAuthorization(legacy.id).device_os, 'android');
    assert.equal(db.getAuthorization(migrationLegacy.id).device_os, 'windows');
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('latest successful authorization can be found by method and identity', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  try {
    db.saveAuthorization({
      method: 'email', identity: 'guest@example.com', clientIp: '192.0.2.3', clientMac: '',
      gatewayMode: 'mock', gatewaySessionId: null, status: 'failed',
      expiresAt: Date.now() + 60000, redirectUrl: '', gatewayResponse: null, error: 'failed'
    });
    const successful = db.saveAuthorization({
      method: 'email', identity: 'guest@example.com', clientIp: '192.0.2.4', clientMac: '',
      gatewayMode: 'mock', gatewaySessionId: 'email-session', status: 'active',
      expiresAt: Date.now() + 60000, redirectUrl: '', gatewayResponse: {}, error: ''
    });
    assert.equal(
      db.getLatestSuccessfulAuthorization('email', 'guest@example.com').id,
      successful.id
    );
    assert.equal(db.getLatestSuccessfulAuthorization('sms', 'guest@example.com'), null);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('expired active authorizations can be listed by gateway mode', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const now = Date.UTC(2026, 5, 27, 0, 40, 0);
  try {
    const expired = db.saveAuthorization({
      method: 'email', identity: 'expired@example.com', clientIp: '192.0.2.10', clientMac: '',
      gatewayMode: 'opnsense-api', gatewaySessionId: '0:expired-session', status: 'active',
      expiresAt: now - 1000, redirectUrl: '', gatewayResponse: {}, error: ''
    });
    db.saveAuthorization({
      method: 'email', identity: 'active@example.com', clientIp: '192.0.2.11', clientMac: '',
      gatewayMode: 'opnsense-api', gatewaySessionId: '0:active-session', status: 'active',
      expiresAt: now + 60000, redirectUrl: '', gatewayResponse: {}, error: ''
    });
    db.saveAuthorization({
      method: 'email', identity: 'mock@example.com', clientIp: '192.0.2.12', clientMac: '',
      gatewayMode: 'mock', gatewaySessionId: 'mock-session', status: 'active',
      expiresAt: now - 1000, redirectUrl: '', gatewayResponse: {}, error: ''
    });

    assert.deepEqual(
      db.listExpiredActiveAuthorizations({ now, gatewayMode: 'opnsense-api' }).map(row => row.id),
      [expired.id]
    );
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('expired authorization cleanups include early ended rows until Kea deletion is marked', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const now = Date.UTC(2026, 5, 27, 0, 40, 0);
  try {
    const ended = db.saveAuthorization({
      method: 'email', identity: 'ended@example.com', clientIp: '192.0.2.20', clientMac: '',
      gatewayMode: 'opnsense-api', gatewaySessionId: '0:ended-session', status: 'active',
      expiresAt: now - 1000, redirectUrl: '', gatewayResponse: {}, error: ''
    });
    db.endAuthorization(ended.id, 'session_ip_mac_mismatch');
    db.saveAuthorization({
      method: 'email', identity: 'active@example.com', clientIp: '192.0.2.21', clientMac: '',
      gatewayMode: 'opnsense-api', gatewaySessionId: '0:active-session', status: 'active',
      expiresAt: now + 60000, redirectUrl: '', gatewayResponse: {}, error: ''
    });

    assert.deepEqual(
      db.listExpiredAuthorizationCleanups({ now, gatewayMode: 'opnsense-api' }).map(row => row.id),
      [ended.id]
    );

    db.markAuthorizationKeaDeleted(ended.id, now);

    assert.deepEqual(
      db.listExpiredAuthorizationCleanups({ now, gatewayMode: 'opnsense-api' }).map(row => row.id),
      []
    );
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('migration reopens early IP mismatch disconnects whose access duration has not expired', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const databasePath = path.join(directory, 'test.db');
  let db = new HotspotDatabase(databasePath);
  try {
    const authorization = db.saveAuthorization({
      method: 'voucher', identity: 'voucher-1', clientIp: '172.16.3.2',
      clientMac: '28:16:7F:27:46:71', gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:old-session', status: 'active',
      expiresAt: Date.now() + 3600000, redirectUrl: '', gatewayResponse: {}, error: ''
    });
    db.endAuthorization(authorization.id, 'session_ip_changed_without_cookie');
    db.close();
    db = null;

    db = new HotspotDatabase(databasePath);
    const reopened = db.getAuthorization(authorization.id);

    assert.equal(reopened.ended_at, null);
    assert.equal(reopened.disconnect_reason, null);
    assert.equal(reopened.gateway_session_id, null);
  } finally {
    if (db) db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('active authorization can be found by MAC after a client IP change', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const now = Date.UTC(2026, 5, 27, 3, 0, 0);
  try {
    db.saveAuthorization({
      method: 'email',
      identity: 'failed@example.com',
      clientIp: '172.16.3.1',
      clientMac: 'AA:BB:CC:DD:EE:FF',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: null,
      status: 'failed',
      expiresAt: now + 60000,
      redirectUrl: '',
      gatewayResponse: null,
      error: 'failed'
    });
    const active = db.saveAuthorization({
      method: 'sms',
      identity: '905551112233',
      clientIp: '172.16.3.3',
      clientMac: 'AA:BB:CC:DD:EE:FF',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:old-session',
      status: 'active',
      expiresAt: now + 60000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });

    assert.equal(db.getActiveAuthorizationForClient('172.16.3.2', now), null);
    assert.equal(db.getActiveAuthorizationForMac('aa-bb-cc-dd-ee-ff', now).id, active.id);
    assert.equal(db.getActiveAuthorizationForMac('aa-bb-cc-dd-ee-ff', now + 60001), null);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('active authorizations can be listed by client IP', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const now = Date.UTC(2026, 5, 27, 3, 0, 0);
  try {
    const active = db.saveAuthorization({
      method: 'email',
      identity: 'active@example.com',
      clientIp: '172.16.3.3',
      clientMac: 'AA:BB:CC:DD:EE:FF',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:active-session',
      status: 'active',
      expiresAt: now + 60000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    db.saveAuthorization({
      method: 'sms',
      identity: '905551112233',
      clientIp: '172.16.3.3',
      clientMac: '11:22:33:44:55:66',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:expired-session',
      status: 'active',
      expiresAt: now - 60000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    db.saveAuthorization({
      method: 'telegram',
      identity: '905551114455',
      clientIp: '172.16.3.4',
      clientMac: 'AA:BB:CC:DD:EE:FF',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:other-session',
      status: 'active',
      expiresAt: now + 60000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });

    assert.deepEqual(
      db.listActiveAuthorizationsForClient('172.16.3.3', now).map(row => row.id),
      [active.id]
    );
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('gateway session moves can explicitly clear a stale client MAC', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  try {
    const authorization = db.saveAuthorization({
      method: 'email',
      identity: 'guest@example.com',
      clientIp: '172.16.2.100',
      clientMac: '28:16:7F:27:46:71',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: '1:session-1',
      status: 'active',
      expiresAt: Date.now() + 60000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });

    assert.equal(db.moveAuthorizationGatewaySession(authorization.id, {
      clientIp: '172.16.3.3',
      clientMac: '',
      clearClientMac: true,
      gatewaySessionId: '1:session-1',
      gatewayResponse: null
    }), true);

    const updated = db.getAuthorization(authorization.id);
    assert.equal(updated.client_ip, '172.16.3.3');
    assert.equal(updated.client_mac, null);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('verification cooldowns are stored per method and IP and can be conditionally released', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  try {
    const requestedAt = Date.UTC(2026, 5, 26, 10, 0, 0);
    db.setVerificationCooldown('email', '192.0.2.10', requestedAt);
    const cooldown = db.getVerificationCooldown('email', '192.0.2.10');
    assert.equal(cooldown.method, 'email');
    assert.equal(cooldown.client_ip, '192.0.2.10');
    assert.equal(cooldown.requested_at, requestedAt);
    assert.equal(db.getVerificationCooldown('sms', '192.0.2.10'), null);
    assert.equal(
      db.releaseVerificationCooldown('email', '192.0.2.10', requestedAt + 1),
      false
    );
    assert.equal(
      db.releaseVerificationCooldown('email', '192.0.2.10', requestedAt),
      true
    );
    assert.equal(db.getVerificationCooldown('email', '192.0.2.10'), null);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('operational traffic logs can be listed, aggregated and expired', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  const now = Date.UTC(2026, 5, 27, 10, 0, 0);
  const currentRecordAt = now - 40 * 60 * 1000;
  const secondRecordAt = now - 20 * 60 * 1000;
  try {
    const result = db.appendTrafficLogs([
      {
        dedupeKey: 'flow-current',
        kind: 'session',
        source: 'opnsense-session',
        clientIp: '172.16.2.42',
        clientMac: 'aa:bb:cc:dd:ee:ff',
        subscriberId: 'sms:905551112233',
        sourceIp: '172.16.2.42',
        sourcePort: '5353',
        destinationIp: '8.8.8.8',
        destinationPort: '53',
        destinationDomain: 'dns.google',
        protocol: 'udp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: currentRecordAt,
        endedAt: currentRecordAt,
        downloadBytes: 1000,
        uploadBytes: 200,
        rawJson: JSON.stringify({
          gatewaySessionId: 'session-1',
          cumulativeDownloadBytes: 1000,
          cumulativeUploadBytes: 200
        }),
        createdAt: currentRecordAt
      },
      {
        dedupeKey: 'flow-current-2',
        kind: 'session',
        source: 'opnsense-session',
        clientIp: '172.16.2.42',
        clientMac: 'aa:bb:cc:dd:ee:ff',
        subscriberId: 'sms:905551112233',
        sourceIp: '172.16.2.42',
        sourcePort: '5353',
        destinationIp: '8.8.8.8',
        destinationPort: '53',
        destinationDomain: 'dns.google',
        protocol: 'udp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: secondRecordAt,
        endedAt: secondRecordAt,
        downloadBytes: 500,
        uploadBytes: 150,
        rawJson: JSON.stringify({
          gatewaySessionId: 'session-1',
          cumulativeDownloadBytes: 1500,
          cumulativeUploadBytes: 350
        }),
        createdAt: secondRecordAt
      },
      {
        dedupeKey: 'flow-live',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '172.16.2.44',
        sourceIp: '172.16.2.44',
        destinationIp: '9.9.9.9',
        protocol: 'udp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: now - 10 * 1000,
        downloadBytes: 600,
        uploadBytes: 1200,
        createdAt: now - 10 * 1000
      },
      {
        dedupeKey: 'flow-old',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '172.16.2.43',
        sourceIp: '172.16.2.43',
        destinationIp: '1.1.1.1',
        protocol: 'tcp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: now - 3 * 24 * 60 * 60 * 1000,
        downloadBytes: 10,
        uploadBytes: 5,
        createdAt: now - 3 * 24 * 60 * 60 * 1000
      }
    ]);
    assert.deepEqual(result, { inserted: 4, skipped: 0 });
    assert.deepEqual(db.appendTrafficLogs([{
      dedupeKey: 'flow-current',
      kind: 'flow',
      source: 'opnsense-filterlog',
      clientIp: '172.16.2.42',
      sourceIp: '172.16.2.42',
      serviceType: 'firewall-pass-out',
      startedAt: currentRecordAt
    }]), {
      inserted: 0,
      skipped: 1
    });

    const series = db.trafficLogSeries({ period: '60m', now });
    assert.equal(series.source, 'traffic_rollups');
    assert.equal(series.summary.totalDownloadBytes, 1100);
    assert.equal(series.summary.totalUploadBytes, 1350);
    assert.equal(series.points.find(point => point.startAt === currentRecordAt).records, 1);
    assert.equal(series.points.find(point => point.startAt === secondRecordAt).downloadBytes, 500);

    const filtered = db.listTrafficLogs({ search: 'dns.google', period: '60m', now });
    assert.equal(filtered.total, 2);
    assert.equal(filtered.rows[0].destination_domain, 'dns.google');
    assert.equal(filtered.rows[0].effective_download_bytes, 500);
    assert.equal(filtered.rows[0].effective_upload_bytes, 150);
    assert.equal(filtered.summary.clients, 1);
    assert.equal(filtered.summary.downloadBytes, 500);
    assert.equal(filtered.summary.uploadBytes, 150);
    assert.equal(filtered.summary.liveDownloadBps, 0);
    assert.equal(filtered.summary.liveUploadBps, 0);

    const live = db.listTrafficLogs({ period: '60m', now });
    assert.equal(live.summary.liveWindowSeconds, 60);
    assert.equal(live.summary.liveRecords, 1);
    assert.equal(live.summary.liveDownloadBps, 10);
    assert.equal(live.summary.liveUploadBps, 20);

    const endpointFiltered = db.listTrafficLogs({
      sourceIp: '172.16.2.42',
      sourcePort: '5353',
      destinationIp: '8.8.8.8',
      destinationPort: '53',
      period: '60m',
      now
    });
    assert.equal(endpointFiltered.total, 2);
    assert.equal(endpointFiltered.summary.downloadBytes, 500);
    assert.equal(db.listTrafficLogs({ destinationPort: '9999', period: '60m', now }).total, 0);

    const cleanup = db.cleanupTrafficLogsDetailed(60, now);
    assert.equal(cleanup.deleted, 1);
    assert.equal(cleanup.retentionMinutes, 60);
    assert.equal(cleanup.deletedRollups, Object.values(cleanup.rollups).reduce((sum, value) => sum + value, 0));
    assert.equal(db.cleanupTrafficLogs(60, now), 0);
    assert.equal(db.listTrafficLogs({ period: '60m', now }).total, 3);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('traffic rollups drive dashboard series and top sites', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-traffic-rollups-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const now = Date.UTC(2026, 5, 27, 12, 0, 0);
  try {
    db.appendTrafficLogs([
      {
        dedupeKey: 'rollup-example-1',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '172.16.2.40',
        sourceIp: '172.16.2.40',
        destinationIp: '93.184.216.34',
        destinationPort: '443',
        destinationDomain: 'www.example.com',
        protocol: 'tcp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: now - 10 * 60 * 1000,
        downloadBytes: 200,
        uploadBytes: 20,
        createdAt: now - 10 * 60 * 1000
      },
      {
        dedupeKey: 'rollup-example-2',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '172.16.2.41',
        sourceIp: '172.16.2.41',
        destinationIp: '93.184.216.34',
        destinationPort: '443',
        destinationDomain: 'example.com',
        protocol: 'tcp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: now - 9 * 60 * 1000,
        downloadBytes: 100,
        uploadBytes: 30,
        createdAt: now - 9 * 60 * 1000
      },
      {
        dedupeKey: 'rollup-other',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '172.16.2.40',
        sourceIp: '172.16.2.40',
        destinationIp: '203.0.113.10',
        destinationPort: '443',
        destinationDomain: 'other.example',
        protocol: 'tcp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: now - 8 * 60 * 1000,
        downloadBytes: 500,
        uploadBytes: 50,
        createdAt: now - 8 * 60 * 1000
      },
      {
        dedupeKey: 'rollup-dns-skipped',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '172.16.2.42',
        sourceIp: '172.16.2.42',
        destinationIp: '8.8.8.8',
        destinationPort: '53',
        destinationDomain: 'dns.google',
        protocol: 'udp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: now - 7 * 60 * 1000,
        downloadBytes: 50,
        uploadBytes: 10,
        createdAt: now - 7 * 60 * 1000
      }
    ]);

    const series = db.trafficLogSeries({ period: '60m', now });
    assert.equal(series.source, 'traffic_rollups');
    assert.equal(series.summary.records, 4);
    assert.equal(series.summary.totalDownloadBytes, 850);
    assert.equal(series.summary.totalUploadBytes, 110);

    const topSites = db.topTrafficLogSites({ minutes: 60, now });
    assert.equal(topSites.source, 'traffic_rollups');
    assert.equal(topSites.totalSites, 2);
    assert.equal(topSites.totalVisits, 3);
    assert.deepEqual(topSites.rows.map(row => row.site), ['example.com', 'other.example']);
    assert.equal(topSites.rows[0].clients, 2);
    assert.equal(topSites.rows[0].totalBytes, 350);

    const topBandwidthSites = db.topTrafficLogSites({ minutes: 60, sort: 'bytes', now });
    assert.equal(topBandwidthSites.sort, 'bytes');
    assert.deepEqual(topBandwidthSites.rows.map(row => row.site), ['other.example', 'example.com']);
    assert.equal(topBandwidthSites.rows[0].totalBytes, 550);

    const topClients = db.topTrafficLogClients({ minutes: 60, now });
    assert.equal(topClients.totalClients, 3);
    assert.deepEqual(topClients.rows.map(row => row.clientIp), ['172.16.2.40', '172.16.2.41', '172.16.2.42']);
    assert.equal(topClients.rows[0].totalBytes, 770);

    db.appendTrafficLogs([
      {
        dedupeKey: 'rollup-session-preferred',
        kind: 'session',
        source: 'opnsense-session',
        clientIp: '172.16.2.40',
        sourceIp: '172.16.2.40',
        protocol: 'ip',
        serviceType: 'internet-access',
        direction: 'session',
        startedAt: now - 6 * 60 * 1000,
        downloadBytes: 900,
        uploadBytes: 10,
        createdAt: now - 6 * 60 * 1000
      },
      {
        dedupeKey: 'rollup-wan-client-skipped',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '192.168.1.144',
        sourceIp: '192.168.1.144',
        destinationIp: '8.8.8.8',
        protocol: 'udp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: now - 5 * 60 * 1000,
        downloadBytes: 5000,
        uploadBytes: 1000,
        rawJson: JSON.stringify({ interface: 'wan' }),
        createdAt: now - 5 * 60 * 1000
      },
      {
        dedupeKey: 'rollup-other-opnsense-subnet',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '10.10.10.25',
        sourceIp: '10.10.10.25',
        destinationIp: '8.8.4.4',
        protocol: 'udp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: now - 4 * 60 * 1000,
        downloadBytes: 2000,
        uploadBytes: 100,
        rawJson: JSON.stringify({ interface: 'lan' }),
        createdAt: now - 4 * 60 * 1000
      }
    ]);
    const scopedTopClients = db.topTrafficLogClients({ minutes: 60, networks: '172.16.2.0/24', now });
    assert.deepEqual(scopedTopClients.rows.map(row => row.clientIp), ['172.16.2.40', '172.16.2.41', '172.16.2.42']);
    assert.equal(scopedTopClients.rows[0].source, 'sessions');
    assert.equal(scopedTopClients.rows[0].totalBytes, 910);
    const allOpnsenseClients = db.topTrafficLogClients({ minutes: 60, networks: 'any', excludedInterfaces: ['wan'], now });
    assert.equal(allOpnsenseClients.rows.some(row => row.clientIp === '10.10.10.25'), true);
    assert.equal(allOpnsenseClients.rows.some(row => row.clientIp === '192.168.1.144'), false);

    db.db.prepare('DELETE FROM traffic_log_client_detail_minute_rollups').run();
    db.setRuntimeState('traffic_log_rollups_version', 'v1', now);
    db.ensureTrafficLogRollups({ now });
    const migratedClients = db.topTrafficLogClients({ minutes: 60, networks: 'any', excludedInterfaces: ['wan'], now });
    assert.equal(migratedClients.rows.some(row => row.clientIp === '10.10.10.25'), true);
    assert.equal(migratedClients.rows.some(row => row.clientIp === '192.168.1.144'), false);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('operational traffic file logs can be filtered and expired', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-traffic-file-'));
  const now = Date.UTC(2026, 5, 27, 12, 0, 0);
  const config = {
    databasePath: path.join(directory, 'hotspot.db'),
    trafficLogs: {
      enabled: true,
      retentionMinutes: 60,
      resolveDomains: false,
      liveRefreshSeconds: 5
    }
  };
  const oldCreatedAt = now - 3 * 24 * 60 * 60 * 1000;
  const recentCreatedAt = now - 30 * 60 * 1000;
  try {
    const first = appendTrafficLogFileRecords(config, [
      {
        dedupeKey: 'traffic-file-old',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '172.16.2.20',
        sourceIp: '172.16.2.20',
        destinationIp: '1.1.1.1',
        destinationDomain: 'one.one.one.one',
        protocol: 'udp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: oldCreatedAt,
        downloadBytes: 100,
        uploadBytes: 40,
        createdAt: oldCreatedAt
      },
      {
        dedupeKey: 'traffic-file-live',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '172.16.2.22',
        sourceIp: '172.16.2.22',
        destinationIp: '9.9.9.9',
        destinationDomain: 'dns.quad9.net',
        protocol: 'udp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: now - 10 * 1000,
        downloadBytes: 120,
        uploadBytes: 240,
        createdAt: now - 10 * 1000
      },
      {
        dedupeKey: 'traffic-file-recent',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '172.16.2.21',
        sourceIp: '172.16.2.21',
        destinationIp: '8.8.8.8',
        destinationDomain: 'dns.google',
        protocol: 'udp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: recentCreatedAt,
        downloadBytes: 500,
        uploadBytes: 75,
        createdAt: recentCreatedAt
      }
    ], { now });
    assert.equal(first.inserted, 3);
    assert.equal(
      fs.existsSync(path.join(directory, 'traffic-records', 'traffic.log')),
      true
    );
    assert.deepEqual(
      appendTrafficLogFileRecords(config, [{
        dedupeKey: 'traffic-file-recent',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '172.16.2.21',
        sourceIp: '172.16.2.21',
        startedAt: recentCreatedAt,
        createdAt: recentCreatedAt
      }], { now }),
      {
        enabled: true,
        inserted: 0,
        skipped: 1,
        filePath: path.join(directory, 'traffic-records', 'traffic.log')
      }
    );

    const filtered = listTrafficLogFileRecords(config, {
      search: 'dns.google',
      startAt: now - 60 * 60 * 1000,
      endAt: now,
      now
    });
    assert.equal(filtered.total, 1);
    assert.equal(filtered.rows[0].destination_domain, 'dns.google');
    assert.equal(filtered.summary.downloadBytes, 500);
    assert.equal(filtered.summary.uploadBytes, 75);
    assert.equal(filtered.summary.liveDownloadBps, 0);
    assert.equal(filtered.summary.liveUploadBps, 0);

    const live = listTrafficLogFileRecords(config, { period: '60m', now });
    assert.equal(live.summary.liveWindowSeconds, 60);
    assert.equal(live.summary.liveRecords, 1);
    assert.equal(live.summary.liveDownloadBps, 2);
    assert.equal(live.summary.liveUploadBps, 4);

    const series = trafficLogFileSeries(config, { period: '60m', now });
    assert.equal(series.source, 'traffic_log_file');
    assert.equal(series.summary.totalDownloadBytes, 620);
    assert.equal(series.summary.totalUploadBytes, 315);
    assert.equal(series.summary.liveRecords, 1);
    assert.equal(series.summary.liveClients, 1);
    assert.equal(series.points.reduce((sum, point) => sum + point.records, 0), 2);

    const topSites = topTrafficLogFileSites(config, { minutes: 60, now });
    assert.deepEqual(topSites.rows.map(row => row.site), ['dns.google', 'dns.quad9.net']);
    assert.equal(topSites.totalVisits, 2);

    const topBandwidthSites = topTrafficLogFileSites(config, { minutes: 60, sort: 'bytes', now });
    assert.equal(topBandwidthSites.sort, 'bytes');
    assert.deepEqual(topBandwidthSites.rows.map(row => row.site), ['dns.google', 'dns.quad9.net']);
    assert.equal(topBandwidthSites.rows[0].totalBytes, 575);

    const topClients = topTrafficLogFileClients(config, { minutes: 60, now });
    assert.equal(topClients.totalClients, 2);
    assert.deepEqual(topClients.rows.map(row => row.clientIp), ['172.16.2.21', '172.16.2.22']);
    assert.equal(topClients.rows[0].totalBytes, 575);

    appendTrafficLogFileRecords(config, [{
      dedupeKey: 'traffic-file-wan-client-skipped',
      kind: 'flow',
      source: 'opnsense-filterlog',
      clientIp: '192.168.1.144',
      sourceIp: '192.168.1.144',
      destinationIp: '8.8.8.8',
      protocol: 'udp',
      serviceType: 'firewall-pass-out',
      direction: 'outgoing',
      startedAt: now - 20 * 60 * 1000,
      downloadBytes: 5000,
      uploadBytes: 1000,
      rawJson: JSON.stringify({ interface: 'wan' }),
      createdAt: now - 20 * 60 * 1000
    }, {
      dedupeKey: 'traffic-file-other-opnsense-subnet',
      kind: 'flow',
      source: 'opnsense-filterlog',
      clientIp: '10.10.10.25',
      sourceIp: '10.10.10.25',
      destinationIp: '8.8.4.4',
      protocol: 'udp',
      serviceType: 'firewall-pass-out',
      direction: 'outgoing',
      startedAt: now - 19 * 60 * 1000,
      downloadBytes: 2000,
      uploadBytes: 100,
      rawJson: JSON.stringify({ interface: 'lan' }),
      createdAt: now - 19 * 60 * 1000
    }], { now });
    const scopedTopClients = topTrafficLogFileClients(config, { minutes: 60, networks: '172.16.2.0/24', now });
    assert.deepEqual(scopedTopClients.rows.map(row => row.clientIp), ['172.16.2.21', '172.16.2.22']);
    const allOpnsenseClients = topTrafficLogFileClients(config, { minutes: 60, networks: 'any', excludedInterfaces: ['wan'], now });
    assert.equal(allOpnsenseClients.rows.some(row => row.clientIp === '10.10.10.25'), true);
    assert.equal(allOpnsenseClients.rows.some(row => row.clientIp === '192.168.1.144'), false);

    assert.equal(cleanupTrafficLogFile(config, 60, now).deleted, 1);
    assert.equal(listTrafficLogFileRecords(config, { period: '60m', now }).total, 4);
    appendTrafficLogFileRecords(config, [{
      dedupeKey: 'traffic-file-after-index',
      kind: 'flow',
      source: 'opnsense-filterlog',
      clientIp: '172.16.2.23',
      sourceIp: '172.16.2.23',
      destinationIp: '4.4.4.4',
      destinationDomain: 'dns.google',
      protocol: 'udp',
      serviceType: 'firewall-pass-out',
      direction: 'outgoing',
      startedAt: now - 5 * 1000,
      downloadBytes: 80,
      uploadBytes: 20,
      createdAt: now - 5 * 1000
    }], { now });
    const updated = listTrafficLogFileRecords(config, { period: '60m', now });
    assert.equal(updated.total, 5);
    assert.equal(updated.rows[0].dedupe_key, 'traffic-file-after-index');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('operational traffic file series prefers WAN interface counters for totals', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-traffic-wan-series-'));
  const now = Date.UTC(2026, 5, 27, 12, 0, 0);
  const config = {
    databasePath: path.join(directory, 'hotspot.db'),
    trafficLogs: {
      enabled: true,
      retentionMinutes: 60,
      resolveDomains: false,
      liveRefreshSeconds: 5
    }
  };
  try {
    const samples = [
      { interfaceName: 'wan', rxBytes: 1000, txBytes: 500, endpoint: 'test', sampledAt: now - 30 * 60 * 1000 },
      { interfaceName: 'wan', rxBytes: 2500, txBytes: 700, endpoint: 'test', sampledAt: now - 20 * 60 * 1000 },
      { interfaceName: 'wan', rxBytes: 3000, txBytes: 1200, endpoint: 'test', sampledAt: now - 10 * 60 * 1000 }
    ];
    appendTrafficLogFileRecords(config, [
      {
        dedupeKey: 'filterlog-total-should-not-drive-series',
        kind: 'flow',
        source: 'opnsense-filterlog',
        clientIp: '172.16.2.20',
        sourceIp: '172.16.2.20',
        destinationIp: '8.8.8.8',
        protocol: 'udp',
        serviceType: 'firewall-pass-out',
        direction: 'outgoing',
        startedAt: now - 15 * 60 * 1000,
        downloadBytes: 999999,
        uploadBytes: 888888,
        createdAt: now - 15 * 60 * 1000
      },
      ...samples.map(sample => trafficLogRecordFromInterfaceCounters(sample, { enabled: true }))
    ], { now });

    const series = trafficLogFileSeries(config, { period: '60m', now });
    assert.equal(series.source, 'traffic_log_wan_interface');
    assert.equal(series.interfaceName, 'wan');
    assert.equal(series.summary.totalDownloadBytes, 2000);
    assert.equal(series.summary.totalUploadBytes, 700);
    assert.equal(series.points.reduce((sum, point) => sum + point.records, 0), 3);

    const fifteenMinutes = trafficLogFileSeries(config, { period: '15m', now });
    assert.equal(fifteenMinutes.period, '15m');
    assert.equal(fifteenMinutes.bucket, 'minute');
    assert.equal(fifteenMinutes.points.length, 15);
    assert.equal(fifteenMinutes.summary.totalDownloadBytes, 500);

    const thirtyMinutes = trafficLogFileSeries(config, { period: '30m', now });
    assert.equal(thirtyMinutes.period, '30m');
    assert.equal(thirtyMinutes.bucket, 'minute');
    assert.equal(thirtyMinutes.points.length, 30);

    const fortyFiveMinutes = trafficLogFileSeries(config, { period: '45m', now });
    assert.equal(fortyFiveMinutes.period, '45m');
    assert.equal(fortyFiveMinutes.bucket, 'minute');
    assert.equal(fortyFiveMinutes.points.length, 45);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('operational traffic session logs reject network CIDR client addresses', () => {
  assert.equal(trafficLogRecordFromSession({
    sessionId: 'network-row',
    clientIp: '172.16.2.0/26',
    downloadBytes: 1180260905151,
    uploadBytes: 890881503149
  }, null, { enabled: true }), null);
});

test('authorization live traffic is calculated from gateway usage samples', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-live-traffic-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const now = Date.now();
  try {
    const authorization = db.saveAuthorization({
      method: 'voucher',
      identity: 'live-test',
      clientIp: '172.16.2.60',
      clientMac: 'AA:BB:CC:DD:EE:60',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: 'session-live',
      status: 'active',
      expiresAt: now + 60 * 60 * 1000
    });
    db.updateAuthorizationUsage(authorization.id, {
      downloadBytes: 1000,
      uploadBytes: 2000,
      lastSeenAt: now - 10000,
      sampledAt: now - 10000
    });
    assert.equal(db.authorizationLiveTraffic({ now }).liveRecords, 0);
    db.updateAuthorizationUsage(authorization.id, {
      downloadBytes: 11000,
      uploadBytes: 5000,
      lastSeenAt: now,
      sampledAt: now
    });
    const live = db.authorizationLiveTraffic({ now });
    assert.equal(live.liveSource, 'gateway_sessions');
    assert.equal(live.liveWindowSeconds, 10);
    assert.equal(live.liveRecords, 1);
    assert.equal(live.liveClients, 1);
    assert.equal(live.liveDownloadBps, 1000);
    assert.equal(live.liveUploadBps, 300);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('database vacuum compacts free pages and reports maintenance stats', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-vacuum-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  try {
    db.db.exec(`
      CREATE TABLE vacuum_payload (
        id INTEGER PRIMARY KEY,
        body TEXT NOT NULL
      ) STRICT;
    `);
    const payload = 'x'.repeat(4096);
    const insert = db.db.prepare('INSERT INTO vacuum_payload(body) VALUES (?)');
    for (let index = 0; index < 200; index += 1) insert.run(payload);
    db.db.exec('DELETE FROM vacuum_payload');

    const before = db.databaseMaintenanceStats();
    assert.ok(before.freelistCount > 0);
    const checkpoint = db.checkpointDatabase('TRUNCATE');
    assert.equal(checkpoint.ok, true);
    assert.equal(checkpoint.mode, 'TRUNCATE');
    assert.ok(checkpoint.after.totalFileBytes <= checkpoint.before.totalFileBytes);
    const result = db.vacuumDatabase();
    assert.equal(result.ok, true);
    assert.equal(result.before.path, path.join(directory, 'hotspot.db'));
    assert.equal(result.after.freelistCount, 0);
    assert.equal(fs.existsSync(result.backupPath), true);
    assert.ok(result.backupBytes > 0);
    assert.ok(result.durationMs >= 0);
    assert.ok(result.reclaimedBytes >= 0);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
