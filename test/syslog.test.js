import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { HotspotDatabase } from '../src/db.js';
import {
  createSyslogAutoExporter, createSyslogExportArchive, createSyslogHealthGuard, createSyslogServer,
  syslogCsv, syslogRecordFromSession, syslogRecordsFromMessage
} from '../src/services/syslog.js';
import { timedatectlNtpStatus } from '../src/services/law5651.js';
import { ipv4InNetworkList } from '../src/lib/network.js';

test('syslog records are scoped by network and chained with hashes', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  try {
    assert.equal(ipv4InNetworkList('172.16.2.42', '172.16.2.0/24'), true);
    assert.equal(ipv4InNetworkList('172.16.3.42', '172.16.2.0/24'), false);

    const lawConfig = { enabled: true, networks: '172.16.2.0/24' };
    const authorization = {
      id: 'auth-1',
      method: 'sms',
      identity: '905551112233',
      client_ip: '172.16.2.42',
      client_mac: 'aa:bb:cc:dd:ee:ff',
      created_at: 1760000000000
    };
    const session = {
      sessionId: 'session-1',
      clientIp: '172.16.2.42',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      downloadBytes: 1000,
      uploadBytes: 200,
      lastSeenAt: 1760000060000,
      raw: { sessionId: 'session-1' }
    };
    const outside = syslogRecordFromSession({ ...session, clientIp: '10.0.0.5' }, null, lawConfig);
    assert.equal(outside, null);

    const record = syslogRecordFromSession(session, authorization, lawConfig);
    const first = db.appendSyslogLogs([record, record]);
    assert.equal(first.inserted, 1);
    assert.equal(first.skipped, 1);
    assert.match(first.lastHash, /^[a-f0-9]{64}$/u);

    const secondRecord = syslogRecordFromSession({
      ...session,
      downloadBytes: 1200
    }, authorization, lawConfig);
    const second = db.appendSyslogLogs([secondRecord]);
    assert.equal(second.inserted, 1);
    const rows = db.listSyslogLogs({ order: 'asc' }).rows;
    assert.equal(rows.length, 2);
    assert.equal(rows[0].previous_hash, '0'.repeat(64));
    assert.equal(rows[1].previous_hash, rows[0].record_hash);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('authorization syslog quota usage does not sum cumulative session snapshots', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-quota-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const mebibyte = 1024 * 1024;
  const startedAt = Date.UTC(2026, 5, 27, 9, 0, 0);
  const periodEndAt = startedAt + 24 * 60 * 60 * 1000;
  const authorization = {
    id: 'auth-quota-1',
    method: 'sms',
    identity: '905551112233',
    client_ip: '172.16.2.42',
    client_mac: 'aa:bb:cc:dd:ee:ff',
    created_at: startedAt,
    expires_at: periodEndAt
  };
  try {
    db.appendSyslogLogs([
      syslogRecordFromSession({
        sessionId: 'session-1',
        clientIp: '172.16.2.42',
        clientMac: 'aa:bb:cc:dd:ee:ff',
        downloadBytes: 100 * mebibyte,
        uploadBytes: 20 * mebibyte,
        lastSeenAt: startedAt + 60_000
      }, authorization, { enabled: true, networks: '172.16.2.0/24' }),
      syslogRecordFromSession({
        sessionId: 'session-1',
        clientIp: '172.16.2.42',
        clientMac: 'aa:bb:cc:dd:ee:ff',
        downloadBytes: 120 * mebibyte,
        uploadBytes: 30 * mebibyte,
        lastSeenAt: startedAt + 120_000
      }, authorization, { enabled: true, networks: '172.16.2.0/24' })
    ]);
    const sessionUsage = db.authorizationSyslogUsage(authorization, {
      periodStartAt: startedAt,
      periodEndAt
    });
    assert.equal(sessionUsage.downloadBytes, 120 * mebibyte);
    assert.equal(sessionUsage.uploadBytes, 30 * mebibyte);
    assert.equal(sessionUsage.sessionRecords, 2);
    assert.equal(sessionUsage.flowRecords, 0);

    db.appendSyslogLogs([
      {
        dedupeKey: 'flow-quota-1',
        kind: 'flow',
        source: 'opnsense-filterlog',
        network: '172.16.2.0/24',
        clientIp: '172.16.2.42',
        clientMac: 'aa:bb:cc:dd:ee:ff',
        subscriberId: 'sms:905551112233',
        sourceIp: '172.16.2.42',
        destinationIp: '8.8.8.8',
        protocol: 'tcp',
        serviceType: 'firewall-pass-out',
        startedAt: startedAt + 180_000,
        downloadBytes: 30 * mebibyte,
        uploadBytes: 5 * mebibyte
      },
      {
        dedupeKey: 'flow-quota-2',
        kind: 'flow',
        source: 'opnsense-filterlog',
        network: '172.16.2.0/24',
        clientIp: '172.16.2.42',
        clientMac: 'aa:bb:cc:dd:ee:ff',
        subscriberId: 'sms:905551112233',
        sourceIp: '172.16.2.42',
        destinationIp: '1.1.1.1',
        protocol: 'tcp',
        serviceType: 'firewall-pass-out',
        startedAt: startedAt + 240_000,
        downloadBytes: 40 * mebibyte,
        uploadBytes: 7 * mebibyte
      }
    ]);
    const flowUsage = db.authorizationSyslogUsage(authorization, {
      periodStartAt: startedAt,
      periodEndAt
    });
    assert.equal(flowUsage.downloadBytes, 70 * mebibyte);
    assert.equal(flowUsage.uploadBytes, 12 * mebibyte);
    assert.equal(flowUsage.flowDownloadBytes, 70 * mebibyte);
    assert.equal(flowUsage.sessionDownloadBytes, 120 * mebibyte);
    assert.equal(flowUsage.flowRecords, 2);

    const resetAt = startedAt + 300_000;
    const resetUsage = db.resetAuthorizationQuotaUsage(authorization, {
      key: 'daily:2026-06-27',
      startAt: startedAt,
      endAt: periodEndAt
    }, {
      downloadBytes: 120 * mebibyte,
      uploadBytes: 30 * mebibyte,
      resetAt
    });
    assert.equal(resetUsage.download_bytes, 0);
    assert.equal(resetUsage.upload_bytes, 0);
    assert.equal(resetUsage.last_gateway_download_bytes, 120 * mebibyte);
    assert.equal(resetUsage.reset_at, resetAt);
    assert.equal(db.authorizationSyslogUsage(authorization, {
      periodStartAt: startedAt,
      periodEndAt,
      resetAt,
      baselineDownloadBytes: 120 * mebibyte,
      baselineUploadBytes: 30 * mebibyte
    }).downloadBytes, 0);

    db.appendSyslogLogs([{
      dedupeKey: 'session-quota-after-reset',
      kind: 'session',
      source: 'opnsense-session',
      network: '172.16.2.0/24',
      clientIp: '172.16.2.42',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      subscriberId: 'sms:905551112233',
      sourceIp: '172.16.2.42',
      protocol: 'ip',
      serviceType: 'internet-access',
      startedAt,
      endedAt: resetAt + 60_000,
      downloadBytes: 150 * mebibyte,
      uploadBytes: 35 * mebibyte,
      createdAt: resetAt + 1000
    }]);
    const afterResetUsage = db.authorizationSyslogUsage(authorization, {
      periodStartAt: startedAt,
      periodEndAt,
      resetAt,
      baselineDownloadBytes: 120 * mebibyte,
      baselineUploadBytes: 30 * mebibyte
    });
    assert.equal(afterResetUsage.downloadBytes, 30 * mebibyte);
    assert.equal(afterResetUsage.uploadBytes, 5 * mebibyte);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog parser records firewall flows for selected networks', () => {
  const message = [
    '<134>1 2026-06-26T16:45:00Z opnsense filterlog[70765]:',
    '100,0,,123,igb1,match,pass,out,4,0x0,,64,1,0,none,6,tcp,60,172.16.2.2,8.8.8.8,54321,443,0,S,1,0,65535,,mss'
  ].join(' ') + '\n';
  const records = syslogRecordsFromMessage(message, {
    enabled: true,
    syslogEnabled: true,
    networks: '172.16.2.0/24'
  }, 1782492300000, 'test');
  assert.equal(records.length, 1);
  assert.equal(records[0].kind, 'flow');
  assert.equal(records[0].source, 'opnsense-filterlog');
  assert.equal(records[0].clientIp, '172.16.2.2');
  assert.equal(records[0].sourceIp, '172.16.2.2');
  assert.equal(records[0].destinationIp, '8.8.8.8');
  assert.equal(records[0].sourcePort, '54321');
  assert.equal(records[0].destinationPort, '443');
  assert.equal(records[0].protocol, 'tcp');
  assert.equal(records[0].uploadBytes, 60);
  assert.equal(records[0].downloadBytes, 0);
});

test('syslog parser enriches firewall flows with client MAC lookup', () => {
  const message = [
    '<134>1 2026-06-26T16:45:00Z opnsense filterlog[70765]:',
    '100,0,,123,igb1,match,pass,in,4,0x0,,64,1,0,none,17,udp,73,172.16.3.4,172.16.3.1,40549,53,53'
  ].join(' ') + '\n';
  const records = syslogRecordsFromMessage(message, {
    enabled: true,
    syslogEnabled: true,
    networks: '172.16.3.0/24'
  }, 1782492300000, 'mac-lookup', new Map([
    ['172.16.3.4', { clientMac: 'fa:93:8f:47:d5:8b' }]
  ]));
  assert.equal(records.length, 1);
  assert.equal(records[0].clientIp, '172.16.3.4');
  assert.equal(records[0].clientMac, 'FA:93:8F:47:D5:8B');
});

test('syslog parser falls back to generic IP and port extraction', () => {
  const message = '<134>2026-06-26 opnsense firewall pass out tcp 172.16.2.2 54321 8.8.8.8 443 length 72';
  const records = syslogRecordsFromMessage(message, {
    enabled: true,
    syslogEnabled: true,
    networks: '172.16.2.0/24'
  }, 1782492300000, 'fallback');
  assert.equal(records.length, 1);
  assert.equal(records[0].clientIp, '172.16.2.2');
  assert.equal(records[0].destinationIp, '8.8.8.8');
  assert.equal(records[0].sourcePort, '54321');
  assert.equal(records[0].destinationPort, '443');
  assert.equal(records[0].uploadBytes, 72);
});

test('syslog append fills missing flow MAC from active authorization identity', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-flow-mac-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  try {
    db.saveAuthorization({
      method: 'sms',
      identity: '905551112233',
      clientIp: '172.16.2.42',
      clientMac: 'aa:bb:cc:dd:ee:ff',
      gatewayMode: 'opnsense-api',
      gatewaySessionId: 'session-1',
      status: 'active',
      expiresAt: Date.now() + 60_000,
      redirectUrl: '',
      gatewayResponse: null,
      error: ''
    });
    const message = [
      '<134>1 2026-06-26T16:45:00Z opnsense filterlog[70765]:',
      '100,0,,123,igb1,match,pass,out,4,0x0,,64,1,0,none,6,tcp,60,172.16.2.42,8.8.8.8,54321,443,0,S,1,0,65535,,mss'
    ].join(' ') + '\n';
    const records = syslogRecordsFromMessage(message, {
      enabled: true,
      syslogEnabled: true,
      networks: '172.16.2.0/24'
    }, Date.now() + 1000, 'active-auth');
    assert.equal(records[0].clientMac, '');
    db.appendSyslogLogs(records);
    const row = db.listSyslogLogs({ order: 'asc' }).rows[0];
    assert.equal(row.client_mac, 'AA:BB:CC:DD:EE:FF');
    assert.equal(row.subscriber_id, 'sms:905551112233');
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog CSV uses the configured export time zone', () => {
  const csv = syslogCsv([{
    sequence: 1,
    created_at: Date.UTC(2026, 5, 27, 13, 59, 50, 366),
    kind: 'flow',
    source: 'opnsense-filterlog',
    network: '172.16.2.0/24',
    client_ip: '172.16.2.42',
    client_mac: 'AA:BB:CC:DD:EE:FF',
    subscriber_id: '',
    source_ip: '172.16.2.42',
    source_port: '54321',
    destination_ip: '8.8.8.8',
    destination_port: '443',
    protocol: 'tcp',
    service_type: 'firewall-pass-out',
    started_at: Date.UTC(2026, 5, 27, 13, 59, 50, 366),
    ended_at: Date.UTC(2026, 5, 27, 13, 59, 50, 366),
    download_bytes: 0,
    upload_bytes: 60,
    previous_hash: '0'.repeat(64),
    record_hash: '1'.repeat(64)
  }], { timeZone: 'Europe/Istanbul' });
  assert.match(csv, /Created At \(Europe\/Istanbul\)/u);
  assert.match(csv, /2026-06-27T16:59:50\.366\+03:00/u);
  assert.doesNotMatch(csv, /2026-06-27T13:59:50\.366Z/u);
});

test('syslog export writes a daily log file', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-export-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  try {
    const lawConfig = { enabled: true, networks: 'any' };
    const record = syslogRecordFromSession({
      sessionId: 'session-1',
      clientIp: '192.168.10.50',
      downloadBytes: 10,
      uploadBytes: 5,
      lastSeenAt: 1760000060000
    }, {
      id: 'auth-1',
      method: 'voucher',
      identity: 'voucher-1',
      client_ip: '192.168.10.50',
      created_at: 1760000000000
    }, lawConfig);
    db.appendSyslogLogs([record]);
    const result = await createSyslogExportArchive({
      db,
      config: {
        appName: 'G-Hotspot',
        syslog: {
          exportDirectory: path.join(directory, 'exports'),
          timeZone: 'UTC',
          kamusmTimestampEnabled: false
        }
      }
    });
    assert.equal(result.recordCount, 1);
    assert.equal(result.timestampStatus, 'disabled');
    assert.match(result.filePath, /\.log$/u);
    assert.equal(fs.existsSync(result.filePath), true);
    const body = fs.readFileSync(result.filePath, 'utf8');
    assert.match(body, /# G-Hotspot 5651 daily syslog/u);
    assert.match(body, /"clientIp":"192\.168\.10\.50"/u);
    assert.equal(result.manifestPath, result.filePath);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog export timestamps the daily log with KamuSM credentials', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-kamusm-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const requests = [];
  const tsa = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    requests.push({
      authorization: request.headers.authorization,
      contentType: request.headers['content-type'],
      body
    });
    response.writeHead(200, { 'content-type': 'application/timestamp-reply' });
    response.end(Buffer.from('timestamp-token'));
  });
  await new Promise(resolve => tsa.listen(0, '127.0.0.1', resolve));
  try {
    const lawConfig = { enabled: true, networks: 'any' };
    const record = syslogRecordFromSession({
      sessionId: 'session-kamusm',
      clientIp: '192.168.10.51',
      downloadBytes: 15,
      uploadBytes: 7,
      lastSeenAt: 1760000060000
    }, {
      id: 'auth-kamusm',
      method: 'voucher',
      identity: 'voucher-kamusm',
      client_ip: '192.168.10.51',
      created_at: 1760000000000
    }, lawConfig);
    db.appendSyslogLogs([record]);
    db.setLaw5651State('timestamp_enabled_since_at', String(Date.UTC(2025, 9, 8, 0, 0, 0)), Date.UTC(2025, 9, 8, 0, 0, 0));
    const notifications = [];
    const result = await createSyslogExportArchive({
      db,
      config: {
        appName: 'G-Hotspot',
        syslog: {
          exportDirectory: path.join(directory, 'exports'),
          timeZone: 'UTC',
          kamusmTimestampEnabled: true,
          kamusmUser: 'user',
          kamusmPassword: 'pass',
          kamusmUrl: `http://127.0.0.1:${tsa.address().port}/tsa`,
          kamusmTimeoutSeconds: 60
        }
      },
      periodStartAt: Date.UTC(2025, 9, 9, 0, 0, 0),
      periodEndAt: Date.UTC(2025, 9, 10, 0, 0, 0),
      notificationSender: event => notifications.push(event)
    });

    const lastExport = db.syslogSummary().lastExport;
    assert.equal(result.timestampStatus, 'created');
    assert.equal(result.timestampMode, 'kamusm-rfc3161');
    assert.match(result.filePath, /2025-10-09\.log$/u);
    assert.equal(fs.existsSync(result.timestampRequestPath), true);
    assert.equal(fs.readFileSync(result.timestampTokenPath, 'utf8'), 'timestamp-token');
    assert.equal(requests.length, 1);
    assert.equal(requests[0].authorization, `Basic ${Buffer.from('user:pass').toString('base64')}`);
    assert.equal(requests[0].contentType, 'application/timestamp-query');
    assert.equal(requests[0].body[0], 0x30);
    assert.equal(result.signatureStatus, 'disabled');
    assert.equal(lastExport.timestampMode, 'kamusm-rfc3161');
    assert.equal(notifications.length, 1);
    assert.equal(notifications[0].event_type || notifications[0].eventType, 'syslog_kamusm_timestamp_succeeded');
  } finally {
    await new Promise(resolve => tsa.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog timestamp export reuses an existing timestamped period', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-kamusm-reuse-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  let requestCount = 0;
  const tsa = http.createServer(async (request, response) => {
    for await (const _chunk of request) {}
    requestCount += 1;
    response.writeHead(200, { 'content-type': 'application/timestamp-reply' });
    response.end(Buffer.from('timestamp-token'));
  });
  await new Promise(resolve => tsa.listen(0, '127.0.0.1', resolve));
  try {
    const periodStart = Date.UTC(2025, 9, 9, 0, 0, 0);
    const periodEnd = Date.UTC(2025, 9, 10, 0, 0, 0);
    const record = syslogRecordFromSession({
      sessionId: 'session-kamusm-reuse',
      clientIp: '192.168.10.52',
      downloadBytes: 15,
      uploadBytes: 7,
      lastSeenAt: periodStart + 60000
    }, {
      id: 'auth-kamusm-reuse',
      method: 'voucher',
      identity: 'voucher-kamusm-reuse',
      client_ip: '192.168.10.52',
      created_at: periodStart + 30000
    }, { enabled: true, networks: 'any' });
    record.createdAt = periodStart + 60000;
    db.appendSyslogLogs([record]);
    db.setLaw5651State('timestamp_enabled_since_at', String(periodStart - 60 * 60 * 1000), periodStart);

    const config = {
      appName: 'G-Hotspot',
      syslog: {
        exportDirectory: path.join(directory, 'exports'),
        timeZone: 'UTC',
        kamusmTimestampEnabled: true,
        kamusmUser: 'user',
        kamusmPassword: 'pass',
        kamusmUrl: `http://127.0.0.1:${tsa.address().port}/tsa`,
        kamusmTimeoutSeconds: 60
      }
    };
    const first = await createSyslogExportArchive({
      db,
      config,
      exportReason: 'kamusm',
      periodStartAt: periodStart,
      periodEndAt: periodEnd
    });
    const second = await createSyslogExportArchive({
      db,
      config,
      exportReason: 'kamusm',
      periodStartAt: periodStart,
      periodEndAt: periodEnd
    });

    assert.equal(requestCount, 1);
    assert.equal(second.id, first.id);
    assert.equal(second.reused, true);
    assert.equal(second.timestampStatus, 'created');
  } finally {
    await new Promise(resolve => tsa.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog export refuses retroactive timestamp when timestamping was disabled during the period', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-kamusm-gap-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  try {
    const periodStart = Date.UTC(2026, 6, 8, 10, 0, 0);
    const periodEnd = periodStart + 60 * 60 * 1000;
    const record = syslogRecordFromSession({
      sessionId: 'session-kamusm-gap',
      clientIp: '192.168.10.53',
      downloadBytes: 15,
      uploadBytes: 7,
      lastSeenAt: periodStart + 60000
    }, {
      id: 'auth-kamusm-gap',
      method: 'voucher',
      identity: 'voucher-kamusm-gap',
      client_ip: '192.168.10.53',
      created_at: periodStart + 30000
    }, { enabled: true, networks: 'any' });
    record.createdAt = periodStart + 60000;
    db.appendSyslogLogs([record]);
    db.setLaw5651State('timestamp_enabled_since_at', String(periodStart - 60 * 60 * 1000), periodStart);
    db.setLaw5651State('timestamp_disabled_intervals_json', JSON.stringify([{
      startAt: periodStart + 30 * 1000,
      endAt: periodStart + 90 * 1000
    }]), periodStart);

    const result = await createSyslogExportArchive({
      db,
      config: {
        appName: 'G-Hotspot',
        syslog: {
          exportDirectory: path.join(directory, 'exports'),
          timeZone: 'UTC',
          kamusmTimestampEnabled: true,
          kamusmUser: 'user',
          kamusmPassword: 'pass',
          kamusmUrl: 'http://127.0.0.1:1/tsa',
          kamusmTimeoutSeconds: 5
        }
      },
      exportReason: 'kamusm',
      periodStartAt: periodStart,
      periodEndAt: periodEnd
    });

    assert.equal(result.timestampStatus, 'evidence-gap');
    assert.match(result.timestampError, /not continuously enabled/u);
    assert.equal(result.timestampRequestPath, '');
    assert.equal(result.timestampTokenPath, '');
    assert.equal(fs.existsSync(`${result.filePath}.tsq`), false);
    assert.equal(fs.existsSync(`${result.filePath}.tsr`), false);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog export timestamps the daily log with a generic RFC3161 TSA URL', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-rfc3161-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const requests = [];
  const tsa = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requests.push({
      authorization: request.headers.authorization,
      contentType: request.headers['content-type'],
      accept: request.headers.accept,
      body: Buffer.concat(chunks)
    });
    response.writeHead(200, { 'content-type': 'application/timestamp-reply' });
    response.end(Buffer.from('rfc3161-token'));
  });
  await new Promise(resolve => tsa.listen(0, '127.0.0.1', resolve));
  try {
    const record = syslogRecordFromSession({
      sessionId: 'session-rfc3161',
      clientIp: '192.168.10.52',
      downloadBytes: 15,
      uploadBytes: 7,
      lastSeenAt: 1760000060000
    }, {
      id: 'auth-rfc3161',
      method: 'voucher',
      identity: 'voucher-rfc3161',
      client_ip: '192.168.10.52',
      created_at: 1760000000000
    }, { enabled: true, networks: 'any' });
    db.appendSyslogLogs([record]);
    db.setLaw5651State('timestamp_enabled_since_at', String(Date.UTC(2025, 9, 8, 0, 0, 0)), Date.UTC(2025, 9, 8, 0, 0, 0));
    const notifications = [];
    const result = await createSyslogExportArchive({
      db,
      config: {
        appName: 'G-Hotspot',
        syslog: {
          exportDirectory: path.join(directory, 'exports'),
          timeZone: 'UTC',
          timestampMode: 'rfc3161',
          timestampUrl: `http://127.0.0.1:${tsa.address().port}/tsa`,
          timestampTimeoutSeconds: 60
        }
      },
      periodStartAt: Date.UTC(2025, 9, 9, 0, 0, 0),
      periodEndAt: Date.UTC(2025, 9, 10, 0, 0, 0),
      notificationSender: event => notifications.push(event)
    });

    assert.equal(result.timestampStatus, 'created');
    assert.equal(result.timestampMode, 'rfc3161-url');
    assert.equal(fs.readFileSync(result.timestampTokenPath, 'utf8'), 'rfc3161-token');
    assert.equal(requests.length, 1);
    assert.equal(requests[0].authorization, undefined);
    assert.equal(requests[0].contentType, 'application/timestamp-query');
    assert.equal(requests[0].accept, 'application/timestamp-reply');
    assert.equal(requests[0].body[0], 0x30);
    assert.equal(notifications.length, 1);
    assert.equal(notifications[0].event_type || notifications[0].eventType, 'syslog_timestamp_succeeded');
  } finally {
    await new Promise(resolve => tsa.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog export timestamps the daily log with API key RFC3161 headers', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-api-key-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const requests = [];
  const tsa = http.createServer(async (request, response) => {
    for await (const _chunk of request) {}
    requests.push({
      authorization: request.headers.authorization,
      apiKey: request.headers['x-api-key'],
      contentType: request.headers['content-type']
    });
    response.writeHead(200, { 'content-type': 'application/timestamp-reply' });
    response.end(Buffer.from('api-key-token'));
  });
  await new Promise(resolve => tsa.listen(0, '127.0.0.1', resolve));
  try {
    const record = syslogRecordFromSession({
      sessionId: 'session-api-key',
      clientIp: '192.168.10.53',
      downloadBytes: 15,
      uploadBytes: 7,
      lastSeenAt: 1760000060000
    }, {
      id: 'auth-api-key',
      method: 'voucher',
      identity: 'voucher-api-key',
      client_ip: '192.168.10.53',
      created_at: 1760000000000
    }, { enabled: true, networks: 'any' });
    db.appendSyslogLogs([record]);
    db.setLaw5651State('timestamp_enabled_since_at', String(Date.UTC(2025, 9, 8, 0, 0, 0)), Date.UTC(2025, 9, 8, 0, 0, 0));
    const result = await createSyslogExportArchive({
      db,
      config: {
        appName: 'G-Hotspot',
        syslog: {
          exportDirectory: path.join(directory, 'exports'),
          timeZone: 'UTC',
          timestampMode: 'api-key',
          timestampApiUrl: `http://127.0.0.1:${tsa.address().port}/tsa`,
          timestampApiKey: 'secret-key',
          timestampApiKeyHeader: 'X-API-Key',
          timestampApiKeyPrefix: '',
          timestampApiTimeoutSeconds: 60
        }
      },
      periodStartAt: Date.UTC(2025, 9, 9, 0, 0, 0),
      periodEndAt: Date.UTC(2025, 9, 10, 0, 0, 0)
    });

    assert.equal(result.timestampStatus, 'created');
    assert.equal(result.timestampMode, 'api-key-rfc3161');
    assert.equal(fs.readFileSync(result.timestampTokenPath, 'utf8'), 'api-key-token');
    assert.equal(requests.length, 1);
    assert.equal(requests[0].authorization, undefined);
    assert.equal(requests[0].apiKey, 'secret-key');
    assert.equal(requests[0].contentType, 'application/timestamp-query');
  } finally {
    await new Promise(resolve => tsa.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog receiver stores raw firewall messages', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-receiver-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const receiver = createSyslogServer({
    db,
    config: {
      appName: 'G-Hotspot',
      syslog: {
        enabled: true,
        syslogEnabled: true,
        networks: 'any',
        syslogHost: '127.0.0.1',
        syslogPort: 0
      }
    },
    logger: { log() {}, warn() {} }
  });
  const sender = dgram.createSocket('udp4');
  try {
    receiver.start();
    await new Promise((resolve, reject) => {
      const startedAt = Date.now();
      const timer = setInterval(() => {
        if (receiver.status().listening) {
          clearInterval(timer);
          resolve();
        } else if (Date.now() - startedAt > 2000) {
          clearInterval(timer);
          reject(new Error('syslog receiver did not start'));
        }
      }, 10);
    });
    const message = '<134>2026-06-26 opnsense firewall pass out tcp 172.16.2.2 54321 8.8.8.8 443 length 72';
    await new Promise((resolve, reject) => {
      sender.send(Buffer.from(message), receiver.status().port, '127.0.0.1', error => {
        if (error) reject(error);
        else resolve();
      });
    });
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal(db.listSyslogLogs({ order: 'asc' }).rows.length, 1);
  } finally {
    sender.close();
    receiver.close();
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('traffic logs store OPNsense WAN filterlog flows outside 5651 scope', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-traffic-wan-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const receiver = createSyslogServer({
    db,
    config: {
      appName: 'G-Hotspot',
      syslog: {
        enabled: false,
        syslogEnabled: true,
        networks: '172.16.2.0/24',
        syslogHost: '127.0.0.1',
        syslogPort: 0
      },
      trafficLogs: {
        enabled: true,
        retentionDays: 30,
        resolveDomains: false
      }
    },
    logger: { log() {}, warn() {} }
  });
  const sender = dgram.createSocket('udp4');
  try {
    receiver.start();
    await new Promise((resolve, reject) => {
      const startedAt = Date.now();
      const timer = setInterval(() => {
        if (receiver.status().listening) {
          clearInterval(timer);
          resolve();
        } else if (Date.now() - startedAt > 2000) {
          clearInterval(timer);
          reject(new Error('syslog receiver did not start'));
        }
      }, 10);
    });
    const message = [
      '<134>1 2026-06-29T08:31:27+03:00 opnsense filterlog[70765]:',
      '100,0,,123,wan,match,pass,out,4,0x0,,64,1,0,none,17,udp,60,203.0.113.10,157.240.234.60,39660,443,0'
    ].join(' ') + '\n';
    await new Promise((resolve, reject) => {
      sender.send(Buffer.from(message), receiver.status().port, '127.0.0.1', error => {
        if (error) reject(error);
        else resolve();
      });
    });
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal(db.listSyslogLogs({ order: 'asc' }).rows.length, 0);
    const rows = db.listTrafficLogs({ kind: 'flow', order: 'asc' }).rows;
    assert.equal(rows.length, 1);
    assert.equal(rows[0].source, 'opnsense-filterlog');
    assert.equal(rows[0].client_ip, '203.0.113.10');
    assert.equal(rows[0].source_ip, '203.0.113.10');
    assert.equal(rows[0].destination_ip, '157.240.234.60');
    assert.equal(rows[0].source_port, '39660');
    assert.equal(rows[0].destination_port, '443');
    assert.equal(rows[0].protocol, 'udp');
    assert.equal(rows[0].direction, 'outgoing');
    assert.equal(rows[0].upload_bytes, 60);
    assert.equal(rows[0].download_bytes, 0);
    assert.match(rows[0].raw_json, /"interface":"wan"/u);
  } finally {
    sender.close();
    receiver.close();
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog retention cleanup does not delete old records automatically', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-retention-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  try {
    const record = syslogRecordFromSession({
      sessionId: 'session-old',
      clientIp: '192.168.10.52',
      downloadBytes: 1,
      uploadBytes: 1,
      lastSeenAt: Date.UTC(2024, 0, 1, 0, 1, 0)
    }, {
      id: 'auth-old',
      method: 'voucher',
      identity: 'voucher-old',
      client_ip: '192.168.10.52',
      created_at: Date.UTC(2024, 0, 1, 0, 0, 0)
    }, { enabled: true, networks: 'any' });
    record.createdAt = Date.UTC(2024, 0, 1, 0, 1, 0);
    db.appendSyslogLogs([record]);
    assert.equal(db.cleanupSyslogLogs(180, Date.UTC(2026, 0, 1, 0, 0, 0)), 0);
    assert.equal(db.listSyslogLogs().rows.length, 1);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog retention cleanup deletes only archived old records', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-retention-archived-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const oldAt = Date.UTC(2024, 0, 1, 0, 1, 0);
  const recentAt = Date.UTC(2025, 11, 1, 0, 1, 0);
  try {
    const lawConfig = { enabled: true, networks: 'any' };
    const oldRecord = syslogRecordFromSession({
      sessionId: 'session-old-archived',
      clientIp: '192.168.10.53',
      downloadBytes: 1,
      uploadBytes: 1,
      lastSeenAt: oldAt
    }, {
      id: 'auth-old-archived',
      method: 'voucher',
      identity: 'voucher-old-archived',
      client_ip: '192.168.10.53',
      created_at: oldAt - 60000
    }, lawConfig);
    oldRecord.createdAt = oldAt;
    const recentRecord = syslogRecordFromSession({
      sessionId: 'session-recent',
      clientIp: '192.168.10.54',
      downloadBytes: 2,
      uploadBytes: 2,
      lastSeenAt: recentAt
    }, {
      id: 'auth-recent',
      method: 'voucher',
      identity: 'voucher-recent',
      client_ip: '192.168.10.54',
      created_at: recentAt - 60000
    }, lawConfig);
    recentRecord.createdAt = recentAt;
    db.appendSyslogLogs([oldRecord, recentRecord]);
    const exported = await createSyslogExportArchive({
      db,
      config: {
        appName: 'G-Hotspot',
        syslog: {
          exportDirectory: path.join(directory, 'exports'),
          timeZone: 'UTC',
          kamusmTimestampEnabled: false
        }
      },
      exportReason: 'auto',
      periodStartAt: Date.UTC(2024, 0, 1, 0, 0, 0),
      periodEndAt: Date.UTC(2024, 0, 2, 0, 0, 0)
    });
    assert.equal(exported.recordCount, 1);
    assert.equal(exported.firstSequence, 1);
    assert.equal(exported.lastSequence, 1);
    assert.equal(db.cleanupSyslogLogs(180, Date.UTC(2026, 0, 1, 0, 0, 0)), 1);
    const remaining = db.listSyslogLogs({ order: 'asc' }).rows;
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0].client_ip, '192.168.10.54');
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog retention cleanup supports legacy archives without sequence metadata', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-retention-legacy-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const oldAt = Date.UTC(2024, 0, 1, 0, 1, 0);
  try {
    const lawConfig = { enabled: true, networks: 'any' };
    const record = syslogRecordFromSession({
      sessionId: 'session-old-legacy',
      clientIp: '192.168.10.56',
      downloadBytes: 1,
      uploadBytes: 1,
      lastSeenAt: oldAt
    }, {
      id: 'auth-old-legacy',
      method: 'voucher',
      identity: 'voucher-old-legacy',
      client_ip: '192.168.10.56',
      created_at: oldAt - 60000
    }, lawConfig);
    record.createdAt = oldAt;
    db.appendSyslogLogs([record]);

    const exportDirectory = path.join(directory, 'exports');
    fs.mkdirSync(exportDirectory, { recursive: true });
    const exportPath = path.join(exportDirectory, 'legacy.csv');
    fs.writeFileSync(exportPath, 'legacy syslog export\n');
    const exportHash = createHash('sha256').update(fs.readFileSync(exportPath)).digest('hex');
    db.createLaw5651Export({
      exportReason: 'auto',
      periodStartAt: Date.UTC(2024, 0, 1, 0, 0, 0),
      periodEndAt: Date.UTC(2024, 0, 2, 0, 0, 0),
      filePath: exportPath,
      manifestPath: `${exportPath}.manifest.json`,
      recordCount: 1,
      firstCreatedAt: oldAt,
      lastCreatedAt: oldAt,
      exportHash,
      timestampStatus: 'disabled'
    });

    assert.equal(db.cleanupSyslogLogs(180, Date.UTC(2026, 0, 1, 0, 0, 0)), 1);
    assert.equal(db.listSyslogLogs().rows.length, 0);
    const exportRow = db.latestLaw5651Export({ reason: 'auto' });
    assert.equal(exportRow.first_sequence, 1);
    assert.equal(exportRow.last_sequence, 1);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog retention cleanup keeps old records when archive file is missing', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-retention-missing-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const oldAt = Date.UTC(2024, 0, 1, 0, 1, 0);
  try {
    const lawConfig = { enabled: true, networks: 'any' };
    const record = syslogRecordFromSession({
      sessionId: 'session-old-missing',
      clientIp: '192.168.10.55',
      downloadBytes: 1,
      uploadBytes: 1,
      lastSeenAt: oldAt
    }, {
      id: 'auth-old-missing',
      method: 'voucher',
      identity: 'voucher-old-missing',
      client_ip: '192.168.10.55',
      created_at: oldAt - 60000
    }, lawConfig);
    record.createdAt = oldAt;
    db.appendSyslogLogs([record]);
    const exported = await createSyslogExportArchive({
      db,
      config: {
        appName: 'G-Hotspot',
        syslog: {
          exportDirectory: path.join(directory, 'exports'),
          timeZone: 'UTC',
          kamusmTimestampEnabled: false
        }
      },
      exportReason: 'auto',
      periodStartAt: Date.UTC(2024, 0, 1, 0, 0, 0),
      periodEndAt: Date.UTC(2024, 0, 2, 0, 0, 0)
    });
    fs.rmSync(exported.filePath);
    assert.equal(db.cleanupSyslogLogs(180, Date.UTC(2026, 0, 1, 0, 0, 0)), 0);
    assert.equal(db.listSyslogLogs().rows.length, 1);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog health guard records NTP loss and restoration', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-health-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  let synced = false;
  try {
    const guard = createSyslogHealthGuard({
      db,
      config: {
        appName: 'G-Hotspot',
        syslog: {
          enabled: true,
          exportDirectory: path.join(directory, 'exports'),
          timeZone: 'UTC',
          healthCheckIntervalSeconds: 60,
          clockSkewAlertSeconds: 120,
          ntpCheckEnabled: true
        }
      },
      ntpStatusProvider: async () => ({ synced, error: '' }),
      logger: { warn() {} }
    });
    await guard.check(Date.now());
    synced = true;
    await guard.check(Date.now());
    const eventTypes = db.listSyslogEvents({ order: 'asc' }).rows.map(row => row.event_type);
    assert.equal(eventTypes.includes('ntp_sync_lost'), true);
    assert.equal(eventTypes.includes('ntp_sync_restored'), true);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('timedatectl NTP status reports missing command errors clearly', async () => {
  const error = new Error('spawn timedatectl ENOENT');
  error.code = 'ENOENT';
  const result = await timedatectlNtpStatus({
    execFileRunner: async () => {
      throw error;
    }
  });
  assert.equal(result.synced, null);
  assert.match(result.error, /timedatectl is not available/u);
  assert.match(result.error, /SYSLOG_NTP_CHECK_ENABLED=false/u);
  assert.doesNotMatch(result.error, /spawn timedatectl ENOENT/u);
});

test('timedatectl NTP status reports unavailable systemd bus clearly', async () => {
  const error = new Error('Command failed: timedatectl show');
  error.stderr = 'System has not been booted with systemd as init system. Failed to connect to bus.';
  const result = await timedatectlNtpStatus({
    execFileRunner: async () => {
      throw error;
    }
  });
  assert.equal(result.synced, null);
  assert.match(result.error, /systemd or DBus is not available/u);
  assert.doesNotMatch(result.error, /Command failed/u);
});

test('syslog health guard records warning, blocking and recovery storage transitions', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-storage-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  let storage = {
    available: true,
    directory,
    usagePercent: 45,
    alertPercent: 40,
    blockPercent: 90,
    warning: true,
    blocking: false
  };
  try {
    const guard = createSyslogHealthGuard({
      db,
      config: {
        appName: 'G-Hotspot',
        syslog: {
          enabled: true,
          exportDirectory: path.join(directory, 'exports'),
          timeZone: 'UTC',
          healthCheckIntervalSeconds: 60,
          clockSkewAlertSeconds: 120,
          ntpCheckEnabled: false
        }
      },
      storageStatusProvider: () => storage,
      ntpStatusProvider: null,
      logger: { warn() {} }
    });
    await guard.check(Date.now());
    storage = { ...storage, usagePercent: 95, warning: true, blocking: true };
    await guard.check(Date.now());
    storage = { ...storage, usagePercent: 20, warning: false, blocking: false };
    await guard.check(Date.now());
    const eventTypes = db.listSyslogEvents({ order: 'asc' }).rows
      .map(row => row.event_type)
      .filter(value => value.startsWith('syslog_storage_'));
    assert.deepEqual([...eventTypes].sort(), [
      'syslog_storage_block_threshold_reached',
      'syslog_storage_recovered',
      'syslog_storage_warning_threshold_reached',
    ].sort());
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog storage notifications repeat by configured interval', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-notify-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  let now = 1782600000000;
  const notifications = [];
  const storage = {
    available: true,
    directory,
    usagePercent: 65,
    alertPercent: 40,
    blockPercent: 90,
    warning: true,
    blocking: false
  };
  try {
    const guard = createSyslogHealthGuard({
      db,
      config: {
        appName: 'G-Hotspot',
        notifications: {
          emailRepeatFrequency: 'daily',
          smsRepeatFrequency: 'state-change'
        },
        syslog: {
          enabled: true,
          exportDirectory: path.join(directory, 'exports'),
          timeZone: 'UTC',
          healthCheckIntervalSeconds: 60,
          clockSkewAlertSeconds: 999999999,
          ntpCheckEnabled: false
        }
      },
      storageStatusProvider: () => storage,
      notificationSender: (event, options = {}) => {
        const type = event.eventType || event.event_type;
        if (String(type).startsWith('syslog_storage_')) {
          notifications.push({ type, channels: options.channels || ['email', 'sms'] });
        }
      },
      nowProvider: () => now,
      ntpStatusProvider: null,
      logger: { warn() {} }
    });
    await guard.check(now);
    now += 60 * 60 * 1000;
    await guard.check(now);
    now += 24 * 60 * 60 * 1000;
    await guard.check(now);
    assert.deepEqual(notifications, [
      { type: 'syslog_storage_warning_threshold_reached', channels: ['email', 'sms'] },
      { type: 'syslog_storage_warning_threshold_reached', channels: ['email'] }
    ]);
    assert.equal(
      db.listSyslogEvents({ order: 'asc' }).rows
        .filter(row => row.event_type === 'syslog_storage_warning_threshold_reached').length,
      1
    );
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog storage notifications can repeat on every system startup', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-startup-notify-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const notifications = [];
  const storage = {
    available: true,
    directory,
    usagePercent: 65,
    alertPercent: 40,
    blockPercent: 90,
    warning: true,
    blocking: false
  };
  const config = {
    appName: 'G-Hotspot',
    notifications: {
      emailRepeatFrequency: 'state-change',
      emailStartupEnabled: true,
      smsRepeatFrequency: 'state-change',
      smsStartupEnabled: false
    },
    syslog: {
      enabled: true,
      exportDirectory: path.join(directory, 'exports'),
      timeZone: 'UTC',
      healthCheckIntervalSeconds: 60,
      clockSkewAlertSeconds: 999999999,
      ntpCheckEnabled: false
    }
  };
  const createGuard = () => createSyslogHealthGuard({
    db,
    config,
    storageStatusProvider: () => storage,
    notificationSender: (event, options = {}) => {
      const type = event.eventType || event.event_type;
      if (String(type).startsWith('syslog_storage_')) {
        notifications.push({ type, channels: options.channels || ['email', 'sms'] });
      }
    },
    ntpStatusProvider: null,
    logger: { warn() {} }
  });
  try {
    await createGuard().check(Date.now());
    const restartedGuard = createGuard();
    await restartedGuard.check(Date.now());
    await restartedGuard.check(Date.now());
    assert.deepEqual(notifications, [
      { type: 'syslog_storage_warning_threshold_reached', channels: ['email', 'sms'] },
      { type: 'syslog_storage_warning_threshold_reached', channels: ['email'] }
    ]);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog automatic exporter catches up completed daily KamuSM logs after restart', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-auto-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const tsa = http.createServer(async (request, response) => {
    for await (const _chunk of request) {}
    response.writeHead(200, { 'content-type': 'application/timestamp-reply' });
    response.end(Buffer.from('timestamp-token'));
  });
  await new Promise(resolve => tsa.listen(0, '127.0.0.1', resolve));
  try {
    const record = syslogRecordFromSession({
      sessionId: 'session-auto',
      clientIp: '172.16.2.42',
      downloadBytes: 10,
      uploadBytes: 5,
      lastSeenAt: Date.UTC(2026, 5, 26, 21, 55, 0)
    }, {
      id: 'auth-auto',
      method: 'voucher',
      identity: 'voucher-auto',
      client_ip: '172.16.2.42',
      created_at: Date.UTC(2026, 5, 26, 21, 1, 0)
    }, { enabled: true, networks: '172.16.2.0/24' });
    record.createdAt = Date.UTC(2026, 5, 26, 21, 55, 0);
    db.appendSyslogLogs([record]);
    db.setLaw5651State('timestamp_enabled_since_at', String(Date.UTC(2026, 5, 26, 20, 0, 0)), Date.UTC(2026, 5, 26, 20, 0, 0));

    const config = {
      appName: 'G-Hotspot',
      syslog: {
        enabled: true,
        timeZone: 'Europe/Istanbul',
        exportDirectory: path.join(directory, 'exports'),
        kamusmTimestampEnabled: true,
        kamusmUser: 'user',
        kamusmPassword: 'pass',
        kamusmUrl: `http://127.0.0.1:${tsa.address().port}/tsa`,
        kamusmTimeoutSeconds: 60
      }
    };
    const exporter = createSyslogAutoExporter({ db, config, logger: { warn() {} } });
    assert.equal((await exporter.runDueExports(Date.UTC(2026, 5, 27, 20, 59, 58))).length, 0);
    const results = await exporter.runDueExports(Date.UTC(2026, 5, 27, 21, 1, 0));
    assert.equal(results.length, 1);
    assert.equal(results[0].exportReason, 'kamusm');
    assert.equal(results[0].periodStartAt, Date.UTC(2026, 5, 26, 21, 0, 0));
    assert.equal(results[0].periodEndAt, Date.UTC(2026, 5, 27, 21, 0, 0));
    assert.equal(results[0].recordCount, 1);
    assert.match(results[0].filePath, /2026-06-27\.log$/u);
    assert.equal((await exporter.runDueExports(Date.UTC(2026, 5, 27, 21, 1, 0))).length, 0);
  } finally {
    await new Promise(resolve => tsa.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog automatic exporter rate-limits timestamp catch-up to the selected interval', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-auto-kamusm-rate-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  let requestCount = 0;
  const tsa = http.createServer(async (request, response) => {
    for await (const _chunk of request) {}
    requestCount += 1;
    response.writeHead(200, { 'content-type': 'application/timestamp-reply' });
    response.end(Buffer.from('timestamp-token'));
  });
  await new Promise(resolve => tsa.listen(0, '127.0.0.1', resolve));
  try {
    const hour = 60 * 60 * 1000;
    const startedAt = Date.UTC(2026, 5, 29, 5, 0, 0);
    const dueAt = startedAt + 3 * hour;
    const record = syslogRecordFromSession({
      sessionId: 'session-auto-kamusm-rate',
      clientIp: '172.16.3.4',
      downloadBytes: 1280,
      uploadBytes: 0,
      lastSeenAt: startedAt + 60000
    }, {
      id: 'auth-auto-kamusm-rate',
      method: 'voucher',
      identity: 'voucher-auto-kamusm-rate',
      client_ip: '172.16.3.4',
      created_at: startedAt
    }, { enabled: true, networks: '172.16.3.0/24' });
    record.createdAt = startedAt;
    db.appendSyslogLogs([record]);
    db.setLaw5651State('timestamp_enabled_since_at', String(startedAt - hour), startedAt - hour);

    const config = {
      appName: 'G-Hotspot',
      syslog: {
        enabled: true,
        timeZone: 'Europe/Istanbul',
        exportDirectory: path.join(directory, 'exports'),
        kamusmTimestampEnabled: true,
        kamusmUser: 'user',
        kamusmPassword: 'pass',
        kamusmUrl: `http://127.0.0.1:${tsa.address().port}/tsa`,
        kamusmTimeoutSeconds: 60,
        autoExportEnabled: true,
        autoExportInterval: '1h',
        autoExportIntervalMinutes: 60
      }
    };
    const exporter = createSyslogAutoExporter({ db, config, logger: { warn() {} } });
    const first = await exporter.runDueExports(dueAt);
    assert.equal(first.length, 1);
    assert.equal(first[0].exportReason, 'kamusm');
    assert.equal(first[0].periodStartAt, startedAt);
    assert.equal(first[0].periodEndAt, startedAt + hour);
    assert.equal(first[0].timestampStatus, 'created');
    assert.equal(requestCount, 1);

    assert.equal((await exporter.runDueExports(dueAt)).length, 0);
    assert.equal(requestCount, 1);

    const second = await exporter.runDueExports(dueAt + hour);
    assert.equal(second.length, 1);
    assert.equal(second[0].periodStartAt, startedAt + hour);
    assert.equal(second[0].periodEndAt, startedAt + 2 * hour);
    assert.equal(second[0].timestampStatus, 'created');
    assert.equal(requestCount, 2);
  } finally {
    await new Promise(resolve => tsa.close(resolve));
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog automatic exporter writes interval exports without KamuSM', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-auto-interval-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const startedAt = Date.UTC(2026, 5, 29, 5, 31, 27, 496);
  try {
    const record = syslogRecordFromSession({
      sessionId: 'session-auto-interval',
      clientIp: '172.16.3.2',
      downloadBytes: 1280,
      uploadBytes: 0,
      lastSeenAt: startedAt
    }, {
      id: 'auth-auto-interval',
      method: 'voucher',
      identity: 'voucher-auto-interval',
      client_ip: '172.16.3.2',
      created_at: startedAt
    }, { enabled: true, networks: '172.16.3.0/24' });
    record.createdAt = startedAt;
    db.appendSyslogLogs([record]);

    const config = {
      appName: 'G-Hotspot',
      syslog: {
        enabled: true,
        timeZone: 'Europe/Istanbul',
        exportDirectory: path.join(directory, 'exports'),
        kamusmTimestampEnabled: false,
        autoExportEnabled: true,
        autoExportInterval: '6h',
        autoExportIntervalMinutes: 360
      }
    };
    const exporter = createSyslogAutoExporter({ db, config, logger: { warn() {} } });
    assert.equal((await exporter.runDueExports(startedAt + 6 * 60 * 60 * 1000 - 1)).length, 0);
    const results = await exporter.runDueExports(startedAt + 6 * 60 * 60 * 1000);
    assert.equal(results.length, 1);
    assert.equal(results[0].exportReason, 'auto');
    assert.equal(results[0].periodStartAt, startedAt);
    assert.equal(results[0].periodEndAt, startedAt + 6 * 60 * 60 * 1000);
    assert.equal(results[0].recordCount, 1);
    assert.equal(results[0].timestampStatus, 'disabled');
    assert.equal(fs.existsSync(results[0].filePath), true);
    assert.doesNotMatch(path.basename(results[0].filePath), /^2026-06-29\.log$/u);
    assert.equal((await exporter.runDueExports(startedAt + 6 * 60 * 60 * 1000)).length, 0);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('syslog automatic exporter waits for fresh OPNsense communication', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-syslog-auto-gateway-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  const startedAt = Date.UTC(2026, 5, 29, 5, 31, 27);
  const dueAt = startedAt + 60 * 60 * 1000;
  try {
    const record = syslogRecordFromSession({
      sessionId: 'session-auto-gateway',
      clientIp: '172.16.3.2',
      downloadBytes: 1280,
      uploadBytes: 0,
      lastSeenAt: startedAt
    }, {
      id: 'auth-auto-gateway',
      method: 'voucher',
      identity: 'voucher-auto-gateway',
      client_ip: '172.16.3.2',
      created_at: startedAt
    }, { enabled: true, networks: '172.16.3.0/24' });
    record.createdAt = startedAt;
    db.appendSyslogLogs([record]);

    const config = {
      appName: 'G-Hotspot',
      gateway: {
        mode: 'opnsense-api',
        syncEnabled: true,
        syncIntervalSeconds: 10
      },
      syslog: {
        enabled: true,
        timeZone: 'Europe/Istanbul',
        exportDirectory: path.join(directory, 'exports'),
        kamusmTimestampEnabled: false,
        autoExportEnabled: true,
        autoExportInterval: '1h',
        autoExportIntervalMinutes: 60
      }
    };
    const exporter = createSyslogAutoExporter({ db, config, logger: { warn() {} } });
    assert.equal((await exporter.runDueExports(dueAt)).length, 0);
    assert.equal(exporter.status().waitingForGateway, true);
    db.setRuntimeState('opnsense_last_successful_sync_at', String(dueAt), dueAt);
    const results = await exporter.runDueExports(dueAt);
    assert.equal(results.length, 1);
    assert.equal(results[0].exportReason, 'auto');
    assert.equal(results[0].periodStartAt, startedAt);
    assert.equal(results[0].periodEndAt, dueAt);
    assert.equal(exporter.status().waitingForGateway, false);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
