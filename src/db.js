import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { isIP } from 'node:net';
import { normalizeMac } from './lib/security.js';
import { normalizeLanguage } from './lib/languages.js';
import { ipv4InNetworkList, isPrivateIpv4, normalizeNetworkList } from './lib/network.js';

const LIVE_TRAFFIC_WINDOW_MS = 60 * 1000;
const TRAFFIC_ROLLUP_BACKFILL_DAYS = 32;
const TRAFFIC_ROLLUP_BACKFILL_BATCH = 5000;
const INTERFACE_COUNTER_SOURCE = 'opnsense-interface-counter';

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(item => stableJson(item)).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key =>
      `${JSON.stringify(key)}:${stableJson(value[key])}`
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256Hex(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function minuteBucket(timestamp) {
  return Math.floor(Math.max(0, Math.trunc(Number(timestamp) || 0)) / 60000) * 60000;
}

function integerTimestamp(value, fallback = Date.now()) {
  const timestamp = Number(value);
  if (Number.isFinite(timestamp)) return Math.trunc(timestamp);
  return Math.trunc(Number(fallback) || Date.now());
}

function cleanSiteText(value, limit = 255) {
  return String(value || '').trim().slice(0, limit);
}

function publicDestinationIp(value) {
  const text = cleanSiteText(value, 64);
  if (isIP(text) !== 4) return isIP(text) === 6 && !/^(::1|fe80:|fc|fd)/iu.test(text) ? text : '';
  const octets = text.split('.').map(part => Number(part));
  if (octets.length !== 4 || octets.some(part => !Number.isInteger(part))) return '';
  if (octets[0] === 10 || octets[0] === 127 || octets[0] === 0) return '';
  if (octets[0] === 169 && octets[1] === 254) return '';
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return '';
  if (octets[0] === 192 && octets[1] === 168) return '';
  if (octets[0] >= 224) return '';
  return text;
}

function safeNetworkList(value) {
  try {
    return normalizeNetworkList(value);
  } catch {
    return 'any';
  }
}

function trafficLogRawJson(row) {
  if (!row?.raw_json) return {};
  try {
    return JSON.parse(row.raw_json);
  } catch {
    return {};
  }
}

function trafficLogInterfaceName(row) {
  const raw = trafficLogRawJson(row);
  return String(raw.interface || raw.interfaceName || '').trim().toLowerCase();
}

function trafficLogSiteLabel(row = {}) {
  const domain = cleanSiteText(row.destination_domain, 255)
    .toLowerCase()
    .replace(/\.$/u, '')
    .replace(/^www\./u, '');
  if (domain.includes('.')) return domain;
  return publicDestinationIp(row.destination_ip);
}

function isDnsResolverTraffic(row = {}) {
  const port = String(row.destination_port || '').trim();
  const service = String(row.service_type || '').trim().toLowerCase();
  return port === '53' || service === 'dns' || service === 'domain';
}

function isInterfaceCounterTraffic(row = {}) {
  return row.source === INTERFACE_COUNTER_SOURCE || row.service_type === 'interface-counter';
}

function fileHash(filePath) {
  return createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function normalizedLeaseSeconds(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  return Math.min(4294967295, Math.max(60, Math.ceil(seconds)));
}

function law5651HashPayload(record, previousHash) {
  return stableJson({
    previousHash,
    kind: record.kind,
    source: record.source,
    network: record.network,
    clientIp: record.clientIp,
    clientMac: record.clientMac,
    subscriberId: record.subscriberId,
    sourceIp: record.sourceIp,
    sourcePort: record.sourcePort,
    destinationIp: record.destinationIp,
    destinationPort: record.destinationPort,
    protocol: record.protocol,
    serviceType: record.serviceType,
    startedAt: record.startedAt,
    endedAt: record.endedAt,
    downloadBytes: record.downloadBytes,
    uploadBytes: record.uploadBytes,
    rawJson: record.rawJson,
    createdAt: record.createdAt
  });
}

function law5651EventHashPayload(event, previousHash) {
  return stableJson({
    previousHash,
    eventType: event.eventType,
    severity: event.severity,
    message: event.message,
    detailJson: event.detailJson,
    createdAt: event.createdAt
  });
}

export class HotspotDatabase {
  constructor(filePath) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    this.filePath = filePath;
    this.db = new DatabaseSync(filePath, { timeout: 5000 });
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
    this.migrate();
  }

  migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS challenges (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('email', 'whatsapp', 'sms', 'telegram', 'nvi')),
        target TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        client_mac TEXT,
        redirect_url TEXT,
        language TEXT NOT NULL DEFAULT 'en',
        status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'verified', 'expired', 'failed')),
        attempts INTEGER NOT NULL DEFAULT 0,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        verified_at INTEGER,
        last_error TEXT
      ) STRICT;

      CREATE INDEX IF NOT EXISTS challenges_target_created_idx
        ON challenges(kind, target, created_at);
      CREATE INDEX IF NOT EXISTS challenges_client_created_idx
        ON challenges(kind, client_ip, created_at);
      CREATE INDEX IF NOT EXISTS challenges_secret_idx
        ON challenges(kind, secret_hash);

      CREATE TABLE IF NOT EXISTS vouchers (
        id TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL UNIQUE,
        code_hint TEXT NOT NULL,
        code_prefix TEXT NOT NULL DEFAULT '',
        label TEXT,
        max_uses INTEGER NOT NULL DEFAULT 1,
        used_count INTEGER NOT NULL DEFAULT 0,
        duration_minutes INTEGER NOT NULL,
        valid_from INTEGER,
        expires_at INTEGER,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS authorizations (
        id TEXT PRIMARY KEY,
        method TEXT NOT NULL CHECK (method IN ('voucher', 'email', 'whatsapp', 'sms', 'telegram', 'admin-approval', 'nvi')),
        identity TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        client_mac TEXT,
        gateway_mode TEXT NOT NULL,
        gateway_session_id TEXT,
        status TEXT NOT NULL CHECK (status IN ('active', 'failed')),
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        redirect_url TEXT,
        gateway_response_json TEXT,
        error TEXT,
        kea_deleted_at INTEGER,
        lease_seconds INTEGER,
        quota_blocked_until INTEGER,
        quota_period_key TEXT,
        quota_exceeded_at INTEGER
      ) STRICT;

      CREATE INDEX IF NOT EXISTS authorizations_ip_created_idx
        ON authorizations(client_ip, created_at);
      CREATE INDEX IF NOT EXISTS authorizations_mac_created_idx
        ON authorizations(client_mac, created_at);

      CREATE TABLE IF NOT EXISTS security_events (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        subject TEXT,
        client_ip TEXT NOT NULL,
        created_at INTEGER NOT NULL
      ) STRICT;

      CREATE INDEX IF NOT EXISTS security_events_lookup_idx
        ON security_events(kind, client_ip, subject, created_at);

      CREATE TABLE IF NOT EXISTS verification_cooldowns (
        method TEXT NOT NULL CHECK (method IN ('email', 'whatsapp', 'sms', 'telegram', 'admin-approval', 'nvi')),
        client_ip TEXT NOT NULL,
        requested_at INTEGER NOT NULL,
        PRIMARY KEY (method, client_ip)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS admin_approval_requests (
        id TEXT PRIMARY KEY,
        full_name TEXT NOT NULL,
        contact TEXT,
        contact_type TEXT NOT NULL DEFAULT 'none' CHECK (contact_type IN ('none', 'email', 'phone')),
        identity TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        client_mac TEXT,
        redirect_url TEXT,
        language TEXT NOT NULL DEFAULT 'en',
        status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'failed')),
        request_expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        decided_at INTEGER,
        decided_by TEXT,
        decision_message TEXT,
        authorization_id TEXT,
        last_error TEXT
      ) STRICT;

      CREATE INDEX IF NOT EXISTS admin_approval_requests_status_created_idx
        ON admin_approval_requests(status, created_at);
      CREATE INDEX IF NOT EXISTS admin_approval_requests_client_created_idx
        ON admin_approval_requests(client_ip, created_at);
      CREATE INDEX IF NOT EXISTS admin_approval_requests_identity_created_idx
        ON admin_approval_requests(identity, created_at);

      CREATE TABLE IF NOT EXISTS admin_audit (
        id TEXT PRIMARY KEY,
        admin_user TEXT NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT,
        target_id TEXT,
        detail_json TEXT,
        client_ip TEXT NOT NULL,
        created_at INTEGER NOT NULL
      ) STRICT;

      CREATE INDEX IF NOT EXISTS admin_audit_created_idx
        ON admin_audit(created_at);

      CREATE TABLE IF NOT EXISTS runtime_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS law5651_logs (
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

      CREATE INDEX IF NOT EXISTS law5651_logs_created_idx
        ON law5651_logs(created_at);
      CREATE INDEX IF NOT EXISTS law5651_logs_client_idx
        ON law5651_logs(client_ip, created_at);

      CREATE TABLE IF NOT EXISTS law5651_exports (
        id TEXT PRIMARY KEY,
        export_reason TEXT NOT NULL DEFAULT 'manual',
        period_start_at INTEGER,
        period_end_at INTEGER,
        file_path TEXT NOT NULL,
        manifest_path TEXT NOT NULL,
        timestamp_request_path TEXT,
        timestamp_token_path TEXT,
        timestamp_mode TEXT NOT NULL DEFAULT 'disabled',
        signature_path TEXT,
        signature_mode TEXT NOT NULL DEFAULT 'hmac-sha256',
        record_count INTEGER NOT NULL,
        first_sequence INTEGER,
        last_sequence INTEGER,
        first_created_at INTEGER,
        last_created_at INTEGER,
        previous_export_hash TEXT NOT NULL,
        export_hash TEXT NOT NULL,
        timestamp_status TEXT NOT NULL,
        timestamp_error TEXT,
        signature_status TEXT NOT NULL DEFAULT 'disabled',
        signature_error TEXT,
        backup_status TEXT NOT NULL DEFAULT 'disabled',
        backup_error TEXT,
        created_at INTEGER NOT NULL
      ) STRICT;

      CREATE INDEX IF NOT EXISTS law5651_exports_created_idx
        ON law5651_exports(created_at);

      CREATE TABLE IF NOT EXISTS law5651_events (
        id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'error', 'critical')),
        message TEXT NOT NULL,
        detail_json TEXT,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL
      ) STRICT;

      CREATE INDEX IF NOT EXISTS law5651_events_created_idx
        ON law5651_events(created_at);
      CREATE INDEX IF NOT EXISTS law5651_events_type_idx
        ON law5651_events(event_type, created_at);

      CREATE TABLE IF NOT EXISTS law5651_backups (
        id TEXT PRIMARY KEY,
        export_id TEXT NOT NULL,
        target_directory TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed')),
        error TEXT,
        file_count INTEGER NOT NULL DEFAULT 0,
        total_bytes INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      ) STRICT;

      CREATE INDEX IF NOT EXISTS law5651_backups_created_idx
        ON law5651_backups(created_at);
      CREATE INDEX IF NOT EXISTS law5651_backups_export_idx
        ON law5651_backups(export_id, created_at);

      CREATE TABLE IF NOT EXISTS law5651_state (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at INTEGER NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS traffic_logs (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        dedupe_key TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL CHECK (kind IN ('session', 'flow')),
        source TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        client_mac TEXT,
        subscriber_id TEXT,
        source_ip TEXT NOT NULL,
        source_port TEXT,
        destination_ip TEXT,
        destination_port TEXT,
        destination_domain TEXT,
        protocol TEXT,
        service_type TEXT NOT NULL,
        direction TEXT,
        started_at INTEGER NOT NULL,
        ended_at INTEGER,
        download_bytes INTEGER NOT NULL DEFAULT 0,
        upload_bytes INTEGER NOT NULL DEFAULT 0,
        raw_json TEXT,
        created_at INTEGER NOT NULL
      ) STRICT;

      CREATE INDEX IF NOT EXISTS traffic_logs_created_idx
        ON traffic_logs(created_at);
      CREATE INDEX IF NOT EXISTS traffic_logs_client_idx
        ON traffic_logs(client_ip, created_at);
      CREATE INDEX IF NOT EXISTS traffic_logs_destination_idx
        ON traffic_logs(destination_ip, created_at);
      CREATE INDEX IF NOT EXISTS traffic_logs_domain_idx
        ON traffic_logs(destination_domain, created_at);

      CREATE TABLE IF NOT EXISTS traffic_log_minute_rollups (
        series_source TEXT NOT NULL CHECK (series_source IN ('traffic', 'interface')),
        bucket_start_at INTEGER NOT NULL,
        records INTEGER NOT NULL DEFAULT 0,
        download_bytes INTEGER NOT NULL DEFAULT 0,
        upload_bytes INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (series_source, bucket_start_at)
      ) STRICT;

      CREATE INDEX IF NOT EXISTS traffic_log_minute_rollups_bucket_idx
        ON traffic_log_minute_rollups(bucket_start_at);

      CREATE TABLE IF NOT EXISTS traffic_log_client_minute_rollups (
        bucket_start_at INTEGER NOT NULL,
        client_ip TEXT NOT NULL,
        records INTEGER NOT NULL DEFAULT 0,
        download_bytes INTEGER NOT NULL DEFAULT 0,
        upload_bytes INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket_start_at, client_ip)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS traffic_log_client_detail_minute_rollups (
        bucket_start_at INTEGER NOT NULL,
        client_ip TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('session', 'flow')),
        interface_name TEXT NOT NULL DEFAULT '',
        records INTEGER NOT NULL DEFAULT 0,
        download_bytes INTEGER NOT NULL DEFAULT 0,
        upload_bytes INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket_start_at, client_ip, kind, interface_name)
      ) STRICT;

      CREATE INDEX IF NOT EXISTS traffic_log_client_detail_bucket_idx
        ON traffic_log_client_detail_minute_rollups(bucket_start_at);

      CREATE TABLE IF NOT EXISTS traffic_log_site_minute_rollups (
        bucket_start_at INTEGER NOT NULL,
        site TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        records INTEGER NOT NULL DEFAULT 0,
        download_bytes INTEGER NOT NULL DEFAULT 0,
        upload_bytes INTEGER NOT NULL DEFAULT 0,
        last_seen_at INTEGER NOT NULL,
        PRIMARY KEY (bucket_start_at, site, client_ip)
      ) STRICT;

      CREATE INDEX IF NOT EXISTS traffic_log_site_minute_rollups_site_idx
        ON traffic_log_site_minute_rollups(site, bucket_start_at);

      CREATE TABLE IF NOT EXISTS authorization_quota_usage (
        authorization_id TEXT NOT NULL,
        period_key TEXT NOT NULL,
        period_start_at INTEGER NOT NULL,
        period_end_at INTEGER NOT NULL,
        download_bytes INTEGER NOT NULL DEFAULT 0,
        upload_bytes INTEGER NOT NULL DEFAULT 0,
        last_gateway_download_bytes INTEGER NOT NULL DEFAULT 0,
        last_gateway_upload_bytes INTEGER NOT NULL DEFAULT 0,
        authorization_download_bytes_at_reset INTEGER NOT NULL DEFAULT 0,
        authorization_upload_bytes_at_reset INTEGER NOT NULL DEFAULT 0,
        reset_at INTEGER,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (authorization_id, period_key)
      ) STRICT;

      CREATE INDEX IF NOT EXISTS authorization_quota_usage_period_idx
        ON authorization_quota_usage(period_key, period_end_at);
    `);

    const voucherColumns = new Set(
      this.db.prepare('PRAGMA table_info(vouchers)').all().map(row => row.name)
    );
    if (!voucherColumns.has('code_prefix')) {
      this.db.exec("ALTER TABLE vouchers ADD COLUMN code_prefix TEXT NOT NULL DEFAULT ''");
    }

    const authorizationColumns = new Set(
      this.db.prepare('PRAGMA table_info(authorizations)').all().map(row => row.name)
    );
    const additions = [
      ['download_bytes', 'INTEGER NOT NULL DEFAULT 0'],
      ['upload_bytes', 'INTEGER NOT NULL DEFAULT 0'],
      ['last_seen_at', 'INTEGER'],
      ['ended_at', 'INTEGER'],
      ['disconnect_reason', 'TEXT'],
      ['device_name', 'TEXT'],
      ['unlimited', 'INTEGER NOT NULL DEFAULT 0'],
      ['kea_deleted_at', 'INTEGER'],
      ['lease_seconds', 'INTEGER'],
      ['quota_blocked_until', 'INTEGER'],
      ['quota_period_key', 'TEXT'],
      ['quota_exceeded_at', 'INTEGER'],
      ['previous_gateway_download_bytes', 'INTEGER NOT NULL DEFAULT 0'],
      ['previous_gateway_upload_bytes', 'INTEGER NOT NULL DEFAULT 0'],
      ['previous_gateway_seen_at', 'INTEGER'],
      ['gateway_sampled_at', 'INTEGER'],
      ['previous_gateway_sampled_at', 'INTEGER']
    ];
    for (const [name, definition] of additions) {
      if (!authorizationColumns.has(name)) {
        this.db.exec(`ALTER TABLE authorizations ADD COLUMN ${name} ${definition}`);
      }
    }
    const quotaUsageColumns = new Set(
      this.db.prepare('PRAGMA table_info(authorization_quota_usage)').all().map(row => row.name)
    );
    const quotaUsageAdditions = [
      ['reset_at', 'INTEGER'],
      ['authorization_download_bytes_at_reset', 'INTEGER NOT NULL DEFAULT 0'],
      ['authorization_upload_bytes_at_reset', 'INTEGER NOT NULL DEFAULT 0']
    ];
    for (const [name, definition] of quotaUsageAdditions) {
      if (!quotaUsageColumns.has(name)) {
        this.db.exec(`ALTER TABLE authorization_quota_usage ADD COLUMN ${name} ${definition}`);
      }
    }
    const trafficLogColumns = new Set(
      this.db.prepare('PRAGMA table_info(traffic_logs)').all().map(row => row.name)
    );
    const trafficLogAdditions = [
      ['destination_domain', 'TEXT'],
      ['direction', 'TEXT']
    ];
    for (const [name, definition] of trafficLogAdditions) {
      if (!trafficLogColumns.has(name)) {
        this.db.exec(`ALTER TABLE traffic_logs ADD COLUMN ${name} ${definition}`);
      }
    }
    this.db.prepare(`
      UPDATE authorizations
      SET ended_at=NULL, disconnect_reason=NULL, gateway_session_id=NULL, kea_deleted_at=NULL
      WHERE status='active'
        AND expires_at > ?
        AND disconnect_reason IN ('session_ip_changed_without_cookie', 'session_ip_mac_mismatch')
    `).run(Date.now());
    this.db.exec(`
      UPDATE authorizations
      SET lease_seconds=MIN(4294967295, MAX(60, CAST((expires_at - created_at + 999) / 1000 AS INTEGER)))
      WHERE lease_seconds IS NULL
        AND expires_at > created_at;
    `);
    const law5651ExportColumns = new Set(
      this.db.prepare('PRAGMA table_info(law5651_exports)').all().map(row => row.name)
    );
    const law5651ExportAdditions = [
      ['export_reason', "TEXT NOT NULL DEFAULT 'manual'"],
      ['period_start_at', 'INTEGER'],
      ['period_end_at', 'INTEGER'],
      ['timestamp_request_path', 'TEXT'],
      ['timestamp_mode', "TEXT NOT NULL DEFAULT 'disabled'"],
      ['signature_path', 'TEXT'],
      ['signature_mode', "TEXT NOT NULL DEFAULT 'hmac-sha256'"],
      ['signature_status', "TEXT NOT NULL DEFAULT 'disabled'"],
      ['signature_error', 'TEXT'],
      ['backup_status', "TEXT NOT NULL DEFAULT 'disabled'"],
      ['backup_error', 'TEXT'],
      ['first_sequence', 'INTEGER'],
      ['last_sequence', 'INTEGER']
    ];
    for (const [name, definition] of law5651ExportAdditions) {
      if (!law5651ExportColumns.has(name)) {
        this.db.exec(`ALTER TABLE law5651_exports ADD COLUMN ${name} ${definition}`);
      }
    }
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS law5651_exports_period_idx
        ON law5651_exports(export_reason, period_start_at, period_end_at);
    `);
    this.migrateVerificationMethods();
    const challengeColumns = new Set(
      this.db.prepare('PRAGMA table_info(challenges)').all().map(row => row.name)
    );
    if (!challengeColumns.has('language')) {
      this.db.exec("ALTER TABLE challenges ADD COLUMN language TEXT NOT NULL DEFAULT 'en'");
    }
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS authorizations_ip_created_idx
        ON authorizations(client_ip, created_at);
      CREATE INDEX IF NOT EXISTS authorizations_mac_created_idx
        ON authorizations(client_mac, created_at);
    `);
    this.db.exec(`
      UPDATE challenges AS challenge
      SET client_mac = (
        SELECT authorization.client_mac
        FROM authorizations AS authorization
        WHERE authorization.method = challenge.kind
          AND authorization.identity = challenge.target
          AND authorization.client_ip = challenge.client_ip
          AND authorization.client_mac IS NOT NULL
          AND authorization.client_mac != ''
        ORDER BY ABS(authorization.created_at - COALESCE(challenge.verified_at, challenge.created_at))
        LIMIT 1
      )
      WHERE (challenge.client_mac IS NULL OR challenge.client_mac = '')
        AND EXISTS (
          SELECT 1 FROM authorizations AS authorization
          WHERE authorization.method = challenge.kind
            AND authorization.identity = challenge.target
            AND authorization.client_ip = challenge.client_ip
            AND authorization.client_mac IS NOT NULL
            AND authorization.client_mac != ''
        );
    `);
    this.ensureTrafficLogRollups();
    this.repairAuthorizationQuotaResetBaselines();
  }

  migrateVerificationMethods() {
    const challengeSql = String(this.db.prepare(
      `SELECT sql FROM sqlite_master WHERE type='table' AND name='challenges'`
    ).get()?.sql || '');
    const challengeMethods = ["'telegram'", "'nvi'"];
    if (challengeMethods.some(method => !challengeSql.includes(method))) {
      const challengeColumns = new Set(
        this.db.prepare('PRAGMA table_info(challenges)').all().map(row => row.name)
      );
      const languageInsertColumn = challengeColumns.has('language') ? ', language' : '';
      const languageSelectColumn = challengeColumns.has('language') ? ', language' : '';
      this.db.exec(`
        BEGIN IMMEDIATE;
        DROP INDEX IF EXISTS challenges_target_created_idx;
        DROP INDEX IF EXISTS challenges_client_created_idx;
        DROP INDEX IF EXISTS challenges_secret_idx;
        ALTER TABLE challenges RENAME TO challenges_legacy;
        CREATE TABLE challenges (
          id TEXT PRIMARY KEY,
          kind TEXT NOT NULL CHECK (kind IN ('email', 'whatsapp', 'sms', 'telegram', 'nvi')),
          target TEXT NOT NULL,
          secret_hash TEXT NOT NULL,
          client_ip TEXT NOT NULL,
          client_mac TEXT,
          redirect_url TEXT,
          language TEXT NOT NULL DEFAULT 'en',
          status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'verified', 'expired', 'failed')),
          attempts INTEGER NOT NULL DEFAULT 0,
          expires_at INTEGER NOT NULL,
          created_at INTEGER NOT NULL,
          verified_at INTEGER,
          last_error TEXT
        ) STRICT;
        INSERT INTO challenges
          (id, kind, target, secret_hash, client_ip, client_mac, redirect_url,
           status, attempts, expires_at, created_at, verified_at, last_error${languageInsertColumn})
        SELECT id, kind, target, secret_hash, client_ip, client_mac, redirect_url,
          status, attempts, expires_at, created_at, verified_at, last_error${languageSelectColumn}
        FROM challenges_legacy;
        DROP TABLE challenges_legacy;
        CREATE INDEX challenges_target_created_idx ON challenges(kind, target, created_at);
        CREATE INDEX challenges_client_created_idx ON challenges(kind, client_ip, created_at);
        CREATE INDEX challenges_secret_idx ON challenges(kind, secret_hash);
        COMMIT;
      `);
    }

    const authorizationSql = String(this.db.prepare(
      `SELECT sql FROM sqlite_master WHERE type='table' AND name='authorizations'`
    ).get()?.sql || '');
    if (!authorizationSql.includes("'telegram'") ||
        !authorizationSql.includes("'admin-approval'") ||
        !authorizationSql.includes("'nvi'")) {
      this.db.exec(`
        BEGIN IMMEDIATE;
        DROP INDEX IF EXISTS authorizations_ip_created_idx;
        DROP INDEX IF EXISTS authorizations_mac_created_idx;
        ALTER TABLE authorizations RENAME TO authorizations_legacy;
        CREATE TABLE authorizations (
          id TEXT PRIMARY KEY,
          method TEXT NOT NULL CHECK (method IN ('voucher', 'email', 'whatsapp', 'sms', 'telegram', 'admin-approval', 'nvi')),
          identity TEXT NOT NULL,
          client_ip TEXT NOT NULL,
          client_mac TEXT,
          gateway_mode TEXT NOT NULL,
          gateway_session_id TEXT,
          status TEXT NOT NULL CHECK (status IN ('active', 'failed')),
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          redirect_url TEXT,
          gateway_response_json TEXT,
          error TEXT,
          download_bytes INTEGER NOT NULL DEFAULT 0,
          upload_bytes INTEGER NOT NULL DEFAULT 0,
          last_seen_at INTEGER,
          ended_at INTEGER,
          disconnect_reason TEXT,
          device_name TEXT,
	          unlimited INTEGER NOT NULL DEFAULT 0,
	          kea_deleted_at INTEGER,
	          lease_seconds INTEGER,
	          quota_blocked_until INTEGER,
	          quota_period_key TEXT,
	          quota_exceeded_at INTEGER,
	          previous_gateway_download_bytes INTEGER NOT NULL DEFAULT 0,
	          previous_gateway_upload_bytes INTEGER NOT NULL DEFAULT 0,
	          previous_gateway_seen_at INTEGER,
	          gateway_sampled_at INTEGER,
	          previous_gateway_sampled_at INTEGER
	        ) STRICT;
	        INSERT INTO authorizations
	          (id, method, identity, client_ip, client_mac, gateway_mode, gateway_session_id,
	           status, created_at, expires_at, redirect_url, gateway_response_json, error,
	           download_bytes, upload_bytes, last_seen_at, ended_at, disconnect_reason, device_name,
	           unlimited, kea_deleted_at, lease_seconds, quota_blocked_until, quota_period_key, quota_exceeded_at,
	           previous_gateway_download_bytes, previous_gateway_upload_bytes, previous_gateway_seen_at,
	           gateway_sampled_at, previous_gateway_sampled_at)
	        SELECT id, method, identity, client_ip, client_mac, gateway_mode, gateway_session_id,
	          status, created_at, expires_at, redirect_url, gateway_response_json, error,
	          download_bytes, upload_bytes, last_seen_at, ended_at, disconnect_reason, device_name,
	          COALESCE(unlimited, 0), kea_deleted_at, lease_seconds,
	          quota_blocked_until, quota_period_key, quota_exceeded_at,
	          previous_gateway_download_bytes, previous_gateway_upload_bytes, previous_gateway_seen_at,
	          gateway_sampled_at, previous_gateway_sampled_at
	        FROM authorizations_legacy;
        DROP TABLE authorizations_legacy;
        CREATE INDEX authorizations_ip_created_idx ON authorizations(client_ip, created_at);
        CREATE INDEX authorizations_mac_created_idx ON authorizations(client_mac, created_at);
        COMMIT;
      `);
    }

    const cooldownSql = String(this.db.prepare(
      `SELECT sql FROM sqlite_master WHERE type='table' AND name='verification_cooldowns'`
    ).get()?.sql || '');
    if (!cooldownSql.includes("'telegram'") ||
        !cooldownSql.includes("'admin-approval'") ||
        !cooldownSql.includes("'nvi'")) {
      this.db.exec(`
        BEGIN IMMEDIATE;
        ALTER TABLE verification_cooldowns RENAME TO verification_cooldowns_legacy;
        CREATE TABLE verification_cooldowns (
          method TEXT NOT NULL CHECK (method IN ('email', 'whatsapp', 'sms', 'telegram', 'admin-approval', 'nvi')),
          client_ip TEXT NOT NULL,
          requested_at INTEGER NOT NULL,
          PRIMARY KEY (method, client_ip)
        ) STRICT;
        INSERT INTO verification_cooldowns SELECT * FROM verification_cooldowns_legacy;
        DROP TABLE verification_cooldowns_legacy;
        COMMIT;
      `);
    }
  }

  close() {
    this.db.close();
  }

  databaseMaintenanceStats() {
    const pageSize = Number(this.db.prepare('PRAGMA page_size').get().page_size || 0);
    const pageCount = Number(this.db.prepare('PRAGMA page_count').get().page_count || 0);
    const freelistCount = Number(this.db.prepare('PRAGMA freelist_count').get().freelist_count || 0);
    const fileBytes = fs.existsSync(this.filePath) ? fs.statSync(this.filePath).size : 0;
    const walPath = `${this.filePath}-wal`;
    const shmPath = `${this.filePath}-shm`;
    const walBytes = fs.existsSync(walPath) ? fs.statSync(walPath).size : 0;
    const shmBytes = fs.existsSync(shmPath) ? fs.statSync(shmPath).size : 0;
    return {
      path: this.filePath,
      pageSize,
      pageCount,
      freelistCount,
      databaseBytes: pageSize * pageCount,
      freeBytes: pageSize * freelistCount,
      usedBytes: pageSize * Math.max(0, pageCount - freelistCount),
      fileBytes,
      walBytes,
      shmBytes,
      totalFileBytes: fileBytes + walBytes + shmBytes
    };
  }

  vacuumDatabase() {
    const startedAt = Date.now();
    this.db.exec('PRAGMA wal_checkpoint(TRUNCATE);');
    const before = this.databaseMaintenanceStats();
    const backupPath = `${this.filePath}.backup-${new Date(startedAt).toISOString().replace(/[:.]/gu, '-')}`;
    fs.copyFileSync(this.filePath, backupPath, fs.constants.COPYFILE_EXCL);
    const backupBytes = fs.statSync(backupPath).size;
    this.db.exec('VACUUM; PRAGMA wal_checkpoint(TRUNCATE); PRAGMA optimize;');
    const after = this.databaseMaintenanceStats();
    const completedAt = Date.now();
    return {
      ok: true,
      startedAt,
      completedAt,
      durationMs: completedAt - startedAt,
      backupPath,
      backupBytes,
      before,
      after,
      reclaimedBytes: Math.max(0, before.totalFileBytes - after.totalFileBytes),
      freeBytesReclaimed: Math.max(0, before.freeBytes - after.freeBytes)
    };
  }

  cleanup(now = Date.now()) {
    this.db.prepare(`UPDATE challenges SET status='expired' WHERE status='pending' AND expires_at < ?`).run(now);
    this.expireAdminApprovalRequests(now);
    this.db.prepare('DELETE FROM security_events WHERE created_at < ?').run(now - 24 * 60 * 60 * 1000);
  }

  recordEvent(kind, clientIp, subject = '') {
    this.db.prepare(`INSERT INTO security_events(id, kind, subject, client_ip, created_at)
                     VALUES (?, ?, ?, ?, ?)`)
      .run(randomUUID(), kind, subject, clientIp, Date.now());
  }

  countEvents(kind, clientIp, subject, since) {
    const row = this.db.prepare(`SELECT COUNT(*) AS count FROM security_events
      WHERE kind = ? AND client_ip = ? AND subject = ? AND created_at >= ?`)
      .get(kind, clientIp, subject, since);
    return Number(row?.count || 0);
  }

  getVerificationCooldown(method, clientIp) {
    return this.db.prepare(`
      SELECT method, client_ip, requested_at
      FROM verification_cooldowns
      WHERE method=? AND client_ip=?
    `).get(method, clientIp) || null;
  }

  setVerificationCooldown(method, clientIp, requestedAt = Date.now()) {
    this.db.prepare(`
      INSERT INTO verification_cooldowns(method, client_ip, requested_at)
      VALUES (?, ?, ?)
      ON CONFLICT(method, client_ip) DO UPDATE SET requested_at=excluded.requested_at
    `).run(method, clientIp, requestedAt);
    return requestedAt;
  }

  releaseVerificationCooldown(method, clientIp, requestedAt) {
    return Number(this.db.prepare(`
      DELETE FROM verification_cooldowns
      WHERE method=? AND client_ip=? AND requested_at=?
    `).run(method, clientIp, requestedAt).changes) === 1;
  }

  createAdminApprovalRequest({
    fullName, contact = '', contactType = 'none', identity, clientIp,
    clientMac = '', redirectUrl = '', expiresAt, language = 'en'
  }) {
    const id = randomUUID();
    const createdAt = Date.now();
    const normalizedLanguage = normalizeLanguage(language, 'en');
    this.db.prepare(`
      INSERT INTO admin_approval_requests
        (id, full_name, contact, contact_type, identity, client_ip, client_mac,
         redirect_url, language, request_expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      fullName,
      contact || null,
      contactType || 'none',
      identity,
      clientIp,
      clientMac || null,
      redirectUrl || null,
      normalizedLanguage,
      expiresAt,
      createdAt
    );
    return this.getAdminApprovalRequest(id);
  }

  getAdminApprovalRequest(id) {
    return this.db.prepare(`
      SELECT request.*, authorization.expires_at AS access_expires_at,
        authorization.unlimited AS access_unlimited
      FROM admin_approval_requests AS request
      LEFT JOIN authorizations AS authorization ON authorization.id=request.authorization_id
      WHERE request.id=?
    `).get(id) || null;
  }

  getPendingAdminApprovalRequestByClient(clientIp, now = Date.now()) {
    return this.db.prepare(`
      SELECT *
      FROM admin_approval_requests
      WHERE client_ip=? AND status='pending' AND request_expires_at >= ?
      ORDER BY created_at DESC LIMIT 1
    `).get(clientIp, now) || null;
  }

  expireAdminApprovalRequests(now = Date.now()) {
    return Number(this.db.prepare(`
      UPDATE admin_approval_requests
      SET status='expired', last_error=COALESCE(last_error, 'Request expired before administrator decision.')
      WHERE status='pending' AND request_expires_at < ?
    `).run(now).changes);
  }

  listAdminApprovalRequests({
    search = '', status = '', limit = 100, offset = 0, now = Date.now()
  } = {}) {
    this.expireAdminApprovalRequests(now);
    const where = [];
    const params = [];
    if (search) {
      where.push(`(request.full_name LIKE ? OR request.contact LIKE ? OR request.client_ip LIKE ?
        OR request.client_mac LIKE ? OR request.identity LIKE ?)`);
      const term = `%${search}%`;
      params.push(term, term, term, term, term);
    }
    if (status) {
      where.push('request.status=?');
      params.push(status);
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const total = this.db.prepare(`
      SELECT COUNT(*) count FROM admin_approval_requests AS request ${clause}
    `).get(...params);
    const rows = this.db.prepare(`
      SELECT request.*, authorization.expires_at AS access_expires_at,
        authorization.unlimited AS access_unlimited
      FROM admin_approval_requests AS request
      LEFT JOIN authorizations AS authorization ON authorization.id=request.authorization_id
      ${clause}
      ORDER BY request.created_at DESC LIMIT ? OFFSET ?
    `).all(...params, limit, offset);
    return { rows, total: Number(total.count || 0) };
  }

  decideAdminApprovalRequest(id, {
    status, adminUser = '', message = '', authorizationId = '', error = '', decidedAt = Date.now()
  }) {
    const result = this.db.prepare(`
      UPDATE admin_approval_requests
      SET status=?,
        decided_at=?,
        decided_by=?,
        decision_message=?,
        authorization_id=COALESCE(NULLIF(?, ''), authorization_id),
        last_error=?
      WHERE id=? AND status='pending'
    `).run(
      status,
      decidedAt,
      adminUser || null,
      message || null,
      authorizationId || '',
      error || null,
      id
    );
    return Number(result.changes) === 1 ? this.getAdminApprovalRequest(id) : null;
  }

  createChallenge({ kind, target, secretHash, clientIp, clientMac, redirectUrl, expiresAt, language = 'en' }) {
    const id = randomUUID();
    const createdAt = Date.now();
    const normalizedLanguage = normalizeLanguage(language, 'en');
    this.db.prepare(`INSERT INTO challenges
      (id, kind, target, secret_hash, client_ip, client_mac, redirect_url, language, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id, kind, target, secretHash, clientIp, clientMac || null, redirectUrl || null,
        normalizedLanguage, expiresAt, createdAt);
    return this.getChallenge(id);
  }

  getChallenge(id) {
    return this.db.prepare('SELECT * FROM challenges WHERE id = ?').get(id) || null;
  }

  getChallengeBySecret(kind, secretHash) {
    return this.db.prepare(`SELECT * FROM challenges
      WHERE kind = ? AND secret_hash = ? ORDER BY created_at DESC LIMIT 1`)
      .get(kind, secretHash) || null;
  }

  getPendingChallengeByTarget(kind, target, now = Date.now()) {
    return this.db.prepare(`SELECT * FROM challenges
      WHERE kind = ? AND target = ? AND status = 'pending' AND expires_at >= ?
      ORDER BY created_at DESC LIMIT 1`)
      .get(kind, target, now) || null;
  }

  getPendingChallengeByClient(kind, clientIp, now = Date.now()) {
    return this.db.prepare(`SELECT * FROM challenges
      WHERE kind = ? AND client_ip = ? AND status = 'pending' AND expires_at >= ?
      ORDER BY created_at DESC LIMIT 1`)
      .get(kind, clientIp, now) || null;
  }

  incrementChallengeAttempts(id) {
    this.db.prepare('UPDATE challenges SET attempts = attempts + 1 WHERE id = ?').run(id);
    return this.getChallenge(id);
  }

  setChallengeDetail(id, detail) {
    this.db.prepare('UPDATE challenges SET last_error=? WHERE id=?')
      .run(detail || null, id);
    return this.getChallenge(id);
  }

  appendChallengeDetail(id, detail) {
    const clean = String(detail || '').trim();
    if (!clean) return this.getChallenge(id);
    const current = this.getChallenge(id);
    const previous = String(current?.last_error || '').trim();
    return this.setChallengeDetail(id, previous ? `${previous}\n${clean}` : clean);
  }

  updateChallengeSecret(id, secretHash, expiresAt) {
    this.db.prepare(`UPDATE challenges
      SET secret_hash=?, expires_at=?, attempts=0, last_error=NULL
      WHERE id=? AND status='pending'`)
      .run(secretHash, expiresAt, id);
    return this.getChallenge(id);
  }

  claimChallenge(id) {
    const result = this.db.prepare(`UPDATE challenges SET status='processing'
      WHERE id = ? AND status='pending' AND expires_at >= ?`).run(id, Date.now());
    return Number(result.changes) === 1;
  }

  finishChallenge(id, success, error = '', clientMac = '') {
    this.db.prepare(`UPDATE challenges SET status=?, verified_at=?,
      last_error=CASE
        WHEN ? IS NOT NULL THEN ?
        WHEN ? = 1 THEN last_error
        ELSE NULL
      END,
      client_mac=COALESCE(NULLIF(?, ''), client_mac) WHERE id=?`)
      .run(
        success ? 'verified' : 'pending',
        success ? Date.now() : null,
        error || null,
        error || null,
        success ? 1 : 0,
        clientMac,
        id
      );
  }

  failChallenge(id, error) {
    this.db.prepare(`UPDATE challenges SET status='failed', last_error=? WHERE id=?`).run(error, id);
  }

  createVoucher({ codeHash, codeHint, codePrefix = '', label, maxUses, durationMinutes, validFrom, expiresAt }) {
    const id = randomUUID();
    this.db.prepare(`INSERT INTO vouchers
      (id, code_hash, code_hint, code_prefix, label, max_uses, duration_minutes, valid_from, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        id,
        codeHash,
        codeHint,
        String(codePrefix || '').slice(0, 4),
        label || null,
        maxUses,
        durationMinutes,
        validFrom || null,
        expiresAt || null,
        Date.now()
      );
    return id;
  }

  listVouchers() {
    return this.db.prepare(`SELECT id, code_hint, code_prefix, label, max_uses, used_count, duration_minutes,
      valid_from, expires_at, enabled, created_at FROM vouchers ORDER BY created_at DESC`).all();
  }

  disableVoucher(id) {
    return Number(this.db.prepare('UPDATE vouchers SET enabled=0 WHERE id=?').run(id).changes) === 1;
  }

  setVoucherEnabled(id, enabled) {
    return Number(this.db.prepare('UPDATE vouchers SET enabled=? WHERE id=?')
      .run(enabled ? 1 : 0, id).changes) === 1;
  }

  claimVoucher(codeHash, now = Date.now(), codePrefix = '') {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const voucher = this.db.prepare('SELECT * FROM vouchers WHERE code_hash=?').get(codeHash);
      if (!voucher) {
        this.db.exec('ROLLBACK');
        return { ok: false, reason: 'not_found' };
      }
      if (!voucher.enabled) {
        this.db.exec('ROLLBACK');
        return { ok: false, reason: 'disabled' };
      }
      if (voucher.valid_from && Number(voucher.valid_from) > now) {
        this.db.exec('ROLLBACK');
        return { ok: false, reason: 'not_started' };
      }
      if (voucher.expires_at && Number(voucher.expires_at) < now) {
        this.db.exec('ROLLBACK');
        return { ok: false, reason: 'expired' };
      }
      if (Number(voucher.used_count) >= Number(voucher.max_uses)) {
        this.db.exec('ROLLBACK');
        return { ok: false, reason: 'used' };
      }
      const prefix = String(codePrefix || '').slice(0, 4);
      if (prefix) {
        this.db.prepare(`
          UPDATE vouchers
          SET used_count=used_count+1,
            code_prefix=CASE WHEN code_prefix IS NULL OR code_prefix='' THEN ? ELSE code_prefix END
          WHERE id=?
        `).run(prefix, voucher.id);
      } else {
        this.db.prepare('UPDATE vouchers SET used_count=used_count+1 WHERE id=?').run(voucher.id);
      }
      this.db.exec('COMMIT');
      return { ok: true, voucher: { ...voucher, code_prefix: voucher.code_prefix || prefix, used_count: Number(voucher.used_count) + 1 } };
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch {}
      throw error;
    }
  }

  releaseVoucherUse(id) {
    this.db.prepare(`UPDATE vouchers SET used_count=CASE WHEN used_count > 0 THEN used_count - 1 ELSE 0 END WHERE id=?`).run(id);
  }

  saveAuthorization({ method, identity, clientIp, clientMac, gatewayMode, gatewaySessionId,
    status, expiresAt, unlimited = false, leaseSeconds = null, redirectUrl, gatewayResponse, error }) {
    const id = randomUUID();
    const createdAt = Date.now();
    const storedLeaseSeconds = normalizedLeaseSeconds(leaseSeconds) ||
      normalizedLeaseSeconds((Number(expiresAt) - createdAt) / 1000);
    this.db.prepare(`INSERT INTO authorizations
      (id, method, identity, client_ip, client_mac, gateway_mode, gateway_session_id,
       status, created_at, expires_at, unlimited, lease_seconds, redirect_url, gateway_response_json, error)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id, method, identity, clientIp, clientMac || null, gatewayMode,
        gatewaySessionId || null, status, createdAt, expiresAt, unlimited ? 1 : 0, storedLeaseSeconds, redirectUrl || null,
        gatewayResponse == null ? null : JSON.stringify(gatewayResponse), error || null);
    return this.getAuthorization(id);
  }

  getAuthorization(id) {
    return this.db.prepare(`
      SELECT a.*, v.label voucher_label, v.code_hint voucher_hint, v.code_prefix voucher_code_prefix
      FROM authorizations a
      LEFT JOIN vouchers v ON a.method='voucher' AND a.identity=v.id
      WHERE a.id=?
    `).get(id) || null;
  }

  listOpenAuthorizationsForMethods(methods, { limit = 1000 } = {}) {
    const selected = [...new Set((methods || []).map(method => String(method || '').trim()).filter(Boolean))];
    if (!selected.length) return [];
    const placeholders = selected.map(() => '?').join(',');
    return this.db.prepare(`
      SELECT * FROM authorizations
      WHERE status='active'
        AND ended_at IS NULL
        AND method IN (${placeholders})
      ORDER BY created_at DESC
      LIMIT ?
    `).all(...selected, Math.max(1, Math.trunc(Number(limit) || 1000)));
  }

  updateAuthorizationAccessDuration(id, { expiresAt, unlimited = false, leaseSeconds = null } = {}) {
    const normalizedExpiresAt = integerTimestamp(expiresAt);
    const normalizedLease = normalizedLeaseSeconds(leaseSeconds);
    return Number(this.db.prepare(`
      UPDATE authorizations
      SET expires_at=?,
        unlimited=?,
        lease_seconds=?
      WHERE id=? AND status='active' AND ended_at IS NULL
    `).run(
      normalizedExpiresAt,
      unlimited ? 1 : 0,
      normalizedLease,
      id
    ).changes) === 1;
  }

  getActiveAuthorizationForClient(clientIp, now = Date.now()) {
    return this.db.prepare(`
      SELECT a.*, v.label voucher_label, v.code_hint voucher_hint, v.code_prefix voucher_code_prefix
      FROM authorizations a
      LEFT JOIN vouchers v ON a.method='voucher' AND a.identity=v.id
      WHERE a.client_ip=? AND a.status='active' AND a.ended_at IS NULL AND a.expires_at > ?
      ORDER BY a.created_at DESC LIMIT 1
    `).get(clientIp, now) || null;
  }

  listActiveAuthorizationsForClient(clientIp, now = Date.now()) {
    return this.db.prepare(`
      SELECT * FROM authorizations
      WHERE client_ip=? AND status='active' AND ended_at IS NULL AND expires_at > ?
      ORDER BY created_at DESC
    `).all(clientIp, now);
  }

  listActiveBandwidthAuthorizations({ now = Date.now(), gatewayMode = '' } = {}) {
    const params = [now];
    let gatewayClause = '';
    if (gatewayMode) {
      gatewayClause = ' AND gateway_mode=?';
      params.push(gatewayMode);
    }
    return this.db.prepare(`
      SELECT * FROM authorizations
      WHERE status='active'
        AND ended_at IS NULL
        AND expires_at > ?
        AND client_ip IS NOT NULL
        AND client_ip != ''
        ${gatewayClause}
      ORDER BY method, client_ip, created_at DESC
    `).all(...params);
  }

  getActiveAuthorizationForMac(clientMac, now = Date.now()) {
    const normalized = normalizeMac(clientMac);
    if (!normalized) return null;
    return this.db.prepare(`
      SELECT a.*, v.label voucher_label, v.code_hint voucher_hint, v.code_prefix voucher_code_prefix
      FROM authorizations a
      LEFT JOIN vouchers v ON a.method='voucher' AND a.identity=v.id
      WHERE UPPER(a.client_mac)=? AND a.status='active' AND a.ended_at IS NULL AND a.expires_at > ?
      ORDER BY a.created_at DESC LIMIT 1
    `).get(normalized, now) || null;
  }

  listExpiredActiveAuthorizations({ now = Date.now(), limit = 100, gatewayMode = '' } = {}) {
    const params = [now];
    let gatewayClause = '';
    if (gatewayMode) {
      gatewayClause = ' AND gateway_mode=?';
      params.push(gatewayMode);
    }
    params.push(Math.max(1, Math.trunc(Number(limit) || 100)));
    return this.db.prepare(`
      SELECT * FROM authorizations
      WHERE status='active' AND ended_at IS NULL AND expires_at <= ?${gatewayClause}
      ORDER BY expires_at ASC LIMIT ?
    `).all(...params);
  }

  listExpiredAuthorizationCleanups({ now = Date.now(), limit = 100, gatewayMode = '' } = {}) {
    const params = [now];
    let gatewayClause = '';
    if (gatewayMode) {
      gatewayClause = ' AND gateway_mode=?';
      params.push(gatewayMode);
    }
    params.push(Math.max(1, Math.trunc(Number(limit) || 100)));
    return this.db.prepare(`
      SELECT * FROM authorizations
      WHERE status='active'
        AND expires_at <= ?
        ${gatewayClause}
        AND (ended_at IS NULL OR kea_deleted_at IS NULL)
      ORDER BY expires_at ASC LIMIT ?
    `).all(...params);
  }

  getLatestSuccessfulAuthorization(method, identity) {
    return this.db.prepare(`
      SELECT * FROM authorizations
      WHERE method=? AND identity=? AND status='active'
      ORDER BY created_at DESC LIMIT 1
    `).get(method, identity) || null;
  }

  logAdminEvent({ adminUser, action, targetType = '', targetId = '', detail = null, clientIp }) {
    this.db.prepare(`INSERT INTO admin_audit
      (id, admin_user, action, target_type, target_id, detail_json, client_ip, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(randomUUID(), adminUser, action, targetType || null, targetId || null,
        detail == null ? null : JSON.stringify(detail), clientIp, Date.now());
  }

  setRuntimeState(key, value, now = Date.now()) {
    this.db.prepare(`
      INSERT INTO runtime_state (key, value, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
    `).run(String(key), String(value), now);
  }

  getRuntimeState(key) {
    const row = this.db.prepare(`
      SELECT key, value, updated_at FROM runtime_state WHERE key=?
    `).get(String(key));
    if (!row) return null;
    return { key: row.key, value: row.value, updatedAt: Number(row.updated_at) };
  }

  dashboard(now = Date.now(), days = 7) {
    const todayStart = new Date(now);
    todayStart.setHours(0, 0, 0, 0);
    const since = now - days * 86400000;
    const lastGatewaySync = this.getRuntimeState('opnsense_last_successful_sync_at');
    const summary = this.db.prepare(`
      SELECT
        SUM(CASE WHEN status='active' AND ended_at IS NULL AND expires_at > ? THEN 1 ELSE 0 END) active_sessions,
        SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) today_sessions,
        COALESCE(SUM(download_bytes), 0) download_bytes,
        COALESCE(SUM(upload_bytes), 0) upload_bytes,
        COUNT(DISTINCT CASE WHEN created_at >= ? THEN identity END) unique_users
      FROM authorizations
    `).get(now, todayStart.getTime(), since);

    const vouchers = this.db.prepare(`
      SELECT
        SUM(CASE WHEN enabled=1 AND used_count < max_uses
          AND (valid_from IS NULL OR valid_from <= ?)
          AND (expires_at IS NULL OR expires_at >= ?) THEN 1 ELSE 0 END) usable,
        COALESCE(SUM(used_count), 0) redeemed
      FROM vouchers
    `).get(now, now);

    const methods = this.db.prepare(`
      SELECT method, COUNT(*) count
      FROM authorizations WHERE created_at >= ?
      GROUP BY method ORDER BY count DESC
    `).all(since);

    const daily = this.db.prepare(`
      SELECT strftime('%Y-%m-%d', created_at / 1000, 'unixepoch', 'localtime') day,
        COUNT(*) sessions,
        COALESCE(SUM(download_bytes + upload_bytes), 0) traffic
      FROM authorizations WHERE created_at >= ?
      GROUP BY day ORDER BY day
    `).all(since);

    const recent = this.db.prepare(`
      SELECT a.*, v.label voucher_label, v.code_hint voucher_hint
      FROM authorizations a
      LEFT JOIN vouchers v ON a.method='voucher' AND a.identity=v.id
      ORDER BY a.created_at DESC LIMIT 8
    `).all();

    this.expireAdminApprovalRequests(now);
    const adminApprovalSummary = this.db.prepare(`
      SELECT
        SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) pending,
        SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) today
      FROM admin_approval_requests
    `).get(todayStart.getTime());
    const pendingAdminApprovals = this.db.prepare(`
      SELECT *
      FROM admin_approval_requests
      WHERE status='pending'
      ORDER BY created_at DESC LIMIT 8
    `).all();

    return {
      summary: {
        activeSessions: Number(summary.active_sessions || 0),
        todaySessions: Number(summary.today_sessions || 0),
        downloadBytes: Number(summary.download_bytes || 0),
        uploadBytes: Number(summary.upload_bytes || 0),
        uniqueUsers: Number(summary.unique_users || 0),
        usableVouchers: Number(vouchers.usable || 0),
        redeemedVouchers: Number(vouchers.redeemed || 0)
      },
      methods: methods.map(row => ({ method: row.method, count: Number(row.count) })),
      daily: daily.map(row => ({
        day: row.day,
        sessions: Number(row.sessions),
        traffic: Number(row.traffic)
      })),
      gateway: {
        lastSuccessfulSyncAt: lastGatewaySync ? Number(lastGatewaySync.value) || null : null
      },
      adminApproval: {
        pending: Number(adminApprovalSummary.pending || 0),
        today: Number(adminApprovalSummary.today || 0),
        requests: pendingAdminApprovals
      },
      recent
    };
  }

  listAuthorizations({ search = '', method = '', state = '', limit = 100, offset = 0, now = Date.now() } = {}) {
    const where = [];
    const params = [];
    if (search) {
      where.push(`(a.identity LIKE ? OR a.client_ip LIKE ? OR a.client_mac LIKE ?
        OR a.gateway_session_id LIKE ? OR v.label LIKE ? OR v.code_hint LIKE ?)`);
      const term = `%${search}%`;
      params.push(term, term, term, term, term, term);
    }
    if (method) {
      where.push('a.method=?');
      params.push(method);
    }
    if (state === 'active') {
      where.push(`a.status='active' AND a.ended_at IS NULL AND a.expires_at > ?`);
      params.push(now);
    } else if (state === 'ended') {
      where.push(`(a.ended_at IS NOT NULL OR a.expires_at <= ?)`);
      params.push(now);
    } else if (state === 'failed') {
      where.push(`a.status='failed'`);
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const total = this.db.prepare(`
      SELECT COUNT(*) count FROM authorizations a
      LEFT JOIN vouchers v ON a.method='voucher' AND a.identity=v.id ${clause}
    `).get(...params);
    const rows = this.db.prepare(`
      SELECT a.*, v.label voucher_label, v.code_hint voucher_hint
      FROM authorizations a
      LEFT JOIN vouchers v ON a.method='voucher' AND a.identity=v.id
      ${clause} ORDER BY a.created_at DESC LIMIT ? OFFSET ?
    `).all(...params, limit, offset);
    return { rows, total: Number(total.count) };
  }

  listChallenges({ search = '', kind = '', status = '', limit = 100, offset = 0 } = {}) {
    const challengeRows = [];
    let challengeTotal = 0;
    if (kind !== 'voucher') {
      const where = [];
      const params = [];
      if (search) {
        where.push('(target LIKE ? OR client_ip LIKE ? OR client_mac LIKE ?)');
        const term = `%${search}%`;
        params.push(term, term, term);
      }
      if (kind) {
        where.push('kind=?');
        params.push(kind);
      }
      if (status) {
        where.push('status=?');
        params.push(status);
      }
      const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
      const total = this.db.prepare(`SELECT COUNT(*) count FROM challenges ${clause}`).get(...params);
      challengeTotal = Number(total.count || 0);
      challengeRows.push(...this.db.prepare(`
        SELECT id, kind, target, client_ip, client_mac, status, attempts, expires_at,
          created_at, verified_at, last_error,
          (
            SELECT authorization.expires_at
            FROM authorizations AS authorization
            WHERE authorization.method = challenges.kind
              AND authorization.identity = challenges.target
              AND authorization.client_ip = challenges.client_ip
              AND authorization.status = 'active'
            ORDER BY authorization.created_at DESC LIMIT 1
          ) AS access_expires_at,
          (
            SELECT authorization.unlimited
            FROM authorizations AS authorization
            WHERE authorization.method = challenges.kind
              AND authorization.identity = challenges.target
              AND authorization.client_ip = challenges.client_ip
              AND authorization.status = 'active'
            ORDER BY authorization.created_at DESC LIMIT 1
          ) AS access_unlimited
        FROM challenges ${clause} ORDER BY created_at DESC LIMIT ? OFFSET ?
      `).all(...params, limit + offset, 0));
    }

    const voucherRows = [];
    let voucherTotal = 0;
    if (!kind || kind === 'voucher') {
      const where = ["a.method='voucher'"];
      const params = [];
      if (search) {
        where.push(`(a.id LIKE ? OR a.identity LIKE ? OR a.client_ip LIKE ? OR a.client_mac LIKE ?
          OR v.label LIKE ? OR v.code_hint LIKE ?)`);
        const term = `%${search}%`;
        params.push(term, term, term, term, term, term);
      }
      if (status) {
        where.push(status === 'verified'
          ? "a.status!='failed'"
          : status === 'failed' ? "a.status='failed'" : '0');
      }
      const clause = `WHERE ${where.join(' AND ')}`;
      const total = this.db.prepare(`
        SELECT COUNT(*) count
        FROM authorizations a
        LEFT JOIN vouchers v ON a.identity=v.id
        ${clause}
      `).get(...params);
      voucherTotal = Number(total.count || 0);
      voucherRows.push(...this.db.prepare(`
        SELECT
          a.id,
          'voucher' AS kind,
          COALESCE(NULLIF(v.label, ''), 'Voucher access') AS target,
          a.client_ip,
          a.client_mac,
          CASE WHEN a.status='failed' THEN 'failed' ELSE 'verified' END AS status,
          0 AS attempts,
          a.created_at AS expires_at,
          a.created_at,
          CASE WHEN a.status='failed' THEN NULL ELSE a.created_at END AS verified_at,
          a.error AS last_error,
          a.expires_at AS access_expires_at,
          a.unlimited AS access_unlimited,
          v.code_hint AS voucher_hint,
          v.label AS voucher_label
        FROM authorizations a
        LEFT JOIN vouchers v ON a.identity=v.id
        ${clause}
        ORDER BY a.created_at DESC LIMIT ? OFFSET ?
      `).all(...params, limit + offset, 0));
    }

    const adminApprovalRows = [];
    let adminApprovalTotal = 0;
    if (!kind || kind === 'admin-approval') {
      this.expireAdminApprovalRequests();
      const where = [];
      const params = [];
      if (search) {
        where.push(`(request.full_name LIKE ? OR request.contact LIKE ? OR request.identity LIKE ?
          OR request.client_ip LIKE ? OR request.client_mac LIKE ?)`);
        const term = `%${search}%`;
        params.push(term, term, term, term, term);
      }
      if (status) {
        if (status === 'verified') where.push("request.status='approved'");
        else if (status === 'failed') where.push("request.status IN ('rejected', 'failed')");
        else where.push('request.status=?');
        if (!['verified', 'failed'].includes(status)) params.push(status);
      }
      const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
      const total = this.db.prepare(`
        SELECT COUNT(*) count FROM admin_approval_requests AS request ${clause}
      `).get(...params);
      adminApprovalTotal = Number(total.count || 0);
      adminApprovalRows.push(...this.db.prepare(`
        SELECT
          request.id,
          'admin-approval' AS kind,
          request.identity AS target,
          request.client_ip,
          request.client_mac,
          request.status,
          0 AS attempts,
          request.request_expires_at AS expires_at,
          request.created_at,
          CASE WHEN request.status='approved' THEN request.decided_at ELSE NULL END AS verified_at,
          COALESCE(request.last_error, request.decision_message) AS last_error,
          authorization.expires_at AS access_expires_at,
          authorization.unlimited AS access_unlimited,
          request.full_name AS admin_approval_full_name,
          request.contact AS admin_approval_contact,
          request.contact_type AS admin_approval_contact_type,
          request.decided_at AS admin_approval_decided_at,
          request.decided_by AS admin_approval_decided_by,
          request.decision_message AS admin_approval_decision_message
        FROM admin_approval_requests AS request
        LEFT JOIN authorizations AS authorization ON authorization.id=request.authorization_id
        ${clause}
        ORDER BY request.created_at DESC LIMIT ? OFFSET ?
      `).all(...params, limit + offset, 0));
    }

    const rows = [...challengeRows, ...voucherRows, ...adminApprovalRows]
      .sort((left, right) => Number(right.created_at || 0) - Number(left.created_at || 0))
      .slice(offset, offset + limit);
    return { rows, total: challengeTotal + voucherTotal + adminApprovalTotal };
  }

  listVouchersAdmin({ search = '', status = '', limit = 100, offset = 0, now = Date.now() } = {}) {
    const where = [];
    const params = [];
    if (search) {
      where.push('(label LIKE ? OR code_hint LIKE ? OR id LIKE ?)');
      const term = `%${search}%`;
      params.push(term, term, term);
    }
    if (status === 'active') {
      where.push(`enabled=1 AND used_count < max_uses
        AND (valid_from IS NULL OR valid_from <= ?)
        AND (expires_at IS NULL OR expires_at >= ?)`);
      params.push(now, now);
    } else if (status === 'used') {
      where.push('used_count >= max_uses');
    } else if (status === 'disabled') {
      where.push('enabled=0');
    } else if (status === 'expired') {
      where.push('expires_at IS NOT NULL AND expires_at < ?');
      params.push(now);
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const total = this.db.prepare(`SELECT COUNT(*) count FROM vouchers ${clause}`).get(...params);
    const rows = this.db.prepare(`
      SELECT id, code_hint, code_prefix, label, max_uses, used_count, duration_minutes,
        valid_from, expires_at, enabled, created_at
      FROM vouchers ${clause} ORDER BY created_at DESC LIMIT ? OFFSET ?
    `).all(...params, limit, offset);
    return { rows, total: Number(total.count) };
  }

  listActivity({ search = '', kind = '', limit = 150 } = {}) {
    const events = [];
    const authRows = this.db.prepare(`
      SELECT id, method, identity, client_ip, status, created_at, error
      FROM authorizations ORDER BY created_at DESC LIMIT ?
    `).all(limit);
    for (const row of authRows) {
      events.push({
        id: row.id,
        kind: 'authorization',
        action: row.status === 'active' ? 'access_granted' : 'access_failed',
        subject: row.identity,
        method: row.method,
        clientIp: row.client_ip,
        detail: row.error || '',
        createdAt: Number(row.created_at)
      });
    }
    const challengeRows = this.db.prepare(`
      SELECT id, kind, target, client_ip, status, created_at, last_error
      FROM challenges ORDER BY created_at DESC LIMIT ?
    `).all(limit);
    for (const row of challengeRows) {
      events.push({
        id: row.id,
        kind: 'verification',
        action: `verification_${row.status}`,
        subject: row.target,
        method: row.kind,
        clientIp: row.client_ip,
        detail: row.last_error || '',
        createdAt: Number(row.created_at)
      });
    }
    const adminApprovalRows = this.db.prepare(`
      SELECT id, full_name, contact, contact_type, identity, client_ip, status,
        created_at, decided_at, decided_by, decision_message, last_error
      FROM admin_approval_requests ORDER BY created_at DESC LIMIT ?
    `).all(limit);
    for (const row of adminApprovalRows) {
      events.push({
        id: row.id,
        kind: 'verification',
        action: `admin_approval_${row.status}`,
        subject: row.identity || row.full_name,
        method: 'admin-approval',
        clientIp: row.client_ip,
        detail: row.decision_message || row.last_error || '',
        createdAt: Number(row.decided_at || row.created_at)
      });
    }
    const auditRows = this.db.prepare(`
      SELECT id, admin_user, action, target_type, target_id, detail_json, client_ip, created_at
      FROM admin_audit ORDER BY created_at DESC LIMIT ?
    `).all(limit);
    for (const row of auditRows) {
      events.push({
        id: row.id,
        kind: 'admin',
        action: row.action,
        subject: row.target_id || row.admin_user,
        method: row.target_type || 'admin',
        clientIp: row.client_ip,
        detail: row.detail_json || '',
        createdAt: Number(row.created_at)
      });
    }
    const syslogRows = this.db.prepare(`
      SELECT id, event_type, severity, message, detail_json, created_at
      FROM law5651_events ORDER BY created_at DESC LIMIT ?
    `).all(limit);
    for (const row of syslogRows) {
      events.push({
        id: row.id,
        kind: 'syslog',
        action: row.event_type,
        subject: row.severity,
        method: 'syslog',
        clientIp: '',
        detail: row.message || row.detail_json || '',
        createdAt: Number(row.created_at)
      });
    }
    return events
      .filter(row => !kind || row.kind === kind)
      .filter(row => !search || JSON.stringify(row).toLowerCase().includes(search.toLowerCase()))
      .sort((left, right) => right.createdAt - left.createdAt)
      .slice(0, limit);
  }

  activeClientIdentityForTrafficLog(clientIp, at = Date.now()) {
    if (!clientIp) return null;
    const timestamp = Math.trunc(Number(at) || Date.now());
    return this.db.prepare(`
      SELECT method, identity, client_mac
      FROM authorizations
      WHERE client_ip=?
        AND status='active'
        AND ended_at IS NULL
        AND created_at <= ?
        AND expires_at > ?
      ORDER BY created_at DESC LIMIT 1
    `).get(clientIp, timestamp, timestamp) || null;
  }

  trafficLogEffectiveDeltasFromCounters(row, counters) {
    const cumulative = this.trafficLogCumulativeCounters(row);
    if (!cumulative) {
      return {
        downloadBytes: Math.max(0, Math.trunc(Number(row.download_bytes || 0))),
        uploadBytes: Math.max(0, Math.trunc(Number(row.upload_bytes || 0)))
      };
    }
    const key = this.trafficLogSessionKey(row);
    const previous = counters.get(key);
    counters.set(key, cumulative);
    if (!previous) return { downloadBytes: 0, uploadBytes: 0 };
    return {
      downloadBytes: cumulative.downloadBytes >= previous.downloadBytes
        ? cumulative.downloadBytes - previous.downloadBytes
        : cumulative.downloadBytes,
      uploadBytes: cumulative.uploadBytes >= previous.uploadBytes
        ? cumulative.uploadBytes - previous.uploadBytes
        : cumulative.uploadBytes
    };
  }

  trafficLogEffectiveInsertDeltas(row) {
    const cumulative = this.trafficLogCumulativeCounters(row);
    if (!cumulative) {
      return {
        downloadBytes: Math.max(0, Math.trunc(Number(row.download_bytes || 0))),
        uploadBytes: Math.max(0, Math.trunc(Number(row.upload_bytes || 0)))
      };
    }
    const key = this.trafficLogSessionKey(row);
    const candidates = this.db.prepare(`
      SELECT sequence, kind, client_ip, subscriber_id, source_ip, raw_json,
        download_bytes, upload_bytes, created_at
      FROM traffic_logs
      WHERE kind='session'
        AND client_ip=?
        AND source_ip=?
        AND COALESCE(subscriber_id, '')=?
        AND created_at <= ?
      ORDER BY created_at DESC, sequence DESC
      LIMIT 25
    `).all(
      row.client_ip || '',
      row.source_ip || '',
      row.subscriber_id || '',
      Number(row.created_at || 0)
    );
    for (const candidate of candidates) {
      if (this.trafficLogSessionKey(candidate) !== key) continue;
      const previous = this.trafficLogCumulativeCounters(candidate);
      if (!previous) continue;
      return {
        downloadBytes: cumulative.downloadBytes >= previous.downloadBytes
          ? cumulative.downloadBytes - previous.downloadBytes
          : cumulative.downloadBytes,
        uploadBytes: cumulative.uploadBytes >= previous.uploadBytes
          ? cumulative.uploadBytes - previous.uploadBytes
          : cumulative.uploadBytes
      };
    }
    return { downloadBytes: 0, uploadBytes: 0 };
  }

  recordTrafficLogRollups(row, { downloadBytes = 0, uploadBytes = 0 } = {}) {
    const bucketStartAt = minuteBucket(row.created_at);
    if (!bucketStartAt) return;
    const effectiveDownload = Math.max(0, Math.trunc(Number(downloadBytes || 0)));
    const effectiveUpload = Math.max(0, Math.trunc(Number(uploadBytes || 0)));
    const interfaceCounter = isInterfaceCounterTraffic(row);
    const seriesSource = interfaceCounter ? 'interface' : 'traffic';
    this.db.prepare(`
      INSERT INTO traffic_log_minute_rollups
        (series_source, bucket_start_at, records, download_bytes, upload_bytes)
      VALUES (?, ?, 1, ?, ?)
      ON CONFLICT(series_source, bucket_start_at) DO UPDATE SET
        records=records + 1,
        download_bytes=download_bytes + excluded.download_bytes,
        upload_bytes=upload_bytes + excluded.upload_bytes
    `).run(seriesSource, bucketStartAt, effectiveDownload, effectiveUpload);

    if (interfaceCounter || !row.client_ip) return;
    this.db.prepare(`
      INSERT INTO traffic_log_client_minute_rollups
        (bucket_start_at, client_ip, records, download_bytes, upload_bytes)
      VALUES (?, ?, 1, ?, ?)
      ON CONFLICT(bucket_start_at, client_ip) DO UPDATE SET
        records=records + 1,
        download_bytes=download_bytes + excluded.download_bytes,
        upload_bytes=upload_bytes + excluded.upload_bytes
    `).run(bucketStartAt, row.client_ip, effectiveDownload, effectiveUpload);

    const kind = row.kind === 'flow' ? 'flow' : 'session';
    const interfaceName = kind === 'flow' ? trafficLogInterfaceName(row).slice(0, 80) : '';
    this.db.prepare(`
      INSERT INTO traffic_log_client_detail_minute_rollups
        (bucket_start_at, client_ip, kind, interface_name, records, download_bytes, upload_bytes)
      VALUES (?, ?, ?, ?, 1, ?, ?)
      ON CONFLICT(bucket_start_at, client_ip, kind, interface_name) DO UPDATE SET
        records=records + 1,
        download_bytes=download_bytes + excluded.download_bytes,
        upload_bytes=upload_bytes + excluded.upload_bytes
    `).run(bucketStartAt, row.client_ip, kind, interfaceName, effectiveDownload, effectiveUpload);

    if (isDnsResolverTraffic(row)) return;
    const site = trafficLogSiteLabel(row);
    if (!site) return;
    this.db.prepare(`
      INSERT INTO traffic_log_site_minute_rollups
        (bucket_start_at, site, client_ip, records, download_bytes, upload_bytes, last_seen_at)
      VALUES (?, ?, ?, 1, ?, ?, ?)
      ON CONFLICT(bucket_start_at, site, client_ip) DO UPDATE SET
        records=records + 1,
        download_bytes=download_bytes + excluded.download_bytes,
        upload_bytes=upload_bytes + excluded.upload_bytes,
        last_seen_at=MAX(last_seen_at, excluded.last_seen_at)
    `).run(bucketStartAt, site, row.client_ip, effectiveDownload, effectiveUpload, Number(row.created_at || bucketStartAt));
  }

  ensureTrafficLogRollups({ now = Date.now(), force = false } = {}) {
    const version = 'v2';
    if (!force && this.getRuntimeState('traffic_log_rollups_version')?.value === version) return;
    const cutoff = Math.max(0, Math.trunc(Number(now) || Date.now()) -
      TRAFFIC_ROLLUP_BACKFILL_DAYS * 24 * 60 * 60 * 1000);
    const total = Number(this.db.prepare(`
      SELECT COUNT(*) count FROM traffic_logs WHERE created_at >= ?
    `).get(cutoff)?.count || 0);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare('DELETE FROM traffic_log_minute_rollups WHERE bucket_start_at >= ?')
        .run(minuteBucket(cutoff));
      this.db.prepare('DELETE FROM traffic_log_client_minute_rollups WHERE bucket_start_at >= ?')
        .run(minuteBucket(cutoff));
      this.db.prepare('DELETE FROM traffic_log_client_detail_minute_rollups WHERE bucket_start_at >= ?')
        .run(minuteBucket(cutoff));
      this.db.prepare('DELETE FROM traffic_log_site_minute_rollups WHERE bucket_start_at >= ?')
        .run(minuteBucket(cutoff));
      const counters = new Map();
      let lastSequence = 0;
      let processed = 0;
      while (processed < total) {
        const rows = this.db.prepare(`
          SELECT sequence, kind, source, client_ip, client_mac, subscriber_id,
            source_ip, source_port, destination_ip, destination_port, destination_domain,
            protocol, service_type, direction, started_at, ended_at, download_bytes,
            upload_bytes, raw_json, created_at
          FROM traffic_logs
          WHERE created_at >= ? AND sequence > ?
          ORDER BY sequence ASC
          LIMIT ?
        `).all(cutoff, lastSequence, TRAFFIC_ROLLUP_BACKFILL_BATCH);
        if (!rows.length) break;
        for (const row of rows) {
          const effective = this.trafficLogEffectiveDeltasFromCounters(row, counters);
          this.recordTrafficLogRollups(row, effective);
          lastSequence = Number(row.sequence || lastSequence);
          processed += 1;
        }
      }
      this.setRuntimeState('traffic_log_rollups_version', version, now);
      this.setRuntimeState('traffic_log_rollups_backfilled_at', String(now), now);
      this.setRuntimeState('traffic_log_rollups_backfilled_records', String(processed), now);
      this.db.exec('COMMIT');
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch {}
      throw error;
    }
  }

  appendTrafficLogs(records = []) {
    if (!records.length) return { inserted: 0, skipped: 0 };
    let inserted = 0;
    let skipped = 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const input of records) {
        if (!input?.dedupeKey || !input.clientIp || !input.sourceIp || !input.startedAt) {
          skipped += 1;
          continue;
        }
        const exists = this.db.prepare('SELECT 1 FROM traffic_logs WHERE dedupe_key=?')
          .get(String(input.dedupeKey));
        if (exists) {
          skipped += 1;
          continue;
        }
        const startedAt = Math.trunc(Number(input.startedAt));
        const createdAt = Math.trunc(Number(input.createdAt) || Date.now());
        let clientMac = normalizeMac(input.clientMac);
        let subscriberId = String(input.subscriberId || '').slice(0, 128);
        if (!clientMac || !subscriberId) {
          const identity = this.activeClientIdentityForTrafficLog(input.clientIp, startedAt || createdAt);
          if (!clientMac) clientMac = normalizeMac(identity?.client_mac);
          if (!subscriberId && identity) subscriberId = `${identity.method}:${identity.identity}`.slice(0, 128);
        }
        const row = {
          kind: input.kind === 'flow' ? 'flow' : 'session',
          source: String(input.source || 'opnsense').slice(0, 80),
          client_ip: String(input.clientIp).slice(0, 64),
          client_mac: clientMac || null,
          subscriber_id: subscriberId || null,
          source_ip: String(input.sourceIp).slice(0, 64),
          source_port: input.sourcePort ? String(input.sourcePort).slice(0, 16) : null,
          destination_ip: input.destinationIp ? String(input.destinationIp).slice(0, 64) : null,
          destination_port: input.destinationPort ? String(input.destinationPort).slice(0, 16) : null,
          destination_domain: input.destinationDomain ? String(input.destinationDomain).slice(0, 255) : null,
          protocol: input.protocol ? String(input.protocol).slice(0, 32) : null,
          service_type: String(input.serviceType || 'internet-access').slice(0, 80),
          direction: input.direction ? String(input.direction).slice(0, 32) : null,
          started_at: startedAt,
          ended_at: input.endedAt ? Math.trunc(Number(input.endedAt)) : null,
          download_bytes: Math.max(0, Math.trunc(Number(input.downloadBytes) || 0)),
          upload_bytes: Math.max(0, Math.trunc(Number(input.uploadBytes) || 0)),
          raw_json: input.rawJson ? String(input.rawJson).slice(0, 10000) : null,
          created_at: createdAt
        };
        const effective = this.trafficLogEffectiveInsertDeltas(row);
        this.db.prepare(`
          INSERT INTO traffic_logs
            (id, dedupe_key, kind, source, client_ip, client_mac, subscriber_id,
             source_ip, source_port, destination_ip, destination_port, destination_domain,
             protocol, service_type, direction, started_at, ended_at, download_bytes,
             upload_bytes, raw_json, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          randomUUID(),
          String(input.dedupeKey),
          row.kind,
          row.source,
          row.client_ip,
          row.client_mac,
          row.subscriber_id,
          row.source_ip,
          row.source_port,
          row.destination_ip,
          row.destination_port,
          row.destination_domain,
          row.protocol,
          row.service_type,
          row.direction,
          row.started_at,
          row.ended_at,
          row.download_bytes,
          row.upload_bytes,
          row.raw_json,
          row.created_at
        );
        this.recordTrafficLogRollups(row, effective);
        inserted += 1;
      }
      this.db.exec('COMMIT');
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch {}
      throw error;
    }
    return { inserted, skipped };
  }

  trafficLogPeriod(period = 'daily', now = Date.now()) {
    const selected = ['hourly', '6h', '12h', 'daily', 'weekly', 'monthly'].includes(period) ? period : 'daily';
    const current = Math.trunc(Number(now) || Date.now());
    const rolling = {
      hourly: { bucket: '5min', bucketMs: 5 * 60 * 1000, count: 12 },
      '6h': { bucket: '30min', bucketMs: 30 * 60 * 1000, count: 12 },
      '12h': { bucket: 'hour', bucketMs: 60 * 60 * 1000, count: 12 }
    }[selected];
    if (rolling) {
      const endAt = Math.ceil((current + 1) / rolling.bucketMs) * rolling.bucketMs;
      return {
        period: selected,
        ...rolling,
        startAt: endAt - rolling.count * rolling.bucketMs,
        endAt
      };
    }
    const dayStart = new Date(Math.trunc(Number(now) || Date.now()));
    dayStart.setHours(0, 0, 0, 0);
    const dayStartAt = dayStart.getTime();
    if (selected === 'daily') {
      return {
        period: selected,
        bucket: 'hour',
        bucketMs: 60 * 60 * 1000,
        count: 24,
        startAt: dayStartAt,
        endAt: dayStartAt + 24 * 60 * 60 * 1000
      };
    }
    const count = selected === 'weekly' ? 7 : 30;
    return {
      period: selected,
      bucket: 'day',
      bucketMs: 24 * 60 * 60 * 1000,
      count,
      startAt: dayStartAt - (count - 1) * 24 * 60 * 60 * 1000,
      endAt: dayStartAt + 24 * 60 * 60 * 1000
    };
  }

  trafficLogPointLabel(date, bucket) {
    if (['5min', '30min', 'hour'].includes(bucket)) {
      return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
    }
    return [
      date.getFullYear(),
      String(date.getMonth() + 1).padStart(2, '0'),
      String(date.getDate()).padStart(2, '0')
    ].join('-');
  }

  trafficLogCumulativeCounters(row) {
    if (row?.kind !== 'session' || !row.raw_json) return null;
    try {
      const raw = JSON.parse(row.raw_json);
      const download = Number(raw.cumulativeDownloadBytes);
      const upload = Number(raw.cumulativeUploadBytes);
      if (!Number.isFinite(download) || !Number.isFinite(upload)) return null;
      return {
        downloadBytes: Math.max(0, Math.trunc(download)),
        uploadBytes: Math.max(0, Math.trunc(upload))
      };
    } catch {
      return null;
    }
  }

  trafficLogSessionKey(row) {
    let sessionId = '';
    if (row?.raw_json) {
      try {
        const raw = JSON.parse(row.raw_json);
        const gateway = raw.gateway || {};
        sessionId = String(
          raw.gatewaySessionId ||
          gateway.sessionId ||
          gateway.session_id ||
          gateway.sessionid ||
          gateway.id ||
          ''
        );
      } catch {}
    }
    return [
      sessionId || 'session',
      row.subscriber_id || '',
      row.client_ip || '',
      row.source_ip || ''
    ].join('|');
  }

  effectiveTrafficLogRows(rows = []) {
    const counters = new Map();
    return [...rows]
      .sort((left, right) =>
        Number(left.created_at || 0) - Number(right.created_at || 0) ||
        Number(left.sequence || 0) - Number(right.sequence || 0)
      )
      .map(row => {
        const cumulative = this.trafficLogCumulativeCounters(row);
        if (!cumulative) {
          return {
            ...row,
            effective_download_bytes: Number(row.download_bytes || 0),
            effective_upload_bytes: Number(row.upload_bytes || 0)
          };
        }
        const key = this.trafficLogSessionKey(row);
        const previous = counters.get(key);
        counters.set(key, cumulative);
        if (!previous) {
          return { ...row, effective_download_bytes: 0, effective_upload_bytes: 0 };
        }
        return {
          ...row,
          effective_download_bytes: cumulative.downloadBytes >= previous.downloadBytes
            ? cumulative.downloadBytes - previous.downloadBytes
            : cumulative.downloadBytes,
          effective_upload_bytes: cumulative.uploadBytes >= previous.uploadBytes
            ? cumulative.uploadBytes - previous.uploadBytes
            : cumulative.uploadBytes
        };
      });
  }

  trafficLogSeries({ period = 'daily', now = Date.now() } = {}) {
    const window = this.trafficLogPeriod(period, now);
    const points = Array.from({ length: window.count }, (_, index) => {
      const startAt = window.startAt + index * window.bucketMs;
      const date = new Date(startAt);
      const key = this.trafficLogPointLabel(date, window.bucket);
      return {
        key,
        label: key,
        startAt,
        endAt: startAt + window.bucketMs,
        downloadBytes: 0,
        uploadBytes: 0,
        records: 0
      };
    });
    const interfaceRecords = Number(this.db.prepare(`
      SELECT COALESCE(SUM(records), 0) records
      FROM traffic_log_minute_rollups
      WHERE series_source='interface'
        AND bucket_start_at >= ?
        AND bucket_start_at < ?
    `).get(window.startAt, window.endAt)?.records || 0);
    const seriesSource = interfaceRecords ? 'interface' : 'traffic';
    const rows = this.db.prepare(`
      SELECT bucket_start_at,
        COALESCE(SUM(records), 0) records,
        COALESCE(SUM(download_bytes), 0) download_bytes,
        COALESCE(SUM(upload_bytes), 0) upload_bytes
      FROM traffic_log_minute_rollups
      WHERE series_source=?
        AND bucket_start_at >= ?
        AND bucket_start_at < ?
      GROUP BY bucket_start_at
      ORDER BY bucket_start_at ASC
    `).all(seriesSource, window.startAt, window.endAt);
    let source = seriesSource === 'interface' ? 'traffic_rollups_interface' : 'traffic_rollups';
    let fallbackRows = [];
    if (!rows.length) {
      fallbackRows = this.db.prepare(`
        SELECT created_at, download_bytes, upload_bytes
        FROM authorizations
        WHERE created_at >= ? AND created_at < ?
      `).all(window.startAt, window.endAt);
      source = 'authorizations';
    }
    for (const row of rows) {
      const index = Math.floor((Number(row.bucket_start_at) - window.startAt) / window.bucketMs);
      if (index < 0 || index >= points.length) continue;
      points[index].downloadBytes += Number(row.download_bytes || 0);
      points[index].uploadBytes += Number(row.upload_bytes || 0);
      points[index].records += Number(row.records || 0);
    }
    for (const row of fallbackRows) {
      const index = Math.floor((Number(row.created_at) - window.startAt) / window.bucketMs);
      if (index < 0 || index >= points.length) continue;
      points[index].downloadBytes += Number(row.download_bytes || 0);
      points[index].uploadBytes += Number(row.upload_bytes || 0);
      points[index].records += 1;
    }
    const totalDownloadBytes = points.reduce((sum, point) => sum + point.downloadBytes, 0);
    const totalUploadBytes = points.reduce((sum, point) => sum + point.uploadBytes, 0);
    const peak = points.reduce((best, point) =>
      point.downloadBytes + point.uploadBytes > best.downloadBytes + best.uploadBytes ? point : best
    , points[0] || { downloadBytes: 0, uploadBytes: 0, label: '' });
    const activeRow = this.db.prepare(`
      SELECT COUNT(*) clients, COALESCE(SUM(records), 0) records
      FROM traffic_log_client_minute_rollups
      WHERE bucket_start_at >= ?
    `).get(minuteBucket(Math.trunc(Number(now) || Date.now()) - 5 * 60 * 1000));
    const recordCount = rows.reduce((sum, row) => sum + Number(row.records || 0), 0) + fallbackRows.length;
    return {
      ...window,
      source,
      points,
      summary: {
        totalDownloadBytes,
        totalUploadBytes,
        totalBytes: totalDownloadBytes + totalUploadBytes,
        records: recordCount,
        peakLabel: peak.label,
        peakBytes: Number(peak.downloadBytes || 0) + Number(peak.uploadBytes || 0),
        liveClients: Number(activeRow?.clients || 0),
        liveRecords: Number(activeRow?.records || 0)
      }
    };
  }

  topTrafficLogSites({ hours = 6, limit = 10, sort = 'visits', now = Date.now() } = {}) {
    const safeHours = [1, 6, 12, 24].includes(Number(hours)) ? Number(hours) : 6;
    const safeLimit = Math.max(1, Math.min(25, Math.trunc(Number(limit) || 10)));
    const safeSort = sort === 'bytes' ? 'bytes' : 'visits';
    const orderBy = safeSort === 'bytes'
      ? `total_bytes DESC,
        visits DESC,
        site ASC`
      : `visits DESC,
        total_bytes DESC,
        site ASC`;
    const endAt = Math.trunc(Number(now) || Date.now()) + 1;
    const startAt = endAt - safeHours * 60 * 60 * 1000;
    const bucketStartAt = minuteBucket(startAt);
    const rows = this.db.prepare(`
      SELECT site,
        COALESCE(SUM(records), 0) visits,
        COUNT(DISTINCT client_ip) clients,
        COALESCE(SUM(download_bytes), 0) download_bytes,
        COALESCE(SUM(upload_bytes), 0) upload_bytes,
        COALESCE(SUM(download_bytes), 0) + COALESCE(SUM(upload_bytes), 0) total_bytes,
        MAX(last_seen_at) last_seen_at
      FROM traffic_log_site_minute_rollups
      WHERE bucket_start_at >= ?
        AND bucket_start_at < ?
      GROUP BY site
      ORDER BY ${orderBy}
      LIMIT ?
    `).all(bucketStartAt, endAt, safeLimit).map(row => ({
      site: row.site,
      visits: Number(row.visits || 0),
      clients: Number(row.clients || 0),
      downloadBytes: Number(row.download_bytes || 0),
      uploadBytes: Number(row.upload_bytes || 0),
      totalBytes: Number(row.total_bytes || 0),
      lastSeenAt: row.last_seen_at ? Number(row.last_seen_at) : null
    }));
    const summary = this.db.prepare(`
      SELECT COUNT(*) total_sites, COALESCE(SUM(visits), 0) total_visits
      FROM (
        SELECT site, COALESCE(SUM(records), 0) visits
        FROM traffic_log_site_minute_rollups
        WHERE bucket_start_at >= ?
          AND bucket_start_at < ?
        GROUP BY site
      )
    `).get(bucketStartAt, endAt);
    return {
      source: 'traffic_rollups',
      hours: safeHours,
      limit: safeLimit,
      sort: safeSort,
      startAt,
      endAt,
      totalVisits: Number(summary?.total_visits || 0),
      totalSites: Number(summary?.total_sites || 0),
      rows
    };
  }

  trafficLogClientInScope(clientIp, networks) {
    if (isIP(clientIp) !== 4) return false;
    const safeNetworks = safeNetworkList(networks);
    if (safeNetworks !== 'any') {
      try {
        return ipv4InNetworkList(clientIp, safeNetworks);
      } catch {
        return false;
      }
    }
    return isPrivateIpv4(clientIp);
  }

  trafficLogClientChartRowAllowed(row, { networks = 'any', excludedInterfaces = [] } = {}) {
    if (!this.trafficLogClientInScope(row.client_ip, networks)) return false;
    if (row.kind !== 'flow') return true;
    const interfaceName = trafficLogInterfaceName(row);
    if (!interfaceName || !excludedInterfaces.includes(interfaceName)) return true;
    return false;
  }

  topTrafficLogClients({ hours = 6, limit = 10, networks = 'any', excludedInterfaces = [], now = Date.now() } = {}) {
    const safeHours = [1, 6, 12, 24].includes(Number(hours)) ? Number(hours) : 6;
    const safeLimit = Math.max(1, Math.min(25, Math.trunc(Number(limit) || 10)));
    const endAt = Math.trunc(Number(now) || Date.now()) + 1;
    const startAt = endAt - safeHours * 60 * 60 * 1000;
    const bucketStartAt = minuteBucket(startAt);
    const blockedInterfaces = [...new Set(excludedInterfaces.map(value => String(value || '').trim().toLowerCase()).filter(Boolean))];
    const interfaceFilter = blockedInterfaces.length
      ? `AND (kind != 'flow' OR interface_name = '' OR interface_name NOT IN (${blockedInterfaces.map(() => '?').join(', ')}))`
      : '';
    const records = this.db.prepare(`
      SELECT client_ip, kind,
        COALESCE(SUM(records), 0) records,
        COALESCE(SUM(download_bytes), 0) download_bytes,
        COALESCE(SUM(upload_bytes), 0) upload_bytes
      FROM traffic_log_client_detail_minute_rollups
      WHERE bucket_start_at >= ?
        AND bucket_start_at < ?
        ${interfaceFilter}
      GROUP BY client_ip, kind
    `).all(bucketStartAt, endAt, ...blockedInterfaces);
    const groups = new Map();
    for (const row of records) {
      if (!this.trafficLogClientInScope(row.client_ip, networks)) continue;
      const existing = groups.get(row.client_ip) || {
        clientIp: row.client_ip,
        sessionRecords: 0,
        sessionDownloadBytes: 0,
        sessionUploadBytes: 0,
        flowRecords: 0,
        flowDownloadBytes: 0,
        flowUploadBytes: 0
      };
      if (row.kind === 'session') {
        existing.sessionRecords += Number(row.records || 0);
        existing.sessionDownloadBytes += Number(row.download_bytes || 0);
        existing.sessionUploadBytes += Number(row.upload_bytes || 0);
      } else {
        existing.flowRecords += Number(row.records || 0);
        existing.flowDownloadBytes += Number(row.download_bytes || 0);
        existing.flowUploadBytes += Number(row.upload_bytes || 0);
      }
      groups.set(row.client_ip, existing);
    }
    const allRows = [...groups.values()].map(row => {
      const sessionBytes = row.sessionDownloadBytes + row.sessionUploadBytes;
      const useSession = sessionBytes > 0;
      const downloadBytes = useSession ? row.sessionDownloadBytes : row.flowDownloadBytes;
      const uploadBytes = useSession ? row.sessionUploadBytes : row.flowUploadBytes;
      const records = useSession ? row.sessionRecords : row.flowRecords;
      return {
        clientIp: row.clientIp,
        label: row.clientIp,
        records,
        downloadBytes,
        uploadBytes,
        totalBytes: downloadBytes + uploadBytes,
        source: useSession ? 'sessions' : 'flows'
      };
    }).filter(row => row.records > 0 && row.totalBytes > 0);
    const rows = allRows
      .sort((left, right) =>
        right.totalBytes - left.totalBytes ||
        right.records - left.records ||
        left.clientIp.localeCompare(right.clientIp)
      )
      .slice(0, safeLimit);
    return {
      source: 'traffic_rollups',
      hours: safeHours,
      limit: safeLimit,
      startAt,
      endAt,
      networks: safeNetworkList(networks),
      excludedInterfaces: blockedInterfaces,
      totalRecords: allRows.reduce((sum, row) => sum + row.records, 0),
      totalClients: allRows.length,
      rows
    };
  }

  trafficLogStoredEffectiveDeltas(row) {
    const cumulative = this.trafficLogCumulativeCounters(row);
    if (!cumulative) {
      return {
        effective_download_bytes: Math.max(0, Math.trunc(Number(row.download_bytes || 0))),
        effective_upload_bytes: Math.max(0, Math.trunc(Number(row.upload_bytes || 0)))
      };
    }
    const key = this.trafficLogSessionKey(row);
    const candidates = this.db.prepare(`
      SELECT sequence, kind, client_ip, subscriber_id, source_ip, raw_json,
        download_bytes, upload_bytes, created_at
      FROM traffic_logs
      WHERE kind='session'
        AND client_ip=?
        AND source_ip=?
        AND COALESCE(subscriber_id, '')=?
        AND (
          created_at < ?
          OR (created_at = ? AND sequence < ?)
        )
      ORDER BY created_at DESC, sequence DESC
      LIMIT 25
    `).all(
      row.client_ip || '',
      row.source_ip || '',
      row.subscriber_id || '',
      Number(row.created_at || 0),
      Number(row.created_at || 0),
      Number(row.sequence || 0)
    );
    for (const candidate of candidates) {
      if (this.trafficLogSessionKey(candidate) !== key) continue;
      const previous = this.trafficLogCumulativeCounters(candidate);
      if (!previous) continue;
      return {
        effective_download_bytes: cumulative.downloadBytes >= previous.downloadBytes
          ? cumulative.downloadBytes - previous.downloadBytes
          : cumulative.downloadBytes,
        effective_upload_bytes: cumulative.uploadBytes >= previous.uploadBytes
          ? cumulative.uploadBytes - previous.uploadBytes
          : cumulative.uploadBytes
      };
    }
    return { effective_download_bytes: 0, effective_upload_bytes: 0 };
  }

  trafficLogRollupSummary({ kind = '', window, now = Date.now() } = {}) {
    const bucketStartAt = minuteBucket(window.startAt);
    const kindClause = kind === 'session' || kind === 'flow' ? 'AND kind=?' : '';
    const kindParams = kindClause ? [kind] : [];
    const summary = this.db.prepare(`
      SELECT
        COALESCE(SUM(records), 0) records,
        COUNT(DISTINCT client_ip) clients,
        COALESCE(SUM(download_bytes), 0) download_bytes,
        COALESCE(SUM(upload_bytes), 0) upload_bytes
      FROM traffic_log_client_detail_minute_rollups
      WHERE bucket_start_at >= ?
        AND bucket_start_at < ?
        ${kindClause}
    `).get(bucketStartAt, window.endAt, ...kindParams);
    const last = this.db.prepare(`
      SELECT MAX(created_at) last_created_at
      FROM traffic_logs
      WHERE created_at >= ?
        AND created_at < ?
        AND source != ?
        AND service_type != 'interface-counter'
        ${kindClause}
    `).get(window.startAt, window.endAt, INTERFACE_COUNTER_SOURCE, ...kindParams);
    const liveEndAt = Math.trunc(Number(now) || Date.now()) + 1;
    const liveStartAt = Math.max(0, liveEndAt - LIVE_TRAFFIC_WINDOW_MS);
    const live = this.db.prepare(`
      SELECT
        COALESCE(SUM(records), 0) records,
        COUNT(DISTINCT client_ip) clients,
        COALESCE(SUM(download_bytes), 0) download_bytes,
        COALESCE(SUM(upload_bytes), 0) upload_bytes
      FROM traffic_log_client_detail_minute_rollups
      WHERE bucket_start_at >= ?
        AND bucket_start_at < ?
        ${kindClause}
    `).get(minuteBucket(liveStartAt), liveEndAt, ...kindParams);
    const liveWindowSeconds = Math.max(1, Math.round(LIVE_TRAFFIC_WINDOW_MS / 1000));
    const liveDownloadBytes = Number(live?.download_bytes || 0);
    const liveUploadBytes = Number(live?.upload_bytes || 0);
    return {
      records: Number(summary?.records || 0),
      clients: Number(summary?.clients || 0),
      downloadBytes: Number(summary?.download_bytes || 0),
      uploadBytes: Number(summary?.upload_bytes || 0),
      liveWindowSeconds,
      liveRecords: Number(live?.records || 0),
      liveClients: Number(live?.clients || 0),
      liveDownloadBytes,
      liveUploadBytes,
      liveDownloadBps: Math.round(liveDownloadBytes / liveWindowSeconds),
      liveUploadBps: Math.round(liveUploadBytes / liveWindowSeconds),
      lastCreatedAt: last?.last_created_at ? Number(last.last_created_at) : null
    };
  }

  listTrafficLogs({
    search = '',
    kind = '',
    period = '',
    sourceIp = '',
    sourcePort = '',
    destinationIp = '',
    destinationPort = '',
    startAt = null,
    endAt = null,
    limit = 150,
    offset = 0,
    order = 'desc',
    now = Date.now()
  } = {}) {
    const filters = [];
    const filterParams = [];
    const interfaceCounterFilter = 'source != ? AND service_type != ?';
    const interfaceCounterParams = [INTERFACE_COUNTER_SOURCE, 'interface-counter'];
    const endpointFilters = [
      ['source_ip', sourceIp, 'like'],
      ['source_port', sourcePort, 'exact'],
      ['destination_ip', destinationIp, 'like'],
      ['destination_port', destinationPort, 'exact']
    ];
    const hasSearch = Boolean(String(search || '').trim());
    let hasEndpointFilter = false;
    if (search) {
      filters.push(`(client_ip LIKE ? OR client_mac LIKE ? OR subscriber_id LIKE ?
        OR source_ip LIKE ? OR source_port LIKE ? OR destination_ip LIKE ?
        OR destination_port LIKE ? OR destination_domain LIKE ? OR protocol LIKE ?
        OR service_type LIKE ?)`);
      const term = `%${search}%`;
      filterParams.push(term, term, term, term, term, term, term, term, term, term);
    }
    for (const [column, value, mode] of endpointFilters) {
      const text = String(value || '').trim();
      if (!text) continue;
      hasEndpointFilter = true;
      filters.push(`${column}${mode === 'like' ? ' LIKE ?' : '=?'}`);
      filterParams.push(mode === 'like' ? `%${text}%` : text);
    }
    if (kind === 'session' || kind === 'flow') {
      filters.push('kind=?');
      filterParams.push(kind);
    }
    const customStart = startAt == null || startAt === '' ? null : Math.trunc(Number(startAt));
    const customEnd = endAt == null || endAt === '' ? null : Math.trunc(Number(endAt));
    const hasCustomWindow = Number.isFinite(customStart) || Number.isFinite(customEnd);
    const safeCustomStart = Number.isFinite(customStart) ? Math.max(0, customStart) : 0;
    const safeCustomEnd = Number.isFinite(customEnd)
      ? Math.max(safeCustomStart, customEnd)
      : Math.trunc(Number(now) || Date.now()) + 1;
    const window = hasCustomWindow
      ? { startAt: safeCustomStart, endAt: safeCustomEnd }
      : (['hourly', '6h', '12h', 'daily', 'weekly', 'monthly'].includes(period)
          ? this.trafficLogPeriod(period, now)
          : null);
    const safeOffset = Math.max(0, Math.trunc(Number(offset) || 0));
    const safeLimit = Math.max(1, Math.trunc(Number(limit) || 150));
    if (window && safeLimit <= 1000 && !hasCustomWindow && !hasSearch && !hasEndpointFilter) {
      const pageWhere = [
        interfaceCounterFilter,
        'created_at >= ? AND created_at < ?',
        ...(kind === 'session' || kind === 'flow' ? ['kind=?'] : [])
      ];
      const pageParams = [
        ...interfaceCounterParams,
        window.startAt,
        window.endAt,
        ...(kind === 'session' || kind === 'flow' ? [kind] : [])
      ];
      const direction = order === 'asc' ? 'ASC' : 'DESC';
      const pageRows = this.db.prepare(`
        SELECT *
        FROM traffic_logs
        WHERE ${pageWhere.join(' AND ')}
        ORDER BY sequence ${direction}
        LIMIT ? OFFSET ?
      `).all(...pageParams, safeLimit, safeOffset)
        .map(row => ({ ...row, ...this.trafficLogStoredEffectiveDeltas(row) }));
      const summary = this.trafficLogRollupSummary({ kind, window, now });
      return {
        source: 'traffic_rollups',
        rows: pageRows,
        total: summary.records,
        summary
      };
    }
    const contextWhere = [...filters];
    const contextParams = [...filterParams];
    contextWhere.push(interfaceCounterFilter);
    contextParams.push(...interfaceCounterParams);
    const lookbackAt = window ? Math.max(0, window.startAt - 48 * 60 * 60 * 1000) : null;
    if (window) {
      contextWhere.push('created_at >= ? AND created_at < ?');
      contextParams.push(lookbackAt, window.endAt);
    }
    const contextClause = contextWhere.length ? `WHERE ${contextWhere.join(' AND ')}` : '';
    let rows = this.effectiveTrafficLogRows(this.db.prepare(`
      SELECT *
      FROM traffic_logs ${contextClause}
      ORDER BY created_at ASC, sequence ASC
    `).all(...contextParams));
    if (window) {
      rows = rows.filter(row => Number(row.created_at) >= window.startAt);
    }
    const liveEndAt = Math.trunc(Number(now) || Date.now()) + 1;
    const liveStartAt = Math.max(0, liveEndAt - LIVE_TRAFFIC_WINDOW_MS);
    const liveContextWhere = [...filters, interfaceCounterFilter, 'created_at >= ? AND created_at < ?'];
    const liveContextParams = [
      ...filterParams,
      ...interfaceCounterParams,
      Math.max(0, liveStartAt - 48 * 60 * 60 * 1000),
      liveEndAt
    ];
    const liveRows = this.effectiveTrafficLogRows(this.db.prepare(`
      SELECT *
      FROM traffic_logs
      WHERE ${liveContextWhere.join(' AND ')}
      ORDER BY created_at ASC, sequence ASC
    `).all(...liveContextParams))
      .filter(row => Number(row.created_at || 0) >= liveStartAt);
    const liveDownloadBytes = liveRows.reduce((sum, row) =>
      sum + Number(row.effective_download_bytes ?? row.download_bytes ?? 0), 0);
    const liveUploadBytes = liveRows.reduce((sum, row) =>
      sum + Number(row.effective_upload_bytes ?? row.upload_bytes ?? 0), 0);
    const liveWindowSeconds = Math.max(1, Math.round(LIVE_TRAFFIC_WINDOW_MS / 1000));
    const direction = order === 'asc' ? 'ASC' : 'DESC';
    const orderedRows = [...rows].sort((left, right) => {
      const sequence = Number(left.sequence || 0) - Number(right.sequence || 0);
      return direction === 'ASC' ? sequence : -sequence;
    });
    const pageRows = orderedRows.slice(
      safeOffset,
      safeOffset + safeLimit
    );
    const clients = new Set(rows.map(row => row.client_ip).filter(Boolean));
    return {
      rows: pageRows,
      total: rows.length,
      summary: {
        records: rows.length,
        clients: clients.size,
        downloadBytes: rows.reduce((sum, row) => sum + Number(row.effective_download_bytes ?? row.download_bytes ?? 0), 0),
        uploadBytes: rows.reduce((sum, row) => sum + Number(row.effective_upload_bytes ?? row.upload_bytes ?? 0), 0),
        liveWindowSeconds,
        liveRecords: liveRows.length,
        liveClients: new Set(liveRows.map(row => row.client_ip).filter(Boolean)).size,
        liveDownloadBytes,
        liveUploadBytes,
        liveDownloadBps: Math.round(liveDownloadBytes / liveWindowSeconds),
        liveUploadBps: Math.round(liveUploadBytes / liveWindowSeconds),
        lastCreatedAt: rows.length
          ? rows.reduce((latest, row) => {
            const createdAt = Number(row.created_at || 0);
            return Number.isFinite(createdAt) && createdAt > latest ? createdAt : latest;
          }, 0)
          : null
      }
    };
  }

  cleanupTrafficLogs(retentionDays, now = Date.now()) {
    const days = Math.max(1, Math.trunc(Number(retentionDays) || 30));
    const cutoff = Math.trunc(Number(now) || Date.now()) - days * 24 * 60 * 60 * 1000;
    const bucketCutoff = minuteBucket(cutoff);
    const deleted = Number(this.db.prepare('DELETE FROM traffic_logs WHERE created_at < ?')
      .run(cutoff).changes);
    this.db.prepare('DELETE FROM traffic_log_minute_rollups WHERE bucket_start_at < ?')
      .run(bucketCutoff);
    this.db.prepare('DELETE FROM traffic_log_client_minute_rollups WHERE bucket_start_at < ?')
      .run(bucketCutoff);
    this.db.prepare('DELETE FROM traffic_log_client_detail_minute_rollups WHERE bucket_start_at < ?')
      .run(bucketCutoff);
    this.db.prepare('DELETE FROM traffic_log_site_minute_rollups WHERE bucket_start_at < ?')
      .run(bucketCutoff);
    return deleted;
  }

  updateAuthorizationUsage(id, {
    downloadBytes, uploadBytes, lastSeenAt = Date.now(), sampledAt = Date.now(), deviceName = '', clientMac = '',
    allowDecrease = false
  }) {
    const downloadExpression = allowDecrease ? '?' : 'MAX(download_bytes, ?)';
    const uploadExpression = allowDecrease ? '?' : 'MAX(upload_bytes, ?)';
    return Number(this.db.prepare(`
      UPDATE authorizations SET
        previous_gateway_download_bytes=download_bytes,
        previous_gateway_upload_bytes=upload_bytes,
        previous_gateway_seen_at=last_seen_at,
        previous_gateway_sampled_at=gateway_sampled_at,
        download_bytes=${downloadExpression},
        upload_bytes=${uploadExpression},
        last_seen_at=?,
        gateway_sampled_at=?,
        device_name=COALESCE(NULLIF(?, ''), device_name),
        client_mac=COALESCE(NULLIF(?, ''), client_mac)
      WHERE id=?
    `).run(Math.max(0, Math.trunc(downloadBytes || 0)), Math.max(0, Math.trunc(uploadBytes || 0)),
      integerTimestamp(lastSeenAt), integerTimestamp(sampledAt), deviceName, clientMac, id).changes) === 1;
  }

  authorizationLiveTraffic({ now = Date.now(), maxAgeMs = 120000 } = {}) {
    const currentTime = Math.trunc(Number(now) || Date.now());
    const minSeenAt = currentTime - Math.max(5000, Math.trunc(Number(maxAgeMs) || 120000));
    const rows = this.db.prepare(`
      SELECT client_ip, download_bytes, upload_bytes,
        previous_gateway_download_bytes, previous_gateway_upload_bytes,
        gateway_sampled_at, previous_gateway_sampled_at
      FROM authorizations
      WHERE status='active'
        AND ended_at IS NULL
        AND expires_at > ?
        AND gateway_sampled_at IS NOT NULL
        AND previous_gateway_sampled_at IS NOT NULL
        AND gateway_sampled_at > previous_gateway_sampled_at
        AND gateway_sampled_at >= ?
    `).all(currentTime, minSeenAt);
    let downloadBps = 0;
    let uploadBps = 0;
    let downloadBytes = 0;
    let uploadBytes = 0;
    let lastSampleAt = null;
    const clients = new Set();
    for (const row of rows) {
      const elapsedSeconds = Math.max(1, (Number(row.gateway_sampled_at) - Number(row.previous_gateway_sampled_at)) / 1000);
      const currentDownload = Math.max(0, Number(row.download_bytes || 0));
      const currentUpload = Math.max(0, Number(row.upload_bytes || 0));
      const previousDownload = Math.max(0, Number(row.previous_gateway_download_bytes || 0));
      const previousUpload = Math.max(0, Number(row.previous_gateway_upload_bytes || 0));
      const downloadDelta = currentDownload >= previousDownload ? currentDownload - previousDownload : currentDownload;
      const uploadDelta = currentUpload >= previousUpload ? currentUpload - previousUpload : currentUpload;
      downloadBytes += downloadDelta;
      uploadBytes += uploadDelta;
      downloadBps += downloadDelta / elapsedSeconds;
      uploadBps += uploadDelta / elapsedSeconds;
      if (row.client_ip) clients.add(row.client_ip);
      lastSampleAt = Math.max(Number(lastSampleAt || 0), Number(row.gateway_sampled_at || 0));
    }
    return {
      liveSource: rows.length ? 'gateway_sessions' : 'gateway_sessions_waiting',
      liveWindowSeconds: rows.length
        ? Math.max(1, Math.round((rows.reduce((sum, row) =>
            sum + Math.max(1, Number(row.gateway_sampled_at) - Number(row.previous_gateway_sampled_at)), 0) / rows.length) / 1000))
        : 0,
      liveRecords: rows.length,
      liveClients: clients.size,
      liveDownloadBytes: Math.round(downloadBytes),
      liveUploadBytes: Math.round(uploadBytes),
      liveDownloadBps: Math.round(downloadBps),
      liveUploadBps: Math.round(uploadBps),
      liveLastSampleAt: lastSampleAt
    };
  }

  recordAuthorizationQuotaUsage(authorization, period, {
    downloadBytes, uploadBytes, updatedAt = Date.now()
  }) {
    const authorizationId = authorization?.id || '';
    const periodKey = period?.key || '';
    if (!authorizationId || !periodKey) return null;
    const currentDownload = Math.max(0, Math.trunc(Number(downloadBytes || 0)));
    const currentUpload = Math.max(0, Math.trunc(Number(uploadBytes || 0)));
    const existing = this.db.prepare(`
      SELECT * FROM authorization_quota_usage
      WHERE authorization_id=? AND period_key=?
    `).get(authorizationId, periodKey);
    const previousDownload = existing
      ? Number(existing.last_gateway_download_bytes || 0)
      : Number(authorization.download_bytes || 0);
    const previousUpload = existing
      ? Number(existing.last_gateway_upload_bytes || 0)
      : Number(authorization.upload_bytes || 0);
    const downloadDelta = currentDownload >= previousDownload
      ? currentDownload - previousDownload
      : currentDownload;
    const uploadDelta = currentUpload >= previousUpload
      ? currentUpload - previousUpload
      : currentUpload;
    if (existing) {
      this.db.prepare(`
        UPDATE authorization_quota_usage
        SET download_bytes=download_bytes + ?,
          upload_bytes=upload_bytes + ?,
          period_start_at=?,
          period_end_at=?,
          last_gateway_download_bytes=?,
          last_gateway_upload_bytes=?,
          updated_at=?
        WHERE authorization_id=? AND period_key=?
      `).run(
        downloadDelta,
        uploadDelta,
        Math.trunc(Number(period.startAt)),
        Math.trunc(Number(period.endAt)),
        currentDownload,
        currentUpload,
        Math.trunc(Number(updatedAt)),
        authorizationId,
        periodKey
      );
    } else {
      this.db.prepare(`
        INSERT INTO authorization_quota_usage
          (authorization_id, period_key, period_start_at, period_end_at,
           download_bytes, upload_bytes, last_gateway_download_bytes,
           last_gateway_upload_bytes, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        authorizationId,
        periodKey,
        Math.trunc(Number(period.startAt)),
        Math.trunc(Number(period.endAt)),
        downloadDelta,
        uploadDelta,
        currentDownload,
        currentUpload,
        Math.trunc(Number(updatedAt))
      );
    }
    return this.db.prepare(`
      SELECT * FROM authorization_quota_usage
      WHERE authorization_id=? AND period_key=?
    `).get(authorizationId, periodKey) || null;
  }

  getAuthorizationQuotaUsage(authorizationId, periodKey) {
    if (!authorizationId || !periodKey) return null;
    return this.db.prepare(`
      SELECT * FROM authorization_quota_usage
      WHERE authorization_id=? AND period_key=?
    `).get(authorizationId, periodKey) || null;
  }

  authorizationSyslogUsage(authorization, {
    periodStartAt, periodEndAt, resetAt = 0, baselineDownloadBytes = 0, baselineUploadBytes = 0
  }) {
    const subscriberId = `${authorization.method}:${authorization.identity}`.slice(0, 128);
    const startedAt = Math.max(Number(authorization.created_at || 0), Number(periodStartAt || 0));
    const endedBefore = Math.min(
      Number(periodEndAt || Date.now()),
      Number(authorization.expires_at || periodEndAt || Date.now())
    );
    const effectiveResetAt = Math.max(0, Number(resetAt || 0));
    const flowStartedAt = effectiveResetAt ? Math.max(startedAt, effectiveResetAt) : startedAt;
    const flowRow = this.db.prepare(`
      SELECT
        COALESCE(SUM(download_bytes), 0) download_bytes,
        COALESCE(SUM(upload_bytes), 0) upload_bytes,
        COUNT(*) records
      FROM law5651_logs
      WHERE client_ip=?
        AND kind='flow'
        AND started_at >= ?
        AND started_at < ?
        AND (subscriber_id=? OR subscriber_id IS NULL OR subscriber_id='')
    `).get(authorization.client_ip, flowStartedAt, endedBefore, subscriberId);
    const sessionRow = effectiveResetAt
      ? this.db.prepare(`
        SELECT
          COALESCE(MAX(download_bytes), 0) download_bytes,
          COALESCE(MAX(upload_bytes), 0) upload_bytes,
          COUNT(*) records
        FROM law5651_logs
        WHERE client_ip=?
          AND kind='session'
          AND created_at >= ?
          AND created_at < ?
          AND (subscriber_id=? OR subscriber_id IS NULL OR subscriber_id='')
      `).get(authorization.client_ip, effectiveResetAt, endedBefore, subscriberId)
      : this.db.prepare(`
        SELECT
          COALESCE(MAX(download_bytes), 0) download_bytes,
          COALESCE(MAX(upload_bytes), 0) upload_bytes,
          COUNT(*) records
        FROM law5651_logs
        WHERE client_ip=?
          AND kind='session'
          AND started_at >= ?
          AND started_at < ?
          AND (subscriber_id=? OR subscriber_id IS NULL OR subscriber_id='')
      `).get(authorization.client_ip, startedAt, endedBefore, subscriberId);
    const flowRecords = Number(flowRow?.records || 0);
    const flowDownloadBytes = Number(flowRow?.download_bytes || 0);
    const flowUploadBytes = Number(flowRow?.upload_bytes || 0);
    const sessionDownloadBytes = Math.max(
      0,
      Number(sessionRow?.download_bytes || 0) - (effectiveResetAt ? Math.max(0, Number(baselineDownloadBytes || 0)) : 0)
    );
    const sessionUploadBytes = Math.max(
      0,
      Number(sessionRow?.upload_bytes || 0) - (effectiveResetAt ? Math.max(0, Number(baselineUploadBytes || 0)) : 0)
    );
    return {
      downloadBytes: flowRecords ? flowDownloadBytes : sessionDownloadBytes,
      uploadBytes: flowRecords ? flowUploadBytes : sessionUploadBytes,
      flowDownloadBytes,
      flowUploadBytes,
      sessionDownloadBytes,
      sessionUploadBytes,
      flowRecords,
      sessionRecords: Number(sessionRow?.records || 0)
    };
  }

  repairAuthorizationQuotaResetBaselines({ now = Date.now() } = {}) {
    const version = 'v1';
    if (this.getRuntimeState('authorization_quota_reset_baselines_repaired')?.value === version) return 0;
    const rows = this.db.prepare(`
      SELECT usage.authorization_id,
        usage.period_key,
        usage.period_start_at,
        usage.period_end_at,
        usage.reset_at,
        authorization.id,
        authorization.method,
        authorization.identity,
        authorization.client_ip,
        authorization.created_at,
        authorization.expires_at,
        authorization.download_bytes,
        authorization.upload_bytes
      FROM authorization_quota_usage AS usage
      JOIN authorizations AS authorization ON authorization.id=usage.authorization_id
      WHERE usage.reset_at IS NOT NULL
        AND usage.reset_at > authorization.created_at + 60000
        AND usage.authorization_download_bytes_at_reset=0
        AND usage.authorization_upload_bytes_at_reset=0
    `).all();
    let repaired = 0;
    for (const row of rows) {
      const resetAt = Number(row.reset_at || 0);
      const usage = this.authorizationSyslogUsage(row, {
        periodStartAt: row.period_start_at,
        periodEndAt: Math.min(Number(row.period_end_at || resetAt), resetAt)
      });
      const baselineDownload = Math.max(
        Number(row.download_bytes || 0),
        Number(usage.sessionDownloadBytes || 0),
        Number(usage.downloadBytes || 0)
      );
      const baselineUpload = Math.max(
        Number(row.upload_bytes || 0),
        Number(usage.sessionUploadBytes || 0),
        Number(usage.uploadBytes || 0)
      );
      if (!baselineDownload && !baselineUpload) continue;
      this.db.prepare(`
        UPDATE authorization_quota_usage
        SET authorization_download_bytes_at_reset=?,
          authorization_upload_bytes_at_reset=?
        WHERE authorization_id=? AND period_key=?
      `).run(
        Math.trunc(baselineDownload),
        Math.trunc(baselineUpload),
        row.authorization_id,
        row.period_key
      );
      repaired += 1;
    }
    this.setRuntimeState('authorization_quota_reset_baselines_repaired', version, now);
    this.setRuntimeState('authorization_quota_reset_baselines_repaired_count', String(repaired), now);
    return repaired;
  }

  resetAuthorizationQuotaUsage(authorization, period, {
    downloadBytes = 0, uploadBytes = 0, resetAt = Date.now(),
    authorizationDownloadBytes = 0, authorizationUploadBytes = 0
  } = {}) {
    const authorizationId = authorization?.id || '';
    const periodKey = period?.key || '';
    if (!authorizationId || !periodKey) return null;
    const baselineDownload = Math.max(0, Math.trunc(Number(downloadBytes || 0)));
    const baselineUpload = Math.max(0, Math.trunc(Number(uploadBytes || 0)));
    const authorizationDownloadAtReset = Math.max(0, Math.trunc(Number(authorizationDownloadBytes || 0)));
    const authorizationUploadAtReset = Math.max(0, Math.trunc(Number(authorizationUploadBytes || 0)));
    const now = Math.trunc(Number(resetAt || Date.now()));
    const existing = this.getAuthorizationQuotaUsage(authorizationId, periodKey);
    if (existing) {
      this.db.prepare(`
        UPDATE authorization_quota_usage
        SET period_start_at=?,
          period_end_at=?,
          download_bytes=0,
          upload_bytes=0,
          last_gateway_download_bytes=?,
          last_gateway_upload_bytes=?,
          authorization_download_bytes_at_reset=?,
          authorization_upload_bytes_at_reset=?,
          reset_at=?,
          updated_at=?
        WHERE authorization_id=? AND period_key=?
      `).run(
        Math.trunc(Number(period.startAt)),
        Math.trunc(Number(period.endAt)),
        baselineDownload,
        baselineUpload,
        authorizationDownloadAtReset,
        authorizationUploadAtReset,
        now,
        now,
        authorizationId,
        periodKey
      );
    } else {
      this.db.prepare(`
        INSERT INTO authorization_quota_usage
          (authorization_id, period_key, period_start_at, period_end_at,
           download_bytes, upload_bytes, last_gateway_download_bytes,
           last_gateway_upload_bytes, authorization_download_bytes_at_reset,
           authorization_upload_bytes_at_reset, reset_at, updated_at)
        VALUES (?, ?, ?, ?, 0, 0, ?, ?, ?, ?, ?, ?)
      `).run(
        authorizationId,
        periodKey,
        Math.trunc(Number(period.startAt)),
        Math.trunc(Number(period.endAt)),
        baselineDownload,
        baselineUpload,
        authorizationDownloadAtReset,
        authorizationUploadAtReset,
        now,
        now
      );
    }
    return this.getAuthorizationQuotaUsage(authorizationId, periodKey);
  }

  setAuthorizationQuotaBlock(id, {
    periodKey, blockedUntil, exceededAt = Date.now()
  }) {
    return Number(this.db.prepare(`
      UPDATE authorizations
      SET quota_blocked_until=?,
        quota_period_key=?,
        quota_exceeded_at=?,
        gateway_session_id=NULL,
        gateway_response_json=NULL,
        last_seen_at=?
      WHERE id=? AND status='active' AND ended_at IS NULL
    `).run(
      Math.trunc(Number(blockedUntil || 0)),
      periodKey || null,
      Math.trunc(Number(exceededAt || Date.now())),
      Math.trunc(Number(exceededAt || Date.now())),
      id
    ).changes) === 1;
  }

  clearExpiredAuthorizationQuotaBlocks(now = Date.now()) {
    return Number(this.db.prepare(`
      UPDATE authorizations
      SET quota_blocked_until=NULL,
        quota_period_key=NULL,
        quota_exceeded_at=NULL
      WHERE quota_blocked_until IS NOT NULL AND quota_blocked_until <= ?
    `).run(Math.trunc(Number(now))).changes);
  }

  clearAuthorizationQuotaBlock(id, now = Date.now()) {
    return Number(this.db.prepare(`
      UPDATE authorizations
      SET quota_blocked_until=NULL,
        quota_period_key=NULL,
        quota_exceeded_at=NULL,
        last_seen_at=?
      WHERE id=? AND status='active' AND ended_at IS NULL
    `).run(Math.trunc(Number(now)), id).changes) === 1;
  }

  moveAuthorizationGatewaySession(id, {
    clientIp, clientMac = '', clearClientMac = false, gatewaySessionId = '',
    gatewayResponse = null, lastSeenAt = Date.now()
  }) {
    return Number(this.db.prepare(`
      UPDATE authorizations SET
        client_ip=?,
        client_mac=CASE WHEN ? THEN NULL ELSE COALESCE(NULLIF(?, ''), client_mac) END,
        gateway_session_id=COALESCE(NULLIF(?, ''), gateway_session_id),
        gateway_response_json=COALESCE(?, gateway_response_json),
        last_seen_at=?
      WHERE id=? AND status='active' AND ended_at IS NULL
    `).run(clientIp, clearClientMac ? 1 : 0, clientMac, gatewaySessionId,
      gatewayResponse == null ? null : JSON.stringify(gatewayResponse),
      integerTimestamp(lastSeenAt), id).changes) === 1;
  }

  clearAuthorizationGatewaySession(id, { lastSeenAt = Date.now() } = {}) {
    return Number(this.db.prepare(`
      UPDATE authorizations SET
        gateway_session_id=NULL,
        gateway_response_json=NULL,
        last_seen_at=?
      WHERE id=? AND status='active' AND ended_at IS NULL
    `).run(integerTimestamp(lastSeenAt), id).changes) === 1;
  }

  findAuthorizationForGateway({ sessionId = '', clientIp = '', userName = '' }) {
    if (sessionId) {
      const row = this.db.prepare(`
        SELECT * FROM authorizations WHERE gateway_session_id=?
        ORDER BY created_at DESC LIMIT 1
      `).get(sessionId);
      if (row) return row;
    }
    if (clientIp) {
      const row = this.db.prepare(`
        SELECT * FROM authorizations
        WHERE client_ip=? AND status='active' AND ended_at IS NULL
        ORDER BY created_at DESC LIMIT 1
      `).get(clientIp);
      if (row) return row;
    }
    if (userName) {
      return this.db.prepare(`
        SELECT * FROM authorizations
        WHERE (? = method || ':' || identity) AND status='active' AND ended_at IS NULL
        ORDER BY created_at DESC LIMIT 1
      `).get(userName) || null;
    }
    return null;
  }

  hasEarlierAuthorizationForGatewaySession(authorization) {
    const sessionId = authorization?.gateway_session_id || '';
    if (!authorization?.id || !sessionId) return false;
    const row = this.db.prepare(`
      SELECT 1
      FROM authorizations
      WHERE id != ?
        AND gateway_session_id=?
        AND created_at < ?
      LIMIT 1
    `).get(authorization.id, sessionId, Number(authorization.created_at || 0));
    return Boolean(row);
  }

  endAuthorization(id, reason = 'admin_disconnect') {
    return Number(this.db.prepare(`
      UPDATE authorizations SET ended_at=?, disconnect_reason=? WHERE id=? AND ended_at IS NULL
    `).run(Date.now(), reason, id).changes) === 1;
  }

  markAuthorizationKeaDeleted(id, deletedAt = Date.now()) {
    return Number(this.db.prepare(`
      UPDATE authorizations SET kea_deleted_at=COALESCE(kea_deleted_at, ?) WHERE id=?
    `).run(deletedAt, id).changes) === 1;
  }

  markAuthorizationKeaSynced(id) {
    return Number(this.db.prepare(`
      UPDATE authorizations SET kea_deleted_at=NULL WHERE id=?
    `).run(id).changes) === 1;
  }

  activeClientIdentityForLaw5651(clientIp, at = Date.now()) {
    if (!clientIp) return null;
    const timestamp = Math.trunc(Number(at) || Date.now());
    return this.db.prepare(`
      SELECT method, identity, client_mac
      FROM authorizations
      WHERE client_ip=?
        AND status='active'
        AND ended_at IS NULL
        AND created_at <= ?
        AND expires_at > ?
        AND client_mac IS NOT NULL
        AND client_mac != ''
      ORDER BY created_at DESC LIMIT 1
    `).get(clientIp, timestamp, timestamp) || null;
  }

  appendLaw5651Logs(records = []) {
    if (!records.length) return { inserted: 0, skipped: 0, lastHash: this.latestLaw5651Hash() };
    let inserted = 0;
    let skipped = 0;
    let lastHash = this.latestLaw5651Hash();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const input of records) {
        if (!input?.dedupeKey || !input.clientIp || !input.sourceIp || !input.startedAt) {
          skipped += 1;
          continue;
        }
        const exists = this.db.prepare('SELECT 1 FROM law5651_logs WHERE dedupe_key=?')
          .get(input.dedupeKey);
        if (exists) {
          skipped += 1;
          continue;
        }
        const startedAt = Math.trunc(Number(input.startedAt));
        const createdAt = Math.trunc(Number(input.createdAt) || Date.now());
        let clientMac = normalizeMac(input.clientMac);
        let subscriberId = input.subscriberId || '';
        if (!clientMac) {
          const identity = this.activeClientIdentityForLaw5651(input.clientIp, startedAt || createdAt);
          clientMac = normalizeMac(identity?.client_mac);
          if (!subscriberId && identity) subscriberId = `${identity.method}:${identity.identity}`;
        }
        const previousHash = lastHash || '0'.repeat(64);
        const record = {
          kind: input.kind || 'session',
          source: input.source || 'opnsense',
          network: input.network || '',
          clientIp: input.clientIp,
          clientMac,
          subscriberId,
          sourceIp: input.sourceIp,
          sourcePort: input.sourcePort || '',
          destinationIp: input.destinationIp || '',
          destinationPort: input.destinationPort || '',
          protocol: input.protocol || '',
          serviceType: input.serviceType || 'internet-access',
          startedAt,
          endedAt: input.endedAt ? Math.trunc(Number(input.endedAt)) : null,
          downloadBytes: Math.max(0, Math.trunc(Number(input.downloadBytes) || 0)),
          uploadBytes: Math.max(0, Math.trunc(Number(input.uploadBytes) || 0)),
          rawJson: input.rawJson || '',
          createdAt
        };
        const recordHash = sha256Hex(law5651HashPayload(record, previousHash));
        this.db.prepare(`
          INSERT INTO law5651_logs
            (id, dedupe_key, kind, source, network, client_ip, client_mac, subscriber_id,
             source_ip, source_port, destination_ip, destination_port, protocol, service_type,
             started_at, ended_at, download_bytes, upload_bytes, raw_json, previous_hash,
             record_hash, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          randomUUID(),
          input.dedupeKey,
          record.kind,
          record.source,
          record.network || null,
          record.clientIp,
          record.clientMac || null,
          record.subscriberId || null,
          record.sourceIp,
          record.sourcePort || null,
          record.destinationIp || null,
          record.destinationPort || null,
          record.protocol || null,
          record.serviceType,
          record.startedAt,
          record.endedAt,
          record.downloadBytes,
          record.uploadBytes,
          record.rawJson || null,
          previousHash,
          recordHash,
          record.createdAt
        );
        lastHash = recordHash;
        inserted += 1;
      }
      this.db.exec('COMMIT');
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch {}
      throw error;
    }
    return { inserted, skipped, lastHash };
  }

  latestLaw5651Hash() {
    return this.db.prepare(`
      SELECT record_hash FROM law5651_logs ORDER BY sequence DESC LIMIT 1
    `).get()?.record_hash || '';
  }

  latestLaw5651EventHash() {
    return this.db.prepare(`
      SELECT event_hash FROM law5651_events ORDER BY rowid DESC LIMIT 1
    `).get()?.event_hash || '';
  }

  recordLaw5651Event({
    eventType,
    severity = 'info',
    message = '',
    detail = null,
    createdAt = Date.now()
  }) {
    const cleanEventType = String(eventType || '').trim();
    if (!cleanEventType) throw new Error('Syslog event type is required');
    const cleanSeverity = ['info', 'warning', 'error', 'critical'].includes(severity) ? severity : 'info';
    const detailJson = detail == null ? '' : JSON.stringify(detail);
    const event = {
      eventType: cleanEventType,
      severity: cleanSeverity,
      message: String(message || cleanEventType),
      detailJson,
      createdAt: Math.trunc(Number(createdAt) || Date.now())
    };
    const previousHash = this.latestLaw5651EventHash() || '0'.repeat(64);
    const eventHash = sha256Hex(law5651EventHashPayload(event, previousHash));
    const id = randomUUID();
    this.db.prepare(`
      INSERT INTO law5651_events
        (id, event_type, severity, message, detail_json, previous_hash, event_hash, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      event.eventType,
      event.severity,
      event.message,
      event.detailJson || null,
      previousHash,
      eventHash,
      event.createdAt
    );
    return this.db.prepare('SELECT * FROM law5651_events WHERE id=?').get(id);
  }

  listLaw5651Events({
    limit = 1000,
    offset = 0,
    order = 'desc',
    createdFrom = null,
    createdBefore = null,
    severity = ''
  } = {}) {
    const where = [];
    const params = [];
    if (createdFrom != null) {
      where.push('created_at >= ?');
      params.push(Math.trunc(Number(createdFrom)));
    }
    if (createdBefore != null) {
      where.push('created_at < ?');
      params.push(Math.trunc(Number(createdBefore)));
    }
    if (severity) {
      where.push('severity=?');
      params.push(severity);
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const direction = order === 'asc' ? 'ASC' : 'DESC';
    const total = this.db.prepare(`SELECT COUNT(*) count FROM law5651_events ${clause}`)
      .get(...params);
    const rows = this.db.prepare(`
      SELECT * FROM law5651_events ${clause}
      ORDER BY created_at ${direction}, id ${direction} LIMIT ? OFFSET ?
    `).all(...params, Math.max(1, Math.trunc(Number(limit) || 1000)), Math.max(0, Math.trunc(Number(offset) || 0)));
    return { rows, total: Number(total.count) };
  }

  recordLaw5651Backup({
    exportId,
    targetDirectory,
    status,
    error = '',
    fileCount = 0,
    totalBytes = 0,
    createdAt = Date.now()
  }) {
    const id = randomUUID();
    this.db.prepare(`
      INSERT INTO law5651_backups
        (id, export_id, target_directory, status, error, file_count, total_bytes, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      exportId,
      targetDirectory,
      status === 'succeeded' ? 'succeeded' : 'failed',
      error || null,
      Math.max(0, Math.trunc(Number(fileCount) || 0)),
      Math.max(0, Math.trunc(Number(totalBytes) || 0)),
      Math.trunc(Number(createdAt) || Date.now())
    );
    return this.db.prepare('SELECT * FROM law5651_backups WHERE id=?').get(id);
  }

  listLaw5651Backups({ limit = 20, exportId = '' } = {}) {
    if (exportId) {
      return this.db.prepare(`
        SELECT * FROM law5651_backups
        WHERE export_id=?
        ORDER BY created_at DESC LIMIT ?
      `).all(exportId, Math.max(1, Math.trunc(Number(limit) || 20)));
    }
    return this.db.prepare(`
      SELECT * FROM law5651_backups
      ORDER BY created_at DESC LIMIT ?
    `).all(Math.max(1, Math.trunc(Number(limit) || 20)));
  }

  updateLaw5651ExportStatus(id, {
    signaturePath = null,
    signatureStatus = null,
    signatureError = null,
    backupStatus = null,
    backupError = null
  } = {}) {
    return Number(this.db.prepare(`
      UPDATE law5651_exports SET
        signature_path=COALESCE(?, signature_path),
        signature_status=COALESCE(?, signature_status),
        signature_error=?,
        backup_status=COALESCE(?, backup_status),
        backup_error=?
      WHERE id=?
    `).run(
      signaturePath,
      signatureStatus,
      signatureError,
      backupStatus,
      backupError,
      id
    ).changes) === 1;
  }

  getLaw5651State(key) {
    return this.db.prepare('SELECT key, value, updated_at FROM law5651_state WHERE key=?')
      .get(key) || null;
  }

  setLaw5651State(key, value, updatedAt = Date.now()) {
    this.db.prepare(`
      INSERT INTO law5651_state(key, value, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
    `).run(key, String(value ?? ''), Math.trunc(Number(updatedAt) || Date.now()));
    return this.getLaw5651State(key);
  }

  law5651Summary() {
    const summary = this.db.prepare(`
      SELECT COUNT(*) count, MIN(created_at) first_created_at, MAX(created_at) last_created_at,
        COALESCE(SUM(download_bytes), 0) download_bytes,
        COALESCE(SUM(upload_bytes), 0) upload_bytes
      FROM law5651_logs
    `).get();
    const last = this.db.prepare(`
      SELECT sequence, record_hash, created_at FROM law5651_logs ORDER BY sequence DESC LIMIT 1
    `).get() || null;
    const lastExport = this.db.prepare(`
      SELECT * FROM law5651_exports ORDER BY created_at DESC LIMIT 1
    `).get() || null;
    const events = this.db.prepare(`
      SELECT COUNT(*) count,
        SUM(CASE WHEN severity IN ('warning', 'error', 'critical') THEN 1 ELSE 0 END) alert_count
      FROM law5651_events
    `).get();
    const lastEvent = this.db.prepare(`
      SELECT * FROM law5651_events ORDER BY rowid DESC LIMIT 1
    `).get() || null;
    const lastAlert = this.db.prepare(`
      SELECT * FROM law5651_events
      WHERE severity IN ('warning', 'error', 'critical')
      ORDER BY rowid DESC LIMIT 1
    `).get() || null;
    const lastBackup = this.db.prepare(`
      SELECT * FROM law5651_backups ORDER BY created_at DESC LIMIT 1
    `).get() || null;
    return {
      count: Number(summary.count || 0),
      firstCreatedAt: summary.first_created_at == null ? null : Number(summary.first_created_at),
      lastCreatedAt: summary.last_created_at == null ? null : Number(summary.last_created_at),
      downloadBytes: Number(summary.download_bytes || 0),
      uploadBytes: Number(summary.upload_bytes || 0),
      lastSequence: last ? Number(last.sequence) : 0,
      lastHash: last?.record_hash || '',
      lastHashCreatedAt: last ? Number(last.created_at) : null,
      eventCount: Number(events.count || 0),
      alertCount: Number(events.alert_count || 0),
      lastEvent: lastEvent ? {
        id: lastEvent.id,
        eventType: lastEvent.event_type,
        severity: lastEvent.severity,
        message: lastEvent.message,
        eventHash: lastEvent.event_hash,
        createdAt: Number(lastEvent.created_at)
      } : null,
      lastAlert: lastAlert ? {
        id: lastAlert.id,
        eventType: lastAlert.event_type,
        severity: lastAlert.severity,
        message: lastAlert.message,
        eventHash: lastAlert.event_hash,
        createdAt: Number(lastAlert.created_at)
      } : null,
      lastBackup: lastBackup ? {
        id: lastBackup.id,
        exportId: lastBackup.export_id,
        targetDirectory: lastBackup.target_directory,
        status: lastBackup.status,
        error: lastBackup.error || '',
        fileCount: Number(lastBackup.file_count || 0),
        totalBytes: Number(lastBackup.total_bytes || 0),
        createdAt: Number(lastBackup.created_at)
      } : null,
      lastExport: lastExport ? {
        id: lastExport.id,
        exportReason: lastExport.export_reason || 'manual',
        periodStartAt: lastExport.period_start_at == null ? null : Number(lastExport.period_start_at),
        periodEndAt: lastExport.period_end_at == null ? null : Number(lastExport.period_end_at),
        filePath: lastExport.file_path,
        manifestPath: lastExport.manifest_path,
        timestampRequestPath: lastExport.timestamp_request_path || '',
        timestampTokenPath: lastExport.timestamp_token_path || '',
        timestampMode: lastExport.timestamp_mode || 'disabled',
        signaturePath: lastExport.signature_path || '',
        signatureMode: lastExport.signature_mode || 'hmac-sha256',
        recordCount: Number(lastExport.record_count),
        firstSequence: lastExport.first_sequence == null ? null : Number(lastExport.first_sequence),
        lastSequence: lastExport.last_sequence == null ? null : Number(lastExport.last_sequence),
        exportHash: lastExport.export_hash,
        timestampStatus: lastExport.timestamp_status,
        timestampError: lastExport.timestamp_error || '',
        signatureStatus: lastExport.signature_status || 'disabled',
        signatureError: lastExport.signature_error || '',
        backupStatus: lastExport.backup_status || 'disabled',
        backupError: lastExport.backup_error || '',
        createdAt: Number(lastExport.created_at)
      } : null
    };
  }

  listLaw5651Logs({
    search = '',
    limit = 1000,
    offset = 0,
    order = 'desc',
    createdFrom = null,
    createdBefore = null
  } = {}) {
    const where = [];
    const params = [];
    if (search) {
      where.push(`(client_ip LIKE ? OR client_mac LIKE ? OR subscriber_id LIKE ?
        OR source_ip LIKE ? OR destination_ip LIKE ? OR record_hash LIKE ?)`);
      const term = `%${search}%`;
      params.push(term, term, term, term, term, term);
    }
    if (createdFrom != null) {
      where.push('created_at >= ?');
      params.push(Math.trunc(Number(createdFrom)));
    }
    if (createdBefore != null) {
      where.push('created_at < ?');
      params.push(Math.trunc(Number(createdBefore)));
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const direction = order === 'asc' ? 'ASC' : 'DESC';
    const total = this.db.prepare(`SELECT COUNT(*) count FROM law5651_logs ${clause}`)
      .get(...params);
    const rows = this.db.prepare(`
      SELECT * FROM law5651_logs ${clause}
      ORDER BY sequence ${direction} LIMIT ? OFFSET ?
    `).all(...params, limit, offset);
    return { rows, total: Number(total.count) };
  }

  cleanupLaw5651Logs(retentionDays, now = Date.now(), options = {}) {
    return this.cleanupArchivedLaw5651Logs({ retentionDays, now, ...options });
  }

  law5651ExportFileVerified(row) {
    const filePath = row?.file_path || '';
    const expectedHash = row?.export_hash || '';
    if (!filePath || !expectedHash || !fs.existsSync(filePath)) return false;
    try {
      return fileHash(filePath) === expectedHash;
    } catch {
      return false;
    }
  }

  law5651ExportCleanupRange(row, { requireTimestamp = false, requireBackup = false } = {}) {
    const firstSequence = Math.trunc(Number(row?.first_sequence));
    const lastSequence = Math.trunc(Number(row?.last_sequence));
    const recordCount = Math.trunc(Number(row?.record_count) || 0);
    const firstCreatedAt = Math.trunc(Number(row?.first_created_at));
    const lastCreatedAt = Math.trunc(Number(row?.last_created_at));
    if (!recordCount ||
        !Number.isFinite(firstCreatedAt) ||
        !Number.isFinite(lastCreatedAt)) {
      return null;
    }
    if (requireTimestamp && row.timestamp_status !== 'created') return false;
    if (requireBackup && row.backup_status !== 'succeeded') return false;
    if (!this.law5651ExportFileVerified(row)) return false;
    if (Number.isFinite(firstSequence) &&
        Number.isFinite(lastSequence) &&
        firstSequence > 0 &&
        lastSequence >= firstSequence) {
      const current = this.db.prepare(`
        SELECT COUNT(*) count
        FROM law5651_logs
        WHERE sequence BETWEEN ? AND ?
          AND created_at >= ?
          AND created_at <= ?
      `).get(firstSequence, lastSequence, firstCreatedAt, lastCreatedAt);
      if (Number(current?.count || 0) > recordCount) return null;
      return { firstSequence, lastSequence, firstCreatedAt, lastCreatedAt };
    }
    const current = this.db.prepare(`
      SELECT COUNT(*) count, MIN(sequence) first_sequence, MAX(sequence) last_sequence
      FROM law5651_logs
      WHERE created_at >= ?
        AND created_at <= ?
    `).get(firstCreatedAt, lastCreatedAt);
    const currentCount = Number(current?.count || 0);
    if (!currentCount || currentCount > recordCount) return null;
    const derivedFirstSequence = Math.trunc(Number(current.first_sequence));
    const derivedLastSequence = Math.trunc(Number(current.last_sequence));
    if (!Number.isFinite(derivedFirstSequence) ||
        !Number.isFinite(derivedLastSequence) ||
        derivedFirstSequence <= 0 ||
        derivedLastSequence < derivedFirstSequence) {
      return null;
    }
    return {
      firstSequence: derivedFirstSequence,
      lastSequence: derivedLastSequence,
      firstCreatedAt,
      lastCreatedAt,
      derivedSequence: true
    };
  }

  law5651ExportCleanupSafe(row, options = {}) {
    return Boolean(this.law5651ExportCleanupRange(row, options));
  }

  cleanupArchivedLaw5651Logs({
    retentionDays,
    now = Date.now(),
    requireTimestamp = false,
    requireBackup = false,
    reasons = ['auto', 'kamusm', 'manual']
  } = {}) {
    const days = Math.max(1, Math.trunc(Number(retentionDays) || 730));
    const cutoff = Math.trunc(Number(now) || Date.now()) - days * 24 * 60 * 60 * 1000;
    const allowedReasons = [...new Set(reasons.map(reason => String(reason || '').trim()).filter(Boolean))];
    if (!allowedReasons.length) return 0;
    const placeholders = allowedReasons.map(() => '?').join(', ');
    const exports = this.db.prepare(`
      SELECT *
      FROM law5651_exports
      WHERE export_reason IN (${placeholders})
        AND record_count > 0
        AND first_created_at IS NOT NULL
        AND last_created_at IS NOT NULL
        AND last_created_at < ?
      ORDER BY first_created_at ASC, last_created_at ASC, created_at ASC
    `).all(...allowedReasons, cutoff);
    let deleted = 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const row of exports) {
        const range = this.law5651ExportCleanupRange(row, { requireTimestamp, requireBackup });
        if (!range) continue;
        if (range.derivedSequence) {
          this.db.prepare(`
            UPDATE law5651_exports
            SET first_sequence=?, last_sequence=?
            WHERE id=?
          `).run(range.firstSequence, range.lastSequence, row.id);
        }
        const result = this.db.prepare(`
          DELETE FROM law5651_logs
          WHERE sequence BETWEEN ? AND ?
            AND created_at >= ?
            AND created_at <= ?
            AND created_at < ?
        `).run(
          range.firstSequence,
          range.lastSequence,
          range.firstCreatedAt,
          range.lastCreatedAt,
          cutoff
        );
        deleted += Number(result.changes || 0);
      }
      this.db.exec('COMMIT');
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch {}
      throw error;
    }
    return deleted;
  }

  createLaw5651Export({
    exportReason = 'manual',
    periodStartAt = null,
    periodEndAt = null,
    filePath,
    manifestPath,
    timestampRequestPath = '',
    timestampTokenPath = '',
    timestampMode = 'disabled',
    recordCount,
    firstSequence = null,
    lastSequence = null,
    firstCreatedAt = null,
    lastCreatedAt = null,
    previousExportHash = '',
    exportHash,
    timestampStatus = 'disabled',
    timestampError = '',
    signaturePath = '',
    signatureMode = 'hmac-sha256',
    signatureStatus = 'disabled',
    signatureError = '',
    backupStatus = 'disabled',
    backupError = ''
  }) {
    const id = randomUUID();
    this.db.prepare(`
      INSERT INTO law5651_exports
        (id, export_reason, period_start_at, period_end_at,
         file_path, manifest_path, timestamp_request_path, timestamp_token_path,
         timestamp_mode, signature_path, signature_mode, record_count,
         first_sequence, last_sequence, first_created_at, last_created_at,
         previous_export_hash, export_hash,
         timestamp_status, timestamp_error, signature_status, signature_error,
         backup_status, backup_error, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      exportReason || 'manual',
      periodStartAt == null ? null : Math.trunc(Number(periodStartAt)),
      periodEndAt == null ? null : Math.trunc(Number(periodEndAt)),
      filePath,
      manifestPath,
      timestampRequestPath || null,
      timestampTokenPath || null,
      timestampMode || 'disabled',
      signaturePath || null,
      signatureMode || 'hmac-sha256',
      Math.max(0, Math.trunc(Number(recordCount) || 0)),
      firstSequence == null ? null : Math.trunc(Number(firstSequence)),
      lastSequence == null ? null : Math.trunc(Number(lastSequence)),
      firstCreatedAt == null ? null : Math.trunc(Number(firstCreatedAt)),
      lastCreatedAt == null ? null : Math.trunc(Number(lastCreatedAt)),
      previousExportHash || '',
      exportHash,
      timestampStatus,
      timestampError || null,
      signatureStatus || 'disabled',
      signatureError || null,
      backupStatus || 'disabled',
      backupError || null,
      Date.now()
    );
    return this.db.prepare('SELECT * FROM law5651_exports WHERE id=?').get(id);
  }

  latestLaw5651Export({ reason = '' } = {}) {
    if (reason) {
      return this.db.prepare(`
        SELECT * FROM law5651_exports
        WHERE export_reason=?
        ORDER BY COALESCE(period_end_at, created_at) DESC, created_at DESC
        LIMIT 1
      `).get(reason) || null;
    }
    return this.db.prepare(`
      SELECT * FROM law5651_exports ORDER BY created_at DESC LIMIT 1
    `).get() || null;
  }

  listLaw5651Exports({ reasons = [], limit = 100, order = 'desc' } = {}) {
    const direction = order === 'asc' ? 'ASC' : 'DESC';
    const safeLimit = Math.max(1, Math.min(1000, Math.trunc(Number(limit) || 100)));
    const values = Array.isArray(reasons)
      ? reasons.map(reason => String(reason || '').trim()).filter(Boolean)
      : [];
    if (values.length) {
      const placeholders = values.map(() => '?').join(', ');
      return this.db.prepare(`
        SELECT *
        FROM law5651_exports
        WHERE export_reason IN (${placeholders})
        ORDER BY COALESCE(period_end_at, created_at) ${direction}, created_at ${direction}
        LIMIT ?
      `).all(...values, safeLimit);
    }
    return this.db.prepare(`
      SELECT *
      FROM law5651_exports
      ORDER BY COALESCE(period_end_at, created_at) ${direction}, created_at ${direction}
      LIMIT ?
    `).all(safeLimit);
  }

  findLaw5651ExportByPeriod({ reason = 'auto', periodStartAt, periodEndAt }) {
    return this.db.prepare(`
      SELECT * FROM law5651_exports
      WHERE export_reason=? AND period_start_at=? AND period_end_at=?
      ORDER BY created_at DESC
      LIMIT 1
    `).get(
      reason,
      Math.trunc(Number(periodStartAt)),
      Math.trunc(Number(periodEndAt))
    ) || null;
  }

  activeClientIdentityForSyslog(clientIp, at = Date.now()) {
    return this.activeClientIdentityForLaw5651(clientIp, at);
  }

  appendSyslogLogs(records = []) {
    return this.appendLaw5651Logs(records);
  }

  latestSyslogHash() {
    return this.latestLaw5651Hash();
  }

  latestSyslogEventHash() {
    return this.latestLaw5651EventHash();
  }

  recordSyslogEvent(options) {
    return this.recordLaw5651Event(options);
  }

  listSyslogEvents(options = {}) {
    return this.listLaw5651Events(options);
  }

  recordSyslogBackup(options) {
    return this.recordLaw5651Backup(options);
  }

  listSyslogBackups(options = {}) {
    return this.listLaw5651Backups(options);
  }

  updateSyslogExportStatus(id, options = {}) {
    return this.updateLaw5651ExportStatus(id, options);
  }

  getSyslogState(key) {
    return this.getLaw5651State(key);
  }

  setSyslogState(key, value, updatedAt = Date.now()) {
    return this.setLaw5651State(key, value, updatedAt);
  }

  syslogSummary() {
    return this.law5651Summary();
  }

  listSyslogLogs(options = {}) {
    return this.listLaw5651Logs(options);
  }

  cleanupSyslogLogs(retentionDays, now = Date.now(), options = {}) {
    return this.cleanupLaw5651Logs(retentionDays, now, options);
  }

  createSyslogExport(options) {
    return this.createLaw5651Export(options);
  }

  latestSyslogExport(options = {}) {
    return this.latestLaw5651Export(options);
  }

  findSyslogExportByPeriod(options) {
    return this.findLaw5651ExportByPeriod(options);
  }
}
