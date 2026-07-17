import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import dgram from 'node:dgram';
import { promisify } from 'node:util';
import { gzipSync } from 'node:zlib';
import { performance } from 'node:perf_hooks';
import { ipv4InNetworkList } from '../lib/network.js';
import { normalizeMac } from '../lib/security.js';
import {
  appendTrafficLogFileRecords,
  cleanupTrafficLogFile,
  enrichTrafficLogRecords,
  trafficLogSettings
} from './trafficLogs.js';
import { createZipArchive } from './opnsenseTemplate.js';

const execFileAsync = promisify(execFile);
const AUTO_EXPORT_CHECK_MS = 60 * 1000;
const AUTO_EXPORT_GRACE_MS = 5 * 1000;
const MAX_AUTO_EXPORT_CATCHUP_WINDOWS = 100;
const TRAFFIC_LOG_FILE_CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const AUTO_EXPORT_REASONS = ['auto', 'kamusm', 'timestamp'];
const TIMESTAMP_MODES = new Set(['disabled', 'kamusm', 'rfc3161', 'api-key', 'command']);
const TIMESTAMP_PROVIDER_ATTEMPT_STATUSES = new Set(['created', 'failed', 'missing-token']);
const TIMESTAMP_EVIDENCE_GAP_STATUS = 'evidence-gap';
const TIMESTAMP_DISABLED_SINCE_STATE = 'timestamp_disabled_since_at';
const TIMESTAMP_DISABLED_INTERVALS_STATE = 'timestamp_disabled_intervals_json';
const TIMESTAMP_ENABLED_SINCE_STATE = 'timestamp_enabled_since_at';
const TIMESTAMP_DISABLED_INTERVAL_LIMIT = 200;
const AUTO_EXPORT_INTERVAL_MINUTES = {
  '1h': 60,
  '6h': 6 * 60,
  '12h': 12 * 60,
  '24h': 24 * 60,
  daily: 24 * 60
};
const CLIENT_IDENTITY_CACHE_MS = 30 * 1000;
const EXPORT_PAGE_SIZE = 10000;
const STORAGE_NOTIFICATION_INTERVALS = {
  hourly: 60 * 60 * 1000,
  daily: 24 * 60 * 60 * 1000,
  monthly: 30 * 24 * 60 * 60 * 1000
};
const STORAGE_NOTIFICATION_CHANNELS = ['email', 'sms', 'telegram', 'android'];
const NTP_STATUS_HINT =
  'Install timedatectl with systemd/DBus support, or set SYSLOG_NTP_CHECK_ENABLED=false to hide this check.';
let syslogNonce = 0;

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fileHash(filePath) {
  return createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function fileSize(filePath) {
  return fs.statSync(filePath).size;
}

function configFlag(value) {
  if (typeof value === 'boolean') return value;
  return ['1', 'true', 'yes', 'on'].includes(String(value ?? '').trim().toLowerCase());
}

function exportZipPath(logPath) {
  return String(logPath).endsWith('.log')
    ? `${String(logPath).slice(0, -4)}.zip`
    : `${logPath}.zip`;
}

function retentionDaysValue(value) {
  return Math.max(1, Math.min(1000, Math.trunc(Number(value) || 730)));
}

function exportRetentionCutoff(retentionDays, now = Date.now()) {
  return Math.trunc(Number(now) || Date.now()) - retentionDaysValue(retentionDays) * 24 * 60 * 60 * 1000;
}

function pathInsideDirectory(filePath, directory) {
  const resolvedFile = path.resolve(String(filePath || ''));
  const resolvedDirectory = path.resolve(String(directory || ''));
  const relative = path.relative(resolvedDirectory, resolvedFile);
  return Boolean(relative) && !relative.startsWith('..') && !path.isAbsolute(relative);
}

function timestampSidecarPaths(logPath) {
  return [`${logPath}.tsq`, `${logPath}.tsr`];
}

function logPathFromArchivePath(filePath) {
  const text = String(filePath || '');
  return text.endsWith('.zip') ? `${text.slice(0, -4)}.log` : text;
}

function exportArtifactPaths(row = {}) {
  const paths = new Set();
  const add = value => {
    const text = String(value || '').trim();
    if (text) paths.add(text);
  };
  add(row.file_path);
  add(row.manifest_path);
  add(row.timestamp_request_path);
  add(row.timestamp_token_path);
  add(row.signature_path);

  const primary = String(row.file_path || '');
  const logPath = logPathFromArchivePath(primary);
  if (logPath) {
    add(logPath);
    add(exportZipPath(logPath));
    for (const sidecar of timestampSidecarPaths(logPath)) add(sidecar);
  }
  return [...paths];
}

function retentionFileExtensions(lawConfig = {}) {
  const extensions = configFlag(lawConfig.exportZipEnabled)
    ? ['.zip', '.log', '.tsq', '.tsr']
    : ['.log', '.tsq', '.tsr'];
  return new Set(extensions);
}

function removeExportRetentionFile(filePath, exportDirectory, totals, logger = console) {
  try {
    if (!pathInsideDirectory(filePath, exportDirectory) || !fs.existsSync(filePath)) return false;
    const stats = fs.statSync(filePath);
    if (!stats.isFile()) return false;
    fs.rmSync(filePath, { force: true });
    totals.deletedFiles += 1;
    totals.deletedBytes += Number(stats.size || 0);
    totals.deletedPaths.push(filePath);
    return true;
  } catch (error) {
    totals.errors.push({ filePath, error: error.message });
    logger.warn?.(`Expired syslog export file could not be removed: ${filePath}: ${error.message}`);
    return false;
  }
}

function createExportZipArtifact(lawConfig, files = []) {
  if (!configFlag(lawConfig.exportZipEnabled)) {
    return {
      filePath: '',
      entries: [],
      sourceFiles: [],
      sourceFilesDeleted: false
    };
  }
  const sourceFiles = [...new Set(files.filter(Boolean))]
    .filter(filePath => fs.existsSync(filePath));
  if (!sourceFiles.length) {
    return {
      filePath: '',
      entries: [],
      sourceFiles: [],
      sourceFilesDeleted: false
    };
  }
  const logPath = sourceFiles[0];
  const archivePath = exportZipPath(logPath);
  const entries = sourceFiles.map(filePath => ({
    name: path.basename(filePath),
    data: fs.readFileSync(filePath)
  }));
  fs.writeFileSync(archivePath, createZipArchive(entries), { mode: 0o600 });
  if (configFlag(lawConfig.exportDeleteSourceAfterZip)) {
    for (const filePath of sourceFiles) {
      fs.rmSync(filePath, { force: true });
    }
  }
  return {
    filePath: archivePath,
    entries: entries.map(entry => entry.name),
    sourceFiles,
    sourceFilesDeleted: configFlag(lawConfig.exportDeleteSourceAfterZip)
  };
}

function hmacSha256Hex(key, value) {
  return createHmac('sha256', key).update(value).digest('hex');
}

function derLength(length) {
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag, body) {
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

function derSequence(...items) {
  return der(0x30, Buffer.concat(items));
}

function derInteger(value) {
  let body;
  if (typeof value === 'number') {
    const bytes = [];
    let current = Math.max(0, Math.trunc(value));
    do {
      bytes.unshift(current & 0xff);
      current >>= 8;
    } while (current > 0);
    body = Buffer.from(bytes);
  } else {
    body = Buffer.from(value);
  }
  while (body.length > 1 && body[0] === 0 && (body[1] & 0x80) === 0) body = body.subarray(1);
  if (body[0] & 0x80) body = Buffer.concat([Buffer.from([0]), body]);
  return der(0x02, body);
}

function derBoolean(value) {
  return der(0x01, Buffer.from([value ? 0xff : 0x00]));
}

function derOctetString(value) {
  return der(0x04, Buffer.from(value));
}

function derNull() {
  return der(0x05, Buffer.alloc(0));
}

function derOidSha256() {
  return der(0x06, Buffer.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]));
}

function rfc3161TimestampQuery(messageDigest, { certReq = true } = {}) {
  const algorithmIdentifier = derSequence(derOidSha256(), derNull());
  const messageImprint = derSequence(algorithmIdentifier, derOctetString(messageDigest));
  return derSequence(
    derInteger(1),
    messageImprint,
    derInteger(randomBytes(16)),
    derBoolean(certReq)
  );
}

function writeGzipFile(filePath, content) {
  fs.writeFileSync(filePath, gzipSync(Buffer.from(content, 'utf8')), { mode: 0o600 });
}

function safeRecordEvent(db, event, logger = console) {
  try {
    if (typeof db.recordLaw5651Event === 'function') return db.recordLaw5651Event(event);
    if (typeof db.recordSyslogEvent === 'function') return db.recordSyslogEvent(event);
  } catch (error) {
    logger.warn?.(`Syslog event could not be recorded: ${error.message}`);
  }
  return null;
}

function backupDirectories(lawConfig) {
  if (Array.isArray(lawConfig.backupDirectories)) return lawConfig.backupDirectories.filter(Boolean);
  return String(lawConfig.backupDirectories || lawConfig.backupDirs || '')
    .split(/[\n;,]+/u)
    .map(item => item.trim())
    .filter(Boolean);
}

function currentSystemTimeZone() {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
}

function readBootId() {
  try {
    return fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
  } catch {
    return '';
  }
}

function normalizeStoragePercent(value, fallback) {
  const percent = Number(value);
  if (!Number.isFinite(percent)) return fallback;
  return Math.max(1, Math.min(100, Math.trunc(percent)));
}

function storageDirectory(config) {
  return config.law5651.exportDirectory || path.dirname(config.databasePath || process.cwd());
}

export function law5651StorageStatus(config) {
  const lawConfig = config.law5651 || config.syslog || {};
  const directory = storageDirectory({ ...config, law5651: lawConfig });
  try {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (typeof fs.statfsSync !== 'function') {
      return {
        available: false,
        directory,
        error: 'Filesystem usage is not available on this Node.js runtime.'
      };
    }
    const stats = fs.statfsSync(directory);
    const blockSize = Number(stats.bsize || stats.frsize || 0);
    const totalBytes = Number(stats.blocks || 0) * blockSize;
    const freeBytes = Number(stats.bavail ?? stats.bfree ?? 0) * blockSize;
    const usedBytes = Math.max(0, totalBytes - freeBytes);
    const usagePercent = totalBytes > 0 ? Math.round((usedBytes / totalBytes) * 10000) / 100 : 0;
    const alertPercent = normalizeStoragePercent(lawConfig.storageAlertPercent, 85);
    const blockPercent = normalizeStoragePercent(lawConfig.storageBlockPercent, 99);
    return {
      available: true,
      directory,
      totalBytes,
      freeBytes,
      usedBytes,
      usagePercent,
      alertPercent,
      blockPercent,
      warning: usagePercent >= alertPercent,
      blocking: usagePercent >= blockPercent
    };
  } catch (error) {
    return {
      available: false,
      directory,
      error: error.message
    };
  }
}

export function assertLaw5651PortalWritable({ db, config, context = {} }) {
  const lawConfig = config.law5651 || config.syslog || {};
  if (!lawConfig.enabled) return { ok: true, enabled: false };
  const storage = law5651StorageStatus({ ...config, law5651: lawConfig });
  if (!storage.available) {
    const error = new Error(`Syslog storage could not be checked: ${storage.error}`);
    error.code = 'syslog_unavailable';
    throw error;
  }
  if (storage.blocking) {
    safeRecordEvent(db, {
      eventType: 'syslog_storage_blocked_portal',
      severity: 'critical',
      message: `Syslog storage is ${storage.usagePercent}% full; new portal sessions are blocked.`,
      detail: { storage, context }
    });
    const error = new Error(`Syslog storage is ${storage.usagePercent}% full; new sessions are temporarily blocked.`);
    error.code = 'syslog_unavailable';
    throw error;
  }
  try {
    db.recordLaw5651Event({
      eventType: 'portal_log_write_check',
      severity: 'info',
      message: 'Portal syslog write check completed before accepting a new session.',
      detail: {
        clientIp: context.clientIp || '',
        method: context.method || '',
        storage: {
          directory: storage.directory,
          usagePercent: storage.usagePercent,
          freeBytes: storage.freeBytes
        }
      }
    });
  } catch (error) {
    const wrapped = new Error(`Syslog is not writable; new sessions are temporarily blocked: ${error.message}`);
    wrapped.code = 'syslog_unavailable';
    throw wrapped;
  }
  return { ok: true, enabled: true, storage };
}

function escapeCsv(value) {
  const text = value == null ? '' : String(value);
  return /[",\n]/u.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function jsonLine(value) {
  return `${JSON.stringify(value)}\n`;
}

function timeZoneParts(value, timeZone) {
  const date = new Date(Number(value));
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23'
  }).formatToParts(date);
  const map = Object.fromEntries(parts.map(part => [part.type, part.value]));
  return {
    year: Number(map.year),
    month: Number(map.month),
    day: Number(map.day),
    hour: Number(map.hour),
    minute: Number(map.minute),
    second: Number(map.second),
    millisecond: date.getUTCMilliseconds()
  };
}

function offsetText(offsetMinutes) {
  const sign = offsetMinutes >= 0 ? '+' : '-';
  const absolute = Math.abs(offsetMinutes);
  const hours = String(Math.trunc(absolute / 60)).padStart(2, '0');
  const minutes = String(absolute % 60).padStart(2, '0');
  return `${sign}${hours}:${minutes}`;
}

export function law5651IsoDate(value = Date.now(), timeZone = 'UTC') {
  if (value == null || value === '') return '';
  const timestamp = Number(value);
  if (!Number.isFinite(timestamp)) return '';
  const parts = timeZoneParts(timestamp, timeZone || 'UTC');
  const localAsUtc = Date.UTC(
    parts.year,
    parts.month - 1,
    parts.day,
    parts.hour,
    parts.minute,
    parts.second,
    parts.millisecond
  );
  const offsetMinutes = Math.round((localAsUtc - timestamp) / 60000);
  return [
    String(parts.year).padStart(4, '0'),
    '-',
    String(parts.month).padStart(2, '0'),
    '-',
    String(parts.day).padStart(2, '0'),
    'T',
    String(parts.hour).padStart(2, '0'),
    ':',
    String(parts.minute).padStart(2, '0'),
    ':',
    String(parts.second).padStart(2, '0'),
    '.',
    String(parts.millisecond).padStart(3, '0'),
    offsetText(offsetMinutes)
  ].join('');
}

export function law5651FileDate(value = Date.now(), timeZone = 'UTC') {
  return law5651IsoDate(value, timeZone).replace(/[:.]/gu, '-');
}

function isoOrEmpty(value, timeZone) {
  return value == null ? '' : law5651IsoDate(value, timeZone);
}

function padDatePart(value) {
  return String(value).padStart(2, '0');
}

function localDateLabelFromParts(parts) {
  return [
    String(parts.year).padStart(4, '0'),
    padDatePart(parts.month),
    padDatePart(parts.day)
  ].join('-');
}

function zonedDateTimeToUtcMs(parts, timeZone) {
  const targetAsUtc = Date.UTC(
    parts.year,
    parts.month - 1,
    parts.day,
    parts.hour || 0,
    parts.minute || 0,
    parts.second || 0,
    parts.millisecond || 0
  );
  let guess = targetAsUtc;
  for (let index = 0; index < 4; index += 1) {
    const local = timeZoneParts(guess, timeZone || 'UTC');
    const localAsUtc = Date.UTC(
      local.year,
      local.month - 1,
      local.day,
      local.hour,
      local.minute,
      local.second,
      local.millisecond
    );
    const offset = localAsUtc - guess;
    const next = targetAsUtc - offset;
    if (Math.abs(next - guess) < 1) return next;
    guess = next;
  }
  return guess;
}

function localDayStartAt(value, timeZone) {
  const parts = timeZoneParts(value, timeZone || 'UTC');
  return zonedDateTimeToUtcMs({
    year: parts.year,
    month: parts.month,
    day: parts.day
  }, timeZone || 'UTC');
}

function addLocalDays(dayStart, days, timeZone) {
  const parts = timeZoneParts(dayStart, timeZone || 'UTC');
  const shifted = new Date(Date.UTC(parts.year, parts.month - 1, parts.day + days));
  return zonedDateTimeToUtcMs({
    year: shifted.getUTCFullYear(),
    month: shifted.getUTCMonth() + 1,
    day: shifted.getUTCDate()
  }, timeZone || 'UTC');
}

function isLocalDailyWindow(periodStart, periodEnd, timeZone) {
  const start = Math.trunc(Number(periodStart));
  const end = Math.trunc(Number(periodEnd));
  if (!Number.isFinite(start) || !Number.isFinite(end)) return false;
  const dayStart = localDayStartAt(start, timeZone);
  return start === dayStart && end === addLocalDays(dayStart, 1, timeZone);
}

function exportPeriodLabel(periodStart, periodEnd, timeZone) {
  if (isLocalDailyWindow(periodStart, periodEnd, timeZone)) {
    return localDateLabelFromParts(timeZoneParts(periodStart, timeZone));
  }
  return `${law5651FileDate(periodStart, timeZone)}_to_${law5651FileDate(periodEnd, timeZone)}`;
}

function completedDailyWindow(now = Date.now(), timeZone = 'UTC') {
  const periodEnd = localDayStartAt(Math.trunc(Number(now) || Date.now()) - AUTO_EXPORT_GRACE_MS, timeZone);
  const periodStart = addLocalDays(periodEnd, -1, timeZone);
  return {
    periodStart,
    periodEnd,
    dateLabel: localDateLabelFromParts(timeZoneParts(periodStart, timeZone))
  };
}

function nextDailyExportRunAt(now = Date.now(), timeZone = 'UTC') {
  const timestamp = Math.trunc(Number(now) || Date.now());
  const todayStart = localDayStartAt(timestamp, timeZone);
  const todayRunAt = addLocalDays(todayStart, 1, timeZone) - 1000;
  if (timestamp < todayRunAt) return todayRunAt;
  return addLocalDays(addLocalDays(todayStart, 1, timeZone), 1, timeZone) - 1000;
}

function dailyClosedEnd(now = Date.now(), timeZone = 'UTC') {
  const timestamp = Math.trunc(Number(now) || Date.now());
  const todayStart = localDayStartAt(timestamp, timeZone);
  const todayRunAt = addLocalDays(todayStart, 1, timeZone) - 1000;
  return timestamp >= todayRunAt ? addLocalDays(todayStart, 1, timeZone) : todayStart;
}

function autoExportInterval(lawConfig = {}) {
  const selected = String(lawConfig.autoExportInterval || '').trim().toLowerCase();
  const configuredMinutes = Math.trunc(Number(lawConfig.autoExportIntervalMinutes) || 0);
  const inferred = Object.entries(AUTO_EXPORT_INTERVAL_MINUTES)
    .find(([, minutes]) => minutes === configuredMinutes)?.[0];
  const schedule = Object.hasOwn(AUTO_EXPORT_INTERVAL_MINUTES, selected) ? selected : (inferred || 'daily');
  const intervalMinutes = Math.max(
    1,
    configuredMinutes || AUTO_EXPORT_INTERVAL_MINUTES[schedule]
  );
  return {
    schedule,
    intervalMinutes,
    intervalMs: intervalMinutes * 60 * 1000,
    daily: schedule === 'daily'
  };
}

function selectedTimestampMode(lawConfig = {}) {
  const configured = String(lawConfig.timestampMode || '').trim().toLowerCase();
  if (TIMESTAMP_MODES.has(configured)) return configured;
  if (lawConfig.kamusmTimestampEnabled) return 'kamusm';
  if (lawConfig.timestampApiUrl || lawConfig.timestampApiKey) return 'api-key';
  if (lawConfig.timestampCommand) return 'command';
  if (lawConfig.timestampUrl) return 'rfc3161';
  return 'disabled';
}

function timestampEnabled(lawConfig = {}) {
  return selectedTimestampMode(lawConfig) !== 'disabled';
}

function autoExportReason(lawConfig = {}) {
  const mode = selectedTimestampMode(lawConfig);
  if (mode === 'kamusm') return 'kamusm';
  return mode === 'disabled' ? 'auto' : 'timestamp';
}

function automaticExportTime(row) {
  return Number(row?.period_end_at ?? row?.created_at ?? 0);
}

function latestAutomaticExport(db, lawConfig = null) {
  const rows = automaticExportRows(db);
  const filtered = lawConfig
    ? rows.filter(row => automaticExportSatisfied(db, row, lawConfig))
    : rows;
  filtered.sort((left, right) => automaticExportTime(right) - automaticExportTime(left));
  return filtered[0] || null;
}

function automaticExportRows(db) {
  return typeof db.listLaw5651Exports === 'function'
    ? db.listLaw5651Exports({ reasons: AUTO_EXPORT_REASONS, limit: 1000 })
    : AUTO_EXPORT_REASONS.map(reason => db.latestLaw5651Export({ reason })).filter(Boolean);
}

function findAutomaticExportByPeriod(db, periodStartAt, periodEndAt) {
  return AUTO_EXPORT_REASONS
    .map(reason => db.findLaw5651ExportByPeriod({ reason, periodStartAt, periodEndAt }))
    .find(Boolean) || null;
}

function timestampAttempted(row = {}) {
  const status = String(row.timestamp_status || row.timestampStatus || '').trim().toLowerCase();
  if (TIMESTAMP_PROVIDER_ATTEMPT_STATUSES.has(status)) return true;
  const mode = String(row.timestamp_mode || row.timestampMode || '').trim().toLowerCase();
  return Boolean(!status && mode && mode !== 'disabled');
}

function timestampAttemptMatchesInterval(row = {}, interval = null, timeZone = 'UTC') {
  if (!interval) return true;
  const periodStart = Math.trunc(Number(row.period_start_at ?? row.periodStartAt));
  const periodEnd = Math.trunc(Number(row.period_end_at ?? row.periodEndAt));
  if (!Number.isFinite(periodStart) || !Number.isFinite(periodEnd) || periodEnd <= periodStart) return true;
  if (interval.daily) return isLocalDailyWindow(periodStart, periodEnd, timeZone);
  return periodEnd - periodStart === interval.intervalMs;
}

function exportTimestampStatus(row = {}) {
  row = row || {};
  return String(row.timestamp_status || row.timestampStatus || '').trim().toLowerCase();
}

function timestampDisabledExport(row = {}) {
  return exportTimestampStatus(row) === 'disabled';
}

function timestampRuntimeMode(lawConfig = {}) {
  const mode = selectedTimestampMode(lawConfig);
  if (mode === 'disabled') return 'disabled';
  if (mode === 'kamusm') return 'kamusm-rfc3161';
  if (mode === 'api-key') return 'api-key-rfc3161';
  if (mode === 'command') return 'command';
  return 'rfc3161-url';
}

function law5651StateValue(db, key) {
  try {
    return db.getLaw5651State?.(key)?.value ?? null;
  } catch {
    return null;
  }
}

function setLaw5651StateValue(db, key, value, now = Date.now()) {
  try {
    db.setLaw5651State?.(key, value, now);
  } catch {
    // State tracking is a hardening layer; export code still records explicit failures below.
  }
}

function parseTimestampDisabledIntervals(value) {
  try {
    const parsed = JSON.parse(String(value || '[]'));
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map(item => ({
        startAt: Math.trunc(Number(item?.startAt) || 0),
        endAt: Math.trunc(Number(item?.endAt) || 0)
      }))
      .filter(item => item.startAt > 0 && item.endAt > item.startAt);
  } catch {
    return [];
  }
}

function timestampDisabledIntervals(db) {
  return parseTimestampDisabledIntervals(law5651StateValue(db, TIMESTAMP_DISABLED_INTERVALS_STATE));
}

function storeTimestampDisabledIntervals(db, intervals, now = Date.now()) {
  const safe = intervals
    .filter(item => item.startAt > 0 && item.endAt > item.startAt)
    .slice(-TIMESTAMP_DISABLED_INTERVAL_LIMIT);
  setLaw5651StateValue(db, TIMESTAMP_DISABLED_INTERVALS_STATE, JSON.stringify(safe), now);
}

function inferTimestampEnabledSince(db, now = Date.now()) {
  const current = Math.trunc(Number(now) || Date.now());
  const futureTolerance = current + AUTO_EXPORT_GRACE_MS;
  const rows = automaticExportRows(db)
    .filter(timestampAttempted)
    .filter(row => {
      const createdAt = Math.trunc(Number(row.created_at) || 0);
      return createdAt > 0 && createdAt <= futureTolerance;
    })
    .sort((left, right) => {
      const leftStart = Number(left.period_start_at ?? left.created_at ?? 0);
      const rightStart = Number(right.period_start_at ?? right.created_at ?? 0);
      return leftStart - rightStart;
    });
  const first = rows[0];
  const periodStart = Math.trunc(Number(first?.period_start_at) || 0);
  if (periodStart > 0) return periodStart;
  const createdAt = Math.trunc(Number(first?.created_at) || 0);
  return createdAt > 0 ? createdAt : current;
}

function observeTimestampModeState(db, lawConfig = {}, now = Date.now()) {
  const current = Math.trunc(Number(now) || Date.now());
  if (!db?.getLaw5651State || !db?.setLaw5651State) return;
  if (timestampEnabled(lawConfig)) {
    const disabledSince = Math.trunc(Number(law5651StateValue(db, TIMESTAMP_DISABLED_SINCE_STATE)) || 0);
    if (disabledSince > 0 && current > disabledSince) {
      storeTimestampDisabledIntervals(db, [
        ...timestampDisabledIntervals(db),
        { startAt: disabledSince, endAt: current }
      ], current);
      setLaw5651StateValue(db, TIMESTAMP_DISABLED_SINCE_STATE, '', current);
      setLaw5651StateValue(db, TIMESTAMP_ENABLED_SINCE_STATE, String(current), current);
      return;
    }
    const enabledSince = Math.trunc(Number(law5651StateValue(db, TIMESTAMP_ENABLED_SINCE_STATE)) || 0);
    const intervals = timestampDisabledIntervals(db);
    const inferredSince = inferTimestampEnabledSince(db, current);
    if (!enabledSince || (!intervals.length && inferredSince > 0 && inferredSince < enabledSince)) {
      setLaw5651StateValue(db, TIMESTAMP_ENABLED_SINCE_STATE, String(inferredSince), current);
    }
    return;
  }
  const disabledSince = Math.trunc(Number(law5651StateValue(db, TIMESTAMP_DISABLED_SINCE_STATE)) || 0);
  if (!disabledSince) {
    setLaw5651StateValue(db, TIMESTAMP_DISABLED_SINCE_STATE, String(current), current);
  }
}

export function observeLaw5651TimestampModeState(db, lawConfig = {}, now = Date.now()) {
  observeTimestampModeState(db, lawConfig, now);
}

function timestampEvidenceGap(db, lawConfig = {}, periodStartAt = null, periodEndAt = null, now = Date.now()) {
  if (!timestampEnabled(lawConfig) || periodStartAt == null || periodEndAt == null) return null;
  const periodStart = Math.trunc(Number(periodStartAt));
  const periodEnd = Math.trunc(Number(periodEndAt));
  if (!Number.isFinite(periodStart) || !Number.isFinite(periodEnd) || periodEnd <= periodStart) return null;
  void db;
  void now;
  return null;
}

function evidenceGapTimestamp(lawConfig = {}, gap = {}) {
  const start = gap.startAt ? new Date(gap.startAt).toISOString() : '';
  const end = gap.endAt ? new Date(gap.endAt).toISOString() : '';
  const range = start && end ? ` (${start} - ${end})` : '';
  return {
    status: TIMESTAMP_EVIDENCE_GAP_STATUS,
    error: `Timestamping was not continuously enabled for this syslog period${range}; refusing to create a retroactive timestamp.`,
    tokenPath: '',
    requestPath: '',
    mode: timestampRuntimeMode(lawConfig)
  };
}

function latestAutomaticTimestampAttempt(db, now = Date.now(), { interval = null, timeZone = 'UTC' } = {}) {
  const rows = automaticExportRows(db);
  const current = Math.trunc(Number(now) || Date.now());
  const futureTolerance = current + AUTO_EXPORT_GRACE_MS;
  return rows
    .filter(timestampAttempted)
    .filter(row => timestampAttemptMatchesInterval(row, interval, timeZone))
    .filter(row => {
      const createdAt = Math.trunc(Number(row.created_at) || 0);
      return createdAt > 0 && createdAt <= futureTolerance;
    })
    .sort((left, right) => Number(right.created_at || 0) - Number(left.created_at || 0))[0] || null;
}

function latestAutomaticTimestampAttemptAt(db, state = {}, now = Date.now(), options = {}) {
  const schedule = options.interval?.schedule || '';
  const stateSchedule = String(state.lastTimestampAttemptSchedule || '');
  const stateAttemptAt = !schedule || !stateSchedule || stateSchedule === schedule
    ? Math.trunc(Number(state.lastTimestampAttemptAt) || 0)
    : 0;
  const persistedAttemptAt = Math.trunc(Number(latestAutomaticTimestampAttempt(db, now, options)?.created_at) || 0);
  return Math.max(stateAttemptAt, persistedAttemptAt);
}

function nextAutomaticTimestampAllowedAt(
  db,
  state,
  interval,
  now = Date.now(),
  timeZone = 'UTC',
  { periodEndAt = null } = {}
) {
  const lastAttemptAt = latestAutomaticTimestampAttemptAt(db, state, now, { interval, timeZone });
  const periodEnd = Math.trunc(Number(periodEndAt));
  if (Number.isFinite(periodEnd) && periodEnd > lastAttemptAt) return null;
  return lastAttemptAt > 0 ? lastAttemptAt + interval.intervalMs : null;
}

function automaticExportSatisfied(db, existing, lawConfig = {}) {
  if (!existing) return false;
  if (timestampEnabled(lawConfig)) {
    const timestampStatus = exportTimestampStatus(existing);
    if (timestampStatus === TIMESTAMP_EVIDENCE_GAP_STATUS) {
      const gap = timestampEvidenceGap(
        db,
        lawConfig,
        existing.period_start_at,
        existing.period_end_at
      );
      if (!gap) return false;
    } else if (timestampDisabledExport(existing)) {
      // Already exported while timestamping was off; keep it unsigned but still verify the archive below.
    } else if (timestampStatus !== 'created') {
      return false;
    }
  }
  if (existing.period_start_at != null && existing.period_end_at != null) {
    const total = db.listLaw5651Logs({
      limit: 1,
      createdFrom: Number(existing.period_start_at),
      createdBefore: Number(existing.period_end_at)
    }).total;
    if (total > 0) {
      if (existing.first_sequence == null || existing.last_sequence == null) return false;
      try {
        if (!existing.file_path || !fs.existsSync(existing.file_path) || fileHash(existing.file_path) !== existing.export_hash) {
          return false;
        }
      } catch {
        return false;
      }
    }
    return total <= Number(existing.record_count || 0);
  }
  return true;
}

function law5651ExportResultFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    exportReason: row.export_reason || 'manual',
    periodStartAt: row.period_start_at == null ? null : Number(row.period_start_at),
    periodEndAt: row.period_end_at == null ? null : Number(row.period_end_at),
    filePath: row.file_path,
    jsonlPath: '',
    eventsPath: '',
    manifestPath: row.manifest_path || row.file_path,
    archivePath: String(row.file_path || '').endsWith('.zip') ? row.file_path : '',
    archiveEntries: [],
    sourceFiles: [],
    sourceFilesDeleted: false,
    timestampRequestPath: row.timestamp_request_path || '',
    timestampTokenPath: row.timestamp_token_path || '',
    timestampMode: row.timestamp_mode || 'disabled',
    signaturePath: row.signature_path || '',
    signatureMode: row.signature_mode || 'disabled',
    recordCount: Number(row.record_count || 0),
    firstSequence: row.first_sequence == null ? null : Number(row.first_sequence),
    lastSequence: row.last_sequence == null ? null : Number(row.last_sequence),
    eventCount: 0,
    exportHash: row.export_hash || '',
    timestampStatus: row.timestamp_status || 'disabled',
    timestampError: row.timestamp_error || '',
    signatureStatus: row.signature_status || 'disabled',
    signatureError: row.signature_error || '',
    backupStatus: row.backup_status || 'disabled',
    backupError: row.backup_error || '',
    backupResults: [],
    reused: true
  };
}

function firstIntervalExportStart(db, now) {
  const { rows } = db.listLaw5651Logs({
    limit: 1,
    order: 'asc',
    createdBefore: now
  });
  return rows[0] ? Math.trunc(Number(rows[0].created_at)) : null;
}

function nextIntervalExportRunAt(db, now, intervalMs, lawConfig = {}) {
  const previous = latestAutomaticExport(db, lawConfig);
  if (previous?.period_end_at != null) return Math.trunc(Number(previous.period_end_at)) + intervalMs;
  const firstStart = firstIntervalExportStart(db, now);
  return firstStart == null ? null : firstStart + intervalMs;
}

function opnsenseCommunicationReady(db, config = {}, now = Date.now()) {
  const gateway = config.gateway || {};
  if (!gateway.mode || gateway.mode === 'mock' || gateway.syncEnabled === false) return true;
  const state = db.getRuntimeState?.('opnsense_last_successful_sync_at');
  const lastSuccessfulSyncAt = Math.trunc(Number(state?.value) || 0);
  if (!lastSuccessfulSyncAt) return false;
  const syncIntervalMs = Math.max(5, Number(gateway.syncIntervalSeconds || 10)) * 1000;
  return Math.trunc(Number(now) || Date.now()) - lastSuccessfulSyncAt <= Math.max(60 * 1000, syncIntervalMs * 3);
}

function cleanupExpiredLaw5651DatabaseRecords({ db, config, logger = console, now = Date.now() } = {}) {
  const lawConfig = config.law5651 || config.syslog || {};
  if (typeof db.cleanupLaw5651Logs !== 'function') return 0;
  try {
    return db.cleanupLaw5651Logs(retentionDaysValue(lawConfig.retentionDays), now, {
      reasons: AUTO_EXPORT_REASONS,
      requireTimestamp: timestampEnabled(lawConfig),
      requireBackup: Boolean(lawConfig.backupEnabled && lawConfig.backupWormRequired)
    });
  } catch (error) {
    logger.warn?.(`Syslog retention cleanup failed: ${error.message}`);
    return 0;
  }
}

function cleanupExpiredLaw5651ExportDirectoryFiles({ lawConfig, cutoff, totals, logger = console }) {
  const exportDirectory = lawConfig.exportDirectory;
  if (!exportDirectory || !fs.existsSync(exportDirectory)) return;
  const extensions = retentionFileExtensions(lawConfig);
  const stack = [exportDirectory];
  while (stack.length) {
    const directory = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true });
    } catch (error) {
      totals.errors.push({ filePath: directory, error: error.message });
      logger.warn?.(`Syslog export directory could not be scanned for retention cleanup: ${directory}: ${error.message}`);
      continue;
    }
    for (const entry of entries) {
      const filePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (pathInsideDirectory(filePath, exportDirectory)) stack.push(filePath);
        continue;
      }
      if (!entry.isFile() || !extensions.has(path.extname(entry.name).toLowerCase())) continue;
      try {
        const stats = fs.statSync(filePath);
        if (Number(stats.mtimeMs || 0) >= cutoff) continue;
      } catch (error) {
        totals.errors.push({ filePath, error: error.message });
        logger.warn?.(`Syslog export file could not be checked for retention cleanup: ${filePath}: ${error.message}`);
        continue;
      }
      removeExportRetentionFile(filePath, exportDirectory, totals, logger);
    }
  }
}

export function cleanupExpiredLaw5651ExportFiles({ db, config, logger = console, now = Date.now() } = {}) {
  const lawConfig = config.law5651 || config.syslog || {};
  const exportDirectory = lawConfig.exportDirectory;
  const retentionDays = retentionDaysValue(lawConfig.retentionDays);
  const cutoff = exportRetentionCutoff(retentionDays, now);
  const totals = {
    retentionDays,
    cutoff,
    exportDirectory: exportDirectory || '',
    deletedFiles: 0,
    deletedBytes: 0,
    deletedPaths: [],
    errors: []
  };
  if (!exportDirectory) return totals;

  try {
    const rows = typeof db?.listExpiredLaw5651Exports === 'function'
      ? db.listExpiredLaw5651Exports({ cutoff, reasons: AUTO_EXPORT_REASONS })
      : [];
    for (const row of rows) {
      for (const filePath of exportArtifactPaths(row)) {
        removeExportRetentionFile(filePath, exportDirectory, totals, logger);
      }
    }
  } catch (error) {
    totals.errors.push({ filePath: exportDirectory, error: error.message });
    logger.warn?.(`Syslog export retention metadata cleanup failed: ${error.message}`);
  }

  cleanupExpiredLaw5651ExportDirectoryFiles({ lawConfig, cutoff, totals, logger });
  return totals;
}

function dailyLogLine(row, timeZone) {
  return JSON.stringify({
    sequence: Number(row.sequence),
    id: row.id,
    createdAt: law5651IsoDate(row.created_at, timeZone),
    kind: row.kind,
    source: row.source,
    network: row.network || '',
    clientIp: row.client_ip,
    clientMac: row.client_mac || '',
    subscriberId: row.subscriber_id || '',
    sourceIp: row.source_ip,
    sourcePort: row.source_port || '',
    destinationIp: row.destination_ip,
    destinationPort: row.destination_port || '',
    protocol: row.protocol || '',
    serviceType: row.service_type,
    startedAt: law5651IsoDate(row.started_at, timeZone),
    endedAt: row.ended_at ? law5651IsoDate(row.ended_at, timeZone) : '',
    downloadBytes: Number(row.download_bytes || 0),
    uploadBytes: Number(row.upload_bytes || 0),
    rawJson: row.raw_json || '',
    previousHash: row.previous_hash,
    recordHash: row.record_hash
  });
}

function law5651DailyLog(records, {
  appName = 'G-Hotspot',
  timeZone = 'UTC',
  dateLabel = '',
  periodStart = null,
  periodEnd = null
} = {}) {
  const header = [
    `# ${appName} 5651 daily syslog`,
    `# date=${dateLabel}`,
    `# timezone=${timeZone}`,
    `# period_start=${isoOrEmpty(periodStart, timeZone)}`,
    `# period_end=${isoOrEmpty(periodEnd, timeZone)}`,
    `# record_count=${records.length}`,
    '# format=json-lines'
  ];
  return `${header.join('\n')}\n${records.map(row => dailyLogLine(row, timeZone)).join('\n')}${records.length ? '\n' : ''}`;
}

function law5651DailyLogHeader({
  appName = 'G-Hotspot',
  timeZone = 'UTC',
  dateLabel = '',
  periodStart = null,
  periodEnd = null,
  recordCount = 0
} = {}) {
  return [
    `# ${appName} 5651 daily syslog`,
    `# date=${dateLabel}`,
    `# timezone=${timeZone}`,
    `# period_start=${isoOrEmpty(periodStart, timeZone)}`,
    `# period_end=${isoOrEmpty(periodEnd, timeZone)}`,
    `# record_count=${Math.max(0, Math.trunc(Number(recordCount) || 0))}`,
    '# format=json-lines'
  ].join('\n');
}

function writeLaw5651DailyLogFile(db, logPath, {
  appName = 'G-Hotspot',
  timeZone = 'UTC',
  dateLabel = '',
  periodStart = null,
  periodEnd = null
} = {}) {
  const firstPage = db.listLaw5651Logs({
    limit: EXPORT_PAGE_SIZE,
    offset: 0,
    order: 'asc',
    createdFrom: periodStart,
    createdBefore: periodEnd
  });
  const total = Number(firstPage.total || 0);
  fs.writeFileSync(logPath, `${law5651DailyLogHeader({
    appName,
    timeZone,
    dateLabel,
    periodStart,
    periodEnd,
    recordCount: total
  })}\n`, { mode: 0o600 });
  let written = 0;
  let firstRow = null;
  let lastRow = null;
  for (let offset = 0; offset < total; offset += EXPORT_PAGE_SIZE) {
    const rows = offset === 0
      ? firstPage.rows
      : db.listLaw5651Logs({
          limit: EXPORT_PAGE_SIZE,
          offset,
          order: 'asc',
          createdFrom: periodStart,
          createdBefore: periodEnd
        }).rows;
    if (!rows.length) break;
    if (!firstRow) firstRow = rows[0];
    lastRow = rows.at(-1);
    fs.appendFileSync(logPath, `${rows.map(row => dailyLogLine(row, timeZone)).join('\n')}\n`, { mode: 0o600 });
    written += rows.length;
  }
  return {
    recordCount: written,
    firstSequence: firstRow ? Number(firstRow.sequence) : null,
    lastSequence: lastRow ? Number(lastRow.sequence) : null,
    firstCreatedAt: firstRow ? Number(firstRow.created_at) : null,
    lastCreatedAt: lastRow ? Number(lastRow.created_at) : null
  };
}

function isInScope(clientIp, networks) {
  try {
    return Boolean(clientIp) && ipv4InNetworkList(clientIp, networks);
  } catch {
    return false;
  }
}

function trafficLogScopeConfig(config = {}) {
  return {
    ...(config.law5651 || {}),
    networks: config.law5651?.networks || 'any',
    requireTrafficNetworkScope: false
  };
}

function identityRowMac(value) {
  if (typeof value === 'string') return normalizeMac(value);
  return normalizeMac(value?.clientMac || value?.client_mac || value?.mac || value?.macAddress);
}

function clientIdentityForIp(clientIp, lookup) {
  if (!lookup || !clientIp) return null;
  if (lookup instanceof Map) return lookup.get(clientIp) || null;
  if (typeof lookup === 'object') return lookup[clientIp] || null;
  return null;
}

function clientIdentityMap(rows = []) {
  const output = new Map();
  for (const row of rows || []) {
    const clientIp = String(row?.clientIp || row?.client_ip || row?.ip || '').trim();
    const clientMac = identityRowMac(row);
    if (clientIp && clientMac) output.set(clientIp, { ...row, clientIp, clientMac });
  }
  return output;
}

function applyClientIdentity(record, identity) {
  if (!identity) return record;
  const clientMac = identityRowMac(identity);
  if (!clientMac) return record;
  return {
    ...record,
    clientMac: record.clientMac || clientMac
  };
}

export function law5651RecordFromSession(session, authorization, lawConfig) {
  if (!lawConfig.enabled) return null;
  const clientIp = session.clientIp || authorization?.client_ip || '';
  if (!isInScope(clientIp, lawConfig.networks)) return null;
  const startedAt = Number(authorization?.created_at || session.startedAt || Date.now());
  const endedAt = Math.max(startedAt, Number(session.lastSeenAt || Date.now()));
  const subscriberId = authorization
    ? `${authorization.method}:${authorization.identity}`
    : (session.userName || '');
  const downloadBytes = Math.max(0, Math.trunc(Number(session.downloadBytes) || 0));
  const uploadBytes = Math.max(0, Math.trunc(Number(session.uploadBytes) || 0));
  return {
    dedupeKey: [
      'session',
      session.sessionId || '',
      authorization?.id || '',
      clientIp,
      subscriberId,
      startedAt,
      downloadBytes,
      uploadBytes
    ].join('|'),
    kind: 'session',
    source: 'opnsense-session',
    network: lawConfig.networks,
    clientIp,
    clientMac: normalizeMac(session.clientMac || authorization?.client_mac || ''),
    subscriberId,
    sourceIp: clientIp,
    sourcePort: session.sourcePort || '',
    destinationIp: session.destinationIp || '',
    destinationPort: session.destinationPort || '',
    protocol: session.protocol || 'ip',
    serviceType: session.serviceType || 'internet-access',
    startedAt,
    endedAt,
    downloadBytes,
    uploadBytes,
    rawJson: session.raw ? JSON.stringify(session.raw) : '',
    createdAt: Date.now()
  };
}

function filterlogPayload(message) {
  const match = String(message).trim().match(/filterlog(?:\[\d+\])?:\s*(.+)$/u);
  return match?.[1] || '';
}

function ipv4Values(value) {
  return [...String(value).matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/gu)].map(match => match[0]);
}

function syslogFlowFromFields(message) {
  const payload = filterlogPayload(message);
  if (!payload) return null;
  const fields = payload.split(',').map(item => item.trim());
  if (fields.length < 20 || fields[8] !== '4') return null;
  const protocol = (fields[16] || '').toLowerCase();
  return {
    payload,
    fields,
    action: fields[6] || 'event',
    direction: fields[7] || '',
    interfaceName: fields[4] || '',
    protocol,
    packetBytes: Math.max(0, Math.trunc(Number(fields[17]) || 0)),
    sourceIp: fields[18] || '',
    destinationIp: fields[19] || '',
    sourcePort: ['tcp', 'udp'].includes(protocol) ? (fields[20] || '') : '',
    destinationPort: ['tcp', 'udp'].includes(protocol) ? (fields[21] || '') : ''
  };
}

function syslogFlowFallback(message) {
  const text = String(message);
  const ips = ipv4Values(text);
  if (ips.length < 2) return null;
  const lower = text.toLowerCase();
  const protocol = lower.includes(' udp ') || lower.includes(',udp,') ? 'udp'
    : lower.includes(' tcp ') || lower.includes(',tcp,') ? 'tcp'
      : '';
  const sourcePattern = ips[0].replaceAll('.', '\\.');
  const destinationPattern = ips[1].replaceAll('.', '\\.');
  const portMatch = text.match(new RegExp(
    `\\b${sourcePattern}\\b(?::|\\s+)(\\d{1,5})\\b[^\\n\\r]+?\\b${destinationPattern}\\b(?::|\\s+)(\\d{1,5})\\b`,
    'u'
  ));
  const lengthMatch = text.match(/\blength[=:\s]+(\d{1,6})\b/iu) ||
    text.match(/\blen[=:\s]+(\d{1,6})\b/iu);
  return {
    payload: text,
    fields: [],
    action: lower.includes('block') ? 'block' : lower.includes('pass') ? 'pass' : 'event',
    direction: lower.includes(' out ') ? 'out' : lower.includes(' in ') ? 'in' : '',
    interfaceName: '',
    protocol,
    packetBytes: Math.max(0, Math.trunc(Number(lengthMatch?.[1]) || 0)),
    sourceIp: ips[0],
    destinationIp: ips[1],
    sourcePort: portMatch?.[1] || '',
    destinationPort: portMatch?.[2] || ''
  };
}

export function law5651RecordsFromSyslog(
  message,
  lawConfig,
  now = Date.now(),
  nonce = '',
  clientIdentityLookup = null
) {
  if (!lawConfig.enabled || !lawConfig.syslogEnabled) return [];
  const flow = syslogFlowFromFields(message) || syslogFlowFallback(message);
  if (!flow) return [];
  const {
    payload, action, direction, interfaceName, protocol, packetBytes,
    sourceIp, destinationIp, sourcePort, destinationPort
  } = flow;
  const sourceInScope = isInScope(sourceIp, lawConfig.networks);
  const destinationInScope = isInScope(destinationIp, lawConfig.networks);
  if (!sourceInScope && !destinationInScope) return [];

  const clientIp = sourceInScope ? sourceIp : destinationIp;
  const uploadBytes = sourceInScope ? packetBytes : 0;
  const downloadBytes = destinationInScope && !sourceInScope ? packetBytes : 0;
  const createdAt = Math.trunc(Number(now) || Date.now());
  const record = {
    dedupeKey: `filterlog|${sha256Hex(`${payload}|${createdAt}|${nonce}`)}`,
    kind: 'flow',
    source: 'opnsense-filterlog',
    network: lawConfig.networks,
    clientIp,
    clientMac: '',
    subscriberId: '',
    sourceIp,
    sourcePort,
    destinationIp,
    destinationPort,
    protocol,
    serviceType: `firewall-${action}${direction ? `-${direction}` : ''}`,
    startedAt: createdAt,
    endedAt: createdAt,
    downloadBytes,
    uploadBytes,
    rawJson: JSON.stringify({
      interface: interfaceName,
      action,
      direction,
      parser: flow.fields.length ? 'filterlog' : 'fallback',
      message: String(message)
    }),
    createdAt
  };
  return [applyClientIdentity(record, clientIdentityForIp(clientIp, clientIdentityLookup))];
}

export function trafficLogRecordsFromSyslogMessage(
  message,
  lawConfig = {},
  settings = {},
  now = Date.now(),
  nonce = '',
  clientIdentityLookup = null
) {
  if (settings.enabled === false) return [];
  const flow = syslogFlowFromFields(message) || syslogFlowFallback(message);
  if (!flow) return [];
  const {
    payload, action, direction, interfaceName, protocol, packetBytes,
    sourceIp, destinationIp, sourcePort, destinationPort
  } = flow;
  if (!sourceIp && !destinationIp) return [];
  const sourceInScope = isInScope(sourceIp, lawConfig.networks);
  const destinationInScope = isInScope(destinationIp, lawConfig.networks);
  if (lawConfig.requireTrafficNetworkScope && !sourceInScope && !destinationInScope) return [];
  let clientIp = '';
  if (sourceInScope && !destinationInScope) clientIp = sourceIp;
  else if (destinationInScope && !sourceInScope) clientIp = destinationIp;
  else if (sourceInScope && destinationInScope) clientIp = sourceIp || destinationIp;
  else if (direction === 'in') clientIp = destinationIp || sourceIp;
  else clientIp = sourceIp || destinationIp;
  if (!clientIp) return [];
  const outgoing = clientIp === sourceIp;
  const incoming = !outgoing && clientIp === destinationIp;
  const createdAt = Math.trunc(Number(now) || Date.now());
  const record = {
    dedupeKey: `filterlog-live|${sha256Hex(`${payload}|${createdAt}|${nonce}`)}`,
    kind: 'flow',
    source: 'opnsense-filterlog',
    clientIp,
    clientMac: '',
    subscriberId: '',
    sourceIp,
    sourcePort,
    destinationIp,
    destinationPort,
    destinationDomain: '',
    protocol,
    serviceType: `firewall-${action}${direction ? `-${direction}` : ''}`,
    direction: outgoing ? 'outgoing' : incoming ? 'incoming' : 'flow',
    startedAt: createdAt,
    endedAt: createdAt,
    downloadBytes: incoming ? packetBytes : 0,
    uploadBytes: outgoing ? packetBytes : 0,
    rawJson: JSON.stringify({
      interface: interfaceName,
      action,
      direction,
      parser: flow.fields.length ? 'filterlog' : 'fallback',
      message: String(message)
    }),
    createdAt
  };
  return [applyClientIdentity(record, clientIdentityForIp(clientIp, clientIdentityLookup))];
}

function exportRows(records, timeZone) {
  return records.map(row => ({
    sequence: Number(row.sequence),
    createdAt: law5651IsoDate(row.created_at, timeZone),
    kind: row.kind,
    source: row.source,
    network: row.network || '',
    clientIp: row.client_ip,
    clientMac: row.client_mac || '',
    subscriberId: row.subscriber_id || '',
    sourceIp: row.source_ip,
    sourcePort: row.source_port || '',
    destinationIp: row.destination_ip || '',
    destinationPort: row.destination_port || '',
    protocol: row.protocol || '',
    serviceType: row.service_type,
    startedAt: law5651IsoDate(row.started_at, timeZone),
    endedAt: row.ended_at ? law5651IsoDate(row.ended_at, timeZone) : '',
    downloadBytes: Number(row.download_bytes || 0),
    uploadBytes: Number(row.upload_bytes || 0),
    previousHash: row.previous_hash,
    recordHash: row.record_hash
  }));
}

export function law5651Csv(records, { timeZone = 'UTC' } = {}) {
  const headers = [
    'Sequence', `Created At (${timeZone})`, 'Kind', 'Source', 'Network', 'Client IP',
    'Client MAC', 'Subscriber ID', 'Source IP', 'Source Port', 'Destination IP',
    'Destination Port', 'Protocol', 'Service Type', `Started At (${timeZone})`,
    `Ended At (${timeZone})`, 'Download Bytes', 'Upload Bytes', 'Previous Hash', 'Record Hash'
  ];
  const lines = [
    headers,
    ...exportRows(records, timeZone).map(row => [
      row.sequence,
      row.createdAt,
      row.kind,
      row.source,
      row.network,
      row.clientIp,
      row.clientMac,
      row.subscriberId,
      row.sourceIp,
      row.sourcePort,
      row.destinationIp,
      row.destinationPort,
      row.protocol,
      row.serviceType,
      row.startedAt,
      row.endedAt,
      row.downloadBytes,
      row.uploadBytes,
      row.previousHash,
      row.recordHash
    ])
  ];
  return `\uFEFF${lines.map(columns => columns.map(escapeCsv).join(',')).join('\n')}`;
}

async function runTimestampCommand(lawConfig, manifestPath, tokenPath) {
  if (!lawConfig.timestampCommand) return { status: 'disabled', error: '', tokenPath: '' };
  try {
    await execFileAsync(lawConfig.timestampCommand, [manifestPath, tokenPath], {
      timeout: Math.max(5, Number(lawConfig.timestampTimeoutSeconds) || 60) * 1000,
      maxBuffer: 1024 * 1024
    });
    return {
      status: fs.existsSync(tokenPath) ? 'created' : 'missing-token',
      error: fs.existsSync(tokenPath) ? '' : 'Timestamp command completed without creating the token file.',
      tokenPath: fs.existsSync(tokenPath) ? tokenPath : ''
    };
  } catch (error) {
    return { status: 'failed', error: error.message, tokenPath: '' };
  }
}

function timestampHeaders(lawConfig) {
  if (!lawConfig.timestampHeadersJson) return {};
  const parsed = JSON.parse(lawConfig.timestampHeadersJson);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('SYSLOG_TIMESTAMP_HEADERS_JSON must be a JSON object');
  }
  return Object.fromEntries(Object.entries(parsed).map(([key, value]) => [key, String(value)]));
}

function postTimestampQuery(urlValue, body, headers, timeoutMs) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlValue);
    const transport = url.protocol === 'https:' ? https : url.protocol === 'http:' ? http : null;
    if (!transport) {
      reject(new Error('RFC3161 TSA URL must use http or https'));
      return;
    }
    const request = transport.request(url, {
      method: 'POST',
      timeout: timeoutMs,
      headers: {
        ...headers,
        'content-type': headers['content-type'] || headers['Content-Type'] || 'application/timestamp-query',
        accept: headers.accept || headers.Accept || 'application/timestamp-reply',
        'content-length': body.length
      }
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        const payload = Buffer.concat(chunks);
        if (response.statusCode < 200 || response.statusCode >= 300) {
          reject(new Error(`RFC3161 TSA returned HTTP ${response.statusCode}: ${payload.toString('utf8').slice(0, 500)}`));
          return;
        }
        resolve(payload);
      });
    });
    request.on('timeout', () => request.destroy(new Error('RFC3161 TSA request timed out')));
    request.on('error', reject);
    request.end(body);
  });
}

function basicAuthHeader(username, password) {
  return `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`;
}

async function runKamusmTimestamp(lawConfig, logPath, tokenPath, requestPath) {
  try {
    const digest = createHash('sha256').update(fs.readFileSync(logPath)).digest();
    const query = rfc3161TimestampQuery(digest, { certReq: true });
    fs.writeFileSync(requestPath, query, { mode: 0o600 });
    const token = await postTimestampQuery(
      lawConfig.kamusmUrl || 'http://zd.kamusm.gov.tr',
      query,
      {
        Authorization: basicAuthHeader(lawConfig.kamusmUser || '', lawConfig.kamusmPassword || '')
      },
      Math.max(5, Number(lawConfig.kamusmTimeoutSeconds) || 60) * 1000
    );
    if (!token.length) {
      return {
        status: 'missing-token',
        error: 'KamuSM timestamp service returned an empty response.',
        tokenPath: '',
        requestPath,
        mode: 'kamusm-rfc3161'
      };
    }
    fs.writeFileSync(tokenPath, token, { mode: 0o600 });
    return {
      status: 'created',
      error: '',
      tokenPath,
      requestPath,
      mode: 'kamusm-rfc3161'
    };
  } catch (error) {
    return {
      status: 'failed',
      error: error.message,
      tokenPath: '',
      requestPath: fs.existsSync(requestPath) ? requestPath : '',
      mode: 'kamusm-rfc3161'
    };
  }
}

async function runRfc3161Timestamp(lawConfig, manifestPath, tokenPath, requestPath) {
  if (!lawConfig.timestampUrl) {
    return {
      status: 'failed',
      error: 'RFC3161 TSA URL is not configured.',
      tokenPath: '',
      requestPath: '',
      mode: 'rfc3161-url'
    };
  }
  try {
    const digest = createHash('sha256').update(fs.readFileSync(manifestPath)).digest();
    const query = rfc3161TimestampQuery(digest, { certReq: lawConfig.timestampCertRequest !== false });
    fs.writeFileSync(requestPath, query, { mode: 0o600 });
    const token = await postTimestampQuery(
      lawConfig.timestampUrl,
      query,
      timestampHeaders(lawConfig),
      Math.max(5, Number(lawConfig.timestampTimeoutSeconds) || 60) * 1000
    );
    fs.writeFileSync(tokenPath, token, { mode: 0o600 });
    return {
      status: token.length ? 'created' : 'missing-token',
      error: token.length ? '' : 'RFC3161 TSA completed without returning a timestamp token.',
      tokenPath: token.length ? tokenPath : '',
      requestPath,
      mode: 'rfc3161-url'
    };
  } catch (error) {
    return {
      status: 'failed',
      error: error.message,
      tokenPath: '',
      requestPath: fs.existsSync(requestPath) ? requestPath : '',
      mode: 'rfc3161-url'
    };
  }
}

function timestampApiHeaders(lawConfig) {
  const headers = timestampHeaders(lawConfig);
  const headerName = String(lawConfig.timestampApiKeyHeader || 'Authorization').trim();
  const apiKey = String(lawConfig.timestampApiKey || '').trim();
  const prefix = String(lawConfig.timestampApiKeyPrefix || '').trim();
  headers[headerName] = prefix ? `${prefix} ${apiKey}` : apiKey;
  return headers;
}

async function runApiKeyTimestamp(lawConfig, manifestPath, tokenPath, requestPath) {
  if (!lawConfig.timestampApiUrl) {
    return {
      status: 'failed',
      error: 'Timestamp API URL is not configured.',
      tokenPath: '',
      requestPath: '',
      mode: 'api-key-rfc3161'
    };
  }
  if (!lawConfig.timestampApiKey) {
    return {
      status: 'failed',
      error: 'Timestamp API key is not configured.',
      tokenPath: '',
      requestPath: '',
      mode: 'api-key-rfc3161'
    };
  }
  try {
    const digest = createHash('sha256').update(fs.readFileSync(manifestPath)).digest();
    const query = rfc3161TimestampQuery(digest, { certReq: lawConfig.timestampCertRequest !== false });
    fs.writeFileSync(requestPath, query, { mode: 0o600 });
    const token = await postTimestampQuery(
      lawConfig.timestampApiUrl,
      query,
      timestampApiHeaders(lawConfig),
      Math.max(5, Number(lawConfig.timestampApiTimeoutSeconds || lawConfig.timestampTimeoutSeconds) || 60) * 1000
    );
    fs.writeFileSync(tokenPath, token, { mode: 0o600 });
    return {
      status: token.length ? 'created' : 'missing-token',
      error: token.length ? '' : 'API key timestamp service completed without returning a timestamp token.',
      tokenPath: token.length ? tokenPath : '',
      requestPath,
      mode: 'api-key-rfc3161'
    };
  } catch (error) {
    return {
      status: 'failed',
      error: error.message,
      tokenPath: '',
      requestPath: fs.existsSync(requestPath) ? requestPath : '',
      mode: 'api-key-rfc3161'
    };
  }
}

async function runTimestamp(lawConfig, manifestPath, tokenPath, requestPath) {
  const mode = selectedTimestampMode(lawConfig);
  if (mode === 'disabled') {
    return { status: 'disabled', error: '', tokenPath: '', requestPath: '', mode: 'disabled' };
  }
  if (mode === 'kamusm') {
    return runKamusmTimestamp(lawConfig, manifestPath, tokenPath, requestPath);
  }
  if (mode === 'api-key') {
    return runApiKeyTimestamp(lawConfig, manifestPath, tokenPath, requestPath);
  }
  if (mode === 'command' || lawConfig.timestampCommand) {
    const result = await runTimestampCommand(lawConfig, manifestPath, tokenPath);
    return { ...result, requestPath: '', mode: 'command' };
  }
  return runRfc3161Timestamp(lawConfig, manifestPath, tokenPath, requestPath);
}

async function runExternalSignature(lawConfig, manifestPath, signaturePath) {
  if (!lawConfig.signatureCommand) return null;
  try {
    await execFileAsync(lawConfig.signatureCommand, [manifestPath, signaturePath], {
      timeout: Math.max(5, Number(lawConfig.signatureTimeoutSeconds) || 60) * 1000,
      maxBuffer: 1024 * 1024
    });
    return {
      status: fs.existsSync(signaturePath) ? 'created' : 'missing-signature',
      error: fs.existsSync(signaturePath) ? '' : 'Signature command completed without creating the signature file.',
      signaturePath: fs.existsSync(signaturePath) ? signaturePath : '',
      mode: 'external-command'
    };
  } catch (error) {
    return { status: 'failed', error: error.message, signaturePath: '', mode: 'external-command' };
  }
}

function createHmacManifestSignature(config, manifestPath, signaturePath) {
  const lawConfig = config.law5651 || config.syslog || {};
  const signingKey = String(lawConfig.archiveSigningKey || config.appSecret || '');
  if (!signingKey) {
    return { status: 'missing-key', error: 'Archive signing key is not configured.', signaturePath: '', mode: 'hmac-sha256' };
  }
  try {
    const signature = hmacSha256Hex(signingKey, fs.readFileSync(manifestPath));
    fs.writeFileSync(signaturePath, `${signature}\n`, { mode: 0o600 });
    return {
      status: 'created',
      error: '',
      signaturePath,
      signature,
      algorithm: 'hmac-sha256',
      mode: 'hmac-sha256'
    };
  } catch (error) {
    return { status: 'failed', error: error.message, signaturePath: '', mode: 'hmac-sha256' };
  }
}

async function createManifestSignature(config, manifestPath, signaturePath) {
  const lawConfig = config.law5651 || config.syslog || {};
  const external = await runExternalSignature(lawConfig, manifestPath, signaturePath);
  if (!external) return createHmacManifestSignature(config, manifestPath, signaturePath);
  if (external.status === 'created') return external;
  const fallback = createHmacManifestSignature(config, manifestPath, signaturePath);
  return {
    ...fallback,
    status: fallback.status === 'created' ? 'failed-fallback' : external.status,
    error: fallback.status === 'created'
      ? `External signature failed; local HMAC fallback created. ${external.error}`
      : `External signature failed and HMAC fallback failed. ${external.error}; ${fallback.error}`,
    mode: fallback.status === 'created' ? 'external-command+hmac-fallback' : external.mode
  };
}

function exportFileEntry(filePath, { role, contentType }) {
  return {
    role,
    path: filePath,
    contentType,
    compression: 'gzip',
    bytes: fileSize(filePath),
    sha256: fileHash(filePath)
  };
}

function backupTargetPath(targetDirectory, sourcePath) {
  return path.join(targetDirectory, path.basename(sourcePath));
}

function copyVerifiedFile(sourcePath, targetPath) {
  fs.copyFileSync(sourcePath, targetPath);
  const sourceHash = fileHash(sourcePath);
  const targetHash = fileHash(targetPath);
  if (sourceHash !== targetHash) {
    throw new Error(`Backup verification failed for ${path.basename(sourcePath)}`);
  }
  return fileSize(targetPath);
}

async function hardenBackupFile(lawConfig, targetPath) {
  const warnings = [];
  if (lawConfig.backupReadonly) {
    fs.chmodSync(targetPath, 0o440);
  }
  if (lawConfig.backupImmutableCommand) {
    try {
      await execFileAsync(lawConfig.backupImmutableCommand, [targetPath], {
        timeout: Math.max(5, Number(lawConfig.signatureTimeoutSeconds || 60)) * 1000,
        maxBuffer: 1024 * 1024
      });
    } catch (error) {
      if (lawConfig.backupWormRequired) throw error;
      warnings.push(error.message);
    }
  }
  return warnings;
}

async function backupLaw5651Export({ db, config, exportId, files, logger = console }) {
  const lawConfig = config.law5651 || config.syslog || {};
  const directories = backupDirectories(lawConfig);
  if (!lawConfig.backupEnabled || directories.length === 0) {
    return { status: 'disabled', error: '', results: [] };
  }
  const results = [];
  for (const targetDirectory of directories) {
    try {
      fs.mkdirSync(targetDirectory, { recursive: true, mode: 0o700 });
      let totalBytes = 0;
      const wormWarnings = [];
      for (const filePath of files) {
        if (!filePath) continue;
        const targetPath = backupTargetPath(targetDirectory, filePath);
        totalBytes += copyVerifiedFile(filePath, targetPath);
        wormWarnings.push(...await hardenBackupFile(lawConfig, targetPath));
      }
      const row = db.recordLaw5651Backup({
        exportId,
        targetDirectory,
        status: 'succeeded',
        fileCount: files.filter(Boolean).length,
        totalBytes,
        error: wormWarnings.length ? `WORM hardening warning: ${wormWarnings.join('; ')}` : ''
      });
      if (wormWarnings.length) {
        safeRecordEvent(db, {
          eventType: 'syslog_backup_worm_warning',
          severity: 'warning',
          message: `Syslog archive backup completed but WORM hardening reported warnings for ${targetDirectory}.`,
          detail: { exportId, targetDirectory, warnings: wormWarnings }
        }, logger);
      }
      safeRecordEvent(db, {
        eventType: 'syslog_backup_succeeded',
        severity: 'info',
        message: `Syslog archive backup completed for ${targetDirectory}.`,
        detail: {
          exportId,
          targetDirectory,
          fileCount: row.file_count,
          totalBytes: row.total_bytes,
          readonly: Boolean(lawConfig.backupReadonly),
          immutableCommand: Boolean(lawConfig.backupImmutableCommand)
        }
      }, logger);
      results.push({ targetDirectory, status: 'succeeded', fileCount: Number(row.file_count), totalBytes });
    } catch (error) {
      db.recordLaw5651Backup({
        exportId,
        targetDirectory,
        status: 'failed',
        error: error.message
      });
      safeRecordEvent(db, {
        eventType: 'syslog_backup_failed',
        severity: 'error',
        message: `Syslog archive backup failed for ${targetDirectory}: ${error.message}`,
        detail: { exportId, targetDirectory }
      }, logger);
      logger.warn?.(`Syslog archive backup failed for ${targetDirectory}: ${error.message}`);
      results.push({ targetDirectory, status: 'failed', error: error.message });
    }
  }
  const failures = results.filter(item => item.status === 'failed');
  return {
    status: failures.length === 0 ? 'succeeded' : failures.length === results.length ? 'failed' : 'partial',
    error: failures.map(item => `${item.targetDirectory}: ${item.error}`).join('\n'),
    results
  };
}

function mirrorSyslogMessage(lawConfig, text) {
  if (!lawConfig.remoteMirrorEnabled || !lawConfig.remoteMirrorHost) {
    return Promise.resolve(false);
  }
  const payload = Buffer.from(String(text).endsWith('\n') ? String(text) : `${text}\n`, 'utf8');
  if (lawConfig.remoteMirrorProtocol === 'tcp') {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({
        host: lawConfig.remoteMirrorHost,
        port: lawConfig.remoteMirrorPort
      }, () => {
        socket.end(payload);
      });
      socket.setTimeout(5000, () => socket.destroy(new Error('Remote syslog mirror timed out')));
      socket.on('error', reject);
      socket.on('close', hadError => {
        if (!hadError) resolve(true);
      });
    });
  }
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    socket.send(payload, lawConfig.remoteMirrorPort, lawConfig.remoteMirrorHost, error => {
      socket.close();
      if (error) reject(error);
      else resolve(true);
    });
  });
}

export async function createLaw5651ExportArchive({
  db,
  config,
  exportReason = 'manual',
  periodStartAt = null,
  periodEndAt = null,
  logger = console,
  notificationSender = null
}) {
  const lawConfig = config.law5651 || config.syslog || {};
  const timeZone = lawConfig.timeZone || 'UTC';
  const now = Date.now();
  observeTimestampModeState(db, lawConfig, now);
  let hasPeriod = periodStartAt != null && periodEndAt != null;
  let periodStart = hasPeriod ? Math.trunc(Number(periodStartAt)) : null;
  let periodEnd = hasPeriod ? Math.trunc(Number(periodEndAt)) : null;
  let dateLabel = hasPeriod ? exportPeriodLabel(periodStart, periodEnd, timeZone) : '';
  if (!hasPeriod && timestampEnabled(lawConfig)) {
    const completed = completedDailyWindow(now, timeZone);
    periodStart = completed.periodStart;
    periodEnd = completed.periodEnd;
    dateLabel = completed.dateLabel;
    hasPeriod = true;
  }
  if (hasPeriod && (!Number.isFinite(periodStart) || !Number.isFinite(periodEnd) || periodEnd <= periodStart)) {
    throw new Error('Syslog export period is invalid');
  }
  const safeReason = String(exportReason || 'manual').replace(/[^a-z0-9_-]/giu, '-').toLowerCase();
  if (hasPeriod) {
    const existing = findAutomaticExportByPeriod(db, periodStart, periodEnd);
    const shouldReuseExisting = AUTO_EXPORT_REASONS.includes(safeReason) || timestampDisabledExport(existing);
    if (shouldReuseExisting && automaticExportSatisfied(db, existing, lawConfig)) {
      return law5651ExportResultFromRow(existing);
    }
  }
  const exportDirectory = lawConfig.exportDirectory;
  fs.mkdirSync(exportDirectory, { recursive: true, mode: 0o700 });
  const stamp = law5651FileDate(now, timeZone);
  const periodSuffix = hasPeriod
    ? `-${law5651FileDate(periodStart, timeZone)}_to_${law5651FileDate(periodEnd, timeZone)}`
    : '';
  const basePath = hasPeriod && dateLabel
    ? path.join(exportDirectory, dateLabel)
    : path.join(exportDirectory, `syslog-${safeReason}${periodSuffix}-${stamp}`);
  const logPath = `${basePath}.log`;
  const timestampRequestPath = `${logPath}.tsq`;
  const tokenPath = `${logPath}.tsr`;
  const exportStats = writeLaw5651DailyLogFile(db, logPath, {
    appName: config.appName || 'G-Hotspot',
    timeZone,
    dateLabel: dateLabel || law5651FileDate(now, timeZone).slice(0, 10),
    periodStart,
    periodEnd
  });
  const previousExportHash = db.law5651Summary().lastExport?.exportHash || '';
  const gap = timestampEvidenceGap(db, lawConfig, periodStart, periodEnd, now);
  const timestamp = gap
    ? evidenceGapTimestamp(lawConfig, gap)
    : await runTimestamp(lawConfig, logPath, tokenPath, timestampRequestPath);
  const archive = createExportZipArtifact(lawConfig, [logPath, timestamp.requestPath, timestamp.tokenPath]);
  const exportedFilePath = archive.filePath || logPath;
  const exportHash = fileHash(exportedFilePath);
  const exportRow = db.createLaw5651Export({
    exportReason: safeReason,
    periodStartAt: periodStart,
    periodEndAt: periodEnd,
    filePath: exportedFilePath,
    manifestPath: exportedFilePath,
    timestampRequestPath: timestamp.requestPath,
    timestampTokenPath: timestamp.tokenPath,
    timestampMode: timestamp.mode,
    signaturePath: '',
    signatureMode: 'disabled',
    recordCount: exportStats.recordCount,
    firstSequence: exportStats.firstSequence,
    lastSequence: exportStats.lastSequence,
    firstCreatedAt: exportStats.firstCreatedAt,
    lastCreatedAt: exportStats.lastCreatedAt,
    previousExportHash,
    exportHash,
    timestampStatus: timestamp.status,
    timestampError: timestamp.error,
    signatureStatus: 'disabled',
    signatureError: '',
    backupStatus: 'disabled',
    backupError: ''
  });
  if (timestampEnabled(lawConfig)) {
    const ok = timestamp.status === 'created';
    const mode = selectedTimestampMode(lawConfig);
    const provider = mode === 'kamusm' ? 'KamuSM' : mode === 'api-key' ? 'API key RFC3161 TSA' : 'RFC3161 TSA';
    const payload = {
      eventType: mode === 'kamusm'
        ? (ok ? 'syslog_kamusm_timestamp_succeeded' : 'syslog_kamusm_timestamp_failed')
        : (ok ? 'syslog_timestamp_succeeded' : 'syslog_timestamp_failed'),
      severity: ok ? 'info' : 'error',
      message: ok
        ? `${provider} timestamp created for ${path.basename(logPath)}.`
        : `${provider} timestamp failed for ${path.basename(logPath)}: ${timestamp.error || timestamp.status}`,
      detail: {
        exportId: exportRow.id,
        date: dateLabel,
        filePath: exportedFilePath,
        sourceFilePath: logPath,
        archivePath: archive.filePath,
        archiveEntries: archive.entries,
        sourceFilesDeleted: archive.sourceFilesDeleted,
        timestampRequestPath: timestamp.requestPath,
        timestampTokenPath: timestamp.tokenPath,
        timestampMode: timestamp.mode,
        timestampStatus: timestamp.status,
        timestampError: timestamp.error,
        periodStartAt: periodStart,
        periodEndAt: periodEnd,
        recordCount: exportStats.recordCount
      }
    };
    const row = safeRecordEvent(db, payload, logger);
    if (notificationSender) {
      Promise.resolve(notificationSender(row || payload)).catch(error => {
        logger.warn?.(`System notification could not be sent: ${error.message}`);
      });
    }
  }
  return {
    id: exportRow.id,
    exportReason: safeReason,
    periodStartAt: periodStart,
    periodEndAt: periodEnd,
    filePath: exportedFilePath,
    jsonlPath: '',
    eventsPath: '',
    manifestPath: exportedFilePath,
    sourceFilePath: logPath,
    archivePath: archive.filePath,
    archiveEntries: archive.entries,
    sourceFiles: archive.sourceFiles,
    sourceFilesDeleted: archive.sourceFilesDeleted,
    timestampRequestPath: timestamp.requestPath,
    timestampTokenPath: timestamp.tokenPath,
    timestampMode: timestamp.mode,
    signaturePath: '',
    signatureMode: 'disabled',
    recordCount: exportStats.recordCount,
    firstSequence: exportStats.firstSequence,
    lastSequence: exportStats.lastSequence,
    eventCount: 0,
    exportHash,
    timestampStatus: timestamp.status,
    timestampError: timestamp.error,
    signatureStatus: 'disabled',
    signatureError: '',
    backupStatus: 'disabled',
    backupError: '',
    backupResults: []
  };
}

export async function createLaw5651TimestampDisableExport({
  db,
  config,
  now = Date.now(),
  logger = console,
  notificationSender = null
}) {
  const lawConfig = config.law5651 || config.syslog || {};
  if (!timestampEnabled(lawConfig)) return null;
  const current = Math.trunc(Number(now) || Date.now());
  const timeZone = lawConfig.timeZone || 'UTC';
  const interval = autoExportInterval(lawConfig);
  const previous = latestAutomaticExport(db);
  const first = db.listLaw5651Logs({
    limit: 1,
    order: 'asc',
    createdBefore: current
  }).rows[0] || null;
  if (!first) return null;
  const previousEnd = Math.trunc(Number(previous?.period_end_at));
  let periodStart = Number.isFinite(previousEnd) && previousEnd > 0
    ? previousEnd
    : Math.trunc(Number(first.created_at));
  if (interval.daily) periodStart = previousEnd > 0 ? previousEnd : localDayStartAt(periodStart, timeZone);
  if (!Number.isFinite(periodStart) || periodStart >= current) return null;
  const pending = db.listLaw5651Logs({
    limit: 1,
    createdFrom: periodStart,
    createdBefore: current
  }).total;
  if (pending <= 0) return null;
  return createLaw5651ExportArchive({
    db,
    config,
    exportReason: autoExportReason(lawConfig),
    periodStartAt: periodStart,
    periodEndAt: current,
    logger,
    notificationSender
  });
}

function firstDailyExportStart(db, closedEnd, timeZone) {
  const { rows } = db.listLaw5651Logs({
    limit: 1,
    order: 'asc',
    createdBefore: closedEnd
  });
  return rows[0]
    ? localDayStartAt(Number(rows[0].created_at), timeZone)
    : closedEnd;
}

export function createLaw5651AutoExporter({ db, config, logger = console, notificationSender = null }) {
  let timer = null;
  const state = {
    enabled: false,
    running: false,
    intervalMinutes: 1440,
    schedule: 'daily',
    lastRunAt: null,
    nextRunAt: null,
    lastExportAt: null,
    lastExportId: '',
    lastTimestampAttemptAt: null,
    lastTimestampAttemptSchedule: '',
    nextTimestampAllowedAt: null,
    timestampRateLimited: false,
    lastError: '',
    waitingForGateway: false,
    exportedWindows: 0,
    lastRetentionCleanupAt: null,
    lastRetentionDeleted: 0,
    totalRetentionDeleted: 0,
    lastRetentionDeletedFiles: 0,
    totalRetentionDeletedFiles: 0,
    lastRetentionDeletedBytes: 0,
    totalRetentionDeletedBytes: 0
  };

  function refreshState(now = Date.now()) {
    const lawConfig = config.law5651;
    const timeZone = lawConfig.timeZone || 'UTC';
    observeTimestampModeState(db, lawConfig, now);
    const interval = autoExportInterval(lawConfig);
    const scheduledNextRunAt = interval.daily
      ? nextDailyExportRunAt(now, timeZone)
      : nextIntervalExportRunAt(db, now, interval.intervalMs, lawConfig);
    const timestampNextRunAt = timestampEnabled(lawConfig)
      ? nextAutomaticTimestampAllowedAt(db, state, interval, now, timeZone)
      : null;
    state.enabled = Boolean(lawConfig.enabled && lawConfig.autoExportEnabled !== false);
    state.intervalMinutes = interval.intervalMinutes;
    state.schedule = interval.schedule;
    state.nextTimestampAllowedAt = state.enabled ? timestampNextRunAt : null;
    state.timestampRateLimited = Boolean(
      state.enabled && timestampNextRunAt && Math.trunc(Number(now) || Date.now()) < timestampNextRunAt
    );
    state.nextRunAt = state.enabled
      ? (scheduledNextRunAt && timestampNextRunAt
        ? Math.max(scheduledNextRunAt, timestampNextRunAt)
        : (scheduledNextRunAt || timestampNextRunAt))
      : null;
    return { enabled: state.enabled, timeZone, interval, lawConfig };
  }

  async function exportWindow(periodStart, periodEnd, lawConfig) {
    const existing = findAutomaticExportByPeriod(db, periodStart, periodEnd);
    if (automaticExportSatisfied(db, existing, lawConfig)) return null;
    return createLaw5651ExportArchive({
      db,
      config,
      exportReason: autoExportReason(lawConfig),
      periodStartAt: periodStart,
      periodEndAt: periodEnd,
      logger,
      notificationSender
    });
  }

  async function runDueExports(now = Date.now()) {
    const current = Math.trunc(Number(now) || Date.now());
    const { enabled, timeZone, interval, lawConfig } = refreshState(current);
    if (!enabled || state.running) return [];
    state.running = true;
    state.lastRunAt = current;
    try {
      if (!opnsenseCommunicationReady(db, config, current)) {
        state.waitingForGateway = true;
        refreshState(current);
        return [];
      }
      state.waitingForGateway = false;
      if (!timestampEnabled(lawConfig)) {
        state.lastTimestampAttemptAt = null;
        state.lastTimestampAttemptSchedule = '';
        state.nextTimestampAllowedAt = null;
        state.timestampRateLimited = false;
      }
      const closedEnd = interval.daily
        ? dailyClosedEnd(current, timeZone)
        : current;
      const previous = latestAutomaticExport(db, lawConfig);
      let periodStart;
      if (previous?.period_end_at != null) {
        periodStart = Math.trunc(Number(previous.period_end_at));
      } else if (interval.daily) {
        periodStart = firstDailyExportStart(db, closedEnd, timeZone);
      } else {
        periodStart = firstIntervalExportStart(db, closedEnd);
      }
      const exports = [];
      let windowCount = 0;
      let timestampAttemptedThisRun = false;
      while (periodStart != null && periodStart < closedEnd && windowCount < MAX_AUTO_EXPORT_CATCHUP_WINDOWS) {
        const periodEnd = interval.daily
          ? addLocalDays(periodStart, 1, timeZone)
          : periodStart + interval.intervalMs;
        if (periodEnd > closedEnd) break;
        if (timestampEnabled(lawConfig)) {
          const timestampAllowedAt = nextAutomaticTimestampAllowedAt(db, state, interval, current, timeZone, {
            periodEndAt: periodEnd
          });
          state.nextTimestampAllowedAt = timestampAllowedAt;
          state.timestampRateLimited = Boolean(timestampAllowedAt && current < timestampAllowedAt);
          if (state.timestampRateLimited) {
            state.lastError = '';
            refreshState(current);
            return exports;
          }
        }
        const result = await exportWindow(periodStart, periodEnd, lawConfig);
        if (result) {
          exports.push(result);
          state.lastExportAt = current;
          state.lastExportId = result.id;
          state.exportedWindows += 1;
          if (timestampEnabled(lawConfig) && timestampAttempted(result)) {
            state.lastTimestampAttemptAt = current;
            state.lastTimestampAttemptSchedule = interval.schedule;
            state.nextTimestampAllowedAt = current + interval.intervalMs;
            timestampAttemptedThisRun = true;
          }
        }
        periodStart = periodEnd;
        windowCount += 1;
        if (timestampAttemptedThisRun) break;
      }
      state.lastError = windowCount >= MAX_AUTO_EXPORT_CATCHUP_WINDOWS && periodStart < closedEnd
        ? 'Syslog automatic export catch-up limit reached; remaining windows will continue on the next check.'
        : '';
      if (state.lastError) logger.warn?.(state.lastError);
      const deletedExpired = cleanupExpiredLaw5651DatabaseRecords({ db, config, logger, now: current });
      const deletedFiles = cleanupExpiredLaw5651ExportFiles({ db, config, logger, now: current });
      state.lastRetentionCleanupAt = current;
      state.lastRetentionDeleted = deletedExpired;
      state.totalRetentionDeleted += deletedExpired;
      state.lastRetentionDeletedFiles = deletedFiles.deletedFiles;
      state.totalRetentionDeletedFiles += deletedFiles.deletedFiles;
      state.lastRetentionDeletedBytes = deletedFiles.deletedBytes;
      state.totalRetentionDeletedBytes += deletedFiles.deletedBytes;
      if (deletedExpired > 0 || deletedFiles.deletedFiles > 0) {
        safeRecordEvent(db, {
          eventType: 'syslog_retention_cleanup',
          severity: 'info',
          message: `Syslog retention cleanup removed ${deletedExpired} archived records from the database and ${deletedFiles.deletedFiles} expired export files.`,
          detail: {
            deletedExpired,
            deletedFiles: deletedFiles.deletedFiles,
            deletedBytes: deletedFiles.deletedBytes,
            retentionDays: retentionDaysValue(lawConfig.retentionDays)
          }
        }, logger);
      }
      refreshState(current);
      return exports;
    } catch (error) {
      state.lastError = error.message;
      logger.warn?.(`Syslog automatic export failed: ${error.message}`);
      return [];
    } finally {
      state.running = false;
    }
  }

  return {
    start() {
      if (timer) return true;
      refreshState();
      if (state.enabled) {
        safeRecordEvent(db, {
          eventType: 'syslog_auto_exporter_started',
          severity: 'info',
          message: 'Syslog automatic export service started.',
          detail: { schedule: state.schedule }
        }, logger);
      }
      timer = setInterval(() => {
        runDueExports().catch(error => {
          state.lastError = error.message;
          logger.warn?.(`Syslog automatic export failed: ${error.message}`);
        });
      }, AUTO_EXPORT_CHECK_MS);
      timer.unref();
      runDueExports().catch(error => {
        state.lastError = error.message;
        logger.warn?.(`Syslog automatic export failed: ${error.message}`);
      });
      return true;
    },
    status() {
      refreshState();
      return { ...state };
    },
    runDueExports,
    close() {
      if (!timer) return;
      clearInterval(timer);
      timer = null;
      if (state.enabled) {
        safeRecordEvent(db, {
          eventType: 'syslog_auto_exporter_stopped',
          severity: 'warning',
          message: 'Syslog automatic export service stopped.',
          detail: { schedule: state.schedule }
        }, logger);
      }
    }
  };
}

function timedatectlErrorMessage(error) {
  const detail = [error?.stderr, error?.stdout, error?.message]
    .filter(Boolean)
    .map(value => String(value).trim())
    .filter(Boolean)
    .join(' ')
    .replace(/\s+/gu, ' ')
    .trim();

  if (error?.code === 'ENOENT') {
    return `timedatectl is not available in this environment. ${NTP_STATUS_HINT}`;
  }
  if (/system has not been booted with systemd|failed to connect to bus|d-?bus/iu.test(detail)) {
    return `timedatectl cannot query NTP because systemd or DBus is not available. ${NTP_STATUS_HINT}`;
  }
  if (error?.killed || /timed?\s*out|timeout/iu.test(detail)) {
    return 'timedatectl NTP status check timed out.';
  }
  return detail || 'timedatectl NTP status check failed.';
}

export async function timedatectlNtpStatus(options = {}) {
  const { command = 'timedatectl', execFileRunner = execFileAsync } = options || {};
  try {
    const { stdout } = await execFileRunner(command, ['show', '-p', 'NTPSynchronized', '--value'], {
      timeout: 3000,
      maxBuffer: 64 * 1024
    });
    const value = String(stdout || '').trim().toLowerCase();
    if (['yes', 'true', '1'].includes(value)) return { synced: true, error: '' };
    if (['no', 'false', '0'].includes(value)) return { synced: false, error: '' };
    return { synced: null, error: `Unexpected timedatectl response: ${value || '(empty)'}` };
  } catch (error) {
    return { synced: null, error: timedatectlErrorMessage(error) };
  }
}

export function createLaw5651HealthGuard({
  db,
  config,
  logger = console,
  notificationSender = null,
  storageStatusProvider = law5651StorageStatus,
  ntpStatusProvider = timedatectlNtpStatus,
  nowProvider = Date.now
}) {
  let timer = null;
  let wallBaseline = nowProvider();
  let monoBaseline = performance.now();
  const storageStartupReminderSent = new Set();
  const state = {
    enabled: false,
    running: false,
    lastCheckAt: null,
    lastError: '',
    lastClockDriftMs: 0,
    storage: null,
    ntp: { checkedAt: null, synced: null, error: '' },
    systemTimeZone: currentSystemTimeZone(),
    configuredTimeZone: config.law5651.timeZone || 'UTC',
    bootId: readBootId()
  };

  function lawConfig() {
    return config.law5651 || config.syslog || {};
  }

  function notify(eventPayload, options = {}) {
    if (notificationSender) {
      Promise.resolve(notificationSender(eventPayload, options)).catch(error => {
        logger.warn?.(`System notification could not be sent: ${error.message}`);
      });
    }
  }

  function event(eventType, severity, message, detail = {}) {
    const payload = { eventType, severity, message, detail };
    const row = safeRecordEvent(db, payload, logger);
    notify(row || payload);
    return row;
  }

  function stateValue(key) {
    try {
      return db.getLaw5651State?.(key)?.value ?? null;
    } catch (error) {
      state.lastError = error.message;
      return null;
    }
  }

  function setStateValue(key, value) {
    try {
      db.setLaw5651State?.(key, value);
    } catch (error) {
      state.lastError = error.message;
    }
  }

  function storageNotificationPayload(current, storage) {
    if (current === 'unavailable') {
      return {
        eventType: 'syslog_storage_status_failed',
        severity: 'error',
        message: `Syslog storage status could not be checked: ${storage.error}`,
        detail: storage
      };
    }
    if (current === 'blocking') {
      return {
        eventType: 'syslog_storage_block_threshold_reached',
        severity: 'critical',
        message: `Syslog storage is ${storage.usagePercent}% full.`,
        detail: storage
      };
    }
    if (current === 'warning') {
      return {
        eventType: 'syslog_storage_warning_threshold_reached',
        severity: 'warning',
        message: `Syslog storage is ${storage.usagePercent}% full.`,
        detail: storage
      };
    }
    return null;
  }

  function notificationFrequency(channel) {
    const frequency = config.notifications?.[`${channel}RepeatFrequency`] || 'state-change';
    return Object.hasOwn(STORAGE_NOTIFICATION_INTERVALS, frequency) || frequency === 'state-change'
      ? frequency
      : 'state-change';
  }

  function channelEnabled(channel) {
    const notifications = config.notifications || {};
    const storageKey = `${channel}SyslogStorageEnabled`;
    const storageEnabled = Object.hasOwn(notifications, storageKey)
      ? notifications[storageKey] !== false
      : notifications.syslogStorageEnabled !== false;
    return notifications[`${channel}Enabled`] !== false && storageEnabled;
  }

  function startupNotificationEnabled(channel) {
    return config.notifications?.[`${channel}StartupEnabled`] === true;
  }

  function markStorageNotificationSent(current, channel, now) {
    if (!['warning', 'blocking', 'unavailable'].includes(current)) return;
    setStateValue(`storage_notification_last_${current}_${channel}`, String(Math.trunc(now)));
  }

  function sendStorageReminderIfDue(current, storage, { transitionSent = false, now = nowProvider() } = {}) {
    if (!['warning', 'blocking', 'unavailable'].includes(current)) return;
    if (transitionSent) {
      for (const channel of STORAGE_NOTIFICATION_CHANNELS) {
        if (!channelEnabled(channel)) continue;
        if (startupNotificationEnabled(channel)) storageStartupReminderSent.add(channel);
        markStorageNotificationSent(current, channel, now);
      }
      return;
    }
    const payload = storageNotificationPayload(current, storage);
    if (!payload) return;
    const dueChannels = new Set();
    for (const channel of STORAGE_NOTIFICATION_CHANNELS) {
      if (!channelEnabled(channel)) continue;
      if (startupNotificationEnabled(channel) && !storageStartupReminderSent.has(channel)) {
        storageStartupReminderSent.add(channel);
        markStorageNotificationSent(current, channel, now);
        dueChannels.add(channel);
      }
      const frequency = notificationFrequency(channel);
      if (frequency === 'state-change') continue;
      const interval = STORAGE_NOTIFICATION_INTERVALS[frequency];
      const last = Number(stateValue(`storage_notification_last_${current}_${channel}`) || 0);
      if (Number.isFinite(last) && last > 0 && now - last < interval) continue;
      markStorageNotificationSent(current, channel, now);
      dueChannels.add(channel);
    }
    if (dueChannels.size) notify(payload, { channels: [...dueChannels] });
  }

  function checkClock(now = nowProvider()) {
    const expected = wallBaseline + (performance.now() - monoBaseline);
    const driftMs = Math.trunc(now - expected);
    state.lastClockDriftMs = driftMs;
    const thresholdMs = Math.max(1, Number(lawConfig().clockSkewAlertSeconds || 120)) * 1000;
    if (Math.abs(driftMs) >= thresholdMs) {
      const backward = driftMs < 0;
      event(
        backward ? 'clock_moved_backward' : 'clock_jumped_forward',
        'warning',
        backward
          ? `System clock moved backward by ${Math.abs(Math.round(driftMs / 1000))} seconds.`
          : `System clock jumped forward by ${Math.abs(Math.round(driftMs / 1000))} seconds.`,
        { driftMs, thresholdMs, observedAt: now }
      );
      wallBaseline = now;
      monoBaseline = performance.now();
    }
  }

  function checkTimeZone() {
    const systemTimeZone = currentSystemTimeZone();
    const configuredTimeZone = lawConfig().timeZone || 'UTC';
    const value = `${systemTimeZone}|${configuredTimeZone}`;
    const previous = stateValue('time_zone');
    state.systemTimeZone = systemTimeZone;
    state.configuredTimeZone = configuredTimeZone;
    if (previous && previous !== value) {
      const [previousSystem, previousConfigured] = previous.split('|');
      event('timezone_changed', 'warning', 'Syslog time zone setting changed.', {
        previousSystemTimeZone: previousSystem || '',
        previousConfiguredTimeZone: previousConfigured || '',
        systemTimeZone,
        configuredTimeZone
      });
    }
    setStateValue('time_zone', value);
  }

  function checkBootId() {
    const bootId = readBootId();
    if (!bootId) return;
    const previous = stateValue('boot_id');
    state.bootId = bootId;
    if (!previous) {
      event('system_boot_observed', 'info', 'System boot identifier recorded.', { bootId });
    } else if (previous !== bootId) {
      event('system_boot_detected', 'warning', 'A new system boot was detected.', {
        previousBootId: previous,
        bootId
      });
    }
    setStateValue('boot_id', bootId);
  }

  function checkStorage() {
    const storage = storageStatusProvider({ ...config, law5651: lawConfig() });
    const now = nowProvider();
    state.storage = storage;
    const legacyPrevious = stateValue('storage_warning_active') === '1';
    const previous = stateValue('storage_alert_state') || (legacyPrevious ? 'warning' : 'ok');
    const current = !storage.available
      ? 'unavailable'
      : storage.blocking ? 'blocking' : storage.warning ? 'warning' : 'ok';
    let transitionSent = false;
    if (!storage.available) {
      if (previous !== 'unavailable') {
        event('syslog_storage_status_failed', 'error', `Syslog storage status could not be checked: ${storage.error}`, storage);
        transitionSent = true;
      }
      setStateValue('storage_warning_active', '1');
      setStateValue('storage_alert_state', current);
      sendStorageReminderIfDue(current, storage, { transitionSent, now });
      return;
    }
    if (current === 'warning' && previous !== 'warning') {
      event(
        'syslog_storage_warning_threshold_reached',
        'warning',
        `Syslog storage is ${storage.usagePercent}% full.`,
        storage
      );
      transitionSent = true;
    } else if (current === 'blocking' && previous !== 'blocking') {
      event(
        'syslog_storage_block_threshold_reached',
        'critical',
        `Syslog storage is ${storage.usagePercent}% full.`,
        storage
      );
      transitionSent = true;
    } else if (current === 'ok' && previous !== 'ok') {
      event('syslog_storage_recovered', 'info', `Syslog storage usage recovered to ${storage.usagePercent}%.`, storage);
    }
    setStateValue('storage_warning_active', current === 'ok' ? '0' : '1');
    setStateValue('storage_alert_state', current);
    sendStorageReminderIfDue(current, storage, { transitionSent, now });
  }

  async function checkNtp() {
    if (lawConfig().ntpCheckEnabled === false || !ntpStatusProvider) return;
    const result = await ntpStatusProvider();
    state.ntp = {
      checkedAt: Date.now(),
      synced: result?.synced ?? null,
      error: result?.error || ''
    };
    const value = result?.synced === true ? 'synced' : result?.synced === false ? 'lost' : `unknown:${result?.error || ''}`;
    const previous = stateValue('ntp_status');
    if (previous && previous !== value) {
      if (result?.synced === false) {
        event('ntp_sync_lost', 'critical', 'NTP synchronization was lost.', result);
      } else if (result?.synced === true) {
        event('ntp_sync_restored', 'info', 'NTP synchronization was restored.', result);
      } else {
        event('ntp_status_unknown', 'warning', `NTP synchronization status could not be checked: ${result?.error || 'unknown error'}`, result);
      }
    } else if (!previous && result?.synced === false) {
      event('ntp_sync_lost', 'critical', 'NTP synchronization is not active.', result);
    }
    setStateValue('ntp_status', value);
  }

  async function check(now = nowProvider()) {
    state.enabled = Boolean(lawConfig().enabled);
    if (!state.enabled || state.running) return { ...state };
    state.running = true;
    state.lastCheckAt = Date.now();
    try {
      observeTimestampModeState(db, lawConfig(), now);
      checkClock(now);
      checkTimeZone();
      checkBootId();
      checkStorage();
      await checkNtp();
      state.lastError = '';
    } catch (error) {
      state.lastError = error.message;
      logger.warn?.(`Syslog health guard failed: ${error.message}`);
    } finally {
      state.running = false;
    }
    return { ...state };
  }

  return {
    start() {
      if (timer) return true;
      state.enabled = Boolean(lawConfig().enabled);
      if (!state.enabled) return false;
      event('syslog_service_started', 'info', 'Syslog guard service started.', {
        processId: process.pid,
        configuredTimeZone: lawConfig().timeZone || 'UTC'
      });
      const intervalMs = Math.max(10, Number(lawConfig().healthCheckIntervalSeconds || 60)) * 1000;
      timer = setInterval(() => {
        check().catch(error => {
          state.lastError = error.message;
          logger.warn?.(`Syslog health guard failed: ${error.message}`);
        });
      }, intervalMs);
      timer.unref();
      check().catch(error => {
        state.lastError = error.message;
        logger.warn?.(`Syslog health guard failed: ${error.message}`);
      });
      return true;
    },
    status() {
      state.enabled = Boolean(lawConfig().enabled);
      return { ...state };
    },
    check,
    close() {
      if (!timer) return;
      clearInterval(timer);
      timer = null;
      if (lawConfig().enabled) {
        event('syslog_service_stopped', 'warning', 'Syslog guard service stopped.', { processId: process.pid });
      }
    }
  };
}

export function createLaw5651SyslogServer({
  db,
  config,
  logger = console,
  clientIdentityProvider = null
}) {
  let socket = null;
  let identityRefreshTimer = null;
  let identityRefreshPromise = null;
  let identityCache = new Map();
  let identityAttemptAt = 0;
  let trafficLogFileCleanupAt = Date.now();
  const state = {
    enabled: false,
    listening: false,
    host: config.law5651.syslogHost,
    port: config.law5651.syslogPort,
    received: 0,
    stored: 0,
    ignored: 0,
    lastReceivedAt: null,
    lastStoredAt: null,
    lastError: '',
    lastMessage: '',
    remoteMirrorEnabled: Boolean(config.law5651.remoteMirrorEnabled && config.law5651.remoteMirrorHost),
    remoteMirrorHost: config.law5651.remoteMirrorHost || '',
    remoteMirrorPort: config.law5651.remoteMirrorPort || 514,
    remoteMirrorProtocol: config.law5651.remoteMirrorProtocol || 'udp',
    remoteMirrorSent: 0,
    remoteMirrorLastError: '',
    clientIdentityCacheSize: 0,
    clientIdentityUpdatedAt: null,
    clientIdentityLastError: ''
  };

  async function refreshClientIdentityCache({ force = false } = {}) {
    if (!clientIdentityProvider) return identityCache;
    const now = Date.now();
    if (!force && identityAttemptAt && now - identityAttemptAt < CLIENT_IDENTITY_CACHE_MS) {
      return identityCache;
    }
    if (identityRefreshPromise) return identityRefreshPromise;
    identityAttemptAt = now;
    identityRefreshPromise = Promise.resolve()
      .then(() => clientIdentityProvider())
      .then(rows => {
        identityCache = clientIdentityMap(rows);
        state.clientIdentityCacheSize = identityCache.size;
        state.clientIdentityUpdatedAt = Date.now();
        state.clientIdentityLastError = '';
        return identityCache;
      })
      .catch(error => {
        state.clientIdentityLastError = error.message;
        logger.warn?.(`Syslog client MAC cache could not be refreshed: ${error.message}`);
        return identityCache;
      })
      .finally(() => {
        identityRefreshPromise = null;
      });
    return identityRefreshPromise;
  }

  async function handleMessage(message) {
    const text = message.toString('utf8');
    state.received += 1;
    state.lastReceivedAt = Date.now();
    state.lastMessage = text.slice(0, 500);
    mirrorSyslogMessage(config.law5651, text)
      .then(sent => {
        if (sent) {
          state.remoteMirrorSent += 1;
          state.remoteMirrorLastError = '';
        }
      })
      .catch(error => {
        state.remoteMirrorLastError = error.message;
        safeRecordEvent(db, {
          eventType: 'syslog_remote_mirror_failed',
          severity: 'error',
          message: `Remote syslog mirror failed: ${error.message}`,
          detail: {
            host: config.law5651.remoteMirrorHost,
            port: config.law5651.remoteMirrorPort,
            protocol: config.law5651.remoteMirrorProtocol
          }
        }, logger);
      });
    try {
      syslogNonce += 1;
      const receivedAt = Date.now();
      const identityCache = await refreshClientIdentityCache();
      const settings = trafficLogSettings(config);
      const records = law5651RecordsFromSyslog(
        text,
        config.law5651,
        receivedAt,
        syslogNonce,
        identityCache
      );
      let trafficEligible = 0;
      if (records.length) {
        const result = db.appendLaw5651Logs(records);
        state.stored += result.inserted;
        state.ignored += result.skipped;
        if (result.inserted) state.lastStoredAt = Date.now();
      }
      if (typeof db.appendTrafficLogs === 'function' && settings.enabled) {
        const trafficRecords = trafficLogRecordsFromSyslogMessage(
          text,
          trafficLogScopeConfig(config),
          settings,
          receivedAt,
          syslogNonce,
          identityCache
        );
        trafficEligible = trafficRecords.length;
        const enriched = await enrichTrafficLogRecords(trafficRecords, settings);
        if (enriched.length) {
          const trafficFileConfig = config.databasePath || !db?.filePath
            ? config
            : { ...config, databasePath: db.filePath };
          db.appendTrafficLogs(enriched);
          appendTrafficLogFileRecords(trafficFileConfig, enriched);
          db.cleanupTrafficLogs?.(settings.retentionMinutes);
          if (receivedAt - trafficLogFileCleanupAt >= TRAFFIC_LOG_FILE_CLEANUP_INTERVAL_MS) {
            trafficLogFileCleanupAt = receivedAt;
            cleanupTrafficLogFile(trafficFileConfig, settings.retentionMinutes, receivedAt);
          }
        }
      }
      if (!records.length && !trafficEligible) {
        state.ignored += 1;
      }
    } catch (error) {
      state.lastError = error.message;
      logger.warn?.(`Syslog record could not be stored: ${error.message}`);
    }
  }

  return {
    start() {
      const settings = trafficLogSettings(config);
      state.enabled = Boolean(config.law5651.syslogEnabled && (config.law5651.enabled || settings.enabled));
      state.host = config.law5651.syslogHost;
      state.port = config.law5651.syslogPort;
      state.remoteMirrorEnabled = Boolean(config.law5651.remoteMirrorEnabled && config.law5651.remoteMirrorHost);
      state.remoteMirrorHost = config.law5651.remoteMirrorHost || '';
      state.remoteMirrorPort = config.law5651.remoteMirrorPort || 514;
      state.remoteMirrorProtocol = config.law5651.remoteMirrorProtocol || 'udp';
      if (!state.enabled) return false;
      safeRecordEvent(db, {
        eventType: 'syslog_receiver_starting',
        severity: 'info',
        message: 'Syslog receiver is starting.',
        detail: { host: state.host, port: state.port }
      }, logger);
      socket = dgram.createSocket('udp4');
      socket.on('message', message => {
        handleMessage(message);
      });
      socket.on('error', error => {
        state.listening = false;
        state.lastError = error.message;
        safeRecordEvent(db, {
          eventType: 'syslog_receiver_error',
          severity: 'error',
          message: `Syslog receiver failed: ${error.message}`,
          detail: { host: state.host, port: state.port }
        }, logger);
        logger.warn?.(`Syslog receiver failed: ${error.message}`);
      });
      socket.bind(config.law5651.syslogPort, config.law5651.syslogHost, () => {
        state.listening = true;
        state.lastError = '';
        const address = socket.address();
        state.host = address.address;
        state.port = address.port;
        safeRecordEvent(db, {
          eventType: 'syslog_receiver_started',
          severity: 'info',
          message: `Syslog receiver listening on udp://${state.host}:${state.port}.`,
          detail: { host: state.host, port: state.port }
        }, logger);
        logger.log?.(
          `Syslog receiver listening on udp://${state.host}:${state.port}`
        );
      });
      refreshClientIdentityCache({ force: true }).catch(() => {});
      if (clientIdentityProvider) {
        identityRefreshTimer = setInterval(() => {
          refreshClientIdentityCache({ force: true }).catch(() => {});
        }, CLIENT_IDENTITY_CACHE_MS);
        identityRefreshTimer.unref();
      }
      return true;
    },
    status() {
      return { ...state };
    },
    close() {
      if (!socket) return;
      socket.close();
      socket = null;
      if (identityRefreshTimer) {
        clearInterval(identityRefreshTimer);
        identityRefreshTimer = null;
      }
      state.listening = false;
      safeRecordEvent(db, {
        eventType: 'syslog_receiver_stopped',
        severity: 'warning',
        message: 'Syslog receiver stopped.',
        detail: { host: state.host, port: state.port }
      }, logger);
    }
  };
}
