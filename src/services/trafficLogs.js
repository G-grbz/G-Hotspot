import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns/promises';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { normalizeMac } from '../lib/security.js';
import { ipv4InNetworkList, isPrivateIpv4, normalizeNetworkList } from '../lib/network.js';

const DOMAIN_CACHE_MS = 10 * 60 * 1000;
const DEFAULT_DNS_TIMEOUT_MS = 650;
const TRAFFIC_LOG_DIRECTORY_NAME = 'traffic-records';
const TRAFFIC_LOG_FILE_NAME = 'traffic.log';
const TRAFFIC_LOG_CACHE_LIMIT = 50000;
const TRAFFIC_LOG_INDEX_CHUNK_BYTES = 1024 * 1024;
const TRAFFIC_LOG_WINDOW_INITIAL_SCAN_BYTES = 4 * 1024 * 1024;
const TRAFFIC_LOG_WINDOW_MAX_SCAN_BYTES = 64 * 1024 * 1024;
const TRAFFIC_LOG_DEDUPE_TAIL_BYTES = 16 * 1024 * 1024;
const TRAFFIC_LOG_EFFECTIVE_LOOKBACK_MS = 48 * 60 * 60 * 1000;
const LIVE_TRAFFIC_WINDOW_MS = 60 * 1000;
const INTERFACE_COUNTER_SOURCE = 'opnsense-interface-counter';
const domainCache = new Map();
const fileDedupeCaches = new Map();
const fileRowCaches = new Map();
const fileIndexCaches = new Map();
const fileWindowIndexCaches = new Map();

function sha256Hex(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function cleanText(value, limit = 255) {
  return String(value || '').trim().slice(0, limit);
}

function cleanPort(value) {
  const text = cleanText(value, 16);
  return /^\d{1,5}$/u.test(text) ? text : text;
}

function cleanBytes(value) {
  return Math.max(0, Math.trunc(Number(value) || 0));
}

function cleanNumber(value, fallback = null) {
  if (value == null || value === '') return fallback;
  const number = Math.trunc(Number(value));
  return Number.isFinite(number) ? number : fallback;
}

function cleanTimestamp(value, fallback = Date.now()) {
  const timestamp = Math.trunc(Number(value));
  return Number.isFinite(timestamp) && timestamp > 0 ? timestamp : Math.trunc(Number(fallback) || Date.now());
}

function trafficEnabled(settings = {}) {
  return settings.enabled !== false;
}

function inferDirection({ clientIp = '', sourceIp = '', destinationIp = '', kind = '' }) {
  if (sourceIp && sourceIp === clientIp) return 'outgoing';
  if (destinationIp && destinationIp === clientIp) return 'incoming';
  return kind === 'session' ? 'session' : 'flow';
}

export function trafficLogSettings(config = {}) {
  const settings = config.trafficLogs || {};
  const databaseDirectory = config.databasePath
    ? path.dirname(path.resolve(config.databasePath))
    : path.resolve('data');
  const logDirectory = path.resolve(settings.logDirectory || path.join(databaseDirectory, TRAFFIC_LOG_DIRECTORY_NAME));
  const logFile = path.join(logDirectory, TRAFFIC_LOG_FILE_NAME);
  return {
    enabled: settings.enabled !== false,
    retentionDays: Math.max(1, Math.min(365, Math.trunc(Number(settings.retentionDays) || 30))),
    resolveDomains: settings.resolveDomains !== false,
    liveRefreshSeconds: Math.max(2, Math.min(60, Math.trunc(Number(settings.liveRefreshSeconds) || 5))),
    logDirectory,
    logFile
  };
}

function trafficLogPeriod(period = 'daily', now = Date.now()) {
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

function trafficLogPointLabel(date, bucket) {
  if (['5min', '30min', 'hour'].includes(bucket)) {
    return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
  }
  return [
    date.getFullYear(),
    String(date.getMonth() + 1).padStart(2, '0'),
    String(date.getDate()).padStart(2, '0')
  ].join('-');
}

function customTrafficLogWindow({ startAt = null, endAt = null } = {}, now = Date.now()) {
  const start = cleanNumber(startAt, null);
  const end = cleanNumber(endAt, null);
  if (start == null && end == null) return null;
  const safeStart = Math.max(0, start ?? 0);
  const safeEnd = Math.max(safeStart, end ?? (Math.trunc(Number(now) || Date.now()) + 1));
  return {
    period: 'custom',
    bucket: 'custom',
    bucketMs: 0,
    count: 0,
    startAt: safeStart,
    endAt: safeEnd
  };
}

function trafficLogWindow(options = {}) {
  return customTrafficLogWindow(options, options.now) ||
    trafficLogPeriod(options.period || 'daily', options.now);
}

function trafficLogScanBytesForWindow({ startAt = 0, endAt = 0 } = {}) {
  const spanMs = Math.max(0, Number(endAt || 0) - Number(startAt || 0));
  if (spanMs <= 75 * 60 * 1000) return 8 * 1024 * 1024;
  if (spanMs <= 7 * 60 * 60 * 1000) return 16 * 1024 * 1024;
  if (spanMs <= 13 * 60 * 60 * 1000) return 32 * 1024 * 1024;
  return TRAFFIC_LOG_WINDOW_MAX_SCAN_BYTES;
}

function rowText(value, limit = 255) {
  return String(value || '').trim().slice(0, limit);
}

function recordValue(record, snakeKey, camelKey, fallback = '') {
  return record?.[snakeKey] ?? record?.[camelKey] ?? fallback;
}

function trafficLogFileRowFromRecord(record = {}, { sequence = 0, loggedAt = Date.now() } = {}) {
  const createdAt = cleanTimestamp(recordValue(record, 'created_at', 'createdAt'), loggedAt);
  const startedAt = cleanTimestamp(recordValue(record, 'started_at', 'startedAt'), createdAt);
  const rawKind = rowText(record.kind, 32).toLowerCase();
  const kind = ['flow', 'session', 'interface'].includes(rawKind) ? rawKind : 'session';
  const dedupeKey = rowText(recordValue(record, 'dedupe_key', 'dedupeKey'), 180) ||
    `file|${sha256Hex(JSON.stringify([record.kind, record.source, record.clientIp, record.sourceIp, createdAt]))}`;
  const rawJson = recordValue(record, 'raw_json', 'rawJson', '');
  const row = {
    sequence,
    id: rowText(record.id, 80) || sha256Hex(`${dedupeKey}|${createdAt}`),
    dedupe_key: dedupeKey,
    kind,
    source: rowText(record.source || 'opnsense', 80),
    client_ip: rowText(recordValue(record, 'client_ip', 'clientIp'), 64),
    client_mac: normalizeMac(recordValue(record, 'client_mac', 'clientMac')) || null,
    subscriber_id: rowText(recordValue(record, 'subscriber_id', 'subscriberId'), 128) || null,
    source_ip: rowText(recordValue(record, 'source_ip', 'sourceIp'), 64),
    source_port: rowText(recordValue(record, 'source_port', 'sourcePort'), 16) || null,
    destination_ip: rowText(recordValue(record, 'destination_ip', 'destinationIp'), 64) || null,
    destination_port: rowText(recordValue(record, 'destination_port', 'destinationPort'), 16) || null,
    destination_domain: rowText(recordValue(record, 'destination_domain', 'destinationDomain'), 255) || null,
    protocol: rowText(record.protocol, 32) || null,
    service_type: rowText(recordValue(record, 'service_type', 'serviceType', 'internet-access'), 80),
    direction: rowText(record.direction, 32) || null,
    started_at: startedAt,
    ended_at: cleanNumber(recordValue(record, 'ended_at', 'endedAt'), null),
    download_bytes: cleanBytes(recordValue(record, 'download_bytes', 'downloadBytes')),
    upload_bytes: cleanBytes(recordValue(record, 'upload_bytes', 'uploadBytes')),
    raw_json: rawJson ? String(rawJson).slice(0, 10000) : null,
    created_at: createdAt,
    created_at_iso: new Date(createdAt).toISOString(),
    logged_at: cleanTimestamp(loggedAt),
    logged_at_iso: new Date(cleanTimestamp(loggedAt)).toISOString()
  };
  return row.client_ip && row.source_ip && row.started_at ? row : null;
}

function trafficLogFilePaths(config = {}) {
  const settings = trafficLogSettings(config);
  return {
    directory: settings.logDirectory,
    filePath: settings.logFile
  };
}

function parseTrafficLogFileLine(line, sequence) {
  const text = String(line || '').trim();
  if (!text) return null;
  try {
    const parsed = JSON.parse(text);
    return trafficLogFileRowFromRecord(parsed.record || parsed, {
      sequence,
      loggedAt: parsed.logged_at ?? parsed.loggedAt ?? parsed.logged_at_ms ?? parsed.loggedAtMs ?? Date.now()
    });
  } catch {
    return null;
  }
}

function parseTrafficLogFileText(text, startSequence = 1) {
  if (!text.trim()) return { rows: [], remainder: '', nextSequence: startSequence };
  const lines = text.split(/\n/u);
  const remainder = lines.pop() || '';
  return {
    rows: lines
      .map((line, index) => parseTrafficLogFileLine(line, startSequence + index))
      .filter(Boolean),
    remainder,
    nextSequence: startSequence + lines.length
  };
}

function readFileRange(filePath, start, end) {
  const size = Math.max(0, end - start);
  if (!size) return '';
  const file = fs.openSync(filePath, 'r');
  try {
    const buffer = Buffer.allocUnsafe(size);
    const bytesRead = fs.readSync(file, buffer, 0, size, start);
    return buffer.toString('utf8', 0, bytesRead);
  } finally {
    fs.closeSync(file);
  }
}

function scanTrafficLogFileRange(filePath, {
  start = 0,
  end = null,
  startSequence = 1,
  remainder = '',
  remainderOffset = start,
  onRow = () => {}
} = {}) {
  const file = fs.openSync(filePath, 'r');
  let position = Math.max(0, Math.trunc(Number(start) || 0));
  const safeEnd = Math.max(position, Math.trunc(Number(end) || fs.fstatSync(file).size));
  let sequence = Math.max(1, Math.trunc(Number(startSequence) || 1));
  let carry = Buffer.from(String(remainder || ''), 'utf8');
  let carryOffset = carry.length ? Math.max(0, Math.trunc(Number(remainderOffset) || position)) : position;
  try {
    const buffer = Buffer.allocUnsafe(TRAFFIC_LOG_INDEX_CHUNK_BYTES);
    while (position < safeEnd) {
      const bytesRead = fs.readSync(file, buffer, 0, Math.min(buffer.length, safeEnd - position), position);
      if (!bytesRead) break;
      const chunk = buffer.subarray(0, bytesRead);
      const combinedBaseOffset = carry.length ? carryOffset : position;
      const combined = carry.length ? Buffer.concat([carry, chunk]) : chunk;
      let lineStart = 0;
      for (let index = 0; index < combined.length; index += 1) {
        if (combined[index] !== 10) continue;
        let lineEnd = index;
        if (lineEnd > lineStart && combined[lineEnd - 1] === 13) lineEnd -= 1;
        const lineBuffer = combined.subarray(lineStart, lineEnd);
        const row = parseTrafficLogFileLine(lineBuffer.toString('utf8'), sequence);
        if (row) {
          onRow(row, {
            offset: combinedBaseOffset + lineStart,
            length: lineEnd - lineStart,
            sequence
          });
        }
        sequence += 1;
        lineStart = index + 1;
      }
      carry = combined.subarray(lineStart);
      carryOffset = combinedBaseOffset + lineStart;
      position += bytesRead;
    }
  } finally {
    fs.closeSync(file);
  }
  return {
    remainder: carry.toString('utf8'),
    remainderOffset: carry.length ? carryOffset : safeEnd,
    nextSequence: sequence
  };
}

function trafficLogRawSummary(row = {}) {
  if (!row.raw_json) return null;
  try {
    const raw = JSON.parse(row.raw_json);
    const summary = {
      interface: cleanText(raw.interface || raw.interfaceName || raw.iface, 80),
      interfaceName: cleanText(raw.interfaceName || raw.interface || raw.iface, 80),
      action: cleanText(raw.action, 32)
    };
    return Object.values(summary).some(Boolean) ? JSON.stringify(summary) : null;
  } catch {
    return null;
  }
}

function trafficLogFileIndexEntry(row, { offset = 0, length = 0, sequence = 0 } = {}) {
  const cumulative = trafficLogCumulativeCounters(row);
  return {
    offset,
    length,
    sequence,
    id: row.id,
    dedupe_key: row.dedupe_key,
    kind: row.kind,
    source: row.source,
    client_ip: row.client_ip,
    client_mac: row.client_mac,
    subscriber_id: row.subscriber_id,
    source_ip: row.source_ip,
    source_port: row.source_port,
    destination_ip: row.destination_ip,
    destination_port: row.destination_port,
    destination_domain: row.destination_domain,
    protocol: row.protocol,
    service_type: row.service_type,
    direction: row.direction,
    started_at: Number(row.started_at || 0),
    ended_at: row.ended_at == null ? null : Number(row.ended_at),
    download_bytes: Number(row.download_bytes || 0),
    upload_bytes: Number(row.upload_bytes || 0),
    raw_json: trafficLogRawSummary(row),
    created_at: Number(row.created_at || 0),
    cumulative_download_bytes: cumulative?.downloadBytes ?? null,
    cumulative_upload_bytes: cumulative?.uploadBytes ?? null,
    cumulative_key: cumulative ? trafficLogSessionKey(row) : '',
    is_interface_counter: isInterfaceCounterRow(row)
  };
}

function applyEffectiveTrafficLogIndexEntries(entries = []) {
  const counters = new Map();
  const chronological = [...entries].sort((left, right) =>
    Number(left.created_at || 0) - Number(right.created_at || 0) ||
    Number(left.sequence || 0) - Number(right.sequence || 0)
  );
  for (const entry of chronological) {
    const download = Number(entry.cumulative_download_bytes);
    const upload = Number(entry.cumulative_upload_bytes);
    if (!entry.cumulative_key || !Number.isFinite(download) || !Number.isFinite(upload)) {
      entry.effective_download_bytes = Number(entry.download_bytes || 0);
      entry.effective_upload_bytes = Number(entry.upload_bytes || 0);
      continue;
    }
    const previous = counters.get(entry.cumulative_key);
    counters.set(entry.cumulative_key, { downloadBytes: download, uploadBytes: upload });
    if (!previous) {
      entry.effective_download_bytes = 0;
      entry.effective_upload_bytes = 0;
      continue;
    }
    entry.effective_download_bytes = download >= previous.downloadBytes
      ? download - previous.downloadBytes
      : download;
    entry.effective_upload_bytes = upload >= previous.uploadBytes
      ? upload - previous.uploadBytes
      : upload;
  }
  return entries;
}

function readTrafficLogFileIndex(filePath) {
  if (!fs.existsSync(filePath)) {
    fileIndexCaches.delete(filePath);
    return { entries: [], size: 0, mtimeMs: 0, remainder: '', remainderOffset: 0, nextSequence: 1 };
  }
  const stat = fs.statSync(filePath);
  const cached = fileIndexCaches.get(filePath);
  if (cached && cached.size === stat.size && cached.mtimeMs === stat.mtimeMs) return cached;
  if (cached && stat.size > cached.size) {
    const nextEntries = [];
    const parsed = scanTrafficLogFileRange(filePath, {
      start: cached.size,
      end: stat.size,
      startSequence: cached.nextSequence,
      remainder: cached.remainder,
      remainderOffset: cached.remainderOffset,
      onRow: (row, meta) => nextEntries.push(trafficLogFileIndexEntry(row, meta))
    });
    const index = {
      entries: applyEffectiveTrafficLogIndexEntries(cached.entries.concat(nextEntries)),
      size: stat.size,
      mtimeMs: stat.mtimeMs,
      remainder: parsed.remainder,
      remainderOffset: parsed.remainderOffset,
      nextSequence: parsed.nextSequence
    };
    fileIndexCaches.set(filePath, index);
    return index;
  }
  const entries = [];
  const parsed = scanTrafficLogFileRange(filePath, {
    start: 0,
    end: stat.size,
    startSequence: 1,
    onRow: (row, meta) => entries.push(trafficLogFileIndexEntry(row, meta))
  });
  const index = {
    entries: applyEffectiveTrafficLogIndexEntries(entries),
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    remainder: parsed.remainder,
    remainderOffset: parsed.remainderOffset,
    nextSequence: parsed.nextSequence
  };
  fileIndexCaches.set(filePath, index);
  return index;
}

function readTrafficLogFileTailEntries(filePath, maxBytes = TRAFFIC_LOG_DEDUPE_TAIL_BYTES) {
  if (!fs.existsSync(filePath)) return [];
  const stat = fs.statSync(filePath);
  const bytes = Math.max(0, Math.min(stat.size, Math.trunc(Number(maxBytes) || 0)));
  const entries = [];
  scanTrafficLogFileRange(filePath, {
    start: Math.max(0, stat.size - bytes),
    end: stat.size,
    startSequence: 1,
    onRow: (row, meta) => entries.push(trafficLogFileIndexEntry(row, meta))
  });
  return entries;
}

function readTrafficLogFileWindowIndex(filePath, {
  startAt = 0,
  endAt = Date.now() + 1,
  lookbackMs = TRAFFIC_LOG_EFFECTIVE_LOOKBACK_MS,
  initialScanBytes = TRAFFIC_LOG_WINDOW_INITIAL_SCAN_BYTES,
  maxScanBytes = TRAFFIC_LOG_WINDOW_MAX_SCAN_BYTES
} = {}) {
  if (!fs.existsSync(filePath)) {
    fileWindowIndexCaches.delete(filePath);
    return { entries: [], partial: false, scannedBytes: 0, size: 0, oldestCreatedAt: null };
  }
  const stat = fs.statSync(filePath);
  const safeEndAt = Math.trunc(Number(endAt) || Date.now() + 1);
  const safeStartAt = Math.max(0, Math.trunc(Number(startAt) || 0));
  const targetStartAt = Math.max(0, safeStartAt - Math.max(0, Math.trunc(Number(lookbackMs) || 0)));
  let scanBytes = Math.min(
    stat.size,
    Math.max(TRAFFIC_LOG_INDEX_CHUNK_BYTES, Math.trunc(Number(initialScanBytes) || TRAFFIC_LOG_WINDOW_INITIAL_SCAN_BYTES))
  );
  const maxBytes = Math.min(
    stat.size,
    Math.max(scanBytes, Math.trunc(Number(maxScanBytes) || TRAFFIC_LOG_WINDOW_MAX_SCAN_BYTES))
  );
  const cacheKey = [
    stat.size,
    stat.mtimeMs,
    safeStartAt,
    safeEndAt,
    targetStartAt,
    scanBytes,
    maxBytes
  ].join('|');
  const cached = fileWindowIndexCaches.get(filePath)?.get(cacheKey);
  if (cached) return cached;

  while (true) {
    const start = Math.max(0, stat.size - scanBytes);
    const parsedEntries = [];
    scanTrafficLogFileRange(filePath, {
      start,
      end: stat.size,
      startSequence: 1,
      onRow: (row, meta) => parsedEntries.push(trafficLogFileIndexEntry(row, meta))
    });
    let oldestCreatedAt = null;
    const entries = [];
    for (const entry of parsedEntries) {
      const createdAt = Number(entry.created_at || 0);
      if (!Number.isFinite(createdAt) || createdAt <= 0) continue;
      oldestCreatedAt = oldestCreatedAt == null ? createdAt : Math.min(oldestCreatedAt, createdAt);
      if (createdAt >= targetStartAt && createdAt < safeEndAt) entries.push(entry);
    }
    const coversStart = start === 0 || (oldestCreatedAt != null && oldestCreatedAt <= targetStartAt);
    if (coversStart || scanBytes >= maxBytes || start === 0) {
      const result = {
        entries: applyEffectiveTrafficLogIndexEntries(entries),
        partial: !coversStart,
        scannedBytes: stat.size - start,
        size: stat.size,
        oldestCreatedAt
      };
      const fileCache = fileWindowIndexCaches.get(filePath) || new Map();
      fileCache.set(cacheKey, result);
      if (fileCache.size > 24) fileCache.delete(fileCache.keys().next().value);
      fileWindowIndexCaches.set(filePath, fileCache);
      return result;
    }
    scanBytes = Math.min(maxBytes, scanBytes * 2);
  }
}

function trafficLogFileIndexRow(entry = {}) {
  return {
    sequence: entry.sequence,
    id: entry.id,
    dedupe_key: entry.dedupe_key,
    kind: entry.kind,
    source: entry.source,
    client_ip: entry.client_ip,
    client_mac: entry.client_mac,
    subscriber_id: entry.subscriber_id,
    source_ip: entry.source_ip,
    source_port: entry.source_port,
    destination_ip: entry.destination_ip,
    destination_port: entry.destination_port,
    destination_domain: entry.destination_domain,
    protocol: entry.protocol,
    service_type: entry.service_type,
    direction: entry.direction,
    started_at: entry.started_at,
    ended_at: entry.ended_at,
    download_bytes: entry.download_bytes,
    upload_bytes: entry.upload_bytes,
    raw_json: entry.raw_json,
    created_at: entry.created_at,
    effective_download_bytes: entry.effective_download_bytes ?? entry.download_bytes ?? 0,
    effective_upload_bytes: entry.effective_upload_bytes ?? entry.upload_bytes ?? 0
  };
}

function readTrafficLogFileRows(filePath) {
  if (!fs.existsSync(filePath)) {
    fileRowCaches.delete(filePath);
    return [];
  }
  const stat = fs.statSync(filePath);
  const cached = fileRowCaches.get(filePath);
  if (cached && cached.size === stat.size && cached.mtimeMs === stat.mtimeMs) return cached.rows;
  if (cached && stat.size > cached.size) {
    const parsed = parseTrafficLogFileText(
      `${cached.remainder || ''}${readFileRange(filePath, cached.size, stat.size)}`,
      cached.nextSequence
    );
    const rows = cached.rows.concat(parsed.rows);
    fileRowCaches.set(filePath, {
      rows,
      size: stat.size,
      mtimeMs: stat.mtimeMs,
      remainder: parsed.remainder,
      nextSequence: parsed.nextSequence
    });
    return rows;
  }
  const text = fs.readFileSync(filePath, 'utf8');
  const parsed = parseTrafficLogFileText(text);
  const rows = parsed.rows;
  fileRowCaches.set(filePath, {
    rows,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    remainder: parsed.remainder,
    nextSequence: parsed.nextSequence
  });
  return rows;
}

function seedDedupeCache(filePath) {
  if (fileDedupeCaches.has(filePath)) return fileDedupeCaches.get(filePath);
  const keys = new Set();
  for (const row of readTrafficLogFileTailEntries(filePath)) {
    if (row.dedupe_key) keys.add(row.dedupe_key);
  }
  fileDedupeCaches.set(filePath, keys);
  return keys;
}

function rememberDedupeKey(keys, key) {
  if (!key) return;
  keys.add(key);
  if (keys.size <= TRAFFIC_LOG_CACHE_LIMIT) return;
  const removeCount = Math.max(1, keys.size - TRAFFIC_LOG_CACHE_LIMIT);
  let removed = 0;
  for (const existing of keys) {
    keys.delete(existing);
    removed += 1;
    if (removed >= removeCount) break;
  }
}

export function appendTrafficLogFileRecords(config = {}, records = [], { now = Date.now() } = {}) {
  const settings = trafficLogSettings(config);
  const { directory, filePath } = trafficLogFilePaths(config);
  if (!settings.enabled) {
    return { enabled: false, inserted: 0, skipped: records.length, filePath };
  }
  if (!records.length) {
    return { enabled: true, inserted: 0, skipped: 0, filePath };
  }
  const keys = seedDedupeCache(filePath);
  const lines = [];
  let skipped = 0;
  for (const record of records) {
    const row = trafficLogFileRowFromRecord(record, { loggedAt: now });
    if (!row) {
      skipped += 1;
      continue;
    }
    if (row.dedupe_key && keys.has(row.dedupe_key)) {
      skipped += 1;
      continue;
    }
    lines.push(JSON.stringify(row));
    rememberDedupeKey(keys, row.dedupe_key);
  }
  if (lines.length) {
    fs.mkdirSync(directory, { recursive: true });
    fs.appendFileSync(filePath, `${lines.join('\n')}\n`, { mode: 0o600 });
    fileWindowIndexCaches.delete(filePath);
  }
  return { enabled: true, inserted: lines.length, skipped, filePath };
}

export function cleanupTrafficLogFile(config = {}, retentionDays = 30, now = Date.now()) {
  const { directory, filePath } = trafficLogFilePaths(config);
  if (!fs.existsSync(filePath)) return { deleted: 0, kept: 0, filePath };
  const days = Math.max(1, Math.trunc(Number(retentionDays) || 30));
  const cutoff = Math.trunc(Number(now) || Date.now()) - days * 24 * 60 * 60 * 1000;
  const rows = readTrafficLogFileRows(filePath);
  const kept = rows.filter(row => Number(row.created_at || 0) >= cutoff);
  const deleted = rows.length - kept.length;
  if (deleted <= 0) return { deleted: 0, kept: kept.length, filePath };
  fs.mkdirSync(directory, { recursive: true });
  const tempPath = `${filePath}.tmp`;
  fs.writeFileSync(tempPath, kept.map(row => JSON.stringify(row)).join('\n') + (kept.length ? '\n' : ''), {
    mode: 0o600
  });
  fs.renameSync(tempPath, filePath);
  fileDedupeCaches.delete(filePath);
  fileRowCaches.delete(filePath);
  fileIndexCaches.delete(filePath);
  fileWindowIndexCaches.delete(filePath);
  seedDedupeCache(filePath);
  return { deleted, kept: kept.length, filePath };
}

function trafficLogCumulativeCounters(row) {
  if ((row?.kind !== 'session' && row?.source !== INTERFACE_COUNTER_SOURCE) || !row.raw_json) return null;
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

function trafficLogSessionKey(row) {
  let sessionId = '';
  let interfaceName = '';
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
      interfaceName = String(raw.interfaceName || raw.interface || '');
    } catch {}
  }
  return [
    row.source || '',
    row.kind || '',
    interfaceName || '',
    sessionId || 'session',
    row.subscriber_id || '',
    row.client_ip || '',
    row.source_ip || ''
  ].join('|');
}

export function effectiveTrafficLogFileRows(rows = []) {
  const counters = new Map();
  return [...rows]
    .sort((left, right) =>
      Number(left.created_at || 0) - Number(right.created_at || 0) ||
      Number(left.sequence || 0) - Number(right.sequence || 0)
    )
    .map(row => {
      const cumulative = trafficLogCumulativeCounters(row);
      if (!cumulative) {
        return {
          ...row,
          effective_download_bytes: Number(row.download_bytes || 0),
          effective_upload_bytes: Number(row.upload_bytes || 0)
        };
      }
      const key = trafficLogSessionKey(row);
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

function trafficLogRowMatches(row, {
  search = '',
  kind = '',
  sourceIp = '',
  sourcePort = '',
  destinationIp = '',
  destinationPort = ''
} = {}) {
  const term = String(search || '').trim().toLowerCase();
  if (term) {
    const haystack = [
      row.client_ip,
      row.client_mac,
      row.subscriber_id,
      row.source_ip,
      row.source_port,
      row.destination_ip,
      row.destination_port,
      row.destination_domain,
      row.protocol,
      row.service_type
    ].map(value => String(value || '').toLowerCase());
    if (!haystack.some(value => value.includes(term))) return false;
  }
  if ((kind === 'session' || kind === 'flow') && row.kind !== kind) return false;
  const sourceIpText = String(sourceIp || '').trim();
  if (sourceIpText && !String(row.source_ip || '').includes(sourceIpText)) return false;
  const sourcePortText = String(sourcePort || '').trim();
  if (sourcePortText && String(row.source_port || '') !== sourcePortText) return false;
  const destinationIpText = String(destinationIp || '').trim();
  if (destinationIpText && !String(row.destination_ip || '').includes(destinationIpText)) return false;
  const destinationPortText = String(destinationPort || '').trim();
  if (destinationPortText && String(row.destination_port || '') !== destinationPortText) return false;
  return true;
}

function publicDestinationIp(value) {
  const text = cleanText(value, 64);
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

function siteLabel(row) {
  const domain = cleanText(row.destination_domain, 255)
    .toLowerCase()
    .replace(/\.$/u, '')
    .replace(/^www\./u, '');
  if (domain.includes('.')) return domain;
  return publicDestinationIp(row.destination_ip);
}

function isDnsResolverTraffic(row) {
  const port = String(row.destination_port || '').trim();
  const service = String(row.service_type || '').trim().toLowerCase();
  return port === '53' || service === 'dns' || service === 'domain';
}

function interfaceCounterTotals(sample = {}) {
  const interfaceName = cleanText(sample.interfaceName || sample.name || sample.interface || 'wan', 64) || 'wan';
  const rxBytes = cleanBytes(sample.rxBytes);
  const txBytes = cleanBytes(sample.txBytes);
  const lanLike = interfaceName.toLowerCase().includes('lan');
  return {
    interfaceName,
    rxBytes,
    txBytes,
    downloadBytes: lanLike ? txBytes : rxBytes,
    uploadBytes: lanLike ? rxBytes : txBytes
  };
}

function isInterfaceCounterRow(row) {
  return row?.source === INTERFACE_COUNTER_SOURCE || row?.service_type === 'interface-counter';
}

function safeNetworkList(value) {
  try {
    return normalizeNetworkList(value);
  } catch {
    return 'any';
  }
}

function trafficLogClientInScope(clientIp, networks = 'any') {
  if (isIP(clientIp) !== 4) return false;
  const safeNetworks = safeNetworkList(networks);
  if (safeNetworks === 'any') return isPrivateIpv4(clientIp);
  try {
    return ipv4InNetworkList(clientIp, safeNetworks);
  } catch {
    return false;
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

function trafficLogClientChartRowAllowed(row, { networks = 'any', excludedInterfaces = [] } = {}) {
  if (!trafficLogClientInScope(row.client_ip, networks)) return false;
  if (row.kind !== 'flow') return true;
  const interfaceName = trafficLogInterfaceName(row);
  if (!interfaceName || !excludedInterfaces.includes(interfaceName)) return true;
  return false;
}

export function topTrafficLogFileSites(config = {}, { hours = 6, limit = 10, sort = 'visits', now = Date.now() } = {}) {
  const settings = trafficLogSettings(config);
  const { filePath } = trafficLogFilePaths(config);
  const safeHours = [1, 6, 12, 24].includes(Number(hours)) ? Number(hours) : 6;
  const safeLimit = Math.max(1, Math.min(25, Math.trunc(Number(limit) || 10)));
  const safeSort = sort === 'bytes' ? 'bytes' : 'visits';
  const endAt = Math.trunc(Number(now) || Date.now()) + 1;
  const startAt = endAt - safeHours * 60 * 60 * 1000;
  const scanBytes = trafficLogScanBytesForWindow({ startAt, endAt });
  const index = readTrafficLogFileWindowIndex(filePath, {
    startAt,
    endAt,
    initialScanBytes: scanBytes,
    maxScanBytes: scanBytes
  });
  const groups = new Map();
  for (const row of index.entries) {
    const createdAt = Number(row.created_at || 0);
    if (createdAt < startAt || createdAt >= endAt) continue;
    if (row.is_interface_counter) continue;
    if (isDnsResolverTraffic(row)) continue;
    const label = siteLabel(row);
    if (!label) continue;
    const existing = groups.get(label) || {
      site: label,
      visits: 0,
      clients: new Set(),
      downloadBytes: 0,
      uploadBytes: 0,
      lastSeenAt: 0
    };
    existing.visits += 1;
    if (row.client_ip) existing.clients.add(row.client_ip);
    existing.downloadBytes += Number(row.effective_download_bytes ?? row.download_bytes ?? 0);
    existing.uploadBytes += Number(row.effective_upload_bytes ?? row.upload_bytes ?? 0);
    existing.lastSeenAt = Math.max(existing.lastSeenAt, createdAt);
    groups.set(label, existing);
  }
  const rows = [...groups.values()]
    .sort((left, right) => {
      const leftBytes = left.downloadBytes + left.uploadBytes;
      const rightBytes = right.downloadBytes + right.uploadBytes;
      if (safeSort === 'bytes') {
        return rightBytes - leftBytes ||
          right.visits - left.visits ||
          left.site.localeCompare(right.site);
      }
      return right.visits - left.visits ||
        rightBytes - leftBytes ||
        left.site.localeCompare(right.site);
    })
    .slice(0, safeLimit)
    .map(row => ({
      site: row.site,
      visits: row.visits,
      clients: row.clients.size,
      downloadBytes: Math.round(row.downloadBytes),
      uploadBytes: Math.round(row.uploadBytes),
      totalBytes: Math.round(row.downloadBytes + row.uploadBytes),
      lastSeenAt: row.lastSeenAt || null
    }));
  return {
    source: 'traffic_log_file',
    logFile: settings.logFile,
    hours: safeHours,
    limit: safeLimit,
    sort: safeSort,
    startAt,
    endAt,
    partial: index.partial,
    scannedBytes: index.scannedBytes,
    logFileBytes: index.size,
    totalVisits: rows.reduce((sum, row) => sum + row.visits, 0),
    totalSites: groups.size,
    rows
  };
}

export function topTrafficLogFileClients(config = {}, { hours = 6, limit = 10, networks = 'any', excludedInterfaces = [], now = Date.now() } = {}) {
  const settings = trafficLogSettings(config);
  const { filePath } = trafficLogFilePaths(config);
  const safeHours = [1, 6, 12, 24].includes(Number(hours)) ? Number(hours) : 6;
  const safeLimit = Math.max(1, Math.min(25, Math.trunc(Number(limit) || 10)));
  const endAt = Math.trunc(Number(now) || Date.now()) + 1;
  const startAt = endAt - safeHours * 60 * 60 * 1000;
  const blockedInterfaces = [...new Set(excludedInterfaces.map(value => String(value || '').trim().toLowerCase()).filter(Boolean))];
  const scanBytes = trafficLogScanBytesForWindow({ startAt, endAt });
  const index = readTrafficLogFileWindowIndex(filePath, {
    startAt,
    endAt,
    initialScanBytes: scanBytes,
    maxScanBytes: scanBytes
  });
  const groups = new Map();
  const rowsInWindow = index.entries.filter(row => {
    const createdAt = Number(row.created_at || 0);
    return createdAt >= startAt && createdAt < endAt;
  });
  for (const row of effectiveTrafficLogFileRows(rowsInWindow)) {
    if (row.is_interface_counter || isInterfaceCounterRow(row) || !trafficLogClientChartRowAllowed(row, { networks, excludedInterfaces: blockedInterfaces })) continue;
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
      existing.sessionRecords += 1;
      existing.sessionDownloadBytes += Number(row.effective_download_bytes ?? row.download_bytes ?? 0);
      existing.sessionUploadBytes += Number(row.effective_upload_bytes ?? row.upload_bytes ?? 0);
    } else {
      existing.flowRecords += 1;
      existing.flowDownloadBytes += Number(row.effective_download_bytes ?? row.download_bytes ?? 0);
      existing.flowUploadBytes += Number(row.effective_upload_bytes ?? row.upload_bytes ?? 0);
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
      downloadBytes: Math.round(downloadBytes),
      uploadBytes: Math.round(uploadBytes),
      totalBytes: Math.round(downloadBytes + uploadBytes),
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
    source: 'traffic_log_file',
    logFile: settings.logFile,
    hours: safeHours,
    limit: safeLimit,
    networks: safeNetworkList(networks),
    excludedInterfaces: blockedInterfaces,
    startAt,
    endAt,
    partial: index.partial,
    scannedBytes: index.scannedBytes,
    logFileBytes: index.size,
    totalRecords: allRows.reduce((sum, row) => sum + row.records, 0),
    totalClients: allRows.length,
    rows
  };
}

export function listTrafficLogFileRecords(config = {}, {
  search = '',
  kind = '',
  period = 'daily',
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
  const settings = trafficLogSettings(config);
  const { filePath } = trafficLogFilePaths(config);
  const window = trafficLogWindow({ period, startAt, endAt, now });
  const direction = order === 'asc' ? 'ASC' : 'DESC';
  const safeOffset = Math.max(0, Math.trunc(Number(offset) || 0));
  const safeLimit = Math.max(1, Math.trunc(Number(limit) || 150));
  const liveEndAt = Math.trunc(Number(now) || Date.now()) + 1;
  const liveStartAt = Math.max(0, liveEndAt - LIVE_TRAFFIC_WINDOW_MS);
  const scanWindow = {
    startAt: Math.min(window.startAt, liveStartAt),
    endAt: Math.max(window.endAt, liveEndAt)
  };
  const scanBytes = trafficLogScanBytesForWindow(scanWindow);
  const index = readTrafficLogFileWindowIndex(filePath, {
    ...scanWindow,
    initialScanBytes: scanBytes,
    maxScanBytes: scanBytes
  });
  const entries = index.entries;
  const clients = new Set();
  const liveClients = new Set();
  const pageRows = [];
  const liveWindowSeconds = Math.max(1, Math.round(LIVE_TRAFFIC_WINDOW_MS / 1000));
  const filters = { search, kind, sourceIp, sourcePort, destinationIp, destinationPort };
  let rows = 0;
  let skipped = 0;
  let downloadBytes = 0;
  let uploadBytes = 0;
  let liveRecords = 0;
  let liveDownloadBytes = 0;
  let liveUploadBytes = 0;
  let lastCreatedAt = null;
  const scanEntry = entry => {
    if (entry.is_interface_counter) return;
    if (!trafficLogRowMatches(entry, filters)) return;
    const createdAt = Number(entry.created_at || 0);
    const effectiveDownload = Number(entry.effective_download_bytes ?? entry.download_bytes ?? 0);
    const effectiveUpload = Number(entry.effective_upload_bytes ?? entry.upload_bytes ?? 0);
    if (createdAt >= liveStartAt && createdAt < liveEndAt) {
      liveRecords += 1;
      liveDownloadBytes += effectiveDownload;
      liveUploadBytes += effectiveUpload;
      if (entry.client_ip) liveClients.add(entry.client_ip);
    }
    if (createdAt < window.startAt || createdAt >= window.endAt) return;
    rows += 1;
    downloadBytes += effectiveDownload;
    uploadBytes += effectiveUpload;
    if (entry.client_ip) clients.add(entry.client_ip);
    lastCreatedAt = lastCreatedAt == null ? createdAt : Math.max(lastCreatedAt, createdAt);
    if (skipped < safeOffset) {
      skipped += 1;
      return;
    }
    if (pageRows.length < safeLimit) pageRows.push(trafficLogFileIndexRow(entry));
  };
  if (direction === 'ASC') {
    for (const entry of entries) scanEntry(entry);
  } else {
    for (let index = entries.length - 1; index >= 0; index -= 1) scanEntry(entries[index]);
  }
  return {
    source: 'traffic_log_file',
    logFile: settings.logFile,
    rows: pageRows,
    total: rows,
    partial: index.partial,
    scannedBytes: index.scannedBytes,
    logFileBytes: index.size,
    summary: {
      records: rows,
      clients: clients.size,
      downloadBytes,
      uploadBytes,
      liveWindowSeconds,
      liveRecords,
      liveClients: liveClients.size,
      liveDownloadBytes,
      liveUploadBytes,
      liveDownloadBps: Math.round(liveDownloadBytes / liveWindowSeconds),
      liveUploadBps: Math.round(liveUploadBytes / liveWindowSeconds),
      lastCreatedAt
    }
  };
}

export function trafficLogFileSeries(config = {}, { period = 'daily', now = Date.now() } = {}) {
  const settings = trafficLogSettings(config);
  const { filePath } = trafficLogFilePaths(config);
  const window = trafficLogPeriod(period, now);
  const points = Array.from({ length: window.count }, (_, index) => {
    const startAt = window.startAt + index * window.bucketMs;
    const date = new Date(startAt);
    const key = trafficLogPointLabel(date, window.bucket);
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
  const lookbackAt = Math.max(0, Number(window.startAt || 0) - 48 * 60 * 60 * 1000);
  const scanBytes = trafficLogScanBytesForWindow(window);
  const index = readTrafficLogFileWindowIndex(filePath, {
    startAt: lookbackAt,
    endAt: window.endAt,
    lookbackMs: 0,
    initialScanBytes: scanBytes,
    maxScanBytes: scanBytes
  });
  const rawRows = index.entries;
  const interfaceRows = rawRows
    .filter(row => row.is_interface_counter && Number(row.created_at || 0) >= window.startAt);
  const rows = (interfaceRows.length
    ? interfaceRows
    : rawRows.filter(row => !row.is_interface_counter))
    .filter(row => Number(row.created_at || 0) >= window.startAt);
  for (const row of rows) {
    const index = Math.floor((Number(row.created_at || 0) - window.startAt) / window.bucketMs);
    if (index < 0 || index >= points.length) continue;
    points[index].downloadBytes += Number(row.effective_download_bytes ?? row.download_bytes ?? 0);
    points[index].uploadBytes += Number(row.effective_upload_bytes ?? row.upload_bytes ?? 0);
    points[index].records += 1;
  }
  const totalDownloadBytes = points.reduce((sum, point) => sum + point.downloadBytes, 0);
  const totalUploadBytes = points.reduce((sum, point) => sum + point.uploadBytes, 0);
  const peak = points.reduce((best, point) =>
    point.downloadBytes + point.uploadBytes > best.downloadBytes + best.uploadBytes ? point : best
  , points[0] || { downloadBytes: 0, uploadBytes: 0, label: '' });
  const liveStartAt = Math.trunc(Number(now) || Date.now()) - 5 * 60 * 1000;
  const liveRows = rawRows.filter(row =>
    Number(row.created_at || 0) >= liveStartAt &&
    (!interfaceRows.length || isInterfaceCounterRow(row)));
  return {
    ...window,
    source: interfaceRows.length ? 'traffic_log_wan_interface' : 'traffic_log_file',
    logFile: settings.logFile,
    partial: index.partial,
    scannedBytes: index.scannedBytes,
    logFileBytes: index.size,
    interfaceName: interfaceRows.length ? interfaceRows[0].client_ip : '',
    points,
    summary: {
      totalDownloadBytes,
      totalUploadBytes,
      totalBytes: totalDownloadBytes + totalUploadBytes,
      records: rows.length,
      peakLabel: peak.label,
      peakBytes: Number(peak.downloadBytes || 0) + Number(peak.uploadBytes || 0),
      liveClients: new Set(liveRows.map(row => row.client_ip).filter(Boolean)).size,
      liveRecords: liveRows.length
    }
  };
}

export function trafficLogRecordFromInterfaceCounters(sample = {}, settings = {}) {
  if (!trafficEnabled(settings)) return null;
  const sampledAt = cleanTimestamp(sample.sampledAt, Date.now());
  const totals = interfaceCounterTotals(sample);
  return {
    dedupeKey: `interface-counter|${totals.interfaceName}|${sampledAt}|${totals.rxBytes}|${totals.txBytes}`,
    kind: 'interface',
    source: INTERFACE_COUNTER_SOURCE,
    clientIp: totals.interfaceName,
    clientMac: '',
    subscriberId: `interface:${totals.interfaceName}`.slice(0, 128),
    sourceIp: totals.interfaceName,
    sourcePort: '',
    destinationIp: '',
    destinationPort: '',
    destinationDomain: '',
    protocol: 'counter',
    serviceType: 'interface-counter',
    direction: 'counter',
    startedAt: sampledAt,
    endedAt: sampledAt,
    downloadBytes: totals.downloadBytes,
    uploadBytes: totals.uploadBytes,
    rawJson: JSON.stringify({
      interfaceName: totals.interfaceName,
      endpoint: sample.endpoint || '',
      rxBytes: totals.rxBytes,
      txBytes: totals.txBytes,
      cumulativeDownloadBytes: totals.downloadBytes,
      cumulativeUploadBytes: totals.uploadBytes
    }),
    createdAt: sampledAt
  };
}

export function trafficLogRecordFromSession(session = {}, authorization = null, settings = {}) {
  if (!trafficEnabled(settings)) return null;
  const clientIp = cleanText(session.clientIp || authorization?.client_ip, 64);
  if (!clientIp || !isIP(clientIp)) return null;
  const sourceIp = cleanText(session.sourceIp || clientIp, 64);
  if (!isIP(sourceIp)) return null;
  const destinationIp = cleanText(session.destinationIp, 64);
  const startedAt = cleanTimestamp(authorization?.created_at || session.startedAt);
  const endedAt = cleanTimestamp(session.lastSeenAt || session.endedAt || Date.now(), Date.now());
  const downloadBytes = cleanBytes(session.downloadDeltaBytes ?? session.trafficDownloadBytes ?? session.downloadBytes);
  const uploadBytes = cleanBytes(session.uploadDeltaBytes ?? session.trafficUploadBytes ?? session.uploadBytes);
  const subscriberId = authorization
    ? `${authorization.method}:${authorization.identity}`.slice(0, 128)
    : cleanText(session.userName, 128);
  const protocol = cleanText(session.protocol || 'ip', 32);
  const serviceType = cleanText(session.serviceType || 'internet-access', 80);
  const sourcePort = cleanPort(session.sourcePort);
  const destinationPort = cleanPort(session.destinationPort);
  const cumulativeDownloadBytes = cleanBytes(session.cumulativeDownloadBytes ?? session.downloadBytes);
  const cumulativeUploadBytes = cleanBytes(session.cumulativeUploadBytes ?? session.uploadBytes);
  const payload = [
    'session',
    session.sessionId || '',
    authorization?.id || '',
    clientIp,
    sourceIp,
    sourcePort,
    destinationIp,
    destinationPort,
    protocol,
    serviceType,
    startedAt,
    downloadBytes,
    uploadBytes,
    cumulativeDownloadBytes,
    cumulativeUploadBytes
  ].join('|');
  const raw = {
    ...(session.sessionId ? { gatewaySessionId: session.sessionId } : {}),
    ...(session.raw ? { gateway: session.raw } : {}),
    ...(cumulativeDownloadBytes || cumulativeUploadBytes ? {
      cumulativeDownloadBytes,
      cumulativeUploadBytes
    } : {})
  };
  return {
    dedupeKey: `session|${sha256Hex(payload)}`,
    kind: 'session',
    source: 'opnsense-session',
    clientIp,
    clientMac: normalizeMac(session.clientMac || authorization?.client_mac || ''),
    subscriberId,
    sourceIp,
    sourcePort,
    destinationIp,
    destinationPort,
    destinationDomain: cleanText(session.destinationDomain, 255),
    protocol,
    serviceType,
    direction: inferDirection({ clientIp, sourceIp, destinationIp, kind: 'session' }),
    startedAt,
    endedAt,
    downloadBytes,
    uploadBytes,
    rawJson: Object.keys(raw).length ? JSON.stringify(raw) : '',
    createdAt: cleanTimestamp(session.createdAt || session.lastSeenAt || Date.now())
  };
}

export function trafficLogRecordsFromFlowRecords(records = [], settings = {}) {
  if (!trafficEnabled(settings)) return [];
  return records.map(record => {
    const clientIp = cleanText(record.clientIp, 64);
    const sourceIp = cleanText(record.sourceIp || clientIp, 64);
    if (!clientIp || !sourceIp) return null;
    const destinationIp = cleanText(record.destinationIp, 64);
    const startedAt = cleanTimestamp(record.startedAt || record.createdAt);
    const downloadBytes = cleanBytes(record.downloadBytes);
    const uploadBytes = cleanBytes(record.uploadBytes);
    const payload = record.dedupeKey || [
      'flow',
      record.source || '',
      clientIp,
      sourceIp,
      record.sourcePort || '',
      destinationIp,
      record.destinationPort || '',
      record.protocol || '',
      startedAt,
      downloadBytes,
      uploadBytes,
      record.rawJson || ''
    ].join('|');
    return {
      dedupeKey: `flow|${sha256Hex(payload)}`,
      kind: 'flow',
      source: cleanText(record.source || 'opnsense-filterlog', 80),
      clientIp,
      clientMac: normalizeMac(record.clientMac || ''),
      subscriberId: cleanText(record.subscriberId, 128),
      sourceIp,
      sourcePort: cleanPort(record.sourcePort),
      destinationIp,
      destinationPort: cleanPort(record.destinationPort),
      destinationDomain: cleanText(record.destinationDomain, 255),
      protocol: cleanText(record.protocol, 32),
      serviceType: cleanText(record.serviceType || 'firewall-flow', 80),
      direction: inferDirection({ clientIp, sourceIp, destinationIp, kind: 'flow' }),
      startedAt,
      endedAt: record.endedAt ? cleanTimestamp(record.endedAt, startedAt) : startedAt,
      downloadBytes,
      uploadBytes,
      rawJson: cleanText(record.rawJson, 10000),
      createdAt: cleanTimestamp(record.createdAt || startedAt)
    };
  }).filter(Boolean);
}

async function reverseLookup(ip, timeoutMs = DEFAULT_DNS_TIMEOUT_MS) {
  const key = cleanText(ip, 64);
  if (!key || !isIP(key)) return '';
  const cached = domainCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.domain;
  let timer;
  try {
    const names = await Promise.race([
      dns.reverse(key),
      new Promise(resolve => {
        timer = setTimeout(() => resolve([]), timeoutMs);
      })
    ]);
    const domain = Array.isArray(names) ? cleanText(names[0], 255) : '';
    domainCache.set(key, { domain, expiresAt: Date.now() + DOMAIN_CACHE_MS });
    return domain;
  } catch {
    domainCache.set(key, { domain: '', expiresAt: Date.now() + DOMAIN_CACHE_MS });
    return '';
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function enrichTrafficLogRecords(records = [], settings = {}) {
  if (!trafficEnabled(settings) || settings.resolveDomains === false) return records;
  const ips = [...new Set(records
    .map(record => record.destinationIp)
    .filter(ip => ip && isIP(ip)))];
  if (!ips.length) return records;
  const entries = await Promise.all(ips.map(async ip => [ip, await reverseLookup(ip)]));
  const domains = new Map(entries);
  return records.map(record => ({
    ...record,
    destinationDomain: record.destinationDomain || domains.get(record.destinationIp) || ''
  }));
}
