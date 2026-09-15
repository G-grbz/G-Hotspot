import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { parentPort, workerData } from 'node:worker_threads';
import { createZipArchive } from './opnsenseTemplate.js';
import { law5651DailyLogHeader, law5651DailyLogLine } from './law5651.js';

const EXPORT_PAGE_SIZE = 5000;
const DELETE_BATCH_SIZE = 2000;

function delay(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

function fileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const input = fs.createReadStream(filePath);
    input.on('data', chunk => hash.update(chunk));
    input.once('error', reject);
    input.once('end', () => resolve(hash.digest('hex')));
  });
}

function databaseMaintenanceStats(database, filePath) {
  const pageSize = Number(database.prepare('PRAGMA page_size').get().page_size || 0);
  const pageCount = Number(database.prepare('PRAGMA page_count').get().page_count || 0);
  const freelistCount = Number(database.prepare('PRAGMA freelist_count').get().freelist_count || 0);
  const autoVacuum = Number(database.prepare('PRAGMA auto_vacuum').get().auto_vacuum || 0);
  const fileBytes = fs.existsSync(filePath) ? fs.statSync(filePath).size : 0;
  const walPath = `${filePath}-wal`;
  const shmPath = `${filePath}-shm`;
  const walBytes = fs.existsSync(walPath) ? fs.statSync(walPath).size : 0;
  const shmBytes = fs.existsSync(shmPath) ? fs.statSync(shmPath).size : 0;
  return {
    pageSize,
    pageCount,
    freelistCount,
    autoVacuum,
    incrementalVacuumEnabled: autoVacuum === 2,
    databaseBytes: pageSize * pageCount,
    freeBytes: pageSize * freelistCount,
    fileBytes,
    walBytes,
    shmBytes,
    totalFileBytes: fileBytes + walBytes + shmBytes
  };
}

function maintainDatabase({ syslogFilePath, maxPages = 16384 }) {
  const database = new DatabaseSync(syslogFilePath, { timeout: 5000 });
  try {
    database.exec('PRAGMA busy_timeout=5000; PRAGMA wal_checkpoint(PASSIVE);');
    const before = databaseMaintenanceStats(database, syslogFilePath);
    const requestedPages = before.autoVacuum === 2
      ? Math.max(0, Math.min(before.freelistCount, Math.trunc(Number(maxPages) || 16384)))
      : 0;
    if (requestedPages > 0) database.exec(`PRAGMA incremental_vacuum(${requestedPages});`);
    database.exec('PRAGMA wal_checkpoint(PASSIVE); PRAGMA optimize;');
    const after = databaseMaintenanceStats(database, syslogFilePath);
    return {
      ok: true,
      supported: before.autoVacuum === 2,
      requestedPages,
      before,
      after,
      reclaimedBytes: Math.max(0, before.totalFileBytes - after.totalFileBytes),
      requiresFullVacuum: before.autoVacuum !== 2
    };
  } finally {
    database.close();
  }
}

async function verifiedCleanupRange(database, row, {
  requireTimestamp = false,
  requireBackup = false,
  allowMissingArchiveBefore = null
} = {}) {
  const firstSequence = Math.trunc(Number(row?.first_sequence));
  const lastSequence = Math.trunc(Number(row?.last_sequence));
  const recordCount = Math.trunc(Number(row?.record_count) || 0);
  const firstCreatedAt = Math.trunc(Number(row?.first_created_at));
  const lastCreatedAt = Math.trunc(Number(row?.last_created_at));
  if (!recordCount || !Number.isFinite(firstCreatedAt) || !Number.isFinite(lastCreatedAt)) return null;
  const periodStartAt = Math.trunc(Number(row?.period_start_at));
  const periodEndAt = Math.trunc(Number(row?.period_end_at));
  const hasPeriodBounds = Number.isFinite(periodStartAt) && Number.isFinite(periodEndAt) &&
    periodEndAt > periodStartAt;
  const createdFrom = hasPeriodBounds ? periodStartAt : firstCreatedAt;
  const createdBefore = hasPeriodBounds ? periodEndAt : lastCreatedAt + 1;
  if (requireTimestamp && row.timestamp_status !== 'created') return null;
  if (requireBackup && row.backup_status !== 'succeeded') return null;

  let range;
  if (Number.isFinite(firstSequence) && Number.isFinite(lastSequence) &&
      firstSequence > 0 && lastSequence >= firstSequence) {
    const current = database.prepare(`
      SELECT COUNT(*) count
      FROM law5651_logs
      WHERE sequence BETWEEN ? AND ?
        AND created_at >= ? AND created_at < ?
    `).get(firstSequence, lastSequence, createdFrom, createdBefore);
    const currentCount = Number(current?.count || 0);
    if (!currentCount || currentCount > recordCount) return null;
    range = { firstSequence, lastSequence, createdFrom, createdBefore, derivedSequence: false };
  } else {
    const current = database.prepare(`
      SELECT COUNT(*) count, MIN(sequence) first_sequence, MAX(sequence) last_sequence
      FROM law5651_logs
      WHERE created_at >= ? AND created_at < ?
    `).get(createdFrom, createdBefore);
    const currentCount = Number(current?.count || 0);
    const derivedFirstSequence = Math.trunc(Number(current?.first_sequence));
    const derivedLastSequence = Math.trunc(Number(current?.last_sequence));
    if (!currentCount || currentCount > recordCount ||
        !Number.isFinite(derivedFirstSequence) || !Number.isFinite(derivedLastSequence) ||
        derivedFirstSequence <= 0 || derivedLastSequence < derivedFirstSequence) return null;
    range = {
      firstSequence: derivedFirstSequence,
      lastSequence: derivedLastSequence,
      createdFrom,
      createdBefore,
      derivedSequence: true
    };
  }

  const archiveExpired = Number.isFinite(Number(allowMissingArchiveBefore)) &&
    createdBefore <= Number(allowMissingArchiveBefore);
  if (!archiveExpired) {
    if (!row.file_path || !row.export_hash || !fs.existsSync(row.file_path)) return null;
    try {
      if (await fileHash(row.file_path) !== row.export_hash) return null;
    } catch {
      return null;
    }
  }
  return range;
}

async function deleteCleanupRange(database, row, range, cutoff) {
  if (range.derivedSequence) {
    database.prepare(`
      UPDATE law5651_exports SET first_sequence=?, last_sequence=? WHERE id=?
    `).run(range.firstSequence, range.lastSequence, row.id);
  }
  const remove = database.prepare(`
    DELETE FROM law5651_logs
    WHERE sequence IN (
      SELECT sequence
      FROM law5651_logs
      WHERE sequence BETWEEN ? AND ?
        AND created_at >= ? AND created_at < ? AND created_at < ?
      ORDER BY sequence ASC
      LIMIT ?
    )
  `);
  let deleted = 0;
  while (true) {
    let result = null;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      try {
        database.exec('BEGIN IMMEDIATE');
        result = remove.run(
          range.firstSequence,
          range.lastSequence,
          range.createdFrom,
          range.createdBefore,
          cutoff,
          DELETE_BATCH_SIZE
        );
        database.exec('COMMIT');
        break;
      } catch (error) {
        try { database.exec('ROLLBACK'); } catch {}
        if (!/locked|busy/iu.test(error.message) || attempt === 9) throw error;
        await delay(50 * (attempt + 1));
      }
    }
    const changes = Number(result?.changes || 0);
    deleted += changes;
    if (changes < DELETE_BATCH_SIZE) break;
    await delay(20);
  }
  return deleted;
}

async function cleanupExpiredRecords({
  syslogFilePath,
  retentionDays,
  now = Date.now(),
  requireTimestamp = false,
  requireBackup = false,
  allowMissingArchiveBefore = null,
  reasons = ['auto', 'kamusm', 'timestamp']
}) {
  const database = new DatabaseSync(syslogFilePath, { timeout: 5000 });
  try {
    database.exec('PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON;');
    const days = Math.max(1, Math.trunc(Number(retentionDays) || 730));
    const cutoff = Math.trunc(Number(now) || Date.now()) - days * 24 * 60 * 60 * 1000;
    const allowedReasons = [...new Set(reasons.map(reason => String(reason || '').trim()).filter(Boolean))];
    if (!allowedReasons.length) return { deleted: 0 };
    const placeholders = allowedReasons.map(() => '?').join(', ');
    const exports = database.prepare(`
      SELECT * FROM law5651_exports
      WHERE export_reason IN (${placeholders})
        AND record_count > 0
        AND first_created_at IS NOT NULL
        AND last_created_at IS NOT NULL
        AND COALESCE(period_start_at, first_created_at) < ?
      ORDER BY COALESCE(period_start_at, first_created_at) ASC,
        COALESCE(period_end_at, last_created_at + 1) ASC, created_at ASC
    `).all(...allowedReasons, cutoff);
    let deleted = 0;
    for (const row of exports) {
      const range = await verifiedCleanupRange(database, row, {
        requireTimestamp,
        requireBackup,
        allowMissingArchiveBefore
      });
      if (!range) continue;
      deleted += await deleteCleanupRange(database, row, range, cutoff);
    }
    return { deleted };
  } finally {
    database.close();
  }
}

function writeDailyLog({ syslogFilePath, logPath, options = {} }) {
  const database = new DatabaseSync(syslogFilePath, { readOnly: true, timeout: 5000 });
  let descriptor = null;
  try {
    database.exec('PRAGMA busy_timeout=5000; PRAGMA query_only=ON;');
    const where = [];
    const rangeParameters = [];
    if (options.periodStart != null) {
      where.push('created_at >= ?');
      rangeParameters.push(Math.trunc(Number(options.periodStart)));
    }
    if (options.periodEnd != null) {
      where.push('created_at < ?');
      rangeParameters.push(Math.trunc(Number(options.periodEnd)));
    }
    const rangeClause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const range = database.prepare(`
      SELECT COUNT(*) record_count,
        MIN(sequence) first_sequence,
        MAX(sequence) last_sequence,
        MIN(created_at) first_created_at,
        MAX(created_at) last_created_at
      FROM law5651_logs ${rangeClause}
    `).get(...rangeParameters);
    const total = Number(range?.record_count || 0);
    const firstSequence = range?.first_sequence == null ? null : Number(range.first_sequence);
    const maximumSequence = range?.last_sequence == null ? null : Number(range.last_sequence);
    descriptor = fs.openSync(logPath, 'w', 0o600);
    fs.writeSync(descriptor, `${law5651DailyLogHeader({
      ...options,
      recordCount: total
    })}\n`);
    if (!total || firstSequence == null || maximumSequence == null) {
      return {
        recordCount: 0,
        firstSequence: null,
        lastSequence: null,
        firstCreatedAt: null,
        lastCreatedAt: null
      };
    }

    const pageWhere = ['sequence > ?', 'sequence <= ?', ...where];
    const page = database.prepare(`
      SELECT * FROM law5651_logs
      WHERE ${pageWhere.join(' AND ')}
      ORDER BY sequence ASC
      LIMIT ?
    `);
    let cursor = firstSequence - 1;
    let written = 0;
    let lastRow = null;
    while (cursor < maximumSequence) {
      const rows = page.all(
        cursor,
        maximumSequence,
        ...rangeParameters,
        EXPORT_PAGE_SIZE
      );
      if (!rows.length) break;
      lastRow = rows.at(-1);
      fs.writeSync(
        descriptor,
        `${rows.map(row => law5651DailyLogLine(row, options.timeZone)).join('\n')}\n`
      );
      written += rows.length;
      cursor = Number(lastRow.sequence);
    }
    if (written !== total) {
      throw new Error(`Syslog export changed while being read (${written}/${total} records written)`);
    }
    return {
      recordCount: written,
      firstSequence,
      lastSequence: maximumSequence,
      firstCreatedAt: Number(range.first_created_at),
      lastCreatedAt: Number(range.last_created_at)
    };
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
    database.close();
  }
}

function createZipFallback({ archivePath, sourceFiles = [] }) {
  const entries = sourceFiles.map(filePath => ({
    name: path.basename(filePath),
    data: fs.readFileSync(filePath)
  }));
  fs.writeFileSync(archivePath, createZipArchive(entries), { mode: 0o600 });
  return { archivePath, entries: entries.map(entry => entry.name) };
}

function commandData() {
  if (workerData) return workerData;
  const payload = String(process.argv[2] || '');
  if (!payload) throw new Error('Syslog export worker input is missing');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

function sendResult(data, message) {
  if (parentPort) parentPort.postMessage(message);
  else if (data?.resultPath) fs.writeFileSync(data.resultPath, JSON.stringify(message), { mode: 0o600 });
  else process.stdout.write(JSON.stringify(message));
}

let data = null;
try {
  data = commandData();
  const result = data.job === 'cleanup-expired-records'
    ? await cleanupExpiredRecords(data)
    : data.job === 'write-daily-log'
    ? writeDailyLog(data)
    : data.job === 'maintain-database'
      ? maintainDatabase(data)
    : data.job === 'zip'
      ? createZipFallback(data)
      : (() => { throw new Error('Unknown syslog export worker job'); })();
  sendResult(data, { ok: true, result });
} catch (error) {
  sendResult(data, { ok: false, error: error?.message || String(error) });
  process.exitCode = 1;
}
