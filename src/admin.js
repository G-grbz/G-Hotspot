import { generateSecret, generateVoucherCode, keyedHash, normalizeIp, normalizeVoucher, safeEqualHex } from './lib/security.js';
import { HttpError, getClientIp, readJson, sendJson } from './lib/http.js';
import { isIP } from 'node:net';
import {
  authorizeGateway, deleteGatewayKeaDhcpLease, disconnectGatewaySession, ensureGatewayBandwidthLimits,
  ensureGatewayKeaDhcpLease, listGatewayArpEntries, listGatewayDhcpLeases,
  listGatewayInterfaces, listGatewayNetworkChoices, listGatewaySessions, readGatewayInterfaceTrafficCounters
} from './services/opnsense.js';
import {
  createSyslogExportArchive, syslogCsv, syslogFileDate, syslogRecordFromSession, syslogStorageStatus
} from './services/syslog.js';
import { getSettings, getTrafficLogSettings, saveSettings, saveTrafficLogSettings } from './settings.js';
import { sendMail } from './services/smtp.js';
import { isValidEmail, normalizeEmail } from './lib/security.js';
import { requestLanguage } from './i18n.js';
import {
  authorizationWithEffectiveAccess,
  grantAccess,
  normalizeActiveAuthorizationDurations
} from './services/access.js';
import { sendAdminApprovalNotification, sendSystemNotification } from './services/notifications.js';
import {
  appearanceAssets, deleteAppearanceAsset, saveAppearanceAsset, saveAppearanceAssetChunk
} from './appearance.js';
import {
  gatewayHasBandwidthProfiles,
  quotaEnabled,
  quotaExceeded,
  quotaLimitBytes,
  quotaPeriodWindow,
  quotaProfileForMethod
} from './services/quotas.js';
import {
  appendTrafficLogFileRecords,
  cleanupTrafficLogFile,
  enrichTrafficLogRecords,
  listTrafficLogFileRecords,
  topTrafficLogFileClients,
  topTrafficLogFileSites,
  trafficLogFileSeries,
  trafficLogRecordFromInterfaceCounters,
  trafficLogRecordFromSession,
  trafficLogSettings
} from './services/trafficLogs.js';
import { OPNSENSE_TEMPLATE_DEFAULTS, createOpnsenseTemplateZip } from './services/opnsenseTemplate.js';
import { projectAbout } from './about.js';

const GATEWAY_COUNTER_INHERIT_GRACE_MS = 5000;

const COOKIE_NAME = 'gh_admin';
const TRAFFIC_LOG_FILE_CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const RELEASE_CHECK_CACHE_MS = 30 * 60 * 1000;
const RELEASE_FETCH_TIMEOUT_MS = 5000;
const RELEASE_REPOSITORY = {
  owner: 'G-grbz',
  name: 'G-Hotspot',
  url: 'https://github.com/G-grbz/G-Hotspot',
  futureUrl: 'https://github.com/G-grbz/G-Hotspot'
};

function cookieValue(request, name) {
  const cookies = String(request.headers.cookie || '').split(';');
  for (const cookie of cookies) {
    const [key, ...rest] = cookie.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return '';
}

function integerParam(value, fallback, { min = 0, max = 500 } = {}) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function parseTime(value) {
  if (value == null || value === '') return null;
  if (typeof value === 'number') return value > 1e12 ? value : value * 1000;
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return numeric > 1e12 ? numeric : numeric * 1000;
  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) ? parsed : null;
}

function numberField(row, names) {
  for (const name of names) {
    if (row[name] == null) continue;
    const value = Number(String(row[name]).replace(/[^\d.-]/g, ''));
    if (Number.isFinite(value)) return Math.max(0, value);
  }
  return 0;
}

function textField(row, names) {
  for (const name of names) {
    const value = row[name];
    if (value != null && String(value).trim()) return String(value).trim();
  }
  return '';
}

function normalizedMac(value) {
  const match = String(value || '').match(/[0-9a-f]{2}/giu);
  return match?.length === 6 ? match.map(part => part.toUpperCase()).join(':') : '';
}

function isIpv4(value) {
  const parts = String(value || '').split('.');
  return parts.length === 4 && parts.every(part => {
    if (!/^\d{1,3}$/u.test(part)) return false;
    const value = Number(part);
    return value >= 0 && value <= 255;
  });
}

function cleanIpCandidate(value) {
  return normalizeIp(String(value || '')
    .replace(/^"/u, '')
    .replace(/"$/u, '')
    .replace(/^\[/u, '')
    .replace(/\]$/u, '')
    .replace(/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/u, '$1')
    .trim());
}

function isPrivateOrSpecialIp(value) {
  const ip = cleanIpCandidate(value).toLowerCase();
  if (!ip || !isIP(ip)) return true;
  if (isIpv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168);
  }
  return ip === '::1' ||
    ip === '::' ||
    ip.startsWith('fc') ||
    ip.startsWith('fd') ||
    ip.startsWith('fe80:');
}

export function publicIpCandidate(value) {
  const ip = cleanIpCandidate(value);
  return ip && !isPrivateOrSpecialIp(ip) ? ip : '';
}

export function assertSyslogTimestampDisableAllowed(input = {}, { db = null, config = {} } = {}) {
  if (!Object.hasOwn(input || {}, 'SYSLOG_TIMESTAMP_MODE')) return true;
  const nextMode = String(input.SYSLOG_TIMESTAMP_MODE || '').trim().toLowerCase();
  if (nextMode !== 'disabled') return true;
  const syslogConfig = config.syslog || config.law5651 || {};
  const currentMode = String(
    syslogConfig.timestampMode ||
    (syslogConfig.kamusmTimestampEnabled ? 'kamusm' : 'disabled')
  ).trim().toLowerCase();
  if (!currentMode || currentMode === 'disabled') return true;
  const summary = typeof db?.law5651Summary === 'function' ? db.law5651Summary() : null;
  if (Number(summary?.count || 0) <= 0) return true;
  throw new HttpError(
    409,
    'Timestamp provider cannot be disabled after syslog evidence logging has started. Create a new installation/evidence chain if timestamping must be stopped.',
    'syslog_timestamp_disable_blocked'
  );
}

export function authorizationLeaseSeconds(runtimeConfig, authorization) {
  authorization = authorizationWithEffectiveAccess(runtimeConfig, authorization);
  const stored = Number(authorization?.lease_seconds);
  if (Number.isFinite(stored) && stored > 0) return stored;
  const createdAt = Number(authorization?.created_at);
  const expiresAt = Number(authorization?.expires_at);
  if (!Number.isFinite(createdAt) || !Number.isFinite(expiresAt) || expiresAt <= createdAt) return null;
  return Math.ceil((expiresAt - createdAt) / 1000);
}

function ipListField(row, names) {
  const output = [];
  const add = value => {
    const ip = String(value || '').trim();
    if (isIpv4(ip) && !output.includes(ip)) output.push(ip);
  };
  for (const name of names) {
    const value = row[name];
    if (Array.isArray(value)) {
      value.forEach(add);
    } else if (value != null && String(value).trim()) {
      String(value).split(/[\s,]+/u).forEach(add);
    }
  }
  return output;
}

function buildArpLookup(rows) {
  const ipToMac = new Map();
  for (const row of rows) {
    if (!isIpv4(row.clientIp)) continue;
    const mac = normalizedMac(row.clientMac);
    if (!mac) continue;
    ipToMac.set(row.clientIp, mac);
  }
  return { ipToMac };
}

function normalizeGatewaySession(row) {
  const rawSessionId = textField(row, ['sessionId', 'session_id', 'sessionid', 'id']);
  const zoneId = textField(row, ['gHotspotZoneId', 'zoneId', 'zone_id']);
  const sessionId = rawSessionId && zoneId && !/^\d{1,2}:/u.test(rawSessionId)
    ? `${zoneId}:${rawSessionId}`
    : rawSessionId;
  const rawClientIp = textField(row, ['ipAddress', 'ip_address', 'ip', 'address']);
  const clientIps = ipListField(row, ['ipAddresses', 'ip_addresses', 'ips', 'addresses']);
  if (isIpv4(rawClientIp) && !clientIps.includes(rawClientIp)) clientIps.unshift(rawClientIp);
  const clientIp = isIpv4(rawClientIp) ? rawClientIp : (clientIps[0] || '');
  return {
    sessionId,
    clientIp,
    clientIps,
    userName: textField(row, ['userName', 'username', 'user']),
    clientMac: textField(row, ['macAddress', 'mac_address', 'mac']),
    deviceName: textField(row, ['hostname', 'hostName', 'deviceName']),
    sourcePort: textField(row, ['sourcePort', 'source_port', 'srcPort', 'src_port', 'sport']),
    destinationIp: textField(row, ['destinationIp', 'destination_ip', 'dstIp', 'dst_ip']),
    destinationPort: textField(row, ['destinationPort', 'destination_port', 'dstPort', 'dst_port', 'dport']),
    protocol: textField(row, ['protocol', 'proto']),
    serviceType: textField(row, ['serviceType', 'service_type', 'service']),
    startedAt: parseTime(textField(row, [
      'startTime', 'start_time', 'startedAt', 'createdAt', 'loginTime', 'connectTime'
    ])),
    downloadBytes: numberField(row, [
      'downloadBytes', 'bytesOut', 'bytes_out', 'outputOctets', 'octetsOut', 'trafficOut', 'rxBytes'
    ]),
    uploadBytes: numberField(row, [
      'uploadBytes', 'bytesIn', 'bytes_in', 'inputOctets', 'octetsIn', 'trafficIn', 'txBytes'
    ]),
    lastSeenAt: parseTime(textField(row, [
      'lastAccess', 'last_accessed', 'last_seen', 'lastSeenAt', 'updatedAt'
    ])) || Date.now(),
    raw: row
  };
}

function authorizationGatewayResponseIp(authorization) {
  try {
    const response = JSON.parse(authorization?.gateway_response_json || 'null');
    const ip = textField(response || {}, ['ipAddress', 'ip_address', 'ip', 'address']);
    return isIpv4(ip) ? ip : '';
  } catch {
    return '';
  }
}

function preferredAuthorizationIp(row, authorization) {
  const responseIp = authorizationGatewayResponseIp(authorization);
  if (responseIp && row.clientIps.includes(responseIp)) return responseIp;
  return authorization?.client_ip || '';
}

function alignGatewaySessionToAuthorization(row, authorization) {
  const clientIp = preferredAuthorizationIp(row, authorization);
  if (isIpv4(clientIp) && row.clientIp !== clientIp && row.clientIps.includes(clientIp)) {
    return { ...row, clientIp, clientMac: '', alignedFromGatewayList: true };
  }
  return row;
}

function escapeCsv(value) {
  const text = value == null ? '' : String(value);
  return /[",\n]/u.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function usageDelta(current, previous) {
  const currentBytes = Math.max(0, Math.trunc(Number(current) || 0));
  const previousBytes = Math.max(0, Math.trunc(Number(previous) || 0));
  return currentBytes >= previousBytes ? currentBytes - previousBytes : currentBytes;
}

function gatewaySessionStartedBeforeAuthorization(row, authorization) {
  const startedAt = Number(row?.startedAt || 0);
  const authorizedAt = Number(authorization?.created_at || 0);
  return Boolean(startedAt && authorizedAt && startedAt + GATEWAY_COUNTER_INHERIT_GRACE_MS < authorizedAt);
}

function periodParam(value) {
  return ['hourly', '6h', '12h', 'daily', 'weekly', 'monthly'].includes(value) ? value : 'daily';
}

export function releaseVersion(value) {
  const match = String(value || '').match(/(?:^|[^\d])v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?:\+[-0-9A-Za-z.]+)?(?:$|[^\d])/u);
  return match ? match[1] : '';
}

function releaseVersionParts(value) {
  const [main, prerelease = ''] = String(value || '').split('-', 2);
  const numbers = main.split('.').map(part => Number.parseInt(part, 10));
  if (numbers.length !== 3 || numbers.some(part => !Number.isInteger(part) || part < 0)) return null;
  return { numbers, prerelease };
}

export function compareReleaseVersions(left, right) {
  const a = releaseVersionParts(left);
  const b = releaseVersionParts(right);
  if (!a || !b) return 0;
  for (let index = 0; index < 3; index += 1) {
    if (a.numbers[index] !== b.numbers[index]) return a.numbers[index] > b.numbers[index] ? 1 : -1;
  }
  if (a.prerelease === b.prerelease) return 0;
  if (!a.prerelease) return 1;
  if (!b.prerelease) return -1;
  return a.prerelease.localeCompare(b.prerelease, 'en');
}

function normalizeGitHubRelease(release, currentVersion, repository = RELEASE_REPOSITORY) {
  const title = String(release?.name || release?.tag_name || '').trim();
  const tag = String(release?.tag_name || '').trim();
  const body = String(release?.body || '').slice(0, 50000);
  const version = releaseVersion(`${title} ${tag}`);
  return {
    id: release?.id != null ? String(release.id) : tag || title,
    title,
    tag,
    version,
    body,
    url: String(release?.html_url || `${repository.url}/releases`).trim(),
    publishedAt: release?.published_at || release?.created_at || '',
    prerelease: Boolean(release?.prerelease),
    draft: Boolean(release?.draft),
    updateAvailable: Boolean(version && currentVersion && compareReleaseVersions(version, currentVersion) > 0)
  };
}

async function fetchReleaseStatus({
  releaseFetcher = globalThis.fetch,
  currentVersion = projectAbout().version || '',
  repository = RELEASE_REPOSITORY
} = {}) {
  const checkedAt = Date.now();
  if (typeof releaseFetcher !== 'function') {
    return {
      ok: false,
      repository,
      currentVersion,
      updateAvailable: false,
      checkedAt,
      error: 'Release check is not available in this runtime.'
    };
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), RELEASE_FETCH_TIMEOUT_MS);
  try {
    const response = await releaseFetcher(
      `https://api.github.com/repos/${repository.owner}/${repository.name}/releases?per_page=20`,
      {
        headers: {
          accept: 'application/vnd.github+json',
          'user-agent': 'G-Hotspot admin update checker'
        },
        signal: controller.signal
      }
    );
    if (response.status === 404) {
      return {
        ok: true,
        repository,
        currentVersion,
        updateAvailable: false,
        checkedAt,
        release: null,
        message: 'No release was found for the configured repository.'
      };
    }
    if (!response.ok) throw new Error(`GitHub release check failed with HTTP ${response.status}`);
    const payload = await response.json();
    const releases = Array.isArray(payload) ? payload : [];
    const published = releases.filter(release => !release?.draft);
    const selected = published.find(release => !release?.prerelease) || published[0];
    const release = selected ? normalizeGitHubRelease(selected, currentVersion, repository) : null;
    return {
      ok: true,
      repository,
      currentVersion,
      updateAvailable: Boolean(release?.updateAvailable),
      checkedAt,
      release,
      message: release ? '' : 'No release was found in the configured repository.'
    };
  } catch (error) {
    return {
      ok: false,
      repository,
      currentVersion,
      updateAvailable: false,
      checkedAt,
      error: error.name === 'AbortError' ? 'GitHub release check timed out.' : error.message
    };
  } finally {
    clearTimeout(timeout);
  }
}

function trafficLogQuery(url, { limit = 150, offset = 0, order = 'desc' } = {}) {
  return {
    search: url.searchParams.get('search') || '',
    kind: url.searchParams.get('kind') || '',
    period: periodParam(url.searchParams.get('period') || 'daily'),
    sourceIp: url.searchParams.get('sourceIp') || '',
    sourcePort: url.searchParams.get('sourcePort') || '',
    destinationIp: url.searchParams.get('destinationIp') || '',
    destinationPort: url.searchParams.get('destinationPort') || '',
    startAt: parseTime(url.searchParams.get('startAt')),
    endAt: parseTime(url.searchParams.get('endAt')),
    limit,
    offset,
    order
  };
}

function trafficEndpointCsv(ip, port = '', domain = '') {
  const address = ip || '';
  const label = domain ? `${domain} · ${address}` : address;
  return `${label}${port ? `:${port}` : ''}`;
}

function trafficRemoteEndpointCsv(row) {
  if (row.direction === 'incoming' || (row.client_ip && row.destination_ip === row.client_ip)) {
    return trafficEndpointCsv(row.source_ip, row.source_port);
  }
  return trafficEndpointCsv(row.destination_ip, row.destination_port, row.destination_domain);
}

function trafficPacketRouteCsv(row) {
  return `${trafficEndpointCsv(row.source_ip, row.source_port)} -> ${trafficEndpointCsv(
    row.destination_ip,
    row.destination_port,
    row.destination_domain
  )}`;
}

function trafficLogsCsv(rows = []) {
  const headers = [
    'Created At', 'Kind', 'Source', 'Client IP', 'Client MAC', 'Subscriber',
    'Direction', 'Remote Endpoint', 'Packet Route', 'Source IP', 'Source Port',
    'Destination IP', 'Destination Port', 'Destination Domain', 'Protocol',
    'Service', 'Download Bytes', 'Upload Bytes'
  ];
  const lines = [headers, ...rows.map(row => [
    new Date(Number(row.created_at)).toISOString(),
    row.kind,
    row.source,
    row.client_ip,
    row.client_mac || '',
    row.subscriber_id || '',
    row.direction || '',
    trafficRemoteEndpointCsv(row),
    trafficPacketRouteCsv(row),
    row.source_ip,
    row.source_port || '',
    row.destination_ip || '',
    row.destination_port || '',
    row.destination_domain || '',
    row.protocol || '',
    row.service_type || '',
    row.effective_download_bytes ?? row.download_bytes ?? 0,
    row.effective_upload_bytes ?? row.upload_bytes ?? 0
  ])];
  return `\uFEFF${lines.map(columns => columns.map(escapeCsv).join(',')).join('\n')}`;
}

export function createAdminController({
  db,
  config,
  syslogReceiverStatus = () => null,
  syslogAutoExportStatus = () => null,
  syslogHealthStatus = () => null,
  releaseFetcher = globalThis.fetch
}) {
  if (!config.syslog && config.law5651) config.syslog = config.law5651;
  if (!config.law5651 && config.syslog) config.law5651 = config.syslog;
  const sessions = new Map();
  let releaseStatusCache = null;
  let releaseStatusCacheExpiresAt = 0;
  const gatewayTrafficState = {
    previous: null,
    current: null,
    checkedAt: 0,
    error: '',
    errorCode: ''
  };
  const interfaceCounterLogState = {
    lastWarningAt: 0
  };
  const bandwidthSyncState = {
    lastErrorAt: 0,
    backoffMs: 0,
    lastError: ''
  };
  const trafficLogFileCleanupState = {
    lastRunAt: Date.now()
  };

  function cleanupSessions() {
    const now = Date.now();
    for (const [hash, session] of sessions) {
      if (session.expiresAt <= now) sessions.delete(hash);
    }
  }

  function currentSession(request) {
    cleanupSessions();
    const token = cookieValue(request, COOKIE_NAME);
    if (!token) return null;
    return sessions.get(keyedHash(config.appSecret, token)) || null;
  }

  function requireSession(request, { csrf = false } = {}) {
    if (!config.admin.enabled) throw new HttpError(503, 'Admin panel is not configured', 'admin_disabled');
    const session = currentSession(request);
    if (!session) throw new HttpError(401, 'Admin session required', 'admin_unauthorized');
    if (csrf && request.headers['x-csrf-token'] !== session.csrfToken) {
      throw new HttpError(403, 'Invalid CSRF token', 'invalid_csrf');
    }
    return session;
  }

  function audit(request, session, action, targetType = '', targetId = '', detail = null) {
    db.logAdminEvent({
      adminUser: session.username,
      action,
      targetType,
      targetId,
      detail,
      clientIp: getClientIp(request, config.trustProxy)
    });
  }

  function trafficLogStorageConfig() {
    return config.databasePath || !db?.filePath
      ? config
      : { ...config, databasePath: db.filePath };
  }

  function localTrafficClientNetworks() {
    const shaperNetwork = String(config.gateway?.shaperNetwork || '').trim();
    if (shaperNetwork && shaperNetwork.toLowerCase() !== 'any') return shaperNetwork;
    return config.syslog?.networks || config.law5651?.networks || 'any';
  }

  function localTrafficExcludedInterfaces() {
    return [config.gateway?.shaperInterface || 'wan'];
  }

  function cleanupTrafficLogFileIfDue(storageConfig, retentionDays, now = Date.now()) {
    const settings = trafficLogSettings(storageConfig);
    if (now - trafficLogFileCleanupState.lastRunAt < TRAFFIC_LOG_FILE_CLEANUP_INTERVAL_MS) {
      return { deleted: 0, kept: 0, skipped: true, filePath: settings.logFile };
    }
    trafficLogFileCleanupState.lastRunAt = now;
    return cleanupTrafficLogFile(storageConfig, retentionDays, now);
  }

  function listTrafficLogs(options = {}) {
    const storageConfig = trafficLogStorageConfig();
    const settings = trafficLogSettings(storageConfig);
    const result = settings.enabled
      ? listTrafficLogFileRecords(storageConfig, options)
      : db.listTrafficLogs(options);
    const live = db.authorizationLiveTraffic?.({
      now: options.now || Date.now(),
      maxAgeMs: Math.max(30, Number(config.gateway.syncIntervalSeconds || 10) * 4) * 1000
    }) || {};
    return {
      ...result,
      summary: {
        ...(result.summary || {}),
        liveSource: live.liveSource || 'gateway_sessions_waiting',
        liveWindowSeconds: live.liveWindowSeconds || 0,
        liveRecords: live.liveRecords || 0,
        liveClients: live.liveClients || 0,
        liveDownloadBytes: live.liveDownloadBytes || 0,
        liveUploadBytes: live.liveUploadBytes || 0,
        liveDownloadBps: live.liveDownloadBps || 0,
        liveUploadBps: live.liveUploadBps || 0,
        liveLastSampleAt: live.liveLastSampleAt || null
      }
    };
  }

  function dashboardTrafficSeries(period, now = Date.now()) {
    const storageConfig = trafficLogStorageConfig();
    const settings = trafficLogSettings(storageConfig);
    if (db.trafficLogSeries) return db.trafficLogSeries({ period, now });
    return settings.enabled
      ? trafficLogFileSeries(storageConfig, { period, now })
      : { period, source: 'disabled', points: [], summary: {} };
  }

  function dashboardTopSites(hours, now = Date.now()) {
    const storageConfig = trafficLogStorageConfig();
    const settings = trafficLogSettings(storageConfig);
    if (db.topTrafficLogSites) return db.topTrafficLogSites({ hours, limit: 10, now });
    return settings.enabled
      ? topTrafficLogFileSites(storageConfig, { hours, limit: 10, now })
      : { source: 'disabled', hours: 6, limit: 10, rows: [], totalVisits: 0, totalSites: 0 };
  }

  function dashboardTopBandwidthClients(hours, now = Date.now()) {
    const storageConfig = trafficLogStorageConfig();
    const settings = trafficLogSettings(storageConfig);
    const networks = localTrafficClientNetworks();
    const excludedInterfaces = localTrafficExcludedInterfaces();
    if (db.topTrafficLogClients) return db.topTrafficLogClients({ hours, limit: 10, networks, excludedInterfaces, now });
    return settings.enabled
      ? topTrafficLogFileClients(storageConfig, { hours, limit: 10, networks, excludedInterfaces, now })
      : { source: 'disabled', hours: 6, limit: 10, rows: [], totalRecords: 0, totalClients: 0 };
  }

  async function gatewayLiveInterfaceTraffic() {
    if (config.gateway.mode !== 'opnsense-api') {
      return { liveSource: 'gateway_interface_unavailable', liveError: 'OPNsense API mode is not active.' };
    }
    const now = Date.now();
    if (now - gatewayTrafficState.checkedAt < 3000) {
      return gatewayTrafficSummary(gatewayTrafficState);
    }
    gatewayTrafficState.checkedAt = now;
    try {
      const sample = await readGatewayInterfaceTrafficCounters(config.gateway, config.gateway.shaperInterface || 'wan');
      gatewayTrafficState.previous = gatewayTrafficState.current;
      gatewayTrafficState.current = sample;
      gatewayTrafficState.error = '';
      gatewayTrafficState.errorCode = '';
    } catch (error) {
      gatewayTrafficState.error = error.message;
      gatewayTrafficState.errorCode = error.code || '';
    }
    return gatewayTrafficSummary(gatewayTrafficState);
  }

  function gatewayTrafficSummary(state) {
    if (state.error) {
      return {
        liveSource: state.errorCode === 'opnsense_interface_forbidden'
          ? 'gateway_interface_forbidden'
          : 'gateway_interface_error',
        liveError: state.error,
        liveWindowSeconds: 0,
        liveDownloadBps: 0,
        liveUploadBps: 0
      };
    }
    if (!state.current || !state.previous || state.current.sampledAt <= state.previous.sampledAt) {
      return {
        liveSource: 'gateway_interface_waiting',
        liveWindowSeconds: 0,
        liveDownloadBps: 0,
        liveUploadBps: 0
      };
    }
    const elapsedSeconds = Math.max(1, (state.current.sampledAt - state.previous.sampledAt) / 1000);
    const rxDelta = state.current.rxBytes >= state.previous.rxBytes
      ? state.current.rxBytes - state.previous.rxBytes
      : state.current.rxBytes;
    const txDelta = state.current.txBytes >= state.previous.txBytes
      ? state.current.txBytes - state.previous.txBytes
      : state.current.txBytes;
    const interfaceName = String(config.gateway.shaperInterface || '').toLowerCase();
    const lanLike = interfaceName.includes('lan');
    return {
      liveSource: 'gateway_interface',
      liveInterface: state.current.interfaceName || config.gateway.shaperInterface || '',
      liveEndpoint: state.current.endpoint || '',
      liveWindowSeconds: Math.round(elapsedSeconds),
      liveRecords: 1,
      liveClients: 0,
      liveDownloadBytes: lanLike ? txDelta : rxDelta,
      liveUploadBytes: lanLike ? rxDelta : txDelta,
      liveDownloadBps: Math.round((lanLike ? txDelta : rxDelta) / elapsedSeconds),
      liveUploadBps: Math.round((lanLike ? rxDelta : txDelta) / elapsedSeconds),
      liveLastSampleAt: state.current.sampledAt
    };
  }

  async function deleteAuthorizationKeaLease(authorization, { markDeleted = false } = {}) {
    if (config.gateway.keaLeaseSyncEnabled !== true) return;
    try {
      await deleteGatewayKeaDhcpLease(config.gateway, authorization);
      if (markDeleted) db.markAuthorizationKeaDeleted(authorization.id);
    } catch (error) {
      console.warn(`Kea DHCP reservation could not be removed: ${error.message}`);
    }
  }

  async function synchronizeAuthorizationKeaLease(authorization) {
    if (config.gateway.keaLeaseSyncEnabled !== true) return;
    if (!authorization) return;
    try {
      const result = await ensureGatewayKeaDhcpLease(config.gateway, {
        authorizationId: authorization.id,
        clientIp: authorization.client_ip,
        clientMac: authorization.client_mac,
        expiresAt: authorization.expires_at,
        leaseSeconds: authorizationLeaseSeconds(config, authorization),
        method: authorization.method,
        identity: authorization.identity
    });
    if (result.applied) db.markAuthorizationKeaSynced(authorization.id);
  } catch (error) {
    console.warn(`Kea DHCP lease lifetime could not be synchronized: ${error.message}`);
  }
}

  function setSessionCookie(response, token, maxAge) {
    const secure = String(config.publicBaseUrl).startsWith('https://');
    response.setHeader('set-cookie',
      `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge};${secure ? ' Secure;' : ''}`
    );
  }

  function notificationClientIp(request, reportedPublicIp = '') {
    const forwarded = typeof request.headers['x-forwarded-for'] === 'string'
      ? request.headers['x-forwarded-for'].split(',')
      : [];
    const forwardedHeader = typeof request.headers.forwarded === 'string'
      ? [...request.headers.forwarded.matchAll(/for="?([^;,"]+)/giu)].map(match => match[1])
      : [];
    const candidates = [
      request.headers['cf-connecting-ip'],
      request.headers['x-real-ip'],
      request.headers['x-client-ip'],
      ...forwarded,
      ...forwardedHeader
    ].map(cleanIpCandidate)
      .filter(Boolean);
    const publicIp = candidates.map(publicIpCandidate).find(Boolean);
    if (publicIp) return publicIp;
    const browserPublicIp = publicIpCandidate(reportedPublicIp);
    if (browserPublicIp) return browserPublicIp;
    for (const candidate of candidates) {
      if (candidate !== '0.0.0.0') return candidate;
    }
    return getClientIp(request, config.trustProxy);
  }

  function opnsenseTemplateDefaultTargetUrl(request) {
    const forwardedProto = config.trustProxy && typeof request.headers['x-forwarded-proto'] === 'string'
      ? request.headers['x-forwarded-proto'].split(',')[0].trim()
      : '';
    const forwardedHost = config.trustProxy && typeof request.headers['x-forwarded-host'] === 'string'
      ? request.headers['x-forwarded-host'].split(',')[0].trim()
      : '';
    const protocol = forwardedProto || (request.socket.encrypted ? 'https' : 'http');
    const host = forwardedHost || request.headers.host ||
      `${config.host && config.host !== '0.0.0.0' ? config.host : '127.0.0.1'}:${config.port}`;
    try {
      return new URL(`${protocol}://${host}/`).toString();
    } catch {
      return OPNSENSE_TEMPLATE_DEFAULTS.targetUrl;
    }
  }

  function systemNotification(eventType, severity, message, detail = {}) {
    return sendSystemNotification(config, { eventType, severity, message, detail })
      .catch(error => {
        console.warn(`System notification failed: ${error.message}`);
        return { sent: 0, failed: 1, error: error.message };
      });
  }

  function notifyAdminLogin(request, session, reportedPublicIp = '') {
    systemNotification('admin_login_succeeded', 'info', 'Administrator signed in.', {
      adminUser: session.username,
      clientIp: notificationClientIp(request, reportedPublicIp)
    });
  }

  function notifyAdminLoginFailed(request, suppliedUser = '', error = 'invalid_credentials', reportedPublicIp = '') {
    systemNotification('admin_login_failed', 'warning', 'Failed administrator sign-in attempt.', {
      adminUser: suppliedUser,
      clientIp: notificationClientIp(request, reportedPublicIp),
      error
    });
  }

  async function notifyAccessExpired(authorization) {
    if (!authorization) return;
    await systemNotification('access_expired', 'info', 'Access duration expired.', {
      authorizationId: authorization.id,
      method: authorization.method,
      identity: authorization.identity,
      clientIp: authorization.client_ip,
      clientMac: authorization.client_mac || '',
      expiresAt: Number(authorization.expires_at || 0)
    });
  }

  async function notifyUserVerified(result, { method, identity, clientIp, clientMac = '' } = {}) {
    await systemNotification('user_verified', 'info', 'User verification completed.', {
      authorizationId: result.authorizationId || '',
      method,
      identity,
      clientIp,
      clientMac,
      expiresAt: Number(result.expiresAt || 0)
    });
  }

  async function notifyOpnsenseConnectionLost(error) {
    if (db.getRuntimeState('opnsense_connection_lost_notified')?.value === 'true') return;
    const result = await systemNotification('opnsense_connection_lost', 'error', 'OPNsense connection lost.', {
      error: error.message,
      gatewayMode: config.gateway.mode,
      gatewayBaseUrl: config.gateway.baseUrl || ''
    });
    if (!result?.skipped) {
      db.setRuntimeState('opnsense_connection_lost_notified', 'true');
    }
  }

  function markOpnsenseConnectionRestored(now = Date.now()) {
    if (db.getRuntimeState('opnsense_connection_lost_notified')?.value === 'true') {
      db.setRuntimeState('opnsense_connection_lost_notified', 'false', now);
    }
  }

  function activeBandwidthAuthorizations(now = Date.now()) {
    return db.listActiveBandwidthAuthorizations
      ? db.listActiveBandwidthAuthorizations({ now, gatewayMode: config.gateway.mode })
      : [];
  }

  function quotaTimeZone() {
    return config.syslog?.timeZone || config.law5651?.timeZone || 'UTC';
  }

  function inheritedGatewayCounters(row, authorization, storedQuotaUsage = null) {
    if (Number(storedQuotaUsage?.reset_at || 0)) return false;
    if (!Number(row?.downloadBytes || 0) && !Number(row?.uploadBytes || 0)) return false;
    return gatewaySessionStartedBeforeAuthorization(row, authorization) ||
      Boolean(db.hasEarlierAuthorizationForGatewaySession?.(authorization));
  }

  function authorizationTrafficDeltas(row, authorization) {
    if (!authorization) {
      return {
        downloadDelta: Math.max(0, Math.trunc(Number(row.downloadBytes) || 0)),
        uploadDelta: Math.max(0, Math.trunc(Number(row.uploadBytes) || 0))
      };
    }
    const profile = quotaProfileForMethod(config, authorization.method);
    if (profile && quotaEnabled(profile)) {
      const period = quotaPeriodWindow(profile.quotaPeriod, Date.now(), quotaTimeZone());
      const stored = db.getAuthorizationQuotaUsage?.(authorization.id, period.key) || null;
      if (inheritedGatewayCounters(row, authorization, stored)) {
        return { downloadDelta: 0, uploadDelta: 0 };
      }
      if (Number(stored?.reset_at || 0)) {
        return {
          downloadDelta: usageDelta(row.downloadBytes, stored.last_gateway_download_bytes),
          uploadDelta: usageDelta(row.uploadBytes, stored.last_gateway_upload_bytes)
        };
      }
    }
    return {
      downloadDelta: usageDelta(row.downloadBytes, authorization.download_bytes),
      uploadDelta: usageDelta(row.uploadBytes, authorization.upload_bytes)
    };
  }

  async function ensureConfiguredBandwidthLimits({ force = false, now = Date.now() } = {}) {
    if (!gatewayHasBandwidthProfiles(config.gateway) && !force) {
      return { applied: false, disabled: true };
    }
    if (!force && bandwidthSyncState.lastErrorAt &&
        now - bandwidthSyncState.lastErrorAt < bandwidthSyncState.backoffMs) {
      return {
        applied: false,
        skipped: true,
        reason: 'bandwidth_sync_backoff',
        error: bandwidthSyncState.lastError
      };
    }
    try {
      const result = await ensureGatewayBandwidthLimits(config.gateway, {
        force,
        authorizations: activeBandwidthAuthorizations(now)
      });
      bandwidthSyncState.lastErrorAt = 0;
      bandwidthSyncState.backoffMs = 0;
      bandwidthSyncState.lastError = '';
      return result;
    } catch (error) {
      if (!force) {
        bandwidthSyncState.lastErrorAt = Date.now();
        bandwidthSyncState.backoffMs = Math.min(
          bandwidthSyncState.backoffMs ? bandwidthSyncState.backoffMs * 2 : 60000,
          10 * 60000
        );
        bandwidthSyncState.lastError = error.message;
      }
      throw error;
    }
  }

  async function enforceAuthorizationQuota(row, authorization) {
    const profile = quotaProfileForMethod(config, authorization.method);
    if (!profile || !quotaEnabled(profile)) return null;
    const now = Date.now();
    const period = quotaPeriodWindow(profile.quotaPeriod, now, quotaTimeZone());
    const existingUsage = db.getAuthorizationQuotaUsage?.(authorization.id, period.key) || null;
    const inheritedCounters = inheritedGatewayCounters(row, authorization, existingUsage);
    const sampled = inheritedCounters
      ? db.resetAuthorizationQuotaUsage?.(authorization, period, {
        downloadBytes: row.downloadBytes,
        uploadBytes: row.uploadBytes,
        resetAt: now
      })
      : db.recordAuthorizationQuotaUsage?.(authorization, period, {
        downloadBytes: row.downloadBytes,
        uploadBytes: row.uploadBytes,
        updatedAt: now
      });
    const quotaUsage = sampled || { download_bytes: 0, upload_bytes: 0 };
    const syslogUsage = db.authorizationSyslogUsage?.(authorization, {
      periodStartAt: period.startAt,
      periodEndAt: period.endAt,
      resetAt: quotaUsage.reset_at,
      baselineDownloadBytes: quotaUsage.last_gateway_download_bytes,
      baselineUploadBytes: quotaUsage.last_gateway_upload_bytes
    }) || { downloadBytes: 0, uploadBytes: 0 };
    const usage = {
      downloadBytes: Math.max(Number(quotaUsage.download_bytes || 0), Number(syslogUsage.downloadBytes || 0)),
      uploadBytes: Math.max(Number(quotaUsage.upload_bytes || 0), Number(syslogUsage.uploadBytes || 0))
    };
    const usageBaseline = {
      downloadBytes: Number(quotaUsage.authorization_download_bytes_at_reset || 0),
      uploadBytes: Number(quotaUsage.authorization_upload_bytes_at_reset || 0)
    };
    const exceeded = quotaExceeded(profile, usage);
    if (!exceeded) {
      return {
        exceeded: false,
        usage,
        usageBaseline,
        period,
        resetAt: Number(quotaUsage.reset_at || 0),
        inheritedCounters
      };
    }
    if (row.sessionId) await disconnectGatewaySession(config.gateway, row.sessionId);
    db.setAuthorizationQuotaBlock?.(authorization.id, {
      periodKey: period.key,
      blockedUntil: Math.min(Number(authorization.expires_at || period.endAt), period.endAt),
      exceededAt: now
    });
    return {
      exceeded: true,
      direction: exceeded,
      usage,
      usageBaseline,
      period,
      resetAt: Number(quotaUsage.reset_at || 0),
      inheritedCounters
    };
  }

  function quotaSummaryForAuthorization(authorization, now = Date.now()) {
    authorization = authorizationWithEffectiveAccess(config, authorization);
    const profile = quotaProfileForMethod(config, authorization.method);
    if (!profile) return {};
    const period = quotaPeriodWindow(profile.quotaPeriod, now, quotaTimeZone());
    const stored = db.getAuthorizationQuotaUsage?.(authorization.id, period.key) || null;
    const syslogUsage = db.authorizationSyslogUsage?.(authorization, {
      periodStartAt: period.startAt,
      periodEndAt: period.endAt,
      resetAt: stored?.reset_at,
      baselineDownloadBytes: stored?.last_gateway_download_bytes,
      baselineUploadBytes: stored?.last_gateway_upload_bytes
    }) || { downloadBytes: 0, uploadBytes: 0 };
    const resetAt = Number(stored?.reset_at || 0);
    const fallbackDownload = !resetAt && Number(authorization.created_at || 0) >= period.startAt
      ? Number(authorization.download_bytes || 0)
      : 0;
    const fallbackUpload = !resetAt && Number(authorization.created_at || 0) >= period.startAt
      ? Number(authorization.upload_bytes || 0)
      : 0;
    return {
      quota_period: profile.quotaPeriod || 'daily',
      quota_period_start_at: period.startAt,
      quota_period_end_at: period.endAt,
      quota_download_limit_bytes: quotaLimitBytes(profile.downloadQuotaGb),
      quota_upload_limit_bytes: quotaLimitBytes(profile.uploadQuotaGb),
      quota_download_bytes: Math.max(
        Number(stored?.download_bytes || 0),
        Number(syslogUsage.downloadBytes || 0),
        fallbackDownload
      ),
      quota_upload_bytes: Math.max(
        Number(stored?.upload_bytes || 0),
        Number(syslogUsage.uploadBytes || 0),
        fallbackUpload
      )
    };
  }

  function quotaGatewayUser(authorization) {
    return `${authorization.method}:${authorization.identity}`.slice(0, 128);
  }

  async function resetAuthorizationQuota(authorization) {
    authorization = authorizationWithEffectiveAccess(config, authorization);
    const profile = quotaProfileForMethod(config, authorization.method);
    if (!profile || !quotaEnabled(profile)) {
      throw new HttpError(400, 'This session does not have a quota limit.', 'quota_not_configured');
    }
    const now = Date.now();
    const period = quotaPeriodWindow(profile.quotaPeriod, now, quotaTimeZone());
    const syslogUsage = db.authorizationSyslogUsage?.(authorization, {
      periodStartAt: period.startAt,
      periodEndAt: period.endAt
    }) || { downloadBytes: 0, uploadBytes: 0 };
    const baselineDownload = Math.max(
      Number(authorization.download_bytes || 0),
      Number(syslogUsage.sessionDownloadBytes || 0),
      Number(syslogUsage.downloadBytes || 0)
    );
    const baselineUpload = Math.max(
      Number(authorization.upload_bytes || 0),
      Number(syslogUsage.sessionUploadBytes || 0),
      Number(syslogUsage.uploadBytes || 0)
    );
    db.resetAuthorizationQuotaUsage?.(authorization, period, {
      downloadBytes: baselineDownload,
      uploadBytes: baselineUpload,
      authorizationDownloadBytes: baselineDownload,
      authorizationUploadBytes: baselineUpload,
      resetAt: now
    });
    db.clearAuthorizationQuotaBlock?.(authorization.id, now);

    let gatewayRestored = false;
    let gatewayError = '';
    const active = authorization.status === 'active' &&
      !authorization.ended_at &&
      Number(authorization.expires_at) > now;
    if (active && authorization.client_ip) {
      try {
        const gateway = await authorizeGateway(config.gateway, {
          user: quotaGatewayUser(authorization),
          clientIp: authorization.client_ip
        });
        db.moveAuthorizationGatewaySession(authorization.id, {
          clientIp: authorization.client_ip,
          clientMac: authorization.client_mac || gateway.clientMac || '',
          gatewaySessionId: gateway.storedSessionId || gateway.sessionId,
          gatewayResponse: gateway.response,
          lastSeenAt: now
        });
        const restored = db.getAuthorization(authorization.id);
        await synchronizeAuthorizationKeaLease(restored);
        await ensureConfiguredBandwidthLimits({ now }).catch(error => {
          console.warn(`Bandwidth limits could not be synchronized after quota reset: ${error.message}`);
        });
        gatewayRestored = true;
      } catch (error) {
        gatewayError = error.message;
        console.warn(`Gateway access could not be restored after quota reset: ${error.message}`);
      }
    }

    const updated = db.getAuthorization(authorization.id) || authorization;
    return {
      ok: true,
      gatewayRestored,
      gatewayError,
      session: { ...updated, ...quotaSummaryForAuthorization(updated, now) }
    };
  }

  async function syncUsage() {
    db.clearExpiredAuthorizationQuotaBlocks?.();
    let rawRows;
    try {
      rawRows = await listGatewaySessions(config.gateway);
    } catch (error) {
      await notifyOpnsenseConnectionLost(error);
      throw error;
    }
    const sampledAt = Date.now();
    let arpRows = [];
    try {
      arpRows = await listGatewayArpEntries(config.gateway);
    } catch (error) {
      console.warn(`OPNsense ARP table could not be read: ${error.message}`);
    }
    let dhcpRows = [];
    try {
      dhcpRows = await listGatewayDhcpLeases(config.gateway);
    } catch (error) {
      console.warn(`OPNsense DHCP leases could not be read: ${error.message}`);
    }
    const arpLookup = buildArpLookup([...arpRows, ...dhcpRows]);
    let matched = 0;
    let expiredDisconnected = 0;
    let staleIpDisconnected = 0;
    let staleIpMoved = 0;
    let staleIpFailed = 0;
    let quotaDisconnected = 0;
    let totalDownload = 0;
    let totalUpload = 0;
    const syslogRecords = [];
    const trafficSettings = trafficLogSettings(config);
    const trafficRecords = [];
    if (trafficSettings.enabled && config.gateway.mode === 'opnsense-api') {
      try {
        const sample = await readGatewayInterfaceTrafficCounters(config.gateway, config.gateway.shaperInterface || 'wan');
        gatewayTrafficState.previous = gatewayTrafficState.current;
        gatewayTrafficState.current = sample;
        gatewayTrafficState.checkedAt = sample.sampledAt || Date.now();
        gatewayTrafficState.error = '';
        gatewayTrafficState.errorCode = '';
        const interfaceRecord = trafficLogRecordFromInterfaceCounters(sample, trafficSettings);
        if (interfaceRecord) trafficRecords.push(interfaceRecord);
      } catch (error) {
        gatewayTrafficState.error = error.message;
        gatewayTrafficState.errorCode = error.code || '';
        const warningAt = Date.now();
        if (warningAt - interfaceCounterLogState.lastWarningAt > 60 * 1000) {
          interfaceCounterLogState.lastWarningAt = warningAt;
          console.warn(`OPNsense interface traffic counters could not be logged: ${error.message}`);
        }
      }
    }
    for (const raw of rawRows) {
      const baseRow = normalizeGatewaySession(raw);
      const authorization = db.findAuthorizationForGateway(baseRow);
      const row = authorization ? alignGatewaySessionToAuthorization(baseRow, authorization) : baseRow;
      const resolvedClientMac = authorization
        ? usageClientMac(row, authorization, arpLookup)
        : (arpLookup.ipToMac.get(row.clientIp) || normalizedMac(row.clientMac));
      const syslogRecord = syslogRecordFromSession({
        ...row,
        clientMac: resolvedClientMac || row.clientMac
      }, authorization, config.syslog);
      if (syslogRecord) syslogRecords.push(syslogRecord);
      if (trafficSettings.enabled) {
        const { downloadDelta, uploadDelta } = authorizationTrafficDeltas(row, authorization);
        if (downloadDelta || uploadDelta || row.sourcePort || row.destinationIp || row.destinationPort) {
          const trafficRecord = trafficLogRecordFromSession({
            ...row,
            clientMac: resolvedClientMac || row.clientMac,
            downloadDeltaBytes: downloadDelta,
            uploadDeltaBytes: uploadDelta,
            cumulativeDownloadBytes: row.downloadBytes,
            cumulativeUploadBytes: row.uploadBytes,
            createdAt: Date.now()
          }, authorization, trafficSettings);
          if (trafficRecord) trafficRecords.push(trafficRecord);
        }
      }
      if (!authorization) continue;
      if (authorization.ended_at || Number(authorization.expires_at) <= Date.now()) {
        if (row.sessionId) {
          try {
            await disconnectGatewaySession(config.gateway, row.sessionId);
            await deleteAuthorizationKeaLease(authorization, { markDeleted: true });
            if (db.endAuthorization(authorization.id, 'session_expired')) {
              expiredDisconnected += 1;
              await notifyAccessExpired(authorization);
            }
          } catch (error) {
            console.warn(`Expired OPNsense session could not be disconnected: ${error.message}`);
          }
        }
        matched += 1;
        continue;
      }
      let staleIpAction = '';
      try {
        staleIpAction = await repairStaleIpSession(row, authorization, arpLookup);
      } catch (error) {
        staleIpFailed += 1;
        console.warn(`Stale OPNsense session could not be repaired: ${error.message}`);
        matched += 1;
        continue;
      }
      if (staleIpAction) {
        if (staleIpAction === 'disconnected') staleIpDisconnected += 1;
        matched += 1;
        continue;
      }
      refreshAuthorizationGatewaySession(row, authorization, arpLookup);
      const quota = await enforceAuthorizationQuota(row, authorization);
      const usageDownloadBytes = quota?.resetAt
        ? Number(quota.usageBaseline?.downloadBytes || 0) + quota.usage.downloadBytes
        : row.downloadBytes;
      const usageUploadBytes = quota?.resetAt
        ? Number(quota.usageBaseline?.uploadBytes || 0) + quota.usage.uploadBytes
        : row.uploadBytes;
      db.updateAuthorizationUsage(authorization.id, {
        ...row,
        downloadBytes: usageDownloadBytes,
        uploadBytes: usageUploadBytes,
        clientMac: usageClientMac(row, authorization, arpLookup),
        sampledAt,
        allowDecrease: Boolean(quota?.resetAt)
      });
      const updatedAuthorization = db.getAuthorization(authorization.id);
      if (quota?.exceeded) {
        quotaDisconnected += 1;
        matched += 1;
        totalDownload += row.downloadBytes;
        totalUpload += row.uploadBytes;
        continue;
      }
      await synchronizeAuthorizationKeaLease(updatedAuthorization);
      matched += 1;
      totalDownload += row.downloadBytes;
      totalUpload += row.uploadBytes;
    }
    const expired = await expireAuthorizations();
    expiredDisconnected += expired.disconnected;
    await ensureConfiguredBandwidthLimits({ now: Date.now() }).catch(error => {
      console.warn(`Bandwidth limits could not be synchronized: ${error.message}`);
    });
    const syslog = config.syslog.enabled
      ? {
        enabled: true,
        networks: config.syslog.networks,
        eligible: syslogRecords.length,
        ...db.appendSyslogLogs(syslogRecords),
        deletedExpired: 0
      }
      : { enabled: false, networks: config.syslog.networks, eligible: 0, inserted: 0, skipped: 0 };
    let traffic;
    if (trafficSettings.enabled) {
      const enrichedTrafficRecords = await enrichTrafficLogRecords(trafficRecords, trafficSettings);
      const databaseResult = db.appendTrafficLogs(enrichedTrafficRecords);
      const storageConfig = trafficLogStorageConfig();
      const fileResult = appendTrafficLogFileRecords(storageConfig, enrichedTrafficRecords);
      const fileCleanup = cleanupTrafficLogFileIfDue(storageConfig, trafficSettings.retentionDays);
      traffic = {
        enabled: true,
        eligible: trafficRecords.length,
        ...databaseResult,
        deletedExpired: db.cleanupTrafficLogs(trafficSettings.retentionDays),
        file: {
          inserted: fileResult.inserted,
          skipped: fileResult.skipped,
          deletedExpired: fileCleanup.deleted,
          path: fileResult.filePath
        }
      };
    } else {
      traffic = { enabled: false, eligible: 0, inserted: 0, skipped: 0, deletedExpired: 0 };
    }
    const syncedAt = Date.now();
    db.setRuntimeState('opnsense_last_successful_sync_at', syncedAt, syncedAt);
    markOpnsenseConnectionRestored(syncedAt);
    return {
      gatewayMode: config.gateway.mode,
      received: rawRows.length,
      matched,
      expiredDisconnected,
      staleIpDisconnected,
      staleIpMoved,
      staleIpFailed,
      quotaDisconnected,
      arpEntries: arpRows.length,
      dhcpLeases: dhcpRows.length,
      downloadBytes: totalDownload,
      uploadBytes: totalUpload,
      law5651: syslog,
      syslog,
      trafficLogs: traffic,
      syncedAt
    };
  }

  function refreshAuthorizationGatewaySession(row, authorization, arpLookup) {
    if (!isIpv4(row.clientIp)) return false;
    const authorizationMac = normalizedMac(authorization.client_mac);
    const rowMac = normalizedMac(row.clientMac);
    const currentIpOwnerMac = arpLookup.ipToMac.get(row.clientIp);
    if (row.clientIp !== authorization.client_ip) return false;
    if (authorizationMac && currentIpOwnerMac && currentIpOwnerMac !== authorizationMac) return false;
    if (authorizationMac && rowMac && rowMac !== authorizationMac) return false;
    const sessionChanged = row.sessionId && row.sessionId !== authorization.gateway_session_id;
    const macDiscovered = !authorizationMac && (currentIpOwnerMac || rowMac);
    if (!sessionChanged && !macDiscovered) return false;
    return db.moveAuthorizationGatewaySession(authorization.id, {
      clientIp: row.clientIp,
      clientMac: authorizationMac || currentIpOwnerMac || rowMac,
      gatewaySessionId: row.sessionId || authorization.gateway_session_id,
      gatewayResponse: null,
      lastSeenAt: row.lastSeenAt || Date.now()
    });
  }

  function usageClientMac(row, authorization, arpLookup) {
    const ownerMac = isIpv4(row.clientIp) ? arpLookup.ipToMac.get(row.clientIp) : '';
    if (ownerMac) return ownerMac;
    const authorizationMac = normalizedMac(authorization.client_mac);
    const rowMac = normalizedMac(row.clientMac);
    if (!authorizationMac) return '';
    if (authorizationMac && rowMac && rowMac !== authorizationMac) return '';
    return rowMac;
  }

  async function repairStaleIpSession(row, authorization, arpLookup) {
    if (!row.sessionId || !isIpv4(row.clientIp)) return '';
    const authorizationMac = normalizedMac(authorization.client_mac);
    const rowMac = normalizedMac(row.clientMac);
    if (row.clientIp !== authorization.client_ip) {
      await disconnectGatewaySession(config.gateway, row.sessionId);
      db.clearAuthorizationGatewaySession(authorization.id, { lastSeenAt: row.lastSeenAt || Date.now() });
      return 'disconnected';
    }
    if (!authorizationMac) return '';
    const currentIpOwnerMac = arpLookup.ipToMac.get(row.clientIp);
    const observedMac = currentIpOwnerMac || rowMac;
    if (!observedMac || observedMac === authorizationMac) {
      return '';
    }

    await disconnectGatewaySession(config.gateway, row.sessionId);
    db.clearAuthorizationGatewaySession(authorization.id, { lastSeenAt: row.lastSeenAt || Date.now() });
    return 'disconnected';
  }

  async function expireAuthorizations({ now = Date.now(), limit = 100 } = {}) {
    normalizeActiveAuthorizationDurations(db, config, { limit: Math.max(1000, limit) });
    const rows = config.gateway.keaLeaseSyncEnabled === true
      ? db.listExpiredAuthorizationCleanups({ now, limit, gatewayMode: config.gateway.mode })
      : db.listExpiredActiveAuthorizations({ now, limit, gatewayMode: config.gateway.mode });
    let disconnected = 0;
    let failed = 0;
    let missingGatewaySession = 0;
    for (const authorization of rows) {
      try {
        if (!authorization.ended_at) {
          if (authorization.gateway_session_id) {
            await disconnectGatewaySession(config.gateway, authorization.gateway_session_id);
            if (db.endAuthorization(authorization.id, 'session_expired')) {
              disconnected += 1;
              await notifyAccessExpired(authorization);
            }
          } else {
            missingGatewaySession += 1;
            if (db.endAuthorization(authorization.id, 'session_expired')) {
              await notifyAccessExpired(authorization);
            }
          }
        }
        if (!authorization.kea_deleted_at) {
          await deleteAuthorizationKeaLease(authorization, { markDeleted: true });
        }
      } catch (error) {
        failed += 1;
        console.warn(`Expired OPNsense session could not be disconnected: ${error.message}`);
      }
    }
    return {
      checked: rows.length,
      disconnected,
      failed,
      missingGatewaySession,
      expiredAt: Date.now()
    };
  }

  function adminApprovalMessage(input, fallback) {
    return String(input || fallback || '').replace(/\s+/gu, ' ').trim().slice(0, 500);
  }

  async function notifyAdminApprovalDecision(approvalRequest, decision) {
    try {
      return await sendAdminApprovalNotification(config, approvalRequest, decision);
    } catch (error) {
      console.warn(`Admin approval notification failed: ${error.message}`);
      return { sent: 0, failed: 1, error: error.message };
    }
  }

  async function latestReleaseStatus({ refresh = false } = {}) {
    const now = Date.now();
    if (!refresh && releaseStatusCache && releaseStatusCacheExpiresAt > now) return releaseStatusCache;
    releaseStatusCache = await fetchReleaseStatus({ releaseFetcher });
    releaseStatusCacheExpiresAt = now + RELEASE_CHECK_CACHE_MS;
    return releaseStatusCache;
  }

  async function handle(request, response, url) {
    const path = url.pathname;
    if (!path.startsWith('/api/admin/')) return false;

    if (request.method === 'GET' && path === '/api/admin/session') {
      const session = currentSession(request);
      sendJson(response, 200, {
        enabled: config.admin.enabled,
        authenticated: Boolean(session),
        user: session?.username || '',
        csrfToken: session?.csrfToken || '',
        appName: config.appName,
        gatewayMode: config.gateway.mode,
        defaultLanguage: config.defaultLanguage
      });
      return true;
    }

    if (request.method === 'POST' && path === '/api/admin/login') {
      if (!config.admin.enabled) throw new HttpError(503, 'Set ADMIN_PASSWORD to enable the admin panel', 'admin_disabled');
      const clientIp = getClientIp(request, config.trustProxy);
      if (db.countEvents('admin_login', clientIp, '', Date.now() - 15 * 60 * 1000) >= 10) {
        throw new HttpError(429, 'Too many login attempts. Try again later.', 'rate_limited');
      }
      db.recordEvent('admin_login', clientIp, '');
      const { value } = await readJson(request);
      const suppliedUser = String(value.username || '');
      const suppliedHash = keyedHash(config.appSecret, String(value.password || ''));
      const expectedHash = keyedHash(config.appSecret, config.admin.password);
      if (suppliedUser !== config.admin.username || !safeEqualHex(suppliedHash, expectedHash)) {
        notifyAdminLoginFailed(request, suppliedUser, 'invalid_credentials', value.notificationPublicIp);
        throw new HttpError(401, 'Invalid username or password', 'invalid_credentials');
      }
      const sessionTtl = config.admin.sessionHours * 60 * 60 * 1000;
      const token = generateSecret(32);
      const session = {
        username: config.admin.username,
        csrfToken: generateSecret(24),
        expiresAt: Date.now() + sessionTtl
      };
      sessions.set(keyedHash(config.appSecret, token), session);
      setSessionCookie(response, token, Math.floor(sessionTtl / 1000));
      audit(request, session, 'admin_login');
      notifyAdminLogin(request, session, value.notificationPublicIp);
      sendJson(response, 200, {
        authenticated: true,
        user: session.username,
        csrfToken: session.csrfToken
      });
      return true;
    }

    if (request.method === 'POST' && path === '/api/admin/logout') {
      const session = currentSession(request);
      const token = cookieValue(request, COOKIE_NAME);
      if (session) audit(request, session, 'admin_logout');
      if (token) sessions.delete(keyedHash(config.appSecret, token));
      setSessionCookie(response, '', 0);
      sendJson(response, 200, { ok: true });
      return true;
    }

    const needsCsrf = !['GET', 'HEAD'].includes(request.method);
    const session = requireSession(request, { csrf: needsCsrf });

    if (request.method === 'GET' && path === '/api/admin/settings') {
      sendJson(response, 200, {
        ...getSettings(),
        appearanceAssets: appearanceAssets(config)
      });
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/releases/latest') {
      sendJson(response, 200, await latestReleaseStatus({
        refresh: url.searchParams.get('refresh') === '1'
      }));
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/opnsense-template') {
      sendJson(response, 200, {
        defaults: {
          ...OPNSENSE_TEMPLATE_DEFAULTS,
          targetUrl: opnsenseTemplateDefaultTargetUrl(request)
        }
      });
      return true;
    }

    if (request.method === 'POST' && path === '/api/admin/opnsense-template.zip') {
      const { value } = await readJson(request, 16 * 1024);
      let archive;
      try {
        archive = createOpnsenseTemplateZip(value.template || value);
      } catch (error) {
        throw new HttpError(400, error.message, error.code || 'invalid_opnsense_template');
      }
      audit(request, session, 'opnsense_template_created', 'opnsense_template', 'index.html', {
        filename: archive.filename,
        bytes: archive.buffer.length
      });
      response.writeHead(200, {
        'content-type': 'application/zip',
        'content-disposition': `attachment; filename="${archive.filename}"`,
        'content-length': archive.buffer.length,
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff'
      });
      response.end(archive.buffer);
      return true;
    }

    if (request.method === 'PUT' && path === '/api/admin/settings') {
      const { value } = await readJson(request, 256 * 1024);
      assertSyslogTimestampDisableAllowed(value.settings || {}, { db, config });
      const result = saveSettings(value.settings);
      const accessDurationChanged = result.saved.some(key => /_ACCESS_DURATION_(VALUE|UNIT)$/u.test(key));
      const accessDurationRefresh = accessDurationChanged
        ? normalizeActiveAuthorizationDurations(db, config, { limit: 5000 })
        : { checked: 0, updated: 0 };
      const accessDurationExpiry = accessDurationRefresh.updated
        ? await expireAuthorizations({ limit: 500 })
        : null;
      let bandwidthWarning = '';
      let bandwidthWarningCode = '';
      const bandwidthConnectionKeys = new Set([
        'GATEWAY_MODE',
        'OPNSENSE_BASE_URL',
        'OPNSENSE_ZONE_ID',
        'OPNSENSE_API_KEY',
        'OPNSENSE_API_SECRET',
        'OPNSENSE_TLS_REJECT_UNAUTHORIZED'
      ]);
      const bandwidthSettingKeys = new Set([
        'OPNSENSE_SHAPER_INTERFACE',
        'OPNSENSE_SHAPER_NETWORK',
        'VOUCHER_DOWNLOAD_SPEED_LIMIT_MBPS',
        'VOUCHER_UPLOAD_SPEED_LIMIT_MBPS',
        'ADMIN_APPROVAL_DOWNLOAD_SPEED_LIMIT_MBPS',
        'ADMIN_APPROVAL_UPLOAD_SPEED_LIMIT_MBPS',
        'NVI_DOWNLOAD_SPEED_LIMIT_MBPS',
        'NVI_UPLOAD_SPEED_LIMIT_MBPS',
        'EMAIL_DOWNLOAD_SPEED_LIMIT_MBPS',
        'EMAIL_UPLOAD_SPEED_LIMIT_MBPS',
        'WHATSAPP_DOWNLOAD_SPEED_LIMIT_MBPS',
        'WHATSAPP_UPLOAD_SPEED_LIMIT_MBPS',
        'TELEGRAM_DOWNLOAD_SPEED_LIMIT_MBPS',
        'TELEGRAM_UPLOAD_SPEED_LIMIT_MBPS',
        'SMS_DOWNLOAD_SPEED_LIMIT_MBPS',
        'SMS_UPLOAD_SPEED_LIMIT_MBPS'
      ]);
      const bandwidthSettingsChanged = result.saved.some(key => bandwidthSettingKeys.has(key));
      const connectionChangedWithActiveLimits =
        result.saved.some(key => bandwidthConnectionKeys.has(key)) &&
        gatewayHasBandwidthProfiles(config.gateway);
      if (bandwidthSettingsChanged || connectionChangedWithActiveLimits) {
        try {
          await ensureConfiguredBandwidthLimits({ force: true });
        } catch (error) {
          bandwidthWarning = error.message;
          bandwidthWarningCode = error.code || '';
        }
      }
      audit(request, session, 'settings_updated', 'settings', '', {
        keys: result.saved,
        restartRequired: result.restartRequired,
        accessDurationRefresh,
        accessDurationExpiry,
        bandwidthWarning,
        bandwidthWarningCode
      });
      sendJson(response, 200, {
        ok: true,
        ...result,
        accessDurationRefresh,
        accessDurationExpiry,
        bandwidthWarning,
        bandwidthWarningCode,
        appName: config.appName,
        defaultLanguage: config.defaultLanguage,
        gatewayMode: config.gateway.mode,
        emailEnabled: config.smtp.enabled,
        nviEnabled: config.nvi.enabled,
        whatsappEnabled: config.whatsapp.enabled,
        telegramEnabled: config.telegram.enabled,
        smsEnabled: config.sms.enabled
      });
      return true;
    }

    const appearanceAssetMatch = path.match(
      /^\/api\/admin\/appearance\/assets\/(logo|card-background|body-background)$/u
    );
    if (request.method === 'PUT' && appearanceAssetMatch) {
      const kind = appearanceAssetMatch[1];
      const chunked = Boolean(request.headers['x-gh-upload-id']);
      const result = chunked
        ? await saveAppearanceAssetChunk(request, config, kind)
        : { complete: true, asset: await saveAppearanceAsset(request, config, kind) };
      if (!result.complete) {
        sendJson(response, 200, { ok: true, complete: false, received: result.received });
        return true;
      }
      const asset = result.asset;
      audit(request, session, 'appearance_asset_uploaded', 'appearance_asset', kind, {
        contentType: asset.contentType,
        size: asset.size
      });
      sendJson(response, 200, { ok: true, complete: true, asset });
      return true;
    }

    if (request.method === 'DELETE' && appearanceAssetMatch) {
      const kind = appearanceAssetMatch[1];
      const asset = deleteAppearanceAsset(config, kind);
      audit(request, session, 'appearance_asset_deleted', 'appearance_asset', kind);
      sendJson(response, 200, { ok: true, asset });
      return true;
    }

    if (request.method === 'POST' && path === '/api/admin/settings/test-email') {
      if (!config.smtp.enabled) {
        throw new HttpError(503, 'Email verification is not configured', 'email_disabled');
      }
      const { value } = await readJson(request);
      const recipient = normalizeEmail(value.recipient);
      if (!isValidEmail(recipient)) {
        throw new HttpError(400, 'Enter a valid test recipient email address', 'invalid_email');
      }
      const language = requestLanguage(request, value.language, config.defaultLanguage);
      const testCode = '246810';
      try {
        await sendMail(config.smtp, {
          to: recipient,
          subject: `${config.appName} SMTP test`,
          text: `${config.appName} SMTP configuration is working.\n\nTest code: ${testCode}`,
          html: `<div style="font-family:system-ui,sans-serif;max-width:520px;margin:auto"><h2>${config.appName}</h2><p>${language === 'tr' ? 'SMTP yapılandırması çalışıyor.' : 'SMTP configuration is working.'}</p><p style="font-size:28px;font-weight:700;letter-spacing:6px">${testCode}</p></div>`
        });
      } catch (error) {
        throw new HttpError(502, error.message, 'smtp_test_failed');
      }
      audit(request, session, 'smtp_test_sent', 'email', recipient);
      sendJson(response, 200, { ok: true, recipient });
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/dashboard') {
      const period = periodParam(url.searchParams.get('trafficPeriod') || 'daily');
      const topSitesHours = integerParam(url.searchParams.get('topSitesHours'), 6, { min: 1, max: 24 });
      const topBandwidthHours = integerParam(url.searchParams.get('topBandwidthHours'), topSitesHours, { min: 1, max: 24 });
      sendJson(response, 200, {
        ...db.dashboard(),
        traffic: dashboardTrafficSeries(period),
        topSites: dashboardTopSites(topSitesHours),
        topBandwidthClients: dashboardTopBandwidthClients(topBandwidthHours),
        trafficLogSettings: trafficLogSettings(trafficLogStorageConfig())
      });
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/traffic/series') {
      sendJson(response, 200, {
        ...dashboardTrafficSeries(periodParam(url.searchParams.get('period') || 'daily')),
        settings: trafficLogSettings(trafficLogStorageConfig())
      });
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/gateway/status') {
      if (config.gateway.mode === 'mock') {
        sendJson(response, 200, { connected: true, gatewayMode: 'mock', sessions: 0 });
        return true;
      }
      try {
        const rows = await listGatewaySessions(config.gateway);
        sendJson(response, 200, {
          connected: true,
          gatewayMode: config.gateway.mode,
          sessions: rows.length
        });
      } catch (error) {
        sendJson(response, 200, {
          connected: false,
          gatewayMode: config.gateway.mode,
          sessions: 0,
          error: error.message
        });
      }
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/sessions') {
      normalizeActiveAuthorizationDurations(db, config, { limit: 5000 });
      const result = db.listAuthorizations({
        search: url.searchParams.get('search') || '',
        method: url.searchParams.get('method') || '',
        state: url.searchParams.get('state') || '',
        limit: integerParam(url.searchParams.get('limit'), 100, { min: 1, max: 500 }),
        offset: integerParam(url.searchParams.get('offset'), 0, { min: 0, max: 100000 })
      });
      sendJson(response, 200, {
        ...result,
        rows: result.rows.map(row => {
          const authorization = authorizationWithEffectiveAccess(config, row);
          return { ...authorization, ...quotaSummaryForAuthorization(authorization) };
        })
      });
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/verifications') {
      sendJson(response, 200, db.listChallenges({
        search: url.searchParams.get('search') || '',
        kind: url.searchParams.get('kind') || '',
        status: url.searchParams.get('status') || '',
        limit: integerParam(url.searchParams.get('limit'), 100, { min: 1, max: 500 }),
        offset: integerParam(url.searchParams.get('offset'), 0, { min: 0, max: 100000 })
      }));
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/admin-approval/requests') {
      sendJson(response, 200, db.listAdminApprovalRequests({
        search: url.searchParams.get('search') || '',
        status: url.searchParams.get('status') || '',
        limit: integerParam(url.searchParams.get('limit'), 100, { min: 1, max: 500 }),
        offset: integerParam(url.searchParams.get('offset'), 0, { min: 0, max: 100000 })
      }));
      return true;
    }

    const adminApprovalDecisionMatch = path.match(/^\/api\/admin\/admin-approval\/requests\/([^/]+)\/(approve|reject)$/u);
    if (request.method === 'POST' && adminApprovalDecisionMatch) {
      const id = decodeURIComponent(adminApprovalDecisionMatch[1]);
      const action = adminApprovalDecisionMatch[2];
      const approvalRequest = db.getAdminApprovalRequest(id);
      if (!approvalRequest) throw new HttpError(404, 'Admin approval request not found', 'admin_approval_not_found');
      if (approvalRequest.status !== 'pending') {
        throw new HttpError(409, 'Admin approval request is no longer pending', 'admin_approval_not_pending');
      }
      if (Number(approvalRequest.request_expires_at) < Date.now()) {
        db.expireAdminApprovalRequests();
        throw new HttpError(410, 'Admin approval request has expired', 'admin_approval_expired');
      }

      const { value } = await readJson(request);
      if (action === 'approve') {
        const message = adminApprovalMessage(value.message, config.adminApproval.approveText);
        let result;
        try {
          result = await grantAccess({
            db,
            config,
            method: 'admin-approval',
            identity: approvalRequest.identity,
            clientIp: approvalRequest.client_ip,
            clientMac: approvalRequest.client_mac,
            duration: config.adminApproval.accessDuration,
            redirectUrl: approvalRequest.redirect_url
          });
        } catch (error) {
          const failed = db.decideAdminApprovalRequest(id, {
            status: 'failed',
            adminUser: session.username,
            message,
            authorizationId: error.authorizationId || '',
            error: error.message
          }) || db.getAdminApprovalRequest(id);
          audit(request, session, 'admin_approval_failed', 'admin_approval', id, {
            clientIp: approvalRequest.client_ip,
            error: error.message
          });
          sendJson(response, error.code === 'quota_exceeded' ? 429 : 502, {
            ok: false,
            request: failed,
            error: error.code === 'quota_exceeded' ? 'quota_exceeded' : 'gateway_failed',
            message: error.message,
            retryAt: error.retryAt || null
          });
          return true;
        }
        const decided = db.decideAdminApprovalRequest(id, {
          status: 'approved',
          adminUser: session.username,
          message,
          authorizationId: result.authorizationId
        });
        if (!decided) throw new HttpError(409, 'Admin approval request is no longer pending', 'admin_approval_not_pending');
        await notifyUserVerified(result, {
          method: 'admin-approval',
          identity: approvalRequest.identity,
          clientIp: approvalRequest.client_ip,
          clientMac: approvalRequest.client_mac
        });
        const notification = await notifyAdminApprovalDecision(decided, {
          status: 'approved',
          message,
          decidedAt: decided.decided_at,
          expiresAt: result.expiresAt
        });
        audit(request, session, 'admin_approval_approved', 'admin_approval', id, {
          clientIp: approvalRequest.client_ip,
          authorizationId: result.authorizationId,
          notification
        });
        sendJson(response, 200, { ok: true, request: decided, authorization: result, notification });
        return true;
      }

      const message = adminApprovalMessage(value.message, config.adminApproval.rejectText);
      const decided = db.decideAdminApprovalRequest(id, {
        status: 'rejected',
        adminUser: session.username,
        message
      });
      if (!decided) throw new HttpError(409, 'Admin approval request is no longer pending', 'admin_approval_not_pending');
      const notification = await notifyAdminApprovalDecision(decided, {
        status: 'rejected',
        message,
        decidedAt: decided.decided_at
      });
      audit(request, session, 'admin_approval_rejected', 'admin_approval', id, {
        clientIp: approvalRequest.client_ip,
        notification
      });
      sendJson(response, 200, { ok: true, request: decided, notification });
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/vouchers') {
      sendJson(response, 200, db.listVouchersAdmin({
        search: url.searchParams.get('search') || '',
        status: url.searchParams.get('status') || '',
        limit: integerParam(url.searchParams.get('limit'), 100, { min: 1, max: 500 }),
        offset: integerParam(url.searchParams.get('offset'), 0, { min: 0, max: 100000 })
      }));
      return true;
    }

    if (request.method === 'POST' && path === '/api/admin/vouchers') {
      const { value } = await readJson(request);
      const count = integerParam(value.count, 1, { min: 1, max: 500 });
      const durationMinutes = integerParam(value.durationMinutes, config.sessionMinutes, { min: 1, max: 10080 });
      const maxUses = integerParam(value.maxUses, 1, { min: 1, max: 1000 });
      const label = String(value.label || '').trim().slice(0, 100);
      const validFrom = parseTime(value.validFrom);
      const expiresAt = parseTime(value.expiresAt);
      if (validFrom && expiresAt && expiresAt <= validFrom) {
        throw new HttpError(400, 'The expiration date must be after the start date', 'invalid_date_range');
      }
      const vouchers = [];
      for (let index = 0; index < count; index += 1) {
        const code = generateVoucherCode();
        const id = db.createVoucher({
          codeHash: keyedHash(config.appSecret, normalizeVoucher(code)),
          codeHint: code.slice(-4),
          codePrefix: normalizeVoucher(code).slice(0, 4),
          label,
          maxUses,
          durationMinutes,
          validFrom,
          expiresAt
        });
        vouchers.push({ id, code });
      }
      audit(request, session, 'vouchers_created', 'voucher_batch', '', {
        count, label, durationMinutes, maxUses, validFrom, expiresAt
      });
      sendJson(response, 201, { vouchers });
      return true;
    }

    const voucherToggle = path.match(/^\/api\/admin\/vouchers\/([^/]+)\/toggle$/u);
    if (request.method === 'POST' && voucherToggle) {
      const id = decodeURIComponent(voucherToggle[1]);
      const { value } = await readJson(request);
      if (!db.setVoucherEnabled(id, Boolean(value.enabled))) {
        throw new HttpError(404, 'Voucher not found', 'voucher_not_found');
      }
      audit(request, session, value.enabled ? 'voucher_enabled' : 'voucher_disabled', 'voucher', id);
      sendJson(response, 200, { ok: true });
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/logs') {
      sendJson(response, 200, {
        rows: db.listActivity({
          search: url.searchParams.get('search') || '',
          kind: url.searchParams.get('kind') || '',
          limit: integerParam(url.searchParams.get('limit'), 150, { min: 1, max: 500 })
        })
      });
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/traffic-logs') {
      const result = listTrafficLogs(trafficLogQuery(url, {
        limit: integerParam(url.searchParams.get('limit'), 150, { min: 1, max: 500 }),
        offset: integerParam(url.searchParams.get('offset'), 0, { min: 0, max: 100000 })
      }));
      const live = await gatewayLiveInterfaceTraffic();
      sendJson(response, 200, {
        ...result,
        summary: {
          ...(result.summary || {}),
          ...live
        },
        settings: trafficLogSettings(trafficLogStorageConfig())
      });
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/traffic-logs/settings') {
      sendJson(response, 200, {
        ...getTrafficLogSettings(),
        runtime: trafficLogSettings(trafficLogStorageConfig())
      });
      return true;
    }

    if (request.method === 'PUT' && path === '/api/admin/traffic-logs/settings') {
      const { value } = await readJson(request);
      const result = saveTrafficLogSettings(value.settings || {});
      const deletedExpired = db.cleanupTrafficLogs(config.trafficLogs.retentionDays);
      const fileCleanup = cleanupTrafficLogFile(trafficLogStorageConfig(), config.trafficLogs.retentionDays);
      audit(request, session, 'traffic_logs_settings_updated', 'traffic_logs', '', {
        keys: result.saved,
        deletedExpired,
        fileDeletedExpired: fileCleanup.deleted
      });
      sendJson(response, 200, {
        ok: true,
        ...result,
        deletedExpired,
        fileDeletedExpired: fileCleanup.deleted,
        runtime: trafficLogSettings(trafficLogStorageConfig())
      });
      return true;
    }

    if (request.method === 'GET' && ['/api/admin/syslog/status', '/api/admin/5651/status'].includes(path)) {
      const healthRuntime = syslogHealthStatus();
      const storageRuntime = config.syslog.enabled
        ? syslogStorageStatus(config)
        : healthRuntime.storage;
      const timestampMode = config.syslog.timestampMode ||
        (config.syslog.kamusmTimestampEnabled ? 'kamusm' : 'disabled');
      const timestampEnabled = timestampMode !== 'disabled';
      const timestampProfile = {
        kamusm: 'kamusm-rfc3161',
        rfc3161: 'rfc3161-url',
        'api-key': 'api-key-rfc3161'
      }[timestampMode] || 'disabled';
      sendJson(response, 200, {
        enabled: config.syslog.enabled,
        networks: config.syslog.networks,
        timeZone: config.syslog.timeZone,
        retentionDays: config.syslog.retentionDays,
        exportDirectory: config.syslog.exportDirectory,
        timestampConfigured: timestampEnabled,
        timestampMode,
        timestampProfile,
        timestampUrlConfigured: Boolean(config.syslog.timestampUrl || config.syslog.timestampApiUrl || config.syslog.kamusmUrl),
        timestampApiKeyConfigured: Boolean(config.syslog.timestampApiKey),
        kamusmTimestampEnabled: Boolean(config.syslog.kamusmTimestampEnabled),
        kamusmUserConfigured: Boolean(config.syslog.kamusmUser),
        syslogEnabled: config.syslog.syslogEnabled,
        syslogHost: config.syslog.syslogHost,
        syslogPort: config.syslog.syslogPort,
        syslogRuntime: syslogReceiverStatus(),
        autoExportEnabled: Boolean(config.syslog.enabled && config.syslog.autoExportEnabled !== false),
        autoExportInterval: config.syslog.autoExportInterval || 'daily',
        autoExportIntervalMinutes: config.syslog.autoExportIntervalMinutes || 1440,
        autoExportRuntime: syslogAutoExportStatus(),
        storageAlertPercent: config.syslog.storageAlertPercent,
        storageBlockPercent: config.syslog.storageBlockPercent,
        backupEnabled: false,
        backupDirectories: [],
        evidenceProfile: {
          timestamp: timestampProfile,
          signature: 'disabled',
          backup: 'disabled',
          backupWormRequired: false,
          remoteMirror: 'disabled',
          automaticExport: config.syslog.enabled ? (config.syslog.autoExportInterval || 'daily') : 'disabled'
        },
        healthRuntime: {
          ...healthRuntime,
          storage: storageRuntime
        },
        summary: db.syslogSummary()
      });
      return true;
    }

    if (request.method === 'GET' && [
      '/api/admin/gateway/networks',
      '/api/admin/syslog/networks',
      '/api/admin/5651/networks'
    ].includes(path)) {
      try {
        sendJson(response, 200, {
          choices: await listGatewayNetworkChoices(config.gateway),
          error: ''
        });
      } catch (error) {
        sendJson(response, 200, {
          choices: [],
          error: 'OPNsense networks could not be discovered automatically. You can enter networks manually.'
        });
      }
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/gateway/interfaces') {
      try {
        sendJson(response, 200, {
          interfaces: await listGatewayInterfaces(config.gateway),
          error: ''
        });
      } catch (error) {
        sendJson(response, 200, {
          interfaces: [],
          error: 'OPNsense interfaces could not be discovered automatically. You can enter the interface manually.'
        });
      }
      return true;
    }

    if (request.method === 'POST' && ['/api/admin/syslog/sync', '/api/admin/5651/sync'].includes(path)) {
      const result = await syncUsage();
      audit(request, session, 'syslog_sync', 'syslog', config.syslog.networks, result.syslog);
      sendJson(response, 200, result);
      return true;
    }

    if (request.method === 'POST' && ['/api/admin/syslog/export', '/api/admin/5651/export'].includes(path)) {
      const timestampMode = config.syslog.timestampMode ||
        (config.syslog.kamusmTimestampEnabled ? 'kamusm' : 'disabled');
      const result = await createSyslogExportArchive({
        db,
        config,
        exportReason: timestampMode === 'kamusm'
          ? 'kamusm'
          : (timestampMode === 'disabled' ? 'manual' : 'timestamp')
      });
      audit(request, session, 'syslog_export', 'syslog', result.id, result);
      sendJson(response, 200, result);
      return true;
    }

    if (request.method === 'POST' && ['/api/admin/syslog/vacuum', '/api/admin/5651/vacuum'].includes(path)) {
      const result = db.vacuumDatabase();
      audit(request, session, 'syslog_vacuum', 'database', db.filePath, {
        durationMs: result.durationMs,
        reclaimedBytes: result.reclaimedBytes,
        backupPath: result.backupPath,
        backupBytes: result.backupBytes,
        before: result.before,
        after: result.after
      });
      sendJson(response, 200, result);
      return true;
    }

    if (request.method === 'POST' && path === '/api/admin/sync') {
      const result = await syncUsage();
      audit(request, session, 'gateway_sync', 'gateway', config.gateway.mode, result);
      sendJson(response, 200, result);
      return true;
    }

    const resetQuotaMatch = path.match(/^\/api\/admin\/sessions\/([^/]+)\/reset-quota$/u);
    if (request.method === 'POST' && resetQuotaMatch) {
      const id = decodeURIComponent(resetQuotaMatch[1]);
      const authorization = db.getAuthorization(id);
      if (!authorization) throw new HttpError(404, 'Session not found', 'session_not_found');
      const result = await resetAuthorizationQuota(authorization);
      audit(request, session, 'session_quota_reset', 'authorization', id, {
        clientIp: authorization.client_ip,
        method: authorization.method,
        gatewayRestored: result.gatewayRestored,
        gatewayError: result.gatewayError
      });
      sendJson(response, 200, result);
      return true;
    }

    const disconnectMatch = path.match(/^\/api\/admin\/sessions\/([^/]+)\/disconnect$/u);
    if (request.method === 'POST' && disconnectMatch) {
      const id = decodeURIComponent(disconnectMatch[1]);
      const authorization = db.getAuthorization(id);
      if (!authorization) throw new HttpError(404, 'Session not found', 'session_not_found');
      if (authorization.gateway_session_id) {
        await disconnectGatewaySession(config.gateway, authorization.gateway_session_id);
      }
      await deleteAuthorizationKeaLease(authorization);
      db.endAuthorization(id, 'admin_disconnect');
      audit(request, session, 'session_disconnected', 'authorization', id, {
        clientIp: authorization.client_ip,
        gatewaySessionId: authorization.gateway_session_id
      });
      sendJson(response, 200, { ok: true });
      return true;
    }

    if (request.method === 'GET' && ['/api/admin/export/syslog.csv', '/api/admin/export/5651.csv'].includes(path)) {
      const result = db.listSyslogLogs({ limit: 100000, order: 'asc' });
      const body = syslogCsv(result.rows, { timeZone: config.syslog.timeZone });
      response.writeHead(200, {
        'content-type': 'text/csv; charset=utf-8',
        'content-disposition': `attachment; filename="syslog-logs-${syslogFileDate(Date.now(), config.syslog.timeZone).slice(0, 10)}.csv"`,
        'content-length': Buffer.byteLength(body),
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff'
      });
      response.end(body);
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/export/traffic-logs.csv') {
      const result = listTrafficLogs(trafficLogQuery(url, {
        limit: 100000,
        order: 'asc'
      }));
      const body = trafficLogsCsv(result.rows);
      response.writeHead(200, {
        'content-type': 'text/csv; charset=utf-8',
        'content-disposition': `attachment; filename="traffic-logs-${new Date().toISOString().slice(0, 10)}.csv"`,
        'content-length': Buffer.byteLength(body),
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff'
      });
      response.end(body);
      return true;
    }

    if (request.method === 'GET' && path === '/api/admin/export/sessions.csv') {
      normalizeActiveAuthorizationDurations(db, config, { limit: 5000 });
      const result = db.listAuthorizations({ limit: 5000 });
      const headers = [
        'Date', 'Method', 'Identity', 'IP', 'MAC', 'Status', 'Download (bytes)',
        'Upload (bytes)', 'Expires', 'Gateway Session'
      ];
      const lines = [headers, ...result.rows.map(row => {
        row = authorizationWithEffectiveAccess(config, row);
        return [
          new Date(Number(row.created_at)).toISOString(),
          row.method,
          row.method === 'voucher' ? `${row.voucher_label || 'Voucher'} (…${row.voucher_hint || ''})` : row.identity,
          row.client_ip,
          row.client_mac || '',
          row.status,
          row.download_bytes || 0,
          row.upload_bytes || 0,
          new Date(Number(row.expires_at)).toISOString(),
          row.gateway_session_id || ''
        ];
      })].map(columns => columns.map(escapeCsv).join(',')).join('\n');
      const body = `\uFEFF${lines}`;
      response.writeHead(200, {
        'content-type': 'text/csv; charset=utf-8',
        'content-disposition': `attachment; filename="hotspot-sessions-${new Date().toISOString().slice(0, 10)}.csv"`,
        'content-length': Buffer.byteLength(body),
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff'
      });
      response.end(body);
      return true;
    }

    throw new HttpError(404, 'Admin API endpoint not found', 'not_found');
  }

  return { handle, syncUsage, expireAuthorizations };
}
