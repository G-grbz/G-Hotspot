import http from 'node:http';
import path from 'node:path';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { config } from './config.js';
import { HotspotDatabase } from './db.js';
import { HttpError, getClientIp, readJson, sendJson, sendText, serveStatic } from './lib/http.js';
import {
  COUNTRY_CALLING_CODES, generateOtp, generateSecret, isAllowedCountryCode, isValidEmail,
  isValidPhoneForCountry, keyedHash, normalizeCountryCode, normalizePhoneForCountry, safeEqualHex,
  isValidTckn, normalizeEmail, normalizeMac, normalizePhone, normalizeTckn, normalizeVoucher, sanitizeRedirectUrl
} from './lib/security.js';
import { sendMail } from './services/smtp.js';
import { sendWhatsAppOtp } from './services/whatsapp.js';
import { sendSmsOtp } from './services/sms.js';
import { verifyNviIdentity } from './services/nvi.js';
import { createDeliveryGuard } from './services/deliveryGuard.js';
import { sendSystemNotification } from './services/notifications.js';
import {
  deleteTelegramWebhook, getTelegramUpdates, telegramAppUrl, telegramStartCommand,
  sendTelegramContactRequest, sendTelegramOtp, sendTelegramText, telegramStartUrl
} from './services/telegram.js';
import {
  authorizationWithEffectiveAccess,
  grantAccess,
  normalizeActiveAuthorizationDurations,
  reverificationState
} from './services/access.js';
import {
  authorizeGateway, deleteGatewayKeaDhcpLease, disconnectGatewaySession,
  ensureGatewayBandwidthLimits, ensureGatewayKeaDhcpLease, listGatewayClientOwnership,
  listGatewayNetworkChoices, listGatewaySessions
} from './services/opnsense.js';
import { createAdminController } from './admin.js';
import { projectAbout } from './about.js';
import { normalizeLanguage, requestLanguage, translate } from './i18n.js';
import {
  appearanceAssets, portalThemeCss, serveAppearanceAsset
} from './appearance.js';
import { createSyslogAutoExporter, createSyslogHealthGuard, createSyslogServer } from './services/syslog.js';
import {
  authorizationQuotaBlocked,
  gatewayHasBandwidthProfiles,
  quotaLimitBytes,
  quotaPeriodWindow,
  quotaProfileForMethod
} from './services/quotas.js';
import {
  completeInstallation, generateInstallSecret, getInstallStatus, getSettings, installOpnsenseGateway
} from './settings.js';

const publicDir = path.resolve('public');
const db = new HotspotDatabase(config.databasePath);
const syslogReceiver = createSyslogServer({
  db,
  config,
  clientIdentityProvider: syslogClientIdentityRows
});
const syslogAutoExporter = createSyslogAutoExporter({
  db,
  config,
  notificationSender: (event, options = {}) => sendSystemNotification(config, event, options)
});
const syslogHealthGuard = createSyslogHealthGuard({
  db,
  config,
  notificationSender: (event, options = {}) => sendSystemNotification(config, event, options)
});
const admin = createAdminController({
  db,
  config,
  syslogReceiverStatus: () => syslogReceiver.status(),
  syslogAutoExportStatus: () => syslogAutoExporter.status(),
  syslogHealthStatus: () => syslogHealthGuard.status()
});
const OTP_TTL_MS = 5 * 60 * 1000;
const WHATSAPP_TTL_MS = 10 * 60 * 1000;
const USER_COOKIE_NAME = 'gh_session';
const SESSION_PAGE_PATHS = new Set(['/session', '/session/', '/session.html']);
const INSTALL_PAGE_PATHS = new Set(['/install', '/install/', '/install.html']);
const processingIdentities = new Set();
const deliveryGuard = createDeliveryGuard();
const authorizationMaintenanceSyncs = new Set();

function cookieValue(request, name) {
  for (const cookie of String(request.headers.cookie || '').split(';')) {
    const [key, ...rest] = cookie.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return '';
}

function setUserSessionCookie(response, authorization) {
  authorization = authorizationWithEffectiveAccess(config, authorization);
  const id = authorization?.id || '';
  const token = id ? `${id}.${keyedHash(config.appSecret, id)}` : '';
  const secure = String(config.publicBaseUrl).startsWith('https://');
  const remainingSeconds = authorization
    ? Math.max(0, Math.min(10 * 365 * 86400, Math.ceil((Number(authorization.expires_at) - Date.now()) / 1000)))
    : 0;
  response.setHeader('set-cookie',
    `${USER_COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${remainingSeconds};${secure ? ' Secure;' : ''}`
  );
}

function redirectToPortal(response) {
  response.writeHead(302, {
    location: '/',
    'content-length': 0,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  response.end();
}

function redirectTo(response, location) {
  response.writeHead(302, {
    location,
    'content-length': 0,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  response.end();
}

function isInstallAssetPath(pathname) {
  return pathname === '/favicon.ico' ||
    pathname === '/install.css' ||
    pathname === '/install.js' ||
    pathname === '/i18n.js' ||
    pathname === '/img/favicon.ico' ||
    pathname.startsWith('/i18n/');
}

function gatewayUserName(authorization) {
  return `${authorization.method}:${authorization.identity}`.slice(0, 128);
}

function isActiveAuthorization(authorization, now = Date.now()) {
  authorization = authorizationWithEffectiveAccess(config, authorization);
  return authorization?.status === 'active' &&
    !authorization.ended_at &&
    Number(authorization.expires_at) > now;
}

function isUsableAuthorization(authorization, now = Date.now()) {
  return isActiveAuthorization(authorization, now) &&
    !authorizationQuotaBlocked(authorization, now);
}

function authorizationLeaseSeconds(authorization) {
  authorization = authorizationWithEffectiveAccess(config, authorization);
  const stored = Number(authorization?.lease_seconds);
  if (Number.isFinite(stored) && stored > 0) return stored;
  const createdAt = Number(authorization?.created_at);
  const expiresAt = Number(authorization?.expires_at);
  if (!Number.isFinite(createdAt) || !Number.isFinite(expiresAt) || expiresAt <= createdAt) return null;
  return Math.ceil((expiresAt - createdAt) / 1000);
}

function queryClientMac(url) {
  return normalizeMac(url?.searchParams?.get('client_mac') || url?.searchParams?.get('mac') || '');
}

function textField(row, names) {
  for (const name of names) {
    const value = row?.[name];
    if (value != null && String(value).trim()) return String(value).trim();
  }
  return '';
}

function isIpv4(value) {
  const parts = String(value || '').split('.');
  return parts.length === 4 && parts.every(part => {
    if (!/^\d{1,3}$/u.test(part)) return false;
    const value = Number(part);
    return value >= 0 && value <= 255;
  });
}

function ipListField(row, names) {
  const output = [];
  const add = value => {
    const ip = String(value || '').trim();
    if (isIpv4(ip) && !output.includes(ip)) output.push(ip);
  };
  for (const name of names) {
    const value = row?.[name];
    if (Array.isArray(value)) {
      value.forEach(add);
    } else if (value != null && String(value).trim()) {
      String(value).split(/[\s,]+/u).forEach(add);
    }
  }
  return output;
}

function normalizeGatewaySessionRow(row) {
  const rawSessionId = textField(row, ['sessionId', 'session_id', 'sessionid', 'id']);
  const zoneId = textField(row, ['gHotspotZoneId', 'zoneId', 'zone_id']);
  const rawClientIp = textField(row, ['ipAddress', 'ip_address', 'ip', 'address']);
  const clientIps = ipListField(row, ['ipAddresses', 'ip_addresses', 'ips', 'addresses']);
  if (isIpv4(rawClientIp) && !clientIps.includes(rawClientIp)) clientIps.unshift(rawClientIp);
  const clientIp = isIpv4(rawClientIp) ? rawClientIp : (clientIps[0] || '');
  return {
    sessionId: rawSessionId && zoneId && !/^\d{1,2}:/u.test(rawSessionId)
      ? `${zoneId}:${rawSessionId}`
      : rawSessionId,
    clientIp,
    clientIps,
    userName: textField(row, ['userName', 'username', 'user']),
    clientMac: normalizeMac(textField(row, ['macAddress', 'mac_address', 'mac']))
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

function alignGatewaySessionRow(row, clientIp) {
  if (isIpv4(clientIp) && row.clientIp !== clientIp && row.clientIps.includes(clientIp)) {
    return { ...row, clientIp, clientMac: '' };
  }
  return row;
}

function alignGatewaySessionToAuthorization(row, authorization) {
  const clientIp = preferredAuthorizationIp(row, authorization);
  if (isIpv4(clientIp) && row.clientIp !== clientIp && row.clientIps.includes(clientIp)) {
    return { ...row, clientIp, clientMac: '', alignedFromGatewayList: true };
  }
  return row;
}

async function gatewayClientOwnership(context = 'restoring session') {
  return listGatewayClientOwnership(config.gateway, { context });
}

async function requestClientMac(url, clientIp) {
  const providedClientMac = queryClientMac(url);
  if (providedClientMac) return providedClientMac;
  if (config.gateway.mode !== 'opnsense-api' || !clientIp) return '';
  return (await gatewayClientOwnership('resolving portal client MAC')).ipToMac.get(clientIp) || '';
}

async function syslogClientIdentityRows() {
  if (config.gateway.mode !== 'opnsense-api') return [];
  return (await listGatewayClientOwnership(config.gateway, {
    context: 'refreshing syslog client MAC cache'
  })).rows;
}

async function existingGatewaySessionForClient(authorization, clientIp, clientMac = '') {
  if (config.gateway.mode !== 'opnsense-api') return null;
  const userName = gatewayUserName(authorization);
  const gatewaySessionId = authorization.gateway_session_id || '';
  try {
    const rows = await listGatewaySessions(config.gateway);
    for (const raw of rows) {
      const row = alignGatewaySessionRow(normalizeGatewaySessionRow(raw), clientIp);
      if (row.clientIp !== clientIp) continue;
      const sessionMatches = gatewaySessionId && row.sessionId === gatewaySessionId;
      const userMatches = row.userName === userName;
      if (!sessionMatches && !userMatches) continue;
      db.moveAuthorizationGatewaySession(authorization.id, {
        clientIp,
        clientMac,
        gatewaySessionId: row.sessionId || authorization.gateway_session_id,
        gatewayResponse: null
      });
      return db.getAuthorization(authorization.id);
    }
  } catch (error) {
    console.warn(`Existing OPNsense session lookup failed for ${clientIp}: ${error.message}`);
  }
  return null;
}

async function disconnectAuthorizationGatewaySession(authorization, reason) {
  if (authorization.gateway_session_id) {
    try {
      await disconnectGatewaySession(config.gateway, authorization.gateway_session_id);
    } catch (error) {
      console.warn(`Gateway session could not be disconnected: ${error.message}`);
    }
  }
  db.clearAuthorizationGatewaySession(authorization.id);
}

async function synchronizeAuthorizationKeaLease(authorization) {
  if (config.gateway.keaLeaseSyncEnabled !== true) return;
  try {
    const result = await ensureGatewayKeaDhcpLease(config.gateway, {
      authorizationId: authorization.id,
      clientIp: authorization.client_ip,
      clientMac: authorization.client_mac,
      expiresAt: authorization.expires_at,
      leaseSeconds: authorizationLeaseSeconds(authorization),
      method: authorization.method,
      identity: authorization.identity
    });
    if (result.applied) db.markAuthorizationKeaSynced(authorization.id);
  } catch (error) {
    console.warn(`Kea DHCP lease lifetime could not be synchronized: ${error.message}`);
  }
}

async function deleteAuthorizationKeaLease(authorization) {
  if (config.gateway.keaLeaseSyncEnabled !== true) return;
  try {
    await deleteGatewayKeaDhcpLease(config.gateway, authorization);
  } catch (error) {
    console.warn(`Kea DHCP reservation could not be removed: ${error.message}`);
  }
}

async function synchronizeBandwidthLimits() {
  if (!gatewayHasBandwidthProfiles(config.gateway)) return;
  try {
    await ensureGatewayBandwidthLimits(config.gateway, {
      authorizations: db.listActiveBandwidthAuthorizations
        ? db.listActiveBandwidthAuthorizations({ gatewayMode: config.gateway.mode })
        : []
    });
  } catch (error) {
    console.warn(`Bandwidth limits could not be synchronized: ${error.message}`);
  }
}

function queueAuthorizationMaintenance(authorization) {
  const needsKea = config.gateway.keaLeaseSyncEnabled === true;
  const needsBandwidth = gatewayHasBandwidthProfiles(config.gateway);
  if (!authorization || (!needsKea && !needsBandwidth)) return;
  const key = [
    authorization.id,
    needsKea ? authorization.lease_seconds || '' : '',
    needsBandwidth ? 'bandwidth' : ''
  ].join('|');
  if (authorizationMaintenanceSyncs.has(key)) return;
  authorizationMaintenanceSyncs.add(key);
  setTimeout(() => {
    (async () => {
      await synchronizeAuthorizationKeaLease(authorization);
      await synchronizeBandwidthLimits();
    })().finally(() => {
      authorizationMaintenanceSyncs.delete(key);
    });
  }, 0);
}

async function moveAuthorizationToClient(authorization, clientIp, clientMac = '', options = {}) {
  const previousSessionId = authorization.gateway_session_id || '';
  if (options.disconnectPreviousFirst && previousSessionId) {
    try {
      await disconnectGatewaySession(config.gateway, previousSessionId);
    } catch (error) {
      console.warn(`Previous gateway session could not be disconnected: ${error.message}`);
    }
  }
  const gateway = await authorizeGateway(config.gateway, {
    user: gatewayUserName(authorization),
    clientIp
  });
  const nextSessionId = gateway.storedSessionId || gateway.sessionId || '';
  if (!options.disconnectPreviousFirst && previousSessionId && previousSessionId !== nextSessionId) {
    try {
      await disconnectGatewaySession(config.gateway, previousSessionId);
    } catch (error) {
      console.warn(`Previous gateway session could not be disconnected: ${error.message}`);
    }
  }
  db.moveAuthorizationGatewaySession(authorization.id, {
    clientIp,
    clientMac: normalizeMac(clientMac) || normalizeMac(authorization.client_mac) || normalizeMac(gateway.clientMac),
    gatewaySessionId: nextSessionId || previousSessionId,
    gatewayResponse: gateway.response
  });
  const moved = db.getAuthorization(authorization.id);
  queueAuthorizationMaintenance(moved);
  return moved;
}

async function closeConflictingAuthorizationForIp(clientIp, currentClientMac, skipId = '') {
  const conflict = db.getActiveAuthorizationForClient(clientIp);
  if (!conflict || conflict.id === skipId) return true;
  const conflictMac = normalizeMac(conflict.client_mac);
  if (config.gateway.mode === 'opnsense-api' && currentClientMac && conflictMac && currentClientMac !== conflictMac) {
    await disconnectAuthorizationGatewaySession(conflict, 'session_ip_mac_mismatch');
    return true;
  }
  return false;
}

async function restoreAuthorizationForClient(
  authorization,
  clientIp,
  confirmedClientMac = '',
  ownership = null,
  { allowIpMove = false } = {}
) {
  authorization = authorizationWithEffectiveAccess(config, authorization);
  if (!isUsableAuthorization(authorization)) return null;

  const authorizationMac = normalizeMac(authorization.client_mac);
  let currentClientMac = normalizeMac(confirmedClientMac);
  if (config.gateway.mode === 'opnsense-api') {
    const resolvedOwnership = ownership || await gatewayClientOwnership();
    if (!currentClientMac) currentClientMac = resolvedOwnership.ipToMac.get(clientIp) || '';
    if (authorization.client_ip === clientIp) {
      if (authorizationMac && currentClientMac && currentClientMac !== authorizationMac) {
        await disconnectAuthorizationGatewaySession(authorization, 'session_ip_mac_mismatch');
        return null;
      }
      if (!authorization.gateway_session_id) {
        try {
          return await moveAuthorizationToClient(authorization, clientIp, currentClientMac || authorizationMac);
        } catch (error) {
          console.warn(`Active session could not be restored for ${clientIp}: ${error.message}`);
          return null;
        }
      }
      if (!authorizationMac && currentClientMac) {
        db.moveAuthorizationGatewaySession(authorization.id, {
          clientIp,
          clientMac: currentClientMac,
          gatewaySessionId: authorization.gateway_session_id,
          gatewayResponse: null
        });
        const moved = db.getAuthorization(authorization.id);
        queueAuthorizationMaintenance(moved);
        return moved;
      }
      queueAuthorizationMaintenance(authorization);
      return authorization;
    }
    if (!allowIpMove) return null;
    if (!await closeConflictingAuthorizationForIp(clientIp, currentClientMac, authorization.id)) {
      return null;
    }
  } else if (authorization.client_ip === clientIp) {
    if (authorizationMac && currentClientMac && currentClientMac !== authorizationMac) return null;
    return authorization;
  } else if (!allowIpMove) {
    return null;
  }

  const existing = await existingGatewaySessionForClient(authorization, clientIp, currentClientMac || authorizationMac);
  if (existing) return existing;

  try {
    return await moveAuthorizationToClient(authorization, clientIp, currentClientMac || authorizationMac);
  } catch (error) {
    console.warn(`Active session could not be moved to ${clientIp}: ${error.message}`);
    return null;
  }
}

async function currentAuthorization(request, url = null, { allowQuotaBlocked = false } = {}) {
  db.clearExpiredAuthorizationQuotaBlocks?.();
  const clientIp = getClientIp(request, config.trustProxy);
  const now = Date.now();
  const claimedClientMac = queryClientMac(url);
  let confirmedClientMac = config.gateway.mode === 'opnsense-api' ? '' : claimedClientMac;
  let confirmedClientMacLoaded = config.gateway.mode !== 'opnsense-api';
  let ownership = null;
  let ownershipLoaded = false;
  async function getOwnership() {
    if (!ownershipLoaded) {
      ownership = await gatewayClientOwnership();
      ownershipLoaded = true;
    }
    return ownership;
  }
  async function getConfirmedClientMac() {
    if (!confirmedClientMacLoaded) {
      confirmedClientMac = (await getOwnership()).ipToMac.get(clientIp) || '';
      confirmedClientMacLoaded = true;
    }
    return confirmedClientMac;
  }

  const token = cookieValue(request, USER_COOKIE_NAME);
  if (token) {
    const separator = token.lastIndexOf('.');
    const id = separator > 0 ? token.slice(0, separator) : '';
    const signature = separator > 0 ? token.slice(separator + 1) : '';
    if (id && safeEqualHex(keyedHash(config.appSecret, id), signature)) {
      const authorization = db.getAuthorization(id);
      const effectiveAuthorization = authorizationWithEffectiveAccess(config, authorization);
      if (authorizationQuotaBlocked(effectiveAuthorization, now)) {
        if (allowQuotaBlocked &&
            isActiveAuthorization(effectiveAuthorization, now) &&
            effectiveAuthorization.client_ip === clientIp) {
          return effectiveAuthorization;
        }
      } else if (isUsableAuthorization(effectiveAuthorization, now)) {
        if (config.gateway.mode === 'opnsense-api' &&
            effectiveAuthorization.client_ip === clientIp &&
            effectiveAuthorization.gateway_session_id &&
            effectiveAuthorization.client_mac) {
          queueAuthorizationMaintenance(effectiveAuthorization);
          return effectiveAuthorization;
        }
        const restored = await restoreAuthorizationForClient(
          effectiveAuthorization,
          clientIp,
          await getConfirmedClientMac(),
          config.gateway.mode === 'opnsense-api' ? await getOwnership() : null,
          { allowIpMove: config.gateway.cookieIpMoveEnabled }
        );
        if (restored) return restored;
      }
    }
  }
  if (config.gateway.sessionCookieRequired) return null;

  const direct = db.getActiveAuthorizationForClient(clientIp, now);
  if (direct) {
    const effectiveDirect = authorizationWithEffectiveAccess(config, direct);
    if (authorizationQuotaBlocked(effectiveDirect, now)) return allowQuotaBlocked ? effectiveDirect : null;
    const restored = await restoreAuthorizationForClient(
      effectiveDirect,
      clientIp,
      await getConfirmedClientMac(),
      config.gateway.mode === 'opnsense-api' ? await getOwnership() : null
    );
    if (restored?.client_ip === clientIp) return restored;
    return null;
  }

  return null;
}

function quotaTimeZone() {
  return config.syslog?.timeZone || config.law5651?.timeZone || 'UTC';
}

function quotaSummaryPublic(authorization, now = Date.now()) {
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
    quotaPeriod: period.period,
    quotaPeriodStartAt: period.startAt,
    quotaPeriodEndAt: period.endAt,
    quotaDownloadLimitBytes: quotaLimitBytes(profile.downloadQuotaGb),
    quotaUploadLimitBytes: quotaLimitBytes(profile.uploadQuotaGb),
    quotaDownloadBytes: Math.max(
      Number(stored?.download_bytes || 0),
      Number(syslogUsage.downloadBytes || 0),
      fallbackDownload
    ),
    quotaUploadBytes: Math.max(
      Number(stored?.upload_bytes || 0),
      Number(syslogUsage.uploadBytes || 0),
      fallbackUpload
    )
  };
}

function maskedIdentity(method, identity, row = {}) {
  if (method === 'voucher') {
    return String(row.voucher_code_prefix || '').slice(0, 4);
  }
  if (method === 'email') {
    const [name, domain] = String(identity).split('@');
    return `${name?.slice(0, 2) || ''}${name?.length > 2 ? '•••' : ''}@${domain || ''}`;
  }
  if (method === 'sms' || method === 'whatsapp') {
    const value = String(identity);
    return `+${value.slice(0, 2)} ••• ••• ${value.slice(-4)}`;
  }
  return '••••';
}

function authorizationPublic(row) {
  row = authorizationWithEffectiveAccess(config, row);
  const now = Date.now();
  const quotaBlocked = authorizationQuotaBlocked(row, now);
  return {
    id: row.id,
    method: row.method,
    identity: maskedIdentity(row.method, row.identity, row),
    clientIp: row.client_ip,
    clientMac: row.client_mac || '',
    deviceName: row.device_name || '',
    gatewayMode: row.gateway_mode,
    gatewayConnected: row.status === 'active' && !row.ended_at && Number(row.expires_at) > now && !quotaBlocked,
    quotaBlockedUntil: row.quota_blocked_until ? Number(row.quota_blocked_until) : null,
    quotaExceededAt: row.quota_exceeded_at ? Number(row.quota_exceeded_at) : null,
    ...quotaSummaryPublic(row, now),
    createdAt: Number(row.created_at),
    expiresAt: Number(row.expires_at),
    unlimited: Boolean(row.unlimited),
    downloadBytes: Number(row.download_bytes || 0),
    uploadBytes: Number(row.upload_bytes || 0),
    redirectUrl: row.redirect_url || ''
  };
}

function sendAccessResult(response, statusCode, result) {
  const authorization = db.getAuthorization(result.authorizationId);
  setUserSessionCookie(response, authorization);
  sendJson(response, statusCode, { ...result, sessionUrl: '/session' });
}

async function notifyUserVerified(result, { method, identity, clientIp, clientMac = '' } = {}) {
  try {
    await sendSystemNotification(config, {
      eventType: 'user_verified',
      severity: 'info',
      message: 'User verification completed.',
      detail: {
        authorizationId: result.authorizationId || '',
        method,
        identity,
        clientIp,
        clientMac,
        expiresAt: Number(result.expiresAt || 0)
      }
    });
  } catch (error) {
    console.warn(`User verification notification failed: ${error.message}`);
  }
}

function notifySystemStartup() {
  sendSystemNotification(config, {
    eventType: 'system_startup',
    severity: 'info',
    message: 'System startup detected.',
    detail: {
      gatewayMode: config.gateway.mode
    }
  }).catch(error => {
    console.warn(`System startup notification failed: ${error.message}`);
  });
}

function cleanMac(value) {
  return normalizeMac(value);
}

function enforceRateLimit(kind, clientIp, subject, limit, windowMs) {
  const count = db.countEvents(kind, clientIp, subject, Date.now() - windowMs);
  if (count >= limit) throw new HttpError(429, 'Too many attempts. Please wait and try again.', 'rate_limited');
  db.recordEvent(kind, clientIp, subject);
}

function methodLimits(method) {
  return {
    email: config.smtp.limits,
    whatsapp: config.whatsapp.limits,
    sms: config.sms.limits,
    telegram: config.telegram.limits,
    nvi: config.nvi.limits,
    'admin-approval': config.adminApproval.limits
  }[method];
}

function claimIpRequestInterval(method, clientIp) {
  const previous = db.getVerificationCooldown(method, clientIp);
  if (previous) {
    const state = reverificationState(
      methodLimits(method).ipRetryInterval,
      Number(previous.requested_at)
    );
    if (!state.allowed) {
      throw new HttpError(
        429,
        state.permanent
          ? 'This IP address cannot request another verification code.'
          : 'This IP address must wait before requesting another verification code.',
        state.permanent ? 'ip_request_permanently_blocked' : 'ip_request_limited',
        state.retryAt ? { retryAt: state.retryAt } : null
      );
    }
  }
  return db.setVerificationCooldown(method, clientIp);
}

function releaseIpRequestInterval(method, clientIp, requestedAt) {
  db.releaseVerificationCooldown(method, clientIp, requestedAt);
}

function assertReverificationAllowed(method, identity) {
  const previous = db.getLatestSuccessfulAuthorization(method, identity);
  if (!previous) return;
  const state = reverificationState(
    methodLimits(method).reverifyDuration,
    Number(previous.created_at)
  );
  if (state.allowed) return;
  if (state.permanent) {
    throw new HttpError(
      429,
      'This identity has already been verified and cannot be verified again.',
      'reverification_permanently_blocked'
    );
  }
  throw new HttpError(
    429,
    'This identity cannot be verified again yet.',
    'reverification_limited',
    { retryAt: state.retryAt }
  );
}

function challengePublic(row) {
  return {
    id: row.id,
    kind: row.kind,
    status: row.status,
    expiresAt: Number(row.expires_at),
    verifiedAt: row.verified_at ? Number(row.verified_at) : null,
    error: row.status === 'failed' ? row.last_error : null
  };
}

function deliveryDetail(method, delivery = {}) {
  const channel = {
    email: 'SMTP server',
    sms: 'SMS provider',
    whatsapp: 'WhatsApp Cloud API',
    telegram: 'Telegram Bot API'
  }[method] || 'Verification provider';
  const parts = [`${channel} accepted the verification code request.`];
  if (delivery.provider) parts.push(`provider=${delivery.provider}`);
  if (delivery.messageId) parts.push(`message_id=${delivery.messageId}`);
  return parts.join(' ');
}

function nviLookupDetail() {
  return 'NVI identity lookup succeeded.';
}

function telegramRequestDetail() {
  return 'Telegram request created. Waiting for the user to share their Telegram phone number with the bot.';
}

function challengeLanguage(challenge) {
  return normalizeLanguage(challenge?.language, config.defaultLanguage);
}

function telegramMessageLanguage(message, challenge = null) {
  return normalizeLanguage(challenge?.language || message?.from?.language_code, config.defaultLanguage);
}

function accessGrantDetail(result) {
  const parts = [
    'Gateway authorization succeeded.',
    `authorization_id=${result.authorizationId}`
  ];
  if (result.gatewayMode) parts.push(`gateway_mode=${result.gatewayMode}`);
  if (result.unlimited) parts.push('access=unlimited');
  else if (result.expiresAt) parts.push(`access_expires_at=${new Date(Number(result.expiresAt)).toISOString()}`);
  return parts.join(' ');
}

function accessHttpError(error) {
  if (error?.code === 'syslog_unavailable') {
    return new HttpError(503, error.message, 'syslog_unavailable');
  }
  if (error?.code === 'quota_exceeded') {
    return new HttpError(
      429,
      'Your usage quota is exhausted. Internet access will be available again in the next quota period.',
      'quota_exceeded',
      error.retryAt ? { retryAt: error.retryAt } : null
    );
  }
  return new HttpError(502, `Gateway authorization failed: ${error.message}`, 'gateway_failed');
}

function isPositiveChallengeDetail(value) {
  return /accepted|request created|authorization succeeded|lookup succeeded/iu.test(String(value || ''));
}

function phoneCountryCode(phone) {
  return COUNTRY_CALLING_CODES
    .filter(code => String(phone || '').startsWith(code))
    .sort((left, right) => right.length - left.length)[0] || '';
}

function maskPhone(phone) {
  const countryCode = phoneCountryCode(phone);
  const prefix = countryCode ? `+${countryCode}` : '+';
  return `${prefix} ••• ••• ${phone.slice(-4)}`;
}

function countryCodeAllowed(value) {
  return isAllowedCountryCode(value, config.allowedCountryCodes);
}

function phoneAllowed(phone) {
  const countryCode = phoneCountryCode(phone);
  return Boolean(countryCode) && countryCodeAllowed(countryCode) && isValidPhoneForCountry(phone, countryCode);
}

function phoneFromRequest(value, message = 'Enter a valid phone number', code = 'invalid_phone') {
  const inferredCountryCode = phoneCountryCode(normalizePhone(value?.phone, config.defaultCountryCode));
  const countryCode = normalizeCountryCode(value?.countryCode) || inferredCountryCode || config.defaultCountryCode;
  if (!countryCodeAllowed(countryCode)) throw new HttpError(400, message, code);
  const phone = normalizePhoneForCountry(value?.phone, countryCode);
  if (!isValidPhoneForCountry(phone, countryCode)) throw new HttpError(400, message, code);
  return phone;
}

function normalizeFullName(value) {
  return String(value || '')
    .replace(/\s+/gu, ' ')
    .trim()
    .slice(0, 120);
}

function normalizeNviName(value) {
  return String(value || '')
    .replace(/\s+/gu, ' ')
    .trim()
    .slice(0, 80);
}

function nviBirthYear(value) {
  const year = Number.parseInt(String(value || '').replace(/\D/g, ''), 10);
  const currentYear = new Date().getFullYear();
  if (!Number.isInteger(year) || year < 1880 || year > currentYear) return 0;
  return year;
}

function isValidFullName(value) {
  const parts = normalizeFullName(value).split(' ').filter(Boolean);
  return parts.length >= 2 && parts.join('').length >= 4;
}

function adminApprovalContact(raw, countryCodeValue) {
  const value = String(raw || '').trim();
  if (!value) return { contact: '', contactType: 'none' };
  const email = normalizeEmail(value);
  if (isValidEmail(email)) return { contact: email, contactType: 'email' };
  const inferredCountryCode = phoneCountryCode(normalizePhone(value, config.defaultCountryCode));
  const countryCode = normalizeCountryCode(countryCodeValue) || inferredCountryCode || config.defaultCountryCode;
  if (countryCodeAllowed(countryCode)) {
    const phone = normalizePhoneForCountry(value, countryCode);
    if (isValidPhoneForCountry(phone, countryCode)) return { contact: phone, contactType: 'phone' };
  }
  throw new HttpError(400, 'Enter a valid e-mail address or phone number', 'invalid_contact');
}

function adminApprovalIdentity(fullName, contact, contactType) {
  if (contactType === 'email') return `${fullName} <${contact}>`;
  if (contactType === 'phone') return `${fullName} +${contact}`;
  return fullName;
}

function adminApprovalPublic(row) {
  return {
    id: row.id,
    status: row.status,
    fullName: row.full_name,
    contact: row.contact || '',
    contactType: row.contact_type || 'none',
    createdAt: Number(row.created_at),
    requestExpiresAt: Number(row.request_expires_at),
    decidedAt: row.decided_at ? Number(row.decided_at) : null,
    decisionMessage: row.decision_message || '',
    error: row.last_error || '',
    accessExpiresAt: row.access_expires_at ? Number(row.access_expires_at) : null,
    accessUnlimited: Boolean(row.access_unlimited)
  };
}

async function handleAdminApprovalRequest(request, response) {
  if (!config.adminApproval.enabled) {
    throw new HttpError(503, 'Admin approval verification is not configured', 'admin_approval_disabled');
  }
  const { value } = await readJson(request);
  const clientIp = getClientIp(request, config.trustProxy);
  const fullName = normalizeFullName(value.fullName || value.name);
  const language = requestLanguage(request, value.language, config.defaultLanguage);
  if (!isValidFullName(fullName)) {
    throw new HttpError(400, 'Enter your first and last name', 'invalid_full_name');
  }
  const { contact, contactType } = adminApprovalContact(value.contact, value.countryCode);
  const identity = adminApprovalIdentity(fullName, contact, contactType);
  assertReverificationAllowed('admin-approval', identity);
  const existing = db.getPendingAdminApprovalRequestByClient(clientIp);
  if (existing) {
    sendJson(response, 200, adminApprovalPublic(existing));
    return;
  }
  const cooldownClaimedAt = claimIpRequestInterval('admin-approval', clientIp);
  try {
    const approvalRequest = db.createAdminApprovalRequest({
      fullName,
      contact,
      contactType,
      identity,
      clientIp,
      clientMac: cleanMac(value.clientMac),
      redirectUrl: sanitizeRedirectUrl(value.redirectUrl),
      expiresAt: Date.now() + config.adminApproval.requestTtlMinutes * 60 * 1000,
      language
    });
    sendJson(response, 201, adminApprovalPublic(approvalRequest));
  } catch (error) {
    releaseIpRequestInterval('admin-approval', clientIp, cooldownClaimedAt);
    throw error;
  }
}

function sendApprovedAdminApprovalStatus(request, response, approvalRequest) {
  const storedAuthorization = approvalRequest.authorization_id
    ? db.getAuthorization(approvalRequest.authorization_id)
    : db.getActiveAuthorizationForClient(getClientIp(request, config.trustProxy));
  const authorization = authorizationWithEffectiveAccess(config, storedAuthorization);
  if (authorization) setUserSessionCookie(response, authorization);
  sendJson(response, 200, {
    ...adminApprovalPublic(approvalRequest),
    ok: true,
    authorizationId: authorization?.id || approvalRequest.authorization_id || '',
    expiresAt: authorization ? Number(authorization.expires_at) : Number(approvalRequest.access_expires_at || 0),
    redirectUrl: authorization?.redirect_url || approvalRequest.redirect_url || '',
    sessionUrl: '/session'
  });
}

async function handleAdminApprovalStatus(request, response, id) {
  const approvalRequest = db.getAdminApprovalRequest(id);
  if (!approvalRequest) throw new HttpError(404, 'Admin approval request not found', 'admin_approval_not_found');
  if (approvalRequest.client_ip !== getClientIp(request, config.trustProxy)) {
    throw new HttpError(403, 'This verification belongs to another device', 'client_mismatch');
  }
  if (approvalRequest.status === 'pending' && Number(approvalRequest.request_expires_at) < Date.now()) {
    db.expireAdminApprovalRequests();
    sendJson(response, 200, adminApprovalPublic(db.getAdminApprovalRequest(id)));
    return;
  }
  if (approvalRequest.status === 'approved') {
    sendApprovedAdminApprovalStatus(request, response, approvalRequest);
    return;
  }
  sendJson(response, 200, adminApprovalPublic(approvalRequest));
}

async function completeChallenge(challenge, method, identity) {
  const identityLock = `${method}:${identity}`;
  if (processingIdentities.has(identityLock)) {
    throw new HttpError(409, 'Verification is already being processed', 'challenge_busy');
  }
  processingIdentities.add(identityLock);
  try {
    assertReverificationAllowed(method, identity);
    if (!db.claimChallenge(challenge.id)) {
      const current = db.getChallenge(challenge.id);
      if (current?.status === 'verified') return challengePublic(current);
      throw new HttpError(409, 'Verification is already being processed', 'challenge_busy');
    }
    try {
      const result = await grantAccess({
        db,
        config,
        method,
        identity,
        clientIp: challenge.client_ip,
        clientMac: challenge.client_mac,
        duration: {
          email: config.smtp.accessDuration,
          whatsapp: config.whatsapp.accessDuration,
          sms: config.sms.accessDuration,
          telegram: config.telegram.accessDuration,
          nvi: config.nvi.accessDuration
        }[method],
        redirectUrl: challenge.redirect_url
      });
      const detail = accessGrantDetail(result);
      const current = db.getChallenge(challenge.id);
      if (current?.last_error && !isPositiveChallengeDetail(current.last_error)) {
        db.setChallengeDetail(challenge.id, detail);
      } else {
        db.appendChallengeDetail(challenge.id, detail);
      }
      db.finishChallenge(challenge.id, true, '', result.clientMac);
      await notifyUserVerified(result, {
        method,
        identity,
        clientIp: challenge.client_ip,
        clientMac: result.clientMac || challenge.client_mac
      });
      return { ...result, challenge: challengePublic(db.getChallenge(challenge.id)) };
    } catch (error) {
      db.finishChallenge(challenge.id, false, error.message);
      throw accessHttpError(error);
    }
  } finally {
    processingIdentities.delete(identityLock);
  }
}

async function handleVoucher(request, response) {
  if (!config.voucher.enabled) throw new HttpError(503, 'Voucher verification is disabled', 'voucher_disabled');
  const { value } = await readJson(request);
  const clientIp = getClientIp(request, config.trustProxy);
  const code = normalizeVoucher(value.code);
  if (code.length < 8 || code.length > 32) throw new HttpError(400, 'Invalid voucher code', 'invalid_voucher');
  enforceRateLimit('voucher_redeem', clientIp, '', 10, 15 * 60 * 1000);
  const claim = db.claimVoucher(keyedHash(config.appSecret, code), Date.now(), code.slice(0, 4));
  if (!claim.ok) throw new HttpError(401, 'Voucher is invalid, expired or already used', `voucher_${claim.reason}`);
  const redirectUrl = sanitizeRedirectUrl(value.redirectUrl);
  try {
    const result = await grantAccess({
      db,
      config,
      method: 'voucher',
      identity: claim.voucher.id,
      clientIp,
      clientMac: cleanMac(value.clientMac),
      durationMinutes: Number(claim.voucher.duration_minutes),
      redirectUrl
    });
    await notifyUserVerified(result, {
      method: 'voucher',
      identity: claim.voucher.id,
      clientIp,
      clientMac: cleanMac(value.clientMac) || result.clientMac
    });
    sendAccessResult(response, 200, result);
  } catch (error) {
    db.releaseVoucherUse(claim.voucher.id);
    throw accessHttpError(error);
  }
}

async function handleEmailRequest(request, response) {
  if (!config.smtp.enabled) throw new HttpError(503, 'E-mail verification is not configured', 'email_disabled');
  const { value } = await readJson(request);
  const clientIp = getClientIp(request, config.trustProxy);
  const email = normalizeEmail(value.email);
  const language = requestLanguage(request, value.language, config.defaultLanguage);
  if (!isValidEmail(email)) throw new HttpError(400, 'Enter a valid e-mail address', 'invalid_email');
  assertReverificationAllowed('email', email);
  const cooldownClaimedAt = claimIpRequestInterval('email', clientIp);
  const otp = generateOtp();
  let challenge;
  try {
    challenge = db.createChallenge({
      kind: 'email',
      target: email,
      secretHash: keyedHash(config.appSecret, otp),
      clientIp,
      clientMac: cleanMac(value.clientMac),
      redirectUrl: sanitizeRedirectUrl(value.redirectUrl),
      expiresAt: Date.now() + OTP_TTL_MS
    });
  } catch (error) {
    releaseIpRequestInterval('email', clientIp, cooldownClaimedAt);
    throw error;
  }
  try {
    await deliveryGuard.run('email', () => sendMail(config.smtp, {
      to: email,
      subject: translate(language, 'emailSubject', { appName: config.appName }),
      text: translate(language, 'emailText', { appName: config.appName, code: otp, minutes: 5 }),
      html: `<div style="font-family:system-ui,sans-serif;max-width:520px;margin:auto"><h2>${config.appName}</h2><p>${translate(language, 'emailIntro')}</p><p style="font-size:32px;font-weight:700;letter-spacing:8px">${otp}</p><p>${translate(language, 'codeValidity', { minutes: 5 })}</p></div>`
    }));
    db.setChallengeDetail(challenge.id, deliveryDetail('email'));
  } catch (error) {
    db.failChallenge(challenge.id, error.message);
    if (error instanceof HttpError) throw error;
    throw new HttpError(502, `E-mail could not be sent: ${error.message}`, 'email_send_failed');
  }
  sendJson(response, 201, { challengeId: challenge.id, expiresAt: Number(challenge.expires_at) });
}

async function handleSmsRequest(request, response) {
  if (!config.sms.enabled) throw new HttpError(503, 'SMS verification is not configured', 'sms_disabled');
  const { value } = await readJson(request);
  const clientIp = getClientIp(request, config.trustProxy);
  const phone = phoneFromRequest(value);
  assertReverificationAllowed('sms', phone);
  const cooldownClaimedAt = claimIpRequestInterval('sms', clientIp);
  const otp = generateOtp();
  let challenge;
  try {
    challenge = db.createChallenge({
      kind: 'sms',
      target: phone,
      secretHash: keyedHash(config.appSecret, otp),
      clientIp,
      clientMac: cleanMac(value.clientMac),
      redirectUrl: sanitizeRedirectUrl(value.redirectUrl),
      expiresAt: Date.now() + config.sms.otpMinutes * 60 * 1000
    });
  } catch (error) {
    releaseIpRequestInterval('sms', clientIp, cooldownClaimedAt);
    throw error;
  }
  try {
    const delivery = await deliveryGuard.run('sms', () =>
      sendSmsOtp(config.sms, { phone, code: otp, appName: config.appName })
    );
    db.setChallengeDetail(challenge.id, deliveryDetail('sms', delivery));
    sendJson(response, 201, {
      challengeId: challenge.id,
      expiresAt: Number(challenge.expires_at),
      messageId: delivery.messageId,
      provider: delivery.provider,
      maskedPhone: `+${phone.slice(0, 2)} ••• ••• ${phone.slice(-4)}`
    });
  } catch (error) {
    db.failChallenge(challenge.id, error.message);
    if (error instanceof HttpError) throw error;
    throw new HttpError(502, `SMS message could not be sent: ${error.message}`, 'sms_send_failed');
  }
}

async function handleSmsVerify(request, response) {
  const { value } = await readJson(request);
  const clientIp = getClientIp(request, config.trustProxy);
  const challenge = db.getChallenge(String(value.challengeId || ''));
  if (!challenge || challenge.kind !== 'sms') {
    throw new HttpError(404, 'Verification request not found', 'challenge_not_found');
  }
  if (challenge.client_ip !== clientIp) {
    throw new HttpError(403, 'This verification belongs to another device', 'client_mismatch');
  }
  if (challenge.status === 'verified') {
    const authorization = db.getActiveAuthorizationForClient(clientIp);
    if (!authorization) throw new HttpError(404, 'Session not found', 'session_not_found');
    setUserSessionCookie(response, authorization);
    sendJson(response, 200, {
      ok: true,
      authorizationId: authorization.id,
      expiresAt: Number(authorization.expires_at),
      redirectUrl: authorization.redirect_url || '',
      sessionUrl: '/session',
      challenge: challengePublic(challenge)
    });
    return;
  }
  if (challenge.status !== 'pending' || Number(challenge.expires_at) < Date.now()) {
    throw new HttpError(410, 'Verification code has expired', 'challenge_expired');
  }
  if (Number(challenge.attempts) >= 5) throw new HttpError(429, 'Too many incorrect codes', 'attempts_exceeded');
  const codeHash = keyedHash(config.appSecret, String(value.code || '').trim());
  if (!safeEqualHex(codeHash, challenge.secret_hash)) {
    const updated = db.incrementChallengeAttempts(challenge.id);
    if (Number(updated.attempts) >= 5) db.failChallenge(challenge.id, 'Too many incorrect codes');
    throw new HttpError(401, 'Incorrect verification code', 'incorrect_code');
  }
  const result = await completeChallenge(challenge, 'sms', challenge.target);
  sendAccessResult(response, 200, result);
}

async function handleNviRequest(request, response) {
  if (!config.nvi.enabled) throw new HttpError(503, 'NVI verification is not configured', 'nvi_disabled');
  const { value } = await readJson(request);
  const clientIp = getClientIp(request, config.trustProxy);
  const tckn = normalizeTckn(value.tckn || value.tcKimlikNo || value.identity);
  const firstName = normalizeNviName(value.firstName || value.name || value.ad);
  const lastName = normalizeNviName(value.lastName || value.surname || value.soyad);
  const birthYear = nviBirthYear(value.birthYear || value.dogumYili);
  const language = requestLanguage(request, value.language, config.defaultLanguage);
  const smsRequired = Boolean(config.nvi.sendSmsCode);
  if (!isValidTckn(tckn)) throw new HttpError(400, 'Enter a valid T.C. identity number', 'invalid_tckn');
  if (firstName.length < 2) throw new HttpError(400, 'Enter your first name', 'invalid_first_name');
  if (lastName.length < 2) throw new HttpError(400, 'Enter your last name', 'invalid_last_name');
  if (!birthYear) throw new HttpError(400, 'Enter a valid birth year', 'invalid_birth_year');
  if (smsRequired && !config.sms.enabled) {
    throw new HttpError(503, 'SMS verification is not configured', 'sms_disabled');
  }
  const phone = smsRequired ? phoneFromRequest(value) : '';
  assertReverificationAllowed('nvi', tckn);
  const cooldownClaimedAt = claimIpRequestInterval('nvi', clientIp);
  let nviOk = false;
  try {
    nviOk = await deliveryGuard.run('nvi', () => verifyNviIdentity(config.nvi, {
      tckn,
      firstName,
      lastName,
      birthYear
    }));
  } catch (error) {
    releaseIpRequestInterval('nvi', clientIp, cooldownClaimedAt);
    throw new HttpError(502, `NVI verification could not be completed: ${error.message}`, 'nvi_provider_failed');
  }
  if (!nviOk) {
    throw new HttpError(401, 'T.C. identity information could not be verified', 'nvi_verification_failed');
  }

  const otp = smsRequired ? generateOtp() : generateSecret(18);
  let challenge;
  try {
    challenge = db.createChallenge({
      kind: 'nvi',
      target: tckn,
      secretHash: keyedHash(config.appSecret, otp),
      clientIp,
      clientMac: cleanMac(value.clientMac),
      redirectUrl: sanitizeRedirectUrl(value.redirectUrl),
      expiresAt: Date.now() + (smsRequired ? config.sms.otpMinutes * 60 * 1000 : OTP_TTL_MS),
      language
    });
  } catch (error) {
    releaseIpRequestInterval('nvi', clientIp, cooldownClaimedAt);
    throw error;
  }

  if (!smsRequired) {
    db.setChallengeDetail(challenge.id, nviLookupDetail());
    const result = await completeChallenge(challenge, 'nvi', tckn);
    sendAccessResult(response, 200, result);
    return;
  }

  try {
    const delivery = await deliveryGuard.run('sms', () =>
      sendSmsOtp(config.sms, { phone, code: otp, appName: config.appName })
    );
    db.setChallengeDetail(challenge.id, `${nviLookupDetail()} ${deliveryDetail('sms', delivery)}`);
    sendJson(response, 201, {
      challengeId: challenge.id,
      expiresAt: Number(challenge.expires_at),
      messageId: delivery.messageId,
      provider: delivery.provider,
      maskedPhone: maskPhone(phone)
    });
  } catch (error) {
    db.failChallenge(challenge.id, error.message);
    if (error instanceof HttpError) throw error;
    throw new HttpError(502, `SMS message could not be sent: ${error.message}`, 'sms_send_failed');
  }
}

async function handleNviVerify(request, response) {
  const { value } = await readJson(request);
  const clientIp = getClientIp(request, config.trustProxy);
  const challenge = db.getChallenge(String(value.challengeId || ''));
  if (!challenge || challenge.kind !== 'nvi') {
    throw new HttpError(404, 'Verification request not found', 'challenge_not_found');
  }
  if (challenge.client_ip !== clientIp) {
    throw new HttpError(403, 'This verification belongs to another device', 'client_mismatch');
  }
  if (challenge.status === 'verified') {
    const authorization = db.getActiveAuthorizationForClient(clientIp);
    if (!authorization) throw new HttpError(404, 'Session not found', 'session_not_found');
    setUserSessionCookie(response, authorization);
    sendJson(response, 200, {
      ok: true,
      authorizationId: authorization.id,
      expiresAt: Number(authorization.expires_at),
      redirectUrl: authorization.redirect_url || '',
      sessionUrl: '/session',
      challenge: challengePublic(challenge)
    });
    return;
  }
  if (challenge.status !== 'pending' || Number(challenge.expires_at) < Date.now()) {
    throw new HttpError(410, 'Verification code has expired', 'challenge_expired');
  }
  if (Number(challenge.attempts) >= 5) {
    throw new HttpError(429, 'Too many incorrect codes', 'attempts_exceeded');
  }
  const codeHash = keyedHash(config.appSecret, String(value.code || '').trim());
  if (!safeEqualHex(codeHash, challenge.secret_hash)) {
    const updated = db.incrementChallengeAttempts(challenge.id);
    if (Number(updated.attempts) >= 5) db.failChallenge(challenge.id, 'Too many incorrect codes');
    throw new HttpError(401, 'Incorrect verification code', 'incorrect_code');
  }
  const result = await completeChallenge(challenge, 'nvi', challenge.target);
  sendAccessResult(response, 200, result);
}

async function handleEmailVerify(request, response) {
  const { value } = await readJson(request);
  const clientIp = getClientIp(request, config.trustProxy);
  const challenge = db.getChallenge(String(value.challengeId || ''));
  if (!challenge || challenge.kind !== 'email') throw new HttpError(404, 'Verification request not found', 'challenge_not_found');
  if (challenge.client_ip !== clientIp) throw new HttpError(403, 'This verification belongs to another device', 'client_mismatch');
  if (challenge.status === 'verified') {
    const authorization = db.getActiveAuthorizationForClient(clientIp);
    if (!authorization) throw new HttpError(404, 'Session not found', 'session_not_found');
    setUserSessionCookie(response, authorization);
    sendJson(response, 200, {
      ok: true,
      authorizationId: authorization.id,
      expiresAt: Number(authorization.expires_at),
      redirectUrl: authorization.redirect_url || '',
      sessionUrl: '/session',
      challenge: challengePublic(challenge)
    });
    return;
  }
  if (challenge.status !== 'pending' || Number(challenge.expires_at) < Date.now()) {
    throw new HttpError(410, 'Verification code has expired', 'challenge_expired');
  }
  if (Number(challenge.attempts) >= 5) throw new HttpError(429, 'Too many incorrect codes', 'attempts_exceeded');
  const codeHash = keyedHash(config.appSecret, String(value.code || '').trim());
  if (!safeEqualHex(codeHash, challenge.secret_hash)) {
    const updated = db.incrementChallengeAttempts(challenge.id);
    if (Number(updated.attempts) >= 5) db.failChallenge(challenge.id, 'Too many incorrect codes');
    throw new HttpError(401, 'Incorrect verification code', 'incorrect_code');
  }
  const result = await completeChallenge(challenge, 'email', challenge.target);
  sendAccessResult(response, 200, result);
}

async function handleWhatsAppRequest(request, response) {
  if (!config.whatsapp.enabled) throw new HttpError(503, 'WhatsApp verification is not configured', 'whatsapp_disabled');
  const { value } = await readJson(request);
  const clientIp = getClientIp(request, config.trustProxy);
  const phone = phoneFromRequest(value);
  assertReverificationAllowed('whatsapp', phone);
  const cooldownClaimedAt = claimIpRequestInterval('whatsapp', clientIp);
  const otp = generateOtp();
  let challenge;
  try {
    challenge = db.createChallenge({
      kind: 'whatsapp',
      target: phone,
      secretHash: keyedHash(config.appSecret, otp),
      clientIp,
      clientMac: cleanMac(value.clientMac),
      redirectUrl: sanitizeRedirectUrl(value.redirectUrl),
      expiresAt: Date.now() + WHATSAPP_TTL_MS
    });
  } catch (error) {
    releaseIpRequestInterval('whatsapp', clientIp, cooldownClaimedAt);
    throw error;
  }
  let delivery;
  try {
    delivery = await deliveryGuard.run('whatsapp', () =>
      sendWhatsAppOtp(config.whatsapp, { to: phone, code: otp })
    );
    db.setChallengeDetail(challenge.id, deliveryDetail('whatsapp', delivery));
  } catch (error) {
    db.failChallenge(challenge.id, error.message);
    if (error instanceof HttpError) throw error;
    throw new HttpError(502, `WhatsApp message could not be sent: ${error.message}`, 'whatsapp_send_failed');
  }
  sendJson(response, 201, {
    challengeId: challenge.id,
    expiresAt: Number(challenge.expires_at),
    messageId: delivery.messageId,
    maskedPhone: `+${phone.slice(0, 2)} ••• ••• ${phone.slice(-4)}`
  });
}

async function handleWhatsAppVerify(request, response) {
  const { value } = await readJson(request);
  const clientIp = getClientIp(request, config.trustProxy);
  const challenge = db.getChallenge(String(value.challengeId || ''));
  if (!challenge || challenge.kind !== 'whatsapp') {
    throw new HttpError(404, 'Verification request not found', 'challenge_not_found');
  }
  if (challenge.client_ip !== clientIp) {
    throw new HttpError(403, 'This verification belongs to another device', 'client_mismatch');
  }
  if (challenge.status === 'verified') {
    const authorization = db.getActiveAuthorizationForClient(clientIp);
    if (!authorization) throw new HttpError(404, 'Session not found', 'session_not_found');
    setUserSessionCookie(response, authorization);
    sendJson(response, 200, {
      ok: true,
      authorizationId: authorization.id,
      expiresAt: Number(authorization.expires_at),
      redirectUrl: authorization.redirect_url || '',
      sessionUrl: '/session',
      challenge: challengePublic(challenge)
    });
    return;
  }
  if (challenge.status !== 'pending' || Number(challenge.expires_at) < Date.now()) {
    throw new HttpError(410, 'Verification code has expired', 'challenge_expired');
  }
  if (Number(challenge.attempts) >= 5) {
    throw new HttpError(429, 'Too many incorrect codes', 'attempts_exceeded');
  }
  const codeHash = keyedHash(config.appSecret, String(value.code || '').trim());
  if (!safeEqualHex(codeHash, challenge.secret_hash)) {
    const updated = db.incrementChallengeAttempts(challenge.id);
    if (Number(updated.attempts) >= 5) db.failChallenge(challenge.id, 'Too many incorrect codes');
    throw new HttpError(401, 'Incorrect verification code', 'incorrect_code');
  }
  const result = await completeChallenge(challenge, 'whatsapp', challenge.target);
  sendAccessResult(response, 200, result);
}

async function handleTelegramRequest(request, response) {
  if (!config.telegram.enabled) throw new HttpError(503, 'Telegram verification is not configured', 'telegram_disabled');
  const { value } = await readJson(request);
  const clientIp = getClientIp(request, config.trustProxy);
  const phone = phoneFromRequest(value);
  const language = requestLanguage(request, value.language, config.defaultLanguage);
  assertReverificationAllowed('telegram', phone);
  const cooldownClaimedAt = claimIpRequestInterval('telegram', clientIp);
  let challenge;
  try {
    challenge = db.createChallenge({
      kind: 'telegram',
      target: phone,
      secretHash: keyedHash(config.appSecret, generateSecret(18)),
      clientIp,
      clientMac: cleanMac(value.clientMac),
      redirectUrl: sanitizeRedirectUrl(value.redirectUrl),
      expiresAt: Date.now() + config.telegram.otpMinutes * 60 * 1000,
      language
    });
  } catch (error) {
    releaseIpRequestInterval('telegram', clientIp, cooldownClaimedAt);
    throw error;
  }
  try {
    const payload = {
      challengeId: challenge.id,
      expiresAt: Number(challenge.expires_at),
      botUrl: telegramStartUrl(config.telegram, challenge.id),
      appUrl: telegramAppUrl(config.telegram, challenge.id),
      startCommand: telegramStartCommand(challenge.id),
      maskedPhone: maskPhone(phone)
    };
    db.setChallengeDetail(challenge.id, telegramRequestDetail());
    sendJson(response, 201, payload);
  } catch (error) {
    releaseIpRequestInterval('telegram', clientIp, cooldownClaimedAt);
    db.failChallenge(challenge.id, error.message);
    throw error;
  }
}

function handleTelegramResume(request, response, challengeId) {
  if (!config.telegram.enabled) throw new HttpError(503, 'Telegram verification is not configured', 'telegram_disabled');
  const challenge = db.getChallenge(challengeId);
  sendJson(response, 200, telegramResumePayload(request, challenge));
}

function handleTelegramCurrent(request, response, options = {}) {
  if (!config.telegram.enabled) throw new HttpError(503, 'Telegram verification is not configured', 'telegram_disabled');
  const clientIp = getClientIp(request, config.trustProxy);
  const challenge = db.getPendingChallengeByClient('telegram', clientIp);
  if (!challenge) {
    if (options.optional) {
      sendJson(response, 200, { active: false });
      return;
    }
    throw new HttpError(404, 'Telegram verification request not found', 'challenge_not_found');
  }
  sendJson(response, 200, telegramResumePayload(request, challenge));
}

function telegramResumePayload(request, challenge) {
  if (!challenge || challenge.kind !== 'telegram' ||
      challenge.status !== 'pending' || Number(challenge.expires_at) < Date.now()) {
    throw new HttpError(404, 'Telegram verification request not found', 'challenge_not_found');
  }
  if (challenge.client_ip !== getClientIp(request, config.trustProxy)) {
    throw new HttpError(403, 'This verification belongs to another device', 'client_mismatch');
  }
  return {
    challengeId: challenge.id,
    expiresAt: Number(challenge.expires_at),
    botUrl: telegramStartUrl(config.telegram, challenge.id),
    appUrl: telegramAppUrl(config.telegram, challenge.id),
    startCommand: telegramStartCommand(challenge.id),
    maskedPhone: maskPhone(challenge.target)
  };
}

async function handleTelegramVerify(request, response) {
  const { value } = await readJson(request);
  const clientIp = getClientIp(request, config.trustProxy);
  const challenge = db.getChallenge(String(value.challengeId || ''));
  if (!challenge || challenge.kind !== 'telegram') {
    throw new HttpError(404, 'Verification request not found', 'challenge_not_found');
  }
  if (challenge.client_ip !== clientIp) {
    throw new HttpError(403, 'This verification belongs to another device', 'client_mismatch');
  }
  if (challenge.status === 'verified') {
    const authorization = db.getActiveAuthorizationForClient(clientIp);
    if (!authorization) throw new HttpError(404, 'Session not found', 'session_not_found');
    setUserSessionCookie(response, authorization);
    sendJson(response, 200, {
      ok: true,
      authorizationId: authorization.id,
      expiresAt: Number(authorization.expires_at),
      redirectUrl: authorization.redirect_url || '',
      sessionUrl: '/session',
      challenge: challengePublic(challenge)
    });
    return;
  }
  if (challenge.status !== 'pending' || Number(challenge.expires_at) < Date.now()) {
    throw new HttpError(410, 'Verification code has expired', 'challenge_expired');
  }
  if (Number(challenge.attempts) >= 5) {
    throw new HttpError(429, 'Too many incorrect codes', 'attempts_exceeded');
  }
  const codeHash = keyedHash(config.appSecret, String(value.code || '').trim());
  if (!safeEqualHex(codeHash, challenge.secret_hash)) {
    const updated = db.incrementChallengeAttempts(challenge.id);
    if (Number(updated.attempts) >= 5) db.failChallenge(challenge.id, 'Too many incorrect codes');
    throw new HttpError(401, 'Incorrect verification code', 'incorrect_code');
  }
  const result = await completeChallenge(challenge, 'telegram', challenge.target);
  sendAccessResult(response, 200, result);
}

function verifyMetaSignature(raw, signature) {
  if (!config.whatsapp.metaAppSecret) return true;
  if (!signature?.startsWith('sha256=')) return false;
  const expected = `sha256=${createHmac('sha256', config.whatsapp.metaAppSecret).update(raw).digest('hex')}`;
  const left = Buffer.from(expected);
  const right = Buffer.from(signature);
  return left.length === right.length && timingSafeEqual(left, right);
}

function extractWhatsAppMessages(payload) {
  const output = [];
  for (const entry of payload.entry || []) {
    for (const change of entry.changes || []) {
      for (const message of change.value?.messages || []) {
        if (message.type === 'text' && message.text?.body && message.from) {
          output.push({ from: String(message.from).replace(/\D/g, ''), body: message.text.body });
        }
      }
    }
  }
  return output;
}

async function handleWhatsAppWebhook(request, response) {
  const { raw, value } = await readJson(request, 256 * 1024);
  if (!verifyMetaSignature(raw, request.headers['x-hub-signature-256'])) {
    throw new HttpError(401, 'Invalid Meta webhook signature', 'invalid_signature');
  }
  sendJson(response, 200, { received: true });
  for (const message of extractWhatsAppMessages(value)) {
    const match = message.body.toUpperCase().match(/\bGH-([23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8})\b/u);
    if (!match) continue;
    const challenge = db.getChallengeBySecret('whatsapp', keyedHash(config.appSecret, match[1]));
    if (!challenge || challenge.status !== 'pending' || Number(challenge.expires_at) < Date.now()) continue;
    if (normalizePhone(message.from, config.defaultCountryCode) !== challenge.target) continue;
    try {
      await completeChallenge(challenge, 'whatsapp', challenge.target);
    } catch (error) {
      console.error('WhatsApp authorization failed:', error.message);
    }
  }
}

function verifyTelegramSecret(request) {
  if (!config.telegram.webhookSecret) return true;
  const supplied = String(request.headers['x-telegram-bot-api-secret-token'] || '');
  const expected = String(config.telegram.webhookSecret);
  const left = Buffer.from(supplied);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function telegramMessage(payload) {
  return payload.message || payload.edited_message || null;
}

function telegramChatId(message) {
  const id = message?.chat?.id;
  return id == null ? '' : String(id);
}

function telegramStartPayload(text) {
  const match = String(text || '').trim().match(/^\/start(?:@\w+)?(?:\s+([A-Za-z0-9_-]{1,64}))?$/u);
  return match?.[1] || '';
}

function isTelegramStartCommand(text) {
  return /^\/start(?:@\w+)?(?:\s|$)/u.test(String(text || '').trim());
}

async function processTelegramUpdate(update) {
  const message = telegramMessage(update);
  const chatId = telegramChatId(message);
  if (!message || !chatId) return;

  try {
    const startPayload = telegramStartPayload(message.text);
    if (startPayload) {
      const challenge = db.getChallenge(startPayload);
      if (challenge?.kind === 'telegram' &&
          challenge.status === 'pending' &&
          Number(challenge.expires_at) >= Date.now()) {
        await deliveryGuard.run('telegram', () =>
          sendTelegramContactRequest(config.telegram, {
            chatId,
            appName: config.appName,
            language: challengeLanguage(challenge)
          })
        );
      } else {
        const language = telegramMessageLanguage(message, challenge);
        await deliveryGuard.run('telegram', () => sendTelegramText(config.telegram, {
          chatId,
          text: translate(language, 'telegramExpiredStartAgain', { appName: config.appName })
        }));
      }
      return;
    }
    if (isTelegramStartCommand(message.text)) {
      const language = telegramMessageLanguage(message);
      await deliveryGuard.run('telegram', () => sendTelegramText(config.telegram, {
        chatId,
        text: translate(language, 'telegramStartFromPortalFirst', { appName: config.appName })
      }));
      return;
    }

    if (/^\+?\d[\d\s().-]{6,}\d$/u.test(String(message.text || '').trim())) {
      const typedPhone = normalizePhone(message.text, config.defaultCountryCode);
      const challenge = phoneAllowed(typedPhone)
        ? db.getPendingChallengeByTarget('telegram', typedPhone)
        : null;
      const language = telegramMessageLanguage(message, challenge);
      await deliveryGuard.run('telegram', () => sendTelegramText(config.telegram, {
        chatId,
        text: translate(language, 'telegramDoNotTypePhone', { appName: config.appName })
      }));
      return;
    }

    const contact = message.contact;
    if (!contact?.phone_number) return;
    const phone = normalizePhone(contact.phone_number, config.defaultCountryCode);
    const phoneChallenge = phoneAllowed(phone)
      ? db.getPendingChallengeByTarget('telegram', phone)
      : null;
    if (contact.user_id == null || String(contact.user_id) !== String(message.from?.id)) {
      const language = telegramMessageLanguage(message, phoneChallenge);
      await deliveryGuard.run('telegram', () => sendTelegramText(config.telegram, {
        chatId,
        text: translate(language, 'telegramShareOwnPhone', { appName: config.appName })
      }));
      return;
    }

    const challenge = phoneChallenge;
    if (!challenge) {
      const language = telegramMessageLanguage(message);
      await deliveryGuard.run('telegram', () => sendTelegramText(config.telegram, {
        chatId,
        text: translate(language, 'telegramNoPendingVerification', { appName: config.appName })
      }));
      return;
    }

    const otp = generateOtp();
    const expiresAt = Date.now() + config.telegram.otpMinutes * 60 * 1000;
    db.updateChallengeSecret(challenge.id, keyedHash(config.appSecret, otp), expiresAt);
    const delivery = await deliveryGuard.run('telegram', () => sendTelegramOtp(config.telegram, {
      chatId,
      phone,
      code: otp,
      appName: config.appName,
      language: challengeLanguage(challenge)
    }));
    db.setChallengeDetail(challenge.id, deliveryDetail('telegram', delivery));
  } catch (error) {
    console.error('Telegram update handling failed:', error.message);
  }
}

async function handleTelegramWebhook(request, response) {
  const { value } = await readJson(request, 256 * 1024);
  if (!verifyTelegramSecret(request)) {
    throw new HttpError(401, 'Invalid Telegram webhook secret', 'invalid_signature');
  }
  sendJson(response, 200, { received: true });
  await processTelegramUpdate(value);
}

async function handleInstallRoute(request, response, url) {
  if (request.method === 'GET' && url.pathname === '/api/install/status') {
    sendJson(response, 200, getInstallStatus());
    return true;
  }

  if (request.method === 'POST' && url.pathname === '/api/install/secret') {
    if (!config.installRequired) throw new HttpError(409, 'System is already installed', 'already_installed');
    sendJson(response, 200, { secret: generateInstallSecret() });
    return true;
  }

  if (request.method === 'GET' && url.pathname === '/api/install/settings') {
    if (!config.installRequired) throw new HttpError(409, 'System is already installed', 'already_installed');
    sendJson(response, 200, getSettings());
    return true;
  }

  if (request.method === 'POST' && url.pathname === '/api/install/opnsense-test') {
    if (!config.installRequired) throw new HttpError(409, 'System is already installed', 'already_installed');
    const { value } = await readJson(request, 32 * 1024);
    let gateway;
    try {
      gateway = installOpnsenseGateway(value.settings || value);
    } catch (error) {
      throw new HttpError(400, error.message, error.code || 'invalid_opnsense_settings');
    }
    try {
      const sessions = await listGatewaySessions(gateway);
      sendJson(response, 200, {
        ok: true,
        zoneId: Number(gateway.zoneId || 0),
        sessions: sessions.length
      });
    } catch (error) {
      throw new HttpError(502, error.message, error.code || 'opnsense_test_failed');
    }
    return true;
  }

  if (request.method === 'POST' && url.pathname === '/api/install/gateway/networks') {
    if (!config.installRequired) throw new HttpError(409, 'System is already installed', 'already_installed');
    const { value } = await readJson(request, 32 * 1024);
    let gateway;
    try {
      gateway = installOpnsenseGateway(value.settings || value);
    } catch (error) {
      throw new HttpError(400, error.message, error.code || 'invalid_opnsense_settings');
    }
    try {
      sendJson(response, 200, {
        choices: await listGatewayNetworkChoices(gateway),
        error: ''
      });
    } catch {
      sendJson(response, 200, {
        choices: [],
        error: 'OPNsense networks could not be discovered automatically. You can enter networks manually.'
      });
    }
    return true;
  }

  if (request.method === 'POST' && url.pathname === '/api/install') {
    if (!config.installRequired) throw new HttpError(409, 'System is already installed', 'already_installed');
    const { value } = await readJson(request, 256 * 1024);
    try {
      sendJson(response, 200, completeInstallation(value.settings || value));
    } catch (error) {
      throw new HttpError(400, error.message, 'install_failed');
    }
    return true;
  }

  if (request.method === 'GET' && INSTALL_PAGE_PATHS.has(url.pathname)) {
    if (!config.installRequired) {
      redirectTo(response, '/admin');
      return true;
    }
    if (serveStatic(response, publicDir, '/install.html')) return true;
  }

  return false;
}

async function route(request, response) {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  if (await handleInstallRoute(request, response, url)) return;

  if (request.method === 'GET' && url.pathname === '/health') {
    sendJson(response, 200, {
      status: config.installRequired ? 'install_required' : 'ok',
      app: config.appName,
      gatewayMode: config.gateway.mode,
      installRequired: config.installRequired
    });
    return;
  }

  if (config.installRequired) {
    if (request.method === 'GET' && (
      url.pathname === '/' ||
      url.pathname === '/admin' ||
      url.pathname === '/admin/' ||
      SESSION_PAGE_PATHS.has(url.pathname)
    )) {
      if (serveStatic(response, publicDir, '/install.html')) return;
    }
    if (request.method === 'GET' && isInstallAssetPath(url.pathname)) {
      const pathname = url.pathname === '/favicon.ico' ? '/img/favicon.ico' : url.pathname;
      if (serveStatic(response, publicDir, pathname)) return;
    }
    throw new HttpError(503, 'System installation is required', 'install_required');
  }

  if (await admin.handle(request, response, url)) return;
  if (request.method === 'GET' && url.pathname === '/favicon.ico') {
    if (serveStatic(response, publicDir, '/img/favicon.ico')) return;
  }
  if (request.method === 'GET' && url.pathname === '/api/v1/about') {
    sendJson(response, 200, projectAbout());
    return;
  }
  if (request.method === 'GET' && url.pathname === '/api/v1/config') {
    const assets = appearanceAssets(config);
    const clientIp = getClientIp(request, config.trustProxy);
    sendJson(response, 200, {
      appName: config.appName,
      voucherEnabled: config.voucher.enabled,
      emailEnabled: config.smtp.enabled,
      whatsappEnabled: config.whatsapp.enabled,
      telegramEnabled: config.telegram.enabled,
      smsEnabled: config.sms.enabled,
      adminApprovalEnabled: config.adminApproval.enabled,
      nviEnabled: config.nvi.enabled,
      nviSendSmsCode: config.nvi.sendSmsCode,
      gatewayMode: config.gateway.mode,
      clientIp,
      defaultCountryCode: config.defaultCountryCode,
      allowedCountryCodes: config.allowedCountryCodes,
      countryCallingCodes: COUNTRY_CALLING_CODES,
      defaultLanguage: config.defaultLanguage,
      languages: ['en', 'tr'],
      portal: {
        titleText: config.portal.titleText,
        networkLabelText: config.portal.networkLabelText,
        verificationPromptText: config.portal.verificationPromptText
      },
      terms: {
        text: config.portal.termsText,
        markdown: config.portal.termsMarkdown,
        policyMarkdown: config.portal.policyMarkdown,
        privacyMarkdown: config.portal.privacyMarkdown
      },
      appearance: {
        logoUrl: assets.logo.url
      }
    });
    return;
  }
  if (request.method === 'GET' && url.pathname === '/api/v1/client-mac') {
    const clientIp = getClientIp(request, config.trustProxy);
    sendJson(response, 200, {
      clientIp,
      clientMac: await requestClientMac(url, clientIp)
    });
    return;
  }
  if (request.method === 'GET' && url.pathname === '/portal-theme.css') {
    sendText(response, 200, portalThemeCss(config), 'text/css; charset=utf-8');
    return;
  }
  const appearanceAssetMatch = url.pathname.match(
    /^\/api\/v1\/appearance\/assets\/(logo|card-background|body-background)$/u
  );
  if (request.method === 'GET' && appearanceAssetMatch) {
    serveAppearanceAsset(response, config, appearanceAssetMatch[1]);
    return;
  }
  if (request.method === 'GET' && url.pathname === '/api/v1/session') {
    normalizeActiveAuthorizationDurations(db, config, { limit: 5000 });
    const authorization = await currentAuthorization(request, url, { allowQuotaBlocked: true });
    if (!authorization) {
      if (url.searchParams.get('optional') === '1') {
        sendJson(response, 200, { active: false });
        return;
      }
      throw new HttpError(404, 'Session not found', 'session_not_found');
    }
    setUserSessionCookie(response, authorization);
    sendJson(response, 200, authorizationPublic(authorization));
    return;
  }
  if (request.method === 'POST' && url.pathname === '/api/v1/session/logout') {
    if (request.headers['x-session-action'] !== 'logout') {
      throw new HttpError(403, 'Invalid session action', 'invalid_session_action');
    }
    const authorization = await currentAuthorization(request, url, { allowQuotaBlocked: true });
    if (!authorization) throw new HttpError(404, 'Session not found', 'session_not_found');
    if (authorization.gateway_session_id) {
      try {
        await disconnectGatewaySession(config.gateway, authorization.gateway_session_id);
      } catch (error) {
        console.warn(`User session could not be disconnected from OPNsense: ${error.message}`);
        throw new HttpError(502, `Gateway disconnect failed: ${error.message}`, 'gateway_disconnect_failed');
      }
    }
    db.endAuthorization(authorization.id, 'user_logout');
    await deleteAuthorizationKeaLease(authorization);
    setUserSessionCookie(response, null);
    sendJson(response, 200, { ok: true, redirectUrl: '/' });
    return;
  }
  if (request.method === 'POST' && url.pathname === '/api/v1/voucher/redeem') return handleVoucher(request, response);
  if (request.method === 'POST' && url.pathname === '/api/v1/admin-approval/request') {
    return handleAdminApprovalRequest(request, response);
  }
  if (request.method === 'GET' && url.pathname.startsWith('/api/v1/admin-approval/status/')) {
    return handleAdminApprovalStatus(
      request,
      response,
      decodeURIComponent(url.pathname.slice('/api/v1/admin-approval/status/'.length))
    );
  }
  if (request.method === 'POST' && url.pathname === '/api/v1/email/request') return handleEmailRequest(request, response);
  if (request.method === 'POST' && url.pathname === '/api/v1/email/verify') return handleEmailVerify(request, response);
  if (request.method === 'POST' && url.pathname === '/api/v1/nvi/request') return handleNviRequest(request, response);
  if (request.method === 'POST' && url.pathname === '/api/v1/nvi/verify') return handleNviVerify(request, response);
  if (request.method === 'POST' && url.pathname === '/api/v1/whatsapp/request') return handleWhatsAppRequest(request, response);
  if (request.method === 'POST' && url.pathname === '/api/v1/whatsapp/verify') return handleWhatsAppVerify(request, response);
  if (request.method === 'POST' && url.pathname === '/api/v1/telegram/request') return handleTelegramRequest(request, response);
  if (request.method === 'POST' && url.pathname === '/api/v1/telegram/verify') return handleTelegramVerify(request, response);
  if (request.method === 'GET' && url.pathname === '/api/v1/telegram/current') {
    return handleTelegramCurrent(request, response, { optional: url.searchParams.get('optional') === '1' });
  }
  if (request.method === 'GET' && url.pathname.startsWith('/api/v1/telegram/resume/')) {
    return handleTelegramResume(request, response, decodeURIComponent(url.pathname.slice('/api/v1/telegram/resume/'.length)));
  }
  if (request.method === 'POST' && url.pathname === '/api/v1/sms/request') return handleSmsRequest(request, response);
  if (request.method === 'POST' && url.pathname === '/api/v1/sms/verify') return handleSmsVerify(request, response);
  if (request.method === 'GET' && url.pathname.startsWith('/api/v1/whatsapp/status/')) {
    const id = decodeURIComponent(url.pathname.slice('/api/v1/whatsapp/status/'.length));
    const challenge = db.getChallenge(id);
    if (!challenge || challenge.kind !== 'whatsapp') throw new HttpError(404, 'Verification request not found', 'challenge_not_found');
    if (challenge.client_ip !== getClientIp(request, config.trustProxy)) throw new HttpError(403, 'This verification belongs to another device', 'client_mismatch');
    sendJson(response, 200, challengePublic(challenge));
    return;
  }
  if (request.method === 'GET' && url.pathname === '/webhooks/whatsapp') {
    if (url.searchParams.get('hub.mode') === 'subscribe' &&
        url.searchParams.get('hub.verify_token') === config.whatsapp.verifyToken) {
      sendText(response, 200, url.searchParams.get('hub.challenge') || '');
    } else sendText(response, 403, 'Forbidden');
    return;
  }
  if (request.method === 'POST' && url.pathname === '/webhooks/whatsapp') return handleWhatsAppWebhook(request, response);
  if (request.method === 'POST' && url.pathname === '/webhooks/telegram') return handleTelegramWebhook(request, response);
  if (request.method === 'GET' && (url.pathname === '/admin' || url.pathname === '/admin/')) {
    if (serveStatic(response, publicDir, '/admin/index.html')) return;
  }
  if (request.method === 'GET' && SESSION_PAGE_PATHS.has(url.pathname)) {
    const authorization = await currentAuthorization(request, url, { allowQuotaBlocked: true });
    if (!authorization) {
      redirectToPortal(response);
      return;
    }
    setUserSessionCookie(response, authorization);
    if (serveStatic(response, publicDir, '/session.html')) return;
  }
  if (request.method === 'GET' && serveStatic(response, publicDir, url.pathname)) return;
  throw new HttpError(404, 'Not found', 'not_found');
}

const server = http.createServer(async (request, response) => {
  try {
    await route(request, response);
  } catch (error) {
    if (response.headersSent) return;
    const status = error instanceof HttpError ? error.statusCode : 500;
    if (status >= 500 && !(error instanceof HttpError && error.code === 'install_required')) {
      console.error(error);
    }
    sendJson(response, status, {
      error: error instanceof HttpError ? error.code : 'internal_error',
      message: status === 500 ? 'Internal server error' : error.message,
      ...(error instanceof HttpError && error.details ? error.details : {})
    });
  }
});

const cleanupTimer = setInterval(() => db.cleanup(), 10 * 60 * 1000);
cleanupTimer.unref();
syslogReceiver.start();
syslogAutoExporter.start();
syslogHealthGuard.start();
let authorizationExpiryRunning = false;
function runAuthorizationExpiry() {
  if (authorizationExpiryRunning) return;
  authorizationExpiryRunning = true;
  admin.expireAuthorizations({ limit: 500 })
    .catch(error => console.warn(`Expired authorization cleanup failed: ${error.message}`))
    .finally(() => { authorizationExpiryRunning = false; });
}
runAuthorizationExpiry();
const authorizationExpiryTimer = setInterval(runAuthorizationExpiry, 30 * 1000);
authorizationExpiryTimer.unref();
let usageSyncRunning = false;
const usageSyncTimer = setInterval(() => {
  if (config.gateway.mode !== 'opnsense-api') return;
  if (!config.gateway.syncEnabled) return;
  if (usageSyncRunning) return;
  usageSyncRunning = true;
  admin.syncUsage()
    .catch(error => console.warn(`OPNsense usage sync failed: ${error.message}`))
    .finally(() => { usageSyncRunning = false; });
}, Math.max(5, Number(config.gateway.syncIntervalSeconds || 10)) * 1000);
usageSyncTimer.unref();

let telegramPollingStopped = false;
let telegramPollingOffset = 0;
let telegramWebhookDeleted = false;

async function pollTelegramUpdates() {
  if (telegramPollingStopped || !config.telegram.enabled || config.telegram.mode !== 'polling') return;
  try {
    if (!telegramWebhookDeleted) {
      await deleteTelegramWebhook(config.telegram);
      telegramWebhookDeleted = true;
    }
    const updates = await getTelegramUpdates(config.telegram, {
      offset: telegramPollingOffset,
      timeout: 20,
      limit: 25
    });
    for (const update of updates) {
      telegramPollingOffset = Math.max(telegramPollingOffset, Number(update.update_id) + 1);
      await processTelegramUpdate(update);
    }
  } catch (error) {
    console.warn(`Telegram polling failed: ${error.message}`);
  } finally {
    if (!telegramPollingStopped) setTimeout(pollTelegramUpdates, 1000).unref();
  }
}

if (config.telegram.enabled && config.telegram.mode === 'polling') {
  pollTelegramUpdates();
}

server.listen(config.port, config.host, () => {
  console.log(`${config.appName} listening on http://${config.host}:${config.port}`);
  console.log(`Gateway mode: ${config.gateway.mode}`);
  notifySystemStartup();
  if (!config.smtp.enabled) console.log('E-mail verification: disabled');
  if (!config.whatsapp.enabled) {
    console.log('WhatsApp verification: disabled (set PHONE_NUMBER_ID, ACCESS_TOKEN and TEMPLATE_NAME)');
  }
  if (!config.telegram.enabled) console.log('Telegram verification: disabled');
  else console.log(`Telegram verification: ${config.telegram.mode}`);
  if (!config.sms.enabled) console.log('SMS verification: disabled');
  if (!config.nvi.enabled) console.log('NVI verification: disabled');
  if (!config.adminApproval.enabled) console.log('Admin approval verification: disabled');
  if (config.syslog.enabled) {
    console.log(`Syslog logging: enabled for ${config.syslog.networks}`);
    console.log(config.syslog.autoExportEnabled
      ? `Syslog automatic export: ${config.syslog.autoExportInterval === 'daily'
        ? 'daily at 23:59:59'
        : `every ${config.syslog.autoExportIntervalMinutes} minutes`}`
      : 'Syslog automatic export: disabled');
    if (!config.syslog.syslogEnabled) {
      console.log('OPNsense firewall syslog receiver: disabled');
    }
  }
  if (config.whatsapp.verifyToken && !config.whatsapp.metaAppSecret) {
    console.warn('Warning: META_APP_SECRET is empty; WhatsApp webhook signatures are not verified.');
  }
  if (gatewayHasBandwidthProfiles(config.gateway)) {
    ensureGatewayBandwidthLimits(config.gateway, {
      force: true,
      authorizations: db.listActiveBandwidthAuthorizations
        ? db.listActiveBandwidthAuthorizations({ gatewayMode: config.gateway.mode })
        : []
    }).catch(error => {
      console.warn(`Bandwidth limits could not be applied: ${error.message}`);
    });
  }
});

function shutdown(signal) {
  console.log(`\n${signal} received, shutting down...`);
  telegramPollingStopped = true;
  clearInterval(cleanupTimer);
  clearInterval(usageSyncTimer);
  syslogReceiver.close();
  syslogAutoExporter.close();
  syslogHealthGuard.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
