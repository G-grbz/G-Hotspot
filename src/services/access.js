import {
  authorizeGateway, disconnectGatewaySession, ensureGatewayKeaDhcpLease,
  ensureGatewayBandwidthLimits, listGatewayClientOwnership
} from './opnsense.js';
import { assertLaw5651PortalWritable } from './law5651.js';
import { normalizeMac } from '../lib/security.js';
import { authorizationQuotaBlocked, gatewayHasBandwidthProfiles } from './quotas.js';

const UNLIMITED_EXPIRES_AT = Date.UTC(9999, 11, 31, 23, 59, 59);
const postAccessSyncs = new Set();
const CONFIGURED_ACCESS_DURATION_METHODS = {
  'admin-approval': config => config?.adminApproval?.accessDuration,
  email: config => config?.smtp?.accessDuration,
  nvi: config => config?.nvi?.accessDuration,
  sms: config => config?.sms?.accessDuration,
  telegram: config => config?.telegram?.accessDuration,
  whatsapp: config => config?.whatsapp?.accessDuration
};

export function accessExpiry(duration, now = Date.now()) {
  if (!duration || duration.unit === 'minutes') {
    return { expiresAt: now + Number(duration?.value || 0) * 60 * 1000, unlimited: false };
  }
  if (duration.unit === 'unlimited') {
    return { expiresAt: UNLIMITED_EXPIRES_AT, unlimited: true };
  }
  const value = Math.max(1, Number(duration.value) || 1);
  const date = new Date(now);
  if (duration.unit === 'hours') date.setUTCHours(date.getUTCHours() + value);
  else if (duration.unit === 'days') date.setUTCDate(date.getUTCDate() + value);
  else if (duration.unit === 'months') date.setUTCMonth(date.getUTCMonth() + value);
  else if (duration.unit === 'years') date.setUTCFullYear(date.getUTCFullYear() + value);
  else throw new Error(`Unsupported access duration unit: ${duration.unit}`);
  return { expiresAt: date.getTime(), unlimited: false };
}

export function accessDurationForMethod(config, method) {
  const resolver = CONFIGURED_ACCESS_DURATION_METHODS[method];
  return resolver ? resolver(config) || null : null;
}

export function effectiveAuthorizationAccess(config, authorization) {
  const storedExpiresAt = Number(authorization?.expires_at);
  const storedUnlimited = Boolean(Number(authorization?.unlimited || 0));
  const createdAt = Number(authorization?.created_at);
  const duration = accessDurationForMethod(config, authorization?.method);
  if (!duration || !Number.isFinite(createdAt) || createdAt <= 0) {
    return {
      expiresAt: storedExpiresAt,
      unlimited: storedUnlimited,
      leaseSeconds: Number(authorization?.lease_seconds || 0) || null,
      changed: false
    };
  }
  const expiry = accessExpiry(duration, createdAt);
  const expiresAt = Math.trunc(Number(expiry.expiresAt));
  const unlimited = Boolean(expiry.unlimited);
  const leaseSeconds = Math.max(60, Math.ceil((expiresAt - createdAt) / 1000));
  return {
    expiresAt,
    unlimited,
    leaseSeconds,
    changed: expiresAt !== storedExpiresAt || unlimited !== storedUnlimited
  };
}

export function authorizationWithEffectiveAccess(config, authorization) {
  if (!authorization) return authorization;
  const effective = effectiveAuthorizationAccess(config, authorization);
  if (!effective.changed) return authorization;
  return {
    ...authorization,
    expires_at: effective.expiresAt,
    unlimited: effective.unlimited ? 1 : 0,
    lease_seconds: effective.leaseSeconds
  };
}

export function normalizeActiveAuthorizationDurations(db, config, { limit = 1000 } = {}) {
  if (!db?.listOpenAuthorizationsForMethods || !db?.updateAuthorizationAccessDuration) {
    return { checked: 0, updated: 0 };
  }
  const methods = Object.keys(CONFIGURED_ACCESS_DURATION_METHODS)
    .filter(method => accessDurationForMethod(config, method));
  const rows = db.listOpenAuthorizationsForMethods(methods, { limit });
  let updated = 0;
  for (const row of rows) {
    const effective = effectiveAuthorizationAccess(config, row);
    if (!effective.changed) continue;
    if (db.updateAuthorizationAccessDuration(row.id, effective)) updated += 1;
  }
  return { checked: rows.length, updated };
}

export function reverificationState(duration, verifiedAt, now = Date.now()) {
  if (!verifiedAt) return { allowed: true, retryAt: null, permanent: false };
  const expiry = accessExpiry(duration, Number(verifiedAt));
  if (expiry.unlimited) return { allowed: false, retryAt: null, permanent: true };
  return {
    allowed: expiry.expiresAt <= now,
    retryAt: expiry.expiresAt,
    permanent: false
  };
}

function macForClientIp(rows, clientIp) {
  for (const row of rows) {
    if (row?.clientIp === clientIp) {
      const mac = normalizeMac(row.clientMac);
      if (mac) return mac;
    }
  }
  return '';
}

async function gatewayClientOwnership(gateway) {
  return listGatewayClientOwnership(gateway, { context: 'granting access' });
}

function accessClientMac(gatewayMode, { requestedClientMac = '', gatewayClientMac = '', ownedClientMac = '' }) {
  if (gatewayMode === 'opnsense-api') {
    return normalizeMac(ownedClientMac);
  }
  return normalizeMac(requestedClientMac) || normalizeMac(gatewayClientMac);
}

function accessResultFromAuthorization(authorization, redirectUrl = '') {
  return {
    ok: true,
    authorizationId: authorization.id,
    expiresAt: Number(authorization.expires_at),
    unlimited: Boolean(authorization.unlimited),
    clientMac: authorization.client_mac || '',
    redirectUrl: authorization.redirect_url || redirectUrl || '',
    gatewayMode: authorization.gateway_mode
  };
}

function activeIpConflictError(authorization) {
  const error = new Error(
    `This IP address already has active internet access until ${new Date(Number(authorization.expires_at)).toISOString()}.`
  );
  error.code = 'active_ip_authorization_exists';
  error.authorizationId = authorization.id;
  return error;
}

function quotaBlockedError(authorization) {
  const error = new Error(
    `This access quota is exhausted until ${new Date(Number(authorization.quota_blocked_until)).toISOString()}.`
  );
  error.code = 'quota_exceeded';
  error.authorizationId = authorization.id;
  error.retryAt = Number(authorization.quota_blocked_until);
  return error;
}

function sameAuthorization(authorization, method, identity) {
  return authorization.method === method && authorization.identity === identity;
}

async function restoreExistingAuthorizationAccess({
  db, config, authorization, method, identity, clientIp, clientMac, redirectUrl
}) {
  let current = authorization;
  if (config.gateway.mode === 'opnsense-api' && !authorization.gateway_session_id) {
    const gateway = await authorizeGateway(config.gateway, {
      user: `${method}:${identity}`.slice(0, 128),
      clientIp
    });
    db.moveAuthorizationGatewaySession(authorization.id, {
      clientIp,
      clientMac: normalizeMac(clientMac) || normalizeMac(authorization.client_mac) || normalizeMac(gateway.clientMac),
      gatewaySessionId: gateway.storedSessionId || gateway.sessionId,
      gatewayResponse: gateway.response
    });
    current = db.getAuthorization(authorization.id);
  }
  queuePostAccessSync(config, db, current);
  return accessResultFromAuthorization(current, redirectUrl);
}

async function synchronizeKeaLease(config, authorization, leaseSeconds = null, db = null) {
  if (config.gateway.keaLeaseSyncEnabled !== true) return;
  try {
    const result = await ensureGatewayKeaDhcpLease(config.gateway, {
      authorizationId: authorization.id,
      clientIp: authorization.client_ip,
      clientMac: authorization.client_mac,
      expiresAt: authorization.expires_at,
      leaseSeconds: leaseSeconds || authorization.lease_seconds,
      method: authorization.method,
      identity: authorization.identity
    });
    if (result.applied && db?.markAuthorizationKeaSynced) db.markAuthorizationKeaSynced(authorization.id);
  } catch (error) {
    console.warn(`Kea DHCP lease lifetime could not be synchronized: ${error.message}`);
  }
}

async function synchronizeBandwidthLimits(config, db) {
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

function queuePostAccessSync(config, db, authorization, leaseSeconds = null) {
  const needsKea = config.gateway.keaLeaseSyncEnabled === true;
  const needsBandwidth = gatewayHasBandwidthProfiles(config.gateway);
  if (!needsKea && !needsBandwidth) return;
  const key = [
    authorization.id,
    needsKea ? authorization.lease_seconds || leaseSeconds || '' : '',
    needsBandwidth ? 'bandwidth' : ''
  ].join('|');
  if (postAccessSyncs.has(key)) return;
  postAccessSyncs.add(key);
  setTimeout(() => {
    (async () => {
      await synchronizeKeaLease(config, authorization, leaseSeconds, db);
      await synchronizeBandwidthLimits(config, db);
    })().finally(() => {
      postAccessSyncs.delete(key);
    });
  }, 0);
}

async function resolveClientIpConflicts({ db, config, method, identity, clientIp, clientMac, redirectUrl }) {
  const active = db.listActiveAuthorizationsForClient(clientIp);
  for (const authorization of active) {
    const authorizationMac = normalizeMac(authorization.client_mac);
    const currentMac = normalizeMac(clientMac);
    if (sameAuthorization(authorization, method, identity)) {
      if (authorizationQuotaBlocked(authorization)) throw quotaBlockedError(authorization);
      if (!authorizationMac || !currentMac || authorizationMac === currentMac) {
        return restoreExistingAuthorizationAccess({
          db, config, authorization, method, identity, clientIp, clientMac: currentMac, redirectUrl
        });
      }
      throw activeIpConflictError(authorization);
    }
    if (config.gateway.mode === 'opnsense-api' && authorizationMac && currentMac && authorizationMac !== currentMac) {
      if (authorization.gateway_session_id) {
        try {
          await disconnectGatewaySession(config.gateway, authorization.gateway_session_id);
        } catch (error) {
          console.warn(`Conflicting gateway session could not be disconnected: ${error.message}`);
        }
      }
      db.clearAuthorizationGatewaySession(authorization.id);
      continue;
    }
    throw activeIpConflictError(authorization);
  }
  return null;
}

export async function grantAccess({
  db, config, method, identity, clientIp, clientMac, duration, durationMinutes, redirectUrl
}) {
  const accessStartedAt = Date.now();
  normalizeActiveAuthorizationDurations(db, config, { limit: 5000 });
  assertLaw5651PortalWritable({
    db,
    config,
    context: { method, identity, clientIp }
  });
  const { expiresAt, unlimited } = accessExpiry(
    duration || { value: durationMinutes, unit: 'minutes' },
    accessStartedAt
  );
  const leaseSeconds = Math.ceil((expiresAt - accessStartedAt) / 1000);
  const gatewayUser = `${method}:${identity}`.slice(0, 128);
  const ownership = await gatewayClientOwnership(config.gateway);
  const ownedClientMac = macForClientIp(ownership.rows, clientIp);
  const requestedClientMac = accessClientMac(config.gateway.mode, {
    requestedClientMac: clientMac,
    ownedClientMac
  });
  const existing = await resolveClientIpConflicts({
    db,
    config,
    method,
    identity,
    clientIp,
    clientMac: requestedClientMac,
    redirectUrl
  });
  if (existing) return existing;
  try {
    const gateway = await authorizeGateway(config.gateway, { user: gatewayUser, clientIp });
    const resolvedClientMac = accessClientMac(config.gateway.mode, {
      requestedClientMac: clientMac,
      gatewayClientMac: gateway.clientMac,
      ownedClientMac
    });
    const authorization = db.saveAuthorization({
      method,
      identity,
      clientIp,
      clientMac: resolvedClientMac,
      gatewayMode: config.gateway.mode,
      gatewaySessionId: gateway.storedSessionId || gateway.sessionId,
      status: 'active',
      expiresAt,
      unlimited,
      leaseSeconds,
      redirectUrl,
      gatewayResponse: gateway.response,
      error: ''
    });
    queuePostAccessSync(config, db, authorization, leaseSeconds);
    return {
      ok: true,
      authorizationId: authorization.id,
      expiresAt,
      unlimited,
      clientMac: authorization.client_mac || '',
      redirectUrl: redirectUrl || '',
      gatewayMode: config.gateway.mode
    };
  } catch (error) {
    const resolvedClientMac = accessClientMac(config.gateway.mode, {
      requestedClientMac: clientMac
    });
    const authorization = db.saveAuthorization({
      method,
      identity,
      clientIp,
      clientMac: resolvedClientMac,
      gatewayMode: config.gateway.mode,
      gatewaySessionId: null,
      status: 'failed',
      expiresAt,
      unlimited,
      leaseSeconds,
      redirectUrl,
      gatewayResponse: null,
      error: error.message
    });
    error.authorizationId = authorization.id;
    throw error;
  }
}
