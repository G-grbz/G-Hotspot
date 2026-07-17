import fs from 'node:fs';
import { createSign } from 'node:crypto';

const FCM_SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const TOKEN_MARGIN_MS = 60_000;

let credentialCache = null;
let accessTokenCache = null;
let accessTokenPromise = null;

function base64Url(value) {
  return Buffer.from(value).toString('base64url');
}

function serviceAccountPath(config) {
  return String(
    config.notifications?.androidFcmServiceAccountFile ||
    process.env.GOOGLE_APPLICATION_CREDENTIALS ||
    ''
  ).trim();
}

function readServiceAccount(config) {
  const file = serviceAccountPath(config);
  if (!file) return null;
  if (credentialCache?.file === file) return credentialCache.value;
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!value.project_id || !value.client_email || !value.private_key) {
    throw new Error('Firebase service account must include project_id, client_email, and private_key');
  }
  credentialCache = { file, value };
  accessTokenCache = null;
  return value;
}

export function androidPushConfigured(config) {
  try {
    return Boolean(readServiceAccount(config));
  } catch {
    return false;
  }
}

async function mintAccessToken(config) {
  const now = Date.now();
  if (accessTokenCache && accessTokenCache.expiresAt - TOKEN_MARGIN_MS > now) {
    return accessTokenCache.value;
  }
  const credentials = readServiceAccount(config);
  if (!credentials) throw new Error('Firebase service account is not configured');
  const issuedAt = Math.floor(now / 1000);
  const header = base64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = base64Url(JSON.stringify({
    iss: credentials.client_email,
    scope: FCM_SCOPE,
    aud: GOOGLE_TOKEN_URL,
    iat: issuedAt,
    exp: issuedAt + 3600
  }));
  const unsigned = `${header}.${claims}`;
  const signer = createSign('RSA-SHA256');
  signer.update(unsigned);
  signer.end();
  const assertion = `${unsigned}.${signer.sign(credentials.private_key, 'base64url')}`;
  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion
    })
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.access_token) {
    throw new Error(result.error_description || result.error || `Google OAuth failed (${response.status})`);
  }
  accessTokenCache = {
    value: result.access_token,
    expiresAt: now + Math.max(60, Number(result.expires_in) || 3600) * 1000
  };
  return accessTokenCache.value;
}

async function accessToken(config) {
  const now = Date.now();
  if (accessTokenCache && accessTokenCache.expiresAt - TOKEN_MARGIN_MS > now) {
    return accessTokenCache.value;
  }
  if (!accessTokenPromise) {
    accessTokenPromise = mintAccessToken(config).finally(() => {
      accessTokenPromise = null;
    });
  }
  return accessTokenPromise;
}

function compactNotification(notification) {
  return {
    id: notification.id,
    type: notification.type,
    title: String(notification.title || '').slice(0, 160),
    body: String(notification.body || '').slice(0, 2000),
    payload: notification.type === 'admin-approval'
      ? { requestId: notification.payload?.requestId || '' }
      : {},
    actions: Array.isArray(notification.actions) ? notification.actions.slice(0, 4) : [],
    createdAt: Number(notification.createdAt || 0),
    expiresAt: notification.expiresAt == null ? null : Number(notification.expiresAt)
  };
}

export function androidPushMessage(device, notification, now = Date.now()) {
  const expiresAt = Number(notification.expiresAt || 0);
  const ttlSeconds = expiresAt
    ? Math.max(0, Math.min(86_400, Math.floor((expiresAt - now) / 1000)))
    : 86_400;
  return {
    message: {
      token: device.fcm_token,
      data: {
        notification: JSON.stringify(compactNotification(notification))
      },
      android: {
        priority: 'HIGH',
        ttl: `${ttlSeconds}s`
      }
    }
  };
}

function fcmErrorCode(result) {
  const details = Array.isArray(result?.error?.details) ? result.error.details : [];
  return String(details.find(detail => detail?.errorCode)?.errorCode || result?.error?.status || '');
}

export async function sendAndroidPush(config, device, notification) {
  if (!device?.fcm_token || !androidPushConfigured(config)) return { sent: false, reason: 'not_configured' };
  const credentials = readServiceAccount(config);
  const token = await accessToken(config);
  const response = await fetch(
    `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(credentials.project_id)}/messages:send`,
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json'
      },
      body: JSON.stringify(androidPushMessage(device, notification))
    }
  );
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(result?.error?.message || `FCM send failed (${response.status})`);
    error.code = fcmErrorCode(result);
    throw error;
  }
  return { sent: true, name: result.name || '' };
}

export function dispatchAndroidPush(db, config, device, notification) {
  if (!device?.fcm_token || !androidPushConfigured(config)) return;
  void sendAndroidPush(config, device, notification).catch(error => {
    if (error.code === 'UNREGISTERED') {
      db.clearAndroidDevicePushToken(device.id, device.fcm_token);
      return;
    }
    console.error(`Android FCM delivery failed for device ${device.id}:`, error.message);
  });
}
