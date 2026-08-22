import { createSign } from 'node:crypto';
import path from 'node:path';
import { readRegularFileSync } from '../lib/files.js';

const FCM_SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const FCM_API_ORIGIN = 'https://fcm.googleapis.com';
const TOKEN_MARGIN_MS = 60_000;
const FIREBASE_PROJECT_ID_PATTERN = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/u;
const SERVICE_ACCOUNT_EMAIL_PATTERN = /^[a-z0-9][a-z0-9._-]{2,126}@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/u;

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

function configuredProjectId(config) {
  const projectId = String(config.notifications?.androidFcmProjectId || '').trim();
  if (!FIREBASE_PROJECT_ID_PATTERN.test(projectId)) {
    throw new Error('Firebase project ID is missing or invalid');
  }
  return projectId;
}

function readServiceAccount(config) {
  const file = serviceAccountPath(config);
  if (!file) return null;
  const projectId = configuredProjectId(config);
  const resolvedFile = path.resolve(file);
  if (credentialCache?.file === resolvedFile && credentialCache?.projectId === projectId) {
    return credentialCache.value;
  }
  const parsed = JSON.parse(readRegularFileSync(resolvedFile, 'utf8').data);
  const clientEmail = String(parsed?.client_email || '').trim().toLowerCase();
  const privateKey = String(parsed?.private_key || '');
  if (parsed?.type !== 'service_account' ||
      parsed?.project_id !== projectId ||
      !SERVICE_ACCOUNT_EMAIL_PATTERN.test(clientEmail) ||
      !clientEmail.endsWith(`@${projectId}.iam.gserviceaccount.com`) ||
      privateKey.length < 1024 || privateKey.length > 16 * 1024 ||
      !privateKey.startsWith('-----BEGIN PRIVATE KEY-----\n') ||
      !privateKey.trimEnd().endsWith('-----END PRIVATE KEY-----') ||
      (parsed?.token_uri && parsed.token_uri !== GOOGLE_TOKEN_URL)) {
    throw new Error('Firebase service account is invalid or does not match the configured project');
  }
  const value = Object.freeze({ client_email: clientEmail, private_key: privateKey });
  credentialCache = { file: resolvedFile, projectId, value };
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
  const projectId = configuredProjectId(config);
  const token = await accessToken(config);
  const endpoint = new URL(`/v1/projects/${encodeURIComponent(projectId)}/messages:send`, FCM_API_ORIGIN);
  const response = await fetch(
    endpoint,
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
