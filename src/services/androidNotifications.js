import { dispatchAndroidPush } from './androidPush.js';

function cleanText(value, limit = 500) {
  return String(value || '').replace(/\s+/gu, ' ').trim().slice(0, limit);
}

function locale(config) {
  return config.defaultLanguage || 'en';
}

function androidChannelEnabled(config) {
  return config.notifications?.androidEnabled === true;
}

export function shouldQueueAndroidAdminApprovalRequest(config) {
  const notifications = config.notifications || {};
  if (!androidChannelEnabled(config)) return false;
  if (Object.hasOwn(notifications, 'androidAdminApprovalEnabled')) {
    return notifications.androidAdminApprovalEnabled !== false;
  }
  if (Object.hasOwn(notifications, 'adminApprovalEnabled')) {
    return notifications.adminApprovalEnabled !== false;
  }
  return true;
}

export function queueAndroidNotification(db, config, {
  type = 'system',
  title,
  body,
  payload = null,
  actions = [],
  expiresAt = null
} = {}) {
  if (!androidChannelEnabled(config)) return { sent: 0, skipped: true, reason: 'disabled' };
  const devices = db.listAndroidDevices({ enabled: true, limit: 500 }).rows;
  if (!devices.length) return { sent: 0, skipped: true, reason: 'no_devices' };
  const createdAt = Date.now();
  let sent = 0;
  for (const device of devices) {
    const notification = db.createAndroidNotification({
      deviceId: device.id,
      type,
      title: cleanText(title, 160) || config.appName || 'G-Hotspot',
      body: cleanText(body, 2000),
      payload,
      actions,
      expiresAt,
      createdAt
    });
    dispatchAndroidPush(db, config, device, notification);
    sent += 1;
  }
  return { sent, devices: sent };
}

export function queueAndroidSystemNotification(db, config, { title, body, event }) {
  const detail = event?.detail || event?.detail_json || {};
  return queueAndroidNotification(db, config, {
    type: 'system',
    title: title || `${config.appName || 'G-Hotspot'} notification`,
    body,
    payload: {
      eventType: event?.eventType || event?.event_type || '',
      severity: event?.severity || 'info',
      detail
    }
  });
}

export function queueAndroidAdminApprovalRequest(db, config, request) {
  if (!shouldQueueAndroidAdminApprovalRequest(config)) {
    return { sent: 0, skipped: true, reason: 'disabled' };
  }
  const appName = config.appName || 'G-Hotspot';
  const tr = locale(config) === 'tr';
  const title = tr ? `${appName}: Yönetici onayı` : `${appName}: Admin approval`;
  const identity = cleanText(request.full_name || request.identity || '', 120);
  const clientIp = cleanText(request.client_ip || '', 64);
  const body = tr
    ? `${identity || 'Misafir'} internet erişimi istiyor${clientIp ? ` (${clientIp})` : ''}.`
    : `${identity || 'Guest'} is requesting internet access${clientIp ? ` (${clientIp})` : ''}.`;
  return queueAndroidNotification(db, config, {
    type: 'admin-approval',
    title,
    body,
    payload: {
      requestId: request.id,
      fullName: request.full_name || '',
      contact: request.contact || '',
      contactType: request.contact_type || 'none',
      identity: request.identity || '',
      clientIp: request.client_ip || '',
      clientMac: request.client_mac || '',
      createdAt: Number(request.created_at || 0),
      expiresAt: Number(request.request_expires_at || 0)
    },
    actions: [
      { id: 'approve', label: tr ? 'Onayla' : 'Approve' },
      { id: 'reject', label: tr ? 'Reddet' : 'Reject' }
    ],
    expiresAt: Number(request.request_expires_at || 0) || null
  });
}
