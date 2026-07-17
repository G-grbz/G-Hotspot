import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { HotspotDatabase } from '../src/db.js';
import { generateSecret, keyedHash } from '../src/lib/security.js';
import {
  queueAndroidAdminApprovalRequest,
  queueAndroidSystemNotification
} from '../src/services/androidNotifications.js';
import { androidPushMessage } from '../src/services/androidPush.js';

test('android admin approval notifications are queued for registered devices', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-android-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  try {
    const token = generateSecret(32);
    const device = db.createAndroidDevice({
      tokenHash: keyedHash('test-secret', token),
      adminUser: 'admin',
      name: 'Pixel'
    });
    const request = db.createAdminApprovalRequest({
      fullName: 'Ada Lovelace',
      identity: 'Ada Lovelace',
      clientIp: '192.168.1.20',
      expiresAt: Date.now() + 60000
    });
    const result = queueAndroidAdminApprovalRequest(db, {
      appName: 'G-Hotspot',
      defaultLanguage: 'en',
      notifications: {
        androidEnabled: true,
        androidAdminApprovalEnabled: true
      }
    }, request);

    assert.equal(result.sent, 1);
    const rows = db.listAndroidNotifications(device.id);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].type, 'admin-approval');
    assert.equal(rows[0].payload.requestId, request.id);
    assert.deepEqual(rows[0].actions.map(action => action.id), ['approve', 'reject']);
    db.markAndroidNotificationDelivered(rows[0].id, device.id);
    assert.equal(db.listAndroidNotifications(device.id).length, 0);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('android admin approval notifications can be dismissed by request id', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-android-dismiss-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  try {
    const token = generateSecret(32);
    const device = db.createAndroidDevice({
      tokenHash: keyedHash('test-secret', token),
      adminUser: 'admin',
      name: 'Pixel'
    });
    const request = db.createAdminApprovalRequest({
      fullName: 'Grace Hopper',
      identity: 'Grace Hopper',
      clientIp: '192.168.1.30',
      expiresAt: Date.now() + 60000
    });
    queueAndroidAdminApprovalRequest(db, {
      appName: 'G-Hotspot',
      defaultLanguage: 'en',
      notifications: {
        androidEnabled: true,
        androidAdminApprovalEnabled: true
      }
    }, request);

    assert.equal(db.listAndroidNotifications(device.id).length, 1);
    assert.equal(db.dismissAndroidNotificationsForAdminApprovalRequest(request.id), 1);
    assert.equal(db.listAndroidNotifications(device.id).length, 0);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('android admin approval notifications are hidden after a decision', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-android-decided-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  try {
    const token = generateSecret(32);
    const device = db.createAndroidDevice({
      tokenHash: keyedHash('test-secret', token),
      adminUser: 'admin',
      name: 'Pixel'
    });
    const request = db.createAdminApprovalRequest({
      fullName: 'Nikola Tesla',
      identity: 'Nikola Tesla',
      clientIp: '192.168.1.40',
      expiresAt: Date.now() + 60000
    });
    queueAndroidAdminApprovalRequest(db, {
      appName: 'G-Hotspot',
      defaultLanguage: 'en',
      notifications: {
        androidEnabled: true,
        androidAdminApprovalEnabled: true
      }
    }, request);

    const [notification] = db.listAndroidNotifications(device.id);
    assert.ok(notification);
    db.decideAdminApprovalRequest(request.id, {
      status: 'approved',
      adminUser: 'admin',
      message: 'Approved'
    });
    assert.equal(db.listAndroidNotifications(device.id, { since: 0 }).length, 0);
    assert.ok(db.getAndroidNotification(notification.id, device.id).deliveredAt);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('android pairing codes create pending devices that can be approved', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-android-pair-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  try {
    const code = 'ABCD1234';
    const pairing = db.createAndroidPairingCode({
      codeHash: keyedHash('test-secret', code),
      codeHint: code.slice(-4),
      createdBy: 'admin',
      expiresAt: Date.now() + 60000
    });
    const device = db.createAndroidDevice({
      tokenHash: keyedHash('test-secret', generateSecret(32)),
      adminUser: 'pending',
      name: 'Pixel',
      status: 'pending',
      pairingCodeHint: pairing.code_hint
    });

    assert.equal(db.claimAndroidPairingCode(pairing.id, device.id).claimed_device_id, device.id);
    assert.equal(db.getAndroidDevice(device.id).status, 'pending');
    const approved = db.approveAndroidDevice(device.id, { adminUser: 'admin' });
    assert.equal(approved.status, 'approved');
    assert.equal(approved.enabled, 1);
    assert.equal(approved.admin_user, 'admin');
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('android system notification queue returns disabled when channel is off', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-android-disabled-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  try {
    const result = queueAndroidSystemNotification(db, {
      appName: 'G-Hotspot',
      notifications: {
        androidEnabled: false
      }
    }, {
      title: 'G-Hotspot',
      body: 'System notification',
      event: { eventType: 'system_startup', severity: 'info', detail: {} }
    });

    assert.equal(result.skipped, true);
    assert.equal(result.reason, 'disabled');
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('android devices persist and rotate Firebase registration tokens', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-android-fcm-'));
  const db = new HotspotDatabase(path.join(directory, 'hotspot.db'));
  try {
    const device = db.createAndroidDevice({
      tokenHash: keyedHash('test-secret', generateSecret(32)),
      adminUser: 'admin',
      name: 'Pixel',
      fcmToken: 'first-firebase-registration-token'
    });
    assert.equal(device.fcm_token, 'first-firebase-registration-token');
    assert.equal(
      db.setAndroidDevicePushToken(device.id, 'second-firebase-registration-token').fcm_token,
      'second-firebase-registration-token'
    );
    db.clearAndroidDevicePushToken(device.id, 'stale-token');
    assert.equal(db.getAndroidDevice(device.id).fcm_token, 'second-firebase-registration-token');
    db.clearAndroidDevicePushToken(device.id, 'second-firebase-registration-token');
    assert.equal(db.getAndroidDevice(device.id).fcm_token, null);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('FCM payload is high priority, bounded, and contains the visible notification', () => {
  const message = androidPushMessage({ fcm_token: 'firebase-token' }, {
    id: 'notification-id',
    type: 'admin-approval',
    title: 'Approval',
    body: 'x'.repeat(5000),
    payload: { requestId: 'request-id', ignored: 'y'.repeat(5000) },
    actions: [{ id: 'approve', label: 'Approve' }, { id: 'reject', label: 'Reject' }],
    createdAt: 1000,
    expiresAt: 61_000
  }, 1000);

  assert.equal(message.message.android.priority, 'HIGH');
  assert.equal(message.message.android.ttl, '60s');
  assert.ok(Buffer.byteLength(message.message.data.notification) < 4096);
  const notification = JSON.parse(message.message.data.notification);
  assert.equal(notification.body.length, 2000);
  assert.deepEqual(notification.payload, { requestId: 'request-id' });
  assert.deepEqual(notification.actions.map(action => action.id), ['approve', 'reject']);
});
