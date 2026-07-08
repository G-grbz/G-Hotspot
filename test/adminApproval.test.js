import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { HotspotDatabase } from '../src/db.js';

test('admin approval requests can be approved and listed as verification records', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g-hotspot-admin-approval-'));
  const db = new HotspotDatabase(path.join(directory, 'test.db'));
  try {
    const request = db.createAdminApprovalRequest({
      fullName: 'Ada Lovelace',
      contact: 'ada@example.com',
      contactType: 'email',
      identity: 'Ada Lovelace <ada@example.com>',
      clientIp: '172.16.2.44',
      clientMac: '28:16:7F:27:46:71',
      redirectUrl: '',
      expiresAt: Date.now() + 3600000,
      language: 'en'
    });
    assert.equal(request.status, 'pending');
    assert.equal(db.dashboard().adminApproval.pending, 1);

    const authorization = db.saveAuthorization({
      method: 'admin-approval',
      identity: request.identity,
      clientIp: request.client_ip,
      clientMac: request.client_mac,
      gatewayMode: 'mock',
      gatewaySessionId: 'mock-session',
      status: 'active',
      expiresAt: Date.now() + 7200000,
      redirectUrl: '',
      gatewayResponse: {},
      error: ''
    });
    const decided = db.decideAdminApprovalRequest(request.id, {
      status: 'approved',
      adminUser: 'admin',
      message: 'Approved.',
      authorizationId: authorization.id
    });

    assert.equal(decided.status, 'approved');
    assert.equal(decided.authorization_id, authorization.id);
    assert.equal(db.dashboard().adminApproval.pending, 0);
    assert.equal(db.listAdminApprovalRequests({ status: 'approved' }).total, 1);

    const verifications = db.listChallenges({ kind: 'admin-approval' });
    assert.equal(verifications.total, 1);
    assert.equal(verifications.rows[0].kind, 'admin-approval');
    assert.equal(verifications.rows[0].status, 'approved');
    assert.equal(verifications.rows[0].access_expires_at, authorization.expires_at);
  } finally {
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
