import test from 'node:test';
import assert from 'node:assert/strict';
import { authorizationLeaseSeconds } from '../src/admin.js';

test('admin Kea lease helper uses the supplied runtime config', () => {
  const createdAt = Date.UTC(2026, 6, 7, 12, 0, 0);
  const expiresAt = createdAt + 3 * 60 * 60 * 1000;
  assert.equal(
    authorizationLeaseSeconds({
      smtp: {
        accessDuration: { value: 1, unit: 'days' }
      }
    }, {
      method: 'email',
      created_at: createdAt,
      expires_at: expiresAt,
      lease_seconds: null
    }),
    86400
  );
});

test('admin Kea lease helper prefers stored lease seconds', () => {
  assert.equal(
    authorizationLeaseSeconds({}, {
      method: 'voucher',
      created_at: Date.now(),
      expires_at: Date.now() + 1000,
      lease_seconds: 3600
    }),
    3600
  );
});
