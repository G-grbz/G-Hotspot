import test from 'node:test';
import assert from 'node:assert/strict';
import { createDeliveryGuard } from '../src/services/deliveryGuard.js';

test('delivery guard limits concurrent provider sends per method', async () => {
  const guard = createDeliveryGuard({ maxInFlight: 1 });
  let releaseFirst;
  const first = guard.run('sms', () => new Promise(resolve => { releaseFirst = resolve; }));

  await assert.rejects(
    () => guard.run('sms', () => Promise.resolve('second')),
    error => {
      assert.equal(error.statusCode, 429);
      assert.equal(error.code, 'delivery_busy');
      return true;
    }
  );

  releaseFirst('first');
  assert.equal(await first, 'first');
  assert.equal(await guard.run('sms', () => Promise.resolve('after-release')), 'after-release');
});

test('delivery guard opens a temporary circuit after repeated provider failures', async () => {
  let currentTime = 1000;
  const guard = createDeliveryGuard({
    failureThreshold: 3,
    circuitMs: 60000,
    now: () => currentTime
  });
  const fail = () => guard.run('email', () => Promise.reject(new Error('provider down')));

  await assert.rejects(fail, /provider down/u);
  await assert.rejects(fail, /provider down/u);
  await assert.rejects(fail, /provider down/u);

  await assert.rejects(
    () => guard.run('email', () => Promise.resolve('not called')),
    error => {
      assert.equal(error.statusCode, 503);
      assert.equal(error.code, 'delivery_provider_unavailable');
      assert.equal(error.details.retryAt, 61000);
      return true;
    }
  );

  currentTime = 62000;
  assert.equal(await guard.run('email', () => Promise.resolve('recovered')), 'recovered');
  assert.equal(guard.snapshot('email').failures, 0);
});
