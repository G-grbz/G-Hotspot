import { HttpError } from '../lib/http.js';

export function createDeliveryGuard({
  maxInFlight = 2,
  failureThreshold = 3,
  circuitMs = 60 * 1000,
  now = () => Date.now()
} = {}) {
  const states = new Map();

  function stateFor(method) {
    if (!states.has(method)) {
      states.set(method, {
        inFlight: 0,
        failures: 0,
        openUntil: 0
      });
    }
    return states.get(method);
  }

  async function run(method, callback) {
    const state = stateFor(method);
    const currentTime = now();
    if (state.openUntil > currentTime) {
      throw new HttpError(
        503,
        'Verification delivery is temporarily unavailable. Please try again shortly.',
        'delivery_provider_unavailable',
        { retryAt: state.openUntil }
      );
    }
    if (state.inFlight >= maxInFlight) {
      throw new HttpError(
        429,
        'Verification delivery is busy. Please try again shortly.',
        'delivery_busy'
      );
    }
    state.inFlight += 1;
    try {
      const result = await callback();
      state.failures = 0;
      state.openUntil = 0;
      return result;
    } catch (error) {
      state.failures += 1;
      if (state.failures >= failureThreshold) {
        state.openUntil = now() + circuitMs;
      }
      throw error;
    } finally {
      state.inFlight = Math.max(0, state.inFlight - 1);
    }
  }

  function snapshot(method) {
    return { ...stateFor(method) };
  }

  return { run, snapshot };
}
