'use strict';

/**
 * Shared contract test suite for AttemptStore implementations.
 *
 * The exact same suite runs against MemoryAttemptStore always, and against
 * RedisAttemptStore when REDIS_URL is set (skipped cleanly otherwise). Both
 * implementations must exhibit identical observable behaviour.
 */

const { MemoryAttemptStore, RedisAttemptStore } = require('../attemptStore');

const DUR = Object.freeze({
  maxFailedAttempts: 3,
  lockoutDurationMs: 1000,
  windowMs: 1000,
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function makeVirtualClock(start = 1_700_000_000_000) {
  const state = { t: start };
  return { state, now: () => state.t };
}

// --- Store factories --------------------------------------------------------
const memoryFactory = (opts) => new MemoryAttemptStore(opts);

let redisAvailable = false;
let Redis = null;
let redisClient = null;
let prefixCounter = 0;

if (process.env.REDIS_URL) {
  try {
    // eslint-disable-next-line global-require
    Redis = require('ioredis');
    redisClient = new Redis(process.env.REDIS_URL);
    redisAvailable = true;
  } catch (err) {
    redisAvailable = false;
  }
}

function redisFactory(opts) {
  // Unique key prefix per store so tests are isolated on a shared client.
  const keyPrefix = `bftest:${Date.now()}:${prefixCounter++}`;
  return new RedisAttemptStore(redisClient, { ...opts, keyPrefix });
}

afterAll(async () => {
  if (redisClient) {
    try {
      const keys = await redisClient.keys('bftest:*');
      if (keys.length) await redisClient.del(...keys);
    } catch (err) {
      /* best-effort cleanup */
    }
    await redisClient.quit();
  }
});

// --- The contract -----------------------------------------------------------
function runContract(label, factory) {
  describe(`AttemptStore contract: ${label}`, () => {
    test('increments and locks at the threshold, capping the count', async () => {
      const { now } = makeVirtualClock();
      const store = factory({ ...DUR, now });
      const key = 'acct-increment';

      const r1 = await store.recordFailure(key);
      expect(r1.count).toBe(1);
      expect(r1.becameLocked).toBe(false);

      const r2 = await store.recordFailure(key);
      expect(r2.count).toBe(2);
      expect(r2.becameLocked).toBe(false);

      const r3 = await store.recordFailure(key);
      expect(r3.count).toBe(3);
      expect(r3.becameLocked).toBe(true);

      const status = await store.getStatus(key);
      expect(status.locked).toBe(true);
      expect(status.count).toBe(3);
    });

    test('does not increment the counter while locked', async () => {
      const { now } = makeVirtualClock();
      const store = factory({ ...DUR, now });
      const key = 'acct-locked-noinc';

      await store.recordFailure(key);
      await store.recordFailure(key);
      await store.recordFailure(key); // now locked at count 3

      const r4 = await store.recordFailure(key);
      expect(r4.count).toBe(3); // unchanged
      expect(r4.becameLocked).toBe(false);
    });

    test('reset clears the counter and any lock', async () => {
      const { now } = makeVirtualClock();
      const store = factory({ ...DUR, now });
      const key = 'acct-reset';

      await store.recordFailure(key);
      await store.recordFailure(key);
      await store.reset(key);

      const status = await store.getStatus(key);
      expect(status.count).toBe(0);
      expect(status.locked).toBe(false);

      const fresh = await store.recordFailure(key);
      expect(fresh.count).toBe(1);
    });

    test('lockout expires once the clock passes lockedUntil', async () => {
      const clock = makeVirtualClock();
      const store = factory({ ...DUR, now: clock.now });
      const key = 'acct-expiry';

      await store.recordFailure(key);
      await store.recordFailure(key);
      await store.recordFailure(key);
      expect((await store.getStatus(key)).locked).toBe(true);

      clock.state.t += DUR.lockoutDurationMs + 1;
      expect((await store.getStatus(key)).locked).toBe(false);
    });

    test('concurrent failures lock exactly once and never over-count', async () => {
      const { now } = makeVirtualClock();
      const store = factory({ ...DUR, now });
      const key = 'acct-concurrent';

      const results = await Promise.all(
        Array.from({ length: 5 }, () => store.recordFailure(key))
      );

      const maxCount = Math.max(...results.map((r) => r.count));
      expect(maxCount).toBe(DUR.maxFailedAttempts); // never exceeds threshold

      const lockTransitions = results.filter((r) => r.becameLocked).length;
      expect(lockTransitions).toBe(1); // atomic: locked exactly once

      const status = await store.getStatus(key);
      expect(status.count).toBe(DUR.maxFailedAttempts);
      expect(status.locked).toBe(true);
    });

    test('failures older than the window expire', async () => {
      // Small real window + real sleep so this holds for TTL-backed stores too.
      const store = factory({
        maxFailedAttempts: 3,
        lockoutDurationMs: 500,
        windowMs: 120,
        now: Date.now,
      });
      const key = 'acct-window';

      await store.recordFailure(key); // 1
      await store.recordFailure(key); // 2
      await sleep(220); // exceed the window

      const fresh = await store.recordFailure(key); // fresh count
      expect(fresh.count).toBe(1);
      expect(fresh.becameLocked).toBe(false);
    });
  });
}

runContract('MemoryAttemptStore', memoryFactory);

if (redisAvailable) {
  runContract('RedisAttemptStore', redisFactory);
} else {
  describe('AttemptStore contract: RedisAttemptStore', () => {
    // eslint-disable-next-line jest/no-disabled-tests
    test.skip('skipped — REDIS_URL not set', () => {});
  });
}