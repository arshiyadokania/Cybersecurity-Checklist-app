'use strict';

/**
 * AttemptStore: storage abstraction for the per-account failure/lockout state
 * machine.
 *
 * Two concrete implementations satisfy the same contract:
 *   - MemoryAttemptStore: single-process, synchronous mutation. Used by the
 *     demo server and the test suite.
 *   - RedisAttemptStore:  distributed, backed by ioredis. The increment-and-
 *     check is performed inside a single atomic Lua script.
 *
 * The state machine, per account key:
 *   1. recordFailure(): atomically increment the counter and refresh the
 *      window TTL. If the counter reaches maxFailedAttempts, set
 *      lockedUntil = now + lockoutDurationMs. Never increment while locked.
 *   2. reset(): clear the counter (called on a successful, non-locked login).
 *   3. getStatus(): report the effective count and whether the account is
 *      currently locked, applying window + lockout expiry relative to now().
 *
 * A `now()` function is injected so tests can advance a virtual clock instead
 * of sleeping for real minutes.
 */

const config = require('./config');

class AttemptStore {
  /**
   * @param {object} [options]
   * @param {() => number} [options.now] injected clock returning epoch ms
   * @param {number} [options.maxFailedAttempts]
   * @param {number} [options.lockoutDurationMs]
   * @param {number} [options.windowMs]
   */
  constructor(options = {}) {
    this.now = options.now || Date.now;
    this.maxFailedAttempts =
      options.maxFailedAttempts != null
        ? options.maxFailedAttempts
        : config.MAX_FAILED_ATTEMPTS;
    this.lockoutDurationMs =
      options.lockoutDurationMs != null
        ? options.lockoutDurationMs
        : config.LOCKOUT_DURATION_MS;
    this.windowMs =
      options.windowMs != null ? options.windowMs : config.ATTEMPT_WINDOW_MS;
  }

  /* eslint-disable no-unused-vars */
  // Record one failed attempt atomically. Resolves to:
  //   { count, lockedUntil, becameLocked }
  async recordFailure(key) {
    throw new Error('not implemented');
  }

  // Report current state:
  //   { count, lockedUntil, locked }
  async getStatus(key) {
    throw new Error('not implemented');
  }

  // Reset the failure counter (and any lock) for a key.
  async reset(key) {
    throw new Error('not implemented');
  }

  // Release any resources (Redis connection, etc.).
  async close() {}
  /* eslint-enable no-unused-vars */
}

/**
 * In-memory implementation. All mutation happens synchronously inside a single
 * tick of the Node.js event loop, which makes recordFailure atomic with respect
 * to other concurrent callers: there is no await between read and write, so two
 * "simultaneous" failed attempts can never both observe the same count and both
 * skip the lockout.
 */
class MemoryAttemptStore extends AttemptStore {
  constructor(options = {}) {
    super(options);
    /** @type {Map<string, {count:number, windowExpiry:number, lockedUntil:number}>} */
    this._entries = new Map();
  }

  _get(key) {
    return (
      this._entries.get(key) || { count: 0, windowExpiry: 0, lockedUntil: 0 }
    );
  }

  async recordFailure(key) {
    const now = this.now();
    const entry = this._get(key);

    // Never increment while the account is locked.
    if (entry.lockedUntil > now) {
      return {
        count: entry.count,
        lockedUntil: entry.lockedUntil,
        becameLocked: false,
      };
    }

    // Expire a stale counter: failures older than the window no longer count.
    if (entry.windowExpiry !== 0 && now >= entry.windowExpiry) {
      entry.count = 0;
    }

    entry.count += 1;
    entry.windowExpiry = now + this.windowMs;

    let becameLocked = false;
    if (entry.count >= this.maxFailedAttempts) {
      entry.lockedUntil = now + this.lockoutDurationMs;
      becameLocked = true;
    }

    this._entries.set(key, entry);
    return {
      count: entry.count,
      lockedUntil: entry.lockedUntil,
      becameLocked,
    };
  }

  async getStatus(key) {
    const now = this.now();
    const entry = this._entries.get(key);
    if (!entry) {
      return { count: 0, lockedUntil: 0, locked: false };
    }

    let count = entry.count;
    if (entry.windowExpiry !== 0 && now >= entry.windowExpiry) {
      count = 0;
    }

    return {
      count,
      lockedUntil: entry.lockedUntil,
      locked: entry.lockedUntil > now,
    };
  }

  async reset(key) {
    this._entries.delete(key);
  }
}

/**
 * Redis-backed implementation using ioredis.
 *
 * The increment-and-check is a single Lua script so that concurrent failed
 * attempts across many processes are still atomic — Redis executes the script
 * without interleaving. The counter key carries a PEXPIRE window TTL; when it
 * lapses Redis deletes it and the next INCR naturally restarts at 1, giving us
 * the "failures older than the window expire" behaviour for free.
 *
 * The ioredis client is injected rather than imported here, so this module can
 * be required even in environments where ioredis is not installed. server.js
 * performs the guarded require and only constructs this class when REDIS_URL is
 * configured.
 */
const RECORD_FAILURE_LUA = `
local countKey = KEYS[1]
local lockKey  = KEYS[2]
local now               = tonumber(ARGV[1])
local maxFailedAttempts = tonumber(ARGV[2])
local lockoutDurationMs = tonumber(ARGV[3])
local windowMs          = tonumber(ARGV[4])

local lockedUntil = tonumber(redis.call('GET', lockKey) or '0')
if lockedUntil > now then
  local existing = tonumber(redis.call('GET', countKey) or '0')
  return { existing, lockedUntil, 0 }
end

local count = redis.call('INCR', countKey)
redis.call('PEXPIRE', countKey, windowMs)

local becameLocked = 0
local newLockedUntil = 0
if count >= maxFailedAttempts then
  newLockedUntil = now + lockoutDurationMs
  redis.call('SET', lockKey, tostring(newLockedUntil), 'PX', lockoutDurationMs)
  becameLocked = 1
end

return { count, newLockedUntil, becameLocked }
`;

class RedisAttemptStore extends AttemptStore {
  /**
   * @param {import('ioredis').Redis} redisClient a connected ioredis client
   * @param {object} [options] same options as AttemptStore, plus keyPrefix
   */
  constructor(redisClient, options = {}) {
    super(options);
    if (!redisClient) {
      throw new Error('RedisAttemptStore requires an ioredis client');
    }
    this.redis = redisClient;
    this.keyPrefix = options.keyPrefix || config.REDIS_KEY_PREFIX;

    this.redis.defineCommand('bfRecordFailure', {
      numberOfKeys: 2,
      lua: RECORD_FAILURE_LUA,
    });
  }

  _countKey(key) {
    return `${this.keyPrefix}:count:${key}`;
  }

  _lockKey(key) {
    return `${this.keyPrefix}:lock:${key}`;
  }

  async recordFailure(key) {
    const now = this.now();
    const result = await this.redis.bfRecordFailure(
      this._countKey(key),
      this._lockKey(key),
      now,
      this.maxFailedAttempts,
      this.lockoutDurationMs,
      this.windowMs
    );
    // Lua returns integers as a flat array [count, lockedUntil, becameLocked].
    return {
      count: Number(result[0]),
      lockedUntil: Number(result[1]),
      becameLocked: Number(result[2]) === 1,
    };
  }

  async getStatus(key) {
    const now = this.now();
    const [lockRaw, countRaw] = await this.redis
      .pipeline()
      .get(this._lockKey(key))
      .get(this._countKey(key))
      .exec()
      .then((res) => [res[0][1], res[1][1]]);

    const lockedUntil = Number(lockRaw || 0);
    const count = Number(countRaw || 0);
    return {
      count,
      lockedUntil,
      locked: lockedUntil > now,
    };
  }

  async reset(key) {
    await this.redis.del(this._countKey(key), this._lockKey(key));
  }

  async close() {
    if (this.redis && typeof this.redis.quit === 'function') {
      await this.redis.quit();
    }
  }
}

module.exports = {
  AttemptStore,
  MemoryAttemptStore,
  RedisAttemptStore,
};