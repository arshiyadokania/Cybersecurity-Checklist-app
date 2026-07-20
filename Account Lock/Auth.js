'use strict';

/**
 * Core authentication + lockout logic.
 *
 * This module is deliberately free of any Express/HTTP concerns so it can be
 * unit-tested in isolation. Every side-effecting dependency (the store, the
 * user directory, bcrypt, the progressive-delay function, the logger and the
 * clock) is injected, which is what makes the lockout logic pure and testable.
 */

const crypto = require('crypto');
const bcryptLib = require('bcrypt');
const config = require('./config');

// Result "kinds" the HTTP layer maps onto responses. The important property is
// that FAILURE is returned identically for every unsuccessful path, so the HTTP
// layer cannot accidentally leak which path was taken.
const RESULT = Object.freeze({
  SUCCESS: 'SUCCESS',
  FAILURE: 'FAILURE',
  BAD_REQUEST: 'BAD_REQUEST',
});

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// Normalise a username into its account key: trimmed + lowercased.
function normalizeUsername(username) {
  return String(username).trim().toLowerCase();
}

function defaultDelay(ms) {
  if (!ms) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function defaultLogger(entry) {
  // A single structured JSON line per event. Never contains passwords,
  // password lengths, or raw usernames.
  process.stdout.write(JSON.stringify(entry) + '\n');
}

class Authenticator {
  /**
   * @param {object} deps
   * @param {import('./attemptStore').AttemptStore} deps.store
   * @param {Map<string, {hash:string}>} deps.users
   * @param {object} [deps.bcrypt] override bcrypt (tests)
   * @param {(ms:number)=>Promise<void>} [deps.delay] progressive-delay fn
   * @param {(entry:object)=>void} [deps.logger]
   * @param {()=>number} [deps.now]
   * @param {string} [deps.dummyHash] precomputed bcrypt hash for unknown users
   */
  constructor(deps = {}) {
    if (!deps.store) throw new Error('Authenticator requires a store');
    if (!deps.users) throw new Error('Authenticator requires a users map');

    this.store = deps.store;
    this.users = deps.users;
    this.bcrypt = deps.bcrypt || bcryptLib;
    this.delay = deps.delay || defaultDelay;
    this.logger = deps.logger || defaultLogger;
    this.now = deps.now || Date.now;

    // Precompute a dummy bcrypt hash so that bcrypt.compare runs for unknown
    // usernames too, keeping response timing comparable and preventing username
    // enumeration via timing. Generated once at construction.
    this.dummyHash =
      deps.dummyHash ||
      this.bcrypt.hashSync(
        crypto.randomBytes(config.DUMMY_SECRET_BYTES).toString('hex'),
        config.BCRYPT_COST
      );
  }

  /**
   * Register a demo user. Throws { code: 'BAD_REQUEST' } style errors on
   * invalid input. Passwords are only ever stored as bcrypt hashes.
   */
  async register(username, password) {
    if (
      typeof username !== 'string' ||
      typeof password !== 'string' ||
      username.trim() === ''
    ) {
      const err = new Error('username and password are required');
      err.code = RESULT.BAD_REQUEST;
      throw err;
    }
    if (password.length < config.MIN_PASSWORD_LENGTH) {
      const err = new Error(
        `password must be at least ${config.MIN_PASSWORD_LENGTH} characters`
      );
      err.code = RESULT.BAD_REQUEST;
      throw err;
    }

    const key = normalizeUsername(username);
    const hash = await this.bcrypt.hash(password, config.BCRYPT_COST);
    this.users.set(key, { hash });
    return { key };
  }

  /**
   * Attempt a login.
   *
   * Returns one of:
   *   { kind: RESULT.SUCCESS }
   *   { kind: RESULT.FAILURE }
   *   { kind: RESULT.BAD_REQUEST }
   *
   * The four sensitive cases — unknown username, wrong password, locked
   * account, and locked account with the correct password — all return
   * RESULT.FAILURE and are indistinguishable to the caller.
   */
  async login({ username, password, ip }) {
    if (typeof username !== 'string' || typeof password !== 'string') {
      return { kind: RESULT.BAD_REQUEST };
    }

    const key = normalizeUsername(username);
    if (key === '') {
      return { kind: RESULT.BAD_REQUEST };
    }

    const user = this.users.get(key);
    const usernameHash = sha256(key);

    const status = await this.store.getStatus(key);

    // --- Locked account -------------------------------------------------------
    // Reject ALL logins (including the correct password) with the generic
    // failure. Still run a bcrypt.compare so timing matches the normal path, and
    // do NOT increment the counter.
    if (status.locked) {
      await this.bcrypt.compare(password, user ? user.hash : this.dummyHash);
      this._log({
        event: 'login_blocked_locked',
        usernameHash,
        ip,
        count: status.count,
      });
      return { kind: RESULT.FAILURE };
    }

    // --- Normal path ----------------------------------------------------------
    // Always run bcrypt.compare (against a dummy hash for unknown users) so the
    // response timing does not reveal whether the username exists.
    const hashToCompare = user ? user.hash : this.dummyHash;
    const compareResult = await this.bcrypt.compare(password, hashToCompare);
    const passwordMatches = Boolean(user) && compareResult;

    if (passwordMatches) {
      // Successful login on an unlocked account resets the counter.
      await this.store.reset(key);
      return { kind: RESULT.SUCCESS };
    }

    // --- Failed attempt -------------------------------------------------------
    const outcome = await this.store.recordFailure(key);

    // Progressive delay applied BEFORE responding to this failure. Failure #n
    // (1-indexed) uses PROGRESSIVE_DELAYS_MS[n-1], clamped to the last entry.
    const idx = Math.min(
      Math.max(outcome.count - 1, 0),
      config.PROGRESSIVE_DELAYS_MS.length - 1
    );
    const delayMs = config.PROGRESSIVE_DELAYS_MS[idx];
    await this.delay(delayMs);

    this._log({
      event: 'login_failed',
      usernameHash,
      ip,
      count: outcome.count,
    });

    if (outcome.becameLocked) {
      this._log({
        event: 'account_locked',
        usernameHash,
        ip,
        count: outcome.count,
      });
    }

    return { kind: RESULT.FAILURE };
  }

  _log(fields) {
    this.logger({ timestamp: new Date(this.now()).toISOString(), ...fields });
  }
}

module.exports = {
  Authenticator,
  RESULT,
  normalizeUsername,
  sha256,
  defaultDelay,
};