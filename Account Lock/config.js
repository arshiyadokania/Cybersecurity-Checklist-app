'use strict';

/**
 * Central configuration for the brute-force protection service.
 *
 * Every tunable lives here so there are NO magic numbers scattered through the
 * codebase. The lockout state machine, progressive delays, per-IP rate limits
 * and password policy are all driven by these constants.
 */

const MINUTE_MS = 60 * 1000;

const config = Object.freeze({
  // --- Account lockout policy ------------------------------------------------
  // Lock the account on the MAX_FAILED_ATTEMPTS-th consecutive failure.
  MAX_FAILED_ATTEMPTS: 3,

  // How long an account stays locked once the threshold is reached.
  LOCKOUT_DURATION_MS: 15 * MINUTE_MS,

  // Consecutive-failure counters older than this window expire, so a burst of
  // failures long ago cannot combine with a fresh failure to trigger a lockout.
  ATTEMPT_WINDOW_MS: 15 * MINUTE_MS,

  // Delay applied BEFORE responding to failure #1, #2 and #3 respectively.
  // Index i corresponds to the (i+1)-th consecutive failure.
  PROGRESSIVE_DELAYS_MS: Object.freeze([0, 1000, 2000]),

  // --- Per-IP rate limiting --------------------------------------------------
  // At most IP_RATE_LIMIT_POINTS login requests per IP per window, regardless
  // of which username(s) are targeted.
  IP_RATE_LIMIT_POINTS: 10,
  IP_RATE_LIMIT_DURATION_S: 60,

  // --- Password / crypto policy ---------------------------------------------
  BCRYPT_COST: 12,
  MIN_PASSWORD_LENGTH: 12,

  // Byte lengths for random material.
  TOKEN_BYTES: 24, // opaque demo session token
  DUMMY_SECRET_BYTES: 32, // seed for the anti-enumeration dummy bcrypt hash

  // --- Generic responses (anti-enumeration) ---------------------------------
  // The single failure body every unsuccessful login must return, byte-for-byte.
  GENERIC_FAILURE_BODY: Object.freeze({ error: 'Invalid credentials' }),
  GENERIC_FAILURE_STATUS: 401,

  // Redis key namespace.
  REDIS_KEY_PREFIX: 'bf',
});

module.exports = config;