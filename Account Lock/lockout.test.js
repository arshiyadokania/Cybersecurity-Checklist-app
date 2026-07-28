'use strict';

const request = require('supertest');
const bcrypt = require('bcrypt');

const { createApp } = require('../server');
const { MemoryAttemptStore } = require('../attemptStore');
const config = require('../config');

const USERNAME = 'Alice'; // stored/normalised as 'alice'
const KEY = 'alice';
const PASSWORD = 'correct-horse-battery-staple'; // >= MIN_PASSWORD_LENGTH
const WRONG = 'totally-wrong-password';

// Precompute bcrypt hashes once — bcrypt at cost 12 is deliberately slow, so we
// avoid re-hashing in every test.
let knownHash;
let dummyHash;

beforeAll(async () => {
  knownHash = await bcrypt.hash(PASSWORD, config.BCRYPT_COST);
  dummyHash = await bcrypt.hash('a-dummy-value-for-unknown-users', config.BCRYPT_COST);
});

/**
 * Build a fully isolated app instance: fresh store (with an injectable virtual
 * clock), fresh user directory, fresh per-IP limiter, a delay spy that resolves
 * instantly, and a captured log buffer.
 */
function buildApp(overrides = {}) {
  const state = { t: 1_700_000_000_000 };
  const now = overrides.now || (() => state.t);
  const store = overrides.store || new MemoryAttemptStore({ now });
  const users =
    overrides.users || new Map([[KEY, { hash: knownHash }]]);
  const delaySpy = overrides.delay || jest.fn(() => Promise.resolve());
  const logs = [];
  const logger = (entry) => logs.push(entry);

  const app = createApp({
    store,
    users,
    now,
    delay: delaySpy,
    dummyHash,
    logger,
    rateLimiter: overrides.rateLimiter,
  });

  return { app, store, users, state, delaySpy, logs };
}

const login = (app, username, password) =>
  request(app).post('/login').send({ username, password });

async function failOnce(app, username = USERNAME) {
  return login(app, username, WRONG);
}

describe('brute-force account lockout', () => {
  // 1. Correct credentials -> 200.
  test('correct credentials return 200 with a token', async () => {
    const { app } = buildApp();
    const res = await login(app, USERNAME, PASSWORD);
    expect(res.status).toBe(200);
    expect(typeof res.body.token).toBe('string');
    expect(res.body.token.length).toBeGreaterThan(0);
  });

  // 2. 2 failures then correct password -> 200, and the counter is reset.
  test('successful login after 2 failures resets the counter', async () => {
    const { app } = buildApp();

    expect((await failOnce(app)).status).toBe(401);
    expect((await failOnce(app)).status).toBe(401);

    // Correct password succeeds (count was 2, below the threshold).
    expect((await login(app, USERNAME, PASSWORD)).status).toBe(200);

    // Counter was reset: a single fresh failure must NOT lock the account.
    expect((await failOnce(app)).status).toBe(401);
    // Proof it is not locked: the correct password still works.
    expect((await login(app, USERNAME, PASSWORD)).status).toBe(200);
  });

  // 3. 3 consecutive failures -> account locked.
  test('3 consecutive failures lock the account', async () => {
    const { app, store } = buildApp();
    await failOnce(app);
    await failOnce(app);
    await failOnce(app);

    const status = await store.getStatus(KEY);
    expect(status.locked).toBe(true);
    expect(status.count).toBe(config.MAX_FAILED_ATTEMPTS);
  });

  // 4. Locked account + CORRECT password -> 401 generic body.
  test('locked account rejects the correct password with 401', async () => {
    const { app } = buildApp();
    await failOnce(app);
    await failOnce(app);
    await failOnce(app);

    const res = await login(app, USERNAME, PASSWORD);
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Invalid credentials' });
  });

  // 5. Locked account body is byte-identical to the wrong-password body
  //    (and to the unknown-user body): all four sensitive cases indistinguishable.
  test('all four failure cases return byte-identical responses', async () => {
    // wrong password (known user, not locked)
    const a = buildApp();
    const wrongPw = await login(a.app, USERNAME, WRONG);

    // unknown username
    const b = buildApp();
    const unknown = await login(b.app, 'nobody-here', WRONG);

    // locked account + wrong password
    const c = buildApp();
    await failOnce(c.app);
    await failOnce(c.app);
    await failOnce(c.app);
    const lockedWrong = await login(c.app, USERNAME, WRONG);

    // locked account + CORRECT password
    const d = buildApp();
    await failOnce(d.app);
    await failOnce(d.app);
    await failOnce(d.app);
    const lockedCorrect = await login(d.app, USERNAME, PASSWORD);

    for (const res of [wrongPw, unknown, lockedWrong, lockedCorrect]) {
      expect(res.status).toBe(401);
      expect(res.headers['retry-after']).toBeUndefined();
    }

    // Byte-for-byte identical bodies.
    expect(unknown.text).toBe(wrongPw.text);
    expect(lockedWrong.text).toBe(wrongPw.text);
    expect(lockedCorrect.text).toBe(wrongPw.text);
    expect(wrongPw.text).toBe('{"error":"Invalid credentials"}');
  });

  // 6. Unknown username -> 401 with identical body.
  test('unknown username returns the generic 401 body', async () => {
    const { app } = buildApp();
    const res = await login(app, 'does-not-exist', WRONG);
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Invalid credentials' });
  });

  // 7. Lockout expiry via injected clock (no real 15-minute sleeps).
  test('lockout expires after LOCKOUT_DURATION_MS and login succeeds', async () => {
    const { app, state } = buildApp();
    await failOnce(app);
    await failOnce(app);
    await failOnce(app);

    // Still locked: correct password rejected.
    expect((await login(app, USERNAME, PASSWORD)).status).toBe(401);

    // Advance the virtual clock past the lockout window.
    state.t += config.LOCKOUT_DURATION_MS + 1;

    // Now the account is unlocked and the correct password works.
    expect((await login(app, USERNAME, PASSWORD)).status).toBe(200);
  });

  // 8. Failures outside ATTEMPT_WINDOW_MS expire: 2 old + 1 new != lockout.
  test('failures older than the attempt window expire', async () => {
    const { app, state } = buildApp();

    await failOnce(app); // count 1
    await failOnce(app); // count 2

    // Advance beyond the attempt window so the two old failures expire.
    state.t += config.ATTEMPT_WINDOW_MS + 1;

    await failOnce(app); // fresh count 1 — must NOT lock

    // Proof: correct password still works (not locked).
    expect((await login(app, USERNAME, PASSWORD)).status).toBe(200);
  });

  // 9. Concurrency: 5 simultaneous failed attempts -> consistent state,
  //    account locked exactly once, counter never exceeds the threshold.
  test('concurrent failed attempts lock the account exactly once', async () => {
    const { app, store, logs } = buildApp();

    const results = await Promise.all(
      Array.from({ length: 5 }, () => login(app, USERNAME, WRONG))
    );

    // Every concurrent request gets the generic 401.
    results.forEach((r) => expect(r.status).toBe(401));

    const status = await store.getStatus(KEY);
    expect(status.locked).toBe(true);
    // No lost updates and no over-counting: exactly the threshold, not 5.
    expect(status.count).toBe(config.MAX_FAILED_ATTEMPTS);

    // The lockout transition fired exactly once.
    const lockEvents = logs.filter((e) => e.event === 'account_locked');
    expect(lockEvents).toHaveLength(1);
  });

  // 10. Progressive delay: failure #2 measurably slower than failure #1,
  //     asserted via the injected delay function (not wall time).
  test('progressive delay grows with the failure count', async () => {
    const { app, delaySpy } = buildApp();

    await failOnce(app); // failure #1
    await failOnce(app); // failure #2

    expect(delaySpy).toHaveBeenNthCalledWith(1, config.PROGRESSIVE_DELAYS_MS[0]);
    expect(delaySpy).toHaveBeenNthCalledWith(2, config.PROGRESSIVE_DELAYS_MS[1]);

    // Failure #2's delay is strictly larger than failure #1's.
    const delayForFirst = delaySpy.mock.calls[0][0];
    const delayForSecond = delaySpy.mock.calls[1][0];
    expect(delayForSecond).toBeGreaterThan(delayForFirst);
  });

  // 11. Per-IP limiter: 11th request in 60s from one IP -> 429, across usernames.
  test('per-IP rate limit triggers 429 on the 11th request', async () => {
    const { app } = buildApp(); // default real in-memory limiter

    // 10 requests, each a different username, all from the same IP.
    for (let i = 0; i < config.IP_RATE_LIMIT_POINTS; i += 1) {
      const res = await login(app, `user-${i}`, WRONG);
      expect(res.status).not.toBe(429);
    }

    // The next request from the same IP is rate limited regardless of username.
    const limited = await login(app, 'yet-another-user', WRONG);
    expect(limited.status).toBe(429);
  });

  // Bonus: /register enforces the minimum password length.
  test('register rejects passwords shorter than the minimum length', async () => {
    const { app } = buildApp();
    const short = await request(app)
      .post('/register')
      .send({ username: 'bob', password: 'short' });
    expect(short.status).toBe(400);

    const ok = await request(app)
      .post('/register')
      .send({ username: 'bob', password: 'a-sufficiently-long-password' });
    expect(ok.status).toBe(201);
  });

  // Bonus: malformed JSON and missing fields -> 400 (not 401).
  test('malformed JSON and missing fields return 400', async () => {
    const { app } = buildApp();

    const malformed = await request(app)
      .post('/login')
      .set('Content-Type', 'application/json')
      .send('{"username": "alice", ');
    expect(malformed.status).toBe(400);

    const missing = await request(app).post('/login').send({ username: 'alice' });
    expect(missing.status).toBe(400);
  });
});