# Brute-Force Login Protection

A runnable Node.js/Express authentication service with account lockout,
progressive delays, per-IP rate limiting, and anti-enumeration guarantees,
built for a financial-services login flow.

## What it does

- **Account lockout** — locks an account for 15 minutes after 3 consecutive
  failed attempts within a 15-minute window.
- **Progressive delays** — waits `0 / 1000 / 2000 ms` before responding to the
  1st / 2nd / 3rd consecutive failure, slowing automated guessing.
- **Per-IP rate limiting** — at most 10 login requests per IP per 60 seconds,
  regardless of the targeted username (returns `429`).
- **Anti-enumeration** — unknown username, wrong password, locked account, and
  locked account with the correct password all return an identical
  `401 {"error":"Invalid credentials"}` with no timing or header side-channels.
- **Atomic state machine** — the increment-and-lock check is atomic
  (synchronous mutation in memory; a single Lua script in Redis), so concurrent
  failures can never lose an update or skip the lockout.

## Architecture

| File | Responsibility |
| --- | --- |
| `config.js` | All tunable constants — no magic numbers live anywhere else. |
| `attemptStore.js` | `AttemptStore` interface + `MemoryAttemptStore` and `RedisAttemptStore` (ioredis, Lua). |
| `auth.js` | Pure, unit-testable lockout logic with injected clock/bcrypt/delay/logger. |
| `server.js` | Express wiring: `createApp()` factory, endpoints, per-IP limiter. |
| `__tests__/lockout.test.js` | End-to-end lockout, anti-enumeration, concurrency, delay, and rate-limit tests. |
| `__tests__/store.contract.test.js` | Contract suite run against both store implementations. |

A `now()` function is injected into the store and authenticator so lockout and
window expiry are tested with a virtual clock — no real 15-minute sleeps.

## Endpoints

- `POST /register` `{username, password}` → `201` (demo helper). Password must be
  at least 12 characters. Passwords are stored only as bcrypt hashes (cost 12).
- `POST /login` `{username, password}` →
  - `200 {"token":"<opaque token>"}` on success
  - `401 {"error":"Invalid credentials"}` on any failure (generic, indistinguishable)
  - `400` for malformed JSON or missing fields
  - `429` from the per-IP rate limiter

## Run instructions

Requires Node.js 20+.

```bash
cd brute-force-auth
npm install

# Run the full test suite (this is the acceptance gate).
npm test

# Start the demo server (in-memory store, no Redis required).
npm start
# → listens on :3000 (override with PORT)
```

### Try it

```bash
# Register a demo user
curl -sX POST localhost:3000/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct-horse-battery-staple"}'

# Successful login
curl -sX POST localhost:3000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct-horse-battery-staple"}'

# Three wrong attempts lock the account; even the correct password then 401s.
```

### Redis backend (optional)

Set `REDIS_URL` to use the distributed, multi-instance-safe store and rate
limiter:

```bash
REDIS_URL=redis://localhost:6379 npm start
```

When `REDIS_URL` is set, the `store.contract.test.js` suite additionally runs
the full contract against `RedisAttemptStore`; without it, those cases are
skipped cleanly and the in-memory contract still runs.

## Logging

Every failed attempt and every lockout emits a single structured JSON line:

```json
{"timestamp":"...","event":"login_failed","usernameHash":"<sha256>","ip":"...","count":2}
```

Passwords, password lengths, and raw usernames are never logged; usernames are
only ever recorded as a SHA-256 hash. Request bodies are never logged.

## Production hardening

The demo is intentionally minimal. Before production use, address each of the
following:

- **Redis deployment.** The in-memory store is single-process and loses all
  lockout state on restart — trivially defeated by a process bounce and useless
  behind more than one instance. Deploy `RedisAttemptStore` against a highly
  available Redis (primary + replicas or Cluster), enable persistence
  (AOF/RDB) so lockout state survives failover, use TLS (`rediss://`) and
  AUTH/ACLs, and set `maxmemory`/eviction policy so counter keys are never
  evicted under pressure (a security counter must not be silently dropped).
- **HTTPS/TLS termination.** Never accept credentials over plaintext. Terminate
  TLS at a load balancer or reverse proxy (or in-process), enforce HSTS,
  redirect HTTP→HTTPS, and set `app.set('trust proxy', ...)` correctly so the
  per-IP limiter keys on the real client IP (`X-Forwarded-For`) rather than the
  proxy's address — otherwise all traffic shares one bucket or is trivially
  spoofable.
- **Secrets management.** Redis URLs/passwords, token-signing keys, and pepper
  values must come from a secrets manager (Vault, AWS/GCP Secrets Manager,
  Kubernetes secrets) — never from source, `.env` in the repo, or logs. Rotate
  regularly and scope credentials to least privilege.
- **CAPTCHA escalation.** Add a risk-based challenge (CAPTCHA / proof-of-work)
  that escalates after the first failure or on anomalous IP/device/velocity
  signals, before the hard lockout triggers. This raises attacker cost without
  immediately locking legitimate users, and blunts distributed low-and-slow
  attacks that stay under the per-account threshold.
- **Credential-stuffing monitoring.** The per-account counter does not catch an
  attacker spraying one password across thousands of accounts from many IPs.
  Monitor global failure rates, failures-per-IP and per-ASN, impossible-travel,
  and breached-password hits (e.g. Have I Been Pwned k-anonymity range API),
  and feed alerts to SOC tooling. Consider device fingerprinting and
  reputation-based blocking at the edge.
- **Account-lockout DoS trade-offs of the 3-attempt threshold.** A low, strict
  threshold (3) is strong against targeted guessing but is itself a
  denial-of-service vector: an attacker who knows a victim's username can lock
  them out repeatedly and cheaply. Mitigations: prefer per-IP/velocity throttling
  and progressive delays + CAPTCHA over hard account locks where possible; scope
  locks so they cannot be triggered purely by an unauthenticated third party
  (e.g. require some signal tying attempts to the real user); cap lockout
  duration and auto-unlock (already implemented via `LOCKOUT_DURATION_MS`);
  provide a fast, well-protected self-service unlock/step-up path; and alert on
  mass-lockout patterns that indicate the lockout mechanism is being weaponized.
  The 3-attempt value is a deliberate, tunable trade-off in `config.js` between
  guessing resistance and lockout-DoS exposure — raise it, or gate it behind
  risk signals, if lockout-abuse is the greater threat for your user base.