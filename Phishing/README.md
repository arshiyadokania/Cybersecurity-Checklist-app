# Phishing-Awareness Messaging System

A runnable React 18 + Node/Express feature that delivers phishing-awareness
messages at the right moments, lets users **report** phishing (the point of the
system), and never habituates users with a permanent banner.

It is a detection-and-education loop:

- **Page triggers** (`login_success`, `password_change_initiated`,
  `email_change_initiated`, `new_payee_or_transfer_setup`,
  `security_settings_viewed`) deliver standard tips, rate-limited by an
  anti-fatigue policy.
- **Risk-event triggers** (`new_device_login`, `new_geo_login`,
  `unrequested_password_reset`, `anomalous_transfer_flagged`) are
  server-initiated, delivered on the next poll, and **bypass** anti-fatigue —
  a new-device warning is never suppressed because a tip was shown this morning.
- A per-user **priority queue**: `risk_event > urgent > standard`.
- A **report-phishing loop**: every standard message can open an in-app report
  form; reports persist and are listed for the SOC.

The server is the single authority on all frequency, priority, and eligibility
logic. **The client never implements frequency logic.**

## Architecture

| File | Responsibility |
| --- | --- |
| `messagingConfig.js` | All constants, thresholds, enums (no magic numbers elsewhere). |
| `content/en.json`, `content/es.json` | Externalized message content, both locales complete. |
| `stores/messageStateStore.js` | Per-user anti-fatigue, dismissal cooldown, risk queue, urgent tracking. |
| `stores/reportStore.js` | Persists phishing reports. |
| `stores/userProfileStore.js` | Per-user segmentation profile. |
| `selectNextMessage.js` | Pure, deterministic message selection (no `Math.random`). |
| `server.js` | Express endpoints + content loader (exits on malformed content). |
| `src/AwarenessProvider.jsx` | Orchestrates fetch → present → act. |
| `src/AwarenessBanner.jsx` | Banner (`role="status"`, `aria-live="polite"`). |
| `src/AwarenessModal.jsx` | Modal (focus trap, Escape, focus return). |
| `src/ReportPhishingForm.jsx` | In-app report form. |
| `src/useAwareness.js` | API client (no frequency logic). |

All stores accept an injected `now()` clock, so tests advance a virtual clock —
there are **no real sleeps** anywhere in the suite.

## Endpoints

| Method | Path | Result |
| --- | --- | --- |
| GET | `/api/awareness/next?userId=&trigger=&locale=` | `200 {message}` or `204` |
| POST | `/api/awareness/event` | `202` / `400` (strict telemetry enum) |
| POST | `/api/awareness/report` | `202 {reportId, message}` / `400` |
| POST | `/api/risk-event` (internal demo) | `202` |
| POST | `/api/awareness/campaign` (admin demo) | `201` / `400` |
| GET | `/api/awareness/reports` (admin demo) | `200 {reports}` |

## Run instructions

Requires Node.js 20+.

```bash
cd phishing-awareness
npm install

# Run the full test suite (frontend + backend + content). Acceptance gate.
npm test

# Start the demo API server (in-memory stores; exits if content is malformed).
npm start
# → listens on :4000 (override with PORT)
```

The React components are exported from `src/` for embedding in a host app; the
test suite renders them with React Testing Library.

### Content rules (enforced by `__tests__/content.test.js`)

- Every message body ≤ 60 words.
- Flesch-Kincaid grade ≤ 8 (measured with the `text-readability` package).
- No `http://` or `https://` anywhere.
- Every message has ≥ 1 action.
- `es.json` has every id `en.json` has, under the same rules.
- `m4` contains the exact line: *"We will never ask for your password, one-time
  codes, or full card number by email, text, or phone."*

## Why not a permanent banner

A message that is always on the screen becomes wallpaper. **Habituation** is the
core failure mode of security awareness UI: users learn to tab past a fixed
banner within days, so at the moment it matters (a real lookalike email) it
carries zero attention. This system renders a message **only on trigger
delivery**, caps standard messages hard (`MAX_STANDARD_PER_SESSION`,
`MIN_HOURS_BETWEEN_STANDARD`), rotates content so the same tip is not repeated,
and suppresses anything a user has dismissed twice for 30 days. Scarcity is the
point: a message that appears rarely, tied to a relevant action, is a message
that still gets read.

## Measuring effectiveness

- **Reports are the primary success metric.** A user who reports a phishing
  attempt has demonstrably done the right thing. The whole system is built
  around making that action one tap away from any message, and persisting the
  result. Report volume and report quality (channel breakdown, time-to-report)
  are the signals that the program is working.
- **Dismiss and CTA rates are weak proxies.** A dismiss can mean "I understand"
  or "go away"; a CTA click can mean genuine engagement or a misclick. They are
  useful for detecting fatigue and dead content, not for proving that behavior
  changed. Treat them as diagnostics, never as the headline metric.
- **Simulated phishing is the only true outcome metric.** The only way to know
  whether awareness translates into resistance is to measure whether users
  actually resist a realistic (benign) phishing simulation — click rate,
  credential-submission rate, and report rate on the sim.
  **Ethical requirement:** simulations must be *educational, never punitive* —
  no naming-and-shaming, no performance consequences, no dark patterns; a user
  who "fails" gets a teaching moment, not a mark on their record. Punitive sims
  destroy the trust the report loop depends on and suppress reporting. Building
  the simulation platform (targeting, consent posture, teaching flow, metric
  pipeline) is **out of scope here** precisely because doing it ethically is a
  program, not a component.

## Channel consistency

This control only works if the company's own outbound communications do not
teach the opposite lesson. The training says "we will never ask you to click a
link to verify your account" — so **outbound email hygiene is a hard
dependency**:

- No login or "verify your account" links in marketing or transactional email.
- One consistent, small set of sender domains — no per-campaign lookalike
  subdomains that train users to accept novelty.
- **DMARC at `p=reject`** (with SPF and DKIM aligned) so attackers cannot spoof
  the real domain, and so "does it come from our exact domain" is a signal users
  can actually rely on.

Without this, the company contradicts its own training every week, and the most
security-aware users are the ones most likely to (correctly) distrust
legitimate mail — or (incorrectly) trust a lookalike because "the bank always
sends links."

## Production hardening

- **Real store backends.** The in-memory `Map` stores are for the demo only.
  Back `messageStateStore`, `reportStore`, and `userProfileStore` with durable,
  shared storage (Redis for counters/queues with TTLs; Postgres for reports and
  profiles) behind the same interfaces, so frequency state survives restarts and
  is consistent across instances.
- **Authn/authz on admin endpoints.** `/api/awareness/campaign`,
  `/api/awareness/reports`, and `/api/risk-event` are unauthenticated demo
  endpoints. In production they require authentication, role-based authorization
  (campaign authors vs. SOC analysts), audit logging, and rate limiting.
- **SOC integration for the report queue.** Reports should flow into a durable
  queue (SQS/Kafka) consumed by SOC tooling / SOAR playbooks, with
  deduplication, enrichment (sender domain, campaign correlation), and
  case-management hooks — not sit in a demo list endpoint.
- **Localization pipeline beyond two hand-written locales.** `en.json` and
  `es.json` are hand-authored and hand-tuned for readability. A real deployment
  needs a translation-management pipeline (TMS, translator review, and an
  automated readability + no-link + action-count gate in CI for every locale)
  so new languages meet the same content rules without manual tuning.