# Security Testing Pipeline (self-scanning)

A runnable, defensive security CI/CD pipeline that scans **this repository's own
code and dependencies**, consolidates every scanner's findings into one SARIF-based
gate, fails the build on severity, and proves it actually detects vulnerabilities
by catching deliberately-planted ones in `__fixtures__/vulnerable/`.

It never attacks external systems. The only dynamic scan (ZAP baseline) runs in
passive mode against a **local** instance of the app on localhost, and skips
cleanly when that is not feasible.

## Scanners (all pinned, all defensive)

| Layer | Tool | Version | Output |
| --- | --- | --- | --- |
| SCA (deps) | osv-scanner (+ `npm audit --json` supplement) | 1.9.2 | SARIF |
| SAST | Semgrep (`p/ci`, `p/owasp-top-ten`) | 1.96.0 | SARIF |
| Secrets | gitleaks (working tree **and** full git history) | 8.21.2 | SARIF |
| SBOM | syft (CycloneDX) | 1.18.1 | CycloneDX JSON |
| DAST | OWASP ZAP baseline (passive, localhost) | 2.15.0 | ZAP report |

Versions are pinned in `securityConfig.js` (`TOOL_VERSIONS`), the scripts, and the
workflow. Nothing uses `latest` — security tooling that auto-updates breaks builds
unpredictably.

## How the gate works

1. Each scanner writes SARIF to `reports/`. `scripts/run-security-scan.sh` also
   writes a `*.status.json` per scanner recording its exit code.
2. `consolidate.js` (pure, no I/O in its logic) does the work:
   - `parseSarif` → normalized `{scanner, ruleId, severity, cvss?, file, line, message}`.
     Severity comes from SARIF `properties.security-severity` (CVSS 0–10) when present,
     else from `level` (`error`→high, `warning`→medium, `note`→low).
   - `applySuppressions` drops findings matching a **non-expired** allowlist entry.
   - `computeExitCode` returns nonzero if any remaining finding is at/above
     `FAIL_THRESHOLD` (`high`).
3. A crashed scanner (`ok:false`) becomes a synthetic **critical** finding, so the
   build fails closed — a scanner that did not run is never a pass.

All gating constants live in `securityConfig.js` (no magic numbers elsewhere):
`FAIL_THRESHOLD = "high"`, `WARN_THRESHOLD = "medium"`, the CVSS bands, and the
level→severity map.

## Suppressions (`suppressions.json`) — with mandatory expiry

Each entry is `{ ruleId, file?, reason (required), expiresAt (required ISO date), addedBy }`.

- A suppression missing `reason` or `expiresAt` is **invalid** → the pipeline fails
  at config load with a clear error (it is never silently ignored).
- An **expired** suppression stops suppressing — its finding re-surfaces and can fail
  the build. This forces periodic re-review instead of permanent blindness.
- Suppressions are per-`ruleId` (optionally scoped to a `file`), never "ignore all".

## Run it

```bash
cd security-pipeline
npm install
npm test                 # the consolidation gate + fixture-detection tests

# Full local scan (needs the scanners installed; same gate as CI → parity):
npm run security:scan
npm run sbom
```

`npm test` passes on a dev box even without every scanner installed: the
fixture-detection tests (`__tests__/fixtures.test.js`) are guarded and **skip
cleanly** where a tool is absent. CI installs the pinned tools and runs them for
real. The local script and CI both call `consolidate.js`, so the gate result is
identical (parity).

### CI

`.github/workflows/security.yml` runs on **push/PR** and on a **weekly schedule**,
uploads SARIF to the private code-scanning Security tab, and stores the SBOM as a
build artifact. Finding details are never published anywhere public.

---

## What this catches and what it doesn't

This pipeline is a set of **found-pattern and known-CVE detectors**:

- SCA finds dependencies with **publicly disclosed** CVEs.
- SAST finds **known dangerous code patterns** (e.g. `eval` of input, string-built
  shell commands).
- Secret scanning finds **secret-shaped strings** in code and git history.
- ZAP baseline is a **passive** pass that flags obvious misconfigurations (missing
  security headers, etc.).

It does **not** replace manual penetration testing and does **not** find novel logic
flaws, authentication/authorization bypasses, broken access control, or
business-logic abuse (e.g. "user A can read user B's data by changing an id"). Those
require humans who understand intent. Treat a green pipeline as "no known-pattern
issues found", not "secure".

## Why scheduled scans

A dependency that is clean at commit time is **not clean forever**. New CVEs are
disclosed daily against versions you already shipped. The push/PR scan checks
changed code fast; the **weekly full scan** re-checks the *unchanged* codebase and
its locked dependencies against the latest vulnerability databases, so a CVE
published after your last commit still gets caught instead of sitting silently in
production.

## Reachability and noise

These tools report vulnerabilities **without proving they are exploitable in your
context**. osv-scanner will flag a CVE in a dependency even if your code never calls
the affected function; Semgrep will flag a sink even if the input is trusted.
Triage is required — that is a limitation to plan for, not a bug. **Reachability
analysis (proving a finding is actually reachable with attacker-controlled input) is
out of scope here.** Use the severity gate plus the suppression allowlist (with
expiry) to manage noise honestly, never by blanket-ignoring.

## Secrets in history

Once a secret has been committed, **it is compromised** — deleting the line does not
un-leak it, because it lives forever in git history (and likely in clones, forks,
and CI logs). That is why gitleaks scans the **full history**, not just the working
tree. When a real secret is found, the remediation is **ROTATE the secret**
(revoke and reissue at the provider), then purge history — not merely remove the
line and move on.

## Remediation workflow

Scanning that nobody acts on is theater. Findings must feed a tracker:

- Every confirmed finding becomes a ticket with **severity**, an **owner**, and an
  **SLA-to-fix** (e.g. critical: days; high: weeks).
- The SARIF upload surfaces findings in the code-scanning Security tab; from there
  they should sync to the issue tracker.
- Suppressions require a written **reason** and an **expiry** so accepted risk is
  reviewed on a schedule, not forgotten.

## Production hardening

This pipeline is a baseline. It does **not** replace, and should be layered with:

- **Authenticated DAST** — logged-in, role-aware dynamic scans (the baseline here is
  passive and unauthenticated) exercise far more of the attack surface.
- **SAST in the IDE** — shift left so developers see findings as they type, not only
  in CI.
- **Dependency auto-update PRs** — Dependabot or Renovate to keep dependencies
  patched continuously, so the weekly scan has less to find.
- **Periodic third-party manual penetration testing** — humans probing logic, auth,
  and business rules. This is the layer automated scanning fundamentally does not
  replace.