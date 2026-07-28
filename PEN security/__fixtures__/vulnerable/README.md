# Detection fixtures (deliberately vulnerable)

These files are **planted vulnerabilities** used to prove the scanners actually
detect things. They are:

- `hardcoded-secret.js` — an AWS-key-shaped **fake** string → gitleaks must flag it.
- `package.json` + `package-lock.json` — pins `lodash@4.17.4`, which has known
  published CVEs (e.g. CVE-2019-10744 prototype pollution) → osv-scanner must flag it.
- `command-injection.js` — `eval()` of input and a concatenated `exec()` command
  → Semgrep must flag it.

Rules:

- **Never import these from application code.** They are excluded from the app
  build and from the real gating scan; they are only targeted directly by the
  detection tests (`__tests__/fixtures.test.js`).
- The dependency here is **not installed** into the app; the lockfile is read
  statically by osv-scanner.
- The secret is **not a real credential** and grants access to nothing.