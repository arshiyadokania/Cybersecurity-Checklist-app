#!/usr/bin/env bash
#
# run-security-scan.sh — run all self-scanners against THIS repo, write SARIF to
# reports/, and gate the build via consolidate.js.
#
# FAIL-CLOSED: a scanner that errors (any exit code that is NOT its documented
# "findings present" code) is recorded as ok:false, which consolidate.js turns
# into a critical finding that fails the build. Scanner errors are never swallowed.
#
# Local and CI both run THIS script, so the gate result is identical (parity).

set -euo pipefail

# --- Pinned tool versions (mirror securityConfig.js TOOL_VERSIONS; explicit pins only) ---
OSV_SCANNER_VERSION="1.9.2"
SEMGREP_VERSION="1.96.0"
GITLEAKS_VERSION="8.21.2"
ZAP_VERSION="2.15.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORTS="$ROOT_DIR/reports"
SCAN_TARGET="${SCAN_TARGET:-$ROOT_DIR}"

# Exclude the deliberately-vulnerable detection fixtures from the REAL gating
# scan (they are validated separately by __tests__/fixtures.test.js).
EXCLUDE_DIR="__fixtures__"

mkdir -p "$REPORTS"
# `rm -f` returns success even when the globs match nothing, so no fallback needed.
rm -f "$REPORTS"/*.sarif "$REPORTS"/*.status.json 2>/dev/null

echo ">> tool versions: osv-scanner=$OSV_SCANNER_VERSION semgrep=$SEMGREP_VERSION gitleaks=$GITLEAKS_VERSION zap=$ZAP_VERSION"

# run_scanner NAME FINDINGS_EXIT_CODE  -- CMD...
# Records ok:true if the scanner exits 0 or with its findings-present code;
# ok:false (a real error) otherwise. NEVER turns an error into a pass.
run_scanner() {
  local name="$1"; local findings_code="$2"; shift 2
  local code=0
  "$@" || code=$?
  if [ "$code" -eq 0 ] || [ "$code" -eq "$findings_code" ]; then
    printf '{"name":"%s","exitCode":%s,"ok":true}\n' "$name" "$code" > "$REPORTS/$name.status.json"
    echo ">> $name completed (exit $code)"
  else
    printf '{"name":"%s","exitCode":%s,"ok":false}\n' "$name" "$code" > "$REPORTS/$name.status.json"
    echo "::error:: scanner '$name' errored (exit $code) — build will fail closed" >&2
  fi
}

# --- 1. SCA: osv-scanner (SARIF) ------------------------------------------
run_scanner "osv-scanner" 1 \
  osv-scanner scan --recursive --format sarif --output "$REPORTS/osv-scanner.sarif" "$SCAN_TARGET"

# --- 1b. SCA supplement: npm audit (JSON, Node-specific) ------------------
# npm audit exits nonzero when vulnerabilities exist; capture that explicitly.
npm_audit_code=0
npm audit --json > "$REPORTS/npm-audit.json" || npm_audit_code=$?
echo ">> npm audit completed (exit $npm_audit_code) — supplement artifact only"

# --- 2. SAST: Semgrep (SARIF) ---------------------------------------------
run_scanner "semgrep" 1 \
  semgrep scan --config p/ci --config p/owasp-top-ten \
    --sarif --output "$REPORTS/semgrep.sarif" \
    --exclude "$EXCLUDE_DIR" "$SCAN_TARGET"

# --- 3. Secrets: gitleaks — working tree AND full git history (SARIF) ------
run_scanner "gitleaks-worktree" 1 \
  gitleaks detect --source "$SCAN_TARGET" --no-git \
    --report-format sarif --report-path "$REPORTS/gitleaks-worktree.sarif"

run_scanner "gitleaks-history" 1 \
  gitleaks detect --source "$SCAN_TARGET" --log-opts="--all --full-history" \
    --report-format sarif --report-path "$REPORTS/gitleaks-history.sarif"

# --- 5. DAST: OWASP ZAP baseline (passive, localhost only) -----------------
# Only runs when an app URL is provided AND docker is available. Otherwise it
# skips CLEANLY (no status file → not treated as a scanner error, not a fake pass).
if [ -n "${APP_URL:-}" ] && command -v docker >/dev/null 2>&1; then
  echo ">> DAST: ZAP baseline (passive) against $APP_URL"
  run_scanner "zap-baseline" 2 \
    docker run --rm --network host \
      -v "$REPORTS:/zap/wrk:rw" \
      "ghcr.io/zaproxy/zaproxy:${ZAP_VERSION}" \
      zap-baseline.py -t "$APP_URL" -J zap-baseline.json -x zap-baseline.xml
else
  echo ">> DAST: skipped cleanly (set APP_URL to a localhost app to enable ZAP baseline)"
fi

# --- Gate: consolidate all SARIF + status markers and set the exit code -----
echo ">> consolidating findings and applying the severity gate"
node "$ROOT_DIR/consolidate.js" \
  --reports "$REPORTS" \
  --suppressions "$ROOT_DIR/suppressions.json"