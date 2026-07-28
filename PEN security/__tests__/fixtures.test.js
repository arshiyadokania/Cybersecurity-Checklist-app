'use strict';

/**
 * Test 8 — anti-theater fixture detection (integration).
 *
 * Each planted vulnerability in __fixtures__/vulnerable/ must be caught by its
 * scanner. These tests are GUARDED: they run only where the scanner is
 * installed and skip cleanly otherwise (so `npm test` is green on a dev box
 * without every tool, while CI — which installs the tools — actually exercises
 * detection). They must never be disabled to force a pass.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, execSync } = require('child_process');

const FIXTURES = path.join(__dirname, '..', '__fixtures__', 'vulnerable');

function hasTool(name) {
  try {
    execSync(`command -v ${name}`, { stdio: 'ignore' });
    return true;
  } catch (err) {
    return false;
  }
}

// Run a scanner and capture stdout even on the "findings present" nonzero exit.
function runCapture(cmd, args) {
  try {
    return { code: 0, stdout: execFileSync(cmd, args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }) };
  } catch (err) {
    return {
      code: err.status == null ? 1 : err.status,
      stdout: (err.stdout || '').toString(),
      stderr: (err.stderr || '').toString(),
    };
  }
}

const gitleaksTest = hasTool('gitleaks') ? test : test.skip;
const osvTest = hasTool('osv-scanner') ? test : test.skip;
const semgrepTest = hasTool('semgrep') ? test : test.skip;

describe('fixture detection (test 8)', () => {
  if (!hasTool('gitleaks') && !hasTool('osv-scanner') && !hasTool('semgrep')) {
    // Visible in the reporter so a skipped run is never mistaken for a pass.
    // eslint-disable-next-line no-console
    console.warn(
      '[fixtures.test] No scanners installed (gitleaks/osv-scanner/semgrep) — ' +
        'detection tests skipped. CI installs them and runs them for real.'
    );
  }

  gitleaksTest('gitleaks flags the planted AWS-shaped secret', () => {
    const reportPath = path.join(os.tmpdir(), `gitleaks-${Date.now()}.json`);
    runCapture('gitleaks', [
      'detect',
      '--source', FIXTURES,
      '--no-git',
      '--report-format', 'json',
      '--report-path', reportPath,
      '--exit-code', '0',
    ]);
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    expect(Array.isArray(report)).toBe(true);
    expect(report.length).toBeGreaterThan(0);
    const hitAws = report.some(
      (r) => /AKIA/.test(r.Secret || '') || /aws/i.test(r.RuleID || '')
    );
    expect(hitAws).toBe(true);
  });

  osvTest('osv-scanner flags the vulnerable lodash dependency', () => {
    const res = runCapture('osv-scanner', [
      '--lockfile', path.join(FIXTURES, 'package-lock.json'),
      '--format', 'json',
    ]);
    const data = JSON.parse(res.stdout);
    const packages = (data.results || []).flatMap((r) => r.packages || []);
    const lodash = packages.find((p) => p.package && p.package.name === 'lodash');
    expect(lodash).toBeDefined();
    expect((lodash.vulnerabilities || []).length).toBeGreaterThan(0);
  });

  semgrepTest('semgrep flags the eval/exec sinks', () => {
    const res = runCapture('semgrep', [
      '--config', 'p/owasp-top-ten',
      '--json',
      '--quiet',
      path.join(FIXTURES, 'command-injection.js'),
    ]);
    const data = JSON.parse(res.stdout);
    expect(Array.isArray(data.results)).toBe(true);
    expect(data.results.length).toBeGreaterThan(0);
  });
});