'use strict';

/**
 * consolidate.js — pure consolidation + gating logic.
 *
 * The exported functions are pure (no file/network I/O): they take SARIF /
 * findings objects and return normalized data. This is what makes the gate
 * testable and what guarantees local↔CI parity (both call the same functions).
 *
 * A thin CLI at the bottom (guarded by `require.main === module`) does the file
 * reading and process.exit — that is the ONLY place I/O happens.
 */

const fs = require('fs');
const path = require('path');
const config = require('./securityConfig');

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

function severityRank(severity) {
  const rank = config.SEVERITY_ORDER.indexOf(severity);
  return rank === -1 ? 0 : rank;
}

function cvssToSeverity(score) {
  const value = Number(score);
  for (const band of config.CVSS_BANDS) {
    if (value >= band.min) return band.severity;
  }
  return config.SEVERITY.INFO;
}

function levelToSeverity(level) {
  const key = level || config.DEFAULT_SARIF_LEVEL;
  return config.LEVEL_TO_SEVERITY[key] || config.SEVERITY.INFO;
}

// ---------------------------------------------------------------------------
// parseSarif: normalize a SARIF document into findings
// ---------------------------------------------------------------------------

/**
 * @param {object|string} sarifJson a SARIF 2.1.0 document (object or JSON string)
 * @returns {Array<{scanner,ruleId,severity,cvss,file,line,message}>}
 * @throws if the document is not valid SARIF (so a garbled scanner output is
 *         never silently treated as "zero findings").
 */
function parseSarif(sarifJson) {
  const doc = typeof sarifJson === 'string' ? JSON.parse(sarifJson) : sarifJson;
  if (!doc || !Array.isArray(doc.runs)) {
    throw new Error('Invalid SARIF: expected a "runs" array');
  }

  const findings = [];

  for (const run of doc.runs) {
    const driver = (run.tool && run.tool.driver) || {};
    const scanner = driver.name || 'unknown';

    // Build a ruleId → rule.properties map (rules can live on the driver or on
    // extensions). Scanners like Semgrep and osv-scanner attach
    // `security-severity` (CVSS) to the rule, not the individual result.
    const ruleProps = new Map();
    const ruleArrays = [driver.rules];
    if (Array.isArray(run.tool && run.tool.extensions)) {
      for (const ext of run.tool.extensions) {
        if (Array.isArray(ext.rules)) ruleArrays.push(ext.rules);
      }
    }
    for (const arr of ruleArrays) {
      if (!Array.isArray(arr)) continue;
      for (const rule of arr) {
        if (rule && rule.id) ruleProps.set(rule.id, rule.properties || {});
      }
    }

    const results = Array.isArray(run.results) ? run.results : [];
    for (const result of results) {
      const ruleId =
        result.ruleId || (result.rule && result.rule.id) || 'unknown';
      const rp = ruleProps.get(ruleId) || {};

      // Prefer CVSS security-severity (result-level, then rule-level).
      const rawSeverity =
        (result.properties && result.properties['security-severity']) !== undefined
          ? result.properties['security-severity']
          : rp['security-severity'];

      let severity;
      let cvss;
      if (
        rawSeverity !== undefined &&
        rawSeverity !== null &&
        rawSeverity !== '' &&
        !Number.isNaN(Number(rawSeverity))
      ) {
        cvss = Number(rawSeverity);
        severity = cvssToSeverity(cvss);
      } else {
        const level = result.level || rp.level || config.DEFAULT_SARIF_LEVEL;
        severity = levelToSeverity(level);
        cvss = undefined;
      }

      const physical =
        (result.locations &&
          result.locations[0] &&
          result.locations[0].physicalLocation) ||
        {};
      const file =
        (physical.artifactLocation && physical.artifactLocation.uri) || null;
      const line = (physical.region && physical.region.startLine) || null;
      const message = (result.message && result.message.text) || '';

      findings.push({ scanner, ruleId, severity, cvss, file, line, message });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Suppressions
// ---------------------------------------------------------------------------

/**
 * Validate the suppression allowlist. A suppression missing a non-empty
 * `reason` or a valid `expiresAt` is INVALID and throws — the pipeline must
 * fail at config load rather than silently ignore a malformed entry.
 *
 * @param {Array} suppressions
 * @returns {Array} the same list (validated)
 * @throws Error on any invalid entry
 */
function validateSuppressions(suppressions) {
  if (!Array.isArray(suppressions)) {
    throw new Error('suppressions must be an array');
  }
  suppressions.forEach((entry, index) => {
    const where = `suppressions[${index}]`;
    if (!entry || typeof entry !== 'object') {
      throw new Error(`${where}: must be an object`);
    }
    for (const field of config.SUPPRESSION_REQUIRED_FIELDS) {
      const value = entry[field];
      if (typeof value !== 'string' || value.trim() === '') {
        throw new Error(
          `${where}: missing or empty required field "${field}" ` +
            '(every suppression needs a ruleId, a non-empty reason, and an expiresAt)'
        );
      }
    }
    const expiry = new Date(entry.expiresAt).getTime();
    if (Number.isNaN(expiry)) {
      throw new Error(`${where}: expiresAt "${entry.expiresAt}" is not a valid ISO date`);
    }
    if (entry.file !== undefined && typeof entry.file !== 'string') {
      throw new Error(`${where}: file, when present, must be a string`);
    }
  });
  return suppressions;
}

/**
 * Drop findings matching a NON-EXPIRED suppression. An expired suppression no
 * longer suppresses — its finding re-surfaces (the anti-rot rule).
 *
 * @param {Array} findings
 * @param {Array} suppressions (assumed validated)
 * @param {Date|number|string} now current time
 * @returns {Array} the findings that remain after suppression
 */
function applySuppressions(findings, suppressions, now) {
  const nowMs =
    now instanceof Date ? now.getTime() : new Date(now).getTime();

  const active = (suppressions || []).filter(
    (s) => new Date(s.expiresAt).getTime() > nowMs
  );

  return findings.filter((finding) => {
    const matched = active.some(
      (s) =>
        s.ruleId === finding.ruleId &&
        (s.file === undefined || s.file === finding.file)
    );
    return !matched;
  });
}

// ---------------------------------------------------------------------------
// Gating
// ---------------------------------------------------------------------------

/**
 * @param {Array} findings
 * @param {string} [threshold] severity at/above which the build fails
 * @returns {number} nonzero if any finding is at/above threshold, else 0
 */
function computeExitCode(findings, threshold = config.FAIL_THRESHOLD) {
  const gate = severityRank(threshold);
  const failing = findings.some((f) => severityRank(f.severity) >= gate);
  return failing ? config.EXIT.FAIL : config.EXIT.PASS;
}

/**
 * Build a synthetic critical finding representing a crashed/errored scanner.
 * Fail-closed: a scanner that does not run cleanly must fail the build.
 */
function makeScannerError(scanner, message) {
  return {
    scanner: scanner || 'unknown',
    ruleId: config.SCANNER_ERROR.ruleId,
    severity: config.SCANNER_ERROR.severity,
    cvss: undefined,
    file: null,
    line: null,
    message: message || 'scanner failed to run',
  };
}

/**
 * Per-severity + per-scanner counts for the consolidated summary.
 */
function summarize(findings) {
  const bySeverity = {};
  for (const level of config.SEVERITY_ORDER) bySeverity[level] = 0;
  const byScanner = {};

  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byScanner[f.scanner] = (byScanner[f.scanner] || 0) + 1;
  }

  return { total: findings.length, bySeverity, byScanner };
}

/**
 * Full consolidation pipeline — the single source of truth used by BOTH the
 * local runner and CI (parity).
 *
 * @param {object} input
 * @param {Array<{scanner?:string, sarif?:object, error?:string}>} input.sarifDocs
 *        Each entry is either a SARIF doc ({scanner, sarif}) or a scanner error
 *        marker ({scanner, error}). A doc that fails to parse becomes a
 *        scanner-error finding (fail-closed).
 * @param {Array} [input.suppressions]
 * @param {Date|number|string} [input.now]
 * @param {string} [input.failThreshold]
 * @returns {{allFindings, findings, suppressedCount, summary, exitCode, threshold}}
 */
function consolidate({
  sarifDocs = [],
  suppressions = [],
  now = new Date(),
  failThreshold = config.FAIL_THRESHOLD,
}) {
  validateSuppressions(suppressions);

  const allFindings = [];
  for (const doc of sarifDocs) {
    if (doc && doc.error) {
      allFindings.push(makeScannerError(doc.scanner, doc.error));
      continue;
    }
    try {
      const parsed = parseSarif(doc.sarif !== undefined ? doc.sarif : doc);
      allFindings.push(...parsed);
    } catch (err) {
      // A scanner that emitted unparseable output is treated as a failure.
      allFindings.push(makeScannerError(doc && doc.scanner, err.message));
    }
  }

  const kept = applySuppressions(allFindings, suppressions, now);
  const summary = summarize(kept);
  const exitCode = computeExitCode(kept, failThreshold);

  return {
    allFindings,
    findings: kept,
    suppressedCount: allFindings.length - kept.length,
    summary,
    exitCode,
    threshold: failThreshold,
  };
}

module.exports = {
  severityRank,
  cvssToSeverity,
  levelToSeverity,
  parseSarif,
  validateSuppressions,
  applySuppressions,
  computeExitCode,
  makeScannerError,
  summarize,
  consolidate,
};

// ---------------------------------------------------------------------------
// CLI (the only place with I/O). Reads reports/*.sarif and reports/*.status.json
// and gates the build. Used by scripts/run-security-scan.sh AND by CI, so both
// produce identical results.
// ---------------------------------------------------------------------------
function readReportsDir(reportsDir) {
  const sarifDocs = [];
  if (!fs.existsSync(reportsDir)) return sarifDocs;

  const entries = fs.readdirSync(reportsDir);

  // Scanner status markers: {name, exitCode, ok}. ok:false → scanner error.
  for (const name of entries.filter((n) => n.endsWith('.status.json'))) {
    const status = JSON.parse(fs.readFileSync(path.join(reportsDir, name), 'utf8'));
    if (status && status.ok === false) {
      sarifDocs.push({
        scanner: status.name,
        error: `scanner exited with code ${status.exitCode}`,
      });
    }
  }

  for (const name of entries.filter((n) => n.endsWith('.sarif'))) {
    const raw = fs.readFileSync(path.join(reportsDir, name), 'utf8');
    sarifDocs.push({ scanner: name.replace(/\.sarif$/, ''), sarif: raw });
  }

  return sarifDocs;
}

function parseArgs(argv) {
  const args = { reports: 'reports', failThreshold: config.FAIL_THRESHOLD, suppressions: 'suppressions.json' };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--reports') args.reports = argv[i + 1];
    else if (argv[i] === '--fail-threshold') args.failThreshold = argv[i + 1];
    else if (argv[i] === '--suppressions') args.suppressions = argv[i + 1];
  }
  return args;
}

if (require.main === module) {
  const args = parseArgs(process.argv.slice(2));
  let suppressions = [];
  if (fs.existsSync(args.suppressions)) {
    suppressions = JSON.parse(fs.readFileSync(args.suppressions, 'utf8'));
  }

  let result;
  try {
    result = consolidate({
      sarifDocs: readReportsDir(args.reports),
      suppressions,
      now: new Date(),
      failThreshold: args.failThreshold,
    });
  } catch (err) {
    process.stderr.write(`Config error: ${err.message}\n`);
    process.exit(config.EXIT.CONFIG_ERROR); // config-load failure is fail-closed too
  }

  process.stdout.write('Security scan consolidated summary\n');
  process.stdout.write(`  total findings (after suppression): ${result.summary.total}\n`);
  process.stdout.write(`  suppressed: ${result.suppressedCount}\n`);
  for (const level of config.SEVERITY_ORDER.slice().reverse()) {
    process.stdout.write(`  ${level}: ${result.summary.bySeverity[level]}\n`);
  }
  process.stdout.write(`  by scanner: ${JSON.stringify(result.summary.byScanner)}\n`);
  process.stdout.write(`  fail threshold: ${result.threshold} → exit ${result.exitCode}\n`);

  process.exit(result.exitCode);
}