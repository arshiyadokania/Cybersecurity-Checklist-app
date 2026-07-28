'use strict';

/**
 * Central configuration for the security pipeline.
 *
 * ALL thresholds, severity bands, level mappings and tool version pins live
 * here so there are no magic numbers anywhere else (consolidate.js, scripts,
 * and the workflow all reference these).
 */

// Ordered from least to most severe. Index === rank.
const SEVERITY_ORDER = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);

const SEVERITY = Object.freeze({
  INFO: 'info',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
});

// --- Gating thresholds -------------------------------------------------------
// Fail the build on high + critical; warn (report only) on medium; low/info
// are report-only.
const FAIL_THRESHOLD = 'high';
const WARN_THRESHOLD = 'medium';

// --- SARIF level → severity (used when no CVSS security-severity is present) --
const LEVEL_TO_SEVERITY = Object.freeze({
  error: 'high',
  warning: 'medium',
  note: 'low',
  none: 'info',
});

// SARIF's own default level when a result omits `level` and no rule default
// applies (per the SARIF 2.1.0 spec).
const DEFAULT_SARIF_LEVEL = 'warning';

// --- CVSS (0–10) → severity bands (CVSS v3 qualitative ranges) ---------------
// Evaluated top-down; first band whose `min` is met wins.
const CVSS_BANDS = Object.freeze([
  Object.freeze({ min: 9.0, severity: 'critical' }),
  Object.freeze({ min: 7.0, severity: 'high' }),
  Object.freeze({ min: 4.0, severity: 'medium' }),
  Object.freeze({ min: 0.1, severity: 'low' }),
  Object.freeze({ min: 0.0, severity: 'info' }),
]);

// --- Fail-closed: a scanner that crashes becomes a synthetic critical --------
const SCANNER_ERROR = Object.freeze({
  ruleId: 'pipeline/scanner-execution-error',
  severity: 'critical',
});

// --- Suppression / allowlist rules ------------------------------------------
// Every suppression MUST carry these non-empty fields. `file` is optional.
const SUPPRESSION_REQUIRED_FIELDS = Object.freeze(['ruleId', 'reason', 'expiresAt']);

// --- Scanner "findings present" exit codes ----------------------------------
// These nonzero exits mean "the scanner ran fine and found something", which
// the gate (consolidate.js) decides on. ANY OTHER nonzero exit is a real
// scanner error and must fail the pipeline (fail-closed).
const SCANNER_FINDINGS_EXIT_CODE = Object.freeze({
  'osv-scanner': 1,
  semgrep: 1,
  gitleaks: 1,
});

// --- Process exit codes ------------------------------------------------------
const EXIT = Object.freeze({
  PASS: 0, // no finding at/above the fail threshold
  FAIL: 1, // a finding at/above the fail threshold remains (build must fail)
  CONFIG_ERROR: 2, // invalid config (e.g. malformed suppression) — fail-closed
});

// --- Pinned tool versions (explicit pins only) ------------------------------
const TOOL_VERSIONS = Object.freeze({
  osvScanner: '1.9.2',
  semgrep: '1.96.0',
  gitleaks: '8.21.2',
  syft: '1.18.1',
  zap: '2.15.0',
});

module.exports = Object.freeze({
  SEVERITY,
  SEVERITY_ORDER,
  FAIL_THRESHOLD,
  WARN_THRESHOLD,
  LEVEL_TO_SEVERITY,
  DEFAULT_SARIF_LEVEL,
  CVSS_BANDS,
  SCANNER_ERROR,
  SUPPRESSION_REQUIRED_FIELDS,
  SCANNER_FINDINGS_EXIT_CODE,
  EXIT,
  TOOL_VERSIONS,
});