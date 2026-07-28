'use strict';

/*
 * DETECTION FIXTURE — NOT APPLICATION CODE.
 *
 * Deliberately vulnerable sinks so the SAST scanner (Semgrep, rulesets p/ci and
 * p/owasp-top-ten) has something to catch. This proves SAST detection is wired
 * up. This file must NEVER be imported by application code and is excluded from
 * the real gating scan (see scripts/run-security-scan.sh).
 */

const { exec } = require('child_process');

// Sink 1: eval of attacker-controlled input (code injection).
function runUserExpression(userInput) {
  // eslint-disable-next-line no-eval
  return eval(userInput);
}

// Sink 2: OS command built by string concatenation (command injection).
function listDirectory(userSuppliedPath, callback) {
  exec('ls -la ' + userSuppliedPath, callback);
}

module.exports = { runUserExpression, listDirectory };