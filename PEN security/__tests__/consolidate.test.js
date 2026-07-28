'use strict';

/**
 * Tests 1–7, 9, 10 — the pure consolidation + gating core.
 */

const {
  parseSarif,
  validateSuppressions,
  applySuppressions,
  computeExitCode,
  makeScannerError,
  consolidate,
  summarize,
} = require('../consolidate');

// A multi-run SARIF: one Semgrep run (rule-level CVSS) + one gitleaks run.
function multiRunSarif() {
  return {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'semgrep',
            rules: [
              {
                id: 'javascript.lang.security.audit.eval-detected',
                properties: { 'security-severity': '7.5' },
              },
            ],
          },
        },
        results: [
          {
            ruleId: 'javascript.lang.security.audit.eval-detected',
            level: 'error',
            message: { text: 'eval() on user input' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: '__fixtures__/vulnerable/command-injection.js' },
                  region: { startLine: 16 },
                },
              },
            ],
          },
        ],
      },
      {
        tool: { driver: { name: 'gitleaks' } },
        results: [
          {
            ruleId: 'aws-access-token',
            level: 'error',
            message: { text: 'AWS Access Key detected' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: '__fixtures__/vulnerable/hardcoded-secret.js' },
                  region: { startLine: 15 },
                },
              },
            ],
          },
        ],
      },
    ],
  };
}

describe('parseSarif (test 1)', () => {
  test('normalizes a multi-run SARIF into expected findings', () => {
    const findings = parseSarif(multiRunSarif());
    expect(findings).toHaveLength(2);

    const semgrep = findings.find((f) => f.scanner === 'semgrep');
    expect(semgrep).toMatchObject({
      scanner: 'semgrep',
      ruleId: 'javascript.lang.security.audit.eval-detected',
      severity: 'high', // from CVSS 7.5
      cvss: 7.5,
      file: '__fixtures__/vulnerable/command-injection.js',
      line: 16,
    });

    const gitleaks = findings.find((f) => f.scanner === 'gitleaks');
    expect(gitleaks).toMatchObject({
      scanner: 'gitleaks',
      ruleId: 'aws-access-token',
      severity: 'high', // level "error" → high (no CVSS present)
      file: '__fixtures__/vulnerable/hardcoded-secret.js',
      line: 15,
    });
    expect(gitleaks.cvss).toBeUndefined();
  });

  test('accepts a JSON string as well as an object', () => {
    const findings = parseSarif(JSON.stringify(multiRunSarif()));
    expect(findings).toHaveLength(2);
  });

  test('throws on non-SARIF input (never silently zero findings)', () => {
    expect(() => parseSarif({ not: 'sarif' })).toThrow(/Invalid SARIF/);
  });
});

describe('security-severity vs level (test 2)', () => {
  test('CVSS security-severity is preferred over level mapping', () => {
    const sarif = {
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'osv-scanner' } },
          results: [
            {
              ruleId: 'GHSA-jf85-cpcp-j695',
              level: 'note', // level alone would map to LOW
              properties: { 'security-severity': '9.8' }, // but CVSS says CRITICAL
              message: { text: 'Prototype pollution in lodash' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'package-lock.json' },
                    region: { startLine: 1 },
                  },
                },
              ],
            },
          ],
        },
      ],
    };
    const [finding] = parseSarif(sarif);
    expect(finding.cvss).toBe(9.8);
    expect(finding.severity).toBe('critical');
    expect(finding.severity).not.toBe('low');
  });
});

describe('applySuppressions (tests 3, 4)', () => {
  const findings = [
    { scanner: 'osv-scanner', ruleId: 'GHSA-aaaa', severity: 'high', file: 'package-lock.json' },
    { scanner: 'semgrep', ruleId: 'rule-b', severity: 'high', file: 'src/app.js' },
  ];

  test('drops a matching, non-expired finding (test 3)', () => {
    const suppressions = [
      { ruleId: 'GHSA-aaaa', file: 'package-lock.json', reason: 'triaged', expiresAt: '2999-01-01' },
    ];
    const kept = applySuppressions(findings, suppressions, new Date('2026-01-01'));
    expect(kept).toHaveLength(1);
    expect(kept[0].ruleId).toBe('rule-b');
  });

  test('an EXPIRED suppression does NOT drop its finding (test 4)', () => {
    const suppressions = [
      { ruleId: 'GHSA-aaaa', file: 'package-lock.json', reason: 'triaged', expiresAt: '2020-01-01' },
    ];
    const kept = applySuppressions(findings, suppressions, new Date('2026-01-01'));
    expect(kept).toHaveLength(2);
    expect(kept.map((f) => f.ruleId).sort()).toEqual(['GHSA-aaaa', 'rule-b']);
  });

  test('a file-less suppression matches the ruleId regardless of file', () => {
    const suppressions = [{ ruleId: 'rule-b', reason: 'accepted risk', expiresAt: '2999-01-01' }];
    const kept = applySuppressions(findings, suppressions, new Date('2026-01-01'));
    expect(kept.map((f) => f.ruleId)).toEqual(['GHSA-aaaa']);
  });
});

describe('suppression validation (test 5)', () => {
  test('missing reason → throws at config load', () => {
    expect(() =>
      validateSuppressions([{ ruleId: 'x', expiresAt: '2999-01-01' }])
    ).toThrow(/reason/);
  });

  test('empty reason → throws', () => {
    expect(() =>
      validateSuppressions([{ ruleId: 'x', reason: '   ', expiresAt: '2999-01-01' }])
    ).toThrow(/reason/);
  });

  test('missing expiresAt → throws', () => {
    expect(() =>
      validateSuppressions([{ ruleId: 'x', reason: 'ok' }])
    ).toThrow(/expiresAt/);
  });

  test('invalid expiresAt date → throws', () => {
    expect(() =>
      validateSuppressions([{ ruleId: 'x', reason: 'ok', expiresAt: 'not-a-date' }])
    ).toThrow(/valid ISO date/);
  });

  test('a fully valid suppression passes', () => {
    expect(() =>
      validateSuppressions([{ ruleId: 'x', reason: 'ok', expiresAt: '2999-01-01' }])
    ).not.toThrow();
  });
});

describe('computeExitCode (test 6)', () => {
  test('returns nonzero for a High when threshold=high', () => {
    const findings = [{ severity: 'high' }];
    expect(computeExitCode(findings, 'high')).not.toBe(0);
  });

  test('returns zero when all findings are below threshold', () => {
    const findings = [{ severity: 'medium' }, { severity: 'low' }, { severity: 'info' }];
    expect(computeExitCode(findings, 'high')).toBe(0);
  });

  test('critical also fails a high threshold', () => {
    expect(computeExitCode([{ severity: 'critical' }], 'high')).not.toBe(0);
  });
});

describe('fail-closed (test 7)', () => {
  test('a scanner-error finding forces a nonzero exit even at high threshold', () => {
    const err = makeScannerError('semgrep', 'exited with code 2');
    expect(err.severity).toBe('critical');
    expect(computeExitCode([err], 'high')).not.toBe(0);
  });

  test('consolidate turns a scanner error marker into a failing build', () => {
    const result = consolidate({
      sarifDocs: [{ scanner: 'gitleaks', error: 'exited with code 127' }],
      suppressions: [],
      now: new Date('2026-01-01'),
      failThreshold: 'high',
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.allFindings[0].ruleId).toBe('pipeline/scanner-execution-error');
  });

  test('consolidate treats unparseable scanner output as a failure', () => {
    const result = consolidate({
      sarifDocs: [{ scanner: 'osv-scanner', sarif: '{ this is not sarif' }],
      now: new Date('2026-01-01'),
    });
    expect(result.exitCode).not.toBe(0);
  });
});

describe('consolidated summary (test 9)', () => {
  test('lists findings from all scanners with per-severity counts', () => {
    const result = consolidate({
      sarifDocs: [
        { scanner: 'combined', sarif: multiRunSarif() },
        {
          scanner: 'osv',
          sarif: {
            version: '2.1.0',
            runs: [
              {
                tool: { driver: { name: 'osv-scanner' } },
                results: [
                  {
                    ruleId: 'GHSA-jf85-cpcp-j695',
                    properties: { 'security-severity': '9.8' },
                    message: { text: 'lodash prototype pollution' },
                    locations: [
                      {
                        physicalLocation: {
                          artifactLocation: { uri: 'package-lock.json' },
                          region: { startLine: 1 },
                        },
                      },
                    ],
                  },
                ],
              },
            ],
          },
        },
      ],
      now: new Date('2026-01-01'),
      failThreshold: 'high',
    });

    expect(result.summary.total).toBe(3);
    expect(result.summary.bySeverity.high).toBe(2); // semgrep + gitleaks
    expect(result.summary.bySeverity.critical).toBe(1); // osv 9.8
    expect(result.summary.byScanner.semgrep).toBe(1);
    expect(result.summary.byScanner.gitleaks).toBe(1);
    expect(result.summary.byScanner['osv-scanner']).toBe(1);
    expect(result.exitCode).not.toBe(0);
  });
});

describe('local↔CI parity (test 10)', () => {
  test('consolidate is a pure function of its inputs — identical results', () => {
    const inputs = {
      sarifDocs: [{ scanner: 'combined', sarif: multiRunSarif() }],
      suppressions: [{ ruleId: 'unused', reason: 'x', expiresAt: '2999-01-01' }],
      now: new Date('2026-01-01T00:00:00Z'),
      failThreshold: 'high',
    };
    const localRun = consolidate(inputs);
    const ciRun = consolidate(inputs);
    expect(localRun).toEqual(ciRun);
  });

  test('SARIF-as-string and SARIF-as-object yield identical findings', () => {
    const asObject = summarize(parseSarif(multiRunSarif()));
    const asString = summarize(parseSarif(JSON.stringify(multiRunSarif())));
    expect(asString).toEqual(asObject);
  });
});