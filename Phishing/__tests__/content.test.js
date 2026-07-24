'use strict';

/**
 * Test 16 — content integrity across BOTH locales.
 */

const path = require('path');
const rs = require('text-readability').default;
const config = require('../messagingConfig');

const en = require('../content/en.json');
const es = require('../content/es.json');

const HTTP_PATTERN = /https?:\/\//i;
const M4_REQUIRED_LINE =
  'We will never ask for your password, one-time codes, or full card number by email, text, or phone.';

function wordCount(text) {
  return text.trim().split(/\s+/).filter(Boolean).length;
}

describe('content integrity (test 16)', () => {
  test('both locale files load and expose a messages array', () => {
    expect(Array.isArray(en.messages)).toBe(true);
    expect(Array.isArray(es.messages)).toBe(true);
    expect(en.messages.length).toBeGreaterThan(0);
  });

  test('every id in en.json is present in es.json and vice versa', () => {
    const enIds = en.messages.map((m) => m.id).sort();
    const esIds = es.messages.map((m) => m.id).sort();
    expect(esIds).toEqual(enIds);
  });

  test('m4 in en.json contains the exact "We will never ask" line', () => {
    const m4 = en.messages.find((m) => m.id === 'm4');
    expect(m4).toBeDefined();
    expect(m4.body).toContain(M4_REQUIRED_LINE);
  });

  describe.each([
    ['en', en],
    ['es', es],
  ])('locale %s', (locale, data) => {
    test.each(data.messages.map((m) => [m.id, m]))(
      '%s: body <= max words, FK grade <= max, has >=1 action, no http(s)',
      (id, message) => {
        // >= 1 action
        expect(Array.isArray(message.actions)).toBe(true);
        expect(message.actions.length).toBeGreaterThanOrEqual(1);

        // body word count
        expect(wordCount(message.body)).toBeLessThanOrEqual(config.MAX_BODY_WORDS);

        // Flesch-Kincaid grade (text-readability package)
        const fk = rs.fleschKincaidGrade(message.body);
        expect(fk).toBeLessThanOrEqual(config.MAX_FK_GRADE);

        // no http(s) anywhere in title or body
        expect(HTTP_PATTERN.test(message.body)).toBe(false);
        expect(HTTP_PATTERN.test(message.title)).toBe(false);
      }
    );
  });

  test('required content set is present (m1-m6 standard, r1-r4 risk_event)', () => {
    const byId = new Map(en.messages.map((m) => [m.id, m]));
    for (const id of ['m1', 'm2', 'm3', 'm4', 'm5', 'm6']) {
      expect(byId.get(id).class).toBe(config.MESSAGE_CLASS.STANDARD);
    }
    for (const id of ['r1', 'r2', 'r3', 'r4']) {
      expect(byId.get(id).class).toBe(config.MESSAGE_CLASS.RISK_EVENT);
      // each risk message has an act_now action and a dismissal
      expect(byId.get(id).actions).toContain('act_now');
      expect(byId.get(id).actions).toContain('acknowledge_dismiss');
    }
  });

  test('content directory path is stable', () => {
    // sanity: files resolve from the expected location
    expect(path.basename(require.resolve('../content/en.json'))).toBe('en.json');
  });
});