'use strict';

/**
 * selectNextMessage: pure, deterministic message selection.
 *
 * Given a user's segmentation profile, their standard-message show history, and
 * the list of currently eligible standard messages, choose the next message.
 *
 * Deterministic — NO Math.random — so tests can assert exact selection.
 *
 * Weighting rules (in order):
 *   - accountAgeDays < NEW_ACCOUNT_AGE_DAYS  → prefer m1, m2 first
 *   - recentContactChange                    → prefer m4, m5 first
 *   - priorDismissRate > HIGH_DISMISS_RATE   → tie-break toward shorter bodies
 *   - otherwise                              → round-robin (least recently shown)
 *
 * @param {object} profile  { accountAgeDays, recentContactChange, priorReports, priorDismissRate }
 * @param {string[]} history ordered list of previously shown standard ids (oldest first)
 * @param {Array<{id:string, body:string}>} eligible currently eligible standard messages
 * @returns {object|null} the selected message, or null if none eligible
 */

const config = require('./messagingConfig');

function bodyWordCount(message) {
  return message.body.trim().split(/\s+/).filter(Boolean).length;
}

function selectNextMessage(profile, history, eligible) {
  if (!Array.isArray(eligible) || eligible.length === 0) {
    return null;
  }

  const p = profile || {};
  const hist = Array.isArray(history) ? history : [];

  // 1. Segmentation preference: build an ordered list of preferred ids.
  let preferredIds = [];
  if ((p.accountAgeDays != null ? p.accountAgeDays : Infinity) < config.NEW_ACCOUNT_AGE_DAYS) {
    preferredIds = ['m1', 'm2'];
  } else if (p.recentContactChange) {
    preferredIds = ['m4', 'm5'];
  }

  const preferredPool = preferredIds
    .map((id) => eligible.find((m) => m.id === id))
    .filter(Boolean);

  // If none of the preferred ids are eligible, fall back to the full pool.
  const pool = preferredPool.length > 0 ? preferredPool : eligible.slice();

  const highDismiss = (p.priorDismissRate || 0) > config.HIGH_DISMISS_RATE_THRESHOLD;

  // 2. Round-robin: rank by how recently each message was last shown.
  //    Never-shown (-1) sorts first; among shown, the least-recently-shown wins.
  const ranked = pool.map((message, originalIndex) => ({
    message,
    originalIndex,
    lastShownRank: hist.lastIndexOf(message.id), // -1 if never shown
    words: bodyWordCount(message),
  }));

  ranked.sort((a, b) => {
    if (a.lastShownRank !== b.lastShownRank) {
      return a.lastShownRank - b.lastShownRank; // older / never-shown first
    }
    // 3. Tie-break: shorter body first for high-dismiss users.
    if (highDismiss && a.words !== b.words) {
      return a.words - b.words;
    }
    // Otherwise stable: preserve preference / eligibility order.
    return a.originalIndex - b.originalIndex;
  });

  return ranked[0].message;
}

module.exports = { selectNextMessage, bodyWordCount };