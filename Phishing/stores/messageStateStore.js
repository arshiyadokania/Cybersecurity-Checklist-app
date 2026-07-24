'use strict';

/**
 * MessageStateStore: all per-user frequency / anti-fatigue / priority-queue
 * state. THIS is where every frequency decision is enforced — never the client.
 *
 * An injected now() clock (epoch ms) is required so tests advance a virtual
 * clock instead of sleeping. The in-memory Map implementation is for the demo;
 * production would back this with Redis/Postgres behind the same interface.
 */

const config = require('../messagingConfig');

function createUserState() {
  return {
    // Anti-fatigue (standard messages).
    sessionStandardCount: 0,
    lastStandardShownAt: null,
    standardHistory: [], // ordered list of shown standard ids (oldest first)
    // Per-message dismissal tracking.
    messages: new Map(), // id -> { dismissCount, suppressedUntil, shownCount, lastShownAt }
    // Risk-event priority queue (FIFO among equal-priority risk events).
    riskQueue: [],
    // Urgent campaign tracking.
    seenCampaigns: new Set(),
    urgentDayBucket: null,
    urgentDayCount: 0,
  };
}

class MessageStateStore {
  /**
   * @param {object} [options]
   * @param {() => number} [options.now] injected clock (epoch ms)
   */
  constructor(options = {}) {
    this.now = options.now || Date.now;
    this._users = new Map();
  }

  _user(userId) {
    let u = this._users.get(userId);
    if (!u) {
      u = createUserState();
      this._users.set(userId, u);
    }
    return u;
  }

  _message(userId, messageId) {
    const u = this._user(userId);
    let m = u.messages.get(messageId);
    if (!m) {
      m = { dismissCount: 0, suppressedUntil: null, shownCount: 0, lastShownAt: null };
      u.messages.set(messageId, m);
    }
    return m;
  }

  // --- Session / standard frequency -----------------------------------------
  startSession(userId) {
    this._user(userId).sessionStandardCount = 0;
  }

  isSuppressed(userId, messageId) {
    const m = this._message(userId, messageId);
    return m.suppressedUntil != null && m.suppressedUntil > this.now();
  }

  canShowStandard(userId) {
    const u = this._user(userId);
    if (u.sessionStandardCount >= config.MAX_STANDARD_PER_SESSION) {
      return false;
    }
    if (u.lastStandardShownAt != null) {
      const elapsedHours = (this.now() - u.lastStandardShownAt) / config.HOUR_MS;
      if (elapsedHours < config.MIN_HOURS_BETWEEN_STANDARD) {
        return false;
      }
    }
    return true;
  }

  recordStandardShown(userId, messageId) {
    const u = this._user(userId);
    u.sessionStandardCount += 1;
    u.lastStandardShownAt = this.now();
    u.standardHistory.push(messageId);
    const m = this._message(userId, messageId);
    m.shownCount += 1;
    m.lastShownAt = this.now();
  }

  getStandardHistory(userId) {
    return this._user(userId).standardHistory.slice();
  }

  recordDismiss(userId, messageId) {
    const m = this._message(userId, messageId);
    m.dismissCount += 1;
    if (m.dismissCount >= config.DISMISS_SUPPRESS_THRESHOLD) {
      m.suppressedUntil = this.now() + config.DISMISS_COOLDOWN_DAYS * config.DAY_MS;
    }
    return { dismissCount: m.dismissCount, suppressedUntil: m.suppressedUntil };
  }

  // --- Risk-event priority queue --------------------------------------------
  enqueueRiskEvent(userId, riskItem) {
    this._user(userId).riskQueue.push(riskItem);
  }

  hasRiskEvent(userId) {
    return this._user(userId).riskQueue.length > 0;
  }

  dequeueRiskEvent(userId) {
    return this._user(userId).riskQueue.shift() || null;
  }

  // --- Urgent campaigns ------------------------------------------------------
  hasSeenCampaign(userId, campaignId) {
    return this._user(userId).seenCampaigns.has(campaignId);
  }

  canShowUrgentToday(userId) {
    const u = this._user(userId);
    const bucket = Math.floor(this.now() / config.DAY_MS);
    if (u.urgentDayBucket !== bucket) {
      return true; // new day → count effectively 0
    }
    return u.urgentDayCount < config.MAX_URGENT_PER_DAY;
  }

  recordUrgentShown(userId, campaignId) {
    const u = this._user(userId);
    const bucket = Math.floor(this.now() / config.DAY_MS);
    if (u.urgentDayBucket !== bucket) {
      u.urgentDayBucket = bucket;
      u.urgentDayCount = 0;
    }
    u.urgentDayCount += 1;
    u.seenCampaigns.add(campaignId);
  }
}

module.exports = { MessageStateStore };