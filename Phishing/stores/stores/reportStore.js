'use strict';

/**
 * ReportStore: persists phishing reports submitted by users. The report loop is
 * the whole point of the system, so reports are first-class records.
 *
 * In-memory Map implementation for the demo; production would route these into
 * a durable queue consumed by the SOC (see README "Production hardening").
 */

const crypto = require('crypto');

class ReportStore {
  /**
   * @param {object} [options]
   * @param {() => number} [options.now] injected clock (epoch ms)
   */
  constructor(options = {}) {
    this.now = options.now || Date.now;
    this._reports = new Map(); // reportId -> report
  }

  /**
   * @param {object} input
   * @param {string} input.userId opaque user id (only PII we keep)
   * @param {string} input.channel one of the valid channels
   * @param {string} [input.note] optional free-text note
   * @returns {object} the stored report including its generated reportId
   */
  save({ userId, channel, note }) {
    const reportId = `rpt_${crypto.randomUUID()}`;
    const report = {
      reportId,
      userId,
      channel,
      note: note || null,
      timestamp: new Date(this.now()).toISOString(),
    };
    this._reports.set(reportId, report);
    return report;
  }

  get(reportId) {
    return this._reports.get(reportId) || null;
  }

  list() {
    return Array.from(this._reports.values());
  }

  count() {
    return this._reports.size;
  }
}

module.exports = { ReportStore };