'use strict';

/**
 * Express server for the phishing-awareness messaging system.
 *
 * The server is the SINGLE authority on frequency, priority and eligibility.
 * `createServer` is a factory so tests can inject a virtual clock and fresh
 * stores. Running this file directly loads and validates content, exiting the
 * process if the content is malformed (it never serves partial content).
 *
 * Priority queue per user:  risk_event > urgent > standard.
 */

const fs = require('fs');
const path = require('path');
const express = require('express');

const config = require('./messagingConfig');
const { selectNextMessage } = require('./selectNextMessage');
const { MessageStateStore } = require('./stores/messageStateStore');
const { ReportStore } = require('./stores/reportStore');
const { UserProfileStore } = require('./stores/userProfileStore');

const HTTP_URL_PATTERN = /https?:\/\//i;

// ---------------------------------------------------------------------------
// Content loading + validation (the "config loader")
// ---------------------------------------------------------------------------

function validateMessage(message, locale) {
  const where = `content/${locale}.json message ${message && message.id}`;
  if (!message || typeof message !== 'object') {
    throw new Error(`${where}: message must be an object`);
  }
  for (const field of ['id', 'title', 'body', 'class']) {
    if (typeof message[field] !== 'string' || message[field].length === 0) {
      throw new Error(`${where}: missing or invalid "${field}"`);
    }
  }
  if (!Array.isArray(message.actions) || message.actions.length < 1) {
    throw new Error(`${where}: every message must carry at least one action`);
  }
  for (const action of message.actions) {
    if (!config.MESSAGE_ACTIONS.includes(action)) {
      throw new Error(`${where}: unknown action "${action}"`);
    }
  }
  if (HTTP_URL_PATTERN.test(message.body) || HTTP_URL_PATTERN.test(message.title)) {
    throw new Error(`${where}: content must not contain http(s) links`);
  }
  if (!Array.isArray(message.triggerAffinity)) {
    throw new Error(`${where}: triggerAffinity must be an array`);
  }
}

function parseLocaleFile(filePath, locale) {
  const raw = fs.readFileSync(filePath, 'utf8');
  // JSON.parse throws on malformed JSON — we let it propagate so startup fails.
  const data = JSON.parse(raw);
  if (!data || !Array.isArray(data.messages)) {
    throw new Error(`content/${locale}.json: missing "messages" array`);
  }
  const byId = new Map();
  for (const message of data.messages) {
    validateMessage(message, locale);
    if (byId.has(message.id)) {
      throw new Error(`content/${locale}.json: duplicate id "${message.id}"`);
    }
    byId.set(message.id, message);
  }
  return { locale, list: data.messages, byId };
}

/**
 * Load and validate both locale files from a directory. Throws on any malformed
 * or invalid content so the caller can refuse to serve partial content.
 *
 * @param {string} contentDir directory containing en.json and es.json
 * @returns {{en: object, es: object}}
 */
function loadContent(contentDir) {
  const en = parseLocaleFile(path.join(contentDir, 'en.json'), 'en');
  const es = parseLocaleFile(path.join(contentDir, 'es.json'), 'es');

  // Cross-locale integrity: es must have every id en has.
  for (const id of en.byId.keys()) {
    if (!es.byId.has(id)) {
      throw new Error(`content/es.json: missing id "${id}" present in en.json`);
    }
  }
  return { en, es };
}

// ---------------------------------------------------------------------------
// Server factory
// ---------------------------------------------------------------------------

/**
 * @param {object} [options]
 * @param {{en:object, es:object}} [options.content] pre-loaded content
 * @param {string} [options.contentDir] directory to load content from
 * @param {MessageStateStore} [options.messageStateStore]
 * @param {ReportStore} [options.reportStore]
 * @param {UserProfileStore} [options.userProfileStore]
 * @param {() => number} [options.now] injected clock (epoch ms)
 */
function createServer(options = {}) {
  const now = options.now || Date.now;
  const content =
    options.content || loadContent(options.contentDir || path.join(__dirname, 'content'));

  const messageStateStore =
    options.messageStateStore || new MessageStateStore({ now });
  const reportStore = options.reportStore || new ReportStore({ now });
  const userProfileStore = options.userProfileStore || new UserProfileStore();

  // Urgent campaigns live in a simple in-memory map for the demo.
  const campaigns = new Map(); // id -> campaign message

  function localeContent(locale) {
    return content[locale] || content.en;
  }

  function riskMessageFor(type, locale) {
    const id = config.RISK_EVENT_MESSAGE_MAP[type];
    return localeContent(locale).byId.get(id) || null;
  }

  function eligibleUrgentCampaign(userId) {
    for (const campaign of campaigns.values()) {
      if (campaign.expiresAt <= now()) continue; // expired
      if (messageStateStore.hasSeenCampaign(userId, campaign.id)) continue;
      return campaign;
    }
    return null;
  }

  const app = express();
  app.use(express.json());

  // Malformed request JSON → 400.
  app.use((err, req, res, next) => {
    if (err && err.type === 'entity.parse.failed') {
      return res.status(400).json({ error: 'Malformed JSON' });
    }
    return next(err);
  });

  // --- GET /api/awareness/next ----------------------------------------------
  app.get('/api/awareness/next', (req, res) => {
    const userId = req.query.userId;
    const trigger = req.query.trigger;
    const locale = req.query.locale === 'es' ? 'es' : 'en';

    if (!userId || !trigger) {
      return res.status(400).json({ error: 'userId and trigger are required' });
    }

    // Priority 1: risk events bypass ALL anti-fatigue counters.
    if (messageStateStore.hasRiskEvent(userId)) {
      const item = messageStateStore.dequeueRiskEvent(userId);
      const message = riskMessageFor(item.type, locale);
      if (message) {
        return res.status(200).json({ message });
      }
    }

    // Priority 2: urgent campaigns (bypass standard caps, own daily cap).
    if (messageStateStore.canShowUrgentToday(userId)) {
      const campaign = eligibleUrgentCampaign(userId);
      if (campaign) {
        messageStateStore.recordUrgentShown(userId, campaign.id);
        return res.status(200).json({ message: campaign });
      }
    }

    // Priority 3: standard messages, subject to anti-fatigue.
    if (trigger === config.SESSION_RESET_TRIGGER) {
      messageStateStore.startSession(userId);
    }

    if (!messageStateStore.canShowStandard(userId)) {
      return res.status(204).end();
    }

    const eligible = localeContent(locale).list.filter(
      (m) =>
        m.class === config.MESSAGE_CLASS.STANDARD &&
        m.triggerAffinity.includes(trigger) &&
        !messageStateStore.isSuppressed(userId, m.id)
    );

    if (eligible.length === 0) {
      return res.status(204).end();
    }

    const profile = userProfileStore.get(userId);
    const history = messageStateStore.getStandardHistory(userId);
    const message = selectNextMessage(profile, history, eligible);

    if (!message) {
      return res.status(204).end();
    }

    messageStateStore.recordStandardShown(userId, message.id);
    return res.status(200).json({ message });
  });

  // --- POST /api/awareness/event (telemetry) --------------------------------
  app.post('/api/awareness/event', (req, res) => {
    const { userId, messageId, action } = req.body || {};
    if (!userId || !action) {
      return res.status(400).json({ error: 'userId and action are required' });
    }
    if (!config.TELEMETRY_ACTIONS.includes(action)) {
      return res.status(400).json({ error: 'unknown telemetry action' });
    }
    if (action === 'dismissed' && messageId) {
      messageStateStore.recordDismiss(userId, messageId);
    }
    return res.status(202).json({ status: 'recorded' });
  });

  // --- POST /api/awareness/report -------------------------------------------
  app.post('/api/awareness/report', (req, res) => {
    const { userId, channel, note } = req.body || {};
    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }
    if (!config.VALID_CHANNELS.includes(channel)) {
      return res.status(400).json({ error: 'invalid channel' });
    }
    if (note != null) {
      if (typeof note !== 'string' || note.length > config.MAX_REPORT_NOTE_LENGTH) {
        return res.status(400).json({ error: 'note too long' });
      }
    }
    const report = reportStore.save({ userId, channel, note });
    return res.status(202).json({
      reportId: report.reportId,
      message:
        'Thanks for reporting. Our security team has received this and will review it.',
    });
  });

  // --- POST /api/risk-event (internal demo) ---------------------------------
  app.post('/api/risk-event', (req, res) => {
    const { userId, type } = req.body || {};
    if (!userId || !config.RISK_EVENT_TRIGGERS.includes(type)) {
      return res.status(400).json({ error: 'valid userId and risk type required' });
    }
    messageStateStore.enqueueRiskEvent(userId, { type });
    return res.status(202).json({ status: 'queued' });
  });

  // --- POST /api/awareness/campaign (admin demo) ----------------------------
  app.post('/api/awareness/campaign', (req, res) => {
    const { id, title, body, expiresAt } = req.body || {};
    if (
      typeof id !== 'string' ||
      typeof title !== 'string' ||
      typeof body !== 'string' ||
      expiresAt == null
    ) {
      return res.status(400).json({ error: 'id, title, body, expiresAt are required' });
    }
    const expiresAtMs =
      typeof expiresAt === 'number' ? expiresAt : Date.parse(expiresAt);
    if (Number.isNaN(expiresAtMs)) {
      return res.status(400).json({ error: 'expiresAt is invalid' });
    }
    if (HTTP_URL_PATTERN.test(body) || HTTP_URL_PATTERN.test(title)) {
      return res.status(400).json({ error: 'content must not contain http(s) links' });
    }
    const wordCount = body.trim().split(/\s+/).filter(Boolean).length;
    if (wordCount > config.MAX_BODY_WORDS) {
      return res.status(400).json({ error: 'body exceeds max words' });
    }

    const campaign = {
      id,
      title,
      body,
      class: config.MESSAGE_CLASS.URGENT,
      priority: config.PRIORITY.urgent,
      expiresAt: expiresAtMs,
      // Urgent messages always carry a report_phishing action (design rule 3).
      actions: ['report_phishing', 'acknowledge_dismiss'],
      triggerAffinity: [],
    };
    campaigns.set(id, campaign);
    return res.status(201).json({ message: campaign });
  });

  // --- GET /api/awareness/reports (admin demo) ------------------------------
  app.get('/api/awareness/reports', (req, res) => {
    return res.status(200).json({ reports: reportStore.list() });
  });

  // Expose internals for tests/inspection.
  app.locals.stores = { messageStateStore, reportStore, userProfileStore };
  app.locals.campaigns = campaigns;
  app.locals.content = content;
  return app;
}

// ---------------------------------------------------------------------------
// Standalone startup: refuse to serve partial content.
// ---------------------------------------------------------------------------
if (require.main === module) {
  let content;
  try {
    content = loadContent(path.join(__dirname, 'content'));
  } catch (err) {
    process.stderr.write(
      JSON.stringify({ event: 'content_load_failed', message: err.message }) + '\n'
    );
    process.exit(1);
  }
  const app = createServer({ content });
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    process.stdout.write(
      JSON.stringify({ event: 'server_started', port: Number(port) }) + '\n'
    );
  });
}

module.exports = { createServer, loadContent, validateMessage };