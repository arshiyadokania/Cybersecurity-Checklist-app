'use strict';

/**
 * Central configuration for the phishing-awareness messaging system.
 *
 * ALL frequency logic, thresholds, enums and content constraints live here so
 * there are no magic numbers anywhere else in the codebase. The server is the
 * single authority on frequency; the client never implements any of this.
 */

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

const messagingConfig = Object.freeze({
  // --- Anti-fatigue policy (STANDARD messages only) --------------------------
  MAX_STANDARD_PER_SESSION: 1,
  MIN_HOURS_BETWEEN_STANDARD: 24,
  DISMISS_COOLDOWN_DAYS: 30,
  // A message dismissed this many times enters the cooldown suppression.
  DISMISS_SUPPRESS_THRESHOLD: 2,

  // --- Urgent campaign policy (Phase 3) --------------------------------------
  MAX_URGENT_PER_DAY: 1,

  // --- Report policy ---------------------------------------------------------
  MAX_REPORT_NOTE_LENGTH: 500,

  // --- Content constraints (enforced by the content test) --------------------
  MAX_BODY_WORDS: 60,
  MAX_FK_GRADE: 8,

  // --- Segmentation thresholds (Phase 2) -------------------------------------
  NEW_ACCOUNT_AGE_DAYS: 30,
  HIGH_DISMISS_RATE_THRESHOLD: 0.8,

  // --- Priority queue: risk_event > urgent > standard ------------------------
  PRIORITY: Object.freeze({
    standard: 1,
    urgent: 2,
    risk_event: 3,
  }),

  MESSAGE_CLASS: Object.freeze({
    STANDARD: 'standard',
    URGENT: 'urgent',
    RISK_EVENT: 'risk_event',
  }),

  // --- Triggers --------------------------------------------------------------
  PAGE_TRIGGERS: Object.freeze([
    'login_success',
    'password_change_initiated',
    'email_change_initiated',
    'new_payee_or_transfer_setup',
    'security_settings_viewed',
  ]),

  RISK_EVENT_TRIGGERS: Object.freeze([
    'new_device_login',
    'new_geo_login',
    'unrequested_password_reset',
    'anomalous_transfer_flagged',
  ]),

  // A new login begins a new anti-fatigue session for the user.
  SESSION_RESET_TRIGGER: 'login_success',

  // Triggers that must render as a modal instead of a banner. Risk-event
  // messages are ALSO modal (decided by message class), handled separately.
  MODAL_TRIGGERS: Object.freeze(['new_payee_or_transfer_setup']),

  // --- Enums (strict validation) ---------------------------------------------
  VALID_CHANNELS: Object.freeze(['email', 'sms', 'call', 'other']),
  TELEMETRY_ACTIONS: Object.freeze([
    'shown',
    'dismissed',
    'cta_clicked',
    'reported',
  ]),
  MESSAGE_ACTIONS: Object.freeze([
    'report_phishing',
    'go_to_security_settings',
    'acknowledge_dismiss',
    'act_now',
  ]),

  // Maps a risk-event trigger type to its content message id.
  RISK_EVENT_MESSAGE_MAP: Object.freeze({
    new_device_login: 'r1',
    new_geo_login: 'r2',
    unrequested_password_reset: 'r3',
    anomalous_transfer_flagged: 'r4',
  }),

  // Derived time constants (not magic numbers — computed from the above).
  HOUR_MS,
  DAY_MS,
});

module.exports = messagingConfig;