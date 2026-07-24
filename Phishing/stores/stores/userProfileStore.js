'use strict';

/**
 * UserProfileStore: per-user segmentation profile used by selectNextMessage.
 *
 * In-memory Map implementation for the demo. Unknown users get a safe default
 * profile (established account, no recent contact change, no dismissals) so the
 * selector falls back to plain round-robin.
 */

function defaultProfile() {
  return {
    accountAgeDays: Number.MAX_SAFE_INTEGER,
    recentContactChange: false,
    priorReports: 0,
    priorDismissRate: 0,
  };
}

class UserProfileStore {
  constructor() {
    this._profiles = new Map();
  }

  get(userId) {
    return this._profiles.get(userId) || defaultProfile();
  }

  set(userId, profile) {
    this._profiles.set(userId, { ...defaultProfile(), ...profile });
    return this.get(userId);
  }

  has(userId) {
    return this._profiles.has(userId);
  }
}

module.exports = { UserProfileStore, defaultProfile };