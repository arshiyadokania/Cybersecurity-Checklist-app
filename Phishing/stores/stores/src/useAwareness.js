'use strict';

import { useMemo } from 'react';

/**
 * useAwareness: thin client for the awareness API.
 *
 * IMPORTANT: the client implements NO frequency logic. It only calls the
 * server, which is the single authority on what to show and when. This hook
 * exposes fetchNext / sendEvent / submitReport and nothing else.
 *
 * @param {string} [apiBase] base URL for the API (default same origin)
 */
export function useAwareness(apiBase = '') {
  return useMemo(() => {
    async function fetchNext(userId, trigger, locale = 'en') {
      const params = new URLSearchParams({ userId, trigger, locale });
      const res = await fetch(`${apiBase}/api/awareness/next?${params.toString()}`);
      if (res.status === 204) return null;
      if (!res.ok) return null;
      const data = await res.json();
      return data.message || null;
    }

    async function sendEvent(userId, messageId, action) {
      // Telemetry is best-effort; never block the UI on it.
      try {
        await fetch(`${apiBase}/api/awareness/event`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userId, messageId, action }),
        });
      } catch (err) {
        /* swallow: telemetry must never break the experience */
      }
    }

    async function submitReport(userId, channel, note) {
      const res = await fetch(`${apiBase}/api/awareness/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, channel, note }),
      });
      const data = await res.json();
      return data;
    }

    return { fetchNext, sendEvent, submitReport };
  }, [apiBase]);
}