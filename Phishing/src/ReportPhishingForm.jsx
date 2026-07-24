'use strict';

import { useEffect, useRef, useState } from 'react';
import messagingConfig from '../messagingConfig';
import styles from './ReportPhishingForm.module.css';

const CHANNEL_OPTIONS = [
  { value: 'email', label: 'Email' },
  { value: 'sms', label: 'Text message' },
  { value: 'call', label: 'Phone call' },
  { value: 'other', label: 'Other' },
];

/**
 * Minimal in-app phishing report form: channel select + optional note.
 * Submitting fires the report endpoint (via the provider's onSubmit). No
 * external links; keyboard-reachable; the note is capped to the server limit.
 */
export function ReportPhishingForm({ onSubmit, onCancel }) {
  const [channel, setChannel] = useState('email');
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const firstFieldRef = useRef(null);

  useEffect(() => {
    if (firstFieldRef.current) firstFieldRef.current.focus();
  }, []);

  async function handleSubmit(event) {
    event.preventDefault();
    setSubmitting(true);
    await onSubmit({ channel, note: note.trim() ? note.trim() : undefined });
    setSubmitting(false);
  }

  return (
    <form
      className={styles.form}
      onSubmit={handleSubmit}
      aria-label="Report phishing"
      data-testid="report-form"
    >
      <label htmlFor="pa-report-channel">How did they contact you?</label>
      <select
        id="pa-report-channel"
        ref={firstFieldRef}
        value={channel}
        onChange={(event) => setChannel(event.target.value)}
      >
        {CHANNEL_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      <label htmlFor="pa-report-note">Add a note (optional)</label>
      <textarea
        id="pa-report-note"
        value={note}
        maxLength={messagingConfig.MAX_REPORT_NOTE_LENGTH}
        onChange={(event) => setNote(event.target.value)}
      />

      <div className={styles.actions}>
        <button type="submit" disabled={submitting}>
          Send report
        </button>
        <button type="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}