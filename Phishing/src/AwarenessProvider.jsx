'use strict';

import { createContext, useContext, useEffect, useRef, useState } from 'react';
import messagingConfig from '../messagingConfig';
import { useAwareness } from './useAwareness';
import { AwarenessBanner } from './AwarenessBanner';
import { AwarenessModal } from './AwarenessModal';
import { ReportPhishingForm } from './ReportPhishingForm';

const AwarenessContext = createContext(null);

export function useAwarenessContext() {
  return useContext(AwarenessContext);
}

/**
 * Orchestrates awareness delivery. Given a `trigger` (and userId), it asks the
 * server for the next message and renders it as a banner or modal, wires up the
 * action buttons, the report form, and the aria-live confirmation.
 *
 * The client owns NO frequency logic — it only presents what the server sends.
 * Presentation (modal vs banner) is a pure UI decision based on the message
 * class and the trigger.
 */
export function AwarenessProvider({
  userId,
  trigger,
  locale = 'en',
  apiBase = '',
  onNavigate = () => {},
  children,
}) {
  const api = useAwareness(apiBase);
  const [message, setMessage] = useState(null);
  const [presentation, setPresentation] = useState('banner');
  const [reportOpen, setReportOpen] = useState(false);
  const [confirmation, setConfirmation] = useState('');
  const messageRef = useRef(null);
  messageRef.current = message;

  function decidePresentation(msg, activeTrigger) {
    const isRisk = msg.class === messagingConfig.MESSAGE_CLASS.RISK_EVENT;
    const isModalTrigger = messagingConfig.MODAL_TRIGGERS.includes(activeTrigger);
    return isRisk || isModalTrigger ? 'modal' : 'banner';
  }

  useEffect(() => {
    let cancelled = false;
    async function run() {
      setConfirmation('');
      setReportOpen(false);
      if (!userId || !trigger) {
        setMessage(null);
        return;
      }
      const next = await api.fetchNext(userId, trigger, locale);
      if (cancelled) return;
      if (!next) {
        setMessage(null);
        return;
      }
      setMessage(next);
      setPresentation(decidePresentation(next, trigger));
      api.sendEvent(userId, next.id, 'shown');
    }
    run();
    return () => {
      cancelled = true;
    };
  }, [userId, trigger, locale, api]);

  function clearMessage() {
    setMessage(null);
  }

  function handleAction(action) {
    const current = messageRef.current;
    if (!current) return;
    switch (action) {
      case 'acknowledge_dismiss':
        api.sendEvent(userId, current.id, 'dismissed');
        clearMessage();
        break;
      case 'report_phishing':
        api.sendEvent(userId, current.id, 'cta_clicked');
        setReportOpen(true);
        break;
      case 'go_to_security_settings':
        api.sendEvent(userId, current.id, 'cta_clicked');
        onNavigate('security_settings');
        clearMessage();
        break;
      case 'act_now':
        api.sendEvent(userId, current.id, 'cta_clicked');
        onNavigate('password_change');
        clearMessage();
        break;
      default:
        break;
    }
  }

  async function handleReportSubmit({ channel, note }) {
    const current = messageRef.current;
    const result = await api.submitReport(userId, channel, note);
    if (current) {
      api.sendEvent(userId, current.id, 'reported');
    }
    setConfirmation(
      (result && result.message) ||
        'Thanks for reporting. Our security team has received this.'
    );
    setReportOpen(false);
    clearMessage();
  }

  function handleReportCancel() {
    setReportOpen(false);
  }

  const showBanner = message && !reportOpen && presentation === 'banner';
  const showModal = message && !reportOpen && presentation === 'modal';

  return (
    <AwarenessContext.Provider value={{ activeMessage: message }}>
      {children}
      {showBanner && (
        <AwarenessBanner message={message} onAction={handleAction} />
      )}
      {showModal && (
        <AwarenessModal
          message={message}
          onAction={handleAction}
          onClose={() => handleAction('acknowledge_dismiss')}
        />
      )}
      {reportOpen && (
        <ReportPhishingForm
          onSubmit={handleReportSubmit}
          onCancel={handleReportCancel}
        />
      )}
      {confirmation ? (
        <div role="status" aria-live="polite" data-testid="report-confirmation">
          {confirmation}
        </div>
      ) : null}
    </AwarenessContext.Provider>
  );
}