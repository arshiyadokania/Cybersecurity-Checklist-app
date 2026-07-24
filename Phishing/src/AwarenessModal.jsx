'use strict';

import { useEffect, useRef } from 'react';
import { labelFor } from './actionLabels';
import styles from './AwarenessModal.module.css';

const FOCUSABLE =
  'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

/**
 * Modal presentation (for new_payee_or_transfer_setup and risk-event triggers).
 * Implements a focus trap, Escape-to-close, and focus return to the invoker.
 */
export function AwarenessModal({ message, onAction, onClose }) {
  const dialogRef = useRef(null);
  const previouslyFocused = useRef(null);

  useEffect(() => {
    previouslyFocused.current = document.activeElement;
    const node = dialogRef.current;

    const getFocusable = () => Array.from(node.querySelectorAll(FOCUSABLE));
    const first = getFocusable()[0];
    if (first) first.focus();

    function onKeyDown(event) {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key === 'Tab') {
        const items = getFocusable();
        if (items.length === 0) return;
        const firstEl = items[0];
        const lastEl = items[items.length - 1];
        if (event.shiftKey && document.activeElement === firstEl) {
          event.preventDefault();
          lastEl.focus();
        } else if (!event.shiftKey && document.activeElement === lastEl) {
          event.preventDefault();
          firstEl.focus();
        }
      }
    }

    node.addEventListener('keydown', onKeyDown);
    return () => {
      node.removeEventListener('keydown', onKeyDown);
      // Return focus to whatever invoked the modal.
      const prev = previouslyFocused.current;
      if (prev && typeof prev.focus === 'function') {
        prev.focus();
      }
    };
  }, [onClose]);

  return (
    <div className={styles.overlay} data-testid="modal-overlay">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={message.title}
        data-testid="awareness-modal"
        data-message-id={message.id}
        data-message-class={message.class}
        className={styles.modal}
      >
        <h2 className={styles.title}>{message.title}</h2>
        <p className={styles.body}>{message.body}</p>
        <div className={styles.actions}>
          {message.actions.map((action) => (
            <button
              key={action}
              type="button"
              className={styles.action}
              data-action={action}
              onClick={() => onAction(action)}
            >
              {labelFor(action)}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}