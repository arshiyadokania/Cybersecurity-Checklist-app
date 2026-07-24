'use strict';

import messagingConfig from '../messagingConfig';
import { labelFor } from './actionLabels';
import styles from './AwarenessBanner.module.css';

/**
 * Banner presentation. Rendered only on trigger delivery — never a permanent
 * banner. role="status" + aria-live="polite" so screen readers announce it
 * without stealing focus. All interactive elements are buttons (no <a href>),
 * keyboard-reachable by default.
 */
export function AwarenessBanner({ message, onAction }) {
  const isUrgent = message.class === messagingConfig.MESSAGE_CLASS.URGENT;
  return (
    <section
      role="status"
      aria-live="polite"
      data-testid="awareness-banner"
      data-message-id={message.id}
      data-message-class={message.class}
      className={isUrgent ? styles.urgent : styles.banner}
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
    </section>
  );
}