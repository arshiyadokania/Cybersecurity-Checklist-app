'use strict';

/**
 * Human-readable labels for action buttons. Labels name the DESTINATION for
 * navigation actions (design rule 2): no button says "verify", and no message
 * uses a clickable external link — navigation is always an in-app router button.
 */
export const ACTION_LABELS = {
  report_phishing: 'Report phishing',
  go_to_security_settings: 'Go to security settings',
  acknowledge_dismiss: 'Dismiss',
  act_now: 'Change password now',
};

export function labelFor(action) {
  return ACTION_LABELS[action] || action;
}