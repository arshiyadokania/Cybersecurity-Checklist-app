/** @jest-environment jsdom */
'use strict';

/**
 * Frontend tests (1–6): rendering, dismissal telemetry, the report loop,
 * modal focus management, the no-external-link guarantee, and risk-event modals.
 */

import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { AwarenessProvider } from '../src/AwarenessProvider';
import { AwarenessBanner } from '../src/AwarenessBanner';
import { AwarenessModal } from '../src/AwarenessModal';

const en = require('../content/en.json');
const es = require('../content/es.json');
const m1 = en.messages.find((m) => m.id === 'm1'); // banner, has report_phishing
const r1 = en.messages.find((m) => m.id === 'r1'); // risk_event, has act_now

function makeResponse(status, body) {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => body,
  };
}

function installFetch({
  nextMessage = null,
  reportResponse = { reportId: 'rpt_1', message: 'Thanks for reporting. We received it.' },
} = {}) {
  const calls = [];
  global.fetch = jest.fn((url, options = {}) => {
    calls.push({
      url,
      method: options.method || 'GET',
      body: options.body ? JSON.parse(options.body) : undefined,
    });
    if (url.includes('/api/awareness/next')) {
      return Promise.resolve(
        nextMessage
          ? makeResponse(200, { message: nextMessage })
          : makeResponse(204, null)
      );
    }
    if (url.includes('/api/awareness/event')) {
      return Promise.resolve(makeResponse(202, { status: 'recorded' }));
    }
    if (url.includes('/api/awareness/report')) {
      return Promise.resolve(makeResponse(202, reportResponse));
    }
    return Promise.resolve(makeResponse(404, {}));
  });
  return calls;
}

afterEach(() => {
  delete global.fetch;
  jest.restoreAllMocks();
});

describe('frontend', () => {
  // 1
  test('trigger renders the returned message', async () => {
    installFetch({ nextMessage: m1 });
    render(<AwarenessProvider userId="u1" trigger="login_success" />);
    expect(await screen.findByText(m1.title)).toBeInTheDocument();
    expect(screen.getByText(m1.body)).toBeInTheDocument();
  });

  test('204 renders nothing in the DOM', async () => {
    const calls = installFetch({ nextMessage: null });
    render(<AwarenessProvider userId="u1" trigger="login_success" />);
    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/api/awareness/next'))).toBe(true)
    );
    expect(screen.queryByTestId('awareness-banner')).toBeNull();
    expect(screen.queryByTestId('awareness-modal')).toBeNull();
  });

  // 2
  test('dismiss fires "dismissed" telemetry and removes the message', async () => {
    const user = userEvent.setup();
    const calls = installFetch({ nextMessage: m1 });
    render(<AwarenessProvider userId="u1" trigger="login_success" />);
    await screen.findByText(m1.title);

    await user.click(screen.getByRole('button', { name: 'Dismiss' }));

    await waitFor(() => expect(screen.queryByText(m1.title)).toBeNull());
    const dismissed = calls.find(
      (c) => c.url.includes('/api/awareness/event') && c.body && c.body.action === 'dismissed'
    );
    expect(dismissed).toBeTruthy();
    expect(dismissed.body.messageId).toBe('m1');
  });

  // 3
  test('report flow: button → form → submit → POST /report → confirmation announced', async () => {
    const user = userEvent.setup();
    const calls = installFetch({
      nextMessage: m1,
      reportResponse: { reportId: 'rpt_9', message: 'Thanks for reporting. We received it.' },
    });
    render(<AwarenessProvider userId="u1" trigger="login_success" />);
    await screen.findByText(m1.title);

    await user.click(screen.getByRole('button', { name: 'Report phishing' }));

    const form = await screen.findByTestId('report-form');
    await user.selectOptions(within(form).getByRole('combobox'), 'sms');
    await user.type(within(form).getByRole('textbox'), 'got a fake text');
    await user.click(within(form).getByRole('button', { name: 'Send report' }));

    const confirmation = await screen.findByTestId('report-confirmation');
    expect(confirmation).toHaveAttribute('aria-live', 'polite');
    expect(confirmation).toHaveTextContent('received');

    const reportCall = calls.find(
      (c) => c.url.includes('/api/awareness/report') && c.method === 'POST'
    );
    expect(reportCall).toBeTruthy();
    expect(reportCall.body).toMatchObject({
      userId: 'u1',
      channel: 'sms',
      note: 'got a fake text',
    });

    const reported = calls.find(
      (c) => c.url.includes('/api/awareness/event') && c.body && c.body.action === 'reported'
    );
    expect(reported).toBeTruthy();
  });

  // 4
  test('modal: focus trap, Escape closes, focus returns to invoker', async () => {
    const user = userEvent.setup();
    installFetch({ nextMessage: r1 }); // risk_event → modal

    function Harness() {
      const [trigger, setTrigger] = React.useState(null);
      return (
        <div>
          <button type="button" onClick={() => setTrigger('login_success')}>
            open
          </button>
          <AwarenessProvider userId="u1" trigger={trigger} />
        </div>
      );
    }

    render(<Harness />);
    const opener = screen.getByRole('button', { name: 'open' });
    opener.focus();
    await user.click(opener);

    const modal = await screen.findByTestId('awareness-modal');
    const firstButton = within(modal).getAllByRole('button')[0];
    await waitFor(() => expect(firstButton).toHaveFocus());

    // Focus trap: Tab from the last element wraps back to the first.
    const buttons = within(modal).getAllByRole('button');
    buttons[buttons.length - 1].focus();
    await user.tab();
    expect(firstButton).toHaveFocus();

    // Escape closes and returns focus to the invoker.
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByTestId('awareness-modal')).toBeNull());
    expect(opener).toHaveFocus();
  });

  // 5
  test('no external <a href> across ALL messages in both locales', () => {
    const allMessages = [...en.messages, ...es.messages];
    for (const message of allMessages) {
      const banner = render(<AwarenessBanner message={message} onAction={() => {}} />);
      expect(banner.container.querySelectorAll('a').length).toBe(0);
      expect(/https?:\/\//i.test(banner.container.textContent)).toBe(false);
      banner.unmount();

      const modal = render(
        <AwarenessModal message={message} onAction={() => {}} onClose={() => {}} />
      );
      expect(modal.container.querySelectorAll('a').length).toBe(0);
      expect(/https?:\/\//i.test(modal.container.textContent)).toBe(false);
      modal.unmount();
    }
  });

  // 6
  test('risk-event message renders as a modal with an act_now action', async () => {
    installFetch({ nextMessage: r1 });
    render(<AwarenessProvider userId="u1" trigger="login_success" />);

    const modal = await screen.findByTestId('awareness-modal');
    expect(modal).toHaveAttribute('role', 'dialog');
    expect(modal).toHaveAttribute('aria-modal', 'true');
    expect(
      within(modal).getByRole('button', { name: 'Change password now' })
    ).toBeInTheDocument();
  });
});