'use strict';

/**
 * Backend tests (7–15): frequency, rotation, suppression, priority, urgent
 * campaigns, reports, telemetry, and the startup content guard.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');

const config = require('../messagingConfig');
const { createServer, loadContent } = require('../server');
const { MessageStateStore } = require('../stores/messageStateStore');
const { ReportStore } = require('../stores/reportStore');
const { UserProfileStore } = require('../stores/userProfileStore');
const { selectNextMessage } = require('../selectNextMessage');

const content = loadContent(path.join(__dirname, '..', 'content'));

function makeClock(start = 1_700_000_000_000) {
  const s = { t: start };
  return {
    now: () => s.t,
    advanceHours: (h) => {
      s.t += h * config.HOUR_MS;
    },
    advanceDays: (d) => {
      s.t += d * config.DAY_MS;
    },
  };
}

function buildApp() {
  const clock = makeClock();
  const messageStateStore = new MessageStateStore({ now: clock.now });
  const reportStore = new ReportStore({ now: clock.now });
  const userProfileStore = new UserProfileStore();
  const app = createServer({
    content,
    now: clock.now,
    messageStateStore,
    reportStore,
    userProfileStore,
  });
  return { app, clock, messageStateStore, reportStore, userProfileStore };
}

const next = (app, userId, trigger, locale) =>
  request(app)
    .get('/api/awareness/next')
    .query(locale ? { userId, trigger, locale } : { userId, trigger });

describe('backend', () => {
  // 7
  test('standard frequency: session cap, 24h gate, then unlock', async () => {
    const { app, clock } = buildApp();
    const u = 'u-freq';

    const r1 = await next(app, u, 'login_success');
    expect(r1.status).toBe(200);
    expect(r1.body.message.class).toBe('standard');

    // 2nd request in the same session → session cap → 204
    const r2 = await next(app, u, 'security_settings_viewed');
    expect(r2.status).toBe(204);

    // New session within 24h → time gate still blocks → 204
    clock.advanceHours(1);
    const r3 = await next(app, u, 'login_success');
    expect(r3.status).toBe(204);

    // After 24h → 200
    clock.advanceHours(24);
    const r4 = await next(app, u, 'login_success');
    expect(r4.status).toBe(200);
  });

  // 8
  test('rotation returns different ids on consecutive eligible requests', async () => {
    const { app, clock } = buildApp();
    const u = 'u-rot';
    const ids = [];
    for (let i = 0; i < 3; i += 1) {
      const r = await next(app, u, 'login_success');
      expect(r.status).toBe(200);
      ids.push(r.body.message.id);
      clock.advanceHours(25); // pass the 24h gate; login_success resets session
    }
    expect(ids[0]).not.toBe(ids[1]);
    expect(ids[1]).not.toBe(ids[2]);
  });

  // 9
  test('double-dismissed id is suppressed for 30 days', async () => {
    const { app, clock, messageStateStore, userProfileStore } = buildApp();
    const u = 'u-dismiss';
    userProfileStore.set(u, { accountAgeDays: 10 }); // new account prefers m1, m2

    const first = await next(app, u, 'login_success');
    expect(first.body.message.id).toBe('m1');

    await request(app)
      .post('/api/awareness/event')
      .send({ userId: u, messageId: 'm1', action: 'dismissed' });
    await request(app)
      .post('/api/awareness/event')
      .send({ userId: u, messageId: 'm1', action: 'dismissed' });
    expect(messageStateStore.isSuppressed(u, 'm1')).toBe(true);

    clock.advanceHours(25);
    const second = await next(app, u, 'login_success');
    expect(second.body.message.id).toBe('m2'); // m1 suppressed

    clock.advanceDays(config.DISMISS_COOLDOWN_DAYS);
    expect(messageStateStore.isSuppressed(u, 'm1')).toBe(false);
    const third = await next(app, u, 'login_success');
    expect(third.body.message.id).toBe('m1'); // suppression lifted
  });

  // 10a
  test('risk event delivered on next poll even when standard caps are exhausted', async () => {
    const { app } = buildApp();
    const u = 'u-risk';

    expect((await next(app, u, 'login_success')).status).toBe(200); // standard shown
    expect((await next(app, u, 'security_settings_viewed')).status).toBe(204); // capped

    await request(app)
      .post('/api/risk-event')
      .send({ userId: u, type: 'new_device_login' })
      .expect(202);

    const r = await next(app, u, 'security_settings_viewed');
    expect(r.status).toBe(200);
    expect(r.body.message.class).toBe('risk_event');
    expect(r.body.message.id).toBe('r1');
  });

  // 10b
  test('priority order: risk_event > urgent > standard', async () => {
    const { app, clock } = buildApp();
    const u = 'u-prio';

    await request(app)
      .post('/api/awareness/campaign')
      .send({
        id: 'camp1',
        title: 'Heads up',
        body:
          'A scam is going around by phone. We will never ask for your codes. Report anything odd here.',
        expiresAt: clock.now() + config.DAY_MS * 30,
      })
      .expect(201);

    await request(app)
      .post('/api/risk-event')
      .send({ userId: u, type: 'new_geo_login' })
      .expect(202);

    const a = await next(app, u, 'login_success');
    expect(a.body.message.class).toBe('risk_event');

    const b = await next(app, u, 'login_success');
    expect(b.body.message.class).toBe('urgent');

    const c = await next(app, u, 'login_success');
    expect(c.body.message.class).toBe('standard');
  });

  // 11
  test('segmentation: new account prefers m1/m2; recentContactChange prefers m4/m5', () => {
    const eligible = content.en.list.filter((m) => m.class === 'standard');

    const newAccount = {
      accountAgeDays: 5,
      recentContactChange: false,
      priorReports: 0,
      priorDismissRate: 0,
    };
    expect(['m1', 'm2']).toContain(
      selectNextMessage(newAccount, [], eligible).id
    );

    const contactChange = {
      accountAgeDays: 400,
      recentContactChange: true,
      priorReports: 0,
      priorDismissRate: 0,
    };
    expect(['m4', 'm5']).toContain(
      selectNextMessage(contactChange, [], eligible).id
    );
  });

  // 12
  test('urgent campaign: shown once and not re-shown', async () => {
    const { app, clock } = buildApp();
    await request(app)
      .post('/api/awareness/campaign')
      .send({
        id: 'c-live',
        title: 'Alert',
        body:
          'A scam is going around by text. We will never ask for your codes. Report it here.',
        expiresAt: clock.now() + config.DAY_MS * 30,
      })
      .expect(201);

    const u = 'u-urg';
    const first = await next(app, u, 'login_success');
    expect(first.body.message.class).toBe('urgent');
    expect(first.body.message.id).toBe('c-live');

    clock.advanceHours(25); // new day, standard gate open — but campaign already seen
    const second = await next(app, u, 'login_success');
    const secondClass = second.body.message ? second.body.message.class : 'none';
    expect(secondClass).not.toBe('urgent');
  });

  test('urgent campaign: not shown after expiresAt', async () => {
    const { app, clock } = buildApp();
    await request(app)
      .post('/api/awareness/campaign')
      .send({
        id: 'c-exp',
        title: 'Alert',
        body: 'A short scam warning. Report anything odd here.',
        expiresAt: clock.now() + config.HOUR_MS,
      })
      .expect(201);

    clock.advanceHours(2); // past expiry
    const u = 'u-urg-exp';
    const res = await next(app, u, 'login_success');
    if (res.body.message) {
      expect(res.body.message.class).not.toBe('urgent');
    }
  });

  test('campaign rejected: URL in body or missing expiresAt → 400', async () => {
    const { app, clock } = buildApp();
    await request(app)
      .post('/api/awareness/campaign')
      .send({
        id: 'c-url',
        title: 'x',
        body: 'Please visit https://evil.example right now',
        expiresAt: clock.now() + config.DAY_MS,
      })
      .expect(400);

    await request(app)
      .post('/api/awareness/campaign')
      .send({ id: 'c-noexp', title: 'x', body: 'no link here at all' })
      .expect(400);
  });

  // 13
  test('report endpoint: valid 202 with reportId; bad channel 400; long note 400; listed', async () => {
    const { app } = buildApp();

    const ok = await request(app)
      .post('/api/awareness/report')
      .send({ userId: 'u-rep', channel: 'email', note: 'got a fake email' });
    expect(ok.status).toBe(202);
    expect(typeof ok.body.reportId).toBe('string');
    expect(ok.body.message).toBeTruthy();

    await request(app)
      .post('/api/awareness/report')
      .send({ userId: 'u-rep', channel: 'pigeon' })
      .expect(400);

    const longNote = 'x'.repeat(config.MAX_REPORT_NOTE_LENGTH + 1);
    await request(app)
      .post('/api/awareness/report')
      .send({ userId: 'u-rep', channel: 'email', note: longNote })
      .expect(400);

    const list = await request(app).get('/api/awareness/reports');
    expect(list.status).toBe(200);
    expect(list.body.reports.some((r) => r.reportId === ok.body.reportId)).toBe(
      true
    );
  });

  // 14
  test('telemetry rejects unknown action (400), accepts known (202)', async () => {
    const { app } = buildApp();
    await request(app)
      .post('/api/awareness/event')
      .send({ userId: 'u', messageId: 'm1', action: 'shown' })
      .expect(202);
    await request(app)
      .post('/api/awareness/event')
      .send({ userId: 'u', messageId: 'm1', action: 'hovered' })
      .expect(400);
  });

  // 15
  test('loadContent throws on malformed en.json (startup guard)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-content-'));
    fs.writeFileSync(path.join(dir, 'en.json'), '{ this is not valid json ');
    fs.writeFileSync(
      path.join(dir, 'es.json'),
      JSON.stringify({ locale: 'es', messages: [] })
    );
    expect(() => loadContent(dir)).toThrow();
  });
});