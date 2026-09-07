// Integration tests, against a real Postgres and a real listener.
//
// The bias here is towards the moments where the gateway says no, because
// that is the only thing it exists to do: a bug that lets someone in is not
// a bug in a feature, it is the product failing.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const h = require('./helpers.js');

const HTML = { accept: 'text/html' };

test('gateway', { skip: h.skip, concurrency: 1 }, async (t) => {
  await h.boot();
  t.after(() => h.teardown());
  t.beforeEach(() => h.resetDb());

  // ----------------------------------------------------------------
  // The reserved namespace
  // ----------------------------------------------------------------
  await t.test('an undefined gate URL 404s instead of reaching the app', async () => {
    const c = h.client();
    const res = await c('/__access/not-a-real-route');

    assert.equal(res.status, 404);
    assert.deepEqual(await res.json(), { error: 'Not found' });
    // The point of the check: the app must never see a request inside the one
    // namespace this design promises it will never own.
    assert.equal(h.upstream.requests.length, 0);
  });

  await t.test('the gate namespace is sealed for POSTs too', async () => {
    const c = h.client();
    const res = await c.json('/__access/api/not-a-real-route', {});
    assert.equal(res.status, 404);
    assert.equal(h.upstream.requests.length, 0);
  });

  // The one gate URL that answers before anyone has authenticated, which is
  // why what it does NOT say matters as much as what it does. It used to
  // return UPSTREAM_URL -- the address of the app the whole system exists to
  // keep off the public internet -- to any anonymous caller.
  await t.test('health reports the database without disclosing the upstream', async () => {
    const c = h.client();
    const res = await c('/__access/health');
    const body = await res.json();

    assert.equal(res.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.database, 'ok');
    assert.equal(JSON.stringify(body).includes(String(h.upstream.port)), false);
    assert.equal('upstream' in body, false);
  });

  // ----------------------------------------------------------------
  // resolveSession: every way in is a way to be refused
  // ----------------------------------------------------------------
  await t.test('no session: HTML redirects to login, anything else gets a 401', async () => {
    const c = h.client();

    const page = await c('/some/app/page', { headers: HTML });
    assert.equal(page.status, 302);
    const location = page.headers.get('location');
    assert.match(location, /^\/__access\/login\?/);
    assert.match(location, /reason=no_session/);
    // Where they were headed is preserved, so login can return them there.
    assert.match(location, /next=%2Fsome%2Fapp%2Fpage/);

    const xhr = await c('/api/data');
    assert.equal(xhr.status, 401);
    assert.deepEqual(await xhr.json(), { error: 'Access no longer valid', reason: 'no_session' });

    assert.equal(h.upstream.requests.length, 0);
  });

  await t.test('a garbled cookie is bad_token, not a 500', async () => {
    const c = h.client();
    c.setCookie(h.COOKIE_NAME, 'this.is.not.a.jwt');
    const res = await c('/');
    assert.equal(res.status, 401);
    assert.equal((await res.json()).reason, 'bad_token');
  });

  await t.test('a session for a grant that no longer exists is grant_missing', async () => {
    const c = h.client();
    c.setCookie(h.COOKIE_NAME, h.sessionCookie(
      '3f2504e0-4f89-41d3-9a0c-0305e82c3301', 'ghost@example.com'
    ));
    const res = await c('/');
    assert.equal((await res.json()).reason, 'grant_missing');
  });

  await t.test('a revoked grant kills a live session on the next request', async () => {
    const grant = await h.makeGrant({ status: 'REVOKED' });
    const c = h.client();
    c.setCookie(h.COOKIE_NAME, h.sessionCookie(grant.id, grant.email));

    const res = await c('/');
    assert.equal((await res.json()).reason, 'revoked');
    assert.equal(h.upstream.requests.length, 0);
  });

  await t.test('a PENDING grant cannot carry a session', async () => {
    const grant = await h.makeGrant({ status: 'PENDING' });
    const c = h.client();
    c.setCookie(h.COOKIE_NAME, h.sessionCookie(grant.id, grant.email));
    assert.equal((await c('/')).status, 401);
  });

  await t.test('a lapsed window is expired, and is flipped in the database', async () => {
    const grant = await h.makeGrant({ expiresAt: new Date(Date.now() - 1000) });
    const c = h.client();
    c.setCookie(h.COOKIE_NAME, h.sessionCookie(grant.id, grant.email));

    const res = await c('/');
    assert.equal((await res.json()).reason, 'expired');

    const { rows } = await h.query('SELECT status FROM access_grants WHERE id = $1', [grant.id]);
    assert.equal(rows[0].status, 'EXPIRED');
    assert.ok((await h.auditEvents(grant.id)).some((e) => e.event === 'GRANT_EXPIRED'));
  });

  // The distinction customers actually feel: "your time ran out" versus "you
  // still have time, sign in again". Both arrive as an expired JWT.
  await t.test('an aged-out login on a live grant is session_expired, not expired', async () => {
    const grant = await h.makeGrant();
    const c = h.client();
    c.setCookie(h.COOKIE_NAME, h.sessionCookie(grant.id, grant.email, { expiresIn: -10 }));

    const res = await c('/', { headers: HTML });
    assert.match(res.headers.get('location'), /reason=session_expired/);
  });

  await t.test('an aged-out login on a closed grant is expired', async () => {
    const grant = await h.makeGrant({ status: 'EXPIRED', expiresAt: new Date(Date.now() - 1000) });
    const c = h.client();
    c.setCookie(h.COOKIE_NAME, h.sessionCookie(grant.id, grant.email, { expiresIn: -10 }));

    const res = await c('/', { headers: HTML });
    assert.match(res.headers.get('location'), /reason=expired/);
  });

  // ----------------------------------------------------------------
  // Login
  // ----------------------------------------------------------------
  await t.test('login works whatever case the customer types', async () => {
    await h.makeGrant({ email: 'contractor@firm.com', password: 'correct-horse' });

    const c = h.client();
    const res = await c.json('/__access/api/auth/login', {
      email: '  Contractor@Firm.COM ',
      password: 'correct-horse',
    });

    assert.equal(res.status, 200);
    assert.ok(c.jar.has(h.COOKIE_NAME));
  });

  await t.test('a wrong password is counted against the right grant', async () => {
    const grant = await h.makeGrant({ password: 'correct-horse' });

    const c = h.client();
    const res = await c.json('/__access/api/auth/login', {
      email: grant.email, password: 'wrong',
    });

    assert.equal(res.status, 401);
    assert.deepEqual(await res.json(), { error: 'Invalid credentials' });
    assert.equal(c.jar.has(h.COOKIE_NAME), false);

    const { rows } = await h.query(
      'SELECT failed_login_attempts FROM access_grants WHERE id = $1', [grant.id]);
    assert.equal(rows[0].failed_login_attempts, 1);
  });

  await t.test('an expired grant refuses a login and closes itself', async () => {
    const grant = await h.makeGrant({
      password: 'correct-horse', expiresAt: new Date(Date.now() - 1000),
    });

    const c = h.client();
    const res = await c.json('/__access/api/auth/login', {
      email: grant.email, password: 'correct-horse',
    });

    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, 'Access expired');
    const { rows } = await h.query('SELECT status FROM access_grants WHERE id = $1', [grant.id]);
    assert.equal(rows[0].status, 'EXPIRED');
  });

  await t.test('a revoked grant is indistinguishable from no grant at all', async () => {
    const grant = await h.makeGrant({ status: 'REVOKED', password: 'correct-horse' });

    const c = h.client();
    const res = await c.json('/__access/api/auth/login', {
      email: grant.email, password: 'correct-horse',
    });

    assert.equal(res.status, 401);
    assert.deepEqual(await res.json(), { error: 'Invalid credentials' });
    const events = await h.auditEvents();
    assert.equal(events.at(-1).detail.reason, 'no_active_grant');
  });

  // GRANT_MAX_FAILED_ATTEMPTS is 3 in the test environment.
  await t.test('a grant locks after repeated failures, and says so', async () => {
    const grant = await h.makeGrant({ password: 'correct-horse' });
    const c = h.client();
    const attempt = (password) => c.json('/__access/api/auth/login', { email: grant.email, password });

    assert.equal((await attempt('wrong-1')).status, 401);
    assert.equal((await attempt('wrong-2')).status, 401);

    const locked = await attempt('wrong-3');
    assert.equal(locked.status, 429);
    const body = await locked.json();
    assert.equal(body.reason, 'locked');
    assert.match(body.error, /Try again in 15 minutes/);

    // The point of a lockout: the right password does not lift it.
    const rightPassword = await attempt('correct-horse');
    assert.equal(rightPassword.status, 429);
    assert.equal(c.jar.has(h.COOKIE_NAME), false);

    // And it is a control an operator can see, which is what the counter
    // alone never was.
    const events = await h.auditEvents(grant.id);
    assert.ok(events.some((e) => e.event === 'GRANT_LOCKED'));
  });

  await t.test('a lockout releases, and a good login clears the counter', async () => {
    const grant = await h.makeGrant({
      password: 'correct-horse',
      failedAttempts: 2,
      lockedUntil: new Date(Date.now() - 1000), // already elapsed
    });

    const c = h.client();
    const res = await c.json('/__access/api/auth/login', {
      email: grant.email, password: 'correct-horse',
    });

    assert.equal(res.status, 200);
    const { rows } = await h.query(
      'SELECT failed_login_attempts, locked_until FROM access_grants WHERE id = $1', [grant.id]);
    assert.equal(rows[0].failed_login_attempts, 0);
    assert.equal(rows[0].locked_until, null);
  });

  // ----------------------------------------------------------------
  // Grant lifecycle
  // ----------------------------------------------------------------
  await t.test('activation moves PENDING to ACTIVE and starts the clock', async () => {
    const grant = await h.makeGrant({ status: 'PENDING', durationSeconds: 3600 });
    const c = h.client();

    const res = await c(`/__access/api/activate/${grant.token}`);
    assert.equal(res.status, 200);

    const { rows } = await h.query(
      'SELECT status, activated_at, expires_at FROM access_grants WHERE id = $1', [grant.id]);
    assert.equal(rows[0].status, 'ACTIVE');
    assert.ok(rows[0].activated_at);
    // The clock starts on activation, not creation.
    const window = new Date(rows[0].expires_at) - new Date(rows[0].activated_at);
    assert.ok(Math.abs(window - 3600_000) < 2000, `window was ${window}ms`);

    // Reopening the link is innocent -- a refresh, or checking the time left.
    const again = await c(`/__access/api/activate/${grant.token}`);
    assert.equal(again.status, 200);
    assert.match((await again.json()).message, /already active/);
  });

  await t.test('a revoked link cannot be activated', async () => {
    const grant = await h.makeGrant({ status: 'REVOKED' });
    const res = await h.client()(`/__access/api/activate/${grant.token}`);
    assert.equal(res.status, 410);
  });

  await t.test('opening a lapsed link expires it rather than admitting it', async () => {
    const grant = await h.makeGrant({ expiresAt: new Date(Date.now() - 1000) });
    const res = await h.client()(`/__access/api/activate/${grant.token}`);

    assert.equal(res.status, 410);
    const { rows } = await h.query('SELECT status FROM access_grants WHERE id = $1', [grant.id]);
    assert.equal(rows[0].status, 'EXPIRED');
  });

  // ----------------------------------------------------------------
  // The link's own clock, which is not the access window
  // ----------------------------------------------------------------
  await t.test('a link opened after its deadline does not activate', async () => {
    const grant = await h.makeGrant({
      status: 'PENDING',
      createdAt: new Date(Date.now() - 25 * 3600 * 1000), // link validity is 24h
    });

    const res = await h.client()(`/__access/api/activate/${grant.token}`);
    assert.equal(res.status, 410);
    const body = await res.json();
    // Named, so the page can say "expired" rather than "invalid" -- one of
    // those means "ask for another" and the other means something is wrong.
    assert.equal(body.reason, 'link_expired');

    const { rows } = await h.query('SELECT status FROM access_grants WHERE id = $1', [grant.id]);
    assert.equal(rows[0].status, 'EXPIRED');
    assert.ok((await h.auditEvents(grant.id)).some((e) => e.event === 'GRANT_LINK_EXPIRED'));
  });

  // Checked in the route as well as the sweeper: the sweeper runs on an
  // interval, and a link opened between two sweeps would otherwise activate.
  await t.test('the sweeper expires unopened links, as a separate event', async () => {
    const stale = await h.makeGrant({
      email: 'stale@example.com',
      status: 'PENDING',
      createdAt: new Date(Date.now() - 25 * 3600 * 1000),
    });
    const fresh = await h.makeGrant({ email: 'fresh@example.com', status: 'PENDING' });

    await h.sweep();

    const { rows } = await h.query('SELECT id, status FROM access_grants ORDER BY email');
    const byId = Object.fromEntries(rows.map((r) => [r.id, r.status]));
    assert.equal(byId[stale.id], 'EXPIRED');
    assert.equal(byId[fresh.id], 'PENDING');

    // The two clocks stay separable in the log: "they ran out of time" and
    // "they never showed up" are different facts about a customer.
    const events = await h.auditEvents(stale.id);
    assert.ok(events.some((e) => e.event === 'GRANT_LINK_EXPIRED'));
    assert.ok(!events.some((e) => e.event === 'GRANT_EXPIRED'));
  });

  await t.test('an expired link says so, rather than looking invalid', async () => {
    const grant = await h.makeGrant({
      status: 'PENDING',
      createdAt: new Date(Date.now() - 25 * 3600 * 1000),
    });
    await h.sweep();

    // Opened after the sweeper already closed it.
    const res = await h.client()(`/__access/api/activate/${grant.token}`);
    assert.equal(res.status, 410);
    assert.equal((await res.json()).reason, 'link_expired');
  });

  await t.test('an expired link frees the address for a new grant', async () => {
    await h.makeGrant({
      email: 'contractor@firm.com',
      status: 'PENDING',
      createdAt: new Date(Date.now() - 25 * 3600 * 1000),
    });
    await h.sweep();

    await h.makeAdmin();
    const admin = h.client();
    await h.signIn(admin);
    const res = await admin.json('/__access/api/admin/grants', {
      email: 'contractor@firm.com', durationHours: 8,
    });
    assert.equal(res.status, 202);
  });

  await t.test('a malformed token is refused before it reaches the database', async () => {
    const res = await h.client()('/__access/api/activate/not-a-token');
    assert.equal(res.status, 404);
  });

  // ----------------------------------------------------------------
  // The proxy
  // ----------------------------------------------------------------
  await t.test('a live session reaches the app, carrying an identity it cannot forge', async () => {
    const grant = await h.makeGrant({ email: 'customer@example.com', password: 'correct-horse' });
    const c = h.client();
    await c.json('/__access/api/auth/login', { email: grant.email, password: 'correct-horse' });

    // A cookie the app set for itself, which must survive the trip.
    c.setCookie('app_pref', 'dark');

    const res = await c('/dashboard', {
      headers: {
        ...HTML,
        // Everything a client might try to assert about itself.
        'X-Temp-Access-Email': 'attacker@evil.com',
        'X-Gateway-Secret': 'guessed',
      },
    });
    assert.equal(res.status, 200);

    const body = await res.text();
    assert.match(body, /internal app/);
    assert.match(body, /ta-banner/, 'the countdown banner should be injected');

    const forwarded = h.upstream.lastRequest.headers;
    assert.equal(forwarded['x-temp-access-email'], 'customer@example.com');
    assert.equal(forwarded['x-temp-access-grant'], grant.id);
    // Proof the request came through the gateway, for an app that checks it.
    assert.equal(forwarded['x-gateway-secret'], h.UPSTREAM_SECRET);
    // The gateway's own cookie never reaches the app; the app's does.
    assert.ok(!forwarded.cookie.includes(h.COOKIE_NAME));
    assert.match(forwarded.cookie, /app_pref=dark/);
  });

  await t.test('an admin revoke cuts the customer off on the very next request', async () => {
    const grant = await h.makeGrant({ password: 'correct-horse' });
    await h.makeAdmin();

    const customer = h.client();
    await customer.json('/__access/api/auth/login', {
      email: grant.email, password: 'correct-horse',
    });
    assert.equal((await customer('/', { headers: HTML })).status, 200);

    const admin = h.client();
    await h.signIn(admin);
    const revoked = await admin.json(`/__access/api/admin/grants/${grant.id}/revoke`, {});
    assert.equal(revoked.status, 200);

    // No sleep: revoking busts the cache directly, which is the whole reason
    // the cache is allowed to exist on the hot path.
    const after = await customer('/', { headers: HTML });
    assert.equal(after.status, 302);
    assert.match(after.headers.get('location'), /reason=revoked/);
  });

  await t.test('logging out ends the grant, not just the session', async () => {
    const grant = await h.makeGrant({ password: 'correct-horse' });
    const c = h.client();
    await c.json('/__access/api/auth/login', { email: grant.email, password: 'correct-horse' });

    const res = await c.json('/__access/api/auth/logout', {});
    assert.equal(res.status, 200);

    const { rows } = await h.query('SELECT status FROM access_grants WHERE id = $1', [grant.id]);
    assert.equal(rows[0].status, 'REVOKED');

    // The emailed credentials are permanently spent, even with time left.
    const retry = await c.json('/__access/api/auth/login', {
      email: grant.email, password: 'correct-horse',
    });
    assert.equal(retry.status, 401);
  });

  await t.test('the banner is nonced so a strict upstream CSP does not eat it', async () => {
    h.upstream.csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'";

    const grant = await h.makeGrant({ password: 'correct-horse' });
    const c = h.client();
    await c.json('/__access/api/auth/login', { email: grant.email, password: 'correct-horse' });

    const res = await c('/', { headers: HTML });
    const body = await res.text();
    const nonce = body.match(/<script nonce="([^"]+)"/)?.[1];
    assert.ok(nonce, 'the injected script should carry a nonce');

    const csp = res.headers.get('content-security-policy');
    assert.ok(csp.includes(`script-src 'self' 'nonce-${nonce}'`), csp);
    assert.ok(csp.includes(`style-src 'self' 'nonce-${nonce}'`), csp);
    // The countdown re-syncs against the gateway, which no nonce can authorise.
    assert.match(csp, /connect-src 'self'/);
    // And the app keeps the policy it set, for everything the banner does not
    // need -- this is the whole reason for not stripping the header.
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /img-src 'self'/);

    // Two responses must not share a nonce, or it is not a nonce.
    const second = await (await c('/', { headers: HTML })).text();
    assert.notEqual(second.match(/<script nonce="([^"]+)"/)[1], nonce);
  });

  await t.test('assets stream untouched', async () => {
    const grant = await h.makeGrant({ password: 'correct-horse' });
    const c = h.client();
    await c.json('/__access/api/auth/login', { email: grant.email, password: 'correct-horse' });

    const res = await c('/styles.css');
    assert.equal(res.status, 200);
    assert.equal(await res.text(), 'body{color:#000}');
  });

  // ----------------------------------------------------------------
  // Admin console
  // ----------------------------------------------------------------
  await t.test('an issued grant is stored normalised and is usable end to end', async () => {
    await h.makeAdmin();
    const admin = h.client();
    await h.signIn(admin);

    const res = await admin.json('/__access/api/admin/grants', {
      email: '  Contractor@Firm.COM ',
      durationHours: 8,
    });
    // 202 because email is deliberately unconfigured in the tests: the grant
    // is real, and the password comes back for the admin to relay by hand.
    assert.equal(res.status, 202);
    const created = await res.json();
    assert.equal(created.grant.email, 'contractor@firm.com');
    assert.ok(created.password);

    const token = created.accessUrl.split('/').pop();
    const customer = h.client();
    assert.equal((await customer(`/__access/api/activate/${token}`)).status, 200);

    const login = await customer.json('/__access/api/auth/login', {
      email: 'CONTRACTOR@firm.com',
      password: created.password,
    });
    assert.equal(login.status, 200);
  });

  await t.test('a second live grant for the same person is refused, not silently broken', async () => {
    await h.makeAdmin();
    const admin = h.client();
    await h.signIn(admin);

    const first = await (await admin.json('/__access/api/admin/grants', {
      email: 'contractor@firm.com', durationHours: 8,
    })).json();

    const second = await admin.json('/__access/api/admin/grants', {
      email: 'Contractor@Firm.com', durationHours: 8,
    });
    assert.equal(second.status, 409);
    const body = await second.json();
    // The admin is told which grant is in the way, so revoking it is a
    // deliberate act rather than a guess.
    assert.equal(body.existingGrant.id, first.grant.id);
    assert.equal(body.existingGrant.status, 'PENDING');

    // Only ever one grant, and the first one is untouched.
    const { rows } = await h.query(
      "SELECT count(*)::int AS n FROM access_grants WHERE email = 'contractor@firm.com'");
    assert.equal(rows[0].n, 1);

    // Revoking clears the way.
    await admin.json(`/__access/api/admin/grants/${first.grant.id}/revoke`, {});
    const third = await admin.json('/__access/api/admin/grants', {
      email: 'contractor@firm.com', durationHours: 8,
    });
    assert.equal(third.status, 202);
  });

  await t.test('the console can find a live grant before it submits', async () => {
    await h.makeAdmin();
    const admin = h.client();
    await h.signIn(admin);

    const none = await admin('/__access/api/admin/grants/live?email=nobody@example.com');
    assert.equal(none.status, 200);
    assert.equal((await none.json()).grant, null);

    const grant = await h.makeGrant({ email: 'contractor@firm.com', status: 'PENDING' });
    // Case-insensitive, like every other lookup.
    const found = await admin('/__access/api/admin/grants/live?email=Contractor@Firm.com');
    const body = await found.json();
    assert.equal(body.grant.id, grant.id);
    assert.equal(body.grant.status, 'PENDING');
    // The console needs the duration to reissue with the same window.
    assert.equal(body.grant.duration_seconds, 3600);

    assert.equal((await admin('/__access/api/admin/grants/live?email=nonsense')).status, 400);
  });

  await t.test('revoke and reissue is two ordinary calls, and it works', async () => {
    await h.makeAdmin();
    const admin = h.client();
    await h.signIn(admin);

    const first = await (await admin.json('/__access/api/admin/grants', {
      email: 'contractor@firm.com', durationHours: 8,
    })).json();

    // What the console's one button does: revoke, then create.
    await admin.json(`/__access/api/admin/grants/${first.grant.id}/revoke`, {});
    const second = await admin.json('/__access/api/admin/grants', {
      email: 'contractor@firm.com', durationHours: 8,
    });
    assert.equal(second.status, 202);

    const reissued = await second.json();
    assert.notEqual(reissued.grant.id, first.grant.id);
    // A new password, because none is stored in plaintext to re-send.
    assert.notEqual(reissued.password, first.password);
  });

  await t.test('the password comes back only when an admin asks to relay it', async () => {
    // Email has to work for this to mean anything: on the failure path the
    // password comes back regardless. A stub provider stands in for Resend.
    const sent = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (url, opts) => {
      if (String(url).includes('api.resend.com')) {
        sent.push(JSON.parse(opts.body));
        return new Response('{"id":"stub"}', { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return realFetch(url, opts);
    };
    process.env.RESEND_API_KEY = 're_stub';
    process.env.EMAIL_FROM = 'access@example.com';

    try {
      await h.makeAdmin();
      const admin = h.client();
      await h.signIn(admin);

      const quiet = await admin.json('/__access/api/admin/grants', {
        email: 'first@example.com', durationHours: 8,
      });
      assert.equal(quiet.status, 201);
      const quietBody = await quiet.json();
      assert.equal(quietBody.password, undefined, 'a password has no business in a response nobody asked for');
      assert.equal(sent.length, 1);
      // The email carries both clocks.
      assert.match(sent[0].text, /opened within 24 hours/);
      assert.match(sent[0].text, /access lasts 8 hours/);

      const relayed = await admin.json('/__access/api/admin/grants', {
        email: 'second@example.com', durationHours: 8, relay: true,
      });
      assert.equal(relayed.status, 201);
      const relayedBody = await relayed.json();
      assert.ok(relayedBody.password, 'the admin asked to read it out');

      // A credential leaving by a second route is a thing the log answers for.
      const events = (await h.auditEvents(relayedBody.grant.id)).map((e) => e.event);
      assert.ok(events.includes('GRANT_PASSWORD_RELAYED'));
      assert.ok(events.includes('GRANT_EMAIL_ACCEPTED'));
    } finally {
      globalThis.fetch = realFetch;
      process.env.RESEND_API_KEY = '';
      process.env.EMAIL_FROM = '';
    }
  });

  await t.test('the console is told the limits it has to render', async () => {
    await h.makeAdmin();
    const admin = h.client();
    await h.signIn(admin);

    const me = await (await admin('/__access/api/admin/auth/me')).json();
    assert.equal(me.email, 'admin@example.com');
    // Both env vars are left empty by the harness, so these assert the code's
    // own defaults -- which must agree with .env.example. A fallback that
    // silently widens the ceiling when the variable is dropped is the failure
    // this is here to catch.
    assert.equal(me.maxDurationHours, 24);
    assert.equal(me.pendingExpiryHours, 24);
  });

  await t.test('a duration above the ceiling is refused', async () => {
    await h.makeAdmin();
    const admin = h.client();
    await h.signIn(admin);

    const res = await admin.json('/__access/api/admin/grants', {
      email: 'contractor@firm.com', durationHours: 72,
    });
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /<= 24/);
  });

  await t.test('the email audit event claims acceptance, not delivery', async () => {
    await h.makeAdmin();
    const admin = h.client();
    await h.signIn(admin);

    // Email is unconfigured here, so this is the failure path.
    const res = await admin.json('/__access/api/admin/grants', {
      email: 'contractor@firm.com', durationHours: 8,
    });
    const { grant } = await res.json();
    const events = (await h.auditEvents(grant.id)).map((e) => e.event);
    assert.ok(events.includes('GRANT_EMAIL_FAILED'));
    assert.ok(!events.includes('GRANT_EMAIL_SENT'), 'nothing should claim a message was sent');
  });

  await t.test('a malformed grant id is a 404, not a 500', async () => {
    await h.makeAdmin();
    const admin = h.client();
    await h.signIn(admin);

    const res = await admin.json('/__access/api/admin/grants/not-a-uuid/revoke', {});
    assert.equal(res.status, 404);

    const log = await admin('/__access/api/admin/audit-log?grantId=not-a-uuid');
    assert.equal(log.status, 400);
  });

  await t.test('an unauthenticated caller cannot touch the admin API', async () => {
    const grant = await h.makeGrant();
    const c = h.client();
    assert.equal((await c('/__access/api/admin/grants')).status, 401);
    assert.equal((await c.json('/__access/api/admin/grants', {
      email: 'x@y.com', durationHours: 1,
    })).status, 401);
    assert.equal((await c.json(`/__access/api/admin/grants/${grant.id}/revoke`, {})).status, 401);
  });

  await t.test('a customer session is not an admin session', async () => {
    const grant = await h.makeGrant({ password: 'correct-horse' });
    const c = h.client();
    await c.json('/__access/api/auth/login', { email: grant.email, password: 'correct-horse' });

    // The same token replayed under the admin cookie's name. It fails at the
    // signature check, because admin sessions are signed with a derived key.
    c.setCookie(h.ADMIN_COOKIE_NAME, c.jar.get(h.COOKIE_NAME));
    assert.equal((await c('/__access/api/admin/grants')).status, 401);
  });

  // ADMIN_MAX_FAILED_ATTEMPTS is 3 in the test environment.
  await t.test('an admin account locks, holds, and then releases', async () => {
    const admin = await h.makeAdmin();
    const c = h.client();

    for (let i = 0; i < 3; i++) {
      const res = await h.signIn(c, { email: admin.email, password: `wrong-${i}` });
      assert.equal(res.status, 401);
    }

    const locked = await h.signIn(c, { email: admin.email, password: admin.password });
    assert.equal(locked.status, 401);
    assert.equal(c.jar.has(h.ADMIN_COOKIE_NAME), false);

    const events = await h.auditEvents();
    assert.ok(events.some((e) => e.event === 'ADMIN_LOCKED'));

    await h.query('UPDATE admins SET locked_until = now() - interval \'1 minute\' WHERE id = $1',
      [admin.id]);

    const after = await h.signIn(c, { email: admin.email, password: admin.password });
    assert.equal(after.status, 200);
    const { rows } = await h.query(
      'SELECT failed_login_attempts, locked_until FROM admins WHERE id = $1', [admin.id]);
    assert.equal(rows[0].failed_login_attempts, 0);
    assert.equal(rows[0].locked_until, null);
  });

  // ----------------------------------------------------------------
  // Schema guarantees
  // ----------------------------------------------------------------
  // This used to assert the opposite: a CHECK constraint pinned totp_enabled to
  // false, because the login branch behind it returned 501 and flipping the
  // column locked that admin out permanently. TOTP is implemented now, and the
  // migration drops the constraint -- so the test that guarded the gap becomes
  // the test that the gap is closed. See test/admin.test.js for the behaviour.
  await t.test('the database now permits an enabled TOTP account', async () => {
    const admin = await h.makeAdmin();
    await h.query('UPDATE admins SET totp_enabled = true, totp_secret = $2 WHERE id = $1',
      [admin.id, 'JBSWY3DPEHPK3PXP']);
    const { rows } = await h.query('SELECT totp_enabled FROM admins WHERE id = $1', [admin.id]);
    assert.equal(rows[0].totp_enabled, true);
  });

  // CI applies schema.sql twice, but against an empty database -- which is the
  // one state that cannot catch this. The failure it missed: an earlier
  // section added a CHECK pinning totp_enabled to false and a later one
  // dropped it, so the file ended in the right state and was re-runnable
  // exactly once. The second run's ADD executed against a database where an
  // admin had since enrolled, failed, and took every statement after it down
  // with it -- meaning `npm run migrate` stopped working on the day someone
  // turned on two-factor, and the next deploy was what found out.
  //
  // So this re-applies the schema over rows that exist, which is what every
  // upgrade after the first one actually does.
  await t.test('schema.sql re-applies over live data, including an enrolled admin', async () => {
    await h.makeAdmin({ email: 'enrolled@example.com', totpSecret: 'JBSWY3DPEHPK3PXP' });
    await h.makeGrant({ email: 'someone@example.com', status: 'ACTIVE' });

    const schema = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8');
    await h.query(schema);
    await h.query(schema);

    const { rows } = await h.query(
      "SELECT totp_enabled, role FROM admins WHERE email = 'enrolled@example.com'"
    );
    assert.equal(rows[0].totp_enabled, true, 'the migration must not undo an enrolment');
    assert.equal(rows[0].role, 'owner');
  });

  await t.test('every admin row carries a role the application recognises', async () => {
    const admin = await h.makeAdmin({ role: 'auditor' });
    assert.equal(admin.role, 'auditor');
    await assert.rejects(
      () => h.query('UPDATE admins SET role = $2 WHERE id = $1', [admin.id, 'superuser']),
      /admins_role_valid/
    );
  });

  await t.test('the database refuses a second live grant even under a race', async () => {
    await h.makeGrant({ email: 'contractor@firm.com', status: 'ACTIVE' });
    await assert.rejects(
      () => h.makeGrant({ email: 'contractor@firm.com', status: 'PENDING' }),
      /uniq_live_grant_per_email/
    );
    // A closed grant is no obstacle to issuing the next one.
    await h.query("UPDATE access_grants SET status = 'EXPIRED' WHERE email = 'contractor@firm.com'");
    await h.makeGrant({ email: 'contractor@firm.com', status: 'PENDING' });
  });
});
