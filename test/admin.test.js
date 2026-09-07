// Integration tests for the console's own controls: roles, team management,
// two-factor, the grant lifecycle actions, the audit export, and the
// observability surface.
//
// Same harness and same rules as gateway.test.js -- a real Postgres, skipped
// rather than failed when TEST_DATABASE_URL is absent.

const test = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers.js');
const totp = require('../lib/totp.js');

const API = '/__access/api/admin';

// A live code for a secret, computed the way an authenticator app would.
const codeFor = (secret, atMs = Date.now()) =>
  totp.hotp(totp.base32Decode(secret), totp.stepFor(atMs));

// Signs in and returns the client, failing loudly rather than letting a later
// assertion report a 401 as though it were the thing under test.
async function as(role, opts = {}) {
  const email = opts.email || `${role}@example.com`;
  const password = opts.password || 'admin-password-123';
  await h.makeAdmin({ email, password, role, ...opts });
  const client = h.client();
  const res = await h.signIn(client, { email, password });
  assert.equal(res.status, 200, `${role} could not sign in`);
  return client;
}

test('console', { skip: h.skip, concurrency: false }, async (t) => {
  await h.boot();
  t.after(h.teardown);
  t.beforeEach(async () => {
    await h.resetDb();
    // Every test starts from the shipped defaults. A test that turns a policy
    // on must not decide what the next one is testing.
    process.env.ADMIN_REQUIRE_TOTP = '';
    process.env.REQUIRE_GRANT_REASON = '';
    process.env.WEBHOOK_URL = '';
    process.env.WEBHOOK_SECRET = '';
  });

  // ----------------------------------------------------------------
  // Roles
  // ----------------------------------------------------------------
  await t.test('an auditor can read everything and change nothing', async () => {
    const grant = await h.makeGrant({ email: 'customer@example.com', status: 'ACTIVE' });
    const auditor = await as('auditor');

    // Reading is the auditor's entire job.
    for (const path of ['/grants', '/audit-log', '/audit-log.csv']) {
      assert.equal((await auditor(API + path)).status, 200, path);
    }

    // Nothing that changes state.
    const denied = [
      [`${API}/grants`, { email: 'new@example.com', durationHours: 1 }],
      [`${API}/grants/${grant.id}/revoke`, {}],
      [`${API}/grants/${grant.id}/extend`, { addHours: 1 }],
      [`${API}/grants/${grant.id}/resend`, {}],
      [`${API}/admins`, { email: 'someone@example.com', role: 'owner' }],
    ];
    for (const [path, body] of denied) {
      const res = await auditor.json(path, body);
      assert.equal(res.status, 403, path);
      assert.equal((await res.json()).role, 'auditor');
    }

    // And the grant is untouched by any of it.
    const { rows } = await h.query('SELECT status FROM access_grants WHERE id = $1', [grant.id]);
    assert.equal(rows[0].status, 'ACTIVE');
  });

  await t.test('an admin issues access but cannot change the team', async () => {
    const admin = await as('admin');

    const created = await admin.json(`${API}/grants`, {
      email: 'customer@example.com',
      durationHours: 2,
    });
    assert.equal(created.status, 202, 'no email provider configured, so 202 with the password');

    // Listing colleagues is not privileged; adding one is.
    assert.equal((await admin(`${API}/admins`)).status, 200);
    const blocked = await admin.json(`${API}/admins`, { email: 'x@example.com', role: 'admin' });
    assert.equal(blocked.status, 403);
  });

  await t.test('the role on the row wins over the role in the token', async () => {
    const client = await as('owner');
    // Demoted after the session was issued. The next request must already see
    // it -- a role carried in the JWT would stay true for the hour.
    await h.query("UPDATE admins SET role = 'auditor' WHERE email = 'owner@example.com'");

    const res = await client.json(`${API}/grants`, { email: 'c@example.com', durationHours: 1 });
    assert.equal(res.status, 403);
    assert.equal((await client(`${API}/auth/me`)).status, 200, 'still a valid session');
  });

  // ----------------------------------------------------------------
  // Team management
  // ----------------------------------------------------------------
  await t.test('an owner creates an admin who must change the password first', async () => {
    const owner = await as('owner');

    const res = await owner.json(`${API}/admins`, {
      email: 'New.Colleague@Example.com',
      role: 'admin',
    });
    assert.equal(res.status, 201);
    const { admin, temporaryPassword } = await res.json();
    assert.equal(admin.email, 'new.colleague@example.com', 'normalised on the way in');
    assert.equal(admin.role, 'admin');
    assert.equal(admin.must_change_password, true);
    assert.ok(temporaryPassword.length >= 16);

    // The temporary password signs them in, and then nothing else works.
    const fresh = h.client();
    const login = await h.signIn(fresh, {
      email: 'new.colleague@example.com',
      password: temporaryPassword,
    });
    assert.equal(login.status, 200);
    assert.equal((await login.json()).mustChangePassword, true);

    const blocked = await fresh.json(`${API}/grants`, { email: 'c@example.com', durationHours: 1 });
    assert.equal(blocked.status, 403);
    assert.equal((await blocked.json()).reason, 'password_change_required');

    // Signing out has to keep working, or the console is a room with no door.
    assert.equal((await fresh.json(`${API}/auth/logout`, {})).status, 200);
  });

  await t.test('changing the password clears the block and needs the old one', async () => {
    const owner = await as('owner');
    const created = await (await owner.json(`${API}/admins`,
      { email: 'colleague@example.com', role: 'admin' })).json();

    const client = h.client();
    await h.signIn(client, {
      email: 'colleague@example.com',
      password: created.temporaryPassword,
    });

    // A session cookie is something an unattended laptop also has.
    const wrong = await client.json(`${API}/auth/password`, {
      currentPassword: 'not-the-password',
      newPassword: 'a-brand-new-password-1',
    });
    assert.equal(wrong.status, 401);

    // And the new password has to clear the floor.
    const short = await client.json(`${API}/auth/password`, {
      currentPassword: created.temporaryPassword,
      newPassword: 'short',
    });
    assert.equal(short.status, 400);

    const ok = await client.json(`${API}/auth/password`, {
      currentPassword: created.temporaryPassword,
      newPassword: 'a-brand-new-password-1',
    });
    assert.equal(ok.status, 200);

    // The block is gone, and the old password is dead.
    assert.equal(
      (await client.json(`${API}/grants`, { email: 'c@example.com', durationHours: 1 })).status,
      202
    );
    const stale = await h.signIn(h.client(), {
      email: 'colleague@example.com',
      password: created.temporaryPassword,
    });
    assert.equal(stale.status, 401);

    const events = await h.auditEvents();
    assert.ok(events.some((e) => e.event === 'ADMIN_PASSWORD_CHANGED'));
    assert.ok(events.some((e) => e.event === 'ADMIN_PASSWORD_CHANGE_FAILED'));
  });

  await t.test('the last owner cannot be demoted or disabled', async () => {
    const owner = await as('owner');
    const { rows } = await h.query("SELECT id FROM admins WHERE role = 'owner'");
    const ownerId = rows[0].id;

    const demote = await owner.json(`${API}/admins/${ownerId}/role`, { role: 'admin' });
    assert.equal(demote.status, 409);
    assert.match((await demote.json()).error, /last owner/);

    // Disabling yourself is refused before the owner count is even consulted:
    // it is never what someone meant to do.
    const self = await owner.json(`${API}/admins/${ownerId}/disable`, {});
    assert.equal(self.status, 409);
    assert.match((await self.json()).error, /your own account/);

    // With a second owner in place, the first can step down.
    const second = await (await owner.json(`${API}/admins`,
      { email: 'second@example.com', role: 'owner' })).json();
    const now = await owner.json(`${API}/admins/${ownerId}/role`, { role: 'admin' });
    assert.equal(now.status, 200);
    assert.equal((await now.json()).admin.role, 'admin');
    assert.equal(second.admin.role, 'owner');
  });

  await t.test('disabling an admin ends their session on the next request', async () => {
    const owner = await as('owner');
    const created = await (await owner.json(`${API}/admins`,
      { email: 'leaver@example.com', role: 'admin' })).json();

    const leaver = h.client();
    await h.signIn(leaver, {
      email: 'leaver@example.com',
      password: created.temporaryPassword,
    });
    assert.equal((await leaver(`${API}/auth/me`)).status, 200);

    const off = await owner.json(`${API}/admins/${created.admin.id}/disable`, {});
    assert.equal(off.status, 200);

    // Their token is still unexpired and still correctly signed.
    assert.equal((await leaver(`${API}/auth/me`)).status, 401);
    // Disabling twice is a 409, not a silent success.
    assert.equal((await owner.json(`${API}/admins/${created.admin.id}/disable`, {})).status, 409);

    const on = await owner.json(`${API}/admins/${created.admin.id}/enable`, {});
    assert.equal(on.status, 200);
    assert.equal((await h.signIn(h.client(), {
      email: 'leaver@example.com',
      password: created.temporaryPassword,
    })).status, 200);

    const events = await h.auditEvents();
    assert.ok(events.some((e) => e.event === 'ADMIN_DISABLED'));
    assert.ok(events.some((e) => e.event === 'ADMIN_ENABLED'));
  });

  await t.test('a duplicate admin is refused, and an unknown role rejected', async () => {
    const owner = await as('owner');
    assert.equal((await owner.json(`${API}/admins`,
      { email: 'dupe@example.com', role: 'admin' })).status, 201);
    assert.equal((await owner.json(`${API}/admins`,
      { email: 'dupe@example.com', role: 'admin' })).status, 409);
    assert.equal((await owner.json(`${API}/admins`,
      { email: 'x@example.com', role: 'superuser' })).status, 400);
    assert.equal((await owner.json(`${API}/admins`,
      { email: 'not-an-email', role: 'admin' })).status, 400);
  });

  // ----------------------------------------------------------------
  // Two-factor
  // ----------------------------------------------------------------
  await t.test('enrolment issues a secret, verifies it, and hands back recovery codes', async () => {
    const owner = await as('owner');

    const setup = await (await owner.json(`${API}/auth/totp/setup`, {})).json();
    assert.match(setup.secret, /^[A-Z2-7]+$/);
    assert.match(setup.otpauthUri, /^otpauth:\/\/totp\//);

    // The secret is stored but not yet trusted: nothing in the login path
    // looks at an unconfirmed one.
    let { rows } = await h.query("SELECT totp_enabled FROM admins WHERE email = 'owner@example.com'");
    assert.equal(rows[0].totp_enabled, false);

    // A wrong code does not enrol.
    assert.equal((await owner.json(`${API}/auth/totp/enable`, { code: '000000' })).status, 400);

    const enabled = await owner.json(`${API}/auth/totp/enable`, { code: codeFor(setup.secret) });
    assert.equal(enabled.status, 200);
    const { backupCodes } = await enabled.json();
    assert.equal(backupCodes.length, totp.BACKUP_CODE_COUNT);
    assert.equal(new Set(backupCodes).size, totp.BACKUP_CODE_COUNT, 'no duplicates');

    ({ rows } = await h.query(
      "SELECT totp_enabled, totp_confirmed_at FROM admins WHERE email = 'owner@example.com'"));
    assert.equal(rows[0].totp_enabled, true);
    assert.ok(rows[0].totp_confirmed_at);

    // Stored hashed, never retrievable.
    const stored = await h.query('SELECT code_hash FROM admin_backup_codes');
    assert.equal(stored.rows.length, totp.BACKUP_CODE_COUNT);
    for (const row of stored.rows) {
      assert.match(row.code_hash, /^scrypt\$16384\$8\$1\$/, 'scrypt with its parameters, not plaintext');
      assert.equal(backupCodes.includes(row.code_hash), false);
    }
  });

  await t.test('sign-in asks for a code, and a wrong one counts towards the lockout', async () => {
    const secret = totp.generateSecret();
    await h.makeAdmin({ email: 'tf@example.com', password: 'admin-password-123', totpSecret: secret });

    // The password alone gets an explicit ask, not a session.
    const client = h.client();
    const step1 = await h.signIn(client, { email: 'tf@example.com' });
    assert.equal(step1.status, 401);
    assert.equal((await step1.json()).reason, 'totp_required');
    assert.equal(client.jar.has(h.ADMIN_COOKIE_NAME), false);

    // A wrong code is a failed attempt, or a valid password buys unlimited
    // guesses at six digits and the second factor is decoration.
    // ADMIN_MAX_FAILED_ATTEMPTS is 3 in the harness.
    for (let i = 0; i < 3; i++) {
      const bad = await h.signIn(client, { email: 'tf@example.com', totpCode: '000000' });
      assert.equal(bad.status, 401);
    }
    const locked = await h.signIn(client, {
      email: 'tf@example.com',
      totpCode: codeFor(secret),
    });
    assert.equal(locked.status, 401, 'a correct code must not open a locked account');

    const events = await h.auditEvents();
    assert.ok(events.some((e) => e.event === 'ADMIN_LOCKED'));
    assert.ok(events.some((e) => e.detail?.reason === 'bad_totp'));

    // Once the lockout lapses, the right code works and the login is recorded
    // as having used a second factor.
    await h.query("UPDATE admins SET locked_until = now() - interval '1 minute'");
    const ok = await h.signIn(client, { email: 'tf@example.com', totpCode: codeFor(secret) });
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).totpEnabled, true);

    const after = await h.auditEvents();
    const success = after.filter((e) => e.event === 'ADMIN_LOGIN_SUCCESS').pop();
    assert.equal(success.detail.secondFactor, 'totp');
  });

  await t.test('a code cannot be used twice', async () => {
    const secret = totp.generateSecret();
    await h.makeAdmin({ email: 'tf@example.com', password: 'admin-password-123', totpSecret: secret });

    const code = codeFor(secret);
    assert.equal((await h.signIn(h.client(), { email: 'tf@example.com', totpCode: code })).status, 200);

    // Same code, still inside its 30-second window, and inside the skew for
    // another minute after that. Without totp_last_step this succeeds.
    const replay = await h.signIn(h.client(), { email: 'tf@example.com', totpCode: code });
    assert.equal(replay.status, 401);

    const events = await h.auditEvents();
    assert.ok(events.some((e) => e.detail?.reason === 'bad_totp'),
      'a replayed code is refused by the verifier before it reaches the marker');
  });

  await t.test('a recovery code works once and is then spent', async () => {
    const owner = await as('owner');
    const setup = await (await owner.json(`${API}/auth/totp/setup`, {})).json();
    const { backupCodes } = await (await owner.json(`${API}/auth/totp/enable`,
      { code: codeFor(setup.secret) })).json();

    const first = await h.signIn(h.client(), {
      email: 'owner@example.com',
      backupCode: backupCodes[0],
    });
    assert.equal(first.status, 200);

    const again = await h.signIn(h.client(), {
      email: 'owner@example.com',
      backupCode: backupCodes[0],
    });
    assert.equal(again.status, 401, 'a spent code must not work a second time');

    // A different one still does, and the codes are case- and dash-insensitive.
    const second = await h.signIn(h.client(), {
      email: 'owner@example.com',
      backupCode: backupCodes[1].toLowerCase().replace('-', ' '),
    });
    assert.equal(second.status, 200);

    const { rows } = await h.query(
      'SELECT count(*)::int AS n FROM admin_backup_codes WHERE used_at IS NOT NULL');
    assert.equal(rows[0].n, 2);

    const events = await h.auditEvents();
    const used = events.filter((e) => e.event === 'ADMIN_BACKUP_CODE_USED');
    assert.equal(used.length, 2);
    assert.equal(used[1].detail.remaining, totp.BACKUP_CODE_COUNT - 2);
  });

  await t.test('re-issuing recovery codes invalidates the previous set', async () => {
    const owner = await as('owner');
    const setup = await (await owner.json(`${API}/auth/totp/setup`, {})).json();
    const old = (await (await owner.json(`${API}/auth/totp/enable`,
      { code: codeFor(setup.secret) })).json()).backupCodes;

    // The password is required, so a stolen session cookie alone cannot mint a
    // fresh set of standing credentials.
    assert.equal((await owner.json(`${API}/auth/totp/backup-codes`,
      { password: 'wrong' })).status, 401);

    const fresh = await owner.json(`${API}/auth/totp/backup-codes`,
      { password: 'admin-password-123' });
    assert.equal(fresh.status, 200);
    const { backupCodes } = await fresh.json();
    assert.equal(backupCodes.length, totp.BACKUP_CODE_COUNT);

    assert.equal((await h.signIn(h.client(),
      { email: 'owner@example.com', backupCode: old[0] })).status, 401);
    assert.equal((await h.signIn(h.client(),
      { email: 'owner@example.com', backupCode: backupCodes[0] })).status, 200);
  });

  await t.test('turning two-factor off costs both other factors', async () => {
    const owner = await as('owner');
    const setup = await (await owner.json(`${API}/auth/totp/setup`, {})).json();
    await owner.json(`${API}/auth/totp/enable`, { code: codeFor(setup.secret) });

    assert.equal((await owner.json(`${API}/auth/totp/disable`,
      { password: 'admin-password-123' })).status, 401, 'no code');
    assert.equal((await owner.json(`${API}/auth/totp/disable`,
      { password: 'wrong', code: codeFor(setup.secret) })).status, 401, 'no password');

    const off = await owner.json(`${API}/auth/totp/disable`, {
      password: 'admin-password-123',
      // A step ahead of the one enable() consumed, since a spent step stays spent.
      code: codeFor(setup.secret, Date.now() + 30_000),
    });
    assert.equal(off.status, 200);

    const { rows } = await h.query(
      "SELECT totp_enabled, totp_secret FROM admins WHERE email = 'owner@example.com'");
    assert.equal(rows[0].totp_enabled, false);
    assert.equal(rows[0].totp_secret, null, 'the secret is destroyed, not just disabled');
    const codes = await h.query('SELECT count(*)::int AS n FROM admin_backup_codes');
    assert.equal(codes.rows[0].n, 0);
  });

  await t.test('ADMIN_REQUIRE_TOTP blocks the console until an account enrols', async () => {
    process.env.ADMIN_REQUIRE_TOTP = 'true';
    const owner = await as('owner');

    const blocked = await owner.json(`${API}/grants`, { email: 'c@example.com', durationHours: 1 });
    assert.equal(blocked.status, 403);
    assert.equal((await blocked.json()).reason, 'totp_enrolment_required');

    // The way out stays open.
    const me = await (await owner(`${API}/auth/me`)).json();
    assert.equal(me.totpRequired, true);
    const setup = await (await owner.json(`${API}/auth/totp/setup`, {})).json();
    assert.equal((await owner.json(`${API}/auth/totp/enable`,
      { code: codeFor(setup.secret) })).status, 200);

    assert.equal((await owner.json(`${API}/grants`,
      { email: 'c@example.com', durationHours: 1 })).status, 202);

    // And it cannot be turned back off while the deployment requires it.
    const off = await owner.json(`${API}/auth/totp/disable`, {
      password: 'admin-password-123',
      code: codeFor(setup.secret, Date.now() + 30_000),
    });
    assert.equal(off.status, 403);
  });

  // ----------------------------------------------------------------
  // Grant lifecycle
  // ----------------------------------------------------------------
  await t.test('REQUIRE_GRANT_REASON refuses a grant nobody justified', async () => {
    const admin = await as('admin');
    process.env.REQUIRE_GRANT_REASON = 'true';

    const bare = await admin.json(`${API}/grants`, { email: 'c@example.com', durationHours: 1 });
    assert.equal(bare.status, 400);
    assert.equal((await bare.json()).reason, 'reason_required');

    // Whitespace is not a justification.
    assert.equal((await admin.json(`${API}/grants`,
      { email: 'c@example.com', durationHours: 1, reason: '   ' })).status, 400);

    const ok = await admin.json(`${API}/grants`, {
      email: 'c@example.com',
      durationHours: 1,
      reason: 'INC-4821 vendor debugging the billing export',
    });
    assert.equal(ok.status, 202);

    const { rows } = await h.query('SELECT reason, created_by_email FROM access_grants');
    assert.match(rows[0].reason, /INC-4821/);
    assert.equal(rows[0].created_by_email, 'admin@example.com', 'the issuer is on the row');
  });

  await t.test('extending an active grant moves the deadline without touching the session', async () => {
    const admin = await as('admin');
    const grant = await h.makeGrant({ status: 'ACTIVE', durationSeconds: 3600 });

    // The customer is logged in and working.
    const customer = h.client();
    customer.setCookie(h.COOKIE_NAME, h.sessionCookie(grant.id, grant.email));
    assert.equal((await customer('/')).status, 200);

    const before = new Date((await h.query(
      'SELECT expires_at FROM access_grants WHERE id = $1', [grant.id])).rows[0].expires_at);

    const res = await admin.json(`${API}/grants/${grant.id}/extend`, { addHours: 2 });
    assert.equal(res.status, 200);

    const after = new Date((await res.json()).grant.expires_at);
    assert.equal(Math.round((after - before) / 1000), 7200);

    const { rows } = await h.query(
      'SELECT extended_seconds, duration_seconds FROM access_grants WHERE id = $1', [grant.id]);
    // Kept apart from the original duration: "issued for an hour and extended
    // twice" and "issued for three hours" are different facts.
    assert.equal(rows[0].duration_seconds, 3600);
    assert.equal(rows[0].extended_seconds, 7200);

    // Still in, uninterrupted.
    assert.equal((await customer('/')).status, 200);

    const events = await h.auditEvents(grant.id);
    const extended = events.find((e) => e.event === 'GRANT_EXTENDED');
    assert.equal(extended.detail.addHours, 2);
    assert.equal(extended.actor, 'admin@example.com');
  });

  await t.test('an extension cannot walk a grant past the ceiling an hour at a time', async () => {
    const admin = await as('admin');
    // The harness leaves MAX_DURATION_HOURS at its shipped default of 24.
    const grant = await h.makeGrant({ status: 'ACTIVE', durationSeconds: 20 * 3600 });

    assert.equal((await admin.json(`${API}/grants/${grant.id}/extend`, { addHours: 4 })).status, 200);

    const over = await admin.json(`${API}/grants/${grant.id}/extend`, { addHours: 1 });
    assert.equal(over.status, 400, 'the ceiling is on the total, not the increment');
    assert.equal((await over.json()).maxDurationHours, 24);

    for (const addHours of [0, -1, 'soon', null]) {
      assert.equal((await admin.json(`${API}/grants/${grant.id}/extend`, { addHours })).status, 400,
        String(addHours));
    }
  });

  await t.test('a closed grant is reissued, never extended', async () => {
    const admin = await as('admin');
    for (const status of ['EXPIRED', 'REVOKED']) {
      const grant = await h.makeGrant({ email: `${status}@example.com`, status });
      const res = await admin.json(`${API}/grants/${grant.id}/extend`, { addHours: 1 });
      assert.equal(res.status, 409, status);
    }
    // A malformed id is a 404, and Postgres never sees the value.
    assert.equal((await admin.json(`${API}/grants/not-a-uuid/extend`, { addHours: 1 })).status, 404);
  });

  await t.test('extending a pending grant changes the window, not the clock', async () => {
    const admin = await as('admin');
    const grant = await h.makeGrant({ status: 'PENDING', durationSeconds: 3600 });

    assert.equal((await admin.json(`${API}/grants/${grant.id}/extend`, { addHours: 1 })).status, 200);

    const { rows } = await h.query(
      'SELECT expires_at, extended_seconds FROM access_grants WHERE id = $1', [grant.id]);
    assert.equal(rows[0].expires_at, null, 'an unopened link must not start ticking');
    assert.equal(rows[0].extended_seconds, 3600);

    // And the added time is honoured when they do open it.
    const activated = await h.client()(`/__access/api/activate/${grant.token}`);
    assert.equal(activated.status, 200);
  });

  await t.test('re-sending rotates both secrets and resets the link clock', async () => {
    const admin = await as('admin');
    const grant = await h.makeGrant({ status: 'PENDING', password: 'original-password' });
    // Issued nearly a day ago: the link's own deadline is almost up.
    await h.query("UPDATE access_grants SET created_at = now() - interval '23 hours' WHERE id = $1",
      [grant.id]);

    const res = await admin.json(`${API}/grants/${grant.id}/resend`, { relay: true });
    assert.equal(res.status, 202, 'no email provider in the harness');
    const data = await res.json();
    assert.ok(data.password && data.password !== 'original-password');
    assert.equal(data.grant.resend_count, 1);

    // The old link is dead.
    assert.equal((await h.client()(`/__access/api/activate/${grant.token}`)).status, 404);
    // The new one works, and carries a full window again.
    const token = data.accessUrl.split('/').pop();
    assert.equal((await h.client()(`/__access/api/activate/${token}`)).status, 200);

    const events = await h.auditEvents(grant.id);
    assert.ok(events.some((e) => e.event === 'GRANT_CREDENTIALS_REISSUED'));
  });

  await t.test('re-sending is refused once someone is actually using the grant', async () => {
    const admin = await as('admin');
    const grant = await h.makeGrant({ status: 'ACTIVE' });
    const res = await admin.json(`${API}/grants/${grant.id}/resend`, {});
    assert.equal(res.status, 409, 'rotating the password would end their session');
    assert.equal((await res.json()).status, 'ACTIVE');
  });

  await t.test('the grant list filters by status and by person', async () => {
    const admin = await as('admin');
    await h.makeGrant({ email: 'alice@example.com', status: 'ACTIVE' });
    await h.makeGrant({ email: 'bob@example.com', status: 'REVOKED' });
    await h.makeGrant({ email: 'bob@example.com', status: 'PENDING' });

    const live = await (await admin(`${API}/grants?status=PENDING,ACTIVE`)).json();
    assert.equal(live.grants.length, 2);

    const bob = await (await admin(`${API}/grants?email=BOB@example.com`)).json();
    assert.equal(bob.grants.length, 2, 'the address is normalised before it is matched');

    const both = await (await admin(`${API}/grants?email=bob@example.com&status=REVOKED`)).json();
    assert.equal(both.grants.length, 1);

    assert.equal((await admin(`${API}/grants?status=NONSENSE`)).status, 400);
  });

  // ----------------------------------------------------------------
  // Audit log
  // ----------------------------------------------------------------
  await t.test('the audit log filters by event, actor and time', async () => {
    const admin = await as('admin');
    await admin.json(`${API}/grants`, { email: 'c@example.com', durationHours: 1 });

    const byEvent = await (await admin(`${API}/audit-log?event=GRANT_CREATED`)).json();
    assert.equal(byEvent.events.length, 1);
    assert.equal(byEvent.events[0].actor, 'admin@example.com');
    // The request that caused it is recorded alongside.
    assert.match(byEvent.events[0].request_id, /^[0-9a-f-]{36}$/);

    // A list, because the questions people ask span several events.
    const several = await (await admin(
      `${API}/audit-log?event=GRANT_CREATED,ADMIN_LOGIN_SUCCESS`)).json();
    assert.equal(several.events.length, 2);

    const byActor = await (await admin(`${API}/audit-log?actor=ADMIN@example.com`)).json();
    assert.ok(byActor.events.length >= 2, 'the actor is matched case-insensitively');

    const future = await (await admin(
      `${API}/audit-log?from=${new Date(Date.now() + 86400000).toISOString()}`)).json();
    assert.equal(future.events.length, 0);

    assert.equal((await admin(`${API}/audit-log?from=not-a-date`)).status, 400);
    assert.equal((await admin(`${API}/audit-log?grantId=nope`)).status, 400);
  });

  await t.test('the CSV export is well-formed, filtered and formula-safe', async () => {
    const admin = await as('admin');
    await admin.json(`${API}/grants`, { email: 'c@example.com', durationHours: 1 });

    // A whole field that a spreadsheet would treat as a live formula. Written
    // straight to the table because the API validates the columns it owns --
    // the export must be safe regardless of how a row got there, including
    // rows written by a future caller or by hand during an incident.
    await h.query(
      'INSERT INTO audit_log (event, actor, detail) VALUES ($1, $2, $3)',
      ['LOGIN_FAILED', '=HYPERLINK("http://evil.example","click")', JSON.stringify({ a: 1 })]
    );

    const formulaRow = await admin(`${API}/audit-log.csv?event=LOGIN_FAILED`);
    const formulaBody = await formulaRow.text();
    assert.match(formulaBody, /"'=HYPERLINK/,
      'a leading = is neutralised, and the field is quoted because it has commas');

    const res = await admin(`${API}/audit-log.csv?event=GRANT_CREATED`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/csv/);
    assert.match(res.headers.get('content-disposition'), /attachment; filename="audit-log-/);

    const body = await res.text();
    const lines = body.trim().split('\n');
    assert.equal(lines[0],
      'id,created_at,event,actor,grant_id,ip_address,user_agent,request_id,detail');
    // A terminator, so a truncated download is detectable.
    assert.match(lines[lines.length - 1], /^#end,\d+ rows$/);
    assert.equal(lines.length, 3, 'header, one filtered row, terminator');
    assert.match(lines[1], /GRANT_CREATED/);
    // The detail column holds JSON with commas and quotes: it must be quoted,
    // and its quotes doubled.
    assert.match(lines[1], /"\{""/);

    // The export is itself an event worth recording.
    const events = await h.auditEvents();
    const exported = events.find((e) => e.event === 'AUDIT_LOG_EXPORTED');
    assert.equal(exported.detail.rows, 1);
  });

  // ----------------------------------------------------------------
  // Observability
  // ----------------------------------------------------------------
  await t.test('liveness does not depend on the database, readiness does', async () => {
    const client = h.client();

    const live = await client('/__access/health/live');
    assert.equal(live.status, 200);
    assert.ok((await live.json()).uptimeSeconds >= 0);

    const ready = await client('/__access/health/ready');
    assert.equal(ready.status, 200);
    assert.equal((await ready.json()).database, 'ok');

    // The original path still answers, so an existing probe keeps working.
    assert.equal((await client('/__access/health')).status, 200);
  });

  await t.test('metrics need the token, and never carry a URL as a label', async () => {
    const admin = await as('admin');
    await admin.json(`${API}/grants`, { email: 'c@example.com', durationHours: 1 });
    await h.makeGrant({ email: 'live@example.com', status: 'ACTIVE' });
    await require('../server.js').refreshGauges();

    const client = h.client();
    assert.equal((await client('/__access/metrics')).status, 404, 'no token, no answer');
    assert.equal((await client('/__access/metrics', {
      headers: { authorization: 'Bearer wrong' },
    })).status, 404, 'a wrong token is indistinguishable from no endpoint');

    const res = await client('/__access/metrics', {
      headers: { authorization: `Bearer ${h.METRICS_TOKEN}` },
    });
    assert.equal(res.status, 200);
    const body = await res.text();

    assert.match(body, /gateway_grants_total\{transition="created"\}/);
    assert.match(body, /gateway_logins_total\{outcome="success",principal="admin"\}/);
    assert.match(body, /gateway_grants_live\{status="ACTIVE"\} 1/);
    assert.match(body, /gateway_http_requests_total\{/);

    // No email address, no grant id, no raw path anywhere in the output.
    assert.equal(/c@example\.com/.test(body), false);
    assert.equal(/[0-9a-f]{8}-[0-9a-f]{4}-/.test(body), false);
  });

  await t.test('a request id is echoed, reused when sane, and replaced when not', async () => {
    const client = h.client();

    const generated = await client('/__access/health/live');
    assert.match(generated.headers.get('x-request-id'), /^[0-9a-f-]{36}$/);

    const passed = await client('/__access/health/live', {
      headers: { 'x-request-id': 'trace-abc-123' },
    });
    assert.equal(passed.headers.get('x-request-id'), 'trace-abc-123');

    // An unbounded header ends up in a log line and a database column, so a
    // value carrying a newline is discarded rather than trusted.
    const forged = await client('/__access/health/live', {
      headers: { 'x-request-id': 'ok-part then junk!' },
    });
    assert.notEqual(forged.headers.get('x-request-id'), 'ok-part then junk!');
    assert.match(forged.headers.get('x-request-id'), /^[0-9a-f-]{36}$/);
  });

  // ----------------------------------------------------------------
  // Webhooks
  // ----------------------------------------------------------------
  await t.test('events are queued durably and delivered signed', async () => {
    const received = [];
    // Fails the first GRANT_CREATED delivery and accepts everything else.
    // Keyed on the event rather than on arrival order: signing in enqueues an
    // ADMIN_LOGIN_SUCCESS first, and a sink that counts requests would spend
    // its one failure on that instead.
    const failOnce = new Set(['GRANT_CREATED']);
    const sink = await new Promise((resolve) => {
      const s = require('http').createServer((req, res) => {
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
          received.push({ headers: req.headers, body: Buffer.concat(chunks).toString() });
          const event = req.headers['x-gateway-event'];
          const fail = failOnce.delete(event);
          res.writeHead(fail ? 500 : 200).end();
        });
      });
      s.listen(0, '127.0.0.1', () => resolve(s));
    });

    try {
      process.env.WEBHOOK_URL = `http://127.0.0.1:${sink.address().port}/hook`;
      process.env.WEBHOOK_SECRET = 'webhook-secret';

      const admin = await as('admin');
      await admin.json(`${API}/grants`, { email: 'c@example.com', durationHours: 1 });

      const queued = await h.query(
        "SELECT event, status FROM webhook_outbox WHERE event = 'GRANT_CREATED'");
      assert.equal(queued.rows.length, 1, 'written inside the request, not posted from it');
      assert.equal(queued.rows[0].status, 'PENDING');

      const server = require('../server.js');

      // First drain: the sink answers 500, so the row stays pending and is
      // scheduled for a retry rather than being lost.
      await server.webhooks.drain(server.pool);
      const failed = await h.query(
        "SELECT status, attempts, last_error FROM webhook_outbox WHERE event = 'GRANT_CREATED'");
      assert.equal(failed.rows[0].status, 'PENDING');
      assert.equal(failed.rows[0].attempts, 1);
      assert.match(failed.rows[0].last_error, /HTTP 500/);

      // Second drain, once the backoff is cleared.
      await h.query('UPDATE webhook_outbox SET next_attempt_at = now()');
      await server.webhooks.drain(server.pool);

      const delivered = await h.query(
        "SELECT status FROM webhook_outbox WHERE event = 'GRANT_CREATED'");
      assert.equal(delivered.rows[0].status, 'DELIVERED');

      const last = received[received.length - 1];
      const payload = JSON.parse(last.body);
      assert.equal(payload.event, 'GRANT_CREATED');
      assert.equal(payload.data.actor, 'admin@example.com');
      assert.equal(payload.attempt, 2);

      // The signature covers the timestamp as well as the body, which is what
      // lets a receiver reject a replay.
      const expected = 'sha256=' + require('../lib/webhooks.js')
        .sign('webhook-secret', Number(last.headers['x-gateway-timestamp']), last.body);
      assert.equal(last.headers['x-gateway-signature'], expected);
      assert.equal(last.headers['x-gateway-event'], 'GRANT_CREATED');
    } finally {
      await new Promise((r) => sink.close(r));
    }
  });

  await t.test('a webhook that cannot be queued never fails the grant', async () => {
    // A URL that resolves nowhere. The grant must still be created and the
    // admin must still get their credentials: the access decision is the
    // product, the notification is not.
    process.env.WEBHOOK_URL = 'http://127.0.0.1:1/hook';
    const admin = await as('admin');

    const res = await admin.json(`${API}/grants`, { email: 'c@example.com', durationHours: 1 });
    assert.equal(res.status, 202);
    assert.ok((await res.json()).password);

    const server = require('../server.js');
    await server.webhooks.drain(server.pool);
    const { rows } = await h.query(
      "SELECT status, attempts FROM webhook_outbox WHERE event = 'GRANT_CREATED'");
    assert.equal(rows[0].status, 'PENDING', 'still queued for a retry');
    assert.ok(rows[0].attempts >= 1);
  });
});
