// Test harness.
//
// The integration tests need a real Postgres, because most of what they cover
// lives in the database: statuses, lockouts, and the fact that a revoke is
// visible to the very next request. They are skipped, not failed, when
// TEST_DATABASE_URL is absent -- so `npm test` still runs the unit tests on a
// machine with no database.
//
//   TEST_DATABASE_URL=postgres://user:pass@localhost:5432/temp_access_test npm test
//
// Point it at a throwaway database: every test truncates all three tables. A
// schema inside an existing database works too, if creating one is easier:
//   ...temp_access?options=-c%20search_path%3Dta_test,public

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL || '';
const skip = TEST_DATABASE_URL ? false : 'set TEST_DATABASE_URL to run integration tests';

const JWT_SECRET = 'test-jwt-secret-at-least-32-characters-long';
const UPSTREAM_SECRET = 'test-upstream-secret';

// Stand-in for the internal app. Records what the gateway forwarded, so the
// tests can assert on the identity headers rather than trusting them.
const upstream = {
  server: null,
  port: 0,
  requests: [],
  // Upgrades are recorded separately from requests because the interesting
  // assertion is that most of them never arrive at all.
  upgrades: [],
  sockets: new Set(),
  csp: null,
  body: '<html><head><title>internal</title></head><body><h1>internal app</h1></body></html>',
  reset() {
    this.requests = [];
    this.upgrades = [];
    this.csp = null;
  },
  get lastRequest() {
    return this.requests[this.requests.length - 1] || null;
  },
  get lastUpgrade() {
    return this.upgrades[this.upgrades.length - 1] || null;
  },
};

let gateway = null;
let server = null;

async function boot() {
  upstream.server = await new Promise((resolve) => {
    const s = http.createServer((req, res) => {
      upstream.requests.push({ url: req.url, method: req.method, headers: req.headers });
      if (req.url.endsWith('.css')) {
        res.writeHead(200, { 'content-type': 'text/css' });
        return res.end('body{color:#000}');
      }
      const headers = { 'content-type': 'text/html; charset=utf-8' };
      if (upstream.csp) headers['content-security-policy'] = upstream.csp;
      res.writeHead(200, headers);
      res.end(upstream.body);
    });
    // Completes a real handshake, so a test can tell "the gateway refused the
    // socket" apart from "the socket reached the app" -- which is the whole
    // question for the upgrade path.
    s.on('upgrade', (req, socket) => {
      upstream.upgrades.push({ url: req.url, headers: req.headers });
      // An upgraded socket is detached from the server's connection tracking,
      // so server.close() would wait on it forever. Tracked here so teardown
      // can end it, rather than hanging the whole run.
      upstream.sockets.add(socket);
      socket.on('close', () => upstream.sockets.delete(socket));
      const accept = crypto
        .createHash('sha1')
        .update(`${req.headers['sec-websocket-key'] || ''}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
        .digest('base64');
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n'
          + 'Upgrade: websocket\r\nConnection: Upgrade\r\n'
          + `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
      );
      socket.on('error', () => {});
    });
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
  upstream.port = upstream.server.address().port;

  // Set before requiring server.js: it reads config at load time, and dotenv
  // will not overwrite a variable that is already present. Blanking the email
  // credentials matters -- a developer's real .env is sitting right there, and
  // no test should be able to send mail to anyone.
  Object.assign(process.env, {
    DATABASE_URL: TEST_DATABASE_URL,
    JWT_SECRET,
    PUBLIC_BASE_URL: 'http://127.0.0.1',
    UPSTREAM_URL: `http://127.0.0.1:${upstream.port}`,
    PORT: '0',
    EMAIL_PROVIDER: '',
    RESEND_API_KEY: '',
    EMAIL_FROM: '',
    SES_REGION: '',
    SES_ACCESS_KEY_ID: '',
    SES_SECRET_ACCESS_KEY: '',
    UPSTREAM_SHARED_SECRET: UPSTREAM_SECRET,
    GRANT_CACHE_TTL_MS: '50',
    // Deliberately blank rather than '24': an empty value is falsy, so the code
    // falls back to its own default and the assertions below cover that default
    // instead of covering a number this file just set. These two are the
    // shipped ceilings, and a default that quietly disagrees with
    // .env.example is exactly the drift worth catching here.
    MAX_DURATION_HOURS: '',
    PENDING_EXPIRY_HOURS: '',
    GRANT_MAX_FAILED_ATTEMPTS: '3',
    GRANT_LOCKOUT_MINUTES: '15',
    ADMIN_MAX_FAILED_ATTEMPTS: '3',
    ADMIN_LOCKOUT_MINUTES: '15',
    // The rate limiters are per IP and every test comes from 127.0.0.1, so
    // they are opened up here. The lockouts above are what these tests are
    // about, and they must not be masked by a 429 from a limiter.
    LOGIN_RATE_MAX: '10000',
    ADMIN_LOGIN_RATE_MAX: '10000',
    SWEEP_INTERVAL_MS: '3600000',
    ADMIN_IP_ALLOWLIST: '',
    // The new controls default to off so the existing tests describe the
    // shipped defaults. The tests that cover them set them per-case through
    // the same process.env the server reads at call time.
    ADMIN_REQUIRE_TOTP: '',
    REQUIRE_GRANT_REASON: '',
    METRICS_TOKEN: 'test-metrics-token',
    WEBHOOK_URL: '',
    WEBHOOK_SECRET: '',
    LOG_LEVEL: 'error',
    LOG_FORMAT: 'json',
  });

  server = require('../server.js');
  await assertDisposableTarget();
  await server.pool.query(fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8'));
  gateway = await server.start();
  return gateway;
}

// These tests TRUNCATE all three tables and run schema.sql, whose migrations
// rewrite rows. Pointed at the wrong database that is not a failing test, it is
// someone's data gone -- so the target has to prove it is disposable first.
//
// The trap this exists for: Postgres silently ignores a schema in search_path
// that does not exist. A connection string carrying
// `search_path=my_test_schema,public` therefore falls all the way back to
// `public` if that schema was never created, and every destructive statement
// below lands on the real tables while appearing to be isolated.
async function assertDisposableTarget() {
  const { rows } = await server.pool.query(
    'SELECT current_database() AS db, current_schema() AS schema'
  );
  const { db, schema } = rows[0];

  // Either a database that is obviously a test one, or a schema that is not
  // the default. Both are cheap to say and hard to arrive at by accident.
  if (/test/i.test(db) || (schema && schema !== 'public')) return;

  throw new Error([
    `Refusing to run: TEST_DATABASE_URL points at "${db}", schema "${schema}", which is not`,
    'obviously disposable, and these tests truncate every table.',
    '  Use a database whose name contains "test", or a dedicated schema:',
    '    CREATE SCHEMA ta_test;',
    '    TEST_DATABASE_URL=".../yourdb?options=-c%20search_path%3Dta_test,public"',
    `  (current_schema() came back as "${schema}" -- if you expected a schema here, it does`,
    '  not exist, and Postgres quietly fell back to public.)',
  ].join('\n'));
}

async function teardown() {
  // The upstream's sockets go first: a proxied websocket holds both ends
  // open, so stopping the gateway while the app still has its end would leave
  // each side waiting on the other.
  for (const socket of upstream.sockets) socket.destroy();
  if (gateway) await gateway.stop();
  // boot() can fail before the gateway exists -- the disposable-target check
  // above is meant to -- and the pool it already opened would hold the process
  // open, turning a clear refusal into a hung test run.
  else if (server) await server.pool.end().catch(() => {});
  if (upstream.server) {
    for (const socket of upstream.sockets) socket.destroy();
    upstream.server.closeAllConnections?.();
    await new Promise((r) => upstream.server.close(r));
  }
}

const query = (...args) => server.pool.query(...args);
const sweep = () => server.sweepExpired();

async function resetDb() {
  // admin_backup_codes and webhook_outbox came later; CASCADE from admins
  // covers the first, and the second has no foreign key at all, so it is named
  // explicitly. A table left out here leaks rows between tests, and the
  // symptom is a test that passes alone and fails in the suite.
  await query(
    'TRUNCATE audit_log, access_grants, admins, admin_backup_codes, webhook_outbox '
    + 'RESTART IDENTITY CASCADE'
  );
  upstream.reset();
}

const base = () => `http://127.0.0.1:${gateway.port}`;

// A browser's cookie jar, minus everything these tests do not need: one
// origin, no expiry, no paths. Redirects are deliberately not followed --
// where the gateway sends an unauthenticated request is itself under test.
function client() {
  const jar = new Map();

  const call = async (url, opts = {}) => {
    const headers = { ...(opts.headers || {}) };
    if (jar.size) headers.cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');

    const res = await fetch(base() + url, { ...opts, headers, redirect: 'manual' });
    for (const raw of res.headers.getSetCookie()) {
      const pair = raw.split(';')[0];
      const i = pair.indexOf('=');
      const name = pair.slice(0, i);
      const value = pair.slice(i + 1);
      if (value === '') jar.delete(name);
      else jar.set(name, value);
    }
    return res;
  };

  call.json = async (url, body, opts = {}) => call(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    body: JSON.stringify(body),
    ...opts,
  });
  call.jar = jar;
  call.setCookie = (name, value) => jar.set(name, value);
  return call;
}

const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex');

// Grants are inserted directly rather than issued through the API, so a test
// can start from any point in the lifecycle without walking there first.
async function makeGrant({
  email = 'customer@example.com',
  password = 'test-password',
  status = 'ACTIVE',
  durationSeconds = 3600,
  createdAt = new Date(),
  expiresAt = status === 'ACTIVE' ? new Date(Date.now() + durationSeconds * 1000) : null,
  activatedAt = status === 'PENDING' ? null : new Date(),
  failedAttempts = 0,
  lockedUntil = null,
} = {}) {
  // Same shape the server mints: 32 random bytes as base64url. A fixture that
  // built a token the route guard would reject would fail every activation
  // test for a reason that had nothing to do with what was being tested.
  const token = crypto.randomBytes(32).toString('base64url');
  const { rows } = await query(
    `INSERT INTO access_grants
       (email, token_hash, password_hash, duration_seconds, status,
        created_at, activated_at, expires_at, failed_login_attempts, locked_until)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
    [email, hashToken(token), bcrypt.hashSync(password, 4), durationSeconds, status,
      createdAt, activatedAt, expiresAt, failedAttempts, lockedUntil]
  );
  return { ...rows[0], token, password };
}

async function makeAdmin({
  email = 'admin@example.com',
  password = 'admin-password-123',
  role = 'owner',
  mustChangePassword = false,
  totpSecret = null,
} = {}) {
  const { rows } = await query(
    `INSERT INTO admins (email, password_hash, role, must_change_password,
                         totp_secret, totp_enabled)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
    [email, bcrypt.hashSync(password, 4), role, mustChangePassword,
      totpSecret, Boolean(totpSecret)]
  );
  return { ...rows[0], password };
}

async function signIn(as, {
  email = 'admin@example.com',
  password = 'admin-password-123',
  totpCode,
  backupCode,
} = {}) {
  return as.json('/__access/api/admin/auth/login', { email, password, totpCode, backupCode });
}

// Forges a session cookie directly. Some states -- an expired JWT against a
// still-open grant, a session for a grant that no longer exists -- cannot be
// reached by logging in and waiting.
function sessionCookie(grantId, email, { expiresIn = 3600 } = {}) {
  return jwt.sign({ grantId, email }, JWT_SECRET, { expiresIn });
}

async function auditEvents(grantId = null) {
  const { rows } = grantId
    ? await query('SELECT * FROM audit_log WHERE grant_id = $1 ORDER BY id', [grantId])
    : await query('SELECT * FROM audit_log ORDER BY id');
  return rows;
}

module.exports = {
  skip,
  boot,
  teardown,
  resetDb,
  query,
  sweep,
  client,
  base,
  upstream,
  makeGrant,
  makeAdmin,
  signIn,
  sessionCookie,
  auditEvents,
  hashToken,
  METRICS_TOKEN: 'test-metrics-token',
  UPSTREAM_SECRET,
  COOKIE_NAME: 'ta_session',
  ADMIN_COOKIE_NAME: 'ta_admin',
};

// A note on running these files.
//
// `node --test` runs test FILES in parallel by default. Every integration file
// here points at the same TEST_DATABASE_URL and truncates every table between
// cases, so two files running at once delete each other's fixtures -- and the
// failures land in whichever file happened to be mid-assertion, which is never
// the one with the problem.
//
// npm test therefore pins --test-concurrency=1. Running a single file directly
// needs no flag; running two by hand does.
