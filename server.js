require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const ipaddr = require('ipaddr.js');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

const { log } = require('./lib/logger');
const metrics = require('./lib/metrics');
const totp = require('./lib/totp');
const webhooks = require('./lib/webhooks');
const { version: SERVICE_VERSION } = require('./package.json');

// ============================================================
// Config
// ============================================================
// Fail at boot, not at the first request. A gateway that starts without an
// upstream or a signing secret is worse than one that refuses to start: it
// looks healthy while being either useless or insecure.
const REQUIRED = ['DATABASE_URL', 'JWT_SECRET', 'PUBLIC_BASE_URL', 'UPSTREAM_URL'];
const missing = REQUIRED.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`Refusing to start. Missing required env vars: ${missing.join(', ')}`);
  process.exit(1);
}
if (process.env.JWT_SECRET.length < 32) {
  console.error('Refusing to start. JWT_SECRET must be at least 32 characters.');
  process.exit(1);
}

// Every gateway-owned URL lives under this one prefix. Everything else on
// this origin is forwarded to the upstream app untouched, so the app keeps
// its own URL structure and its root-relative links keep working. Reserving
// a single namespace is what makes that collision-free -- the app is free to
// have its own /api, /login or /admin.
const GATE = '/__access';

// Mirrors the CHECK constraint on access_grants.status. Kept here so a filter
// value from a query string is validated against the same list the database
// enforces, rather than being interpolated and turning a typo into a 500.
const GRANT_STATUSES = ['PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED'];

const PORT = Number(process.env.PORT || 3000);
const UPSTREAM_URL = process.env.UPSTREAM_URL;
const COOKIE_NAME = 'ta_session';
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true'
  || process.env.PUBLIC_BASE_URL.startsWith('https://');
// Named once and pinned on both sign and verify. jsonwebtoken already refuses
// `alg: none` for a symmetric secret, so this changes nothing today -- it is
// here so that a future version relaxing that default, or a key that stops
// being symmetric, cannot quietly turn "signed" into "claims to be signed".
const JWT_ALG = 'HS256';
// Three independent clocks, and conflating any two of them produces a bug
// that is very hard to see from a support ticket:
//
//   PENDING_EXPIRY_HOURS  the unopened link      runs from grant creation
//   duration_seconds      the access window      runs from activation
//   SESSION_TTL_SECONDS   one login              runs from login
//
// MAX_DURATION_HOURS is a ceiling on the second, not a default -- the admin
// names a duration on every grant and this only rejects values above it.
//
// The fallback matches .env.example deliberately. It used to be 720, so
// dropping the variable silently widened the ceiling from a day to a month on
// a system called temporary access -- the kind of default that is only ever
// discovered by whoever is reviewing it.
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 3600);
const MAX_DURATION_HOURS = Number(process.env.MAX_DURATION_HOURS || 24);

// How long an unopened access link stays activatable. Without this a grant
// created and never opened stayed live indefinitely -- next month, next year
// -- and so did the credentials sitting in the customer's inbox.
const PENDING_EXPIRY_HOURS = Number(process.env.PENDING_EXPIRY_HOURS || 24);
const SWEEP_INTERVAL_MS = Number(process.env.SWEEP_INTERVAL_MS || 60_000);
const GRANT_CACHE_TTL_MS = Number(process.env.GRANT_CACHE_TTL_MS || 5000);
const INJECT_BANNER = process.env.INJECT_BANNER !== 'false';
const STRIP_UPSTREAM_CSP = process.env.STRIP_UPSTREAM_CSP === 'true';

// Customer-side lockout, mirroring the admin one. Deliberately its own pair of
// knobs rather than reusing the admin numbers: a customer is retyping a
// 16-character password read off a screen, so the threshold that is right for
// an admin typing a password they chose themselves is wrong here.
const GRANT_MAX_FAILED_ATTEMPTS = Number(process.env.GRANT_MAX_FAILED_ATTEMPTS || 8);
const GRANT_LOCKOUT_MINUTES = Number(process.env.GRANT_LOCKOUT_MINUTES || 15);

// Sent on every proxied request when set. The gateway's whole value rests on
// the app being unreachable except through it, and nothing in this codebase
// can enforce that -- but if the app rejects any request without this header,
// a customer who finds the app's own address gets nothing. Optional, because
// it needs a matching middleware on the app's side; see DEPLOY.md.
const UPSTREAM_SHARED_SECRET = process.env.UPSTREAM_SHARED_SECRET || '';
const UPSTREAM_SECRET_HEADER = process.env.UPSTREAM_SECRET_HEADER || 'X-Gateway-Secret';

// Two policy switches, read at the point of use rather than captured at load
// like the rest of the config above.
//
// The difference is deliberate and narrow: everything else here is a value the
// gateway needs before it can serve a single request, and reading it once at
// boot is what makes a missing one a refusal to start. These two only change
// what an authenticated admin is asked for, so a stale copy has no failure mode
// -- and reading them live is what lets the tests cover both settings without
// standing up a second gateway to hold the other value.

// Requires the admin to say why, on every grant. Off by default because it is
// a policy question rather than a technical one -- but a company that will ever
// be asked "who had access to this system in March, and on whose authority"
// has to have the answer written down at the moment access is granted. There is
// no reconstructing it afterwards.
const requireGrantReason = () => process.env.REQUIRE_GRANT_REASON === 'true';
const MAX_REASON_LENGTH = 500;

// ---- observability ----
// The metrics endpoint is not public. It publishes the shape of the traffic,
// the number of live grants and the failure counts -- reconnaissance, in other
// words, on the one door into the internal network. It is served only when a
// token is configured, and compared in constant time.
const METRICS_TOKEN = process.env.METRICS_TOKEN || '';

// ---- admin ----
const ADMIN_COOKIE_NAME = 'ta_admin';
// Refuse to let an account without two-factor use the console. Off by default
// so an existing deployment keeps working across the upgrade that added TOTP;
// a company should turn it on, and the console walks each admin through
// enrolment rather than locking them out (see requireEnrolled).
const requireAdminTotp = () => process.env.ADMIN_REQUIRE_TOTP === 'true';
const ADMIN_SESSION_TTL_SECONDS = Number(process.env.ADMIN_SESSION_TTL_SECONDS || 3600);
const ADMIN_MAX_FAILED_ATTEMPTS = Number(process.env.ADMIN_MAX_FAILED_ATTEMPTS || 5);
const ADMIN_LOCKOUT_MINUTES = Number(process.env.ADMIN_LOCKOUT_MINUTES || 15);
const ADMIN_MIN_PASSWORD_LENGTH = 12;

// Admin sessions are signed with a key *derived* from JWT_SECRET rather than
// with JWT_SECRET itself. Both cookies would otherwise verify against the same
// secret, and a customer's session token could be replayed as an admin token.
// Deriving the key makes that fail at the signature check, structurally --
// rather than depending on someone remembering to check a claim.
const ADMIN_JWT_KEY = crypto
  .createHmac('sha256', process.env.JWT_SECRET)
  .update('admin-sessions-v1')
  .digest();

// Comma-separated CIDRs allowed to reach the admin console. Empty means no
// restriction, which keeps local development working; production should scope
// this to the VPN or office range so the console is not answerable to the
// public internet at all.
const ADMIN_IP_ALLOWLIST = (process.env.ADMIN_IP_ALLOWLIST || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
  .map((cidr) => {
    try {
      return cidr.includes('/') ? ipaddr.parseCIDR(cidr) : ipaddr.parseCIDR(`${cidr}/32`);
    } catch {
      console.error(`Refusing to start. ADMIN_IP_ALLOWLIST entry is not valid CIDR: ${cidr}`);
      process.exit(1);
    }
  });

// Managed Postgres (Neon/Supabase/RDS) requires TLS; a local socket does not.
// Certificate verification, and its one explicit escape hatch, live in
// lib/db-ssl.js so the scripts cannot drift from the gateway.
const databaseSsl = require('./lib/db-ssl');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: databaseSsl(),
  // Without a connection timeout, a query against a Postgres that accepts TCP
  // but never answers hangs forever -- and the readiness probe below hangs
  // with it, so the orchestrator sees no answer instead of the 503 that would
  // take this instance out of rotation. A slow failure is worse than a fast
  // one here, because only the fast one is actionable.
  connectionTimeoutMillis: Number(process.env.DB_CONNECT_TIMEOUT_MS || 5000),
  idleTimeoutMillis: Number(process.env.DB_IDLE_TIMEOUT_MS || 30_000),
  max: Number(process.env.DB_POOL_MAX || 10),
  // Caps a single statement rather than the pool: one pathological audit-log
  // query should not hold a connection the proxy hot path needs.
  statement_timeout: Number(process.env.DB_STATEMENT_TIMEOUT_MS || 15_000),
});

// `pg` emits 'error' on idle clients when a connection drops -- a Postgres
// restart, a failover, an idle timeout on a managed instance. With no listener
// Node treats that as an unhandled 'error' event and kills the process. On a
// single-instance deployment where the gateway is the only route to the app,
// that turns a database blip the pool would have recovered from on the next
// checkout into a total outage for everyone using the gateway.
pool.on('error', (err) => {
  log.error('idle database client error', { err: err.message });
});

// ============================================================
// Crypto helpers
// ============================================================
// 256 bits of base64url, the sole bearer secret in the emailed link.
//
// This was nine decimal digits -- about 30 bits, and stored as an unsalted
// SHA-256, so anyone who read the database could recover every live token by
// exhausting the space in seconds. Nobody types this value: it is clicked, so
// a longer one costs the customer nothing. The character class is url-safe by
// construction, which is what keeps the route guards below simple.
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

function generateToken() {
  return crypto.randomBytes(32).toString('base64url');
}
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
function generatePassword(length = 16) {
  // Ambiguous glyphs (0/O, 1/l/I) are omitted: these passwords get read off a
  // screen and retyped by hand, so transcription errors are the failure mode
  // actually worth designing against.
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  // Rejection sampling rather than `% charset.length`. 256 is not a multiple
  // of 57, so the modulo would make the first 28 glyphs a fifth likelier than
  // the rest. It costs a handful of bits out of ninety-odd and would never be
  // the way in -- but a generator with a known skew is the kind of thing that
  // has to be explained in a security review, and not having it is free.
  const limit = 256 - (256 % charset.length);
  let out = '';
  while (out.length < length) {
    for (const byte of crypto.randomBytes(length)) {
      if (byte >= limit) continue;
      out += charset[byte % charset.length];
      if (out.length === length) break;
    }
  }
  return out;
}
async function hashPassword(password) {
  return bcrypt.hash(password, await bcrypt.genSalt(12));
}

// ============================================================
// Small helpers
// ============================================================
// Emails are stored and compared in exactly one form. Without this, an admin
// who types `Contractor@Firm.com` creates a grant that `contractor@firm.com`
// can never log into -- and the failure surfaces as "Invalid credentials",
// which reads as a wrong password rather than a mistyped grant.
function normaliseEmail(value) {
  return String(value == null ? '' : value).trim().toLowerCase();
}

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function escapeHtml(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

// Postgres throws 22P02 on a malformed UUID, which reaches the client as a
// generic 500. Path parameters are shape-checked before they are ever put in a
// query, so a bad id is a 404 -- which is the honest answer anyway.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isUuid(value) {
  return typeof value === 'string' && UUID_RE.test(value);
}

function hoursLabel(hours) {
  return `${hours} hour${hours === 1 ? '' : 's'}`;
}

// ============================================================
// Email
// ============================================================
// One message, two backends. Everything provider-specific lives behind
// `send`, so nothing else in the codebase learns which one is in use and
// adding a third is a function rather than a refactor.
//
// Resend is what this deploys on; its free tier covers the expected volume.
// SES is here so the provider is a config-level swap rather than a rewrite if
// that ever changes. It is not a security improvement over Resend and should
// not be sold as one.
const SES_KEYS = ['SES_REGION', 'SES_ACCESS_KEY_ID', 'SES_SECRET_ACCESS_KEY'];

function renderAccessEmail({ accessUrl, username, password, durationLabel, linkExpiryLabel }) {
  // Both clocks, spelled out. The old copy mentioned only that the countdown
  // starts on opening, which left the customer with no idea the link itself
  // has a deadline. Ambiguity here does not cause security incidents; it
  // causes support calls, reliably.
  const timing = `This link must be opened within ${linkExpiryLabel}.`
    + ` Once you open it, your access lasts ${durationLabel}.`;

  const text = `Your temporary access has been created.

Access URL:
${accessUrl}

Username:
${username}

Temporary Password:
${password}

Access Duration:
${durationLabel}

${timing}`;

  // Every interpolated value is escaped. `username` is an email an admin typed
  // into a form, and an email regex accepts a great deal that is not an email
  // -- this message goes out over the client's name, so it does not get to
  // carry markup from a form field.
  const e = escapeHtml;
  const html = `<p>Your temporary access has been created.</p>
<p><b>Access URL:</b><br><a href="${e(accessUrl)}">${e(accessUrl)}</a></p>
<p><b>Username:</b><br>${e(username)}</p>
<p><b>Temporary Password:</b><br><code>${e(password)}</code></p>
<p><b>Access Duration:</b><br>${e(durationLabel)}</p>
<p style="color:#6b7280;font-size:13px">${e(timing)}</p>`;

  return { subject: 'Your temporary access', text, html };
}

async function sendViaResend({ to, subject, text, html }) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from: process.env.EMAIL_FROM, to, subject, text, html }),
  });
  if (!res.ok) throw new Error(`Email send failed: ${res.status} ${await res.text()}`);
  return res.json();
}

// Brevo, for a deployment with no domain to verify. Resend delivers only to its
// own account holder until a domain is verified, and free hosts commonly block
// outbound SMTP; Brevo's free plan sends from a single sender address confirmed
// by an emailed link, over HTTPS. EMAIL_FROM may carry a display name
// ("Acme Access <access@acme.com>"); the address has to be the verified one.
function parseSender(from) {
  const fallbackName = process.env.EMAIL_FROM_NAME || 'Temporary Access';
  const match = /^\s*(.*?)\s*<([^>]+)>\s*$/.exec(from || '');
  if (match) return { name: match[1] || fallbackName, email: match[2].trim() };
  return { name: fallbackName, email: String(from || '').trim() };
}

async function sendViaBrevo({ to, subject, text, html }) {
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': process.env.BREVO_API_KEY,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      sender: parseSender(process.env.EMAIL_FROM),
      to: [{ email: to }],
      subject,
      textContent: text,
      htmlContent: html,
    }),
  });
  if (!res.ok) throw new Error(`Email send failed: ${res.status} ${await res.text()}`);
  return res.json();
}

// SigV4, signed by hand rather than pulling in the AWS SDK. One request to one
// endpoint does not justify ~20MB of dependency, and the signing steps below
// are the whole of what the SDK would do for this call.
function sha256Hex(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}
function hmac(key, value) {
  return crypto.createHmac('sha256', key).update(value, 'utf8').digest();
}

async function sendViaSes({ to, subject, text, html }) {
  const region = process.env.SES_REGION;
  const host = `email.${region}.amazonaws.com`;
  const canonicalUri = '/v2/email/outbound-emails';
  const body = JSON.stringify({
    FromEmailAddress: process.env.EMAIL_FROM,
    Destination: { ToAddresses: [to] },
    Content: {
      Simple: {
        Subject: { Data: subject, Charset: 'UTF-8' },
        Body: {
          Text: { Data: text, Charset: 'UTF-8' },
          Html: { Data: html, Charset: 'UTF-8' },
        },
      },
    },
  });

  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''); // 20240101T000000Z
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(body);

  const signedHeaders = 'content-type;host;x-amz-content-sha256;x-amz-date';
  const canonicalHeaders = `content-type:application/json\n`
    + `host:${host}\n`
    + `x-amz-content-sha256:${payloadHash}\n`
    + `x-amz-date:${amzDate}\n`;
  const canonicalRequest = ['POST', canonicalUri, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');

  const scope = `${dateStamp}/${region}/ses/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256Hex(canonicalRequest)].join('\n');

  const signingKey = hmac(
    hmac(hmac(hmac(`AWS4${process.env.SES_SECRET_ACCESS_KEY}`, dateStamp), region), 'ses'),
    'aws4_request'
  );
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign, 'utf8').digest('hex');

  const res = await fetch(`https://${host}${canonicalUri}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Host: host,
      'X-Amz-Content-Sha256': payloadHash,
      'X-Amz-Date': amzDate,
      Authorization: `AWS4-HMAC-SHA256 Credential=${process.env.SES_ACCESS_KEY_ID}/${scope}, `
        + `SignedHeaders=${signedHeaders}, Signature=${signature}`,
    },
    body,
  });
  if (!res.ok) throw new Error(`Email send failed: ${res.status} ${await res.text()}`);
  return res.json();
}

// Explicit when EMAIL_PROVIDER is set, inferred from whichever credentials
// exist otherwise -- so an existing Resend deployment keeps working with no
// config change at all.
function resolveEmailProvider() {
  const resend = {
    name: 'resend',
    send: sendViaResend,
    ready: Boolean(process.env.RESEND_API_KEY),
    missing: 'RESEND_API_KEY',
  };
  const ses = {
    name: 'ses',
    send: sendViaSes,
    ready: SES_KEYS.every((k) => process.env[k]),
    missing: SES_KEYS.filter((k) => !process.env[k]).join(', '),
  };

  const brevo = {
    name: 'brevo',
    send: sendViaBrevo,
    ready: Boolean(process.env.BREVO_API_KEY),
    missing: 'BREVO_API_KEY',
  };

  const named = (process.env.EMAIL_PROVIDER || '').trim().toLowerCase();
  if (named === 'resend') return resend;
  if (named === 'ses') return ses;
  if (named === 'brevo') return brevo;
  if (named) {
    return {
      name: named,
      send: null,
      ready: false,
      missing: `EMAIL_PROVIDER="${named}" is not a known provider (use "resend", "ses" or "brevo")`,
    };
  }

  if (resend.ready) return resend;
  if (ses.ready) return ses;
  if (brevo.ready) return brevo;
  return {
    name: 'none',
    send: null,
    ready: false,
    missing: 'RESEND_API_KEY, BREVO_API_KEY, or all of ' + SES_KEYS.join(', '),
  };
}

async function sendAccessEmail({ to, ...message }) {
  const provider = resolveEmailProvider();
  if (!provider.ready) throw new Error(`Email is not configured: missing ${provider.missing}`);
  if (!process.env.EMAIL_FROM) throw new Error('EMAIL_FROM is not configured');
  // Passed through rather than re-destructured: naming the fields twice means
  // adding one to the message silently drops it here.
  return provider.send({ to, ...renderAccessEmail(message) });
}

// ============================================================
// Audit log
// ============================================================
// Append-only, and never allowed to break the calling request: if the audit
// insert itself fails we log to stderr rather than fail a user-facing flow
// for a logging problem. `req` may be null for events raised by background
// jobs, which have no request context.
async function audit(req, { grantId = null, event, actor = null, detail = null }) {
  const ip = req ? (req.ip || req.socket?.remoteAddress || null) : null;
  const userAgent = req ? (req.header?.('User-Agent') || null) : null;
  const requestId = req?.id || null;

  try {
    await pool.query(
      `INSERT INTO audit_log (grant_id, event, actor, ip_address, user_agent, detail, request_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [grantId, event, actor, ip, userAgent, detail ? JSON.stringify(detail) : null, requestId]
    );
  } catch (err) {
    log.error('audit log write failed', { event, err: err.message });
  }

  // Same rule as the insert: a notification problem must never fail the flow
  // that produced the event. `enqueue` swallows its own errors for that reason,
  // and this is only awaited so the row is written inside the request rather
  // than after the response, where an error would have nowhere to go.
  await webhooks.enqueue(pool, event, {
    grantId,
    actor,
    ip,
    requestId,
    ...(detail || {}),
  });

  // Also emitted to the process log. The audit table is the record of
  // authorization decisions and is queried by a human after the fact; this is
  // the line that shows up in a log search next to the request that caused it.
  log.info('audit', { event, actor, grantId, requestId });
}

// ============================================================
// Grant status cache
// ============================================================
// The proxy re-authorizes on EVERY forwarded request, including every image
// and stylesheet the upstream app pulls in. Hitting Postgres for each of
// those would make the gateway the slowest thing in the stack, so statuses
// are cached for a few seconds. Revocation stays effectively instant because
// logout and admin-revoke bust the entry directly; the TTL is only the worst
// case for a change made by some other process.
const grantCache = new Map();

function cacheBust(grantId) {
  grantCache.delete(grantId);
}

// The TTL is only checked on read, so an entry that is never read again is
// never removed: one entry per grant this process has ever proxied, held for
// the life of a process meant to run for months. The sweeper bounds it by
// dropping everything already past the TTL, which by definition cannot be
// serving a cache hit to anyone.
function sweepGrantCache() {
  const cutoff = Date.now() - GRANT_CACHE_TTL_MS;
  for (const [id, entry] of grantCache) {
    if (entry.at < cutoff) grantCache.delete(id);
  }
}

async function loadGrant(grantId) {
  const hit = grantCache.get(grantId);
  if (hit && Date.now() - hit.at < GRANT_CACHE_TTL_MS) return hit.grant;
  const { rows } = await pool.query(
    'SELECT id, email, status, expires_at FROM access_grants WHERE id = $1',
    [grantId]
  );
  const grant = rows[0] || null;
  grantCache.set(grantId, { at: Date.now(), grant });
  return grant;
}

// ============================================================
// Session resolution
// ============================================================
// Sessions are carried in an httpOnly cookie rather than an Authorization
// header. The proxy forces this: when the browser loads the upstream app's
// own stylesheets, scripts and XHRs, it attaches cookies but never a bearer
// token. A header-based session simply cannot gate a reverse proxy.
function readSessionCookie(req) {
  if (req.cookies && req.cookies[COOKIE_NAME]) return req.cookies[COOKIE_NAME];
  // Raw-header fallback for the websocket upgrade path, which does not run
  // through Express middleware and so has no req.cookies.
  const raw = req.headers?.cookie;
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === COOKIE_NAME) return decodeURIComponent(v.join('='));
  }
  return null;
}

// Returns { ok: true, session } or { ok: false, reason }. Verifying the JWT
// signature is necessary but not sufficient -- the grant is re-read so that a
// revoked or expired grant kills the session immediately, instead of lingering
// until the token's own expiry catches up.
async function resolveSession(req) {
  const token = readSessionCookie(req);
  if (!token) return { ok: false, reason: 'no_session' };

  let payload;
  let sessionLapsed = false;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: [JWT_ALG] });
  } catch (err) {
    if (err.name !== 'TokenExpiredError') return { ok: false, reason: 'bad_token' };
    // The session is capped at the grant's expiry, so when a window closes
    // naturally the JWT and the grant expire at the same instant. Reporting
    // 'bad_token' there would tell a customer their session was unverifiable
    // when in truth their time simply ran out. Re-read the token with the
    // signature still enforced, purely to name the reason accurately -- the
    // grant lookup below remains the thing that actually decides access.
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET, {
        algorithms: [JWT_ALG],
        ignoreExpiration: true,
      });
      sessionLapsed = true;
    } catch {
      return { ok: false, reason: 'bad_token' };
    }
  }

  const grant = await loadGrant(payload.grantId);
  if (!grant) return { ok: false, reason: 'grant_missing' };
  if (grant.status === 'REVOKED') return { ok: false, reason: 'revoked' };
  // A window can be closed either by the background sweeper or lazily by the
  // check further down, depending on which got there first. Both mean the same
  // thing to the customer, so both must report the same reason -- otherwise
  // the message they see depends on timing they cannot observe.
  if (grant.status === 'EXPIRED') return { ok: false, reason: 'expired' };
  if (grant.status !== 'ACTIVE') return { ok: false, reason: 'not_active' };

  if (grant.expires_at && new Date() > new Date(grant.expires_at)) {
    await pool.query("UPDATE access_grants SET status = 'EXPIRED' WHERE id = $1", [grant.id]);
    cacheBust(grant.id);
    await audit(req, { grantId: grant.id, event: 'GRANT_EXPIRED', actor: 'system' });
    return { ok: false, reason: 'expired' };
  }

  // The grant is still open but this particular login has aged out. That is a
  // materially different message from 'expired': the customer still has time
  // left and can simply log in again with the same emailed credentials.
  if (sessionLapsed) return { ok: false, reason: 'session_expired' };

  return {
    ok: true,
    session: { grantId: grant.id, email: grant.email, expiresAt: grant.expires_at },
  };
}

// ============================================================
// Middleware
// ============================================================
function cookieOptions() {
  return { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'lax', path: '/' };
}

function adminCookieOptions() {
  // sameSite 'strict' rather than the customer cookie's 'lax'. The admin
  // console is never reached by cross-site navigation, and strict is what
  // stops a cross-site POST from riding an authenticated admin's cookie --
  // this is the CSRF control for every state-changing admin route.
  return { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'strict', path: GATE };
}

// Normalises an IPv4-mapped IPv6 address (::ffff:10.0.0.5) down to plain IPv4.
// Without this every IPv4 admin is denied on a dual-stack host, because the
// address arrives in v6 form and never matches a v4 CIDR.
function clientAddr(req) {
  const raw = req.ip || req.socket?.remoteAddress || '';
  try {
    const parsed = ipaddr.parse(raw.replace(/^::ffff:/i, ''));
    return parsed;
  } catch {
    return null;
  }
}

// First line of defence for the admin console: network position. The premise
// of this whole system is that admins have VPN access and customers do not,
// so the console has no business answering the public internet.
async function adminIpAllowlist(req, res, next) {
  if (!ADMIN_IP_ALLOWLIST.length) return next();

  const addr = clientAddr(req);
  const allowed = addr && ADMIN_IP_ALLOWLIST.some((cidr) => {
    // A v4 address cannot match a v6 range or vice versa; match() throws on
    // a kind mismatch rather than returning false.
    if (cidr[0].kind() !== addr.kind()) return false;
    return addr.match(cidr);
  });

  if (!allowed) {
    await audit(req, {
      event: 'ADMIN_IP_DENIED',
      actor: 'system',
      detail: { ip: req.ip || null, path: req.originalUrl },
    });
    // 404 rather than 403: an address that isn't permitted to use the console
    // learns nothing about whether one exists here.
    return res.status(404).json({ error: 'Not found' });
  }
  next();
}

// Mirrors requireSessionApi for customers: the admin row is re-read on every
// request, so disabling an account takes effect immediately rather than
// whenever the token happens to expire.
async function requireAdminSession(req, res, next) {
  const token = req.cookies?.[ADMIN_COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'Admin authentication required' });

  let payload;
  try {
    payload = jwt.verify(token, ADMIN_JWT_KEY, { algorithms: [JWT_ALG] });
  } catch {
    res.clearCookie(ADMIN_COOKIE_NAME, adminCookieOptions());
    return res.status(401).json({ error: 'Admin session invalid or expired' });
  }
  // Belt-and-braces alongside the derived signing key above.
  if (payload.typ !== 'admin') {
    res.clearCookie(ADMIN_COOKIE_NAME, adminCookieOptions());
    return res.status(401).json({ error: 'Admin session invalid' });
  }

  const { rows } = await pool.query(
    `SELECT id, email, role, disabled_at, must_change_password, totp_enabled
       FROM admins WHERE id = $1`,
    [payload.adminId]
  );
  const admin = rows[0];
  if (!admin || admin.disabled_at) {
    res.clearCookie(ADMIN_COOKIE_NAME, adminCookieOptions());
    return res.status(401).json({ error: 'Admin account is no longer active' });
  }

  // The role is read from the row on every request, not taken from the token.
  // A demotion has to take effect at once, for the same reason disabling an
  // account does -- a role carried in a JWT stays true until the token expires,
  // which is exactly the hour you did not want it to.
  req.admin = {
    id: admin.id,
    email: admin.email,
    role: admin.role,
    mustChangePassword: admin.must_change_password,
    totpEnabled: admin.totp_enabled,
  };
  next();
}

// ------------------------------------------------------------------
// Roles
// ------------------------------------------------------------------
// A capability check, not a role comparison. Handlers name what they need --
// `requireRole('owner')` -- rather than testing `role !== 'auditor'`, because
// the second form silently grants every future role that gets added.
const ROLES = ['owner', 'admin', 'auditor'];

function requireRole(...allowed) {
  return (req, res, next) => {
    if (allowed.includes(req.admin.role)) return next();
    // 403 rather than 404 here, unlike the IP allowlist: this caller has
    // already proved who they are, and hiding the route from them produces a
    // support ticket about a broken console rather than an understood refusal.
    return res.status(403).json({
      error: 'Your account does not have permission to do this.',
      requiredRole: allowed,
      role: req.admin.role,
    });
  };
}

// Two states in which an authenticated admin is allowed to do nothing except
// fix that state: a password that must be changed, and -- when the deployment
// requires two-factor -- an account that has not enrolled.
//
// Enforced server-side rather than by the console hiding buttons. A console
// that merely declines to show the form is a console, not a control.
function requireEnrolled(req, res, next) {
  if (req.admin.mustChangePassword) {
    return res.status(403).json({
      error: 'Change your password before using the console.',
      reason: 'password_change_required',
    });
  }
  if (requireAdminTotp() && !req.admin.totpEnabled) {
    return res.status(403).json({
      error: 'Two-factor authentication is required before using the console.',
      reason: 'totp_enrolment_required',
    });
  }
  next();
}

// Applied to every admin route, in order: network first, then identity, then
// whether that identity is in a state allowed to do anything.
const adminOnly = [adminIpAllowlist, requireAdminSession, requireEnrolled];
// For the handful of routes that must stay reachable while an admin is in one
// of those states -- changing the password, enrolling in TOTP, signing out.
const adminAuthed = [adminIpAllowlist, requireAdminSession];

async function requireSessionApi(req, res, next) {
  const result = await resolveSession(req);
  if (!result.ok) {
    res.clearCookie(COOKIE_NAME, cookieOptions());
    return res.status(401).json({ error: 'Access no longer valid', reason: result.reason });
  }
  req.session = result.session;
  next();
}

// ============================================================
// App
// ============================================================
const app = express();

// Only trust X-Forwarded-For when a reverse proxy is genuinely in front.
// Trusting it unconditionally would let any client spoof its own IP in the
// audit log and evade per-IP rate limiting.
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
app.disable('x-powered-by');

// ------------------------------------------------------------------
// Request identity, access logging and metrics
// ------------------------------------------------------------------
// First in the chain, so that everything after it -- including the rate
// limiters and the 404s -- is counted and correlated. A middleware that only
// covers the handlers that succeeded measures the wrong population.
const INBOUND_REQUEST_ID = /^[A-Za-z0-9_.-]{1,128}$/;

app.use((req, res, next) => {
  // An id from a load balancer or a calling service is reused so a trace does
  // not break at this hop, but it is validated first: the value ends up in log
  // lines and in a database column, and an unbounded header is how a log file
  // acquires forged newlines and a JSON collector acquires a parse error.
  const inbound = req.headers['x-request-id'];
  req.id = INBOUND_REQUEST_ID.test(inbound || '') ? inbound : crypto.randomUUID();
  req.log = log.child({ requestId: req.id });
  // Echoed back so a customer reporting a failure can quote something that
  // finds the exact request in the logs.
  res.setHeader('X-Request-Id', req.id);

  const startedAt = process.hrtime.bigint();
  // 'finish' fires only on a completed response; 'close' also covers a client
  // that hung up mid-transfer, which on a proxy is a normal and interesting
  // event rather than an edge case.
  res.once('close', () => {
    const seconds = Number(process.hrtime.bigint() - startedAt) / 1e9;
    const route = metrics.routePattern(req);
    const labels = { route, method: req.method, status: metrics.statusClass(res.statusCode) };
    metrics.counter('gateway_http_requests_total', labels);
    metrics.observe('gateway_http_request_duration_seconds', { route }, seconds);

    // Access lines are debug-level for the ordinary case: on a reverse proxy
    // this fires for every image and stylesheet the upstream app pulls in, and
    // at info level a single page load buries whatever else was happening.
    // Server errors are always worth a line.
    const level = res.statusCode >= 500 ? 'error' : 'debug';
    req.log[level]('request', {
      method: req.method,
      // The gate's own paths are bounded and safe to log whole. Everything else
      // belongs to the upstream app, whose URLs can carry anything a customer
      // types -- so those are logged without the query string.
      path: req.originalUrl.startsWith(GATE) ? req.originalUrl : req.path,
      status: res.statusCode,
      durationMs: Math.round(seconds * 1000),
      ip: req.ip,
    });
  });

  next();
});

app.use(cookieParser());

// Body parsing is scoped to the gate's own API. Applying express.json()
// globally would consume the request stream before the proxy could forward
// it, which silently hangs every POST and PUT bound for the upstream app.
app.use(`${GATE}/api`, express.json({ limit: '100kb' }));

app.use(GATE, helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      frameAncestors: ["'none'"],
    },
  },
}));

const gateLimiter = rateLimit({ windowMs: 60_000, max: 300 });
const createLimiter = rateLimit({ windowMs: 60_000, max: 20 });
const activateLimiter = rateLimit({ windowMs: 60_000, max: 30 });
// Per IP, in memory. The per-grant lockout in the login handler is the other
// half of this pair, for the same reason it is on the admin side: this limiter
// stops one source hammering, and the database lockout is what catches an
// attempt spread across many addresses, which a per-IP counter cannot see at
// all. Keep it looser than GRANT_MAX_FAILED_ATTEMPTS so a single-source attack
// still reaches the lockout and produces an audited GRANT_LOCKED event rather
// than an opaque 429.
const loginLimiter = rateLimit({
  windowMs: Number(process.env.LOGIN_RATE_WINDOW_MINUTES || 1) * 60_000,
  max: Number(process.env.LOGIN_RATE_MAX || 10),
  // JSON, because the login page parses the body to show the message. The
  // library's plain-text default reaches the customer as "Could not reach the
  // server", which sends them looking for the wrong problem.
  handler: (_req, res) => res.status(429).json({
    error: 'Too many attempts. Wait a minute and try again.',
    reason: 'rate_limited',
  }),
});
// Two different controls guard admin sign-in, and they are deliberately not
// the same number:
//
//   - this limiter is PER IP, in memory, and stops one source hammering or
//     spraying across many accounts;
//   - the lockout in the login handler is PER ACCOUNT, in Postgres, survives a
//     restart, and is what catches a distributed attempt on one account.
//
// The limiter must be the looser of the two, otherwise it always trips first
// and the account lockout becomes unreachable dead code -- and an operator
// sees an opaque 429 instead of an audited ADMIN_LOCKED event.
const adminLoginLimiter = rateLimit({
  windowMs: Number(process.env.ADMIN_LOGIN_RATE_WINDOW_MINUTES || 15) * 60_000,
  max: Number(process.env.ADMIN_LOGIN_RATE_MAX || 10),
  skipSuccessfulRequests: true,
  handler: async (req, res) => {
    await audit(req, {
      event: 'ADMIN_LOGIN_RATE_LIMITED',
      actor: 'system',
      detail: { ip: req.ip || null },
    });
    res.status(429).json({ error: 'Too many attempts. Try again later.' });
  },
});
app.use(GATE, gateLimiter);

// Static assets for the gate's own pages only. The previous build served
// __dirname, which published server.js, schema.sql and package.json to
// anyone who asked for them.
//
// `index: false` and the extension filter matter as much as the directory
// does: serving public/ wholesale also served admin.html and admin-login.html
// at their own filenames, which reach the same markup as the routes below
// without passing the IP allowlist those routes are wrapped in. Assets are
// public by nature; the console's markup is not.
const gateStatic = express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',
  index: false,
});
app.use(GATE, (req, res, next) =>
  /\.html?$/i.test(req.path) ? next() : gateStatic(req, res, next)
);

const page = (name) => (_req, res) => res.sendFile(path.join(__dirname, 'public', name));
app.get(`${GATE}/login`, page('login.html'));
app.get(`${GATE}/dashboard`, page('dashboard.html'));
// Both admin pages sit behind the IP allowlist too, so a disallowed network
// cannot even discover that a console exists here.
app.get(`${GATE}/admin`, adminIpAllowlist, page('admin.html'));
app.get(`${GATE}/admin-login`, adminIpAllowlist, page('admin-login.html'));
// Unauthenticated, so it says as little as possible: it used to return
// UPSTREAM_URL, which published the internal address of the app this whole
// system exists to keep off the public internet, to anyone who asked.
//
// It reports the database because that is the dependency whose loss the
// gateway cannot paper over -- no grant can be read, so nobody gets in --
// and because a container orchestrator restarting on a 503 is the behaviour
// you want. A process that is listening but cannot reach Postgres is not
// healthy, and answering `{"ok":true}` from it delays every alarm.
async function readiness(_req, res) {
  try {
    await pool.query('SELECT 1');
  } catch (err) {
    log.error('readiness: database unreachable', { err: err.message });
    return res.status(503).json({ ok: false, database: 'unreachable' });
  }
  res.json({ ok: true, database: 'ok' });
}

app.get(`${GATE}/health`, readiness);
app.get(`${GATE}/health/ready`, readiness);

// Liveness is deliberately not readiness, and the difference is not
// pedantry. A liveness probe that checks Postgres tells the orchestrator to
// *restart the gateway* when the database has a bad minute -- so a database
// blip the pool would have ridden out becomes a rolling restart of every
// instance, and the restarts keep coming for as long as the blip lasts.
//
// So: liveness answers "is this process still able to serve", readiness
// answers "should traffic be sent to it right now", and only the second one
// depends on anything downstream.
app.get(`${GATE}/health/live`, (_req, res) => {
  res.json({ ok: true, uptimeSeconds: Math.round(process.uptime()), version: SERVICE_VERSION });
});

// Prometheus scrape target. Served only when METRICS_TOKEN is set: the numbers
// here describe how much access is being granted and how often sign-in fails,
// which is reconnaissance on the one door into the internal network.
//
// The token is compared with timingSafeEqual over digests rather than the raw
// strings, so that neither the length nor a shared prefix is measurable.
app.get(`${GATE}/metrics`, (req, res) => {
  if (!METRICS_TOKEN) return res.status(404).json({ error: 'Not found' });

  const presented = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const a = crypto.createHash('sha256').update(presented).digest();
  const b = crypto.createHash('sha256').update(METRICS_TOKEN).digest();
  if (!crypto.timingSafeEqual(a, b)) return res.status(404).json({ error: 'Not found' });

  res.type('text/plain; version=0.0.4').send(metrics.render());
});

// The link in the access email points here.
app.get(`${GATE}/link/:token`, (req, res) => {
  if (!TOKEN_RE.test(req.params.token)) return res.status(404).send('Invalid access link');
  res.sendFile(path.join(__dirname, 'public', 'activate.html'));
});

// ============================================================
// Gate API -- admin authentication
// ============================================================
// Stricter than "contains an @", and length-capped. The loose version happily
// accepted `<img src=x onerror=...>@evil.com`, which then went into the HTML
// of an email sent over the client's name. That value is escaped at render
// time now; this is the cheaper half of the same fix -- refuse it at the door.
const MAX_EMAIL_LENGTH = 254;
const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;

function isValidEmail(value) {
  return typeof value === 'string' && value.length <= MAX_EMAIL_LENGTH && EMAIL_RE.test(value);
}

app.post(`${GATE}/api/admin/auth/login`, adminIpAllowlist, adminLoginLimiter, async (req, res) => {
  const { email, password, totpCode, backupCode } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const normalised = String(email).trim().toLowerCase();
  const { rows } = await pool.query('SELECT * FROM admins WHERE email = $1', [normalised]);
  const admin = rows[0];

  // Every failure below returns the same message and, as far as the caller can
  // measure, takes the same time -- an attacker learns nothing about which
  // admin emails exist.
  const deny = async (reason, status = 401) => {
    await audit(req, {
      event: 'ADMIN_LOGIN_FAILED',
      actor: normalised,
      detail: { reason },
    });
    return res.status(status).json({ error: 'Invalid credentials' });
  };

  if (!admin) {
    await bcrypt.compare(password, DUMMY_HASH);
    return deny('unknown_email');
  }
  if (admin.disabled_at) {
    await bcrypt.compare(password, DUMMY_HASH);
    return deny('disabled');
  }
  // Checked before the password: a locked account stays locked even when the
  // correct password finally arrives, which is the entire point of a lockout.
  if (admin.locked_until && new Date(admin.locked_until) > new Date()) {
    await bcrypt.compare(password, DUMMY_HASH);
    return deny('locked');
  }

  // Shared by the password branch and the second-factor branch below. A wrong
  // code has to count towards the lockout exactly as a wrong password does --
  // otherwise an attacker holding a valid password gets unlimited guesses at
  // six digits, and the second factor is worth nothing.
  const countFailure = async () => {
    // Incremented in the statement rather than read, added to, and written
    // back: guesses arriving together all read the same value under a
    // read-modify-write, so a parallel attacker records one attempt per round
    // instead of one per guess -- which is the lockout not working in exactly
    // the case it exists for. Postgres decides whether this attempt is the one
    // that locks, and says so in RETURNING.
    const { rows } = await pool.query(
      `UPDATE admins
          SET failed_login_attempts =
                CASE WHEN failed_login_attempts + 1 >= $1 THEN 0
                     ELSE failed_login_attempts + 1 END,
              locked_until =
                CASE WHEN failed_login_attempts + 1 >= $1
                     THEN now() + ($2 || ' minutes')::interval
                     ELSE locked_until END
        WHERE id = $3
       RETURNING failed_login_attempts, locked_until`,
      [ADMIN_MAX_FAILED_ATTEMPTS, String(ADMIN_LOCKOUT_MINUTES), admin.id]
    );
    // The counter resets to 0 as it locks, so 0 is how a lock reports itself.
    const lock = rows[0]?.failed_login_attempts === 0;
    if (lock) {
      await audit(req, {
        event: 'ADMIN_LOCKED',
        actor: admin.email,
        detail: { minutes: ADMIN_LOCKOUT_MINUTES, afterAttempts: ADMIN_MAX_FAILED_ATTEMPTS },
      });
    }
  };

  if (!(await bcrypt.compare(password, admin.password_hash))) {
    await countFailure();
    metrics.counter('gateway_logins_total', { principal: 'admin', outcome: 'bad_password' });
    return deny('bad_password');
  }

  // ---- second factor ----
  // Everything above this point answers identically whether or not the account
  // exists. Below it, the reply necessarily differs: asking for a code tells
  // the caller the password was right.
  //
  // That leak is inherent to any second factor presented after a password, and
  // it is the trade every two-step sign-in makes. It is acceptable here for the
  // reason it is acceptable everywhere: what the attacker learns is that a
  // password they already hold is correct, and the point of the second factor
  // is that this is no longer enough. The alternative -- always demanding a
  // code, including from accounts that have none -- turns an unenrolled admin's
  // sign-in into an unexplainable failure.
  let usedBackupCode = false;
  if (admin.totp_enabled) {
    const submittedBackup = totp.normaliseBackupCode(backupCode);

    if (!totpCode && !submittedBackup) {
      // Not counted as a failure. No credential was guessed here -- the console
      // simply has not asked for the code yet.
      return res.status(401).json({
        error: 'Enter the code from your authenticator app.',
        reason: 'totp_required',
      });
    }

    if (submittedBackup) {
      const codes = await pool.query(
        'SELECT id, code_hash FROM admin_backup_codes WHERE admin_id = $1 AND used_at IS NULL',
        [admin.id]
      );
      // Every unused code is compared, with no early exit, so the time taken
      // does not reveal the matching code's position in the list. They run
      // concurrently on the threadpool -- sequentially this would hold the
      // event loop, and therefore every proxied request, for the duration.
      const results = await Promise.all(
        codes.rows.map((row) => totp.verifyBackupCode(submittedBackup, row.code_hash))
      );
      const matched = codes.rows.find((_, i) => results[i])?.id || null;
      if (!matched) {
        await countFailure();
        metrics.counter('gateway_logins_total', { principal: 'admin', outcome: 'bad_backup_code' });
        return deny('bad_backup_code');
      }
      // Spent with the null check in the WHERE clause, so two sign-ins racing
      // with the same code cannot both consume it -- one UPDATE returns a row
      // and the other returns none.
      const spent = await pool.query(
        'UPDATE admin_backup_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL RETURNING id',
        [matched]
      );
      if (!spent.rows[0]) {
        await countFailure();
        return deny('backup_code_already_used');
      }
      usedBackupCode = true;

      const left = await pool.query(
        'SELECT count(*)::int AS n FROM admin_backup_codes WHERE admin_id = $1 AND used_at IS NULL',
        [admin.id]
      );
      await audit(req, {
        event: 'ADMIN_BACKUP_CODE_USED',
        actor: admin.email,
        detail: { remaining: left.rows[0].n },
      });
    } else {
      // `afterStep` is what makes a code single-use: see admins.totp_last_step.
      const step = totp.verify(admin.totp_secret, totpCode, { afterStep: admin.totp_last_step });
      if (step === null) {
        await countFailure();
        metrics.counter('gateway_logins_total', { principal: 'admin', outcome: 'bad_totp' });
        return deny('bad_totp');
      }
      // Conditional on the stored value so that two requests racing with the
      // same code cannot both move the marker forward and both succeed.
      const consumed = await pool.query(
        `UPDATE admins SET totp_last_step = $2
          WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)
        RETURNING id`,
        [admin.id, step]
      );
      if (!consumed.rows[0]) {
        await countFailure();
        return deny('totp_code_replayed');
      }
    }
  }

  await pool.query(
    'UPDATE admins SET failed_login_attempts = 0, locked_until = NULL, last_login_at = now() WHERE id = $1',
    [admin.id]
  );

  const token = jwt.sign(
    { adminId: admin.id, email: admin.email, typ: 'admin' },
    ADMIN_JWT_KEY,
    { algorithm: JWT_ALG, expiresIn: ADMIN_SESSION_TTL_SECONDS }
  );

  await audit(req, {
    event: 'ADMIN_LOGIN_SUCCESS',
    actor: admin.email,
    detail: { secondFactor: admin.totp_enabled ? (usedBackupCode ? 'backup_code' : 'totp') : 'none' },
  });
  metrics.counter('gateway_logins_total', { principal: 'admin', outcome: 'success' });

  res.cookie(ADMIN_COOKIE_NAME, token, {
    ...adminCookieOptions(),
    maxAge: ADMIN_SESSION_TTL_SECONDS * 1000,
  });
  // The console needs both flags to know whether to route straight to a forced
  // password change or an enrolment screen instead of the grants view.
  res.json({
    email: admin.email,
    role: admin.role,
    mustChangePassword: admin.must_change_password,
    totpEnabled: admin.totp_enabled,
    totpRequired: requireAdminTotp(),
  });
});

// adminAuthed, not adminOnly: someone stuck behind a forced password change or
// a two-factor enrolment must still be able to sign out. A console you can
// enter and not leave is a bug report.
app.post(`${GATE}/api/admin/auth/logout`, adminAuthed, async (req, res) => {
  await audit(req, { event: 'ADMIN_LOGOUT', actor: req.admin.email });
  res.clearCookie(ADMIN_COOKIE_NAME, adminCookieOptions());
  res.json({ message: 'Signed out.' });
});

// Also carries the two limits the console needs to render honestly: it should
// not offer a duration the server will reject, and it should be able to tell
// an admin how long the link they are about to send stays openable.
//
// adminAuthed rather than adminOnly, because this is how the console discovers
// that it is in one of those states in the first place.
app.get(`${GATE}/api/admin/auth/me`, adminAuthed, (req, res) => {
  res.json({
    email: req.admin.email,
    role: req.admin.role,
    mustChangePassword: req.admin.mustChangePassword,
    totpEnabled: req.admin.totpEnabled,
    totpRequired: requireAdminTotp(),
    maxDurationHours: MAX_DURATION_HOURS,
    pendingExpiryHours: PENDING_EXPIRY_HOURS,
    requireGrantReason: requireGrantReason(),
  });
});

// ============================================================
// Gate API -- the admin's own account
// ============================================================
// Everything in this section acts on req.admin and takes no id. Changing
// someone else's password or resetting someone else's second factor is not
// something this system offers at all: an owner can disable an account and
// issue a new one, which is auditable and does not leave one admin able to
// impersonate another.

function passwordProblem(password) {
  if (typeof password !== 'string' || password.length < ADMIN_MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${ADMIN_MIN_PASSWORD_LENGTH} characters.`;
  }
  // Capped because bcrypt silently truncates at 72 bytes: a 200-character
  // passphrase would be stored as its first 72 and the rest would do nothing,
  // which is worse than saying so.
  if (Buffer.byteLength(password) > 72) return 'Password must be 72 bytes or fewer.';
  return null;
}

app.post(`${GATE}/api/admin/auth/password`, adminAuthed, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};

  const problem = passwordProblem(newPassword);
  if (problem) return res.status(400).json({ error: problem });
  if (currentPassword === newPassword) {
    return res.status(400).json({ error: 'The new password must be different.' });
  }

  const { rows } = await pool.query('SELECT password_hash FROM admins WHERE id = $1', [req.admin.id]);
  // Re-checked even though the caller already holds a valid session. A session
  // cookie is something an unattended laptop also has; the current password is
  // what proves the person at the keyboard is the account holder.
  if (!rows[0] || !(await bcrypt.compare(String(currentPassword || ''), rows[0].password_hash))) {
    await audit(req, {
      event: 'ADMIN_PASSWORD_CHANGE_FAILED',
      actor: req.admin.email,
      detail: { reason: 'bad_current_password' },
    });
    return res.status(401).json({ error: 'Current password is incorrect.' });
  }

  await pool.query(
    `UPDATE admins
        SET password_hash = $2, must_change_password = false, password_changed_at = now(),
            failed_login_attempts = 0, locked_until = NULL
      WHERE id = $1`,
    [req.admin.id, await hashPassword(newPassword)]
  );

  await audit(req, { event: 'ADMIN_PASSWORD_CHANGED', actor: req.admin.email });
  res.json({ message: 'Password updated.' });
});

// ---- two-factor enrolment ----
// Three steps, because a secret that is stored the moment it is displayed
// produces accounts that are half-enrolled: the admin closed the tab, the
// column has a secret, and nothing can tell whether their phone has it too.
//
//   setup    issues a secret, stores it unconfirmed, returns it once
//   enable   verifies a code against it, flips totp_enabled, issues backup codes
//   disable  requires the password and a live code
app.post(`${GATE}/api/admin/auth/totp/setup`, adminAuthed, async (req, res) => {
  if (req.admin.totpEnabled) {
    return res.status(409).json({ error: 'Two-factor is already enabled for this account.' });
  }

  const secret = totp.generateSecret();
  // Overwrites any earlier unconfirmed secret. Calling setup twice means the
  // admin restarted enrolment -- the first secret was never proved and must
  // stop working, or two phones end up able to sign in as this account.
  await pool.query(
    'UPDATE admins SET totp_secret = $2, totp_confirmed_at = NULL WHERE id = $1',
    [req.admin.id, secret]
  );
  await audit(req, { event: 'ADMIN_TOTP_SETUP_STARTED', actor: req.admin.email });

  res.json({
    secret,
    // The issuer is the public hostname, so an admin holding codes for several
    // environments can tell staging from production on their phone.
    otpauthUri: totp.otpauthUri({
      secret,
      account: req.admin.email,
      issuer: new URL(process.env.PUBLIC_BASE_URL).host,
    }),
    digits: totp.DIGITS,
    periodSeconds: totp.STEP_SECONDS,
  });
});

app.post(`${GATE}/api/admin/auth/totp/enable`, adminAuthed, async (req, res) => {
  const { code } = req.body || {};
  if (req.admin.totpEnabled) {
    return res.status(409).json({ error: 'Two-factor is already enabled for this account.' });
  }

  const { rows } = await pool.query('SELECT totp_secret FROM admins WHERE id = $1', [req.admin.id]);
  const secret = rows[0]?.totp_secret;
  if (!secret) return res.status(409).json({ error: 'Start enrolment first.', reason: 'no_secret' });

  const step = totp.verify(secret, code);
  if (step === null) {
    await audit(req, {
      event: 'ADMIN_TOTP_ENABLE_FAILED',
      actor: req.admin.email,
      detail: { reason: 'bad_code' },
    });
    return res.status(400).json({ error: 'That code is not valid. Check your phone clock and try again.' });
  }

  // Recovery codes are generated here and shown exactly once. They are the
  // answer to a lost phone, and without them the only recovery is SSH to the
  // host -- which is a real control, but not one to rely on at 2am.
  const codes = Array.from({ length: totp.BACKUP_CODE_COUNT }, () => totp.generateBackupCode());

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `UPDATE admins
          SET totp_enabled = true, totp_confirmed_at = now(), totp_last_step = $2
        WHERE id = $1`,
      [req.admin.id, step]
    );
    // Any codes from a previous enrolment are cleared, not added to: a set
    // printed for an old secret must not still open the account.
    await client.query('DELETE FROM admin_backup_codes WHERE admin_id = $1', [req.admin.id]);
    // Hashed concurrently on the libuv threadpool rather than one after
    // another. See lib/totp.js: ten sequential bcrypt hashes here would block
    // the event loop -- and therefore every proxied request -- for seconds.
    const hashes = await Promise.all(codes.map((code) => totp.hashBackupCode(code)));
    await client.query(
      `INSERT INTO admin_backup_codes (admin_id, code_hash)
       SELECT $1, unnest($2::text[])`,
      [req.admin.id, hashes]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }

  await audit(req, { event: 'ADMIN_TOTP_ENABLED', actor: req.admin.email });
  res.json({ message: 'Two-factor enabled.', backupCodes: codes });
});

app.post(`${GATE}/api/admin/auth/totp/disable`, adminAuthed, async (req, res) => {
  const { password, code } = req.body || {};
  if (!req.admin.totpEnabled) {
    return res.status(409).json({ error: 'Two-factor is not enabled for this account.' });
  }
  // Checked before anything is verified, because the answer does not depend on
  // the credentials: when the deployment mandates two-factor, there is no
  // combination of password and code that turns it off.
  if (requireAdminTotp()) {
    return res.status(403).json({
      error: 'This deployment requires two-factor authentication. It cannot be turned off.',
    });
  }
  // Turning the second factor off is the one action an attacker holding a
  // stolen session cookie most wants, so it costs both the other factors.
  const { rows } = await pool.query(
    'SELECT password_hash, totp_secret, totp_last_step FROM admins WHERE id = $1',
    [req.admin.id]
  );
  const admin = rows[0];
  const passwordOk = admin && await bcrypt.compare(String(password || ''), admin.password_hash);
  const codeOk = admin && totp.verify(admin.totp_secret, code, { afterStep: admin.totp_last_step }) !== null;
  if (!passwordOk || !codeOk) {
    await audit(req, {
      event: 'ADMIN_TOTP_DISABLE_FAILED',
      actor: req.admin.email,
      detail: { reason: passwordOk ? 'bad_code' : 'bad_password' },
    });
    return res.status(401).json({ error: 'Password and a current code are both required.' });
  }

  await pool.query(
    `UPDATE admins
        SET totp_enabled = false, totp_secret = NULL, totp_confirmed_at = NULL, totp_last_step = NULL
      WHERE id = $1`,
    [req.admin.id]
  );
  await pool.query('DELETE FROM admin_backup_codes WHERE admin_id = $1', [req.admin.id]);

  await audit(req, { event: 'ADMIN_TOTP_DISABLED', actor: req.admin.email });
  res.json({ message: 'Two-factor disabled.' });
});

// Re-issuing recovery codes invalidates the previous set, which is the point:
// it is what an admin does after using one, or after finding the printout in a
// drawer they no longer trust.
app.post(`${GATE}/api/admin/auth/totp/backup-codes`, adminAuthed, async (req, res) => {
  const { password } = req.body || {};
  if (!req.admin.totpEnabled) {
    return res.status(409).json({ error: 'Two-factor is not enabled for this account.' });
  }
  const { rows } = await pool.query('SELECT password_hash FROM admins WHERE id = $1', [req.admin.id]);
  if (!rows[0] || !(await bcrypt.compare(String(password || ''), rows[0].password_hash))) {
    return res.status(401).json({ error: 'Password is incorrect.' });
  }

  const codes = Array.from({ length: totp.BACKUP_CODE_COUNT }, () => totp.generateBackupCode());
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM admin_backup_codes WHERE admin_id = $1', [req.admin.id]);
    const hashes = await Promise.all(codes.map((code) => totp.hashBackupCode(code)));
    await client.query(
      `INSERT INTO admin_backup_codes (admin_id, code_hash)
       SELECT $1, unnest($2::text[])`,
      [req.admin.id, hashes]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }

  await audit(req, { event: 'ADMIN_BACKUP_CODES_REISSUED', actor: req.admin.email });
  res.json({ backupCodes: codes });
});

// ============================================================
// Gate API -- team management
// ============================================================
// Creating admins used to require SSH to the host and `npm run create-admin`.
// That was a real control -- recovery needed shell access -- but it does not
// survive contact with a company: onboarding a colleague should not be a
// deploy, and offboarding one at 6pm on a Friday must not wait for whoever
// holds the SSH key.
//
// The control it replaces is kept in a different form: only an owner can do
// any of this, every action is audited with both parties named, and there is
// still no self-service signup and no password-reset email.

const ADMIN_LIST_FIELDS = `id, email, role, disabled_at, last_login_at, created_at,
                           totp_enabled, must_change_password`;

// Owner and admin can see who else holds an account -- knowing which colleagues
// can mint access is not privileged information within a team, and hiding it
// mostly stops people noticing an account that should have been removed.
app.get(`${GATE}/api/admin/admins`, adminOnly, requireRole('owner', 'admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT ${ADMIN_LIST_FIELDS} FROM admins ORDER BY disabled_at NULLS FIRST, email`
  );
  res.json({ admins: rows, roles: ROLES });
});

app.post(`${GATE}/api/admin/admins`, adminOnly, requireRole('owner'), async (req, res) => {
  const email = normaliseEmail(req.body?.email);
  const role = String(req.body?.role || 'admin');

  if (!isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });
  if (!ROLES.includes(role)) {
    return res.status(400).json({ error: `role must be one of: ${ROLES.join(', ')}` });
  }

  // Generated here rather than chosen by the creator. A password one person
  // picks for another is a password that person still knows, and
  // must_change_password below is what bounds how long that matters.
  const temporaryPassword = generatePassword(20);

  let created;
  try {
    const { rows } = await pool.query(
      `INSERT INTO admins (email, password_hash, role, must_change_password)
       VALUES ($1, $2, $3, true)
       RETURNING ${ADMIN_LIST_FIELDS}`,
      [email, await hashPassword(temporaryPassword), role]
    );
    created = rows[0];
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'That admin already exists.' });
    throw err;
  }

  await audit(req, {
    event: 'ADMIN_CREATED',
    actor: req.admin.email,
    detail: { subject: email, role },
  });

  // Returned once and never retrievable. The console shows it to the owner to
  // relay; there is deliberately no email path for admin credentials, because
  // an inbox is exactly where an attacker who has compromised one would look.
  res.status(201).json({ admin: created, temporaryPassword });
});

// The two guards below are the same guard twice: an owner must not be able to
// leave the system with no owner in it. Nothing in this application can create
// the first owner, so recovering from that means SQL on the host -- which is
// a fine last resort and a terrible thing to reach by clicking a button.
async function otherActiveOwnerExists(excludingId) {
  const { rows } = await pool.query(
    `SELECT count(*)::int AS n FROM admins
      WHERE role = 'owner' AND disabled_at IS NULL AND id <> $1`,
    [excludingId]
  );
  return rows[0].n > 0;
}

app.post(`${GATE}/api/admin/admins/:id/role`, adminOnly, requireRole('owner'), async (req, res) => {
  if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Admin not found' });
  const role = String(req.body?.role || '');
  if (!ROLES.includes(role)) {
    return res.status(400).json({ error: `role must be one of: ${ROLES.join(', ')}` });
  }

  const { rows: found } = await pool.query('SELECT id, email, role FROM admins WHERE id = $1', [req.params.id]);
  const subject = found[0];
  if (!subject) return res.status(404).json({ error: 'Admin not found' });
  if (subject.role === role) return res.json({ admin: subject });

  if (subject.role === 'owner' && !(await otherActiveOwnerExists(subject.id))) {
    return res.status(409).json({ error: 'This is the last owner. Promote someone else first.' });
  }

  const { rows } = await pool.query(
    `UPDATE admins SET role = $2 WHERE id = $1 RETURNING ${ADMIN_LIST_FIELDS}`,
    [subject.id, role]
  );
  await audit(req, {
    event: 'ADMIN_ROLE_CHANGED',
    actor: req.admin.email,
    detail: { subject: subject.email, from: subject.role, to: role },
  });
  res.json({ admin: rows[0] });
});

// Disable rather than delete. The grants this person issued reference their row
// -- see access_grants.created_by -- and an audit trail that has lost the name
// of whoever authorised a window of access is not an audit trail.
app.post(`${GATE}/api/admin/admins/:id/disable`, adminOnly, requireRole('owner'), async (req, res) => {
  if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Admin not found' });
  if (req.params.id === req.admin.id) {
    return res.status(409).json({ error: 'You cannot disable your own account.' });
  }

  const { rows: found } = await pool.query('SELECT id, email, role FROM admins WHERE id = $1', [req.params.id]);
  const subject = found[0];
  if (!subject) return res.status(404).json({ error: 'Admin not found' });
  if (subject.role === 'owner' && !(await otherActiveOwnerExists(subject.id))) {
    return res.status(409).json({ error: 'This is the last owner. Promote someone else first.' });
  }

  const { rows } = await pool.query(
    `UPDATE admins SET disabled_at = now() WHERE id = $1 AND disabled_at IS NULL
     RETURNING ${ADMIN_LIST_FIELDS}`,
    [subject.id]
  );
  if (!rows[0]) return res.status(409).json({ error: 'That account is already disabled.' });

  // Takes effect on their very next request, not at token expiry:
  // requireAdminSession re-reads disabled_at on every call. That is the whole
  // reason it re-reads.
  await audit(req, {
    event: 'ADMIN_DISABLED',
    actor: req.admin.email,
    detail: { subject: subject.email },
  });
  res.json({ admin: rows[0] });
});

app.post(`${GATE}/api/admin/admins/:id/enable`, adminOnly, requireRole('owner'), async (req, res) => {
  if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Admin not found' });

  // The lockout counters are cleared alongside: an account disabled during an
  // incident is often also an account that was being guessed at, and coming
  // back to a fresh lockout is a confusing way to return.
  const { rows } = await pool.query(
    `UPDATE admins
        SET disabled_at = NULL, failed_login_attempts = 0, locked_until = NULL
      WHERE id = $1 AND disabled_at IS NOT NULL
      RETURNING ${ADMIN_LIST_FIELDS}`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'No disabled admin with that id.' });

  await audit(req, {
    event: 'ADMIN_ENABLED',
    actor: req.admin.email,
    detail: { subject: rows[0].email },
  });
  res.json({ admin: rows[0] });
});

// ============================================================
// Gate API -- admin
// ============================================================

app.post(`${GATE}/api/admin/grants`, adminOnly, requireRole('owner', 'admin'), createLimiter, async (req, res) => {
  const { durationHours, relay } = req.body || {};
  // Normalised before it is stored, because login normalises before it looks
  // up. Storing what the admin typed and matching on it exactly is what made a
  // mixed-case address create a grant nobody could use.
  const email = normaliseEmail(req.body?.email);
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });

  const hours = Number(durationHours);
  if (!Number.isFinite(hours) || hours <= 0 || hours > MAX_DURATION_HOURS) {
    return res.status(400).json({ error: `durationHours must be > 0 and <= ${MAX_DURATION_HOURS}` });
  }

  // Trimmed to null so that a field the admin tabbed through is stored as
  // "absent" rather than as an empty string that reads like an answer.
  const reason = String(req.body?.reason || '').trim().slice(0, MAX_REASON_LENGTH) || null;
  if (requireGrantReason() && !reason) {
    return res.status(400).json({
      error: 'A reason is required. Reference the ticket, incident or contract this access is for.',
      reason: 'reason_required',
    });
  }

  // The invariant: at most one LIVE grant per email, where live means PENDING
  // or ACTIVE. Two concurrent live grants used to be accepted silently and
  // then half-work -- login reads the newest row only, so the older grant's
  // password (entirely valid, freshly emailed) failed against the newer
  // grant's hash, and the failure was counted against the wrong grant.
  //
  // uniq_live_grant_per_email is the enforcement; this lookup exists to give
  // the console something useful to say, including which grant is in the way.
  const live = await pool.query(
    `SELECT id, status, expires_at FROM access_grants
     WHERE email = $1 AND status IN ('PENDING','ACTIVE')
     ORDER BY created_at DESC LIMIT 1`,
    [email]
  );
  if (live.rows[0]) {
    await audit(req, {
      grantId: live.rows[0].id,
      event: 'GRANT_CREATE_REJECTED',
      actor: req.admin.email,
      detail: { reason: 'live_grant_exists', email },
    });
    return res.status(409).json({
      error: 'This person already has a live grant. Revoke it before issuing a new one.',
      existingGrant: {
        id: live.rows[0].id,
        status: live.rows[0].status,
        expiresAt: live.rows[0].expires_at,
      },
    });
  }

  const token = generateToken();
  const password = generatePassword();
  const durationSeconds = Math.round(hours * 3600);

  let grant;
  try {
    const { rows } = await pool.query(
      `INSERT INTO access_grants
         (email, token_hash, password_hash, duration_seconds, status, reason,
          created_by, created_by_email)
       VALUES ($1, $2, $3, $4, 'PENDING', $5, $6, $7)
       RETURNING id, email, status, created_at, reason, created_by_email`,
      [email, hashToken(token), await hashPassword(password), durationSeconds, reason,
        req.admin.id, req.admin.email]
    );
    grant = rows[0];
  } catch (err) {
    // Two admins issuing to the same person at the same moment lose the race
    // here rather than at the check above. Told apart by constraint name --
    // the other 23505 in this route is a token collision, which means
    // something entirely different to the admin reading the message.
    if (err.code === '23505' && err.constraint === 'uniq_live_grant_per_email') {
      return res.status(409).json({
        error: 'This person already has a live grant. Revoke it before issuing a new one.',
      });
    }
    if (err.code === '23505') return res.status(409).json({ error: 'Token collision, please retry' });
    throw err;
  }

  await audit(req, {
    grantId: grant.id,
    event: 'GRANT_CREATED',
    actor: req.admin.email,
    detail: { email, durationHours: hours, reason },
  });
  metrics.counter('gateway_grants_total', { transition: 'created' });

  const accessUrl = `${process.env.PUBLIC_BASE_URL}${GATE}/link/${token}`;
  const durationLabel = hoursLabel(hours);
  const payload = {
    grant: {
      id: grant.id,
      email: grant.email,
      status: grant.status,
      createdAt: grant.created_at,
      reason: grant.reason,
      createdByEmail: grant.created_by_email,
    },
    accessUrl,
  };

  try {
    await sendAccessEmail({
      to: email,
      accessUrl,
      username: email,
      password,
      durationLabel,
      linkExpiryLabel: hoursLabel(PENDING_EXPIRY_HOURS),
    });
  } catch (err) {
    await audit(req, {
      grantId: grant.id,
      event: 'GRANT_EMAIL_FAILED',
      actor: req.admin.email,
      detail: { error: err.message },
    });
    metrics.counter('gateway_email_total', { outcome: 'failed' });
    // The grant is real even though the email is not, so hand the admin the
    // credentials to relay by hand. Without the password here the grant would
    // be dead on arrival and would have to be recreated.
    return res.status(202).json({
      ...payload,
      warning: 'Grant created, but the email failed to send. Relay these credentials manually.',
      detail: err.message,
      password,
    });
  }

  // ACCEPTED, not SENT. A 200 from the provider means it took the message,
  // not that anyone received it -- a later bounce or spam-filter drop is
  // invisible here, and an audit trail that says "sent" would agree with the
  // admin and disagree with reality. Webhooks would close the gap and are not
  // on the plan; naming the event honestly is the next best thing.
  await audit(req, { grantId: grant.id, event: 'GRANT_EMAIL_ACCEPTED', actor: req.admin.email });
  metrics.counter('gateway_email_total', { outcome: 'accepted' });

  // Opt-in, because the admin asked to read the password out rather than rely
  // on the email -- the reissue path, usually, after a message that was
  // accepted and never arrived. It is not returned by default: the password
  // has no business being in a response body, a browser tab or a screen
  // recording unless someone deliberately needs it there.
  //
  // Audited as its own event. A credential leaving the system by a second
  // route is exactly the kind of thing the log should be able to answer for.
  if (relay) {
    await audit(req, {
      grantId: grant.id,
      event: 'GRANT_PASSWORD_RELAYED',
      actor: req.admin.email,
      detail: { reason: 'admin_requested_manual_relay' },
    });
    return res.status(201).json({ ...payload, password });
  }

  res.status(201).json(payload);
});

// Readable by every role, auditors included: reading who has access is the
// whole job of an auditor, and it is the routes that change something that
// carry a role check.
//
// Filterable, because a console that can only show the newest hundred rows
// stops being useful at the point a company actually starts using it -- "did
// this contractor ever have access" is unanswerable from a fixed window.
app.get(`${GATE}/api/admin/grants`, adminOnly, async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
  const conditions = [];
  const params = [];

  if (req.query.status) {
    const statuses = String(req.query.status).split(',').map((s) => s.trim().toUpperCase());
    const valid = statuses.filter((s) => GRANT_STATUSES.includes(s));
    if (!valid.length) return res.status(400).json({ error: `status must be one of: ${GRANT_STATUSES.join(', ')}` });
    params.push(valid);
    conditions.push(`status = ANY($${params.length})`);
  }
  if (req.query.email) {
    // Normalised, not pattern-matched: this searches for a person, and the
    // index on access_grants(email) is on the raw column, so a LIKE with a
    // leading wildcard would scan the table on every keystroke.
    params.push(normaliseEmail(req.query.email));
    conditions.push(`email = $${params.length}`);
  }
  params.push(limit);

  const { rows } = await pool.query(
    `SELECT id, email, status, created_at, activated_at, expires_at, activated_ip,
            duration_seconds, extended_seconds, reason, created_by_email, resend_count
       FROM access_grants
      ${conditions.length ? `WHERE ${conditions.join(' AND ')}` : ''}
      ORDER BY created_at DESC LIMIT $${params.length}`,
    params
  );
  res.json({ grants: rows });
});

// Powers the console's check before the admin submits, so a collision with an
// existing live grant is visible up front rather than as an error afterwards.
// Deliberately not a general search: it answers one question about one address.
app.get(`${GATE}/api/admin/grants/live`, adminOnly, async (req, res) => {
  const email = normaliseEmail(req.query.email);
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });

  const { rows } = await pool.query(
    `SELECT id, email, status, created_at, expires_at, duration_seconds
     FROM access_grants WHERE email = $1 AND status IN ('PENDING','ACTIVE')
     ORDER BY created_at DESC LIMIT 1`,
    [email]
  );
  res.json({ grant: rows[0] || null });
});

app.post(`${GATE}/api/admin/grants/:id/revoke`, adminOnly, requireRole('owner', 'admin'), async (req, res) => {
  // A malformed id is a 404, not a 500: an id that cannot exist is a grant
  // that does not exist, and Postgres should never see the value at all.
  if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Grant not found or not revocable' });

  const { rows } = await pool.query(
    `UPDATE access_grants SET status = 'REVOKED'
     WHERE id = $1 AND status IN ('PENDING','ACTIVE') RETURNING id, status`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Grant not found or not revocable' });

  cacheBust(rows[0].id);
  await audit(req, {
    grantId: rows[0].id,
    event: 'GRANT_REVOKED',
    actor: req.admin.email,
    detail: { reason: 'admin_action' },
  });
  metrics.counter('gateway_grants_total', { transition: 'revoked' });
  res.json({ grant: rows[0] });
});

// Adds time to a window that is already running.
//
// Without this the only way to give someone another hour was to revoke and
// reissue: new link, new password, a fresh email, and whatever they were in the
// middle of thrown away. That is a bad enough experience that the real-world
// workaround is to issue every grant for far longer than it needs to be, which
// defeats the point of the product.
//
// The ceiling is on the total, not on the increment, so repeated extensions
// cannot walk a one-hour grant past MAX_DURATION_HOURS an hour at a time.
app.post(`${GATE}/api/admin/grants/:id/extend`, adminOnly, requireRole('owner', 'admin'), async (req, res) => {
  if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Grant not found' });

  const addHours = Number(req.body?.addHours);
  if (!Number.isFinite(addHours) || addHours <= 0) {
    return res.status(400).json({ error: 'addHours must be greater than 0' });
  }
  const addSeconds = Math.round(addHours * 3600);

  const { rows: found } = await pool.query(
    `SELECT id, email, status, duration_seconds, extended_seconds, expires_at
       FROM access_grants WHERE id = $1`,
    [req.params.id]
  );
  const grant = found[0];
  if (!grant || !['PENDING', 'ACTIVE'].includes(grant.status)) {
    // An expired or revoked window is not extended, it is reissued. Reopening
    // one would resurrect credentials that have already been treated as dead --
    // including by whoever revoked them.
    return res.status(409).json({ error: 'Only a pending or active grant can be extended.' });
  }

  const totalSeconds = grant.duration_seconds + grant.extended_seconds + addSeconds;
  if (totalSeconds > MAX_DURATION_HOURS * 3600) {
    return res.status(400).json({
      error: `That would take the total past the ${MAX_DURATION_HOURS}-hour ceiling.`,
      currentTotalHours: Number(((grant.duration_seconds + grant.extended_seconds) / 3600).toFixed(2)),
      maxDurationHours: MAX_DURATION_HOURS,
    });
  }

  // Two clocks again, and they move differently. An ACTIVE grant has a real
  // expires_at to push out; a PENDING one has not started, so only the duration
  // it will get when it does changes -- writing an expires_at onto it here
  // would start the clock without anyone opening the link.
  const { rows } = await pool.query(
    `UPDATE access_grants
        SET extended_seconds = extended_seconds + $2,
            expires_at = CASE WHEN status = 'ACTIVE'
                              THEN expires_at + ($3 || ' seconds')::interval
                              ELSE expires_at END
      WHERE id = $1 AND status IN ('PENDING','ACTIVE')
      RETURNING id, email, status, expires_at, duration_seconds, extended_seconds`,
    [grant.id, addSeconds, String(addSeconds)]
  );
  if (!rows[0]) return res.status(409).json({ error: 'Only a pending or active grant can be extended.' });

  // The cached copy carries expires_at, and the proxy reads it on every
  // request. Without this the customer keeps being cut off at the old time for
  // up to GRANT_CACHE_TTL_MS after being told they had longer.
  cacheBust(grant.id);
  await audit(req, {
    grantId: grant.id,
    event: 'GRANT_EXTENDED',
    actor: req.admin.email,
    detail: {
      addHours,
      newExpiresAt: rows[0].expires_at,
      totalHours: Number((totalSeconds / 3600).toFixed(2)),
    },
  });
  metrics.counter('gateway_grants_total', { transition: 'extended' });
  res.json({ grant: rows[0] });
});

// Re-sends the credentials for a grant that has not been opened yet, with a
// new password and a new link.
//
// The common case is mundane: the message went to spam, or the address had a
// typo the admin has since noticed on the phone. The old behaviour -- revoke
// and reissue -- worked, but it made the audit trail read as though access had
// been granted twice and withdrawn once, which is not what happened.
//
// Both secrets are rotated rather than re-sent. The first pair has been sitting
// in a mail queue, a spam quarantine and possibly the wrong person's inbox; a
// resend is exactly the moment to assume they are compromised.
app.post(`${GATE}/api/admin/grants/:id/resend`, adminOnly, requireRole('owner', 'admin'), createLimiter, async (req, res) => {
  if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Grant not found' });
  const { relay } = req.body || {};

  const { rows: found } = await pool.query(
    'SELECT id, email, status, duration_seconds, extended_seconds FROM access_grants WHERE id = $1',
    [req.params.id]
  );
  const grant = found[0];
  if (!grant) return res.status(404).json({ error: 'Grant not found' });
  if (grant.status !== 'PENDING') {
    // Deliberately not offered for an ACTIVE grant. The customer is already in;
    // rotating the password under them would end their session and produce a
    // support ticket rather than solve one.
    return res.status(409).json({
      error: 'Only a grant that has not been opened yet can be re-sent.',
      status: grant.status,
    });
  }

  const token = generateToken();
  const password = generatePassword();

  // created_at is reset with them, because PENDING_EXPIRY_HOURS runs from it:
  // a link re-sent twenty-three hours in would otherwise arrive with an hour
  // left on a clock the customer knows nothing about.
  const { rows } = await pool.query(
    `UPDATE access_grants
        SET token_hash = $2, password_hash = $3, created_at = now(),
            resend_count = resend_count + 1, failed_login_attempts = 0, locked_until = NULL
      WHERE id = $1 AND status = 'PENDING'
      RETURNING id, email, status, created_at, resend_count`,
    [grant.id, hashToken(token), await hashPassword(password)]
  );
  if (!rows[0]) return res.status(409).json({ error: 'Only a grant that has not been opened yet can be re-sent.' });

  const accessUrl = `${process.env.PUBLIC_BASE_URL}${GATE}/link/${token}`;
  const hours = (grant.duration_seconds + grant.extended_seconds) / 3600;
  const payload = { grant: rows[0], accessUrl };

  await audit(req, {
    grantId: grant.id,
    event: 'GRANT_CREDENTIALS_REISSUED',
    actor: req.admin.email,
    detail: { resendCount: rows[0].resend_count },
  });

  try {
    await sendAccessEmail({
      to: grant.email,
      accessUrl,
      username: grant.email,
      password,
      durationLabel: hoursLabel(Number(hours.toFixed(2))),
      linkExpiryLabel: hoursLabel(PENDING_EXPIRY_HOURS),
    });
  } catch (err) {
    await audit(req, {
      grantId: grant.id,
      event: 'GRANT_EMAIL_FAILED',
      actor: req.admin.email,
      detail: { error: err.message, phase: 'resend' },
    });
    metrics.counter('gateway_email_total', { outcome: 'failed' });
    // The old credentials are already dead at this point, so withholding the
    // new ones would leave the grant unusable by anyone.
    return res.status(202).json({
      ...payload,
      warning: 'Credentials rotated, but the email failed to send. Relay these manually.',
      detail: err.message,
      password,
    });
  }

  metrics.counter('gateway_email_total', { outcome: 'accepted' });
  await audit(req, { grantId: grant.id, event: 'GRANT_EMAIL_ACCEPTED', actor: req.admin.email });

  if (relay) {
    await audit(req, {
      grantId: grant.id,
      event: 'GRANT_PASSWORD_RELAYED',
      actor: req.admin.email,
      detail: { reason: 'admin_requested_manual_relay', phase: 'resend' },
    });
    return res.json({ ...payload, password });
  }
  res.json(payload);
});

// Builds the WHERE clause shared by the JSON and CSV views, so the export can
// never disagree with what the console showed. Returns null when a parameter is
// malformed, and the caller turns that into a 400.
//
// Every value is a bound parameter. The only thing interpolated into the SQL is
// `$n`, generated from params.length.
function auditFilters(query) {
  const conditions = [];
  const params = [];

  if (query.grantId !== undefined && query.grantId !== '') {
    // Same reasoning as revoke: this reaches a UUID column, so it is
    // shape-checked rather than handed to Postgres to throw 22P02 on.
    if (!isUuid(query.grantId)) return { error: 'grantId must be a UUID' };
    params.push(query.grantId);
    conditions.push(`grant_id = $${params.length}`);
  }
  if (query.event) {
    // A list, because the questions people actually ask span several events:
    // "every failed sign-in" is LOGIN_FAILED and ADMIN_LOGIN_FAILED.
    const events = String(query.event).split(',').map((e) => e.trim().toUpperCase()).filter(Boolean);
    if (events.length) {
      params.push(events);
      conditions.push(`event = ANY($${params.length})`);
    }
  }
  if (query.actor) {
    params.push(normaliseEmail(query.actor));
    conditions.push(`lower(actor) = $${params.length}`);
  }
  for (const [key, op] of [['from', '>='], ['to', '<=']]) {
    if (!query[key]) continue;
    const at = new Date(query[key]);
    if (Number.isNaN(at.getTime())) return { error: `${key} must be an ISO 8601 timestamp` };
    params.push(at.toISOString());
    conditions.push(`created_at ${op} $${params.length}`);
  }

  return { where: conditions.length ? `WHERE ${conditions.join(' AND ')}` : '', params };
}

app.get(`${GATE}/api/admin/audit-log`, adminOnly, async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 200, 1000);
  const filters = auditFilters(req.query);
  if (filters.error) return res.status(400).json({ error: filters.error });

  const params = [...filters.params, limit];
  const { rows } = await pool.query(
    `SELECT * FROM audit_log ${filters.where} ORDER BY created_at DESC, id DESC LIMIT $${params.length}`,
    params
  );
  res.json({ events: rows });
});

// A field is quoted whenever it contains a delimiter, a quote or a newline, and
// an embedded quote is doubled. That is the whole of RFC 4180, and it is here
// rather than as a dependency for the same reason as everything else in this
// codebase's lib/.
//
// The leading apostrophe on a value starting with = + - @ is not RFC 4180 and
// is not decoration: spreadsheets treat those as the start of a formula, so an
// audit row whose actor is `=HYPERLINK(...)` becomes a live formula the moment
// a compliance reviewer opens the export. The export is read in Excel far more
// often than by a parser, and that is the reader worth protecting.
function csvField(value) {
  if (value == null) return '';
  let text = typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

// CSV rather than the JSON above, because the person asking for this is
// producing evidence for an auditor, and "export the access log for Q3" ends in
// a spreadsheet every time. Streamed, and capped well above the JSON view: an
// export that silently stops at a thousand rows is worse than no export, since
// nothing in the file says it is incomplete.
app.get(`${GATE}/api/admin/audit-log.csv`, adminOnly, async (req, res) => {
  const filters = auditFilters(req.query);
  if (filters.error) return res.status(400).json({ error: filters.error });

  const limit = Math.min(Number(req.query.limit) || 100_000, 500_000);
  const params = [...filters.params, limit];

  const stamp = new Date().toISOString().slice(0, 10);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="audit-log-${stamp}.csv"`);

  // Paging the query bounds how much is read from Postgres at once; this
  // bounds how much is held for a client that reads slowly. Without it,
  // res.write() returning false is ignored and Node buffers the remainder in
  // memory -- so a large export over a slow connection reintroduces exactly
  // the problem the paging was there to avoid.
  //
  // 'close' resolves it as well as 'drain'. A client that disconnects while
  // the buffer is full never drains, and waiting on 'drain' alone would leave
  // this handler awaiting an event that is now impossible -- one leaked
  // request context per cancelled download, held for the life of the process.
  const write = (chunk) => {
    if (res.write(chunk)) return null;
    return new Promise((resolve) => {
      const done = () => {
        res.off('drain', done);
        res.off('close', done);
        resolve();
      };
      res.once('drain', done);
      res.once('close', done);
    });
  };

  await write('id,created_at,event,actor,grant_id,ip_address,user_agent,request_id,detail\n');

  // Cursored rather than one query with a huge LIMIT: a 500,000-row result set
  // is materialised in this process's memory before the first byte is written,
  // and this is the process every customer's traffic flows through.
  const PAGE = 2000;
  let after = null;
  let written = 0;
  try {
    while (written < limit) {
      const pageParams = [...filters.params];
      let cursor = '';
      if (after !== null) {
        pageParams.push(after);
        cursor = filters.where ? ` AND id < $${pageParams.length}` : ` WHERE id < $${pageParams.length}`;
      }
      pageParams.push(Math.min(PAGE, limit - written));

      const { rows } = await pool.query(
        `SELECT id, created_at, event, actor, grant_id, ip_address, user_agent, request_id, detail
           FROM audit_log ${filters.where}${cursor}
          ORDER BY id DESC LIMIT $${pageParams.length}`,
        pageParams
      );
      if (!rows.length) break;

      for (const row of rows) {
        await write([
          row.id, row.created_at.toISOString(), row.event, row.actor, row.grant_id,
          row.ip_address, row.user_agent, row.request_id, row.detail,
        ].map(csvField).join(',') + '\n');
      }
      written += rows.length;

      // A client that navigated away or cancelled the download. Without this
      // the loop keeps querying Postgres and writing into a dead socket for
      // however many pages remain.
      if (res.writableEnded || res.destroyed) {
        req.log.debug('audit CSV export abandoned by the client', { written });
        return;
      }
      after = rows[rows.length - 1].id;
      if (rows.length < PAGE) break;
    }
  } catch (err) {
    // Headers are long gone, so there is no status code left to change. Ending
    // the response without the trailer below is what tells the caller the file
    // is short -- and the log line is what tells us why.
    req.log.error('audit CSV export failed mid-stream', { err: err.message, written });
    return res.end();
  }

  await audit(req, {
    event: 'AUDIT_LOG_EXPORTED',
    actor: req.admin.email,
    detail: { rows: written, filters: { ...req.query } },
  });
  // A terminator, so a truncated download is detectable. Prefixed with # so
  // it is a comment to most parsers and obvious to a human either way.
  //
  // Written only on the path that ran to completion: every early return above
  // leaves the file without it, which is the signal.
  res.end(`#end,${written} rows\n`);
});

// ============================================================
// Gate API -- activation, login, session
// ============================================================
app.get(`${GATE}/api/activate/:token`, activateLimiter, async (req, res) => {
  if (!TOKEN_RE.test(req.params.token)) {
    return res.status(404).json({ error: 'Invalid or expired access link' });
  }

  const { rows } = await pool.query(
    'SELECT * FROM access_grants WHERE token_hash = $1',
    [hashToken(req.params.token)]
  );
  const grant = rows[0];
  if (!grant) {
    await audit(req, { event: 'ACTIVATE_INVALID_TOKEN' });
    return res.status(404).json({ error: 'Invalid or expired access link' });
  }

  if (grant.status === 'PENDING') {
    // The link's own clock, which is not the access window. Checked here and
    // not left to the sweeper alone: the sweeper runs on an interval, and a
    // link opened between two sweeps would otherwise activate normally.
    const ageHours = (Date.now() - new Date(grant.created_at).getTime()) / 3_600_000;
    if (ageHours > PENDING_EXPIRY_HOURS) {
      await pool.query("UPDATE access_grants SET status = 'EXPIRED' WHERE id = $1", [grant.id]);
      cacheBust(grant.id);
      await audit(req, {
        grantId: grant.id,
        event: 'GRANT_LINK_EXPIRED',
        actor: grant.email,
        detail: { reason: 'opened_after_link_expiry', linkExpiryHours: PENDING_EXPIRY_HOURS },
      });
      return res.status(410).json({
        error: `This access link expired. Links must be opened within ${hoursLabel(PENDING_EXPIRY_HOURS)}`
          + ' of being issued. Ask your contact for a new one.',
        reason: 'link_expired',
      });
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + grant.duration_seconds * 1000);
    await pool.query(
      `UPDATE access_grants
       SET status = 'ACTIVE', activated_at = $1, expires_at = $2,
           activated_ip = $3, activated_user_agent = $4
       WHERE id = $5`,
      [now, expiresAt, req.ip || null, req.header('User-Agent') || null, grant.id]
    );
    cacheBust(grant.id);
    await audit(req, {
      grantId: grant.id,
      event: 'GRANT_ACTIVATED',
      actor: grant.email,
      detail: { expiresAt },
    });
    metrics.counter('gateway_grants_total', { transition: 'activated' });
    return res.json({ message: 'Access activated.', activatedAt: now, expiresAt });
  }

  if (grant.status === 'ACTIVE') {
    if (new Date() > new Date(grant.expires_at)) {
      await pool.query("UPDATE access_grants SET status = 'EXPIRED' WHERE id = $1", [grant.id]);
      cacheBust(grant.id);
      await audit(req, { grantId: grant.id, event: 'GRANT_EXPIRED', actor: 'system' });
      return res.status(410).json({ error: 'This access link has expired', reason: 'expired' });
    }
    // Reopening an active link is usually innocent -- a refresh, or checking
    // the time left -- so it isn't blocked. But an open from a different IP or
    // browser than the one that first activated it can mean the link was
    // forwarded or intercepted, which earns a distinct audit event.
    const mismatch = (grant.activated_ip && grant.activated_ip !== req.ip)
      || (grant.activated_user_agent && grant.activated_user_agent !== req.header('User-Agent'));
    await audit(req, {
      grantId: grant.id,
      event: mismatch ? 'ACTIVATE_REOPENED_FINGERPRINT_MISMATCH' : 'ACTIVATE_REOPENED',
      actor: grant.email,
      detail: mismatch ? { firstIp: grant.activated_ip, thisIp: req.ip } : null,
    });
    return res.json({ message: 'Access already active.', expiresAt: grant.expires_at });
  }

  await audit(req, {
    grantId: grant.id,
    event: 'ACTIVATE_REJECTED',
    actor: grant.email,
    detail: { status: grant.status },
  });

  // A grant that reached EXPIRED without ever being activated is a link that
  // ran out, not a window that did -- almost always because the sweeper got
  // to it first. The customer needs to be told which of the two happened,
  // because only one of them means "you waited too long".
  if (grant.status === 'EXPIRED' && !grant.activated_at) {
    return res.status(410).json({
      error: `This access link expired. Links must be opened within ${hoursLabel(PENDING_EXPIRY_HOURS)}`
        + ' of being issued. Ask your contact for a new one.',
      reason: 'link_expired',
    });
  }
  res.status(410).json({
    error: 'This access link is no longer valid',
    reason: grant.status === 'REVOKED' ? 'revoked' : 'not_valid',
  });
});

// A bcrypt hash of a value nobody can supply. Comparing against it burns the
// same time a real check would, so "no such grant" and "wrong password" are
// indistinguishable by response latency.
const DUMMY_HASH = '$2b$12$C6UzMDM.H6dfI/f/IKcEe.mB1TUpU4A1r9Ea3q2Ao8mwrLIfBSbLC';

app.post(`${GATE}/api/auth/login`, loginLimiter, async (req, res) => {
  const { password } = req.body || {};
  // Normalised to match how grants are stored. Before this, a grant issued to
  // `Contractor@Firm.com` was invisible to the person typing their own address
  // in lower case, and the rejection was indistinguishable from a bad password.
  const email = normaliseEmail(req.body?.email);
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  // At most one PENDING/ACTIVE grant per email exists -- enforced at creation
  // and by a partial unique index -- so this row is unambiguous.
  const { rows } = await pool.query(
    `SELECT * FROM access_grants WHERE email = $1 AND status = 'ACTIVE'
     ORDER BY created_at DESC LIMIT 1`,
    [email]
  );
  const grant = rows[0];

  if (!grant) {
    await bcrypt.compare(password, DUMMY_HASH);
    await audit(req, { event: 'LOGIN_FAILED', actor: email, detail: { reason: 'no_active_grant' } });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (new Date() > new Date(grant.expires_at)) {
    await pool.query("UPDATE access_grants SET status = 'EXPIRED' WHERE id = $1", [grant.id]);
    cacheBust(grant.id);
    await audit(req, { grantId: grant.id, event: 'GRANT_EXPIRED', actor: 'system' });
    return res.status(401).json({ error: 'Access expired' });
  }

  // Checked before the password, exactly as the admin lockout is: a locked
  // grant stays locked even when the right password finally arrives, which is
  // the whole point of a lockout. Unlike the admin path this one says what has
  // happened -- a customer retyping a 16-character password off a screen needs
  // to know they are locked out rather than wrong, or they call someone.
  if (grant.locked_until && new Date(grant.locked_until) > new Date()) {
    await bcrypt.compare(password, DUMMY_HASH);
    const minutes = Math.max(1, Math.ceil((new Date(grant.locked_until) - Date.now()) / 60000));
    await audit(req, {
      grantId: grant.id,
      event: 'LOGIN_FAILED',
      actor: email,
      detail: { reason: 'locked' },
    });
    return res.status(429).json({
      error: `Too many failed attempts. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`,
      reason: 'locked',
    });
  }

  if (!(await bcrypt.compare(password, grant.password_hash))) {
    // The counter was written and never read before this: the column looked
    // like a control during a security review and was not one. It locks now,
    // mirroring the admin path -- persisted in Postgres so it survives a
    // restart, where the per-IP limiter (in memory, per process) does not.
    //
    // Incremented in the statement rather than read, added to, and written
    // back. Under a read-modify-write, guesses arriving together all read the
    // same starting value and all write the same result, so a parallel
    // attacker is charged one attempt per round instead of one per guess --
    // the lockout failing in precisely the case it exists for.
    const { rows: locked } = await pool.query(
      `UPDATE access_grants
          SET failed_login_attempts =
                CASE WHEN failed_login_attempts + 1 >= $1 THEN 0
                     ELSE failed_login_attempts + 1 END,
              locked_until =
                CASE WHEN failed_login_attempts + 1 >= $1
                     THEN now() + ($2 || ' minutes')::interval
                     ELSE locked_until END
        WHERE id = $3
       RETURNING failed_login_attempts`,
      [GRANT_MAX_FAILED_ATTEMPTS, String(GRANT_LOCKOUT_MINUTES), grant.id]
    );
    // The counter resets to 0 as it locks, so 0 is how a lock reports itself;
    // the audit line wants the attempt number a human would count to.
    const lock = locked[0]?.failed_login_attempts === 0;
    const attempts = lock ? GRANT_MAX_FAILED_ATTEMPTS : locked[0]?.failed_login_attempts;
    await audit(req, {
      grantId: grant.id,
      event: 'LOGIN_FAILED',
      actor: email,
      detail: { reason: 'bad_password', attempts },
    });
    metrics.counter('gateway_logins_total', { principal: 'customer', outcome: 'bad_password' });
    if (lock) {
      await audit(req, {
        grantId: grant.id,
        event: 'GRANT_LOCKED',
        actor: email,
        detail: { minutes: GRANT_LOCKOUT_MINUTES, afterAttempts: GRANT_MAX_FAILED_ATTEMPTS },
      });
      metrics.counter('gateway_logins_total', { principal: 'customer', outcome: 'locked' });
      return res.status(429).json({
        error: `Too many failed attempts. Try again in ${GRANT_LOCKOUT_MINUTES} minutes.`,
        reason: 'locked',
      });
    }
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // A session can never outlive the grant that authorized it.
  const capExpiry = new Date(grant.expires_at).getTime();
  const sessionExpiry = Math.min(Date.now() + SESSION_TTL_SECONDS * 1000, capExpiry);
  const expiresInSeconds = Math.max(1, Math.floor((sessionExpiry - Date.now()) / 1000));

  const sessionToken = jwt.sign(
    { grantId: grant.id, email: grant.email },
    process.env.JWT_SECRET,
    { algorithm: JWT_ALG, expiresIn: expiresInSeconds }
  );

  await pool.query(
    'UPDATE access_grants SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1',
    [grant.id]
  );
  await audit(req, {
    grantId: grant.id,
    event: 'LOGIN_SUCCESS',
    actor: grant.email,
    detail: { sessionExpiresAt: new Date(sessionExpiry) },
  });
  metrics.counter('gateway_logins_total', { principal: 'customer', outcome: 'success' });

  res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions(), maxAge: expiresInSeconds * 1000 });
  res.json({ expiresAt: grant.expires_at, sessionExpiresAt: new Date(sessionExpiry) });
});

// Powers the countdown, both on the dashboard and in the banner injected into
// the upstream app's pages.
app.get(`${GATE}/api/session`, requireSessionApi, (req, res) => {
  res.json({
    email: req.session.email,
    expiresAt: req.session.expiresAt,
    remainingSeconds: Math.max(
      0,
      Math.floor((new Date(req.session.expiresAt).getTime() - Date.now()) / 1000)
    ),
  });
});

// Logging out ends the grant, not just the session: the emailed credentials
// become permanently unusable even if time remains on the clock.
app.post(`${GATE}/api/auth/logout`, requireSessionApi, async (req, res) => {
  await pool.query("UPDATE access_grants SET status = 'REVOKED' WHERE id = $1", [req.session.grantId]);
  cacheBust(req.session.grantId);
  await audit(req, {
    grantId: req.session.grantId,
    event: 'GRANT_REVOKED',
    actor: req.session.email,
    detail: { reason: 'user_logout' },
  });
  res.clearCookie(COOKIE_NAME, cookieOptions());
  res.json({ message: 'Access revoked. This pass can no longer be used to log in.' });
});

// Legacy paths from the pre-gateway build. These URLs now belong to the
// upstream app, so redirect rather than silently 404 a bookmarked link.
app.get('/login.html', (_req, res) => res.redirect(`${GATE}/login`));
app.get('/admin.html', (_req, res) => res.redirect(`${GATE}/admin`));
app.get('/dashboard.html', (_req, res) => res.redirect(`${GATE}/dashboard`));
app.get('/access/:token', (req, res) => res.redirect(`${GATE}/link/${req.params.token}`));

// The gate namespace is reserved, and that has to be true for paths the gate
// does NOT define as well as the ones it does. Without this, an unmatched
// /__access/* URL falls through to the proxy below and is forwarded to the
// upstream app -- so the app could see (and answer) requests inside the one
// namespace this design promises it will never own.
app.use(GATE, (_req, res) => res.status(404).json({ error: 'Not found' }));

// ============================================================
// The proxy
// ============================================================
// Injected into every HTML document the upstream app returns, so the customer
// always sees the time left and can end the session from anywhere inside the
// app rather than having to find their way back to the dashboard.
//
// Takes a per-response nonce so it survives a strict upstream CSP. Without one
// the browser silently drops the script: no countdown, no way to end the
// session, and nothing reporting a problem anywhere.
function bannerScript(nonce) {
  const attr = nonce ? ` nonce="${nonce}"` : '';
  const nonceLiteral = JSON.stringify(nonce || '');
  return `
<script${attr}>(function(){
  if (window.top !== window.self) return;
  var NONCE = ${nonceLiteral};
  var bar = document.createElement('div');
  bar.id = 'ta-banner';
  bar.innerHTML = '<span>Temporary access &mdash; <span class="t">--:--:--</span> remaining</span>';
  var btn = document.createElement('button');
  btn.textContent = 'End session';
  btn.onclick = function(){
    fetch('${GATE}/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
      .then(function(){ location.href = '${GATE}/login'; });
  };
  bar.appendChild(btn);

  var css = document.createElement('style');
  // A style element inserted by script is still governed by style-src, so it
  // needs the nonce too -- otherwise the banner appears unstyled rather than
  // not at all, which is arguably worse.
  if (NONCE) css.setAttribute('nonce', NONCE);
  css.textContent = '#ta-banner{position:fixed;top:0;left:0;right:0;z-index:2147483647;display:flex;'
    + 'align-items:center;justify-content:space-between;gap:16px;padding:8px 16px;background:#12151c;'
    + 'color:#f7f4ec;font-family:system-ui,sans-serif;font-size:13px;box-shadow:0 2px 12px rgba(0,0,0,.35)}'
    + '#ta-banner.warn{background:#b4432f}'
    + '#ta-banner .t{font-weight:600;font-variant-numeric:tabular-nums}'
    + '#ta-banner button{border:1px solid rgba(255,255,255,.35);background:transparent;color:inherit;'
    + 'border-radius:6px;padding:4px 12px;font-size:12px;cursor:pointer}'
    + 'body{padding-top:38px!important}';
  document.head.appendChild(css);
  document.body.appendChild(bar);

  function fmt(s){
    var h=Math.floor(s/3600), m=Math.floor(s%3600/60), x=Math.floor(s%60);
    return (h<10?'0':'')+h+':'+(m<10?'0':'')+m+':'+(x<10?'0':'')+x;
  }

  // null until the first sync answers. Starting at 0 meant a first request
  // slower than a second -- a free host waking up -- read as "time's up" and
  // sent the customer to the login page with time still on the clock.
  var left = null;
  function paint(){
    if (left === null) return;
    bar.querySelector('.t').textContent = fmt(Math.max(0,left));
    bar.className = left < 300 ? 'warn' : '';
    if (left <= 0) { location.href = '${GATE}/login?reason=expired'; return; }
    left--;
  }
  // Re-sync against the server rather than trusting the local clock: the
  // countdown is a courtesy, the server is the authority. Every 10 seconds,
  // and at once when the tab comes back into view, so an admin revoke shows on
  // screen within seconds rather than at the next minute. Only a refusal from
  // the server ends the session here: a request dropped by a flaky connection
  // is retried on the next tick instead of throwing the customer out.
  function sync(){
    fetch('${GATE}/api/session', { credentials: 'same-origin' })
      .then(function(r){
        if (r.status === 401 || r.status === 403) {
          return r.json().catch(function(){ return {}; }).then(function(d){
            location.href = '${GATE}/login' + (d.reason ? '?reason=' + encodeURIComponent(d.reason) : '');
          });
        }
        if (!r.ok) return;
        return r.json().then(function(d){ left = d.remainingSeconds; });
      })
      .catch(function(){});
  }
  sync();
  setInterval(paint, 1000);
  setInterval(sync, 10000);
  document.addEventListener('visibilitychange', function(){ if (!document.hidden) sync(); });
  window.addEventListener('focus', sync);
})();</script>`;
}

// Rewrites an upstream CSP so the banner runs, without taking the app's own
// policy away from it. STRIP_UPSTREAM_CSP -- deleting the header outright --
// remains as the escape hatch, but trading an app's CSP for a countdown bar is
// a bad deal, and this is the version that does not make it.
//
// Three narrow changes, and nothing else in the policy is touched:
//   - the nonce is added to whichever script directives exist;
//   - and to the style ones, since the banner inserts a <style> element;
//   - connect-src gains 'self', because the countdown re-syncs against the
//     gateway's own /api/session and a nonce cannot authorise a fetch.
function relaxCspForBanner(csp, nonce) {
  if (!csp) return csp;

  const directives = csp.split(/;/).map((d) => d.trim()).filter(Boolean);
  const nameOf = (d) => d.split(/\s+/)[0].toLowerCase();
  const sourcesOf = (d) => d.split(/\s+/).slice(1);
  const present = new Set(directives.map(nameOf));
  const defaultSrc = directives.find((d) => nameOf(d) === 'default-src');

  // Appending to a source list drops 'none'. A list is either 'none' or a set
  // of sources -- never both -- and a policy that says both is only honoured
  // because browsers parse leniently, which is not something to rely on.
  const add = (directive, ...sources) => {
    const parts = directive.split(/\s+/).filter((p) => p.toLowerCase() !== "'none'");
    for (const source of sources) if (!parts.includes(source)) parts.push(source);
    return parts.join(' ');
  };
  const rename = (directive, name) => [name, ...sourcesOf(directive)].join(' ');
  const allowsSelf = (directive) => sourcesOf(directive).includes("'self'");

  const NONCED = ['script-src', 'script-src-elem', 'style-src', 'style-src-elem'];
  const out = directives.map((d) => {
    const name = nameOf(d);
    if (NONCED.includes(name)) return add(d, `'nonce-${nonce}'`);
    if (name === 'connect-src') return add(d, "'self'");
    return d;
  });

  // A missing script-src/style-src falls back to default-src, so the policy
  // still constrains the banner. Copying default-src into an explicit
  // directive and adding the nonce there keeps everything else -- images,
  // frames, the app's own rules -- exactly as the app set them.
  if (defaultSrc) {
    for (const name of ['script-src', 'style-src']) {
      if (!present.has(name)) out.push(add(rename(defaultSrc, name), `'nonce-${nonce}'`));
    }
    // Only when the fallback would not already have allowed it, so a policy
    // that permits same-origin XHR comes back byte-for-byte unchanged.
    if (!present.has('connect-src') && !allowsSelf(defaultSrc)) {
      out.push(add(rename(defaultSrc, 'connect-src'), "'self'"));
    }
  }

  return out.join('; ');
}

// Hop-by-hop headers belong to a single connection and are ours to terminate
// rather than relay (RFC 7230 6.1). `connection` and `upgrade` are deliberately
// not in this list: the websocket handshake needs them, and http-proxy sets
// both correctly on each path.
const HOP_BY_HOP = [
  'proxy-authorization',
  'proxy-authenticate',
  'te',
  'trailer',
  'transfer-encoding',
  'keep-alive',
];

// Applied to everything leaving the gateway, over plain HTTP and over a
// websocket upgrade alike. The two travel different paths through http-proxy
// and fire different events, but they need identical treatment: the upstream
// app decides who someone is from the headers set here, so any path that skips
// this is a path where a client can name themselves.
function applyGatewayHeaders(proxyReq, req) {
  for (const header of HOP_BY_HOP) proxyReq.removeHeader(header);

  // Never leak the gateway's own cookies to the upstream app. The admin cookie
  // is already scoped to /__access and so should never be attached to a
  // proxied request at all -- it is stripped here too because that is a
  // browser honouring a Path attribute, not something this process enforces.
  const cookie = req.headers.cookie;
  if (cookie) {
    const kept = cookie
      .split(';')
      .filter((c) => {
        const name = c.trim().split('=')[0];
        return name !== COOKIE_NAME && name !== ADMIN_COOKIE_NAME;
      })
      .join(';')
      .trim();
    if (kept) proxyReq.setHeader('cookie', kept);
    else proxyReq.removeHeader('cookie');
  }

  // Tell the upstream app who this is. Set unconditionally (not merged)
  // so a client cannot forge the claim by sending the header itself.
  proxyReq.setHeader('X-Temp-Access-Email', req.session?.email || '');
  proxyReq.setHeader('X-Temp-Access-Grant', req.session?.grantId || '');
  // Proof that a request came through the gateway. Only useful if the app
  // rejects requests without it -- see the integration step in DEPLOY.md.
  // Set unconditionally for the same reason as the headers above.
  if (UPSTREAM_SHARED_SECRET) proxyReq.setHeader(UPSTREAM_SECRET_HEADER, UPSTREAM_SHARED_SECRET);
}

const proxyCommon = {
  target: UPSTREAM_URL,
  changeOrigin: true,
  xfwd: true,
  proxyTimeout: 30_000,
  timeout: 30_000,
  on: {
    proxyReq: applyGatewayHeaders,
    proxyReqWs: applyGatewayHeaders,
    error: (err, req, res) => {
      metrics.counter('gateway_upstream_errors_total', { code: err.code || 'unknown' });
      (req?.log || log).error('proxy error', { err: err.message, code: err.code });
      if (res && !res.headersSent && typeof res.status === 'function') {
        res.status(502).json({ error: 'The application behind the gateway is unreachable.' });
      }
    },
  },
};

// Two proxies, deliberately. The HTML one buffers the response so the
// countdown banner can be injected; the raw one streams. Routing assets and
// downloads through the buffering path would hold whole files in memory for
// no benefit, since only documents can carry the banner.
// `ws: true` is deliberately absent. Setting it makes http-proxy-middleware
// subscribe its own 'upgrade' listener to the HTTP server on the first proxied
// request -- a listener that authorizes nothing and matches every path -- and
// having done so, turns the `proxyRaw.upgrade()` call in startServer into a
// silent no-op. The result is the opposite of what it looks like: the careful
// handler stops working and the unauthenticated one does the proxying.
// With the flag off, that handler stays the only route a socket has upstream.
const proxyRaw = createProxyMiddleware({ ...proxyCommon });

const proxyHtml = createProxyMiddleware({
  ...proxyCommon,
  selfHandleResponse: true,
  on: {
    ...proxyCommon.on,
    proxyRes: responseInterceptor(async (buffer, proxyRes, _req, res) => {
      const type = proxyRes.headers['content-type'] || '';
      if (!type.includes('text/html')) return buffer;

      const nonce = crypto.randomBytes(16).toString('base64');
      if (STRIP_UPSTREAM_CSP) {
        res.removeHeader('content-security-policy');
        res.removeHeader('content-security-policy-report-only');
      } else {
        for (const header of ['content-security-policy', 'content-security-policy-report-only']) {
          const current = res.getHeader(header) ?? proxyRes.headers[header];
          if (!current) continue;
          const value = Array.isArray(current) ? current.join('; ') : String(current);
          res.setHeader(header, relaxCspForBanner(value, nonce));
        }
      }

      const banner = bannerScript(nonce);
      const html = buffer.toString('utf8');
      return html.includes('</body>')
        ? html.replace('</body>', `${banner}</body>`)
        : html + banner;
    }),
  },
});

function wantsHtml(req) {
  return req.method === 'GET' && (req.headers.accept || '').includes('text/html');
}

// Everything not claimed by the gate is forwarded -- but only for a live
// session. This check runs on every single request, which is what makes an
// expiry or a revoke cut a customer off mid-session rather than at next login.
app.use(async (req, res, next) => {
  const result = await resolveSession(req);

  if (!result.ok) {
    if (wantsHtml(req)) {
      // Remember where they were headed so login can return them there.
      const back = encodeURIComponent(req.originalUrl);
      return res.redirect(`${GATE}/login?next=${back}&reason=${result.reason}`);
    }
    return res.status(401).json({ error: 'Access no longer valid', reason: result.reason });
  }

  req.session = result.session;
  return (INJECT_BANNER && wantsHtml(req) ? proxyHtml : proxyRaw)(req, res, next);
});

// ============================================================
// Error handling
// ============================================================
app.use((err, req, res, _next) => {
  // The request id goes into the body as well as the log line. It is the only
  // thing a customer can usefully quote from a 500, and without it a support
  // conversation starts with "roughly what time was that".
  (req?.log || log).error('unhandled error', { err, path: req?.path });
  if (res.headersSent) return;
  res.status(500).json({ error: 'Internal server error', requestId: req?.id });
});

// ============================================================
// Background expiry sweeper
// ============================================================
// Grants would otherwise only flip to EXPIRED when something happened to
// touch them, leaving the admin console showing stale ACTIVE rows for windows
// that closed hours ago.
async function sweepExpired() {
  try {
    // Clock one: the access window ran out.
    const closed = await pool.query(
      `UPDATE access_grants SET status = 'EXPIRED'
       WHERE status = 'ACTIVE' AND expires_at IS NOT NULL AND expires_at <= now()
       RETURNING id`
    );
    metrics.counter('gateway_grants_total', { transition: 'expired' }, closed.rows.length);
    for (const row of closed.rows) {
      cacheBust(row.id);
      await audit(null, {
        grantId: row.id,
        event: 'GRANT_EXPIRED',
        actor: 'system',
        detail: { reason: 'sweeper' },
      });
    }

    // Clock two: the link was never opened. A separate event, so the two
    // clocks stay separable in the audit log -- "they ran out of time" and
    // "they never showed up" are different facts about a customer, and the
    // log is where that question gets answered later.
    const unopened = await pool.query(
      `UPDATE access_grants SET status = 'EXPIRED'
       WHERE status = 'PENDING' AND created_at < now() - ($1 || ' hours')::interval
       RETURNING id`,
      [String(PENDING_EXPIRY_HOURS)]
    );
    metrics.counter('gateway_grants_total', { transition: 'link_expired' }, unopened.rows.length);
    for (const row of unopened.rows) {
      cacheBust(row.id);
      await audit(null, {
        grantId: row.id,
        event: 'GRANT_LINK_EXPIRED',
        actor: 'system',
        detail: { reason: 'sweeper', linkExpiryHours: PENDING_EXPIRY_HOURS },
      });
    }

    if (closed.rows.length || unopened.rows.length) {
      log.info('sweeper closed grants', {
        expiredWindows: closed.rows.length,
        expiredLinks: unopened.rows.length,
      });
    }
  } catch (err) {
    log.error('sweeper failed', { err: err.message });
  }
}

// Gauges are point-in-time, so something has to set them. The sweeper is
// already the one thing that wakes on a timer and already talks to the
// database, and a scrape-time query would put an unauthenticated-ish endpoint
// on the critical path of the database this gateway cannot serve without.
async function refreshGauges() {
  try {
    const { rows } = await pool.query(
      `SELECT status, count(*)::int AS n FROM access_grants
        WHERE status IN ('PENDING','ACTIVE') GROUP BY status`
    );
    const counts = Object.fromEntries(rows.map((r) => [r.status, r.n]));
    for (const status of ['PENDING', 'ACTIVE']) {
      metrics.gauge('gateway_grants_live', { status }, counts[status] || 0);
    }

    if (webhooks.enabled()) {
      const { rows: pending } = await pool.query(
        "SELECT count(*)::int AS n FROM webhook_outbox WHERE status = 'PENDING'"
      );
      metrics.gauge('gateway_webhook_outbox_pending', null, pending[0].n);
    }
  } catch (err) {
    // Never fatal, and never retried: the next tick is a minute away and a
    // stale gauge is a smaller problem than a sweeper that stops sweeping.
    log.warn('metrics refresh failed', { err: err.message });
  }
}

// ============================================================
// Boot
// ============================================================
// An empty admins table means nobody can issue access, and the only symptom
// would be a 401 that looks like a wrong password. Say so plainly at boot.
async function checkAdminSetup() {
  try {
    const { rows } = await pool.query(
      'SELECT count(*)::int AS n FROM admins WHERE disabled_at IS NULL'
    );
    if (rows[0].n === 0) {
      log.warn('no admin accounts exist -- nobody can issue access. Run: npm run create-admin');
    } else {
      log.info('admin accounts', { active: rows[0].n });
    }

    // An owner is the only role that can add or remove admins. A database
    // where every owner has been disabled is recoverable only with SQL, and
    // the symptom -- a 403 on the team page -- does not point at the cause.
    const owners = await pool.query(
      "SELECT count(*)::int AS n FROM admins WHERE role = 'owner' AND disabled_at IS NULL"
    );
    if (rows[0].n > 0 && owners.rows[0].n === 0) {
      log.warn('no active owner: nobody can manage admin accounts from the console');
    }
  } catch (err) {
    log.error('could not read the admins table -- has schema.sql been applied?', { err: err.message });
  }

  if (!ADMIN_IP_ALLOWLIST.length && COOKIE_SECURE) {
    log.warn('ADMIN_IP_ALLOWLIST is empty, so the admin console answers the public '
      + 'internet. Scope it to your VPN or office range.');
  }
  if (!requireAdminTotp() && COOKIE_SECURE) {
    log.warn('ADMIN_REQUIRE_TOTP is off. A stolen admin password is enough to mint '
      + 'access to the internal network.');
  }
}

// Same "fail at boot, not at the first request" rule as the config block. A
// gateway that starts without a database looks healthy and then 500s on the
// first person who tries to get in, which is a worse way to find out.
async function assertDatabaseReachable() {
  try {
    await pool.query('SELECT 1');
  } catch (err) {
    console.error(`Refusing to start. Cannot reach the database: ${err.message}`);
    process.exit(1);
  }
}

function isPublicAddress(address) {
  try {
    return ipaddr.parse(String(address).replace(/^::ffff:/i, '')).range() === 'unicast';
  } catch {
    return false;
  }
}

// The gateway is worth exactly nothing if the app behind it is reachable
// without it, and no code here can prove that it isn't -- the check that
// matters is the firewall, plus auditing every DNS record and hardcoded URL
// that points at the app directly. But an upstream on a routable address is a
// strong hint the isolation was never set up, so say so at boot.
async function warnIfUpstreamIsPublic() {
  let hostname;
  try {
    hostname = new URL(UPSTREAM_URL).hostname;
  } catch {
    return;
  }

  let addresses;
  try {
    addresses = (await dns.lookup(hostname, { all: true })).map((a) => a.address);
  } catch {
    return; // unresolvable is the proxy's problem to report, not this check's
  }

  const publicAddresses = addresses.filter(isPublicAddress);
  if (!publicAddresses.length) return;

  log.warn('UPSTREAM_URL resolves to a public address. If customers can reach the app '
    + 'directly, this gateway is decoration.', {
    addresses: publicAddresses,
    remedy: UPSTREAM_SHARED_SECRET
      ? undefined
      : 'Set UPSTREAM_SHARED_SECRET and reject requests without it in the app.',
  });
}

// Email failure is survivable -- grant creation hands the admin the password
// to relay by hand -- so this warns rather than refusing to start. It is still
// worth saying at boot, because the alternative is finding out from a customer
// who never received their link.
function checkEmailSetup() {
  const provider = resolveEmailProvider();
  if (provider.ready && process.env.EMAIL_FROM) {
    log.info('email configured', { provider: provider.name });
    return;
  }
  const missing = provider.ready ? 'EMAIL_FROM' : provider.missing;
  log.warn('email is not configured. Grants will still be created, but the admin has to '
    + 'relay each password by hand.', { missing });
}

// Exported rather than run on require, so the tests can start a gateway on an
// ephemeral port and shut it down again.
async function start({ handleSignals = false } = {}) {
  await assertDatabaseReachable();

  const server = await new Promise((resolve) => {
    const s = app.listen(PORT, () => resolve(s));
  });
  const port = server.address().port;
  const liveSockets = new Set();

  // Registered before anything is awaited: the socket is already accepting
  // connections, and an upgrade arriving in the meantime would otherwise be
  // handled by nobody.
  //
  // Websocket upgrades bypass Express middleware entirely, so they need their
  // own authorization check. Without this, a customer whose window has closed
  // keeps a live socket into the app.
  server.on('upgrade', async (req, socket, head) => {
    try {
      const result = await resolveSession(req);
      if (!result.ok) return socket.destroy();
      req.session = result.session;
      // Upgraded sockets leave the HTTP server's connection tracking, so
      // server.close() would wait on them indefinitely. Kept here so shutdown
      // can end them deliberately.
      liveSockets.add(socket);
      socket.on('close', () => liveSockets.delete(socket));
      proxyRaw.upgrade(req, socket, head);
    } catch {
      socket.destroy();
    }
  });

  // One line with fields rather than the aligned banner this used to print.
  // In pretty mode it still reads like a banner; in json mode it is a record a
  // collector can answer "what was deployed, where, on the 4th" from.
  log.info('gateway listening', {
    port,
    version: SERVICE_VERSION,
    upstream: UPSTREAM_URL,
    public: process.env.PUBLIC_BASE_URL,
    admin: `${process.env.PUBLIC_BASE_URL}${GATE}/admin`,
    requireTotp: requireAdminTotp(),
    requireGrantReason: requireGrantReason(),
    metrics: METRICS_TOKEN ? `${GATE}/metrics` : 'disabled',
    webhooks: webhooks.enabled() ? 'enabled' : 'disabled',
  });
  metrics.gauge('gateway_build_info', { version: SERVICE_VERSION, node: process.version }, 1);
  checkEmailSetup();
  await checkAdminSetup();
  await warnIfUpstreamIsPublic();

  // One background clock for everything periodic. Each job guards its own
  // errors, and `running` stops a slow tick from overlapping the next one --
  // two concurrent webhook drains against a shared outbox would rely entirely
  // on SKIP LOCKED to stay correct, and a job should not need the database to
  // save it from its own scheduler.
  let running = false;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      await sweepExpired();
      sweepGrantCache();
      await webhooks.drain(pool);
      await refreshGauges();
    } finally {
      running = false;
    }
  };

  const sweepTimer = setInterval(tick, SWEEP_INTERVAL_MS);
  tick();

  // A websocket is not a request that finishes; waiting for one to drain is
  // waiting forever. Ending them lets close() complete, and a client that
  // cares reconnects -- to this instance's replacement.
  const endSockets = () => {
    for (const socket of liveSockets) socket.destroy();
  };

  const stop = async () => {
    clearInterval(sweepTimer);
    endSockets();
    await new Promise((resolve) => server.close(resolve));
    await pool.end();
  };

  if (handleSignals) {
    for (const sig of ['SIGTERM', 'SIGINT']) {
      process.on(sig, () => {
        log.info('shutting down', { signal: sig });
        clearInterval(sweepTimer);
        // server.close() stops accepting and waits for in-flight requests. On a
        // proxy that is not a formality: a customer mid-upload should finish,
        // not get a truncated response because a deploy landed.
        endSockets();
        server.close(() => pool.end().then(() => process.exit(0)));
        // The deadline is shorter than the orchestrator's own grace period
        // (Docker and Kubernetes both default to 30s), so this process is what
        // decides how it dies rather than being SIGKILLed with the pool open.
        setTimeout(() => {
          log.warn('shutdown timed out with connections still open; exiting anyway');
          process.exit(1);
        }, Number(process.env.SHUTDOWN_TIMEOUT_MS || 15_000)).unref();
      });
    }
  }

  return { server, port, stop };
}

if (require.main === module) {
  start({ handleSignals: true }).catch((err) => {
    log.error('refusing to start', { err: err.message });
    process.exit(1);
  });
}

module.exports = {
  app,
  start,
  pool,
  GATE,
  // The sweeper runs on a timer in production; the tests drive it directly
  // rather than waiting out an interval.
  sweepExpired,
  // Exported for the unit tests. Everything here is a pure function.
  normaliseEmail,
  escapeHtml,
  isUuid,
  isValidEmail,
  isPublicAddress,
  relaxCspForBanner,
  renderAccessEmail,
  resolveEmailProvider,
  sendViaBrevo,
  csvField,
  auditFilters,
  // The webhook outbox and the gauges are driven by the same timer as the
  // sweeper; the tests drive them directly for the same reason.
  refreshGauges,
  webhooks,
  metrics,
  totp,
};
