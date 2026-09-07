// Unit tests for lib/ -- TOTP, the logger's redaction, the metrics registry,
// and the webhook signature. No database, no listener, no network, so these run
// on any machine that can run Node.
//
// server.js is deliberately not required here: these modules have no
// dependency on it, and requiring it would drag its config validation into a
// file that has nothing to say about config.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const totp = require('../lib/totp.js');
const metrics = require('../lib/metrics.js');
const webhooks = require('../lib/webhooks.js');
const { redact } = require('../lib/logger.js');

// ==================================================================
// TOTP
// ==================================================================

// RFC 4226, Appendix D. The published HOTP values for the ASCII secret
// "12345678901234567890" at counters 0..9. If this file's arithmetic is wrong
// in any way that matters, it is wrong here first -- and against a fixture
// nobody in this repo chose, which is the point of using the RFC's.
test('hotp reproduces the RFC 4226 test vectors', () => {
  const secret = Buffer.from('12345678901234567890', 'ascii');
  const expected = [
    '755224', '287082', '359152', '969429', '338314',
    '254676', '287922', '162583', '399871', '520489',
  ];
  for (let counter = 0; counter < expected.length; counter++) {
    assert.equal(totp.hotp(secret, counter), expected[counter], `counter ${counter}`);
  }
});

// RFC 6238, Appendix B, SHA-1 rows. These pin the time-to-counter mapping --
// the half of TOTP that HOTP vectors alone cannot cover.
test('totp maps time to the RFC 6238 counters', () => {
  const secret = totp.base32Encode(Buffer.from('12345678901234567890', 'ascii'));
  const rows = [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
  ];
  for (const [seconds, code] of rows) {
    const step = totp.verify(secret, code, { atMs: seconds * 1000 });
    assert.equal(step, Math.floor(seconds / 30), `t=${seconds}`);
  }
});

test('base32 round-trips, and decoding tolerates what people actually type', () => {
  const bytes = crypto.randomBytes(20);
  const encoded = totp.base32Encode(bytes);
  assert.match(encoded, /^[A-Z2-7]+$/, 'no padding, no lower case');
  assert.deepEqual(totp.base32Decode(encoded), bytes);

  // Lower case, the spaces authenticator apps insert, and padding from a
  // paste. All three are the same secret.
  const spaced = encoded.toLowerCase().replace(/(.{4})/g, '$1 ');
  assert.deepEqual(totp.base32Decode(spaced), bytes);
  assert.deepEqual(totp.base32Decode(`${encoded}==`), bytes);

  assert.throws(() => totp.base32Decode('not-base32-!'), /invalid base32/);
});

test('verify accepts one step of drift either way and nothing beyond', () => {
  const secret = totp.generateSecret();
  const now = 1_700_000_000_000;
  const codeFor = (offsetSteps) =>
    totp.hotp(totp.base32Decode(secret), Math.floor(now / 30000) + offsetSteps);

  for (const offset of [-1, 0, 1]) {
    assert.notEqual(totp.verify(secret, codeFor(offset), { atMs: now }), null, `offset ${offset}`);
  }
  for (const offset of [-2, 2, 10]) {
    assert.equal(totp.verify(secret, codeFor(offset), { atMs: now }), null, `offset ${offset}`);
  }
});

// The replay guard. A code stays valid for its whole step and for a step either
// side, so without `afterStep` a captured code works for up to ninety seconds.
test('verify refuses a step that has already been spent', () => {
  const secret = totp.generateSecret();
  const now = 1_700_000_000_000;
  const step = totp.stepFor(now);
  const code = totp.hotp(totp.base32Decode(secret), step);

  assert.equal(totp.verify(secret, code, { atMs: now }), step);
  assert.equal(totp.verify(secret, code, { atMs: now, afterStep: step }), null,
    'the same step must not be accepted twice');
  // And a step older than the marker stays refused, which is what stops a
  // captured code from the previous window being replayed inside the skew.
  assert.equal(totp.verify(secret, code, { atMs: now, afterStep: step + 5 }), null);
});

test('verify rejects malformed input rather than throwing', () => {
  const secret = totp.generateSecret();
  for (const bad of [null, undefined, '', '12345', '1234567', 'abcdef', {}, []]) {
    assert.equal(totp.verify(secret, bad), null, JSON.stringify(bad));
  }
  // A stored secret that is not valid base32 must fail closed, not crash the
  // login route.
  assert.equal(totp.verify('!!!not-base32!!!', '123456'), null);
  assert.equal(totp.verify('', '123456'), null);
});

test('otpauthUri carries the parameters an authenticator app needs', () => {
  const uri = totp.otpauthUri({
    secret: 'JBSWY3DPEHPK3PXP',
    account: 'admin@example.com',
    issuer: 'access.example.com',
  });
  assert.match(uri, /^otpauth:\/\/totp\//);
  // Issuer appears in the label and as a parameter, because apps differ in
  // which one they read.
  assert.match(uri, /access\.example\.com%3Aadmin%40example\.com/);
  const params = new URL(uri).searchParams;
  assert.equal(params.get('secret'), 'JBSWY3DPEHPK3PXP');
  assert.equal(params.get('issuer'), 'access.example.com');
  assert.equal(params.get('algorithm'), 'SHA1');
  assert.equal(params.get('digits'), '6');
  assert.equal(params.get('period'), '30');
});

test('backup codes avoid the glyphs people confuse, and normalise loosely', () => {
  for (let i = 0; i < 50; i++) {
    const code = totp.generateBackupCode();
    assert.match(code, /^[A-Z0-9]{5}-[A-Z0-9]{5}$/);
    assert.equal(/[OIL01]/.test(code), false, `ambiguous glyph in ${code}`);
  }
  // The dash and the case are presentation only.
  assert.equal(totp.normaliseBackupCode('abcde-fghij'), 'ABCDEFGHIJ');
  assert.equal(totp.normaliseBackupCode('ABCDE FGHIJ'), 'ABCDEFGHIJ');
  assert.equal(totp.normaliseBackupCode(null), '');
});

test('recovery codes hash to a self-describing scrypt string and verify', async () => {
  const code = totp.generateBackupCode();
  const stored = await totp.hashBackupCode(code);

  // The parameters travel with the hash, so raising them later applies to new
  // codes without invalidating existing ones.
  assert.match(stored, /^scrypt\$16384\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
  // Salted: the same code hashed twice must not collide.
  assert.notEqual(await totp.hashBackupCode(code), stored);

  assert.equal(await totp.verifyBackupCode(code, stored), true);
  // Normalisation applies on both sides, so the dashes and case are cosmetic.
  assert.equal(await totp.verifyBackupCode(code.toLowerCase().replace('-', ' '), stored), true);
  assert.equal(await totp.verifyBackupCode(totp.generateBackupCode(), stored), false);
});

test('verifying a recovery code fails closed on a malformed stored hash', async () => {
  // Anything that is not a well-formed record is a false, never a throw: this
  // runs inside the admin login path.
  for (const bad of ['', null, 'not-a-hash', 'scrypt$1$2$3', '$2a$12$bcrypt-style-hash',
    'scrypt$16384$8$1$onlyfivefields']) {
    assert.equal(await totp.verifyBackupCode('ABCDE-FGHIJ', bad), false, String(bad));
  }
  // A stored row must not be able to dictate how much memory this process
  // allocates -- N here would ask for gigabytes.
  const absurd = `scrypt$${2 ** 25}$8$1$c2FsdA==$aGFzaA==`;
  assert.equal(await totp.verifyBackupCode('ABCDE-FGHIJ', absurd), false);
});

// ==================================================================
// Logger redaction
// ==================================================================
test('redact removes anything whose key names a credential', () => {
  const out = redact({
    email: 'someone@example.com',
    password: 'hunter2',
    newPassword: 'hunter3',
    totpCode: '123456',
    Authorization: 'Bearer abc',
    cookie: 'ta_session=...',
    apiKey: 'sk-live-1',
    code_hash: '$2a$12$...',
    nested: { adminSecret: 'x', keep: 1 },
  });

  assert.equal(out.email, 'someone@example.com', 'ordinary fields survive');
  assert.equal(out.nested.keep, 1);
  for (const key of ['password', 'newPassword', 'totpCode', 'Authorization', 'cookie',
    'apiKey', 'code_hash']) {
    assert.equal(out[key], '[redacted]', key);
  }
  assert.equal(out.nested.adminSecret, '[redacted]', 'redaction reaches nested objects');
});

test('redaction does not swallow the fields the log exists to report', () => {
  // A bare `otp` in the pattern matched `requireTotp`, so the boot banner
  // announced the two-factor policy as [redacted] -- a security control hiding
  // a security setting from the operator checking it. Over-broad redaction is
  // not the safe direction: it teaches people to stop reading the log.
  const out = redact({
    requireTotp: true,
    totpEnabled: false,
    totpRequired: true,
    // An error code, not a credential, and by far the more common `code`.
    code: 'ECONNREFUSED',
    statusCode: 502,
    event: 'ADMIN_TOTP_ENABLED',
    // These are credentials and must still go.
    totpCode: '123456',
    totpSecret: 'JBSWY3DPEHPK3PXP',
    backupCode: 'ABCDE-FGHIJ',
  });

  assert.equal(out.requireTotp, true);
  assert.equal(out.totpEnabled, false);
  assert.equal(out.totpRequired, true);
  assert.equal(out.code, 'ECONNREFUSED');
  assert.equal(out.statusCode, 502);
  assert.equal(out.event, 'ADMIN_TOTP_ENABLED');

  assert.equal(out.totpCode, '[redacted]');
  assert.equal(out.totpSecret, '[redacted]');
  assert.equal(out.backupCode, '[redacted]');
});

test('redact makes an Error loggable and bounds how deep it will go', () => {
  const err = redact(new Error('boom'));
  assert.equal(err.message, 'boom');
  assert.equal(typeof err.stack, 'string');

  // Without a depth bound, a cyclic or very deep object takes the process out
  // through the logger -- which is the one place that must never fail.
  const deep = { a: { b: { c: { d: { e: { f: { g: 'too far' } } } } } } };
  assert.equal(redact(deep).a.b.c.d.e.f, '[truncated]');

  const cyclic = { name: 'loop' };
  cyclic.self = cyclic;
  assert.doesNotThrow(() => redact(cyclic));
});

// ==================================================================
// Metrics
// ==================================================================
test('the registry renders Prometheus text with escaped labels', () => {
  metrics.reset();
  metrics.counter('gateway_grants_total', { transition: 'created' });
  metrics.counter('gateway_grants_total', { transition: 'created' });
  metrics.counter('gateway_grants_total', { transition: 'revoked' });
  metrics.gauge('gateway_grants_live', { status: 'ACTIVE' }, 7);

  const out = metrics.render();
  assert.match(out, /# HELP gateway_grants_total /);
  assert.match(out, /# TYPE gateway_grants_total counter/);
  assert.match(out, /gateway_grants_total\{transition="created"\} 2/);
  assert.match(out, /gateway_grants_total\{transition="revoked"\} 1/);
  assert.match(out, /gateway_grants_live\{status="ACTIVE"\} 7/);

  // One HELP line per family, however many series it has -- otherwise a scrape
  // is valid but unreadable by a human during an incident.
  assert.equal((out.match(/# HELP gateway_grants_total /g) || []).length, 1);
  metrics.reset();
});

test('histogram buckets are cumulative and carry a sum and a count', () => {
  metrics.reset();
  metrics.observe('gateway_http_request_duration_seconds', { route: '/x' }, 0.03);
  metrics.observe('gateway_http_request_duration_seconds', { route: '/x' }, 0.4);

  const out = metrics.render();
  const ladder = out.split('\n')
    .filter((l) => l.includes('_bucket{'))
    .map((l) => [l.match(/le="([^"]+)"/)[1], Number(l.split(' ').pop())]);
  const at = (le) => ladder.find(([boundary]) => boundary === le)?.[1];

  // Every bucket is present, including the ones neither observation reached.
  // A hole at the bottom is what makes histogram_quantile lie -- and the
  // ordering is by boundary rather than by string, so the ladder reads top to
  // bottom for a person.
  assert.deepEqual(ladder.map(([le]) => le), [...metrics.BUCKETS.map(String), '+Inf']);

  // 0.03 falls in every bucket from 0.05 up; 0.4 in every bucket from 0.5 up.
  assert.equal(at('0.005'), 0);
  assert.equal(at('0.01'), 0);
  assert.equal(at('0.05'), 1);
  assert.equal(at('0.5'), 2);
  assert.equal(at('+Inf'), 2);
  assert.match(out, /_count\{route="\/x"\} 2/);

  // Floating point: 0.03 + 0.4 is not exactly 0.43 in binary, so this is a
  // tolerance rather than an equality.
  const sum = Number(out.match(/_sum\{route="\/x"\} ([\d.]+)/)[1]);
  assert.ok(Math.abs(sum - 0.43) < 1e-9, `sum was ${sum}`);
  metrics.reset();
});

test('routePattern never lets a URL become a label value', () => {
  // An unmatched gate path: bounded namespace, but not a route we defined.
  assert.equal(metrics.routePattern({ originalUrl: '/__access/nope' }), 'gate_other');
  // Everything proxied collapses to one series. The app behind the gateway
  // owns an unbounded URL space, and one series per URL is how a metrics
  // endpoint takes down the scrape target.
  assert.equal(metrics.routePattern({ originalUrl: '/customers/1839/invoice' }), 'upstream');
  assert.equal(
    metrics.routePattern({ baseUrl: '/__access', route: { path: '/link/:token' } }),
    '/__access/link/:token'
  );
});

test('label values with quotes or newlines cannot break the exposition format', () => {
  metrics.reset();
  metrics.counter('gateway_upstream_errors_total', { code: 'we"ird\nvalue' });
  const out = metrics.render();
  assert.match(out, /code="we\\"ird\\nvalue"/);
  // One metric, one line: an unescaped newline would have made two. render()
  // always appends the process gauges, so only this family is counted.
  const lines = out.split('\n').filter((l) => l.startsWith('gateway_upstream_errors_total'));
  assert.equal(lines.length, 1);
  metrics.reset();
});

// ==================================================================
// Webhooks
// ==================================================================
test('the signature covers the timestamp as well as the body', () => {
  const secret = 'shhh';
  const body = JSON.stringify({ event: 'GRANT_CREATED' });
  const signature = webhooks.sign(secret, 1700000000, body);

  assert.equal(
    signature,
    crypto.createHmac('sha256', secret).update(`1700000000.${body}`).digest('hex')
  );
  // A body replayed under a different timestamp must not verify -- that is the
  // entire reason the timestamp is inside the signed string.
  assert.notEqual(webhooks.sign(secret, 1700000001, body), signature);
  assert.notEqual(webhooks.sign('other', 1700000000, body), signature);
});

test('backoff grows, stays bounded, and is jittered', () => {
  const seen = new Set();
  for (let attempt = 1; attempt <= 20; attempt++) {
    const seconds = webhooks.backoffSeconds(attempt);
    assert.ok(seconds > 0, `attempt ${attempt}`);
    // The ceiling plus the widest jitter. Without a bound, an outage of a few
    // hours pushes the next retry past any useful horizon.
    assert.ok(seconds <= 900 * 1.25, `attempt ${attempt} was ${seconds}`);
    seen.add(seconds);
  }
  assert.ok(webhooks.backoffSeconds(1) < webhooks.backoffSeconds(8), 'grows with attempts');
  // Jitter, so a backlog enqueued during one outage does not retry in unison.
  const repeats = new Set(Array.from({ length: 20 }, () => webhooks.backoffSeconds(8)));
  assert.ok(repeats.size > 1, 'identical attempt counts must not produce identical delays');
});
