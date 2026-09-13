// Pure functions only -- no database, no listener, no network. These run
// everywhere, including on a machine that has never had Postgres installed.

const test = require('node:test');
const assert = require('node:assert/strict');

// server.js refuses to load without these, and constructs (but never opens) a
// connection pool. Requiring it here does not start anything: the listener is
// behind a require.main check.
process.env.DATABASE_URL ||= 'postgres://unused@127.0.0.1:5432/unused';
process.env.JWT_SECRET ||= 'unit-test-secret-at-least-32-characters';
process.env.PUBLIC_BASE_URL ||= 'http://127.0.0.1';
process.env.UPSTREAM_URL ||= 'http://127.0.0.1:4000';

const {
  normaliseEmail,
  escapeHtml,
  isUuid,
  isValidEmail,
  isPublicAddress,
  relaxCspForBanner,
  renderAccessEmail,
  resolveEmailProvider,
  sendViaBrevo,
} = require('../server.js');

test('normaliseEmail lower-cases and trims', () => {
  assert.equal(normaliseEmail('  Contractor@Firm.com '), 'contractor@firm.com');
  assert.equal(normaliseEmail('already@lower.com'), 'already@lower.com');
  assert.equal(normaliseEmail(undefined), '');
  assert.equal(normaliseEmail(null), '');
});

test('escapeHtml neutralises every character that can break out of markup', () => {
  assert.equal(
    escapeHtml('<img src=x onerror="alert(1)">'),
    '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;'
  );
  assert.equal(escapeHtml("O'Brien & Sons"), 'O&#39;Brien &amp; Sons');
  assert.equal(escapeHtml('plain text'), 'plain text');
});

test('isUuid accepts a UUID and rejects everything Postgres would throw on', () => {
  assert.ok(isUuid('3f2504e0-4f89-41d3-9a0c-0305e82c3301'));
  assert.ok(isUuid('3F2504E0-4F89-41D3-9A0C-0305E82C3301'));
  for (const bad of ['', 'not-a-uuid', '123', "1' OR '1'='1", null, undefined, 42]) {
    assert.equal(isUuid(bad), false, `expected ${String(bad)} to be rejected`);
  }
});

test('isValidEmail rejects the addresses the old regex let through', () => {
  assert.ok(isValidEmail('customer@example.com'));
  assert.ok(isValidEmail('first.last+tag@sub.example.co.uk'));

  // The whole point of tightening it: this passed /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  // and went straight into the HTML of an outgoing email.
  assert.equal(isValidEmail('<img src=x onerror=alert(1)>@evil.com'), false);
  assert.equal(isValidEmail('"><script>@evil.com'), false);
  assert.equal(isValidEmail('no-at-sign.com'), false);
  assert.equal(isValidEmail('trailing@dot.'), false);
  assert.equal(isValidEmail(`${'a'.repeat(250)}@example.com`), false);
});

test('isPublicAddress separates routable addresses from private ones', () => {
  assert.equal(isPublicAddress('93.184.216.34'), true);
  assert.equal(isPublicAddress('10.0.0.5'), false);
  assert.equal(isPublicAddress('192.168.1.10'), false);
  assert.equal(isPublicAddress('172.16.4.2'), false);
  assert.equal(isPublicAddress('127.0.0.1'), false);
  assert.equal(isPublicAddress('::1'), false);
  assert.equal(isPublicAddress('::ffff:10.0.0.5'), false);
  assert.equal(isPublicAddress('fd00::1'), false);
  assert.equal(isPublicAddress('not-an-address'), false);
});

test('relaxCspForBanner nonces the directives that exist', () => {
  const out = relaxCspForBanner("default-src 'self'; script-src 'self'; style-src 'self'", 'abc123');
  assert.match(out, /script-src 'self' 'nonce-abc123'/);
  assert.match(out, /style-src 'self' 'nonce-abc123'/);
  // Untouched directives survive verbatim.
  assert.match(out, /default-src 'self'/);
});

test('relaxCspForBanner covers script-src-elem, which overrides script-src', () => {
  const out = relaxCspForBanner("script-src 'self'; script-src-elem 'self'", 'n1');
  assert.match(out, /script-src 'self' 'nonce-n1'/);
  assert.match(out, /script-src-elem 'self' 'nonce-n1'/);
});

test('relaxCspForBanner derives script-src and style-src from default-src', () => {
  const out = relaxCspForBanner("default-src 'self'; img-src *", 'n2');
  assert.match(out, /script-src 'self' 'nonce-n2'/);
  assert.match(out, /style-src 'self' 'nonce-n2'/);
  assert.match(out, /img-src \*/);
});

test('relaxCspForBanner lets the countdown reach the gateway', () => {
  // The banner re-syncs against /__access/api/session, and no nonce can
  // authorise a fetch -- only connect-src can.
  const strict = relaxCspForBanner("default-src 'none'; script-src 'self'", 'n3');
  assert.match(strict, /connect-src 'self'/);
  // 'none' does not survive alongside a real source: a list is one or the
  // other, and a policy saying both only works because browsers are lenient.
  assert.ok(!/connect-src[^;]*'none'/.test(strict), strict);

  const already = relaxCspForBanner("connect-src 'self' https://api.example.com", 'n4');
  assert.equal(already.match(/'self'/g).length, 1, "'self' should not be added twice");
});

test("relaxCspForBanner replaces 'none' rather than appending to it", () => {
  const out = relaxCspForBanner("script-src 'none'; style-src 'none'", 'n8');
  assert.equal(out, "script-src 'nonce-n8'; style-src 'nonce-n8'");
});

test('relaxCspForBanner is idempotent about sources it would add twice', () => {
  const once = relaxCspForBanner("default-src 'self'; connect-src 'self'", 'n9');
  assert.equal(once.match(/connect-src 'self'/g).length, 1);
});

test('relaxCspForBanner leaves a policy that does not constrain scripts alone', () => {
  const out = relaxCspForBanner('frame-ancestors https://portal.example.com', 'n5');
  assert.equal(out, 'frame-ancestors https://portal.example.com');
  assert.equal(relaxCspForBanner('', 'n6'), '');
  assert.equal(relaxCspForBanner(undefined, 'n7'), undefined);
});

test('renderAccessEmail escapes every interpolated value in the HTML body', () => {
  const { html, text, subject } = renderAccessEmail({
    accessUrl: 'http://gateway.example.com/__access/link/123456789',
    username: '<img src=x onerror=alert(1)>@evil.com',
    password: 'p4ssw0rd',
    durationLabel: '8 hours',
    linkExpiryLabel: '24 hours',
  });

  assert.equal(subject, 'Your temporary access');
  assert.ok(!html.includes('<img src=x'), 'raw markup must not survive into the HTML body');
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;@evil\.com/);
  // The plain-text part is not markup, so it is not escaped.
  assert.match(text, /<img src=x onerror=alert\(1\)>@evil\.com/);
});

test('renderAccessEmail states both clocks', () => {
  // The old copy said only that the countdown starts on opening, which left
  // the customer with no idea the link itself has a deadline. That ambiguity
  // does not cause security incidents; it causes support calls, reliably.
  const { text, html } = renderAccessEmail({
    accessUrl: 'http://gateway.example.com/__access/link/123456789',
    username: 'customer@example.com',
    password: 'p4ssw0rd',
    durationLabel: '8 hours',
    linkExpiryLabel: '24 hours',
  });

  for (const body of [text, html]) {
    assert.match(body, /opened within 24 hours/);
    assert.match(body, /access lasts 8 hours/);
  }
});

test('sendViaBrevo posts the shape Brevo expects, with the key only in a header', async () => {
  const keys = ['BREVO_API_KEY', 'EMAIL_FROM', 'EMAIL_FROM_NAME'];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  const realFetch = global.fetch;
  let seen;
  try {
    process.env.BREVO_API_KEY = 'xkeysib-test';
    process.env.EMAIL_FROM = 'Acme Access <access@example.com>';
    delete process.env.EMAIL_FROM_NAME;
    global.fetch = async (url, opts) => {
      seen = { url, opts };
      return new Response(JSON.stringify({ messageId: '<x@relay>' }), { status: 201 });
    };

    await sendViaBrevo({ to: 'vendor@example.com', subject: 'S', text: 'T', html: '<p>H</p>' });
    assert.equal(seen.url, 'https://api.brevo.com/v3/smtp/email');
    assert.equal(seen.opts.method, 'POST');
    assert.equal(seen.opts.headers['api-key'], 'xkeysib-test');
    const body = JSON.parse(seen.opts.body);
    assert.deepEqual(body.sender, { name: 'Acme Access', email: 'access@example.com' });
    assert.deepEqual(body.to, [{ email: 'vendor@example.com' }]);
    assert.equal(body.subject, 'S');
    assert.equal(body.textContent, 'T');
    assert.equal(body.htmlContent, '<p>H</p>');
    assert.equal(seen.opts.body.includes('xkeysib-test'), false, 'the key must never be in the body');

    // A bare address gets a default display name, and a refusal from Brevo --
    // an unverified sender, say -- surfaces with its status instead of passing
    // for a sent email.
    process.env.EMAIL_FROM = 'access@example.com';
    global.fetch = async (url, opts) => {
      seen = { url, opts };
      return new Response('{"message":"sender not valid"}', { status: 400 });
    };
    await assert.rejects(
      () => sendViaBrevo({ to: 'v@example.com', subject: 'S', text: 'T', html: 'H' }),
      /400/
    );
    assert.deepEqual(JSON.parse(seen.opts.body).sender, { name: 'Temporary Access', email: 'access@example.com' });
  } finally {
    global.fetch = realFetch;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
});

test('resolveEmailProvider picks a backend and reports what is missing', () => {
  const saved = { ...process.env };
  const clear = () => {
    for (const k of ['EMAIL_PROVIDER', 'RESEND_API_KEY', 'BREVO_API_KEY', 'SES_REGION',
      'SES_ACCESS_KEY_ID', 'SES_SECRET_ACCESS_KEY']) delete process.env[k];
  };

  try {
    clear();
    assert.equal(resolveEmailProvider().ready, false);
    assert.equal(resolveEmailProvider().name, 'none');

    // Inferred from whichever credentials exist, so an existing Resend
    // deployment keeps working with no config change.
    clear();
    process.env.RESEND_API_KEY = 're_test';
    assert.equal(resolveEmailProvider().name, 'resend');
    assert.equal(resolveEmailProvider().ready, true);

    // Brevo is inferred from its key, and can be named explicitly.
    clear();
    process.env.BREVO_API_KEY = 'xkeysib-test';
    assert.equal(resolveEmailProvider().name, 'brevo');
    assert.equal(resolveEmailProvider().ready, true);
    process.env.EMAIL_PROVIDER = 'brevo';
    assert.equal(resolveEmailProvider().name, 'brevo');

    clear();
    Object.assign(process.env, {
      SES_REGION: 'eu-west-1',
      SES_ACCESS_KEY_ID: 'AKIA',
      SES_SECRET_ACCESS_KEY: 'secret',
    });
    assert.equal(resolveEmailProvider().name, 'ses');
    assert.equal(resolveEmailProvider().ready, true);

    // Explicit beats inferred.
    process.env.RESEND_API_KEY = 're_test';
    process.env.EMAIL_PROVIDER = 'resend';
    assert.equal(resolveEmailProvider().name, 'resend');

    // Half-configured SES names the missing keys rather than failing later.
    clear();
    process.env.EMAIL_PROVIDER = 'ses';
    process.env.SES_REGION = 'eu-west-1';
    const partial = resolveEmailProvider();
    assert.equal(partial.ready, false);
    assert.match(partial.missing, /SES_ACCESS_KEY_ID/);

    clear();
    process.env.EMAIL_PROVIDER = 'postmark';
    assert.equal(resolveEmailProvider().ready, false);
    assert.match(resolveEmailProvider().missing, /not a known provider/);
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
});

// ------------------------------------------------------------------
// CSV export
// ------------------------------------------------------------------
const { csvField, auditFilters } = require('../server.js');

test('csvField quotes only what needs quoting, and doubles embedded quotes', () => {
  assert.equal(csvField('plain'), 'plain');
  assert.equal(csvField(null), '');
  assert.equal(csvField(undefined), '');
  assert.equal(csvField(42), '42');
  assert.equal(csvField('has,comma'), '"has,comma"');
  assert.equal(csvField('has"quote'), '"has""quote"');
  assert.equal(csvField('has\nnewline'), '"has\nnewline"');
  // An object is the detail column, and it arrives as JSON.
  assert.equal(csvField({ a: 1 }), '"{""a"":1}"');
});

test('csvField defuses a value a spreadsheet would run as a formula', () => {
  // The export is opened in Excel far more often than it is parsed, and there
  // it is the reader who is at risk, not the format.
  for (const dangerous of ['=1+1', '+1', '-1', '@SUM(A1)', '\tstart']) {
    const out = csvField(dangerous);
    assert.equal(out.replace(/^"|"$/g, '').startsWith("'"), true, dangerous);
  }
  // A leading apostrophe is added, not a replacement: the value is still
  // readable, and this is not silent data loss.
  assert.equal(csvField('=HYPERLINK("x")'), '"\'=HYPERLINK(""x"")"');
  // Ordinary values are untouched.
  assert.equal(csvField('a=b'), 'a=b');
  assert.equal(csvField('2026-09-06T00:00:00.000Z'), '2026-09-06T00:00:00.000Z');
});

test('auditFilters binds every value and interpolates only placeholders', () => {
  const none = auditFilters({});
  assert.equal(none.where, '');
  assert.deepEqual(none.params, []);

  const some = auditFilters({ event: 'a,b', actor: 'ME@Example.com', from: '2026-01-01' });
  // Placeholders are numbered from the parameter array, never from the input.
  assert.equal(some.where, 'WHERE event = ANY($1) AND lower(actor) = $2 AND created_at >= $3');
  assert.deepEqual(some.params[0], ['A', 'B']);
  assert.equal(some.params[1], 'me@example.com');

  // A value that would be an injection if it were interpolated is just a
  // parameter that matches nothing.
  const hostile = auditFilters({ actor: "'; DROP TABLE audit_log; --" });
  assert.equal(hostile.where, 'WHERE lower(actor) = $1');
  assert.equal(hostile.params.length, 1);

  // Malformed input is reported, not thrown and not silently ignored.
  assert.match(auditFilters({ grantId: 'nope' }).error, /UUID/);
  assert.match(auditFilters({ from: 'yesterday' }).error, /ISO 8601/);
});
