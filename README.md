# Temporary Access Gateway

Lets an outside vendor who has **no VPN credentials** reach a VPN-hosted
application for a window of time an admin decides — through a browser, with
nothing to install.

![The whole lifecycle: an admin issues a one-hour grant, the customer activates
the link and logs in, reaches the internal app with a countdown bar, and is cut
off mid-session when the admin revokes.](docs/demo.gif)

*The full lifecycle against a local gateway, with `demo-app` standing in for the
internal application. Note the last two frames: the admin revokes with 56
minutes still on the clock, and the very next request bounces to
`?reason=revoked` — the session cookie was still unexpired and still correctly
signed.*

> This recording predates the console gaining tabs, a reason field, and the
> extend/re-send row actions. The lifecycle it shows is unchanged; the admin
> console it shows is a screen behind. Re-record with `npm run demo`.

An admin enters an email and a duration. The system emails a one-time link and
a temporary password. Opening the link starts the clock. From then until the
window closes, that person's browser reaches the internal app through this
gateway, and the gateway re-checks their authorization on every single request.

## Who this is for

**Outside vendors, not employees.**

This exists for people who do not work for you and never will have a place in
your directory: a vendor's support engineer reproducing a bug in the live app,
an auditor who needs four hours in one system, an integration partner during a
cutover. They have no VPN client, no account in your identity provider, and no
reason to be issued either for a job that lasts an afternoon.

**Employees keep using the VPN.** Nothing here replaces it, competes with it,
or sits in front of it. Staff access is already solved inside your network — a
permanent identity, a directory that owns it, and a VPN that enforces it.
Routing that through a gateway built for people who have no identity at all
would be a downgrade in every direction.

The distinction is the whole design. Everything this does cheaply — issue in
seconds, expire on a clock, revoke mid-session, leave a per-person audit trail
— is cheap precisely because a grant is disposable and owns nothing. That is
the right trade for a two-day vendor engagement and the wrong one for someone
who shows up every morning.

Throughout this document **"the customer"** means the outside party receiving
access, not a customer of yours in the commercial sense.

## How it works

The gateway is an **identity-aware reverse proxy**. It is the only component
that sits in both networks: public on one side, on the VPN on the other.

```
                    ┌─────────────────────────────────────┐
   customer         │  gateway host                       │
   (no VPN)         │                                     │
       │            │   nginx :443  ──▶  node :3000       │
       └── HTTPS ───┼──▶ (TLS)           (this repo)      │
                    │                        │            │
                    │                   Postgres          │
                    └────────────────────────┼────────────┘
                                             │ VPN interface
                                             ▼
                                   the internal app
                                   (never public)
```

The customer never receives VPN credentials and never gets a route into the
internal network. They can reach exactly one thing: whatever `UPSTREAM_URL`
names.

## The flow

```
ADMIN                     GATEWAY                       CUSTOMER
  │                         │                             │
  ├─ email + duration ──────▶                             │
  │                         ├─ link token + password       │
  │                         ├─ create PENDING grant        │
  │                         ├─ email link + password ──────▶
  │                         │                             ├─ opens the link
  │                         │◀──────── activate ───────────┤
  │                         ├─ ACTIVE, timer starts        │
  │                         │                             ├─ logs in
  │                         │◀──────── login ──────────────┤
  │                         ├─ httpOnly session cookie ────▶
  │                         │                             ├─ uses the real app
  │                         │◀═══════ every request ═══════┤
  │                         ├─ re-check grant, then proxy  │
  │                         │                             ├─ ends session
  │                         │◀──────── logout ─────────────┤
  │                         ├─ REVOKED (credentials dead)  │
```

**Authorization is re-checked on every proxied request**, not just at login.
That is what makes an expiry or a revoke cut someone off *mid-session* rather
than at their next login.

**Logging out permanently ends the grant.** It doesn't just clear a session —
the emailed credentials can never be used again, even with time left on the
clock. Getting back in requires a new grant.

## URL layout

The gateway reserves exactly one namespace. Everything else on the origin
belongs to the app.

| Path | Owner |
|---|---|
| `/__access/*` | the gateway |
| everything else | the upstream app, proxied verbatim |

This is why the app keeps its own `/api`, `/login`, `/admin` and its
root-relative asset paths. A gateway mounted at `/` with the app under a
subpath would break every absolute link the app emits.

| Page | Purpose |
|---|---|
| `/__access/admin-login` | Admin sign in |
| `/__access/admin` | Issue, extend, re-send and revoke; the audit log; the team; your own two-factor |
| `/__access/link/<token>` | Opened from the email. Activates the grant and starts the clock |
| `/__access/login` | Email + temporary password |
| `/__access/dashboard` | Countdown, and a way into the app |
| `/__access/health/live` | Liveness. Does not touch the database |
| `/__access/health/ready` | Readiness. Checks Postgres |
| `/__access/metrics` | Prometheus. `404` unless `METRICS_TOKEN` is set and presented |
| `/` and everything else | The internal application |

## Stack

- **Backend:** Node.js 20+ / Express 5, `server.js` plus a small `lib/`
- **Proxy:** `http-proxy-middleware`, with websocket support
- **Database:** PostgreSQL
- **Email:** Resend or Amazon SES (HTTP APIs, no SDK)
- **Auth:** bcrypt passwords (cost 12), JWT in an httpOnly cookie, per-person
  admin accounts with roles, TOTP two-factor and per-account lockout
- **Observability:** structured JSON logs with request ids, Prometheus metrics,
  separate liveness and readiness probes
- **Integration:** HMAC-signed webhooks delivered from a durable outbox
- **Frontend:** plain HTML/CSS/JS, no build step
- **Tests:** `node:test`, no framework and no test dependencies

Nothing in `lib/` is a dependency wrapper. TOTP, the metrics registry and the
logger are each under two hundred lines of standard work, and all three sit in
the authentication or request path of the one process that can reach the
internal network — which is the worst place in this codebase to widen the
supply chain to save an afternoon.

## Project structure

```
server.js               the gateway: routing, authorization, the proxy
lib/
  logger.js             structured logging, with credential redaction
  metrics.js            Prometheus registry and exposition format
  totp.js               RFC 6238 two-factor, and recovery-code hashing
  webhooks.js           outbox delivery, signing, retry and backoff
schema.sql              Postgres tables (re-runnable)
public/                 the gate's own pages
  admin-login.html      admin sign in
  admin.html            issue, extend, re-send and revoke; audit; team; 2FA
  activate.html         landing page for the emailed link
  login.html            credential entry
  dashboard.html        countdown and entry to the app
  styles.css            shared design system
demo-app/app.js         stand-in upstream; also the reference implementation
                        of the app-side shared-secret check
test/
  unit.test.js          pure functions; runs without a database
  lib.test.js           lib/, including the RFC 4226/6238 test vectors
  gateway.test.js       full request lifecycle against Postgres
  admin.test.js         roles, team, two-factor, extend/re-send, export, metrics
  helpers.js            fake upstream, cookie jar, fixtures
scripts/
  create-admin.js       creates the first admin; the recovery path after that
  prune-audit.js        audit-log and outbox retention, meant for cron
  migrate.js            applies schema.sql; no psql needed
deploy/
  nginx.conf            TLS termination and websocket upgrade
  temp-access.service   systemd unit
Dockerfile              one image, used as gateway / demo-app / bootstrap
docker-compose.yml      the whole demo stack, including Postgres
.github/workflows/ci.yml  tests against a real Postgres, plus a stack smoke test
docs/demo.gif           the recording at the top of this file
DEPLOY.md               production runbook
.env.example            annotated configuration template
```

## Running the demo

Everything the system needs — Postgres, the gateway, and a stand-in for the
internal app — in one command. Nothing to install but Docker, and no
third-party account:

```bash
docker compose up --build -d
docker compose logs bootstrap     # prints the admin password, once
```

Then open **http://localhost:3000/__access/admin**, sign in as
`admin@example.com` with that password, and issue a grant to yourself. Email is
not configured, so the send fails and the console shows the access link and
password on screen — which is exactly the fallback a real deployment relies on
when a provider is down. Follow the link, log in, and you are inside the app
with a countdown bar the app itself knows nothing about.

Two things worth doing while it is up:

```bash
# The app refuses anyone who did not come through the gateway. This is
# published on 4001 only so the demo can show the refusal; in production the
# app is not reachable from outside the network at all.
curl -i localhost:4001/          # 403 Direct access is not permitted.

# Revoke the grant in the admin console, then reload the app in the browser.
# The next request bounces to ?reason=revoked, with time still on the clock.
```

`docker compose down` stops it; `docker compose down -v` also drops the
database, so the next start is clean.

The stack ships with a known `JWT_SECRET` and a database password of
`temp_access` — fine on a laptop, disqualifying in production. Every such
value is marked `DEMO ONLY` in `docker-compose.yml`, and [DEPLOY.md](DEPLOY.md)
is the runbook for a real one.

## Running locally, without Docker

```bash
npm install
cp .env.example .env          # then fill in the secrets it names
npm run migrate               # applies schema.sql; re-runnable
npm run create-admin          # create the account you'll sign in with
```

Two processes — the gateway, and something for it to proxy to:

```bash
npm run demo-app     # stand-in upstream on :4000
npm start            # gateway on :3000
```

Then open `http://localhost:3000/__access/admin`, issue a grant to yourself,
and follow the emailed link. With no email provider configured the send fails
— that's expected locally, and the admin console shows the password on screen
so you can carry on.

Point `UPSTREAM_URL` at the real application when you have one. Nothing else
changes.

## Seeing it work

A real transcript against a local gateway, with `demo-app` standing in for the
internal application. The whole lifecycle is seven requests and about ten
seconds.

**1. The admin signs in.** No shared key — an account made by `create-admin`.

```console
$ curl -sS -i -X POST localhost:3000/__access/api/admin/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"admin@example.com","password":"..."}'

HTTP/1.1 200 OK
Set-Cookie: ta_admin=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; Max-Age=3600;
            Path=/__access; HttpOnly; SameSite=Strict
```

`Path=/__access` and `SameSite=Strict` are both load-bearing: the admin cookie
is never attached to a proxied request, so it cannot reach the upstream app,
and it is never sent cross-site.

**2. The admin issues two hours to a customer.**

```console
$ curl -sS -X POST localhost:3000/__access/api/admin/grants \
    -H 'Content-Type: application/json' -H "Cookie: $ADMIN" \
    -d '{"email":"dana@acme-partner.com","durationHours":2}'

{
  "grant": {
    "id": "1a1b1a53-1054-4c76-8ddc-8c94664f48b3",
    "email": "dana@acme-partner.com",
    "status": "PENDING"
  },
  "accessUrl": "https://access.example.com/__access/link/288783494",
  "warning": "Grant created, but the email failed to send. Relay these credentials manually.",
  "password": "6WgAoaxLd68pba9N"
}
```

`PENDING`, and no clock running yet. The `warning` is the unverified-domain
path described under [Email](DEPLOY.md#email): the grant is perfectly valid, and
the password is returned exactly once so the admin can relay it by hand.

**3. The customer opens the emailed link.** This is what starts the two hours —
not the moment the grant was created.

```console
$ curl -sS localhost:3000/__access/api/activate/288783494

{ "message": "Access activated.",
  "activatedAt": "2026-08-29T06:17:58.146Z",
  "expiresAt":  "2026-08-29T08:17:58.146Z" }
```

**4. The customer logs in** with the emailed password.

```console
HTTP/1.1 200 OK
Set-Cookie: ta_session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; Max-Age=3600;
            Path=/; HttpOnly; SameSite=Lax
```

`Lax` here, not `Strict`, because this cookie has to survive the customer
arriving from a link in their mail client.

**5. They reach the internal app** — the point of the entire system.

```console
$ curl -sS -i localhost:3000/ -H 'Accept: text/html' -H "Cookie: $SESSION"

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<h1>Internal Application</h1>
<p>You are inside the VPN-hosted app, reached through the temporary access gateway.</p>
<div class="card">
  <p>The gateway told me who you are:</p>
  <p class="who">dana@acme-partner.com</p>
</div>
...
<script>/* countdown bar injected by the gateway */</script>
```

The app rendered that email itself, from the `X-Temp-Access-Email` header the
gateway set. It implements none of this. The customer, meanwhile, holds no VPN
credentials and has no route into the internal network — they reached exactly
one host, through the gateway.

**6. Time remaining**, which is also what the injected bar polls:

```console
$ curl -sS localhost:3000/__access/api/session -H "Cookie: $SESSION"

{ "email": "dana@acme-partner.com",
  "expiresAt": "2026-08-29T08:17:58.146Z",
  "remainingSeconds": 7199 }
```

**7. The admin revokes**, with 119 minutes still on the clock.

```console
$ curl -sS -X POST \
    localhost:3000/__access/api/admin/grants/1a1b1a53-.../revoke \
    -H "Cookie: $ADMIN"

{"grant":{"id":"1a1b1a53-...","status":"REVOKED"}}
```

**Six seconds later the same cookie is dead** — no logout, no expiry, nothing
the customer's browser did:

```console
$ curl -sS -i localhost:3000/ -H 'Accept: text/html' -H "Cookie: $SESSION"

HTTP/1.1 302 Found
Location: /__access/login?next=%2F&reason=revoked
```

That last pair is the part worth dwelling on. The session cookie is still
unexpired and still correctly signed — it stops working because authorization is
re-checked against Postgres on *every proxied request*, not just at login. That
is what lets a revoke or an expiry reach someone already inside the app, rather
than waiting for them to come back and log in again.

The same flow in a browser: sign in at `/__access/admin`, issue a grant, open
the link from the email, and the app appears with a countdown bar pinned to the
top of every one of its pages.

## Tests

```bash
npm test
```

The unit tests run anywhere — they cover pure functions and `lib/` only, with
no database and no listener. The integration tests need a Postgres, and are
**skipped** rather than failed without one:

```bash
TEST_DATABASE_URL=postgres://user:pass@localhost:5432/temp_access_test npm test
```

Point that at a throwaway database: every test truncates every table and runs
`schema.sql`, whose migrations rewrite rows. If creating a database is
awkward, a schema inside an existing one works:

```bash
docker run -d --name ta-test-db -e POSTGRES_PASSWORD=test   -e POSTGRES_DB=temp_access_test -p 55432:5432 postgres:16-alpine
TEST_DATABASE_URL=postgres://postgres:test@localhost:55432/temp_access_test npm test
docker rm -f ta-test-db
```

Or a schema inside an existing database, if a throwaway one is awkward:

```bash
psql "$DATABASE_URL" -c 'CREATE SCHEMA ta_test'
TEST_DATABASE_URL="...temp_access?options=-c%20search_path%3Dta_test,public" npm test
```

**Create that schema first.** Postgres silently ignores a `search_path` entry
that does not exist, so a connection string naming a schema you never created
falls straight back to `public` and the tests truncate the real tables while
looking isolated. The harness refuses to run unless the database name contains
`test` or `current_schema()` is not `public` — but the underlying trap is worth
knowing about, because it is not specific to this repo.

They start a real gateway on an ephemeral port with a stub upstream behind it,
and the weight is on the moments the gateway says no, because that is the only
thing it exists to do:

- every rejection reason `resolveSession` can produce, including the one that
  distinguishes an expired *window* from an expired *login*
- the grant lifecycle, and revocation from each state it can be revoked in
- an admin revoke reaching a customer who is already inside the app
- login against a wrong password, an expired grant, a revoked grant, and a
  differently-cased email
- both lockouts: that they count, hold against the correct password, and release
- that the reserved `/__access` namespace never falls through to the app
- that the banner survives a strict upstream CSP, with a fresh nonce per response
- that an auditor can read everything and change nothing, and that a demotion
  takes effect on the next request rather than at token expiry
- two-factor end to end: enrolment, a code that cannot be replayed, a wrong code
  counting towards the lockout, a recovery code that works exactly once
- that extending cannot walk a grant past the ceiling, and does not disturb the
  session already in progress
- that a re-send rotates both secrets and kills the old link
- that the CSV export is quoted, filtered, and defuses a spreadsheet formula
- that a webhook survives a consumer returning `500`, and that a webhook that
  cannot be queued at all never fails the grant that triggered it

`lib.test.js` checks the TOTP implementation against the published test vectors
in RFC 4226 and RFC 6238 — fixtures nobody in this repo chose, which is the
point of using them for cryptographic code.

`npm test` pins `--test-concurrency=1`: the integration files share one database
and each truncates every table between cases, so running the files in parallel
(node's default) has them deleting each other's fixtures.

## Admin authentication

Whoever holds admin access can mint access to the internal network for anyone,
indefinitely. It is the most powerful credential in the system, so it is
guarded by several independent layers rather than one shared secret.

**1. Network position.** `ADMIN_IP_ALLOWLIST` (and the matching `allow`/`deny`
block in `deploy/nginx.conf`) restricts the console to your VPN or office
range. Admins already have VPN access by the premise of this system, so the
console never needs to answer the public internet. A request from outside the
allowlist gets a `404`, not a `403` — it learns nothing about what is here.

**2. Per-person accounts, with roles.** Each admin has their own email and
bcrypt password, and can be disabled individually without disrupting anyone
else. Every action in the audit log carries the admin's real email, so the log
can answer *who let this customer in*. Disabling an account takes effect on the
next request, not at token expiry.

| Role | Can |
| --- | --- |
| `auditor` | Read the grant list and the audit log, including the CSV export |
| `admin` | Everything an auditor can, plus issue, extend, re-send and revoke grants |
| `owner` | Everything, plus add, disable and re-role admin accounts |

The role is read from the database on **every** request, not taken from the
session token. A demotion has to take effect at once, for the same reason
disabling an account does — a role carried in a JWT stays true until the token
expires, which is exactly the hour you did not want it to.

The console hides controls a role cannot use, but that is presentation. Every
route carries its own check, and an auditor calling the revoke endpoint
directly gets a `403`.

**3. Two-factor.** TOTP (RFC 6238), compatible with any authenticator app.
Enrolment is two steps — a secret is issued, and it only counts once the admin
proves they can read a code off it — so there is no such thing as a
half-enrolled account whose column says yes and whose phone says no.

Set `ADMIN_REQUIRE_TOTP=true` and an admin without it can sign in and do
exactly one thing: enrol. Nothing else in the console answers until they have.
That is enforced server-side; a console that merely declines to show the form
is a console, not a control.

Three details that are easy to get wrong and are not:

- **A code is single-use.** A TOTP code stays valid for its whole 30-second
  step, and for a step either side once clock skew is allowed — so without a
  guard, a code read over a shoulder or captured by a proxy is replayable for
  ninety seconds. The accepted step is recorded and anything at or below it is
  refused.
- **A wrong code counts towards the lockout,** exactly as a wrong password
  does. Otherwise an attacker holding a valid password gets unlimited guesses
  at six digits and the second factor is decoration.
- **Recovery codes are compared in full.** Ten single-use codes are issued at
  enrolment and shown once. A sign-in that presents one is checked against
  every unused code with no early exit, so the time taken does not reveal which
  one matched.

Turning two-factor off costs the password *and* a current code, and is refused
outright when `ADMIN_REQUIRE_TOTP` is set. Re-issuing recovery codes needs the
password and invalidates the previous set.

**4. Lockout and rate limiting.** Two deliberately different controls:
`ADMIN_MAX_FAILED_ATTEMPTS` (default 5) locks a single **account** in Postgres,
surviving restarts; `ADMIN_LOGIN_RATE_MAX` (default 10) throttles a single
**IP**, catching spraying across accounts. The limiter is the looser of the two
on purpose — if it tripped first, the account lockout would be unreachable dead
code and operators would see an opaque `429` instead of an audited
`ADMIN_LOCKED` event.

### Creating accounts

The **first** account is created on the host:

```bash
npm run create-admin                                  # prompts
npm run create-admin -- you@example.com               # prompts for the password only
npm run create-admin -- you@example.com --role=admin  # owner, admin or auditor

# Unattended, for a container bootstrap or CI. --force is required to touch an
# account that already exists, because there is nobody there to confirm it.
ADMIN_EMAIL=you@example.com ADMIN_PASSWORD=... npm run create-admin -- --force
npm run create-admin -- you@example.com --generate --force   # prints one, once
```

The password comes from the environment rather than an argument on purpose: an
argument shows up in `ps` and in shell history. The role defaults to `owner`,
because the usual reason to run this is that there is nobody to add you yet. An
existing account's role is left alone unless `--role` is passed explicitly —
this command is also the password-recovery path, and recovery must not double
as a promotion.

**After that, an owner adds colleagues from the console.** They get a generated
temporary password, shown once, and cannot do anything until they have replaced
it — a password one person chose for another is a password that person still
knows. There is still no signup page and no password-reset email: recovery from
a lost password means SSH plus `create-admin`, so host access remains the
recovery control.

Accounts are **disabled**, never deleted. The grants they issued reference
their row, and an audit trail that has lost the name of whoever authorised a
window of access is not an audit trail. The last active owner cannot be
demoted or disabled, and nobody can disable themselves.

## Access grant lifecycle

```
PENDING ──opened──→ ACTIVE ──window ends──→ EXPIRED
   │                  │
   │                  └────→ REVOKED   (admin revoke, or customer logout)
   │
   └──never opened, 24h after creation──→ EXPIRED
```

- **PENDING** — created, link not yet opened, access clock not started. Ages
  out on its own after `PENDING_EXPIRY_HOURS`.
- **ACTIVE** — link opened, clock running, login and proxying allowed.
- **EXPIRED** — one of the two clocks ran out. Which one is recoverable from
  the audit log: `GRANT_EXPIRED` means the access window closed,
  `GRANT_LINK_EXPIRED` means the link was never opened. The customer is told
  which, because only one of them means *you waited too long*.
- **REVOKED** — admin revoked it, or the customer logged out. Permanent.

Two actions change a live grant without ending it, and neither is a new state:

- **Extend** adds time to a window already running. The customer is not
  interrupted, does not log in again, and does not receive a new email. The
  added time is recorded separately from the original duration, because
  *issued for one hour and extended twice* and *issued for three hours* are
  different facts, and the second one is what an auditor is looking for. The
  ceiling in `MAX_DURATION_HOURS` is on the **total**, so repeated extensions
  cannot walk a one-hour grant past it an hour at a time.

  Only a `PENDING` or `ACTIVE` grant can be extended. Reopening an expired or
  revoked one would resurrect credentials that have already been treated as
  dead — including by whoever revoked them.

- **Re-send** rotates the link and the password on a grant nobody has opened
  yet, and emails them again. The usual reason is mundane: the message went to
  spam, or the address had a typo. Both secrets are replaced rather than
  re-sent — the first pair has been sitting in a mail queue, a spam quarantine
  and possibly the wrong person's inbox, and a re-send is exactly the moment to
  assume they are compromised. The link's own clock restarts with them, so a
  message re-sent twenty-three hours in does not arrive with an hour left on a
  deadline the customer knows nothing about.

  Not offered for an `ACTIVE` grant: the customer is already in, and rotating
  the password under them would end their session and create a support ticket
  rather than solve one. That case is still revoke-and-reissue.

Every grant also records **who issued it** and, optionally, **why**. Set
`REQUIRE_GRANT_REASON=true` and the console will not issue access without a
ticket, incident or contract reference. Turn it on if anyone will ever ask who
had access to this system in March and on whose authority — the answer has to
be written down at the moment access is granted, and there is no reconstructing
it from timestamps afterwards.

## Operating it

**Structured logs.** One JSON object per line, or a readable line when stdout
is a terminal — the same call, chosen by destination rather than by `NODE_ENV`,
which is what gets `npm start` on a server and a container run interactively
both right. `LOG_LEVEL=debug` adds a line per proxied request, which on a
reverse proxy means every image and stylesheet the upstream app pulls in.

Keys that name a credential — password, secret, token, cookie, authorization —
are redacted centrally rather than at each call site, because a rule that
depends on every future caller remembering it is not a rule.

**Request ids.** Every request gets one, taken from an inbound `X-Request-Id`
when it is present and well-formed and generated otherwise. It comes back in
the response header, appears in every log line for that request, and is stored
on the `audit_log` row. A customer reporting a failure can quote the header and
that finds the exact request; a `500` carries it in the body for the same
reason.

Inbound values are validated before being trusted. They end up in a log line
and a database column, and an unbounded header is how a log file acquires
forged newlines.

**Probes.** `/__access/health/live` answers whether the process can serve;
`/__access/health/ready` answers whether it should be sent traffic, and is the
one that checks Postgres. The distinction is not pedantry: a liveness probe
that checks the database tells the orchestrator to *restart the gateway* when
the database has a bad minute, so a blip the connection pool would have ridden
out becomes a rolling restart of every instance, for as long as the blip lasts.
`/__access/health` still answers, so existing probes keep working.

**Metrics.** A Prometheus scrape target at `/__access/metrics`, served only
when `METRICS_TOKEN` is set and only to a caller presenting it as a bearer
token; anything else gets a `404`, so a scanner cannot tell the endpoint
exists. Grants by transition, logins by principal and outcome, live grants,
request rate and latency, upstream errors, webhook delivery, and the
undelivered-outbox depth.

Every label value comes from a fixed set — a route pattern, a status class, an
event name — and never from a URL, an email address or a grant id. A label with
unbounded values multiplies into a series per distinct value and takes the
scrape target down with it, which is the standard way a metrics endpoint
becomes the outage.

**Webhooks.** Set `WEBHOOK_URL` and lifecycle events are pushed to a SIEM, a
SOC channel or a ticketing system. Two things make this safe to depend on:

- *An outbox.* The event is written to a table inside the request that caused
  it and delivered from there by the background sweeper. A slow or unreachable
  consumer cannot slow down issuing a grant, and a delivery interrupted by a
  deploy is still queued afterwards. For a feed whose whole purpose is
  recording security events, a fire-and-forget POST that evaporates is worse
  than no feed at all, because someone will have stopped watching the console
  on the strength of it. Rows are claimed with `FOR UPDATE SKIP LOCKED`, so two
  gateway processes against one database do not both deliver the same event.

- *A signature.* `X-Gateway-Signature: sha256=<hex>` over `<timestamp>.<body>`,
  with the timestamp beside it in `X-Gateway-Timestamp`. The timestamp is
  inside the signed string rather than only in a header, which is what lets a
  receiver reject a replay — a body captured today is otherwise
  indistinguishable from a fresh one. Receivers should check the age and
  compare with a constant-time function.

Failed deliveries retry with exponential backoff and jitter, capped at fifteen
minutes, and are marked `FAILED` after `WEBHOOK_MAX_ATTEMPTS`. `prune-audit`
sweeps delivered rows and never touches failed ones — a security event that was
never handed to the consumer is exactly what someone will want to find later.

**Audit export.** The console filters the log by event, actor and date range,
and exports the same query as CSV. Streamed in pages rather than as one large
result set, because materialising half a million rows in memory would do it
inside the process every customer's traffic flows through. Fields that a
spreadsheet would run as a formula (`=`, `+`, `-`, `@`) are prefixed with an
apostrophe: the export is opened in Excel far more often than it is parsed, and
that reader is the one worth protecting. The file ends with a `#end,<n> rows`
line so a truncated download is detectable, and the export is itself an audited
event.

## Design notes

- **Three clocks, kept distinct.** Conflating any two of them produces a bug
  that is very hard to recognise from a support ticket:

  | Clock | Controlled by | Starts | Shipped value |
  | --- | --- | --- | --- |
  | Link validity | `PENDING_EXPIRY_HOURS` | grant creation | 24h |
  | Access window | `durationHours` per grant, capped by `MAX_DURATION_HOURS` | activation | admin-chosen, max 24h |
  | Login session | `SESSION_TTL_SECONDS`, capped at the grant's expiry | login | 1h |

- **The access clock starts on activation, not creation.** A grant created at
  10am and opened at 4pm runs from 4pm. The link's own clock, though, runs from
  creation — an unopened link used to stay activatable indefinitely, which also
  meant the credentials sitting in someone's inbox stayed live indefinitely.
- **`MAX_DURATION_HOURS` is a ceiling, not a default.** There is no default
  duration in the code; the admin names one on every grant and the check only
  rejects values above the ceiling. 24 hours is a deliberate starting position
  rather than a permanent constraint — a contractor on a two-week job would
  need a fresh link daily under it, so it is worth asking a client for their
  longest realistic access period. Raising it is a one-line change.
- **Sessions live in an httpOnly cookie, not `sessionStorage`.** This is forced
  by the proxy: when the browser fetches the app's own stylesheets, scripts and
  XHRs it attaches cookies but never an `Authorization` header. A bearer-token
  session cannot gate a reverse proxy.
- **Sessions are capped at the grant's expiry** — `min(now + SESSION_TTL, grant.expires_at)`
  — so a session can never outlive its grant.
- **Grant status is cached for a few seconds** on the proxy hot path, because
  re-reading Postgres for every image would make the gateway the slowest thing
  in the stack. Logout and admin-revoke bust the cache directly, so revocation
  stays effectively instant.
- **The session cookie is stripped from proxied HTTP requests** before
  forwarding, so the upstream app never sees it. Those requests carry
  `X-Temp-Access-Email` and `X-Temp-Access-Grant` instead, set unconditionally
  on the way through so a client cannot forge them. Websocket upgrades get
  exactly the same treatment, through the same function.
- **A countdown bar is injected into the app's HTML pages** so the customer can
  always see the time left and end the session from anywhere inside the app.
  Only documents are buffered for injection; assets stream untouched.
- **Websocket upgrades are authorized separately**, since they bypass Express
  middleware entirely. The session is resolved before the socket is handed
  to the proxy, and tests cover the refusals — no session, a revoked grant —
  as well as the header hygiene on an upgrade that is allowed through.
- **Token vs. password.** The link token is 256 random bits, SHA-256 hashed
  for lookup; nobody types it, so its length costs the customer nothing. The
  password is a real credential, bcrypt cost 12.
- **Email is accepted, not delivered.** A provider returning `200` means it
  took the message, not that anyone received it. The audit event is
  `GRANT_EMAIL_ACCEPTED` and the console says *accepted for delivery*, because
  a log that said "sent" would agree with the admin and disagree with reality.
  Delivery webhooks would close the gap and are not on the plan; the answer to
  a link that never arrived is **Revoke and reissue** in the console, which is
  one action. No plaintext password is stored to re-send — reissuing generates
  a new one, returns it for the admin to read out, and records
  `GRANT_PASSWORD_RELAYED`, because a credential leaving by a second route is
  exactly what an audit log should be able to answer for.
- **Failed logins are counted, audited, and eventually lock the grant**, and a
  login against a non-existent grant still runs a bcrypt comparison, so
  response timing does not reveal which emails have grants. The lockout lives
  in Postgres for the same reason the admin one does: it survives a restart,
  and it catches an attempt spread across many IPs, which a per-IP limiter
  cannot see at all. A locked-out customer is told they are locked out rather
  than told their password is wrong — they are typing a generated password off
  a screen, and the alternative is a support call.
- **Emails are stored and compared lower-cased.** An admin who types
  `Contractor@Firm.com` and a customer who types `contractor@firm.com` are the
  same person, and any other answer produces a grant that cannot be used and a
  rejection that reads as a wrong password.
- **The injected banner carries a per-response CSP nonce**, added to the
  upstream's own `script-src`/`style-src` rather than stripping the header.
  An app with a strict CSP would otherwise silently drop the banner: no
  countdown, no way to end the session, and nothing reporting a problem.
- **A background sweeper** flips lapsed grants to `EXPIRED`, so the admin
  console doesn't show stale `ACTIVE` rows for windows that closed hours ago.
- **Admin and customer sessions cannot be swapped.** Admin tokens are signed
  with a key *derived* from `JWT_SECRET`, not `JWT_SECRET` itself, so a
  customer's cookie replayed as an admin cookie fails the signature check
  structurally — rather than depending on someone remembering to check a claim.
- **The reserved namespace is sealed in both directions.** A `/__access/*` URL
  the gateway does not define returns 404 instead of falling through to the
  proxy, so the app can never see or answer requests inside the one namespace
  this design promises it will never own.

## Deliberate constraints

**One instance.** `grantCache` is per-process and `express-rate-limit` uses its
in-memory store, so both are correct for a single instance and quietly wrong
for two: a revoke would lag on whichever instance did not handle it until the
cache TTL expired, and every rate limit would divide per instance. This suits
the deployment it is built for — one VM, co-located with the app it fronts —
and it is a constraint rather than an oversight. Running more than one instance
needs a shared cache (Redis) for grant status and a shared store for the rate
limiters. Nothing else in the design is in the way.

**At most one live grant per email address**, where live means `PENDING` or
`ACTIVE`. Issuing a second one returns `409` with the existing grant's id,
status and expiry, and the `uniq_live_grant_per_email` partial index enforces
it under a race. Two live grants for one person cannot be told apart at login
— a password can only be checked against one of them — so the older one would
silently stop working, and its failed attempts would be counted against the
wrong grant.

The console offers **Revoke and reissue** as a single confirmed action, and
says plainly that revoking ends any session in progress immediately. It is
never automatic: auto-revoking would cut someone off mid-task to make room for
a grant nobody had confirmed they wanted.

**Audit retention is 12 months by default.** The log is append-only and the
application never deletes from it; `npm run prune-audit` is the single
exception, meant for cron, and it writes an `AUDIT_PRUNED` event of its own.
Set `AUDIT_RETENTION_MONTHS` to whatever the client's policy actually says.

```bash
npm run prune-audit -- --dry-run     # count what would go
npm run prune-audit -- --months=24
```

**Email is not a hard dependency.** Resend is what this runs on; its free tier
(3,000/month, 100/day) covers the expected volume. SES is supported behind the
same interface so the provider is a config-level swap rather than a rewrite —
it is not a security improvement over Resend and is not treated as one. If a
send fails outright, grant creation still returns `202` with the password in
the body so the admin can relay it by hand: the grant is real either way, and
losing it to an email outage would only mean issuing it again.

## Not handled (by design)

Per the project's convenience-over-maximum-security philosophy, this does not
attempt to solve: phishing, social engineering, credential sharing,
screenshotted or forwarded credentials, or compromised customer devices.

The fingerprint captured at activation flags a link opened from a different
IP or browser (`ACTIVATE_REOPENED_FINGERPRINT_MISMATCH` in the audit log) but
deliberately does not block it — customers roam between networks, and a false
lockout is worse than a logged anomaly.

Also out of scope, and worth saying plainly rather than leaving to be
discovered:

- **Employee or staff access.** This is not a VPN replacement and not an
  identity provider. Employees have permanent identities that a directory
  owns; this issues disposable ones that expire. Pointing it at your own
  workforce would mean re-issuing links to the same people forever, with no
  directory behind them — see [Who this is for](#who-this-is-for).
- **Multi-instance / horizontal scaling** — see the constraint above. The
  webhook outbox is already safe to drain from several processes, and the
  grant-status cache is bounded by a short TTL, but the rate limiters are
  per-process and in memory, which is the piece that would need a shared store
  first.
- **Customer-side SSO or MFA.** The emailed password is the whole credential.
  Two-factor exists for admins only, which is where the powerful credential is.
- **Admin SSO / SAML / SCIM.** Accounts are local. For a company already
  running an identity provider this is the next thing worth building, and the
  roles are the seam it would attach to.
- **Per-application or granular permissions.** One gateway fronts one upstream;
  a grant is all-or-nothing within it.
- **The upstream app's own security posture.** The gateway controls *who
  reaches* the app and *for how long*. What the app does with a request is the
  app's business, and a vulnerability inside it is not something a proxy in
  front can fix.
- **Proving the app is unreachable except through the gateway.**
  `UPSTREAM_SHARED_SECRET` lets the app refuse anything that did not come via
  the gateway, and the gateway warns at boot if `UPSTREAM_URL` looks public —
  but the actual isolation is a network and DNS property of the deployment.
  DEPLOY.md treats it as a required integration step, not a hardening tip.

## Extending later

Extending an active window and TOTP two-factor used to be listed here. Both
are implemented. What remains, roughly in the order a company would want it:

- **Admin SSO** (OIDC or SAML), with the existing roles as the mapping target
- **Multiple upstreams,** with a grant scoped to one of them — the largest of
  these, because routing by hostname changes the shape of the proxy
- **A shared rate-limit store,** which is what stands between this and running
  more than one instance
- One-time (single-use) links
- Per-grant path allowlists within the app
- Ephemeral WireGuard peers, for non-HTTP access (SSH, RDP, databases)

## Deployment

[DEPLOY.md](DEPLOY.md) is the runbook: a systemd unit, nginx terminating TLS, a
firewall, and the upstream isolation the whole design rests on.

**The compose stack is not that.** It exists so the system can be run and shown
in one command, and it makes three choices no production deployment should
inherit:

| | demo (`docker compose`) | production (DEPLOY.md) |
|---|---|---|
| secrets | committed defaults, marked `DEMO ONLY` | generated per environment, in `.env` on the host |
| database | a container with a local volume | managed Postgres, or local with `pg_dump` to somewhere else |
| TLS | none; `COOKIE_SECURE=false` | nginx, real certificate, secure cookies |
| upstream | `demo-app`, published on 4001 to demonstrate the refusal | the real app, unreachable except through the gateway |
| admin console | open to whoever can reach the port | scoped to a VPN range with `ADMIN_IP_ALLOWLIST` |

Running the image in production is reasonable — it is the same image — but the
compose file is a demo harness, not a deployment manifest. Point `UPSTREAM_URL`
at the real application, supply real secrets, and put nginx in front.
