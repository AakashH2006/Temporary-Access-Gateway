# Deploying the gateway

The gateway is the only machine that needs to sit in two networks at once:
reachable from the public internet, and able to reach the VPN-hosted app.
Nothing else changes about the app, and customers install nothing.

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

The security property that matters: **the gateway's own network position is
the secret.** A customer never receives VPN credentials, never gets a route
into the internal network, and can only reach whatever single upstream
`UPSTREAM_URL` names.

**Who this is being deployed for: outside vendors, not employees.** Everyone
on this page is an external party — a vendor's engineer, an auditor, an
integration partner — who has no account in your directory and no VPN client,
and who needs one application for hours or days. Employees keep using the VPN;
this does not replace it, front it, or interact with it. That boundary is why
several choices below are safe: a grant is disposable, owns nothing, and
expires on a clock. See ["Who this is for"](README.md#who-this-is-for).

**Showing it rather than shipping it?** `docker compose up --build` runs the
whole system on a laptop, with a stand-in for the internal app -- see
[README.md](README.md#running-the-demo). The rest of this file is the real
deployment; ["A demo on a public URL"](#a-demo-on-a-public-url) at the end is
the short path between the two, and ["A free demo on Render +
Neon"](#a-free-demo-on-render--neon) is the one that costs nothing.

---

## 1. Host prerequisites

A small VM is plenty — this is I/O-bound, not CPU-bound.

```bash
sudo apt update
sudo apt install -y nodejs npm postgresql nginx certbot python3-certbot-nginx
node -v      # needs >= 20
```

The host must already be on the VPN and able to reach the app:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://<internal-app>:<port>/
```

If that doesn't return a status code, stop here — the gateway cannot forward
to something it can't reach, and nothing downstream will work.

## 2. Service user and code

```bash
sudo useradd --system --home /opt/temp-access --shell /usr/sbin/nologin tempaccess
sudo mkdir -p /opt/temp-access
sudo chown tempaccess:tempaccess /opt/temp-access

sudo -u tempaccess git clone <your-repo> /opt/temp-access
cd /opt/temp-access
sudo -u tempaccess npm ci --omit=dev
```

## 3. Database

```bash
sudo -u postgres psql <<'SQL'
CREATE USER temp_access_user WITH PASSWORD 'CHANGE-ME';
CREATE DATABASE temp_access OWNER temp_access_user;
SQL

```

Then apply the schema. Do this after step 4, once `.env` holds the
`DATABASE_URL` -- `npm run migrate` reads it from there, and uses the same `pg`
driver the application does, so it needs no Postgres client tools installed:

```bash
sudo -u tempaccess npm run migrate
```

`schema.sql` is written to be re-runnable, so applying it again on upgrade is
safe -- and is the upgrade step. There is no version table and no down
direction; if that stops being enough, that is the moment to adopt a real
migration tool rather than to hand-edit the database.

## 4. Configuration

```bash
sudo -u tempaccess cp .env.example .env
sudo -u tempaccess nano .env
```

Generate the signing secret:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

There is no admin API key to generate any more — admin access is per-person
accounts, created in step 4b.

The values that actually decide whether this works:

| Variable | Production value | What breaks if wrong |
|---|---|---|
| `PUBLIC_BASE_URL` | `https://access.example.com` | Emailed links point somewhere dead. Must be the **public** URL, https, no trailing slash. |
| `UPSTREAM_URL` | `http://10.x.x.x:8080` | 502 for every customer. Must be reachable from this host and **not** from the internet. |
| `TRUST_PROXY` | `true` | Left `false` behind nginx, every visitor shares one rate-limit bucket and the audit log records nginx's IP for everyone. |
| `JWT_SECRET` | 48 random bytes | Under 32 chars the gateway refuses to boot. Changing it later invalidates every live session. |
| `DATABASE_SSL` | `true` for managed Postgres | Connection failures at boot. |
| `DATABASE_CA_FILE` | Path to the provider's CA bundle, when `DATABASE_SSL=true` | A certificate error at boot. Certificates are verified; fetch the bundle rather than turning verification off. |
| `DATABASE_SSL_INSECURE` | Leave unset | Set to `true`, the database connection is encrypted but unauthenticated, and anyone on the path can read every credential. |
| `ADMIN_IP_ALLOWLIST` | your VPN/office CIDRs | Left empty, the admin console answers the public internet. This is the cheapest strong control available -- use it. |
| `UPSTREAM_SHARED_SECRET` | 32 random bytes | Left empty, anyone who learns the app's own address bypasses the gateway entirely. See step 7b -- it needs a matching check in the app. |
| `AUDIT_RETENTION_MONTHS` | your policy, default 12 | Only read by `npm run prune-audit`. Nothing is deleted until that runs. |
| `MAX_DURATION_HOURS` | `24` | A ceiling on the access window, not a default. Same value if unset, so dropping it cannot widen the ceiling. |
| `PENDING_EXPIRY_HOURS` | `24` | How long an unopened link stays activatable. Unset, the code default is also 24. Not the same clock as the one above. |
| `ADMIN_REQUIRE_TOTP` | `true` | Left off, a stolen or phished admin password is enough to mint access to the internal network. Turning it on does not lock anyone out -- they sign in and are shown the enrolment screen and nothing else. |
| `REQUIRE_GRANT_REASON` | `true` if anyone will audit this | Left off, nothing records *why* a window of access was opened, and it cannot be reconstructed later. |
| `METRICS_TOKEN` | 32 random bytes | Left empty, `/__access/metrics` returns 404 and you have no numbers. Set, it is served only to a caller presenting the bearer token. |
| `WEBHOOK_URL` / `WEBHOOK_SECRET` | your SIEM or SOC channel | Left empty, nothing is sent. Set the URL without the secret and the receiver is trusting anyone who learns the URL. |
| `LOG_FORMAT` | leave unset | Defaults to `json` when stdout is not a terminal, which is what systemd gives it. Set `pretty` only if a human is reading the journal directly. |

Lock the file down — it holds the key to the internal network:

```bash
sudo chown root:tempaccess .env && sudo chmod 640 .env
```

## 4b. Create the first admin

There is no shared admin key and no signup page. Accounts are created here:

```bash
sudo -u tempaccess npm run create-admin
```

Use a real address and a password from a password manager. Nothing can be
issued until at least one account exists -- the gateway warns loudly at boot
when the table is empty.

This same command is the recovery path: re-running it for an existing email
resets the password and clears any lockout. Losing an admin password therefore
requires SSH to fix, which is itself a control worth keeping.

The account it creates is an **owner** -- the only role that can add anyone
else. Add the rest of the team from the console rather than from here: those
accounts are created with a temporary password that must be changed at first
sign-in, and the whole thing is audited with both parties named.

```bash
# Or create a colleague directly, at a narrower role.
sudo -u tempaccess npm run create-admin -- them@example.com --role=auditor
```

**Two-factor.** With `ADMIN_REQUIRE_TOTP=true` in `.env`, enrol before you hand
the console to anyone:

1. Sign in and open **Security**.
2. Add the key shown there to an authenticator app and enter the code.
3. **Save the ten recovery codes.** They are shown once. Without them, a lost
   phone means SSH and SQL.

There is no way for one admin to reset another's second factor. An owner can
disable the account and issue a new one, which is auditable; being able to
impersonate a colleague is not a feature worth having in the system that opens
the internal network.

## 5. Service

```bash
sudo cp deploy/temp-access.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now temp-access
sudo journalctl -u temp-access -f
```

A healthy start logs the upstream and admin URLs. A misconfigured one exits
immediately naming the missing variable, rather than starting and failing per
request.

## 6. TLS and nginx

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/temp-access
sudo nano /etc/nginx/sites-available/temp-access     # set your hostname
sudo ln -s /etc/nginx/sites-available/temp-access /etc/nginx/sites-enabled/
```

Add to the `http {}` block of `/etc/nginx/nginx.conf` if not already present:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

Then:

```bash
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d access.example.com
```

Certbot rewrites the TLS paths itself, so run it after the config is in place.

## 7. Firewall

The gateway is the only public surface. Node must not be reachable directly —
if it is, `TRUST_PROXY=true` lets anyone forge their source IP.

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80,443/tcp
sudo ufw deny 3000/tcp
sudo ufw enable
```

Confirm from a machine that is **not** on the VPN:

```bash
curl -sS -m 5 http://<gateway-public-ip>:3000/    # must fail
curl -sS -m 5 http://<internal-app>:<port>/       # must fail
```

Both failing is the whole point of the design. If either succeeds, the
gateway is being bypassed.

## 7b. Upstream isolation

**This is an integration step, not a hardening note.** Everything else in this
runbook is worthless if the app answers requests that did not come through the
gateway. There are two halves, and you want both.

**Network.** The app should accept connections only from the gateway host --
a security group, a firewall rule, or binding to an interface the internet
cannot reach. This is the half that actually enforces the property.

**A shared secret**, as defence in depth for when the network half is wrong,
which is a thing that happens quietly:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

Put it in the gateway's `.env` as `UPSTREAM_SHARED_SECRET`. The gateway then
sends it on every proxied request, overwriting anything the client tried to
send under the same name. In the app, reject requests that do not carry it --
about ten lines, wherever middleware goes. Express, for illustration:

```js
const SECRET = process.env.GATEWAY_SECRET;
app.use((req, res, next) => {
  const given = req.get('X-Gateway-Secret') || '';
  const ok = given.length === SECRET.length
    && require('crypto').timingSafeEqual(Buffer.from(given), Buffer.from(SECRET));
  if (!ok) return res.status(403).send('Direct access is not permitted.');
  next();
});
```

Health checks and anything else that must reach the app directly need an
explicit exemption -- decide that deliberately rather than discovering it when
monitoring goes red.

**Then audit every path that points at the app directly.** This is the single
most likely way a real deployment ends up worthless:

- DNS records resolving to the app's own address (including stale ones)
- hardcoded URLs in the app's own pages, emails, scripts and mobile clients
- bookmarks and links in the client's internal documentation
- other services that call the app and have their own route to it

The gateway warns at boot if `UPSTREAM_URL` resolves to a public address, but
that catches only the most obvious case. Nothing in software can do this audit
for you.

## 8. Verify

```bash
curl -sS https://access.example.com/__access/health
# {"ok":true,"database":"ok"}
# 503 {"ok":false,"database":"unreachable"} if Postgres is unreachable, which
# is the honest answer: no grant can be read, so nobody is getting in.
# It deliberately does not name the upstream -- this URL answers anonymously.

curl -sSI https://access.example.com/
# HTTP/2 302 ... location: /__access/login?next=%2F&reason=no_session
```

That 302 on `/` is the real test: an unauthenticated visitor is bounced to the
login page instead of reaching the app.

Then issue a grant to yourself at `https://access.example.com/__access/admin`
and walk the flow once end to end.

---

## Email

Resend is what this runs on; Brevo covers a deployment with no domain to verify
(see "Email on the free plan" above). SES is supported behind the same interface
(`EMAIL_PROVIDER`, or inferred from whichever credentials are present) so the
provider is a config-level swap rather than a rewrite -- but it is not a
security improvement over Resend, and changing provider is not security work.

### Domain verification -- start this first

**This is the longest lead time in the project.** It depends on the client's
DNS, which depends on whoever owns their DNS, and nothing else here is blocked
by anyone but you.

- `EMAIL_FROM=access@mail.theircompany.com` -- a **subdomain**, so the sending
  reputation of these messages is isolated from their corporate mail. A spam
  complaint about an access link should not touch their invoices.
- The client adds Resend's **SPF and DKIM** records at
  [resend.com/domains](https://resend.com/domains).
- **DMARC at `p=none`** initially. Tightening it later is a decision to take
  with real delivery data, not before.
- `PUBLIC_BASE_URL` must be the real HTTPS origin. `COOKIE_SECURE` is derived
  from it and every emailed link is built from it -- a wrong value ships dead
  links with insecure cookies, and both failures land on the customer.

Until the domain is verified, Resend sends only **from** `onboarding@resend.dev`
**to** the address the account was registered with. Real customers receive
nothing.

### Plan limits

The free tier is 3,000 emails a month and **100 a day**, which is comfortably
above the expected volume. The daily cap is the one that bites: onboarding more
than ~90 people in a single day needs a plan upgrade arranged first, not
discovered at grant 101.

### Delivery is not visible

A `200` from the provider means the message was accepted, not delivered. A
later bounce or spam-filter drop is invisible here: the admin sees success, the
customer sees nothing, and an audit log that said *sent* would side with the
admin. So it says `GRANT_EMAIL_ACCEPTED`, and the console says *accepted for
delivery*. Delivery webhooks would close the gap and are not on the free plan.

When a customer says the email never arrived, the answer is **Revoke and
reissue** in the console -- one action, and it produces a new password for the
admin to read out. There is deliberately no stored plaintext password to
re-send. That path records `GRANT_PASSWORD_RELAYED` alongside the usual
`GRANT_CREATED`: a credential leaving the system by a route other than the
email is worth being able to account for later.

### SES, if the provider ever changes

`SES_REGION`, `SES_ACCESS_KEY_ID`, `SES_SECRET_ACCESS_KEY`. Two things catch
people out: a new SES account is **sandboxed** and can only send to verified
addresses until you request production access, and `EMAIL_FROM` must be a
verified identity in that region. Use an IAM user scoped to `ses:SendEmail` and
nothing else.

### Account hygiene

- The Resend API key is scoped to **sending only** -- no log read permission.
  The key sits on an internet-facing VM; it should not be able to read the
  message bodies, which contain live credentials.
- **2FA on the Resend account itself.** Whoever holds it can read delivery logs
  and change the sending domain.

Whichever provider is configured, the console still works when a send fails
outright: the password comes back on screen for the admin to relay by hand, and
the grant itself is valid. The gateway logs which provider it resolved at boot
and warns when none is configured.

**Issue a grant to yourself and confirm the email actually arrives** before
handover, and again after any change of provider or sending domain.

## Operating notes

**Upgrades**

```bash
cd /opt/temp-access
sudo -u tempaccess git pull
sudo -u tempaccess npm ci --omit=dev
sudo -u tempaccess npm run migrate     # re-runnable
sudo systemctl restart temp-access
```

Restarting drops live sessions only if `JWT_SECRET` changed; otherwise
customers keep working, since sessions are stateless and re-checked against
Postgres on every request.

**Backups.** Postgres is local to this VM, so a lost VM is lost access records.
Nightly `pg_dump`, plus provider snapshots of the instance itself:

```bash
# /etc/cron.d/temp-access-backup
# cron does not read .env, hence the explicit source; % must be escaped here.
30 2 * * * tempaccess set -a; . /opt/temp-access/.env; set +a; pg_dump "$DATABASE_URL" | gzip > /var/backups/temp-access-$(date +\%F).sql.gz
```

**Restore the backup once, before handover.** Into a scratch database, and
check the row counts. An untested backup is a belief, not a control.

**Audit retention.** `audit_log` is append-only and nothing deletes from it
until you schedule this. The default window is 12 months
(`AUDIT_RETENTION_MONTHS`); set it to whatever the client's policy says, and
know the answer before their compliance people ask:

```bash
# /etc/cron.d/temp-access-prune
0 3 * * 0 tempaccess cd /opt/temp-access && npm run prune-audit
```

Check what it would remove first with `npm run prune-audit -- --dry-run`. The
prune writes an `AUDIT_PRUNED` row of its own, so the shortening is itself in
the log.

The same job sweeps delivered `webhook_outbox` rows after
`WEBHOOK_RETENTION_DAYS` (30). Failed ones are never swept.

**Monitoring.** The gateway being down does not merely degrade the app: it
makes the app unreachable for every temporary user, and the people affected are
the ones least able to tell you.

Two probes, and they are not interchangeable:

| Probe | Checks | Use it for |
|---|---|---|
| `GET /__access/health/live` | the process only | restart policy |
| `GET /__access/health/ready` | the process **and** Postgres | load-balancer membership, uptime checks |

Do not point a restart policy at readiness. A liveness probe that checks the
database tells the supervisor to restart the gateway every time Postgres has a
bad minute, so a blip the connection pool would have ridden out becomes a
restart loop that lasts as long as the blip. `GET /__access/health` still
answers as an alias for readiness, so an existing check keeps working.

**Metrics.** Set `METRICS_TOKEN` and scrape `/__access/metrics`:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: temp-access
    metrics_path: /__access/metrics
    authorization: { credentials: "<METRICS_TOKEN>" }
    static_configs: [{ targets: ["access.example.com:443"] }]
    scheme: https
```

Four alerts worth having on day one:

| Alert | Expression | Why |
|---|---|---|
| Gateway down | `up == 0` | Nobody can reach the app |
| Upstream unreachable | `rate(gateway_upstream_errors_total[5m]) > 0` | The gateway is fine and the app behind it is not |
| Admin sign-in being guessed | `rate(gateway_logins_total{principal="admin",outcome!="success"}[15m]) > 0.1` | The credential that mints access is under attack |
| Webhook feed stalled | `gateway_webhook_outbox_pending > 50` | Security events are being recorded and not delivered |

`gateway_grants_live` is the one to put on a dashboard: it is the answer to
*how many people can reach the internal network right now*, which is a question
worth being able to answer without opening the console.

**Webhooks.** If `WEBHOOK_URL` is set, the receiver must verify the signature.
The gateway sends `X-Gateway-Signature: sha256=<hex>`, computed as an HMAC-SHA256
of `<timestamp>.<raw body>` using `WEBHOOK_SECRET`, with the timestamp in
`X-Gateway-Timestamp`:

```js
const expected = crypto.createHmac('sha256', SECRET)
  .update(`${req.headers['x-gateway-timestamp']}.${rawBody}`)
  .digest('hex');

// Constant-time, and reject anything older than five minutes -- the timestamp
// is inside the signed string precisely so a captured body cannot be replayed.
const fresh = Math.abs(Date.now() / 1000 - Number(req.headers['x-gateway-timestamp'])) < 300;
const ok = fresh && crypto.timingSafeEqual(
  Buffer.from(expected),
  Buffer.from(String(req.headers['x-gateway-signature']).replace('sha256=', ''))
);
```

Answer `2xx` to acknowledge. Anything else is retried with exponential backoff
for `WEBHOOK_MAX_ATTEMPTS` tries and then marked `FAILED` and left in the
`webhook_outbox` table, where it stays -- a security event that was never
delivered is exactly what someone will want to find later:

```sql
SELECT id, event, attempts, last_error, created_at
  FROM webhook_outbox WHERE status = 'FAILED' ORDER BY id DESC LIMIT 20;
```

**Logs.** Under systemd, stdout is not a terminal, so the gateway emits one
JSON object per line. Every line for a single request carries the same
`requestId`, which is also returned to the caller in the `X-Request-Id`
response header and stored on the `audit_log` row -- so a customer quoting the
header from an error page is handing you the exact request:

```bash
sudo journalctl -u temp-access -o cat | jq 'select(.requestId == "<id>")'
sudo journalctl -u temp-access -o cat | jq 'select(.level == "error")'
```

`LOG_LEVEL=debug` adds a line per proxied request. On a reverse proxy that is
every image and stylesheet the upstream app pulls in -- useful for an hour
while diagnosing, expensive as a steady state.

**Log rotation.** Everything goes to the systemd journal, which is not capped
by default on every distro:

```bash
sudo sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=500M/' /etc/systemd/journald.conf
sudo systemctl restart systemd-journald
```

**Unattended security upgrades** on the host, since this VM is internet-facing:

```bash
sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades
```

**Rotating `JWT_SECRET`.** This is the break-glass response to a suspected leak
of the secret itself. Changing it invalidates **every** live customer session
and **every** admin session at once, immediately -- customers must log in again
with their emailed credentials (which still work; the grants are unaffected),
and admins must sign in again. Grants themselves are not touched. Rotate it by
editing `.env` and restarting.

**Admin account recovery** requires SSH plus `npm run create-admin`. That is
deliberate -- it means an internet-facing password reset does not exist for the
credential that mints access to the internal network. It also means **at least
two people must have host access**. One person holding it is one resignation
away from a client who cannot issue access at all.

**Removing an admin.** Takes effect on their next request, no restart needed:

```sql
UPDATE admins SET disabled_at = now() WHERE email = 'someone@example.com';
```

**Revoking customer access in a hurry.** Any of these ends access immediately:

- the Revoke button in the admin console (takes effect within `GRANT_CACHE_TTL_MS`, default 5s)
- `systemctl stop temp-access` — kills all access at once
- `UPDATE access_grants SET status='REVOKED' WHERE status='ACTIVE';` in psql

**Reading the audit log.**

```sql
SELECT created_at, event, actor, ip_address, detail
FROM audit_log ORDER BY created_at DESC LIMIT 50;
```

`ADMIN_LOGIN_FAILED`, `ADMIN_LOCKED` and `ADMIN_IP_DENIED` are the admin-side
events worth alerting on -- repeated ones mean someone is probing the console.

`ACTIVATE_REOPENED_FINGERPRINT_MISMATCH` is the customer-side one: an
access link opened from a different IP or browser than the one that first
activated it, which is what a forwarded or intercepted link looks like.

`GRANT_EXPIRED` and `GRANT_LINK_EXPIRED` are deliberately different events.
The first means the access window ran out; the second means the link was never
opened within `PENDING_EXPIRY_HOURS`. "They ran out of time" and "they never
showed up" are different facts about a customer, and this log is where that
question gets answered months later.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Exits at boot with `Cannot reach the database` | Postgres is down or `DATABASE_URL` is wrong. Deliberate: the gateway refuses to start rather than 500ing on the first customer. |
| Customer sign-in returns 429 | Either the per-IP throttle, or that grant is locked after `GRANT_MAX_FAILED_ATTEMPTS` failures (`GRANT_LOCKED` in the audit log). The message names the wait. Issuing a fresh grant also clears it. |
| Issuing a grant returns 409 | That person already has a live (`PENDING` or `ACTIVE`) grant. The console offers **Revoke and reissue** as one action; revoking ends any session in progress immediately. |
| Customer says the link says "Link expired" | It was not opened within `PENDING_EXPIRY_HOURS` (24h). Reissue -- that is a new grant and a new password, by design. |
| Customer says the email never arrived | The provider accepted it; delivery is not visible from here. Check their spam folder, then **Revoke and reissue**. Verify SPF/DKIM are actually in the client's DNS. |
| Duration options missing from the console | It only offers what `MAX_DURATION_HOURS` allows, read from `/auth/me` at load. |
| Countdown bar missing on the app's pages | The app's CSP. The gateway nonces the banner into `script-src`/`style-src` automatically; if a policy defeats that, `STRIP_UPSTREAM_CSP=true` is the escape hatch, at the cost of the app's own CSP. |
| `WARNING: UPSTREAM_URL resolves to a public address` | The app may be reachable without the gateway. See step 7b. |
| Admin console 404s from your own machine | Your IP is outside `ADMIN_IP_ALLOWLIST` or nginx's `allow` list. Check the `ADMIN_IP_DENIED` audit rows for the address it actually saw. |
| Admin sign-in 401s with the right password | The account is locked (`ADMIN_LOCKED` in the audit log). Wait `ADMIN_LOCKOUT_MINUTES`, or re-run `npm run create-admin`. |
| Admin sign-in returns 429 | Per-IP throttle; waits out `ADMIN_LOGIN_RATE_WINDOW_MINUTES`. |
| `no admin accounts exist` at boot | Run `npm run create-admin`. |
| Exits at boot naming a variable | That variable is missing from `.env`. |
| `502` on every page | `UPSTREAM_URL` unreachable from this host. Test with `curl` as the service user. |
| Redirect loop at login | `COOKIE_SECURE=true` while serving over plain HTTP — the browser refuses to store the cookie. |
| Login works, app pages 401 | Something is stripping cookies between nginx and node. |
| Countdown bar missing | The app sets a `Content-Security-Policy`. Set `STRIP_UPSTREAM_CSP=true`, or `INJECT_BANNER=false` to drop the bar. |
| All audit rows share one IP | `TRUST_PROXY` is not `true` while nginx is in front. |
| Everyone rate-limited at once | Same cause. |
| App's links point at the internal hostname | The app has a hardcoded base URL. Configure the app to use `https://access.example.com`, or have it honour `X-Forwarded-Host`. |

---

## A free demo on Render + Neon

For a pitch: a public URL that costs nothing and needs no card. Render's free
web service runs the gateway and the stand-in app in one container
(`scripts/start-demo-stack.js`), with the app bound to loopback so the gateway
is the only way in. Postgres is Neon's free plan.

**1. Database (Neon).** Create a project at neon.com in a region near the
service (AWS Singapore matches `render.yaml`). Copy its connection string and
keep `?sslmode=require` on the end. Neon's certificates chain to Let's
Encrypt, which Node already trusts, so there is no CA file to supply.

**2. Service (Render).** With this repo on GitHub, open the Render dashboard,
choose **New -> Blueprint**, and pick the repository and branch. `render.yaml`
defines the service; Render asks for:

- `DATABASE_URL` -- the Neon connection string.
- `BREVO_API_KEY` and `EMAIL_FROM` -- optional, for real emails; see "Email on
  the free plan" below. Left blank, grants still work and the console shows
  each password to relay by hand.

`JWT_SECRET` and `UPSTREAM_SHARED_SECRET` are generated by Render and never
appear in the repo.

If Render asks for a card, stop -- free services do not need one. Create the
service by hand instead: **New -> Web Service**, Docker, **Free** instance type,
Docker command `node scripts/start-demo-stack.js`, health check path
`/__access/health/ready`, and the same environment variables, with the two
secrets from `openssl rand -base64 48`.

**3. First admin, from your own machine.** The free plan has no shell, and
nothing here needs one: the script connects straight to Neon.

```bash
DATABASE_URL='<neon connection string>' ADMIN_EMAIL=you@yourcompany.com \
  npm run create-admin -- --generate --force
```

Its first line names the database it is writing to -- check that it ends in
`neon.tech`. If it says `localhost` and `from .env`, DATABASE_URL was not set in
that terminal, and the account went to your local database instead. It prints
the password once, and the console makes you change it at first sign-in.

**4. Open it** at `https://<service-name>.onrender.com/__access/admin`.

**Email on the free plan.** Resend delivers only to your own account address
until a domain is verified, and Render's free services block outbound SMTP, so
neither Resend nor a mailbox login gets an email to a vendor here without
paying for something. Brevo's free plan does: 300 emails a day, no card, and
one sender address confirmed by clicking an emailed link -- no domain.

1. Sign up at brevo.com and add your address as a sender; click the
   confirmation link Brevo sends to it.
2. Create an API key in the account's **SMTP & API** settings.
3. In the Render service's **Environment** tab, set `BREVO_API_KEY` to the key
   and `EMAIL_FROM` to the verified address -- optionally with a name,
   `Acme Access <you@gmail.com>`. Render redeploys with it.

Messages from a free mailbox address sent through a third party can land in
spam. For a pitch that is usually fine; for a client, verify their domain.

Still demo-shaped:

- **It sleeps.** After 15 minutes without traffic the service spins down, and
  the next request takes about a minute. Open the URL a few minutes before the
  pitch. Access stays enforced regardless -- expiry is checked against the
  database on every request; only the sweeper's status updates wait for the
  service to wake.
- **Free limits.** Render allows 750 free instance hours per workspace per
  month. Neon's free plan is 0.5 GB and suspends after 5 idle minutes, waking
  on the next connection.
- **The console is public.** Anyone with the URL reaches the admin sign-in.
  Set `ADMIN_IP_ALLOWLIST` for anything longer-lived than a demo.
- **`demo-app` stands in for the real application.** A VPN-hosted app needs
  the deployment at the top of this file.

## A demo on a public URL

For a demo somebody else has to reach -- a client, a colleague in another
office -- on a single throwaway VM. This is not the deployment above and does
not pretend to be: it exists to be shown and then destroyed.

```bash
# On the VM, with Docker installed and 80/443 open.
git clone <your-repo> temp-access && cd temp-access

cat > .env <<ENV
JWT_SECRET=$(openssl rand -base64 48 | tr -d '=+/')
PUBLIC_BASE_URL=https://demo.example.com
GATEWAY_PORT=127.0.0.1:3000
TRUST_PROXY=true
DEMO_ADMIN_EMAIL=you@yourcompany.com
ENV

docker compose up --build -d
docker compose logs bootstrap        # the admin password
```

Four things must change from the laptop defaults, and each one is a way the
demo goes wrong if it doesn't:

1. **`JWT_SECRET`.** The compose default is in the repo, so anyone reading it
   can mint a session cookie for any email. On a public URL that is not a
   theoretical problem.
2. **`GATEWAY_PORT=127.0.0.1:3000`** binds the published port to loopback, so
   the only way in is through the TLS proxy below. Without the prefix Docker
   publishes on every interface and answers plain HTTP on :3000 -- with, on
   most cloud VMs, a firewall rule the daemon added for you.
3. **`PUBLIC_BASE_URL`** must be the https:// hostname people will actually
   type. Every access link is built from it, so a wrong value emails links
   that go nowhere -- and it is also what switches the session cookie to
   `Secure`.
4. **TLS in front.** Caddy is two lines and gets a certificate on its own:

   ```
   demo.example.com {
     reverse_proxy 127.0.0.1:3000
   }
   ```

   `TRUST_PROXY=true` belongs with it, in the same change: without it every
   visitor shares one rate-limit bucket and the audit log records the proxy's
   address for all of them. Setting it *without* a proxy is the worse mistake
   -- then any client can spoof its own address in both.
   `deploy/nginx.conf` is the nginx equivalent, and section 6 covers it
   properly.

Still demo-shaped after all that: the database password is the compose default
in a container with no backups, `demo-app` stands in for the real application,
and the admin console answers anyone who reaches the URL --
`ADMIN_IP_ALLOWLIST` is the fix, and section 7 is the rest of it. Take it down
with `docker compose down -v` when the demo is over, and destroy the VM.
