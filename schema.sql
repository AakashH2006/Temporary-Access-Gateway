CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS access_grants (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email          TEXT NOT NULL,
  token_hash     TEXT NOT NULL UNIQUE,
  password_hash  TEXT NOT NULL,
  duration_seconds INTEGER NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  activated_at   TIMESTAMPTZ,
  expires_at     TIMESTAMPTZ,
  status         TEXT NOT NULL DEFAULT 'PENDING'
                 CHECK (status IN ('PENDING','ACTIVE','EXPIRED','REVOKED')),
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  -- Set once failed_login_attempts crosses GRANT_MAX_FAILED_ATTEMPTS. Held in
  -- the database rather than in memory so a lockout survives a restart, and
  -- so it is not per-process the way the rate limiter is.
  locked_until          TIMESTAMPTZ,
  -- Fingerprint captured at first activation. Used to flag (not block)
  -- later opens of the same link from a different device/network, which
  -- can indicate the link was forwarded or intercepted.
  activated_ip         TEXT,
  activated_user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_access_grants_email ON access_grants(email);
CREATE INDEX IF NOT EXISTS idx_access_grants_status ON access_grants(status);

-- Safe to re-run: adds the fingerprint columns to an already-existing
-- access_grants table (CREATE TABLE IF NOT EXISTS above won't touch an
-- existing table's columns).
ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS activated_ip TEXT;
ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS activated_user_agent TEXT;
ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

-- Append-only audit trail. Never updated or deleted by the app;
-- independent of access_grants.status so history survives even if a
-- grant row is later purged.
CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGSERIAL PRIMARY KEY,
  grant_id    UUID REFERENCES access_grants(id) ON DELETE SET NULL,
  event       TEXT NOT NULL,       -- e.g. GRANT_CREATED, GRANT_ACTIVATED, LOGIN_SUCCESS,
                                    -- LOGIN_FAILED, GRANT_REVOKED, GRANT_EXPIRED, LOGOUT
  actor       TEXT,                -- 'admin', an email, or 'system'
  ip_address  TEXT,
  user_agent  TEXT,
  detail      JSONB,               -- freeform context (e.g. {"reason":"admin_revoke"})
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_grant_id ON audit_log(grant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_event ON audit_log(event);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- ------------------------------------------------------------------
-- Grant migrations that write to audit_log, so they live below it.
-- ------------------------------------------------------------------
-- Emails are stored lower-cased and trimmed, and the application normalises on
-- both write and read. Existing rows are normalised in place rather than being
-- matched with lower(email) at query time, because idx_access_grants_email is
-- on the raw column and a function in the predicate would not use it.
--
-- (CITEXT would fix this at the schema level instead. It is not used here only
-- because it needs an extension on the host, and one lower() at each of the
-- two call sites is a smaller thing to carry.)
UPDATE access_grants
   SET email = lower(btrim(email))
 WHERE email <> lower(btrim(email));

-- The invariant: at most one LIVE grant per email, where live means PENDING or
-- ACTIVE.
--
-- Two concurrent live grants for one email used to be accepted and then only
-- half work: login reads the newest row, so the older grant's password -- valid,
-- freshly emailed -- failed against the newer grant's hash, and the failure was
-- counted against the wrong grant. The application now refuses the second grant
-- with a 409; this index is what makes that true under a race, and what stops
-- the state ever existing again.
--
-- It must run AFTER the lower-casing above, or rows differing only by case will
-- not collide and the index will happily admit the duplicates it exists to
-- prevent.
--
-- Creating it fails outright if live duplicates are already present, so they
-- are resolved first: all but the newest per email are revoked, which is what
-- the application would have done had it been able to. Every one of them is
-- written to the audit log rather than disappearing quietly -- someone's access
-- is being ended here.
WITH ranked AS (
  SELECT id,
         row_number() OVER (PARTITION BY email ORDER BY created_at DESC, id DESC) AS rn
    FROM access_grants
   WHERE status IN ('PENDING','ACTIVE')
), superseded AS (
  UPDATE access_grants g
     SET status = 'REVOKED'
    FROM ranked r
   WHERE g.id = r.id AND r.rn > 1
  RETURNING g.id, g.email
)
INSERT INTO audit_log (grant_id, event, actor, detail)
SELECT id, 'GRANT_SUPERSEDED', 'system',
       jsonb_build_object('reason', 'migration_one_open_grant_per_email', 'email', email)
  FROM superseded;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_live_grant_per_email
    ON access_grants (email)
 WHERE status IN ('PENDING','ACTIVE');
-- Admin accounts. Whoever holds one of these can mint access to the internal
-- network for anyone, so this table gets the same protections the customer
-- grants get: bcrypt hashing, failed-attempt counting, and a disable switch
-- that takes effect immediately rather than at token expiry.
--
-- There is deliberately no self-service signup and no password-reset email:
-- accounts are created on the host with `npm run create-admin`, so recovery
-- requires SSH access, which is itself a control.
CREATE TABLE IF NOT EXISTS admins (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email                 TEXT NOT NULL UNIQUE,
  password_hash         TEXT NOT NULL,
  -- TOTP two-factor. `totp_secret` holds an unconfirmed secret between the
  -- two steps of enrolment; only `totp_enabled` decides whether sign-in asks
  -- for a code, so a secret nobody proved they could read is inert. See the
  -- two-factor section further down for the rest of the columns.
  totp_secret           TEXT,
  totp_enabled          BOOLEAN NOT NULL DEFAULT false,
  -- Persisted rather than held in memory so a lockout survives a restart;
  -- an in-memory counter would reset on every deploy.
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until          TIMESTAMPTZ,
  disabled_at           TIMESTAMPTZ,
  last_login_at         TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admins_email ON admins(email);

-- Safe to re-run against an admins table created by an earlier version.
ALTER TABLE admins ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;

-- An earlier version added a CHECK constraint here pinning totp_enabled to
-- false, because the login branch behind it returned 501 and flipping the
-- column would have locked that admin out permanently.
--
-- The constraint is gone, not merely dropped further down. Adding it here and
-- dropping it later reads as harmless -- the file ends in the right state --
-- but it makes this schema re-runnable exactly once: on the second run the ADD
-- executes against a database where an admin has already enrolled, and fails
-- outright. Nothing after it applies, so `npm run migrate` stops working the
-- day someone turns on two-factor, and the next deploy is the one that finds
-- out. The drop for existing databases lives in the two-factor section below.

-- ==================================================================
-- Roles
-- ==================================================================
-- Before this column every admin could do everything: issue access, revoke it,
-- read the audit log, and (once the routes below existed) create more admins.
-- That is defensible for one operator and indefensible for a team, where the
-- person who needs to read the log at audit time is usually not the person who
-- should be able to mint access to the internal network.
--
--   owner    everything, including managing admin accounts
--   admin    issue, extend, resend and revoke grants; read the log
--   auditor  read-only: grants and the audit log, nothing that changes state
--
-- Existing rows become owners. They already had every capability, and a
-- migration that silently takes one away is how a deploy locks a team out of
-- its own console.
ALTER TABLE admins ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'owner';

DO $$ BEGIN
  ALTER TABLE admins ADD CONSTRAINT admins_role_valid
    CHECK (role IN ('owner','admin','auditor'));
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

-- The DEFAULT above is 'owner' only so the ALTER can backfill existing rows in
-- one statement. Every INSERT in the application names a role explicitly, so
-- the default never decides what a new account can do.

-- ==================================================================
-- Admin credential lifecycle
-- ==================================================================
-- An admin created by `npm run create-admin` gets a password that was typed on
-- a terminal and read out over some other channel. Forcing a change at first
-- sign-in is what stops that value staying valid for the life of the account.
ALTER TABLE admins ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;

-- ==================================================================
-- Two-factor (TOTP)
-- ==================================================================
-- The columns and the login branch were staged by an earlier version, guarded
-- by a CHECK constraint pinning totp_enabled to false: the branch returned 501,
-- so anything flipping the column to true locked that admin out permanently.
--
-- TOTP is implemented now, so the guard comes off. Dropping it here rather than
-- carving out an exception is the point -- the constraint existed to describe
-- what the code could not do, and the code can do it.
ALTER TABLE admins DROP CONSTRAINT IF EXISTS admins_totp_not_implemented;

-- Enrolment is two steps: a secret is issued, and it only counts once the admin
-- has proved they can read a code off it. An unconfirmed secret sits in
-- totp_secret with totp_enabled still false, and nothing in the login path
-- looks at it.
ALTER TABLE admins ADD COLUMN IF NOT EXISTS totp_confirmed_at TIMESTAMPTZ;

-- The last time-step a code was accepted for. A TOTP code stays valid for its
-- whole 30-second step, and for a step either side once clock skew is allowed,
-- so without this a code read over a shoulder or captured by a proxy can be
-- replayed for up to a minute and a half. Recording the step and refusing
-- anything at or below it makes every code single-use.
ALTER TABLE admins ADD COLUMN IF NOT EXISTS totp_last_step BIGINT;

-- Single-use recovery codes, hashed like any other credential: whoever holds
-- one can sign in as that admin, so the database must not be able to hand them
-- back. bcrypt rather than SHA-256, for the same reason passwords use it --
-- these are short enough to be worth grinding offline.
CREATE TABLE IF NOT EXISTS admin_backup_codes (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id   UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,
  used_at    TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Partial, because the only query that runs is "the unused ones for this
-- admin", on every sign-in that presents a recovery code.
CREATE INDEX IF NOT EXISTS idx_admin_backup_codes_admin
    ON admin_backup_codes(admin_id) WHERE used_at IS NULL;

-- ==================================================================
-- Grant provenance and lifecycle
-- ==================================================================
-- Why the access was granted. Auditing this later means tying a window of
-- access to the ticket, incident or contract that justified it, and
-- reconstructing that from a timestamp and an email address is guesswork.
-- Optional at the schema level, required by the application when
-- REQUIRE_GRANT_REASON is set.
ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS reason TEXT;

-- Who issued it. This is in the audit log too, but the log is prunable and the
-- grant row is what the console lists -- "who let this person in" should be
-- answerable without a join to a table that may have been rotated out.
--
-- ON DELETE SET NULL on the id, with the email kept beside it: an admin who
-- leaves gets their row removed, and the grants they issued must not lose the
-- name of the person who was accountable for them.
ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES admins(id) ON DELETE SET NULL;
ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS created_by_email TEXT;

-- Time added after the fact, kept separate from duration_seconds. Folding an
-- extension into the original duration would make a grant extended three times
-- indistinguishable from one issued for the total -- which is exactly the
-- distinction an auditor is looking for.
ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS extended_seconds INTEGER NOT NULL DEFAULT 0;

-- How many times the credentials have been re-sent. A grant on its fourth
-- resend is a support problem, and possibly someone working an admin over the
-- phone; either way it belongs in the list rather than only in the log.
ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS resend_count INTEGER NOT NULL DEFAULT 0;

-- ==================================================================
-- Audit log correlation
-- ==================================================================
-- Ties an audit row to the HTTP request that produced it, and so to every log
-- line the process emitted while handling it. Without it, matching "the console
-- showed an error at 14:02" to a stack trace means scanning by timestamp.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS request_id TEXT;

-- ==================================================================
-- Webhook outbox
-- ==================================================================
-- Lifecycle events reach a SIEM or a chat channel by being written here inside
-- the transaction that caused them, and sent from this table afterwards.
--
-- The outbox is the whole point. Firing the HTTP request in line would make
-- every grant creation as slow and as failure-prone as the slowest consumer,
-- and a delivery that fails during a deploy would simply be lost -- which for a
-- security event feed is the one outcome that must not happen quietly. Rows
-- here are durable, retried with backoff, and still visible once they give up.
CREATE TABLE IF NOT EXISTS webhook_outbox (
  id              BIGSERIAL PRIMARY KEY,
  event           TEXT NOT NULL,
  payload         JSONB NOT NULL,
  status          TEXT NOT NULL DEFAULT 'PENDING'
                  CHECK (status IN ('PENDING','DELIVERED','FAILED')),
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_error      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at    TIMESTAMPTZ
);

-- Partial: the only query is "due PENDING rows", and delivered history is the
-- larger part of this table on any system that is working.
CREATE INDEX IF NOT EXISTS idx_webhook_outbox_due
    ON webhook_outbox (next_attempt_at) WHERE status = 'PENDING';
