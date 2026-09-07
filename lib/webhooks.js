// Outbound webhooks for lifecycle events, so a company's SIEM, SOC channel or
// ticketing system learns about access being granted without anyone reading the
// console.
//
// Two decisions shape this file.
//
// The first is the outbox. `enqueue` writes a row and returns; nothing here
// makes an HTTP request on the path of a user's request. A consumer that is
// slow, down, or behind a captive proxy therefore cannot slow down issuing a
// grant, and a delivery interrupted by a deploy is still in the table
// afterwards. For a feed whose whole purpose is to record security events, a
// fire-and-forget POST that quietly evaporates is worse than no feed at all,
// because someone will have stopped watching the console on the strength of it.
//
// The second is that the payload is signed and timestamped. A receiver that
// trusts an unauthenticated POST on a public URL is trusting anyone who learns
// the URL, and "access was granted to X" is a message worth forging.

const crypto = require('crypto');
const { log } = require('./logger');
const metrics = require('./metrics');

const MAX_ATTEMPTS = Number(process.env.WEBHOOK_MAX_ATTEMPTS || 8);
const TIMEOUT_MS = Number(process.env.WEBHOOK_TIMEOUT_MS || 5000);
const BATCH = Number(process.env.WEBHOOK_BATCH || 20);

// Which events to send. Empty means all of them; the audit log has events that
// are noisy for a chat channel (every LOGIN_SUCCESS) and essential for a SIEM,
// and that is the receiver's call, not this file's.
const SUBSCRIBED = (process.env.WEBHOOK_EVENTS || '')
  .split(',')
  .map((s) => s.trim().toUpperCase())
  .filter(Boolean);

function config() {
  return {
    url: process.env.WEBHOOK_URL || '',
    secret: process.env.WEBHOOK_SECRET || '',
  };
}

function enabled() {
  return Boolean(config().url);
}

function subscribes(event) {
  return !SUBSCRIBED.length || SUBSCRIBED.includes(String(event).toUpperCase());
}

// Exponential with a ceiling, plus jitter. The ceiling matters because a
// consumer that has been down for a day should still be retried within the
// hour once it returns, and the jitter matters because without it every row
// enqueued during an outage retries in the same instant and re-creates the
// thundering herd that took the consumer down.
function backoffSeconds(attempts) {
  const base = Math.min(2 ** attempts, 900);
  return Math.round(base * (0.75 + Math.random() * 0.5));
}

// Called inside the same request that produced the event. Deliberately never
// throws: a webhook that cannot be queued must not fail the grant creation that
// triggered it -- the access decision is the product, the notification is not.
async function enqueue(pool, event, payload) {
  if (!enabled() || !subscribes(event)) return;
  try {
    await pool.query(
      'INSERT INTO webhook_outbox (event, payload) VALUES ($1, $2)',
      [event, JSON.stringify(payload ?? {})]
    );
  } catch (err) {
    log.error('webhook enqueue failed', { event, err: err.message });
  }
}

// Signature scheme: HMAC-SHA256 over `${timestamp}.${body}`, hex, in
// X-Gateway-Signature, with the timestamp beside it in X-Gateway-Timestamp.
//
// The timestamp is inside the signed string rather than only in a header, which
// is what lets a receiver reject a replay: a body captured today is
// indistinguishable from a fresh one unless the age is part of what was signed.
// Receivers should check the age (five minutes is the usual bound) and compare
// the digest with a constant-time function.
function sign(secret, timestamp, body) {
  return crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
}

async function post(url, secret, row) {
  const body = JSON.stringify({
    id: String(row.id),
    event: row.event,
    // The moment the event happened, not the moment it was delivered. A
    // consumer ordering by receipt time gets the wrong story after an outage
    // drains a backlog out of order.
    occurredAt: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
    attempt: row.attempts + 1,
    data: row.payload,
  });

  const timestamp = Math.floor(Date.now() / 1000);
  const headers = {
    'content-type': 'application/json',
    'user-agent': 'temp-access-gateway',
    'x-gateway-event': row.event,
    'x-gateway-delivery': String(row.id),
    'x-gateway-timestamp': String(timestamp),
  };
  if (secret) headers['x-gateway-signature'] = `sha256=${sign(secret, timestamp, body)}`;

  // An unbounded fetch against a consumer that accepts the connection and never
  // answers holds a worker until the process dies.
  const abort = AbortSignal.timeout(TIMEOUT_MS);
  const res = await fetch(url, { method: 'POST', headers, body, signal: abort });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status} ${text.slice(0, 200)}`);
  }
}

// Drains due rows. Run from the same interval as the expiry sweeper rather than
// on a timer of its own -- one background clock is easier to reason about, and
// the sweeper's cadence (a minute by default) is the right order of magnitude
// for a notification feed.
//
// Rows are claimed with FOR UPDATE SKIP LOCKED so that two gateway processes
// against one database do not both deliver the same event. Without it, running
// two instances for availability silently doubles every notification.
async function drain(pool) {
  if (!enabled()) return { delivered: 0, failed: 0 };

  const { url, secret } = config();
  let delivered = 0;
  let failed = 0;

  const client = await pool.connect();
  let rows;
  try {
    await client.query('BEGIN');
    ({ rows } = await client.query(
      `SELECT * FROM webhook_outbox
        WHERE status = 'PENDING' AND next_attempt_at <= now()
        ORDER BY id
        LIMIT $1
        FOR UPDATE SKIP LOCKED`,
      [BATCH]
    ));
    // Claimed by pushing the next attempt out before the lock is released, so a
    // process that dies mid-delivery leaves rows that another process retries
    // after the backoff rather than rows nobody will ever look at again.
    if (rows.length) {
      await client.query(
        `UPDATE webhook_outbox
            SET next_attempt_at = now() + ($2 || ' seconds')::interval
          WHERE id = ANY($1::bigint[])`,
        [rows.map((r) => r.id), String(Math.max(TIMEOUT_MS / 1000 * 2, 30))]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    log.error('webhook drain could not claim rows', { err: err.message });
    client.release();
    return { delivered, failed };
  } finally {
    client.release();
  }

  for (const row of rows) {
    try {
      await post(url, secret, row);
      await pool.query(
        `UPDATE webhook_outbox
            SET status = 'DELIVERED', delivered_at = now(), attempts = attempts + 1,
                last_error = NULL
          WHERE id = $1`,
        [row.id]
      );
      metrics.counter('gateway_webhook_deliveries_total', { outcome: 'delivered' });
      delivered++;
      log.debug('webhook delivered', { event: row.event, deliveryId: String(row.id) });
    } catch (err) {
      const attempts = row.attempts + 1;
      const giveUp = attempts >= MAX_ATTEMPTS;
      await pool.query(
        `UPDATE webhook_outbox
            SET attempts = $2,
                status = CASE WHEN $3 THEN 'FAILED' ELSE 'PENDING' END,
                next_attempt_at = now() + ($4 || ' seconds')::interval,
                last_error = $5
          WHERE id = $1`,
        [row.id, attempts, giveUp, String(backoffSeconds(attempts)), String(err.message).slice(0, 500)]
      );
      metrics.counter('gateway_webhook_deliveries_total', {
        outcome: giveUp ? 'abandoned' : 'retrying',
      });
      failed++;
      // Warn on the last attempt, debug on the ones that will be retried. A
      // transient 502 from a consumer is not worth waking anyone; a security
      // event that will now never be delivered is.
      const line = giveUp ? log.warn : log.debug;
      line('webhook delivery failed', {
        event: row.event,
        deliveryId: String(row.id),
        attempts,
        giveUp,
        err: err.message,
      });
    }
  }

  return { delivered, failed };
}

module.exports = { enqueue, drain, sign, enabled, subscribes, backoffSeconds, MAX_ATTEMPTS };
