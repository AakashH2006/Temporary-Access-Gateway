// Prometheus metrics, in the text exposition format, with no client library.
//
// The reasoning is the same as lib/totp.js: this is a counter map and a string
// builder, and prom-client would pull a dependency tree into a process that is
// the only route into the internal network. What it costs is the automatic
// process/GC collectors, which are replaced below by the handful of
// process.memoryUsage() fields anyone actually alerts on.
//
// What matters more than the format is the label discipline. Every label value
// here comes from a fixed set -- a route pattern, an HTTP status, an event name
// -- and never from user input. A label whose values are unbounded (a raw path,
// an email address, a grant id) multiplies into a series per distinct value and
// takes the scrape target down with it, which is the standard way a metrics
// endpoint becomes the outage.

const registry = new Map();

function key(name, labels) {
  const entries = Object.entries(labels || {}).sort(([a], [b]) => (a < b ? -1 : 1));
  if (!entries.length) return name;
  return `${name}{${entries.map(([k, v]) => `${k}="${escapeLabel(v)}"`).join(',')}}`;
}

// The exposition format has exactly three escapes in a label value.
function escapeLabel(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}

const help = new Map();
const types = new Map();

function declare(name, type, description) {
  help.set(name, description);
  types.set(name, type);
}

function counter(name, labels, by = 1) {
  const k = key(name, labels);
  registry.set(k, (registry.get(k) || 0) + by);
}

function gauge(name, labels, value) {
  registry.set(key(name, labels), value);
}

// Fixed buckets in seconds, cumulative as the format requires. Chosen for the
// two things this proxy does: answer its own pages in single-digit
// milliseconds, and forward to an app on the far side of a VPN. A default
// bucket set tuned for microservice RPC puts almost every observation in +Inf
// and tells you nothing about either.
const BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

function observe(name, labels, seconds) {
  // Every bucket is touched, including the ones this observation does not fall
  // into. A histogram has to expose its whole ladder: emitting only the buckets
  // that have been hit leaves holes at the bottom, and histogram_quantile
  // interpolates across a missing bucket as though nothing had ever been faster
  // than the lowest one present -- so the p50 of a fast endpoint reads as its
  // slowest bucket.
  for (const bucket of BUCKETS) {
    counter(`${name}_bucket`, { ...labels, le: String(bucket) }, seconds <= bucket ? 1 : 0);
  }
  counter(`${name}_bucket`, { ...labels, le: '+Inf' });
  counter(`${name}_sum`, labels, seconds);
  counter(`${name}_count`, labels);
}

// ------------------------------------------------------------------
// The metrics this gateway exports
// ------------------------------------------------------------------
declare('gateway_http_requests_total', 'counter',
  'HTTP requests handled, by route pattern, method and status class.');
declare('gateway_http_request_duration_seconds', 'histogram',
  'Wall time from request received to response finished.');
declare('gateway_grants_total', 'counter',
  'Access grants by lifecycle transition (created, activated, revoked, expired).');
declare('gateway_logins_total', 'counter',
  'Login attempts by principal (customer, admin) and outcome.');
declare('gateway_grants_live', 'gauge',
  'Grants currently in each live status, refreshed by the sweeper.');
declare('gateway_email_total', 'counter',
  'Access emails by outcome.');
declare('gateway_webhook_deliveries_total', 'counter',
  'Webhook delivery attempts by outcome.');
declare('gateway_webhook_outbox_pending', 'gauge',
  'Undelivered webhook events, refreshed by the sweeper. A number that only '
  + 'goes up means the consumer is down.');
declare('gateway_upstream_errors_total', 'counter',
  'Proxy failures reaching the upstream application.');
declare('gateway_process_resident_memory_bytes', 'gauge',
  'Resident set size of the gateway process.');
declare('gateway_process_heap_used_bytes', 'gauge',
  'V8 heap in use.');
declare('gateway_process_uptime_seconds', 'gauge',
  'Seconds since the gateway process started.');
declare('gateway_build_info', 'gauge',
  'Always 1. Carries the version and Node runtime as labels, so a dashboard '
  + 'can show what is actually deployed.');

// A route *pattern*, never a path. `/__access/link/:token` is one series;
// `/__access/link/847362910` would be one series per link ever issued, and the
// token would be in the metrics endpoint besides.
//
// Everything proxied collapses to a single `upstream` label for the same
// reason: the app behind the gateway owns an unbounded URL space, and this
// process has no idea which parts of it are patterns.
function routePattern(req) {
  const path = (req.route && req.baseUrl !== undefined)
    ? `${req.baseUrl}${req.route.path}`
    : null;
  if (path) return path === '/' ? (req.baseUrl || '/') : path;
  return req.originalUrl && req.originalUrl.startsWith('/__access') ? 'gate_other' : 'upstream';
}

function statusClass(status) {
  return `${Math.floor(status / 100)}xx`;
}

// Bucket boundaries are numbers living in a string label, so a plain sort puts
// le="0.1" after le="0.05" but before le="0.025", and le="+Inf" first of all.
// Prometheus parses any order; a person reading `curl /metrics` mid-incident
// does not.
const LE = /[{,]le="([^"]+)"/;

function byLe([a], [b]) {
  const av = a.match(LE);
  const bv = b.match(LE);
  if (av && bv && a.replace(LE, '') === b.replace(LE, '')) {
    const an = av[1] === '+Inf' ? Infinity : Number(av[1]);
    const bn = bv[1] === '+Inf' ? Infinity : Number(bv[1]);
    // Same ladder, different bucket: order by the boundary. Different label
    // sets fall through to the string compare so two ladders do not interleave.
    if (an !== bn) return an - bn;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

function render() {
  gauge('gateway_process_resident_memory_bytes', null, process.memoryUsage().rss);
  gauge('gateway_process_heap_used_bytes', null, process.memoryUsage().heapUsed);
  gauge('gateway_process_uptime_seconds', null, Math.round(process.uptime()));

  // Grouped by metric name so each HELP/TYPE pair is emitted once and all of
  // its series follow it. Prometheus tolerates interleaving, but a human
  // reading `curl /metrics` during an incident should not have to.
  const families = new Map();
  for (const [series, value] of registry) {
    const name = series.split('{')[0].replace(/_(bucket|sum|count)$/, '');
    if (!families.has(name)) families.set(name, []);
    families.get(name).push([series, value]);
  }

  const lines = [];
  for (const [name, series] of [...families].sort()) {
    if (help.has(name)) lines.push(`# HELP ${name} ${help.get(name)}`);
    if (types.has(name)) lines.push(`# TYPE ${name} ${types.get(name)}`);
    for (const [s, v] of series.sort(byLe)) lines.push(`${s} ${v}`);
  }
  return `${lines.join('\n')}\n`;
}

// Only the tests need this; a running process never resets its counters, and a
// counter that can go down is a counter Prometheus will misread as a restart.
function reset() {
  registry.clear();
}

module.exports = {
  counter,
  gauge,
  observe,
  render,
  reset,
  routePattern,
  statusClass,
  declare,
  BUCKETS,
};
