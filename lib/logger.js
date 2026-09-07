// Structured logging.
//
// The gateway used to log with bare console.log, which is fine for one person
// watching a terminal and useless everywhere else: a line like
//
//   sweeper: expired 3 access window(s)
//
// cannot be filtered by severity, grouped by request, or shipped anywhere that
// expects fields. On a host where this is the only route into the internal
// network, "which request produced this error" is the first question asked
// during an incident, and free text cannot answer it.
//
// So: one JSON object per line in production, and a readable line in
// development, from the same call. Nothing here buffers or batches -- stdout is
// the transport, and whatever collects it (journald, Docker, a sidecar) is the
// shipper. That keeps the process with no log-delivery failure mode of its own.

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

const LEVEL_NAME = (process.env.LOG_LEVEL || 'info').toLowerCase();
const THRESHOLD = LEVELS[LEVEL_NAME] ?? LEVELS.info;

// Default by destination rather than by NODE_ENV: a TTY means a human is
// reading, and anything else is a collector. This is right in the cases
// NODE_ENV gets wrong -- `npm start` on a server with NODE_ENV unset, and a
// container run interactively to debug it.
const FORMAT = (process.env.LOG_FORMAT || (process.stdout.isTTY ? 'pretty' : 'json')).toLowerCase();

// Keys whose values never belong in a log line, at any level, matched
// case-insensitively anywhere in the key. Passwords and tokens reach this
// module by accident -- someone logs a whole request body while debugging, and
// it survives review because the line looks harmless in the diff.
//
// The redaction is here rather than at the call sites for exactly that reason:
// a rule that depends on every future caller remembering it is not a rule.
//
// The one-time-code patterns are narrow on purpose. A bare `otp` matched
// `requireTotp`, so the boot banner reported the two-factor policy as
// `[redacted]` -- an operator checking whether two-factor was enforced was
// told nothing, by a security control, about a security control. Over-broad
// redaction is not free: it hides the fields you are reading the log for, and
// people learn to stop trusting the log. A bare `code` is out for the same
// reason -- it is far more often an error code than a credential.
const SECRET_KEY = new RegExp([
  'pass(word|phrase)?',
  'secret',
  'token',
  'authorization',
  'cookie',
  'credential',
  'api[-_]?key',
  'code[-_]?hash',
  'backup[-_]?code',
  't?otp[-_]?code',
].join('|'), 'i');
const REDACTED = '[redacted]';

// Depth-limited: a log line is not a debugger, and an object deep enough to
// need more than this is one that should have been summarised at the call site.
const MAX_DEPTH = 6;

function redact(value, depth = 0) {
  if (value == null || typeof value !== 'object') return value;
  if (depth >= MAX_DEPTH) return '[truncated]';
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));

  // An Error's message and stack are the two fields worth having and neither is
  // enumerable, so a plain spread of an Error logs `{}`.
  if (value instanceof Error) {
    return { name: value.name, message: value.message, stack: value.stack };
  }

  const out = {};
  for (const [key, v] of Object.entries(value)) {
    out[key] = SECRET_KEY.test(key) ? REDACTED : redact(v, depth + 1);
  }
  return out;
}

const COLOURS = { debug: '\x1b[90m', info: '\x1b[36m', warn: '\x1b[33m', error: '\x1b[31m' };
const RESET = '\x1b[0m';

function formatPretty(level, msg, fields) {
  const time = new Date().toISOString().slice(11, 23);
  const colour = process.stdout.isTTY ? COLOURS[level] : '';
  const reset = process.stdout.isTTY ? RESET : '';
  const rest = Object.entries(fields)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
    .join(' ');
  return `${time} ${colour}${level.toUpperCase().padEnd(5)}${reset} ${msg}${rest ? ` ${rest}` : ''}`;
}

function emit(level, msg, fields) {
  if (LEVELS[level] < THRESHOLD) return;

  const safe = redact(fields || {});
  // Warnings and errors go to stderr so that a process whose stdout is being
  // consumed as data -- piped into a collector, or read by a test -- still
  // surfaces its problems somewhere a human looks.
  const stream = LEVELS[level] >= LEVELS.warn ? console.error : console.log;

  if (FORMAT === 'pretty') return stream(formatPretty(level, msg, safe));

  // Field order is deliberate: level and time first, so a truncated line is
  // still triageable, and the message before the payload so grep on a log file
  // behaves the way people expect.
  stream(JSON.stringify({ level, time: new Date().toISOString(), msg, ...safe }));
}

// A logger carrying fields that are added to everything it emits. This is what
// makes a request id useful: the handler logs `log.error('proxy failed', ...)`
// with no knowledge of request ids, and the line still carries one.
function makeLogger(bound = {}) {
  const logger = {
    child: (fields) => makeLogger({ ...bound, ...fields }),
  };
  for (const level of Object.keys(LEVELS)) {
    logger[level] = (msg, fields) => emit(level, msg, { ...bound, ...fields });
  }
  return logger;
}

const log = makeLogger();

module.exports = { log, makeLogger, redact, LEVELS, FORMAT, LEVEL_NAME };
