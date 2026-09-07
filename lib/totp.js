// TOTP (RFC 6238) over HOTP (RFC 4226), with the base32 alphabet from RFC 4648.
//
// Written out rather than pulled from npm. It is about eighty lines of standard
// arithmetic against a HMAC that Node already ships, and the alternative is a
// dependency in the authentication path of the console that mints access to the
// internal network -- which is the single worst place in this codebase to widen
// the supply chain for the sake of eighty lines.
//
// The parameters are the ones every authenticator app assumes when the otpauth
// URI omits them: SHA-1, 6 digits, a 30-second step. They are not configurable
// on purpose. SHA-1 here is not a hash-collision question -- HMAC-SHA1 is not
// broken as a MAC -- and an app that silently assumes the defaults while the
// server uses something else produces codes that are always wrong, with no
// error message anywhere that says why.

const crypto = require('crypto');

const DIGITS = 6;
const STEP_SECONDS = 30;
const ALGORITHM = 'sha1';

// Accept a code from the step either side of now. Phone clocks drift, and a
// person reading six digits and typing them takes a few seconds; without any
// tolerance a correct code is rejected often enough that people stop trusting
// the feature. One step each way is the usual setting -- wider starts to matter
// because it lengthens the window an intercepted code stays useful.
const SKEW_STEPS = 1;

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  // Trailing bits are left-aligned into a final character. No '=' padding: the
  // otpauth URI format does not use it, and several authenticator apps reject
  // a secret that carries it.
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(input) {
  // Tolerant of what a person actually types back in: lower case, the spaces
  // that apps insert every four characters, and padding if they pasted it from
  // somewhere that adds it.
  const clean = String(input || '').toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of clean) {
    const index = B32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error('invalid base32 secret');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

// 20 bytes: the HMAC-SHA1 block feeds on it, and RFC 4226 names 160 bits as the
// minimum for the shared secret.
function generateSecret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

function hotp(secretBuffer, counter) {
  const buf = Buffer.alloc(8);
  // The counter is 64-bit and JavaScript numbers are not, so it is written as
  // two 32-bit halves. At a 30-second step the high half stays zero until the
  // year 6.8 billion, but writing only the low half would be a real bug in any
  // reuse of this function with a larger counter.
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);

  const digest = crypto.createHmac(ALGORITHM, secretBuffer).update(buf).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff);

  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

function stepFor(atMs = Date.now()) {
  return Math.floor(atMs / 1000 / STEP_SECONDS);
}

// Returns the step the code was valid for, or null. The step -- not a boolean
// -- because the caller has to persist it: a code that stays valid for its
// whole window, plus a step either side, is replayable for ninety seconds
// unless the server refuses to accept the same step twice. See
// admins.totp_last_step.
function verify(secret, code, { atMs = Date.now(), afterStep = null } = {}) {
  if (typeof code !== 'string' && typeof code !== 'number') return null;
  const digits = String(code).replace(/\s/g, '');
  if (!new RegExp(`^\\d{${DIGITS}}$`).test(digits)) return null;

  let secretBuffer;
  try {
    secretBuffer = base32Decode(secret);
  } catch {
    return null;
  }
  if (!secretBuffer.length) return null;

  const current = stepFor(atMs);
  for (let offset = -SKEW_STEPS; offset <= SKEW_STEPS; offset++) {
    const step = current + offset;
    // Refuse a step already spent. Checked before the compare so a replayed
    // code costs nothing and, more importantly, cannot succeed by racing.
    if (afterStep !== null && step <= Number(afterStep)) continue;

    const expected = hotp(secretBuffer, step);
    // Both operands are fixed-length digit strings, so timingSafeEqual will not
    // throw on a length mismatch. It is here because a TOTP code is small
    // enough that a byte-at-a-time comparison is a real oracle: six digits is a
    // million possibilities, and learning them one position at a time turns
    // that into sixty guesses.
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(digits))) return step;
  }
  return null;
}

// The string that goes into an authenticator app. `issuer` appears twice by
// convention -- as the label prefix and as a parameter -- because apps differ
// in which one they read, and an account that shows up as a bare email address
// is unidentifiable on a phone holding a dozen of them.
function otpauthUri({ secret, account, issuer }) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: ALGORITHM.toUpperCase(),
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// Recovery codes. Crockford-ish alphabet minus the glyph pairs people confuse,
// for the same reason the customer passwords avoid them: these get printed,
// photographed, and retyped a year later by someone who has lost their phone
// and is not in a patient mood.
const BACKUP_ALPHABET = 'ABCDEFGHJKMNPQRSTVWXYZ23456789';
const BACKUP_CODE_COUNT = 10;
const BACKUP_GROUP = 5;

function generateBackupCode() {
  const raw = Array.from(crypto.randomBytes(BACKUP_GROUP * 2))
    .map((b) => BACKUP_ALPHABET[b % BACKUP_ALPHABET.length])
    .join('');
  return `${raw.slice(0, BACKUP_GROUP)}-${raw.slice(BACKUP_GROUP)}`;
}

// Normalised before hashing and before comparing, so the dashes and the case
// are presentation only and a code typed as `abcde fghij` still works.
function normaliseBackupCode(code) {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

// ------------------------------------------------------------------
// Hashing the recovery codes
// ------------------------------------------------------------------
// scrypt rather than the bcrypt used for passwords everywhere else, and the
// reason is the event loop rather than cryptography.
//
// There are ten codes. Enrolment hashes all ten, and a sign-in that presents
// one compares against every unused code -- deliberately, so the time taken
// does not reveal which one matched. bcryptjs is pure JavaScript and runs on
// the main thread: at cost 12 that is several seconds of a *blocked* event
// loop, on the single process that every customer's traffic is proxied
// through. A colleague turning on two-factor should not stall the gateway.
//
// node's scrypt runs on the libuv threadpool, so the ten run concurrently and
// none of them block. It is also memory-hard, which is strictly better than
// bcrypt against the offline attack this is defending. And the thing being
// hashed is a 49-bit machine-generated random string that exists nowhere else
// -- not a human-chosen password that has to survive being reused on twelve
// other sites, which is the case bcrypt's cost factor is tuned for.
//
// Passwords stay on bcrypt: one hash per sign-in is a cost this codebase
// already accepted, and rehashing every stored credential is not a change to
// make in passing.
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };

function scryptHash(value) {
  const salt = crypto.randomBytes(16);
  return new Promise((resolve, reject) => {
    crypto.scrypt(value, salt, SCRYPT.keylen, SCRYPT, (err, derived) => {
      if (err) return reject(err);
      // The parameters are stored with the hash, so raising them later is a
      // change to new codes only and every existing one still verifies.
      resolve(`scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${derived.toString('base64')}`);
    });
  });
}

function scryptVerify(value, stored) {
  return new Promise((resolve) => {
    const parts = String(stored || '').split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return resolve(false);

    const [, n, r, p, salt, expected] = parts;
    const expectedBuf = Buffer.from(expected, 'base64');
    const params = { N: Number(n), r: Number(r), p: Number(p) };
    // A stored row with absurd parameters would otherwise let a database write
    // dictate how much memory this process allocates.
    if (!(params.N > 0 && params.N <= 1 << 20 && params.r > 0 && params.r <= 32 && params.p > 0 && params.p <= 16)) {
      return resolve(false);
    }

    crypto.scrypt(value, Buffer.from(salt, 'base64'), expectedBuf.length, {
      ...params,
      // scrypt's memory ceiling is derived from N and r; the default is sized
      // for the defaults, so it has to be raised in step or a valid stored
      // parameter set fails to verify.
      maxmem: 256 * params.N * params.r,
    }, (err, derived) => {
      if (err) return resolve(false);
      resolve(crypto.timingSafeEqual(derived, expectedBuf));
    });
  });
}

const hashBackupCode = (code) => scryptHash(normaliseBackupCode(code));
const verifyBackupCode = (code, stored) => scryptVerify(normaliseBackupCode(code), stored);

module.exports = {
  DIGITS,
  STEP_SECONDS,
  SKEW_STEPS,
  BACKUP_CODE_COUNT,
  base32Encode,
  base32Decode,
  generateSecret,
  hotp,
  stepFor,
  verify,
  otpauthUri,
  generateBackupCode,
  normaliseBackupCode,
  hashBackupCode,
  verifyBackupCode,
};
