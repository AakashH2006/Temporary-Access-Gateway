#!/usr/bin/env node
//
// Creates or updates an admin account.
//
//   npm run create-admin                      (prompts)
//   npm run create-admin -- you@example.com   (prompts for the password only)
//   npm run create-admin -- you@example.com --role=auditor
//
// Roles are owner, admin and auditor; see the Roles section of schema.sql. The
// default is owner, because the overwhelmingly common use of this script is
// creating the first account on a new deployment, and an owner is the only
// role that can then add anybody else. Once a team exists, adding people from
// the console is the better path -- it is audited, it does not need SSH, and
// it forces a password change at first sign-in.
//
// Unattended, for a container bootstrap or CI, where there is no terminal to
// prompt at. --force is required to touch an account that already exists,
// because unattended means nobody is there to answer "reset its password?":
//
//   ADMIN_EMAIL=you@example.com ADMIN_PASSWORD=... npm run create-admin -- --force
//   npm run create-admin -- you@example.com --generate --force
//
// ADMIN_PASSWORD is read from the environment rather than taken as an
// argument on purpose: an argument is visible in `ps` output and lands in
// shell history. --generate avoids handling one at all, and prints the
// password once, to stdout.
//
// This is deliberately the ONLY way an admin account comes into existence.
// There is no signup page and no password-reset email, so recovering from a
// lost password requires shell access to the host -- which is itself a
// control, and a far better one than an internet-facing reset flow guarding
// the credential that mints access to the internal network.

require('dotenv').config({ quiet: true });

const crypto = require('crypto');
const readline = require('readline');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const MIN_PASSWORD_LENGTH = 12;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith('--')));
const positional = args.filter((a) => !a.startsWith('--'));
const GENERATE = flags.has('--generate');
const FORCE = flags.has('--force');

const ROLES = ['owner', 'admin', 'auditor'];
const roleFlag = [...flags].find((f) => f.startsWith('--role'));
const ROLE = roleFlag ? roleFlag.split('=')[1] : (process.env.ADMIN_ROLE || 'owner');
if (!ROLES.includes(ROLE)) {
  console.error(`--role must be one of: ${ROLES.join(', ')}`);
  process.exit(1);
}

const unknownFlag = [...flags]
  .find((f) => !['--generate', '--force'].includes(f) && !f.startsWith('--role='));
if (unknownFlag) {
  console.error(`Unknown option ${unknownFlag}. Valid options: --generate, --force, --role=<role>`);
  process.exit(1);
}

// Same alphabet as the gateway's own generated passwords: no 0/O or 1/l/I,
// because these get read off a screen and retyped.
function generatePassword(length = 20) {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) out += charset[bytes[i] % charset.length];
  return out;
}

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. Run this from the project directory with a .env present.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

// Answers are read differently depending on whether a human is typing.
//
// Interactively we mask the password so it is not echoed or left in a
// scrollback buffer. When stdin is piped (CI, or a scripted test) there is no
// terminal to mask and readline's terminal mode misbehaves, so the whole of
// stdin is read up front and consumed a line at a time instead.
const isInteractive = process.stdin.isTTY;
let pipedLines = null;

async function readPipedLines() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8').split(/\r?\n/);
}

async function ask(question, { silent = false } = {}) {
  if (!isInteractive) {
    if (pipedLines === null) pipedLines = await readPipedLines();
    const answer = pipedLines.shift();
    if (answer === undefined) throw new Error('unexpected end of input');
    process.stdout.write(`${question}${silent ? '' : answer}\n`);
    return answer;
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
  });

  if (silent) {
    // readline calls this for every keystroke it would echo; swallowing it
    // keeps the password off the screen while still accepting input.
    let primed = false;
    rl._writeToOutput = (chunk) => {
      if (!primed) { rl.output.write(chunk); primed = true; }
    };
  }

  try {
    const answer = await new Promise((resolve) => rl.question(question, resolve));
    if (silent) process.stdout.write('\n');
    return answer;
  } finally {
    rl.close();
  }
}

(async () => {
  try {
    // Unattended when a password is supplied without a terminal to type it
    // into. Everything below branches on this rather than on isInteractive,
    // so a piped stdin still drives the prompting path it always did.
    const suppliedPassword = process.env.ADMIN_PASSWORD || '';
    const unattended = GENERATE || Boolean(suppliedPassword);

    let email = positional[0] || process.env.ADMIN_EMAIL;
    if (!email) email = await ask('Admin email: ');
    email = String(email).trim().toLowerCase();

    if (!EMAIL_RE.test(email)) {
      console.error('That is not a valid email address.');
      process.exit(1);
    }

    const existing = await pool.query('SELECT id, role, disabled_at FROM admins WHERE email = $1', [email]);
    if (existing.rows[0]) {
      // Resetting an existing admin's password is the recovery path, but it
      // also silently locks that person out of the console. Unattended, there
      // is nobody to ask, so it has to be asked for in advance.
      if (unattended && !FORCE) {
        console.error(`${email} already exists. Re-run with --force to reset its password.`);
        process.exit(1);
      }
      if (!unattended) {
        const answer = await ask(`${email} already exists. Reset its password? [y/N] `);
        if (answer.trim().toLowerCase() !== 'y') {
          console.log('Nothing changed.');
          process.exit(0);
        }
      }
    }

    // ADMIN_PASSWORD wins over --generate, so a caller can pass both: the
    // demo bootstrap always asks for --generate and an operator overrides it
    // with a password of their own by setting the variable, with no second
    // code path to keep in step.
    const generated = !suppliedPassword && GENERATE;
    let password;
    if (suppliedPassword) {
      password = suppliedPassword;
    } else if (GENERATE) {
      password = generatePassword();
    } else {
      password = await ask('Password: ', { silent: true });
    }

    if (password.length < MIN_PASSWORD_LENGTH) {
      console.error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      process.exit(1);
    }

    if (!unattended) {
      const confirm = await ask('Confirm password: ', { silent: true });
      if (password !== confirm) {
        console.error('Passwords do not match.');
        process.exit(1);
      }
    }

    const hash = await bcrypt.hash(password, await bcrypt.genSalt(12));

    // Resets the lockout and re-enables the account, so this doubles as the
    // recovery path for an admin who locked themselves out.
    // The role is only written on insert, or when --role was given explicitly.
    // This script's other job is password recovery, and silently promoting an
    // auditor back to owner because the flag defaults that way is not a
    // recovery -- it is a privilege escalation with a friendly message.
    const { rows } = await pool.query(
      `INSERT INTO admins (email, password_hash, role) VALUES ($1, $2, $3)
       ON CONFLICT (email) DO UPDATE
         SET password_hash = EXCLUDED.password_hash,
             role = CASE WHEN $4 THEN EXCLUDED.role ELSE admins.role END,
             failed_login_attempts = 0,
             locked_until = NULL,
             disabled_at = NULL
       RETURNING id, email, role, created_at`,
      [email, hash, ROLE, Boolean(roleFlag)]
    );

    await pool.query(
      `INSERT INTO audit_log (event, actor, detail)
       VALUES ($1, $2, $3)`,
      [
        existing.rows[0] ? 'ADMIN_PASSWORD_RESET' : 'ADMIN_CREATED',
        'cli',
        JSON.stringify({ email, role: rows[0].role }),
      ]
    );

    console.log(`\n${existing.rows[0] ? 'Updated' : 'Created'} admin: ${rows[0].email} (${rows[0].role})`);
    // Printed once, and only for a password this script invented -- one the
    // operator has no other way to learn. A password they supplied is never
    // echoed back.
    if (generated) console.log(`Password: ${password}`);
    console.log(`Sign in at ${process.env.PUBLIC_BASE_URL || 'http://localhost:3000'}/__access/admin`);
  } catch (err) {
    console.error(`\nFailed: ${err.message}`);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
})();
