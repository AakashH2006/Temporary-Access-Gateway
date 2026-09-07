#!/usr/bin/env node
//
// Applies schema.sql.
//
//   npm run migrate
//   npm run migrate -- --wait     (retry until Postgres accepts connections)
//
// This used to be `psql "$DATABASE_URL" -f schema.sql`, which meant the
// project could not be set up without the Postgres client tools installed --
// true on a bare container and on most Windows machines, and the failure was
// an opaque "psql: command not found" at the second step of the README. The
// application already depends on `pg`, so the driver it will use at runtime is
// the one that applies the schema.
//
// schema.sql is written to be re-runnable (CREATE ... IF NOT EXISTS, ALTER ...
// ADD COLUMN IF NOT EXISTS), so this is safe to run against an existing
// database. It is not a migration framework and does not pretend to be one:
// there is no version table and no down direction. That is a deliberate limit
// of a single-file schema, and the point at which it stops being enough is the
// point to adopt a real tool.

require('dotenv').config({ quiet: true });

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

const SCHEMA_PATH = path.join(__dirname, '..', 'schema.sql');
const WAIT = process.argv.includes('--wait');
// Long enough for a Postgres container's first-boot initdb on a cold machine.
const WAIT_TIMEOUT_MS = Number(process.env.MIGRATE_WAIT_TIMEOUT_MS || 60_000);

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. Run this from the project directory with a .env present.');
  process.exit(1);
}

function connectionConfig() {
  return {
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
  };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Compose can start this the instant the database container exists, which is
// well before Postgres is listening. `depends_on: service_healthy` covers the
// normal case; this covers the rest, and makes the script usable against a
// database that is still coming up for any other reason.
async function connect() {
  const deadline = Date.now() + WAIT_TIMEOUT_MS;
  for (let attempt = 1; ; attempt++) {
    const client = new Client(connectionConfig());
    try {
      await client.connect();
      return client;
    } catch (err) {
      await client.end().catch(() => {});
      if (!WAIT || Date.now() >= deadline) throw err;
      if (attempt === 1) console.log('waiting for Postgres...');
      await sleep(1000);
    }
  }
}

(async () => {
  let client;
  try {
    client = await connect();
  } catch (err) {
    console.error(`Cannot reach the database: ${err.message}`);
    process.exit(1);
  }

  try {
    // One call, not a split on ';'. schema.sql contains a dollar-quoted DO
    // block whose body has its own semicolons, and any naive splitter cuts it
    // in half. The simple query protocol takes the whole file as written.
    await client.query(fs.readFileSync(SCHEMA_PATH, 'utf8'));
    console.log(`applied ${path.relative(process.cwd(), SCHEMA_PATH)}`);
  } catch (err) {
    console.error(`Migration failed: ${err.message}`);
    process.exitCode = 1;
  } finally {
    await client.end();
  }
})();
