// TLS settings for every Postgres connection this repo opens: the gateway and
// all three scripts. It is one module rather than four copies because the
// copies had already drifted into the insecure default -- and a script that
// connects to production without verifying the peer leaks exactly the same
// credentials the gateway does.
//
// Certificates are verified. TLS to an unverified peer authenticates nothing:
// grant passwords, admin hashes and the audit log all cross this connection,
// and for a managed instance they cross the internet to get there.
//
//   DATABASE_SSL=true            use TLS (managed Postgres: Neon, Supabase, RDS)
//   DATABASE_CA_FILE=/path.pem   the provider's CA bundle; all three publish one
//   DATABASE_SSL_INSECURE=true   skip verification. A hole, spelled so that it
//                                cannot be chosen by accident.

const fs = require('fs');

function databaseSsl(env = process.env) {
  if (env.DATABASE_SSL !== 'true') return false;
  if (env.DATABASE_SSL_INSECURE === 'true') return { rejectUnauthorized: false };
  return env.DATABASE_CA_FILE
    ? { rejectUnauthorized: true, ca: fs.readFileSync(env.DATABASE_CA_FILE, 'utf8') }
    : { rejectUnauthorized: true };
}

module.exports = databaseSsl;
