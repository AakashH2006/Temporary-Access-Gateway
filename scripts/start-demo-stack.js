// Starts the whole public demo from one process: the stand-in app on loopback,
// then the gateway in front of it.
//
// Free hosting (Render's free plan) gives one service with one public port.
// Running demo-app as a second service would give it a public URL of its own --
// the exact property this demo exists to show the absence of. Bound to
// 127.0.0.1 inside the same container, nothing outside can reach it, and the
// gateway is the only way in, as it would be on a VPN.
//
// Not for a real deployment. There, point UPSTREAM_URL at the real app and run
// `node server.js` (DEPLOY.md).

const path = require('path');
const { spawn, spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const DEMO_PORT = process.env.DEMO_PORT || '4000';

// Render hands every web service its public https URL. Emailed links are built
// from PUBLIC_BASE_URL, so borrowing Render's value avoids one that has to be
// typed after the first deploy and kept in step with the service name.
if (!process.env.PUBLIC_BASE_URL && process.env.RENDER_EXTERNAL_URL) {
  process.env.PUBLIC_BASE_URL = process.env.RENDER_EXTERNAL_URL;
}
process.env.UPSTREAM_URL = process.env.UPSTREAM_URL || `http://127.0.0.1:${DEMO_PORT}`;

// schema.sql is re-runnable, so applying it on every boot is the upgrade path,
// and a free plan has no separate release step to put it in. --wait covers a
// database still waking from scale-to-zero.
const migrate = spawnSync(process.execPath, [path.join(root, 'scripts', 'migrate.js'), '--wait'], {
  stdio: 'inherit',
  env: process.env,
});
if (migrate.status !== 0) {
  console.error('Migration failed; not starting the gateway.');
  process.exit(1);
}

let stopping = false;
for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => { stopping = true; });

const demo = spawn(process.execPath, [path.join(root, 'demo-app', 'app.js')], {
  stdio: 'inherit',
  env: {
    ...process.env,
    DEMO_HOST: '127.0.0.1',
    DEMO_PORT,
    // The app refuses any request without this, so even another process in
    // the container cannot reach it except through the gateway.
    GATEWAY_SECRET: process.env.UPSTREAM_SHARED_SECRET || '',
  },
});

// If the app behind the gateway dies, every page is a 502. Exiting hands the
// problem to the platform, which restarts the container. During a shutdown the
// app stopping is expected, and the gateway's own handler decides the exit.
demo.on('exit', (code) => {
  if (stopping) return;
  console.error(`demo-app exited (${code}); stopping so the platform can restart.`);
  process.exit(1);
});
process.on('exit', () => demo.kill());

require('../server.js').start({ handleSignals: true }).catch((err) => {
  console.error(err);
  process.exit(1);
});
