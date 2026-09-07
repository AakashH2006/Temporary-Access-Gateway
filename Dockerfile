# The gateway and the demo upstream ship in the same image: they share a
# dependency tree, and one image means one thing to build and one thing to
# scan. `docker-compose.yml` picks between them with `command:`.
FROM node:22-alpine

# dumb-init reaps zombies and forwards SIGTERM to node as PID 1, which is what
# makes the graceful shutdown in server.js actually run on `docker stop`.
# Without it node is PID 1, ignores the default signal disposition, and the
# container is killed after the 10s grace period instead of closing the pool.
RUN apk add --no-cache dumb-init

ENV NODE_ENV=production
WORKDIR /app

# Dependencies first, so a source-only change does not reinstall them.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY . .

# node:alpine ships an unprivileged `node` user. The app never writes to disk
# -- every piece of state is in Postgres -- so the filesystem stays owned by
# root and read-only to the process.
USER node

EXPOSE 3000

# Compose has its own healthcheck for the gateway; this one is here so the
# image is self-describing when it is run without compose.
#
# Readiness, not liveness: a container healthcheck answers "should this receive
# traffic", and readiness is the probe that includes Postgres. Liveness lives
# at /__access/health/live and deliberately does not -- a restart policy driven
# by the database turns a Postgres blip into a restart loop.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/__access/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]
