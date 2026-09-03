# The model broker sidecar (SECURITY.md D1).
#
# This container holds the provider credential, so its attack surface is the one
# that matters most. It therefore ships NO npm dependencies, no shell tooling
# beyond the base image, and no Docker access.
#
#   docker build -f docker/broker.Dockerfile -t atrium/broker:m3 .
FROM node:22-alpine

# Non-root, matching the workspace image's posture. The broker never writes to
# disk, so it also runs fine with --read-only.
RUN addgroup -g 10002 -S broker && adduser -u 10002 -S broker -G broker

WORKDIR /app
COPY apps/broker/dist ./dist

USER 10002:10002
EXPOSE 8900

# No package.json, no node_modules: nothing to install, nothing to compromise.
CMD ["node", "dist/index.js"]
