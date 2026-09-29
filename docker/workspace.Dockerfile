# Atrium workspace base image (M2).
#
# The container this builds is SEMI-HOSTILE by design (SECURITY.md §1): it runs
# model-generated commands and arbitrary `npm install` postinstall scripts.
# Everything below follows from that.
#
# BUILD
#   docker build -f docker/workspace.Dockerfile -t atrium/workspace-base:m2 .
#
# PIN IT
#   `SandboxImageRef.digest` is required and `validateSpec` refuses a reference
#   without one (T12). For a locally built image the content-addressed
#   reference is the image id:
#     docker image inspect --format "{{.Id}}" atrium/workspace-base:m2
#   Feed that sha256:… to `SandboxImageRef.digest`; `resolveImageReference`
#   accepts either a local image id or a registry `repo@sha256:…`. When this
#   image is published, re-pin to the REGISTRY digest from `RepoDigests`, not
#   to the tag.
#
# WHAT IS DELIBERATELY NOT HERE
#   - No credentials, no tokens, no keys, no .netrc, no ssh config, no
#     credential helper. Not now, not later (D1, D2). The model provider key and
#     the Git token live host-side and are reached through brokers.
#   - No sudo, no setuid binaries added, no package manager cache left behind.
#   - No Docker CLI and no docker socket. A workspace container has no business
#     speaking to the engine that created it.
#   - No entrypoint script that "helpfully" chowns the repo mount as root: the
#     container has no root to do it with.
#
# RUNTIME EXPECTATIONS (set by LocalDockerProvider, not by this file)
#   read-only root filesystem, so the only writable paths are the repo bind
#   mount and the tmpfs mounts declared in the spec: /tmp, /home/atrium, /run.
#   `git` needs a writable HOME for its lock files, which is why /home/atrium is
#   a declared tmpfs rather than a baked-in writable directory.

# node:22-alpine, pinned by digest (T12). A tag is a mutable pointer:
# `node:22-alpine` today is not the bytes it was last week. This is the
# manifest-list digest resolved on 2026-09-03, carrying Node 22.23.2.
# Refresh it deliberately — re-pull, re-read the digest, rebuild, rescan —
# never implicitly by dropping the digest.
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32

# git       cloning and every VCS operation an agent performs
# bash      PtyOpts.command defaults to a login shell; alpine ships ash only
# ca-certificates  https to the registry actually verifying anything
# openssh-client is NOT installed: no ssh means no ssh key can be useful (D2)
RUN apk add --no-cache \
      bash \
      ca-certificates \
      git \
      less \
      ncurses-terminfo-base \
    && rm -rf /var/cache/apk/*

# Non-root user. uid/gid 10001 matches `DEFAULT_USER` in spec.ts; the provider
# passes it explicitly on every container and refuses uid 0, so this is defence
# in depth rather than the control itself.
#
# The home directory is created but is a mount point at runtime: the root
# filesystem is read-only, so /home/atrium is only writable because a tmpfs is
# mounted over it.
RUN addgroup -g 10001 atrium \
    && adduser -D -u 10001 -G atrium -h /home/atrium -s /bin/bash atrium \
    && mkdir -p /workspace \
    && chown 10001:10001 /workspace /home/atrium

# ---------------------------------------------------------------------------
# The agent runner (M3b) — @atrium/agent-runner plus the Claude Agent SDK.
# ---------------------------------------------------------------------------
# BAKED IN, NOT MOUNTED, AND THAT IS NOT A PREFERENCE.
#   The SDK ships its CLI as a ~210 MB per-platform NATIVE BINARY delivered
#   through optionalDependencies, not as JavaScript. This base is alpine, so
#   `process.report.getReport().header.glibcVersionRuntime` is undefined and the
#   SDK's resolver prefers `…-linux-<arch>-musl`. The development host here is
#   Windows and holds only `claude.exe`; a bind-mounted host node_modules would
#   fail at spawn every single time, with the SDK's own error about a musl
#   binary and a missing /lib/ld-musl loader. npm on alpine detects libc=musl
#   and picks the right optional package, so the install has to happen HERE.
#   (Cross-building on a glibc host: add --os=linux --cpu=x64 --libc=musl.)
#
# WHY /opt AND NOT /workspace
#   /workspace is the repo bind mount and is writable by the agent. A runner
#   living there is a runner a prompt-injected agent can rewrite before the next
#   session starts (SECURITY.md T1). /opt is on the read-only root filesystem
#   and is owned by root; uid 10001 can execute it and cannot touch it.
#
# WHY SOURCE AND NOT A BUILD
#   The runner is TypeScript compiled by nobody: `erasableSyntaxOnly` is on
#   repo-wide, so `node --experimental-strip-types` runs the source directly,
#   the same way apps/server runs in dev. No compiler and no dist/ in the image.
#
# COST, STATED OUT LOUD
#   This adds roughly 210 MB to the image. Re-pin the FROM digest deliberately
#   when rebuilding; do not drop it (T12).
COPY apps/agent-runner/package.json /opt/atrium-runner/package.json
RUN cd /opt/atrium-runner \
    # `@atrium/shared` is an npm-workspace link that does not exist inside this
    # image, and the runner deliberately imports nothing from it at runtime
    # (apps/agent-runner/src/protocol.ts resolves nothing). Strip it rather than
    # vendoring a package the runner does not use. The SDK's version pin stays
    # canonical in apps/agent-runner/package.json — it is not restated here.
    && node -e 'const f="./package.json",fs=require("fs");const p=JSON.parse(fs.readFileSync(f,"utf8"));delete p.dependencies["@atrium/shared"];delete p.devDependencies;fs.writeFileSync(f,JSON.stringify(p,null,2))' \
    && npm install --omit=dev --no-audit --no-fund \
    && npm cache clean --force \
    # Fail the BUILD, not the first agent session, if the native CLI is absent.
    # A missing binary here surfaces at runtime as an unexplained spawn failure
    # inside a container, which is the worst place to debug it.
    && test -n "$(find /opt/atrium-runner/node_modules/@anthropic-ai -maxdepth 2 -name claude -type f -print -quit)" \
    && chown -R root:root /opt/atrium-runner \
    && chmod -R go-w /opt/atrium-runner
COPY apps/agent-runner/src /opt/atrium-runner/src
RUN chown -R root:root /opt/atrium-runner/src && chmod -R go-w /opt/atrium-runner/src

# Drop every setuid/setgid bit in the image. `no-new-privileges` already stops
# these from escalating, and cap-drop=ALL removes what they would need, but an
# image with no setuid binaries at all is one fewer thing to reason about.
#
# Runs AFTER the npm install above on purpose: a dependency that ships a setuid
# binary would otherwise slip in behind this sweep.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

ENV HOME=/home/atrium \
    LANG=C.UTF-8 \
    TZ=UTC \
    CI=1 \
    npm_config_update_notifier=false \
    npm_config_fund=false \
    GIT_TERMINAL_PROMPT=0 \
    GIT_ASKPASS=/bin/false \
    GIT_CONFIG_NOSYSTEM=1

USER 10001:10001
WORKDIR /workspace

# The provider replaces this with its own idle command; a container that starts
# a shell by accident is a container that exits immediately.
CMD ["/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"]
