/**
 * BrokerSidecars — the container that holds the provider credential, and the
 * only thing that mints the two values allowed to cross into a workspace
 * (SECURITY.md D1, T2; PLAN.md §4).
 *
 * ============================================================================
 * WHY THIS IS A CONTAINER AND NOT A HOST PROCESS
 * ============================================================================
 * The workspace container sits on the `atrium-internal` bridge, which is
 * `Internal: true` — the daemon installs no NAT rule and packets to the
 * internet die in the kernel (D4, and `local-docker.ts` proves the flag by
 * reading it back). A workspace container therefore CANNOT reach a listener on
 * the Windows host: Docker Desktop runs the engine in a WSL2 VM, so the bridge
 * gateway belongs to the VM and a host process is unreachable from there
 * (measured, PLAN.md §4). The broker must be a container on that same bridge,
 * reached by Docker's embedded DNS.
 *
 * ONE SIDECAR PER WORKSPACE. The capability token is documented as
 * "workspace-scoped", and a single shared broker holding a single shared token
 * would make that a comment rather than a fact: any workspace's agent could
 * spend any other workspace's budget with a token it already has. A sidecar per
 * workspace makes the scope structural — a token is only accepted by the one
 * process that minted it, and `ATRIUM_SESSION_TOKEN_BUDGET` becomes a real
 * per-workspace ceiling enforced OUTSIDE the container (T10).
 *
 * ============================================================================
 * WHAT CROSSES WHICH LINE
 * ============================================================================
 *   server process   holds the credential in memory, passes it ONCE at
 *                    `docker create` time and never again.
 *   broker sidecar   holds it for the life of the container. Attaches it
 *                    upstream; strips the capability token before forwarding.
 *   workspace        gets `baseUrl` + `capabilityToken`, and nothing else, ever.
 *
 * The credential is visible in `docker inspect` of the sidecar to anyone who
 * can reach the engine. That is the same accepted posture as M3a's probe and it
 * is not a hole in D1: reaching the engine is already root-equivalent on this
 * host, and the boundary being defended is the one the AGENT is on the far side
 * of. It is never logged, never returned from a route, and never in a spec.
 *
 * ============================================================================
 * WHAT THIS FILE ASSUMES
 * ============================================================================
 * One Atrium server process per host — the same assumption `WorkspaceSandboxes`
 * already makes when it reaps a previous run's orphaned ptys. On the first mint
 * for a workspace this process REPLACES any existing sidecar for it, because
 * the token inside a container it did not create is unknown to it and a broker
 * nobody can authenticate against is worse than no broker.
 */

import { createHash, randomBytes } from "node:crypto";
import Docker from "dockerode";

import type { AgentBrokerBinding } from "../agent/provider.ts";
import type { BrokerBindingSource } from "../realtime/agent-registry.ts";
import { SandboxError } from "./errors.ts";
import {
  INTERNAL_NETWORK_NAME,
  LABEL_CREATED_AT,
  LABEL_MANAGED,
  LABEL_ROLE,
  LABEL_WORKSPACE,
} from "./local-docker.ts";

const WORKSPACE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** Memory and pid ceilings. The broker is one small http server, nothing else. */
const BROKER_MEMORY_BYTES = 256 * 1024 * 1024;
const BROKER_PIDS_LIMIT = 64;
/** How long to wait for `broker listening` in the sidecar's log. */
const BROKER_READY_TIMEOUT_MS = 15_000;
const BROKER_READY_POLL_MS = 250;

export interface BrokerSidecarLogger {
  info(obj: Record<string, unknown>, msg: string): void;
  warn(obj: Record<string, unknown>, msg: string): void;
}

export interface BrokerSidecarsOptions {
  readonly log: BrokerSidecarLogger;
  /** Named pipe or unix socket for the engine. From `config.dockerSocket`. */
  readonly dockerSocket: string;
  readonly image: { readonly repository: string; readonly tag: string };
  readonly port: number;
  readonly upstreamOrigin: string;
  /** Null is a working configuration — see `BrokerSidecarConfig` in config.ts. */
  readonly upstreamCredential: string | null;
  readonly sessionTokenBudget: number;
  readonly upstreamNeedsEgress: boolean;
  readonly tokenTtlMs: number;
}

interface Sidecar {
  /** Container name, which is also its DNS name on the internal bridge. */
  readonly name: string;
  readonly containerId: string;
  readonly capabilityToken: string;
  readonly expiresAt: Date;
}

export class BrokerSidecars implements BrokerBindingSource {
  readonly #docker: Docker;
  readonly #options: BrokerSidecarsOptions;
  readonly #live = new Map<string, Sidecar>();
  readonly #pending = new Map<string, Promise<Sidecar>>();
  #warnedNoCredential = false;

  constructor(options: BrokerSidecarsOptions) {
    this.#options = options;
    this.#docker = new Docker({ socketPath: options.dockerSocket });
  }

  /** Sidecars this process has started. For `/api/health`, not for policy. */
  get count(): number {
    return this.#live.size;
  }

  get credentialConfigured(): boolean {
    return this.#options.upstreamCredential !== null;
  }

  /**
   * `BrokerBindingSource`: the two — and only two — values that may reach the
   * workspace container.
   *
   * `sessionId` is taken for the log and deliberately NOT baked into the token:
   * M3a's broker authenticates one token per process, so the scope this can
   * honestly claim is the workspace, not the session. Saying otherwise in a
   * type would be a control someone believes they have.
   */
  async mint(workspaceId: string, sessionId: string): Promise<AgentBrokerBinding> {
    if (!WORKSPACE_ID_RE.test(workspaceId)) {
      throw new SandboxError("invalid-spec", "workspace id is not a safe id");
    }
    const sidecar = await this.#ensure(workspaceId);
    this.#options.log.info(
      { workspaceId, agentId: sessionId, broker: sidecar.name },
      "issued a broker capability for an agent session",
    );
    return {
      // Reachable FROM THE CONTAINER by Docker's embedded DNS. Never a host
      // address: a workspace container cannot reach the Windows host.
      baseUrl: `http://${sidecar.name}:${this.#options.port}`,
      capabilityToken: sidecar.capabilityToken,
      expiresAt: sidecar.expiresAt,
    };
  }

  async #ensure(workspaceId: string): Promise<Sidecar> {
    const live = this.#live.get(workspaceId);
    if (live !== undefined && live.expiresAt.getTime() > Date.now()) {
      // Cheap liveness re-read: an operator may have removed it, and a binding
      // pointing at a dead name fails as a model timeout three minutes later.
      const running = await this.#isRunning(live.containerId);
      if (running) return live;
      this.#live.delete(workspaceId);
    }

    const inFlight = this.#pending.get(workspaceId);
    if (inFlight !== undefined) return inFlight;

    const pending = this.#create(workspaceId);
    this.#pending.set(workspaceId, pending);
    try {
      const sidecar = await pending;
      this.#live.set(workspaceId, sidecar);
      return sidecar;
    } finally {
      this.#pending.delete(workspaceId);
    }
  }

  async #create(workspaceId: string): Promise<Sidecar> {
    const name = sidecarName(workspaceId);
    await this.#removeByName(name);
    await this.#ensureInternalNetwork();

    if (this.#options.upstreamCredential === null && !this.#warnedNoCredential) {
      this.#warnedNoCredential = true;
      this.#options.log.warn(
        { upstream: this.#options.upstreamOrigin },
        "no ATRIUM_UPSTREAM_API_KEY: the broker will authenticate and budget as usual but refuse to " +
          "forward, so agents fail at their first model call. This is the intended state on a machine " +
          "that holds no key (SECURITY.md D1).",
      );
    }

    // Minted here and nowhere else. Not derived from the workspace id, so
    // knowing the id is not knowing the token.
    const capabilityToken = `cap-${randomBytes(24).toString("base64url")}`;
    const image = `${this.#options.image.repository}:${this.#options.image.tag}`;
    const env = [
      `ATRIUM_BROKER_PORT=${this.#options.port}`,
      `ATRIUM_UPSTREAM_ORIGIN=${this.#options.upstreamOrigin}`,
      `ATRIUM_CAPABILITY_TOKEN=${capabilityToken}`,
      `ATRIUM_SESSION_TOKEN_BUDGET=${this.#options.sessionTokenBudget}`,
    ];
    // The one line in the codebase that moves the provider credential, and it
    // moves it INTO the sidecar. There is no branch here that could put it
    // anywhere else.
    if (this.#options.upstreamCredential !== null) {
      env.push(`ATRIUM_UPSTREAM_API_KEY=${this.#options.upstreamCredential}`);
    }

    let container: Docker.Container;
    try {
      container = await this.#docker.createContainer({
        name,
        Image: image,
        Env: env,
        // Non-root, and the image's own uid. The broker writes nothing.
        User: "10002:10002",
        Labels: {
          [LABEL_MANAGED]: "true",
          // Not "workspace": `listManaged` and sandbox adoption filter on that
          // role, and a broker is not a sandbox.
          [LABEL_ROLE]: "broker",
          [LABEL_WORKSPACE]: workspaceId,
          [LABEL_CREATED_AT]: new Date().toISOString(),
        },
        HostConfig: {
          NetworkMode: INTERNAL_NETWORK_NAME,
          ReadonlyRootfs: true,
          CapDrop: ["ALL"],
          SecurityOpt: ["no-new-privileges"],
          Memory: BROKER_MEMORY_BYTES,
          PidsLimit: BROKER_PIDS_LIMIT,
          // No bind mounts, no tmpfs, no Docker socket: the process that holds
          // the credential touches no filesystem an attacker could reach.
          Binds: [],
          RestartPolicy: { Name: "" },
          AutoRemove: false,
        },
      });
    } catch (err) {
      throw this.#wrap(err, image);
    }

    try {
      // Connected BEFORE start, so the sidecar has its route from the first
      // packet. This is the only container in the design that gets egress: the
      // upstream API lives off-host and the workspace bridge has no route to
      // it, which is exactly the property that makes the broker necessary.
      if (this.#options.upstreamNeedsEgress) {
        await this.#docker.getNetwork("bridge").connect({ Container: container.id });
      }
      await container.start();
      await this.#waitForReady(container);
    } catch (err) {
      await container.remove({ force: true }).catch(() => undefined);
      throw this.#wrap(err, image);
    }

    this.#options.log.info(
      {
        workspaceId,
        broker: name,
        upstream: this.#options.upstreamOrigin,
        egress: this.#options.upstreamNeedsEgress,
        credentialConfigured: this.credentialConfigured,
        budgetTokens: this.#options.sessionTokenBudget,
        // The token and the credential are absent, and must stay absent (T9).
      },
      "broker sidecar ready",
    );

    return {
      name,
      containerId: container.id,
      capabilityToken,
      expiresAt: new Date(Date.now() + this.#options.tokenTtlMs),
    };
  }

  /**
   * The sidecar prints one line when it is listening. Waiting for it turns "the
   * broker image is broken" into a legible start failure instead of a model
   * call that times out inside the container three minutes later.
   */
  async #waitForReady(container: Docker.Container): Promise<void> {
    const deadline = Date.now() + BROKER_READY_TIMEOUT_MS;
    let last = "";
    while (Date.now() < deadline) {
      let text = "";
      try {
        const raw = (await container.logs({ stdout: true, stderr: true, tail: 50 })) as unknown;
        text = Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw);
      } catch {
        text = "";
      }
      // Substring, not a parse: with no tty the stream is multiplexed with
      // 8-byte frame headers and we only need to know the line appeared.
      if (text.includes("broker listening")) return;
      last = text;
      const info = await container.inspect().catch(() => null);
      if (info !== null && info.State.Running === false) break;
      await new Promise((resolve) => setTimeout(resolve, BROKER_READY_POLL_MS));
    }
    throw new SandboxError(
      "internal",
      `the broker sidecar did not report "broker listening" within ${BROKER_READY_TIMEOUT_MS}ms` +
        (last === "" ? "" : `; last output: ${last.replace(/[^\x20-\x7e]+/g, " ").slice(-200)}`),
    );
  }

  async #isRunning(containerId: string): Promise<boolean> {
    try {
      const info = await this.#docker.getContainer(containerId).inspect();
      return info.State.Running === true;
    } catch {
      return false;
    }
  }

  async #removeByName(name: string): Promise<void> {
    try {
      await this.#docker.getContainer(name).remove({ force: true });
      this.#options.log.info({ broker: name }, "replaced a leftover broker sidecar");
    } catch (err) {
      const status = (err as { statusCode?: number }).statusCode;
      // 404 is the ordinary case: there was nothing to replace.
      if (status !== 404 && status !== 409) {
        this.#options.log.warn(
          { broker: name, err: err instanceof Error ? err.message : "unknown" },
          "could not remove a leftover broker sidecar",
        );
      }
    }
  }

  /**
   * The bridge must exist before a container can join it by name.
   *
   * `LocalDockerProvider` is the component that PROVES the network is
   * `Internal` before a workspace container joins it, and it refuses to run one
   * if it is not. This only has to make sure the network exists, since the
   * broker is the one container for which egress is not a violation — but a
   * routable `atrium-internal` is still worth saying out loud here, because the
   * operator reading this log line is one command away from the same failure on
   * the workspace side.
   */
  async #ensureInternalNetwork(): Promise<void> {
    try {
      const info = await this.#docker.getNetwork(INTERNAL_NETWORK_NAME).inspect();
      if (info.Internal !== true) {
        this.#options.log.warn(
          { network: INTERNAL_NETWORK_NAME },
          "the atrium-internal network exists but is not --internal; workspace containers will be refused",
        );
      }
      return;
    } catch (err) {
      if ((err as { statusCode?: number }).statusCode !== 404) {
        throw this.#wrap(err, `${this.#options.image.repository}:${this.#options.image.tag}`);
      }
    }
    try {
      await this.#docker.createNetwork({
        Name: INTERNAL_NETWORK_NAME,
        Driver: "bridge",
        Internal: true,
        Attachable: false,
        EnableIPv6: false,
        Labels: { [LABEL_MANAGED]: "true" },
      });
    } catch (err) {
      // 409: someone else created it between the inspect and the create.
      if ((err as { statusCode?: number }).statusCode !== 409) {
        throw this.#wrap(err, `${this.#options.image.repository}:${this.#options.image.tag}`);
      }
    }
  }

  /** Remove one workspace's sidecar. Idempotent. */
  async release(workspaceId: string): Promise<void> {
    const sidecar = this.#live.get(workspaceId);
    this.#live.delete(workspaceId);
    if (sidecar === undefined) return;
    await this.#docker
      .getContainer(sidecar.containerId)
      .remove({ force: true })
      .catch(() => undefined);
  }

  /**
   * Shutdown. Unlike workspace containers — left running and re-adopted on the
   * next boot — a sidecar is removed: its token lives only in this process's
   * memory, so a survivor is a credential-holding container nothing can
   * authenticate against.
   */
  async closeAll(): Promise<void> {
    const doomed = [...this.#live.values()];
    this.#live.clear();
    await Promise.all(
      doomed.map((s) =>
        this.#docker
          .getContainer(s.containerId)
          .remove({ force: true })
          .catch(() => undefined),
      ),
    );
  }

  #wrap(err: unknown, image: string): SandboxError {
    const message = err instanceof Error ? err.message : String(err);
    const status = (err as { statusCode?: number }).statusCode;
    if (status === 404 && message.includes("No such image")) {
      return new SandboxError(
        "invalid-spec",
        `the broker image ${image} is not present. Build it with ` +
          `\`npm run build --workspace @atrium/broker && docker build -f docker/broker.Dockerfile -t ${image} .\``,
      );
    }
    return new SandboxError("backend-unavailable", `broker sidecar: ${message}`);
  }
}

/**
 * Container name, which is also the DNS name the workspace resolves.
 *
 * Hashed rather than interpolated: workspace ids allow `_` and are
 * case-sensitive, while DNS labels are neither, so `My_WS` and `my-ws` could
 * otherwise collide or produce a name the resolver mangles. 12 hex characters
 * is not a secret — the token is the secret — it is just a stable, legal label.
 */
export function sidecarName(workspaceId: string): string {
  const digest = createHash("sha256").update(workspaceId).digest("hex").slice(0, 12);
  return `atrium-broker-${digest}`;
}
