/**
 * Environment parsing. Fails loudly at boot rather than at first use.
 *
 * SECURITY.md M0: no secret ever has a default value here. A missing
 * credential must stop the process, not silently fall back to a shared one.
 */

import { join } from "node:path";
import { fileURLToPath } from "node:url";

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(
      `Missing required environment variable ${name}. Copy .env.example to .env and fill it in.`,
    );
  }
  return value;
}

function optionalInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) {
    throw new Error(`Environment variable ${name} must be an integer, got ${JSON.stringify(raw)}`);
  }
  return parsed;
}

function optionalString(name: string): string | null {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return null;
  return raw.trim();
}

/** Repo root, derived from this file's location so `cwd` cannot move it. */
function repoRoot(): string {
  // apps/server/src/config.ts -> ../../..  |  apps/server/dist/config.js -> ../../..
  return fileURLToPath(new URL("../../../", import.meta.url));
}

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

/**
 * The workspace container image (M2).
 *
 * `digest` is the content pin SECURITY.md T12 asks for and `validateSpec`
 * refuses a spec without one. It may be null here: when it is, the orchestrator
 * resolves the locally built image's id once at first use and says loudly in
 * the log that the pin came from a mutable tag. Production sets the digest.
 */
export interface WorkspaceImageConfig {
  readonly repository: string;
  readonly tag: string;
  readonly digest: string | null;
}

export interface Config {
  readonly nodeEnv: "development" | "production" | "test";
  readonly port: number;
  readonly host: string;
  readonly databaseUrl: string;
  /** Origins allowed to call the API. The web dev server in development. */
  readonly corsOrigins: readonly string[];
  /**
   * Docker engine endpoint. Docker Desktop for Windows exposes the Linux
   * engine on its own pipe; the classic `docker_engine` pipe can point at the
   * Windows-containers engine, which is not what any of this runs on.
   */
  readonly dockerSocket: string;
  /**
   * Host directory holding one checkout per workspace. The sandbox's
   * `RepoMount.hostPath` is resolved from HERE plus the workspace id, and never
   * from anything in a request (SECURITY.md T5).
   */
  readonly workspacesDir: string;
  readonly workspaceImage: WorkspaceImageConfig;
  /**
   * Public HTTPS repository cloned into an empty workspace checkout, or null to
   * start with an empty directory. Private repos are not supported until the
   * host-side Git proxy lands (D2) — see sandbox/clone.ts.
   */
  readonly workspaceRepoUrl: string | null;
}

export function loadConfig(): Config {
  const nodeEnv = (process.env["NODE_ENV"] ?? "development") as Config["nodeEnv"];

  const digest = optionalString("ATRIUM_WORKSPACE_IMAGE_DIGEST");
  if (digest !== null && !DIGEST_RE.test(digest)) {
    throw new Error(
      "ATRIUM_WORKSPACE_IMAGE_DIGEST must be a sha256 content digest, e.g. sha256:0f2a… " +
        '(docker image inspect --format "{{.Id}}" atrium/workspace-base:m2)',
    );
  }

  return {
    nodeEnv,
    port: optionalInt("PORT", 8787),
    host: process.env["HOST"] ?? "127.0.0.1",
    databaseUrl: required("DATABASE_URL"),
    corsOrigins: (process.env["CORS_ORIGINS"] ?? "http://localhost:5173")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
    dockerSocket:
      optionalString("DOCKER_SOCKET") ??
      (process.platform === "win32"
        ? "//./pipe/dockerDesktopLinuxEngine"
        : "/var/run/docker.sock"),
    workspacesDir:
      optionalString("ATRIUM_WORKSPACES_DIR") ?? join(repoRoot(), ".atrium", "workspaces"),
    workspaceImage: {
      repository: optionalString("ATRIUM_WORKSPACE_IMAGE") ?? "atrium/workspace-base",
      tag: optionalString("ATRIUM_WORKSPACE_IMAGE_TAG") ?? "m2",
      digest,
    },
    workspaceRepoUrl: optionalString("ATRIUM_REPO_URL"),
  };
}
