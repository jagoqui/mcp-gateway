import { spawn } from 'node:child_process';
import net from 'node:net';
import { createPortAllocator } from './port-allocator.js';

const DEFAULT_READY_TIMEOUT_MS = 5000;
const DEFAULT_READY_INTERVAL_MS = 50;

/**
 * Polls 127.0.0.1:<port> with a raw TCP connect until something accepts the
 * connection, or throws once timeoutMs elapses. supergateway/engram mcp
 * need real startup time after spawn; proxying to a not-yet-listening port
 * is a genuine "502 bad_gateway" this closes.
 * @param {number} port
 * @param {{ timeoutMs?: number, intervalMs?: number }} [options]
 * @returns {Promise<void>}
 */
export async function waitUntilReady(port, options = {}) {
  const { timeoutMs = DEFAULT_READY_TIMEOUT_MS, intervalMs = DEFAULT_READY_INTERVAL_MS } = options;
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const connected = await new Promise((resolve) => {
      const socket = net.connect(port, '127.0.0.1');
      socket.once('connect', () => {
        socket.destroy();
        resolve(true);
      });
      socket.once('error', () => {
        socket.destroy();
        resolve(false);
      });
    });
    if (connected) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }

  throw new Error(
    `engram-router: child on port ${port} did not become ready within ${timeoutMs}ms`,
  );
}

/**
 * A child is healthy exactly when it hasn't exited — mirrors node:child_process's
 * own `exitCode` field (null while running), so the real spawnChild below and any
 * test stub shaped the same way both satisfy this check identically.
 * @param {{ exitCode: number | null }} child
 * @returns {boolean}
 */
function isHealthy(child) {
  return child.exitCode === null;
}

/**
 * Production spawn function: a supergateway-wrapped `engram mcp` child on
 * the given port, with the given identity's project + cloud-sync env.
 * @param {{ identity: string, port: number, env: Record<string, string> }} opts
 * @returns {import('node:child_process').ChildProcess}
 */
export function realSpawnChild({ identity, port, env }) {
  const child = spawn(
    'supergateway',
    [
      '--stdio',
      'engram mcp',
      '--outputTransport',
      'streamableHttp',
      '--port',
      String(port),
      '--host',
      '127.0.0.1',
      '--streamableHttpPath',
      '/mcp/engram',
    ],
    { env: { ...process.env, ...env } },
  );

  // Previously left unconsumed: with the default `stdio: 'pipe'`, nothing
  // ever read child.stdout/stderr, hiding every error the wrapped engram
  // mcp process (autosync failures included) ever printed — and risking
  // backpressure once the OS pipe buffer filled. Prefixed so `docker
  // compose logs engram-router` can tell identities apart.
  child.stdout?.on('data', (chunk) => process.stdout.write(`[${identity}] ${chunk}`));
  child.stderr?.on('data', (chunk) => process.stderr.write(`[${identity}] ${chunk}`));

  return child;
}

/**
 * Runs `engram cloud enroll <project>` to completion and resolves, or
 * rejects with a message including the process's stderr. engram's local
 * SQLite requires a project to be enrolled once before autosync will push
 * anything for it (verified against source — env vars alone cannot skip
 * this, it writes local state) — this is that one-time step, run by the
 * router itself so no per-project VPS action is ever needed by a human.
 * @param {{ project: string, env: Record<string, string> }} opts
 * @returns {Promise<void>}
 */
export function realEnrollProject({ project, env }) {
  return new Promise((resolve, reject) => {
    const child = spawn('engram', ['cloud', 'enroll', project], {
      env: { ...process.env, ...env },
    });
    let stderr = '';
    child.stderr?.on('data', (chunk) => {
      stderr += chunk;
    });
    child.once('error', reject);
    child.once('exit', (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(
        new Error(`engram cloud enroll failed for "${project}" (exit ${code}): ${stderr.trim()}`),
      );
    });
  });
}

/**
 * @param {{
 *   maxChildren: number,
 *   portAllocatorOptions: { base: number, max: number },
 *   cloudToken: string,
 *   cloudServer: string,
 *   spawnChild?: (opts: { identity: string, port: number, env: Record<string, string> }) => any,
 *   enrollProject?: (opts: { project: string, env: Record<string, string> }) => Promise<void>,
 *   waitUntilReady?: (port: number, options?: { timeoutMs?: number, intervalMs?: number }) => Promise<void>,
 *   readyTimeoutMs?: number,
 *   readyIntervalMs?: number,
 * }} options
 */
export function createProcessManager({
  maxChildren,
  portAllocatorOptions,
  cloudToken,
  cloudServer,
  spawnChild = realSpawnChild,
  enrollProject = realEnrollProject,
  waitUntilReady: waitForReady = waitUntilReady,
  readyTimeoutMs,
  readyIntervalMs,
}) {
  const portAllocator = createPortAllocator(portAllocatorOptions);
  /** @type {Map<string, { child: any, port: number }>} */
  const children = new Map();

  function buildEnv(identity) {
    return {
      ENGRAM_PROJECT: identity,
      ENGRAM_CLOUD_AUTOSYNC: '1',
      ENGRAM_CLOUD_TOKEN: cloudToken,
      ENGRAM_CLOUD_SERVER: cloudServer,
    };
  }

  /**
   * @param {string} identity
   * @returns {Promise<{ port: number }>}
   */
  async function getOrCreateChild(identity) {
    const existing = children.get(identity);
    if (existing && isHealthy(existing.child)) {
      return { port: existing.port };
    }
    if (existing && !isHealthy(existing.child)) {
      portAllocator.release(existing.port);
      children.delete(identity);
    }

    if (children.size >= maxChildren) {
      throw new Error(`engram-router: at capacity (${maxChildren} concurrent children)`);
    }

    const port = portAllocator.allocate();
    if (port === null) {
      throw new Error('engram-router: at capacity (port range exhausted)');
    }

    const env = buildEnv(identity);
    try {
      await enrollProject({ project: identity, env });
    } catch (err) {
      // Never spawn (or occupy a map slot) for a project that failed to
      // enroll — a retry must be able to attempt enrollment fresh.
      portAllocator.release(port);
      throw err;
    }

    const child = spawnChild({ identity, port, env });
    children.set(identity, { child, port });

    try {
      await waitForReady(port, { timeoutMs: readyTimeoutMs, intervalMs: readyIntervalMs });
    } catch (err) {
      // Never leave a never-became-ready entry occupying a map slot / port —
      // a retry (by this caller or another) must be able to attempt a fresh
      // spawn instead of being told the identity already has a child.
      children.delete(identity);
      portAllocator.release(port);
      throw err;
    }

    return { port };
  }

  return { getOrCreateChild };
}
