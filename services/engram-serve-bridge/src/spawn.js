import { spawn } from 'node:child_process';
import net from 'node:net';

const DEFAULT_READY_TIMEOUT_MS = 5000;
const DEFAULT_READY_INTERVAL_MS = 50;

/**
 * Polls 127.0.0.1:<port> with a raw TCP connect until something accepts the
 * connection, or throws once timeoutMs elapses. Duplicated from
 * engram-router/src/process-manager.js — separate Docker build contexts,
 * no shared package between the two services.
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
    `engram-serve-bridge: engram serve on port ${port} did not become ready within ${timeoutMs}ms`,
  );
}

/**
 * Production spawn function: a single `engram serve` child, multi-project
 * (no ENGRAM_PROJECT), bound to 127.0.0.1:<port> via ENGRAM_PORT — `engram
 * serve` has no flag/env to change its bind host, which is exactly why this
 * wrapper exists to expose it on the container's own 0.0.0.0 listener.
 * @param {{ port: number, env: Record<string, string> }} opts
 * @returns {import('node:child_process').ChildProcess}
 */
export function realSpawnChild({ port, env }) {
  const child = spawn('engram', ['serve'], {
    env: { ...process.env, ...env, ENGRAM_PORT: String(port) },
  });

  child.stdout?.on('data', (chunk) => process.stdout.write(chunk));
  child.stderr?.on('data', (chunk) => process.stderr.write(chunk));

  return child;
}

/**
 * Spawns `engram serve` once and resolves only once it is actually accepting
 * connections — proxying to a not-yet-listening port is a real 502 race.
 * @param {{
 *   port: number,
 *   env: Record<string, string>,
 *   spawnChild?: (opts: { port: number, env: Record<string, string> }) => any,
 *   waitUntilReady?: (port: number, options?: { timeoutMs?: number, intervalMs?: number }) => Promise<void>,
 *   readyTimeoutMs?: number,
 *   readyIntervalMs?: number,
 * }} opts
 * @returns {Promise<any>}
 */
export async function startEngramServe({
  port,
  env,
  spawnChild = realSpawnChild,
  waitUntilReady: waitForReady = waitUntilReady,
  readyTimeoutMs,
  readyIntervalMs,
}) {
  const child = spawnChild({ port, env });
  await waitForReady(port, { timeoutMs: readyTimeoutMs, intervalMs: readyIntervalMs });
  return child;
}
