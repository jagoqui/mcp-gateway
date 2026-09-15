// Bounded in-memory fixed-window login throttle (D12, A9). Keyed by the
// submitted username, never the client IP — the container only ever sees
// Caddy's own address unless X-Forwarded-For is trusted, and trusting a
// client-supplied header for a security control repeats R3's mistake.
// Accepted, documented consequence (D12): with exactly one admin, anyone
// who guesses the username can hold it locked; the escape hatches are
// `bin/admin.js set-password` (bypasses HTTP) and a container restart
// (clears this in-memory map).

/** Failures allowed inside one window before further attempts 429 (A9). */
export const ADMIN_LOGIN_MAX_ATTEMPTS = 5;

/** Fixed window length, in seconds — also the lockout duration once the
 * window fills (no separate escalating penalty). */
export const ADMIN_LOGIN_WINDOW_SECONDS = 900;

/** Bounded entry count (A17): a memory-exhaustion guard against an attacker
 * cycling through many distinct usernames. */
export const ADMIN_THROTTLE_MAX_ENTRIES = 1000;

/**
 * @param {{ maxAttempts?: number, windowSeconds?: number, maxEntries?: number }} [options]
 * @returns {{
 *   isLocked: (key: string, now?: number) => boolean,
 *   recordFailure: (key: string, now?: number) => void,
 *   reset: (key: string) => void,
 *   size: () => number,
 * }}
 */
export function createLoginThrottle(options = {}) {
  const {
    maxAttempts = ADMIN_LOGIN_MAX_ATTEMPTS,
    windowSeconds = ADMIN_LOGIN_WINDOW_SECONDS,
    maxEntries = ADMIN_THROTTLE_MAX_ENTRIES,
  } = options;
  const windowMs = windowSeconds * 1000;

  /** @type {Map<string, { count: number, windowStart: number }>} */
  const entries = new Map();

  /** @param {number} now */
  function pruneExpired(now) {
    for (const [key, entry] of entries) {
      if (now - entry.windowStart >= windowMs) {
        entries.delete(key);
      }
    }
  }

  return {
    isLocked(key, now = Date.now()) {
      pruneExpired(now);
      const entry = entries.get(key);
      return entry !== undefined && entry.count >= maxAttempts;
    },

    recordFailure(key, now = Date.now()) {
      pruneExpired(now);
      let entry = entries.get(key);
      if (!entry) {
        // Map insertion order tracks arrival order, which doubles as the
        // eviction order below — no separate LRU bookkeeping needed for a
        // bound that only exists as a coarse memory-exhaustion guard.
        entry = { count: 0, windowStart: now };
        entries.set(key, entry);
        if (entries.size > maxEntries) {
          const oldestKey = entries.keys().next().value;
          if (oldestKey !== undefined) {
            entries.delete(oldestKey);
          }
        }
      }
      entry.count += 1;
    },

    reset(key) {
      entries.delete(key);
    },

    size() {
      return entries.size;
    },
  };
}
