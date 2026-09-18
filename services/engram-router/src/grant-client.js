/**
 * Real HTTP-calling checkGrant (engram-shared-projects) — calls
 * auth-gateway's internal-only GET /internal/engram-grant, never routed
 * through Caddy (Docker-network-reachable only), shared-secret gated.
 * Fails closed (false) on any non-2xx response or network error: "I
 * couldn't verify the grant" must never be treated as "granted".
 * @param {{ baseUrl: string, secret: string }} opts
 * @returns {(check: { identity: string, project: string }) => Promise<boolean>}
 */
export function createGrantChecker({ baseUrl, secret }) {
  return async function checkGrant({ identity, project }) {
    const url = `${baseUrl}/internal/engram-grant?identity=${encodeURIComponent(identity)}&project=${encodeURIComponent(project)}`;
    let res;
    try {
      res = await fetch(url, { headers: { 'X-Internal-Secret': secret } });
    } catch {
      return false;
    }
    if (!res.ok) {
      return false;
    }
    let body;
    try {
      body = await res.json();
    } catch {
      return false;
    }
    return body?.granted === true;
  };
}

/**
 * Real HTTP-calling fetchIdentityToken (engram-contributor-attribution) —
 * calls auth-gateway's internal-only GET /internal/engram-cloud-token,
 * same trust boundary as createGrantChecker above (Docker-network-only,
 * shared-secret gated). Fails closed to `null` on any non-2xx response,
 * network error, or malformed JSON — UNLIKE checkGrant, `null` here is
 * safe by design: the caller (process-manager.js) treats it as "fall
 * back to the shared token", never as "deny access". Attribution
 * accuracy is a nicety, not a security boundary.
 * @param {{ baseUrl: string, secret: string }} opts
 * @returns {(opts: { identity: string }) => Promise<string | null>}
 */
export function createIdentityTokenFetcher({ baseUrl, secret }) {
  return async function fetchIdentityToken({ identity }) {
    const url = `${baseUrl}/internal/engram-cloud-token?identity=${encodeURIComponent(identity)}`;
    let res;
    try {
      res = await fetch(url, { headers: { 'X-Internal-Secret': secret } });
    } catch {
      return null;
    }
    if (!res.ok) {
      return null;
    }
    let body;
    try {
      body = await res.json();
    } catch {
      return null;
    }
    return typeof body?.token === 'string' ? body.token : null;
  };
}
