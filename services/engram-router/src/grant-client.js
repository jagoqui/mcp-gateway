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
