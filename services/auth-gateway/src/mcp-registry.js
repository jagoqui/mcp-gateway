/**
 * Static, capability-honest inventory of every MCP service the gateway
 * proxies to. There is no database table backing this: it is a frozen
 * constant so the credential panel can only ever render what is actually
 * true about each MCP's credential model.
 *
 * Only `mcp-atlassian` reads a per-request `Authorization` header — it is
 * the only entry with `perUserCredentials: true`. `mcp-context7` is a
 * `supergateway --stdio` wrapper that reads a shared secret once at boot;
 * there is no incoming-header -> child-process injection path, so per-user
 * credentials cannot work for it (see proposal.md's Capability honesty
 * section). `engram` is a third, distinct shape: no credential to
 * configure at all — `engram-router` isolates each user automatically by
 * their gateway identity (see openspec/changes/engram-remote-mcp).
 * `sharedSecretEnv` is therefore optional on a `perUserCredentials: false`
 * entry, not a universal requirement of that shape.
 *
 * `test/mcp-registry.test.js` asserts every `mcp-*` service declared in
 * the repo-root `docker-compose.yml` has exactly one matching entry here
 * (drift guard), so this list MUST be kept in sync with compose.
 * @type {ReadonlyArray<Readonly<{
 *   id: string,
 *   label: string,
 *   route: string,
 *   composeService: string,
 *   perUserCredentials: boolean,
 *   sharedSecretEnv?: string,
 *   note?: string,
 * }>>}
 */
export const MCP_REGISTRY = Object.freeze([
  Object.freeze({
    id: 'atlassian',
    label: 'Atlassian (Jira / Confluence)',
    route: '/mcp/atlassian',
    composeService: 'mcp-atlassian',
    perUserCredentials: true,
  }),
  Object.freeze({
    id: 'context7',
    label: 'Context7',
    route: '/mcp/context7',
    composeService: 'mcp-context7',
    perUserCredentials: false,
    sharedSecretEnv: 'CONTEXT7_API_KEY',
    note:
      'Shared team credential — configured by an admin, not per-user. ' +
      'supergateway --stdio reads it once at boot; there is no incoming-header ' +
      'to child-process injection path, so per-user credentials cannot work here.',
  }),
  Object.freeze({
    id: 'engram',
    label: 'Engram',
    route: '/mcp/engram',
    composeService: 'engram-router',
    perUserCredentials: false,
    note:
      'No credential to configure — engram-router automatically isolates ' +
      'your memories into your own project, derived from your gateway ' +
      'identity. Nothing to enroll, nothing shared with other users.',
  }),
]);

/**
 * @param {string} id
 * @returns {typeof MCP_REGISTRY[number] | undefined}
 */
export function getMcp(id) {
  return MCP_REGISTRY.find((entry) => entry.id === id);
}
