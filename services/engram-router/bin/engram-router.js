import { createServer } from '../src/app.js';
import { createProcessManager } from '../src/process-manager.js';
import { createGrantChecker } from '../src/grant-client.js';

const DEFAULT_PORT = 9000;
const DEFAULT_PORT_BASE = 19100;
const DEFAULT_MAX_CHILDREN = 20;
const DEFAULT_CLOUD_SERVER = 'http://engram-cloud:18080';
const DEFAULT_AUTH_GATEWAY_INTERNAL_URL = 'http://auth-gateway:3000';

/**
 * @param {string} name
 * @returns {string}
 */
function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set`);
  }
  return value;
}

function main() {
  const maxChildren = Number(process.env.MAX_ENGRAM_CHILDREN) || DEFAULT_MAX_CHILDREN;
  const processManager = createProcessManager({
    maxChildren,
    portAllocatorOptions: {
      base: Number(process.env.ENGRAM_ROUTER_PORT_BASE) || DEFAULT_PORT_BASE,
      max: maxChildren,
    },
    // The legacy wildcard token, not a managed principal token — see
    // proposal.md's Approach section for why. Never logged.
    cloudToken: requiredEnv('ENGRAM_CLOUD_TOKEN'),
    cloudServer: process.env.ENGRAM_CLOUD_SERVER || DEFAULT_CLOUD_SERVER,
    // engram-shared-projects: required, no silent default — a shared
    // (isShared: true) request must never be reachable with grant
    // checking unconfigured.
    checkGrant: createGrantChecker({
      baseUrl: process.env.AUTH_GATEWAY_INTERNAL_URL || DEFAULT_AUTH_GATEWAY_INTERNAL_URL,
      secret: requiredEnv('ENGRAM_ROUTER_INTERNAL_SECRET'),
    }),
  });

  const server = createServer(processManager);
  const port = Number(process.env.PORT) || DEFAULT_PORT;
  server.listen(port, () => {
    console.log(`engram-router listening on :${port}`);
  });
}

main();
