import { createServer } from '../src/app.js';
import { startEngramServe } from '../src/spawn.js';

const DEFAULT_PORT = 7437;
const DEFAULT_BACKEND_PORT = 17437;

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

async function main() {
  const backendPort = Number(process.env.ENGRAM_SERVE_PORT) || DEFAULT_BACKEND_PORT;

  await startEngramServe({
    port: backendPort,
    env: {
      // No ENGRAM_PROJECT — engram serve is multi-project here, unlike
      // engram-router's per-identity children.
      ENGRAM_CLOUD_AUTOSYNC: '1',
      // Same legacy wildcard token engram-router uses — see design.md's
      // rationale. Never logged.
      ENGRAM_CLOUD_TOKEN: requiredEnv('ENGRAM_CLOUD_TOKEN'),
      ENGRAM_CLOUD_SERVER: process.env.ENGRAM_CLOUD_SERVER || 'http://engram-cloud:18080',
    },
  });

  const server = createServer(() => backendPort);
  const port = Number(process.env.PORT) || DEFAULT_PORT;
  server.listen(port, () => {
    console.log(`engram-serve-bridge listening on :${port}, proxying to 127.0.0.1:${backendPort}`);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
