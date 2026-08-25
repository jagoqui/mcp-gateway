import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { openDb } from './db.js';
import { decideVerify } from './verify.js';
import { getSessionSecret } from './session.js';

const DEFAULT_PORT = 3000;
const DEFAULT_DOMAIN = 'jagoqui.tech';
const DEFAULT_DB_PATH = '/data/auth-gateway.sqlite';

/**
 * @param {{ domain?: string, sessionSecret?: string }} appConfig
 * @returns {{ domain: string, sessionSecret: string }}
 */
function resolveConfig(appConfig) {
  return {
    domain: appConfig.domain || process.env.DOMAIN || DEFAULT_DOMAIN,
    // Read lazily (never cached) so the secret can rotate without a
    // restart, matching crypto.js's getKey()/getSessionSecret() pattern.
    sessionSecret: appConfig.sessionSecret ?? getSessionSecret(),
  };
}

/**
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string, sessionSecret: string }} config
 */
function handleVerify(req, res, db, config) {
  const decision = decideVerify(
    db,
    {
      authorization: req.headers.authorization,
      cookie: req.headers.cookie,
      accept: req.headers.accept,
      forwardedUri: /** @type {string | undefined} */ (req.headers['x-forwarded-uri']),
    },
    config,
  );

  for (const [key, value] of Object.entries(decision.headers)) {
    res.setHeader(key, value);
  }

  if (decision.body !== undefined) {
    const json = JSON.stringify(decision.body);
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(decision.status);
    res.end(json);
    return;
  }

  res.writeHead(decision.status);
  res.end();
}

/**
 * Creates the auth-gateway request listener (a plain node:http handler —
 * no framework dependency needed for this small, ~4-route surface).
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain?: string, sessionSecret?: string }} [appConfig]
 * @returns {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void}
 */
export function createApp(db, appConfig = {}) {
  return function requestListener(req, res) {
    const url = new URL(req.url ?? '/', 'http://internal');
    const { pathname } = url;

    if (req.method === 'GET' && pathname === '/verify') {
      handleVerify(req, res, db, resolveConfig(appConfig));
      return;
    }

    res.writeHead(404);
    res.end();
  };
}

/**
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain?: string, sessionSecret?: string }} [appConfig]
 * @returns {import('node:http').Server}
 */
export function createServer(db, appConfig = {}) {
  return http.createServer(createApp(db, appConfig));
}

function main() {
  const db = openDb(process.env.AUTH_GATEWAY_DB_PATH || DEFAULT_DB_PATH);
  const server = createServer(db, {});
  const port = Number(process.env.PORT) || DEFAULT_PORT;
  server.listen(port, () => {
    console.log(`auth-gateway listening on :${port}`);
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
