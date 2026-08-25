import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { openDb } from './db.js';
import { decideVerify, authenticate } from './verify.js';
import { getSessionSecret, createSessionToken, serializeSessionCookie } from './session.js';
import { verifyPassword } from './tokens.js';
import { encrypt } from './crypto.js';

const DEFAULT_PORT = 3000;
const DEFAULT_DOMAIN = 'jagoqui.tech';
const DEFAULT_DB_PATH = '/data/auth-gateway.sqlite';
const MAX_REQUEST_BODY_BYTES = 64 * 1024;

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
  let decision;
  try {
    decision = decideVerify(
      db,
      {
        authorization: req.headers.authorization,
        cookie: req.headers.cookie,
        accept: req.headers.accept,
        forwardedUri: /** @type {string | undefined} */ (req.headers['x-forwarded-uri']),
      },
      config,
    );
  } catch {
    // e.g. a mis-configured ATLASSIAN_ENC_KEY blowing up decrypt() —
    // never let that leak into an unauthenticated 5xx-with-body response.
    sendJson(res, 500, { error: 'internal_error' });
    return;
  }

  for (const [key, value] of Object.entries(decision.headers)) {
    res.setHeader(key, value);
  }

  if (decision.body !== undefined) {
    sendJson(res, decision.status, decision.body);
    return;
  }

  res.writeHead(decision.status);
  res.end();
}

/**
 * Reads and parses a JSON request body, capped at MAX_REQUEST_BODY_BYTES.
 * Rejects on oversized, unreadable, or malformed-JSON input.
 * @param {import('node:http').IncomingMessage} req
 * @returns {Promise<any>}
 */
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    /** @type {Buffer[]} */
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_REQUEST_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {unknown} body
 */
function sendJson(res, status, body) {
  const json = JSON.stringify(body);
  res.setHeader('Content-Type', 'application/json');
  res.writeHead(status);
  res.end(json);
}

/**
 * POST /login — validates username/password and, on success, issues a
 * signed HttpOnly session cookie. Case-insensitive username lookup matches
 * users.username's COLLATE NOCASE.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string, sessionSecret: string }} config
 */
async function handleLogin(req, res, db, config) {
  /** @type {any} */
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  const { username, password } = body ?? {};
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  const user = /** @type {any} */ (
    db.prepare('SELECT * FROM users WHERE username = ?').get(username)
  );
  const validPassword = user ? await verifyPassword(password, user.password_hash) : false;

  if (!user || user.disabled_at || !validPassword) {
    sendJson(res, 401, { error: 'invalid_credentials' });
    return;
  }

  const token = createSessionToken({ uid: user.id }, config.sessionSecret);
  res.setHeader('Set-Cookie', serializeSessionCookie(token));
  sendJson(res, 200, { ok: true });
}

/**
 * POST /me/atlassian — an authenticated route (same Bearer/cookie check as
 * /verify) that encrypts and upserts the caller's Atlassian credential.
 * Identity is always taken from the authenticated session, never from the
 * request body, so a client can never write another user's credential row.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string, sessionSecret: string }} config
 */
async function handleEnrollAtlassian(req, res, db, config) {
  const user = authenticate(
    db,
    { authorization: req.headers.authorization, cookie: req.headers.cookie },
    config.sessionSecret,
  );
  if (!user) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }

  /** @type {any} */
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  const { token, scheme, cloudId } = body ?? {};
  if (typeof token !== 'string' || !token || typeof scheme !== 'string' || !scheme) {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  const ciphertext = encrypt(token);
  db.prepare(
    `INSERT INTO atlassian_credentials (user_id, scheme, ciphertext, cloud_id, updated_at)
     VALUES (?, ?, ?, ?, datetime('now'))
     ON CONFLICT(user_id) DO UPDATE SET
       scheme = excluded.scheme,
       ciphertext = excluded.ciphertext,
       cloud_id = excluded.cloud_id,
       updated_at = excluded.updated_at`,
  ).run(user.id, scheme, ciphertext, typeof cloudId === 'string' ? cloudId : null);

  sendJson(res, 200, { ok: true });
}

/**
 * Runs an async route handler, converting any uncaught rejection into a
 * generic 500 response instead of letting it crash the process. Shared by
 * every POST route so each handler only needs to worry about its own
 * expected failure modes (400/401/etc).
 * @param {Promise<void>} handlerPromise
 * @param {import('node:http').ServerResponse} res
 */
function runAsyncHandler(handlerPromise, res) {
  handlerPromise.catch(() => {
    if (!res.headersSent) {
      sendJson(res, 500, { error: 'internal_error' });
    }
  });
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

    if (req.method === 'POST' && pathname === '/login') {
      runAsyncHandler(handleLogin(req, res, db, resolveConfig(appConfig)), res);
      return;
    }

    if (req.method === 'POST' && pathname === '/me/atlassian') {
      runAsyncHandler(handleEnrollAtlassian(req, res, db, resolveConfig(appConfig)), res);
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
