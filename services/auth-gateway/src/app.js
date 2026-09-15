import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { openDb } from './db.js';
import { handleAdminRequest } from './admin-app.js';
import { decideVerify, authenticate, authenticateWithMethod, wantsHtml } from './verify.js';
import { getSessionSecret, createSessionToken, serializeSessionCookie } from './session.js';
import { verifyPassword } from './tokens.js';
import { encrypt } from './crypto.js';
import { buildCredentialStatus } from './credential-status.js';
import { verifyCsrfToken, issueCsrfToken, isAcceptableOrigin } from './csrf.js';
import { PAGE_HEADERS } from './html.js';
import { renderLoginPage, sanitizeNext } from './login-page.js';
import { renderPanel } from './panel.js';

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
 * Reads and parses a request body as either JSON or
 * application/x-www-form-urlencoded, capped at MAX_REQUEST_BODY_BYTES (D4).
 * `isForm` is the unambiguous browser-form signal driving response mode on
 * write routes — a JSON API client sending an urlencoded body never happens
 * by accident, so this flag (not the Accept header) is what must decide
 * 200-JSON vs 302-redirect on those routes.
 * @param {import('node:http').IncomingMessage} req
 * @returns {Promise<{ isForm: boolean, data: Record<string, any> }>}
 */
function readBody(req) {
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
      const contentType = /** @type {string} */ (req.headers['content-type'] || '');
      const isForm = contentType.startsWith('application/x-www-form-urlencoded');
      if (isForm) {
        resolve({ isForm: true, data: Object.fromEntries(new URLSearchParams(raw)) });
        return;
      }
      if (!raw) {
        resolve({ isForm: false, data: {} });
        return;
      }
      try {
        resolve({ isForm: false, data: JSON.parse(raw) });
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
 * GET /login — serves the zero-JS login form (design.md D4). Not gated by
 * Caddy's forward_auth (verified against Caddyfile:57-61 in design.md), so
 * this route must render for a fully unauthenticated browser.
 * @param {import('node:http').ServerResponse} res
 * @param {URL} url
 */
function handleGetLogin(res, url) {
  const next = url.searchParams.get('next');
  res.writeHead(200, PAGE_HEADERS);
  res.end(renderLoginPage({ next }));
}

/**
 * Re-renders the login page as a failure response (design.md
 * "Failure rendering"): same PAGE_HEADERS as GET /login, the generic error
 * message, the submitted username preserved (escaped), and the password
 * field always left empty — a submitted password is never echoed back.
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {{ next?: unknown, username?: unknown, error: string }} options
 */
function sendLoginFailure(res, status, { next, username, error }) {
  res.writeHead(status, PAGE_HEADERS);
  res.end(renderLoginPage({ next, error, username }));
}

/**
 * POST /login — validates username/password and, on success, issues a
 * signed HttpOnly session cookie. Case-insensitive username lookup matches
 * users.username's COLLATE NOCASE. Accepts both application/json and
 * application/x-www-form-urlencoded bodies (D4); response mode is driven
 * by `isForm`, never by the Accept header, so every existing JSON caller
 * keeps its exact JSON response shape.
 *
 * Login CSRF (R5/D5): an Origin/Referer mismatch is rejected with 403, but
 * an absent Origin/Referer is allowed — unlike the stricter cookie-write
 * guard, a pre-session request has no token to bind to, and CLI/curl login
 * carries neither header.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string, sessionSecret: string }} config
 */
async function handleLogin(req, res, db, config) {
  // Served at auth.{$DOMAIN} (Caddyfile), never the apex — the expected
  // Origin/Referer host must match where the form actually posts from.
  const originOk = isAcceptableOrigin(
    { origin: req.headers.origin, referer: req.headers.referer },
    { domain: `auth.${config.domain}`, strict: false },
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  const { isForm, data } = body;
  const { username, password, next } = data ?? {};

  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    if (isForm) {
      sendLoginFailure(res, 400, { next, username, error: 'Invalid username or password.' });
      return;
    }
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  const user = /** @type {any} */ (
    db.prepare('SELECT * FROM users WHERE username = ?').get(username)
  );
  const validPassword = user ? await verifyPassword(password, user.password_hash) : false;

  if (!user || user.disabled_at || !validPassword) {
    if (isForm) {
      sendLoginFailure(res, 401, { next, username, error: 'Invalid username or password.' });
      return;
    }
    sendJson(res, 401, { error: 'invalid_credentials' });
    return;
  }

  const token = createSessionToken({ uid: user.id }, config.sessionSecret);
  res.setHeader('Set-Cookie', serializeSessionCookie(token));

  if (isForm) {
    res.writeHead(302, { Location: sanitizeNext(next) });
    res.end();
    return;
  }

  sendJson(res, 200, { ok: true });
}

/**
 * Steps 1-2 of the cookie-write CSRF guard (design.md "Cookie-write guard
 * order"): authenticate via Bearer/cookie, reporting HOW the request
 * authenticated (D2) rather than sniffing header presence — a garbage
 * Bearer header alongside a valid cookie must still be treated as 'cookie'
 * (R4), or CSRF enforcement below would be silently skippable. For cookie
 * auth only, reject a mismatched OR absent Origin/Referer (R2/D7) BEFORE any
 * body is read, so the cheap reject always fires first for a real
 * cross-site attempt. Bearer auth skips the Origin check entirely — CLI
 * callers are unaffected.
 *
 * Sends the 401/403 response itself and returns `null` on rejection;
 * callers MUST stop immediately when this returns `null`.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string, sessionSecret: string }} config
 * @returns {{ user: any, method: 'bearer' | 'cookie' } | null}
 */
function authenticateCookieWrite(req, res, db, config) {
  const authResult = authenticateWithMethod(
    db,
    { authorization: req.headers.authorization, cookie: req.headers.cookie },
    config.sessionSecret,
  );
  if (!authResult) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return null;
  }
  if (authResult.method === 'cookie') {
    // Same auth.{$DOMAIN} reasoning as handleLogin above — every
    // cookie-authenticated write this guards is served there too.
    const originOk = isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `auth.${config.domain}`, strict: true },
    );
    if (!originOk) {
      sendJson(res, 403, { error: 'csrf_origin_rejected' });
      return null;
    }
  }
  return authResult;
}

/**
 * Step 4 of the cookie-write CSRF guard: verify the CSRF token, but only
 * when auth came from the cookie — Bearer requests skip this entirely (CLI
 * is unbroken). Token transport is the `X-CSRF-Token` header first, else a
 * body `csrf` field (form posts cannot set headers; `DELETE` has no body at
 * all, so it must use the header).
 *
 * On rejection: a form submission (design.md "Cookie-write guard order",
 * step 4) redirects `302 /credentials?error=csrf` — the no-JS panel has no
 * way to show a JSON body — while every other caller gets
 * `403 {error:'csrf_token_invalid'}`. Returns `false` on rejection; callers
 * MUST stop immediately when this returns `false`.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{ user: any, method: 'bearer' | 'cookie' }} authResult
 * @param {{ sessionSecret: string }} config
 * @param {Record<string, any>} [bodyData]
 * @param {boolean} [isForm]
 * @returns {boolean}
 */
function verifyCookieWriteCsrf(req, res, authResult, config, bodyData = {}, isForm = false) {
  if (authResult.method !== 'cookie') {
    return true;
  }
  const csrfToken =
    /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? bodyData.csrf;
  const csrfOk = verifyCsrfToken(csrfToken, {
    uid: authResult.user.id,
    sessionSecret: config.sessionSecret,
  });
  if (!csrfOk) {
    if (isForm) {
      res.writeHead(302, { Location: '/credentials?error=csrf' });
      res.end();
      return false;
    }
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return false;
  }
  return true;
}

/**
 * POST /me/atlassian — an authenticated route that encrypts and upserts the
 * caller's Atlassian credential. Identity is always taken from the
 * authenticated session, never from the request body, so a client can never
 * write another user's credential row.
 *
 * Cookie-authenticated requests go through the shared 5-step CSRF guard
 * (authenticateCookieWrite + verifyCookieWriteCsrf, design.md "Cookie-write
 * guard order"), also applied to DELETE /me/atlassian below.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string, sessionSecret: string }} config
 */
async function handleEnrollAtlassian(req, res, db, config) {
  // 1-2. Authenticate + Origin check (cookie auth only), before body parsing.
  const authResult = authenticateCookieWrite(req, res, db, config);
  if (!authResult) {
    return;
  }
  const { user } = authResult;

  // 3. Parse body (form or JSON, D4).
  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  // 4. CSRF token check for cookie auth (header, else body 'csrf' field).
  // A form failure redirects (design.md "Cookie-write guard order" step 4);
  // every other caller keeps the existing JSON 403.
  if (!verifyCookieWriteCsrf(req, res, authResult, config, data, isForm)) {
    return;
  }

  // 5. Validate fields, then proceed. A form validation failure also
  // redirects rather than returning JSON — the no-JS panel has nowhere to
  // render a JSON error body (design.md open question, accepted: the token
  // field is never re-echoed anyway, so re-rendering submitted values isn't
  // possible regardless).
  const { token, scheme, cloudId } = data ?? {};
  if (typeof token !== 'string' || !token || typeof scheme !== 'string' || !scheme) {
    if (isForm) {
      res.writeHead(302, { Location: '/credentials?error=invalid' });
      res.end();
      return;
    }
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

  // Response mode is driven by isForm, not the Accept header (design.md
  // "Body parsing"): the no-JS panel submits a plain form and expects a
  // redirect back to itself; every existing JSON caller is unaffected.
  if (isForm) {
    res.writeHead(302, { Location: '/credentials' });
    res.end();
    return;
  }
  sendJson(res, 200, { ok: true });
}

/**
 * DELETE /me/atlassian — an authenticated route that clears the caller's own
 * Atlassian credential row. Created directly with the shared CSRF guard
 * already applied (proposal.md's In Scope list) — there is no unguarded
 * intermediate state for this route. Has no request body: `DELETE` cannot
 * carry a form body, so the CSRF token MUST arrive via the `X-CSRF-Token`
 * header (enforced by verifyCookieWriteCsrf's header-first lookup).
 *
 * This is an async function specifically so it goes through
 * runAsyncHandler()'s catch — a synchronous throw from the DB delete below
 * (e.g. a corrupted database file) becomes a rejected promise instead of an
 * uncaught synchronous exception that would crash the whole process
 * (mirroring Unit 2's handleCredentialStatus fix and handleVerify's
 * precedent).
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string, sessionSecret: string }} config
 */
async function handleDeleteAtlassian(req, res, db, config) {
  // 1-2. Authenticate + Origin check (cookie auth only).
  const authResult = authenticateCookieWrite(req, res, db, config);
  if (!authResult) {
    return;
  }
  const { user } = authResult;

  // 4. CSRF token check for cookie auth: header transport only (no body —
  // DELETE cannot carry a form body).
  if (!verifyCookieWriteCsrf(req, res, authResult, config)) {
    return;
  }

  // 5. Delete only the caller's own row — identity always comes from the
  // authenticated session, never from client input.
  db.prepare('DELETE FROM atlassian_credentials WHERE user_id = ?').run(user.id);

  sendJson(res, 200, { ok: true });
}

/**
 * POST /me/atlassian/delete — the no-JS panel's form-reachable equivalent of
 * DELETE /me/atlassian above (design.md D4: plain `<form method="post">`
 * cannot send a DELETE request). Runs the exact same 5-step cookie-write
 * guard end-to-end; only the body transport (form field vs. header-only) and
 * the success/CSRF-failure response shape (302 redirect back to the panel,
 * not JSON) differ from DELETE /me/atlassian.
 *
 * Async and routed through runAsyncHandler for the same reason as
 * handleDeleteAtlassian: a synchronous DB throw becomes a rejected promise
 * instead of an uncaught exception that would crash the process.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string, sessionSecret: string }} config
 */
async function handleDeleteAtlassianForm(req, res, db, config) {
  // 1-2. Authenticate + Origin check (cookie auth only).
  const authResult = authenticateCookieWrite(req, res, db, config);
  if (!authResult) {
    return;
  }
  const { user } = authResult;

  // 3. Parse body (form 'csrf' field; DELETE /me/atlassian above is the
  // header-only equivalent for non-browser clients).
  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  // 4. CSRF token check for cookie auth: a form failure redirects back to
  // the panel with an error banner.
  if (!verifyCookieWriteCsrf(req, res, authResult, config, data, isForm)) {
    return;
  }

  // 5. Delete only the caller's own row — identity always comes from the
  // authenticated session, never from client input.
  db.prepare('DELETE FROM atlassian_credentials WHERE user_id = ?').run(user.id);

  if (isForm) {
    res.writeHead(302, { Location: '/credentials' });
    res.end();
    return;
  }
  sendJson(res, 200, { ok: true });
}

/**
 * GET /me/credentials — an authenticated route (same Bearer/cookie check as
 * /me/atlassian) that returns the caller's per-MCP credential status.
 * Delegates the DB->response projection to buildCredentialStatus(), which
 * enforces the credential-material disclosure limit (R8) via an explicit
 * column SELECT.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string, sessionSecret: string }} config
 */
function handleCredentialStatus(req, res, db, config) {
  const user = authenticate(
    db,
    { authorization: req.headers.authorization, cookie: req.headers.cookie },
    config.sessionSecret,
  );
  if (!user) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }

  /** @type {ReturnType<typeof buildCredentialStatus>} */
  let status;
  try {
    status = buildCredentialStatus(db, user);
  } catch {
    // Mirrors handleVerify's guard: a DB-layer failure here must never
    // propagate as an uncaught synchronous throw and crash the process.
    sendJson(res, 500, { error: 'internal_error' });
    return;
  }
  sendJson(res, 200, status);
}

/**
 * GET /credentials — the zero-JavaScript credential admin panel
 * (design.md D4). Caddy's `forward_auth` normally redirects an
 * unauthenticated browser before this route is ever reached; the in-route
 * check below is defense-in-depth and is what makes this route testable
 * without Caddy. An unauthenticated `Accept: text/html` request redirects
 * *relatively* to `/login?next=%2Fcredentials` (same-origin by
 * construction, and it works over `http://127.0.0.1:<port>` in tests) —
 * deliberately not the absolute `https://auth.{domain}/login?...` that
 * decideVerify() uses. Every other unauthenticated request gets a plain
 * `401` JSON body, matching every other authenticated route in this file.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string, sessionSecret: string }} config
 * @param {URL} url
 */
function handleCredentialsPanel(req, res, db, config, url) {
  const user = authenticate(
    db,
    { authorization: req.headers.authorization, cookie: req.headers.cookie },
    config.sessionSecret,
  );
  if (!user) {
    if (wantsHtml(req.headers.accept)) {
      res.writeHead(302, { Location: '/login?next=%2Fcredentials' });
      res.end();
      return;
    }
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }

  /** @type {ReturnType<typeof buildCredentialStatus>} */
  let status;
  try {
    status = buildCredentialStatus(db, user);
  } catch {
    // Mirrors handleCredentialStatus's guard: a DB-layer failure here must
    // never propagate as an uncaught synchronous throw and crash the
    // process.
    sendJson(res, 500, { error: 'internal_error' });
    return;
  }

  const csrfToken = issueCsrfToken(user.id, config.sessionSecret);
  const errorCode = url.searchParams.get('error');
  res.writeHead(200, PAGE_HEADERS);
  res.end(renderPanel({ status, csrfToken, errorCode }));
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

    // resolveConfig() can throw synchronously (e.g. AUTH_GATEWAY_SESSION_SECRET
    // unset) — this try/catch is the ONLY thing standing between that throw
    // and an uncaught exception crashing the whole process, since it happens
    // before handleVerify's own try/catch or handleLogin/handleEnrollAtlassian's
    // runAsyncHandler(...).catch() ever run. Every route goes through here.
    /** @type {{ domain: string, sessionSecret: string } | undefined} */
    let config;
    try {
      config = resolveConfig(appConfig);
    } catch {
      sendJson(res, 500, { error: 'internal_error' });
      return;
    }

    if (req.method === 'GET' && pathname === '/verify') {
      handleVerify(req, res, db, config);
      return;
    }

    if (req.method === 'GET' && pathname === '/login') {
      handleGetLogin(res, url);
      return;
    }

    if (req.method === 'POST' && pathname === '/login') {
      runAsyncHandler(handleLogin(req, res, db, config), res);
      return;
    }

    if (req.method === 'POST' && pathname === '/me/atlassian') {
      runAsyncHandler(handleEnrollAtlassian(req, res, db, config), res);
      return;
    }

    if (req.method === 'DELETE' && pathname === '/me/atlassian') {
      runAsyncHandler(handleDeleteAtlassian(req, res, db, config), res);
      return;
    }

    if (req.method === 'POST' && pathname === '/me/atlassian/delete') {
      runAsyncHandler(handleDeleteAtlassianForm(req, res, db, config), res);
      return;
    }

    if (req.method === 'GET' && pathname === '/me/credentials') {
      handleCredentialStatus(req, res, db, config);
      return;
    }

    if (req.method === 'GET' && pathname === '/credentials') {
      handleCredentialsPanel(req, res, db, config, url);
      return;
    }

    // D1: one prefix branch hands the entire /admin/* namespace to its own
    // dispatcher, keeping the two authorization models (regular
    // Bearer/cookie above vs. admin-cookie-only below) from interleaving in
    // this file. The boundary is the path prefix, never req.headers.host
    // (D2) — handleAdminRequest and authenticateAdmin never read Host.
    if (pathname === '/admin' || pathname.startsWith('/admin/')) {
      runAsyncHandler(handleAdminRequest(req, res, db, { domain: config.domain }), res);
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
