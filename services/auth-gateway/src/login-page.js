import { escapeHtml, renderDocument } from './html.js';

/**
 * Accepts only a value starting with a single '/' that is neither '//' nor
 * '/\\' (protocol-relative and backslash open-redirect bypasses, threat
 * matrix R1). Anything else — including a value that parses as an absolute
 * URL such as 'https://evil.example' (which does not start with '/' at
 * all) — falls back to '/credentials'. Rejects any embedded ASCII tab,
 * carriage return, or line feed outright: the WHATWG URL parser strips
 * those characters before scheme/host resolution, so a value like
 * '/\t/evil.example' would otherwise pass this prefix check unmodified and
 * be re-parsed by the browser as the protocol-relative '//evil.example'.
 * @param {unknown} raw
 * @returns {string}
 */
export function sanitizeNext(raw) {
  if (typeof raw !== 'string' || raw.length === 0) {
    return '/credentials';
  }
  if (/[\t\r\n]/.test(raw)) {
    return '/credentials';
  }
  if (!raw.startsWith('/')) {
    return '/credentials';
  }
  if (raw.startsWith('//') || raw.startsWith('/\\')) {
    return '/credentials';
  }
  return raw;
}

/**
 * Renders the zero-JavaScript /login page (design.md D4/D5). `next` is
 * always run through sanitizeNext before being embedded, regardless of
 * whether the caller already sanitized it — defense in depth for R1.
 * `error`, when present, is rendered as the generic failure message; the
 * password field is never pre-filled (a submitted password is never
 * echoed back).
 * @param {{ next?: unknown, error?: string, username?: unknown }} options
 * @returns {string}
 */
export function renderLoginPage({ next, error, username } = {}) {
  const safeNext = sanitizeNext(next);
  const errorMarkup = error ? `<p class="error">${escapeHtml(error)}</p>` : '';
  const body = `<main>
  <h1>Sign in</h1>
  ${errorMarkup}
  <form method="post" action="/login">
    <input type="hidden" name="next" value="${escapeHtml(safeNext)}">
    <label>Username <input type="text" name="username" value="${escapeHtml(username ?? '')}" required autofocus autocomplete="username"></label>
    <label>Password <input type="password" name="password" required autocomplete="current-password"></label>
    <button type="submit">Sign in</button>
  </form>
</main>`;
  return renderDocument({ title: 'Sign in', body });
}
