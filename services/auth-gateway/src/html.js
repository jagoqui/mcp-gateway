/**
 * HTML rendering primitives shared by the zero-JavaScript /login and
 * /credentials pages (design.md D4). Every interpolated value MUST go
 * through escapeHtml — cloudId in particular is fully attacker-controlled
 * via POST /me/atlassian (threat matrix R6).
 */

/** @type {Record<string, string>} */
const HTML_ESCAPE_MAP = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/**
 * Escapes &, <, >, ", and ' so an interpolated value can never break out of
 * HTML text/attribute context or introduce a live tag (R6). null/undefined
 * become '' rather than the literal string "null"/"undefined".
 * @param {unknown} value
 * @returns {string}
 */
export function escapeHtml(value) {
  if (value === null || value === undefined) {
    return '';
  }
  return String(value).replace(/[&<>"']/g, (char) => HTML_ESCAPE_MAP[char]);
}

/** Single shared inline stylesheet for both rendered pages (design.md). */
const SHARED_STYLE = `
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1rem;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:44rem;margin:0 auto}
h1{font-size:1.5rem;margin:0 0 .25rem}
.who{margin:0 0 2rem;opacity:.7}
.mcp{border:1px solid currentColor;border-radius:8px;padding:1rem 1.25rem;margin-bottom:1rem}
.mcp h2{font-size:1.1rem;margin:0 0 .5rem}
.state{font-size:.9rem;opacity:.75;margin:0 0 1rem}
.badge{display:inline-block;font-size:.75rem;padding:.1rem .5rem;border:1px solid currentColor;border-radius:999px;vertical-align:.1em}
label{display:block;margin:0 0 .75rem;font-size:.9rem}
input{display:block;width:100%;margin-top:.25rem;padding:.5rem;font:inherit;border:1px solid currentColor;border-radius:4px;background:transparent;color:inherit}
button{font:inherit;padding:.5rem 1rem;border-radius:4px;border:1px solid currentColor;background:transparent;color:inherit;cursor:pointer}
.danger{margin-top:.75rem;opacity:.8}
.error{border:1px solid currentColor;padding:.5rem .75rem;border-radius:4px;margin:0 0 1rem}
.note{margin:0;font-size:.9rem;opacity:.75}
.nav{display:flex;flex-wrap:wrap;align-items:center;gap:1rem;margin:0 0 1.5rem;font-size:.9rem}
.nav form{margin:0}
.nav button{padding:.25rem .75rem}
.shell{display:grid;grid-template-columns:10rem 1fr;grid-template-rows:auto 1fr;gap:1rem;max-width:none}
.shell-header{grid-column:1 / -1;display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:.5rem}
.shell-header form{margin:0}
.shell-sidebar{display:flex;flex-direction:column;gap:.5rem;font-size:.9rem}
.shell-sidebar a{padding:.25rem .5rem;border-radius:4px;text-decoration:none;color:inherit}
.shell-sidebar a.active{border:1px solid currentColor}
.shell-main{max-width:none;margin:0}
.shell-main iframe{width:100%;height:80vh;border:1px solid currentColor;border-radius:8px}
.table-wrap{width:100%;overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{padding:.4rem .6rem;text-align:left;white-space:nowrap}
@media (max-width:640px){
  body{padding:1.25rem .75rem}
  .shell{grid-template-columns:1fr;grid-template-rows:auto auto 1fr}
  .shell-sidebar{flex-direction:row;flex-wrap:wrap}
  .shell-main iframe{height:70vh}
}
`.trim();

/**
 * Wraps a page's body markup in the shared no-JS HTML document shell:
 * doctype, charset/viewport meta, and the single inline <style>. `title`
 * and `body` are the caller's responsibility to have already escaped where
 * needed — this function does not escape anything itself.
 * @param {{ title: string, body: string }} options
 * @returns {string}
 */
export function renderDocument({ title, body }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>${SHARED_STYLE}</style>
</head>
<body>
${body}
</body>
</html>`;
}

/**
 * Response headers shared by every rendered HTML page (design.md D4, R10).
 * No <script> exists anywhere in these pages, so the CSP can be maximally
 * strict. Cache-Control: no-store matters because /credentials embeds a
 * CSRF token in the body.
 * @type {Record<string, string>}
 */
export const PAGE_HEADERS = Object.freeze({
  'Content-Type': 'text/html; charset=utf-8',
  'Content-Security-Policy':
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
});

/**
 * PAGE_HEADERS plus Referrer-Policy: no-referrer (design.md's File Changes
 * table) for every rendered admin panel page (GET /admin/login,
 * GET /admin/users, GET /admin/users/tokens) — a stricter default than the
 * regular panel needs, since admin URLs are the highest-value surface to
 * avoid leaking via Referer to any third party a link is ever pasted into.
 * @type {Record<string, string>}
 */
export const ADMIN_PAGE_HEADERS = Object.freeze({
  ...PAGE_HEADERS,
  // same-origin, not no-referrer (found live, 2026-09-16, via a broken
  // logout button): no-referrer made Chrome send Origin: null on THIS
  // page's own top-level form POSTs (logout, create-user, grants,
  // tokens...), which the strict Origin/Referer CSRF check then rejects —
  // the same Chromium quirk already fixed on the login page. same-origin
  // still sends Referer to this same host (keeping that check working)
  // while never leaking it to a third party a URL is pasted into.
  'Referrer-Policy': 'same-origin',
});

/**
 * ADMIN_PAGE_HEADERS plus `frame-src 'self'` — ONLY the console shell page
 * (Phase 5, GET /admin/console) needs this: it is the sole page in this app
 * that embeds an `<iframe>`. Every other admin page keeps the stricter
 * `default-src 'none'` (no framing directive at all, which blocks any
 * frame). `'self'` is sufficient (not a specific origin) since both framed
 * targets — /monitor and /admin/engram-cloud/sso — are same-origin paths on
 * this same host.
 * @type {Record<string, string>}
 */
export const CONSOLE_PAGE_HEADERS = Object.freeze({
  ...ADMIN_PAGE_HEADERS,
  'Content-Security-Policy': `${ADMIN_PAGE_HEADERS['Content-Security-Policy']}; frame-src 'self'`,
});
