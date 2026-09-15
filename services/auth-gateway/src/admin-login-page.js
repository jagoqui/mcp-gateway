import { escapeHtml, renderDocument } from './html.js';
import { sanitizeNext } from './login-page.js';

/**
 * Renders the zero-JavaScript /admin/login page — mirrors login-page.js's
 * renderLoginPage exactly, reusing the same sanitizeNext (never a second
 * copy of that open-redirect guard), just posting to /admin/login and
 * issuing the admin session instead of the regular one.
 * @param {{ next?: unknown, error?: string, username?: unknown }} [options]
 * @returns {string}
 */
export function renderAdminLoginPage({ next, error, username } = {}) {
  const safeNext = sanitizeNext(next);
  const errorMarkup = error ? `<p class="error">${escapeHtml(error)}</p>` : '';
  const body = `<main>
  <h1>Admin sign in</h1>
  ${errorMarkup}
  <form method="post" action="/admin/login">
    <input type="hidden" name="next" value="${escapeHtml(safeNext)}">
    <label>Email <input type="text" name="username" value="${escapeHtml(username ?? '')}" required autofocus autocomplete="username"></label>
    <label>Password <input type="password" name="password" required autocomplete="current-password"></label>
    <button type="submit">Sign in</button>
  </form>
</main>`;
  return renderDocument({ title: 'Admin sign in', body });
}
