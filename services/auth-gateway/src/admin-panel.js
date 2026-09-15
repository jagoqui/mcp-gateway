import { escapeHtml, renderDocument } from './html.js';

/**
 * Allow-list of `?error=` codes the admin users page will render a banner
 * for — the reflected-XSS guard (A13), mirroring panel.js's PANEL_ERRORS:
 * an unrecognized `errorCode` renders no banner at all, the raw query value
 * is never echoed into the page.
 * @type {Readonly<Record<string, string>>}
 */
export const ADMIN_PANEL_ERRORS = Object.freeze({
  invalid: 'Enter a username and password.',
  duplicate: 'That username is already taken.',
  csrf: 'Your page expired. Reload and try again.',
});

/**
 * One row of the users table. `active_token_count`/`revoked_token_count`
 * are SQL-aggregated integers (listManagedUsers), never user input, so they
 * are interpolated directly — only `username` goes through escapeHtml
 * (A12: stored XSS via a malicious username).
 * @param {{ username: string, disabled_at: string | null, active_token_count: number, revoked_token_count: number }} user
 * @returns {string}
 */
function renderUserRow(user) {
  const badge = user.disabled_at ? 'disabled' : 'active';
  return `<tr>
    <td>${escapeHtml(user.username)}</td>
    <td><span class="badge">${badge}</span></td>
    <td>${user.active_token_count}</td>
    <td>${user.revoked_token_count}</td>
  </tr>`;
}

/**
 * Renders the zero-JavaScript `/admin/users` page: the regular-user list
 * with a token-count summary, plus the create-user form. `isAdmin` is
 * never a field on this form (design.md's Create a Regular User
 * requirement) — the handler that posts here forces is_admin=0
 * unconditionally, so there is nothing here for a submitted body field to
 * override even if one were added.
 * @param {{
 *   users: Array<{ id: number, username: string, created_at: string, disabled_at: string | null, active_token_count: number, revoked_token_count: number }>,
 *   csrfToken: string,
 *   errorCode?: string | null,
 * }} options
 * @returns {string}
 */
export function renderUsersPage({ users, csrfToken, errorCode }) {
  const errorMessage =
    errorCode && Object.prototype.hasOwnProperty.call(ADMIN_PANEL_ERRORS, errorCode)
      ? ADMIN_PANEL_ERRORS[errorCode]
      : null;
  const errorMarkup = errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : '';
  const rows = users.map(renderUserRow).join('\n');
  const body = `<main>
  <h1>Users</h1>
  ${errorMarkup}
  <table>
    <thead>
      <tr><th>Username</th><th>Status</th><th>Active tokens</th><th>Revoked tokens</th></tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
  <h2>Create user</h2>
  <form method="post" action="/admin/users">
    <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
    <label>Username <input type="text" name="username" required autofocus autocomplete="off"></label>
    <label>Password <input type="password" name="password" required autocomplete="new-password"></label>
    <button type="submit">Create user</button>
  </form>
</main>`;
  return renderDocument({ title: 'Admin — Users', body });
}
