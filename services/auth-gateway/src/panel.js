import { escapeHtml, renderDocument } from './html.js';
import { getMcp } from './mcp-registry.js';

/**
 * Allow-list of `?error=` codes the panel will render a banner for. This is
 * the reflected-XSS guard for R7: an unrecognized `errorCode` renders no
 * banner at all — the raw query value is never echoed into the page.
 * @type {Readonly<Record<string, string>>}
 */
export const PANEL_ERRORS = Object.freeze({
  invalid: 'That credential was rejected — check the token and scheme.',
  csrf: 'Your page expired. Reload and try again.',
});

/**
 * Renders the enroll/update form plus, when currently enrolled, the delete
 * form for a `perUserCredentials: true` MCP entry (design.md's `panel.js`
 * markup contract). `cloudId` in particular is fully attacker-controlled via
 * `POST /me/atlassian` — a stored-XSS sink (R6) — so every interpolated
 * value goes through `escapeHtml`.
 * @param {import('./credential-status.js').PerUserStatus} mcp
 * @param {string} csrfToken
 * @returns {string}
 */
function renderPerUserSection(mcp, csrfToken) {
  const badge = mcp.enrolled ? 'enrolled' : 'not enrolled';
  const stateMarkup = mcp.enrolled
    ? `<p class="state">Scheme <code>${escapeHtml(mcp.scheme)}</code> · cloud <code>${escapeHtml(mcp.cloudId)}</code> · updated ${escapeHtml(mcp.updatedAt)}</p>`
    : '';
  const deleteFormMarkup = mcp.enrolled
    ? `<form method="post" action="/me/atlassian/delete" class="danger">
    <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
    <button type="submit">Remove credential</button>
  </form>`
    : '';
  return `<section class="mcp">
  <h2>${escapeHtml(mcp.label)} <span class="badge">${badge}</span></h2>
  ${stateMarkup}
  <form method="post" action="/me/atlassian">
    <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
    <label>API token <input type="password" name="token" required autocomplete="off"></label>
    <label>Scheme <input type="text" name="scheme" value="${escapeHtml(mcp.scheme ?? 'Token')}" required></label>
    <label>Cloud ID <input type="text" name="cloudId" value="${escapeHtml(mcp.cloudId ?? '')}" autocomplete="off"></label>
    <button type="submit">Save credential</button>
  </form>
  ${deleteFormMarkup}
</section>`;
}

/**
 * Renders a read-only row for a `perUserCredentials: false` MCP — no form,
 * nothing to submit, matching the capability-honesty approach in
 * proposal.md. The shared secret's env var *name* (never its value) comes
 * from the static registry, purely for display.
 * @param {import('./credential-status.js').SharedStatus} mcp
 * @returns {string}
 */
function renderSharedSection(mcp) {
  const registryEntry = getMcp(mcp.id);
  const envName = registryEntry?.sharedSecretEnv ?? 'the shared credential';
  const stateText = mcp.configured ? `${envName} is configured.` : `${envName} is not configured.`;
  return `<section class="mcp">
  <h2>${escapeHtml(mcp.label)} <span class="badge">shared credential</span></h2>
  <p class="state">${escapeHtml(stateText)}</p>
  <p class="note">${escapeHtml(mcp.note)}</p>
</section>`;
}

/**
 * Renders the zero-JavaScript `/credentials` panel (design.md D4). Every MCP
 * in `status.mcps` gets one `<section>`; per-user entries get a form (R6-safe
 * via escapeHtml), shared entries get a read-only note. `errorCode` is
 * looked up in the frozen `PANEL_ERRORS` allow-list — an unrecognized value
 * renders no banner at all (R7).
 * @param {{
 *   status: { username: string, mcps: Array<import('./credential-status.js').PerUserStatus | import('./credential-status.js').SharedStatus> },
 *   csrfToken: string,
 *   errorCode?: string | null,
 * }} options
 * @returns {string}
 */
export function renderPanel({ status, csrfToken, errorCode }) {
  const errorMessage =
    errorCode && Object.prototype.hasOwnProperty.call(PANEL_ERRORS, errorCode)
      ? PANEL_ERRORS[errorCode]
      : null;
  const errorMarkup = errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : '';
  const sections = status.mcps
    .map((mcp) =>
      mcp.perUserCredentials
        ? renderPerUserSection(/** @type {any} */ (mcp), csrfToken)
        : renderSharedSection(/** @type {any} */ (mcp)),
    )
    .join('\n');
  const body = `<main>
  <h1>Your MCP credentials</h1>
  <p class="who">Signed in as ${escapeHtml(status.username)}</p>
  ${errorMarkup}
  ${sections}
</main>`;
  return renderDocument({ title: 'Your MCP credentials', body });
}
