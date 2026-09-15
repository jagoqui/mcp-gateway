import { test } from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, PAGE_HEADERS, ADMIN_PAGE_HEADERS } from '../src/html.js';

test('escapeHtml neutralizes &, <, >, ", and \' individually', () => {
  assert.equal(escapeHtml('&'), '&amp;');
  assert.equal(escapeHtml('<'), '&lt;');
  assert.equal(escapeHtml('>'), '&gt;');
  assert.equal(escapeHtml('"'), '&quot;');
  assert.equal(escapeHtml("'"), '&#39;');
});

test('escapeHtml escapes all special characters in a mixed string', () => {
  const input = `<div class="a">Tom & Jerry's "show"</div>`;
  const result = escapeHtml(input);
  assert.equal(
    result,
    '&lt;div class=&quot;a&quot;&gt;Tom &amp; Jerry&#39;s &quot;show&quot;&lt;/div&gt;',
  );
});

test('escapeHtml returns an empty string for null and undefined', () => {
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
});

test('escapeHtml renders a <script>-bearing value inert (R6)', () => {
  const malicious = '<script>alert(document.cookie)</script>';
  const result = escapeHtml(malicious);
  assert.ok(!result.includes('<script'), 'escaped output must not contain a live <script tag');
  assert.equal(result, '&lt;script&gt;alert(document.cookie)&lt;/script&gt;');
});

test('ADMIN_PAGE_HEADERS carries every PAGE_HEADERS entry plus Referrer-Policy: no-referrer', () => {
  for (const [key, value] of Object.entries(PAGE_HEADERS)) {
    assert.equal(ADMIN_PAGE_HEADERS[key], value);
  }
  assert.equal(ADMIN_PAGE_HEADERS['Referrer-Policy'], 'no-referrer');
  assert.ok(Object.isFrozen(ADMIN_PAGE_HEADERS));
});
