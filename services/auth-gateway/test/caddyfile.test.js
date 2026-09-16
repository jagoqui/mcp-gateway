import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Drift test for Unit 12's Caddy routing (design.md's Testing Strategy
// "Contract" row, adapted to the actual deployed shape: the admin panel
// went out on engram-cloud.{$DOMAIN} — see memory #46/#47 — never the
// design's originally proposed standalone admin.{$DOMAIN} vhost). No
// Caddy dependency: a plain regex scan, mirroring mcp-registry.test.js's
// drift-test idiom for docker-compose.yml.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CADDYFILE_PATH = path.join(__dirname, '..', '..', '..', 'Caddyfile');

test('Caddyfile carves out /admin/login* ahead of the broader /admin/* admin-panel gate', () => {
  const caddyfile = fs.readFileSync(CADDYFILE_PATH, 'utf8');
  const loginIndex = caddyfile.indexOf('handle /admin/login*');
  const adminIndex = caddyfile.indexOf('handle /admin/*');
  assert.ok(loginIndex !== -1, 'expected a handle /admin/login* block');
  assert.ok(adminIndex !== -1, 'expected a handle /admin/* block');
  assert.ok(
    loginIndex < adminIndex,
    '/admin/login* must be carved out before the broader /admin/* gate, or it would never be reached unauthenticated',
  );
});

test('the /admin/* gate forward_auths against uri /admin/verify, never the regular /verify', () => {
  const caddyfile = fs.readFileSync(CADDYFILE_PATH, 'utf8');
  const adminIndex = caddyfile.indexOf('handle /admin/*');
  const nextBlockIndex = caddyfile.indexOf('handle', adminIndex + 'handle /admin/*'.length);
  const block = caddyfile.slice(adminIndex, nextBlockIndex === -1 ? undefined : nextBlockIndex);
  assert.ok(
    block.includes('uri /admin/verify'),
    'the /admin/* gate must forward_auth against /admin/verify (the admin-cookie gate), not /verify (the regular-cookie gate)',
  );
  assert.ok(
    block.includes('reverse_proxy auth-gateway:3000'),
    'the /admin/* gate must proxy to auth-gateway, where every /admin/* route (Units 5-11) actually lives',
  );
});

test('the /admin/* gate comes before the catch-all handle block on its site', () => {
  const caddyfile = fs.readFileSync(CADDYFILE_PATH, 'utf8');
  const adminIndex = caddyfile.indexOf('handle /admin/*');
  // The bare catch-all is a `handle {` with nothing between `handle` and
  // `{` — every other block in this file has a path matcher in between.
  const catchAllIndex = caddyfile.indexOf('handle {', adminIndex);
  assert.ok(catchAllIndex !== -1, 'expected a bare catch-all handle block after /admin/*');
  assert.ok(
    adminIndex < catchAllIndex,
    '/admin/* must precede the catch-all, or every admin-panel route would be swallowed by it and proxied to the wrong backend',
  );
});
