import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MCP_REGISTRY, getMcp } from '../src/mcp-registry.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Documented coupling (design.md): resolves the repo-root docker-compose.yml
// from services/auth-gateway/test/.
const COMPOSE_PATH = path.join(__dirname, '..', '..', '..', 'docker-compose.yml');

test('MCP_REGISTRY is a non-empty array', () => {
  assert.ok(Array.isArray(MCP_REGISTRY));
  assert.ok(MCP_REGISTRY.length > 0);
});

test('MCP_REGISTRY and every entry are frozen', () => {
  assert.ok(Object.isFrozen(MCP_REGISTRY), 'the registry array itself must be frozen');
  for (const entry of MCP_REGISTRY) {
    assert.ok(Object.isFrozen(entry), `registry entry '${entry.id}' must be frozen`);
  }
});

test('every registry entry has the shared base shape', () => {
  for (const entry of MCP_REGISTRY) {
    assert.equal(typeof entry.id, 'string');
    assert.ok(entry.id.length > 0);
    assert.equal(typeof entry.label, 'string');
    assert.ok(entry.label.length > 0);
    assert.equal(typeof entry.route, 'string');
    assert.ok(entry.route.startsWith('/mcp/'));
    assert.equal(typeof entry.composeService, 'string');
    assert.ok(entry.composeService.startsWith('mcp-'));
    assert.equal(typeof entry.perUserCredentials, 'boolean');
  }
});

test('a perUserCredentials:false entry carries sharedSecretEnv and note, never a false-shaped per-user entry', () => {
  const sharedEntries = MCP_REGISTRY.filter((entry) => entry.perUserCredentials === false);
  assert.ok(sharedEntries.length > 0, 'expected at least one shared-credential entry');
  for (const entry of sharedEntries) {
    assert.equal(typeof entry.sharedSecretEnv, 'string');
    assert.ok(entry.sharedSecretEnv.length > 0);
    assert.equal(typeof entry.note, 'string');
    assert.ok(entry.note.length > 0);
  }
});

test('atlassian is the only perUserCredentials:true entry', () => {
  const perUserEntries = MCP_REGISTRY.filter((entry) => entry.perUserCredentials === true);
  assert.equal(perUserEntries.length, 1);
  assert.equal(perUserEntries[0].id, 'atlassian');
});

test('every mcp-* service declared in docker-compose.yml has exactly one matching registry entry', () => {
  const compose = fs.readFileSync(COMPOSE_PATH, 'utf8');
  const composeServiceNames = [...compose.matchAll(/^ {2}(mcp-[a-z0-9-]+):/gm)].map((m) => m[1]);
  assert.ok(composeServiceNames.length > 0, 'expected to find at least one mcp-* compose service');

  for (const serviceName of composeServiceNames) {
    const matches = MCP_REGISTRY.filter((entry) => entry.composeService === serviceName);
    assert.equal(
      matches.length,
      1,
      `expected exactly one registry entry for compose service '${serviceName}', found ${matches.length}`,
    );
  }
});

test('getMcp returns the matching entry by id', () => {
  const entry = getMcp('atlassian');
  assert.ok(entry);
  assert.equal(entry.id, 'atlassian');
  assert.equal(entry.perUserCredentials, true);
});

test('getMcp returns undefined for an unknown id', () => {
  assert.equal(getMcp('does-not-exist'), undefined);
});
