import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPortAllocator } from '../src/port-allocator.js';

test('allocates sequential free ports starting at base', () => {
  const allocator = createPortAllocator({ base: 19100, max: 3 });
  assert.equal(allocator.allocate(), 19100);
  assert.equal(allocator.allocate(), 19101);
  assert.equal(allocator.allocate(), 19102);
});

test('refuses once the range is exhausted', () => {
  const allocator = createPortAllocator({ base: 19100, max: 2 });
  allocator.allocate();
  allocator.allocate();
  assert.equal(allocator.allocate(), null);
});

test('releasing a port makes it allocatable again', () => {
  const allocator = createPortAllocator({ base: 19100, max: 2 });
  const first = allocator.allocate();
  allocator.allocate();
  assert.equal(allocator.allocate(), null);
  allocator.release(first);
  assert.equal(allocator.allocate(), first);
});

test('double-release is a no-op, not a crash', () => {
  const allocator = createPortAllocator({ base: 19100, max: 2 });
  const first = allocator.allocate();
  allocator.release(first);
  assert.doesNotThrow(() => allocator.release(first));
});

test('releasing a port outside the managed range is a no-op, not a crash', () => {
  const allocator = createPortAllocator({ base: 19100, max: 2 });
  assert.doesNotThrow(() => allocator.release(80));
});
