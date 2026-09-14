/**
 * Fixed-range internal port allocator. supergateway needs an explicit
 * `--port <N>`, so the router owns a small range and hands out slots from
 * it rather than racing the OS for a "free" port between bind-probe and
 * actually spawning the child.
 * @param {{ base: number, max: number }} options
 * @returns {{ allocate: () => number | null, release: (port: number) => void }}
 */
export function createPortAllocator({ base, max }) {
  const inUse = new Set();

  return {
    allocate() {
      for (let offset = 0; offset < max; offset += 1) {
        const port = base + offset;
        if (!inUse.has(port)) {
          inUse.add(port);
          return port;
        }
      }
      return null;
    },
    release(port) {
      inUse.delete(port);
    },
  };
}
