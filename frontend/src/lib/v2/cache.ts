type CacheEntry = {
  value: unknown;
  expiresAt: number;
};

const globalState = globalThis as unknown as {
  __cveTrackerCache?: Map<string, CacheEntry>;
};

const cacheStore = globalState.__cveTrackerCache ?? new Map<string, CacheEntry>();
if (!globalState.__cveTrackerCache) globalState.__cveTrackerCache = cacheStore;

export function getCache<T>(key: string): T | null {
  const now = Date.now();
  const entry = cacheStore.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= now) {
    cacheStore.delete(key);
    return null;
  }
  return entry.value as T;
}

export function setCache(key: string, value: unknown, ttlSeconds: number) {
  cacheStore.set(key, {
    value,
    expiresAt: Date.now() + ttlSeconds * 1000,
  });
}
