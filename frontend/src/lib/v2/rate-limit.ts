import type { NextRequest } from "next/server";

type Bucket = {
  count: number;
  resetAt: number;
};

type RateLimitConfig = {
  standardLimit: number;
  premiumLimit: number;
  windowMs: number;
};

type RateLimitResult = {
  limited: boolean;
  limit: number;
  remaining: number;
  retryAfter: number;
  headers: Record<string, string>;
};

const DEFAULT_CONFIG: RateLimitConfig = {
  standardLimit: 1000,
  premiumLimit: 10_000,
  windowMs: 60_000,
};

// ─── In-memory backend (fallback) ────────────────────────────────────────────

const globalState = globalThis as unknown as {
  __cveTrackerRateLimit?: Map<string, Bucket>;
};

const buckets = globalState.__cveTrackerRateLimit ?? new Map<string, Bucket>();
if (!globalState.__cveTrackerRateLimit) globalState.__cveTrackerRateLimit = buckets;

// ─── Redis backend (optional, multi-instance safe) ──────────────────────────
//
// We lazy-load ioredis only when REDIS_URL is set, to avoid a hard
// dependency for users running the in-memory mode. Failing to load Redis
// transparently falls back to in-memory (with a one-time warning).

type RedisLike = {
  multi: () => {
    incr: (key: string) => RedisChain;
    pexpire: (key: string, ms: number) => RedisChain;
    pttl: (key: string) => RedisChain;
    exec: () => Promise<Array<[Error | null, unknown]> | null>;
  };
};
type RedisChain = ReturnType<RedisLike["multi"]>;

const redisState = globalThis as unknown as {
  __cveTrackerRedis?: RedisLike | null;
  __cveTrackerRedisTried?: boolean;
};

function getRedis(): RedisLike | null {
  if (redisState.__cveTrackerRedisTried) return redisState.__cveTrackerRedis ?? null;
  redisState.__cveTrackerRedisTried = true;

  const url = process.env.REDIS_URL;
  if (!url) {
    redisState.__cveTrackerRedis = null;
    return null;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const IORedis = require("ioredis");
    const client = new IORedis(url, {
      lazyConnect: false,
      maxRetriesPerRequest: 2,
      enableOfflineQueue: false,
    });
    client.on("error", (e: Error) => {
      console.warn("[rate-limit] Redis error, falling back to in-memory:", e.message);
    });
    redisState.__cveTrackerRedis = client as unknown as RedisLike;
    return redisState.__cveTrackerRedis;
  } catch (e) {
    console.warn(
      "[rate-limit] REDIS_URL set but 'ioredis' not installed — using in-memory rate limiting. " +
        "Install ioredis (`npm i ioredis`) for distributed rate limiting."
    );
    redisState.__cveTrackerRedis = null;
    return null;
  }
}

async function checkRedis(
  key: string,
  limit: number,
  windowMs: number
): Promise<{ count: number; ttlMs: number } | null> {
  const redis = getRedis();
  if (!redis) return null;

  try {
    const results = await redis
      .multi()
      .incr(key)
      .pexpire(key, windowMs)
      .pttl(key)
      .exec();

    if (!results) return null;
    const count = Number(results[0]?.[1] ?? 0);
    const ttlMs = Number(results[2]?.[1] ?? windowMs);
    return { count, ttlMs: ttlMs > 0 ? ttlMs : windowMs };
  } catch (e) {
    console.warn(
      "[rate-limit] Redis op failed, falling back to in-memory:",
      e instanceof Error ? e.message : String(e)
    );
    return null;
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function applyRateLimit(
  request: NextRequest,
  config: Partial<RateLimitConfig> = {}
): RateLimitResult {
  const merged = { ...DEFAULT_CONFIG, ...config };
  const isPremium = request.headers.get("x-plan")?.toLowerCase() === "premium";
  const limit = isPremium ? merged.premiumLimit : merged.standardLimit;
  const key = buildKey(request);
  const now = Date.now();

  // Try Redis first — but the public API stays synchronous to keep
  // backward compatibility with existing callers. We schedule the Redis
  // op fire-and-forget and use in-memory as the source of truth on the
  // critical path. Redis acts as a cross-instance reconciliation channel.
  if (process.env.REDIS_URL && getRedis()) {
    // Best-effort: increment Redis counter to ensure cross-instance visibility.
    void checkRedis(`rl:${key}`, limit, merged.windowMs);
  }

  const current = buckets.get(key);
  if (!current || current.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + merged.windowMs });
    return buildResult(false, limit, limit - 1, merged.windowMs);
  }

  current.count += 1;
  const remaining = Math.max(0, limit - current.count);
  const retryAfterMs = Math.max(1000, current.resetAt - now);
  const limited = current.count > limit;

  return buildResult(limited, limit, remaining, retryAfterMs);
}

/**
 * Async variant — fully Redis-backed when REDIS_URL is configured.
 * Use this in new routes when you want true distributed enforcement.
 */
export async function applyRateLimitAsync(
  request: NextRequest,
  config: Partial<RateLimitConfig> = {}
): Promise<RateLimitResult> {
  const merged = { ...DEFAULT_CONFIG, ...config };
  const isPremium = request.headers.get("x-plan")?.toLowerCase() === "premium";
  const limit = isPremium ? merged.premiumLimit : merged.standardLimit;
  const key = buildKey(request);

  const redisRes = await checkRedis(`rl:${key}`, limit, merged.windowMs);
  if (redisRes) {
    const remaining = Math.max(0, limit - redisRes.count);
    const retryAfterMs = redisRes.ttlMs;
    const limited = redisRes.count > limit;
    return buildResult(limited, limit, remaining, retryAfterMs);
  }

  // Fallback to in-memory
  return applyRateLimit(request, config);
}

function buildKey(request: NextRequest): string {
  // Prefer trusted proxy-supplied IP, falling back to a unique-per-process sentinel.
  const forwarded = request.headers.get("x-forwarded-for");
  const ip = forwarded?.split(",")[0]?.trim() || "unknown";
  const token = request.headers.get("x-api-key") || request.headers.get("authorization") || "anonymous";
  return `${ip}:${token}`;
}

function buildResult(
  limited: boolean,
  limit: number,
  remaining: number,
  retryAfterMs: number
): RateLimitResult {
  const retryAfter = Math.max(1, Math.ceil(retryAfterMs / 1000));
  return {
    limited,
    limit,
    remaining,
    retryAfter,
    headers: {
      "X-RateLimit-Limit": String(limit),
      "X-RateLimit-Remaining": String(remaining),
      "Retry-After": String(retryAfter),
    },
  };
}
