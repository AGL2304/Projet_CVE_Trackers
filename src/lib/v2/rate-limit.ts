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

const globalState = globalThis as unknown as {
  __cveTrackerRateLimit?: Map<string, Bucket>;
};

const buckets = globalState.__cveTrackerRateLimit ?? new Map<string, Bucket>();
if (!globalState.__cveTrackerRateLimit) globalState.__cveTrackerRateLimit = buckets;

export function applyRateLimit(
  request: NextRequest,
  config: Partial<RateLimitConfig> = {}
): RateLimitResult {
  const merged = { ...DEFAULT_CONFIG, ...config };
  const isPremium = request.headers.get("x-plan")?.toLowerCase() === "premium";
  const limit = isPremium ? merged.premiumLimit : merged.standardLimit;
  const key = buildKey(request);
  const now = Date.now();
  const current = buckets.get(key);

  if (!current || current.resetAt <= now) {
    buckets.set(key, {
      count: 1,
      resetAt: now + merged.windowMs,
    });

    return buildResult(false, limit, limit - 1, merged.windowMs);
  }

  current.count += 1;
  const remaining = Math.max(0, limit - current.count);
  const retryAfter = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
  const limited = current.count > limit;

  return buildResult(limited, limit, remaining, retryAfter * 1000);
}

function buildKey(request: NextRequest) {
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
