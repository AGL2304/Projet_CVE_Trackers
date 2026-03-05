import { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";
import { getCache, setCache } from "@/lib/v2/cache";

export async function GET(request: NextRequest) {
  const rate = applyRateLimit(request);
  if (rate.limited) {
    return jsonApiError(
      {
        status: "429",
        title: "Rate limit exceeded",
        detail: "Too many requests",
        code: "RATE_LIMIT",
      },
      429
    );
  }

  try {
    const cacheKey = "analytics:dashboard:v2";
    const cached = getCache<{
      totalCVEs: number;
      totalAssets: number;
      newCVEs7d: number;
      avgCvssV3: number;
      kevCount: number;
      vulnerabilitiesBySeverity: { severity: string; value: number }[];
      vulnerabilitiesByStatus: { status: string; value: number }[];
      timeline: {
        id: string;
        action: string;
        resource: string;
        resourceId: string | null;
        timestamp: Date;
      }[];
    }>(cacheKey);

    if (cached) {
      return jsonApiResponse(
        {
          type: "analytics-dashboard",
          id: "default",
          attributes: cached,
        },
        {
          headers: rate.headers,
          meta: {
            cache: "HIT",
          },
        }
      );
    }

    const [totalCVEs, totalAssets, bySeverity, byStatus, avgCvss, recent, kevCount] =
      await Promise.all([
        db.cVE.count(),
        db.asset.count(),
        db.cVE.groupBy({
          by: ["severity"],
          _count: true,
          orderBy: { severity: "asc" },
        }),
        db.cVE.groupBy({
          by: ["status"],
          _count: true,
          orderBy: { status: "asc" },
        }),
        db.cVE.aggregate({
          _avg: {
            cvssV3Score: true,
          },
        }),
        db.cVE.count({
          where: {
            publishedAt: {
              gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
            },
          },
        }),
        db.cVE.count({
          where: {
            source: "CISA_KEV",
          },
        }),
      ]);

    const vulnerabilitiesBySeverity = bySeverity.map((item) => ({
      severity: item.severity,
      value: item._count,
    }));

    const vulnerabilitiesByStatus = byStatus.map((item) => ({
      status: item.status,
      value: item._count,
    }));

    const timeline = await db.auditLog.findMany({
      orderBy: { timestamp: "desc" },
      take: 20,
      select: {
        id: true,
        action: true,
        resource: true,
        resourceId: true,
        timestamp: true,
      },
    });

    const attributes = {
      totalCVEs,
      totalAssets,
      newCVEs7d: recent,
      avgCvssV3: Number((avgCvss._avg.cvssV3Score ?? 0).toFixed(2)),
      kevCount,
      vulnerabilitiesBySeverity,
      vulnerabilitiesByStatus,
      timeline,
    };

    setCache(cacheKey, attributes, 30);

    return jsonApiResponse(
      {
        type: "analytics-dashboard",
        id: "default",
        attributes,
      },
      {
        headers: rate.headers,
        meta: {
          cache: "MISS",
        },
      }
    );
  } catch (error) {
    console.error("GET /api/v2/analytics/dashboard failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to compute dashboard analytics",
      code: "ANALYTICS_ERROR",
    });
  }
}
