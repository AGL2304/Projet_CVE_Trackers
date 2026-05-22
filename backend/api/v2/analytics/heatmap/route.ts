import { NextRequest } from "next/server";
import { Prisma, Severity } from "@prisma/client";
import { db } from "@/lib/db";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";

/**
 * GET /api/v2/analytics/heatmap?days=N&field=published|modified
 *
 * Returns a daily-binned CVE count series ready for a calendar heatmap.
 *
 * Aggregation is done in SQL so it scales — a naive fetch-all-CVEs approach
 * would not survive a 100k+ CVE table.
 *
 * Response shape:
 *   {
 *     days: number,
 *     from: ISO,
 *     to: ISO,
 *     field: "published" | "modified",
 *     total: number,
 *     maxPerDay: number,
 *     cells: [{ date: "YYYY-MM-DD", total, critical, high, medium, low, none }]
 *   }
 */
export async function GET(request: NextRequest) {
  const rate = applyRateLimit(request);
  if (rate.limited) {
    return jsonApiError(
      { status: "429", title: "Rate limit exceeded", code: "RATE_LIMIT" },
      429
    );
  }

  try {
    const url = new URL(request.url);
    const days = Math.min(730, Math.max(7, Number(url.searchParams.get("days")) || 90));
    const fieldParam = url.searchParams.get("field") === "modified" ? "modified" : "published";
    const column = fieldParam === "modified" ? "modifiedAt" : "publishedAt";

    // Anchor "today" at UTC midnight so cell boundaries are stable across TZs
    const toDate = new Date();
    toDate.setUTCHours(0, 0, 0, 0);
    const endExclusive = new Date(toDate);
    endExclusive.setUTCDate(endExclusive.getUTCDate() + 1); // include today
    const fromDate = new Date(toDate);
    fromDate.setUTCDate(fromDate.getUTCDate() - (days - 1));

    // Raw SQL aggregation: group by day truncated at UTC, pivoted by severity
    // Postgres-specific (date_trunc is standard, filter clause too).
    type Row = {
      day: Date;
      total: bigint;
      critical: bigint;
      high: bigint;
      medium: bigint;
      low: bigint;
      none: bigint;
    };

    const rows = await db.$queryRaw<Row[]>(Prisma.sql`
      SELECT
        date_trunc('day', ${Prisma.raw(`"${column}"`)} AT TIME ZONE 'UTC')::date AS day,
        COUNT(*)::bigint AS total,
        COUNT(*) FILTER (WHERE "severity" = 'CRITICAL')::bigint AS critical,
        COUNT(*) FILTER (WHERE "severity" = 'HIGH')::bigint     AS high,
        COUNT(*) FILTER (WHERE "severity" = 'MEDIUM')::bigint   AS medium,
        COUNT(*) FILTER (WHERE "severity" = 'LOW')::bigint      AS low,
        COUNT(*) FILTER (WHERE "severity" = 'NONE')::bigint     AS none
      FROM "CVE"
      WHERE ${Prisma.raw(`"${column}"`)} >= ${fromDate}
        AND ${Prisma.raw(`"${column}"`)} <  ${endExclusive}
      GROUP BY day
      ORDER BY day ASC
    `);

    // Index rows by ISO date for quick lookup, then fill the gap days with zeros
    // so the frontend doesn't need to know which days are missing.
    const byDate = new Map<string, Row>();
    for (const r of rows) {
      const iso = new Date(r.day).toISOString().slice(0, 10);
      byDate.set(iso, r);
    }

    const cells: Array<{
      date: string;
      total: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
      none: number;
    }> = [];

    for (let i = 0; i < days; i++) {
      const d = new Date(fromDate);
      d.setUTCDate(fromDate.getUTCDate() + i);
      const iso = d.toISOString().slice(0, 10);
      const r = byDate.get(iso);
      cells.push({
        date: iso,
        total: r ? Number(r.total) : 0,
        critical: r ? Number(r.critical) : 0,
        high: r ? Number(r.high) : 0,
        medium: r ? Number(r.medium) : 0,
        low: r ? Number(r.low) : 0,
        none: r ? Number(r.none) : 0,
      });
    }

    const total = cells.reduce((sum, c) => sum + c.total, 0);
    const maxPerDay = cells.reduce((m, c) => (c.total > m ? c.total : m), 0);

    return jsonApiResponse(
      {
        type: "heatmap",
        id: `${fieldParam}-${days}`,
        attributes: {
          days,
          from: fromDate.toISOString(),
          to: endExclusive.toISOString(),
          field: fieldParam,
          total,
          maxPerDay,
          cells,
          // Convenience aggregates
          bySeverity: cells.reduce(
            (acc, c) => {
              acc.CRITICAL += c.critical;
              acc.HIGH += c.high;
              acc.MEDIUM += c.medium;
              acc.LOW += c.low;
              acc.NONE += c.none;
              return acc;
            },
            { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 } as Record<Severity, number>
          ),
        },
      },
      { headers: rate.headers }
    );
  } catch (error) {
    console.error("GET /api/v2/analytics/heatmap failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to compute heatmap",
      code: "HEATMAP_ERROR",
    });
  }
}
