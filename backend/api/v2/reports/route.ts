import { NextRequest } from "next/server";
import { ReportStatus } from "@prisma/client";
import { db } from "@/lib/db";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";

/**
 * Lists the most recent report jobs — newest first.
 * Query params:
 *   - limit (default 20, max 100)
 *   - status (filter by ReportStatus)
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
    const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit")) || 20));
    const statusParam = url.searchParams.get("status");

    const where = statusParam && Object.values(ReportStatus).includes(statusParam as ReportStatus)
      ? { status: statusParam as ReportStatus }
      : undefined;

    const reports = await db.reportJob.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: limit,
      select: {
        id: true,
        format: true,
        status: true,
        filter: true,
        storagePath: true,
        errorMessage: true,
        createdAt: true,
        completedAt: true,
      },
    });

    return jsonApiResponse(
      reports.map((r) => ({
        type: "reports",
        id: r.id,
        attributes: {
          format: r.format,
          status: r.status,
          filter: r.filter,
          createdAt: r.createdAt,
          completedAt: r.completedAt,
          errorMessage: r.errorMessage,
          hasFile: r.status === ReportStatus.COMPLETED && Boolean(r.storagePath),
        },
        links: {
          self: `/api/v2/reports/${r.id}`,
          download: `/api/v2/reports/${r.id}/download`,
        },
      })),
      { headers: rate.headers }
    );
  } catch (error) {
    console.error("GET /api/v2/reports failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to list reports",
      code: "REPORT_LIST_ERROR",
    });
  }
}
