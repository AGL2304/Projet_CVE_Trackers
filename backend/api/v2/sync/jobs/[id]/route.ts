import { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
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
    const { id } = await context.params;
    const job = await db.syncJob.findUnique({
      where: { id },
    });

    if (!job) {
      return jsonApiError(
        {
          status: "404",
          title: "Not found",
          detail: "Sync job not found",
          code: "NOT_FOUND",
        },
        404
      );
    }

    return jsonApiResponse(
      {
        type: "sync-jobs",
        id: job.id,
        attributes: {
          source: job.source,
          status: job.status,
          startedAt: job.startedAt,
          completedAt: job.completedAt,
          newCount: job.newCount,
          updatedCount: job.updatedCount,
          errorCount: job.errorCount,
          logs: job.logs,
        },
      },
      { headers: rate.headers }
    );
  } catch (error) {
    console.error("GET /api/v2/sync/jobs/:id failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to fetch sync job",
      code: "SYNC_JOB_ERROR",
    });
  }
}
