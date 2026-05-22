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
    const report = await db.reportJob.findUnique({
      where: { id },
    });

    if (!report) {
      return jsonApiError(
        {
          status: "404",
          title: "Not found",
          detail: "Report not found",
          code: "NOT_FOUND",
        },
        404
      );
    }

    return jsonApiResponse(
      {
        type: "reports",
        id: report.id,
        attributes: {
          format: report.format,
          status: report.status,
          storagePath: report.storagePath,
          webhookUrl: report.webhookUrl,
          createdAt: report.createdAt,
          completedAt: report.completedAt,
          errorMessage: report.errorMessage,
          payload: report.filter,
        },
      },
      { headers: rate.headers }
    );
  } catch (error) {
    console.error("GET /api/v2/reports/:id failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to fetch report status",
      code: "REPORT_STATUS_ERROR",
    });
  }
}
