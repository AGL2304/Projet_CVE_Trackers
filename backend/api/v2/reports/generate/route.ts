import { CVEStatus, CveSource, ReportFormat, ReportStatus, Severity, UserRole } from "@prisma/client";
import { z } from "zod";
import { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";
import { getActor, hasRole } from "@/lib/v2/auth";
import { writeAuditLog } from "@/lib/v2/audit";

/**
 * Schema for the report filter — keep it permissive but typed so the worker
 * can apply it as a Prisma `where` clause without surprises.
 */
const filterSchema = z
  .object({
    // Report scope: "cve" (default) reports on the CVE database; "assets"
    // reports on the scanned-asset inventory and the products discovered on it.
    scope: z.enum(["cve", "assets"]).optional(),
    severity: z.array(z.nativeEnum(Severity)).optional(),
    status: z.array(z.nativeEnum(CVEStatus)).optional(),
    source: z.array(z.nativeEnum(CveSource)).optional(),
    dateFrom: z.string().datetime().optional(),
    dateTo: z.string().datetime().optional(),
    minCvss: z.number().min(0).max(10).optional(),
    maxCvss: z.number().min(0).max(10).optional(),
    search: z.string().trim().max(200).optional(),
    limit: z.number().int().min(1).max(50_000).optional(),
    title: z.string().trim().max(120).optional(),
    // Asset-scope filters (ignored for cve scope)
    criticality: z.enum(["low", "medium", "high", "critical"]).optional(),
    assetStatus: z.enum(["active", "inactive", "retired"]).optional(),
  })
  .partial();

const generateSchema = z.object({
  format: z.nativeEnum(ReportFormat).default(ReportFormat.PDF),
  filter: filterSchema.optional(),
  webhookUrl: z.string().url().optional(),
});

export async function POST(request: NextRequest) {
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
    const actor = await getActor(request);
    if (!hasRole(actor, [UserRole.ADMIN, UserRole.ANALYST])) {
      return jsonApiError(
        {
          status: "403",
          title: "Forbidden",
          detail: "Insufficient permissions",
          code: "FORBIDDEN",
        },
        403
      );
    }

    const parsed = generateSchema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) {
      return jsonApiError(
        {
          status: "400",
          title: "Validation error",
          detail: parsed.error.issues.map((issue) => issue.message).join("; "),
          code: "VALIDATION_ERROR",
        },
        400
      );
    }

    const input = parsed.data;

    // Enqueue — the worker picks it up on its next tick (~15s).
    // We do NOT compute KPIs inline anymore: report generation paginates the
    // entire matching set, which can take seconds on large filters and would
    // block the request handler.
    const created = await db.reportJob.create({
      data: {
        format: input.format,
        status: ReportStatus.QUEUED,
        requestedById: actor.id === "system" || actor.id === "admin-session" ? null : actor.id,
        filter: (input.filter ?? {}) as object,
        webhookUrl: input.webhookUrl ?? null,
      },
    });

    await writeAuditLog({
      actor,
      action: "report.enqueue",
      resource: "report",
      resourceId: created.id,
      after: {
        format: created.format,
        filter: input.filter,
      },
      request,
    });

    return jsonApiResponse(
      {
        type: "reports",
        id: created.id,
        attributes: {
          format: created.format,
          status: created.status,
          filter: created.filter,
          createdAt: created.createdAt,
          message:
            "Report queued. Poll /api/v2/reports/:id to check progress; download from /api/v2/reports/:id/download when status=COMPLETED.",
        },
      },
      {
        status: 202,
        links: {
          self: "/api/v2/reports/generate",
          job: `/api/v2/reports/${created.id}`,
          download: `/api/v2/reports/${created.id}/download`,
        },
        headers: rate.headers,
      }
    );
  } catch (error) {
    console.error("POST /api/v2/reports/generate failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to queue report",
      code: "REPORT_ERROR",
    });
  }
}
