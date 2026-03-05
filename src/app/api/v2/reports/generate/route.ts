import { ReportFormat, ReportStatus, UserRole } from "@prisma/client";
import { z } from "zod";
import { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";
import { getActor, hasRole } from "@/lib/v2/auth";
import { writeAuditLog } from "@/lib/v2/audit";

const generateSchema = z.object({
  format: z.nativeEnum(ReportFormat).default(ReportFormat.PDF),
  filter: z.record(z.string(), z.unknown()).optional(),
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

    const parsed = generateSchema.safeParse(await request.json());
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
    const created = await db.reportJob.create({
      data: {
        format: input.format,
        status: ReportStatus.RUNNING,
        requestedById: actor.id === "system" ? null : actor.id,
        filter: (input.filter ?? {}) as object,
        webhookUrl: input.webhookUrl ?? null,
      },
    });

    const [totalCVEs, criticalCVEs, avg] = await Promise.all([
      db.cVE.count(),
      db.cVE.count({ where: { severity: "CRITICAL" } }),
      db.cVE.aggregate({
        _avg: { cvssV3Score: true },
      }),
    ]);

    const syntheticPath = `reports/${created.id}.${input.format.toLowerCase()}`;
    const payload = {
      reportId: created.id,
      generatedAt: new Date().toISOString(),
      metrics: {
        totalCVEs,
        criticalCVEs,
        avgCvss: Number((avg._avg.cvssV3Score ?? 0).toFixed(2)),
      },
      filters: input.filter ?? {},
    };

    const completed = await db.reportJob.update({
      where: { id: created.id },
      data: {
        status: ReportStatus.COMPLETED,
        completedAt: new Date(),
        storagePath: syntheticPath,
        filter: payload as object,
      },
    });

    if (input.webhookUrl) {
      void fetch(input.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          reportId: completed.id,
          status: completed.status,
          storagePath: completed.storagePath,
        }),
      }).catch(() => null);
    }

    await writeAuditLog({
      actor,
      action: "report.generate",
      resource: "report",
      resourceId: completed.id,
      after: {
        format: completed.format,
        status: completed.status,
        storagePath: completed.storagePath,
      },
      request,
    });

    return jsonApiResponse(
      {
        type: "reports",
        id: completed.id,
        attributes: {
          format: completed.format,
          status: completed.status,
          storagePath: completed.storagePath,
          createdAt: completed.createdAt,
          completedAt: completed.completedAt,
        },
      },
      {
        status: 202,
        links: {
          self: "/api/v2/reports/generate",
          job: `/api/v2/reports/${completed.id}`,
        },
        headers: rate.headers,
      }
    );
  } catch (error) {
    console.error("POST /api/v2/reports/generate failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to generate report",
      code: "REPORT_ERROR",
    });
  }
}
