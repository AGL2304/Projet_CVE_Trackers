import { CVEStatus, CveSource, Prisma, Severity, SyncJobStatus, SyncSource, UserRole } from "@prisma/client";
import { z } from "zod";
import { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { calculateSeverityFromCvss } from "@/lib/v2/severity";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";
import { getActor, hasRole } from "@/lib/v2/auth";
import { writeAuditLog } from "@/lib/v2/audit";

const syncSchema = z.object({
  source: z.nativeEnum(SyncSource).default(SyncSource.NVD),
  cves: z
    .array(
      z.object({
        cveId: z.string().min(3),
        title: z.string().optional(),
        description: z.string().optional(),
        publishedAt: z.coerce.date().optional(),
        modifiedAt: z.coerce.date().optional(),
        cvssV3Score: z.number().min(0).max(10).optional(),
        cvssV3Vector: z.string().optional(),
        cvssV4Score: z.number().min(0).max(10).optional(),
        epssScore: z.number().min(0).max(1).optional(),
        references: z.string().optional(),
        rawData: z.unknown().optional(),
      })
    )
    .optional(),
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
    if (!hasRole(actor, [UserRole.ADMIN, UserRole.ANALYST, UserRole.API])) {
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

    const parsed = syncSchema.safeParse(await request.json());
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

    const payload = parsed.data;
    const syncJob = await db.syncJob.create({
      data: {
        source: payload.source,
        status: SyncJobStatus.RUNNING,
        triggeredById: actor.id === "system" ? null : actor.id,
        startedAt: new Date(),
        logs: [],
      },
    });

    const stream = payload.cves && payload.cves.length > 0 ? payload.cves : await fetchFromNvd();

    let newCount = 0;
    let updatedCount = 0;
    let errorCount = 0;
    const logs: string[] = [];

    for (const item of stream) {
      try {
        const cvssV3Score = item.cvssV3Score ?? null;
        const cvssV4Score = item.cvssV4Score ?? null;
        const severity = calculateSeverityFromCvss(cvssV3Score, cvssV4Score);

        const existing = await db.cVE.findUnique({
          where: { cveId: item.cveId },
          select: { id: true },
        });

        await db.cVE.upsert({
          where: { cveId: item.cveId },
          update: {
            title: item.title ?? item.cveId,
            description: item.description ?? "Imported from sync feed",
            publishedAt: item.publishedAt ?? null,
            modifiedAt: item.modifiedAt ?? null,
            cvssV3Score,
            cvssV3Vector: item.cvssV3Vector ?? null,
            cvssV4Score,
            epssScore: item.epssScore ?? null,
            status: CVEStatus.ANALYZING,
            severity,
            source: payload.source === SyncSource.NVD ? CveSource.NVD : CveSource.MANUAL,
            rawData: (item.rawData ?? null) as Prisma.InputJsonValue,
            references: item.references ?? null,
            vulnStatus: "analyzing",
            cvssScore: cvssV3Score,
            cvssVector: item.cvssV3Vector ?? null,
            publishedDate: item.publishedAt ?? null,
            lastModifiedDate: item.modifiedAt ?? null,
            version: { increment: 1 },
          },
          create: {
            cveId: item.cveId,
            title: item.title ?? item.cveId,
            description: item.description ?? "Imported from sync feed",
            publishedAt: item.publishedAt ?? null,
            modifiedAt: item.modifiedAt ?? null,
            cvssV3Score,
            cvssV3Vector: item.cvssV3Vector ?? null,
            cvssV4Score,
            epssScore: item.epssScore ?? null,
            status: CVEStatus.NEW,
            severity,
            source: payload.source === SyncSource.NVD ? CveSource.NVD : CveSource.MANUAL,
            rawData: (item.rawData ?? null) as Prisma.InputJsonValue,
            references: item.references ?? null,
            vulnStatus: "new",
            cvssScore: cvssV3Score,
            cvssVector: item.cvssV3Vector ?? null,
            publishedDate: item.publishedAt ?? null,
            lastModifiedDate: item.modifiedAt ?? null,
          },
        });

        if (existing) {
          updatedCount += 1;
          logs.push(`UPDATED ${item.cveId}`);
        } else {
          newCount += 1;
          logs.push(`CREATED ${item.cveId}`);
        }
      } catch (error) {
        errorCount += 1;
        logs.push(`ERROR ${item.cveId}: ${error instanceof Error ? error.message : "unknown"}`);
      }
    }

    const completed = await db.syncJob.update({
      where: { id: syncJob.id },
      data: {
        status: errorCount > 0 ? SyncJobStatus.FAILED : SyncJobStatus.COMPLETED,
        completedAt: new Date(),
        newCount,
        updatedCount,
        errorCount,
        logs: logs as Prisma.InputJsonValue,
      },
    });

    await writeAuditLog({
      actor,
      action: "sync.nvd",
      resource: "syncJob",
      resourceId: completed.id,
      after: {
        source: completed.source,
        status: completed.status,
        newCount,
        updatedCount,
        errorCount,
      },
      request,
    });

    return jsonApiResponse(
      {
        type: "sync-jobs",
        id: completed.id,
        attributes: {
          source: completed.source,
          status: completed.status,
          startedAt: completed.startedAt,
          completedAt: completed.completedAt,
          newCount,
          updatedCount,
          errorCount,
          logs,
        },
      },
      {
        status: 202,
        links: {
          self: `/api/v2/sync/nvd`,
          job: `/api/v2/sync/jobs/${completed.id}`,
        },
        headers: rate.headers,
      }
    );
  } catch (error) {
    console.error("POST /api/v2/sync/nvd failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to start sync job",
      code: "SYNC_ERROR",
    });
  }
}

async function fetchFromNvd() {
  try {
    const endpoint = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
    endpoint.searchParams.set("resultsPerPage", "20");
    const response = await fetch(endpoint.toString(), {
      headers: {
        "User-Agent": "CVE-Tracker-v2/1.0",
      },
      cache: "no-store",
    });

    if (!response.ok) return [];
    const payload = await response.json();

    return (payload?.vulnerabilities ?? []).map((entry: any) => {
      const cve = entry.cve;
      const metric = cve?.metrics?.cvssMetricV31?.[0]?.cvssData;
      return {
        cveId: cve.id as string,
        title: cve.id as string,
        description:
          cve?.descriptions?.find((description: { lang: string }) => description.lang === "en")?.value ??
          cve?.descriptions?.[0]?.value ??
          "Imported from NVD",
        publishedAt: cve?.published ? new Date(cve.published) : undefined,
        modifiedAt: cve?.lastModified ? new Date(cve.lastModified) : undefined,
        cvssV3Score: metric?.baseScore as number | undefined,
        cvssV3Vector: metric?.vectorString as string | undefined,
        references: JSON.stringify(cve?.references?.map((reference: { url: string }) => reference.url) ?? []),
        rawData: cve,
      };
    });
  } catch {
    return [];
  }
}
