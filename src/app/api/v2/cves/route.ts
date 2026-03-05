import { CVEStatus, CveSource, Prisma, Severity, UserRole } from "@prisma/client";
import { z } from "zod";
import { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { mapCveToJsonApiResource } from "@/lib/v2/mappers";
import { calculateSeverityFromCvss } from "@/lib/v2/severity";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { decodeCursor, encodeCursor, parsePositiveInt } from "@/lib/v2/cursor";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";
import { getActor, hasRole } from "@/lib/v2/auth";
import { writeAuditLog } from "@/lib/v2/audit";

const postSchema = z.object({
  cveId: z.string().min(3),
  title: z.string().min(3).optional(),
  description: z.string().min(3),
  publishedAt: z.coerce.date().optional(),
  modifiedAt: z.coerce.date().optional(),
  cvssV3Score: z.number().min(0).max(10).optional(),
  cvssV3Vector: z.string().optional(),
  cvssV4Score: z.number().min(0).max(10).optional(),
  epssScore: z.number().min(0).max(1).optional(),
  status: z.nativeEnum(CVEStatus).optional(),
  source: z.nativeEnum(CveSource).optional(),
  references: z.string().optional(),
  vulnStatus: z.string().optional(),
  rawData: z.unknown().optional(),
});

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
    const searchParams = request.nextUrl.searchParams;
    const limit = parsePositiveInt(searchParams.get("limit"), 20, 100);
    const cursor = decodeCursor(searchParams.get("cursor"));
    const search = searchParams.get("search");
    const severity = searchParams.get("severity");
    const status = searchParams.get("status");

    const where: Prisma.CVEWhereInput = {
      AND: [
        search
          ? {
              OR: [
                { cveId: { contains: search, mode: "insensitive" } },
                { title: { contains: search, mode: "insensitive" } },
                { description: { contains: search, mode: "insensitive" } },
              ],
            }
          : {},
        severity && Object.values(Severity).includes(severity as Severity)
          ? { severity: severity as Severity }
          : {},
        status && Object.values(CVEStatus).includes(status as CVEStatus)
          ? { status: status as CVEStatus }
          : {},
        cursor
          ? {
              OR: [
                {
                  updatedAt: { lt: new Date(cursor.updatedAt) },
                },
                {
                  updatedAt: new Date(cursor.updatedAt),
                  id: { lt: cursor.id },
                },
              ],
            }
          : {},
      ],
    };

    const rows = await db.cVE.findMany({
      where,
      orderBy: [{ updatedAt: "desc" }, { id: "desc" }],
      take: limit + 1,
    });

    const hasNext = rows.length > limit;
    const slice = hasNext ? rows.slice(0, limit) : rows;
    const nextCursor = hasNext
      ? encodeCursor({
          id: slice[slice.length - 1].id,
          updatedAt: slice[slice.length - 1].updatedAt.toISOString(),
        })
      : null;

    return jsonApiResponse(slice.map(mapCveToJsonApiResource), {
      meta: {
        count: slice.length,
        limit,
      },
      links: {
        self: request.nextUrl.pathname + request.nextUrl.search,
        next: nextCursor ? `${request.nextUrl.pathname}?cursor=${nextCursor}&limit=${limit}` : null,
      },
      headers: rate.headers,
    });
  } catch (error) {
    console.error("GET /api/v2/cves failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to list CVEs",
      code: "CVE_LIST_ERROR",
    });
  }
}

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

    const parsed = postSchema.safeParse(await request.json());
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
    const enrichment = await tryEnrichFromNvd(input.cveId);
    const cvssV3Score = input.cvssV3Score ?? enrichment?.cvssV3Score ?? null;
    const cvssV3Vector = input.cvssV3Vector ?? enrichment?.cvssV3Vector ?? null;
    const cvssV4Score = input.cvssV4Score ?? null;
    const severity = calculateSeverityFromCvss(cvssV3Score, cvssV4Score);

    const upserted = await db.cVE.upsert({
      where: { cveId: input.cveId },
      update: {
        title: input.title ?? enrichment?.title ?? input.cveId,
        description: input.description,
        publishedAt: input.publishedAt ?? enrichment?.publishedAt ?? null,
        modifiedAt: input.modifiedAt ?? enrichment?.modifiedAt ?? null,
        cvssV3Score,
        cvssV3Vector,
        cvssV4Score,
        epssScore: input.epssScore ?? null,
        status: input.status ?? CVEStatus.NEW,
        severity,
        source: input.source ?? CveSource.MANUAL,
        rawData: (input.rawData ?? enrichment?.rawData ?? null) as Prisma.InputJsonValue,
        references: input.references ?? enrichment?.references ?? null,
        vulnStatus: input.vulnStatus ?? "analyzed",
        cvssScore: cvssV3Score,
        cvssVector: cvssV3Vector,
        publishedDate: input.publishedAt ?? enrichment?.publishedAt ?? null,
        lastModifiedDate: input.modifiedAt ?? enrichment?.modifiedAt ?? null,
        version: { increment: 1 },
      },
      create: {
        cveId: input.cveId,
        title: input.title ?? enrichment?.title ?? input.cveId,
        description: input.description,
        publishedAt: input.publishedAt ?? enrichment?.publishedAt ?? null,
        modifiedAt: input.modifiedAt ?? enrichment?.modifiedAt ?? null,
        cvssV3Score,
        cvssV3Vector,
        cvssV4Score,
        epssScore: input.epssScore ?? null,
        status: input.status ?? CVEStatus.NEW,
        severity,
        source: input.source ?? CveSource.MANUAL,
        rawData: (input.rawData ?? enrichment?.rawData ?? null) as Prisma.InputJsonValue,
        references: input.references ?? enrichment?.references ?? null,
        vulnStatus: input.vulnStatus ?? "analyzed",
        cvssScore: cvssV3Score,
        cvssVector: cvssV3Vector,
        publishedDate: input.publishedAt ?? enrichment?.publishedAt ?? null,
        lastModifiedDate: input.modifiedAt ?? enrichment?.modifiedAt ?? null,
      },
    });

    await writeAuditLog({
      actor,
      action: "cve.upsert",
      resource: "cve",
      resourceId: upserted.id,
      after: {
        cveId: upserted.cveId,
        status: upserted.status,
        severity: upserted.severity,
      },
      request,
    });

    return jsonApiResponse(mapCveToJsonApiResource(upserted), {
      status: 201,
      headers: rate.headers,
    });
  } catch (error) {
    console.error("POST /api/v2/cves failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to create or update CVE",
      code: "CVE_UPSERT_ERROR",
    });
  }
}

async function tryEnrichFromNvd(cveId: string) {
  try {
    const endpoint = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
    endpoint.searchParams.set("cveId", cveId);

    const response = await fetch(endpoint.toString(), {
      headers: {
        "User-Agent": "CVE-Tracker-v2/1.0",
      },
      cache: "no-store",
    });

    if (!response.ok) return null;
    const payload = await response.json();
    const item = payload?.vulnerabilities?.[0]?.cve;
    if (!item) return null;

    const cvssV31 = item.metrics?.cvssMetricV31?.[0]?.cvssData;
    return {
      title: item.id,
      cvssV3Score: cvssV31?.baseScore ?? null,
      cvssV3Vector: cvssV31?.vectorString ?? null,
      publishedAt: item.published ? new Date(item.published) : null,
      modifiedAt: item.lastModified ? new Date(item.lastModified) : null,
      references: JSON.stringify(item.references?.map((reference: { url: string }) => reference.url) ?? []),
      rawData: item,
    };
  } catch {
    return null;
  }
}
