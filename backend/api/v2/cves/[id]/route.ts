import { CVEStatus, CveSource, Prisma, UserRole } from "@prisma/client";
import { z } from "zod";
import { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { calculateSeverityFromCvss } from "@/lib/v2/severity";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";
import { mapCveToJsonApiResource } from "@/lib/v2/mappers";
import { getActor, hasRole } from "@/lib/v2/auth";
import { writeAuditLog } from "@/lib/v2/audit";

const patchSchema = z.object({
  version: z.number().int().positive(),
  title: z.string().min(3).optional(),
  description: z.string().min(3).optional(),
  publishedAt: z.coerce.date().optional().nullable(),
  modifiedAt: z.coerce.date().optional().nullable(),
  cvssV3Score: z.number().min(0).max(10).optional().nullable(),
  cvssV3Vector: z.string().optional().nullable(),
  cvssV4Score: z.number().min(0).max(10).optional().nullable(),
  epssScore: z.number().min(0).max(1).optional().nullable(),
  status: z.nativeEnum(CVEStatus).optional(),
  source: z.nativeEnum(CveSource).optional(),
  references: z.string().optional().nullable(),
  vulnStatus: z.string().optional().nullable(),
  rawData: z.unknown().optional(),
});

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
    const include = request.nextUrl.searchParams.get("include") ?? "";
    const includes = include.split(",").map((item) => item.trim());

    const cve = await db.cVE.findFirst({
      where: {
        OR: [{ id }, { cveId: id }],
      },
      include: {
        cweLinks: {
          include: { cwe: true },
        },
        productLinks: {
          include: { product: true },
        },
        comments: {
          where: { deleted: false },
          include: { user: true },
          orderBy: { createdAt: "desc" },
        },
        tagLinks: {
          include: { tag: true },
        },
      },
    });

    if (!cve) {
      return jsonApiError(
        {
          status: "404",
          title: "Not found",
          detail: "CVE not found",
          code: "NOT_FOUND",
        },
        404
      );
    }

    const included: unknown[] = [];
    if (includes.includes("cwe")) {
      included.push(
        ...cve.cweLinks.map((link) => ({
          type: "cwes",
          id: link.cwe.id,
          attributes: {
            cweId: link.cwe.cweId,
            name: link.cwe.name,
            description: link.cwe.description,
            category: link.cwe.category,
          },
        }))
      );
    }

    if (includes.includes("products")) {
      included.push(
        ...cve.productLinks.map((link) => ({
          type: "products",
          id: link.product.id,
          attributes: {
            name: link.product.name,
            vendor: link.product.vendor,
            version: link.product.version,
            cpe: link.product.cpe,
            patchStatus: link.patchStatus,
          },
        }))
      );
    }

    if (includes.includes("comments")) {
      included.push(
        ...cve.comments.map((comment) => ({
          type: "comments",
          id: comment.id,
          attributes: {
            content: comment.content,
            parentId: comment.parentId,
            createdAt: comment.createdAt,
            updatedAt: comment.updatedAt,
            author: {
              id: comment.user.id,
              email: comment.user.email,
              name: comment.user.name,
            },
          },
        }))
      );
    }

    if (includes.includes("tags")) {
      included.push(
        ...cve.tagLinks.map((link) => ({
          type: "tags",
          id: link.tag.id,
          attributes: {
            name: link.tag.name,
            color: link.tag.color,
            description: link.tag.description,
          },
        }))
      );
    }

    return jsonApiResponse(mapCveToJsonApiResource(cve), {
      included,
      headers: rate.headers,
    });
  } catch (error) {
    console.error("GET /api/v2/cves/:id failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to fetch CVE details",
      code: "CVE_DETAIL_ERROR",
    });
  }
}

export async function PATCH(
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

    const { id } = await context.params;
    const parsed = patchSchema.safeParse(await request.json());
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

    const patch = parsed.data;
    const target = await db.cVE.findFirst({
      where: {
        OR: [{ id }, { cveId: id }],
      },
    });

    if (!target) {
      return jsonApiError(
        {
          status: "404",
          title: "Not found",
          detail: "CVE not found",
          code: "NOT_FOUND",
        },
        404
      );
    }

    const nextV3 = patch.cvssV3Score ?? target.cvssV3Score;
    const nextV4 = patch.cvssV4Score ?? target.cvssV4Score;
    const severity = calculateSeverityFromCvss(nextV3, nextV4);

    const updatePayload: Prisma.CVEUpdateInput = {
      ...(patch.title !== undefined ? { title: patch.title } : {}),
      ...(patch.description !== undefined ? { description: patch.description } : {}),
      ...(patch.publishedAt !== undefined ? { publishedAt: patch.publishedAt } : {}),
      ...(patch.modifiedAt !== undefined ? { modifiedAt: patch.modifiedAt } : {}),
      ...(patch.cvssV3Score !== undefined ? { cvssV3Score: patch.cvssV3Score } : {}),
      ...(patch.cvssV3Vector !== undefined ? { cvssV3Vector: patch.cvssV3Vector } : {}),
      ...(patch.cvssV4Score !== undefined ? { cvssV4Score: patch.cvssV4Score } : {}),
      ...(patch.epssScore !== undefined ? { epssScore: patch.epssScore } : {}),
      ...(patch.status !== undefined ? { status: patch.status } : {}),
      ...(patch.source !== undefined ? { source: patch.source } : {}),
      ...(patch.references !== undefined ? { references: patch.references } : {}),
      ...(patch.vulnStatus !== undefined ? { vulnStatus: patch.vulnStatus } : {}),
      ...(patch.rawData !== undefined
        ? { rawData: patch.rawData as Prisma.InputJsonValue }
        : {}),
      severity,
      cvssScore: nextV3,
      cvssVector: patch.cvssV3Vector ?? target.cvssV3Vector,
      publishedDate: patch.publishedAt ?? target.publishedAt ?? target.publishedDate,
      lastModifiedDate: patch.modifiedAt ?? target.modifiedAt ?? target.lastModifiedDate,
      version: { increment: 1 },
    };

    const result = await db.cVE.updateMany({
      where: { id: target.id, version: patch.version },
      data: updatePayload,
    });

    if (result.count === 0) {
      return jsonApiError(
        {
          status: "409",
          title: "Conflict",
          detail: "Version mismatch. Refresh before updating.",
          code: "OPTIMISTIC_LOCK_CONFLICT",
        },
        409
      );
    }

    const updated = await db.cVE.findUniqueOrThrow({
      where: { id: target.id },
    });

    await writeAuditLog({
      actor,
      action: "cve.patch",
      resource: "cve",
      resourceId: updated.id,
      before: {
        version: target.version,
        status: target.status,
        severity: target.severity,
      },
      after: {
        version: updated.version,
        status: updated.status,
        severity: updated.severity,
      },
      request,
    });

    return jsonApiResponse(mapCveToJsonApiResource(updated), {
      headers: rate.headers,
    });
  } catch (error) {
    console.error("PATCH /api/v2/cves/:id failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to patch CVE",
      code: "CVE_PATCH_ERROR",
    });
  }
}
