import { Prisma, UserRole } from "@prisma/client";
import { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";
import { getActor, hasRole } from "@/lib/v2/auth";
import { writeAuditLog } from "@/lib/v2/audit";

export async function DELETE(
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
    if (!hasRole(actor, [UserRole.ADMIN])) {
      return jsonApiError(
        {
          status: "403",
          title: "Forbidden",
          detail: "Only admin can anonymize users",
          code: "FORBIDDEN",
        },
        403
      );
    }

    const { id } = await context.params;
    const target = await db.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
      },
    });

    if (!target) {
      return jsonApiError(
        {
          status: "404",
          title: "Not found",
          detail: "User not found",
          code: "NOT_FOUND",
        },
        404
      );
    }

    const anonymizedEmail = `anonymized-${target.id}@redacted.local`;
    const anonymizedName = `Anonymized User ${target.id.slice(0, 6)}`;

    const updated = await db.user.update({
      where: { id: target.id },
      data: {
        email: anonymizedEmail,
        name: anonymizedName,
        mfaEnabled: false,
        preferences: Prisma.JsonNull,
        deletedAt: new Date(),
        anonymizedAt: new Date(),
      },
    });

    await writeAuditLog({
      actor,
      action: "user.anonymize",
      resource: "user",
      resourceId: updated.id,
      before: {
        email: target.email,
        name: target.name,
      },
      after: {
        email: updated.email,
        name: updated.name,
        anonymizedAt: updated.anonymizedAt,
      },
      request,
    });

    return jsonApiResponse(
      {
        type: "users",
        id: updated.id,
        attributes: {
          email: updated.email,
          name: updated.name,
          role: updated.role,
          deletedAt: updated.deletedAt,
          anonymizedAt: updated.anonymizedAt,
        },
      },
      { headers: rate.headers }
    );
  } catch (error) {
    console.error("DELETE /api/v2/users/:id failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to anonymize user",
      code: "USER_ANONYMIZE_ERROR",
    });
  }
}
