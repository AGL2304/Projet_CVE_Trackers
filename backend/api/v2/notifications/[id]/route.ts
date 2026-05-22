import { z } from "zod";
import { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";
import { getActor } from "@/lib/v2/auth";

const patchSchema = z.object({
  read: z.boolean(),
});

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
    if (actor.id === "system") {
      return jsonApiError(
        {
          status: "401",
          title: "Unauthorized",
          detail: "Missing user identity",
          code: "UNAUTHORIZED",
        },
        401
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

    const updated = await db.notification.updateMany({
      where: { id, userId: actor.id },
      data: {
        read: parsed.data.read,
      },
    });

    if (updated.count === 0) {
      return jsonApiError(
        {
          status: "404",
          title: "Not found",
          detail: "Notification not found",
          code: "NOT_FOUND",
        },
        404
      );
    }

    const row = await db.notification.findUniqueOrThrow({ where: { id } });
    return jsonApiResponse(
      {
        type: "notifications",
        id: row.id,
        attributes: {
          read: row.read,
          updatedAt: new Date().toISOString(),
        },
      },
      { headers: rate.headers }
    );
  } catch (error) {
    console.error("PATCH /api/v2/notifications/:id failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to update notification",
      code: "NOTIFICATION_PATCH_ERROR",
    });
  }
}
