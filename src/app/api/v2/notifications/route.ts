import { Severity } from "@prisma/client";
import { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { decodeCursor, encodeCursor, parsePositiveInt } from "@/lib/v2/cursor";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";
import { getActor } from "@/lib/v2/auth";

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
    const actor = await getActor(request);
    if (actor.id === "system") {
      return jsonApiResponse([], {
        meta: {
          count: 0,
        },
        headers: rate.headers,
      });
    }

    const params = request.nextUrl.searchParams;
    const limit = parsePositiveInt(params.get("limit"), 25, 100);
    const cursor = decodeCursor(params.get("cursor"));
    const readParam = params.get("read");
    const severity = params.get("severity");

    const rows = await db.notification.findMany({
      where: {
        userId: actor.id,
        ...(readParam !== null ? { read: readParam === "true" } : {}),
        ...(severity && Object.values(Severity).includes(severity as Severity)
          ? { severity: severity as Severity }
          : {}),
        ...(cursor
          ? {
              OR: [
                {
                  createdAt: { lt: new Date(cursor.updatedAt) },
                },
                {
                  createdAt: new Date(cursor.updatedAt),
                  id: { lt: cursor.id },
                },
              ],
            }
          : {}),
      },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: limit + 1,
      include: {
        cve: {
          select: {
            cveId: true,
          },
        },
      },
    });

    const hasNext = rows.length > limit;
    const slice = hasNext ? rows.slice(0, limit) : rows;
    const next = hasNext
      ? encodeCursor({
          id: slice[slice.length - 1].id,
          updatedAt: slice[slice.length - 1].createdAt.toISOString(),
        })
      : null;

    return jsonApiResponse(
      slice.map((row) => ({
        type: "notifications",
        id: row.id,
        attributes: {
          type: row.type,
          severity: row.severity,
          title: row.title,
          body: row.body,
          read: row.read,
          createdAt: row.createdAt,
          cveId: row.cve?.cveId ?? null,
        },
      })),
      {
        meta: {
          count: slice.length,
          limit,
        },
        links: {
          self: request.nextUrl.pathname + request.nextUrl.search,
          next: next ? `${request.nextUrl.pathname}?cursor=${next}&limit=${limit}` : null,
        },
        headers: rate.headers,
      }
    );
  } catch (error) {
    console.error("GET /api/v2/notifications failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to list notifications",
      code: "NOTIFICATION_LIST_ERROR",
    });
  }
}
