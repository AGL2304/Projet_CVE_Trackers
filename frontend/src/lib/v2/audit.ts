import { Prisma } from "@prisma/client";
import type { NextRequest } from "next/server";
import { db } from "@/lib/db";
import type { ActorContext } from "@/lib/v2/auth";

interface AuditInput {
  actor?: ActorContext | null;
  action: string;
  resource: string;
  resourceId?: string | null;
  before?: unknown;
  after?: unknown;
  request?: NextRequest;
}

// Pseudo-actor IDs that don't correspond to a real User row in DB.
// These are produced by getActor() when the request comes from the admin
// session cookie or no session at all. We must NOT pass them as a foreign
// key — the AuditLog.userId column references User.id.
const PSEUDO_ACTOR_IDS = new Set<string>(["admin-session", "system"]);

export async function writeAuditLog(input: AuditInput) {
  const ipHeader = input.request?.headers.get("x-forwarded-for");
  const ip = ipHeader?.split(",")[0]?.trim() || input.request?.headers.get("x-real-ip") || null;

  const rawId = input.actor?.id ?? null;
  const userId = rawId && !PSEUDO_ACTOR_IDS.has(rawId) ? rawId : null;
  const userAgent = input.request?.headers.get("user-agent") ?? null;

  // Best-effort logging — never let a failed audit insert break the caller.
  // Foreign-key violations on unexpected actor IDs would otherwise 500 the
  // user's actual operation.
  try {
    await db.auditLog.create({
      data: {
        userId,
        action: input.action,
        resource: input.resource,
        resourceId: input.resourceId ?? null,
        before: toJsonOrNull(input.before),
        after: toJsonOrNull(input.after),
        ip,
        userAgent,
      },
    });
  } catch (error) {
    console.error("[audit] failed to write audit log", {
      action: input.action,
      resource: input.resource,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

function toJsonOrNull(value: unknown) {
  if (value === undefined) return undefined;
  if (value === null) return Prisma.JsonNull;
  return value as Prisma.InputJsonValue;
}
