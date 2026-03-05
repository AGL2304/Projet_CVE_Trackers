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

export async function writeAuditLog(input: AuditInput) {
  const ipHeader = input.request?.headers.get("x-forwarded-for");
  const ip = ipHeader?.split(",")[0]?.trim() || input.request?.headers.get("x-real-ip") || null;

  await db.auditLog.create({
    data: {
      userId: input.actor?.id ?? null,
      action: input.action,
      resource: input.resource,
      resourceId: input.resourceId ?? null,
      before: toJsonOrNull(input.before),
      after: toJsonOrNull(input.after),
      ip,
      userAgent: input.request?.headers.get("user-agent") ?? null,
    },
  });
}

function toJsonOrNull(value: unknown) {
  if (value === undefined) return undefined;
  if (value === null) return Prisma.JsonNull;
  return value as Prisma.InputJsonValue;
}
