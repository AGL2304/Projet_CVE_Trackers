import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { SyncJobStatus, SyncSource } from "@prisma/client";
import { db } from "@/lib/db";
import { isAdminAuthenticatedRequest } from "@/lib/admin-auth";
import { verifyCsrf } from "@/lib/csrf";

const triggerSchema = z.object({
  mode: z.enum(["delta", "full"]).default("delta"),
});

/**
 * Manually trigger a NVD scraping run. We don't fetch inline here — we
 * just enqueue a SyncJob row that the background worker will pick up on
 * its next tick. This keeps the request fast and avoids blocking the
 * Next.js process on slow NVD pagination.
 */
export async function POST(request: NextRequest) {
  if (!isAdminAuthenticatedRequest(request)) {
    return NextResponse.json({ error: "Admin authentication required" }, { status: 401 });
  }
  if (!verifyCsrf(request)) {
    return NextResponse.json({ error: "Invalid or missing CSRF token" }, { status: 403 });
  }

  let body: unknown = {};
  try {
    body = await request.json();
  } catch {
    // empty body is fine — defaults apply
  }

  const parsed = triggerSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.issues.map((i) => i.message).join("; ") },
      { status: 400 }
    );
  }

  // Reject if a sync is already running — prevents the user from queueing
  // a dogpile of full syncs that would just thrash NVD's rate limit.
  const inFlight = await db.syncJob.findFirst({
    where: { source: SyncSource.NVD, status: { in: [SyncJobStatus.RUNNING, SyncJobStatus.QUEUED] } },
    select: { id: true, status: true, startedAt: true },
  });
  if (inFlight) {
    return NextResponse.json(
      {
        error: "A sync is already in progress",
        jobId: inFlight.id,
        status: inFlight.status,
        startedAt: inFlight.startedAt,
      },
      { status: 409 }
    );
  }

  const job = await db.syncJob.create({
    data: {
      source: SyncSource.NVD,
      status: SyncJobStatus.QUEUED,
      logs: [`Manually triggered (${parsed.data.mode}) at ${new Date().toISOString()}`],
    },
  });

  return NextResponse.json(
    {
      ok: true,
      jobId: job.id,
      mode: parsed.data.mode,
      message: "Sync enqueued — the worker will pick it up within the poll interval.",
    },
    { status: 202 }
  );
}
