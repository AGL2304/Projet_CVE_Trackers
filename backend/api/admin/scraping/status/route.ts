import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { NextRequest, NextResponse } from "next/server";
import { SyncJobStatus, SyncSource } from "@prisma/client";
import { db } from "@/lib/db";
import { isAdminAuthenticatedRequest } from "@/lib/admin-auth";

const REPORTS_DIR = process.env.REPORTS_DIR || path.join(process.cwd(), "data", "reports");
const PAUSE_MARKER = process.env.NVD_PAUSE_MARKER || path.join(REPORTS_DIR, ".sync-paused");

function readPauseInfo(): { paused: boolean; pausedAt: string | null } {
  if (!existsSync(PAUSE_MARKER)) return { paused: false, pausedAt: null };
  try {
    const data = JSON.parse(readFileSync(PAUSE_MARKER, "utf8"));
    return { paused: true, pausedAt: typeof data?.pausedAt === "string" ? data.pausedAt : null };
  } catch {
    return { paused: true, pausedAt: null };
  }
}

/**
 * Returns a snapshot of the automatic NVD scraping pipeline:
 *   • most recent successful sync
 *   • most recent failed sync
 *   • currently running sync (if any)
 *   • total CVEs stored
 *   • configured intervals (read from env, fall back to defaults)
 *   • estimated next run timestamp
 */
export async function GET(request: NextRequest) {
  if (!isAdminAuthenticatedRequest(request)) {
    return NextResponse.json({ error: "Admin authentication required" }, { status: 401 });
  }

  try {
    const [lastSuccess, lastFailure, running, totalCves, recentJobs] = await Promise.all([
      db.syncJob.findFirst({
        where: { source: SyncSource.NVD, status: SyncJobStatus.COMPLETED },
        orderBy: { completedAt: "desc" },
      }),
      db.syncJob.findFirst({
        where: { source: SyncSource.NVD, status: SyncJobStatus.FAILED },
        orderBy: { completedAt: "desc" },
      }),
      db.syncJob.findFirst({
        where: { source: SyncSource.NVD, status: SyncJobStatus.RUNNING },
        orderBy: { startedAt: "desc" },
      }),
      db.cVE.count(),
      db.syncJob.findMany({
        where: { source: SyncSource.NVD },
        orderBy: { createdAt: "desc" },
        take: 10,
        select: {
          id: true,
          status: true,
          startedAt: true,
          completedAt: true,
          newCount: true,
          updatedCount: true,
          errorCount: true,
        },
      }),
    ]);

    const fullSyncIntervalMs = Number(process.env.NVD_FULL_SYNC_INTERVAL_MS) || 24 * 60 * 60 * 1000;
    const deltaIntervalMs = Number(process.env.NVD_DELTA_INTERVAL_MS) || 15 * 60 * 1000;
    const enabled = (process.env.NVD_AUTO_SYNC_ENABLED ?? "true").toLowerCase() !== "false";
    const pauseInfo = readPauseInfo();

    const lastRunAt = lastSuccess?.completedAt ?? null;
    const nextDeltaAt = lastRunAt ? new Date(lastRunAt.getTime() + deltaIntervalMs) : null;
    const nextFullAt = lastRunAt ? new Date(lastRunAt.getTime() + fullSyncIntervalMs) : null;

    return NextResponse.json({
      enabled,
      paused: pauseInfo.paused,
      pausedAt: pauseInfo.pausedAt,
      intervals: {
        deltaMs: deltaIntervalMs,
        fullMs: fullSyncIntervalMs,
      },
      running: running
        ? {
            id: running.id,
            startedAt: running.startedAt,
          }
        : null,
      lastSuccess: lastSuccess
        ? {
            id: lastSuccess.id,
            completedAt: lastSuccess.completedAt,
            newCount: lastSuccess.newCount,
            updatedCount: lastSuccess.updatedCount,
            errorCount: lastSuccess.errorCount,
          }
        : null,
      lastFailure: lastFailure
        ? {
            id: lastFailure.id,
            completedAt: lastFailure.completedAt,
            errorCount: lastFailure.errorCount,
          }
        : null,
      nextDeltaAt,
      nextFullAt,
      totalCves,
      recentJobs,
    });
  } catch (error) {
    console.error("GET /api/admin/scraping/status failed", error);
    return NextResponse.json({ error: "Unable to read scraping status" }, { status: 500 });
  }
}
