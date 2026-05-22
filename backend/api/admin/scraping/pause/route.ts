import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { NextRequest, NextResponse } from "next/server";
import { isAdminAuthenticatedRequest } from "@/lib/admin-auth";
import { verifyCsrf } from "@/lib/csrf";

const REPORTS_DIR = process.env.REPORTS_DIR || path.join(process.cwd(), "data", "reports");
const PAUSE_MARKER = process.env.NVD_PAUSE_MARKER || path.join(REPORTS_DIR, ".sync-paused");

/**
 * Pause scheduled NVD syncs. Drops a marker file on the shared volume that
 * the worker checks each tick. Manually-triggered SyncJobs continue to run.
 */
export async function POST(request: NextRequest) {
  if (!isAdminAuthenticatedRequest(request)) {
    return NextResponse.json({ error: "Admin authentication required" }, { status: 401 });
  }
  if (!verifyCsrf(request)) {
    return NextResponse.json({ error: "Invalid or missing CSRF token" }, { status: 403 });
  }

  try {
    mkdirSync(path.dirname(PAUSE_MARKER), { recursive: true });
    writeFileSync(
      PAUSE_MARKER,
      JSON.stringify({ pausedAt: new Date().toISOString() }, null, 2),
      "utf8"
    );
    return NextResponse.json({ ok: true, paused: true, markerPath: PAUSE_MARKER });
  } catch (error) {
    console.error("POST /api/admin/scraping/pause failed", error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Unable to pause sync" },
      { status: 500 }
    );
  }
}
