import { existsSync, unlinkSync } from "node:fs";
import path from "node:path";
import { NextRequest, NextResponse } from "next/server";
import { isAdminAuthenticatedRequest } from "@/lib/admin-auth";
import { verifyCsrf } from "@/lib/csrf";

const REPORTS_DIR = process.env.REPORTS_DIR || path.join(process.cwd(), "data", "reports");
const PAUSE_MARKER = process.env.NVD_PAUSE_MARKER || path.join(REPORTS_DIR, ".sync-paused");

/**
 * Resume scheduled NVD syncs by removing the pause marker file.
 */
export async function POST(request: NextRequest) {
  if (!isAdminAuthenticatedRequest(request)) {
    return NextResponse.json({ error: "Admin authentication required" }, { status: 401 });
  }
  if (!verifyCsrf(request)) {
    return NextResponse.json({ error: "Invalid or missing CSRF token" }, { status: 403 });
  }

  try {
    if (existsSync(PAUSE_MARKER)) {
      unlinkSync(PAUSE_MARKER);
    }
    return NextResponse.json({ ok: true, paused: false });
  } catch (error) {
    console.error("POST /api/admin/scraping/resume failed", error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Unable to resume sync" },
      { status: 500 }
    );
  }
}
