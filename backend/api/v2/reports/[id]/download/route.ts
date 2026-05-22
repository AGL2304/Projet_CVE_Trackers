import { createReadStream, statSync } from "node:fs";
import path from "node:path";
import { ReadableOptions } from "node:stream";
import { NextRequest, NextResponse } from "next/server";
import { ReportStatus } from "@prisma/client";
import { db } from "@/lib/db";
import { jsonApiError } from "@/lib/v2/jsonapi";

const REPORTS_DIR = process.env.REPORTS_DIR || path.join(process.cwd(), "data", "reports");

/**
 * Stream the generated report file to the client.
 *
 * - 404 if the job is unknown
 * - 409 if the job is QUEUED or RUNNING (not ready yet)
 * - 500 if COMPLETED but the file is missing (worker/volume mismatch)
 * - 200 with the file content otherwise
 *
 * `?inline=1` switches Content-Disposition from attachment to inline so the
 * UI can open HTML reports directly in a new tab for print-to-PDF.
 */
export async function GET(
  request: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await context.params;
    const report = await db.reportJob.findUnique({ where: { id } });

    if (!report) {
      return jsonApiError(
        { status: "404", title: "Not found", detail: "Report not found", code: "NOT_FOUND" },
        404
      );
    }

    if (report.status !== ReportStatus.COMPLETED) {
      return jsonApiError(
        {
          status: "409",
          title: "Report not ready",
          detail: `Current status: ${report.status}`,
          code: "NOT_READY",
        },
        409
      );
    }

    if (!report.storagePath) {
      return jsonApiError(
        {
          status: "500",
          title: "Storage path missing",
          detail: "Report marked completed but storagePath is empty",
          code: "STORAGE_MISSING",
        },
        500
      );
    }

    // Guard against path traversal — only allow files inside REPORTS_DIR.
    const absolute = path.resolve(report.storagePath);
    const rootResolved = path.resolve(REPORTS_DIR);
    if (!absolute.startsWith(rootResolved + path.sep) && absolute !== rootResolved) {
      // Also accept relative paths stored as `reports/xyz.html` inside REPORTS_DIR
      const fallback = path.resolve(REPORTS_DIR, path.basename(report.storagePath));
      if (!fallback.startsWith(rootResolved + path.sep)) {
        return jsonApiError(
          { status: "400", title: "Invalid storage path", code: "BAD_PATH" },
          400
        );
      }
    }

    let resolved = absolute;
    try {
      statSync(resolved);
    } catch {
      resolved = path.resolve(REPORTS_DIR, path.basename(report.storagePath));
      try {
        statSync(resolved);
      } catch {
        return jsonApiError(
          {
            status: "500",
            title: "Report file missing",
            detail: `File not found on disk: ${report.storagePath}`,
            code: "FILE_MISSING",
          },
          500
        );
      }
    }

    const stats = statSync(resolved);
    const ext = path.extname(resolved).toLowerCase();
    const contentType =
      ext === ".html"
        ? "text/html; charset=utf-8"
        : ext === ".csv"
        ? "text/csv; charset=utf-8"
        : ext === ".json"
        ? "application/json; charset=utf-8"
        : "application/octet-stream";

    const url = new URL(request.url);
    const inline = url.searchParams.get("inline") === "1";
    const filename = `cve-report-${report.id}${ext}`;
    const disposition = inline
      ? `inline; filename="${filename}"`
      : `attachment; filename="${filename}"`;

    // Stream rather than buffer — reports can reach tens of MB.
    const nodeStream = createReadStream(resolved);
    const webStream = nodeToWebStream(nodeStream);

    return new NextResponse(webStream as unknown as BodyInit, {
      status: 200,
      headers: {
        "Content-Type": contentType,
        "Content-Length": String(stats.size),
        "Content-Disposition": disposition,
        "Cache-Control": "private, no-store",
      },
    });
  } catch (error) {
    console.error("GET /api/v2/reports/:id/download failed", error);
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to download report",
      code: "DOWNLOAD_ERROR",
    });
  }
}

function nodeToWebStream(nodeStream: NodeJS.ReadableStream, _opts?: ReadableOptions): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      nodeStream.on("data", (chunk: Buffer | string) => {
        controller.enqueue(typeof chunk === "string" ? new TextEncoder().encode(chunk) : new Uint8Array(chunk));
      });
      nodeStream.on("end", () => controller.close());
      nodeStream.on("error", (err) => controller.error(err));
    },
    cancel() {
      (nodeStream as NodeJS.ReadableStream & { destroy?: () => void }).destroy?.();
    },
  });
}
