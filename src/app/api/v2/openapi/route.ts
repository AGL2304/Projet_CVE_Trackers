import { NextRequest } from "next/server";
import { jsonApiResponse } from "@/lib/v2/jsonapi";

export async function GET(_request: NextRequest) {
  const spec = {
    openapi: "3.1.0",
    info: {
      title: "CVE Tracker API v2",
      version: "2.0.0",
    },
    servers: [{ url: "/api/v2" }],
    paths: {
      "/cves": {
        get: { summary: "List CVEs with cursor pagination" },
        post: { summary: "Create or import a CVE (upsert by cveId)" },
      },
      "/cves/{id}": {
        get: { summary: "Get CVE details" },
        patch: { summary: "Patch CVE with optimistic locking" },
      },
      "/sync/nvd": {
        post: { summary: "Trigger NVD synchronization" },
      },
      "/analytics/dashboard": {
        get: { summary: "Dashboard aggregates" },
      },
      "/reports/generate": {
        post: { summary: "Generate report job" },
      },
      "/notifications": {
        get: { summary: "List current user notifications" },
      },
    },
  };

  return jsonApiResponse(
    {
      type: "openapi",
      id: "v2",
      attributes: spec,
    },
    {
      links: {
        swagger: "/api/v2/openapi",
      },
    }
  );
}
