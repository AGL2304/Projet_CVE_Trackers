import { NextRequest } from "next/server";
import { jsonApiResponse } from "@/lib/v2/jsonapi";

export async function GET(_request: NextRequest) {
  return jsonApiResponse(
    {
      type: "api",
      id: "v2",
      attributes: {
        name: "CVE Tracker API v2",
        specification: "JSON:API",
      },
    },
    {
      links: {
        cves: "/api/v2/cves",
        analytics: "/api/v2/analytics/dashboard",
        sync: "/api/v2/sync/nvd",
        reports: "/api/v2/reports/generate",
        notifications: "/api/v2/notifications",
        openapi: "/api/v2/openapi",
      },
    }
  );
}
