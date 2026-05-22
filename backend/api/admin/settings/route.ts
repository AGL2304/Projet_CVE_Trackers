import { z } from "zod";
import { NextRequest, NextResponse } from "next/server";
import { isAdminAuthenticatedRequest } from "@/lib/admin-auth";
import { getAppSettings, saveAppSettings } from "@/lib/app-settings";
import { verifyCsrf } from "@/lib/csrf";

const settingsSchema = z.object({
  language: z.enum(["fr", "en"]),
  nvdApiKey: z.string().trim().optional().default(""),
  cmdbEndpoint: z.string().trim().url().or(z.literal("")).default(""),
  cmdbApiToken: z.string().trim().optional().default(""),
  webhookUrl: z.string().trim().url().or(z.literal("")).default(""),
  cmdbEnabled: z.boolean().default(false),
});

function unauthorized() {
  return NextResponse.json(
    {
      error: "Admin authentication required",
    },
    { status: 401 }
  );
}

export async function GET(request: NextRequest) {
  if (!isAdminAuthenticatedRequest(request)) {
    return unauthorized();
  }

  try {
    const settings = await getAppSettings();
    return NextResponse.json(settings);
  } catch (error) {
    console.error("GET /api/admin/settings failed", error);
    return NextResponse.json(
      {
        error: "Unable to read settings",
      },
      { status: 500 }
    );
  }
}

export async function PUT(request: NextRequest) {
  if (!isAdminAuthenticatedRequest(request)) {
    return unauthorized();
  }
  if (!verifyCsrf(request)) {
    return NextResponse.json({ error: "Invalid or missing CSRF token" }, { status: 403 });
  }

  try {
    const parsed = settingsSchema.safeParse(await request.json());
    if (!parsed.success) {
      return NextResponse.json(
        {
          error: parsed.error.issues.map((issue) => issue.message).join("; "),
        },
        { status: 400 }
      );
    }

    const settings = await saveAppSettings(parsed.data);
    return NextResponse.json(settings);
  } catch (error) {
    console.error("PUT /api/admin/settings failed", error);
    return NextResponse.json(
      {
        error: "Unable to update settings",
      },
      { status: 500 }
    );
  }
}
