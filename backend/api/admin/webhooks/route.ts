import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { isAdminAuthenticatedRequest } from "@/lib/admin-auth";
import { verifyCsrf } from "@/lib/csrf";
import {
  WebhookEvent,
  deleteSubscription,
  listSubscriptions,
  upsertSubscription,
} from "@/lib/webhooks";

const KNOWN_EVENTS: WebhookEvent[] = [
  "cve.created",
  "cve.severity.changed",
  "cve.status.changed",
  "asset.created",
  "asset.updated",
  "vulnerability.created",
  "vulnerability.resolved",
];

const subscriptionSchema = z.object({
  id: z.string().trim().min(2).max(60).regex(/^[a-z0-9-]+$/i, "id must be alphanumeric or hyphen"),
  url: z.string().url().max(500),
  secret: z.string().min(16, "secret must be at least 16 characters"),
  events: z.array(z.enum(KNOWN_EVENTS as [WebhookEvent, ...WebhookEvent[]])).min(1),
  active: z.boolean().default(true),
});

function unauthorized() {
  return NextResponse.json({ error: "Admin authentication required" }, { status: 401 });
}

export async function GET(request: NextRequest) {
  if (!isAdminAuthenticatedRequest(request)) return unauthorized();
  const subs = listSubscriptions().map((s) => ({ ...s, secret: "***" })); // mask
  return NextResponse.json({ subscriptions: subs, knownEvents: KNOWN_EVENTS });
}

export async function POST(request: NextRequest) {
  if (!isAdminAuthenticatedRequest(request)) return unauthorized();
  if (!verifyCsrf(request)) {
    return NextResponse.json({ error: "Invalid or missing CSRF token" }, { status: 403 });
  }
  const parsed = subscriptionSchema.safeParse(await request.json());
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ") },
      { status: 400 }
    );
  }
  const sub = upsertSubscription(parsed.data);
  return NextResponse.json({ ...sub, secret: "***" }, { status: 201 });
}

export async function DELETE(request: NextRequest) {
  if (!isAdminAuthenticatedRequest(request)) return unauthorized();
  if (!verifyCsrf(request)) {
    return NextResponse.json({ error: "Invalid or missing CSRF token" }, { status: 403 });
  }
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  if (!id) return NextResponse.json({ error: "id required" }, { status: 400 });
  const removed = deleteSubscription(id);
  if (!removed) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json({ ok: true });
}
