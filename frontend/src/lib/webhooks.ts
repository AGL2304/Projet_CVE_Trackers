import { createHmac } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";

/**
 * Lightweight webhook publisher.
 *
 * V1 — JSON-file backed subscription registry, fire-and-forget HTTP POST
 * with HMAC-SHA256 signature. Suitable for a handful of internal
 * subscribers (Scanner, SIEM). A future Prisma model `WebhookSubscription`
 * will replace the file store when we need RBAC and per-event filtering.
 *
 * Subscriber registry shape (`webhooks-subscriptions.json`):
 *   {
 *     "subscriptions": [
 *       {
 *         "id": "siem-prod",
 *         "url": "http://siem:8000/webhooks/cve-tracker",
 *         "secret": "shared-hmac-secret",
 *         "events": ["cve.created", "cve.severity.changed", "asset.created"],
 *         "active": true,
 *         "createdAt": "2026-05-22T14:00:00.000Z"
 *       }
 *     ]
 *   }
 */

export type WebhookEvent =
  | "cve.created"
  | "cve.severity.changed"
  | "cve.status.changed"
  | "asset.created"
  | "asset.updated"
  | "vulnerability.created"
  | "vulnerability.resolved";

export interface WebhookSubscription {
  id: string;
  url: string;
  secret: string;
  events: WebhookEvent[];
  active: boolean;
  createdAt: string;
}

export interface WebhookPayload {
  id: string;
  event: WebhookEvent;
  timestamp: string;
  // ECS-flavoured envelope
  ecs: {
    version: "8.10";
    event: {
      kind: "state" | "event";
      category: string;
      action: WebhookEvent;
      id: string;
    };
  };
  data: Record<string, unknown>;
}

const REPORTS_DIR = process.env.REPORTS_DIR || path.join(process.cwd(), "data", "reports");
const REGISTRY_PATH =
  process.env.WEBHOOKS_REGISTRY ||
  path.join(path.dirname(REPORTS_DIR), "webhooks-subscriptions.json");

function loadRegistry(): { subscriptions: WebhookSubscription[] } {
  if (!existsSync(REGISTRY_PATH)) {
    return { subscriptions: [] };
  }
  try {
    return JSON.parse(readFileSync(REGISTRY_PATH, "utf8"));
  } catch (e) {
    console.error("[webhooks] registry corrupted, returning empty list", e);
    return { subscriptions: [] };
  }
}

function saveRegistry(registry: { subscriptions: WebhookSubscription[] }): void {
  mkdirSync(path.dirname(REGISTRY_PATH), { recursive: true });
  writeFileSync(REGISTRY_PATH, JSON.stringify(registry, null, 2), "utf8");
}

export function listSubscriptions(): WebhookSubscription[] {
  return loadRegistry().subscriptions;
}

export function upsertSubscription(sub: Omit<WebhookSubscription, "createdAt"> & { createdAt?: string }): WebhookSubscription {
  const registry = loadRegistry();
  const idx = registry.subscriptions.findIndex((s) => s.id === sub.id);
  const next: WebhookSubscription = {
    ...sub,
    createdAt: sub.createdAt ?? new Date().toISOString(),
  };
  if (idx >= 0) registry.subscriptions[idx] = next;
  else registry.subscriptions.push(next);
  saveRegistry(registry);
  return next;
}

export function deleteSubscription(id: string): boolean {
  const registry = loadRegistry();
  const before = registry.subscriptions.length;
  registry.subscriptions = registry.subscriptions.filter((s) => s.id !== id);
  if (registry.subscriptions.length === before) return false;
  saveRegistry(registry);
  return true;
}

function sign(body: string, secret: string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

/**
 * Publish an event to all matching subscribers. Fire-and-forget: callers
 * should not await this on the critical path. Failures are logged but
 * never thrown — a flaky subscriber must not break the trigger operation.
 */
export function publishEvent(event: WebhookEvent, data: Record<string, unknown>): void {
  const subs = listSubscriptions().filter((s) => s.active && s.events.includes(event));
  if (subs.length === 0) return;

  const payload: WebhookPayload = {
    id: `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    event,
    timestamp: new Date().toISOString(),
    ecs: {
      version: "8.10",
      event: {
        kind: event.startsWith("asset.") ? "state" : "event",
        category: event.startsWith("cve.") ? "vulnerability" : "host",
        action: event,
        id: `${event}-${Date.now()}`,
      },
    },
    data,
  };
  const body = JSON.stringify(payload);

  for (const sub of subs) {
    const signature = sign(body, sub.secret);
    // No await — let it run async
    fetch(sub.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-cve-tracker-event": event,
        "x-cve-tracker-signature": `sha256=${signature}`,
        "x-cve-tracker-delivery": payload.id,
      },
      body,
    }).catch((err) => {
      console.warn(
        `[webhooks] delivery failed: subscriber=${sub.id} event=${event}: ${err instanceof Error ? err.message : err}`
      );
    });
  }
}
