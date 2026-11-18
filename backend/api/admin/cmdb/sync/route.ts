import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { isAdminAuthenticatedRequest } from "@/lib/admin-auth";
import { fetchCmdbAssets, type CmdbAssetInput } from "@/lib/cmdb";
import { getAppSettings, setCmdbSyncStatus } from "@/lib/app-settings";
import { publishEvent } from "@/lib/webhooks";
import { writeAuditLog } from "@/lib/v2/audit";

// Above this many touched assets we stop emitting one webhook per asset (it
// would spawn thousands of concurrent deliveries); the audit log + sync status
// still capture the run in full.
const PER_ASSET_EVENT_CAP = 500;

function unauthorized() {
  return NextResponse.json({ error: "Admin authentication required" }, { status: 401 });
}

// Match an incoming CMDB asset to an existing row. We try the strongest
// identity first (hostname, then IP) and fall back to name+type so re-syncs
// update in place instead of creating duplicates.
function matchWhere(asset: CmdbAssetInput) {
  return {
    OR: [
      ...(asset.hostname ? [{ hostname: asset.hostname }] : []),
      ...(asset.ip ? [{ ip: asset.ip }] : []),
      { name: asset.name, type: asset.type },
    ],
  };
}

const EVENT_SELECT = {
  id: true,
  name: true,
  type: true,
  ip: true,
  hostname: true,
  criticality: true,
  status: true,
} as const;

export async function POST(request: NextRequest) {
  if (!isAdminAuthenticatedRequest(request)) {
    return unauthorized();
  }

  try {
    const settings = await getAppSettings();

    // Respect the master switch: a manual sync must not silently write assets
    // while the integration is turned off. The UI persists the toggle just
    // before calling this, so an operator who wants to sync has it enabled.
    if (!settings.cmdbEnabled) {
      return NextResponse.json(
        { ok: false, error: "CMDB integration is disabled. Enable it in Settings before running a sync." },
        { status: 409 }
      );
    }

    if (!settings.cmdbEndpoint) {
      return NextResponse.json({ error: "CMDB endpoint is not configured" }, { status: 400 });
    }

    const result = await fetchCmdbAssets({
      cmdbEndpoint: settings.cmdbEndpoint,
      cmdbApiToken: settings.cmdbApiToken,
    });

    let created = 0;
    let updated = 0;
    let failed = 0;
    const createdAssets: Array<Record<string, unknown>> = [];
    const updatedAssets: Array<Record<string, unknown>> = [];

    // Resilient, idempotent upsert. A single malformed record must not abort
    // the whole sync - count it as failed and keep going so the rest still lands.
    for (const asset of result.assets) {
      const data = {
        name: asset.name,
        type: asset.type,
        ip: asset.ip,
        hostname: asset.hostname,
        description: asset.description,
        criticality: asset.criticality,
        status: asset.status,
      };

      try {
        const existing = await db.asset.findFirst({
          where: matchWhere(asset),
          select: { id: true },
        });

        if (existing) {
          const row = await db.asset.update({
            where: { id: existing.id },
            data,
            select: EVENT_SELECT,
          });
          updated += 1;
          updatedAssets.push(row as Record<string, unknown>);
        } else {
          const row = await db.asset.create({ data, select: EVENT_SELECT });
          created += 1;
          createdAssets.push(row as Record<string, unknown>);
        }
      } catch (assetError) {
        failed += 1;
        console.error(
          `[cmdb-sync] failed to upsert asset "${asset.name}": ${
            assetError instanceof Error ? assetError.message : assetError
          }`
        );
      }
    }

    // Notify downstream consumers (SIEM, Scanner) that the inventory changed.
    // Fire-and-forget; capped so a huge sync doesn't flood subscribers.
    const touched = created + updated;
    if (touched <= PER_ASSET_EVENT_CAP) {
      for (const a of createdAssets) {
        publishEvent("asset.created", { ...a, source: "cmdb-sync" });
      }
      for (const a of updatedAssets) {
        publishEvent("asset.updated", { ...a, source: "cmdb-sync" });
      }
    }

    const message = `${created} created, ${updated} updated${failed ? `, ${failed} failed` : ""} from ${result.rawCount} CMDB records`;
    // A run that mapped records but landed none of them is reported as an error
    // so the operator notices, instead of a misleading green "ok".
    const status: "ok" | "error" = result.assets.length > 0 && touched === 0 ? "error" : "ok";
    const syncedSettings = await setCmdbSyncStatus({ status, message });

    await writeAuditLog({
      action: "cmdb.sync",
      resource: "cmdb",
      resourceId: "settings",
      after: { created, updated, failed, rawCount: result.rawCount, mappedCount: result.assets.length },
      request,
    });

    return NextResponse.json({
      ok: status === "ok",
      created,
      updated,
      failed,
      rawCount: result.rawCount,
      mappedCount: result.assets.length,
      lastSyncAt: syncedSettings.cmdbLastSyncAt,
      message,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown CMDB sync error";
    try {
      await setCmdbSyncStatus({ status: "error", message });
    } catch (statusError) {
      console.error("Unable to persist CMDB sync status", statusError);
    }

    return NextResponse.json({ ok: false, error: message }, { status: 502 });
  }
}
