import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { isAdminAuthenticatedRequest } from "@/lib/admin-auth";
import { fetchCmdbAssets } from "@/lib/cmdb";
import { getAppSettings, setCmdbSyncStatus } from "@/lib/app-settings";

function unauthorized() {
  return NextResponse.json(
    {
      error: "Admin authentication required",
    },
    { status: 401 }
  );
}

export async function POST(request: NextRequest) {
  if (!isAdminAuthenticatedRequest(request)) {
    return unauthorized();
  }

  try {
    const settings = await getAppSettings();
    if (!settings.cmdbEndpoint) {
      return NextResponse.json(
        {
          error: "CMDB endpoint is not configured",
        },
        { status: 400 }
      );
    }

    const result = await fetchCmdbAssets({
      cmdbEndpoint: settings.cmdbEndpoint,
      cmdbApiToken: settings.cmdbApiToken,
    });

    let created = 0;
    let updated = 0;

    for (const asset of result.assets) {
      const existing = await db.asset.findFirst({
        where: {
          OR: [
            ...(asset.hostname ? [{ hostname: asset.hostname }] : []),
            ...(asset.ip ? [{ ip: asset.ip }] : []),
            { name: asset.name, type: asset.type },
          ],
        },
        select: { id: true },
      });

      if (existing) {
        await db.asset.update({
          where: { id: existing.id },
          data: {
            name: asset.name,
            type: asset.type,
            ip: asset.ip,
            hostname: asset.hostname,
            description: asset.description,
            criticality: asset.criticality,
            status: asset.status,
          },
        });
        updated += 1;
      } else {
        await db.asset.create({
          data: {
            name: asset.name,
            type: asset.type,
            ip: asset.ip,
            hostname: asset.hostname,
            description: asset.description,
            criticality: asset.criticality,
            status: asset.status,
          },
        });
        created += 1;
      }
    }

    const message = `${created} created, ${updated} updated from ${result.rawCount} CMDB records`;
    const syncedSettings = await setCmdbSyncStatus({
      status: "ok",
      message,
    });

    return NextResponse.json({
      ok: true,
      created,
      updated,
      rawCount: result.rawCount,
      mappedCount: result.assets.length,
      lastSyncAt: syncedSettings.cmdbLastSyncAt,
      message,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown CMDB sync error";
    try {
      await setCmdbSyncStatus({
        status: "error",
        message,
      });
    } catch (statusError) {
      console.error("Unable to persist CMDB sync status", statusError);
    }

    return NextResponse.json(
      {
        ok: false,
        error: message,
      },
      { status: 502 }
    );
  }
}
