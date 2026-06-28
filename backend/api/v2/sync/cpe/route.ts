import { NextRequest } from "next/server";
import { z } from "zod";
import { Prisma, UserRole } from "@prisma/client";
import { db } from "@/lib/db";
import { applyRateLimit } from "@/lib/v2/rate-limit";
import { jsonApiError, jsonApiResponse } from "@/lib/v2/jsonapi";
import { getActor, hasRole } from "@/lib/v2/auth";
import { writeAuditLog } from "@/lib/v2/audit";
import { publishEvent } from "@/lib/webhooks";
import { computeExposure, criticalityMax } from "@/lib/v2/exposure";

/**
 * POST /api/v2/sync/cpe
 *
 * Endpoint d'intégration pour Network Scanner Pro.
 *
 * Reçoit un asset (host) découvert et la liste de ses services (CPE).
 * Pour chaque service :
 *   1. upsert d'un Product par CPE,
 *   2. liaison Asset ↔ Product (table AssetProduct),
 *   3. réutilisation des liens Product ↔ CVE déjà connus (ProductCVE).
 *
 * Retourne le diff :
 *   - createdProducts: nouveaux Product créés
 *   - matchedCves: liste des CVE auxquelles l'asset est désormais exposé
 *   - existingLinks: liens AssetProduct déjà présents avant ce push
 *
 * Authentification :
 *   - cookie admin OU header X-Internal-Auth correspondant à
 *     INTERNAL_API_SHARED_SECRET (configuré côté Scanner).
 */

// ─── Schemas ─────────────────────────────────────────────────────────────────

const cpeRegex = /^cpe:2\.3:[aho]:[^:]+:[^:]+:[^:]+/i;

const serviceSchema = z.object({
  // CPE is now OPTIONAL: a discovered service may have an open port but no
  // fingerprinted product (e.g. a phone's stray port, an IoT device). Such
  // services are still recorded on the asset so the inventory reflects every
  // open port — they just don't create a Product / CVE match.
  cpe: z.string().regex(cpeRegex, "CPE 2.3 invalide").optional().nullable(),
  port: z.number().int().min(1).max(65535).optional().nullable(),
  protocol: z.enum(["tcp", "udp"]).optional().nullable(),
  service: z.string().max(60).optional().nullable(),
  product: z.string().max(120).optional().nullable(),
  version: z.string().max(60).optional().nullable(),
  banner: z.string().max(500).optional().nullable(),
  confidence: z.number().min(0).max(1).optional().nullable(),
});

const syncCpeSchema = z.object({
  host: z.object({
    name: z.string().trim().min(2).max(120),
    type: z.string().trim().min(2).max(60).default("server"),
    ip: z.string().trim().max(45).optional().nullable(),
    hostname: z.string().trim().max(253).optional().nullable(),
    mac: z.string().trim().max(17).optional().nullable(),
    criticality: z.enum(["low", "medium", "high", "critical"]).default("medium"),
    description: z.string().trim().max(2000).optional().nullable(),
  }),
  // Allow an empty list: a discovered host with no open TCP ports (common for
  // phones / IoT seen only via ARP) is still a real inventory device.
  services: z.array(serviceSchema).max(500).default([]),
  scanRef: z.string().max(120).optional(),
});

type SyncCpePayload = z.infer<typeof syncCpeSchema>;

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Parse a CPE 2.3 string into a (vendor, product, version) triple usable
 * for Product.create. We keep this lenient — wfn-strict parsing isn't
 * worth the complexity here.
 */
function parseCpe(cpe: string): { vendor: string; product: string; version: string | null } {
  const parts = cpe.split(":");
  // cpe:2.3:a:vendor:product:version:...
  const vendor = parts[3] || "unknown";
  const product = parts[4] || "unknown";
  const version = parts[5] && parts[5] !== "*" && parts[5] !== "-" ? parts[5] : null;
  return { vendor, product, version };
}

/**
 * Find an existing Asset matching the incoming host. Dedup priority:
 *   1) exact MAC (if provided and looks valid)
 *   2) exact hostname
 *   3) exact IP
 *   4) exact name
 */
async function findExistingAsset(host: SyncCpePayload["host"]) {
  if (host.mac && /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(host.mac)) {
    const byMac = await db.asset.findFirst({
      where: { description: { contains: `mac=${host.mac.toLowerCase()}`, mode: "insensitive" } },
    });
    if (byMac) return byMac;
  }
  if (host.hostname) {
    const byHostname = await db.asset.findFirst({ where: { hostname: host.hostname } });
    if (byHostname) return byHostname;
  }
  if (host.ip) {
    const byIp = await db.asset.findFirst({ where: { ip: host.ip } });
    if (byIp) return byIp;
  }
  return db.asset.findFirst({ where: { name: host.name } });
}

// ─── Handler ────────────────────────────────────────────────────────────────

export async function POST(request: NextRequest) {
  const rate = applyRateLimit(request);
  if (rate.limited) {
    return jsonApiError(
      { status: "429", title: "Rate limit exceeded", code: "RATE_LIMIT" },
      429
    );
  }

  try {
    const actor = await getActor(request);
    if (!hasRole(actor, [UserRole.ADMIN, UserRole.ANALYST, UserRole.API])) {
      return jsonApiError(
        { status: "403", title: "Forbidden", code: "FORBIDDEN" },
        403
      );
    }

    const parsed = syncCpeSchema.safeParse(await request.json());
    if (!parsed.success) {
      return jsonApiError(
        {
          status: "400",
          title: "Validation error",
          detail: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "),
          code: "VALIDATION_ERROR",
        },
        400
      );
    }

    const payload = parsed.data;

    // ── 1. Upsert Asset (déduplication tolérante)
    const existing = await findExistingAsset(payload.host);
    const assetDescription = [
      payload.host.description ?? null,
      payload.host.mac ? `mac=${payload.host.mac.toLowerCase()}` : null,
      payload.scanRef ? `scan=${payload.scanRef}` : null,
    ]
      .filter(Boolean)
      .join(" · ") || null;

    // Normalize the full service list for storage on the asset — every open
    // port and any fingerprint, independent of whether a CPE was identified.
    const servicesJson: Prisma.InputJsonValue = payload.services
      .map((s) => ({
        port: s.port ?? null,
        protocol: s.protocol ?? "tcp",
        service: s.service ?? null,
        product: s.product ?? null,
        version: s.version ?? null,
        cpe: s.cpe ?? null,
        banner: s.banner ? s.banner.slice(0, 300) : null,
      }))
      .sort((a, b) => (a.port ?? 0) - (b.port ?? 0));

    // Derive criticality from the exposed services (Redis/ES/RDP/SMB/… open ⇒
    // high/critical) instead of trusting the scanner's flat "medium". CVE
    // matches aren't known at ingest time, so this is the service-only score;
    // the report/recompute path refines it with matched-CVE severities.
    const exposure = computeExposure(servicesJson as unknown as { port?: number | null }[]);
    // Criticality is driven by exposure, not by the scanner's flat default
    // (it always sends "medium", which would otherwise floor every phone/IoT
    // device at medium). On update we only ever ratchet UP, so a human-pinned
    // higher criticality in the UI is preserved; the recompute script with
    // --force is the deliberate way to reset to the exposure-true value.
    const incomingCriticality = exposure.level;

    const asset = existing
      ? await db.asset.update({
          where: { id: existing.id },
          data: {
            // Never silently downgrade a higher existing (human) criticality;
            // otherwise reflect the current exposure-derived value.
            criticality: criticalityMax(existing.criticality, incomingCriticality),
            ip: payload.host.ip ?? existing.ip,
            hostname: payload.host.hostname ?? existing.hostname,
            type: payload.host.type || existing.type,
            description: assetDescription ?? existing.description,
            services: servicesJson,
          },
        })
      : await db.asset.create({
          data: {
            name: payload.host.name,
            type: payload.host.type,
            ip: payload.host.ip ?? null,
            hostname: payload.host.hostname ?? null,
            criticality: incomingCriticality,
            description: assetDescription,
            status: "active",
            tags: ["discovered:scanner"],
            services: servicesJson,
          },
        });

    // ── 2. Upsert Product par CPE
    const createdProducts: string[] = [];
    const linkedProductIds: string[] = [];

    for (const svc of payload.services) {
      // Only CPE-identified services become Products (and thus get CVE
      // matching). Port-only services are already stored in asset.services.
      if (!svc.cpe) continue;
      const parsedCpe = parseCpe(svc.cpe);
      let product = await db.product.findFirst({ where: { cpe: svc.cpe } });

      if (!product) {
        product = await db.product.create({
          data: {
            name: parsedCpe.product,
            vendor: parsedCpe.vendor,
            version: parsedCpe.version,
            cpe: svc.cpe,
          },
        });
        createdProducts.push(svc.cpe);
      }
      linkedProductIds.push(product.id);

      // ── 3. Lien Asset ↔ Product (idempotent via @@unique)
      await db.assetProduct
        .create({
          data: { assetId: asset.id, productId: product.id },
        })
        .catch((err: unknown) => {
          // P2002 = unique constraint violation → lien déjà présent, on ignore
          if ((err as { code?: string })?.code !== "P2002") throw err;
        });
    }

    // ── 4. Récupération des CVE liées aux produits (matching)
    const productCves = await db.productCVE.findMany({
      where: { productId: { in: linkedProductIds } },
      include: {
        cve: {
          select: {
            id: true,
            cveId: true,
            severity: true,
            cvssV3Score: true,
            title: true,
            publishedAt: true,
          },
        },
        product: { select: { cpe: true, name: true, vendor: true } },
      },
    });

    const matchedCves = productCves.map((pc) => ({
      cveId: pc.cve.cveId,
      severity: pc.cve.severity,
      cvssV3Score: pc.cve.cvssV3Score,
      title: pc.cve.title,
      publishedAt: pc.cve.publishedAt,
      patchStatus: pc.patchStatus,
      productCpe: pc.product.cpe,
    }));

    const criticalCount = matchedCves.filter((c) => c.severity === "CRITICAL").length;
    const highCount = matchedCves.filter((c) => c.severity === "HIGH").length;

    await writeAuditLog({
      actor,
      action: "sync.cpe",
      resource: "asset",
      resourceId: asset.id,
      after: {
        servicesPushed: payload.services.length,
        productsCreated: createdProducts.length,
        cvesMatched: matchedCves.length,
        criticalCount,
        exposureScore: exposure.score,
        criticality: asset.criticality,
        scanRef: payload.scanRef,
      },
      request,
    });

    // Webhook: only emit asset.created when the asset is brand new
    if (!existing) {
      publishEvent("asset.created", {
        assetId: asset.id,
        name: asset.name,
        ip: asset.ip,
        hostname: asset.hostname,
        criticality: asset.criticality,
        cvesMatched: matchedCves.length,
        critical: criticalCount,
        scanRef: payload.scanRef,
      });
    }

    return jsonApiResponse(
      {
        type: "cpe-sync",
        id: asset.id,
        attributes: {
          asset: {
            id: asset.id,
            name: asset.name,
            ip: asset.ip,
            hostname: asset.hostname,
            criticality: asset.criticality,
            created: !existing,
          },
          services: {
            pushed: payload.services.length,
            newProducts: createdProducts.length,
          },
          exposure: {
            cvesMatched: matchedCves.length,
            critical: criticalCount,
            high: highCount,
            score: exposure.score,
            criticality: asset.criticality,
            services: exposure.hits.slice(0, 12),
          },
          matchedCves: matchedCves.slice(0, 100), // cap returned list
        },
      },
      {
        status: existing ? 200 : 201,
        links: {
          self: `/api/v2/sync/cpe`,
          asset: `/api/assets/${asset.id}`,
        },
        headers: rate.headers,
      }
    );
  } catch (error) {
    console.error("POST /api/v2/sync/cpe failed", error);
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      return jsonApiError(
        {
          status: "409",
          title: "Database conflict",
          detail: error.message,
          code: error.code,
        },
        409
      );
    }
    return jsonApiError({
      status: "500",
      title: "Internal server error",
      detail: "Unable to process CPE sync",
      code: "CPE_SYNC_ERROR",
    });
  }
}
