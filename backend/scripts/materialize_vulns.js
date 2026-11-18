/* eslint-disable no-console */
/**
 * Materialize per-asset Vulnerability findings from the asset↔product↔CVE
 * correlation graph.
 *
 * Why: the scanner pushes assets+services, `match_cve.js` correlates each
 * asset's products to CVEs (the `ProductCVE` graph), but nothing ever
 * projected those correlations into the `Vulnerability` table - the
 * status-bearing, per-asset finding list that the tracker's /vulnerabilities
 * view, the dashboard stats, AND the SIEM's CVE-enrichment endpoint
 * (`GET /api/vulnerabilities?assetId=…&status=open`) all read from. Result:
 * 576 CVEs correlated to the Metasploitable box, yet 0 vulnerabilities
 * surfaced anywhere. This script closes that gap.
 *
 * Schema note: `Vulnerability.cveId` is GLOBALLY `@unique`, so a given CVE can
 * be pinned to exactly one asset. We process assets richest-first (by distinct
 * CVE count) so the most-exposed host claims its full set, and a CVE already
 * claimed by a richer asset is skipped for the others. Idempotent: re-running
 * upserts on `cveId` and never duplicates.
 *
 * Usage (inside the worker container):
 *   node backend/scripts/materialize_vulns.js            # all assets
 *   node backend/scripts/materialize_vulns.js <assetId>  # one asset only
 *   node backend/scripts/materialize_vulns.js 192.168.56.106  # by name/ip too
 */

const { PrismaClient } = require("@prisma/client");

const db = new PrismaClient();

// CVE.severity enum (NONE/LOW/MEDIUM/HIGH/CRITICAL) → Vulnerability severity
// string the API/UI expect (critical|high|medium|low). NONE/unknown ⇒ low.
function mapSeverity(sev) {
  const k = String(sev || "").toLowerCase();
  if (k === "critical" || k === "high" || k === "medium" || k === "low") return k;
  return "low";
}

function bestCvss(cve) {
  return cve.cvssV3Score ?? cve.cvssScore ?? cve.cvssV4Score ?? null;
}

function vulnTitle(cve) {
  const base = `${cve.cveId} - ${cve.title || "Vulnérabilité corrélée"}`;
  return base.length > 200 ? base.slice(0, 197) + "…" : base;
}

async function main() {
  const arg = process.argv[2] || null;

  // Pull every asset that has at least one product link, with the full
  // product→CVE graph attached. Filter to a single asset if an arg was given
  // (match by id, name, ip, or hostname).
  const assets = await db.asset.findMany({
    where: arg
      ? {
          OR: [
            { id: arg },
            { name: arg },
            { ip: arg },
            { hostname: arg },
          ],
        }
      : { productLinks: { some: {} } },
    include: {
      productLinks: {
        include: {
          product: {
            include: { cveLinks: { include: { cve: true } } },
          },
        },
      },
    },
  });

  if (assets.length === 0) {
    console.log(arg ? `No asset matched "${arg}".` : "No assets with product links.");
    return;
  }

  // Build per-asset deduped CVE sets.
  const perAsset = assets.map((a) => {
    const cveById = new Map(); // cve.id -> cve
    for (const pl of a.productLinks) {
      for (const cl of pl.product?.cveLinks || []) {
        if (cl.cve && !cveById.has(cl.cve.id)) cveById.set(cl.cve.id, cl.cve);
      }
    }
    return { asset: a, cves: [...cveById.values()] };
  });

  // Richest first so the most-exposed host wins shared CVEs.
  perAsset.sort((x, y) => y.cves.length - x.cves.length);

  const claimed = new Set(); // cve.cveId already pinned to some asset this run
  // Pre-seed with CVEs already present in the table (idempotent re-runs).
  for (const v of await db.vulnerability.findMany({ select: { cveId: true } })) {
    if (v.cveId) claimed.add(v.cveId);
  }

  let created = 0;
  let updated = 0;
  let skippedClaimed = 0;

  for (const { asset, cves } of perAsset) {
    let assetCreated = 0;
    for (const cve of cves) {
      if (!cve.cveId) continue;
      // Already pinned to another asset (or pre-existing) → respect @unique.
      if (claimed.has(cve.cveId)) {
        // If it's pinned but to THIS asset already, an upsert keeps it consistent.
        const existing = await db.vulnerability.findUnique({
          where: { cveId: cve.cveId },
          select: { assetId: true },
        });
        if (!existing || existing.assetId === asset.id) {
          await db.vulnerability.upsert({
            where: { cveId: cve.cveId },
            create: {
              title: vulnTitle(cve),
              description: cve.description ? String(cve.description).slice(0, 5000) : null,
              severity: mapSeverity(cve.severity),
              status: "open",
              cvssScore: bestCvss(cve),
              cveId: cve.cveId,
              assetId: asset.id,
            },
            update: {
              severity: mapSeverity(cve.severity),
              cvssScore: bestCvss(cve),
              title: vulnTitle(cve),
            },
          });
          updated++;
        } else {
          skippedClaimed++;
        }
        continue;
      }
      await db.vulnerability.create({
        data: {
          title: vulnTitle(cve),
          description: cve.description ? String(cve.description).slice(0, 5000) : null,
          severity: mapSeverity(cve.severity),
          status: "open",
          cvssScore: bestCvss(cve),
          cveId: cve.cveId,
          assetId: asset.id,
        },
      });
      claimed.add(cve.cveId);
      created++;
      assetCreated++;
    }
    console.log(
      `  ${asset.name} (${asset.id}) - ${cves.length} correlated CVE(s) → ${assetCreated} new finding(s)`
    );
  }

  const total = await db.vulnerability.count();
  console.log(
    `\nDone. created=${created} updated=${updated} skipped(claimed-elsewhere)=${skippedClaimed} | Vulnerability rows now=${total}`
  );
}

main()
  .catch((e) => {
    console.error("materialize_vulns failed:", e);
    process.exitCode = 1;
  })
  .finally(async () => {
    await db.$disconnect();
  });
