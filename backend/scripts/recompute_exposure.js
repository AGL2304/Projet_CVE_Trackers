/* eslint-disable no-console */
/**
 * Recompute asset criticality from full exposure (open-service surface +
 * matched-CVE severity) and persist it.
 *
 * The sync/cpe ingest path derives criticality from *services only* (CVE
 * matches aren't known yet at push time). After running match_cve.js to
 * populate ProductCVE links, run this once to fold the matched-CVE severities
 * into each asset's stored criticality — and to backfill assets that were
 * ingested back when everything was a flat "medium".
 *
 *   docker exec cve-tracker-worker-dev node backend/scripts/recompute_exposure.js
 *   docker exec cve-tracker-worker-dev node backend/scripts/recompute_exposure.js --dry-run
 *
 * Criticality only ever ratchets UP here (we never silently downgrade a
 * human-pinned higher value); pass --force to also allow downgrades.
 */

const { PrismaClient } = require("@prisma/client");
const { assetExposure, criticalityMax } = require("./exposure.js");

const prisma = new PrismaClient({ log: ["error"] });
const DRY_RUN = process.argv.includes("--dry-run");
const FORCE = process.argv.includes("--force");

async function main() {
  const assets = await prisma.asset.findMany({
    orderBy: { createdAt: "asc" },
    include: {
      productLinks: {
        include: {
          product: {
            select: {
              cveLinks: { select: { cve: { select: { cveId: true, severity: true } } } },
            },
          },
        },
      },
    },
  });

  console.log(`recompute_exposure: ${assets.length} asset(s)${DRY_RUN ? " [DRY-RUN]" : ""}${FORCE ? " [FORCE]" : ""}`);
  let changed = 0;
  for (const a of assets) {
    const exp = assetExposure(a);
    const next = FORCE ? exp.level : criticalityMax(a.criticality, exp.level);
    const arrow = next === a.criticality ? "=" : `→ ${next}`;
    const cveStr = `cve:${exp.cve.total}(C${exp.cve.critical}/H${exp.cve.high})`;
    console.log(
      `  ${(a.name || a.ip || a.id).padEnd(28)} score=${String(exp.score).padStart(3)} ` +
        `${cveStr.padEnd(20)} crit:${a.criticality} ${arrow}`
    );
    if (next !== a.criticality && !DRY_RUN) {
      await prisma.asset.update({ where: { id: a.id }, data: { criticality: next } });
      changed++;
    } else if (next !== a.criticality) {
      changed++;
    }
  }
  console.log(`done — ${changed} asset(s) ${DRY_RUN ? "would change" : "updated"}.`);
}

main()
  .catch((e) => {
    console.error("fatal:", e?.message || e);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
