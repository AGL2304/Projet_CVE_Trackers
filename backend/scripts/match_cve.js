/* eslint-disable no-console */
/**
 * CPE → CVE matcher.
 *
 * The sync/cpe endpoint records Products (by CPE) and *reads* Product↔CVE links
 * (ProductCVE), but nothing ever *creates* those links — so the exposure counts
 * always came back 0. This script closes that gap.
 *
 * For every Product that carries a CPE it:
 *   1. normalizes the vendor (the scanner's fingerprint DB still emits the
 *      retired `redislabs` vendor; NVD moved Redis to `redis:redis`),
 *   2. asks NVD which CVEs apply to that exact product+version via the
 *      `virtualMatchString` parameter (NVD does the version-range matching
 *      server-side, so we don't have to parse cpeMatch ranges ourselves),
 *   3. upserts each returned CVE (same shape as the worker's NVD sync),
 *   4. creates the ProductCVE link (idempotent via the @@unique constraint).
 *
 * This is a MANUAL trigger — it does not touch the scheduled-sync pause marker,
 * so it runs even while auto-sync is paused. Run it from the worker container,
 * which already has the Prisma client and outbound access to NVD:
 *
 *   docker exec cve-tracker-worker-dev node backend/scripts/match_cve.js
 *   docker exec cve-tracker-worker-dev node backend/scripts/match_cve.js --dry-run
 *
 * Honors NVD_API_KEY (faster rate limit) the same way the worker does.
 */

const {
  PrismaClient,
  CVEStatus,
  CveSource,
  Severity,
} = require("@prisma/client");

const prisma = new PrismaClient({ log: ["error"] });

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_PAGE_SIZE = num(process.env.NVD_PAGE_SIZE, 200);
const MAX_PER_PRODUCT = num(process.env.MATCH_MAX_PER_PRODUCT, 500);
const DRY_RUN = process.argv.includes("--dry-run");

// NVD vendor aliases — the scanner's fingerprint DB lags behind NVD's renames.
const VENDOR_ALIASES = {
  redislabs: "redis",
};

function num(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function log(...args) {
  console.log(`[${new Date().toISOString()}] [match]`, ...args);
}
function warn(...args) {
  console.warn(`[${new Date().toISOString()}] [match:warn]`, ...args);
}
function err(...args) {
  console.error(`[${new Date().toISOString()}] [match:error]`, ...args);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function nvdApiKey() {
  return process.env.NVD_API_KEY || undefined;
}

function calculateSeverity(cvssV3Score, cvssV4Score) {
  const score = typeof cvssV4Score === "number" ? cvssV4Score : cvssV3Score;
  if (score === null || score === undefined) return Severity.NONE;
  if (score === 0) return Severity.NONE;
  if (score < 4) return Severity.LOW;
  if (score < 7) return Severity.MEDIUM;
  if (score < 9) return Severity.HIGH;
  return Severity.CRITICAL;
}

// ─── CPE helpers ──────────────────────────────────────────────────────────────

/**
 * Parse a stored Product CPE into the (vendor, product, version) triple and
 * build the NVD virtualMatchString. We keep the version when it is concrete so
 * NVD only returns CVEs that actually apply to this build; a wildcard version
 * falls back to a product-level match.
 */
function buildMatch(cpe) {
  const parts = String(cpe).split(":");
  // cpe:2.3:a:vendor:product:version:...
  let vendor = (parts[3] || "").toLowerCase();
  const product = (parts[4] || "").toLowerCase();
  const version = parts[5];
  vendor = VENDOR_ALIASES[vendor] || vendor;
  if (!vendor || !product || vendor === "*" || product === "*") return null;

  const hasVersion = version && version !== "*" && version !== "-";
  const vms = hasVersion
    ? `cpe:2.3:a:${vendor}:${product}:${version}`
    : `cpe:2.3:a:${vendor}:${product}`;
  return { vms, vendor, product, version: hasVersion ? version : null };
}

// ─── NVD fetch ────────────────────────────────────────────────────────────────

async function fetchNvdByMatch(virtualMatchString, { startIndex, apiKey }) {
  const url = new URL(NVD_API_BASE);
  url.searchParams.set("resultsPerPage", String(NVD_PAGE_SIZE));
  url.searchParams.set("startIndex", String(startIndex));
  url.searchParams.set("virtualMatchString", virtualMatchString);

  const headers = { "User-Agent": "CVE-Tracker/match-cve" };
  if (apiKey) headers.apiKey = apiKey;

  const MAX_ATTEMPTS = 4;
  let lastError = null;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const response = await fetch(url, { headers });
      if (response.status === 200) return response.json();
      if (response.status === 403 || response.status === 429 || response.status >= 500) {
        const backoff = 2000 * attempt;
        warn(`NVD returned ${response.status}, backing off ${backoff}ms (attempt ${attempt}/${MAX_ATTEMPTS})`);
        await sleep(backoff);
        continue;
      }
      throw new Error(`NVD API error ${response.status}: ${response.statusText}`);
    } catch (e) {
      lastError = e;
      await sleep(1500 * attempt);
    }
  }
  throw lastError ?? new Error("NVD fetch failed after retries");
}

// ─── CVE upsert (mirrors worker.upsertCve, but returns the row id) ────────────

async function upsertCve(entry) {
  const cve = entry.cve;
  if (!cve?.id) throw new Error("missing cve.id");

  const description =
    (cve.descriptions || []).find((d) => d.lang === "en")?.value ||
    (cve.descriptions || [])[0]?.value ||
    "No description available";

  const v31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
  const v30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
  const v40 = cve.metrics?.cvssMetricV40?.[0]?.cvssData;
  const cvssV3 = v31 || v30;
  const cvssV3Score = cvssV3?.baseScore ?? null;
  const cvssV3Vector = cvssV3?.vectorString ?? null;
  const cvssV4Score = v40?.baseScore ?? null;
  const severity = calculateSeverity(cvssV3Score, cvssV4Score);

  const publishedAt = cve.published ? new Date(cve.published) : null;
  const modifiedAt = cve.lastModified ? new Date(cve.lastModified) : null;
  const references = (cve.references || []).map((r) => r.url);

  const base = {
    title: cve.id,
    description,
    publishedAt,
    modifiedAt,
    cvssV3Score,
    cvssV3Vector,
    cvssV4Score,
    severity,
    source: CveSource.NVD,
    rawData: entry,
    references: JSON.stringify(references),
    vulnStatus: cve.vulnStatus || null,
    cvssScore: cvssV3Score,
    cvssVector: cvssV3Vector,
    publishedDate: publishedAt,
    lastModifiedDate: modifiedAt,
  };

  const row = await prisma.cVE.upsert({
    where: { cveId: cve.id },
    update: { ...base, version: { increment: 1 } },
    create: { cveId: cve.id, ...base, status: CVEStatus.NEW },
    select: { id: true, cveId: true, severity: true },
  });
  return row;
}

// ─── Per-product matching ─────────────────────────────────────────────────────

async function matchProduct(product, apiKey, rateDelay) {
  const match = buildMatch(product.cpe);
  if (!match) {
    warn(`skip product ${product.id} — unusable CPE ${product.cpe}`);
    return { cves: 0, linked: 0, severities: {} };
  }

  log(`product ${product.vendor}:${product.name}${match.version ? " " + match.version : ""} → ${match.vms}`);

  const seen = new Map(); // cveId -> {id, severity}
  let startIndex = 0;
  while (true) {
    const data = await fetchNvdByMatch(match.vms, { startIndex, apiKey });
    const entries = data.vulnerabilities || [];
    const total = data.totalResults || 0;
    if (entries.length === 0) break;

    for (const entry of entries) {
      if (!DRY_RUN) {
        try {
          const row = await upsertCve(entry);
          seen.set(row.cveId, row);
        } catch (e) {
          warn(`upsert failed for ${entry?.cve?.id || "?"}: ${e?.message || e}`);
        }
      } else {
        const id = entry?.cve?.id;
        if (id) seen.set(id, { cveId: id, severity: "?" });
      }
    }

    startIndex += entries.length;
    if (startIndex >= total || startIndex >= MAX_PER_PRODUCT) break;
    await sleep(rateDelay);
  }

  // Create ProductCVE links (idempotent).
  let linked = 0;
  const severities = {};
  for (const row of seen.values()) {
    severities[row.severity] = (severities[row.severity] || 0) + 1;
    if (DRY_RUN) continue;
    try {
      await prisma.productCVE.create({ data: { productId: product.id, cveId: row.id } });
      linked++;
    } catch (e) {
      if (e?.code !== "P2002") throw e; // already linked → fine
    }
  }

  return { cves: seen.size, linked, severities };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const apiKey = nvdApiKey();
  const rateDelay = apiKey ? 700 : 6_500;

  const products = await prisma.product.findMany({
    where: { cpe: { not: null } },
    orderBy: { createdAt: "asc" },
  });

  log(
    `matching ${products.length} product(s)${DRY_RUN ? " [DRY-RUN]" : ""} ` +
      `(apiKey=${apiKey ? "yes" : "no"}, rateDelay=${rateDelay}ms)`
  );

  const totals = { cves: 0, linked: 0, severities: {} };
  for (const product of products) {
    if (!product.cpe) continue;
    try {
      const r = await matchProduct(product, apiKey, rateDelay);
      totals.cves += r.cves;
      totals.linked += r.linked;
      for (const [sev, n] of Object.entries(r.severities)) {
        totals.severities[sev] = (totals.severities[sev] || 0) + n;
      }
      const sevStr = Object.entries(r.severities)
        .map(([s, n]) => `${s}:${n}`)
        .join(" ");
      log(`  ↳ ${r.cves} CVE(s), ${r.linked} new link(s)  [${sevStr || "none"}]`);
    } catch (e) {
      err(`product ${product.id} failed:`, e?.message || e);
    }
    await sleep(rateDelay);
  }

  log(
    `done — ${totals.cves} CVE match(es) across products, ${totals.linked} new ProductCVE link(s). ` +
      `severities: ${JSON.stringify(totals.severities)}`
  );
}

main()
  .catch((e) => {
    err("fatal:", e?.message || e);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
