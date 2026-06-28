/* eslint-disable no-console */
/**
 * Exposure scoring (CommonJS) — shared by the report worker and the
 * recompute/backfill script. This is the JS twin of
 * frontend/src/lib/v2/exposure.ts (used by the sync/cpe ingest path). The two
 * must be kept in sync by hand: same weights, same thresholds.
 *
 * Open-service surface + matched-CVE severity → a single risk score and a
 * derived criticality bucket.
 */

// Dangerous-by-default services keyed by TCP port; weight = marginal risk of
// finding the port open on the LAN.
const DANGEROUS_SERVICES = {
  2375: { label: "Docker API", weight: 50 },
  2376: { label: "Docker API (TLS)", weight: 30 },
  6379: { label: "Redis", weight: 40 },
  27017: { label: "MongoDB", weight: 38 },
  23: { label: "Telnet", weight: 38 },
  9200: { label: "Elasticsearch", weight: 32 },
  9300: { label: "Elasticsearch (transport)", weight: 28 },
  3389: { label: "RDP", weight: 32 },
  445: { label: "SMB", weight: 30 },
  11211: { label: "Memcached", weight: 28 },
  5900: { label: "VNC", weight: 26 },
  5984: { label: "CouchDB", weight: 26 },
  139: { label: "NetBIOS", weight: 16 },
  3306: { label: "MySQL", weight: 20 },
  5432: { label: "PostgreSQL", weight: 20 },
  1433: { label: "MSSQL", weight: 20 },
  21: { label: "FTP", weight: 18 },
  25: { label: "SMTP", weight: 10 },
  53: { label: "DNS", weight: 8 },
  161: { label: "SNMP", weight: 18 },
  8080: { label: "HTTP-alt", weight: 6 },
  8443: { label: "HTTPS-alt", weight: 6 },
  80: { label: "HTTP", weight: 5 },
  443: { label: "HTTPS", weight: 4 },
  22: { label: "SSH", weight: 6 },
  7547: { label: "TR-069 CWMP", weight: 14 },
};

function criticalityFromScore(score) {
  if (score >= 60) return "critical";
  if (score >= 32) return "high";
  if (score >= 12) return "medium";
  return "low";
}

function serviceExposureScore(services) {
  if (!Array.isArray(services)) return { score: 0, hits: [] };
  const hits = [];
  const seen = new Set();
  let score = 0;
  for (const s of services) {
    const port = typeof s?.port === "number" ? s.port : null;
    if (port == null || seen.has(port)) continue;
    seen.add(port);
    const def = DANGEROUS_SERVICES[port];
    if (def) {
      score += def.weight;
      hits.push({ port, label: def.label, weight: def.weight });
    } else {
      score += 2;
    }
  }
  hits.sort((a, b) => b.weight - a.weight);
  return { score, hits };
}

// Deduped matched-CVE counts for an asset, across all its linked products.
// Expects asset.productLinks[].product.cveLinks[].cve.{cveId,severity}.
function assetCveCounts(asset) {
  const seen = new Map(); // cveId -> severity
  for (const pl of asset.productLinks || []) {
    for (const cl of pl.product?.cveLinks || []) {
      const c = cl.cve;
      if (c?.cveId && !seen.has(c.cveId)) seen.set(c.cveId, c.severity);
    }
  }
  const counts = { total: seen.size, critical: 0, high: 0, medium: 0, low: 0, none: 0 };
  for (const sev of seen.values()) {
    const k = String(sev || "NONE").toLowerCase();
    if (k in counts) counts[k]++;
    else counts.none++;
  }
  return counts;
}

function cveExposureScore(counts) {
  return Math.min((counts.critical || 0) * 18 + (counts.high || 0) * 9 + (counts.medium || 0) * 3, 60);
}

// Full per-asset exposure: open-service surface + matched-CVE severity.
function assetExposure(asset) {
  const cve = assetCveCounts(asset);
  const svc = serviceExposureScore(Array.isArray(asset.services) ? asset.services : []);
  const score = svc.score + cveExposureScore(cve);
  let level = criticalityFromScore(score);
  if (cve.critical > 0 && level === "low") level = "medium";
  if (cve.critical > 0 && level === "medium") level = "high";
  return { score, level, cve, serviceScore: svc.score, hits: svc.hits };
}

const ORDER = { low: 1, medium: 2, high: 3, critical: 4 };
function criticalityMax(a, b) {
  return (ORDER[a] ?? 0) >= (ORDER[b] ?? 0) ? a : b;
}

module.exports = {
  DANGEROUS_SERVICES,
  criticalityFromScore,
  serviceExposureScore,
  assetCveCounts,
  cveExposureScore,
  assetExposure,
  criticalityMax,
};
