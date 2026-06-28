/**
 * Exposure scoring — turns an asset's open services (and, where available, its
 * matched CVEs) into a single risk score and a derived criticality bucket.
 *
 * Why: the scanner always pushed assets as "medium", so criticality told you
 * nothing about real risk. A box exposing Redis + Elasticsearch + RDP + SMB is
 * obviously more dangerous than a phone with one stray port — the criticality
 * should say so. This module is the single source of truth for that mapping and
 * is shared by the ingest path (sync/cpe, which only knows services) and the
 * report/recompute path (which can also fold in matched CVE severities).
 *
 * The weights are deliberately blunt and defensive: they reward *attack surface
 * an attacker can act on directly* (unauthenticated data stores, remote-access
 * and lateral-movement services, cleartext protocols) over plain HTTP fronting.
 */

export type ServiceLike = {
  port?: number | null;
  protocol?: string | null;
  service?: string | null;
};

export type CriticalityLevel = "low" | "medium" | "high" | "critical";

export type ServiceHit = { port: number; label: string; weight: number };

export type ExposureResult = {
  score: number;
  level: CriticalityLevel;
  serviceScore: number;
  cveScore: number;
  hits: ServiceHit[];
};

/**
 * Dangerous-by-default services keyed by TCP port. The weight is the marginal
 * risk of finding that port open and reachable on the LAN. Data stores that are
 * frequently deployed unauthenticated, remote-control surfaces, and cleartext
 * protocols score highest; ordinary web ports score a token amount (they are
 * surface, but expected).
 */
export const DANGEROUS_SERVICES: Record<number, { label: string; weight: number }> = {
  2375: { label: "Docker API (unauth ⇒ root RCE)", weight: 50 },
  2376: { label: "Docker API (TLS)", weight: 30 },
  6379: { label: "Redis (often unauthenticated)", weight: 40 },
  27017: { label: "MongoDB (often unauthenticated)", weight: 38 },
  23: { label: "Telnet (cleartext)", weight: 38 },
  9200: { label: "Elasticsearch (HTTP, often unauth)", weight: 32 },
  9300: { label: "Elasticsearch (transport)", weight: 28 },
  3389: { label: "RDP (remote access / lateral)", weight: 32 },
  445: { label: "SMB (lateral movement)", weight: 30 },
  11211: { label: "Memcached (unauth / amplification)", weight: 28 },
  5900: { label: "VNC (remote desktop)", weight: 26 },
  5984: { label: "CouchDB", weight: 26 },
  139: { label: "NetBIOS session", weight: 16 },
  3306: { label: "MySQL/MariaDB", weight: 20 },
  5432: { label: "PostgreSQL", weight: 20 },
  1433: { label: "MSSQL", weight: 20 },
  21: { label: "FTP (cleartext)", weight: 18 },
  25: { label: "SMTP", weight: 10 },
  53: { label: "DNS", weight: 8 },
  161: { label: "SNMP", weight: 18 },
  8080: { label: "HTTP-alt", weight: 6 },
  8443: { label: "HTTPS-alt", weight: 6 },
  80: { label: "HTTP", weight: 5 },
  443: { label: "HTTPS", weight: 4 },
  22: { label: "SSH", weight: 6 },
  7547: { label: "TR-069 CWMP (CPE mgmt)", weight: 14 },
};

/** Thresholds mapping a combined score to a criticality bucket. */
export function criticalityFromScore(score: number): CriticalityLevel {
  if (score >= 60) return "critical";
  if (score >= 32) return "high";
  if (score >= 12) return "medium";
  return "low";
}

/** Sum of dangerous-service weights for the open ports on an asset. */
export function serviceExposure(services: ServiceLike[] | null | undefined): {
  score: number;
  hits: ServiceHit[];
} {
  if (!Array.isArray(services)) return { score: 0, hits: [] };
  const hits: ServiceHit[] = [];
  let score = 0;
  const seen = new Set<number>();
  for (const s of services) {
    const port = typeof s?.port === "number" ? s.port : null;
    if (port == null || seen.has(port)) continue;
    seen.add(port);
    const def = DANGEROUS_SERVICES[port];
    if (def) {
      score += def.weight;
      hits.push({ port, label: def.label, weight: def.weight });
    } else {
      // Any other open TCP port is a small amount of surface.
      score += 2;
    }
  }
  hits.sort((a, b) => b.weight - a.weight);
  return { score, hits };
}

/**
 * Risk contribution from matched CVEs. Saturating so a single product with
 * dozens of historical CVEs doesn't dwarf the live-service signal, while a
 * critical/high still meaningfully raises the score.
 */
export function cveExposure(counts: {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
}): number {
  const crit = counts.critical ?? 0;
  const high = counts.high ?? 0;
  const med = counts.medium ?? 0;
  const raw = crit * 18 + high * 9 + med * 3;
  // Saturate at 60 so CVEs can push an asset to "critical" but a long historical
  // tail of mediums can't on its own.
  return Math.min(raw, 60);
}

/**
 * Full exposure: open-service surface + matched-CVE severity. `cveCounts` is
 * optional (the ingest path doesn't have matches yet).
 */
export function computeExposure(
  services: ServiceLike[] | null | undefined,
  cveCounts?: { critical?: number; high?: number; medium?: number; low?: number }
): ExposureResult {
  const svc = serviceExposure(services);
  const cveScore = cveCounts ? cveExposure(cveCounts) : 0;
  let score = svc.score + cveScore;
  let level = criticalityFromScore(score);
  // Floor: a matched CRITICAL CVE means at least "high" regardless of surface.
  if ((cveCounts?.critical ?? 0) > 0 && level === "low") level = "medium";
  if ((cveCounts?.critical ?? 0) > 0 && (level === "medium")) level = "high";
  return { score, level, serviceScore: svc.score, cveScore, hits: svc.hits };
}

const ORDER: Record<CriticalityLevel, number> = { low: 1, medium: 2, high: 3, critical: 4 };

/** Return the higher of two criticality buckets (string-safe). */
export function criticalityMax(a: string, b: string): CriticalityLevel {
  const av = ORDER[(a as CriticalityLevel)] ?? 0;
  const bv = ORDER[(b as CriticalityLevel)] ?? 0;
  return (av >= bv ? a : b) as CriticalityLevel;
}
