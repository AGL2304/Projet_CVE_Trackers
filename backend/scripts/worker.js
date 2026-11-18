/* eslint-disable no-console */
/**
 * CVE Tracker background worker.
 *
 * Responsibilities:
 *   1. Periodic NVD full sync (every NVD_FULL_SYNC_INTERVAL_MS, default 24h)
 *   2. Periodic NVD delta sync (every NVD_DELTA_INTERVAL_MS, default 15min)
 *   3. Drain SyncJob.status=QUEUED rows (manually-triggered sync via HTTP)
 *   4. Drain ReportJob.status=QUEUED rows (PDF/CSV/JSON report generation)
 *
 * Runs as a long-lived Node process: `node backend/scripts/worker.js`
 * No build step required - pure JS reading Prisma client.
 */

const fs = require("node:fs");
const path = require("node:path");
const {
  PrismaClient,
  CVEStatus,
  CveSource,
  ReportStatus,
  ReportFormat,
  SyncJobStatus,
  SyncSource,
  Severity,
} = require("@prisma/client");

const prisma = new PrismaClient({ log: ["error"] });

// ─── Config ──────────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS = num(process.env.WORKER_POLL_INTERVAL_MS, 15_000);
const NVD_FULL_SYNC_INTERVAL_MS = num(process.env.NVD_FULL_SYNC_INTERVAL_MS, 24 * 60 * 60 * 1000);
const NVD_DELTA_INTERVAL_MS = num(process.env.NVD_DELTA_INTERVAL_MS, 15 * 60 * 1000);
const NVD_ENABLED = (process.env.NVD_AUTO_SYNC_ENABLED ?? "true").toLowerCase() !== "false";
const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_PAGE_SIZE = num(process.env.NVD_PAGE_SIZE, 200);
const NVD_DELTA_LOOKBACK_HOURS = num(process.env.NVD_DELTA_LOOKBACK_HOURS, 24);
const REPORTS_DIR = process.env.REPORTS_DIR || path.join(process.cwd(), "data", "reports");
// File-based pause marker. The HTTP endpoint /api/admin/scraping/pause creates
// it; /resume removes it. Stored alongside reports so the volume is shared
// between app and worker.
const PAUSE_MARKER = process.env.NVD_PAUSE_MARKER || path.join(REPORTS_DIR, ".sync-paused");

function num(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function nvdApiKey() {
  // Env wins, fall back to AppSettings
  return process.env.NVD_API_KEY || undefined;
}

const lastRun = {
  fullSync: 0,
  deltaSync: 0,
};

// ─── Utilities ───────────────────────────────────────────────────────────────

function log(...args) {
  console.log(`[${new Date().toISOString()}] [worker]`, ...args);
}
function warn(...args) {
  console.warn(`[${new Date().toISOString()}] [worker:warn]`, ...args);
}
function err(...args) {
  console.error(`[${new Date().toISOString()}] [worker:error]`, ...args);
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    if (signal) {
      signal.addEventListener("abort", () => {
        clearTimeout(t);
        reject(new Error("aborted"));
      });
    }
  });
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

// ─── NVD fetch ───────────────────────────────────────────────────────────────

async function fetchNvdPage({ startIndex = 0, perPage = NVD_PAGE_SIZE, lastModStartDate, apiKey, signal }) {
  const url = new URL(NVD_API_BASE);
  url.searchParams.set("resultsPerPage", String(perPage));
  url.searchParams.set("startIndex", String(startIndex));
  if (lastModStartDate) {
    url.searchParams.set("lastModStartDate", lastModStartDate.toISOString());
    url.searchParams.set("lastModEndDate", new Date().toISOString());
  }

  const headers = { "User-Agent": "CVE-Tracker-Worker/2.0" };
  if (apiKey) headers["apiKey"] = apiKey;

  const MAX_ATTEMPTS = 4;
  let lastError;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    if (signal?.aborted) throw new Error("aborted");
    try {
      const response = await fetch(url.toString(), { headers, signal });

      if (response.status === 429 || response.status >= 500) {
        const backoff = Math.min(60_000, 2_000 * 2 ** (attempt - 1));
        warn(`NVD returned ${response.status}, backing off ${backoff}ms (attempt ${attempt}/${MAX_ATTEMPTS})`);
        await sleep(backoff, signal);
        continue;
      }

      if (!response.ok) {
        throw new Error(`NVD API error ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      lastError = error;
      if (signal?.aborted) throw error;
      if (attempt < MAX_ATTEMPTS) {
        await sleep(Math.min(15_000, 1_000 * attempt), signal);
      }
    }
  }
  throw lastError ?? new Error("NVD fetch failed after retries");
}

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

  const existing = await prisma.cVE.findUnique({
    where: { cveId: cve.id },
    select: { id: true, status: true },
  });

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

  if (existing) {
    const keepStatus = existing.status && existing.status !== CVEStatus.NEW;
    await prisma.cVE.update({
      where: { cveId: cve.id },
      data: {
        ...base,
        ...(keepStatus ? {} : { status: CVEStatus.ANALYZING }),
        version: { increment: 1 },
      },
    });
    return "updated";
  }

  await prisma.cVE.create({
    data: { cveId: cve.id, ...base, status: CVEStatus.NEW },
  });
  return "created";
}

// ─── Sync orchestration ──────────────────────────────────────────────────────

async function runNvdSync({ lastModStartDate, maxRecords = 0, triggeredById = null, signal }) {
  const apiKey = nvdApiKey();
  const rateLimitDelay = apiKey ? 600 : 6_500;

  const syncJob = await prisma.syncJob.create({
    data: {
      source: SyncSource.NVD,
      status: SyncJobStatus.RUNNING,
      startedAt: new Date(),
      triggeredById,
      logs: [],
    },
  });

  log(
    `NVD sync started syncJobId=${syncJob.id} mode=${lastModStartDate ? "delta" : "full"} ` +
      (lastModStartDate ? `since=${lastModStartDate.toISOString()}` : "")
  );

  const logs = [];
  let newCount = 0;
  let updatedCount = 0;
  let errorCount = 0;
  let processed = 0;
  let startIndex = 0;
  let page = 0;

  try {
    while (true) {
      if (signal?.aborted) throw new Error("aborted");

      const pageData = await fetchNvdPage({
        startIndex,
        perPage: NVD_PAGE_SIZE,
        lastModStartDate,
        apiKey,
        signal,
      });

      page++;
      const entries = pageData.vulnerabilities || [];
      const totalResults = pageData.totalResults || 0;

      if (entries.length === 0) break;

      const errorsBefore = errorCount;
      for (const entry of entries) {
        try {
          const result = await upsertCve(entry);
          if (result === "created") newCount++;
          else updatedCount++;
        } catch (e) {
          errorCount++;
          const msg = e instanceof Error ? e.message : String(e);
          logs.push(`ERROR ${entry?.cve?.id || "?"}: ${msg}`);
        }
      }
      processed += entries.length;

      logs.push(
        `page=${page} startIndex=${startIndex} fetched=${entries.length} ` +
          `total=${totalResults} newTotal=${newCount} updatedTotal=${updatedCount} ` +
          `errorsThisPage=${errorCount - errorsBefore}`
      );
      log(`NVD sync page ${page}: processed ${processed}/${totalResults}`);

      startIndex += entries.length;
      if (startIndex >= totalResults) break;
      if (maxRecords > 0 && processed >= maxRecords) break;

      await sleep(rateLimitDelay, signal);
    }

    await prisma.syncJob.update({
      where: { id: syncJob.id },
      data: {
        status: SyncJobStatus.COMPLETED,
        completedAt: new Date(),
        newCount,
        updatedCount,
        errorCount,
        logs: logs.slice(-300),
      },
    });
    log(
      `NVD sync completed syncJobId=${syncJob.id} new=${newCount} updated=${updatedCount} errors=${errorCount} processed=${processed}`
    );
    return { syncJobId: syncJob.id, newCount, updatedCount, errorCount };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logs.push(`FATAL: ${msg}`);
    await prisma.syncJob.update({
      where: { id: syncJob.id },
      data: {
        status: SyncJobStatus.FAILED,
        completedAt: new Date(),
        newCount,
        updatedCount,
        errorCount: errorCount + 1,
        logs: logs.slice(-300),
      },
    });
    err(`NVD sync failed syncJobId=${syncJob.id}:`, msg);
    return { syncJobId: syncJob.id, newCount, updatedCount, errorCount, error: msg };
  }
}

// ─── Queue draining ──────────────────────────────────────────────────────────

async function drainQueuedSyncJobs() {
  // Caller-queued jobs (HTTP-triggered) are run as full or delta syncs
  // depending on the absence/presence of `lastModStartDate` in their logs metadata.
  const jobs = await prisma.syncJob.findMany({
    where: { status: SyncJobStatus.QUEUED, source: SyncSource.NVD },
    orderBy: { createdAt: "asc" },
    take: 5,
  });

  for (const job of jobs) {
    try {
      // Mark RUNNING (atomic-ish via update with where filter)
      const claimed = await prisma.syncJob.updateMany({
        where: { id: job.id, status: SyncJobStatus.QUEUED },
        data: { status: SyncJobStatus.RUNNING, startedAt: new Date() },
      });
      if (claimed.count === 0) continue; // someone else claimed it

      log(`Draining queued SyncJob ${job.id}`);
      const result = await runNvdSync({ triggeredById: job.triggeredById });
      // The job we created inside runNvdSync is the new authoritative one;
      // mark the original placeholder as completed referencing it.
      await prisma.syncJob.update({
        where: { id: job.id },
        data: {
          status: SyncJobStatus.COMPLETED,
          completedAt: new Date(),
          newCount: result.newCount,
          updatedCount: result.updatedCount,
          errorCount: result.errorCount,
          logs: [`Delegated to syncJob=${result.syncJobId}`],
        },
      });
    } catch (e) {
      err(`Failed to drain SyncJob ${job.id}:`, e?.message || e);
      await prisma.syncJob
        .update({
          where: { id: job.id },
          data: {
            status: SyncJobStatus.FAILED,
            completedAt: new Date(),
            errorCount: 1,
            logs: [String(e?.message || e)],
          },
        })
        .catch(() => undefined);
    }
  }
}

// ─── Report generation ───────────────────────────────────────────────────────

const REPORT_HARD_CAP = 50_000;

function buildCveWhere(filter) {
  const where = {};
  if (Array.isArray(filter.severity) && filter.severity.length > 0) {
    where.severity = { in: filter.severity };
  }
  if (Array.isArray(filter.status) && filter.status.length > 0) {
    where.status = { in: filter.status };
  }
  if (Array.isArray(filter.source) && filter.source.length > 0) {
    where.source = { in: filter.source };
  }
  const from = filter.dateFrom || filter.from;
  const to = filter.dateTo || filter.to;
  if (from || to) {
    where.publishedAt = {};
    if (from) where.publishedAt.gte = new Date(from);
    if (to) where.publishedAt.lte = new Date(to);
  }
  if (typeof filter.minCvss === "number" || typeof filter.maxCvss === "number") {
    where.cvssV3Score = {};
    if (typeof filter.minCvss === "number") where.cvssV3Score.gte = filter.minCvss;
    if (typeof filter.maxCvss === "number") where.cvssV3Score.lte = filter.maxCvss;
  }
  if (filter.search) {
    where.OR = [
      { cveId: { contains: filter.search, mode: "insensitive" } },
      { title: { contains: filter.search, mode: "insensitive" } },
      { description: { contains: filter.search, mode: "insensitive" } },
    ];
  }
  return where;
}

function aggregateStats(cves) {
  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
  const byStatus = {};
  const bySource = {};
  let cvssSum = 0;
  let cvssCount = 0;
  let oldest = null;
  let newest = null;

  for (const c of cves) {
    bySeverity[c.severity] = (bySeverity[c.severity] || 0) + 1;
    byStatus[c.status] = (byStatus[c.status] || 0) + 1;
    bySource[c.source] = (bySource[c.source] || 0) + 1;
    if (typeof c.cvssV3Score === "number") {
      cvssSum += c.cvssV3Score;
      cvssCount++;
    }
    if (c.publishedAt) {
      const t = +new Date(c.publishedAt);
      if (oldest === null || t < oldest) oldest = t;
      if (newest === null || t > newest) newest = t;
    }
  }

  return {
    total: cves.length,
    avgCvss: cvssCount > 0 ? Number((cvssSum / cvssCount).toFixed(2)) : 0,
    bySeverity,
    byStatus,
    bySource,
    oldestPublished: oldest ? new Date(oldest).toISOString() : null,
    newestPublished: newest ? new Date(newest).toISOString() : null,
  };
}

function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Severity ramp - CVE Tracker charte graphique (low green → critical red).
function severityColor(sev) {
  return (
    {
      CRITICAL: "#E63946",
      HIGH: "#FB8B24",
      MEDIUM: "#FFD166",
      LOW: "#3DDC84",
      NONE: "#7A8AA0",
    }[sev] || "#7A8AA0"
  );
}

// Inline gauge logo (severity dial) - the CVE Tracker brand mark. `stroke`
// recolors the needle/hub so it can sit on light or gradient backgrounds.
function brandLogoSvg(size = 44, needle = "#0B1220") {
  return `<svg viewBox="0 0 200 200" width="${size}" height="${size}" role="img" aria-label="CVE Tracker" style="display:block">
    <circle cx="100" cy="100" r="70" fill="none" stroke="#1E2A40" stroke-width="16"/>
    <path d="M50.5,149.5 A70,70 0 0 1 34.22,76.06" fill="none" stroke="#3DDC84" stroke-width="16" stroke-linecap="round"/>
    <path d="M36.56,70.42 A70,70 0 0 1 100,30" fill="none" stroke="#FFD166" stroke-width="16" stroke-linecap="round"/>
    <path d="M106.1,30.27 A70,70 0 0 1 165.78,76.06" fill="none" stroke="#FB8B24" stroke-width="16" stroke-linecap="round"/>
    <path d="M167.61,81.88 A70,70 0 0 1 145.0,153.62" fill="none" stroke="#E63946" stroke-width="16" stroke-linecap="round"/>
    <circle cx="100" cy="100" r="40" fill="#FFFFFF"/>
    <line x1="100" y1="100" x2="138.3" y2="67.86" stroke="${needle}" stroke-width="6" stroke-linecap="round"/>
    <circle cx="100" cy="100" r="7" fill="${needle}"/>
  </svg>`;
}

// Branding defaults - used when AppSettings is missing/empty or the columns
// don't yet exist (resilient to a not-yet-migrated DB).
const BRANDING_DEFAULTS = {
  brandAppName: "CVE Tracker",
  brandLogoUrl: "",
  brandPrimaryColor: "#2C7BE5",
  reportHeaderText: "",
  reportFooterText: "",
  reportShowToc: true,
};

// Load the admin-configured branding from the AppSettings singleton (id=1).
// Falls back to defaults on any error so report generation never breaks.
async function loadBranding() {
  try {
    const row = await prisma.appSettings.findUnique({
      where: { id: 1 },
      select: {
        brandAppName: true,
        brandLogoUrl: true,
        brandPrimaryColor: true,
        reportHeaderText: true,
        reportFooterText: true,
        reportShowToc: true,
      },
    });
    if (!row) return { ...BRANDING_DEFAULTS };
    return {
      brandAppName: (row.brandAppName || "").trim() || BRANDING_DEFAULTS.brandAppName,
      brandLogoUrl: (row.brandLogoUrl || "").trim(),
      brandPrimaryColor:
        (row.brandPrimaryColor || "").trim() || BRANDING_DEFAULTS.brandPrimaryColor,
      reportHeaderText: (row.reportHeaderText || "").trim(),
      reportFooterText: (row.reportFooterText || "").trim(),
      reportShowToc: row.reportShowToc !== false,
    };
  } catch (e) {
    warn(`Report branding load failed, using defaults: ${e?.message || e}`);
    return { ...BRANDING_DEFAULTS };
  }
}

// Only allow plain hex colors into the stylesheet (prevents CSS injection
// via the user-supplied brand color).
function safeHexColor(value) {
  return /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(value || "") ? value : null;
}

function renderHtmlReport({ job, filter, cves, stats, branding = BRANDING_DEFAULTS }) {
  const generatedAt = new Date().toISOString();
  const title = filter.title || "Rapport CVE complet";
  // ── Branding-derived values
  const brandName = branding.brandAppName || "CVE Tracker";
  const primaryColor = safeHexColor(branding.brandPrimaryColor);
  const headerText = branding.reportHeaderText || "";
  const footerText = branding.reportFooterText || "";
  const showToc = branding.reportShowToc !== false;
  const headerLogoHtml = branding.brandLogoUrl
    ? `<img src="${escapeHtml(branding.brandLogoUrl)}" width="52" height="52" alt="${escapeHtml(brandName)}" style="display:block;object-fit:contain;border-radius:8px;background:#fff;padding:4px" />`
    : brandLogoSvg(52);
  const footerLogoHtml = branding.brandLogoUrl
    ? `<img src="${escapeHtml(branding.brandLogoUrl)}" width="22" height="22" alt="${escapeHtml(brandName)}" style="display:block;object-fit:contain" />`
    : brandLogoSvg(22);
  const primaryOverride = primaryColor
    ? `<style>:root{--accent:${primaryColor};}a{color:${primaryColor};}</style>`
    : "";
  const filterChips = [];
  if (filter.severity?.length) filterChips.push(`Sévérités: ${filter.severity.join(", ")}`);
  if (filter.status?.length) filterChips.push(`Statuts: ${filter.status.join(", ")}`);
  if (filter.source?.length) filterChips.push(`Sources: ${filter.source.join(", ")}`);
  if (filter.dateFrom || filter.from) filterChips.push(`Depuis: ${filter.dateFrom || filter.from}`);
  if (filter.dateTo || filter.to) filterChips.push(`Jusqu'à: ${filter.dateTo || filter.to}`);
  if (typeof filter.minCvss === "number") filterChips.push(`CVSS ≥ ${filter.minCvss}`);
  if (typeof filter.maxCvss === "number") filterChips.push(`CVSS ≤ ${filter.maxCvss}`);
  if (filter.search) filterChips.push(`Recherche: ${escapeHtml(filter.search)}`);

  // SVG bar chart for severity distribution
  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];
  const maxSev = Math.max(...severityOrder.map((s) => stats.bySeverity[s] || 0), 1);
  const barWidth = 60;
  const barGap = 30;
  const chartHeight = 200;
  const chartWidth = severityOrder.length * (barWidth + barGap) + barGap;
  const bars = severityOrder
    .map((sev, i) => {
      const v = stats.bySeverity[sev] || 0;
      const h = Math.max(2, (v / maxSev) * (chartHeight - 40));
      const x = barGap + i * (barWidth + barGap);
      const y = chartHeight - h - 20;
      const color = severityColor(sev);
      return `<g>
        <rect x="${x}" y="${y}" width="${barWidth}" height="${h}" fill="${color}" rx="4"/>
        <text x="${x + barWidth / 2}" y="${y - 6}" text-anchor="middle" font-size="13" fill="#111" font-weight="600">${v}</text>
        <text x="${x + barWidth / 2}" y="${chartHeight - 4}" text-anchor="middle" font-size="11" fill="#444">${sev}</text>
      </g>`;
    })
    .join("");

  // Top 20 most severe CVEs (full description) for the executive section
  const topCves = [...cves]
    .sort((a, b) => (b.cvssV3Score ?? 0) - (a.cvssV3Score ?? 0))
    .slice(0, 20);

  // Full table - keep all entries; modern browsers handle 10k+ rows
  const rowsHtml = cves
    .map((c) => {
      const refs = (() => {
        try {
          return c.references ? JSON.parse(c.references) : [];
        } catch {
          return [];
        }
      })();
      return `<tr>
        <td><a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(c.cveId)}" target="_blank" rel="noopener">${escapeHtml(c.cveId)}</a></td>
        <td><span class="badge" style="background:${severityColor(c.severity)}">${escapeHtml(c.severity)}</span></td>
        <td class="num">${c.cvssV3Score ?? "-"}</td>
        <td>${escapeHtml(c.status)}</td>
        <td>${escapeHtml(c.source)}</td>
        <td>${c.publishedAt ? new Date(c.publishedAt).toISOString().slice(0, 10) : "-"}</td>
        <td>${c.modifiedAt ? new Date(c.modifiedAt).toISOString().slice(0, 10) : "-"}</td>
        <td class="desc">${escapeHtml((c.description || "").slice(0, 280))}${(c.description || "").length > 280 ? "…" : ""}</td>
        <td class="num">${refs.length}</td>
      </tr>`;
    })
    .join("");

  const topCvesHtml = topCves
    .map(
      (c) => `<div class="topcve">
      <div class="topcve-h">
        <strong><a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(c.cveId)}" target="_blank" rel="noopener">${escapeHtml(c.cveId)}</a></strong>
        <span class="badge" style="background:${severityColor(c.severity)}">${escapeHtml(c.severity)}</span>
        <span class="cvss">CVSS ${c.cvssV3Score ?? "-"}</span>
      </div>
      <p>${escapeHtml((c.description || "").slice(0, 420))}${(c.description || "").length > 420 ? "…" : ""}</p>
    </div>`
    )
    .join("");

  const statusRowsHtml = Object.entries(stats.byStatus)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td class="num">${v}</td></tr>`)
    .join("");
  const sourceRowsHtml = Object.entries(stats.bySource)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td class="num">${v}</td></tr>`)
    .join("");

  // Table of contents (Sommaire) - anchors to the section ids below.
  const tocItems = [
    { id: "sec-summary", label: "Synthèse" },
    { id: "sec-severity", label: "Distribution par sévérité" },
    { id: "sec-statussource", label: "Répartition par statut & source" },
    ...(topCves.length > 0 ? [{ id: "sec-top", label: "Top 20 - CVE les plus sévères" }] : []),
    { id: "sec-list", label: `Liste complète (${cves.length})` },
  ];
  const tocHtml = showToc
    ? `<nav class="toc" aria-label="Sommaire">
    <div class="toc-title">Sommaire</div>
    <ol>${tocItems.map((it) => `<li><a href="#${it.id}">${escapeHtml(it.label)}</a></li>`).join("")}</ol>
  </nav>`
    : "";

  return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<style>
  /* CVE Tracker - charte graphique : rampe de sévérité + accent bleu + navy.
     Corps clair (lisible à l'impression) ; bandeau & dégradés de marque. */
  :root {
    color-scheme: light;
    --navy: #0B1220;
    --ink: #16203A;
    --accent: #2C7BE5;
    --accent-light: #6FC0FF;
    --muted: #5A6B86;
    --line: #DCE4F0;
    --panel: #F6F9FF;
    --crit: #E63946; --high: #FB8B24; --med: #FFD166; --low: #3DDC84;
    --grad-severity: linear-gradient(90deg, #3DDC84 0%, #FFD166 50%, #E63946 100%);
    --grad-warm: linear-gradient(100deg, #FFD166 0%, #FB8B24 52%, #E63946 100%);
    --grad-proactive: linear-gradient(125deg, #0B1220 0%, #123A36 38%, #2C8C66 62%, #2C7BE5 100%);
    --grad-accent: linear-gradient(90deg, #4DA8FF 0%, #E63946 100%);
    --display: "Space Grotesk", "Inter", system-ui, sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    font-family: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    margin: 0; padding: 0; color: var(--ink); background: #fff;
    -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }
  .wrap { max-width: 1200px; margin: 0 auto; padding: 0 0 64px; }
  .content { padding: 0 40px; }
  /* Direction 1 - rampe de sévérité : bandeau d'en-tête de page. */
  .brandbar { height: 6px; background: var(--grad-severity); }
  /* Direction 3 - sécurité proactive : bandeau d'aperçu. */
  header {
    background: var(--grad-proactive); color: #EAF2FF;
    padding: 26px 40px 22px; margin-bottom: 24px;
    display: flex; align-items: center; gap: 18px;
  }
  header .logo { width: 52px; height: 52px; flex: 0 0 auto; filter: drop-shadow(0 6px 14px rgba(0,0,0,0.45)); }
  header .eyebrow { font-size: 11px; letter-spacing: 1.8px; text-transform: uppercase; color: var(--accent-light); font-weight: 600; }
  h1 { font-family: var(--display); font-size: 27px; margin: 2px 0 5px; color: #fff; letter-spacing: 0.2px; }
  .sub { color: #C7D6EC; font-size: 12.5px; }
  .sub code { color: #EAF2FF; }
  .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
  .chip { font-size: 11px; padding: 4px 10px; border-radius: 999px; background: rgba(255,255,255,0.14); color: #EAF2FF; border: 1px solid rgba(255,255,255,0.18); }
  .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin: 24px 0; }
  .kpi { padding: 18px; border-radius: 10px; background: var(--panel); border: 1px solid var(--line); position: relative; overflow: hidden; }
  .kpi::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--grad-proactive); }
  .kpi-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
  .kpi-value { font-family: var(--display); font-size: 28px; font-weight: 700; color: var(--navy); margin-top: 4px; }
  .kpi-sub { font-size: 11px; color: var(--muted); margin-top: 4px; }
  h2 { font-family: var(--display); font-size: 18px; margin: 32px 0 12px; color: var(--navy); padding-left: 12px; border-left: 4px solid transparent; border-image: var(--grad-severity) 1; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
  .card { border: 1px solid var(--line); border-radius: 10px; padding: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { background: #EEF3FB; font-weight: 600; color: var(--ink); }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  td.desc { max-width: 380px; color: #33415A; }
  a { color: var(--accent); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; color: #0B1220; font-size: 11px; font-weight: 700; }
  .topcve { border-left: 4px solid transparent; border-image: var(--grad-warm) 1; padding: 10px 14px; margin-bottom: 10px; background: var(--panel); }
  .topcve-h { display: flex; align-items: center; gap: 12px; margin-bottom: 4px; }
  .topcve p { margin: 4px 0 0; color: #33415A; font-size: 12px; line-height: 1.5; }
  .cvss { font-size: 11px; color: var(--muted); margin-left: auto; }
  footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 11px; }
  footer .brandline { display: flex; align-items: center; justify-content: center; gap: 10px; }
  footer .brandline strong { color: var(--navy); font-family: var(--display); }
  footer .accentrule { height: 3px; width: 100%; background: var(--grad-severity); border-radius: 3px; margin-bottom: 14px; opacity: 0.85; }
  .print-only { display: none; }
  @media print {
    body { background: white; }
    .content { padding: 0 16px; }
    header { padding: 18px 16px 16px; }
    .no-print { display: none; }
    .print-only { display: block; }
    table { font-size: 10px; }
    th, td { padding: 4px 6px; }
    h2 { page-break-before: auto; }
    tr { page-break-inside: avoid; }
    .topcve { page-break-inside: avoid; }
  }
  .toolbar { display: flex; gap: 10px; margin: 16px 0; }
  .btn { padding: 8px 16px; border-radius: 8px; border: 1px solid var(--line); background: white; cursor: pointer; font-size: 13px; font-weight: 600; color: var(--ink); }
  .btn:hover { background: #EEF3FB; }
  .btn-primary { background: linear-gradient(140deg, #4DA8FF, #2C7BE5); color: #fff; border: 0; }
  .btn-primary:hover { filter: brightness(1.05); }
  /* Sommaire / table of contents */
  .toc { border: 1px solid var(--line); border-radius: 10px; padding: 14px 18px; margin: 20px 0 8px; background: var(--panel); page-break-inside: avoid; }
  .toc-title { font-family: var(--display); font-size: 13px; color: var(--navy); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1.2px; }
  .toc ol { margin: 0; padding-left: 20px; columns: 2; column-gap: 32px; font-size: 12.5px; line-height: 1.8; }
  .toc a { color: var(--accent); text-decoration: none; }
  .toc a:hover { text-decoration: underline; }
</style>
${primaryOverride}
</head>
<body>
<div class="wrap">
  <div class="brandbar"></div>

  <header>
    <div class="logo">${headerLogoHtml}</div>
    <div>
      <div class="eyebrow">Suite ${escapeHtml(brandName)}</div>
      <h1>${escapeHtml(title)}</h1>
      <div class="sub">Généré le ${escapeHtml(generatedAt)} · Job ID: <code>${escapeHtml(job.id)}</code> · ${stats.total} CVE${stats.total > 1 ? "s" : ""}</div>
      ${headerText ? `<div class="sub" style="margin-top:6px;font-weight:600;color:#EAF2FF">${escapeHtml(headerText)}</div>` : ""}
      ${filterChips.length > 0 ? `<div class="chips">${filterChips.map((c) => `<span class="chip">${c}</span>`).join("")}</div>` : ""}
    </div>
  </header>

  <div class="content">
  <div class="toolbar no-print">
    <button class="btn btn-primary" onclick="window.print()">📄 Enregistrer au format PDF (Ctrl+P)</button>
    <span style="font-size:11px;color:#5A6B86;align-self:center">Dans la fenêtre d'impression, choisissez la destination « Enregistrer au format PDF ».</span>
  </div>
  <div class="no-print" style="margin:0 0 16px;padding:10px 14px;border:1px solid #F3C9A0;background:#FFF7EC;border-radius:8px;font-size:12px;color:#7A4E12;line-height:1.6">
    ⚠️ <strong>Pour un PDF valide</strong>, sélectionnez la destination <strong>« Enregistrer au format PDF »</strong> (moteur du navigateur).
    Évitez <strong>« Microsoft Print to PDF »</strong> : ce pilote produit des en-têtes d'objets non conformes que les lecteurs stricts (Adobe, aperçu Windows) refusent d'ouvrir.
  </div>

  ${tocHtml}

  <section>
    <h2 id="sec-summary">Synthèse</h2>
    <div class="kpis">
      <div class="kpi"><div class="kpi-label">Total CVE</div><div class="kpi-value">${stats.total}</div></div>
      <div class="kpi"><div class="kpi-label">Critiques</div><div class="kpi-value" style="color:#E63946">${stats.bySeverity.CRITICAL}</div></div>
      <div class="kpi"><div class="kpi-label">Élevées</div><div class="kpi-value" style="color:#FB8B24">${stats.bySeverity.HIGH}</div></div>
      <div class="kpi"><div class="kpi-label">Moyennes</div><div class="kpi-value" style="color:#C98A06">${stats.bySeverity.MEDIUM}</div></div>
      <div class="kpi"><div class="kpi-label">CVSS moyen</div><div class="kpi-value">${stats.avgCvss}</div></div>
      <div class="kpi"><div class="kpi-label">Période couverte</div><div class="kpi-value" style="font-size:14px">${stats.oldestPublished ? stats.oldestPublished.slice(0, 10) : "-"}<div class="kpi-sub">au ${stats.newestPublished ? stats.newestPublished.slice(0, 10) : "-"}</div></div></div>
    </div>
  </section>

  <h2 id="sec-severity">Distribution par sévérité</h2>
  <div class="card">
    <svg viewBox="0 0 ${chartWidth} ${chartHeight}" width="100%" height="${chartHeight}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Distribution par sévérité">
      ${bars}
    </svg>
  </div>

  <h2 id="sec-statussource">Répartition par statut &amp; source</h2>
  <div class="grid2">
    <div class="card">
      <h3 style="margin:0 0 10px;font-size:14px;color:#0B1220;font-family:'Space Grotesk',Inter,sans-serif">Par statut</h3>
      <table><thead><tr><th>Statut</th><th class="num">Count</th></tr></thead><tbody>${statusRowsHtml || '<tr><td colspan="2" style="color:#94a3b8">-</td></tr>'}</tbody></table>
    </div>
    <div class="card">
      <h3 style="margin:0 0 10px;font-size:14px;color:#0B1220;font-family:'Space Grotesk',Inter,sans-serif">Par source</h3>
      <table><thead><tr><th>Source</th><th class="num">Count</th></tr></thead><tbody>${sourceRowsHtml || '<tr><td colspan="2" style="color:#94a3b8">-</td></tr>'}</tbody></table>
    </div>
  </div>

  ${
    topCves.length > 0
      ? `<h2 id="sec-top">Top 20 - CVE les plus sévères</h2>
  <div>${topCvesHtml}</div>`
      : ""
  }

  <h2 id="sec-list">Liste complète (${cves.length})</h2>
  <table>
    <thead>
      <tr>
        <th>CVE ID</th>
        <th>Sévérité</th>
        <th class="num">CVSS</th>
        <th>Statut</th>
        <th>Source</th>
        <th>Publié</th>
        <th>Modifié</th>
        <th>Description</th>
        <th class="num">Refs</th>
      </tr>
    </thead>
    <tbody>${rowsHtml || '<tr><td colspan="9" style="text-align:center;color:#94a3b8;padding:24px">Aucune CVE ne correspond aux filtres.</td></tr>'}</tbody>
  </table>

  <footer>
    <div class="accentrule"></div>
    <div class="brandline">${footerLogoHtml}<span><strong>${escapeHtml(brandName)}</strong> · Suite ${escapeHtml(brandName)} · ${escapeHtml(generatedAt)} · ${stats.total} entrées · données source: NVD</span></div>
    ${footerText ? `<div style="text-align:center;margin-top:8px;color:var(--ink)">${escapeHtml(footerText)}</div>` : ""}
  </footer>
  </div>
</div>
</body>
</html>`;
}

function renderCsv(cves) {
  const header = [
    "cveId",
    "title",
    "severity",
    "status",
    "source",
    "cvssV3Score",
    "cvssV3Vector",
    "cvssV4Score",
    "epssScore",
    "publishedAt",
    "modifiedAt",
    "vulnStatus",
    "description",
    "references",
  ];
  const escape = (v) => {
    if (v === null || v === undefined) return "";
    if (v instanceof Date) return v.toISOString();
    const s = String(v).replace(/"/g, '""');
    return /[",\n\r]/.test(s) ? `"${s}"` : s;
  };
  const rows = cves.map((c) => header.map((h) => escape(c[h])).join(","));
  // BOM so Excel detects UTF-8
  return "﻿" + [header.join(","), ...rows].join("\r\n");
}

// ─── Asset-inventory report ──────────────────────────────────────────────────

function assetCriticalityColor(c) {
  switch (c) {
    case "critical": return "#E63946";
    case "high": return "#FB8B24";
    case "medium": return "#FFD166";
    case "low": return "#3DDC84";
    default: return "#94a3b8";
  }
}

function assetProductLabel(product) {
  if (!product) return "";
  return [product.vendor, product.name, product.version].filter(Boolean).join(" ");
}

// Exposure scoring lives in a shared CommonJS module (also used by the
// recompute/backfill script); it is the JS twin of
// frontend/src/lib/v2/exposure.ts used by the sync/cpe ingest path.
// eslint-disable-next-line global-require
const { assetExposure, DANGEROUS_SERVICES } = require("./exposure.js");

const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };

// Deduped, severity-sorted list of every CVE matched to an asset, with the
// product it came from - so each CVE can be listed and linked individually.
function assetCveList(asset) {
  const seen = new Map(); // cveId -> { cveId, severity, score, product, patchStatus }
  for (const pl of asset.productLinks || []) {
    const plabel = assetProductLabel(pl.product);
    for (const cl of pl.product?.cveLinks || []) {
      const c = cl.cve;
      if (!c?.cveId || seen.has(c.cveId)) continue;
      seen.set(c.cveId, {
        cveId: c.cveId,
        severity: c.severity || "NONE",
        score: c.cvssV3Score ?? null,
        product: plabel,
        patchStatus: cl.patchStatus || "UNKNOWN",
      });
    }
  }
  return [...seen.values()].sort(
    (a, b) =>
      (b.score ?? 0) - (a.score ?? 0) ||
      (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) ||
      a.cveId.localeCompare(b.cveId)
  );
}

function aggregateAssetStats(assets) {
  const byCriticality = { critical: 0, high: 0, medium: 0, low: 0 };
  const byStatus = { active: 0, inactive: 0, retired: 0 };
  const byType = {};
  let totalProducts = 0;
  let totalVulns = 0;
  let withVulns = 0;
  let totalPorts = 0;
  let criticalCves = 0;
  let highCves = 0;
  let maxExposure = 0;
  for (const a of assets) {
    if (a.criticality in byCriticality) byCriticality[a.criticality]++;
    if (a.status in byStatus) byStatus[a.status]++;
    byType[a.type] = (byType[a.type] || 0) + 1;
    const prods = a._count?.productLinks ?? (a.productLinks?.length ?? 0);
    const exp = a._exposure || assetExposure(a);
    // "Vulnerabilities" now means matched CVEs (ProductCVE), not the legacy and
    // almost-always-empty Vulnerability relation.
    const vulns = exp.cve.total;
    totalProducts += prods;
    totalVulns += vulns;
    if (vulns > 0) withVulns++;
    criticalCves += exp.cve.critical;
    highCves += exp.cve.high;
    if (exp.score > maxExposure) maxExposure = exp.score;
    totalPorts += Array.isArray(a.services) ? a.services.filter((s) => s && s.port != null).length : 0;
  }
  return {
    total: assets.length,
    byCriticality,
    byStatus,
    byType,
    totalProducts,
    totalVulns,
    withVulns,
    totalPorts,
    criticalCves,
    highCves,
    maxExposure,
  };
}

function renderAssetsCsv(assets) {
  const header = [
    "name", "type", "ip", "hostname", "criticality", "status",
    "products", "cpes", "ports", "exposure_score",
    "cve_total", "cve_critical", "cve_high", "cve_ids", "tags", "description",
  ];
  const escape = (v) => {
    if (v === null || v === undefined) return "";
    if (v instanceof Date) return v.toISOString();
    const s = String(v).replace(/"/g, '""');
    return /[",\n\r]/.test(s) ? `"${s}"` : s;
  };
  const rows = assets.map((a) => {
    const prods = (a.productLinks || []).map((pl) => assetProductLabel(pl.product)).filter(Boolean).join("; ");
    const cpes = (a.productLinks || []).map((pl) => pl.product?.cpe).filter(Boolean).join("; ");
    const ports = (Array.isArray(a.services) ? a.services : [])
      .filter((s) => s && s.port != null)
      .map((s) => (s.service ? `${s.port}/${s.service}` : String(s.port)))
      .join("; ");
    const exp = a._exposure || assetExposure(a);
    const cveIds = assetCveList(a).map((c) => c.cveId).join("; ");
    return [
      a.name, a.type, a.ip, a.hostname, a.criticality, a.status,
      prods, cpes, ports, exp.score,
      exp.cve.total, exp.cve.critical, exp.cve.high, cveIds, (a.tags || []).join("|"), a.description,
    ].map(escape).join(",");
  });
  // BOM so Excel detects UTF-8
  return "﻿" + [header.join(","), ...rows].join("\r\n");
}

// ── BLUF (Bottom Line Up Front) decision support ────────────────────────────
// Everything below turns the raw inventory into "what to do, in what order".

const URGENCY_RANK = { critical: 3, high: 2, medium: 1, low: 0 };

function cveSev(c) {
  return String(c.severity || "NONE").toUpperCase();
}

function urgencyLabel(u) {
  return { critical: "Immédiat", high: "Court terme", medium: "À planifier", low: "Surveillance" }[u] || "-";
}

// Concrete, prioritized remediation steps for ONE asset, derived from its
// open-service exposure (exp.hits) and its matched CVEs (cveList). Each action
// has an urgency so the whole fleet can be ranked into a single queue.
function assetRecommendedActions(exp, cveList) {
  const actions = [];
  const dangerous = (exp.hits || []).filter((h) => h.weight >= 16);
  const crit = cveList.filter((c) => cveSev(c) === "CRITICAL");
  const high = cveList.filter((c) => cveSev(c) === "HIGH");

  if (crit.length) {
    actions.push({
      urgency: "critical",
      label: "Corriger",
      text: `Appliquer en urgence les correctifs de ${crit.length} CVE critique${crit.length > 1 ? "s" : ""} (${crit.slice(0, 3).map((c) => c.cveId).join(", ")}${crit.length > 3 ? ", …" : ""}).`,
    });
  }
  if (dangerous.length) {
    const top = dangerous.slice(0, 4).map((h) => `${h.port}/${h.label}`).join(", ");
    actions.push({
      urgency: dangerous.some((h) => h.weight >= 30) ? "critical" : "high",
      label: "Confiner",
      text: `Restreindre ou segmenter l'exposition réseau : ${top}${dangerous.length > 4 ? ", …" : ""}.`,
    });
  }
  if (!crit.length && high.length) {
    actions.push({
      urgency: "high",
      label: "Planifier",
      text: `Programmer la remédiation de ${high.length} CVE élevée${high.length > 1 ? "s" : ""} (${high.slice(0, 3).map((c) => c.cveId).join(", ")}${high.length > 3 ? ", …" : ""}).`,
    });
  }
  if (!actions.length) {
    actions.push({ urgency: "low", label: "Surveiller", text: "Aucune exposition critique - maintenir la surveillance." });
  }
  // strongest urgency first
  actions.sort((a, b) => URGENCY_RANK[b.urgency] - URGENCY_RANK[a.urgency]);
  return actions;
}

// The decision summary: a posture verdict + the prioritized action queue.
function computeAssetBluf(assets, stats) {
  const ranked = assets
    .map((a) => {
      const exp = a._exposure || assetExposure(a);
      const cves = assetCveList(a);
      return { a, exp, cves, actions: assetRecommendedActions(exp, cves) };
    })
    .sort((x, y) => y.exp.score - x.exp.score);

  // Immediate = a critical CVE is exposed OR a high-weight dangerous service is open.
  const immediate = ranked.filter(
    (r) => r.exp.cve.critical > 0 || (r.exp.hits || []).some((h) => h.weight >= 30)
  );
  const elevated = ranked.filter(
    (r) => !immediate.includes(r) && (r.exp.cve.high > 0 || (r.exp.hits || []).some((h) => h.weight >= 16))
  );

  let dangerousServices = 0;
  for (const r of ranked) dangerousServices += (r.exp.hits || []).filter((h) => h.weight >= 16).length;

  let posture;
  let postureClass;
  let verdict;
  if (immediate.length > 0) {
    posture = "CRITIQUE";
    postureClass = "crit";
    verdict = `${immediate.length} actif${immediate.length > 1 ? "s exigent" : " exige"} une action corrective immédiate : CVE critiques exposées et/ou services à haut risque accessibles sur le réseau.`;
  } else if (elevated.length > 0 || (stats.highCves ?? 0) > 0) {
    posture = "ÉLEVÉE";
    postureClass = "high";
    const n = Math.max(elevated.length, stats.highCves ?? 0);
    verdict = `Aucune exposition critique, mais ${n} point${n > 1 ? "s" : ""} à risque élevé à traiter à court terme avant qu'ils ne s'aggravent.`;
  } else if ((stats.totalVulns ?? 0) > 0 || dangerousServices > 0) {
    posture = "MODÉRÉE";
    postureClass = "med";
    verdict = "Exposition résiduelle modérée ; priorité à la réduction de surface d'attaque et au suivi régulier.";
  } else {
    posture = "MAÎTRISÉE";
    postureClass = "low";
    verdict = "Aucune vulnérabilité ni service dangereux détecté sur le périmètre analysé. Maintenir la posture.";
  }

  // The action queue: assets carrying at least one non-surveillance action.
  const queue = ranked.filter((r) => r.actions.some((ac) => ac.urgency !== "low"));

  return { ranked, immediate, elevated, dangerousServices, posture, postureClass, verdict, queue };
}

// ── Per-asset documentation helpers ─────────────────────────────────────────
// French criticality labels for the prose/fiches (kept apart from the colour map).
const LEVEL_FR = { critical: "Critique", high: "Élevé", medium: "Modéré", low: "Faible" };

// Concrete risk + corrective-measure copy per dangerous port. Keyed by TCP port;
// used to turn an open-service finding into an actionable remediation row. Ports
// absent here fall back to portRemediation()'s generic guidance.
const PORT_REMEDIATION = {
  21: { risk: "FTP en clair : identifiants et fichiers interceptables.", fix: "Désactiver FTP ou migrer vers FTPS/SFTP ; interdire l'accès anonyme." },
  22: { risk: "SSH exposé : cible de force brute.", fix: "Authentification par clé uniquement, désactiver root, restreindre par pare-feu/Fail2ban." },
  23: { risk: "Telnet en clair : session et mot de passe lisibles sur le réseau.", fix: "Désactiver Telnet et le remplacer intégralement par SSH." },
  25: { risk: "SMTP exposé : relais ouvert / énumération possible.", fix: "Restreindre le relais, exiger l'authentification, limiter l'exposition externe." },
  53: { risk: "DNS exposé : amplification / transfert de zone.", fix: "Désactiver la récursion ouverte et les transferts de zone non autorisés." },
  80: { risk: "HTTP en clair : trafic interceptable.", fix: "Forcer HTTPS (redirection + HSTS) et maintenir le serveur à jour." },
  110: { risk: "POP3 en clair.", fix: "Imposer POP3S/IMAPS (TLS) et désactiver les variantes en clair." },
  111: { risk: "rpcbind : cartographie des services RPC (NFS…).", fix: "Filtrer le portmapper, n'exposer RPC que sur réseau de confiance." },
  139: { risk: "NetBIOS : énumération et accès SMB hérité.", fix: "Désactiver NetBIOS, bloquer 137-139 au pare-feu périmétrique." },
  445: { risk: "SMB : mouvement latéral et exécution distante.", fix: "Bloquer SMB en bordure, désactiver SMBv1, appliquer les correctifs (MS17-010…)." },
  161: { risk: "SNMP : fuite de configuration via community par défaut.", fix: "Passer en SNMPv3, supprimer les community 'public'/'private'." },
  512: { risk: "rexec : exécution distante en clair.", fix: "Désactiver les r-services, n'utiliser que SSH." },
  513: { risk: "rlogin : accès basé sur la confiance, en clair.", fix: "Désactiver rlogin et les fichiers .rhosts/hosts.equiv." },
  514: { risk: "rsh : exécution distante en clair, sans authentification forte.", fix: "Désactiver rsh, supprimer la confiance .rhosts, imposer SSH." },
  1099: { risk: "Java RMI : désérialisation → exécution de code distante.", fix: "Restreindre RMI au réseau interne, mettre à jour la JVM, filtrer la désérialisation." },
  1433: { risk: "MSSQL exposé.", fix: "Restreindre par pare-feu, mots de passe forts, désactiver xp_cmdshell." },
  1524: { risk: "ingreslock : port de bind-shell classique (souvent backdoor).", fix: "Investiguer une compromission, fermer le port, ré-imager si confirmé." },
  2049: { risk: "NFS : systèmes de fichiers exportés potentiellement en lecture/écriture.", fix: "Restreindre les exports (no_root_squash off), filtrer par hôte, préférer NFSv4 + Kerberos." },
  2121: { risk: "FTP alternatif en clair.", fix: "Désactiver ou migrer vers SFTP/FTPS." },
  2375: { risk: "API Docker non authentifiée : équivaut à un root distant.", fix: "Ne jamais exposer l'API ; activer TLS (2376) et l'authentification client." },
  2376: { risk: "API Docker (TLS) exposée.", fix: "Restreindre l'accès réseau, vérifier les certificats client." },
  3306: { risk: "MySQL/MariaDB exposé.", fix: "Lier en local/pare-feu, mots de passe forts, désactiver l'accès distant root." },
  3389: { risk: "RDP : accès distant et mouvement latéral.", fix: "VPN + MFA, NLA activé, jamais d'exposition directe Internet, correctifs à jour." },
  3632: { risk: "distccd : compilation distribuée → exécution de code distante.", fix: "Désactiver distcc ou le restreindre strictement au réseau de build." },
  5432: { risk: "PostgreSQL exposé.", fix: "Restreindre pg_hba.conf et le pare-feu, imposer TLS et mots de passe forts." },
  5900: { risk: "VNC : contrôle distant du bureau, souvent faible auth.", fix: "Tunneler via SSH/VPN, mot de passe fort, ne pas exposer en direct." },
  5984: { risk: "CouchDB : base potentiellement non authentifiée.", fix: "Activer l'authentification, restreindre l'interface d'écoute." },
  6000: { risk: "X11 : capture d'écran et de frappe possible.", fix: "Désactiver l'écoute TCP de X (-nolisten tcp), tunneler via SSH." },
  6379: { risk: "Redis : souvent sans authentification → exécution de code.", fix: "Activer requirepass/ACL, lier en local, protected-mode on, pare-feu." },
  6667: { risk: "IRC : canal de contrôle (parfois bot/backdoor).", fix: "Fermer si non requis, investiguer un éventuel C2." },
  6697: { risk: "IRC (TLS).", fix: "Fermer si non requis, surveiller l'usage." },
  8009: { risk: "AJP (Ghostcat, CVE-2020-1938) : lecture de fichiers / RCE Tomcat.", fix: "Désactiver le connecteur AJP ou exiger un secret, mettre Tomcat à jour." },
  8080: { risk: "HTTP alternatif en clair.", fix: "Forcer TLS, authentifier les consoles d'administration." },
  8180: { risk: "Console Tomcat exposée.", fix: "Restreindre l'accès, supprimer les comptes par défaut, mettre à jour." },
  8443: { risk: "HTTPS alternatif / console d'admin.", fix: "Restreindre l'accès, certificats valides, correctifs à jour." },
  8787: { risk: "Ruby DRb : objets distants → exécution de code.", fix: "Désactiver DRb sur interface publique, restreindre au localhost." },
  9200: { risk: "Elasticsearch (HTTP) : souvent non authentifié.", fix: "Activer la sécurité (auth/TLS), lier en local, pare-feu." },
  9300: { risk: "Elasticsearch (transport) exposé.", fix: "Restreindre au cluster, activer TLS de transport." },
  11211: { risk: "Memcached : non authentifié, amplification DDoS.", fix: "Lier en local, désactiver UDP, pare-feu." },
  27017: { risk: "MongoDB : souvent sans authentification.", fix: "Activer l'authentification + TLS, lier en local, pare-feu." },
};

// Remediation copy for a port. Falls back to generic surface-reduction advice
// (scaled by the dangerous-service label when known) for ports outside the map.
function portRemediation(port, label) {
  if (PORT_REMEDIATION[port]) return PORT_REMEDIATION[port];
  return {
    risk: `${label || "Service"} accessible sur le réseau : surface d'attaque exploitable.`,
    fix: "Confirmer la légitimité du service, restreindre l'accès au strict nécessaire (pare-feu/segmentation) ou le désactiver.",
  };
}

// Opening section: what this report is, how it was produced, how to read it.
function renderIntro({ stats, generatedAt, brandName }) {
  const ports = stats.totalPorts ?? 0;
  const scopeLine =
    `${stats.total} actif${stats.total > 1 ? "s" : ""}, ` +
    `${ports} port${ports > 1 ? "s" : ""} ouvert${ports > 1 ? "s" : ""}, ` +
    `${stats.totalProducts} produit${stats.totalProducts > 1 ? "s" : ""} identifié${stats.totalProducts > 1 ? "s" : ""}`;
  const legend = ["critical", "high", "medium", "low"]
    .map((lvl) => `<span class="legend-item"><span class="legend-dot" style="background:${assetCriticalityColor(lvl)}"></span>${LEVEL_FR[lvl]}</span>`)
    .join("");
  return `<section id="sec-intro">
    <h2>Introduction et méthodologie</h2>
    <div class="intro-grid">
      <div class="intro-card">
        <h3>Objet du rapport</h3>
        <p>Ce document présente l'inventaire de sécurité et l'évaluation d'exposition du périmètre analysé par <strong>${escapeHtml(brandName)}</strong> au ${escapeHtml(generatedAt.slice(0, 10))} : ${scopeLine}. Il fournit une posture globale, un plan d'action priorisé et une fiche détaillée par actif.</p>
      </div>
      <div class="intro-card">
        <h3>Méthode</h3>
        <p>Chaque actif est découvert par balayage réseau : services et ports ouverts, bannières, empreintes CPE. Les services porteurs d'un CPE sont corrélés à la base NVD pour identifier les CVE connues. Un score d'exposition combine la <em>surface réseau</em> (services dangereux ouverts) et la <em>sévérité des CVE</em> corrélées.</p>
      </div>
      <div class="intro-card">
        <h3>Comment lire ce rapport</h3>
        <p>Commencez par la <strong>synthèse décisionnelle</strong> (posture + métriques), puis suivez le <strong>plan d'action priorisé</strong> de haut en bas. Les <strong>fiches détaillées</strong> justifient chaque priorité (services, remédiations, CVE) ; le détail du calcul figure en <strong>annexe</strong>.</p>
        <div class="legend">${legend}</div>
      </div>
    </div>
  </section>`;
}

// One self-contained dossier per asset, ordered by exposure: header + metadata,
// the full open-service table (every port, CPE-bearing or not), prioritized
// service remediations, the action plan, and the matched-CVE table. The CVE
// subsection carries id="cve-<assetId>" so the inventory's CVE links resolve.
function renderAssetFiche(entry, idx) {
  const { a, exp, cves, actions } = entry;
  const services = (Array.isArray(a.services) ? a.services : []).filter((s) => s && s.port != null);

  const svcRows = services
    .map((s) => {
      const def = DANGEROUS_SERVICES[s.port];
      return { s, weight: def ? def.weight : 2, label: def ? def.label : (s.service || "-") };
    })
    .sort((x, y) => y.weight - x.weight || x.s.port - y.s.port);

  const svcTable = svcRows
    .map(({ s, weight, label }) => {
      const wcls = weight >= 30 ? "wt wt-crit" : weight >= 16 ? "wt wt-high" : weight >= 6 ? "wt wt-med" : "wt wt-low";
      const banner = (s.banner || "").trim();
      return `<tr>
        <td class="mono">${s.port}/${escapeHtml(s.protocol || "tcp")}</td>
        <td>${escapeHtml(s.service || "-")}</td>
        <td>${escapeHtml([s.product, s.version].filter(Boolean).join(" ") || "-")}</td>
        <td class="mono">${s.cpe ? escapeHtml(s.cpe) : '<span class="muted">-</span>'}</td>
        <td>${banner ? `<span class="muted" title="${escapeHtml(banner)}">${escapeHtml(banner.slice(0, 48))}${banner.length > 48 ? "…" : ""}</span>` : '<span class="muted">-</span>'}</td>
        <td class="num"><span class="${wcls}" title="${escapeHtml(label)}">${weight}</span></td>
      </tr>`;
    })
    .join("");

  const remRows = svcRows
    .filter(({ weight }) => weight >= 16)
    .map(({ s, label }) => {
      const rem = portRemediation(s.port, label);
      return `<tr>
        <td class="mono">${s.port}</td>
        <td><strong>${escapeHtml(label)}</strong><div class="muted">${escapeHtml(rem.risk)}</div></td>
        <td>${escapeHtml(rem.fix)}</td>
      </tr>`;
    })
    .join("");
  const remBlock = remRows
    ? `<h4>Remédiation prioritaire des services exposés</h4>
       <table class="svctab"><thead><tr><th>Port</th><th>Service · risque</th><th>Mesure corrective</th></tr></thead><tbody>${remRows}</tbody></table>`
    : "";

  const actsHtml = actions
    .map((ac) => `<li><span class="act-k act-${ac.urgency}">${escapeHtml(ac.label)}</span> ${escapeHtml(ac.text)}</li>`)
    .join("");

  const cveRows = cves
    .map((c) => {
      const sevKey = String(c.severity).toLowerCase();
      return `<tr>
        <td><a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(c.cveId)}" target="_blank" rel="noopener">${escapeHtml(c.cveId)}</a></td>
        <td><span class="badge" style="background:${assetCriticalityColor(sevKey)}">${escapeHtml(c.severity)}</span></td>
        <td class="num">${c.score != null ? Number(c.score).toFixed(1) : "-"}</td>
        <td>${escapeHtml(c.product || "-")}</td>
        <td>${escapeHtml(String(c.patchStatus).toLowerCase())}</td>
      </tr>`;
    })
    .join("");
  const cveBlock = cves.length
    ? `<h4 id="cve-${escapeHtml(a.id)}">Vulnérabilités confirmées (${cves.length})</h4>
       <p class="muted" style="margin:-2px 0 8px">Chaque identifiant ouvre la fiche officielle sur la base NVD (nvd.nist.gov).</p>
       <table class="svctab"><thead><tr><th>CVE</th><th>Sévérité</th><th class="num">CVSS</th><th>Produit affecté</th><th>Correctif</th></tr></thead><tbody>${cveRows}</tbody></table>`
    : `<h4 id="cve-${escapeHtml(a.id)}">Vulnérabilités confirmées</h4>
       <p class="muted">Aucune CVE corrélée à ce jour pour les produits identifiés. L'exposition provient de la surface réseau (services ouverts ci-dessus). Relancer la corrélation CVE après mise à jour de la base NVD.</p>`;

  const tint = assetCriticalityColor(exp.level);
  const cveScore = exp.score - exp.serviceScore;
  const meta = [
    ["Type", escapeHtml(a.type || "-")],
    ["Statut", escapeHtml(a.status || "-")],
    ["Adresse MAC", a.mac ? `<span class="mono">${escapeHtml(a.mac)}</span>` : "-"],
    ["Services ouverts", String(services.length)],
    ["Surface réseau", `${exp.serviceScore} pts`],
    ["Score CVE", `${cveScore} pts`],
    ["CVE corrélées", `${exp.cve.total} (${exp.cve.critical}C / ${exp.cve.high}H)`],
    ["Score d'exposition", `<strong>${exp.score}</strong> · ${LEVEL_FR[exp.level] || exp.level}`],
  ]
    .map(([k, v]) => `<div class="fiche-meta-k">${k}</div><div class="fiche-meta-v">${v}</div>`)
    .join("");

  return `<section class="fiche" id="fiche-${escapeHtml(a.id)}" style="border-left-color:${tint}">
    <div class="fiche-head" style="background:linear-gradient(120deg, ${tint}22, transparent)">
      <span class="fiche-prio">${idx + 1}</span>
      <div class="fiche-head-main">
        <h3>${escapeHtml(a.name)} <span class="muted mono">${escapeHtml(a.ip || a.hostname || "")}</span></h3>
        <div><span class="badge" style="background:${assetCriticalityColor(a.criticality)}">${escapeHtml(a.criticality)}</span>
          <span class="muted"> exposition ${exp.score} · ${LEVEL_FR[exp.level] || exp.level} · ${services.length} services · ${exp.cve.total} CVE</span></div>
      </div>
      <div class="fiche-score" style="color:${tint}">${exp.score}</div>
    </div>
    ${a.description ? `<p class="fiche-desc">${escapeHtml(a.description)}</p>` : ""}
    <div class="fiche-meta">${meta}</div>
    <h4>Services et ports ouverts (${services.length})</h4>
    <table class="svctab"><thead><tr><th>Port</th><th>Service</th><th>Produit / version</th><th>CPE</th><th>Bannière</th><th class="num">Poids</th></tr></thead><tbody>${svcTable || '<tr><td colspan="6" class="muted">Aucun service ouvert détecté.</td></tr>'}</tbody></table>
    ${remBlock}
    <h4>Plan d'action</h4>
    <ul class="actlist">${actsHtml}</ul>
    ${cveBlock}
  </section>`;
}

// Closing annex: the score model, a glossary, and the legal/ethical frame.
function renderAnnex() {
  return `<section id="sec-annex">
    <h2>Annexes</h2>
    <h3>A · Modèle de score d'exposition</h3>
    <p class="muted" style="margin-top:-4px">Le score d'exposition d'un actif additionne deux composantes, plafonnées pour rester lisibles.</p>
    <table class="gloss">
      <tr><th>Composante</th><th>Calcul</th></tr>
      <tr><td>Surface réseau</td><td>Somme des poids des services ouverts (table des services dangereux). Un port hors table compte pour 2.</td></tr>
      <tr><td>Sévérité CVE</td><td>min(18 × critiques + 9 × élevées + 3 × modérées, 60)</td></tr>
      <tr><td>Score total</td><td>Surface réseau + Sévérité CVE</td></tr>
      <tr><td>Seuils de criticité</td><td>≥ 60 → Critique · ≥ 32 → Élevé · ≥ 12 → Modéré · sinon Faible</td></tr>
    </table>
    <h3>B · Glossaire</h3>
    <table class="gloss">
      <tr><th>Terme</th><th>Définition</th></tr>
      <tr><td>CVE</td><td>Common Vulnerabilities and Exposures - identifiant public unique d'une vulnérabilité connue.</td></tr>
      <tr><td>CPE</td><td>Common Platform Enumeration - désignation normalisée d'un produit/version, clé de corrélation avec les CVE.</td></tr>
      <tr><td>CVSS</td><td>Common Vulnerability Scoring System - score de gravité de 0 à 10 d'une CVE.</td></tr>
      <tr><td>NVD</td><td>National Vulnerability Database (NIST) - base de référence reliant CPE et CVE.</td></tr>
      <tr><td>Exposition</td><td>Score composite (surface réseau + sévérité CVE) traduisant le risque exploitable d'un actif.</td></tr>
      <tr><td>BLUF</td><td>Bottom Line Up Front - synthèse décisionnelle placée en tête de rapport.</td></tr>
      <tr><td>Service dangereux</td><td>Port/service directement exploitable ou facilitant le mouvement latéral (data stores non authentifiés, accès distant, protocoles en clair).</td></tr>
    </table>
    <h3>C · Cadre légal et éthique</h3>
    <p>Les analyses présentées portent exclusivement sur des actifs appartenant au périmètre autorisé du commanditaire. Toute analyse de vulnérabilité doit s'inscrire dans un mandat explicite ; l'accès ou le test de systèmes tiers sans autorisation écrite est susceptible de constituer une infraction (en France, articles 323-1 et suivants du Code pénal). Ce rapport est confidentiel et destiné aux seules équipes habilitées.</p>
  </section>`;
}

function renderAssetsHtmlReport({ job, filter, assets, stats, branding = BRANDING_DEFAULTS }) {
  const generatedAt = new Date().toISOString();
  const title = filter.title || "Rapport d'inventaire des actifs";
  const brandName = branding.brandAppName || "CVE Tracker";
  const primaryColor = safeHexColor(branding.brandPrimaryColor);
  const headerText = branding.reportHeaderText || "";
  const footerText = branding.reportFooterText || "";
  const showToc = branding.reportShowToc !== false;
  const headerLogoHtml = branding.brandLogoUrl
    ? `<img src="${escapeHtml(branding.brandLogoUrl)}" width="52" height="52" alt="${escapeHtml(brandName)}" style="display:block;object-fit:contain;border-radius:8px;background:#fff;padding:4px" />`
    : brandLogoSvg(52);
  const footerLogoHtml = branding.brandLogoUrl
    ? `<img src="${escapeHtml(branding.brandLogoUrl)}" width="22" height="22" alt="${escapeHtml(brandName)}" style="display:block;object-fit:contain" />`
    : brandLogoSvg(22);
  const primaryOverride = primaryColor
    ? `<style>:root{--accent:${primaryColor};}a{color:${primaryColor};}</style>`
    : "";

  const filterChips = [];
  if (filter.search) filterChips.push(`Recherche: ${escapeHtml(filter.search)}`);
  if (filter.criticality) filterChips.push(`Criticité: ${escapeHtml(filter.criticality)}`);
  if (filter.assetStatus) filterChips.push(`Statut: ${escapeHtml(filter.assetStatus)}`);

  const critRows = Object.entries(stats.byCriticality)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => `<tr><td><span class="badge" style="background:${assetCriticalityColor(k)}">${escapeHtml(k)}</span></td><td class="num">${v}</td></tr>`)
    .join("");
  const statusRows = Object.entries(stats.byStatus)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td class="num">${v}</td></tr>`)
    .join("");
  const typeRows = Object.entries(stats.byType)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td class="num">${v}</td></tr>`)
    .join("");

  const rowsHtml = assets
    .map((a) => {
      const prods = (a.productLinks || [])
        .map((pl) => {
          const p = pl.product || {};
          const label = [p.name, p.version].filter(Boolean).join(" ");
          const full = assetProductLabel(p);
          return `<span class="pill" title="${escapeHtml(p.cpe || full)}">${escapeHtml(label || full)}</span>`;
        })
        .join(" ");
      const ports = (Array.isArray(a.services) ? a.services : [])
        .filter((s) => s && s.port != null)
        .map((s) => {
          const ttl = [s.service, s.product, s.version].filter(Boolean).join(" ");
          return `<span class="port" title="${escapeHtml(ttl)}">${s.port}${s.service ? "/" + escapeHtml(s.service) : ""}</span>`;
        })
        .join(" ");
      const exp = a._exposure || assetExposure(a);
      const expPct = Math.min(100, Math.round((exp.score / 130) * 100));
      const cve = exp.cve;
      const vulnInner =
        `<strong>${cve.total}</strong>` +
        (cve.critical ? ` <span class="sev sev-crit" title="critiques">${cve.critical}C</span>` : "") +
        (cve.high ? ` <span class="sev sev-high" title="élevées">${cve.high}H</span>` : "");
      const vulnCell =
        cve.total > 0
          ? `<a class="cvelink" href="#cve-${escapeHtml(a.id)}" title="Voir le détail des CVE">${vulnInner}</a>`
          : '<span class="muted">0</span>';
      const desc = (a.description || "").trim();
      return `<tr>
        <td>
          <strong>${escapeHtml(a.name)}</strong>
          ${desc ? `<div class="muted">${escapeHtml(desc.slice(0, 90))}${desc.length > 90 ? "…" : ""}</div>` : ""}
          ${a.tags?.length ? `<div class="tags">${a.tags.map((t) => `#${escapeHtml(t)}`).join(" ")}</div>` : ""}
        </td>
        <td>${escapeHtml(a.type)}</td>
        <td>
          ${a.ip ? `<div class="mono">${escapeHtml(a.ip)}</div>` : ""}
          ${a.hostname ? `<div class="muted">${escapeHtml(a.hostname)}</div>` : ""}
          ${!a.ip && !a.hostname ? "-" : ""}
        </td>
        <td><span class="badge" style="background:${assetCriticalityColor(a.criticality)}">${escapeHtml(a.criticality)}</span></td>
        <td>${escapeHtml(a.status)}</td>
        <td>
          ${prods || ""}
          ${ports ? `<div class="ports">${ports}</div>` : ""}
          ${!prods && !ports ? '<span class="muted">-</span>' : ""}
        </td>
        <td>
          <div class="expscore">${exp.score}</div>
          <div class="expbar"><span style="width:${expPct}%;background:${assetCriticalityColor(exp.level)}"></span></div>
        </td>
        <td class="num">${vulnCell}</td>
      </tr>`;
    })
    .join("");

  // ── BLUF: decision summary + prioritized action plan ─────────────────────
  const bluf = computeAssetBluf(assets, stats);
  const maxExposure = stats.maxExposure ?? bluf.ranked.reduce((m, r) => Math.max(m, r.exp.score), 0);

  // One detailed dossier per asset, ordered by exposure (bluf.ranked is already
  // sorted). Replaces the old CVE-only sections: each fiche carries the full
  // open-service table, prioritized remediations, the action plan AND the
  // matched-CVE table (anchored id="cve-<id>" so the inventory links resolve).
  const introHtml = renderIntro({ stats, generatedAt, brandName });
  const fichesHtml = bluf.ranked.map((e, i) => renderAssetFiche(e, i)).join("");
  const annexHtml = renderAnnex();

  const headlineMetrics = [
    { label: "Actifs à traiter en priorité", value: bluf.immediate.length, tone: bluf.immediate.length ? "crit" : "ok" },
    { label: "CVE critiques exposées", value: stats.criticalCves ?? 0, tone: (stats.criticalCves ?? 0) ? "crit" : "ok" },
    { label: "Services dangereux exposés", value: bluf.dangerousServices, tone: bluf.dangerousServices ? "high" : "ok" },
    { label: "Score d'exposition max", value: maxExposure, tone: maxExposure >= 60 ? "crit" : maxExposure >= 32 ? "high" : "ok" },
  ];
  const headlineHtml = headlineMetrics
    .map((m) => `<div class="bluf-metric bm-${m.tone}"><div class="bm-val">${m.value}</div><div class="bm-lbl">${escapeHtml(m.label)}</div></div>`)
    .join("");

  const topAction = bluf.queue[0];
  const immediateActionHtml = topAction
    ? `<div class="bluf-now">
        <span class="bluf-now-tag">⚡ Action immédiate</span>
        <span><strong>${escapeHtml(topAction.a.name)}</strong>${topAction.a.ip ? ` <span class="mono muted">${escapeHtml(topAction.a.ip)}</span>` : ""} - ${escapeHtml(topAction.actions[0].text)}</span>
      </div>`
    : "";

  const actionPlanRows = bluf.queue
    .slice(0, 15)
    .map((r, i) => {
      const drivers = [];
      if (r.exp.cve.critical) drivers.push(`<span class="sev sev-crit" title="CVE critiques">${r.exp.cve.critical}C</span>`);
      if (r.exp.cve.high) drivers.push(`<span class="sev sev-high" title="CVE élevées">${r.exp.cve.high}H</span>`);
      const dsvc = (r.exp.hits || [])
        .filter((h) => h.weight >= 16)
        .slice(0, 4)
        .map((h) => `<span class="port" title="${escapeHtml(h.label)} (poids ${h.weight})">${h.port}/${escapeHtml(h.label)}</span>`)
        .join(" ");
      const topUrg = r.actions.reduce((m, a) => (URGENCY_RANK[a.urgency] > URGENCY_RANK[m] ? a.urgency : m), "low");
      const actionsHtml = r.actions
        .filter((a) => a.urgency !== "low")
        .map((a) => `<div class="act"><span class="act-k act-${a.urgency}">${escapeHtml(a.label)}</span> ${escapeHtml(a.text)}</div>`)
        .join("");
      return `<tr>
        <td class="prio"><span class="prio-num">${i + 1}</span></td>
        <td>
          <strong>${escapeHtml(r.a.name)}</strong>
          ${r.a.ip ? `<div class="mono muted">${escapeHtml(r.a.ip)}</div>` : ""}
          <div style="margin-top:3px"><span class="badge" style="background:${assetCriticalityColor(r.a.criticality)}">${escapeHtml(r.a.criticality)}</span></div>
        </td>
        <td>
          ${drivers.join(" ") || '<span class="muted">surface réseau</span>'}
          ${dsvc ? `<div class="ports">${dsvc}</div>` : ""}
          <div class="muted">score exposition ${r.exp.score}</div>
        </td>
        <td>${actionsHtml}</td>
        <td><span class="ublob ublob-${topUrg}">${urgencyLabel(topUrg)}</span></td>
      </tr>`;
    })
    .join("");

  const blufHtml = `<section class="bluf bluf-${bluf.postureClass}" id="sec-bluf">
    <div class="bluf-head">
      <div class="bluf-posture">
        <span class="bluf-plabel">Posture de sécurité</span>
        <span class="bluf-pval">${bluf.posture}</span>
      </div>
      <p class="bluf-verdict">${escapeHtml(bluf.verdict)}</p>
    </div>
    <div class="bluf-metrics">${headlineHtml}</div>
    ${immediateActionHtml}
  </section>`;

  const actionPlanHtml = bluf.queue.length
    ? `<h2 id="sec-actions">Plan d'action priorisé (${bluf.queue.length})</h2>
  <p class="muted" style="margin:-4px 0 12px">Actifs classés par exposition décroissante. Traiter de haut en bas : la priorité 1 est le risque le plus urgent du périmètre.</p>
  <table class="actplan">
    <thead><tr><th>#</th><th>Actif</th><th>Pilotes du risque</th><th>Action recommandée</th><th>Échéance</th></tr></thead>
    <tbody>${actionPlanRows}</tbody>
  </table>`
    : "";

  const tocItems = [
    { id: "sec-bluf", label: "Synthèse décisionnelle (BLUF)" },
  ];
  if (bluf.queue.length > 0) {
    tocItems.push({ id: "sec-actions", label: `Plan d'action priorisé (${bluf.queue.length})` });
  }
  tocItems.push(
    { id: "sec-intro", label: "Introduction et méthodologie" },
    { id: "sec-summary", label: "Indicateurs clés" },
    { id: "sec-breakdown", label: "Répartition (criticité, statut, type)" },
    { id: "sec-inventory", label: `Inventaire détaillé (${assets.length})` },
    { id: "sec-fiches", label: `Fiches détaillées par actif (${assets.length})` },
    { id: "sec-annex", label: "Annexes (modèle de score, glossaire, cadre légal)" }
  );
  const tocHtml = showToc
    ? `<nav class="toc" aria-label="Sommaire">
    <div class="toc-title">Sommaire</div>
    <ol>${tocItems.map((it) => `<li><a href="#${it.id}">${escapeHtml(it.label)}</a></li>`).join("")}</ol>
  </nav>`
    : "";

  return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    color-scheme: light;
    --navy: #0B1220; --ink: #16203A; --accent: #2C7BE5; --accent-light: #6FC0FF;
    --muted: #5A6B86; --line: #DCE4F0; --panel: #F6F9FF;
    --grad-severity: linear-gradient(90deg, #3DDC84 0%, #FFD166 50%, #E63946 100%);
    --grad-proactive: linear-gradient(125deg, #0B1220 0%, #123A36 38%, #2C8C66 62%, #2C7BE5 100%);
    --display: "Space Grotesk", "Inter", system-ui, sans-serif;
  }
  * { box-sizing: border-box; }
  body { font-family: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 0; color: var(--ink); background: #fff; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .wrap { max-width: 1200px; margin: 0 auto; padding: 0 0 64px; }
  .content { padding: 0 40px; }
  .brandbar { height: 6px; background: var(--grad-severity); }
  header { background: var(--grad-proactive); color: #EAF2FF; padding: 26px 40px 22px; margin-bottom: 24px; display: flex; align-items: center; gap: 18px; }
  header .logo { width: 52px; height: 52px; flex: 0 0 auto; filter: drop-shadow(0 6px 14px rgba(0,0,0,0.45)); }
  header .eyebrow { font-size: 11px; letter-spacing: 1.8px; text-transform: uppercase; color: var(--accent-light); font-weight: 600; }
  h1 { font-family: var(--display); font-size: 27px; margin: 2px 0 5px; color: #fff; letter-spacing: 0.2px; }
  .sub { color: #C7D6EC; font-size: 12.5px; }
  .sub code { color: #EAF2FF; }
  .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
  .chip { font-size: 11px; padding: 4px 10px; border-radius: 999px; background: rgba(255,255,255,0.14); color: #EAF2FF; border: 1px solid rgba(255,255,255,0.18); }
  .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin: 24px 0; }
  .kpi { padding: 18px; border-radius: 10px; background: var(--panel); border: 1px solid var(--line); position: relative; overflow: hidden; }
  .kpi::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--grad-proactive); }
  .kpi-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
  .kpi-value { font-family: var(--display); font-size: 28px; font-weight: 700; color: var(--navy); margin-top: 4px; }
  h2 { font-family: var(--display); font-size: 18px; margin: 32px 0 12px; color: var(--navy); padding-left: 12px; border-left: 4px solid transparent; border-image: var(--grad-severity) 1; }
  .grid3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 24px; }
  .card { border: 1px solid var(--line); border-radius: 10px; padding: 16px; }
  .card h3 { margin: 0 0 10px; font-size: 14px; color: var(--navy); font-family: var(--display); }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { background: #EEF3FB; font-weight: 600; color: var(--ink); }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  a { color: var(--accent); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; color: #0B1220; font-size: 11px; font-weight: 700; }
  .pill { display: inline-block; padding: 2px 8px; margin: 1px 2px 1px 0; border-radius: 6px; background: #E8F1FF; color: #1B4B8A; border: 1px solid #BBD6FF; font-size: 11px; font-family: "JetBrains Mono", monospace; }
  .port { display: inline-block; padding: 1px 6px; margin: 1px 2px 0 0; border-radius: 5px; background: #F1F5FB; color: #5A6B86; border: 1px solid #DCE4F0; font-size: 10px; font-family: "JetBrains Mono", monospace; }
  .ports { margin-top: 4px; line-height: 1.7; }
  .sev { display: inline-block; padding: 0 5px; border-radius: 4px; font-size: 10px; font-weight: 700; color: #fff; }
  .sev-crit { background: #E63946; }
  .sev-high { background: #FB8B24; }
  .expscore { font-family: var(--display); font-weight: 700; font-size: 14px; color: var(--navy); }
  .expbar { width: 72px; height: 5px; border-radius: 3px; background: #E8EDF6; margin-top: 3px; overflow: hidden; }
  .expbar span { display: block; height: 100%; border-radius: 3px; }
  /* ── BLUF decision summary ── */
  .bluf { border-radius: 14px; padding: 22px 24px; margin: 4px 0 26px; color: #EAF2FF; position: relative; overflow: hidden; border: 1px solid rgba(255,255,255,0.12); }
  .bluf::after { content: ""; position: absolute; inset: 0 0 auto 0; height: 5px; background: var(--grad-severity); }
  .bluf-crit { background: linear-gradient(135deg, #2A0E14 0%, #5A1722 55%, #8C2230 100%); }
  .bluf-high { background: linear-gradient(135deg, #2A1606 0%, #6B3A0E 60%, #9A5414 100%); }
  .bluf-med  { background: linear-gradient(135deg, #2A2406 0%, #5E5210 60%, #897711 100%); color: #1A1404; }
  .bluf-low  { background: linear-gradient(135deg, #0B1F16 0%, #143A2A 60%, #1C6B49 100%); }
  .bluf-head { display: flex; gap: 22px; align-items: flex-start; flex-wrap: wrap; }
  .bluf-posture { flex: 0 0 auto; }
  .bluf-plabel { display: block; font-size: 10.5px; letter-spacing: 1.6px; text-transform: uppercase; opacity: 0.82; font-weight: 600; }
  .bluf-pval { font-family: var(--display); font-size: 32px; font-weight: 700; line-height: 1.05; letter-spacing: 0.4px; }
  .bluf-verdict { flex: 1 1 320px; margin: 2px 0 0; font-size: 14px; line-height: 1.5; font-weight: 500; align-self: center; }
  .bluf-metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 18px; }
  .bluf-metric { background: rgba(255,255,255,0.10); border: 1px solid rgba(255,255,255,0.16); border-radius: 9px; padding: 12px 14px; }
  .bluf-med .bluf-metric { background: rgba(0,0,0,0.08); border-color: rgba(0,0,0,0.12); }
  .bm-val { font-family: var(--display); font-size: 26px; font-weight: 700; line-height: 1; }
  .bm-lbl { font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.4px; opacity: 0.85; margin-top: 5px; }
  .bm-crit .bm-val { color: #FFB3BB; } .bluf-med .bm-crit .bm-val { color: #B81F2E; }
  .bm-high .bm-val { color: #FFD9A8; } .bluf-med .bm-high .bm-val { color: #8A5410; }
  .bm-ok .bm-val { color: #B7F5D6; } .bluf-med .bm-ok .bm-val { color: #1C6B49; }
  .bluf-now { margin-top: 16px; padding: 12px 14px; border-radius: 9px; background: rgba(0,0,0,0.22); border: 1px solid rgba(255,255,255,0.16); display: flex; gap: 12px; align-items: baseline; font-size: 13px; line-height: 1.45; }
  .bluf-med .bluf-now { background: rgba(0,0,0,0.10); }
  .bluf-now-tag { flex: 0 0 auto; font-weight: 700; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
  /* ── Prioritized action plan ── */
  table.actplan td { vertical-align: top; }
  .actplan .prio { width: 30px; text-align: center; }
  .prio-num { display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 24px; border-radius: 50%; background: var(--navy); color: #fff; font-family: var(--display); font-weight: 700; font-size: 12px; }
  .act { margin: 0 0 5px; font-size: 12px; line-height: 1.45; }
  .act:last-child { margin-bottom: 0; }
  .act-k { display: inline-block; padding: 1px 7px; border-radius: 5px; font-size: 10.5px; font-weight: 700; color: #fff; margin-right: 5px; text-transform: uppercase; letter-spacing: 0.3px; }
  .act-critical { background: #E63946; } .act-high { background: #FB8B24; } .act-medium { background: #C99A06; } .act-low { background: #5A6B86; }
  .ublob { display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; white-space: nowrap; }
  .ublob-critical { background: #FDE2E5; color: #B81F2E; border: 1px solid #F5B5BC; }
  .ublob-high { background: #FDEBD6; color: #9A5414; border: 1px solid #F3CFA0; }
  .ublob-medium { background: #FBF4D2; color: #897711; border: 1px solid #EFE39A; }
  .ublob-low { background: #E6FaF0; color: #1C6B49; border: 1px solid #B7E8CE; }
  .cvelink { font-weight: 700; text-decoration: none; }
  .cvelink:hover { text-decoration: underline; }
  .cvesec { margin: 18px 0 8px; padding: 14px 16px; border: 1px solid var(--line); border-radius: 10px; background: var(--panel); page-break-inside: avoid; }
  .cvesec h3 { margin: 0 0 10px; font-family: var(--display); font-size: 14px; color: var(--navy); }
  .cvesec table { background: #fff; }
  .cvesec td a { font-family: "JetBrains Mono", monospace; font-weight: 600; }
  .mono { font-family: "JetBrains Mono", monospace; }
  .muted { color: var(--muted); font-size: 11px; }
  .tags { color: var(--accent); font-size: 11px; margin-top: 2px; }
  footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 11px; }
  footer .brandline { display: flex; align-items: center; justify-content: center; gap: 10px; }
  footer .brandline strong { color: var(--navy); font-family: var(--display); }
  footer .accentrule { height: 3px; width: 100%; background: var(--grad-severity); border-radius: 3px; margin-bottom: 14px; opacity: 0.85; }
  .toolbar { display: flex; gap: 10px; margin: 16px 0; }
  .btn { padding: 8px 16px; border-radius: 8px; border: 1px solid var(--line); background: white; cursor: pointer; font-size: 13px; font-weight: 600; color: var(--ink); }
  .btn-primary { background: linear-gradient(140deg, #4DA8FF, #2C7BE5); color: #fff; border: 0; }
  .toc { border: 1px solid var(--line); border-radius: 10px; padding: 14px 18px; margin: 20px 0 8px; background: var(--panel); page-break-inside: avoid; }
  .toc-title { font-family: var(--display); font-size: 13px; color: var(--navy); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1.2px; }
  .toc ol { margin: 0; padding-left: 20px; font-size: 12.5px; line-height: 1.8; }
  .toc a { color: var(--accent); text-decoration: none; }
  /* ── Introduction ── */
  .intro-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin: 8px 0 4px; }
  .intro-card { border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px; background: var(--panel); }
  .intro-card h3 { margin: 0 0 8px; font-family: var(--display); font-size: 13.5px; color: var(--navy); }
  .intro-card p { margin: 0; font-size: 12.5px; line-height: 1.55; color: var(--ink); }
  .legend { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; }
  .legend-item { display: inline-flex; align-items: center; gap: 6px; font-size: 11.5px; color: var(--ink); }
  .legend-dot { width: 11px; height: 11px; border-radius: 50%; display: inline-block; }
  /* ── Per-asset fiches ── */
  .fiche { border: 1px solid var(--line); border-left: 5px solid var(--accent); border-radius: 11px; padding: 0 18px 16px; margin: 18px 0; page-break-inside: avoid; }
  .fiche-head { display: flex; align-items: center; gap: 14px; margin: 0 -18px 12px; padding: 14px 18px; border-radius: 6px 6px 0 0; border-bottom: 1px solid var(--line); }
  .fiche-prio { flex: 0 0 auto; width: 30px; height: 30px; border-radius: 50%; background: var(--navy); color: #fff; font-family: var(--display); font-weight: 700; font-size: 14px; display: inline-flex; align-items: center; justify-content: center; }
  .fiche-head-main { flex: 1 1 auto; }
  .fiche-head-main h3 { margin: 0 0 4px; font-family: var(--display); font-size: 16px; color: var(--navy); }
  .fiche-score { flex: 0 0 auto; font-family: var(--display); font-weight: 700; font-size: 30px; line-height: 1; }
  .fiche-desc { margin: 0 0 12px; font-size: 12px; color: var(--muted); }
  .fiche-meta { display: grid; grid-template-columns: max-content 1fr max-content 1fr; gap: 5px 14px; margin: 0 0 14px; font-size: 12px; align-items: baseline; }
  .fiche-meta-k { color: var(--muted); text-transform: uppercase; font-size: 10px; letter-spacing: 0.4px; }
  .fiche-meta-v { color: var(--ink); }
  .fiche h4 { font-family: var(--display); font-size: 13px; color: var(--navy); margin: 16px 0 7px; }
  table.svctab { background: #fff; }
  table.svctab td { vertical-align: top; }
  .wt { display: inline-block; min-width: 26px; text-align: center; padding: 1px 6px; border-radius: 5px; font-weight: 700; font-size: 11px; }
  .wt-crit { background: #FDE2E5; color: #B81F2E; }
  .wt-high { background: #FDEBD6; color: #9A5414; }
  .wt-med { background: #EEF3FB; color: #5A6B86; }
  .wt-low { background: #F1F5FB; color: #94a3b8; }
  ul.actlist { margin: 4px 0 0; padding-left: 18px; font-size: 12px; line-height: 1.7; }
  ul.actlist li { margin-bottom: 4px; }
  table.gloss { margin: 4px 0 16px; }
  table.gloss th { width: 190px; }
  @media print {
    body { background: white; }
    .content { padding: 0 16px; }
    header { padding: 18px 16px 16px; }
    .no-print { display: none; }
    table { font-size: 10px; }
    th, td { padding: 4px 6px; }
    tr { page-break-inside: avoid; }
  }
</style>
${primaryOverride}
</head>
<body>
<div class="wrap">
  <div class="brandbar"></div>
  <header>
    <div class="logo">${headerLogoHtml}</div>
    <div>
      <div class="eyebrow">Suite ${escapeHtml(brandName)} · Inventaire</div>
      <h1>${escapeHtml(title)}</h1>
      <div class="sub">Généré le ${escapeHtml(generatedAt)} · Job ID: <code>${escapeHtml(job.id)}</code> · ${stats.total} actif${stats.total > 1 ? "s" : ""}</div>
      ${headerText ? `<div class="sub" style="margin-top:6px;font-weight:600;color:#EAF2FF">${escapeHtml(headerText)}</div>` : ""}
      ${filterChips.length > 0 ? `<div class="chips">${filterChips.map((c) => `<span class="chip">${c}</span>`).join("")}</div>` : ""}
    </div>
  </header>

  <div class="content">
  <div class="toolbar no-print">
    <button class="btn btn-primary" onclick="window.print()">📄 Enregistrer au format PDF (Ctrl+P)</button>
    <span style="font-size:11px;color:#5A6B86;align-self:center">Dans la fenêtre d'impression, choisissez la destination « Enregistrer au format PDF ».</span>
  </div>
  <div class="no-print" style="margin:0 0 16px;padding:10px 14px;border:1px solid #F3C9A0;background:#FFF7EC;border-radius:8px;font-size:12px;color:#7A4E12;line-height:1.6">
    ⚠️ <strong>Pour un PDF valide</strong>, sélectionnez la destination <strong>« Enregistrer au format PDF »</strong> (moteur du navigateur).
    Évitez <strong>« Microsoft Print to PDF »</strong> : ce pilote produit des en-têtes d'objets non conformes que les lecteurs stricts (Adobe, aperçu Windows) refusent d'ouvrir.
  </div>

  ${blufHtml}

  ${actionPlanHtml}

  ${tocHtml}

  ${introHtml}

  <section>
    <h2 id="sec-summary">Indicateurs clés</h2>
    <div class="kpis">
      <div class="kpi"><div class="kpi-label">Total actifs</div><div class="kpi-value">${stats.total}</div></div>
      <div class="kpi"><div class="kpi-label">Criticité critique</div><div class="kpi-value" style="color:#E63946">${stats.byCriticality.critical}</div></div>
      <div class="kpi"><div class="kpi-label">Actifs en service</div><div class="kpi-value" style="color:#2C8C66">${stats.byStatus.active}</div></div>
      <div class="kpi"><div class="kpi-label">Produits détectés</div><div class="kpi-value">${stats.totalProducts}</div></div>
      <div class="kpi"><div class="kpi-label">Ports ouverts</div><div class="kpi-value">${stats.totalPorts ?? 0}</div></div>
      <div class="kpi"><div class="kpi-label">CVE critiques</div><div class="kpi-value" style="color:#E63946">${stats.criticalCves ?? 0}</div></div>
      <div class="kpi"><div class="kpi-label">CVE élevées</div><div class="kpi-value" style="color:#FB8B24">${stats.highCves ?? 0}</div></div>
      <div class="kpi"><div class="kpi-label">CVE exposées (total)</div><div class="kpi-value">${stats.totalVulns}</div></div>
    </div>
  </section>

  <h2 id="sec-breakdown">Répartition (criticité, statut, type)</h2>
  <div class="grid3">
    <div class="card">
      <h3>Par criticité</h3>
      <table><thead><tr><th>Criticité</th><th class="num">Count</th></tr></thead><tbody>${critRows || '<tr><td colspan="2" class="muted">-</td></tr>'}</tbody></table>
    </div>
    <div class="card">
      <h3>Par statut</h3>
      <table><thead><tr><th>Statut</th><th class="num">Count</th></tr></thead><tbody>${statusRows || '<tr><td colspan="2" class="muted">-</td></tr>'}</tbody></table>
    </div>
    <div class="card">
      <h3>Par type</h3>
      <table><thead><tr><th>Type</th><th class="num">Count</th></tr></thead><tbody>${typeRows || '<tr><td colspan="2" class="muted">-</td></tr>'}</tbody></table>
    </div>
  </div>

  <h2 id="sec-inventory">Inventaire détaillé (${assets.length})</h2>
  <table>
    <thead>
      <tr>
        <th>Nom</th>
        <th>Type</th>
        <th>IP / hostname</th>
        <th>Criticité</th>
        <th>Statut</th>
        <th>Produits / services détectés</th>
        <th>Exposition</th>
        <th class="num">CVE</th>
      </tr>
    </thead>
    <tbody>${rowsHtml || '<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:24px">Aucun actif ne correspond aux filtres.</td></tr>'}</tbody>
  </table>

  <h2 id="sec-fiches">Fiches détaillées par actif (${assets.length})</h2>
  <p class="muted" style="margin:-4px 0 14px">Une fiche par actif, classées par exposition décroissante. Chaque fiche documente les services ouverts, les remédiations prioritaires, le plan d'action et les CVE corrélées (cliquables vers la base NVD).</p>
  ${fichesHtml || '<p class="muted">Aucun actif à détailler.</p>'}

  ${annexHtml}

  <footer>
    <div class="accentrule"></div>
    <div class="brandline">${footerLogoHtml}<span><strong>${escapeHtml(brandName)}</strong> · Suite ${escapeHtml(brandName)} · ${escapeHtml(generatedAt)} · ${stats.total} actifs · ${stats.totalProducts} produits</span></div>
    ${footerText ? `<div style="text-align:center;margin-top:8px;color:var(--ink)">${escapeHtml(footerText)}</div>` : ""}
  </footer>
  </div>
</div>
</body>
</html>`;
}

async function generateAssetReport(job, filter, filepath) {
  const where = {};
  if (filter.search) {
    where.OR = [
      { name: { contains: filter.search, mode: "insensitive" } },
      { hostname: { contains: filter.search, mode: "insensitive" } },
      { ip: { contains: filter.search, mode: "insensitive" } },
      { description: { contains: filter.search, mode: "insensitive" } },
    ];
  }
  if (filter.criticality) where.criticality = filter.criticality;
  if (filter.assetStatus) where.status = filter.assetStatus;

  const take = Math.min(REPORT_HARD_CAP, filter.limit && Number(filter.limit) > 0 ? Number(filter.limit) : 10_000);
  log(`Report ${job.id}: fetching assets (take=${take})...`);
  const assets = await prisma.asset.findMany({
    where,
    orderBy: [{ updatedAt: "desc" }],
    take,
    include: {
      _count: { select: { vulnerabilities: true, productLinks: true } },
      productLinks: {
        take: 40,
        orderBy: { createdAt: "asc" },
        include: {
          product: {
            select: {
              vendor: true,
              name: true,
              version: true,
              cpe: true,
              // Matched CVEs (ProductCVE) drive the real exposure counts; the
              // legacy Vulnerability relation is almost always empty. We also
              // pull the CVSS score so each CVE is individually consultable in
              // the per-asset detail section.
              cveLinks: {
                select: {
                  patchStatus: true,
                  cve: { select: { cveId: true, severity: true, cvssV3Score: true } },
                },
              },
            },
          },
        },
      },
    },
  });
  // Attach a computed exposure (open-service surface + matched-CVE severity) to
  // each asset so the aggregator and all three renderers share one source.
  for (const a of assets) a._exposure = assetExposure(a);
  const stats = aggregateAssetStats(assets);
  log(`Report ${job.id}: ${assets.length} assets, rendering ${job.format}...`);

  if (job.format === ReportFormat.JSON) {
    const payload = {
      reportId: job.id,
      scope: "assets",
      generatedAt: new Date().toISOString(),
      filter,
      stats,
      count: assets.length,
      assets: assets.map((a) => ({
        id: a.id,
        name: a.name,
        type: a.type,
        ip: a.ip,
        hostname: a.hostname,
        criticality: a.criticality,
        status: a.status,
        tags: a.tags,
        description: a.description,
        vulnerabilities: (a._exposure || assetExposure(a)).cve.total,
        exposure: {
          score: (a._exposure || assetExposure(a)).score,
          level: (a._exposure || assetExposure(a)).level,
          cve: (a._exposure || assetExposure(a)).cve,
          dangerousServices: (a._exposure || assetExposure(a)).hits,
        },
        // Every matched CVE, individually consultable (each carries its NVD URL).
        cves: assetCveList(a).map((c) => ({
          cveId: c.cveId,
          severity: c.severity,
          cvssV3Score: c.score,
          product: c.product,
          patchStatus: c.patchStatus,
          url: `https://nvd.nist.gov/vuln/detail/${c.cveId}`,
        })),
        products: (a.productLinks || []).map((pl) => ({
          vendor: pl.product?.vendor,
          name: pl.product?.name,
          version: pl.product?.version,
          cpe: pl.product?.cpe,
          cves: (pl.product?.cveLinks || []).map((cl) => cl.cve?.cveId).filter(Boolean),
        })),
        services: Array.isArray(a.services) ? a.services : [],
      })),
    };
    fs.writeFileSync(filepath, JSON.stringify(payload, null, 2), "utf8");
  } else if (job.format === ReportFormat.CSV) {
    fs.writeFileSync(filepath, renderAssetsCsv(assets), "utf8");
  } else {
    const branding = await loadBranding();
    fs.writeFileSync(filepath, renderAssetsHtmlReport({ job, filter, assets, stats, branding }), "utf8");
  }

  return { filepath, count: assets.length, stats };
}

async function generateReport(job) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });

  const filter = (job.filter && typeof job.filter === "object") ? job.filter : {};
  const ext = job.format === ReportFormat.PDF ? "html" : job.format.toLowerCase();
  const filepath = path.join(REPORTS_DIR, `report-${job.id}.${ext}`);

  // Asset-inventory scope: report on scanned hosts + discovered products
  // instead of the CVE database.
  if (filter.scope === "assets") {
    return generateAssetReport(job, filter, filepath);
  }

  const where = buildCveWhere(filter);
  const take = Math.min(REPORT_HARD_CAP, filter.limit && Number(filter.limit) > 0 ? Number(filter.limit) : 10_000);

  log(`Report ${job.id}: fetching CVEs (take=${take})...`);
  const cves = await prisma.cVE.findMany({
    where,
    orderBy: [{ severity: "desc" }, { publishedAt: "desc" }],
    take,
  });
  log(`Report ${job.id}: ${cves.length} CVEs matched, rendering ${job.format}...`);

  const stats = aggregateStats(cves);

  if (job.format === ReportFormat.JSON) {
    const payload = {
      reportId: job.id,
      generatedAt: new Date().toISOString(),
      filter,
      stats,
      count: cves.length,
      cves,
    };
    fs.writeFileSync(filepath, JSON.stringify(payload, null, 2), "utf8");
  } else if (job.format === ReportFormat.CSV) {
    fs.writeFileSync(filepath, renderCsv(cves), "utf8");
  } else {
    // ReportFormat.PDF - we emit a print-ready HTML.
    // Users click "Enregistrer en PDF" from the browser; no binary PDF needed.
    const branding = await loadBranding();
    fs.writeFileSync(filepath, renderHtmlReport({ job, filter, cves, stats, branding }), "utf8");
  }

  return { filepath, count: cves.length, stats };
}

async function drainQueuedReportJobs() {
  const jobs = await prisma.reportJob.findMany({
    where: { status: ReportStatus.QUEUED },
    orderBy: { createdAt: "asc" },
    take: 5,
  });

  for (const job of jobs) {
    const claimed = await prisma.reportJob.updateMany({
      where: { id: job.id, status: ReportStatus.QUEUED },
      data: { status: ReportStatus.RUNNING },
    });
    if (claimed.count === 0) continue;

    try {
      log(`Generating ReportJob ${job.id} format=${job.format}`);
      const { filepath, count } = await generateReport(job);
      await prisma.reportJob.update({
        where: { id: job.id },
        data: {
          status: ReportStatus.COMPLETED,
          completedAt: new Date(),
          storagePath: filepath,
        },
      });
      log(`ReportJob ${job.id} completed: ${count} CVEs → ${filepath}`);

      if (job.webhookUrl) {
        fetch(job.webhookUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ reportId: job.id, status: "COMPLETED", count }),
        }).catch((e) => warn(`Webhook failed for report ${job.id}:`, e?.message));
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      err(`ReportJob ${job.id} failed:`, msg);
      await prisma.reportJob.update({
        where: { id: job.id },
        data: {
          status: ReportStatus.FAILED,
          completedAt: new Date(),
          errorMessage: msg,
        },
      });
    }
  }
}

// ─── Scheduling ──────────────────────────────────────────────────────────────

/**
 * Returns true when the operator has paused scheduled syncs via the HTTP
 * endpoint (which drops a marker file on the shared volume). Manually
 * enqueued SyncJobs (via the trigger endpoint) still run - pause only
 * affects the *schedule*.
 */
function isSyncPaused() {
  try {
    return fs.existsSync(PAUSE_MARKER);
  } catch {
    return false;
  }
}

async function maybeRunScheduledSyncs() {
  if (!NVD_ENABLED) return;
  if (isSyncPaused()) return; // operator-paused - silently skip schedule
  const now = Date.now();

  if (now - lastRun.fullSync >= NVD_FULL_SYNC_INTERVAL_MS) {
    lastRun.fullSync = now;
    lastRun.deltaSync = now; // a full sync covers the delta window
    log(`Triggering scheduled FULL NVD sync (interval=${NVD_FULL_SYNC_INTERVAL_MS}ms)`);
    runNvdSync({}).catch((e) => err("Scheduled full sync failed:", e?.message));
    return;
  }

  if (now - lastRun.deltaSync >= NVD_DELTA_INTERVAL_MS) {
    lastRun.deltaSync = now;
    const since = new Date(Date.now() - NVD_DELTA_LOOKBACK_HOURS * 60 * 60 * 1000);
    log(`Triggering scheduled DELTA NVD sync since ${since.toISOString()}`);
    runNvdSync({ lastModStartDate: since }).catch((e) => err("Scheduled delta sync failed:", e?.message));
  }
}

async function tick() {
  try {
    await maybeRunScheduledSyncs();
    await drainQueuedSyncJobs();
    await drainQueuedReportJobs();
  } catch (e) {
    err("tick failed:", e?.message || e);
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  log(
    `Worker started: poll=${POLL_INTERVAL_MS}ms ` +
      `nvd_full=${NVD_FULL_SYNC_INTERVAL_MS}ms ` +
      `nvd_delta=${NVD_DELTA_INTERVAL_MS}ms ` +
      `auto_sync=${NVD_ENABLED}`
  );

  // Initial sync at boot - delta if we have prior runs, full if first boot.
  // Honor the pause marker so a restart while paused doesn't kick off a sync.
  if (NVD_ENABLED && !isSyncPaused()) {
    const lastJob = await prisma.syncJob.findFirst({
      where: { source: SyncSource.NVD, status: SyncJobStatus.COMPLETED },
      orderBy: { completedAt: "desc" },
      select: { completedAt: true },
    });
    if (lastJob?.completedAt) {
      log(`Found prior NVD sync at ${lastJob.completedAt.toISOString()} → delta sync at boot`);
      lastRun.deltaSync = Date.now();
      lastRun.fullSync = lastJob.completedAt.getTime();
      runNvdSync({ lastModStartDate: lastJob.completedAt }).catch((e) =>
        err("Boot delta sync failed:", e?.message)
      );
    } else {
      log("No prior NVD sync found → full sync at boot");
      lastRun.fullSync = Date.now();
      lastRun.deltaSync = Date.now();
      // Limit first boot to a reasonable batch to avoid hammering NVD
      const bootCap = num(process.env.NVD_BOOT_MAX_RECORDS, 2000);
      runNvdSync({ maxRecords: bootCap }).catch((e) => err("Boot full sync failed:", e?.message));
    }
  } else if (isSyncPaused()) {
    log("Auto-sync is currently PAUSED (marker file present). Manual triggers will still run.");
  }

  setInterval(tick, POLL_INTERVAL_MS);
}

// Only auto-start the worker loop when run directly (`node worker.js`); when the
// module is required (tests / render harness) the renderers are exported instead.
if (require.main === module) {
  main().catch((e) => {
    err("Fatal error:", e);
    process.exit(1);
  });
}

module.exports = {
  renderAssetsHtmlReport,
  renderHtmlReport,
  renderAssetsCsv,
  renderCsv,
  computeAssetBluf,
  assetRecommendedActions,
  aggregateAssetStats,
};

// ─── Graceful shutdown ───────────────────────────────────────────────────────

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log(`Received ${signal}, shutting down...`);
  await prisma.$disconnect().catch(() => undefined);
  process.exit(0);
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
