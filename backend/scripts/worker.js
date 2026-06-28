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
 * No build step required — pure JS reading Prisma client.
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

// Severity ramp — CVE Tracker charte graphique (low green → critical red).
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

// Inline gauge logo (severity dial) — the CVE Tracker brand mark. `stroke`
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

// Branding defaults — used when AppSettings is missing/empty or the columns
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

  // Full table — keep all entries; modern browsers handle 10k+ rows
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

  // Table of contents (Sommaire) — anchors to the section ids below.
  const tocItems = [
    { id: "sec-summary", label: "Synthèse" },
    { id: "sec-severity", label: "Distribution par sévérité" },
    { id: "sec-statussource", label: "Répartition par statut & source" },
    ...(topCves.length > 0 ? [{ id: "sec-top", label: "Top 20 — CVE les plus sévères" }] : []),
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
  /* CVE Tracker — charte graphique : rampe de sévérité + accent bleu + navy.
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
  /* Direction 1 — rampe de sévérité : bandeau d'en-tête de page. */
  .brandbar { height: 6px; background: var(--grad-severity); }
  /* Direction 3 — sécurité proactive : bandeau d'aperçu. */
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
    <button class="btn btn-primary" onclick="window.print()">📄 Imprimer / Enregistrer en PDF</button>
    <span style="font-size:11px;color:#5A6B86;align-self:center">Astuce: Ctrl+P → "Enregistrer en PDF"</span>
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
      ? `<h2 id="sec-top">Top 20 — CVE les plus sévères</h2>
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
const { assetExposure } = require("./exposure.js");

const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };

// Deduped, severity-sorted list of every CVE matched to an asset, with the
// product it came from — so each CVE can be listed and linked individually.
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
          ${!a.ip && !a.hostname ? "—" : ""}
        </td>
        <td><span class="badge" style="background:${assetCriticalityColor(a.criticality)}">${escapeHtml(a.criticality)}</span></td>
        <td>${escapeHtml(a.status)}</td>
        <td>
          ${prods || ""}
          ${ports ? `<div class="ports">${ports}</div>` : ""}
          ${!prods && !ports ? '<span class="muted">—</span>' : ""}
        </td>
        <td>
          <div class="expscore">${exp.score}</div>
          <div class="expbar"><span style="width:${expPct}%;background:${assetCriticalityColor(exp.level)}"></span></div>
        </td>
        <td class="num">${vulnCell}</td>
      </tr>`;
    })
    .join("");

  // Per-asset CVE detail — every matched CVE is listed and linked to NVD so it
  // can be consulted individually. Assets are ordered by exposure score.
  const assetsWithCves = assets
    .map((a) => ({ a, list: assetCveList(a), exp: a._exposure || assetExposure(a) }))
    .filter((x) => x.list.length > 0)
    .sort((x, y) => y.exp.score - x.exp.score);

  const cveSectionsHtml = assetsWithCves
    .map(({ a, list, exp }) => {
      const cveRows = list
        .map((c) => {
          const sevKey = String(c.severity).toLowerCase();
          return `<tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(c.cveId)}" target="_blank" rel="noopener">${escapeHtml(c.cveId)}</a></td>
            <td><span class="badge" style="background:${assetCriticalityColor(sevKey)}">${escapeHtml(c.severity)}</span></td>
            <td class="num">${c.score != null ? Number(c.score).toFixed(1) : "—"}</td>
            <td>${escapeHtml(c.product || "—")}</td>
            <td>${escapeHtml(String(c.patchStatus).toLowerCase())}</td>
          </tr>`;
        })
        .join("");
      return `<section id="cve-${escapeHtml(a.id)}" class="cvesec">
        <h3>${escapeHtml(a.name)} <span class="muted">${escapeHtml(a.ip || a.hostname || "")}</span>
          <span class="badge" style="background:${assetCriticalityColor(a.criticality)}">${escapeHtml(a.criticality)}</span>
          <span class="muted">· exposition ${exp.score} · ${list.length} CVE</span>
        </h3>
        <table>
          <thead><tr><th>CVE</th><th>Sévérité</th><th class="num">CVSS</th><th>Produit affecté</th><th>Correctif</th></tr></thead>
          <tbody>${cveRows}</tbody>
        </table>
      </section>`;
    })
    .join("");

  const tocItems = [
    { id: "sec-summary", label: "Synthèse" },
    { id: "sec-breakdown", label: "Répartition (criticité, statut, type)" },
    { id: "sec-inventory", label: `Inventaire détaillé (${assets.length})` },
  ];
  if (assetsWithCves.length > 0) {
    tocItems.push({ id: "sec-cves", label: `Vulnérabilités par actif (${assetsWithCves.length})` });
  }
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
    <button class="btn btn-primary" onclick="window.print()">📄 Imprimer / Enregistrer en PDF</button>
    <span style="font-size:11px;color:#5A6B86;align-self:center">Astuce: Ctrl+P → "Enregistrer en PDF"</span>
  </div>

  ${tocHtml}

  <section>
    <h2 id="sec-summary">Synthèse</h2>
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

  ${
    cveSectionsHtml
      ? `<h2 id="sec-cves">Vulnérabilités détectées par actif</h2>
  <p class="muted" style="margin:-4px 0 14px">Chaque CVE est cliquable et ouvre sa fiche détaillée sur la base NVD (nvd.nist.gov).</p>
  ${cveSectionsHtml}`
      : ""
  }

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
    // ReportFormat.PDF — we emit a print-ready HTML.
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
 * enqueued SyncJobs (via the trigger endpoint) still run — pause only
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
  if (isSyncPaused()) return; // operator-paused — silently skip schedule
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

  // Initial sync at boot — delta if we have prior runs, full if first boot.
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

main().catch((e) => {
  err("Fatal error:", e);
  process.exit(1);
});

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
