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

function severityColor(sev) {
  return (
    {
      CRITICAL: "#dc2626",
      HIGH: "#ea580c",
      MEDIUM: "#f59e0b",
      LOW: "#16a34a",
      NONE: "#6b7280",
    }[sev] || "#6b7280"
  );
}

function renderHtmlReport({ job, filter, cves, stats }) {
  const generatedAt = new Date().toISOString();
  const title = filter.title || "Rapport CVE complet";
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

  return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 0; color: #111; background: #fff; }
  .wrap { max-width: 1200px; margin: 0 auto; padding: 32px 40px 64px; }
  header { border-bottom: 3px solid #0ea5e9; padding-bottom: 16px; margin-bottom: 24px; }
  h1 { font-size: 28px; margin: 0 0 4px; color: #0c4a6e; }
  .sub { color: #475569; font-size: 13px; }
  .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
  .chip { font-size: 11px; padding: 4px 10px; border-radius: 999px; background: #e2e8f0; color: #334155; }
  .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin: 24px 0; }
  .kpi { padding: 18px; border-radius: 10px; background: #f8fafc; border: 1px solid #e2e8f0; }
  .kpi-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; }
  .kpi-value { font-size: 28px; font-weight: 700; color: #0f172a; margin-top: 4px; }
  .kpi-sub { font-size: 11px; color: #64748b; margin-top: 4px; }
  h2 { font-size: 18px; margin: 32px 0 12px; color: #0c4a6e; border-left: 4px solid #0ea5e9; padding-left: 10px; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
  .card { border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  th { background: #f1f5f9; font-weight: 600; color: #334155; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  td.desc { max-width: 380px; color: #334155; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; color: white; font-size: 11px; font-weight: 600; }
  .topcve { border-left: 4px solid #cbd5e1; padding: 10px 14px; margin-bottom: 10px; background: #f8fafc; border-radius: 4px; }
  .topcve-h { display: flex; align-items: center; gap: 12px; margin-bottom: 4px; }
  .topcve p { margin: 4px 0 0; color: #334155; font-size: 12px; line-height: 1.5; }
  .cvss { font-size: 11px; color: #64748b; margin-left: auto; }
  footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid #e2e8f0; color: #64748b; font-size: 11px; text-align: center; }
  .print-only { display: none; }
  @media print {
    body { background: white; }
    .wrap { padding: 16px; max-width: none; }
    .no-print { display: none; }
    .print-only { display: block; }
    table { font-size: 10px; }
    th, td { padding: 4px 6px; }
    h2 { page-break-before: auto; }
    tr { page-break-inside: avoid; }
    .topcve { page-break-inside: avoid; }
  }
  .toolbar { display: flex; gap: 10px; margin-bottom: 16px; }
  .btn { padding: 8px 16px; border-radius: 6px; border: 1px solid #cbd5e1; background: white; cursor: pointer; font-size: 13px; }
  .btn:hover { background: #f1f5f9; }
  .btn-primary { background: #0ea5e9; color: white; border-color: #0ea5e9; }
  .btn-primary:hover { background: #0284c7; }
</style>
</head>
<body>
<div class="wrap">
  <div class="toolbar no-print">
    <button class="btn btn-primary" onclick="window.print()">📄 Imprimer / Enregistrer en PDF</button>
    <span style="font-size:11px;color:#64748b;align-self:center">Astuce: Ctrl+P → "Enregistrer en PDF"</span>
  </div>

  <header>
    <h1>${escapeHtml(title)}</h1>
    <div class="sub">Généré le ${escapeHtml(generatedAt)} · Job ID: <code>${escapeHtml(job.id)}</code> · ${stats.total} CVE${stats.total > 1 ? "s" : ""}</div>
    ${filterChips.length > 0 ? `<div class="chips">${filterChips.map((c) => `<span class="chip">${c}</span>`).join("")}</div>` : ""}
  </header>

  <section>
    <div class="kpis">
      <div class="kpi"><div class="kpi-label">Total CVE</div><div class="kpi-value">${stats.total}</div></div>
      <div class="kpi"><div class="kpi-label">Critiques</div><div class="kpi-value" style="color:#dc2626">${stats.bySeverity.CRITICAL}</div></div>
      <div class="kpi"><div class="kpi-label">Élevées</div><div class="kpi-value" style="color:#ea580c">${stats.bySeverity.HIGH}</div></div>
      <div class="kpi"><div class="kpi-label">Moyennes</div><div class="kpi-value" style="color:#f59e0b">${stats.bySeverity.MEDIUM}</div></div>
      <div class="kpi"><div class="kpi-label">CVSS moyen</div><div class="kpi-value">${stats.avgCvss}</div></div>
      <div class="kpi"><div class="kpi-label">Période couverte</div><div class="kpi-value" style="font-size:14px">${stats.oldestPublished ? stats.oldestPublished.slice(0, 10) : "-"}<div class="kpi-sub">au ${stats.newestPublished ? stats.newestPublished.slice(0, 10) : "-"}</div></div></div>
    </div>
  </section>

  <h2>Distribution par sévérité</h2>
  <div class="card">
    <svg viewBox="0 0 ${chartWidth} ${chartHeight}" width="100%" height="${chartHeight}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Distribution par sévérité">
      ${bars}
    </svg>
  </div>

  <div class="grid2" style="margin-top:24px">
    <div class="card">
      <h3 style="margin:0 0 10px;font-size:14px;color:#0c4a6e">Par statut</h3>
      <table><thead><tr><th>Statut</th><th class="num">Count</th></tr></thead><tbody>${statusRowsHtml || '<tr><td colspan="2" style="color:#94a3b8">-</td></tr>'}</tbody></table>
    </div>
    <div class="card">
      <h3 style="margin:0 0 10px;font-size:14px;color:#0c4a6e">Par source</h3>
      <table><thead><tr><th>Source</th><th class="num">Count</th></tr></thead><tbody>${sourceRowsHtml || '<tr><td colspan="2" style="color:#94a3b8">-</td></tr>'}</tbody></table>
    </div>
  </div>

  ${
    topCves.length > 0
      ? `<h2>Top 20 — CVE les plus sévères</h2>
  <div>${topCvesHtml}</div>`
      : ""
  }

  <h2>Liste complète (${cves.length})</h2>
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
    CVE Tracker · ${escapeHtml(generatedAt)} · ${stats.total} entrées · données source: NVD
  </footer>
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

async function generateReport(job) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });

  const filter = (job.filter && typeof job.filter === "object") ? job.filter : {};
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
  const ext = job.format === ReportFormat.PDF ? "html" : job.format.toLowerCase();
  const filename = `report-${job.id}.${ext}`;
  const filepath = path.join(REPORTS_DIR, filename);

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
    fs.writeFileSync(filepath, renderHtmlReport({ job, filter, cves, stats }), "utf8");
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
