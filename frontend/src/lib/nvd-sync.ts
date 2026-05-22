import { CVEStatus, CveSource, Prisma, SyncJobStatus, SyncSource } from "@prisma/client";
import { db } from "@/lib/db";
import { calculateSeverityFromCvss } from "@/lib/v2/severity";

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const DEFAULT_PAGE_SIZE = 200;
const NVD_DELAY_NO_KEY_MS = 6_500;
const NVD_DELAY_WITH_KEY_MS = 600;
const MAX_RETRIES = 3;

export interface NvdCveDescription {
  lang: string;
  value: string;
}

export interface NvdCvssData {
  baseScore?: number;
  baseSeverity?: string;
  vectorString?: string;
}

export interface NvdCveEntry {
  cve: {
    id: string;
    descriptions?: NvdCveDescription[];
    metrics?: {
      cvssMetricV31?: Array<{ cvssData: NvdCvssData }>;
      cvssMetricV30?: Array<{ cvssData: NvdCvssData }>;
      cvssMetricV40?: Array<{ cvssData: NvdCvssData }>;
    };
    references?: Array<{ url: string }>;
    published?: string;
    lastModified?: string;
    vulnStatus?: string;
  };
}

export interface NvdApiResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: NvdCveEntry[];
}

export interface NvdFetchOptions {
  startIndex?: number;
  resultsPerPage?: number;
  lastModStartDate?: Date;
  lastModEndDate?: Date;
  pubStartDate?: Date;
  pubEndDate?: Date;
  apiKey?: string;
  signal?: AbortSignal;
}

export interface SyncResult {
  newCount: number;
  updatedCount: number;
  errorCount: number;
  processedCount: number;
  logs: string[];
}

export interface SyncRunOptions {
  /** Maximum CVEs to process (across pages). 0 = unlimited. */
  maxRecords?: number;
  /** Only fetch CVEs modified after this date (delta sync). */
  lastModStartDate?: Date;
  /** Page size — NVD max is 2000. */
  pageSize?: number;
  /** NVD API key for higher rate limits. */
  apiKey?: string;
  /** Per-page callback for logging/progress. */
  onPage?: (page: number, totalResults: number, processed: number) => void;
  /** Abort signal. */
  signal?: AbortSignal;
}

function getNvdApiKey(): string | undefined {
  return process.env.NVD_API_KEY || undefined;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(t);
      reject(new Error("aborted"));
    });
  });
}

/**
 * Fetch one page of CVEs from NVD with retry/backoff on 429/5xx.
 */
export async function fetchNvdPage(options: NvdFetchOptions = {}): Promise<NvdApiResponse> {
  const url = new URL(NVD_API_BASE);
  url.searchParams.set("resultsPerPage", String(options.resultsPerPage ?? DEFAULT_PAGE_SIZE));
  url.searchParams.set("startIndex", String(options.startIndex ?? 0));
  if (options.lastModStartDate) {
    url.searchParams.set("lastModStartDate", options.lastModStartDate.toISOString());
  }
  if (options.lastModEndDate) {
    url.searchParams.set("lastModEndDate", options.lastModEndDate.toISOString());
  }
  if (options.pubStartDate) {
    url.searchParams.set("pubStartDate", options.pubStartDate.toISOString());
  }
  if (options.pubEndDate) {
    url.searchParams.set("pubEndDate", options.pubEndDate.toISOString());
  }

  const headers: Record<string, string> = {
    "User-Agent": "CVE-Tracker/2.0 (+https://github.com/cve-tracker)",
  };
  const apiKey = options.apiKey ?? getNvdApiKey();
  if (apiKey) headers["apiKey"] = apiKey;

  let lastError: unknown;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    if (options.signal?.aborted) throw new Error("aborted");
    try {
      const response = await fetch(url.toString(), {
        headers,
        cache: "no-store",
        signal: options.signal,
      });

      if (response.status === 429 || response.status >= 500) {
        const backoff = Math.min(30_000, 1_000 * 2 ** attempt);
        await sleep(backoff, options.signal);
        continue;
      }

      if (!response.ok) {
        throw new Error(`NVD API error ${response.status}: ${response.statusText}`);
      }

      return (await response.json()) as NvdApiResponse;
    } catch (error) {
      lastError = error;
      if (options.signal?.aborted) throw error;
      if (attempt < MAX_RETRIES) {
        await sleep(Math.min(10_000, 1_000 * attempt), options.signal);
      }
    }
  }

  throw lastError instanceof Error ? lastError : new Error("NVD fetch failed");
}

/**
 * Upsert a single NVD CVE entry. Returns 'created' | 'updated' | 'error'.
 */
export async function upsertNvdCve(entry: NvdCveEntry): Promise<"created" | "updated"> {
  const cve = entry.cve;
  const cveId = cve.id;

  const description =
    cve.descriptions?.find((d) => d.lang === "en")?.value ??
    cve.descriptions?.[0]?.value ??
    "No description available";

  const v31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
  const v30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
  const v40 = cve.metrics?.cvssMetricV40?.[0]?.cvssData;

  const cvssV3Data = v31 ?? v30;
  const cvssV3Score = cvssV3Data?.baseScore ?? null;
  const cvssV3Vector = cvssV3Data?.vectorString ?? null;
  const cvssV4Score = v40?.baseScore ?? null;

  const severity = calculateSeverityFromCvss(cvssV3Score, cvssV4Score);

  const publishedAt = cve.published ? new Date(cve.published) : null;
  const modifiedAt = cve.lastModified ? new Date(cve.lastModified) : null;
  const references = cve.references?.map((ref) => ref.url) ?? [];

  const existing = await db.cVE.findUnique({
    where: { cveId },
    select: { id: true, status: true },
  });

  const baseData = {
    title: cveId,
    description,
    publishedAt,
    modifiedAt,
    cvssV3Score,
    cvssV3Vector,
    cvssV4Score,
    severity,
    source: CveSource.NVD,
    rawData: entry as unknown as Prisma.InputJsonValue,
    references: JSON.stringify(references),
    vulnStatus: cve.vulnStatus ?? null,
    cvssScore: cvssV3Score,
    cvssVector: cvssV3Vector,
    publishedDate: publishedAt,
    lastModifiedDate: modifiedAt,
  };

  if (existing) {
    // Don't downgrade status from a workflow state back to NEW/ANALYZING.
    const preserveStatus = existing.status && existing.status !== CVEStatus.NEW;
    await db.cVE.update({
      where: { cveId },
      data: {
        ...baseData,
        ...(preserveStatus ? {} : { status: CVEStatus.ANALYZING }),
        version: { increment: 1 },
      },
    });
    return "updated";
  }

  await db.cVE.create({
    data: {
      cveId,
      ...baseData,
      status: CVEStatus.NEW,
    },
  });
  return "created";
}

/**
 * Process a list of pre-fetched NVD entries and upsert them sequentially.
 * Used by the v2 /sync/nvd HTTP endpoint when caller provides the payload.
 */
export async function processNvdEntries(entries: NvdCveEntry[]): Promise<SyncResult> {
  const logs: string[] = [];
  let newCount = 0;
  let updatedCount = 0;
  let errorCount = 0;

  for (const entry of entries) {
    try {
      const result = await upsertNvdCve(entry);
      if (result === "created") {
        newCount++;
        logs.push(`CREATED ${entry.cve.id}`);
      } else {
        updatedCount++;
        logs.push(`UPDATED ${entry.cve.id}`);
      }
    } catch (error) {
      errorCount++;
      const msg = error instanceof Error ? error.message : "unknown";
      logs.push(`ERROR ${entry.cve.id}: ${msg}`);
    }
  }

  return { newCount, updatedCount, errorCount, processedCount: entries.length, logs };
}

/**
 * Full sync run: paginate NVD, upsert each CVE, persist a SyncJob, return result.
 * If `lastModStartDate` provided, performs a delta sync.
 */
export async function runNvdSync(options: SyncRunOptions = {}): Promise<SyncResult & { syncJobId: string }> {
  const apiKey = options.apiKey ?? getNvdApiKey();
  const perPage = Math.min(2000, options.pageSize ?? DEFAULT_PAGE_SIZE);
  const maxRecords = options.maxRecords ?? 0;
  const rateLimitDelay = apiKey ? NVD_DELAY_WITH_KEY_MS : NVD_DELAY_NO_KEY_MS;

  const syncJob = await db.syncJob.create({
    data: {
      source: SyncSource.NVD,
      status: SyncJobStatus.RUNNING,
      startedAt: new Date(),
      logs: [],
    },
  });

  const allLogs: string[] = [];
  let totalNew = 0;
  let totalUpdated = 0;
  let totalErrors = 0;
  let processed = 0;
  let startIndex = 0;
  let page = 0;
  let totalResults = 0;

  try {
    while (true) {
      if (options.signal?.aborted) throw new Error("aborted");

      const pageData = await fetchNvdPage({
        startIndex,
        resultsPerPage: perPage,
        lastModStartDate: options.lastModStartDate,
        apiKey,
        signal: options.signal,
      });

      totalResults = pageData.totalResults;
      page++;
      const entries = pageData.vulnerabilities ?? [];

      if (entries.length === 0) break;

      const result = await processNvdEntries(entries);
      totalNew += result.newCount;
      totalUpdated += result.updatedCount;
      totalErrors += result.errorCount;
      processed += result.processedCount;
      // Keep logs bounded — store only summary + last errors
      if (result.errorCount > 0) {
        allLogs.push(...result.logs.filter((l) => l.startsWith("ERROR")));
      }
      allLogs.push(
        `page=${page} startIndex=${startIndex} fetched=${entries.length} new=${result.newCount} updated=${result.updatedCount} errors=${result.errorCount}`
      );

      options.onPage?.(page, totalResults, processed);

      startIndex += entries.length;
      if (startIndex >= totalResults) break;
      if (maxRecords > 0 && processed >= maxRecords) break;

      // Respect NVD rate limits
      await sleep(rateLimitDelay, options.signal);
    }

    const completed = await db.syncJob.update({
      where: { id: syncJob.id },
      data: {
        status: totalErrors > 0 && processed === 0 ? SyncJobStatus.FAILED : SyncJobStatus.COMPLETED,
        completedAt: new Date(),
        newCount: totalNew,
        updatedCount: totalUpdated,
        errorCount: totalErrors,
        logs: allLogs.slice(-500) as Prisma.InputJsonValue,
      },
    });

    return {
      syncJobId: completed.id,
      newCount: totalNew,
      updatedCount: totalUpdated,
      errorCount: totalErrors,
      processedCount: processed,
      logs: allLogs,
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : "unknown";
    allLogs.push(`FATAL: ${msg}`);
    await db.syncJob.update({
      where: { id: syncJob.id },
      data: {
        status: SyncJobStatus.FAILED,
        completedAt: new Date(),
        newCount: totalNew,
        updatedCount: totalUpdated,
        errorCount: totalErrors + 1,
        logs: allLogs.slice(-500) as Prisma.InputJsonValue,
      },
    });
    throw error;
  }
}

/**
 * Returns the date of the most recent CVE update we have stored.
 * Used to compute the lastModStartDate for delta syncs.
 */
export async function getLastSyncWatermark(): Promise<Date | null> {
  const lastJob = await db.syncJob.findFirst({
    where: { source: SyncSource.NVD, status: SyncJobStatus.COMPLETED },
    orderBy: { completedAt: "desc" },
    select: { completedAt: true },
  });
  return lastJob?.completedAt ?? null;
}
