"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchJson } from "@/lib/api";
import type {
  AssetRecord,
  CVERecord,
  DashboardStatsResponse,
  VulnerabilityRecord,
} from "@/types/security";

interface VulnerabilityListResponse {
  vulnerabilities: VulnerabilityRecord[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
  stats?: {
    total: number;
    avgCvss: number;
    bySeverity: Record<string, number>;
    byStatus: Record<string, number>;
  };
}

interface AssetListResponse {
  assets: AssetRecord[];
  pagination: { page: number; pageSize: number; total: number; pages: number };
  stats: {
    total: number;
    byCriticality: Record<string, number>;
    byStatus: Record<string, number>;
  };
}

export function useDashboardStats() {
  return useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: () => fetchJson<DashboardStatsResponse>("/api/dashboard/stats"),
  });
}

/**
 * Bounded CVE fetch. Never pages the full, NVD-synced table - which can
 * hold hundreds of thousands of rows (an unbounded fetch took ~9 minutes).
 */
export function useRecentCves(limit = 100) {
  return useQuery({
    queryKey: ["cves-recent", limit],
    queryFn: () => fetchJson<CVERecord[]>(`/api/cves?limit=${limit}`),
  });
}

/**
 * Single-CVE lookup by exact cveId (indexed DB lookup). Used by the CVE
 * detail page instead of downloading the full table just to find one row.
 */
export function useCveByCveId(cveId: string | undefined) {
  return useQuery({
    queryKey: ["cve-by-id", cveId],
    queryFn: async () => {
      const rows = await fetchJson<CVERecord[]>(`/api/cves?cveId=${encodeURIComponent(cveId!)}`);
      return rows[0] ?? null;
    },
    enabled: Boolean(cveId),
  });
}

export interface CveHistoryEntry {
  id: string;
  action: string;
  fromStatus: string | null;
  toStatus: string | null;
  note: string | null;
  actorEmail: string | null;
  timestamp: string;
}

/**
 * Remediation/status-change history for a single CVE, pulled from the audit
 * log (?include=history on the v2 detail route) - the documented trail of
 * who changed the fix status, when, and how (note).
 */
export function useCveHistory(cveId: string | undefined) {
  return useQuery({
    queryKey: ["cve-history", cveId],
    queryFn: async () => {
      const res = await fetchJson<{
        included?: Array<{ type: string; id: string; attributes: Omit<CveHistoryEntry, "id"> }>;
      }>(
        `/api/v2/cves/${encodeURIComponent(cveId!)}?include=history`
      );
      return (res.included ?? [])
        .filter((item) => item.type === "audit-logs")
        .map((item) => ({ ...item.attributes, id: item.id }));
    },
    enabled: Boolean(cveId),
  });
}

export interface DashboardAnalyticsV2 {
  totalCVEs: number;
  totalAssets: number;
  newCVEs7d: number;
  avgCvssV3: number;
  kevCount: number;
  vulnerabilitiesBySeverity: { severity: string; value: number }[];
  vulnerabilitiesByStatus: { status: string; value: number }[];
  timeline: { id: string; action: string; resource: string; resourceId: string | null; timestamp: string }[];
}

/**
 * SQL-aggregated dashboard totals/severity-breakdown (cached 30s server-side)
 * so the dashboard's KPIs and pie chart don't require downloading the
 * entire CVE table just to count rows client-side.
 */
export function useDashboardAnalytics() {
  return useQuery({
    queryKey: ["dashboard-analytics-v2"],
    queryFn: () =>
      fetchJson<{ data: { attributes: DashboardAnalyticsV2 } }>("/api/v2/analytics/dashboard").then(
        (res) => res.data.attributes
      ),
  });
}

/**
 * Backward-compatible hook returning just the asset array.
 * Most pages use this for selectors / dropdowns.
 */
export function useAssets() {
  return useQuery({
    queryKey: ["assets", "all"],
    queryFn: async () => {
      const res = await fetchJson<AssetListResponse>("/api/assets?pageSize=500");
      return res.assets;
    },
  });
}

/**
 * Hook for the assets management page - supports filters, sort, and exposes
 * pagination + aggregated stats.
 */
export function useAssetsPage(filters?: {
  search?: string;
  criticality?: string;
  status?: string;
  type?: string;
  sortBy?: string;
  sortDir?: "asc" | "desc";
  page?: number;
  pageSize?: number;
}) {
  const params = new URLSearchParams();
  if (filters?.search) params.set("search", filters.search);
  if (filters?.criticality && filters.criticality !== "all") params.set("criticality", filters.criticality);
  if (filters?.status && filters.status !== "all") params.set("status", filters.status);
  if (filters?.type && filters.type !== "all") params.set("type", filters.type);
  if (filters?.sortBy) params.set("sortBy", filters.sortBy);
  if (filters?.sortDir) params.set("sortDir", filters.sortDir);
  if (filters?.page) params.set("page", String(filters.page));
  params.set("pageSize", String(filters?.pageSize ?? 100));

  return useQuery({
    queryKey: ["assets-page", params.toString()],
    queryFn: () => fetchJson<AssetListResponse>(`/api/assets?${params.toString()}`),
  });
}

export function useVulnerabilities() {
  return useQuery({
    queryKey: ["vulnerabilities"],
    queryFn: async () => {
      const payload = await fetchJson<VulnerabilityListResponse>(
        "/api/vulnerabilities?limit=500&page=1"
      );
      return payload.vulnerabilities;
    },
  });
}

/**
 * Server-driven vulnerabilities page hook: applies filters/sort/pagination
 * server-side and exposes the aggregated stats block.
 */
export function useVulnerabilitiesPage(filters?: {
  search?: string;
  severity?: string;
  status?: string;
  assetId?: string;
  sortBy?: string;
  sortDir?: "asc" | "desc";
  page?: number;
  limit?: number;
}) {
  const params = new URLSearchParams();
  if (filters?.search) params.set("search", filters.search);
  if (filters?.severity && filters.severity !== "all") params.set("severity", filters.severity);
  if (filters?.status && filters.status !== "all") params.set("status", filters.status);
  if (filters?.assetId && filters.assetId !== "all") params.set("assetId", filters.assetId);
  if (filters?.sortBy) params.set("sortBy", filters.sortBy);
  if (filters?.sortDir) params.set("sortDir", filters.sortDir);
  if (filters?.page) params.set("page", String(filters.page));
  params.set("limit", String(filters?.limit ?? 100));

  return useQuery({
    queryKey: ["vulnerabilities-page", params.toString()],
    queryFn: () => fetchJson<VulnerabilityListResponse>(`/api/vulnerabilities?${params.toString()}`),
  });
}
