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

export function useCVEs() {
  return useQuery({
    queryKey: ["cves"],
    queryFn: () => fetchJson<CVERecord[]>("/api/cves"),
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
 * Hook for the assets management page — supports filters, sort, and exposes
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
