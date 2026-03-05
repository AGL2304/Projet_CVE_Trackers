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

export function useAssets() {
  return useQuery({
    queryKey: ["assets"],
    queryFn: () => fetchJson<AssetRecord[]>("/api/assets"),
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
