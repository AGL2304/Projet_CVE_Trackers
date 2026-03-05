export type Severity = "critical" | "high" | "medium" | "low" | "none";

export type VulnerabilityStatus = "open" | "in_progress" | "resolved" | "ignored";

export interface CVERecord {
  id: string;
  cveId: string;
  description: string;
  severity: string;
  cvssScore: number | null;
  cvssVector: string | null;
  publishedDate: string | null;
  lastModifiedDate: string | null;
  references: string | null;
  vulnStatus: string | null;
  importedAt: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface AssetRecord {
  id: string;
  name: string;
  type: string;
  ip: string | null;
  hostname: string | null;
  description: string | null;
  criticality: string;
  status: string;
  createdAt: string;
  updatedAt: string;
}

export interface VulnerabilityRecord {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  status: VulnerabilityStatus;
  cvssScore: number | null;
  cveId: string | null;
  assetId: string | null;
  discoveredAt: string;
  resolvedAt: string | null;
  createdAt: string;
  updatedAt: string;
  asset?: {
    id: string;
    name: string;
    type?: string;
    hostname?: string | null;
    ip?: string | null;
  } | null;
}

export interface DashboardStatsResponse {
  totalAssets: number;
  totalVulnerabilities: number;
  totalCVEs: number;
  criticalVulnerabilities: number;
  resolvedVulnerabilities: number;
  vulnerabilitiesBySeverity: { name: string; value: number; color: string }[];
  assetsByCriticality: { name: string; value: number; color: string }[];
  vulnerabilitiesByStatus: { name: string; value: number; color: string }[];
}
