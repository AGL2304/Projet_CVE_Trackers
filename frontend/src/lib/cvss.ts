import type { Severity } from "@/types/security";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "none"];

export const severityTokens: Record<
  Severity,
  { label: string; labelEn: string; cssClass: string; hex: string }
> = {
  critical: {
    label: "Critique",
    labelEn: "Critical",
    cssClass: "severity-critical",
    hex: "#dc2626",
  },
  high: {
    label: "Haute",
    labelEn: "High",
    cssClass: "severity-high",
    hex: "#f97316",
  },
  medium: {
    label: "Moyenne",
    labelEn: "Medium",
    cssClass: "severity-medium",
    hex: "#facc15",
  },
  low: {
    label: "Faible",
    labelEn: "Low",
    cssClass: "severity-low",
    hex: "#3b82f6",
  },
  none: {
    label: "Aucune",
    labelEn: "None",
    cssClass: "severity-none",
    hex: "#94a3b8",
  },
};

export function normalizeSeverity(value?: string | null): Severity {
  const normalized = value?.toLowerCase().trim();
  if (!normalized) return "none";
  if (normalized.includes("critical")) return "critical";
  if (normalized.includes("high")) return "high";
  if (normalized.includes("medium")) return "medium";
  if (normalized.includes("low")) return "low";
  return "none";
}

export function severityFromScore(score?: number | null): Severity {
  if (score === null || score === undefined) return "none";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}

export function severityLabel(value?: string | null, locale: "fr" | "en" = "fr") {
  const severity = normalizeSeverity(value);
  return locale === "fr" ? severityTokens[severity].label : severityTokens[severity].labelEn;
}

export function getSeverityColor(value?: string | null) {
  return severityTokens[normalizeSeverity(value)].hex;
}

export function getSeverityClass(value?: string | null) {
  return severityTokens[normalizeSeverity(value)].cssClass;
}
