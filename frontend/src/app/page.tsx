"use client";

import * as React from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { scaleLinear } from "d3-scale";
import { Activity, ArrowUpRight, CheckCircle2, ShieldAlert, Timer } from "lucide-react";
import { Pie, PieChart, ResponsiveContainer, Tooltip, Cell } from "recharts";
import { useCVEs, useVulnerabilities } from "@/hooks/queries";
import { normalizeCve, cveDate, cveRelativeDate } from "@/lib/cve-helpers";
import { getSeverityColor, severityLabel } from "@/lib/cvss";
import { useUiPreferencesStore } from "@/store/ui-preferences";
import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { EmptyState } from "@/components/states/empty-state";
import { LoadingGrid } from "@/components/states/loading-grid";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import styles from "@/app/dashboard.module.css";

const currentAnalyst = "analyste.soc";

const copy = {
  fr: {
    loadErrorTitle: "Erreur de chargement",
    loadErrorDesc: "Le dashboard n'a pas pu recuperer les donnees.",
    retry: "Relancer",
    title: "Tableau de bord securite",
    description: "Visibilite immediate de l'exposition CVE et de l'activite de remediation",
    workspace: "Espace SOC desktop-first",
    total: "Total CVEs",
    totalHint: "Inventaire actuel",
    critical: "CVEs critiques",
    criticalHint: "Priorite P1",
    new7d: "Nouvelles CVEs (7j)",
    new7dHint: "Surface recente",
    patched: "CVEs patchees (mois)",
    patchedHint: "SLA remediation",
    avgCvss: "CVSS moyen",
    avgCvssHint: "Risque moyen",
    heatmapTitle: "Heatmap temporelle",
    heatmapDesc: "Densite CVEs par jour",
    heatmapPeriod: "Periode",
    heatmapField: "Champ",
    heatmapPublished: "Publiees",
    heatmapModified: "Modifiees",
    heatmapTotal: "Total periode",
    heatmapPeak: "Pic journalier",
    heatmapAvg: "Moyenne/jour",
    heatmapEmpty: "Aucune CVE sur la periode",
    heatmapLess: "Moins",
    heatmapMore: "Plus",
    heatmapErr: "Heatmap indisponible",
    days30: "30 j",
    days90: "90 j",
    days180: "6 mois",
    days365: "1 an",
    severityDistTitle: "Distribution par severite",
    severityDistDesc: "Drill-down par segment",
    all: "Tout",
    topTitle: "Top 10 CVEs critiques",
    topDesc: "Table condensee avec actions rapides",
    noCve: "Aucune CVE",
    noCveDesc: "Aucune donnee critique pour cette vue.",
    severity: "Severite",
    published: "Publication",
    actions: "Actions",
    detail: "Detail",
    assign: "Assigner",
    myAssignmentsTitle: "Mes assignations",
    myAssignmentsDesc: `CVEs assignees a ${currentAnalyst}`,
    nothingAssigned: "Rien assigne",
    nothingAssignedDesc: "Assignez une CVE depuis le top 10 ou la liste CVE.",
    updated: "Mis a jour",
    timelineTitle: "Timeline d'activite",
    timelineDesc: "Dernieres modifications et nouvelles CVEs",
    cveUpdate: "Mise a jour",
    resolvedPrefix: "Correction",
    detectedPrefix: "Detection",
  },
  en: {
    loadErrorTitle: "Loading error",
    loadErrorDesc: "Dashboard data could not be loaded.",
    retry: "Retry",
    title: "Security dashboard",
    description: "Immediate visibility on CVE exposure and remediation activity",
    workspace: "Desktop-first SOC workspace",
    total: "Total CVEs",
    totalHint: "Current inventory",
    critical: "Critical CVEs",
    criticalHint: "P1 priority",
    new7d: "New CVEs (7d)",
    new7dHint: "Recent surface",
    patched: "Patched CVEs (month)",
    patchedHint: "Remediation SLA",
    avgCvss: "Average CVSS",
    avgCvssHint: "Average risk",
    heatmapTitle: "Time heatmap",
    heatmapDesc: "CVE density per day",
    heatmapPeriod: "Period",
    heatmapField: "Field",
    heatmapPublished: "Published",
    heatmapModified: "Modified",
    heatmapTotal: "Period total",
    heatmapPeak: "Daily peak",
    heatmapAvg: "Avg/day",
    heatmapEmpty: "No CVE in this period",
    heatmapLess: "Less",
    heatmapMore: "More",
    heatmapErr: "Heatmap unavailable",
    days30: "30 d",
    days90: "90 d",
    days180: "6 mo",
    days365: "1 y",
    severityDistTitle: "Severity distribution",
    severityDistDesc: "Segment drill-down",
    all: "All",
    topTitle: "Top 10 critical CVEs",
    topDesc: "Compact table with quick actions",
    noCve: "No CVE",
    noCveDesc: "No critical data for this view.",
    severity: "Severity",
    published: "Published",
    actions: "Actions",
    detail: "Details",
    assign: "Assign",
    myAssignmentsTitle: "My assignments",
    myAssignmentsDesc: `CVEs assigned to ${currentAnalyst}`,
    nothingAssigned: "Nothing assigned",
    nothingAssignedDesc: "Assign a CVE from top 10 or CVE list.",
    updated: "Updated",
    timelineTitle: "Activity timeline",
    timelineDesc: "Latest updates and new CVEs",
    cveUpdate: "Update",
    resolvedPrefix: "Resolved",
    detectedPrefix: "Detected",
  },
} as const;

export default function DashboardPage() {
  const locale = useUiPreferencesStore((state) => state.locale);
  const t = copy[locale];
  const assignments = useUiPreferencesStore((state) => state.assignments);
  const upsertAssignment = useUiPreferencesStore((state) => state.upsertAssignment);

  const {
    data: cveRows,
    isLoading: cvesLoading,
    isError: cvesError,
    refetch: refetchCves,
  } = useCVEs();

  const {
    data: vulnerabilities,
    isLoading: vulnLoading,
    isError: vulnError,
    refetch: refetchVulnerabilities,
  } = useVulnerabilities();

  const [selectedSeverity, setSelectedSeverity] = React.useState<string>("all");

  const cves = React.useMemo(() => (cveRows ?? []).map(normalizeCve), [cveRows]);

  const severityDistribution = React.useMemo(() => {
    const map = new Map<string, number>([
      ["critical", 0],
      ["high", 0],
      ["medium", 0],
      ["low", 0],
      ["none", 0],
    ]);

    cves.forEach((cve) => {
      map.set(cve.severity, (map.get(cve.severity) ?? 0) + 1);
    });

    return Array.from(map.entries()).map(([severity, value]) => ({
      severity,
      value,
      label: severityLabel(severity, locale),
      color: getSeverityColor(severity),
    }));
  }, [cves, locale]);

  const topCritical = React.useMemo(() => {
    return cves
      .filter((cve) => (selectedSeverity === "all" ? true : cve.severity === selectedSeverity))
      .sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0))
      .slice(0, 10);
  }, [cves, selectedSeverity]);


  const metrics = React.useMemo(() => {
    const now = new Date();
    const sevenDaysAgo = new Date(now);
    sevenDaysAgo.setDate(now.getDate() - 7);

    const firstDayOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    const critical = cves.filter((cve) => cve.severity === "critical").length;
    const new7d = cves.filter((cve) => {
      const published = cve.publishedDate ? new Date(cve.publishedDate) : new Date(cve.importedAt);
      return published >= sevenDaysAgo;
    }).length;

    const patchedMonth = (vulnerabilities ?? []).filter((entry) => {
      if (entry.status !== "resolved") return false;
      const referenceDate = new Date(entry.resolvedAt ?? entry.updatedAt ?? entry.createdAt);
      return referenceDate >= firstDayOfMonth;
    }).length;

    const cvss = cves.filter((cve) => typeof cve.cvssScore === "number").map((cve) => Number(cve.cvssScore));
    const avgCvss = cvss.length ? cvss.reduce((sum, value) => sum + value, 0) / cvss.length : 0;

    return {
      total: cves.length,
      critical,
      new7d,
      patchedMonth,
      avgCvss: avgCvss.toFixed(1),
    };
  }, [cves, vulnerabilities]);

  const timeline = React.useMemo(() => {
    const cveTimeline = cves.slice(0, 18).map((item) => ({
      id: item.cveId,
      type: "cve" as const,
      title: `${t.cveUpdate} ${item.cveId}`,
      when: item.lastModifiedDate ?? item.importedAt,
      severity: item.severity,
      details: item.description,
    }));

    const vulnTimeline = (vulnerabilities ?? []).slice(0, 12).map((item) => ({
      id: item.id,
      type: "vulnerability" as const,
      title: item.status === "resolved" ? `${t.resolvedPrefix} ${item.title}` : `${t.detectedPrefix} ${item.title}`,
      when: item.updatedAt,
      severity: item.severity,
      details: item.asset?.name ? `Asset: ${item.asset.name}` : item.description ?? "",
    }));

    return [...cveTimeline, ...vulnTimeline]
      .sort((a, b) => new Date(b.when).getTime() - new Date(a.when).getTime())
      .slice(0, 10);
  }, [cves, vulnerabilities, t.cveUpdate, t.detectedPrefix, t.resolvedPrefix]);

  const myAssignments = React.useMemo(() => {
    return Object.values(assignments)
      .filter((entry) => entry.assignee === currentAnalyst)
      .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime())
      .slice(0, 8);
  }, [assignments]);

  const isLoading = cvesLoading || vulnLoading;
  const isError = cvesError || vulnError;

  if (isLoading) {
    return (
      <div className="p-6 lg:p-8">
        <LoadingGrid rows={10} />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-6 lg:p-8">
        <EmptyState
          title={t.loadErrorTitle}
          description={t.loadErrorDesc}
          actionLabel={t.retry}
          onAction={() => {
            void refetchCves();
            void refetchVulnerabilities();
          }}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6 lg:p-8">
      <PageHeader
        title={t.title}
        description={t.description}
        actions={<Badge variant="secondary">{t.workspace}</Badge>}
      />

      <section id="dashboard-kpis" className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <KpiCard title={t.total} value={metrics.total} hint={t.totalHint} icon={<Activity className="h-4 w-4" />} />
        <KpiCard title={t.critical} value={metrics.critical} hint={t.criticalHint} icon={<ShieldAlert className="h-4 w-4" />} emphasize />
        <KpiCard title={t.new7d} value={metrics.new7d} hint={t.new7dHint} icon={<Timer className="h-4 w-4" />} />
        <KpiCard title={t.patched} value={metrics.patchedMonth} hint={t.patchedHint} icon={<CheckCircle2 className="h-4 w-4" />} />
        <KpiCard title={t.avgCvss} value={metrics.avgCvss} hint={t.avgCvssHint} icon={<ArrowUpRight className="h-4 w-4" />} />
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
        <CveDensityHeatmap t={t} locale={locale} />


        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>{t.severityDistTitle}</CardTitle>
            <CardDescription>{t.severityDistDesc}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="h-60">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityDistribution}
                    dataKey="value"
                    nameKey="label"
                    innerRadius={65}
                    outerRadius={102}
                    paddingAngle={3}
                    onClick={(entry) => setSelectedSeverity(entry.severity)}
                    animationDuration={420}
                  >
                    {severityDistribution.map((segment) => (
                      <Cell key={segment.severity} fill={segment.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    formatter={(value, label) => [`${value}`, label]}
                    contentStyle={{ borderRadius: "0.75rem", border: "1px solid var(--border)" }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant={selectedSeverity === "all" ? "default" : "outline"}
                onClick={() => setSelectedSeverity("all")}
              >
                {t.all}
              </Button>
              {severityDistribution.map((segment) => (
                <Button
                  key={segment.severity}
                  size="sm"
                  variant={selectedSeverity === segment.severity ? "default" : "outline"}
                  onClick={() => setSelectedSeverity(segment.severity)}
                >
                  {segment.label}
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.45fr_1fr]">
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>{t.topTitle}</CardTitle>
            <CardDescription>{t.topDesc}</CardDescription>
          </CardHeader>
          <CardContent>
            {topCritical.length === 0 ? (
              <EmptyState title={t.noCve} description={t.noCveDesc} />
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>CVE</TableHead>
                      <TableHead>{t.severity}</TableHead>
                      <TableHead>CVSS</TableHead>
                      <TableHead>{t.published}</TableHead>
                      <TableHead className="text-right">{t.actions}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {topCritical.map((cve) => (
                      <TableRow key={cve.id}>
                        <TableCell className="font-medium">{cve.cveId}</TableCell>
                        <TableCell>
                          <SeverityBadge value={cve.severity} />
                        </TableCell>
                        <TableCell>{cve.cvssScore?.toFixed(1) ?? "-"}</TableCell>
                        <TableCell>{cveDate(cve.publishedDate ?? cve.importedAt, locale)}</TableCell>
                        <TableCell>
                          <div className="flex justify-end gap-2">
                            <Button asChild size="sm" variant="outline">
                              <Link href={`/cves/${cve.cveId}`}>{t.detail}</Link>
                            </Button>
                            <Button
                              size="sm"
                              onClick={() =>
                                upsertAssignment({
                                  cveId: cve.cveId,
                                  assignee: currentAnalyst,
                                  status: "todo",
                                  updatedAt: new Date().toISOString(),
                                })
                              }
                            >
                              {t.assign}
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>{t.myAssignmentsTitle}</CardTitle>
            <CardDescription>{t.myAssignmentsDesc}</CardDescription>
          </CardHeader>
          <CardContent>
            {myAssignments.length === 0 ? (
              <EmptyState title={t.nothingAssigned} description={t.nothingAssignedDesc} />
            ) : (
              <div className="space-y-2">
                {myAssignments.map((item) => (
                  <div key={item.cveId} className="rounded-lg border bg-card px-3 py-2">
                    <div className="flex items-center justify-between">
                      <Link href={`/cves/${item.cveId}`} className="font-medium hover:underline">
                        {item.cveId}
                      </Link>
                      <Badge variant={item.status === "done" ? "secondary" : "outline"}>{item.status}</Badge>
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">{t.updated} {cveRelativeDate(item.updatedAt, locale)}</p>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </section>

      <section>
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>{t.timelineTitle}</CardTitle>
            <CardDescription>{t.timelineDesc}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {timeline.map((entry, index) => (
                <motion.div
                  key={`${entry.type}-${entry.id}`}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.04 }}
                  className={`rounded-lg border bg-card px-3 py-2 ${styles.timelineCard}`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <SeverityBadge value={entry.severity} />
                      <span className="text-sm font-medium">{entry.title}</span>
                    </div>
                    <span className="text-xs text-muted-foreground">{cveRelativeDate(entry.when, locale)}</span>
                  </div>
                  <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">{entry.details}</p>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}

function KpiCard({
  title,
  value,
  hint,
  icon,
  emphasize = false,
}: {
  title: string;
  value: string | number;
  hint: string;
  icon: React.ReactNode;
  emphasize?: boolean;
}) {
  return (
    <Card className={`proactive-top ${emphasize ? "card-glow" : "card-elevated"}`}>
      <CardHeader className="pb-3">
        <CardDescription className="flex items-center justify-between text-xs uppercase tracking-wide">
          {title}
          {icon}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <p className={`text-3xl font-semibold ${emphasize ? "text-grad-warm" : ""}`}>
          {value}
        </p>
        <p className="text-xs text-muted-foreground">{hint}</p>
      </CardContent>
    </Card>
  );
}

// ─── CVE density heatmap ─────────────────────────────────────────────────────
// Aggregation lives server-side at /api/v2/analytics/heatmap so we don't
// page the whole CVE table to draw a 90-day calendar.

type HeatmapCell = {
  date: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  none: number;
};

type HeatmapResponse = {
  data: {
    type: "heatmap";
    id: string;
    attributes: {
      days: number;
      from: string;
      to: string;
      field: "published" | "modified";
      total: number;
      maxPerDay: number;
      cells: HeatmapCell[];
      bySeverity: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE", number>;
    };
  };
};

const HEATMAP_PERIODS = [
  { id: 30, key: "days30" as const },
  { id: 90, key: "days90" as const },
  { id: 180, key: "days180" as const },
  { id: 365, key: "days365" as const },
];

function CveDensityHeatmap({
  t,
  locale,
}: {
  t: Record<string, string>;
  locale: "fr" | "en";
}) {
  const [days, setDays] = React.useState(90);
  const [field, setField] = React.useState<"published" | "modified">("published");

  const [data, setData] = React.useState<HeatmapResponse["data"]["attributes"] | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetch(`/api/v2/analytics/heatmap?days=${days}&field=${field}`, { credentials: "same-origin" })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((json: HeatmapResponse) => {
        if (!cancelled) setData(json.data.attributes);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "error");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [days, field]);

  const cells = data?.cells ?? [];
  const max = Math.max(1, data?.maxPerDay ?? 1);
  const totalDays = cells.length || 1;
  const avg = data ? data.total / totalDays : 0;

  // GitHub-style colour scale: 5 buckets relative to the period's max
  const colorScale = React.useMemo(
    () =>
      scaleLinear<string>()
        .domain([0, max * 0.1, max * 0.3, max * 0.6, max])
        .range(["#e2e8f0", "#bae6fd", "#38bdf8", "#0284c7", "#0c4a6e"])
        .clamp(true),
    [max]
  );

  // Group into columns of 7 (one column = one calendar week).
  // We left-pad the first column so weekdays align: cell.date.getUTCDay() == 0 means Sunday.
  const weeks = React.useMemo(() => {
    if (cells.length === 0) return [];
    const padStart = new Date(`${cells[0].date}T00:00:00Z`).getUTCDay(); // 0..6
    type Col = Array<HeatmapCell | null>;
    const cols: Col[] = [];
    let current: Col = Array.from({ length: padStart }, () => null);
    for (const cell of cells) {
      current.push(cell);
      if (current.length === 7) {
        cols.push(current);
        current = [];
      }
    }
    if (current.length > 0) {
      while (current.length < 7) current.push(null);
      cols.push(current);
    }
    return cols;
  }, [cells]);

  // Month labels — render once per month transition, above the column where the change happens.
  const monthLabels = React.useMemo(() => {
    const labels: Array<{ index: number; label: string }> = [];
    let lastMonth = -1;
    weeks.forEach((week, idx) => {
      const firstReal = week.find((c) => c !== null);
      if (!firstReal) return;
      const month = new Date(`${firstReal.date}T00:00:00Z`).getUTCMonth();
      if (month !== lastMonth) {
        lastMonth = month;
        labels.push({
          index: idx,
          label: new Date(`${firstReal.date}T00:00:00Z`).toLocaleDateString(
            locale === "fr" ? "fr-FR" : "en-US",
            { month: "short" }
          ),
        });
      }
    });
    return labels;
  }, [weeks, locale]);

  const dayLabels = locale === "fr"
    ? ["", "Lun", "", "Mer", "", "Ven", ""]
    : ["", "Mon", "", "Wed", "", "Fri", ""];

  return (
    <Card className="card-elevated">
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <CardTitle>{t.heatmapTitle}</CardTitle>
            <CardDescription>{t.heatmapDesc}</CardDescription>
          </div>
          <div className="flex flex-wrap items-center gap-1">
            <div className="inline-flex rounded-md border bg-muted/30 p-0.5 text-xs">
              {HEATMAP_PERIODS.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setDays(p.id)}
                  className={`rounded px-2 py-1 transition ${
                    days === p.id
                      ? "bg-background text-foreground shadow"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {t[p.key]}
                </button>
              ))}
            </div>
            <div className="inline-flex rounded-md border bg-muted/30 p-0.5 text-xs">
              {(["published", "modified"] as const).map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setField(f)}
                  className={`rounded px-2 py-1 transition ${
                    field === f
                      ? "bg-background text-foreground shadow"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {f === "published" ? t.heatmapPublished : t.heatmapModified}
                </button>
              ))}
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {/* Stats row */}
        <div className="mb-3 grid grid-cols-3 gap-3 text-xs">
          <div className="rounded-md border p-2">
            <div className="text-muted-foreground">{t.heatmapTotal}</div>
            <div className="mt-0.5 text-lg font-semibold tabular-nums">
              {(data?.total ?? 0).toLocaleString()}
            </div>
          </div>
          <div className="rounded-md border p-2">
            <div className="text-muted-foreground">{t.heatmapPeak}</div>
            <div className="mt-0.5 text-lg font-semibold tabular-nums">
              {(data?.maxPerDay ?? 0).toLocaleString()}
            </div>
          </div>
          <div className="rounded-md border p-2">
            <div className="text-muted-foreground">{t.heatmapAvg}</div>
            <div className="mt-0.5 text-lg font-semibold tabular-nums">
              {avg.toFixed(1)}
            </div>
          </div>
        </div>

        {error ? (
          <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive">
            {t.heatmapErr}: {error}
          </div>
        ) : loading && !data ? (
          <div className="h-[160px] animate-pulse rounded-md bg-muted/40" />
        ) : cells.length === 0 || data?.total === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">{t.heatmapEmpty}</p>
        ) : (
          <div className="overflow-x-auto">
            <div className="inline-flex flex-col gap-1">
              {/* Month labels */}
              <div className="relative ml-7 h-3 text-[10px] text-muted-foreground">
                {monthLabels.map((m) => (
                  <span
                    key={`${m.index}-${m.label}`}
                    style={{ left: m.index * 14, position: "absolute" }}
                  >
                    {m.label}
                  </span>
                ))}
              </div>

              <div className="flex gap-1">
                {/* Weekday labels */}
                <div className="grid grid-rows-7 gap-1 pr-1 text-[10px] text-muted-foreground">
                  {dayLabels.map((label, i) => (
                    <span key={i} className="h-3 leading-3">
                      {label}
                    </span>
                  ))}
                </div>

                {/* Grid */}
                {weeks.map((week, weekIndex) => (
                  <div key={weekIndex} className="grid grid-rows-7 gap-1">
                    {week.map((cell, dayIndex) =>
                      cell ? (
                        <Link
                          key={cell.date}
                          href={`/cves?dateFrom=${cell.date}&dateTo=${cell.date}${
                            field === "published" ? "" : "&useModified=1"
                          }`}
                          className={`h-3 w-3 rounded-[2px] transition hover:ring-1 hover:ring-foreground ${styles.heatmapCell}`}
                          style={{ backgroundColor: colorScale(cell.total) }}
                          title={renderTooltip(cell, locale)}
                          aria-label={renderTooltip(cell, locale)}
                        />
                      ) : (
                        <div
                          key={`pad-${weekIndex}-${dayIndex}`}
                          className="h-3 w-3 rounded-[2px] bg-transparent"
                        />
                      )
                    )}
                  </div>
                ))}
              </div>

              {/* Legend */}
              <div className="ml-7 mt-2 flex items-center gap-1.5 text-[10px] text-muted-foreground">
                <span>{t.heatmapLess}</span>
                {[0, 0.1, 0.3, 0.6, 1].map((scale, i) => (
                  <span
                    key={i}
                    className="h-3 w-3 rounded-[2px]"
                    style={{ backgroundColor: colorScale(max * scale) }}
                  />
                ))}
                <span>{t.heatmapMore}</span>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function renderTooltip(cell: HeatmapCell, locale: "fr" | "en"): string {
  const dateStr = new Date(`${cell.date}T00:00:00Z`).toLocaleDateString(
    locale === "fr" ? "fr-FR" : "en-US",
    { weekday: "short", year: "numeric", month: "short", day: "numeric" }
  );
  if (cell.total === 0) {
    return `${dateStr}\n${locale === "fr" ? "Aucune CVE" : "No CVE"}`;
  }
  const parts: string[] = [`${dateStr}`, `${locale === "fr" ? "Total" : "Total"}: ${cell.total}`];
  if (cell.critical > 0) parts.push(`CRITICAL: ${cell.critical}`);
  if (cell.high > 0) parts.push(`HIGH: ${cell.high}`);
  if (cell.medium > 0) parts.push(`MEDIUM: ${cell.medium}`);
  if (cell.low > 0) parts.push(`LOW: ${cell.low}`);
  if (cell.none > 0) parts.push(`NONE: ${cell.none}`);
  return parts.join("\n");
}


