"use client";

import * as React from "react";
import { useForm, Controller } from "react-hook-form";
import {
  CalendarClock,
  Download,
  FileBarChart,
  FileJson,
  FileSpreadsheet,
  Loader2,
  Play,
  RefreshCw,
  Sparkles,
  Trash2,
  XCircle,
} from "lucide-react";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "@/hooks/use-toast";
import { fetchJson } from "@/lib/api";
import { useUiPreferencesStore } from "@/store/ui-preferences";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const;
const STATUSES = ["NEW", "ANALYZING", "CONFIRMED", "REMEDIATED", "FALSE_POSITIVE", "WONTFIX"] as const;
const SOURCES = ["NVD", "MITRE", "OSV", "CISA_KEV", "MANUAL"] as const;
const FORMATS = ["PDF", "CSV", "JSON"] as const;

const SCOPES = ["cve", "assets"] as const;
const ASSET_CRITICALITIES = ["all", "low", "medium", "high", "critical"] as const;
const ASSET_STATUSES = ["all", "active", "inactive", "retired"] as const;

type GenerateValues = {
  scope: (typeof SCOPES)[number];
  format: (typeof FORMATS)[number];
  title: string;
  severity: (typeof SEVERITIES)[number][];
  status: (typeof STATUSES)[number][];
  source: (typeof SOURCES)[number][];
  dateFrom: string;
  dateTo: string;
  minCvss: string;
  maxCvss: string;
  search: string;
  limit: string;
  assetCriticality: (typeof ASSET_CRITICALITIES)[number];
  assetStatus: (typeof ASSET_STATUSES)[number];
};

type ReportListItem = {
  type: "reports";
  id: string;
  attributes: {
    format: "PDF" | "CSV" | "JSON";
    status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
    filter: Record<string, unknown> | null;
    createdAt: string;
    completedAt: string | null;
    errorMessage: string | null;
    hasFile: boolean;
  };
  links: { self: string; download: string };
};

type ReportsResponse = {
  data: ReportListItem[];
};

const copy = {
  fr: {
    title: "Rapports CVE",
    description:
      "Génère un rapport complet (PDF imprimable, CSV ou JSON) à partir de la base CVE — avec filtres avancés et téléchargement",
    presets: "Préréglages",
    presetCritical: "Toutes les CVE critiques",
    presetCritical7d: "Critiques + élevées (7 j)",
    presetNew: "CVE nouvellement importées",
    presetFull: "Rapport complet (tout)",
    presetAssets: "Inventaire des actifs scannés",
    builder: "Constructeur",
    scope: "Type de rapport",
    scopeCve: "Base CVE",
    scopeAssets: "Actifs scannés",
    scopeHint: "« Actifs scannés » liste les hôtes découverts et leurs produits/services détectés.",
    assetCriticality: "Criticité",
    assetStatus: "Statut de l'actif",
    assetSearch: "Recherche (nom, IP, hostname)",
    assetNote:
      "Ce rapport listera tous les actifs de l'inventaire avec leurs services détectés (CPE) et le nombre de vulnérabilités liées. Les filtres CVE ci-dessous ne s'appliquent pas.",
    format: "Format",
    formatHint: "PDF → HTML imprimable (Ctrl+P pour PDF). CSV pour Excel. JSON pour l'API.",
    titleField: "Titre du rapport",
    severity: "Sévérités",
    status: "Statuts",
    source: "Sources",
    dateFrom: "Publié depuis",
    dateTo: "Publié jusqu'à",
    minCvss: "CVSS min",
    maxCvss: "CVSS max",
    search: "Recherche (titre/desc/cveId)",
    limit: "Limite",
    generate: "Générer le rapport",
    generating: "Mise en file...",
    queued: "Rapport mis en file — le worker le traitera dans les ~15 s.",
    listTitle: "Rapports récents",
    refresh: "Rafraîchir",
    columns: {
      created: "Créé",
      format: "Format",
      status: "Statut",
      filters: "Filtres",
      action: "Action",
    },
    actions: {
      download: "Télécharger",
      view: "Voir",
      retry: "Réessayer",
    },
    empty: "Aucun rapport généré. Lance ta première génération en remplissant le formulaire.",
    loadError: "Impossible de charger les rapports",
  },
  en: {
    title: "CVE reports",
    description:
      "Generate a complete report (printable PDF, CSV or JSON) from the CVE database — with advanced filters and download",
    presets: "Presets",
    presetCritical: "All critical CVEs",
    presetCritical7d: "Critical + high (7 d)",
    presetNew: "Newly imported CVEs",
    presetFull: "Full report (everything)",
    presetAssets: "Scanned-asset inventory",
    builder: "Builder",
    scope: "Report type",
    scopeCve: "CVE database",
    scopeAssets: "Scanned assets",
    scopeHint: "\"Scanned assets\" lists discovered hosts and their detected products/services.",
    assetCriticality: "Criticality",
    assetStatus: "Asset status",
    assetSearch: "Search (name, IP, hostname)",
    assetNote:
      "This report lists every inventory asset with its detected services (CPE) and linked vulnerability count. The CVE filters below do not apply.",
    format: "Format",
    formatHint: "PDF → printable HTML (Ctrl+P to PDF). CSV for Excel. JSON for the API.",
    titleField: "Report title",
    severity: "Severities",
    status: "Statuses",
    source: "Sources",
    dateFrom: "Published from",
    dateTo: "Published until",
    minCvss: "Min CVSS",
    maxCvss: "Max CVSS",
    search: "Search (title/desc/cveId)",
    limit: "Limit",
    generate: "Generate report",
    generating: "Queuing...",
    queued: "Report queued — the worker will pick it up within ~15s.",
    listTitle: "Recent reports",
    refresh: "Refresh",
    columns: {
      created: "Created",
      format: "Format",
      status: "Status",
      filters: "Filters",
      action: "Action",
    },
    actions: {
      download: "Download",
      view: "View",
      retry: "Retry",
    },
    empty: "No report generated yet. Launch your first one by filling the form.",
    loadError: "Unable to load reports",
  },
} as const;

function formatIcon(format: string) {
  if (format === "CSV") return <FileSpreadsheet className="h-4 w-4" />;
  if (format === "JSON") return <FileJson className="h-4 w-4" />;
  return <FileBarChart className="h-4 w-4" />;
}

function statusColor(status: string) {
  switch (status) {
    case "COMPLETED":
      return "text-emerald-600";
    case "RUNNING":
      return "text-amber-600";
    case "QUEUED":
      return "text-sky-600";
    case "FAILED":
      return "text-destructive";
    default:
      return "";
  }
}

function summarizeFilter(filter: Record<string, unknown> | null): string {
  if (!filter || Object.keys(filter).length === 0) return "—";
  const parts: string[] = [];
  if (filter.scope === "assets") {
    parts.push("scope:actifs");
    if (filter.criticality) parts.push(`crit:${String(filter.criticality)}`);
    if (filter.assetStatus) parts.push(`statut:${String(filter.assetStatus)}`);
    if (filter.search) parts.push(`q:"${String(filter.search).slice(0, 30)}"`);
    return parts.join(" · ");
  }
  if (Array.isArray(filter.severity) && filter.severity.length > 0)
    parts.push(`sev:${(filter.severity as string[]).join("|")}`);
  if (Array.isArray(filter.status) && filter.status.length > 0)
    parts.push(`status:${(filter.status as string[]).join("|")}`);
  if (filter.dateFrom) parts.push(`from:${String(filter.dateFrom).slice(0, 10)}`);
  if (filter.dateTo) parts.push(`to:${String(filter.dateTo).slice(0, 10)}`);
  if (typeof filter.minCvss === "number") parts.push(`cvss≥${filter.minCvss}`);
  if (filter.search) parts.push(`q:"${String(filter.search).slice(0, 30)}"`);
  return parts.length > 0 ? parts.join(" · ") : "—";
}

export default function ReportsPage() {
  const locale = useUiPreferencesStore((state) => state.locale);
  const t = copy[locale];

  const [reports, setReports] = React.useState<ReportListItem[]>([]);
  const [loadingList, setLoadingList] = React.useState(true);
  const [generating, setGenerating] = React.useState(false);

  const form = useForm<GenerateValues>({
    defaultValues: {
      scope: "cve",
      format: "PDF",
      title: "",
      severity: [],
      status: [],
      source: [],
      dateFrom: "",
      dateTo: "",
      minCvss: "",
      maxCvss: "",
      search: "",
      limit: "10000",
      assetCriticality: "all",
      assetStatus: "all",
    },
  });

  const scope = form.watch("scope");

  const refreshReports = React.useCallback(async () => {
    try {
      const res = await fetchJson<ReportsResponse>("/api/v2/reports?limit=20");
      setReports(res.data ?? []);
    } catch (e) {
      const msg = e instanceof Error ? e.message : t.loadError;
      toast({ title: t.loadError, description: msg, variant: "destructive" });
    } finally {
      setLoadingList(false);
    }
  }, [t.loadError]);

  React.useEffect(() => {
    void refreshReports();
    // Auto-refresh every 5s if any report is QUEUED/RUNNING
    const interval = setInterval(() => {
      void refreshReports();
    }, 5000);
    return () => clearInterval(interval);
  }, [refreshReports]);

  const generate = form.handleSubmit(async (values) => {
    setGenerating(true);
    try {
      const limit = values.limit === "" ? 10000 : Math.min(50_000, Math.max(1, Number(values.limit) || 10000));

      let payload: Record<string, unknown>;
      if (values.scope === "assets") {
        // Asset-inventory report: CVE filters do not apply.
        payload = {
          format: values.format,
          filter: {
            scope: "assets",
            ...(values.title ? { title: values.title } : {}),
            ...(values.search ? { search: values.search } : {}),
            ...(values.assetCriticality !== "all" ? { criticality: values.assetCriticality } : {}),
            ...(values.assetStatus !== "all" ? { assetStatus: values.assetStatus } : {}),
            limit,
          },
        };
      } else {
        const minCvss = values.minCvss === "" ? undefined : Number(values.minCvss);
        const maxCvss = values.maxCvss === "" ? undefined : Number(values.maxCvss);
        payload = {
          format: values.format,
          filter: {
            ...(values.title ? { title: values.title } : {}),
            ...(values.severity.length > 0 ? { severity: values.severity } : {}),
            ...(values.status.length > 0 ? { status: values.status } : {}),
            ...(values.source.length > 0 ? { source: values.source } : {}),
            ...(values.dateFrom ? { dateFrom: new Date(values.dateFrom).toISOString() } : {}),
            ...(values.dateTo ? { dateTo: new Date(values.dateTo).toISOString() } : {}),
            ...(typeof minCvss === "number" && !Number.isNaN(minCvss) ? { minCvss } : {}),
            ...(typeof maxCvss === "number" && !Number.isNaN(maxCvss) ? { maxCvss } : {}),
            ...(values.search ? { search: values.search } : {}),
            limit,
          },
        };
      }

      await fetchJson("/api/v2/reports/generate", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      toast({ title: t.queued });
      void refreshReports();
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Generation failed";
      toast({ title: "Error", description: msg, variant: "destructive" });
    } finally {
      setGenerating(false);
    }
  });

  const applyPreset = (preset: "critical" | "critical7d" | "new" | "full" | "assets") => {
    const now = new Date();
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
      .toISOString()
      .slice(0, 10);

    const base = {
      scope: "cve" as GenerateValues["scope"],
      format: form.getValues("format"),
      severity: [] as GenerateValues["severity"],
      status: [] as GenerateValues["status"],
      source: [] as GenerateValues["source"],
      dateFrom: "",
      dateTo: "",
      minCvss: "",
      maxCvss: "",
      search: "",
      assetCriticality: "all" as GenerateValues["assetCriticality"],
      assetStatus: "all" as GenerateValues["assetStatus"],
    };
    if (preset === "critical") {
      form.reset({ ...base, title: "CVE critiques", severity: ["CRITICAL"], limit: "10000" });
    } else if (preset === "critical7d") {
      form.reset({
        ...base,
        title: "CVE critiques + élevées (7 j)",
        severity: ["CRITICAL", "HIGH"],
        dateFrom: sevenDaysAgo,
        limit: "10000",
      });
    } else if (preset === "new") {
      form.reset({ ...base, title: "CVE nouvellement importées", status: ["NEW"], limit: "10000" });
    } else if (preset === "assets") {
      form.reset({
        ...base,
        scope: "assets",
        title: "Inventaire des actifs scannés",
        limit: "10000",
      });
    } else {
      form.reset({ ...base, title: "Rapport CVE complet", limit: "50000" });
    }
  };

  return (
    <div className="space-y-6 p-6 lg:p-8">
      <PageHeader title={t.title} description={t.description} />

      {/* Presets */}
      <section>
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Sparkles className="h-4 w-4" /> {t.presets}
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={() => applyPreset("critical")}>
              {t.presetCritical}
            </Button>
            <Button variant="outline" size="sm" onClick={() => applyPreset("critical7d")}>
              {t.presetCritical7d}
            </Button>
            <Button variant="outline" size="sm" onClick={() => applyPreset("new")}>
              {t.presetNew}
            </Button>
            <Button variant="outline" size="sm" onClick={() => applyPreset("full")}>
              {t.presetFull}
            </Button>
            <Button variant="default" size="sm" onClick={() => applyPreset("assets")}>
              {t.presetAssets}
            </Button>
          </CardContent>
        </Card>
      </section>

      {/* Builder */}
      <section>
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>{t.builder}</CardTitle>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={generate}>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                <div className="space-y-1">
                  <Label>{t.scope}</Label>
                  <Controller
                    control={form.control}
                    name="scope"
                    render={({ field }) => (
                      <Select value={field.value} onValueChange={field.onChange}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="cve">{t.scopeCve}</SelectItem>
                          <SelectItem value="assets">{t.scopeAssets}</SelectItem>
                        </SelectContent>
                      </Select>
                    )}
                  />
                  <p className="text-xs text-muted-foreground">{t.scopeHint}</p>
                </div>

                <div className="space-y-1">
                  <Label>{t.format}</Label>
                  <Controller
                    control={form.control}
                    name="format"
                    render={({ field }) => (
                      <Select value={field.value} onValueChange={field.onChange}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {FORMATS.map((f) => (
                            <SelectItem key={f} value={f}>
                              <span className="flex items-center gap-2">
                                {formatIcon(f)}
                                {f}
                              </span>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    )}
                  />
                  <p className="text-xs text-muted-foreground">{t.formatHint}</p>
                </div>

                <div className="space-y-1">
                  <Label>{t.titleField}</Label>
                  <Input {...form.register("title")} placeholder="Rapport..." />
                </div>
              </div>

              {scope === "cve" ? (
                <>
                  <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                    <MultiCheckGroup
                      label={t.severity}
                      options={[...SEVERITIES]}
                      value={form.watch("severity") ?? []}
                      onChange={(v) => form.setValue("severity", v as GenerateValues["severity"])}
                    />
                    <MultiCheckGroup
                      label={t.status}
                      options={[...STATUSES]}
                      value={form.watch("status") ?? []}
                      onChange={(v) => form.setValue("status", v as GenerateValues["status"])}
                    />
                    <MultiCheckGroup
                      label={t.source}
                      options={[...SOURCES]}
                      value={form.watch("source") ?? []}
                      onChange={(v) => form.setValue("source", v as GenerateValues["source"])}
                    />
                  </div>

                  <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
                    <div className="space-y-1">
                      <Label>{t.dateFrom}</Label>
                      <Input type="date" {...form.register("dateFrom")} />
                    </div>
                    <div className="space-y-1">
                      <Label>{t.dateTo}</Label>
                      <Input type="date" {...form.register("dateTo")} />
                    </div>
                    <div className="space-y-1">
                      <Label>{t.minCvss}</Label>
                      <Input
                        type="number"
                        step="0.1"
                        min={0}
                        max={10}
                        {...form.register("minCvss")}
                        placeholder="0.0"
                      />
                    </div>
                    <div className="space-y-1">
                      <Label>{t.maxCvss}</Label>
                      <Input
                        type="number"
                        step="0.1"
                        min={0}
                        max={10}
                        {...form.register("maxCvss")}
                        placeholder="10.0"
                      />
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <div className="rounded-md border border-sky-500/30 bg-sky-500/10 p-3 text-xs text-sky-700 dark:text-sky-300">
                    {t.assetNote}
                  </div>
                  <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                    <div className="space-y-1">
                      <Label>{t.assetCriticality}</Label>
                      <Controller
                        control={form.control}
                        name="assetCriticality"
                        render={({ field }) => (
                          <Select value={field.value} onValueChange={field.onChange}>
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {ASSET_CRITICALITIES.map((c) => (
                                <SelectItem key={c} value={c}>
                                  {c === "all" ? "— (tous)" : c}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        )}
                      />
                    </div>
                    <div className="space-y-1">
                      <Label>{t.assetStatus}</Label>
                      <Controller
                        control={form.control}
                        name="assetStatus"
                        render={({ field }) => (
                          <Select value={field.value} onValueChange={field.onChange}>
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {ASSET_STATUSES.map((s) => (
                                <SelectItem key={s} value={s}>
                                  {s === "all" ? "— (tous)" : s}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        )}
                      />
                    </div>
                  </div>
                </>
              )}

              <div className="grid grid-cols-1 gap-4 md:grid-cols-[2fr_1fr]">
                <div className="space-y-1">
                  <Label>{scope === "assets" ? t.assetSearch : t.search}</Label>
                  <Input
                    {...form.register("search")}
                    placeholder={scope === "assets" ? "AGL23, 192.168.1.207..." : "apache, log4j, ssrf..."}
                  />
                </div>
                <div className="space-y-1">
                  <Label>{t.limit}</Label>
                  <Input type="number" min={1} max={50000} {...form.register("limit")} />
                </div>
              </div>

              <div className="flex justify-end">
                <Button type="submit" disabled={generating}>
                  {generating ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" /> {t.generating}
                    </>
                  ) : (
                    <>
                      <Play className="mr-2 h-4 w-4" /> {t.generate}
                    </>
                  )}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </section>

      {/* Recent reports */}
      <section>
        <Card className="card-elevated">
          <CardHeader className="flex flex-row items-start justify-between gap-2">
            <div>
              <CardTitle className="flex items-center gap-2">
                <CalendarClock className="h-4 w-4" /> {t.listTitle}
              </CardTitle>
              <CardDescription>{reports.length} reports</CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={() => void refreshReports()}>
              <RefreshCw className="mr-2 h-4 w-4" /> {t.refresh}
            </Button>
          </CardHeader>
          <CardContent>
            {loadingList ? (
              <div className="flex items-center justify-center p-8 text-muted-foreground">
                <Loader2 className="h-5 w-5 animate-spin" />
              </div>
            ) : reports.length === 0 ? (
              <p className="p-8 text-center text-sm text-muted-foreground">{t.empty}</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t.columns.created}</TableHead>
                    <TableHead>{t.columns.format}</TableHead>
                    <TableHead>{t.columns.status}</TableHead>
                    <TableHead>{t.columns.filters}</TableHead>
                    <TableHead className="text-right">{t.columns.action}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {reports.map((r) => {
                    const a = r.attributes;
                    return (
                      <TableRow key={r.id}>
                        <TableCell className="text-xs">
                          {new Date(a.createdAt).toLocaleString(locale === "fr" ? "fr-FR" : "en-US")}
                          {a.completedAt && (
                            <div className="text-[10px] text-muted-foreground">
                              {((+new Date(a.completedAt) - +new Date(a.createdAt)) / 1000).toFixed(1)}s
                            </div>
                          )}
                        </TableCell>
                        <TableCell className="text-xs">
                          <span className="inline-flex items-center gap-1">
                            {formatIcon(a.format)}
                            {a.format === "PDF" ? "PDF (HTML)" : a.format}
                          </span>
                        </TableCell>
                        <TableCell className={`text-xs font-medium ${statusColor(a.status)}`}>
                          {a.status === "RUNNING" && (
                            <Loader2 className="mr-1 inline h-3 w-3 animate-spin" />
                          )}
                          {a.status === "FAILED" && (
                            <XCircle className="mr-1 inline h-3 w-3" />
                          )}
                          {a.status}
                          {a.errorMessage && (
                            <div className="mt-1 text-[10px] text-destructive">{a.errorMessage}</div>
                          )}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {summarizeFilter(a.filter)}
                        </TableCell>
                        <TableCell className="text-right">
                          {a.hasFile ? (
                            <div className="flex justify-end gap-1">
                              {a.format === "PDF" && (
                                <a
                                  href={`${r.links.download}?inline=1`}
                                  target="_blank"
                                  rel="noopener"
                                >
                                  <Button size="sm" variant="outline">
                                    {t.actions.view}
                                  </Button>
                                </a>
                              )}
                              <a href={r.links.download} download>
                                <Button size="sm">
                                  <Download className="mr-1 h-3 w-3" /> {t.actions.download}
                                </Button>
                              </a>
                            </div>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </section>
    </div>
  );
}

function MultiCheckGroup({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: string[];
  value: string[];
  onChange: (v: string[]) => void;
}) {
  const toggle = (opt: string, checked: boolean) => {
    onChange(checked ? [...value, opt] : value.filter((v) => v !== opt));
  };
  return (
    <div className="space-y-1">
      <Label>{label}</Label>
      <div className="flex flex-wrap gap-x-3 gap-y-2 rounded-md border bg-muted/30 p-3">
        {options.map((opt) => (
          <label key={opt} className="flex items-center gap-1.5 text-xs">
            <Checkbox
              checked={value.includes(opt)}
              onCheckedChange={(c) => toggle(opt, Boolean(c))}
            />
            <span>{opt}</span>
          </label>
        ))}
      </div>
    </div>
  );
}
