"use client";

import * as React from "react";
import Link from "next/link";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  CheckCircle2,
  Clock,
  ExternalLink,
  Pencil,
  Plus,
  Search,
  ShieldAlert,
  Trash2,
  X,
  XCircle,
} from "lucide-react";
import { useAssets, useVulnerabilitiesPage } from "@/hooks/queries";
import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { EmptyState } from "@/components/states/empty-state";
import { LoadingGrid } from "@/components/states/loading-grid";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "@/hooks/use-toast";
import { fetchJson } from "@/lib/api";
import { useUiPreferencesStore } from "@/store/ui-preferences";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const STATUSES = ["open", "in_progress", "resolved", "ignored"] as const;

const vulnerabilitySchema = z.object({
  title: z.string().min(3, "Title required").max(200),
  description: z.string().optional(),
  severity: z.enum(SEVERITIES),
  status: z.enum(STATUSES),
  cvssScore: z.string().optional(),
  cveId: z.string().optional(),
  assetId: z.string().optional(),
});

type VulnFormValues = z.infer<typeof vulnerabilitySchema>;

type Vulnerability = {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  cvssScore: number | null;
  cveId: string | null;
  discoveredAt: string;
  resolvedAt: string | null;
  asset: {
    id: string;
    name: string;
    type: string;
    hostname: string | null;
    ip: string | null;
    criticality?: string;
  } | null;
};

const copy = {
  fr: {
    title: "Vulnérabilités",
    description: "Backlog opérationnel — suivi, remédiation et SLA",
    newVuln: "Nouvelle vulnérabilité",
    createVuln: "Créer une vulnérabilité",
    editVuln: "Modifier la vulnérabilité",
    createDesc: "Déclaration manuelle d'une vulnérabilité interne",
    editDesc: "Modifier la vulnérabilité sélectionnée",
    filters: "Filtres",
    search: "Rechercher (titre, description, CVE...)",
    backlog: "Backlog",
    all: "Tous",
    asset: "Asset",
    noResultsTitle: "Aucun résultat",
    noResultsDesc: "Assouplissez les filtres ou créez une vulnérabilité.",
    created: "Vulnérabilité créée",
    updated: "Vulnérabilité mise à jour",
    deleted: "Vulnérabilité supprimée",
    createError: "Création impossible",
    updateError: "Mise à jour impossible",
    deleteError: "Suppression impossible",
    statusUpdated: "Statut mis à jour",
    quickResolve: "Marquer résolu",
    save: "Enregistrer",
    add: "Ajouter",
    cancel: "Annuler",
    delete: "Supprimer",
    titleCol: "Titre",
    severityCol: "Sévérité",
    statusCol: "Statut",
    discoveredCol: "Découverte",
    actionsCol: "Actions",
    none: "Aucun",
    kpiTotal: "Total",
    kpiOpen: "Ouvertes",
    kpiInProgress: "En cours",
    kpiResolved: "Résolues",
    kpiAvgCvss: "CVSS moyen",
    deleteConfirmTitle: "Supprimer cette vulnérabilité ?",
    deleteConfirmDesc: "Cette action est irréversible.",
    severity: "Sévérité",
    status: "Statut",
    titleField: "Titre",
    descField: "Description",
    cve: "CVE",
    cvss: "CVSS",
    linkedAsset: "Asset lié",
    none2: "—",
    daysOpen: "j ouvert",
    sortHint: "Cliquez sur une ligne pour modifier",
  },
  en: {
    title: "Vulnerabilities",
    description: "Operational backlog — tracking, remediation and SLA",
    newVuln: "New vulnerability",
    createVuln: "Create vulnerability",
    editVuln: "Edit vulnerability",
    createDesc: "Manual declaration of an internal vulnerability",
    editDesc: "Modify the selected vulnerability",
    filters: "Filters",
    search: "Search (title, description, CVE...)",
    backlog: "Backlog",
    all: "All",
    asset: "Asset",
    noResultsTitle: "No results",
    noResultsDesc: "Relax the filters or create a new vulnerability.",
    created: "Vulnerability created",
    updated: "Vulnerability updated",
    deleted: "Vulnerability deleted",
    createError: "Unable to create",
    updateError: "Update failed",
    deleteError: "Unable to delete",
    statusUpdated: "Status updated",
    quickResolve: "Mark resolved",
    save: "Save",
    add: "Add",
    cancel: "Cancel",
    delete: "Delete",
    titleCol: "Title",
    severityCol: "Severity",
    statusCol: "Status",
    discoveredCol: "Discovered",
    actionsCol: "Actions",
    none: "None",
    kpiTotal: "Total",
    kpiOpen: "Open",
    kpiInProgress: "In progress",
    kpiResolved: "Resolved",
    kpiAvgCvss: "Avg CVSS",
    deleteConfirmTitle: "Delete this vulnerability?",
    deleteConfirmDesc: "This is irreversible.",
    severity: "Severity",
    status: "Status",
    titleField: "Title",
    descField: "Description",
    cve: "CVE",
    cvss: "CVSS",
    linkedAsset: "Linked asset",
    none2: "—",
    daysOpen: "d open",
    sortHint: "Click a row to edit",
  },
} as const;

const statusBadge = (s: string) => {
  switch (s) {
    case "open":
      return "bg-amber-500/15 text-amber-700 border-amber-500/30";
    case "in_progress":
      return "bg-sky-500/15 text-sky-700 border-sky-500/30";
    case "resolved":
      return "bg-emerald-500/15 text-emerald-700 border-emerald-500/30";
    case "ignored":
      return "bg-slate-500/15 text-slate-600 border-slate-500/30";
    default:
      return "";
  }
};

export default function VulnerabilitiesPage() {
  const locale = useUiPreferencesStore((state) => state.locale);
  const t = copy[locale];
  const { data: assets } = useAssets();

  const [search, setSearch] = React.useState("");
  const [debouncedSearch, setDebouncedSearch] = React.useState("");
  const [severityFilter, setSeverityFilter] = React.useState("all");
  const [statusFilter, setStatusFilter] = React.useState("all");
  const [assetFilter, setAssetFilter] = React.useState("all");
  const [sortBy, setSortBy] = React.useState("createdAt");
  const [sortDir, setSortDir] = React.useState<"asc" | "desc">("desc");
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<Vulnerability | null>(null);
  const [deleteTarget, setDeleteTarget] = React.useState<Vulnerability | null>(null);

  React.useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 250);
    return () => clearTimeout(t);
  }, [search]);

  const { data, isLoading, isError, refetch } = useVulnerabilitiesPage({
    search: debouncedSearch,
    severity: severityFilter,
    status: statusFilter,
    assetId: assetFilter,
    sortBy,
    sortDir,
    limit: 200,
  });

  const items = (data?.vulnerabilities ?? []) as Vulnerability[];
  const stats = data?.stats;

  const form = useForm<VulnFormValues>({
    resolver: zodResolver(vulnerabilitySchema),
    defaultValues: {
      title: "",
      description: "",
      severity: "medium",
      status: "open",
      cvssScore: "5.0",
      cveId: "",
      assetId: "",
    },
  });

  React.useEffect(() => {
    if (editing) {
      form.reset({
        title: editing.title,
        description: editing.description ?? "",
        severity: editing.severity as VulnFormValues["severity"],
        status: editing.status as VulnFormValues["status"],
        cvssScore: editing.cvssScore != null ? String(editing.cvssScore) : "",
        cveId: editing.cveId ?? "",
        assetId: editing.asset?.id ?? "",
      });
      setDialogOpen(true);
    }
  }, [editing, form]);

  const save = form.handleSubmit(async (values) => {
    const numericCvss = values.cvssScore ? Number(values.cvssScore) : undefined;
    const payload = {
      ...values,
      cvssScore: Number.isNaN(numericCvss as number) ? null : numericCvss,
      assetId: values.assetId === "" || values.assetId === "none" ? null : values.assetId,
      cveId: values.cveId || null,
    };
    try {
      if (editing) {
        await fetchJson(`/api/vulnerabilities/${editing.id}`, {
          method: "PUT",
          body: JSON.stringify(payload),
        });
        toast({ title: t.updated, description: values.title });
      } else {
        await fetchJson("/api/vulnerabilities", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        toast({ title: t.created, description: values.title });
      }
      form.reset();
      setEditing(null);
      setDialogOpen(false);
      await refetch();
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      toast({
        title: editing ? t.updateError : t.createError,
        description: message,
        variant: "destructive",
      });
    }
  });

  const updateStatus = async (id: string, status: string) => {
    try {
      await fetchJson(`/api/vulnerabilities/${id}`, {
        method: "PUT",
        body: JSON.stringify({ status }),
      });
      toast({ title: t.statusUpdated });
      await refetch();
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      toast({ title: t.updateError, description: message, variant: "destructive" });
    }
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    try {
      await fetchJson(`/api/vulnerabilities/${deleteTarget.id}`, { method: "DELETE" });
      toast({ title: t.deleted, description: deleteTarget.title });
      setDeleteTarget(null);
      await refetch();
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      toast({ title: t.deleteError, description: message, variant: "destructive" });
    }
  };

  const resetFilters = () => {
    setSearch("");
    setSeverityFilter("all");
    setStatusFilter("all");
    setAssetFilter("all");
  };

  const hasFilters =
    debouncedSearch || severityFilter !== "all" || statusFilter !== "all" || assetFilter !== "all";

  const daysOpen = (item: Vulnerability) => {
    if (item.status === "resolved" || item.status === "ignored") return null;
    const ms = Date.now() - new Date(item.discoveredAt).getTime();
    return Math.floor(ms / (1000 * 60 * 60 * 24));
  };

  if (isLoading && !data) {
    return (
      <div className="p-6 lg:p-8">
        <LoadingGrid rows={8} />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-6 lg:p-8">
        <EmptyState
          title="Vulnerabilities unavailable"
          description="Unable to load the backlog."
          actionLabel="Retry"
          onAction={() => void refetch()}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6 lg:p-8">
      <PageHeader
        title={t.title}
        description={t.description}
        actions={
          <Dialog
            open={dialogOpen}
            onOpenChange={(open) => {
              setDialogOpen(open);
              if (!open) {
                setEditing(null);
                form.reset();
              }
            }}
          >
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" /> {t.newVuln}
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>{editing ? t.editVuln : t.createVuln}</DialogTitle>
                <DialogDescription>{editing ? t.editDesc : t.createDesc}</DialogDescription>
              </DialogHeader>

              <Form {...form}>
                <form className="space-y-3" onSubmit={save}>
                  <FormField
                    control={form.control}
                    name="title"
                    render={({ field }) => (
                      <FormItem>
                        <Label>{t.titleField}</Label>
                        <FormControl>
                          <Input {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="description"
                    render={({ field }) => (
                      <FormItem>
                        <Label>{t.descField}</Label>
                        <FormControl>
                          <Input {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <div className="grid gap-3 md:grid-cols-2">
                    <FormField
                      control={form.control}
                      name="severity"
                      render={({ field }) => (
                        <FormItem>
                          <Label>{t.severity}</Label>
                          <Select value={field.value} onValueChange={field.onChange}>
                            <FormControl>
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              {SEVERITIES.map((s) => (
                                <SelectItem key={s} value={s}>
                                  {s}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={form.control}
                      name="status"
                      render={({ field }) => (
                        <FormItem>
                          <Label>{t.status}</Label>
                          <Select value={field.value} onValueChange={field.onChange}>
                            <FormControl>
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              {STATUSES.map((s) => (
                                <SelectItem key={s} value={s}>
                                  {s}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                  <div className="grid gap-3 md:grid-cols-2">
                    <FormField
                      control={form.control}
                      name="cvssScore"
                      render={({ field }) => (
                        <FormItem>
                          <Label>{t.cvss}</Label>
                          <FormControl>
                            <Input type="number" min={0} max={10} step={0.1} {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={form.control}
                      name="cveId"
                      render={({ field }) => (
                        <FormItem>
                          <Label>{t.cve} ID</Label>
                          <FormControl>
                            <Input placeholder="CVE-2026-XXXX" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                  <FormField
                    control={form.control}
                    name="assetId"
                    render={({ field }) => (
                      <FormItem>
                        <Label>{t.linkedAsset}</Label>
                        <Select
                          value={field.value || "none"}
                          onValueChange={(value) => field.onChange(value === "none" ? "" : value)}
                        >
                          <FormControl>
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            <SelectItem value="none">{t.none}</SelectItem>
                            {(assets ?? []).map((a) => (
                              <SelectItem key={a.id} value={a.id}>
                                {a.name} ({a.type})
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button type="submit" className="w-full">
                    {editing ? t.save : t.add}
                  </Button>
                </form>
              </Form>
            </DialogContent>
          </Dialog>
        }
      />

      {/* KPIs */}
      <section className="grid gap-4 md:grid-cols-5">
        <Kpi label={t.kpiTotal} value={stats?.total ?? items.length} />
        <Kpi
          label={t.kpiOpen}
          value={stats?.byStatus?.open ?? 0}
          accent="text-amber-600"
          icon={<ShieldAlert className="h-4 w-4" />}
        />
        <Kpi
          label={t.kpiInProgress}
          value={stats?.byStatus?.in_progress ?? 0}
          accent="text-sky-600"
          icon={<Clock className="h-4 w-4" />}
        />
        <Kpi
          label={t.kpiResolved}
          value={stats?.byStatus?.resolved ?? 0}
          accent="text-emerald-600"
          icon={<CheckCircle2 className="h-4 w-4" />}
        />
        <Kpi label={t.kpiAvgCvss} value={(stats?.avgCvss ?? 0).toFixed(2)} />
      </section>

      {/* Filters */}
      <Card className="card-elevated">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">{t.filters}</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-[2fr_1fr_1fr_1.4fr_auto]">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              className="pl-9"
              placeholder={t.search}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger>
              <SelectValue placeholder={t.severity} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t.all}</SelectItem>
              {SEVERITIES.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger>
              <SelectValue placeholder={t.status} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t.all}</SelectItem>
              {STATUSES.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={assetFilter} onValueChange={setAssetFilter}>
            <SelectTrigger>
              <SelectValue placeholder={t.asset} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t.all}</SelectItem>
              {(assets ?? []).map((a) => (
                <SelectItem key={a.id} value={a.id}>
                  {a.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            variant="ghost"
            size="icon"
            onClick={resetFilters}
            disabled={!hasFilters}
            title="Reset filters"
          >
            <X className="h-4 w-4" />
          </Button>
        </CardContent>
      </Card>

      <Card className="card-elevated">
        <CardHeader className="pb-3">
          <CardTitle>{t.backlog}</CardTitle>
          <CardDescription>
            {items.length} / {stats?.total ?? items.length} · {t.sortHint}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {items.length === 0 ? (
            <EmptyState title={t.noResultsTitle} description={t.noResultsDesc} />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t.titleCol}</TableHead>
                    <TableHead>{t.severityCol}</TableHead>
                    <TableHead className="text-right">{t.cvss}</TableHead>
                    <TableHead>{t.cve}</TableHead>
                    <TableHead>{t.asset}</TableHead>
                    <TableHead>{t.statusCol}</TableHead>
                    <TableHead className="text-right">{t.discoveredCol}</TableHead>
                    <TableHead className="text-right">{t.actionsCol}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((item) => {
                    const open = daysOpen(item);
                    return (
                      <TableRow key={item.id}>
                        <TableCell className="font-medium">
                          <div>{item.title}</div>
                          {item.description && (
                            <div className="mt-0.5 text-xs text-muted-foreground line-clamp-1">
                              {item.description}
                            </div>
                          )}
                        </TableCell>
                        <TableCell>
                          <SeverityBadge value={item.severity} />
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {item.cvssScore != null ? item.cvssScore.toFixed(1) : "—"}
                        </TableCell>
                        <TableCell>
                          {item.cveId ? (
                            <Link
                              href={`/cves/${item.cveId}`}
                              className="inline-flex items-center gap-1 text-sky-600 hover:underline"
                            >
                              <Badge variant="outline">{item.cveId}</Badge>
                              <ExternalLink className="h-3 w-3" />
                            </Link>
                          ) : (
                            <span className="text-muted-foreground">{t.none2}</span>
                          )}
                        </TableCell>
                        <TableCell>
                          {item.asset ? (
                            <div className="text-xs">
                              <div className="font-medium">{item.asset.name}</div>
                              <div className="text-muted-foreground">{item.asset.type}</div>
                            </div>
                          ) : (
                            <span className="text-muted-foreground">{t.none2}</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Select
                            value={item.status}
                            onValueChange={(value) => void updateStatus(item.id, value)}
                          >
                            <SelectTrigger className={`h-8 w-36 text-xs ${statusBadge(item.status)}`}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {STATUSES.map((s) => (
                                <SelectItem key={s} value={s}>
                                  {s}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </TableCell>
                        <TableCell className="text-right text-xs">
                          <div>{new Date(item.discoveredAt).toLocaleDateString()}</div>
                          {open !== null && (
                            <div className={`mt-0.5 ${open > 30 ? "text-red-600" : "text-muted-foreground"}`}>
                              {open}{t.daysOpen}
                            </div>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex justify-end gap-1">
                            {item.status !== "resolved" && (
                              <Button
                                variant="ghost"
                                size="icon"
                                title={t.quickResolve}
                                onClick={() => void updateStatus(item.id, "resolved")}
                              >
                                <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                              </Button>
                            )}
                            <Button
                              variant="ghost"
                              size="icon"
                              title="Edit"
                              onClick={() => setEditing(item)}
                            >
                              <Pencil className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              title="Delete"
                              onClick={() => setDeleteTarget(item)}
                            >
                              <Trash2 className="h-4 w-4 text-destructive" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.deleteConfirmTitle}</AlertDialogTitle>
            <AlertDialogDescription>
              {t.deleteConfirmDesc}
              {deleteTarget && (
                <div className="mt-2 rounded border bg-muted/40 p-2 text-sm">
                  <span className="font-medium">{deleteTarget.title}</span>
                </div>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.cancel}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => void confirmDelete()}
            >
              {t.delete}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function Kpi({
  label,
  value,
  accent,
  icon,
}: {
  label: string;
  value: number | string;
  accent?: string;
  icon?: React.ReactNode;
}) {
  return (
    <Card className="card-elevated">
      <CardContent className="flex items-center justify-between py-4">
        <div>
          <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
          <p className={`mt-1 text-2xl font-bold tabular-nums ${accent ?? ""}`}>{value}</p>
        </div>
        {icon && <div className="rounded-full bg-muted p-2">{icon}</div>}
      </CardContent>
    </Card>
  );
}
