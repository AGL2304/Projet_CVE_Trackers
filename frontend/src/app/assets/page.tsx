"use client";

import * as React from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { scaleLinear } from "d3-scale";
import { ResponsiveContainer, Treemap, Tooltip } from "recharts";
import {
  AlertTriangle,
  ArrowDownAZ,
  ArrowUpAZ,
  Database,
  FileUp,
  Pencil,
  Plus,
  Search,
  Server,
  ShieldAlert,
  Trash2,
  X,
} from "lucide-react";
import { useAssetsPage } from "@/hooks/queries";
import { PageHeader } from "@/components/page-header";
import { EmptyState } from "@/components/states/empty-state";
import { LoadingGrid } from "@/components/states/loading-grid";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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

const CRITICALITIES = ["low", "medium", "high", "critical"] as const;
const STATUSES = ["active", "inactive", "retired"] as const;

const assetSchema = z.object({
  name: z.string().min(2, "Nom requis (≥ 2 caractères)").max(120),
  type: z.string().min(2, "Type requis").max(60),
  ip: z.string().optional(),
  hostname: z.string().optional(),
  description: z.string().optional(),
  criticality: z.enum(CRITICALITIES),
  status: z.enum(STATUSES),
});

type AssetFormValues = z.infer<typeof assetSchema>;

type AssetRow = {
  id: string;
  name: string;
  type: string;
  hostname: string | null;
  ip: string | null;
  criticality: string;
  status: string;
  description: string | null;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  _count?: { vulnerabilities: number; productLinks: number; tagLinks: number };
};

const copy = {
  fr: {
    title: "Gestion des actifs",
    description: "Inventaire serveurs/applications/containers avec cartographie des vulnérabilités",
    importCsv: "Import CSV",
    importing: "Import...",
    newAsset: "Nouvel actif",
    createAsset: "Créer un actif",
    editAsset: "Modifier l'actif",
    createDesc: "Ajout manuel à l'inventaire SOC",
    editDesc: "Modifier les informations de l'actif sélectionné",
    assetCreated: "Actif créé",
    assetUpdated: "Actif mis à jour",
    assetDeleted: "Actif supprimé",
    createError: "Impossible de créer l'actif.",
    updateError: "Mise à jour impossible.",
    deleteError: "Suppression impossible.",
    csvOk: "Import CSV",
    csvFailed: "Import CSV échoué",
    csvFormat: "Vérifiez le format: name,type,ip,hostname,description,criticality,status",
    csvDownload: "Modèle CSV",
    emptyCsv: "CSV vide",
    inventoryTitle: "Inventaire",
    noAssetTitle: "Aucun actif",
    noAssetDesc: "Créez un actif ou importez un CSV pour commencer.",
    noResultsTitle: "Aucun résultat",
    noResultsDesc: "Assouplissez les filtres pour afficher plus d'actifs.",
    surfaceTitle: "Surface d'attaque",
    surfaceDesc: "Répartition de l'exposition cumulée par actif (vulnérabilités liées + criticité)",
    surfaceHint: "Les blocs les plus grands représentent les actifs les plus exposés.",
    noSurfaceTitle: "Pas de surface",
    noSurfaceDesc: "Ajoutez des actifs et des vulnérabilités pour voir la surface.",
    filters: "Filtres",
    search: "Rechercher (nom, IP, hostname, description)",
    all: "Tous",
    name: "Nom",
    type: "Type",
    criticality: "Criticité",
    status: "Statut",
    ip: "IP / hostname",
    vulns: "Vulnérabilités",
    products: "Produits",
    actions: "Actions",
    add: "Ajouter",
    save: "Enregistrer",
    cancel: "Annuler",
    deleteConfirmTitle: "Supprimer cet actif ?",
    deleteConfirmDesc: "Cette action est irréversible. Les vulnérabilités liées seront détachées.",
    delete: "Supprimer",
    description2: "Description",
    kpiTotal: "Total actifs",
    kpiCritical: "Criticité critique",
    kpiActive: "Actifs en service",
    kpiVulns: "Avec vulnérabilités",
    sortHint: "Cliquez sur l'en-tête pour trier",
  },
  en: {
    title: "Asset management",
    description: "Server/application/container inventory with vulnerability mapping",
    importCsv: "Import CSV",
    importing: "Importing...",
    newAsset: "New asset",
    createAsset: "Create asset",
    editAsset: "Edit asset",
    createDesc: "Manual addition to SOC inventory",
    editDesc: "Modify the selected asset's information",
    assetCreated: "Asset created",
    assetUpdated: "Asset updated",
    assetDeleted: "Asset deleted",
    createError: "Unable to create asset.",
    updateError: "Unable to update asset.",
    deleteError: "Unable to delete asset.",
    csvOk: "CSV import",
    csvFailed: "CSV import failed",
    csvFormat: "Check format: name,type,ip,hostname,description,criticality,status",
    csvDownload: "CSV template",
    emptyCsv: "Empty CSV",
    inventoryTitle: "Inventory",
    noAssetTitle: "No asset",
    noAssetDesc: "Create an asset or import a CSV to start.",
    noResultsTitle: "No results",
    noResultsDesc: "Relax the filters to see more assets.",
    surfaceTitle: "Attack surface",
    surfaceDesc: "Cumulative exposure distribution by asset (linked vulnerabilities + criticality)",
    surfaceHint: "Larger blocks represent more exposed assets.",
    noSurfaceTitle: "No surface",
    noSurfaceDesc: "Add assets and vulnerabilities to view the surface.",
    filters: "Filters",
    search: "Search (name, IP, hostname, description)",
    all: "All",
    name: "Name",
    type: "Type",
    criticality: "Criticality",
    status: "Status",
    ip: "IP / hostname",
    vulns: "Vulnerabilities",
    products: "Products",
    actions: "Actions",
    add: "Add",
    save: "Save",
    cancel: "Cancel",
    deleteConfirmTitle: "Delete this asset?",
    deleteConfirmDesc: "This is irreversible. Linked vulnerabilities will be detached.",
    delete: "Delete",
    description2: "Description",
    kpiTotal: "Total assets",
    kpiCritical: "Critical criticality",
    kpiActive: "Active",
    kpiVulns: "With vulnerabilities",
    sortHint: "Click a header to sort",
  },
} as const;

const criticalityColor = (c: string) => {
  switch (c) {
    case "critical":
      return "bg-red-500/15 text-red-600 border-red-500/30";
    case "high":
      return "bg-orange-500/15 text-orange-600 border-orange-500/30";
    case "medium":
      return "bg-yellow-500/15 text-yellow-700 border-yellow-500/30";
    case "low":
      return "bg-emerald-500/15 text-emerald-700 border-emerald-500/30";
    default:
      return "";
  }
};

const statusColor = (s: string) => {
  switch (s) {
    case "active":
      return "bg-emerald-500/15 text-emerald-700 border-emerald-500/30";
    case "inactive":
      return "bg-slate-500/15 text-slate-600 border-slate-500/30";
    case "retired":
      return "bg-red-500/15 text-red-700 border-red-500/30";
    default:
      return "";
  }
};

export default function AssetsPage() {
  const locale = useUiPreferencesStore((state) => state.locale);
  const t = copy[locale];

  const [search, setSearch] = React.useState("");
  const [criticalityFilter, setCriticalityFilter] = React.useState("all");
  const [statusFilter, setStatusFilter] = React.useState("all");
  const [typeFilter, setTypeFilter] = React.useState("all");
  const [sortBy, setSortBy] = React.useState("createdAt");
  const [sortDir, setSortDir] = React.useState<"asc" | "desc">("desc");
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<AssetRow | null>(null);
  const [deleteTarget, setDeleteTarget] = React.useState<AssetRow | null>(null);
  const [csvLoading, setCsvLoading] = React.useState(false);

  // Debounce search to avoid hammering the API on every keystroke
  const [debouncedSearch, setDebouncedSearch] = React.useState(search);
  React.useEffect(() => {
    const handle = setTimeout(() => setDebouncedSearch(search), 250);
    return () => clearTimeout(handle);
  }, [search]);

  const { data, isLoading, isError, refetch } = useAssetsPage({
    search: debouncedSearch,
    criticality: criticalityFilter,
    status: statusFilter,
    type: typeFilter,
    sortBy,
    sortDir,
    pageSize: 200,
  });

  const assets = (data?.assets ?? []) as AssetRow[];
  const stats = data?.stats;

  // Distinct types for the type filter dropdown
  const types = React.useMemo(() => {
    const set = new Set<string>(assets.map((a) => a.type));
    return Array.from(set).sort();
  }, [assets]);

  const treemapData = React.useMemo(
    () =>
      assets.map((asset) => {
        const vulns = asset._count?.vulnerabilities ?? 0;
        const critWeight = { critical: 4, high: 3, medium: 2, low: 1 }[asset.criticality] ?? 1;
        return {
          name: asset.name,
          size: Math.max(1, vulns * 5 + critWeight),
          criticality: asset.criticality,
        };
      }),
    [assets]
  );

  const form = useForm<AssetFormValues>({
    resolver: zodResolver(assetSchema),
    defaultValues: {
      name: "",
      type: "server",
      ip: "",
      hostname: "",
      description: "",
      criticality: "medium",
      status: "active",
    },
  });

  React.useEffect(() => {
    if (editing) {
      form.reset({
        name: editing.name,
        type: editing.type,
        ip: editing.ip ?? "",
        hostname: editing.hostname ?? "",
        description: editing.description ?? "",
        criticality: editing.criticality as AssetFormValues["criticality"],
        status: editing.status as AssetFormValues["status"],
      });
      setDialogOpen(true);
    }
  }, [editing, form]);

  const saveAsset = form.handleSubmit(async (values) => {
    try {
      if (editing) {
        await fetchJson(`/api/assets/${editing.id}`, {
          method: "PUT",
          body: JSON.stringify(values),
        });
        toast({ title: t.assetUpdated, description: values.name });
      } else {
        await fetchJson("/api/assets", {
          method: "POST",
          body: JSON.stringify(values),
        });
        toast({ title: t.assetCreated, description: values.name });
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

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    try {
      await fetchJson(`/api/assets/${deleteTarget.id}`, { method: "DELETE" });
      toast({ title: t.assetDeleted, description: deleteTarget.name });
      setDeleteTarget(null);
      await refetch();
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      toast({ title: t.deleteError, description: message, variant: "destructive" });
    }
  };

  const importCsv = async (file: File) => {
    setCsvLoading(true);
    try {
      const text = await file.text();
      const rows = text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
      if (rows.length <= 1) throw new Error(t.emptyCsv);

      const [header, ...dataRows] = rows;
      const columns = header.split(",").map((c) => c.trim().toLowerCase());
      let imported = 0;
      let errors = 0;
      for (const row of dataRows) {
        const cells = row.split(",").map((c) => c.trim());
        const entry: Record<string, string> = {};
        columns.forEach((col, i) => {
          entry[col] = cells[i] ?? "";
        });
        try {
          await fetchJson("/api/assets", {
            method: "POST",
            body: JSON.stringify({
              name: entry.name,
              type: entry.type || "server",
              ip: entry.ip || null,
              hostname: entry.hostname || null,
              description: entry.description || null,
              criticality: (entry.criticality || "medium") as AssetFormValues["criticality"],
              status: (entry.status || "active") as AssetFormValues["status"],
            }),
          });
          imported++;
        } catch {
          errors++;
        }
      }
      toast({
        title: t.csvOk,
        description: `${imported} OK · ${errors} ${errors > 1 ? "errors" : "error"}`,
      });
      await refetch();
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      toast({
        title: t.csvFailed,
        description: message || t.csvFormat,
        variant: "destructive",
      });
    } finally {
      setCsvLoading(false);
    }
  };

  const downloadCsvTemplate = () => {
    const csv =
      "name,type,ip,hostname,description,criticality,status\n" +
      "web-prod-01,server,10.0.0.5,web1.local,Web frontend,high,active\n" +
      "db-prod-01,database,10.0.0.6,db1.local,Primary PostgreSQL,critical,active\n";
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "assets-template.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  const toggleSort = (key: string) => {
    if (sortBy === key) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortBy(key);
      setSortDir("asc");
    }
  };

  const resetFilters = () => {
    setSearch("");
    setCriticalityFilter("all");
    setStatusFilter("all");
    setTypeFilter("all");
  };

  const hasFilters =
    debouncedSearch || criticalityFilter !== "all" || statusFilter !== "all" || typeFilter !== "all";

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
          title="Assets indisponibles"
          description="Impossible de charger l'inventaire."
          actionLabel="Réessayer"
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
          <>
            <Button variant="outline" onClick={downloadCsvTemplate}>
              <Database className="mr-2 h-4 w-4" /> {t.csvDownload}
            </Button>
            <label className="inline-flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-sm hover:bg-accent">
              <FileUp className="h-4 w-4" />
              {csvLoading ? t.importing : t.importCsv}
              <input
                type="file"
                className="hidden"
                accept=".csv,text/csv"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) {
                    void importCsv(file);
                    e.target.value = "";
                  }
                }}
              />
            </label>
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
                  <Plus className="mr-2 h-4 w-4" /> {t.newAsset}
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>{editing ? t.editAsset : t.createAsset}</DialogTitle>
                  <DialogDescription>{editing ? t.editDesc : t.createDesc}</DialogDescription>
                </DialogHeader>

                <Form {...form}>
                  <form onSubmit={saveAsset} className="space-y-3">
                    <FormField
                      control={form.control}
                      name="name"
                      render={({ field }) => (
                        <FormItem>
                          <Label>{t.name}</Label>
                          <FormControl>
                            <Input {...field} placeholder="web-prod-01" />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <div className="grid gap-3 md:grid-cols-2">
                      <FormField
                        control={form.control}
                        name="type"
                        render={({ field }) => (
                          <FormItem>
                            <Label>{t.type}</Label>
                            <FormControl>
                              <Input {...field} placeholder="server / database / app..." />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="ip"
                        render={({ field }) => (
                          <FormItem>
                            <Label>IP</Label>
                            <FormControl>
                              <Input {...field} placeholder="10.0.0.5" />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>
                    <FormField
                      control={form.control}
                      name="hostname"
                      render={({ field }) => (
                        <FormItem>
                          <Label>Hostname</Label>
                          <FormControl>
                            <Input {...field} placeholder="web1.local" />
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
                          <Label>{t.description2}</Label>
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
                        name="criticality"
                        render={({ field }) => (
                          <FormItem>
                            <Label>{t.criticality}</Label>
                            <Select value={field.value} onValueChange={field.onChange}>
                              <FormControl>
                                <SelectTrigger>
                                  <SelectValue />
                                </SelectTrigger>
                              </FormControl>
                              <SelectContent>
                                {CRITICALITIES.map((c) => (
                                  <SelectItem key={c} value={c}>
                                    {c}
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
                    <Button type="submit" className="w-full">
                      {editing ? t.save : t.add}
                    </Button>
                  </form>
                </Form>
              </DialogContent>
            </Dialog>
          </>
        }
      />

      {/* KPIs */}
      <section className="grid gap-4 md:grid-cols-4">
        <KpiCard
          icon={<Database className="h-4 w-4" />}
          label={t.kpiTotal}
          value={stats?.total ?? assets.length}
        />
        <KpiCard
          icon={<ShieldAlert className="h-4 w-4 text-red-500" />}
          label={t.kpiCritical}
          value={stats?.byCriticality?.critical ?? 0}
          accent="text-red-600"
        />
        <KpiCard
          icon={<Server className="h-4 w-4 text-emerald-500" />}
          label={t.kpiActive}
          value={stats?.byStatus?.active ?? 0}
          accent="text-emerald-600"
        />
        <KpiCard
          icon={<AlertTriangle className="h-4 w-4 text-amber-500" />}
          label={t.kpiVulns}
          value={assets.filter((a) => (a._count?.vulnerabilities ?? 0) > 0).length}
          accent="text-amber-600"
        />
      </section>

      {/* Filters */}
      <Card className="card-elevated">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">{t.filters}</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-[2fr_1fr_1fr_1fr_auto]">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              className="pl-9"
              placeholder={t.search}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <Select value={criticalityFilter} onValueChange={setCriticalityFilter}>
            <SelectTrigger>
              <SelectValue placeholder={t.criticality} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t.all}</SelectItem>
              {CRITICALITIES.map((c) => (
                <SelectItem key={c} value={c}>
                  {c}
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
          <Select value={typeFilter} onValueChange={setTypeFilter}>
            <SelectTrigger>
              <SelectValue placeholder={t.type} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t.all}</SelectItem>
              {types.map((tp) => (
                <SelectItem key={tp} value={tp}>
                  {tp}
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

      <section className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        <Card className="card-elevated">
          <CardHeader className="pb-3">
            <CardTitle>{t.inventoryTitle}</CardTitle>
            <CardDescription>
              {assets.length} / {stats?.total ?? assets.length} · {t.sortHint}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {assets.length === 0 ? (
              <EmptyState
                title={hasFilters ? t.noResultsTitle : t.noAssetTitle}
                description={hasFilters ? t.noResultsDesc : t.noAssetDesc}
              />
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <SortableHead label={t.name} sortKey="name" current={sortBy} dir={sortDir} onClick={toggleSort} />
                      <SortableHead label={t.type} sortKey="type" current={sortBy} dir={sortDir} onClick={toggleSort} />
                      <TableHead>{t.ip}</TableHead>
                      <SortableHead label={t.criticality} sortKey="criticality" current={sortBy} dir={sortDir} onClick={toggleSort} />
                      <SortableHead label={t.status} sortKey="status" current={sortBy} dir={sortDir} onClick={toggleSort} />
                      <TableHead className="text-right">{t.vulns}</TableHead>
                      <TableHead className="text-right">{t.actions}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {assets.map((asset) => (
                      <TableRow key={asset.id}>
                        <TableCell className="font-medium">{asset.name}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">{asset.type}</TableCell>
                        <TableCell className="text-xs">
                          {asset.ip && <div className="font-mono">{asset.ip}</div>}
                          {asset.hostname && <div className="text-muted-foreground">{asset.hostname}</div>}
                          {!asset.ip && !asset.hostname && <span className="text-muted-foreground">—</span>}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={criticalityColor(asset.criticality)}>
                            {asset.criticality}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={statusColor(asset.status)}>
                            {asset.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {asset._count?.vulnerabilities ?? 0}
                        </TableCell>
                        <TableCell>
                          <div className="flex justify-end gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              title="Edit"
                              onClick={() => setEditing(asset)}
                            >
                              <Pencil className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              title="Delete"
                              onClick={() => setDeleteTarget(asset)}
                            >
                              <Trash2 className="h-4 w-4 text-destructive" />
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
          <CardHeader className="pb-3">
            <CardTitle>{t.surfaceTitle}</CardTitle>
            <CardDescription>{t.surfaceDesc}</CardDescription>
          </CardHeader>
          <CardContent>
            {treemapData.length === 0 ? (
              <EmptyState title={t.noSurfaceTitle} description={t.noSurfaceDesc} />
            ) : (
              <div className="h-[360px]">
                <ResponsiveContainer width="100%" height="100%">
                  <Treemap
                    data={treemapData}
                    dataKey="size"
                    stroke="var(--border)"
                    fill="#0ea5e9"
                    content={<CustomizedTreemap />}
                  >
                    <Tooltip formatter={(value) => [`${value}`, "Exposure"]} />
                  </Treemap>
                </ResponsiveContainer>
              </div>
            )}
            <div className="mt-3 rounded-md border bg-muted/40 p-3 text-xs text-muted-foreground">
              {t.surfaceHint}
            </div>
          </CardContent>
        </Card>
      </section>

      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.deleteConfirmTitle}</AlertDialogTitle>
            <AlertDialogDescription>
              {t.deleteConfirmDesc}
              {deleteTarget && (
                <div className="mt-2 rounded border bg-muted/40 p-2 text-sm font-mono">
                  {deleteTarget.name} ({deleteTarget.type})
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

function KpiCard({
  icon,
  label,
  value,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  accent?: string;
}) {
  return (
    <Card className="card-elevated">
      <CardContent className="flex items-center justify-between py-5">
        <div>
          <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
          <p className={`mt-1 text-2xl font-bold tabular-nums ${accent ?? ""}`}>{value}</p>
        </div>
        <div className="rounded-full bg-muted p-2">{icon}</div>
      </CardContent>
    </Card>
  );
}

function SortableHead({
  label,
  sortKey,
  current,
  dir,
  onClick,
}: {
  label: string;
  sortKey: string;
  current: string;
  dir: "asc" | "desc";
  onClick: (k: string) => void;
}) {
  const isActive = current === sortKey;
  return (
    <TableHead className="cursor-pointer select-none" onClick={() => onClick(sortKey)}>
      <span className="inline-flex items-center gap-1">
        {label}
        {isActive &&
          (dir === "asc" ? (
            <ArrowUpAZ className="h-3 w-3 opacity-70" />
          ) : (
            <ArrowDownAZ className="h-3 w-3 opacity-70" />
          ))}
      </span>
    </TableHead>
  );
}

function CustomizedTreemap(props: { x?: number; y?: number; width?: number; height?: number; name?: string; value?: number }) {
  const { x = 0, y = 0, width = 0, height = 0, name = "", value = 0 } = props;
  const intensity = scaleLinear<string>().domain([0, 50]).range(["#38bdf8", "#1e293b"])(Number(value));
  return (
    <g>
      <rect x={x} y={y} width={width} height={height} style={{ fill: intensity, stroke: "var(--border)" }} />
      {width > 80 && height > 24 ? (
        <text x={x + 6} y={y + 16} fill="#ffffff" fontSize={11}>
          {name}
        </text>
      ) : null}
    </g>
  );
}
