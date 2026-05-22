"use client";

import * as React from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { scaleLinear } from "d3-scale";
import { ResponsiveContainer, Treemap, Tooltip } from "recharts";
import { AlertTriangle, Database, FileUp, Plus, Trash2 } from "lucide-react";
import { useAssets, useCVEs } from "@/hooks/queries";
import { normalizeCve } from "@/lib/cve-helpers";
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
  Form,
  FormControl,
  FormField,
  FormItem,
  FormMessage,
} from "@/components/ui/form";
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
import { useUiPreferencesStore } from "@/store/ui-preferences";

const assetSchema = z.object({
  name: z.string().min(2, "Nom requis"),
  type: z.string().min(2, "Type requis"),
  ip: z.string().optional(),
  hostname: z.string().optional(),
  description: z.string().optional(),
  criticality: z.enum(["low", "medium", "high", "critical"]),
  status: z.enum(["active", "inactive", "retired"]),
});

type AssetFormValues = z.infer<typeof assetSchema>;

const copy = {
  fr: {
    title: "Gestion des actifs",
    description: "Inventaire serveurs/applications/containers avec mapping CVE",
    importCsv: "Import CSV",
    importing: "Import...",
    newAsset: "Nouvel actif",
    createAsset: "Creer un actif",
    createDesc: "Ajout manuel a l'inventaire SOC",
    assetCreated: "Actif cree",
    assetDeleted: "Actif supprime",
    createError: "Impossible de creer l'actif.",
    deleteError: "Suppression impossible.",
    csvOk: "Import CSV",
    csvFailed: "Import CSV echoue",
    csvFormat: "Verifiez le format: name,type,ip,hostname,description,criticality,status",
    emptyCsv: "CSV vide",
    unavailableTitle: "Assets indisponibles",
    unavailableDesc: "Impossible de charger l'inventaire assets.",
    retry: "Reessayer",
    inventoryTitle: "Inventaire des assets",
    inventoryDesc: "Mapping CVE par actif avec score d'exposition",
    noAssetTitle: "Aucun actif",
    noAssetDesc: "Creez un actif ou importez un CSV pour commencer.",
    name: "Nom",
    type: "Type",
    criticality: "Criticite",
    linkedCves: "CVEs liees",
    attackScore: "Attack score",
    actions: "Actions",
    surfaceTitle: "Surface d'attaque",
    surfaceDesc: "Visualisation exposition par asset",
    noSurfaceTitle: "Pas de surface",
    noSurfaceDesc: "Ajoutez des assets pour afficher la surface d'attaque.",
    surfaceHint: "Plus la surface est grande, plus l'exposition CVE est elevee.",
    cmdbTitle: "Integration CMDB",
    cmdbDesc: "CSV + connecteur CMDB (ServiceNow, GLPI, interne)",
    cmdbHint: "Format attendu: name,type,ip,hostname,description,criticality,status",
    cmdbConnectorNote: "Utilisez Administration > Actions CMDB pour tester et synchroniser l'inventaire.",
    add: "Ajouter",
    status: "Statut",
    ip: "IP",
  },
  en: {
    title: "Asset management",
    description: "Server/application/container inventory with CVE mapping",
    importCsv: "Import CSV",
    importing: "Importing...",
    newAsset: "New asset",
    createAsset: "Create asset",
    createDesc: "Manual addition to SOC inventory",
    assetCreated: "Asset created",
    assetDeleted: "Asset deleted",
    createError: "Unable to create asset.",
    deleteError: "Unable to delete asset.",
    csvOk: "CSV import",
    csvFailed: "CSV import failed",
    csvFormat: "Check format: name,type,ip,hostname,description,criticality,status",
    emptyCsv: "Empty CSV",
    unavailableTitle: "Assets unavailable",
    unavailableDesc: "Unable to load asset inventory.",
    retry: "Retry",
    inventoryTitle: "Asset inventory",
    inventoryDesc: "CVE mapping by asset with exposure score",
    noAssetTitle: "No asset",
    noAssetDesc: "Create an asset or import a CSV to start.",
    name: "Name",
    type: "Type",
    criticality: "Criticality",
    linkedCves: "Linked CVEs",
    attackScore: "Attack score",
    actions: "Actions",
    surfaceTitle: "Attack surface",
    surfaceDesc: "Exposure visualization by asset",
    noSurfaceTitle: "No surface",
    noSurfaceDesc: "Add assets to display attack surface.",
    surfaceHint: "Larger blocks represent higher cumulative CVE exposure.",
    cmdbTitle: "CMDB integration",
    cmdbDesc: "CSV + CMDB connector (ServiceNow, GLPI, internal)",
    cmdbHint: "Expected format: name,type,ip,hostname,description,criticality,status",
    cmdbConnectorNote: "Use Administration > CMDB actions to test and synchronize the inventory.",
    add: "Add",
    status: "Status",
    ip: "IP",
  },
} as const;

export default function AssetsPage() {
  const locale = useUiPreferencesStore((state) => state.locale);
  const t = copy[locale];
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [csvLoading, setCsvLoading] = React.useState(false);

  const { data: assets, isLoading: assetsLoading, isError: assetsError, refetch: refetchAssets } = useAssets();
  const { data: cves, isLoading: cvesLoading } = useCVEs();

  const cveRecords = React.useMemo(() => (cves ?? []).map(normalizeCve), [cves]);

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

  const mappedAssets = React.useMemo(() => {
    return (assets ?? []).map((asset) => {
      const name = asset.name.toLowerCase();
      const type = asset.type.toLowerCase();

      const linked = cveRecords.filter((cve) => {
        const source = `${cve.description} ${cve.product} ${cve.vendor}`.toLowerCase();
        return source.includes(name) || source.includes(type);
      });

      const exposureScore = linked.reduce((sum, row) => sum + (row.cvssScore ?? 4), 0);

      return {
        ...asset,
        linkedCves: linked,
        linkedCount: linked.length,
        exposureScore: Number(exposureScore.toFixed(1)),
      };
    });
  }, [assets, cveRecords]);

  const treemapData = React.useMemo(
    () =>
      mappedAssets.map((asset) => ({
        name: asset.name,
        size: Math.max(asset.exposureScore, 1),
        criticality: asset.criticality,
      })),
    [mappedAssets]
  );

  const createAsset = form.handleSubmit(async (values) => {
    try {
      const response = await fetch("/api/assets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
      });

      if (!response.ok) throw new Error("asset create failed");

      toast({ title: t.assetCreated, description: `${values.name}` });
      form.reset();
      setDialogOpen(false);
      await refetchAssets();
    } catch (error) {
      console.error(error);
      toast({
        title: "Erreur",
        description: t.createError,
        variant: "destructive",
      });
    }
  });

  const deleteAsset = async (id: string) => {
    try {
      const response = await fetch(`/api/assets/${id}`, { method: "DELETE" });
      if (!response.ok) throw new Error("delete failed");

      toast({ title: t.assetDeleted });
      await refetchAssets();
    } catch (error) {
      console.error(error);
      toast({
        title: "Erreur",
        description: t.deleteError,
        variant: "destructive",
      });
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
      const columns = header.split(",").map((part) => part.trim().toLowerCase());

      const payloads = dataRows.map((row) => {
        const cells = row.split(",").map((cell) => cell.trim());
        const entry: Record<string, string> = {};
        columns.forEach((column, index) => {
          entry[column] = cells[index] ?? "";
        });

        return {
          name: entry.name,
          type: entry.type || "server",
          ip: entry.ip || null,
          hostname: entry.hostname || null,
          description: entry.description || null,
          criticality: (entry.criticality || "medium") as AssetFormValues["criticality"],
          status: (entry.status || "active") as AssetFormValues["status"],
        };
      });

      let imported = 0;

      for (const payload of payloads) {
        const response = await fetch("/api/assets", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (response.ok) imported += 1;
      }

      toast({ title: t.csvOk, description: `${imported}/${payloads.length} assets` });
      await refetchAssets();
    } catch (error) {
      console.error(error);
      toast({
        title: t.csvFailed,
        description: t.csvFormat,
        variant: "destructive",
      });
    } finally {
      setCsvLoading(false);
    }
  };

  if (assetsLoading || cvesLoading) {
    return (
      <div className="p-6 lg:p-8">
        <LoadingGrid rows={8} />
      </div>
    );
  }

  if (assetsError) {
    return (
      <div className="p-6 lg:p-8">
        <EmptyState
          title={t.unavailableTitle}
          description={t.unavailableDesc}
          actionLabel={t.retry}
          onAction={() => {
            void refetchAssets();
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
        actions={
          <>
            <label className="inline-flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-sm">
              <FileUp className="h-4 w-4" />
              {csvLoading ? t.importing : t.importCsv}
              <input
                type="file"
                className="hidden"
                accept=".csv,text/csv"
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (file) {
                    void importCsv(file);
                    event.target.value = "";
                  }
                }}
              />
            </label>
            <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="mr-2 h-4 w-4" /> {t.newAsset}
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>{t.createAsset}</DialogTitle>
                  <DialogDescription>{t.createDesc}</DialogDescription>
                </DialogHeader>

                <Form {...form}>
                  <form onSubmit={createAsset} className="space-y-3">
                    <FormField
                      control={form.control}
                      name="name"
                      render={({ field }) => (
                        <FormItem>
                          <Label>{t.name}</Label>
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
                        name="type"
                        render={({ field }) => (
                          <FormItem>
                            <Label>{t.type}</Label>
                            <FormControl>
                              <Input {...field} />
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
                            <Label>{t.ip}</Label>
                            <FormControl>
                              <Input {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>

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
                                <SelectItem value="low">low</SelectItem>
                                <SelectItem value="medium">medium</SelectItem>
                                <SelectItem value="high">high</SelectItem>
                                <SelectItem value="critical">critical</SelectItem>
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
                                <SelectItem value="active">active</SelectItem>
                                <SelectItem value="inactive">inactive</SelectItem>
                                <SelectItem value="retired">retired</SelectItem>
                              </SelectContent>
                            </Select>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>

                    <Button type="submit" className="w-full">
                      {t.add}
                    </Button>
                  </form>
                </Form>
              </DialogContent>
            </Dialog>
          </>
        }
      />

      <section className="grid gap-4 xl:grid-cols-[1.45fr_1fr]">
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>{t.inventoryTitle}</CardTitle>
            <CardDescription>{t.inventoryDesc}</CardDescription>
          </CardHeader>
          <CardContent>
            {mappedAssets.length === 0 ? (
              <EmptyState title={t.noAssetTitle} description={t.noAssetDesc} />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t.name}</TableHead>
                    <TableHead>{t.type}</TableHead>
                    <TableHead>{t.criticality}</TableHead>
                    <TableHead>{t.linkedCves}</TableHead>
                    <TableHead>{t.attackScore}</TableHead>
                    <TableHead className="text-right">{t.actions}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {mappedAssets.map((asset) => (
                    <TableRow key={asset.id}>
                      <TableCell className="font-medium">{asset.name}</TableCell>
                      <TableCell>{asset.type}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{asset.criticality}</Badge>
                      </TableCell>
                      <TableCell>{asset.linkedCount}</TableCell>
                      <TableCell>{asset.exposureScore}</TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-2">
                          <Button variant="ghost" size="icon" onClick={() => void deleteAsset(asset.id)}>
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card className="card-elevated">
          <CardHeader>
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

      <Card className="card-elevated">
        <CardHeader>
          <CardTitle>{t.cmdbTitle}</CardTitle>
          <CardDescription>{t.cmdbDesc}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
            {t.cmdbHint}: <code>name,type,ip,hostname,description,criticality,status</code>
            <br />
            {t.cmdbConnectorNote}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function CustomizedTreemap(props: any) {
  const { x, y, width, height, name, value } = props;
  const intensity = scaleLinear<string>().domain([0, 100]).range(["#38bdf8", "#1e293b"])(Number(value));

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

