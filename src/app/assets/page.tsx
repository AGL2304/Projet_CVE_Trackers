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

export default function AssetsPage() {
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

      toast({ title: "Actif créé", description: `${values.name} ajouté.` });
      form.reset();
      setDialogOpen(false);
      await refetchAssets();
    } catch (error) {
      console.error(error);
      toast({
        title: "Erreur",
        description: "Impossible de créer l'actif.",
        variant: "destructive",
      });
    }
  });

  const deleteAsset = async (id: string) => {
    try {
      const response = await fetch(`/api/assets/${id}`, { method: "DELETE" });
      if (!response.ok) throw new Error("delete failed");

      toast({ title: "Actif supprimé" });
      await refetchAssets();
    } catch (error) {
      console.error(error);
      toast({
        title: "Erreur",
        description: "Suppression impossible.",
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

      if (rows.length <= 1) throw new Error("CSV vide");

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

      toast({ title: "Import CSV", description: `${imported}/${payloads.length} assets importés.` });
      await refetchAssets();
    } catch (error) {
      console.error(error);
      toast({
        title: "Import CSV échoué",
        description: "Vérifiez le format: name,type,ip,hostname,description,criticality,status",
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
          title="Assets indisponibles"
          description="Impossible de charger l'inventaire assets."
          actionLabel="Réessayer"
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
        title="Gestion des actifs"
        description="Inventaire serveurs/applications/containers avec mapping CVE et vue Attack Surface"
        actions={
          <>
            <label className="inline-flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-sm">
              <FileUp className="h-4 w-4" />
              {csvLoading ? "Import..." : "Import CSV"}
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
                  <Plus className="mr-2 h-4 w-4" /> Nouvel actif
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Créer un actif</DialogTitle>
                  <DialogDescription>Ajout manuel à l'inventaire SOC</DialogDescription>
                </DialogHeader>

                <Form {...form}>
                  <form onSubmit={createAsset} className="space-y-3">
                    <FormField
                      control={form.control}
                      name="name"
                      render={({ field }) => (
                        <FormItem>
                          <Label>Nom</Label>
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
                            <Label>Type</Label>
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
                            <Label>IP</Label>
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
                            <Label>Criticité</Label>
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
                            <Label>Statut</Label>
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
                      Ajouter
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
            <CardTitle>Inventaire des assets</CardTitle>
            <CardDescription>Mapping CVE par actif avec score d'exposition</CardDescription>
          </CardHeader>
          <CardContent>
            {mappedAssets.length === 0 ? (
              <EmptyState title="Aucun actif" description="Créez un actif ou importez un CSV pour commencer." />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Nom</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Criticité</TableHead>
                    <TableHead>CVEs liées</TableHead>
                    <TableHead>Attack score</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
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
            <CardTitle>Attack Surface</CardTitle>
            <CardDescription>Visualisation exposition par asset</CardDescription>
          </CardHeader>
          <CardContent>
            {treemapData.length === 0 ? (
              <EmptyState title="Pas de surface" description="Ajoutez des assets pour afficher la surface d'attaque." />
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
              Plus la surface est grande, plus l'exposition cumulative CVE est élevée.
            </div>
          </CardContent>
        </Card>
      </section>

      <Card className="card-elevated">
        <CardHeader>
          <CardTitle>Intégration CMDB</CardTitle>
          <CardDescription>Import en masse CSV prêt pour extension connecteur CMDB</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
            Format attendu: <code>name,type,ip,hostname,description,criticality,status</code>
            <br />
            La logique d'import est prête pour intégrer ultérieurement ServiceNow/GLPI/CMDB interne.
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