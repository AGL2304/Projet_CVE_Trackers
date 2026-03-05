"use client";

import * as React from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Plus, Search } from "lucide-react";
import { useAssets, useVulnerabilities } from "@/hooks/queries";
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

const vulnerabilitySchema = z.object({
  title: z.string().min(3, "Titre requis"),
  description: z.string().optional(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  status: z.enum(["open", "in_progress", "resolved", "ignored"]),
  cvssScore: z.string().optional(),
  cveId: z.string().optional(),
  assetId: z.string().optional(),
});

type VulnerabilityValues = z.infer<typeof vulnerabilitySchema>;

export default function VulnerabilitiesPage() {
  const { data: vulnerabilities, isLoading, isError, refetch } = useVulnerabilities();
  const { data: assets } = useAssets();

  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const [severityFilter, setSeverityFilter] = React.useState("all");
  const [statusFilter, setStatusFilter] = React.useState("all");

  const form = useForm<VulnerabilityValues>({
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

  const filtered = React.useMemo(() => {
    return (vulnerabilities ?? []).filter((item) => {
      const source = `${item.title} ${item.description ?? ""} ${item.cveId ?? ""}`.toLowerCase();
      const searchOk = search.trim().length === 0 || source.includes(search.toLowerCase());
      const severityOk = severityFilter === "all" || item.severity === severityFilter;
      const statusOk = statusFilter === "all" || item.status === statusFilter;
      return searchOk && severityOk && statusOk;
    });
  }, [vulnerabilities, search, severityFilter, statusFilter]);

  const createVulnerability = form.handleSubmit(async (values) => {
    const numericCvss = values.cvssScore ? Number.parseFloat(values.cvssScore) : undefined;

    try {
      const response = await fetch("/api/vulnerabilities", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...values,
          cvssScore: Number.isNaN(numericCvss) ? undefined : numericCvss,
        }),
      });

      if (!response.ok) throw new Error("create failed");

      toast({ title: "Vulnérabilité créée", description: values.title });
      form.reset();
      setDialogOpen(false);
      await refetch();
    } catch (error) {
      console.error(error);
      toast({ title: "Erreur", description: "Création impossible", variant: "destructive" });
    }
  });

  const updateStatus = async (id: string, status: string) => {
    const current = vulnerabilities?.find((item) => item.id === id);
    if (!current) return;

    try {
      const response = await fetch(`/api/vulnerabilities/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...current,
          status,
          assetId: current.asset?.id ?? null,
        }),
      });

      if (!response.ok) throw new Error("update failed");
      toast({ title: "Statut mis à jour", description: `${current.title} -> ${status}` });
      await refetch();
    } catch (error) {
      console.error(error);
      toast({ title: "Erreur", description: "Mise à jour impossible", variant: "destructive" });
    }
  };

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
          title="Vulnérabilités indisponibles"
          description="Impossible de charger le backlog de vulnérabilités."
          actionLabel="Réessayer"
          onAction={() => {
            void refetch();
          }}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6 lg:p-8">
      <PageHeader
        title="Vulnérabilités"
        description="Backlog opérationnel de suivi et remédiation"
        actions={
          <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" /> Nouvelle vulnérabilité
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Créer une vulnérabilité</DialogTitle>
                <DialogDescription>Déclaration manuelle d'une vulnérabilité interne</DialogDescription>
              </DialogHeader>

              <Form {...form}>
                <form className="space-y-3" onSubmit={createVulnerability}>
                  <FormField
                    control={form.control}
                    name="title"
                    render={({ field }) => (
                      <FormItem>
                        <Label>Titre</Label>
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
                        <Label>Description</Label>
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
                          <Label>Sévérité</Label>
                          <Select value={field.value} onValueChange={field.onChange}>
                            <FormControl>
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="critical">critical</SelectItem>
                              <SelectItem value="high">high</SelectItem>
                              <SelectItem value="medium">medium</SelectItem>
                              <SelectItem value="low">low</SelectItem>
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
                              <SelectItem value="open">open</SelectItem>
                              <SelectItem value="in_progress">in_progress</SelectItem>
                              <SelectItem value="resolved">resolved</SelectItem>
                              <SelectItem value="ignored">ignored</SelectItem>
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
                          <Label>CVSS</Label>
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
                          <Label>CVE ID</Label>
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
                        <Label>Asset lié</Label>
                        <Select value={field.value || "none"} onValueChange={(value) => field.onChange(value === "none" ? "" : value)}>
                          <FormControl>
                            <SelectTrigger>
                              <SelectValue placeholder="Sélection" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            <SelectItem value="none">None</SelectItem>
                            {(assets ?? []).map((asset) => (
                              <SelectItem key={asset.id} value={asset.id}>
                                {asset.name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <Button type="submit" className="w-full">
                    Enregistrer
                  </Button>
                </form>
              </Form>
            </DialogContent>
          </Dialog>
        }
      />

      <Card className="card-elevated">
        <CardHeader>
          <CardTitle>Filtres</CardTitle>
          <CardDescription>Recherche, sévérité et statut</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input className="pl-9" placeholder="Recherche..." value={search} onChange={(event) => setSearch(event.target.value)} />
          </div>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger>
              <SelectValue placeholder="Sévérité" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">all</SelectItem>
              <SelectItem value="critical">critical</SelectItem>
              <SelectItem value="high">high</SelectItem>
              <SelectItem value="medium">medium</SelectItem>
              <SelectItem value="low">low</SelectItem>
            </SelectContent>
          </Select>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger>
              <SelectValue placeholder="Statut" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">all</SelectItem>
              <SelectItem value="open">open</SelectItem>
              <SelectItem value="in_progress">in_progress</SelectItem>
              <SelectItem value="resolved">resolved</SelectItem>
              <SelectItem value="ignored">ignored</SelectItem>
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      <Card className="card-elevated">
        <CardHeader>
          <CardTitle>Backlog</CardTitle>
          <CardDescription>{filtered.length} élément(s)</CardDescription>
        </CardHeader>
        <CardContent>
          {filtered.length === 0 ? (
            <EmptyState title="Aucune vulnérabilité" description="Ajoutez des données ou assouplissez les filtres." />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Titre</TableHead>
                  <TableHead>Sévérité</TableHead>
                  <TableHead>CVSS</TableHead>
                  <TableHead>CVE</TableHead>
                  <TableHead>Asset</TableHead>
                  <TableHead>Statut</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className="font-medium">{item.title}</TableCell>
                    <TableCell>
                      <SeverityBadge value={item.severity} />
                    </TableCell>
                    <TableCell>{item.cvssScore?.toFixed(1) ?? "-"}</TableCell>
                    <TableCell>{item.cveId ? <Badge variant="outline">{item.cveId}</Badge> : "-"}</TableCell>
                    <TableCell>{item.asset?.name ?? "-"}</TableCell>
                    <TableCell>
                      <Select value={item.status} onValueChange={(value) => void updateStatus(item.id, value)}>
                        <SelectTrigger className="w-40">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="open">open</SelectItem>
                          <SelectItem value="in_progress">in_progress</SelectItem>
                          <SelectItem value="resolved">resolved</SelectItem>
                          <SelectItem value="ignored">ignored</SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
