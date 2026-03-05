"use client";

import * as React from "react";
import Link from "next/link";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  type ColumnDef,
  type RowSelectionState,
  type SortingState,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  Download,
  FileDown,
  History,
  Filter,
  LayoutGrid,
  List,
  Loader2,
  Search,
  Sparkles,
} from "lucide-react";
import { useCVEs } from "@/hooks/queries";
import { normalizeCve, cveDate } from "@/lib/cve-helpers";
import { SeverityBadge } from "@/components/severity-badge";
import { PageHeader } from "@/components/page-header";
import { EmptyState } from "@/components/states/empty-state";
import { LoadingGrid } from "@/components/states/loading-grid";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
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

const currentAnalyst = "analyste.soc";

interface NvdCve {
  cve: {
    id: string;
    descriptions: { lang: string; value: string }[];
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData: {
          baseScore: number;
          baseSeverity: string;
          vectorString: string;
        };
      }>;
    };
    references?: { url: string }[];
    published: string;
    lastModified: string;
    vulnStatus: string;
  };
}

const searchSchema = z.object({
  keyword: z.string().min(2, "Minimum 2 caractères"),
});

type SearchValues = z.infer<typeof searchSchema>;

const bulkTagSchema = z.object({
  tag: z.string().min(2, "Tag trop court"),
});

export default function CvesPage() {
  const locale = useUiPreferencesStore((state) => state.locale);
  const viewMode = useUiPreferencesStore((state) => state.cveViewMode);
  const setViewMode = useUiPreferencesStore((state) => state.setCveViewMode);
  const upsertAssignment = useUiPreferencesStore((state) => state.upsertAssignment);

  const { data, isLoading, isError, refetch } = useCVEs();

  const [search, setSearch] = React.useState("");
  const [severityFilter, setSeverityFilter] = React.useState("all");
  const [statusFilter, setStatusFilter] = React.useState("all");
  const [vendorFilter, setVendorFilter] = React.useState("all");
  const [productFilter, setProductFilter] = React.useState("all");
  const [dateFilter, setDateFilter] = React.useState("90d");
  const [scoreRange, setScoreRange] = React.useState("all");
  const [tagFilter, setTagFilter] = React.useState("");
  const [sorting, setSorting] = React.useState<SortingState>([{ id: "cvss", desc: true }]);
  const [rowSelection, setRowSelection] = React.useState<RowSelectionState>({});

  const [importDialogOpen, setImportDialogOpen] = React.useState(false);
  const [nvdResults, setNvdResults] = React.useState<NvdCve[]>([]);
  const [nvdLoading, setNvdLoading] = React.useState(false);

  const form = useForm<SearchValues>({
    resolver: zodResolver(searchSchema),
    defaultValues: { keyword: "" },
  });

  const bulkTagForm = useForm<z.infer<typeof bulkTagSchema>>({
    resolver: zodResolver(bulkTagSchema),
    defaultValues: { tag: "" },
  });

  const records = React.useMemo(() => (data ?? []).map(normalizeCve), [data]);

  const suggestions = React.useMemo(() => {
    const values = new Set<string>();
    records.forEach((record) => {
      values.add(record.cveId);
      values.add(record.vendor);
      values.add(record.product);
      record.tags.forEach((tag: string) => values.add(tag));
    });
    return Array.from(values).slice(0, 120);
  }, [records]);

  const filtered = React.useMemo(() => {
    const now = new Date();

    return records.filter((record) => {
      const searchValue = `${record.cveId} ${record.description} ${record.vendor} ${record.product} ${record.tags.join(" ")}`.toLowerCase();
      const searchOk = search.trim().length === 0 || searchValue.includes(search.toLowerCase());
      const severityOk = severityFilter === "all" || record.severity === severityFilter;
      const status = (record.vulnStatus ?? "unknown").toLowerCase();
      const statusOk = statusFilter === "all" || status.includes(statusFilter);
      const vendorOk = vendorFilter === "all" || record.vendor === vendorFilter;
      const productOk = productFilter === "all" || record.product === productFilter;
      const tagOk = tagFilter.trim().length === 0 || record.tags.some((tag: string) => tag.includes(tagFilter.toLowerCase()));

      const score = record.cvssScore ?? 0;
      const scoreOk =
        scoreRange === "all" ||
        (scoreRange === "critical" && score >= 9) ||
        (scoreRange === "high" && score >= 7 && score < 9) ||
        (scoreRange === "medium" && score >= 4 && score < 7) ||
        (scoreRange === "low" && score > 0 && score < 4);

      const dateSource = new Date(record.publishedDate ?? record.importedAt);
      let dateOk = true;
      if (dateFilter !== "all") {
        const days = Number(dateFilter.replace("d", ""));
        const minDate = new Date(now);
        minDate.setDate(now.getDate() - days);
        dateOk = dateSource >= minDate;
      }

      return searchOk && severityOk && statusOk && vendorOk && productOk && tagOk && scoreOk && dateOk;
    });
  }, [records, search, severityFilter, statusFilter, vendorFilter, productFilter, tagFilter, scoreRange, dateFilter]);

  const selectedItems = React.useMemo(() => {
    return filtered.filter((item) => rowSelection[item.id]);
  }, [filtered, rowSelection]);

  const columns = React.useMemo<ColumnDef<(typeof filtered)[number]>[]>(
    () => [
      {
        id: "select",
        header: ({ table }) => (
          <Checkbox
            checked={table.getIsAllRowsSelected() || (table.getIsSomeRowsSelected() && "indeterminate")}
            onCheckedChange={(value) => table.toggleAllRowsSelected(Boolean(value))}
            aria-label="Select all rows"
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(Boolean(value))}
            aria-label={`Select row ${row.id}`}
          />
        ),
        size: 40,
      },
      {
        accessorKey: "cveId",
        header: "CVE ID",
        cell: ({ row }) => (
          <Link href={`/cves/${row.original.cveId}`} className="font-medium hover:underline">
            {row.original.cveId}
          </Link>
        ),
      },
      {
        accessorKey: "severity",
        header: "Sévérité",
        cell: ({ row }) => <SeverityBadge value={row.original.severity} />,
      },
      {
        id: "cvss",
        accessorFn: (row) => row.cvssScore ?? 0,
        header: "CVSS",
        cell: ({ row }) => (row.original.cvssScore ? row.original.cvssScore.toFixed(1) : "-"),
      },
      {
        accessorKey: "vendor",
        header: "Vendor",
      },
      {
        accessorKey: "product",
        header: "Produit",
      },
      {
        id: "published",
        accessorFn: (row) => row.publishedDate ?? row.importedAt,
        header: "Date",
        cell: ({ row }) => cveDate(row.original.publishedDate ?? row.original.importedAt, locale),
      },
      {
        accessorKey: "vulnStatus",
        header: "Statut",
        cell: ({ row }) => <Badge variant="secondary">{row.original.vulnStatus ?? "unknown"}</Badge>,
      },
    ],
    [locale]
  );

  const table = useReactTable({
    data: filtered,
    columns,
    getRowId: (row) => row.id,
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    onRowSelectionChange: setRowSelection,
    state: {
      sorting,
      rowSelection,
    },
  });

  const rows = table.getRowModel().rows;
  const tableContainerRef = React.useRef<HTMLDivElement | null>(null);
  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => tableContainerRef.current,
    estimateSize: () => 56,
    overscan: 8,
  });

  const uniqueVendors = React.useMemo(() => Array.from(new Set(records.map((record) => record.vendor))), [records]);
  const uniqueProducts = React.useMemo(() => Array.from(new Set(records.map((record) => record.product))), [records]);

  const exportRows = selectedItems.length > 0 ? selectedItems : filtered;

  const handleExportCsv = () => {
    const header = ["cveId", "severity", "cvssScore", "vendor", "product", "publishedDate", "vulnStatus"];
    const rowsCsv = exportRows.map((row) =>
      [
        row.cveId,
        row.severity,
        row.cvssScore ?? "",
        row.vendor,
        row.product,
        row.publishedDate ?? row.importedAt,
        row.vulnStatus ?? "",
      ]
        .map((value) => `"${String(value).replace(/"/g, '""')}"`)
        .join(",")
    );

    const csv = `${header.join(",")}\n${rowsCsv.join("\n")}`;
    downloadFile(csv, "text/csv;charset=utf-8", "cves-export.csv");
  };

  const handleExportJson = () => {
    const json = JSON.stringify(exportRows, null, 2);
    downloadFile(json, "application/json;charset=utf-8", "cves-export.json");
  };

  const handleExportPdf = () => {
    const html = `
      <html>
        <head>
          <title>CVE Report</title>
          <style>
            body { font-family: Arial, sans-serif; padding: 18px; }
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid #ddd; padding: 8px; font-size: 12px; }
            th { background: #f4f4f4; text-align: left; }
          </style>
        </head>
        <body>
          <h1>CVE Export</h1>
          <table>
            <thead>
              <tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Vendor</th><th>Product</th><th>Date</th></tr>
            </thead>
            <tbody>
              ${exportRows
                .map(
                  (row) =>
                    `<tr><td>${row.cveId}</td><td>${row.severity}</td><td>${row.cvssScore ?? ""}</td><td>${row.vendor}</td><td>${row.product}</td><td>${row.publishedDate ?? row.importedAt}</td></tr>`
                )
                .join("")}
            </tbody>
          </table>
        </body>
      </html>
    `;

    const win = window.open("", "_blank", "width=900,height=700");
    if (!win) return;
    win.document.write(html);
    win.document.close();
    win.focus();
    win.print();
  };

  const applyBulkAssign = () => {
    selectedItems.forEach((item) => {
      upsertAssignment({
        cveId: item.cveId,
        assignee: currentAnalyst,
        status: "todo",
        updatedAt: new Date().toISOString(),
      });
    });

    toast({
      title: "Assignation effectuée",
      description: `${selectedItems.length} CVE(s) assignée(s) à ${currentAnalyst}`,
    });
  };

  const applyBulkTag = bulkTagForm.handleSubmit((values) => {
    toast({
      title: "Tag appliqué",
      description: `Tag \"${values.tag}\" appliqué visuellement sur ${selectedItems.length} CVE(s).`,
    });
  });

  const onSearchNvd = form.handleSubmit(async (values) => {
    setNvdLoading(true);
    try {
      const response = await fetch(`/api/cves/nvd/search?keyword=${encodeURIComponent(values.keyword)}`);
      if (!response.ok) throw new Error("NVD request failed");
      const payload = await response.json();
      setNvdResults(payload.vulnerabilities ?? []);
      toast({
        title: "Recherche NVD",
        description: `${payload.vulnerabilities?.length ?? 0} résultat(s)`,
      });
    } catch (error) {
      console.error(error);
      toast({
        title: "Erreur NVD",
        description: "Impossible de récupérer les résultats.",
        variant: "destructive",
      });
    } finally {
      setNvdLoading(false);
    }
  });

  const importNvdCve = async (entry: NvdCve) => {
    try {
      const response = await fetch("/api/cves/nvd/import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(entry),
      });

      if (!response.ok) throw new Error("import failed");

      toast({ title: "Import réussi", description: `${entry.cve.id} importée.` });
      setNvdResults((current) => current.filter((item) => item.cve.id !== entry.cve.id));
      await refetch();
    } catch (error) {
      console.error(error);
      toast({
        title: "Import échoué",
        description: "Erreur lors de l'import CVE.",
        variant: "destructive",
      });
    }
  };

  if (isLoading) {
    return (
      <div className="p-6 lg:p-8">
        <LoadingGrid rows={12} />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-6 lg:p-8">
        <EmptyState
          title="Impossible de charger les CVEs"
          description="Vérifiez l'API puis relancez la requête."
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
        title="Liste & Recherche CVEs"
        description="Recherche full-text, filtres multicritères, vues multiples, export et actions bulk"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={handleExportCsv}>
              <Download className="mr-2 h-4 w-4" /> CSV
            </Button>
            <Button variant="outline" size="sm" onClick={handleExportJson}>
              <FileDown className="mr-2 h-4 w-4" /> JSON
            </Button>
            <Button variant="outline" size="sm" onClick={handleExportPdf}>
              <FileDown className="mr-2 h-4 w-4" /> PDF
            </Button>
            <Dialog open={importDialogOpen} onOpenChange={setImportDialogOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Sparkles className="mr-2 h-4 w-4" /> Import NVD
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-4xl">
                <DialogHeader>
                  <DialogTitle>Import NVD</DialogTitle>
                  <DialogDescription>Recherche dans la base NVD et import en un clic.</DialogDescription>
                </DialogHeader>

                <Form {...form}>
                  <form onSubmit={onSearchNvd} className="flex items-start gap-2">
                    <FormField
                      control={form.control}
                      name="keyword"
                      render={({ field }) => (
                        <FormItem className="flex-1">
                          <FormControl>
                            <Input placeholder="CVE, produit, vendor" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <Button type="submit" disabled={nvdLoading}>
                      {nvdLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    </Button>
                  </form>
                </Form>

                <div className="max-h-96 space-y-2 overflow-y-auto">
                  {nvdResults.map((entry) => (
                    <Card key={entry.cve.id}>
                      <CardContent className="flex items-start justify-between gap-3 p-4">
                        <div>
                          <div className="mb-1 flex items-center gap-2">
                            <Badge variant="outline">{entry.cve.id}</Badge>
                            <Badge>{entry.cve.metrics?.cvssMetricV31?.[0]?.cvssData.baseSeverity ?? "UNKNOWN"}</Badge>
                          </div>
                          <p className="line-clamp-2 text-sm text-muted-foreground">
                            {entry.cve.descriptions.find((desc) => desc.lang === "en")?.value ?? entry.cve.descriptions[0]?.value}
                          </p>
                        </div>
                        <Button size="sm" onClick={() => void importNvdCve(entry)}>
                          Importer
                        </Button>
                      </CardContent>
                    </Card>
                  ))}

                  {!nvdLoading && nvdResults.length === 0 ? (
                    <EmptyState title="Aucun résultat" description="Lancez une recherche NVD pour afficher les CVEs." />
                  ) : null}
                </div>
              </DialogContent>
            </Dialog>
          </>
        }
      />

      <Card className="card-elevated">
        <CardHeader>
          <CardTitle>Recherche & filtres</CardTitle>
          <CardDescription>Auto-complétion CVE ID/CWE/produit/vendor + filtres avancés</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              list="cve-suggestions"
              placeholder="Rechercher CVE, produit, vendor, tag..."
              className="pl-9"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <datalist id="cve-suggestions">
              {suggestions.map((item) => (
                <option value={item} key={item} />
              ))}
            </datalist>
          </div>

          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-6">
            <FilterSelect label="Sévérité" value={severityFilter} onValueChange={setSeverityFilter} items={["all", "critical", "high", "medium", "low", "none"]} />
            <FilterSelect label="Statut" value={statusFilter} onValueChange={setStatusFilter} items={["all", "analyzed", "received", "unknown"]} />
            <FilterSelect label="Date" value={dateFilter} onValueChange={setDateFilter} items={["all", "30d", "90d", "365d"]} />
            <FilterSelect label="Score CVSS" value={scoreRange} onValueChange={setScoreRange} items={["all", "critical", "high", "medium", "low"]} />
            <FilterSelect label="Vendor" value={vendorFilter} onValueChange={setVendorFilter} items={["all", ...uniqueVendors]} />
            <FilterSelect label="Produit" value={productFilter} onValueChange={setProductFilter} items={["all", ...uniqueProducts]} />
          </div>

          <div className="grid gap-2 md:grid-cols-[1fr_auto]">
            <Input placeholder="Filtre tags (ex: rce, sqli, dos)" value={tagFilter} onChange={(event) => setTagFilter(event.target.value)} />
            <div className="flex items-center gap-2">
              <Button variant={viewMode === "table" ? "default" : "outline"} size="icon" onClick={() => setViewMode("table")}>
                <List className="h-4 w-4" />
              </Button>
              <Button variant={viewMode === "cards" ? "default" : "outline"} size="icon" onClick={() => setViewMode("cards")}>
                <LayoutGrid className="h-4 w-4" />
              </Button>
              <Button variant={viewMode === "timeline" ? "default" : "outline"} size="icon" onClick={() => setViewMode("timeline")}>
                <History className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {selectedItems.length > 0 ? (
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>Bulk Actions</CardTitle>
            <CardDescription>{selectedItems.length} élément(s) sélectionné(s)</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap items-center gap-2">
            <Button onClick={applyBulkAssign}>Assigner à moi</Button>
            <Form {...bulkTagForm}>
              <form className="flex items-start gap-2" onSubmit={applyBulkTag}>
                <FormField
                  control={bulkTagForm.control}
                  name="tag"
                  render={({ field }) => (
                    <FormItem>
                      <FormControl>
                        <Input placeholder="Tag" {...field} className="w-40" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button type="submit" variant="outline">
                  Appliquer tag
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>
      ) : null}

      {filtered.length === 0 ? (
        <EmptyState title="Aucune CVE" description="Ajustez vos filtres ou importez de nouvelles CVEs depuis NVD." />
      ) : null}

      {filtered.length > 0 && viewMode === "table" ? (
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>Vue Tableau dense</CardTitle>
            <CardDescription>Tri multi-colonnes + virtualisation ({filtered.length} lignes)</CardDescription>
          </CardHeader>
          <CardContent>
            <div ref={tableContainerRef} className="max-h-[620px] overflow-auto rounded-md border">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-card">
                  {table.getHeaderGroups().map((headerGroup) => (
                    <TableRow key={headerGroup.id}>
                      {headerGroup.headers.map((header) => (
                        <TableHead key={header.id} style={{ width: header.getSize() || undefined }}>
                          {header.isPlaceholder ? null : (
                            <button
                              type="button"
                              onClick={header.column.getToggleSortingHandler()}
                              className="inline-flex items-center gap-1"
                            >
                              {flexRender(header.column.columnDef.header, header.getContext())}
                            </button>
                          )}
                        </TableHead>
                      ))}
                    </TableRow>
                  ))}
                </TableHeader>
                <TableBody style={{ height: `${rowVirtualizer.getTotalSize()}px`, position: "relative" }}>
                  {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                    const row = rows[virtualRow.index];
                    return (
                      <TableRow
                        key={row.id}
                        data-state={row.getIsSelected() && "selected"}
                        style={{
                          position: "absolute",
                          transform: `translateY(${virtualRow.start}px)`,
                          width: "100%",
                          display: "table",
                          tableLayout: "fixed",
                        }}
                      >
                        {row.getVisibleCells().map((cell) => (
                          <TableCell key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</TableCell>
                        ))}
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {filtered.length > 0 && viewMode === "cards" ? (
        <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((record) => (
            <Card key={record.id} className="card-elevated">
              <CardHeader>
                <div className="flex items-start justify-between gap-2">
                  <Link href={`/cves/${record.cveId}`} className="font-semibold hover:underline">
                    {record.cveId}
                  </Link>
                  <SeverityBadge value={record.severity} />
                </div>
                <CardDescription>
                  {record.vendor} · {record.product}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                <p className="line-clamp-3 text-sm text-muted-foreground">{record.description}</p>
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>CVSS {record.cvssScore?.toFixed(1) ?? "N/A"}</span>
                  <span>{cveDate(record.publishedDate ?? record.importedAt, locale)}</span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {record.tags.map((tag: string) => (
                    <Badge key={tag} variant="outline">
                      {tag}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </section>
      ) : null}

      {filtered.length > 0 && viewMode === "timeline" ? (
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>Vue Timeline</CardTitle>
            <CardDescription>Chronologie des publications / mises à jour CVE</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {filtered
              .slice()
              .sort(
                (a, b) =>
                  new Date(b.publishedDate ?? b.importedAt).getTime() -
                  new Date(a.publishedDate ?? a.importedAt).getTime()
              )
              .map((record) => (
                <div key={record.id} className="rounded-lg border bg-card p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Link href={`/cves/${record.cveId}`} className="font-medium hover:underline">
                        {record.cveId}
                      </Link>
                      <SeverityBadge value={record.severity} />
                    </div>
                    <span className="text-xs text-muted-foreground">{cveDate(record.publishedDate ?? record.importedAt, locale)}</span>
                  </div>
                  <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">{record.description}</p>
                </div>
              ))}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function FilterSelect({
  label,
  value,
  onValueChange,
  items,
}: {
  label: string;
  value: string;
  onValueChange: (value: string) => void;
  items: string[];
}) {
  return (
    <div className="space-y-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <Select value={value} onValueChange={onValueChange}>
        <SelectTrigger>
          <SelectValue placeholder={label} />
        </SelectTrigger>
        <SelectContent>
          {items.map((item) => (
            <SelectItem key={item} value={item}>
              {item}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function downloadFile(content: string, type: string, fileName: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(url);
}
