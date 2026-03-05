"use client";

import * as React from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  DndContext,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import {
  SortableContext,
  verticalListSortingStrategy,
  arrayMove,
  useSortable,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { CalendarClock, Download, GripVertical, Mail, WandSparkles } from "lucide-react";
import { useCVEs, useVulnerabilities } from "@/hooks/queries";
import { normalizeCve } from "@/lib/cve-helpers";
import { PageHeader } from "@/components/page-header";
import { LoadingGrid } from "@/components/states/loading-grid";
import { EmptyState } from "@/components/states/empty-state";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Switch } from "@/components/ui/switch";
import { toast } from "@/hooks/use-toast";

const defaultMetrics = [
  "Total CVEs",
  "Critical CVEs",
  "Average CVSS",
  "SLA Compliance",
  "Top Exposed Assets",
  "New CVEs 7d",
];

const scheduleSchema = z.object({
  reportType: z.enum(["executive", "distribution", "sla", "custom"]),
  cadence: z.enum(["daily", "weekly", "monthly"]),
  email: z.string().email("Email invalide"),
  enabled: z.boolean(),
});

type ScheduleValues = z.infer<typeof scheduleSchema>;

export default function ReportsPage() {
  const { data: cves, isLoading: cvesLoading } = useCVEs();
  const { data: vulnerabilities, isLoading: vulnLoading } = useVulnerabilities();

  const [metrics, setMetrics] = React.useState(defaultMetrics);
  const [branding, setBranding] = React.useState({
    logo: "/logo.svg",
    primaryColor: "#0ea5e9",
    company: "CVE Tracker SOC",
  });

  const sensors = useSensors(useSensor(PointerSensor));

  const form = useForm<ScheduleValues>({
    resolver: zodResolver(scheduleSchema),
    defaultValues: {
      reportType: "executive",
      cadence: "weekly",
      email: "soc@company.local",
      enabled: true,
    },
  });

  const rows = React.useMemo(() => (cves ?? []).map(normalizeCve), [cves]);

  const summary = React.useMemo(() => {
    const critical = rows.filter((row) => row.severity === "critical").length;
    const avgCvss = rows.length
      ? rows.reduce((sum, row) => sum + (row.cvssScore ?? 0), 0) / rows.length
      : 0;

    const resolved = (vulnerabilities ?? []).filter((item) => item.status === "resolved").length;
    const sla = vulnerabilities?.length ? (resolved / vulnerabilities.length) * 100 : 0;

    return {
      total: rows.length,
      critical,
      avgCvss: avgCvss.toFixed(1),
      sla: sla.toFixed(1),
    };
  }, [rows, vulnerabilities]);

  const onDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) return;

    const oldIndex = metrics.indexOf(String(active.id));
    const newIndex = metrics.indexOf(String(over.id));
    setMetrics((current) => arrayMove(current, oldIndex, newIndex));
  };

  const exportPdf = (preset: string) => {
    const html = `
      <html>
        <head>
          <title>${preset}</title>
          <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            .title { color: ${branding.primaryColor}; font-size: 22px; margin-bottom: 10px; }
            .kpi { margin-bottom: 8px; }
          </style>
        </head>
        <body>
          <div class="title">${branding.company} - ${preset}</div>
          <div class="kpi">Total CVEs: ${summary.total}</div>
          <div class="kpi">Critical CVEs: ${summary.critical}</div>
          <div class="kpi">Average CVSS: ${summary.avgCvss}</div>
          <div class="kpi">SLA Compliance: ${summary.sla}%</div>
          <hr />
          <div>Metrics order: ${metrics.join(" / ")}</div>
        </body>
      </html>
    `;

    const popup = window.open("", "_blank", "width=900,height=700");
    if (!popup) return;
    popup.document.write(html);
    popup.document.close();
    popup.focus();
    popup.print();
  };

  const schedule = form.handleSubmit((values) => {
    toast({
      title: "Planification enregistrée",
      description: `${values.reportType} envoyé en ${values.cadence} vers ${values.email}`,
    });
  });

  if (cvesLoading || vulnLoading) {
    return (
      <div className="p-6 lg:p-8">
        <LoadingGrid rows={8} />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6 lg:p-8">
      <PageHeader
        title="Reporting & Analytics"
        description="Rapports prédéfinis, constructeur personnalisable, export PDF et planification email"
      />

      <section className="grid gap-4 lg:grid-cols-3">
        <ReportCard
          title="Executive Summary"
          description="Synthèse risque global pour direction"
          onExport={() => exportPdf("Executive Summary")}
        />
        <ReportCard
          title="CVSS Distribution"
          description="Répartition par score/severity"
          onExport={() => exportPdf("CVSS Distribution")}
        />
        <ReportCard
          title="SLA Compliance"
          description="Suivi conformité délais de correction"
          onExport={() => exportPdf("SLA Compliance")}
        />
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <WandSparkles className="h-4 w-4" /> Constructeur glisser-déposer
            </CardTitle>
            <CardDescription>Réordonnez les métriques pour composer un rapport personnalisé</CardDescription>
          </CardHeader>
          <CardContent>
            <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={onDragEnd}>
              <SortableContext items={metrics} strategy={verticalListSortingStrategy}>
                <div className="space-y-2">
                  {metrics.map((metric) => (
                    <SortableMetric key={metric} id={metric} />
                  ))}
                </div>
              </SortableContext>
            </DndContext>

            <Button className="mt-4" onClick={() => exportPdf("Custom Report")}>Exporter le rapport custom</Button>
          </CardContent>
        </Card>

        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>Branding PDF</CardTitle>
            <CardDescription>Logo et charte export configurable</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Label>Entreprise</Label>
            <Input value={branding.company} onChange={(event) => setBranding((state) => ({ ...state, company: event.target.value }))} />
            <Label>Logo URL</Label>
            <Input value={branding.logo} onChange={(event) => setBranding((state) => ({ ...state, logo: event.target.value }))} />
            <Label>Couleur principale</Label>
            <Input type="color" value={branding.primaryColor} onChange={(event) => setBranding((state) => ({ ...state, primaryColor: event.target.value }))} />
          </CardContent>
        </Card>
      </section>

      <section>
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CalendarClock className="h-4 w-4" /> Planification des rapports
            </CardTitle>
            <CardDescription>Envoi récurrent par email</CardDescription>
          </CardHeader>
          <CardContent>
            <Form {...form}>
              <form className="grid gap-4 md:grid-cols-2" onSubmit={schedule}>
                <FormField
                  control={form.control}
                  name="reportType"
                  render={({ field }) => (
                    <FormItem>
                      <Label>Type de rapport</Label>
                      <Select value={field.value} onValueChange={field.onChange}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="executive">Executive Summary</SelectItem>
                          <SelectItem value="distribution">CVSS Distribution</SelectItem>
                          <SelectItem value="sla">SLA Compliance</SelectItem>
                          <SelectItem value="custom">Custom</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="cadence"
                  render={({ field }) => (
                    <FormItem>
                      <Label>Cadence</Label>
                      <Select value={field.value} onValueChange={field.onChange}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="daily">Daily</SelectItem>
                          <SelectItem value="weekly">Weekly</SelectItem>
                          <SelectItem value="monthly">Monthly</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="email"
                  render={({ field }) => (
                    <FormItem>
                      <Label>Email de destination</Label>
                      <FormControl>
                        <Input {...field} type="email" placeholder="secops@company.local" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="enabled"
                  render={({ field }) => (
                    <FormItem className="flex items-center justify-between rounded-md border p-3">
                      <div>
                        <Label>Activer l'envoi automatique</Label>
                        <p className="text-xs text-muted-foreground">Scheduler mail prêt pour intégration backend</p>
                      </div>
                      <FormControl>
                        <Switch checked={field.value} onCheckedChange={field.onChange} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <Button type="submit" className="md:col-span-2">
                  <Mail className="mr-2 h-4 w-4" /> Enregistrer la planification
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>
      </section>

      {rows.length === 0 ? <EmptyState title="Aucune donnée" description="Importez des CVEs pour générer des rapports." /> : null}
    </div>
  );
}

function ReportCard({
  title,
  description,
  onExport,
}: {
  title: string;
  description: string;
  onExport: () => void;
}) {
  return (
    <Card className="card-elevated">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <Button onClick={onExport}>
          <Download className="mr-2 h-4 w-4" /> Export PDF
        </Button>
      </CardContent>
    </Card>
  );
}

function SortableMetric({ id }: { id: string }) {
  const { attributes, listeners, setNodeRef, transform, transition } = useSortable({ id });

  return (
    <div
      ref={setNodeRef}
      style={{ transform: CSS.Transform.toString(transform), transition }}
      className="flex items-center justify-between rounded-md border bg-card px-3 py-2"
    >
      <span className="text-sm font-medium">{id}</span>
      <button type="button" className="cursor-grab text-muted-foreground" {...attributes} {...listeners}>
        <GripVertical className="h-4 w-4" />
      </button>
    </div>
  );
}