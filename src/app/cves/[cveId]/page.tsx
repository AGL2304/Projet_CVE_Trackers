"use client";

import * as React from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  Radar,
  RadarChart,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  ResponsiveContainer,
} from "recharts";
import { ExternalLink, MessageSquare, ShieldCheck, Wrench } from "lucide-react";
import { useCVEs } from "@/hooks/queries";
import { normalizeCve, parseReferences, cveDate, cveRelativeDate } from "@/lib/cve-helpers";
import { SeverityBadge } from "@/components/severity-badge";
import { EmptyState } from "@/components/states/empty-state";
import { LoadingGrid } from "@/components/states/loading-grid";
import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
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
import { Slider } from "@/components/ui/slider";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useUiPreferencesStore } from "@/store/ui-preferences";

const commentSchema = z.object({
  author: z.string().min(2, "Nom requis"),
  message: z.string().min(4, "Commentaire trop court"),
});

type CommentValues = z.infer<typeof commentSchema>;

type InternalComment = {
  id: string;
  author: string;
  message: string;
  createdAt: string;
};

export default function CveDetailPage() {
  const params = useParams<{ cveId: string }>();
  const locale = useUiPreferencesStore((state) => state.locale);
  const { data, isLoading, isError, refetch } = useCVEs();

  const cve = React.useMemo(() => {
    const target = params.cveId;
    return (data ?? []).map(normalizeCve).find((item) => item.cveId === target);
  }, [data, params.cveId]);

  const [vector, setVector] = React.useState({
    attack: 8,
    complexity: 5,
    privileges: 6,
    interaction: 4,
    impact: 8,
  });

  const [comments, setComments] = React.useState<InternalComment[]>([]);

  const form = useForm<CommentValues>({
    resolver: zodResolver(commentSchema),
    defaultValues: {
      author: "",
      message: "",
    },
  });

  React.useEffect(() => {
    if (!params.cveId) return;
    const raw = localStorage.getItem(`cve-comments-${params.cveId}`);
    if (!raw) {
      setComments([]);
      return;
    }
    try {
      setComments(JSON.parse(raw) as InternalComment[]);
    } catch {
      setComments([]);
    }
  }, [params.cveId]);

  const addComment = form.handleSubmit((values) => {
    const next: InternalComment = {
      id: crypto.randomUUID(),
      author: values.author,
      message: values.message,
      createdAt: new Date().toISOString(),
    };

    const updated = [next, ...comments];
    setComments(updated);
    localStorage.setItem(`cve-comments-${params.cveId}`, JSON.stringify(updated));
    form.reset();
  });

  const score =
    (vector.attack + vector.complexity + vector.privileges + vector.interaction + vector.impact) /
    5;

  const radarData = [
    { metric: "Attack", value: vector.attack },
    { metric: "Complexity", value: vector.complexity },
    { metric: "Privileges", value: vector.privileges },
    { metric: "Interaction", value: vector.interaction },
    { metric: "Impact", value: vector.impact },
  ];

  if (isLoading) {
    return (
      <div className="p-6 lg:p-8">
        <LoadingGrid rows={8} cards={2} />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-6 lg:p-8">
        <EmptyState
          title="Erreur CVE"
          description="Impossible de charger les données CVE."
          actionLabel="Réessayer"
          onAction={() => {
            void refetch();
          }}
        />
      </div>
    );
  }

  if (!cve) {
    return (
      <div className="p-6 lg:p-8">
        <EmptyState title="CVE introuvable" description={`Aucun enregistrement pour ${params.cveId}.`} />
      </div>
    );
  }

  const references = parseReferences(cve.references);
  const products = [
    {
      vendor: cve.vendor,
      product: cve.product,
      minVersion: "< 1.0.0",
      maxVersion: "<= 2.9.x",
      patch: cve.vulnStatus?.toLowerCase().includes("analyzed") ? "Patch disponible" : "Workaround requis",
    },
  ];

  const history = [
    { label: "Publication NVD", date: cve.publishedDate ?? cve.importedAt, details: "Entrée publiée" },
    { label: "Dernière modification", date: cve.lastModifiedDate ?? cve.importedAt, details: "Mise à jour des métriques" },
    { label: "Import interne", date: cve.importedAt, details: "Synchronisé dans la plateforme" },
  ];

  return (
    <div className="space-y-6 p-6 lg:p-8">
      <PageHeader
        title={cve.cveId}
        description="Fiche CVE détaillée avec analyse, remédiation et collaboration interne"
        actions={<SeverityBadge value={cve.severity} />}
      />

      <section className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>Informations complètes</CardTitle>
            <CardDescription>{cve.description}</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-2">
            <InfoRow label="CVSS v3/v4" value={cve.cvssScore?.toFixed(1) ?? "N/A"} />
            <InfoRow label="Vecteur" value={cve.cvssVector ?? "N/A"} />
            <InfoRow label="CWE" value={cve.tags[0]?.toUpperCase() ?? "CWE-N/A"} />
            <InfoRow label="Statut NVD" value={cve.vulnStatus ?? "Unknown"} />
            <InfoRow label="Publication" value={cveDate(cve.publishedDate ?? cve.importedAt, locale)} />
            <InfoRow label="Dernière mise à jour" value={cveDate(cve.lastModifiedDate ?? cve.importedAt, locale)} />
          </CardContent>
        </Card>

        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>Liens publics</CardTitle>
            <CardDescription>Sources officielles et POC publics</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {references.length === 0 ? (
              <p className="text-sm text-muted-foreground">Aucune référence enregistrée.</p>
            ) : (
              references.map((reference) => (
                <a
                  key={reference}
                  href={reference}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center justify-between rounded-md border px-3 py-2 text-sm hover:bg-muted"
                >
                  <span className="truncate">{reference}</span>
                  <ExternalLink className="h-4 w-4" />
                </a>
              ))
            )}
            <a
              href={`https://www.exploit-db.com/search?cve=${cve.cveId}`}
              target="_blank"
              rel="noreferrer"
              className="flex items-center justify-between rounded-md border px-3 py-2 text-sm hover:bg-muted"
            >
              <span>Exploit-DB ({cve.cveId})</span>
              <ExternalLink className="h-4 w-4" />
            </a>
          </CardContent>
        </Card>
      </section>

      <Tabs defaultValue="products" className="space-y-4">
        <TabsList>
          <TabsTrigger value="products">Produits affectés</TabsTrigger>
          <TabsTrigger value="calculator">CVSS Calculator</TabsTrigger>
          <TabsTrigger value="history">Historique</TabsTrigger>
          <TabsTrigger value="comments">Commentaires</TabsTrigger>
          <TabsTrigger value="remediation">Remédiation</TabsTrigger>
        </TabsList>

        <TabsContent value="products">
          <Card className="card-elevated">
            <CardHeader>
              <CardTitle>Produits affectés</CardTitle>
              <CardDescription>Versions min/max et disponibilité des correctifs</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {products.map((product) => (
                <div key={`${product.vendor}-${product.product}`} className="rounded-lg border p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="font-medium">
                      {product.vendor} {product.product}
                    </p>
                    <Badge variant="outline">{product.patch}</Badge>
                  </div>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Versions: {product.minVersion} à {product.maxVersion}
                  </p>
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="calculator">
          <Card className="card-elevated">
            <CardHeader>
              <CardTitle>CVSS Calculator interactif</CardTitle>
              <CardDescription>Recalcul rapide avec visualisation radar</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 xl:grid-cols-[1fr_1.1fr]">
              <div className="space-y-4">
                <SliderField label="Attack Vector" value={vector.attack} onChange={(value) => setVector((current) => ({ ...current, attack: value }))} />
                <SliderField label="Attack Complexity" value={vector.complexity} onChange={(value) => setVector((current) => ({ ...current, complexity: value }))} />
                <SliderField label="Privileges" value={vector.privileges} onChange={(value) => setVector((current) => ({ ...current, privileges: value }))} />
                <SliderField label="User Interaction" value={vector.interaction} onChange={(value) => setVector((current) => ({ ...current, interaction: value }))} />
                <SliderField label="Impact" value={vector.impact} onChange={(value) => setVector((current) => ({ ...current, impact: value }))} />
                <div className="rounded-lg border bg-muted/40 p-3">
                  <p className="text-sm text-muted-foreground">Score estimé</p>
                  <p className="text-3xl font-semibold">{score.toFixed(1)}</p>
                </div>
              </div>

              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart data={radarData}>
                    <PolarGrid />
                    <PolarAngleAxis dataKey="metric" />
                    <PolarRadiusAxis domain={[0, 10]} />
                    <Radar dataKey="value" fill="#0ea5e9" fillOpacity={0.4} stroke="#0ea5e9" />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="history">
          <Card className="card-elevated">
            <CardHeader>
              <CardTitle>Historique des modifications</CardTitle>
              <CardDescription>Timeline auteur/date/diff</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {history.map((event) => (
                <div key={event.label} className="rounded-lg border p-3">
                  <div className="flex items-center justify-between">
                    <p className="font-medium">{event.label}</p>
                    <span className="text-xs text-muted-foreground">{cveDate(event.date, locale)}</span>
                  </div>
                  <p className="text-sm text-muted-foreground">{event.details}</p>
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="comments">
          <Card className="card-elevated">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <MessageSquare className="h-4 w-4" /> Commentaires & notes internes
              </CardTitle>
              <CardDescription>Fil de discussion par CVE</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Form {...form}>
                <form onSubmit={addComment} className="space-y-3">
                  <div className="grid gap-3 md:grid-cols-2">
                    <FormField
                      control={form.control}
                      name="author"
                      render={({ field }) => (
                        <FormItem>
                          <Label>Auteur</Label>
                          <FormControl>
                            <Input {...field} placeholder="Nom analyste" />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                  <FormField
                    control={form.control}
                    name="message"
                    render={({ field }) => (
                      <FormItem>
                        <Label>Commentaire</Label>
                        <FormControl>
                          <Textarea {...field} rows={4} placeholder="Contexte, évaluation, remédiation..." />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button type="submit">Ajouter note</Button>
                </form>
              </Form>

              <div className="space-y-2">
                {comments.length === 0 ? (
                  <EmptyState title="Aucun commentaire" description="Ajoutez la première note de suivi." />
                ) : (
                  comments.map((comment) => (
                    <div key={comment.id} className="rounded-lg border p-3">
                      <div className="flex items-center justify-between">
                        <p className="font-medium">{comment.author}</p>
                        <span className="text-xs text-muted-foreground">{cveRelativeDate(comment.createdAt, locale)}</span>
                      </div>
                      <p className="mt-1 text-sm text-muted-foreground">{comment.message}</p>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="remediation">
          <Card className="card-elevated">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Wrench className="h-4 w-4" /> Section remédiation
              </CardTitle>
              <CardDescription>Procédures, patchs et workarounds</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <RemediationItem
                title="Patch management"
                description="Déployer en priorité le correctif éditeur sur les assets exposés internet."
              />
              <RemediationItem
                title="Mesure compensatoire"
                description="Appliquer segmentation réseau et règles WAF/IPS ciblant la signature de l'exploit."
              />
              <RemediationItem
                title="Validation"
                description="Lancer scan post-patch puis ajouter preuve de correction dans la timeline interne."
              />
              <Button asChild variant="outline">
                <Link href="/reports">
                  <ShieldCheck className="mr-2 h-4 w-4" /> Ajouter au rapport de remédiation
                </Link>
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function SliderField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number;
  onChange: (value: number) => void;
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-sm">
        <span>{label}</span>
        <span className="font-medium">{value.toFixed(1)}</span>
      </div>
      <Slider value={[value]} min={0} max={10} step={0.1} onValueChange={(next) => onChange(next[0] ?? value)} />
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border bg-card p-3">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-1 text-sm font-medium">{value}</p>
    </div>
  );
}

function RemediationItem({ title, description }: { title: string; description: string }) {
  return (
    <div className="rounded-lg border bg-card p-3">
      <p className="font-medium">{title}</p>
      <p className="text-sm text-muted-foreground">{description}</p>
    </div>
  );
}