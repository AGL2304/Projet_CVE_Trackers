"use client";

import * as React from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Check, Database, Palette, Shield, Users } from "lucide-react";
import { PageHeader } from "@/components/page-header";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "@/hooks/use-toast";
import { useUiPreferencesStore } from "@/store/ui-preferences";

const dataSourceSchema = z.object({
  nvdApiKey: z.string().optional(),
  cmdbEndpoint: z.string().url("URL invalide").or(z.literal("")),
  webhookUrl: z.string().url("URL invalide").or(z.literal("")),
});

type DataSourceValues = z.infer<typeof dataSourceSchema>;

const rbacMatrix = [
  { role: "Admin", users: 2, cves: true, assets: true, reports: true, settings: true },
  { role: "Analyst", users: 12, cves: true, assets: true, reports: true, settings: false },
  { role: "Viewer", users: 18, cves: true, assets: true, reports: true, settings: false },
];

export default function SettingsPage() {
  const locale = useUiPreferencesStore((state) => state.locale);
  const setLocale = useUiPreferencesStore((state) => state.setLocale);
  const themePreference = useUiPreferencesStore((state) => state.themePreference);
  const setThemePreference = useUiPreferencesStore((state) => state.setThemePreference);

  const [alerts, setAlerts] = React.useState({
    criticalEmail: true,
    digest: true,
    slack: false,
  });

  const [branding, setBranding] = React.useState({
    appName: "CVE Tracker",
    logoUrl: "/logo.svg",
    primary: "#0ea5e9",
  });

  const form = useForm<DataSourceValues>({
    resolver: zodResolver(dataSourceSchema),
    defaultValues: {
      nvdApiKey: "",
      cmdbEndpoint: "",
      webhookUrl: "",
    },
  });

  const saveDataSources = form.handleSubmit((values) => {
    toast({
      title: "Sources mises à jour",
      description: `NVD key: ${values.nvdApiKey ? "configurée" : "non configurée"}`,
    });
  });

  return (
    <div className="space-y-6 p-6 lg:p-8">
      <PageHeader
        title="Administration & Settings"
        description="RBAC, intégrations, notifications, branding et préférences utilisateur"
      />

      <section className="grid gap-4 xl:grid-cols-[1.25fr_1fr]">
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-4 w-4" /> RBAC visuel
            </CardTitle>
            <CardDescription>Gestion des utilisateurs et des rôles</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rôle</TableHead>
                  <TableHead>Utilisateurs</TableHead>
                  <TableHead>CVEs</TableHead>
                  <TableHead>Assets</TableHead>
                  <TableHead>Reports</TableHead>
                  <TableHead>Admin</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rbacMatrix.map((row) => (
                  <TableRow key={row.role}>
                    <TableCell className="font-medium">{row.role}</TableCell>
                    <TableCell>{row.users}</TableCell>
                    <TableCell>{row.cves ? <Check className="h-4 w-4 text-green-600" /> : "-"}</TableCell>
                    <TableCell>{row.assets ? <Check className="h-4 w-4 text-green-600" /> : "-"}</TableCell>
                    <TableCell>{row.reports ? <Check className="h-4 w-4 text-green-600" /> : "-"}</TableCell>
                    <TableCell>{row.settings ? <Check className="h-4 w-4 text-green-600" /> : "-"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-4 w-4" /> Préférences utilisateur
            </CardTitle>
            <CardDescription>Thème, langue, ergonomie</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label>Langue interface</Label>
              <Select value={locale} onValueChange={(value) => setLocale(value as "fr" | "en") }>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="fr">Français</SelectItem>
                  <SelectItem value="en">English</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1">
              <Label>Thème</Label>
              <Select value={themePreference} onValueChange={(value) => setThemePreference(value as "system" | "light" | "dark")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="system">System</SelectItem>
                  <SelectItem value="light">Light</SelectItem>
                  <SelectItem value="dark">Dark</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="rounded-md border p-3 text-sm text-muted-foreground">
              Les préférences sont persistées localement et appliquées immédiatement.
            </div>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-4 w-4" /> Sources de données & intégrations
            </CardTitle>
            <CardDescription>Configuration NVD, CMDB, webhooks</CardDescription>
          </CardHeader>
          <CardContent>
            <Form {...form}>
              <form className="space-y-3" onSubmit={saveDataSources}>
                <FormField
                  control={form.control}
                  name="nvdApiKey"
                  render={({ field }) => (
                    <FormItem>
                      <Label>NVD API Key</Label>
                      <FormControl>
                        <Input {...field} placeholder="optional" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="cmdbEndpoint"
                  render={({ field }) => (
                    <FormItem>
                      <Label>CMDB Endpoint</Label>
                      <FormControl>
                        <Input {...field} placeholder="https://cmdb.local/api" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="webhookUrl"
                  render={({ field }) => (
                    <FormItem>
                      <Label>Webhook Alerting</Label>
                      <FormControl>
                        <Input {...field} placeholder="https://hooks.slack.com/..." />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button type="submit">Sauvegarder intégrations</Button>
              </form>
            </Form>
          </CardContent>
        </Card>

        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>Notifications & alertes</CardTitle>
            <CardDescription>Canaux et triggers</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <ToggleRow
              label="Alerte email CVE critique"
              checked={alerts.criticalEmail}
              onCheckedChange={(value) => setAlerts((state) => ({ ...state, criticalEmail: value }))}
            />
            <ToggleRow
              label="Digest quotidien"
              checked={alerts.digest}
              onCheckedChange={(value) => setAlerts((state) => ({ ...state, digest: value }))}
            />
            <ToggleRow
              label="Webhook Slack"
              checked={alerts.slack}
              onCheckedChange={(value) => setAlerts((state) => ({ ...state, slack: value }))}
            />
          </CardContent>
        </Card>
      </section>

      <section>
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Palette className="h-4 w-4" /> Branding
            </CardTitle>
            <CardDescription>Personnalisation logo et charte</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-3">
            <div className="space-y-1">
              <Label>Nom application</Label>
              <Input value={branding.appName} onChange={(event) => setBranding((state) => ({ ...state, appName: event.target.value }))} />
            </div>
            <div className="space-y-1">
              <Label>Logo URL</Label>
              <Input value={branding.logoUrl} onChange={(event) => setBranding((state) => ({ ...state, logoUrl: event.target.value }))} />
            </div>
            <div className="space-y-1">
              <Label>Couleur principale</Label>
              <Input type="color" value={branding.primary} onChange={(event) => setBranding((state) => ({ ...state, primary: event.target.value }))} />
            </div>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}

function ToggleRow({
  label,
  checked,
  onCheckedChange,
}: {
  label: string;
  checked: boolean;
  onCheckedChange: (value: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between rounded-md border p-3">
      <Label>{label}</Label>
      <Switch checked={checked} onCheckedChange={onCheckedChange} />
    </div>
  );
}