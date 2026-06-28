"use client";

import * as React from "react";
import { useTheme } from "next-themes";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  AlertTriangle,
  Check,
  Database,
  DownloadCloud,
  KeyRound,
  Loader2,
  LogOut,
  Palette,
  PauseCircle,
  PlayCircle,
  PlugZap,
  RefreshCw,
  Shield,
  Users,
} from "lucide-react";
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
import { fetchJson } from "@/lib/api";
import { useUiPreferencesStore } from "@/store/ui-preferences";

const adminLoginSchema = z.object({
  username: z.string().trim().min(1, "Username required"),
  password: z.string().min(1, "Password required"),
});

const dataSourceSchema = z.object({
  language: z.enum(["fr", "en"]),
  nvdApiKey: z.string().optional(),
  cmdbEndpoint: z.string().url("Invalid URL").or(z.literal("")),
  cmdbApiToken: z.string().optional(),
  webhookUrl: z.string().url("Invalid URL").or(z.literal("")),
  cmdbEnabled: z.boolean(),
  // Branding / report personnalisation
  brandAppName: z.string().optional(),
  brandLogoUrl: z.string().url("Invalid URL").or(z.literal("")),
  brandPrimaryColor: z.string().optional(),
  reportHeaderText: z.string().optional(),
  reportFooterText: z.string().optional(),
  reportShowToc: z.boolean(),
});

type AdminLoginValues = z.infer<typeof adminLoginSchema>;
type DataSourceValues = z.infer<typeof dataSourceSchema>;

type AdminSession = {
  authenticated: boolean;
  username: string | null;
};

type CmdbTestResponse = {
  reachable: boolean;
  rawCount: number;
  mappedCount: number;
  sample: Array<{ name: string; type: string; hostname: string | null; ip: string | null }>;
};

type CmdbSyncResponse = {
  ok: boolean;
  created: number;
  updated: number;
  rawCount: number;
  mappedCount: number;
  lastSyncAt: string | null;
  message: string;
};

type ScrapingStatus = {
  enabled: boolean;
  paused: boolean;
  pausedAt: string | null;
  intervals: { deltaMs: number; fullMs: number };
  running: { id: string; startedAt: string } | null;
  lastSuccess: {
    id: string;
    completedAt: string;
    newCount: number;
    updatedCount: number;
    errorCount: number;
  } | null;
  lastFailure: { id: string; completedAt: string; errorCount: number } | null;
  nextDeltaAt: string | null;
  nextFullAt: string | null;
  totalCves: number;
  recentJobs: Array<{
    id: string;
    status: string;
    startedAt: string;
    completedAt: string | null;
    newCount: number;
    updatedCount: number;
    errorCount: number;
  }>;
};

type AppSettingsPayload = {
  language: "fr" | "en";
  nvdApiKey: string;
  cmdbEndpoint: string;
  cmdbApiToken: string;
  webhookUrl: string;
  cmdbEnabled: boolean;
  cmdbLastSyncAt: string | null;
  cmdbLastSyncStatus: string | null;
  cmdbLastSyncMessage: string | null;
  brandAppName: string;
  brandLogoUrl: string;
  brandPrimaryColor: string;
  reportHeaderText: string;
  reportFooterText: string;
  reportShowToc: boolean;
};

const rbacMatrix = [
  { role: "Admin", users: 2, cves: true, assets: true, reports: true, settings: true },
  { role: "Analyst", users: 12, cves: true, assets: true, reports: true, settings: false },
  { role: "Viewer", users: 18, cves: true, assets: true, reports: true, settings: false },
];

const copy = {
  fr: {
    pageTitle: "Administration & Parametres",
    pageDesc: "RBAC, integrations, CMDB, notifications et preferences utilisateur",
    loginTitle: "Authentification administrateur",
    loginDesc: "Seul un administrateur authentifie peut acceder a cette section.",
    username: "Utilisateur",
    password: "Mot de passe",
    loginButton: "Se connecter",
    loggingIn: "Connexion...",
    logout: "Deconnexion",
    rbacTitle: "RBAC visuel",
    rbacDesc: "Gestion des utilisateurs et des roles",
    role: "Role",
    users: "Utilisateurs",
    admin: "Admin",
    userPrefsTitle: "Preferences utilisateur",
    userPrefsDesc: "Theme, langue et ergonomie",
    language: "Langue interface",
    theme: "Theme",
    prefSaved: "Les preferences sont appliquees immediatement.",
    integrationsTitle: "Sources de donnees et integrations",
    integrationsDesc: "Configuration NVD, CMDB et webhooks",
    nvdKey: "NVD API Key",
    cmdbEndpoint: "CMDB endpoint",
    cmdbToken: "CMDB token/API key",
    webhook: "Webhook alerting",
    cmdbEnabled: "Activer sync CMDB",
    cmdbEnabledDesc: "Active la synchronisation CMDB manuelle et planifiee.",
    saveIntegrations: "Sauvegarder les integrations",
    saving: "Sauvegarde...",
    cmdbActions: "Actions CMDB",
    testCmdb: "Tester la connexion",
    syncCmdb: "Lancer la synchronisation",
    cmdbTesting: "Test en cours...",
    cmdbSyncing: "Sync en cours...",
    lastSyncNever: "Aucune synchronisation CMDB effectuee.",
    lastSyncPrefix: "Derniere sync",
    alertsTitle: "Notifications et alertes",
    alertsDesc: "Canaux et triggers",
    brandingTitle: "Branding & rapports",
    brandingDesc: "Logo, charte et personnalisation des rapports PDF",
    appName: "Nom application",
    logoUrl: "Logo URL",
    primaryColor: "Couleur principale",
    reportHeaderText: "En-tete du rapport",
    reportHeaderPlaceholder: "ex. Confidentiel - Direction de la securite",
    reportFooterText: "Pied de page du rapport",
    reportFooterPlaceholder: "ex. (c) 2026 ACME Corp - Diffusion restreinte",
    reportToc: "Sommaire (table des matieres)",
    reportTocDesc: "Ajoute un sommaire cliquable en tete du rapport PDF.",
    saveBranding: "Sauvegarder le branding",
    brandingHint: "Ces reglages s'appliquent aux rapports generes (en-tete, pied de page, sommaire).",
    criticalEmail: "Alerte email CVE critique",
    digest: "Digest quotidien",
    slack: "Webhook Slack",
    loadError: "Impossible de charger les parametres administration.",
    saveSuccess: "Parametres administration sauvegardes.",
    saveError: "Sauvegarde impossible.",
    loginError: "Identifiants invalides.",
    cmdbTestSuccess: "Connexion CMDB validee",
    cmdbTestError: "Test CMDB echoue",
    cmdbSyncSuccess: "Synchronisation CMDB terminee",
    cmdbSyncError: "Synchronisation CMDB echouee",
    reachable: "reachable",
    records: "enregistrements",
    nvdTitle: "Scraping NVD automatique",
    nvdDesc: "Surveillance du flux NVD en arriere-plan",
    nvdEnabled: "Auto-sync active",
    nvdDisabled: "Auto-sync desactive",
    nvdTotalCves: "CVE en base",
    nvdLastSync: "Derniere sync reussie",
    nvdNextDelta: "Prochaine sync delta",
    nvdNextFull: "Prochaine sync complete",
    nvdRunning: "Sync en cours",
    nvdNever: "Jamais",
    nvdTriggerDelta: "Lancer sync delta",
    nvdTriggerFull: "Lancer sync complete",
    nvdTriggering: "Demarrage...",
    nvdTriggered: "Sync planifiee, le worker la prendra en charge",
    nvdTriggerError: "Echec du declenchement",
    nvdRecentJobs: "Historique recent",
    nvdPause: "Mettre en pause",
    nvdResume: "Reprendre",
    nvdPausing: "Mise en pause...",
    nvdResuming: "Reprise...",
    nvdPaused: "En pause",
    nvdPausedDesc: "L'auto-sync est en pause. Les declenchements manuels restent actifs.",
    nvdPauseSuccess: "Auto-sync mis en pause",
    nvdResumeSuccess: "Auto-sync repris",
  },
  en: {
    pageTitle: "Administration & Settings",
    pageDesc: "RBAC, integrations, CMDB, notifications and user preferences",
    loginTitle: "Administrator login",
    loginDesc: "Only an authenticated administrator can access this section.",
    username: "Username",
    password: "Password",
    loginButton: "Sign in",
    loggingIn: "Signing in...",
    logout: "Sign out",
    rbacTitle: "RBAC overview",
    rbacDesc: "Users and roles management",
    role: "Role",
    users: "Users",
    admin: "Admin",
    userPrefsTitle: "User preferences",
    userPrefsDesc: "Theme, language and ergonomics",
    language: "Interface language",
    theme: "Theme",
    prefSaved: "Preferences are applied immediately.",
    integrationsTitle: "Data sources and integrations",
    integrationsDesc: "NVD, CMDB and webhook configuration",
    nvdKey: "NVD API Key",
    cmdbEndpoint: "CMDB endpoint",
    cmdbToken: "CMDB token/API key",
    webhook: "Alert webhook",
    cmdbEnabled: "Enable CMDB sync",
    cmdbEnabledDesc: "Enables manual and scheduled CMDB synchronization.",
    saveIntegrations: "Save integrations",
    saving: "Saving...",
    cmdbActions: "CMDB actions",
    testCmdb: "Test connection",
    syncCmdb: "Run synchronization",
    cmdbTesting: "Testing...",
    cmdbSyncing: "Syncing...",
    lastSyncNever: "No CMDB synchronization executed yet.",
    lastSyncPrefix: "Last sync",
    alertsTitle: "Notifications and alerts",
    alertsDesc: "Channels and triggers",
    brandingTitle: "Branding & reports",
    brandingDesc: "Logo, palette and PDF report customization",
    appName: "Application name",
    logoUrl: "Logo URL",
    primaryColor: "Primary color",
    reportHeaderText: "Report header",
    reportHeaderPlaceholder: "e.g. Confidential - Security Office",
    reportFooterText: "Report footer",
    reportFooterPlaceholder: "e.g. (c) 2026 ACME Corp - Restricted",
    reportToc: "Table of contents",
    reportTocDesc: "Adds a clickable table of contents at the top of the PDF report.",
    saveBranding: "Save branding",
    brandingHint: "These settings apply to generated reports (header, footer, table of contents).",
    criticalEmail: "Critical CVE email alert",
    digest: "Daily digest",
    slack: "Slack webhook",
    loadError: "Unable to load admin settings.",
    saveSuccess: "Admin settings saved.",
    saveError: "Failed to save settings.",
    loginError: "Invalid credentials.",
    cmdbTestSuccess: "CMDB connection validated",
    cmdbTestError: "CMDB test failed",
    cmdbSyncSuccess: "CMDB synchronization completed",
    cmdbSyncError: "CMDB synchronization failed",
    reachable: "reachable",
    records: "records",
    nvdTitle: "Automatic NVD scraping",
    nvdDesc: "Background poller against the NVD feed",
    nvdEnabled: "Auto-sync enabled",
    nvdDisabled: "Auto-sync disabled",
    nvdTotalCves: "CVEs in DB",
    nvdLastSync: "Last successful sync",
    nvdNextDelta: "Next delta sync",
    nvdNextFull: "Next full sync",
    nvdRunning: "Sync running",
    nvdNever: "Never",
    nvdTriggerDelta: "Trigger delta sync",
    nvdTriggerFull: "Trigger full sync",
    nvdTriggering: "Starting...",
    nvdTriggered: "Sync queued — the worker will pick it up",
    nvdTriggerError: "Trigger failed",
    nvdRecentJobs: "Recent runs",
    nvdPause: "Pause auto-sync",
    nvdResume: "Resume auto-sync",
    nvdPausing: "Pausing...",
    nvdResuming: "Resuming...",
    nvdPaused: "Paused",
    nvdPausedDesc: "Auto-sync is paused. Manual triggers still work.",
    nvdPauseSuccess: "Auto-sync paused",
    nvdResumeSuccess: "Auto-sync resumed",
  },
} as const;

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const locale = useUiPreferencesStore((state) => state.locale);
  const setLocale = useUiPreferencesStore((state) => state.setLocale);
  const themePreference = useUiPreferencesStore((state) => state.themePreference);
  const setThemePreference = useUiPreferencesStore((state) => state.setThemePreference);
  const currentThemePreference =
    theme === "system" || theme === "light" || theme === "dark" ? theme : themePreference;

  const t = copy[locale];

  const [alerts, setAlerts] = React.useState({
    criticalEmail: true,
    digest: true,
    slack: false,
  });

  const [sessionChecked, setSessionChecked] = React.useState(false);
  const [authenticated, setAuthenticated] = React.useState(false);
  const [adminUsername, setAdminUsername] = React.useState<string | null>(null);
  const [authenticating, setAuthenticating] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [testingCmdb, setTestingCmdb] = React.useState(false);
  const [syncingCmdb, setSyncingCmdb] = React.useState(false);
  const [lastSyncInfo, setLastSyncInfo] = React.useState<{
    at: string | null;
    status: string | null;
    message: string | null;
  }>({
    at: null,
    status: null,
    message: null,
  });
  const [scrapingStatus, setScrapingStatus] = React.useState<ScrapingStatus | null>(null);
  const [triggeringNvd, setTriggeringNvd] = React.useState<null | "delta" | "full">(null);
  const [togglingPause, setTogglingPause] = React.useState(false);

  const form = useForm<DataSourceValues>({
    resolver: zodResolver(dataSourceSchema),
    defaultValues: {
      language: locale,
      nvdApiKey: "",
      cmdbEndpoint: "",
      cmdbApiToken: "",
      webhookUrl: "",
      cmdbEnabled: false,
      brandAppName: "CVE Tracker",
      brandLogoUrl: "",
      brandPrimaryColor: "#2C7BE5",
      reportHeaderText: "",
      reportFooterText: "",
      reportShowToc: true,
    },
  });

  const loginForm = useForm<AdminLoginValues>({
    resolver: zodResolver(adminLoginSchema),
    defaultValues: {
      username: "",
      password: "",
    },
  });

  const loadSettings = React.useCallback(async () => {
    const settings = await fetchJson<AppSettingsPayload>("/api/admin/settings");
    form.reset({
      language: settings.language,
      nvdApiKey: settings.nvdApiKey,
      cmdbEndpoint: settings.cmdbEndpoint,
      cmdbApiToken: settings.cmdbApiToken,
      webhookUrl: settings.webhookUrl,
      cmdbEnabled: settings.cmdbEnabled,
      brandAppName: settings.brandAppName,
      brandLogoUrl: settings.brandLogoUrl,
      brandPrimaryColor: settings.brandPrimaryColor || "#2C7BE5",
      reportHeaderText: settings.reportHeaderText,
      reportFooterText: settings.reportFooterText,
      reportShowToc: settings.reportShowToc,
    });
    setLocale(settings.language);
    setLastSyncInfo({
      at: settings.cmdbLastSyncAt,
      status: settings.cmdbLastSyncStatus,
      message: settings.cmdbLastSyncMessage,
    });
  }, [form, setLocale]);

  const checkSession = React.useCallback(async () => {
    try {
      const session = await fetchJson<AdminSession>("/api/admin/auth/session");
      setAuthenticated(session.authenticated);
      setAdminUsername(session.username);
      if (session.authenticated) {
        await loadSettings();
      }
    } catch {
      setAuthenticated(false);
      setAdminUsername(null);
    } finally {
      setSessionChecked(true);
    }
  }, [loadSettings]);

  React.useEffect(() => {
    void checkSession();
  }, [checkSession]);

  React.useEffect(() => {
    form.setValue("language", locale);
  }, [form, locale]);

  const refreshScrapingStatus = React.useCallback(async () => {
    try {
      const status = await fetchJson<ScrapingStatus>("/api/admin/scraping/status");
      setScrapingStatus(status);
    } catch {
      // silent — surfaced via UI state instead
      setScrapingStatus(null);
    }
  }, []);

  React.useEffect(() => {
    if (!authenticated) return;
    void refreshScrapingStatus();
    const interval = setInterval(() => void refreshScrapingStatus(), 30_000);
    return () => clearInterval(interval);
  }, [authenticated, refreshScrapingStatus]);

  const triggerNvdSync = async (mode: "delta" | "full") => {
    setTriggeringNvd(mode);
    try {
      await fetchJson<{ ok: boolean; jobId: string }>("/api/admin/scraping/trigger", {
        method: "POST",
        body: JSON.stringify({ mode }),
      });
      toast({ title: t.nvdTriggered });
      // Refresh status a few times to catch the transition
      void refreshScrapingStatus();
      setTimeout(() => void refreshScrapingStatus(), 3000);
      setTimeout(() => void refreshScrapingStatus(), 10000);
    } catch (error) {
      const message = error instanceof Error ? error.message : t.nvdTriggerError;
      toast({ title: t.nvdTriggerError, description: message, variant: "destructive" });
    } finally {
      setTriggeringNvd(null);
    }
  };

  const togglePause = async () => {
    if (!scrapingStatus) return;
    setTogglingPause(true);
    const target = scrapingStatus.paused ? "resume" : "pause";
    try {
      await fetchJson<{ ok: boolean }>(`/api/admin/scraping/${target}`, { method: "POST" });
      toast({
        title: target === "pause" ? t.nvdPauseSuccess : t.nvdResumeSuccess,
      });
      void refreshScrapingStatus();
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      toast({
        title: target === "pause" ? t.nvdPauseSuccess : t.nvdResumeSuccess,
        description: message,
        variant: "destructive",
      });
    } finally {
      setTogglingPause(false);
    }
  };

  const formatDate = (iso: string | null | undefined) => {
    if (!iso) return t.nvdNever;
    return new Date(iso).toLocaleString(locale === "fr" ? "fr-FR" : "en-US");
  };
  const formatInterval = (ms: number) => {
    if (ms >= 3600_000) return `${Math.round(ms / 3600_000)}h`;
    if (ms >= 60_000) return `${Math.round(ms / 60_000)}min`;
    return `${Math.round(ms / 1000)}s`;
  };

  const persistSettings = React.useCallback(
    async (values: DataSourceValues, showToast = true) => {
      const saved = await fetchJson<AppSettingsPayload>("/api/admin/settings", {
        method: "PUT",
        body: JSON.stringify(values),
      });
      setLocale(saved.language);
      setLastSyncInfo({
        at: saved.cmdbLastSyncAt,
        status: saved.cmdbLastSyncStatus,
        message: saved.cmdbLastSyncMessage,
      });

      if (showToast) {
        toast({ title: t.saveSuccess });
      }

      return saved;
    },
    [setLocale, t.saveSuccess]
  );

  const onLogin = loginForm.handleSubmit(async (values) => {
    setAuthenticating(true);
    try {
      await fetchJson<AdminSession>("/api/admin/auth/login", {
        method: "POST",
        body: JSON.stringify(values),
      });
      setAuthenticated(true);
      setAdminUsername(values.username);
      await loadSettings();
      loginForm.reset();
    } catch (error) {
      const message = error instanceof Error ? error.message : t.loginError;
      toast({ title: t.loginError, description: message, variant: "destructive" });
    } finally {
      setAuthenticating(false);
    }
  });

  const onLogout = async () => {
    await fetchJson<{ authenticated: boolean }>("/api/admin/auth/logout", {
      method: "POST",
    });
    setAuthenticated(false);
    setAdminUsername(null);
  };

  const saveDataSources = form.handleSubmit(async (values) => {
    setSaving(true);
    try {
      await persistSettings(values, true);
    } catch (error) {
      const message = error instanceof Error ? error.message : t.saveError;
      toast({ title: t.saveError, description: message, variant: "destructive" });
    } finally {
      setSaving(false);
    }
  });

  const runCmdbTest = async () => {
    setTestingCmdb(true);
    try {
      const values = form.getValues();
      const result = await fetchJson<CmdbTestResponse>("/api/admin/cmdb/test", {
        method: "POST",
        body: JSON.stringify({
          cmdbEndpoint: values.cmdbEndpoint,
          cmdbApiToken: values.cmdbApiToken,
        }),
      });

      toast({
        title: t.cmdbTestSuccess,
        description: `${result.rawCount} ${t.records} (${result.mappedCount} mapped)`,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : t.cmdbTestError;
      toast({ title: t.cmdbTestError, description: message, variant: "destructive" });
    } finally {
      setTestingCmdb(false);
    }
  };

  const runCmdbSync = async () => {
    setSyncingCmdb(true);
    try {
      await persistSettings(form.getValues(), false);
      const result = await fetchJson<CmdbSyncResponse>("/api/admin/cmdb/sync", {
        method: "POST",
      });

      setLastSyncInfo({
        at: result.lastSyncAt,
        status: result.ok ? "ok" : "error",
        message: result.message,
      });

      toast({
        title: t.cmdbSyncSuccess,
        description: `${result.created} created / ${result.updated} updated`,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : t.cmdbSyncError;
      toast({ title: t.cmdbSyncError, description: message, variant: "destructive" });
    } finally {
      setSyncingCmdb(false);
    }
  };

  if (!sessionChecked) {
    return (
      <div className="flex min-h-[55vh] items-center justify-center p-6 lg:p-8">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!authenticated) {
    return (
      <div className="mx-auto flex w-full max-w-xl flex-col gap-6 p-6 lg:p-8">
        <PageHeader title={t.loginTitle} description={t.loginDesc} />
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4" /> {t.loginTitle}
            </CardTitle>
            <CardDescription>{t.loginDesc}</CardDescription>
          </CardHeader>
          <CardContent>
            <Form {...loginForm}>
              <form className="space-y-3" onSubmit={onLogin}>
                <FormField
                  control={loginForm.control}
                  name="username"
                  render={({ field }) => (
                    <FormItem>
                      <Label>{t.username}</Label>
                      <FormControl>
                        <Input {...field} autoComplete="username" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={loginForm.control}
                  name="password"
                  render={({ field }) => (
                    <FormItem>
                      <Label>{t.password}</Label>
                      <FormControl>
                        <Input {...field} type="password" autoComplete="current-password" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button type="submit" className="w-full" disabled={authenticating}>
                  {authenticating ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" /> {t.loggingIn}
                    </>
                  ) : (
                    t.loginButton
                  )}
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6 lg:p-8">
      <PageHeader
        title={t.pageTitle}
        description={t.pageDesc}
        actions={
          <Button variant="outline" onClick={() => void onLogout()}>
            <LogOut className="mr-2 h-4 w-4" /> {t.logout}
            {adminUsername ? ` (${adminUsername})` : ""}
          </Button>
        }
      />

      <section className="grid gap-4 xl:grid-cols-[1.25fr_1fr]">
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-4 w-4" /> {t.rbacTitle}
            </CardTitle>
            <CardDescription>{t.rbacDesc}</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t.role}</TableHead>
                  <TableHead>{t.users}</TableHead>
                  <TableHead>CVEs</TableHead>
                  <TableHead>Assets</TableHead>
                  <TableHead>Reports</TableHead>
                  <TableHead>{t.admin}</TableHead>
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
              <Shield className="h-4 w-4" /> {t.userPrefsTitle}
            </CardTitle>
            <CardDescription>{t.userPrefsDesc}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label>{t.language}</Label>
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant={locale === "fr" ? "default" : "outline"}
                  onClick={() => {
                    setLocale("fr");
                    form.setValue("language", "fr");
                  }}
                >
                  Francais
                </Button>
                <Button
                  type="button"
                  variant={locale === "en" ? "default" : "outline"}
                  onClick={() => {
                    setLocale("en");
                    form.setValue("language", "en");
                  }}
                >
                  English
                </Button>
              </div>
            </div>

            <div className="space-y-1">
              <Label>{t.theme}</Label>
              <Select
                value={currentThemePreference}
                onValueChange={(value) => {
                  const nextTheme = value as "system" | "light" | "dark";
                  setThemePreference(nextTheme);
                  setTheme(nextTheme);
                }}
              >
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

            <div className="rounded-md border p-3 text-sm text-muted-foreground">{t.prefSaved}</div>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-4 w-4" /> {t.integrationsTitle}
            </CardTitle>
            <CardDescription>{t.integrationsDesc}</CardDescription>
          </CardHeader>
          <CardContent>
            <Form {...form}>
              <form className="space-y-3" onSubmit={saveDataSources}>
                <FormField
                  control={form.control}
                  name="nvdApiKey"
                  render={({ field }) => (
                    <FormItem>
                      <Label>{t.nvdKey}</Label>
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
                      <Label>{t.cmdbEndpoint}</Label>
                      <FormControl>
                        <Input {...field} placeholder="https://cmdb.local/api/assets" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="cmdbApiToken"
                  render={({ field }) => (
                    <FormItem>
                      <Label>{t.cmdbToken}</Label>
                      <FormControl>
                        <Input {...field} type="password" placeholder="token" />
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
                      <Label>{t.webhook}</Label>
                      <FormControl>
                        <Input {...field} placeholder="https://hooks.slack.com/..." />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="cmdbEnabled"
                  render={({ field }) => (
                    <FormItem className="flex items-center justify-between rounded-md border p-3">
                      <div>
                        <Label>{t.cmdbEnabled}</Label>
                        <p className="text-xs text-muted-foreground">{t.cmdbEnabledDesc}</p>
                      </div>
                      <FormControl>
                        <Switch checked={field.value} onCheckedChange={field.onChange} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <div className="flex flex-wrap gap-2 pt-1">
                  <Button type="submit" disabled={saving}>
                    {saving ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" /> {t.saving}
                      </>
                    ) : (
                      t.saveIntegrations
                    )}
                  </Button>
                </div>
              </form>
            </Form>
          </CardContent>
        </Card>

        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <PlugZap className="h-4 w-4" /> {t.cmdbActions}
            </CardTitle>
            <CardDescription>{t.integrationsDesc}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button variant="outline" className="w-full" onClick={() => void runCmdbTest()} disabled={testingCmdb}>
              {testingCmdb ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> {t.cmdbTesting}
                </>
              ) : (
                <>
                  <RefreshCw className="mr-2 h-4 w-4" /> {t.testCmdb}
                </>
              )}
            </Button>
            <Button className="w-full" onClick={() => void runCmdbSync()} disabled={syncingCmdb}>
              {syncingCmdb ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> {t.cmdbSyncing}
                </>
              ) : (
                t.syncCmdb
              )}
            </Button>
            <div className="rounded-md border p-3 text-xs text-muted-foreground">
              {lastSyncInfo.at ? (
                <>
                  <p>
                    {t.lastSyncPrefix}: {new Date(lastSyncInfo.at).toLocaleString(locale === "fr" ? "fr-FR" : "en-US")}
                  </p>
                  <p>
                    {lastSyncInfo.status || t.reachable}: {lastSyncInfo.message || "-"}
                  </p>
                </>
              ) : (
                <p>{t.lastSyncNever}</p>
              )}
            </div>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <DownloadCloud className="h-4 w-4" /> {t.nvdTitle}
            </CardTitle>
            <CardDescription>{t.nvdDesc}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="rounded-md border p-3">
                <p className="text-xs uppercase text-muted-foreground">Status</p>
                <p className="mt-1 flex items-center gap-2 font-medium">
                  {scrapingStatus?.paused ? (
                    <>
                      <span className="inline-block h-2 w-2 rounded-full bg-amber-500" />
                      {t.nvdPaused}
                    </>
                  ) : scrapingStatus?.enabled ? (
                    <>
                      <span className="inline-block h-2 w-2 rounded-full bg-green-500" />
                      {t.nvdEnabled}
                    </>
                  ) : (
                    <>
                      <span className="inline-block h-2 w-2 rounded-full bg-muted-foreground" />
                      {t.nvdDisabled}
                    </>
                  )}
                </p>
                {scrapingStatus?.paused && scrapingStatus.pausedAt && (
                  <p className="mt-1 text-[10px] text-muted-foreground">
                    {formatDate(scrapingStatus.pausedAt)}
                  </p>
                )}
              </div>
              <div className="rounded-md border p-3">
                <p className="text-xs uppercase text-muted-foreground">{t.nvdTotalCves}</p>
                <p className="mt-1 font-medium tabular-nums">
                  {scrapingStatus?.totalCves?.toLocaleString() ?? "-"}
                </p>
              </div>
              <div className="rounded-md border p-3">
                <p className="text-xs uppercase text-muted-foreground">{t.nvdLastSync}</p>
                <p className="mt-1 text-xs">{formatDate(scrapingStatus?.lastSuccess?.completedAt)}</p>
                {scrapingStatus?.lastSuccess && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    +{scrapingStatus.lastSuccess.newCount} / ~{scrapingStatus.lastSuccess.updatedCount}
                    {scrapingStatus.lastSuccess.errorCount > 0
                      ? ` / ⚠ ${scrapingStatus.lastSuccess.errorCount}`
                      : ""}
                  </p>
                )}
              </div>
              <div className="rounded-md border p-3">
                <p className="text-xs uppercase text-muted-foreground">{t.nvdNextDelta}</p>
                <p className="mt-1 text-xs">
                  {scrapingStatus?.running ? (
                    <span className="flex items-center gap-1 text-amber-600">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      {t.nvdRunning}
                    </span>
                  ) : (
                    formatDate(scrapingStatus?.nextDeltaAt)
                  )}
                </p>
                {scrapingStatus?.intervals && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    Δ {formatInterval(scrapingStatus.intervals.deltaMs)} ·
                    {" "}full {formatInterval(scrapingStatus.intervals.fullMs)}
                  </p>
                )}
              </div>
            </div>

            {scrapingStatus?.lastFailure && (
              <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/5 p-3 text-xs">
                <AlertTriangle className="mt-0.5 h-4 w-4 text-destructive" />
                <span>
                  Dernier echec : {formatDate(scrapingStatus.lastFailure.completedAt)} (
                  {scrapingStatus.lastFailure.errorCount} erreurs)
                </span>
              </div>
            )}

            {scrapingStatus?.paused && (
              <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-xs">
                <PauseCircle className="mt-0.5 h-4 w-4 text-amber-600" />
                <span>{t.nvdPausedDesc}</span>
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              <Button
                variant={scrapingStatus?.paused ? "default" : "outline"}
                onClick={() => void togglePause()}
                disabled={togglingPause || !scrapingStatus}
              >
                {togglingPause ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    {scrapingStatus?.paused ? t.nvdResuming : t.nvdPausing}
                  </>
                ) : scrapingStatus?.paused ? (
                  <>
                    <PlayCircle className="mr-2 h-4 w-4" /> {t.nvdResume}
                  </>
                ) : (
                  <>
                    <PauseCircle className="mr-2 h-4 w-4" /> {t.nvdPause}
                  </>
                )}
              </Button>
              <Button
                variant="outline"
                onClick={() => void triggerNvdSync("delta")}
                disabled={triggeringNvd !== null || Boolean(scrapingStatus?.running)}
              >
                {triggeringNvd === "delta" ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" /> {t.nvdTriggering}
                  </>
                ) : (
                  <>
                    <RefreshCw className="mr-2 h-4 w-4" /> {t.nvdTriggerDelta}
                  </>
                )}
              </Button>
              <Button
                onClick={() => void triggerNvdSync("full")}
                disabled={triggeringNvd !== null || Boolean(scrapingStatus?.running)}
              >
                {triggeringNvd === "full" ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" /> {t.nvdTriggering}
                  </>
                ) : (
                  <>
                    <DownloadCloud className="mr-2 h-4 w-4" /> {t.nvdTriggerFull}
                  </>
                )}
              </Button>
            </div>

            {scrapingStatus?.recentJobs && scrapingStatus.recentJobs.length > 0 && (
              <div className="rounded-md border">
                <p className="border-b px-3 py-2 text-xs uppercase text-muted-foreground">
                  {t.nvdRecentJobs}
                </p>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">Status</TableHead>
                      <TableHead className="text-xs">Start</TableHead>
                      <TableHead className="text-xs text-right">New</TableHead>
                      <TableHead className="text-xs text-right">Upd</TableHead>
                      <TableHead className="text-xs text-right">Err</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scrapingStatus.recentJobs.slice(0, 5).map((job) => (
                      <TableRow key={job.id}>
                        <TableCell className="text-xs">{job.status}</TableCell>
                        <TableCell className="text-xs">{formatDate(job.startedAt)}</TableCell>
                        <TableCell className="text-xs text-right tabular-nums">{job.newCount}</TableCell>
                        <TableCell className="text-xs text-right tabular-nums">{job.updatedCount}</TableCell>
                        <TableCell className="text-xs text-right tabular-nums">{job.errorCount}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="card-elevated">
          <CardHeader>
            <CardTitle>{t.alertsTitle}</CardTitle>
            <CardDescription>{t.alertsDesc}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <ToggleRow
              label={t.criticalEmail}
              checked={alerts.criticalEmail}
              onCheckedChange={(value) => setAlerts((state) => ({ ...state, criticalEmail: value }))}
            />
            <ToggleRow
              label={t.digest}
              checked={alerts.digest}
              onCheckedChange={(value) => setAlerts((state) => ({ ...state, digest: value }))}
            />
            <ToggleRow
              label={t.slack}
              checked={alerts.slack}
              onCheckedChange={(value) => setAlerts((state) => ({ ...state, slack: value }))}
            />
          </CardContent>
        </Card>

        <Card className="card-elevated">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Palette className="h-4 w-4" /> {t.brandingTitle}
            </CardTitle>
            <CardDescription>{t.brandingDesc}</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3">
            <div className="space-y-1">
              <Label>{t.appName}</Label>
              <Input placeholder="CVE Tracker" {...form.register("brandAppName")} />
            </div>
            <div className="space-y-1">
              <Label>{t.logoUrl}</Label>
              <Input placeholder="https://exemple.com/logo.svg" {...form.register("brandLogoUrl")} />
              {form.formState.errors.brandLogoUrl && (
                <p className="text-xs text-destructive">
                  {form.formState.errors.brandLogoUrl.message}
                </p>
              )}
            </div>
            <div className="space-y-1">
              <Label>{t.primaryColor}</Label>
              <Input type="color" className="h-10 w-20 p-1" {...form.register("brandPrimaryColor")} />
            </div>
            <div className="space-y-1">
              <Label>{t.reportHeaderText}</Label>
              <Input placeholder={t.reportHeaderPlaceholder} {...form.register("reportHeaderText")} />
            </div>
            <div className="space-y-1">
              <Label>{t.reportFooterText}</Label>
              <Input placeholder={t.reportFooterPlaceholder} {...form.register("reportFooterText")} />
            </div>
            <div className="flex items-center justify-between rounded-md border p-3">
              <div>
                <Label>{t.reportToc}</Label>
                <p className="text-xs text-muted-foreground">{t.reportTocDesc}</p>
              </div>
              <Switch
                checked={form.watch("reportShowToc")}
                onCheckedChange={(value) =>
                  form.setValue("reportShowToc", value, { shouldDirty: true })
                }
              />
            </div>
            <p className="text-xs text-muted-foreground">{t.brandingHint}</p>
            <Button type="button" onClick={() => void saveDataSources()} disabled={saving}>
              {saving ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> {t.saving}
                </>
              ) : (
                t.saveBranding
              )}
            </Button>
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
