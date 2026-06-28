"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { useTranslations } from "next-intl";
import {
  BookKey,
  Languages,
  Menu,
  MoonStar,
  Search,
  SunMedium,
} from "lucide-react";
import { Sidebar } from "@/components/Sidebar";
import { BrandMark } from "@/components/brand-mark";
import { Button } from "@/components/ui/button";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { useUiPreferencesStore } from "@/store/ui-preferences";

const quickLinks = [
  { href: "/", label: "dashboard" },
  { href: "/cves", label: "cves" },
  { href: "/vulnerabilities", label: "vulnerabilities" },
  { href: "/assets", label: "assets" },
  { href: "/reports", label: "reports" },
  { href: "/settings", label: "settings" },
] as const;

export function AppShell({ children }: { children: React.ReactNode }) {
  const [mounted, setMounted] = React.useState(false);
  const router = useRouter();
  const t = useTranslations();
  const { theme, setTheme, resolvedTheme } = useTheme();
  const [openCommands, setOpenCommands] = React.useState(false);
  const [pendingGoto, setPendingGoto] = React.useState(false);
  const locale = useUiPreferencesStore((state) => state.locale);
  const setLocale = useUiPreferencesStore((state) => state.setLocale);
  const themePreference = useUiPreferencesStore((state) => state.themePreference);
  const setThemePreference = useUiPreferencesStore((state) => state.setThemePreference);
  const shortcutsOpen = useUiPreferencesStore((state) => state.shortcutsOpen);
  const setShortcutsOpen = useUiPreferencesStore((state) => state.setShortcutsOpen);
  const normalizedThemePreference =
    theme === "light" || theme === "dark" || theme === "system" ? theme : themePreference;
  const effectiveTheme =
    normalizedThemePreference === "system" ? resolvedTheme ?? "light" : normalizedThemePreference;

  React.useEffect(() => {
    setMounted(true);
  }, []);

  React.useEffect(() => {
    if (!pendingGoto) return;
    const timeout = setTimeout(() => setPendingGoto(false), 1200);
    return () => clearTimeout(timeout);
  }, [pendingGoto]);

  React.useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const isCmdK = (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k";
      if (isCmdK) {
        event.preventDefault();
        setOpenCommands((current) => !current);
      }
      if (event.key === "?") {
        event.preventDefault();
        setShortcutsOpen(true);
      }

      if (event.key.toLowerCase() === "g") {
        setPendingGoto(true);
        return;
      }

      if (pendingGoto) {
        const key = event.key.toLowerCase();
        if (key === "d") router.push("/");
        if (key === "c") router.push("/cves");
        if (key === "a") router.push("/assets");
        setPendingGoto(false);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [pendingGoto, router, setShortcutsOpen]);

  const toggleLocale = () => {
    setOpenCommands(false);
    setShortcutsOpen(false);
    setLocale(locale === "fr" ? "en" : "fr");
  };

  const toggleTheme = () => {
    const next = effectiveTheme === "dark" ? "light" : "dark";
    setThemePreference(next);
    setTheme(next);
  };

  if (!mounted) {
    return (
      <div className="flex min-h-screen">
        <div className="hidden w-72 shrink-0 border-r border-sidebar-border bg-sidebar xl:flex" />
        <div className="flex min-h-screen flex-1 flex-col">
          <header className="sticky top-0 z-30 border-b bg-background/85 backdrop-blur-md">
            <div className="h-16 px-4 lg:px-6" />
          </header>
          <main className="flex-1 overflow-x-hidden">{children}</main>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />

      <div className="flex min-h-screen flex-1 flex-col">
        <header className="sticky top-0 z-30 border-b bg-background/85 backdrop-blur-md">
          <div className="flex h-16 items-center gap-3 px-4 lg:px-6">
            <Sheet>
              <SheetTrigger asChild>
                <Button variant="outline" size="icon" className="xl:hidden" aria-label={t("openNavigation")}>
                  <Menu className="h-4 w-4" />
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-72 border-sidebar-border bg-sidebar text-sidebar-foreground">
                <SheetHeader>
                  <SheetTitle className="flex items-center gap-3 text-sidebar-foreground">
                    <BrandMark className="h-8 w-8 shrink-0 drop-shadow-sm" />
                    {t("appName")}
                  </SheetTitle>
                </SheetHeader>
                <div className="mt-6 space-y-2">
                  {quickLinks.map((link) => (
                    <Link
                      key={link.href}
                      href={link.href}
                      className="block rounded-md px-3 py-2 text-sm hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                    >
                      {t(link.label)}
                    </Link>
                  ))}
                </div>
              </SheetContent>
            </Sheet>

            <Button
              id="global-search-trigger"
              variant="outline"
              className="h-10 w-full max-w-xl justify-between text-muted-foreground"
              onClick={() => setOpenCommands(true)}
              aria-label={t("search")}
            >
              <span className="flex items-center gap-2">
                <Search className="h-4 w-4" />
                {t("search")}
              </span>
              <kbd className="rounded border px-2 py-0.5 text-[11px] text-muted-foreground">Ctrl K</kbd>
            </Button>

            <div className="ml-auto flex items-center gap-2">
              <Button variant="outline" size="icon" onClick={toggleLocale} aria-label={t("language")}>
                <Languages className="h-4 w-4" />
              </Button>
              <Button variant="outline" size="icon" onClick={toggleTheme} aria-label={t("theme")}>
                {effectiveTheme === "dark" ? (
                  <SunMedium className="h-4 w-4" />
                ) : (
                  <MoonStar className="h-4 w-4" />
                )}
              </Button>
              <Button variant="outline" size="icon" onClick={() => setShortcutsOpen(true)} aria-label={t("shortcuts")}>
                <BookKey className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-x-hidden">{children}</main>
      </div>

      <CommandDialog
        open={openCommands}
        onOpenChange={setOpenCommands}
        title={t("search")}
        description={t("search")}
      >
        <CommandInput placeholder={`${t("search")}...`} />
        <CommandList>
          <CommandEmpty>{t("noResult")}</CommandEmpty>
          <CommandGroup heading={t("navigation")}>
            {quickLinks.map((item) => (
              <CommandItem
                key={item.href}
                value={`${t(item.label)} ${item.href}`}
                keywords={[item.label, item.href, item.href.replace("/", " ")]}
                onSelect={() => {
                  router.push(item.href);
                  setOpenCommands(false);
                }}
              >
                {t(item.label)}
                <CommandShortcut>{item.href === "/" ? "G D" : item.href}</CommandShortcut>
              </CommandItem>
            ))}
          </CommandGroup>
          <CommandSeparator />
          <CommandGroup heading={t("actions")}>
            <CommandItem
              value={t("theme")}
              keywords={["theme", "dark", "light"]}
              onSelect={() => {
                toggleTheme();
                setOpenCommands(false);
              }}
            >
              {t("theme")}
            </CommandItem>
            <CommandItem
              value={t("language")}
              keywords={["language", "locale", "fr", "en"]}
              onSelect={() => {
                toggleLocale();
                setOpenCommands(false);
              }}
            >
              {t("language")}
            </CommandItem>
          </CommandGroup>
        </CommandList>
      </CommandDialog>

      <Dialog open={shortcutsOpen} onOpenChange={setShortcutsOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("shortcuts")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-2 text-sm">
            <ShortcutItem keys="Ctrl + K" description={t("search")} />
            <ShortcutItem keys="?" description={t("shortcuts")} />
            <ShortcutItem keys="G + D" description={t("dashboard")} />
            <ShortcutItem keys="G + C" description={t("cves")} />
            <ShortcutItem keys="G + A" description={t("assets")} />
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function ShortcutItem({ keys, description }: { keys: string; description: string }) {
  return (
    <div className="flex items-center justify-between rounded-md border bg-card px-3 py-2">
      <span>{description}</span>
      <kbd className="rounded border bg-muted px-2 py-0.5 text-xs">{keys}</kbd>
    </div>
  );
}
