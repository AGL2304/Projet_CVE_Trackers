"use client";

import * as React from "react";
import {
  IntlErrorCode,
  NextIntlClientProvider,
  type IntlError,
} from "next-intl";
import { ThemeProvider, useTheme } from "next-themes";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { i18nMessages } from "@/i18n/messages";
import { useUiPreferencesStore } from "@/store/ui-preferences";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 5 * 60_000,
      retry: 2,
      refetchOnWindowFocus: false,
    },
  },
});

const tourSteps = [
  {
    target: "#main-nav",
    title: "Navigation principale",
    content: "Dashboard, CVEs, assets, reporting et administration.",
  },
  {
    target: "#global-search-trigger",
    title: "Recherche globale",
    content: "Recherche rapide CVE/CWE/produit avec Ctrl+K.",
  },
  {
    target: "#dashboard-kpis",
    title: "KPIs de securite",
    content: "Exposition critique, nouveaux CVEs et score CVSS moyen.",
  },
] as const;

function ThemeBridge() {
  const themePreference = useUiPreferencesStore((state) => state.themePreference);
  const { setTheme } = useTheme();

  React.useEffect(() => {
    setTheme(themePreference);
  }, [setTheme, themePreference]);

  return null;
}

function Onboarding() {
  const [open, setOpen] = React.useState(false);
  const [step, setStep] = React.useState(0);

  React.useEffect(() => {
    const done = localStorage.getItem("cve-tracker-tour-complete");
    if (!done) {
      const handle = setTimeout(() => setOpen(true), 350);
      return () => clearTimeout(handle);
    }
  }, []);

  React.useEffect(() => {
    if (!open) return;

    const current = tourSteps[step];
    const target = document.querySelector(current.target);
    if (!(target instanceof HTMLElement)) return;

    target.scrollIntoView({ behavior: "smooth", block: "center" });
    target.classList.add("ring-2", "ring-ring", "ring-offset-2");

    return () => {
      target.classList.remove("ring-2", "ring-ring", "ring-offset-2");
    };
  }, [open, step]);

  const finish = () => {
    localStorage.setItem("cve-tracker-tour-complete", "true");
    setOpen(false);
    setStep(0);
  };

  const currentStep = tourSteps[step];
  const isLast = step === tourSteps.length - 1;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            Onboarding {step + 1}/{tourSteps.length}
          </DialogTitle>
          <DialogDescription>
            {currentStep.title}: {currentStep.content}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={finish}>
            Passer
          </Button>
          <Button
            onClick={() => {
              if (isLast) {
                finish();
              } else {
                setStep((current) => current + 1);
              }
            }}
          >
            {isLast ? "Terminer" : "Suivant"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function IntlProvider({ children }: { children: React.ReactNode }) {
  const locale = useUiPreferencesStore((state) => state.locale);
  const messages = i18nMessages[locale];
  const handleIntlError = React.useCallback((error: IntlError) => {
    if (error.code === IntlErrorCode.ENVIRONMENT_FALLBACK) {
      return;
    }

    console.error(error);
  }, []);

  return (
    <NextIntlClientProvider
      locale={locale}
      messages={messages}
      timeZone="UTC"
      onError={handleIntlError}
    >
      {children}
    </NextIntlClientProvider>
  );
}

export function AppProviders({ children }: { children: React.ReactNode }) {
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
      <QueryClientProvider client={queryClient}>
        <IntlProvider>
          <ThemeBridge />
          <Onboarding />
          {children}
          <Toaster />
        </IntlProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
