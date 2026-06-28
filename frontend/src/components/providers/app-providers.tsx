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

const tourSteps = {
  fr: [
    {
      target: "#main-nav",
      title: "Navigation principale",
      content: "Dashboard, CVEs, actifs, reporting et administration.",
    },
    {
      target: "#global-search-trigger",
      title: "Recherche globale",
      content: "Recherche rapide CVE/CWE/produit avec Ctrl+K.",
    },
    {
      target: "#dashboard-kpis",
      title: "KPIs securite",
      content: "Exposition critique, nouvelles CVEs et score CVSS moyen.",
    },
  ],
  en: [
    {
      target: "#main-nav",
      title: "Main navigation",
      content: "Dashboard, CVEs, assets, reporting and administration.",
    },
    {
      target: "#global-search-trigger",
      title: "Global search",
      content: "Quick CVE/CWE/product search with Ctrl+K.",
    },
    {
      target: "#dashboard-kpis",
      title: "Security KPIs",
      content: "Critical exposure, new CVEs and average CVSS score.",
    },
  ],
} as const;

const ONBOARDING_ENABLED = false;
let uiPreferencesHydrationRequested = false;
type ThemePreference = "system" | "light" | "dark";

function normalizeThemePreference(value: unknown): ThemePreference {
  if (value === "light" || value === "dark" || value === "system") {
    return value;
  }
  return "system";
}

function useUiPreferencesHydration() {
  // On the server, `createJSONStorage(() => localStorage)` throws (no
  // localStorage), so zustand's persist middleware skips attaching the
  // `.persist` API. Guard every access so SSR renders the un-hydrated
  // default state instead of crashing; the client bundle has `.persist`
  // and performs the real rehydration in the effect below.
  const [hydrated, setHydrated] = React.useState(
    () => useUiPreferencesStore.persist?.hasHydrated() ?? false
  );

  React.useEffect(() => {
    const persistApi = useUiPreferencesStore.persist;
    if (!persistApi) return;

    const unsubscribeHydrate = persistApi.onHydrate(() => setHydrated(false));
    const unsubscribeFinish = persistApi.onFinishHydration(() => setHydrated(true));

    if (!uiPreferencesHydrationRequested) {
      uiPreferencesHydrationRequested = true;
      void persistApi.rehydrate();
    } else {
      setHydrated(persistApi.hasHydrated());
    }

    return () => {
      unsubscribeHydrate();
      unsubscribeFinish();
    };
  }, []);

  return hydrated;
}

function ThemeBridge({ hydrated }: { hydrated: boolean }) {
  const themePreference = useUiPreferencesStore((state) => state.themePreference);
  const setThemePreference = useUiPreferencesStore((state) => state.setThemePreference);
  const initializedRef = React.useRef(false);
  const { theme, setTheme } = useTheme();

  React.useEffect(() => {
    if (!hydrated) return;
    const storeTheme = normalizeThemePreference(themePreference);
    const currentTheme = normalizeThemePreference(theme);

    // First hydration: trust persisted UI preference to avoid random fallback to system/light.
    if (!initializedRef.current) {
      initializedRef.current = true;
      if (currentTheme !== storeTheme) {
        setTheme(storeTheme);
      }
      return;
    }

    // Keep the store aligned with the actual next-themes state.
    if (currentTheme !== storeTheme) {
      setThemePreference(currentTheme);
    }
  }, [hydrated, setTheme, setThemePreference, theme, themePreference]);

  return null;
}

function LocaleHtmlBridge({ hydrated }: { hydrated: boolean }) {
  const locale = useUiPreferencesStore((state) => state.locale);

  React.useEffect(() => {
    if (!hydrated) return;
    document.documentElement.lang = locale;
  }, [hydrated, locale]);

  return null;
}

function Onboarding() {
  const locale = useUiPreferencesStore((state) => state.locale);
  const steps = tourSteps[locale];
  const [open, setOpen] = React.useState(false);
  const [step, setStep] = React.useState(0);

  React.useEffect(() => {
    if (!ONBOARDING_ENABLED) return;
    const done = localStorage.getItem("cve-tracker-tour-complete");
    if (!done) {
      const handle = setTimeout(() => setOpen(true), 350);
      return () => clearTimeout(handle);
    }
  }, []);

  if (!ONBOARDING_ENABLED) return null;

  const finish = () => {
    localStorage.setItem("cve-tracker-tour-complete", "true");
    setOpen(false);
    setStep(0);
  };

  const currentStep = steps[step];
  const isLast = step === steps.length - 1;
  const labels =
    locale === "fr"
      ? { title: "Onboarding", skip: "Passer", done: "Terminer", next: "Suivant" }
      : { title: "Onboarding", skip: "Skip", done: "Finish", next: "Next" };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {labels.title} {step + 1}/{steps.length}
          </DialogTitle>
          <DialogDescription>
            {currentStep.title}: {currentStep.content}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={finish}>
            {labels.skip}
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
            {isLast ? labels.done : labels.next}
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
  const uiPreferencesHydrated = useUiPreferencesHydration();

  return (
    <ThemeProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      disableTransitionOnChange
      storageKey="cve-tracker-theme"
    >
      <QueryClientProvider client={queryClient}>
        <IntlProvider>
          <ThemeBridge hydrated={uiPreferencesHydrated} />
          <LocaleHtmlBridge hydrated={uiPreferencesHydrated} />
          <Onboarding />
          {children}
          <Toaster />
        </IntlProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
