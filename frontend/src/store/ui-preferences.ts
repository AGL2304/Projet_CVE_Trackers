"use client";

import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";

export type CveViewMode = "table" | "cards" | "timeline";
export type DashboardRange = "7d" | "30d" | "90d";
export type ThemePreference = "system" | "light" | "dark";
export type LocalePreference = "fr" | "en";

type AssignmentEntry = {
  cveId: string;
  assignee: string;
  status: "todo" | "in_progress" | "done";
  updatedAt: string;
};

interface UiPreferencesState {
  locale: LocalePreference;
  dashboardRange: DashboardRange;
  cveViewMode: CveViewMode;
  themePreference: ThemePreference;
  selectedColumns: string[];
  quickSearchOpen: boolean;
  shortcutsOpen: boolean;
  assignments: Record<string, AssignmentEntry>;
  setLocale: (locale: LocalePreference) => void;
  setDashboardRange: (range: DashboardRange) => void;
  setCveViewMode: (mode: CveViewMode) => void;
  setThemePreference: (theme: ThemePreference) => void;
  setSelectedColumns: (columns: string[]) => void;
  setQuickSearchOpen: (open: boolean) => void;
  setShortcutsOpen: (open: boolean) => void;
  upsertAssignment: (entry: AssignmentEntry) => void;
  updateAssignmentStatus: (cveId: string, status: AssignmentEntry["status"]) => void;
}

const defaultColumns = [
  "cveId",
  "severity",
  "cvssScore",
  "vendor",
  "product",
  "publishedDate",
  "status",
];

export const useUiPreferencesStore = create<UiPreferencesState>()(
  persist(
    (set) => ({
      locale: "fr",
      dashboardRange: "30d",
      cveViewMode: "table",
      themePreference: "system",
      selectedColumns: defaultColumns,
      quickSearchOpen: false,
      shortcutsOpen: false,
      assignments: {},
      setLocale: (locale) => set({ locale }),
      setDashboardRange: (dashboardRange) => set({ dashboardRange }),
      setCveViewMode: (cveViewMode) => set({ cveViewMode }),
      setThemePreference: (themePreference) => set({ themePreference }),
      setSelectedColumns: (selectedColumns) => set({ selectedColumns }),
      setQuickSearchOpen: (quickSearchOpen) => set({ quickSearchOpen }),
      setShortcutsOpen: (shortcutsOpen) => set({ shortcutsOpen }),
      upsertAssignment: (entry) =>
        set((state) => ({
          assignments: {
            ...state.assignments,
            [entry.cveId]: entry,
          },
        })),
      updateAssignmentStatus: (cveId, status) =>
        set((state) => {
          const current = state.assignments[cveId];
          if (!current) return state;
          return {
            assignments: {
              ...state.assignments,
              [cveId]: {
                ...current,
                status,
                updatedAt: new Date().toISOString(),
              },
            },
          };
        }),
    }),
    {
      name: "cve-tracker-ui-preferences",
      storage: createJSONStorage(() => localStorage),
      skipHydration: true,
      partialize: (state) => ({
        locale: state.locale,
        dashboardRange: state.dashboardRange,
        cveViewMode: state.cveViewMode,
        themePreference: state.themePreference,
        selectedColumns: state.selectedColumns,
        assignments: state.assignments,
      }),
    }
  )
);
