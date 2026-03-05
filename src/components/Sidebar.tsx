"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";
import {
  AlertTriangle,
  BarChart3,
  Database,
  LayoutDashboard,
  Server,
  Settings,
  ShieldCheck,
} from "lucide-react";
import { cn } from "@/lib/utils";

const navigation = [
  { href: "/", key: "dashboard", icon: LayoutDashboard },
  { href: "/cves", key: "cves", icon: Database },
  { href: "/vulnerabilities", key: "vulnerabilities", icon: AlertTriangle },
  { href: "/assets", key: "assets", icon: Server },
  { href: "/reports", key: "reports", icon: BarChart3 },
  { href: "/settings", key: "settings", icon: Settings },
] as const;

export function Sidebar() {
  const pathname = usePathname();
  const t = useTranslations();

  return (
    <aside className="hidden w-72 shrink-0 border-r border-sidebar-border bg-sidebar text-sidebar-foreground xl:flex xl:flex-col">
      <div className="flex h-16 items-center gap-3 border-b border-sidebar-border px-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground shadow-sm">
          <ShieldCheck className="h-5 w-5" aria-hidden="true" />
        </div>
        <div className="space-y-0.5">
          <p className="font-semibold leading-none">{t("appName")}</p>
          <p className="text-xs text-sidebar-foreground/70">SOC Frontend Control Plane</p>
        </div>
      </div>

      <nav id="main-nav" className="flex-1 space-y-1 px-3 py-4" aria-label="Primary navigation">
        {navigation.map((item) => {
          const active = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "group flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors focus-visible:focus-ring",
                active
                  ? "bg-sidebar-primary/15 text-sidebar-primary"
                  : "text-sidebar-foreground/85 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              )}
              aria-current={active ? "page" : undefined}
            >
              <item.icon className="h-4 w-4" aria-hidden="true" />
              <span>{t(item.key)}</span>
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-sidebar-border px-5 py-4 text-xs text-sidebar-foreground/60">
        WCAG 2.1 AA | Keyboard-first | FR/EN
      </div>
    </aside>
  );
}