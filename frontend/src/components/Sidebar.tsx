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
} from "lucide-react";
import { BrandMark } from "@/components/brand-mark";
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
        <BrandMark className="h-9 w-9 shrink-0 drop-shadow-sm" />
        <div className="space-y-0.5">
          <p className="font-semibold leading-none">{t("appName")}</p>
          <p className="text-xs text-sidebar-foreground/70">{t("controlPlane")}</p>
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
                "group relative flex items-center gap-3 overflow-hidden rounded-lg px-3 py-2 text-sm transition-colors focus-visible:focus-ring",
                active
                  ? "bg-sidebar-primary/15 text-sidebar-primary"
                  : "text-sidebar-foreground/85 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              )}
              aria-current={active ? "page" : undefined}
            >
              {active ? (
                <span
                  className="grad-accent absolute inset-y-1 left-0 w-1 rounded-full"
                  aria-hidden="true"
                />
              ) : null}
              <item.icon className="h-4 w-4" aria-hidden="true" />
              <span>{t(item.key)}</span>
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-sidebar-border px-5 py-4 text-xs text-sidebar-foreground/60">
        {t("accessibilityFooter")}
      </div>
    </aside>
  );
}
