"use client";

import { Badge } from "@/components/ui/badge";
import { getSeverityClass, severityLabel } from "@/lib/cvss";
import { useUiPreferencesStore } from "@/store/ui-preferences";

export function SeverityBadge({ value }: { value?: string | null }) {
  const locale = useUiPreferencesStore((state) => state.locale);

  return (
    <Badge className={getSeverityClass(value)}>
      {severityLabel(value, locale)}
    </Badge>
  );
}
