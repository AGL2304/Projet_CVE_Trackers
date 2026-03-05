"use client";

import { Skeleton } from "@/components/ui/skeleton";

export function LoadingGrid({
  cards = 4,
  rows = 8,
}: {
  cards?: number;
  rows?: number;
}) {
  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: cards }).map((_, index) => (
          <Skeleton key={index} className="h-28 rounded-xl" />
        ))}
      </div>
      <div className="space-y-2">
        {Array.from({ length: rows }).map((_, index) => (
          <Skeleton key={index} className="h-10 rounded-md" />
        ))}
      </div>
    </div>
  );
}
