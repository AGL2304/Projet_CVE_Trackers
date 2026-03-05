import { Severity } from "@prisma/client";

export function calculateSeverityFromCvss(
  cvssV3Score?: number | null,
  cvssV4Score?: number | null
): Severity {
  const score = pickScore(cvssV3Score, cvssV4Score);
  if (score === null) return Severity.NONE;

  if (score === 0) return Severity.NONE;
  if (score < 4) return Severity.LOW;
  if (score < 7) return Severity.MEDIUM;
  if (score < 9) return Severity.HIGH;
  return Severity.CRITICAL;
}

export function toLegacySeverityString(severity: Severity): string {
  return severity.toLowerCase();
}

export function pickScore(
  cvssV3Score?: number | null,
  cvssV4Score?: number | null
): number | null {
  if (typeof cvssV4Score === "number") return cvssV4Score;
  if (typeof cvssV3Score === "number") return cvssV3Score;
  return null;
}
