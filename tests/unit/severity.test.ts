import { describe, expect, it } from "vitest";
import { calculateSeverityFromCvss, pickScore } from "@/lib/v2/severity";

describe("calculateSeverityFromCvss", () => {
  it("returns NONE when no score provided", () => {
    expect(calculateSeverityFromCvss(null, null)).toBe("NONE");
    expect(calculateSeverityFromCvss(undefined, undefined)).toBe("NONE");
  });

  it("returns NONE for a zero score", () => {
    expect(calculateSeverityFromCvss(0, null)).toBe("NONE");
  });

  it("classifies LOW (0 < score < 4)", () => {
    expect(calculateSeverityFromCvss(0.1, null)).toBe("LOW");
    expect(calculateSeverityFromCvss(3.9, null)).toBe("LOW");
  });

  it("classifies MEDIUM (4 <= score < 7)", () => {
    expect(calculateSeverityFromCvss(4, null)).toBe("MEDIUM");
    expect(calculateSeverityFromCvss(6.9, null)).toBe("MEDIUM");
  });

  it("classifies HIGH (7 <= score < 9)", () => {
    expect(calculateSeverityFromCvss(7, null)).toBe("HIGH");
    expect(calculateSeverityFromCvss(8.9, null)).toBe("HIGH");
  });

  it("classifies CRITICAL (score >= 9)", () => {
    expect(calculateSeverityFromCvss(9, null)).toBe("CRITICAL");
    expect(calculateSeverityFromCvss(10, null)).toBe("CRITICAL");
  });

  it("prefers CVSS v4 score when both are provided", () => {
    // v4 says LOW, v3 says CRITICAL → v4 wins
    expect(calculateSeverityFromCvss(9.5, 2)).toBe("LOW");
  });
});

describe("pickScore", () => {
  it("prefers v4 over v3", () => {
    expect(pickScore(5, 8)).toBe(8);
  });

  it("falls back to v3 when v4 missing", () => {
    expect(pickScore(5, null)).toBe(5);
    expect(pickScore(5, undefined)).toBe(5);
  });

  it("returns null when neither is a number", () => {
    expect(pickScore(null, null)).toBeNull();
    expect(pickScore(undefined, undefined)).toBeNull();
  });
});
