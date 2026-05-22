import { describe, expect, it, vi } from "vitest";

// Mock prisma to avoid actually hitting a DB — we only test the mapping logic
vi.mock("@/lib/db", () => ({
  db: {
    cVE: {
      findUnique: vi.fn().mockResolvedValue(null),
      create: vi.fn().mockImplementation(({ data }: any) => Promise.resolve({ id: "test", ...data })),
      update: vi.fn(),
    },
    syncJob: {
      create: vi.fn().mockResolvedValue({ id: "job-1" }),
      update: vi.fn().mockResolvedValue({ id: "job-1" }),
      findFirst: vi.fn().mockResolvedValue(null),
    },
  },
}));

describe("nvd-sync — upsertNvdCve mapping", () => {
  it("maps a CVSS v3.1 NVD entry to the expected DB row shape", async () => {
    const { upsertNvdCve } = await import("@/lib/nvd-sync");
    const { db } = await import("@/lib/db");

    const sample = {
      cve: {
        id: "CVE-2026-12345",
        descriptions: [
          { lang: "en", value: "Sample English description" },
          { lang: "fr", value: "Description en français" },
        ],
        metrics: {
          cvssMetricV31: [
            {
              cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N" },
            },
          ],
        },
        references: [{ url: "https://example.com/advisory" }],
        published: "2026-04-01T00:00:00.000Z",
        lastModified: "2026-04-05T00:00:00.000Z",
        vulnStatus: "Analyzed",
      },
    };

    const result = await upsertNvdCve(sample as any);
    expect(result).toBe("created");

    const createCall = (db.cVE.create as any).mock.calls[0][0];
    expect(createCall.data.cveId).toBe("CVE-2026-12345");
    expect(createCall.data.description).toBe("Sample English description");
    expect(createCall.data.cvssV3Score).toBe(9.8);
    expect(createCall.data.severity).toBe("CRITICAL");
    expect(createCall.data.source).toBe("NVD");
    expect(createCall.data.publishedAt).toBeInstanceOf(Date);
    expect(JSON.parse(createCall.data.references)).toEqual(["https://example.com/advisory"]);
  });

  it("falls back to first available description when no English one present", async () => {
    const { upsertNvdCve } = await import("@/lib/nvd-sync");
    const { db } = await import("@/lib/db");
    (db.cVE.create as any).mockClear();

    const sample = {
      cve: {
        id: "CVE-2026-99999",
        descriptions: [{ lang: "ja", value: "日本語の説明" }],
      },
    };

    await upsertNvdCve(sample as any);
    const createCall = (db.cVE.create as any).mock.calls[0][0];
    expect(createCall.data.description).toBe("日本語の説明");
    expect(createCall.data.severity).toBe("NONE");
  });
});
