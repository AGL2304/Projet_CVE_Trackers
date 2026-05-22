import { NextResponse } from "next/server";
import { z } from "zod";
import { Prisma } from "@prisma/client";
import { db } from "@/lib/db";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const STATUSES = ["open", "in_progress", "resolved", "ignored"] as const;

const vulnSchema = z.object({
  title: z.string().trim().min(3).max(200),
  description: z.string().trim().max(5000).optional().nullable(),
  severity: z.enum(SEVERITIES),
  status: z.enum(STATUSES).default("open"),
  cvssScore: z.number().min(0).max(10).optional().nullable(),
  cveId: z.string().trim().max(40).optional().nullable(),
  assetId: z.string().trim().min(1).optional().nullable(),
  discoveredAt: z.string().datetime().optional(),
});

/**
 * GET /api/vulnerabilities
 *
 * Query params:
 *   - page, limit (default 50, max 500)
 *   - severity, status, assetId, cveId: exact filter
 *   - search: substring across title/description/cveId/asset fields
 *   - sortBy: severity | status | cvssScore | discoveredAt | resolvedAt | createdAt
 *   - sortDir: asc | desc
 */
export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const page = Math.max(1, parseInt(searchParams.get("page") || "1"));
    const limit = Math.min(500, Math.max(1, parseInt(searchParams.get("limit") || "50")));
    const severity = searchParams.get("severity");
    const status = searchParams.get("status");
    const search = searchParams.get("search")?.trim() || "";
    const assetId = searchParams.get("assetId");
    const cveId = searchParams.get("cveId");
    const sortBy = searchParams.get("sortBy") || "createdAt";
    const sortDir = searchParams.get("sortDir") === "asc" ? "asc" : "desc";

    const where: Prisma.VulnerabilityWhereInput = {};
    if (severity && severity !== "all") where.severity = severity;
    if (status && status !== "all") where.status = status;
    if (assetId && assetId !== "all") where.assetId = assetId;
    if (cveId) where.cveId = cveId;
    if (search) {
      where.OR = [
        { title: { contains: search, mode: "insensitive" } },
        { description: { contains: search, mode: "insensitive" } },
        { cveId: { contains: search, mode: "insensitive" } },
      ];
    }

    const allowedSorts = new Set([
      "severity",
      "status",
      "cvssScore",
      "discoveredAt",
      "resolvedAt",
      "createdAt",
      "updatedAt",
    ]);
    const sortKey = allowedSorts.has(sortBy) ? sortBy : "createdAt";
    const orderBy: Prisma.VulnerabilityOrderByWithRelationInput = { [sortKey]: sortDir };

    const skip = (page - 1) * limit;

    const [total, vulnerabilities, bySeverity, byStatus, avg] = await Promise.all([
      db.vulnerability.count({ where }),
      db.vulnerability.findMany({
        where,
        include: {
          asset: {
            select: { id: true, name: true, type: true, hostname: true, ip: true, criticality: true },
          },
        },
        orderBy,
        skip,
        take: limit,
      }),
      db.vulnerability.groupBy({ by: ["severity"], _count: { _all: true } }),
      db.vulnerability.groupBy({ by: ["status"], _count: { _all: true } }),
      db.vulnerability.aggregate({ _avg: { cvssScore: true } }),
    ]);

    return NextResponse.json({
      vulnerabilities,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
      stats: {
        total,
        avgCvss: avg._avg.cvssScore ? Number(avg._avg.cvssScore.toFixed(2)) : 0,
        bySeverity: Object.fromEntries(bySeverity.map((g) => [g.severity, g._count._all])),
        byStatus: Object.fromEntries(byStatus.map((g) => [g.status, g._count._all])),
      },
    });
  } catch (error) {
    console.error("Error fetching vulnerabilities:", error);
    return NextResponse.json({ error: "Failed to fetch vulnerabilities" }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    // Sanitize: empty string assetId becomes null to avoid Prisma FK error
    if (body.assetId === "" || body.assetId === "none") body.assetId = null;
    if (typeof body.cvssScore === "string") body.cvssScore = Number(body.cvssScore);
    if (body.cvssScore !== null && body.cvssScore !== undefined && Number.isNaN(body.cvssScore)) {
      body.cvssScore = null;
    }

    const parsed = vulnSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ") },
        { status: 400 }
      );
    }

    const data = parsed.data;
    const vulnerability = await db.vulnerability.create({
      data: {
        title: data.title,
        description: data.description ?? null,
        severity: data.severity,
        status: data.status,
        cvssScore: data.cvssScore ?? null,
        cveId: data.cveId ?? null,
        assetId: data.assetId ?? null,
        discoveredAt: data.discoveredAt ? new Date(data.discoveredAt) : new Date(),
        resolvedAt: data.status === "resolved" ? new Date() : null,
      },
      include: {
        asset: { select: { id: true, name: true, type: true } },
      },
    });
    return NextResponse.json(vulnerability, { status: 201 });
  } catch (error) {
    console.error("Error creating vulnerability:", error);
    return NextResponse.json({ error: "Failed to create vulnerability" }, { status: 500 });
  }
}
