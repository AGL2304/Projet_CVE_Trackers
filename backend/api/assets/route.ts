import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { Prisma } from "@prisma/client";
import { db } from "@/lib/db";

const CRITICALITIES = ["low", "medium", "high", "critical"] as const;
const STATUSES = ["active", "inactive", "retired"] as const;

const createAssetSchema = z.object({
  name: z.string().trim().min(2, "Name must be at least 2 characters").max(120),
  type: z.string().trim().min(2, "Type required").max(60),
  ip: z
    .string()
    .trim()
    .max(45)
    .optional()
    .nullable()
    .refine(
      (v) => !v || /^([0-9.]+|[0-9a-fA-F:]+)$/.test(v),
      { message: "Invalid IP address format" }
    ),
  hostname: z.string().trim().max(253).optional().nullable(),
  description: z.string().trim().max(2000).optional().nullable(),
  criticality: z.enum(CRITICALITIES).default("medium"),
  status: z.enum(STATUSES).default("active"),
  tags: z.array(z.string().trim().max(40)).max(20).optional(),
});

/**
 * GET /api/assets
 *
 * Query params (all optional):
 *   - search: substring match on name/hostname/ip/description
 *   - criticality, status, type: exact filter
 *   - sortBy: name | type | criticality | status | createdAt | updatedAt (default createdAt)
 *   - sortDir: asc | desc (default desc)
 *   - page (1-indexed), pageSize (max 200)
 */
export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const search = url.searchParams.get("search")?.trim() || "";
    const criticality = url.searchParams.get("criticality");
    const status = url.searchParams.get("status");
    const type = url.searchParams.get("type");
    const sortBy = url.searchParams.get("sortBy") || "createdAt";
    const sortDir = url.searchParams.get("sortDir") === "asc" ? "asc" : "desc";
    const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
    const pageSize = Math.min(200, Math.max(1, Number(url.searchParams.get("pageSize")) || 100));

    const where: Prisma.AssetWhereInput = {};
    if (search) {
      where.OR = [
        { name: { contains: search, mode: "insensitive" } },
        { hostname: { contains: search, mode: "insensitive" } },
        { ip: { contains: search, mode: "insensitive" } },
        { description: { contains: search, mode: "insensitive" } },
        { type: { contains: search, mode: "insensitive" } },
      ];
    }
    if (criticality && criticality !== "all" && CRITICALITIES.includes(criticality as typeof CRITICALITIES[number])) {
      where.criticality = criticality;
    }
    if (status && status !== "all" && STATUSES.includes(status as typeof STATUSES[number])) {
      where.status = status;
    }
    if (type && type !== "all") {
      where.type = type;
    }

    const allowedSorts = new Set(["name", "type", "criticality", "status", "createdAt", "updatedAt"]);
    const sortKey = allowedSorts.has(sortBy) ? sortBy : "createdAt";
    const orderBy: Prisma.AssetOrderByWithRelationInput = { [sortKey]: sortDir };

    const [assets, total, byCriticality, byStatus] = await Promise.all([
      db.asset.findMany({
        where,
        orderBy,
        skip: (page - 1) * pageSize,
        take: pageSize,
        include: {
          _count: { select: { vulnerabilities: true, productLinks: true, tagLinks: true } },
        },
      }),
      db.asset.count({ where }),
      db.asset.groupBy({ by: ["criticality"], _count: { _all: true } }),
      db.asset.groupBy({ by: ["status"], _count: { _all: true } }),
    ]);

    return NextResponse.json({
      assets,
      pagination: { page, pageSize, total, pages: Math.ceil(total / pageSize) },
      stats: {
        total,
        byCriticality: Object.fromEntries(byCriticality.map((g) => [g.criticality, g._count._all])),
        byStatus: Object.fromEntries(byStatus.map((g) => [g.status, g._count._all])),
      },
    });
  } catch (error) {
    console.error("Error fetching assets:", error);
    return NextResponse.json({ error: "Failed to fetch assets" }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const parsed = createAssetSchema.safeParse(await request.json());
    if (!parsed.success) {
      return NextResponse.json(
        { error: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ") },
        { status: 400 }
      );
    }

    const asset = await db.asset.create({
      data: {
        name: parsed.data.name,
        type: parsed.data.type,
        ip: parsed.data.ip || null,
        hostname: parsed.data.hostname || null,
        description: parsed.data.description || null,
        criticality: parsed.data.criticality,
        status: parsed.data.status,
        tags: parsed.data.tags ?? [],
      },
    });

    return NextResponse.json(asset, { status: 201 });
  } catch (error) {
    console.error("Error creating asset:", error);
    return NextResponse.json({ error: "Failed to create asset" }, { status: 500 });
  }
}
