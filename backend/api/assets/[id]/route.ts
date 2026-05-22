import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";

const CRITICALITIES = ["low", "medium", "high", "critical"] as const;
const STATUSES = ["active", "inactive", "retired"] as const;

const updateAssetSchema = z.object({
  name: z.string().trim().min(2).max(120).optional(),
  type: z.string().trim().min(2).max(60).optional(),
  ip: z.string().trim().max(45).optional().nullable(),
  hostname: z.string().trim().max(253).optional().nullable(),
  description: z.string().trim().max(2000).optional().nullable(),
  criticality: z.enum(CRITICALITIES).optional(),
  status: z.enum(STATUSES).optional(),
  tags: z.array(z.string().trim().max(40)).max(20).optional(),
});

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const asset = await db.asset.findUnique({
      where: { id },
      include: {
        vulnerabilities: {
          orderBy: { discoveredAt: "desc" },
          take: 100,
        },
        owner: { select: { id: true, email: true, name: true } },
        productLinks: { include: { product: true } },
        tagLinks: { include: { tag: true } },
      },
    });
    if (!asset) return NextResponse.json({ error: "Not found" }, { status: 404 });
    return NextResponse.json(asset);
  } catch (error) {
    console.error("Error fetching asset:", error);
    return NextResponse.json({ error: "Failed to fetch asset" }, { status: 500 });
  }
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const parsed = updateAssetSchema.safeParse(await request.json());
    if (!parsed.success) {
      return NextResponse.json(
        { error: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ") },
        { status: 400 }
      );
    }

    const data = parsed.data;
    const asset = await db.asset.update({
      where: { id },
      data: {
        ...(data.name !== undefined && { name: data.name }),
        ...(data.type !== undefined && { type: data.type }),
        ...(data.ip !== undefined && { ip: data.ip || null }),
        ...(data.hostname !== undefined && { hostname: data.hostname || null }),
        ...(data.description !== undefined && { description: data.description || null }),
        ...(data.criticality !== undefined && { criticality: data.criticality }),
        ...(data.status !== undefined && { status: data.status }),
        ...(data.tags !== undefined && { tags: data.tags }),
      },
    });

    return NextResponse.json(asset);
  } catch (error) {
    console.error("Error updating asset:", error);
    return NextResponse.json({ error: "Failed to update asset" }, { status: 500 });
  }
}

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    await db.asset.delete({ where: { id } });
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Error deleting asset:", error);
    return NextResponse.json({ error: "Failed to delete asset" }, { status: 500 });
  }
}
