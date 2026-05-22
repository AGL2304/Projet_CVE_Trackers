import { NextResponse } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const STATUSES = ["open", "in_progress", "resolved", "ignored"] as const;

const updateSchema = z.object({
  title: z.string().trim().min(3).max(200).optional(),
  description: z.string().trim().max(5000).optional().nullable(),
  severity: z.enum(SEVERITIES).optional(),
  status: z.enum(STATUSES).optional(),
  cvssScore: z.number().min(0).max(10).optional().nullable(),
  cveId: z.string().trim().max(40).optional().nullable(),
  assetId: z.string().trim().min(1).optional().nullable(),
});

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const vulnerability = await db.vulnerability.findUnique({
      where: { id },
      include: {
        asset: {
          select: { id: true, name: true, type: true, hostname: true, ip: true, criticality: true },
        },
      },
    });
    if (!vulnerability) {
      return NextResponse.json({ error: "Vulnerability not found" }, { status: 404 });
    }
    return NextResponse.json(vulnerability);
  } catch (error) {
    console.error("Error fetching vulnerability:", error);
    return NextResponse.json({ error: "Failed to fetch vulnerability" }, { status: 500 });
  }
}

export async function PUT(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const body = await request.json();
    // Sanitize before validation
    if (body.assetId === "" || body.assetId === "none") body.assetId = null;
    if (typeof body.cvssScore === "string") {
      const n = Number(body.cvssScore);
      body.cvssScore = Number.isNaN(n) ? null : n;
    }

    const parsed = updateSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ") },
        { status: 400 }
      );
    }

    // Read current to compute resolvedAt transition correctly:
    //   - resolved → null: clear resolvedAt
    //   - other → resolved: set resolvedAt to now
    //   - resolved → resolved (or no status change): keep existing
    const existing = await db.vulnerability.findUnique({ where: { id } });
    if (!existing) {
      return NextResponse.json({ error: "Not found" }, { status: 404 });
    }

    const data = parsed.data;
    const newStatus = data.status ?? existing.status;
    let resolvedAt: Date | null | undefined = undefined;
    if (data.status !== undefined && data.status !== existing.status) {
      if (newStatus === "resolved") resolvedAt = new Date();
      else resolvedAt = null;
    }

    const vulnerability = await db.vulnerability.update({
      where: { id },
      data: {
        ...(data.title !== undefined && { title: data.title }),
        ...(data.description !== undefined && { description: data.description ?? null }),
        ...(data.severity !== undefined && { severity: data.severity }),
        ...(data.status !== undefined && { status: data.status }),
        ...(data.cvssScore !== undefined && { cvssScore: data.cvssScore ?? null }),
        ...(data.cveId !== undefined && { cveId: data.cveId ?? null }),
        ...(data.assetId !== undefined && { assetId: data.assetId ?? null }),
        ...(resolvedAt !== undefined && { resolvedAt }),
      },
      include: {
        asset: { select: { id: true, name: true, type: true } },
      },
    });

    return NextResponse.json(vulnerability);
  } catch (error) {
    console.error("Error updating vulnerability:", error);
    return NextResponse.json({ error: "Failed to update vulnerability" }, { status: 500 });
  }
}

export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    await db.vulnerability.delete({ where: { id } });
    return NextResponse.json({ message: "Vulnerability deleted successfully" });
  } catch (error) {
    console.error("Error deleting vulnerability:", error);
    return NextResponse.json({ error: "Failed to delete vulnerability" }, { status: 500 });
  }
}
