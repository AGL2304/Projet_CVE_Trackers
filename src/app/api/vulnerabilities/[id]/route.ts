import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

// GET - Get a single vulnerability
export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    const vulnerability = await db.vulnerability.findUnique({
      where: { id },
      include: {
        asset: {
          select: {
            id: true,
            name: true,
            type: true,
            hostname: true,
            ip: true,
            criticality: true,
          },
        },
      },
    })

    if (!vulnerability) {
      return NextResponse.json(
        { error: 'Vulnerability not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(vulnerability)
  } catch (error) {
    console.error('Error fetching vulnerability:', error)
    return NextResponse.json(
      { error: 'Failed to fetch vulnerability' },
      { status: 500 }
    )
  }
}

// PUT - Update a vulnerability
export async function PUT(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    const body = await request.json()

    const vulnerability = await db.vulnerability.update({
      where: { id },
      data: {
        title: body.title,
        description: body.description,
        severity: body.severity,
        status: body.status,
        cvssScore: body.cvssScore,
        cveId: body.cveId,
        assetId: body.assetId,
        resolvedAt: body.status === 'resolved' ? new Date() : null,
      },
      include: {
        asset: {
          select: {
            id: true,
            name: true,
            type: true,
          },
        },
      },
    })

    return NextResponse.json(vulnerability)
  } catch (error) {
    console.error('Error updating vulnerability:', error)
    return NextResponse.json(
      { error: 'Failed to update vulnerability' },
      { status: 500 }
    )
  }
}

// DELETE - Delete a vulnerability
export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    await db.vulnerability.delete({
      where: { id },
    })

    return NextResponse.json({ message: 'Vulnerability deleted successfully' })
  } catch (error) {
    console.error('Error deleting vulnerability:', error)
    return NextResponse.json(
      { error: 'Failed to delete vulnerability' },
      { status: 500 }
    )
  }
}
