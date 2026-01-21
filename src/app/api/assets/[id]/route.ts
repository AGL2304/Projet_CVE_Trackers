import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

// PUT update asset
export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    const body = await request.json()
    const { name, type, ip, hostname, description, criticality, status } = body

    const asset = await db.asset.update({
      where: { id },
      data: {
        name,
        type,
        ip: ip || null,
        hostname: hostname || null,
        description: description || null,
        criticality,
        status,
      },
    })

    return NextResponse.json(asset)
  } catch (error) {
    console.error('Error updating asset:', error)
    return NextResponse.json(
      { error: 'Failed to update asset' },
      { status: 500 }
    )
  }
}

// DELETE asset
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    await db.asset.delete({
      where: { id },
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Error deleting asset:', error)
    return NextResponse.json(
      { error: 'Failed to delete asset' },
      { status: 500 }
    )
  }
}
