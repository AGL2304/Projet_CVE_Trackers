import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

// GET all assets
export async function GET() {
  try {
    const assets = await db.asset.findMany({
      orderBy: {
        createdAt: 'desc',
      },
    })

    return NextResponse.json(assets)
  } catch (error) {
    console.error('Error fetching assets:', error)
    return NextResponse.json(
      { error: 'Failed to fetch assets' },
      { status: 500 }
    )
  }
}

// POST create asset
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { name, type, ip, hostname, description, criticality, status } = body

    if (!name || !type) {
      return NextResponse.json(
        { error: 'Name and type are required' },
        { status: 400 }
      )
    }

    const asset = await db.asset.create({
      data: {
        name,
        type,
        ip: ip || null,
        hostname: hostname || null,
        description: description || null,
        criticality: criticality || 'medium',
        status: status || 'active',
      },
    })

    return NextResponse.json(asset, { status: 201 })
  } catch (error) {
    console.error('Error creating asset:', error)
    return NextResponse.json(
      { error: 'Failed to create asset' },
      { status: 500 }
    )
  }
}
