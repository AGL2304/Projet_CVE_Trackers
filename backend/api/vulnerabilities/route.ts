import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

// GET - List all vulnerabilities
export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url)
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '10')
    const severity = searchParams.get('severity')
    const status = searchParams.get('status')
    const search = searchParams.get('search')
    const assetId = searchParams.get('assetId')

    const skip = (page - 1) * limit

    // Build where clause
    const where: any = {}

    if (severity && severity !== 'all') {
      where.severity = severity
    }

    if (status && status !== 'all') {
      where.status = status
    }

    if (search) {
      where.OR = [
        { title: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } },
        { cveId: { contains: search, mode: 'insensitive' } },
      ]
    }

    if (assetId) {
      where.assetId = assetId
    }

    // Get total count
    const total = await db.vulnerability.count({ where })

    // Get vulnerabilities with pagination
    const vulnerabilities = await db.vulnerability.findMany({
      where,
      include: {
        asset: {
          select: {
            id: true,
            name: true,
            type: true,
            hostname: true,
            ip: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    })

    return NextResponse.json({
      vulnerabilities,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    })
  } catch (error) {
    console.error('Error fetching vulnerabilities:', error)
    return NextResponse.json(
      { error: 'Failed to fetch vulnerabilities' },
      { status: 500 }
    )
  }
}

// POST - Create a new vulnerability
export async function POST(request: Request) {
  try {
    const body = await request.json()

    const vulnerability = await db.vulnerability.create({
      data: {
        title: body.title,
        description: body.description,
        severity: body.severity,
        status: body.status || 'open',
        cvssScore: body.cvssScore,
        cveId: body.cveId,
        assetId: body.assetId,
        discoveredAt: body.discoveredAt ? new Date(body.discoveredAt) : new Date(),
        resolvedAt: body.resolvedAt ? new Date(body.resolvedAt) : null,
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

    return NextResponse.json(vulnerability, { status: 201 })
  } catch (error) {
    console.error('Error creating vulnerability:', error)
    return NextResponse.json(
      { error: 'Failed to create vulnerability' },
      { status: 500 }
    )
  }
}
