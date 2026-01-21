import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

// GET all CVEs
export async function GET() {
  try {
    const cves = await db.cVE.findMany({
      orderBy: {
        importedAt: 'desc',
      },
    })

    return NextResponse.json(cves)
  } catch (error) {
    console.error('Error fetching CVEs:', error)
    return NextResponse.json(
      { error: 'Failed to fetch CVEs' },
      { status: 500 }
    )
  }
}
