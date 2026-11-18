import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { mapCveToLegacy } from '@/lib/v2/mappers'

// GET CVEs. Without `limit`, returns the full table (kept for backward
// compatibility with pages that still do client-side search over the full
// dataset). Callers that only need a bounded, recent slice (e.g. the
// dashboard) should pass `limit` to avoid paging the entire NVD-synced table.
// `cveId` does a single indexed lookup instead of paging anything.
export async function GET(request: NextRequest) {
  try {
    const cveIdParam = request.nextUrl.searchParams.get('cveId')
    if (cveIdParam) {
      const cve = await db.cVE.findUnique({ where: { cveId: cveIdParam } })
      return NextResponse.json(cve ? [mapCveToLegacy(cve)] : [])
    }

    const limitParam = request.nextUrl.searchParams.get('limit')
    const limit = limitParam ? Math.min(Math.max(parseInt(limitParam, 10) || 0, 1), 1000) : undefined

    const cves = await db.cVE.findMany({
      orderBy: {
        importedAt: 'desc',
      },
      ...(limit ? { take: limit } : {}),
    })

    return NextResponse.json(cves.map(mapCveToLegacy))
  } catch (error) {
    console.error('Error fetching CVEs:', error)
    return NextResponse.json(
      { error: 'Failed to fetch CVEs' },
      { status: 500 }
    )
  }
}
