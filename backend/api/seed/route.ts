import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

/**
 * Seeding of mock/demo data is intentionally DISABLED.
 *
 * The system must contain only real, scan-discovered data (pushed via
 * /api/v2/sync/cpe by Network Scanner Pro). This endpoint previously inserted
 * 12 mock assets and 20 mock vulnerabilities; that behaviour has been removed
 * so demo data can never be (re)injected.
 */

export async function POST() {
  return NextResponse.json(
    {
      error: 'Seeding disabled',
      message:
        'Mock/demo seed data is disabled. The system only stores real, ' +
        'scan-discovered data (see POST /api/v2/sync/cpe).',
    },
    { status: 410 }
  )
}

// GET stays read-only: report whether any data currently exists.
export async function GET() {
  try {
    const assetCount = await db.asset.count()
    const vulnCount = await db.vulnerability.count()

    return NextResponse.json({
      hasSeedData: assetCount > 0 || vulnCount > 0,
      assetCount,
      vulnCount,
      seedingEnabled: false,
    })
  } catch (error) {
    console.error('Error checking seed data:', error)
    return NextResponse.json(
      { error: 'Failed to check seed data' },
      { status: 500 }
    )
  }
}
