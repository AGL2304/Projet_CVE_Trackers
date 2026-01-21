import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

interface NVDCVE {
  cve: {
    id: string
    descriptions: { lang: string; value: string }[]
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData: {
          baseScore: number
          baseSeverity: string
          vectorString: string
        }
      }>
    }
    references?: { url: string }[]
    published: string
    lastModified: string
    vulnStatus: string
  }
}

function mapNVDSeverity(severity: string): string {
  const normalizedSeverity = severity?.toLowerCase() || 'unknown'

  if (normalizedSeverity === 'critical') return 'critical'
  if (normalizedSeverity === 'high') return 'high'
  if (normalizedSeverity === 'medium') return 'medium'
  if (normalizedSeverity === 'low') return 'low'

  return 'medium' // Default fallback
}

export async function POST(request: NextRequest) {
  try {
    const nvdCVE: NVDCVE = await request.json()

    // Extract data from NVD format
    const cveId = nvdCVE.cve.id
    const description =
      nvdCVE.cve.descriptions.find((d) => d.lang === 'en')?.value ||
      nvdCVE.cve.descriptions[0]?.value ||
      'No description available'

    const cvssMetric = nvdCVE.cve.metrics?.cvssMetricV31?.[0]
    const cvssScore = cvssMetric?.cvssData.baseScore
    const cvssVector = cvssMetric?.cvssData.vectorString
    const rawSeverity = cvssMetric?.cvssData.baseSeverity

    const severity = mapNVDSeverity(rawSeverity || 'medium')

    const publishedDate = nvdCVE.cve.published
    const lastModifiedDate = nvdCVE.cve.lastModified
    const vulnStatus = nvdCVE.cve.vulnStatus

    // Extract references as JSON array
    const references = nvdCVE.cve.references?.map((ref) => ref.url) || []

    // Check if CVE already exists
    const existingCVE = await db.cVE.findUnique({
      where: { cveId },
    })

    if (existingCVE) {
      // Update existing CVE
      const updatedCVE = await db.cVE.update({
        where: { cveId },
        data: {
          description,
          severity,
          cvssScore,
          cvssVector,
          publishedDate: publishedDate ? new Date(publishedDate) : null,
          lastModifiedDate: lastModifiedDate ? new Date(lastModifiedDate) : null,
          references: JSON.stringify(references),
          vulnStatus,
          updatedAt: new Date(),
        },
      })

      return NextResponse.json(updatedCVE)
    }

    // Create new CVE
    const newCVE = await db.cVE.create({
      data: {
        cveId,
        description,
        severity,
        cvssScore,
        cvssVector,
        publishedDate: publishedDate ? new Date(publishedDate) : null,
        lastModifiedDate: lastModifiedDate ? new Date(lastModifiedDate) : null,
        references: JSON.stringify(references),
        vulnStatus,
        importedAt: new Date(),
      },
    })

    return NextResponse.json(newCVE, { status: 201 })
  } catch (error) {
    console.error('Error importing CVE:', error)
    return NextResponse.json(
      {
        error: 'Failed to import CVE',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}
