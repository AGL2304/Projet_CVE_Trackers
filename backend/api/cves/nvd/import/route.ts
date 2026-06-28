import { CVEStatus, CveSource, Prisma } from '@prisma/client'
import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { calculateSeverityFromCvss } from '@/lib/v2/severity'
import { mapCveToLegacy } from '@/lib/v2/mappers'
import { publishEvent } from '@/lib/webhooks'

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

export async function POST(request: NextRequest) {
  try {
    const nvdCVE: NVDCVE = await request.json()

    const cveId = nvdCVE.cve.id
    const description =
      nvdCVE.cve.descriptions.find((d) => d.lang === 'en')?.value ||
      nvdCVE.cve.descriptions[0]?.value ||
      'No description available'

    const cvssMetric = nvdCVE.cve.metrics?.cvssMetricV31?.[0]
    const cvssV3Score = cvssMetric?.cvssData.baseScore
    const cvssV3Vector = cvssMetric?.cvssData.vectorString
    const severity = calculateSeverityFromCvss(cvssV3Score, null)

    const publishedAt = nvdCVE.cve.published ? new Date(nvdCVE.cve.published) : null
    const modifiedAt = nvdCVE.cve.lastModified ? new Date(nvdCVE.cve.lastModified) : null
    const vulnStatus = nvdCVE.cve.vulnStatus
    const references = nvdCVE.cve.references?.map((ref) => ref.url) || []

    const upserted = await db.cVE.upsert({
      where: { cveId },
      update: {
        title: cveId,
        description,
        publishedAt,
        modifiedAt,
        cvssV3Score,
        cvssV3Vector,
        status: CVEStatus.ANALYZING,
        severity,
        source: CveSource.NVD,
        rawData: nvdCVE as unknown as Prisma.InputJsonValue,
        references: JSON.stringify(references),
        vulnStatus,
        cvssScore: cvssV3Score,
        cvssVector: cvssV3Vector,
        publishedDate: publishedAt,
        lastModifiedDate: modifiedAt,
        version: { increment: 1 },
      },
      create: {
        cveId,
        title: cveId,
        description,
        publishedAt,
        modifiedAt,
        cvssV3Score,
        cvssV3Vector,
        status: CVEStatus.NEW,
        severity,
        source: CveSource.NVD,
        rawData: nvdCVE as unknown as Prisma.InputJsonValue,
        references: JSON.stringify(references),
        vulnStatus,
        cvssScore: cvssV3Score,
        cvssVector: cvssV3Vector,
        publishedDate: publishedAt,
        lastModifiedDate: modifiedAt,
      },
    })

    // Publish a webhook event so subscribers (SIEM…) can react in real time.
    // Fire-and-forget — never block the import on a slow subscriber.
    publishEvent('cve.created', {
      cveId: upserted.cveId,
      severity: upserted.severity,
      cvssV3Score: upserted.cvssV3Score,
      title: upserted.title,
      source: upserted.source,
      publishedAt: upserted.publishedAt,
    })

    return NextResponse.json(mapCveToLegacy(upserted), { status: 201 })
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