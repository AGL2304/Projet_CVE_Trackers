import { NextRequest, NextResponse } from 'next/server'

const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const keyword = searchParams.get('keyword')

    if (!keyword) {
      return NextResponse.json(
        { error: 'Keyword parameter is required' },
        { status: 400 }
      )
    }

    // Build NVD API query
    const url = new URL(NVD_API_BASE)
    url.searchParams.append('keywordSearch', keyword)
    url.searchParams.append('resultsPerPage', '20')

    const response = await fetch(url.toString(), {
      headers: {
        'User-Agent': 'CVE-Tracker/1.0',
      },
    })

    if (!response.ok) {
      throw new Error(`NVD API error: ${response.status}`)
    }

    const data = await response.json()

    // Return the NVD response directly
    return NextResponse.json(data)
  } catch (error) {
    console.error('Error searching NVD:', error)
    return NextResponse.json(
      {
        error: 'Failed to search NVD',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}
