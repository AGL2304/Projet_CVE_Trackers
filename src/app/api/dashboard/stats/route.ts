import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET() {
  try {
    // Get total counts
    const totalAssets = await db.asset.count()
    const totalVulnerabilities = await db.vulnerability.count()
    const criticalVulnerabilities = await db.vulnerability.count({
      where: { severity: 'critical' }
    })
    const resolvedVulnerabilities = await db.vulnerability.count({
      where: { status: 'resolved' }
    })
    const totalCVEs = await db.cVE.count()

    // Vulnerabilities by severity
    const vulnerabilitiesBySeverity = await db.vulnerability.groupBy({
      by: ['severity'],
      _count: true,
      orderBy: { severity: 'asc' },
    })

    // Map severity to colors
    const severityColors = {
      low: '#22c55e',
      medium: '#eab308',
      high: '#f97316',
      critical: '#ef4444',
    }
    const severityLabels = {
      low: 'Low',
      medium: 'Medium',
      high: 'High',
      critical: 'Critical',
    }

    const vulnerabilitiesBySeverityData = vulnerabilitiesBySeverity.map(item => ({
      name: severityLabels[item.severity as keyof typeof severityLabels] || item.severity,
      value: item._count,
      color: severityColors[item.severity as keyof typeof severityColors] || '#94a3b8',
    }))

    // Assets by criticality
    const assetsByCriticality = await db.asset.groupBy({
      by: ['criticality'],
      _count: true,
      orderBy: { criticality: 'asc' },
    })

    const criticalityColors = {
      low: '#22c55e',
      medium: '#eab308',
      high: '#f97316',
      critical: '#ef4444',
    }
    const criticalityLabels = {
      low: 'Low',
      medium: 'Medium',
      high: 'High',
      critical: 'Critical',
    }

    const assetsByCriticalityData = assetsByCriticality.map(item => ({
      name: criticalityLabels[item.criticality as keyof typeof criticalityLabels] || item.criticality,
      value: item._count,
      color: criticalityColors[item.criticality as keyof typeof criticalityColors] || '#94a3b8',
    }))

    // Vulnerabilities by status
    const vulnerabilitiesByStatus = await db.vulnerability.groupBy({
      by: ['status'],
      _count: true,
      orderBy: { status: 'asc' },
    })

    const statusColors = {
      open: '#ef4444',
      in_progress: '#f97316',
      resolved: '#22c55e',
      ignored: '#9ca3af',
    }
    const statusLabels = {
      open: 'Open',
      in_progress: 'In Progress',
      resolved: 'Resolved',
      ignored: 'Ignored',
    }

    const vulnerabilitiesByStatusData = vulnerabilitiesByStatus.map(item => ({
      name: statusLabels[item.status as keyof typeof statusLabels] || item.status,
      value: item._count,
      color: statusColors[item.status as keyof typeof statusColors] || '#94a3b8',
    }))

    return NextResponse.json({
      totalAssets,
      totalVulnerabilities,
      totalCVEs,
      criticalVulnerabilities,
      resolvedVulnerabilities,
      assetsByCriticality: assetsByCriticalityData,
      vulnerabilitiesBySeverity: vulnerabilitiesBySeverityData,
      vulnerabilitiesByStatus: vulnerabilitiesByStatusData,
    })
  } catch (error) {
    console.error('Error fetching dashboard stats:', error)
    return NextResponse.json(
      { error: 'Failed to fetch dashboard stats' },
      { status: 500 }
    )
  }
}
