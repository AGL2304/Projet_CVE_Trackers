'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Server, AlertTriangle, Database, TrendingUp, Shield, Activity, CheckCircle2, Clock } from 'lucide-react'
import { Bar, BarChart, XAxis, YAxis, Tooltip, ResponsiveContainer, Pie, PieChart, Cell, CartesianGrid, Legend } from 'recharts'

interface DashboardStats {
  totalAssets: number
  totalVulnerabilities: number
  totalCVEs: number
  criticalVulnerabilities: number
  resolvedVulnerabilities: number
  vulnerabilitiesBySeverity: { name: string; value: number; color: string }[]
  assetsByCriticality: { name: string; value: number; color: string }[]
  vulnerabilitiesByStatus: { name: string; value: number; color: string }[]
}

const severityColors = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
}

const statusColors = {
  open: '#ef4444',
  in_progress: '#f97316',
  resolved: '#22c55e',
  ignored: '#9ca3af',
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchStats()
  }, [])

  async function fetchStats() {
    try {
      const response = await fetch('/api/dashboard/stats')
      if (response.ok) {
        const data = await response.json()
        setStats(data)
      }
    } catch (error) {
      console.error('Error fetching stats:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="p-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-slate-200 rounded w-48" />
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-32 bg-slate-200 rounded" />
            ))}
          </div>
          <div className="h-96 bg-slate-200 rounded" />
        </div>
      </div>
    )
  }

  // Calculate derived metrics
  const resolutionRate = stats?.totalVulnerabilities && stats.totalVulnerabilities > 0
    ? Math.round(((stats.resolvedVulnerabilities || 0) / stats.totalVulnerabilities) * 100)
    : 0

  const criticalVulns = stats?.vulnerabilitiesBySeverity.find(v => v.name === 'Critical')?.value || 0
  const highVulns = stats?.vulnerabilitiesBySeverity.find(v => v.name === 'High')?.value || 0
  const openVulns = stats?.vulnerabilitiesByStatus.find(s => s.name === 'Open')?.value || 0
  const inProgressVulns = stats?.vulnerabilitiesByStatus.find(s => s.name === 'In Progress')?.value || 0

  const criticalAssets = stats?.assetsByCriticality.reduce((sum, a) => sum + (a.name === 'Critical' ? a.value : 0), 0) || 0

  // Calculate average CVSS score (simplified)
  const totalSeverityScore = stats?.vulnerabilitiesBySeverity.reduce((sum, v) => {
    const multiplier = v.name === 'Critical' ? 10 : v.name === 'High' ? 7 : v.name === 'Medium' ? 5 : 3
    return sum + (v.value * multiplier)
  }, 0) || 0

  const avgCVSS = stats?.totalVulnerabilities && stats.totalVulnerabilities > 0
    ? (totalSeverityScore / stats.totalVulnerabilities).toFixed(1)
    : '0.0'

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground mt-1">
          Vue d'ensemble et analyse de la sécurité
        </p>
      </div>

      {/* Key Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Total Actifs</CardTitle>
            <Server className="h-5 w-5 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{stats?.totalAssets || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Infrastructure suivie</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Vulnérabilités</CardTitle>
            <AlertTriangle className="h-5 w-5 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{stats?.totalVulnerabilities || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Total détectées</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">CVEs Suivis</CardTitle>
            <Database className="h-5 w-5 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{stats?.totalCVEs || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Base NVD</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Critiques</CardTitle>
            <Shield className="h-5 w-5 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-600">{criticalVulns}</div>
            <p className="text-xs text-muted-foreground mt-1">Vulnérabilités critiques</p>
          </CardContent>
        </Card>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Vulnerabilities by Severity Bar Chart */}
        <Card>
          <CardHeader>
            <CardTitle>Vulnérabilités par Sévérité</CardTitle>
            <CardDescription>
              Distribution des vulnérabilités par niveau de sévérité
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={stats?.vulnerabilitiesBySeverity || []}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: '#64748b' }} tickLine={{ stroke: '#94a3b8' }} />
                <YAxis tick={{ fill: '#64748b' }} tickLine={{ stroke: '#94a3b8' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--background))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '0.5rem',
                  }}
                  cursor={{ fill: 'hsl(var(--muted))' }}
                />
                <Bar dataKey="value" name="Vulnérabilités" radius={[8, 8, 8, 8]}>
                  {stats?.vulnerabilitiesBySeverity.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Vulnerabilities by Status Bar Chart */}
        <Card>
          <CardHeader>
            <CardTitle>État des Vulnérabilités</CardTitle>
            <CardDescription>
              Statut actuel des vulnérabilités
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={stats?.vulnerabilitiesByStatus || []} layout="horizontal">
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="value" tick={{ fill: '#64748b' }} tickLine={{ stroke: '#94a3b8' }} />
                <YAxis dataKey="name" type="category" tick={{ fill: '#64748b' }} tickLine={{ stroke: '#94a3b8' }} width={100} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--background))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '0.5rem',
                  }}
                  cursor={{ fill: 'hsl(var(--muted))' }}
                />
                <Bar dataKey="value" name="Nombre" radius={[0, 8, 8, 0]} barSize={30}>
                  {stats?.vulnerabilitiesByStatus.map((entry, index) => (
                    <Cell key={`cell-status-${entry.name}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Assets by Criticality Pie Chart */}
        <Card>
          <CardHeader>
            <CardTitle>Actifs par Criticité</CardTitle>
            <CardDescription>
              Répartition des actifs selon leur niveau de criticité
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={stats?.assetsByCriticality || []}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={(entry) => `${entry.name}: ${entry.value}`}
                  outerRadius={100}
                  fill="url(#colors)"
                >
                  {stats?.assetsByCriticality.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={`url(#color${index})`} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--background))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '0.5rem',
                  }}
                />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  iconType="circle"
                  formatter={(value, entry) => (
                    <span style={{ color: entry.payload.color }}>
                      {entry.name}: {value}
                    </span>
                  )}
                />
                <defs>
                  {stats?.assetsByCriticality.map((entry, index) => (
                    <linearGradient key={`gradient-${index}`} id={`color${index}`} x1="0" y1="0" x2="1" y2="1">
                      <stop offset="5%" stopColor={entry.color} stopOpacity={0.9} />
                      <stop offset="95%" stopColor={entry.color} stopOpacity={0.4} />
                    </linearGradient>
                  ))}
                </defs>
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Security Score Card */}
        <Card className="bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
          <CardHeader>
            <CardTitle>Score Sécurité</CardTitle>
            <CardDescription>
              Évaluation globale de la sécurité
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Resolution Rate */}
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm text-muted-foreground">Taux de résolution</div>
                <div className="text-3xl font-bold text-green-600">
                  {resolutionRate}%
                </div>
              </div>
              <CheckCircle2 className="h-12 w-12 text-green-500" />
            </div>

            {/* Progress Bar */}
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Progression</span>
                <span className="font-medium">{stats?.resolvedVulnerabilities || 0} / {stats?.totalVulnerabilities || 0}</span>
              </div>
              <div className="h-3 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-green-400 to-green-600 rounded-full transition-all"
                  style={{ width: `${resolutionRate}%` }}
                />
              </div>
            </div>

            {/* Quick Stats */}
            <div className="grid grid-cols-2 gap-4 pt-4 border-t border-slate-200 dark:border-slate-700">
              <div className="text-center">
                <div className="text-2xl font-bold text-red-600">{criticalVulns}</div>
                <div className="text-xs text-muted-foreground">Critiques</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-600">{inProgressVulns}</div>
                <div className="text-xs text-muted-foreground">En cours</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Key Metrics Summary */}
      <Card>
        <CardHeader>
          <CardTitle>Métriques Clés</CardTitle>
          <CardDescription>
            Indicateurs de performance de sécurité
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* CVSS Score */}
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-blue-500" />
                <div className="text-sm text-muted-foreground">Score CVSS Moyen</div>
              </div>
              <div className="text-2xl font-bold">
                {avgCVSS}
              </div>
              <div className="text-xs text-muted-foreground">
                Basé sur {stats?.totalVulnerabilities || 0} vulnérabilités
              </div>
            </div>

            {/* Assets at Risk */}
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-red-500" />
                <div className="text-sm text-muted-foreground">Actifs à Risque</div>
              </div>
              <div className="text-2xl font-bold text-red-600">
                {criticalAssets}
              </div>
              <div className="text-xs text-muted-foreground">
                Criticité haute ou critique
              </div>
            </div>

            {/* Open Vulnerabilities */}
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Clock className="h-5 w-5 text-orange-500" />
                <div className="text-sm text-muted-foreground">Vulnérabilités Ouvertes</div>
              </div>
              <div className="text-2xl font-bold text-orange-600">
                {openVulns}
              </div>
              <div className="text-xs text-muted-foreground">
                En attente de correction
              </div>
            </div>
          </div>

          {/* Detailed Status Breakdown */}
          <div className="mt-6 pt-6 border-t border-slate-200 dark:border-slate-700">
            <div className="text-sm font-medium mb-4">Répartition détaillée par statut</div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {stats?.vulnerabilitiesByStatus.map((status) => (
                <div key={status.name} className="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-slate-800">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-3 h-3 rounded-full"
                      style={{ backgroundColor: status.color }}
                    />
                    <span className="text-sm">{status.name}</span>
                  </div>
                  <span className="text-lg font-bold">{status.value}</span>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
