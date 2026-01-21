'use client'

import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Database, Search, Download, ExternalLink, RefreshCw, AlertCircle } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { toast } from '@/hooks/use-toast'

interface CVE {
  id: string
  cveId: string
  description: string
  severity: string
  cvssScore?: number
  cvssVector?: string
  publishedDate?: string
  lastModifiedDate?: string
  references?: string
  vulnStatus?: string
  importedAt: string
}

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

export default function CVEsPage() {
  const [cves, setCves] = useState<CVE[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [nvdSearchTerm, setNvdSearchTerm] = useState('')
  const [nvdResults, setNvdResults] = useState<NVDCVE[]>([])
  const [nvdLoading, setNvdLoading] = useState(false)
  const [isImportDialogOpen, setIsImportDialogOpen] = useState(false)

  useEffect(() => {
    fetchCVEs()
  }, [])

  async function fetchCVEs() {
    try {
      const response = await fetch('/api/cves')
      if (response.ok) {
        const data = await response.json()
        setCves(Array.isArray(data) ? data : [])
      }
    } catch (error) {
      console.error('Error fetching CVEs:', error)
      setCves([])
    } finally {
      setLoading(false)
    }
  }

  async function searchNVD() {
    if (!nvdSearchTerm.trim()) {
      toast({
        title: 'Erreur',
        description: 'Veuillez entrer un terme de recherche',
        variant: 'destructive',
      })
      return
    }

    setNvdLoading(true)
    try {
      const response = await fetch(
        `/api/cves/nvd/search?keyword=${encodeURIComponent(nvdSearchTerm)}`
      )

      if (response.ok) {
        const data = await response.json()
        setNvdResults(data.vulnerabilities || [])
        toast({
          title: 'Recherche terminée',
          description: `${data.vulnerabilities?.length || 0} résultat(s) trouvé(s)`,
        })
      } else {
        throw new Error('Search failed')
      }
    } catch (error) {
      console.error('Error searching NVD:', error)
      toast({
        title: 'Erreur',
        description: 'Échec de la recherche NVD',
        variant: 'destructive',
      })
    } finally {
      setNvdLoading(false)
    }
  }

  async function importCVE(nvdCve: NVDCVE) {
    try {
      const response = await fetch('/api/cves/nvd/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(nvdCve),
      })

      if (response.ok) {
        toast({
          title: 'Succès',
          description: 'CVE importé avec succès',
        })
        fetchCVEs()
        setNvdResults(nvdResults.filter((r) => r.cve.id !== nvdCve.cve.id))
      } else {
        throw new Error('Import failed')
      }
    } catch (error) {
      console.error('Error importing CVE:', error)
      toast({
        title: 'Erreur',
        description: 'Échec de l\'import du CVE',
        variant: 'destructive',
      })
    }
  }

  function getSeverityBadge(severity: string) {
    const colors = {
      low: 'bg-green-100 text-green-800',
      medium: 'bg-yellow-100 text-yellow-800',
      high: 'bg-orange-100 text-orange-800',
      critical: 'bg-red-100 text-red-800',
    }
    const labels = {
      low: 'Faible',
      medium: 'Moyenne',
      high: 'Haute',
      critical: 'Critique',
    }
    return (
      <Badge className={colors[severity?.toLowerCase() as keyof typeof colors] || 'bg-gray-100'}>
        {labels[severity?.toLowerCase() as keyof typeof labels] || severity || 'N/A'}
      </Badge>
    )
  }

  function getNVDSeverity(nvdCve: NVDCVE) {
    const severity = nvdCve.cve.metrics?.cvssMetricV31?.[0]?.cvssData.baseSeverity
    return severity || 'UNKNOWN'
  }

  function getNVDScore(nvdCve: NVDCVE) {
    const score = nvdCve.cve.metrics?.cvssMetricV31?.[0]?.cvssData.baseScore
    return score
  }

  const filteredCVEs = cves.filter((cve) =>
    cve.cveId.toLowerCase().includes(searchTerm.toLowerCase()) ||
    cve.description.toLowerCase().includes(searchTerm.toLowerCase())
  )

  if (loading) {
    return (
      <div className="p-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-slate-200 rounded w-48" />
          <div className="h-96 bg-slate-200 rounded" />
        </div>
      </div>
    )
  }

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold">CVEs</h1>
          <p className="text-muted-foreground mt-1">
            Base de données des vulnérabilités connues (NVD)
          </p>
        </div>
        <Dialog open={isImportDialogOpen} onOpenChange={setIsImportDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Download className="mr-2 h-4 w-4" />
              Importer depuis NVD
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Rechercher et importer depuis NVD</DialogTitle>
              <DialogDescription>
                Recherchez des CVEs dans la base NVD (National Vulnerability Database)
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="flex gap-2">
                <Input
                  placeholder="Entrez un mot-clé, CVE ID, ou produit..."
                  value={nvdSearchTerm}
                  onChange={(e) => setNvdSearchTerm(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && searchNVD()}
                />
                <Button onClick={searchNVD} disabled={nvdLoading}>
                  {nvdLoading ? (
                    <RefreshCw className="h-4 w-4 animate-spin" />
                  ) : (
                    <Search className="h-4 w-4" />
                  )}
                </Button>
              </div>

              {nvdResults.length > 0 && (
                <div className="space-y-2">
                  <Label>Résultats ({nvdResults.length})</Label>
                  <div className="max-h-96 overflow-y-auto space-y-2">
                    {nvdResults.map((nvdCve) => (
                      <Card key={nvdCve.cve.id}>
                        <CardContent className="pt-4">
                          <div className="flex justify-between items-start gap-4">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-2">
                                <Badge variant="outline">{nvdCve.cve.id}</Badge>
                                {getSeverityBadge(getNVDSeverity(nvdCve))}
                              </div>
                              <p className="text-sm mb-2 line-clamp-2">
                                {nvdCve.cve.descriptions[0]?.value || 'Aucune description'}
                              </p>
                              {(() => {
                                const score = getNVDScore(nvdCve)
                                return score !== undefined && (
                                  <Badge variant="secondary">
                                    CVSS: {score.toFixed(1)}
                                  </Badge>
                                )
                              })()}
                            </div>
                            <Button
                              size="sm"
                              onClick={() => importCVE(nvdCve)}
                            >
                              <Download className="h-4 w-4 mr-1" />
                              Importer
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </div>
              )}

              {nvdResults.length === 0 && nvdSearchTerm && !nvdLoading && (
                <div className="text-center py-8 text-muted-foreground">
                  <AlertCircle className="h-12 w-12 mx-auto mb-2 opacity-50" />
                  <p>Aucun résultat trouvé</p>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>CVEs Importés</CardTitle>
          <CardDescription>
            {cves.length} CVE(s) suivi{cves.length !== 1 ? 's' : ''}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Rechercher un CVE..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
          </div>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CVE ID</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Sévérité</TableHead>
                  <TableHead>CVSS</TableHead>
                  <TableHead>Date de publication</TableHead>
                  <TableHead>Importé le</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredCVEs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                      <div className="flex flex-col items-center gap-2">
                        <Database className="h-8 w-8 text-muted-foreground" />
                        <p>Aucun CVE trouvé</p>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredCVEs.map((cve) => (
                    <TableRow key={cve.id}>
                      <TableCell className="font-medium">
                        <Badge variant="outline">{cve.cveId}</Badge>
                      </TableCell>
                      <TableCell>
                        <div className="max-w-md truncate text-sm">
                          {cve.description}
                        </div>
                      </TableCell>
                      <TableCell>{getSeverityBadge(cve.severity)}</TableCell>
                      <TableCell>
                        {cve.cvssScore ? (
                          <span className="font-medium">{cve.cvssScore.toFixed(1)}</span>
                        ) : (
                          '-'
                        )}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {cve.publishedDate
                          ? new Date(cve.publishedDate).toLocaleDateString('fr-FR')
                          : '-'}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(cve.importedAt).toLocaleDateString('fr-FR')}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() =>
                            window.open(
                              `https://nvd.nist.gov/vuln/detail/${cve.cveId}`,
                              '_blank'
                            )
                          }
                        >
                          <ExternalLink className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
