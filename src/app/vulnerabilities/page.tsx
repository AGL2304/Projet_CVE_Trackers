'use client'

import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Plus, Edit, Trash2, AlertTriangle, Search, Filter } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { toast } from '@/hooks/use-toast'

interface Vulnerability {
  id: string
  title: string
  description?: string
  severity: string
  status: string
  cvssScore?: number
  cveId?: string
  asset?: {
    id: string
    name: string
  }
  discoveredAt: string
  resolvedAt?: string
}

export default function VulnerabilitiesPage() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false)
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null)

  // Form state
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    severity: 'medium',
    status: 'open',
    cvssScore: '',
    cveId: '',
    assetId: '',
  })

  useEffect(() => {
    fetchVulnerabilities()
  }, [])

  async function fetchVulnerabilities() {
    try {
      const response = await fetch('/api/vulnerabilities')
      if (response.ok) {
        const data = await response.json()
        setVulnerabilities(data.vulnerabilities || [])
      }
    } catch (error) {
      console.error('Error fetching vulnerabilities:', error)
      setVulnerabilities([])
    } finally {
      setLoading(false)
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    try {
      const url = selectedVulnerability
        ? `/api/vulnerabilities/${selectedVulnerability.id}`
        : '/api/vulnerabilities'
      const method = selectedVulnerability ? 'PUT' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...formData,
          cvssScore: formData.cvssScore ? parseFloat(formData.cvssScore) : null,
          assetId: formData.assetId || null,
        }),
      })

      if (response.ok) {
        toast({
          title: 'Succès',
          description: selectedVulnerability
            ? 'Vulnérabilité mise à jour'
            : 'Vulnérabilité créée',
        })
        setIsCreateDialogOpen(false)
        setIsEditDialogOpen(false)
        setFormData({
          title: '',
          description: '',
          severity: 'medium',
          status: 'open',
          cvssScore: '',
          cveId: '',
          assetId: '',
        })
        setSelectedVulnerability(null)
        fetchVulnerabilities()
      } else {
        toast({
          title: 'Erreur',
          description: 'Échec de l\'opération',
          variant: 'destructive',
        })
      }
    } catch (error) {
      console.error('Error submitting form:', error)
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Êtes-vous sûr de vouloir supprimer cette vulnérabilité ?')) return

    try {
      const response = await fetch(`/api/vulnerabilities/${id}`, {
        method: 'DELETE',
      })

      if (response.ok) {
        toast({
          title: 'Succès',
          description: 'Vulnérabilité supprimée',
        })
        fetchVulnerabilities()
      }
    } catch (error) {
      console.error('Error deleting vulnerability:', error)
    }
  }

  function handleEdit(vulnerability: Vulnerability) {
    setSelectedVulnerability(vulnerability)
    setFormData({
      title: vulnerability.title,
      description: vulnerability.description || '',
      severity: vulnerability.severity,
      status: vulnerability.status,
      cvssScore: vulnerability.cvssScore?.toString() || '',
      cveId: vulnerability.cveId || '',
      assetId: vulnerability.asset?.id || '',
    })
    setIsEditDialogOpen(true)
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
      <Badge className={colors[severity as keyof typeof colors]}>
        {labels[severity as keyof typeof labels] || severity}
      </Badge>
    )
  }

  function getStatusBadge(status: string) {
    const colors = {
      open: 'bg-red-100 text-red-800',
      in_progress: 'bg-orange-100 text-orange-800',
      resolved: 'bg-green-100 text-green-800',
      ignored: 'bg-gray-100 text-gray-800',
    }
    const labels = {
      open: 'Ouvert',
      in_progress: 'En cours',
      resolved: 'Résolu',
      ignored: 'Ignoré',
    }
    return (
      <Badge className={colors[status as keyof typeof colors]}>
        {labels[status as keyof typeof labels] || status}
      </Badge>
    )
  }

  const filteredVulnerabilities = vulnerabilities.filter((vuln) => {
    const matchesSearch =
      vuln.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vuln.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vuln.cveId?.toLowerCase().includes(searchTerm.toLowerCase())

    const matchesSeverity = severityFilter === 'all' || vuln.severity === severityFilter
    const matchesStatus = statusFilter === 'all' || vuln.status === statusFilter

    return matchesSearch && matchesSeverity && matchesStatus
  })

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
          <h1 className="text-3xl font-bold">Vulnérabilités</h1>
          <p className="text-muted-foreground mt-1">
            Suivi et gestion des vulnérabilités de sécurité
          </p>
        </div>
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Nouvelle Vulnérabilité
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Créer une nouvelle vulnérabilité</DialogTitle>
              <DialogDescription>
                Signalez une nouvelle vulnérabilité dans le système
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="title">Titre</Label>
                <Input
                  id="title"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Input
                  id="description"
                  value={formData.description}
                  onChange={(e) =>
                    setFormData({ ...formData, description: e.target.value })
                  }
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="severity">Sévérité</Label>
                  <Select
                    value={formData.severity}
                    onValueChange={(value) =>
                      setFormData({ ...formData, severity: value })
                    }
                  >
                    <SelectTrigger id="severity">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Faible</SelectItem>
                      <SelectItem value="medium">Moyenne</SelectItem>
                      <SelectItem value="high">Haute</SelectItem>
                      <SelectItem value="critical">Critique</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="status">Statut</Label>
                  <Select
                    value={formData.status}
                    onValueChange={(value) =>
                      setFormData({ ...formData, status: value })
                    }
                  >
                    <SelectTrigger id="status">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="open">Ouvert</SelectItem>
                      <SelectItem value="in_progress">En cours</SelectItem>
                      <SelectItem value="resolved">Résolu</SelectItem>
                      <SelectItem value="ignored">Ignoré</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="cvssScore">Score CVSS</Label>
                  <Input
                    id="cvssScore"
                    type="number"
                    step="0.1"
                    min="0"
                    max="10"
                    value={formData.cvssScore}
                    onChange={(e) =>
                      setFormData({ ...formData, cvssScore: e.target.value })
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="cveId">CVE ID</Label>
                  <Input
                    id="cveId"
                    placeholder="CVE-2024-1234"
                    value={formData.cveId}
                    onChange={(e) =>
                      setFormData({ ...formData, cveId: e.target.value })
                    }
                  />
                </div>
              </div>
              <Button type="submit" className="w-full">
                Créer la vulnérabilité
              </Button>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Liste des Vulnérabilités</CardTitle>
          <CardDescription>
            {vulnerabilities.length} vulnérabilité{vulnerabilities.length !== 1 ? 's' : ''} enregistrée{vulnerabilities.length !== 1 ? 's' : ''}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-4 flex gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Rechercher..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-40">
                <Filter className="mr-2 h-4 w-4" />
                <SelectValue placeholder="Sévérité" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Toutes</SelectItem>
                <SelectItem value="critical">Critique</SelectItem>
                <SelectItem value="high">Haute</SelectItem>
                <SelectItem value="medium">Moyenne</SelectItem>
                <SelectItem value="low">Faible</SelectItem>
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-40">
                <Filter className="mr-2 h-4 w-4" />
                <SelectValue placeholder="Statut" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Tous</SelectItem>
                <SelectItem value="open">Ouvert</SelectItem>
                <SelectItem value="in_progress">En cours</SelectItem>
                <SelectItem value="resolved">Résolu</SelectItem>
                <SelectItem value="ignored">Ignoré</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Titre</TableHead>
                  <TableHead>CVE ID</TableHead>
                  <TableHead>Sévérité</TableHead>
                  <TableHead>CVSS</TableHead>
                  <TableHead>Statut</TableHead>
                  <TableHead>Actif</TableHead>
                  <TableHead>Date</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredVulnerabilities.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center text-muted-foreground py-8">
                      <div className="flex flex-col items-center gap-2">
                        <AlertTriangle className="h-8 w-8 text-muted-foreground" />
                        <p>Aucune vulnérabilité trouvée</p>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredVulnerabilities.map((vuln) => (
                    <TableRow key={vuln.id}>
                      <TableCell className="font-medium">{vuln.title}</TableCell>
                      <TableCell>
                        {vuln.cveId ? (
                          <Badge variant="outline">{vuln.cveId}</Badge>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell>{getSeverityBadge(vuln.severity)}</TableCell>
                      <TableCell>
                        {vuln.cvssScore !== null && vuln.cvssScore !== undefined ? (
                          <span className="font-medium">{vuln.cvssScore.toFixed(1)}</span>
                        ) : (
                          '-'
                        )}
                      </TableCell>
                      <TableCell>{getStatusBadge(vuln.status)}</TableCell>
                      <TableCell>
                        {vuln.asset ? (
                          <Badge variant="secondary">{vuln.asset.name}</Badge>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(vuln.discoveredAt).toLocaleDateString('fr-FR')}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleEdit(vuln)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDelete(vuln.id)}
                          >
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Edit Dialog */}
      <Dialog open={isEditDialogOpen} onOpenChange={setIsEditDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Modifier la vulnérabilité</DialogTitle>
            <DialogDescription>
              Mettez à jour les informations de la vulnérabilité
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-title">Titre</Label>
              <Input
                id="edit-title"
                value={formData.title}
                onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-description">Description</Label>
              <Input
                id="edit-description"
                value={formData.description}
                onChange={(e) =>
                  setFormData({ ...formData, description: e.target.value })
                }
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="edit-severity">Sévérité</Label>
                <Select
                  value={formData.severity}
                  onValueChange={(value) =>
                    setFormData({ ...formData, severity: value })
                  }
                >
                  <SelectTrigger id="edit-severity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Faible</SelectItem>
                    <SelectItem value="medium">Moyenne</SelectItem>
                    <SelectItem value="high">Haute</SelectItem>
                    <SelectItem value="critical">Critique</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-status">Statut</Label>
                <Select
                  value={formData.status}
                  onValueChange={(value) =>
                    setFormData({ ...formData, status: value })
                  }
                >
                  <SelectTrigger id="edit-status">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="open">Ouvert</SelectItem>
                    <SelectItem value="in_progress">En cours</SelectItem>
                    <SelectItem value="resolved">Résolu</SelectItem>
                    <SelectItem value="ignored">Ignoré</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="edit-cvssScore">Score CVSS</Label>
                <Input
                  id="edit-cvssScore"
                  type="number"
                  step="0.1"
                  min="0"
                  max="10"
                  value={formData.cvssScore}
                  onChange={(e) =>
                    setFormData({ ...formData, cvssScore: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-cveId">CVE ID</Label>
                <Input
                  id="edit-cveId"
                  placeholder="CVE-2024-1234"
                  value={formData.cveId}
                  onChange={(e) =>
                    setFormData({ ...formData, cveId: e.target.value })
                  }
                />
              </div>
            </div>
            <Button type="submit" className="w-full">
              Mettre à jour la vulnérabilité
            </Button>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
