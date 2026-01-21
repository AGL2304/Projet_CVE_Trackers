'use client'

import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Server, Plus, Edit, Trash2, Search } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { toast } from '@/hooks/use-toast'

interface Asset {
  id: string
  name: string
  type: string
  ip?: string
  hostname?: string
  description?: string
  criticality: string
  status: string
  createdAt: string
}

const errorMsg = "Échec de l'opération"

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false)
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null)

  const [formData, setFormData] = useState({
    name: '',
    type: '',
    ip: '',
    hostname: '',
    description: '',
    criticality: 'medium',
    status: 'active',
  })

  useEffect(() => {
    fetchAssets()
  }, [])

  async function fetchAssets() {
    try {
      const response = await fetch('/api/assets')
      if (response.ok) {
        const data = await response.json()
        setAssets(Array.isArray(data) ? data : [])
      }
    } catch (error) {
      console.error('Error fetching assets:', error)
      setAssets([])
    } finally {
      setLoading(false)
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    try {
      const url = selectedAsset ? `/api/assets/${selectedAsset.id}` : '/api/assets'
      const method = selectedAsset ? 'PUT' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      })

      if (response.ok) {
        toast({
          title: 'Succès',
          description: selectedAsset ? 'Actif mis à jour' : 'Actif créé',
        })
        setIsCreateDialogOpen(false)
        setIsEditDialogOpen(false)
        setFormData({
          name: '',
          type: '',
          ip: '',
          hostname: '',
          description: '',
          criticality: 'medium',
          status: 'active',
        })
        setSelectedAsset(null)
        fetchAssets()
      } else {
        toast({
          title: 'Erreur',
          description: errorMsg,
          variant: 'destructive',
        })
      }
    } catch (error) {
      console.error('Error submitting form:', error)
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Êtes-vous sûr de vouloir supprimer cet actif ?')) return

    try {
      const response = await fetch(`/api/assets/${id}`, {
        method: 'DELETE',
      })

      if (response.ok) {
        toast({
          title: 'Succès',
          description: 'Actif supprimé',
        })
        fetchAssets()
      }
    } catch (error) {
      console.error('Error deleting asset:', error)
    }
  }

  function handleEdit(asset: Asset) {
    setSelectedAsset(asset)
    setFormData({
      name: asset.name,
      type: asset.type,
      ip: asset.ip || '',
      hostname: asset.hostname || '',
      description: asset.description || '',
      criticality: asset.criticality,
      status: asset.status,
    })
    setIsEditDialogOpen(true)
  }

  function getCriticalityBadge(criticality: string) {
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
      <Badge className={colors[criticality as keyof typeof colors] || 'bg-gray-100'}>
        {labels[criticality as keyof typeof labels] || criticality}
      </Badge>
    )
  }

  function getStatusBadge(status: string) {
    const colors = {
      active: 'bg-green-100 text-green-800',
      inactive: 'bg-gray-100 text-gray-800',
      retired: 'bg-red-100 text-red-800',
    }
    const labels = {
      active: 'Actif',
      inactive: 'Inactif',
      retired: 'Retiré',
    }
    return (
      <Badge className={colors[status as keyof typeof colors] || 'bg-gray-100'}>
        {labels[status as keyof typeof labels] || status}
      </Badge>
    )
  }

  const filteredAssets = assets.filter(asset =>
    asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    asset.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
    asset.ip?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    asset.hostname?.toLowerCase().includes(searchTerm.toLowerCase())
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
          <h1 className="text-3xl font-bold">Actifs</h1>
          <p className="text-muted-foreground mt-1">
            Gérez votre infrastructure et vos ressources
          </p>
        </div>
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Nouvel Actif
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Créer un nouvel actif</DialogTitle>
              <DialogDescription>
                Ajoutez un nouvel actif à votre inventaire
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="name">Nom</Label>
                <Input
                  id="name"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="type">Type</Label>
                <Select
                  value={formData.type}
                  onValueChange={(value) => setFormData({ ...formData, type: value })}
                >
                  <SelectTrigger id="type">
                    <SelectValue placeholder="Sélectionner un type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="server">Serveur</SelectItem>
                    <SelectItem value="database">Base de données</SelectItem>
                    <SelectItem value="application">Application</SelectItem>
                    <SelectItem value="network">Équipement réseau</SelectItem>
                    <SelectItem value="container">Conteneur</SelectItem>
                    <SelectItem value="other">Autre</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="ip">Adresse IP</Label>
                  <Input
                    id="ip"
                    value={formData.ip}
                    onChange={(e) => setFormData({ ...formData, ip: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="hostname">Nom d&apos;hôte</Label>
                  <Input
                    id="hostname"
                    value={formData.hostname}
                    onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Input
                  id="description"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="criticality">Criticité</Label>
                  <Select
                    value={formData.criticality}
                    onValueChange={(value) => setFormData({ ...formData, criticality: value })}
                  >
                    <SelectTrigger id="criticality">
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
                    onValueChange={(value) => setFormData({ ...formData, status: value })}
                  >
                    <SelectTrigger id="status">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="active">Actif</SelectItem>
                      <SelectItem value="inactive">Inactif</SelectItem>
                      <SelectItem value="retired">Retiré</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <Button type="submit" className="w-full">
                Créer l&apos;actif
              </Button>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Liste des Actifs</CardTitle>
          <CardDescription>
            {assets.length} actif{assets.length !== 1 ? 's' : ''} dans l&apos;inventaire
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Rechercher un actif..."
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
                  <TableHead>Nom</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>IP / Hostname</TableHead>
                  <TableHead>Criticité</TableHead>
                  <TableHead>Statut</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAssets.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                      <div className="flex flex-col items-center gap-2">
                        <Server className="h-8 w-8 text-muted-foreground" />
                        <p>Aucun actif trouvé</p>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredAssets.map((asset) => (
                    <TableRow key={asset.id}>
                      <TableCell className="font-medium">{asset.name}</TableCell>
                      <TableCell>{asset.type}</TableCell>
                      <TableCell>
                        <div className="text-sm">
                          {asset.ip && <div>{asset.ip}</div>}
                          {asset.hostname && <div className="text-muted-foreground">{asset.hostname}</div>}
                        </div>
                      </TableCell>
                      <TableCell>{getCriticalityBadge(asset.criticality)}</TableCell>
                      <TableCell>{getStatusBadge(asset.status)}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleEdit(asset)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDelete(asset.id)}
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
            <DialogTitle>Modifier l&apos;actif</DialogTitle>
            <DialogDescription>
              Mettez à jour les informations de l&apos;actif
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">Nom</Label>
              <Input
                id="edit-name"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-type">Type</Label>
              <Select
                value={formData.type}
                onValueChange={(value) => setFormData({ ...formData, type: value })}
              >
                <SelectTrigger id="edit-type">
                  <SelectValue placeholder="Sélectionner un type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="server">Serveur</SelectItem>
                  <SelectItem value="database">Base de données</SelectItem>
                  <SelectItem value="application">Application</SelectItem>
                  <SelectItem value="network">Équipement réseau</SelectItem>
                  <SelectItem value="container">Conteneur</SelectItem>
                  <SelectItem value="other">Autre</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="edit-ip">Adresse IP</Label>
                <Input
                  id="edit-ip"
                  value={formData.ip}
                  onChange={(e) => setFormData({ ...formData, ip: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-hostname">Nom d&apos;hôte</Label>
                <Input
                  id="edit-hostname"
                  value={formData.hostname}
                  onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-description">Description</Label>
              <Input
                id="edit-description"
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="edit-criticality">Criticité</Label>
                <Select
                  value={formData.criticality}
                  onValueChange={(value) => setFormData({ ...formData, criticality: value })}
                >
                  <SelectTrigger id="edit-criticality">
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
                  onValueChange={(value) => setFormData({ ...formData, status: value })}
                >
                  <SelectTrigger id="edit-status">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="active">Actif</SelectItem>
                    <SelectItem value="inactive">Inactif</SelectItem>
                    <SelectItem value="retired">Retiré</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <Button type="submit" className="w-full">
              Mettre à jour l&apos;actif
            </Button>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
