import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

const MOCK_ASSETS = [
  {
    name: 'Web Server Production',
    type: 'server',
    ip: '192.168.1.10',
    hostname: 'web-prod-01',
    description: 'Serveur web principal pour l\'application de production',
    criticality: 'critical',
    status: 'active',
  },
  {
    name: 'Database Server Primary',
    type: 'database',
    ip: '192.168.1.20',
    hostname: 'db-prod-01',
    description: 'Base de données principale MySQL',
    criticality: 'critical',
    status: 'active',
  },
  {
    name: 'API Gateway',
    type: 'application',
    ip: '192.168.1.30',
    hostname: 'api-gateway',
    description: 'Passerelle API pour le microservices',
    criticality: 'high',
    status: 'active',
  },
  {
    name: 'Load Balancer',
    type: 'network',
    ip: '192.168.1.40',
    hostname: 'lb-01',
    description: 'Load balancer Nginx',
    criticality: 'high',
    status: 'active',
  },
  {
    name: 'Cache Server Redis',
    type: 'database',
    ip: '192.168.1.50',
    hostname: 'redis-cache',
    description: 'Serveur de cache Redis',
    criticality: 'medium',
    status: 'active',
  },
  {
    name: 'Mail Server',
    type: 'server',
    ip: '192.168.1.60',
    hostname: 'mail-01',
    description: 'Serveur de messagerie Postfix',
    criticality: 'medium',
    status: 'active',
  },
  {
    name: 'File Server',
    type: 'server',
    ip: '192.168.1.70',
    hostname: 'file-server',
    description: 'Serveur de fichiers NFS',
    criticality: 'medium',
    status: 'active',
  },
  {
    name: 'Monitoring Server',
    type: 'server',
    ip: '192.168.1.80',
    hostname: 'monitoring',
    description: 'Serveur de monitoring Prometheus/Grafana',
    criticality: 'low',
    status: 'active',
  },
  {
    name: 'Backup Server',
    type: 'server',
    ip: '192.168.1.90',
    hostname: 'backup-01',
    description: 'Serveur de sauvegardes',
    criticality: 'high',
    status: 'active',
  },
  {
    name: 'Development Server',
    type: 'server',
    ip: '192.168.2.10',
    hostname: 'dev-server-01',
    description: 'Serveur de développement',
    criticality: 'low',
    status: 'active',
  },
  {
    name: 'Docker Host Production',
    type: 'container',
    ip: '192.168.1.100',
    hostname: 'docker-prod-01',
    description: 'Hôte Docker pour conteneurs de production',
    criticality: 'high',
    status: 'active',
  },
  {
    name: 'Test Database',
    type: 'database',
    ip: '192.168.2.20',
    hostname: 'db-test-01',
    description: 'Base de données de test',
    criticality: 'low',
    status: 'inactive',
  },
]

const MOCK_VULNERABILITIES = [
  {
    title: 'SQL Injection vulnerability in login form',
    description: 'Le formulaire de login est vulnérable aux injections SQL permettant aux attaquants de contourner l\'authentification',
    severity: 'critical',
    status: 'open',
    cvssScore: 9.8,
    cveId: 'CVE-2024-1001',
  },
  {
    title: 'Cross-Site Scripting (XSS) in search functionality',
    description: 'La fonctionnalité de recherche est vulnérable aux attaques XSS stockées permettant l\'exécution de scripts malveillants',
    severity: 'high',
    status: 'open',
    cvssScore: 8.5,
    cveId: 'CVE-2024-1002',
  },
  {
    title: 'Unrestricted File Upload',
    description: 'Les utilisateurs peuvent uploader des fichiers sans restriction, permettant l\'exécution de code arbitraire',
    severity: 'critical',
    status: 'in_progress',
    cvssScore: 9.1,
    cveId: 'CVE-2024-1003',
  },
  {
    title: 'Missing Authentication on API Endpoint',
    description: 'L\'endpoint API /api/admin n\'exige pas d\'authentification, exposant des données sensibles',
    severity: 'high',
    status: 'open',
    cvssScore: 7.5,
    cveId: 'CVE-2024-1004',
  },
  {
    title: 'Outdated OpenSSL Version',
    description: 'Le serveur utilise une version d\'OpenSSL avec des vulnérabilités connues',
    severity: 'high',
    status: 'in_progress',
    cvssScore: 7.2,
    cveId: 'CVE-2024-1005',
  },
  {
    title: 'Information Disclosure in HTTP Headers',
    description: 'Les en-têtes HTTP révèlent des informations sur la version du serveur et la technologie utilisée',
    severity: 'low',
    status: 'open',
    cvssScore: 3.7,
    cveId: 'CVE-2024-1006',
  },
  {
    title: 'Weak Password Policy',
    description: 'La politique de mots de passe ne respecte pas les standards de sécurité minimale',
    severity: 'medium',
    status: 'open',
    cvssScore: 5.3,
    cveId: null,
  },
  {
    title: 'CSRF Token Missing',
    description: 'Les formulaires sensibles ne sont pas protégés par des tokens CSRF',
    severity: 'medium',
    status: 'open',
    cvssScore: 6.5,
    cveId: 'CVE-2024-1007',
  },
  {
    title: 'Insecure Direct Object Reference',
    description: 'Les utilisateurs peuvent accéder aux données d\'autres utilisateurs en modifiant les ID dans les URLs',
    severity: 'high',
    status: 'open',
    cvssScore: 7.8,
    cveId: 'CVE-2024-1008',
  },
  {
    title: 'XML External Entity (XXE) Injection',
    description: 'Le parser XML est vulnérable aux attaques XXE permettant l\'accès au système de fichiers',
    severity: 'high',
    status: 'resolved',
    cvssScore: 7.4,
    cveId: 'CVE-2024-1009',
  },
  {
    title: 'Directory Traversal Vulnerability',
    description: 'Une faille de directory traversal permet d\'accéder à des fichiers système sensibles',
    severity: 'critical',
    status: 'in_progress',
    cvssScore: 8.6,
    cveId: 'CVE-2024-1010',
  },
  {
    title: 'Session Fixation',
    description: 'L\'application ne régénère pas l\'ID de session après login, permettant les attaques de fixation',
    severity: 'medium',
    status: 'resolved',
    cvssScore: 5.9,
    cveId: 'CVE-2024-1011',
  },
  {
    title: 'Unencrypted Sensitive Data in Database',
    description: 'Les données sensibles (mots de passe, numéros de carte) ne sont pas chiffrées en base',
    severity: 'critical',
    status: 'open',
    cvssScore: 9.0,
    cveId: null,
  },
  {
    title: 'Open Redirect',
    description: 'Le paramètre redirect n\'est pas validé, permettant des attaques de phishing',
    severity: 'low',
    status: 'open',
    cvssScore: 4.3,
    cveId: 'CVE-2024-1012',
  },
  {
    title: 'OS Command Injection',
    description: 'Le système exécute des commandes système sans validation suffisante',
    severity: 'critical',
    status: 'in_progress',
    cvssScore: 9.3,
    cveId: 'CVE-2024-1013',
  },
  {
    title: 'Broken Authentication and Session Management',
    description: 'Les sessions ne expirent pas correctement et les cookies ne sont pas sécurisés',
    severity: 'high',
    status: 'open',
    cvssScore: 7.5,
    cveId: 'CVE-2024-1014',
  },
  {
    title: 'Missing Security Headers',
    description: 'Les en-têtes de sécurité (CSP, X-Frame-Options, etc.) ne sont pas configurés',
    severity: 'low',
    status: 'open',
    cvssScore: 3.1,
    cveId: null,
  },
  {
    title: 'Server-Side Request Forgery (SSRF)',
    description: 'L\'application peut être forcée de faire des requêtes vers des ressources internes',
    severity: 'high',
    status: 'in_progress',
    cvssScore: 8.2,
    cveId: 'CVE-2024-1015',
  },
  {
    title: 'LDAP Injection',
    description: 'Le filtre LDAP est vulnérable aux injections permettant de contourner l\'authentification',
    severity: 'high',
    status: 'open',
    cvssScore: 7.6,
    cveId: 'CVE-2024-1016',
  },
  {
    title: 'Insecure Deserialization',
    description: 'La désérialisation non sécurisée permet l\'exécution de code arbitraire',
    severity: 'critical',
    status: 'resolved',
    cvssScore: 8.8,
    cveId: 'CVE-2024-1017',
  },
]

export async function POST() {
  try {
    // Create assets
    const createdAssets = await Promise.all(
      MOCK_ASSETS.map(async (asset) => {
        // Check if asset already exists
        const existing = await db.asset.findFirst({
          where: { name: asset.name },
        })

        if (existing) {
          return existing
        }

        return db.asset.create({
          data: asset,
        })
      })
    )

    // Create vulnerabilities and associate them with assets
    const createdVulnerabilities = await Promise.all(
      MOCK_VULNERABILITIES.map(async (vuln, index) => {
        // Assign to random asset based on severity
        let assetIndex
        if (vuln.severity === 'critical') {
          assetIndex = index % 2 // Critical vulns on critical assets
        } else if (vuln.severity === 'high') {
          assetIndex = index % 4 // High vulns on high/medium assets
        } else {
          assetIndex = index % createdAssets.length
        }

        // Check if vulnerability already exists by CVE ID
        if (vuln.cveId) {
          const existing = await db.vulnerability.findFirst({
            where: { cveId: vuln.cveId },
          })

          if (existing) {
            return existing
          }
        }

        return db.vulnerability.create({
          data: {
            ...vuln,
            assetId: createdAssets[assetIndex].id,
            discoveredAt: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000), // Random date in last 30 days
            resolvedAt: vuln.status === 'resolved' ? new Date() : null,
          },
        })
      })
    )

    return NextResponse.json({
      message: 'Seed data created successfully',
      assetsCreated: createdAssets.length,
      vulnerabilitiesCreated: createdVulnerabilities.length,
      assets: createdAssets.map((a) => ({ id: a.id, name: a.name, type: a.type })),
      vulnerabilities: createdVulnerabilities.map((v) => ({
        id: v.id,
        title: v.title,
        severity: v.severity,
        status: v.status,
      })),
    })
  } catch (error) {
    console.error('Error seeding data:', error)
    return NextResponse.json(
      {
        error: 'Failed to seed data',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

// GET to check if seed data exists
export async function GET() {
  try {
    const assetCount = await db.asset.count()
    const vulnCount = await db.vulnerability.count()

    return NextResponse.json({
      hasSeedData: assetCount > 0 || vulnCount > 0,
      assetCount,
      vulnCount,
    })
  } catch (error) {
    console.error('Error checking seed data:', error)
    return NextResponse.json(
      { error: 'Failed to check seed data' },
      { status: 500 }
    )
  }
}
