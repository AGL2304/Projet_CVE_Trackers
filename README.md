# CVE Tracker

Application SOC de suivi CVE/CVSS avec frontend Next.js 15 et backend versionne (`/api/v2`).

## Etat actuel du projet

- Frontend: Next.js 15 (App Router), TypeScript, Tailwind, shadcn/ui.
- Backend: Route Handlers Next.js + API v1 legacy + API v2 JSON:API.
- Data: Prisma ORM + PostgreSQL 16.
- Services support: PgBouncer, Redis, Elasticsearch.
- Infra locale: `docker-compose.dev.yml` (dev) et `docker-compose.yml` (prod-like).

## Prerequis

- Docker Desktop + Docker Compose v2.
- Bun `>= 1.2` (recommande) ou Node.js `>= 20`.
- PowerShell (Windows) ou shell Unix.

## Configuration rapide

1. Installer les dependances:

```bash
bun install
```

2. Creer le fichier d'environnement:

```bash
cp .env.example .env
```

PowerShell:

```powershell
Copy-Item .env.example .env
```

3. Valeurs a verifier dans `.env`:

```env
DATABASE_URL=postgresql://cve_tracker:cve_tracker@localhost:6432/cve_tracker?schema=public
REDIS_URL=redis://localhost:6379
ELASTICSEARCH_URL=http://localhost:9200
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=replace-with-long-random-secret
```

Note:
- Si vous utilisez le mode prod-like avec `gateway` Nginx, `NEXTAUTH_URL` peut etre `http://localhost:8080`.

## Demarrage local recommande (app locale + infra Docker)

1. Demarrer les services de data:

```bash
docker compose -f docker-compose.dev.yml up -d postgres pgbouncer redis elasticsearch
```

2. Appliquer le schema Prisma:

```bash
bun run db:generate
bun run db:migrate:deploy
```

3. Lancer l'application:

```bash
bun run dev
```

4. Ouvrir l'UI:

- `http://localhost:3000`

## Processus de test local (smoke test complet)

### 1. Verifier la sante applicative

```bash
curl http://localhost:3000/health
curl http://localhost:3000/ready
```

PowerShell:

```powershell
Invoke-RestMethod http://localhost:3000/health
Invoke-RestMethod http://localhost:3000/ready
```

### 2. Charger des donnees de demo (v1)

```bash
curl -X POST http://localhost:3000/api/seed
curl http://localhost:3000/api/dashboard/stats
```

PowerShell:

```powershell
Invoke-RestMethod -Method POST http://localhost:3000/api/seed
Invoke-RestMethod http://localhost:3000/api/dashboard/stats
```

### 3. Tester les endpoints API v2

1. Verifier le registry v2:

```bash
curl http://localhost:3000/api/v2
```

2. Injecter une CVE de test via sync idempotent:

```bash
curl -X POST http://localhost:3000/api/v2/sync/nvd \
  -H "Content-Type: application/json" \
  -d '{"source":"MANUAL","cves":[{"cveId":"CVE-2026-0001","title":"Local test CVE","description":"Smoke test CVE","cvssV3Score":9.1,"cvssV3Vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}'
```

PowerShell:

```powershell
$body = @{
  source = "MANUAL"
  cves = @(
    @{
      cveId = "CVE-2026-0001"
      title = "Local test CVE"
      description = "Smoke test CVE"
      cvssV3Score = 9.1
      cvssV3Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }
  )
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method POST -Uri "http://localhost:3000/api/v2/sync/nvd" -ContentType "application/json" -Body $body
```

3. Lister les CVEs v2:

```bash
curl "http://localhost:3000/api/v2/cves?limit=10"
```

4. Lire les analytics dashboard:

```bash
curl http://localhost:3000/api/v2/analytics/dashboard
```

### 4. Script de test PowerShell existant

Vous pouvez aussi lancer:

```powershell
./test-api.ps1
```

Ce script couvre:
- verification serveur,
- seed v1,
- creation d'un asset de test.

## Alternative: tout lancer via Docker Compose dev

1. Build + run:

```bash
docker compose -f docker-compose.dev.yml up --build
```

2. Dans un second terminal, appliquer les migrations:

```bash
docker compose -f docker-compose.dev.yml exec app bun run db:migrate:deploy
```

3. Tester ensuite sur `http://localhost:3000` avec les memes commandes de smoke test.

## Mode prod-like local

```bash
docker compose up --build -d
```

Acces:
- App via Nginx: `http://localhost:8080`
- Health: `http://localhost:8080/health`
- Ready: `http://localhost:8080/ready`

Option monitoring:

```bash
docker compose --profile monitoring up -d
```

## Commandes utiles

```bash
# logs
docker compose -f docker-compose.dev.yml logs -f app

# arret
docker compose -f docker-compose.dev.yml down

# arret + suppression volumes
docker compose -f docker-compose.dev.yml down -v

# status migrations prisma
bun run db:migrate:status
```

## Depannage rapide

- `DATABASE_URL` manquant:
  - Verifier que `.env` existe et est charge.
- `/ready` renvoie `503`:
  - Attendre que `postgres` + `pgbouncer` soient `healthy`.
  - Verifier les logs: `docker compose -f docker-compose.dev.yml logs -f postgres pgbouncer`.
- Port deja utilise:
  - Changer les ports dans le compose, ou stopper le process qui ecoute deja.

## Documentation complementaire

- [Backend v2 notes](docs/backend-v2.md)
