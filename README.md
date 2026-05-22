# CVE Tracker

Plateforme SOC pour suivre des CVE/CVSS, gerer les assets, piloter un backlog de vulnerabilites, et produire des rapports.

Ce README documente l'etat reel du depot (frontend + backend) analyse dans `Projet_CVE_Trackers`.

## 1) Vue d'ensemble

Le projet repose sur une architecture monorepo:

- `frontend/`: application Next.js 15 (App Router) + interface SOC.
- `backend/`: handlers API, Prisma, scripts worker, infra.
- API exposee via `frontend/src/app/api/*` (wrappers) qui reexporte le code de `backend/api/*`.
- Base principale: PostgreSQL 16 via Prisma.
- Services complementaires: PgBouncer, Redis, Elasticsearch.

Le projet contient 2 familles d'API:

- API legacy (v1): endpoints JSON classiques (`/api/assets`, `/api/vulnerabilities`, `/api/cves`, etc.).
- API v2: endpoints JSON:API (`/api/v2/*`) avec pagination curseur, audit, rate limit, role checks.

## 2) Fonctionnalites principales

- Dashboard SOC (KPIs, heatmap, distribution severite, timeline d'activite).
- Gestion CVE: recherche avancee, filtres, import NVD, vues table/cards/timeline, export CSV/JSON/PDF.
- Fiche detail CVE: infos techniques, references, calculateur CVSS, commentaires internes (localStorage), remediation.
- Gestion des vulnerabilites (CRUD v1 + mise a jour de statut).
- Gestion des assets (CRUD, import CSV, visualisation exposition, synchronisation CMDB).
- Reporting (templates, constructeur drag-and-drop, export PDF, planification UI).
- Administration:
  - login/logout/session admin par cookie signe (SameSite=Strict),
  - settings applicatifs (langue, NVD key, CMDB, webhook),
  - test CMDB (`/api/admin/cmdb/test`),
  - sync CMDB (`/api/admin/cmdb/sync`),
  - **statut + declenchement manuel du scraping NVD** (`/api/admin/scraping/status`, `/api/admin/scraping/trigger`),
  - protection CSRF (token double-submit via `/api/admin/csrf`).

### Scraping NVD automatique

Le worker (`backend/scripts/worker.js`) tourne en continu et alimente la base CVE depuis le flux officiel NVD :

- **Delta sync** toutes les `NVD_DELTA_INTERVAL_MS` (defaut 15 min) — recupere uniquement les CVE modifiees depuis la derniere passe.
- **Full sync** toutes les `NVD_FULL_SYNC_INTERVAL_MS` (defaut 24 h) — repagine l'ensemble du flux pour rattrapage.
- Au boot : delta sync depuis la derniere completion connue, sinon full sync borne (`NVD_BOOT_MAX_RECORDS`).
- Respect du rate limit NVD : 6.5 s entre pages sans cle API, 0.6 s avec cle (`NVD_API_KEY`).
- Retry exponentiel sur 429 / 5xx (jusqu'a 4 tentatives par page).
- Toutes les operations creent un `SyncJob` en base (status, compteurs new/updated/error, logs des 300 dernieres lignes).
- Endpoint POST `/api/admin/scraping/trigger` pour declencher une sync ponctuelle depuis l'UI (page Settings).

## 3) Stack technique

- Frontend: Next.js 15, React 19, TypeScript, Tailwind CSS, shadcn/ui, TanStack Query/Table/Virtual, Recharts, dnd-kit, Framer Motion.
- Backend (dans Next route handlers): Prisma ORM, Zod, JSON:API helper, audit log, in-memory cache/rate-limit.
- Base de donnees: PostgreSQL 16.
- Infra conteneurs: Nginx gateway, app, worker, postgres, pgbouncer, redis, elasticsearch (+ Prometheus/Grafana optionnels).

## 4) Arborescence utile

```text
.
|-- backend/
|   |-- api/                      # Handlers API (admin, v1, v2)
|   |-- prisma/                   # Schema + migrations
|   |-- scripts/worker.js         # Worker jobs sync/report
|   |-- infra/                    # Nginx + Prometheus
|   `-- db/initial_data.sql
|-- frontend/
|   |-- src/app/                  # Pages UI + routes API wrappers
|   |-- src/components/           # UI et composants metier
|   |-- src/lib/                  # DB, auth admin, CMDB, utilitaires v2
|   |-- src/hooks/                # React Query hooks
|   `-- src/store/                # Zustand (preferences UI)
|-- docker-compose.dev.yml
|-- docker-compose.yml
|-- Dockerfile
|-- Dockerfile.dev
|-- package.json
`-- test-api.ps1
```

## 5) Prerequis

- Docker Desktop + Docker Compose v2
- Bun >= 1.2 (recommande) ou Node.js >= 20
- PowerShell (Windows) ou shell Unix

## 6) Installation et demarrage local (recommande)

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

3. Demarrer les services data:

```bash
docker compose -f docker-compose.dev.yml up -d postgres pgbouncer redis elasticsearch
```

4. Initialiser Prisma:

```bash
bun run db:generate
bun run db:migrate:deploy
```

5. Lancer l'app:

```bash
bun run dev
```

6. Ouvrir:

- UI: `http://localhost:3000`
- Health: `http://localhost:3000/health`
- Ready: `http://localhost:3000/ready`

Option worker local:

```bash
bun run worker
```

## 7) Variables d'environnement importantes

Extrait de `.env.example`:

```env
NODE_ENV=development
DATABASE_URL=postgresql://cve_tracker:cve_tracker@localhost:6432/cve_tracker
REDIS_URL=redis://localhost:6379
ELASTICSEARCH_URL=http://localhost:9200
NEXTAUTH_URL=http://localhost:8080
NEXTAUTH_SECRET=replace-with-long-random-secret
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123!
ADMIN_AUTH_SECRET=replace-with-long-random-secret
NVD_API_KEY=
CMDB_ENDPOINT=
CMDB_API_TOKEN=
CMDB_API_KEY=
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
```

Notes:

- `ADMIN_USERNAME`/`ADMIN_PASSWORD` servent au login admin de `/settings`.
- `ADMIN_AUTH_SECRET` signe le cookie `cve_admin_session`.
- Pour une CMDB joignable depuis Docker sur la machine hote, `host.docker.internal` est supporte.

## 8) APIs exposees

### Legacy (v1)

- `GET/POST /api/assets`
- `PUT/DELETE /api/assets/:id`
- `GET/POST /api/vulnerabilities`
- `GET/PUT/DELETE /api/vulnerabilities/:id`
- `GET /api/dashboard/stats`
- `GET /api/cves`
- `GET /api/cves/nvd/search`
- `POST /api/cves/nvd/import`
- `GET/POST /api/seed`

### Administration

- `POST /api/admin/auth/login`
- `POST /api/admin/auth/logout`
- `GET /api/admin/auth/session`
- `GET/PUT /api/admin/settings`
- `POST /api/admin/cmdb/test`
- `POST /api/admin/cmdb/sync`

### API v2 (JSON:API)

- `GET /api/v2`
- `GET /api/v2/openapi`
- `GET/POST /api/v2/cves`
- `GET/PATCH /api/v2/cves/:id`
- `POST /api/v2/sync/nvd`
- `GET /api/v2/sync/jobs/:id`
- `GET /api/v2/analytics/dashboard`
- `POST /api/v2/reports/generate`
- `GET /api/v2/reports/:id`
- `GET /api/v2/notifications`
- `PATCH /api/v2/notifications/:id`
- `DELETE /api/v2/users/:id`

## 9) Donnees et modele

Le schema Prisma couvre notamment:

- `CVE`, `CWE`, `Product`, `ProductCVE`
- `Asset`, `Vulnerability`, `AssetProduct`
- `User`, `Notification`, `AuditLog`
- `SyncJob`, `ReportJob`
- `Comment`, `Tag`, tables de liaison (`CVETag`, `AssetTag`, `CVECWE`)
- `AppSettings` (singleton admin/integrations)

Enums metier: severite, statuts CVE, sources, roles, jobs sync/report, etc.

## 10) Lancer en Docker complet

### Dev compose

```bash
docker compose -f docker-compose.dev.yml up --build
```

Puis migrations dans un second terminal:

```bash
docker compose -f docker-compose.dev.yml exec app bun run db:migrate:deploy
```

### Prod-like local

```bash
docker compose up --build -d
```

Acces:

- App via gateway Nginx: `http://localhost:8080`
- Health: `http://localhost:8080/health`
- Ready: `http://localhost:8080/ready`

Monitoring optionnel:

```bash
docker compose --profile monitoring up -d
```

## 11) Scripts utiles

Dans `package.json`:

- `bun run dev` / `bun run build` / `bun run start`
- `bun run worker`
- `bun run lint`
- `bun run db:generate`
- `bun run db:migrate`
- `bun run db:migrate:deploy`
- `bun run db:migrate:status`
- `bun run db:push`
- `bun run db:reset`

Script smoke test PowerShell:

```powershell
./test-api.ps1
```

## 12) Points d'attention

- Le worker (`backend/scripts/worker.js`) implemente actuellement un traitement simplifie des jobs (passage QUEUED -> RUNNING -> COMPLETED).
- Plusieurs fonctions "reporting PDF" cote UI utilisent la fonction d'impression du navigateur (pas de moteur PDF backend dedie).
- Le rate limit v2 est en memoire process (pas distribue).
- Les commentaires de fiche CVE sont stockes en `localStorage` cote client.

## 13) Depannage rapide

- `ready` retourne `503`:
  - verifier `DATABASE_URL`,
  - verifier `postgres`/`pgbouncer` healthy,
  - consulter `docker compose -f docker-compose.dev.yml logs -f postgres pgbouncer app`.
- Echec login admin:
  - verifier `.env` (`ADMIN_USERNAME`, `ADMIN_PASSWORD`, `ADMIN_AUTH_SECRET`),
  - vider les cookies navigateur si necessaire.
- Erreur CMDB depuis Docker:
  - essayer endpoint via `host.docker.internal`.

## 14) Documentation complementaire

- Notes backend v2: `backend/docs/backend-v2.md`
