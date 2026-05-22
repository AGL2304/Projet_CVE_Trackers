# Changelog

Toutes les modifications notables de ce projet sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/) ; versionnage [SemVer](https://semver.org/lang/fr/).

## [Unreleased] — 2026-05-22

### Ajouté

- **Scraping NVD automatique**
  - Worker (`backend/scripts/worker.js`) entièrement réécrit : fetch NVD réel, paginé, avec retry exponentiel sur 429/5xx et respect du rate-limit (6,5 s sans clé / 0,6 s avec clé `NVD_API_KEY`).
  - Sync **delta** toutes les `NVD_DELTA_INTERVAL_MS` (défaut 15 min) — seules les CVE modifiées depuis la dernière passe.
  - Sync **full** toutes les `NVD_FULL_SYNC_INTERVAL_MS` (défaut 24 h) — pagination complète du flux.
  - Au boot : delta depuis la dernière `SyncJob.completedAt`, sinon full borné à `NVD_BOOT_MAX_RECORDS`.
  - Lib partagée `frontend/src/lib/nvd-sync.ts` (fetch + upsert) réutilisable depuis les routes HTTP et les tests.
- **Pilotage du scraping depuis l'UI**
  - `GET /api/admin/scraping/status` — état complet (auto-sync, pause, intervalles, dernier succès/échec, prochaine fenêtre, jobs récents).
  - `POST /api/admin/scraping/trigger` — enqueue d'une sync manuelle (mode `delta`/`full`), refus si une sync est déjà en cours.
  - `POST /api/admin/scraping/pause` / `resume` — toggle persistant via marker file partagé entre app et worker, sans coupure du worker.
  - Page **Settings** : section « Scraping NVD » avec statut live, KPIs, boutons **Pause / Reprendre / Sync delta / Sync complète**, historique des 5 derniers runs (refresh 30 s).
- **Reporting CVE complet**
  - `POST /api/v2/reports/generate` — enqueue d'un report (filtres : `severity`, `status`, `source`, `dateFrom/To`, `minCvss/maxCvss`, `search`, `limit`, `title`).
  - `GET /api/v2/reports` — liste paginée des derniers rapports.
  - `GET /api/v2/reports/[id]/download` — stream le fichier (`?inline=1` pour ouverture navigateur, anti-path-traversal).
  - Génération réelle dans le worker pour trois formats :
    - **PDF (HTML imprimable)** — KPIs, distribution sévérité (SVG), top 20, table complète, bouton « Imprimer / Enregistrer en PDF ».
    - **CSV** — 14 colonnes (CVSS v3/v4, EPSS, vector, refs), BOM UTF-8 pour Excel.
    - **JSON** — payload `{stats, count, cves, filter, generatedAt}`.
  - Page **Reports** refondue : 4 presets (Critiques / Critiques+High 7j / Nouvelles / Complet), formulaire de filtres multi-select, liste live des rapports (polling 5 s) avec boutons **Voir / Télécharger**.
- **Heatmap CVE — refonte**
  - Endpoint `GET /api/v2/analytics/heatmap?days=N&field=published|modified` : agrégation SQL `date_trunc('day')` + pivot par sévérité (FILTER clause Postgres). Scalable sur des centaines de milliers de CVE.
  - Composant `CveDensityHeatmap` (style GitHub) : sélecteurs de période (30 j / 90 j / 6 mois / 1 an) et de champ (publication / modification), labels mois + jours, légende, tooltip avec breakdown par sévérité, deep-link vers la liste CVE filtrée par jour, stats (total période / pic journalier / moyenne).
- **Page Assets**
  - Backend : filtres serveur (search, criticality, status, type), tri sur 6 colonnes, pagination, stats agrégées (`byCriticality`, `byStatus`).
  - Hook `useAssetsPage` ; `useAssets` reste rétro-compatible (renvoie un tableau plat).
  - Frontend : 4 KPIs, barre de filtres avec debounce 250 ms et reset, tri par clic d'en-tête, dialog d'édition (au lieu du seul delete), AlertDialog de confirmation, badges colorés par criticité/statut, **téléchargement modèle CSV**, messages d'erreur API remontés au toast.
- **Page Vulnerabilities**
  - Backend : filtres serveur étendus (search, severity, status, assetId, cveId) + tri sur 7 colonnes, stats agrégées (`bySeverity`, `byStatus`, `avgCvss`).
  - Frontend : 5 KPIs (total, ouvertes, en cours, résolues, CVSS moyen), filtres serveur, dialog d'édition, **action rapide « Marquer résolu »**, lien cliquable vers la fiche CVE, compteur de jours d'ouverture (rouge si > 30 j).
- **Tests unitaires (Vitest)**
  - `tests/unit/severity.test.ts` — calcul de sévérité depuis CVSS v3/v4.
  - `tests/unit/admin-auth.test.ts` — round-trip token + comparaison credentials.
  - `tests/unit/csrf.test.ts` — émission/validation double-submit.
  - `tests/unit/nvd-mapper.test.ts` — mapping NVD → ligne DB.
  - Scripts `npm test` / `test:watch` / `test:coverage` ; config `vitest.config.ts`.

### Modifié

- **Sécurité**
  - `frontend/src/lib/admin-auth.ts` : suppression du fallback `admin/admin123!` en production — boot échoue si `ADMIN_PASSWORD` (< 12 chars) ou `ADMIN_AUTH_SECRET` (< 32 chars) absents. Cookie session passé en `SameSite=Strict`.
  - `frontend/src/lib/v2/auth.ts` : `x-user-id`/`x-user-email` ignorés en production sauf si `INTERNAL_API_SHARED_SECRET` est présenté (fin du spoofing d'identité depuis l'edge).
  - `backend/infra/nginx/default.conf` : strip systématique des headers user/forwarded entrants, `real_ip_header X-Forwarded-For`, headers de hardening, blocage des paths `.git`/`.env`.
  - `frontend/src/lib/v2/rate-limit.ts` : backend Redis optionnel (`ioredis` lazy-loaded si `REDIS_URL`), variante `applyRateLimitAsync` pour enforcement distribué. Fallback in-memory transparent.
  - `frontend/next.config.ts` : **Content-Security-Policy** stricte (`connect-src` autorise `services.nvd.nist.gov`), Permissions-Policy, COOP / CORP.
  - `Dockerfile` (prod) : **HEALTHCHECK**, tini comme PID 1, `npx prisma generate` explicite, `openssl` pour Prisma.
  - Protection **CSRF double-submit** (`frontend/src/lib/csrf.ts` + endpoint `/api/admin/csrf`), branchée automatiquement par `fetchJson` sur les routes `/api/admin/*` mutantes et requise par `/api/admin/settings` (PUT), `/api/admin/scraping/trigger`, `/api/admin/scraping/pause|resume`.
- **Qualité de code**
  - `frontend/eslint.config.mjs` : réactivation des règles critiques (`no-debugger`, `no-undef`, `no-unreachable`, `no-fallthrough`, `react-hooks/rules-of-hooks` en `error` ; autres en `warn`).
  - `frontend/src/lib/v2/audit.ts` : neutralise les pseudo-actors (`admin-session`, `system`) pour ne plus violer la FK `User.id`, et best-effort logging (un audit raté ne casse plus l'action).
- **Infrastructure**
  - `docker-compose.yml` & `docker-compose.dev.yml` : volume `reports-data` partagé entre app et worker pour la livraison des rapports ; variables NVD (`NVD_AUTO_SYNC_ENABLED`, `NVD_FULL_SYNC_INTERVAL_MS`, `NVD_DELTA_INTERVAL_MS`, `NVD_BOOT_MAX_RECORDS`, `NVD_PAGE_SIZE`, `REPORTS_DIR`) exposées au worker. Le compose dev embarque maintenant le service worker.
  - `.env.example` étendu (toutes les variables NVD, `CSRF_SECRET`, `INTERNAL_API_SHARED_SECRET`, `REPORTS_DIR`).
  - `package.json` : ajout `ioredis`, `vitest`, `@vitest/coverage-v8` + scripts `test*`.

### Corrigé

- Vulnerabilities `PUT` : `resolvedAt` n'est plus écrasé sur les modifications hors changement de statut (préservation de la date de résolution).
- Vulnerabilities `POST/PUT` : `assetId === ""` ou `"none"` normalisé à `null` (fin des violations FK Prisma).
- Worker : transitions `QUEUED → RUNNING → COMPLETED` ne sont plus factices — l'état suit la réalité du traitement, et `errorMessage` est renseigné en cas d'échec.
- Dashboard heatmap : ne page plus l'intégralité de la table CVE pour calculer 84 cellules côté client. L'agrégation est SQL.

### Sécurité

- `.env` n'est **pas** commité (vérifié via `git ls-files`). Si vous avez partagé le dossier hors git, planifiez une rotation des secrets (`NVD_API_KEY`, `CMDB_API_TOKEN`, `NEXTAUTH_SECRET`, `ADMIN_AUTH_SECRET`).
- Le compte admin par défaut `admin/admin123!` est désormais **bloqué en production**.

### Notes de migration

- Si vous mettez à jour une instance déployée :
  1. Renseignez en `.env` (production) : `ADMIN_PASSWORD` (≥ 12 chars), `ADMIN_AUTH_SECRET` (≥ 32 chars), `NVD_API_KEY` (recommandé pour x10 sur la vitesse de sync), `CSRF_SECRET`.
  2. `npm install` (nouvelles dépendances : `ioredis`, `vitest`, `@vitest/coverage-v8`).
  3. `docker compose up -d --build` (le `Dockerfile` génère désormais le client Prisma au build).
  4. Aucune migration Prisma à appliquer — toutes les modifications sont au niveau API/UI/worker.

---

## Historique antérieur

Voir [`worklog.md`](worklog.md) pour les notes datées du 2025-01-14 (nettoyage initial du workspace).
