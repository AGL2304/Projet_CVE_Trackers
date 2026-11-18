# Changelog

Toutes les modifications notables de ce projet sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/) ; versionnage [SemVer](https://semver.org/lang/fr/).

## [Unreleased] - 2026-11-13

### Ajouté

- **Suivi de correction par CVE** (`frontend/src/lib/cve-helpers.ts`, `frontend/src/lib/v2/mappers.ts`, `backend/api/cves/route.ts`, `backend/api/v2/cves/[id]/route.ts`, `frontend/src/app/cves/page.tsx`, `frontend/src/app/cves/[cveId]/page.tsx`)
  - Nouveau helper `extractPatchRefs()` qui lit les tags NVD (`Patch`, `Vendor Advisory`) déjà présents dans `CVE.rawData` (synchronisés depuis la NVD mais jamais exploités jusqu'ici) pour déterminer si un correctif éditeur existe.
  - `mapCveToLegacy` expose désormais `hasPatch`, `patchRefs`, `cveStatus`, `dbVersion`, sans alourdir le payload (le `rawData` brut n'est pas renvoyé, seuls les champs dérivés le sont).
  - Colonne « Correctif » sur la liste CVE (tableau dense + vue cartes), badge de statut (Patch disponible / Corrigée / Aucun correctif identifié) sur la fiche CVE, avec les liens NVD (Patch/Vendor Advisory) cliquables et leurs tags.
  - Action « Marquer comme corrigée » qui active enfin `CVE.status` (`CVEStatus.REMEDIATED`, déjà prévu au schéma mais jamais écrit) via le endpoint `PATCH /api/v2/cves/[id]` déjà existant (verrou optimiste par `version` + audit log, déjà en place).
- **Historique du processus de correction** (`backend/api/v2/cves/[id]/route.ts`, `frontend/src/hooks/queries.ts`, `frontend/src/app/cves/[cveId]/page.tsx`)
  - `PATCH /api/v2/cves/[id]` accepte un champ `note` (texte libre, ex: version appliquée, date de déploiement, validation) enregistré dans l'audit log existant (`AuditLog`, dont le `userId` nullable tolère déjà les pseudo-acteurs comme `admin-session` - le modèle `Comment`, à clé étrangère obligatoire, aurait échoué pour ce même acteur).
  - `GET /api/v2/cves/[id]?include=history` renvoie l'historique chronologique des changements de statut pour une CVE.
  - « Marquer comme corrigée » ouvre désormais une boîte de dialogue demandant de décrire le processus suivi avant de confirmer ; une section « Processus de correction » sur la fiche CVE affiche la chronologie complète (qui, quand, statut avant/après, note).

### Corrigé

- **Dashboard lent au démarrage et page qui ne s'affichait pas** (`frontend/src/app/page.tsx`, `backend/api/cves/route.ts`, `frontend/src/hooks/queries.ts`)
  - Cause : le dashboard appelait `useCVEs()` → `GET /api/cves`, dont la requête (`db.cVE.findMany()`) n'avait **aucune limite** et renvoyait toute la table `CVE` (y compris le `rawData` NVD brut de chaque ligne) à chaque chargement. Avec le scraping NVD automatique (sync complète toutes les 24 h), cette table grossit en continu, rendant la requête de plus en plus lente à exécuter, sérialiser et transférer - jusqu'à bloquer durablement le rendu du dashboard (chargement qui ne se termine jamais).
  - `GET /api/cves` accepte désormais un paramètre optionnel `limit` (borné à 1000) ; le comportement par défaut (sans limite) est conservé pour ne pas casser les pages `/cves` et `/cves/[cveId]` qui font encore une recherche cliente sur le jeu complet.
  - Nouveaux hooks `useRecentCves(limit)` (slice bornée) et `useDashboardAnalytics()` branché sur `GET /api/v2/analytics/dashboard` - un agrégat SQL déjà existant et caché 30 s côté serveur, mais jamais utilisé par le dashboard jusqu'ici.
  - Le dashboard calcule maintenant ses KPI (total, critiques, nouvelles CVE 7j, CVSS moyen) et la distribution par sévérité via cet agrégat SQL, et ne récupère plus que les 100 CVE les plus récentes pour le top 10 et la timeline, au lieu de la table entière.
- **Page CVE lente à l'ouverture** (`frontend/src/app/cves/page.tsx`, `frontend/src/app/cves/[cveId]/page.tsx`, `backend/api/cves/route.ts`, `frontend/src/hooks/queries.ts`)
  - Même cause racine que le dashboard : `useCVEs()` pageait toute la table (mesuré à ~529 s sur un appel, au point de saturer la mémoire de la VM WSL2 et de planter Docker Desktop pendant un test). La liste utilise désormais `useRecentCves(2000)` (bornée côté serveur via `GET /api/cves?limit=`), et la fiche CVE fait un lookup direct par `cveId` (`GET /api/cves?cveId=`, indexé unique) au lieu de télécharger toute la table pour y trouver une seule ligne.
- **Bug CSS transversal : la colonne de contenu principale pouvait s'étirer à la largeur de son descendant le plus large (jusqu'à 5507 px mesurés) au lieu de la largeur de l'écran** (`frontend/src/components/app-shell.tsx`)
  - Cause : le conteneur flex `flex-1` enveloppant `<main>` n'avait pas `min-w-0` ; son minimum par défaut (`min-width: auto`) le laissait grossir avec son descendant le plus large (ici, une grille de filtres `md:grid-cols-[2fr_1fr_1fr_1.4fr_auto]` sur la page Vulnérabilités, dont le calcul de largeur intrinsèque des pistes `fr` s'est emballé). Corrigé au niveau du shell partagé - bénéficie à toutes les pages, pas seulement à celle qui a révélé le bug.
- **Page Vulnérabilités qui nécessitait de défiler toute la page pour voir le backlog** (`frontend/src/app/vulnerabilities/page.tsx`)
  - Le tableau du backlog a désormais une hauteur calculée (`calc(100vh - 44rem)`, plancher 200 px) avec défilement interne propre, pour que la page tienne dans la fenêtre sans défilement global sur un écran courant (≥ 900 px de haut).
- **Erreur d'hydratation React sur la page CVEs (`<button>` imbriqué dans `<button>`)** (`frontend/src/app/cves/page.tsx`)
  - L'en-tête de la colonne de sélection (case à cocher) était enveloppé dans le bouton de tri de colonne, générant un HTML invalide. Tri désactivé sur cette colonne ; le bouton de tri n'enveloppe plus que les colonnes réellement triables.
- **Plantage clavier (`event.key` undefined) sur les raccourcis globaux** (`frontend/src/components/app-shell.tsx`)
  - Garde ajoutée (`if (!event.key) return`) avant tout appel à `.toLowerCase()` sur la touche pressée.
- **Tirets cadratins (—) retirés de tout le projet** (40 fichiers : code, commentaires, CHANGELOG, README, docs) - remplacés par des tirets simples.

---

## [Unreleased] - 2026-06-28

### Ajouté

- **Rapport d'inventaire au format BLUF (Bottom Line Up Front)**
  - `backend/scripts/worker.js` : le rapport d'actifs (HTML/PDF) s'ouvre désormais sur une **synthèse décisionnelle** - une bannière de *posture de sécurité* (`CRITIQUE` / `ÉLEVÉE` / `MODÉRÉE` / `MAÎTRISÉE`) avec verdict en une phrase, 4 indicateurs de tête (actifs à traiter en priorité, CVE critiques exposées, services dangereux exposés, score d'exposition max) et une **action immédiate** nommant l'actif et les CVE exactes à corriger.
  - **Plan d'action priorisé** : table des actifs classés par exposition décroissante, chacun avec ses *pilotes du risque* (compteurs CVE crit./élevées + ports dangereux ouverts), des **actions concrètes typées** (`Corriger` / `Confiner` / `Planifier`) dérivées de l'exposition réelle, et une **échéance** (`Immédiat` / `Court terme`).
  - Le détail (indicateurs, répartition, inventaire complet, CVE par actif) reste en annexe, le tout relié par un sommaire ancré.
  - Helpers `computeAssetBluf()` / `assetRecommendedActions()` extraits et `worker.js` rendu testable (`module.exports` + garde `require.main === module`).

- **Rapport d'inventaire enrichi et pleinement documenté** (`backend/scripts/worker.js`)
  - **Introduction et méthodologie** : nouvelle section d'ouverture (`#sec-intro`) - objet du rapport, méthode (découverte réseau → corrélation CPE↔NVD → score d'exposition) et mode d'emploi, avec une légende des niveaux de criticité.
  - **Fiches détaillées par actif** (`#sec-fiches`) : un dossier complet par actif, classé par exposition décroissante. Chaque fiche documente **tous les services/ports ouverts** (port, protocole, service, produit/version, CPE, bannière, **poids d'exposition**), une table de **remédiation prioritaire** (risque concret + mesure corrective par port dangereux ≥ 16), le **plan d'action** typé, et la **table des CVE corrélées** (liens NVD cliquables, ancre `#cve-<id>` résolue depuis l'inventaire).
  - **Annexes** (`#sec-annex`) : A. modèle de calcul du score d'exposition (formule + seuils), B. glossaire (CVE/CPE/CVSS/NVD/exposition/BLUF/service dangereux), C. cadre légal et éthique (périmètre autorisé, art. 323-1 et s. du Code pénal, confidentialité) - structure alignée sur un rapport de pentest pédagogique.
  - Helpers ajoutés : `PORT_REMEDIATION` (copie risque/correctif par port), `portRemediation()`, `LEVEL_FR`, `renderAssetFiche()`, `renderIntro()`, `renderAnnex()`.
  - Vérifié de bout en bout sur une cible Metasploitable : la fiche liste **30 services** (au lieu de 17) et **576 CVE corrélées** (au lieu de 0), score d'exposition 509.

- **Projection des corrélations en vulnérabilités exploitables** (`backend/scripts/materialize_vulns.js`)
  - Le scanner poussait les actifs/services et `match_cve.js` corrélait chaque produit à ses CVE (graphe `ProductCVE`), mais **rien ne projetait ces corrélations dans la table `Vulnerability`** - la liste de constats *par actif* avec statut que lisent la page `/vulnerabilities`, les stats du tableau de bord **et** l'enrichissement du SIEM (`GET /api/vulnerabilities?assetId=…&status=open`). Conséquence : 576 CVE corrélées à la Metasploitable, mais **0 vulnérabilité** affichée où que ce soit.
  - Nouveau script worker qui matérialise un constat `Vulnerability` (statut `open`, sévérité, CVSS, titre) par couple (actif, CVE) à partir du graphe actif↔produit↔CVE. Idempotent (upsert sur `cveId`), il traite les actifs **du plus exposé au moins exposé** pour respecter l'unicité globale de `Vulnerability.cveId` (l'hôte le plus critique réclame ses CVE en premier).
  - Vérifié : **615 constats** créés (Metasploitable 576, AGL23 38, ALG7 1) → le tableau de bord passe de 0 à **615 vulnérabilités ouvertes** (40 critiques, 176 élevées) et le SIEM enrichit désormais chaque alerte avec le contexte CVE réel de l'hôte.

- **Pondérations d'exposition étendues aux services « legacy » dangereux** (`backend/scripts/exposure.js` + `frontend/src/lib/v2/exposure.ts`, gardés synchronisés)
  - Ajout de 15 services classiques directement exploitables qui ne comptaient que pour +2 : NFS (2049), rpcbind (111), rexec/rlogin/rsh (512/513/514), Java RMI (1099), distccd (3632), AJP/Ghostcat (8009), Tomcat (8180), X11 (6000), Ruby DRb (8787), FTP-alt (2121), ingreslock (1524), IRC (6667/6697). Les fiches reflètent désormais le vrai risque de ces ports.

- **Scraping NVD automatique**
  - Worker (`backend/scripts/worker.js`) entièrement réécrit : fetch NVD réel, paginé, avec retry exponentiel sur 429/5xx et respect du rate-limit (6,5 s sans clé / 0,6 s avec clé `NVD_API_KEY`).
  - Sync **delta** toutes les `NVD_DELTA_INTERVAL_MS` (défaut 15 min) - seules les CVE modifiées depuis la dernière passe.
  - Sync **full** toutes les `NVD_FULL_SYNC_INTERVAL_MS` (défaut 24 h) - pagination complète du flux.
  - Au boot : delta depuis la dernière `SyncJob.completedAt`, sinon full borné à `NVD_BOOT_MAX_RECORDS`.
  - Lib partagée `frontend/src/lib/nvd-sync.ts` (fetch + upsert) réutilisable depuis les routes HTTP et les tests.
- **Synchronisation CMDB durcie et actionnable** (`backend/api/admin/cmdb/sync/route.ts`)
  - **Respect du master switch** : une sync manuelle est refusée (HTTP 409) si l'intégration CMDB est désactivée dans Settings - fini les écritures silencieuses pendant que le connecteur est censé être éteint.
  - **Upsert résilient et idempotent** : appariement par identité forte (hostname → ip → name+type) pour mettre à jour en place au lieu de dupliquer ; un enregistrement malformé est compté en `failed` et n'interrompt plus toute la passe (try/catch par actif).
  - **Notification des consommateurs aval** : chaque actif créé/mis à jour émet un webhook `asset.created` / `asset.updated` (source `cmdb-sync`) vers SIEM/Scanner, plafonné à 500 actifs touchés pour ne pas inonder les abonnés sur un gros import.
  - **Journal d'audit** : chaque run écrit une entrée `cmdb.sync` (`created`, `updated`, `failed`, `rawCount`, `mappedCount`).
  - **Statut honnête** : un run qui mappe des enregistrements mais n'en pose aucun est rapporté en `error` (et non un faux « ok » vert) ; le message conserve le format exact « X created, Y updated[, Z failed] from N CMDB records ».
- **Pilotage du scraping depuis l'UI**
  - `GET /api/admin/scraping/status` - état complet (auto-sync, pause, intervalles, dernier succès/échec, prochaine fenêtre, jobs récents).
  - `POST /api/admin/scraping/trigger` - enqueue d'une sync manuelle (mode `delta`/`full`), refus si une sync est déjà en cours.
  - `POST /api/admin/scraping/pause` / `resume` - toggle persistant via marker file partagé entre app et worker, sans coupure du worker.
  - Page **Settings** : section « Scraping NVD » avec statut live, KPIs, boutons **Pause / Reprendre / Sync delta / Sync complète**, historique des 5 derniers runs (refresh 30 s).
- **Reporting CVE complet**
  - `POST /api/v2/reports/generate` - enqueue d'un report (filtres : `severity`, `status`, `source`, `dateFrom/To`, `minCvss/maxCvss`, `search`, `limit`, `title`).
  - `GET /api/v2/reports` - liste paginée des derniers rapports.
  - `GET /api/v2/reports/[id]/download` - stream le fichier (`?inline=1` pour ouverture navigateur, anti-path-traversal).
  - Génération réelle dans le worker pour trois formats :
    - **PDF (HTML imprimable)** - KPIs, distribution sévérité (SVG), top 20, table complète, bouton « Imprimer / Enregistrer en PDF ».
    - **CSV** - 14 colonnes (CVSS v3/v4, EPSS, vector, refs), BOM UTF-8 pour Excel.
    - **JSON** - payload `{stats, count, cves, filter, generatedAt}`.
  - Page **Reports** refondue : 4 presets (Critiques / Critiques+High 7j / Nouvelles / Complet), formulaire de filtres multi-select, liste live des rapports (polling 5 s) avec boutons **Voir / Télécharger**.
- **Heatmap CVE - refonte**
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
  - `tests/unit/severity.test.ts` - calcul de sévérité depuis CVSS v3/v4.
  - `tests/unit/admin-auth.test.ts` - round-trip token + comparaison credentials.
  - `tests/unit/csrf.test.ts` - émission/validation double-submit.
  - `tests/unit/nvd-mapper.test.ts` - mapping NVD → ligne DB.
  - Scripts `npm test` / `test:watch` / `test:coverage` ; config `vitest.config.ts`.

### Modifié

- **Sécurité**
  - `frontend/src/lib/admin-auth.ts` : suppression du fallback `admin/admin123!` en production - boot échoue si `ADMIN_PASSWORD` (< 12 chars) ou `ADMIN_AUTH_SECRET` (< 32 chars) absents. Cookie session passé en `SameSite=Strict`.
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
- Worker : transitions `QUEUED → RUNNING → COMPLETED` ne sont plus factices - l'état suit la réalité du traitement, et `errorMessage` est renseigné en cas d'échec.
- Dashboard heatmap : ne page plus l'intégralité de la table CVE pour calculer 84 cellules côté client. L'agrégation est SQL.

### Sécurité

- `.env` n'est **pas** commité (vérifié via `git ls-files`). Si vous avez partagé le dossier hors git, planifiez une rotation des secrets (`NVD_API_KEY`, `CMDB_API_TOKEN`, `NEXTAUTH_SECRET`, `ADMIN_AUTH_SECRET`).
- Le compte admin par défaut `admin/admin123!` est désormais **bloqué en production**.

### Notes de migration

- Si vous mettez à jour une instance déployée :
  1. Renseignez en `.env` (production) : `ADMIN_PASSWORD` (≥ 12 chars), `ADMIN_AUTH_SECRET` (≥ 32 chars), `NVD_API_KEY` (recommandé pour x10 sur la vitesse de sync), `CSRF_SECRET`.
  2. `npm install` (nouvelles dépendances : `ioredis`, `vitest`, `@vitest/coverage-v8`).
  3. `docker compose up -d --build` (le `Dockerfile` génère désormais le client Prisma au build).
  4. Aucune migration Prisma à appliquer - toutes les modifications sont au niveau API/UI/worker.

---

## Historique antérieur

Voir [`worklog.md`](worklog.md) pour les notes datées du 2025-01-14 (nettoyage initial du workspace).
