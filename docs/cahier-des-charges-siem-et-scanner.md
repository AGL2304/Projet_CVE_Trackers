# Cahier des charges — SIEM Léger & Network Scanner Pro

Projets complémentaires à **CVE Tracker** formant un écosystème SOC cohérent.

| Composant | Rôle dans la chaîne | État |
|---|---|---|
| **Network Scanner Pro** | Découvre les actifs réels du SI et leurs services/versions | À construire |
| **CVE Tracker** | Centralise les vulnérabilités, les assets et la remédiation | Existant |
| **SIEM Léger** | Collecte les logs, détecte les attaques, corrèle avec les CVE | À construire |

Flux global :

```
[ Réseau ]
    │
    │ découverte
    ▼
[ Network Scanner Pro ] ──── assets + CPE ───► [ CVE Tracker ]
                                                     ▲
                                                     │ enrichissement CVE
                                                     │
[ Hôtes / apps ] ──── logs ───► [ SIEM Léger ] ──── alertes corrélées ───►
```

---

## Partie 1 — Network Scanner Pro

### 1.1 Contexte & objectif

Aujourd'hui, l'inventaire de CVE Tracker est alimenté manuellement (CSV, CMDB tierce). Or, **on ne protège que ce qu'on connaît** : un actif oublié = un angle mort permanent. Network Scanner Pro vise à **découvrir automatiquement les machines, services et versions** présents sur un réseau, puis à pousser ces informations dans CVE Tracker pour que le scoring d'exposition soit calculé sur la réalité du SI, pas sur un fichier Excel obsolète.

### 1.2 Périmètre

**Dans le périmètre :**
- Scan IPv4 / IPv6 sur sous-réseaux internes (LAN, VLAN, VPN).
- Détection de services TCP (et UDP courants) avec fingerprinting de version.
- Identification d'OS (best effort).
- Calcul de l'identifiant standardisé **CPE 2.3** (Common Platform Enumeration) pour chaque service détecté.
- Push automatique des résultats vers CVE Tracker via son endpoint `/api/v2/...`.
- Planification récurrente + scan à la demande.

**Hors périmètre (version 1) :**
- Scan d'authentification interne (credentialed scans).
- Test d'exploitabilité actif (pas d'exploit).
- Pentest automatisé.
- Web crawling applicatif (réservé à un futur module).

### 1.3 Acteurs

| Acteur | Besoin |
|---|---|
| Analyste SOC | Lance un scan ponctuel, consulte la dernière cartographie. |
| Administrateur sécurité | Configure les plages d'IP autorisées, les fenêtres de scan, les exclusions. |
| Système (cron) | Déclenche les scans planifiés sans intervention humaine. |

### 1.4 Exigences fonctionnelles

| ID | Exigence |
|---|---|
| F-NS-01 | Scan d'une plage d'IP (CIDR ou liste) avec sélection des ports à sonder. |
| F-NS-02 | Trois profils de scan préconfigurés : **rapide** (top 100 ports), **standard** (top 1000), **complet** (1-65535). |
| F-NS-03 | Détection de la version d'un service (HTTP, SSH, RDP, SMB, FTP, SMTP, etc.) avec confidence score. |
| F-NS-04 | Calcul du CPE et envoi à CVE Tracker pour récupérer les CVE associées. |
| F-NS-05 | Cartographie persistée : nouvel hôte créé / hôte existant mis à jour (déduplication par MAC > hostname > IP). |
| F-NS-06 | Mode **stealth** : taux d'envoi modéré, randomisation, fragmentation, pour éviter d'alerter les IDS lors d'audits autorisés. |
| F-NS-07 | Liste d'exclusion (IP, plages, hôtes critiques) respectée systématiquement. |
| F-NS-08 | Historique des scans avec diff inter-scans (nouveaux services, services disparus, changements de version). |
| F-NS-09 | Export JSON, CSV et XML (compatible importeurs existants). |
| F-NS-10 | API REST permettant à d'autres outils (dont CVE Tracker) de déclencher un scan ciblé. |

### 1.5 Exigences non-fonctionnelles

| Catégorie | Exigence |
|---|---|
| Performance | Scan rapide d'un /24 (256 IP) en < 60 s. Scan standard d'un /24 en < 5 min. |
| Sécurité | Authentification API par token. Logs d'audit horodatés et immuables. Aucun stockage de credentials cible. |
| Conformité | Respect d'une « scan policy » obligatoire avant tout lancement (autorisations, fenêtre horaire, exclusions). |
| Portabilité | Conteneurisé (Docker). Déployable hors-ligne dans un réseau cloisonné. |
| Observabilité | Logs structurés (JSON), métriques Prometheus, healthcheck HTTP. |

### 1.6 Architecture proposée

```
┌────────────────┐    ┌──────────────────┐    ┌────────────────┐
│  Frontend Vue  │───►│  API Gateway     │───►│  Scan Engine   │
│  (dashboard)   │    │  (FastAPI)       │    │  (worker pool) │
└────────────────┘    └──────────────────┘    └───────┬────────┘
                              │                       │
                              ▼                       ▼
                      ┌──────────────┐         ┌────────────────┐
                      │  PostgreSQL  │         │ nmap / masscan │
                      │  (résultats) │         │ (binaires)     │
                      └──────────────┘         └────────────────┘
                              │
                              ▼
                      ┌──────────────┐
                      │ CVE Tracker  │  (push via /api/v2/sync/...)
                      └──────────────┘
```

### 1.7 Stack technique recommandée

- **Backend** : Python 3.12 + FastAPI (excellent pour ce type d'orchestration).
- **Moteur de scan** : nmap + masscan (libres, éprouvés, fingerprinting riche).
- **Base** : PostgreSQL (réutiliser l'instance de CVE Tracker en bases séparées).
- **Worker** : Celery + Redis (déjà disponible dans la stack).
- **Frontend** : Next.js (cohérence avec CVE Tracker) ou un dashboard intégré directement à CVE Tracker via une nouvelle section « Discovery ».
- **Auth** : OAuth2 / clé d'API partagée avec CVE Tracker.

### 1.8 Modèle de données simplifié

| Table | Champs clés |
|---|---|
| `scan_profile` | id, name, port_range, timing, stealth, exclusions[] |
| `scan_run` | id, profile_id, started_at, completed_at, status, total_hosts, total_services |
| `discovered_host` | id, scan_run_id, ip, mac, hostname, os_guess, confidence |
| `discovered_service` | id, host_id, port, protocol, service, version, cpe, banner |
| `audit_log` | id, actor, action, target, ip, timestamp |

### 1.9 Intégration avec CVE Tracker

À la fin d'un scan :
1. Pour chaque `discovered_host` → POST `/api/assets` (création/MAJ avec déduplication).
2. Pour chaque `discovered_service` avec CPE → POST `/api/v2/sync/cpe` (à créer côté CVE Tracker) qui matche le CPE contre les CVE en base et crée les liens `Product ↔ Asset ↔ CVE`.
3. Webhook de retour de CVE Tracker : « 12 CVE critiques découvertes sur les nouveaux assets » → notification dans le dashboard Scanner.

### 1.10 Phases & livrables

| Phase | Durée | Livrables |
|---|---|---|
| **P1 — Socle** | 2 sem. | API auth, modèle DB, exécution nmap pilotée, persistance. |
| **P2 — Fingerprinting** | 2 sem. | Détection de version, calcul CPE, profils rapide/standard. |
| **P3 — Intégration CVE Tracker** | 1 sem. | Push assets + services, endpoint de matching CPE côté CVE Tracker. |
| **P4 — Planification & UI** | 2 sem. | Cron, dashboard, diff entre scans, exports. |
| **P5 — Durcissement** | 1 sem. | Stealth, exclusions, audit log, healthcheck, tests. |

### 1.11 Critères d'acceptation

- Découverte de 95 % des hôtes connus d'un /24 de référence en mode standard.
- Identification correcte de la version pour ≥ 80 % des services HTTP, SSH, RDP, SMB.
- Push des assets dans CVE Tracker visible en moins de 30 s après la fin du scan.
- Aucun faux positif sur un sous-réseau vide (zéro hôte signalé là où il n'y en a pas).
- Logs d'audit présents pour 100 % des scans.

### 1.12 Risques & mitigations

| Risque | Mitigation |
|---|---|
| Scan perçu comme attaque par l'IDS | Mode stealth + scan policy + plage horaire négociée. |
| Saturation réseau | Limite de débit configurable (PPS), worker pool dimensionné. |
| Mauvaise identification de version → faux CVE | Toujours stocker le `confidence score`, n'auto-créer un lien CVE qu'au-dessus d'un seuil. |
| Scan d'IP non autorisées | Liste blanche stricte + refus du moteur si plage hors policy. |

---

## Partie 2 — SIEM Léger

### 2.1 Contexte & objectif

CVE Tracker dit *« cette CVE existe et touche votre serveur »*. Il ne dit pas *« quelqu'un est en train de l'exploiter en ce moment »*. C'est le rôle d'un SIEM (Security Information and Event Management) : **collecter les logs des hôtes/applications, détecter les comportements suspects, et alerter**. La version « légère » vise une stack accessible (pas Splunk Enterprise) mais opérationnelle pour un parc PME-ETI ou un environnement projet/labo.

### 2.2 Périmètre

**Dans le périmètre :**
- Ingestion de logs (syslog, fichiers, applicatifs JSON, beats).
- Normalisation au format **ECS (Elastic Common Schema)**.
- Stockage / indexation dans Elasticsearch.
- Moteur de règles de détection (déclaratives YAML).
- Corrélation simple multi-événements (échec de connexion en rafale, scan de ports détecté, etc.).
- Alerting (UI + webhook + email).
- Mapping **MITRE ATT&CK** par règle.
- Pont vers CVE Tracker : *si un log mentionne une CVE connue ou cible un service vulnérable, lever une alerte critique.*

**Hors périmètre (v1) :**
- UEBA (machine learning comportemental utilisateur).
- SOAR complet (orchestration de réponse automatisée).
- Forensic timeline avancé (réservé à un futur module).

### 2.3 Acteurs

| Acteur | Besoin |
|---|---|
| Analyste SOC niveau 1 | Triage des alertes, marquage faux positifs. |
| Analyste SOC niveau 2 | Création/ajustement de règles, investigation multi-source. |
| Administrateur | Onboarding de nouvelles sources de logs, retention policy. |
| Système (cron / streaming) | Indexation continue, application des règles en quasi temps réel. |

### 2.4 Exigences fonctionnelles

| ID | Exigence |
|---|---|
| F-SIEM-01 | Collecte syslog (UDP/TCP 514) et lecture de fichiers de logs (rotation comprise). |
| F-SIEM-02 | Support des principaux beats (Filebeat, Winlogbeat) pour systèmes Windows et Linux. |
| F-SIEM-03 | Normalisation systématique en ECS (mêmes noms de champs quelle que soit la source). |
| F-SIEM-04 | Moteur de règles déclaratif (format Sigma de préférence — standard ouvert). |
| F-SIEM-05 | Règles préchargées : brute-force SSH, élévation sudo suspecte, exécution PowerShell encodée, scan de ports détecté, accès admin Windows hors horaires. |
| F-SIEM-06 | Corrélation par fenêtre temporelle (ex. 5 échecs de login en 60 s → alerte). |
| F-SIEM-07 | Mapping de chaque règle à une technique MITRE ATT&CK (T1110, T1059.001, etc.). |
| F-SIEM-08 | Dashboard de triage (alertes ouvertes, par sévérité, par hôte, par technique). |
| F-SIEM-09 | Workflow d'alerte : ouvert → en cours → résolu → faux positif, avec commentaires. |
| F-SIEM-10 | Webhook sortant et email sur alerte critique. |
| F-SIEM-11 | Recherche libre type Kibana (KQL ou Lucene) sur les logs bruts. |
| F-SIEM-12 | **Corrélation CVE** : enrichissement automatique des événements avec les CVE pertinentes pour l'hôte (consultation de CVE Tracker en temps réel). |

### 2.5 Exigences non-fonctionnelles

| Catégorie | Exigence |
|---|---|
| Performance | Ingestion soutenue à 2 000 EPS (événements par seconde) sur un nœud unique. |
| Latence | Délai règle → alerte < 30 s en charge normale. |
| Sécurité | TLS sur tous les transports, RBAC analyste/admin, audit log des accès. |
| Rétention | 30 jours à chaud configurable, archivage froid optionnel S3. |
| Disponibilité | Mode dégradé sans corrélation CVE si CVE Tracker indisponible. |
| Observabilité | Métriques EPS, queue lag, alertes par seconde, taux de faux positifs. |

### 2.6 Architecture proposée

```
┌─────────────┐  syslog/beats ┌──────────────┐   ┌──────────────┐
│  Sources    │──────────────►│  Collector   │──►│ Normalizer   │
│ (hosts/app) │               │ (Vector/Logstash)│ (ECS)        │
└─────────────┘               └──────────────┘   └──────┬───────┘
                                                        │
                                                        ▼
                                              ┌──────────────────┐
                                              │  Elasticsearch   │
                                              │  (déjà en stack) │
                                              └────┬─────────┬───┘
                                                   │         │
                              ┌────────────────────┘         └────────┐
                              ▼                                       ▼
                      ┌──────────────┐                       ┌────────────────┐
                      │ Rule Engine  │  ── enrich CVE ────►  │  CVE Tracker   │
                      │ (Sigma + cron│  ◄── lookup hôte ──  │  /api/v2/cves  │
                      │  ou stream)  │                       └────────────────┘
                      └──────┬───────┘
                             │ alerte
                             ▼
                      ┌──────────────┐
                      │  Frontend    │
                      │  + webhook   │
                      └──────────────┘
```

### 2.7 Stack technique recommandée

- **Collecte/transport** : Vector (rapide, faible footprint) ou Logstash.
- **Stockage** : Elasticsearch (**déjà présent dans la stack CVE Tracker** — gros gain de réutilisation).
- **Moteur de règles** : pySigma + scheduler (Python).
- **Frontend** : Kibana pour la recherche libre + une UI Next.js dédiée pour le triage des alertes (cohérence visuelle avec CVE Tracker).
- **Stockage des alertes** : PostgreSQL (réutiliser l'instance de CVE Tracker).

### 2.8 Modèle de données (côté alertes)

| Table | Champs clés |
|---|---|
| `rule` | id, sigma_yaml, name, severity, mitre_techniques[], enabled, created_by |
| `alert` | id, rule_id, severity, status, host, user, raw_event_ref, mitre, created_at |
| `alert_comment` | id, alert_id, author, body, created_at |
| `correlation_window` | id, rule_id, key, count, first_event, last_event |
| `audit_log` | id, actor, action, target, timestamp |

### 2.9 Intégration avec CVE Tracker

**Sens 1 — Enrichissement des alertes** :
À chaque alerte concernant un hôte H, le SIEM appelle `GET /api/assets?search=H` puis `GET /api/vulnerabilities?assetId=...` sur CVE Tracker. Si l'hôte a des CVE critiques ouvertes → la sévérité de l'alerte est rehaussée et un encart « contexte vulnérabilité » apparaît dans le triage.

**Sens 2 — Détection ciblée** :
CVE Tracker publie un événement (webhook) « nouvelle CVE critique pour service X ». Le SIEM active automatiquement une règle Sigma spécifique pour ce service pendant N jours (chasse proactive).

**Sens 3 — Boucle de remédiation** :
Une alerte SIEM est résolue → crée optionnellement une `Vulnerability` dans CVE Tracker liée à l'asset pour traçabilité (« exploitation tentée le ... sur cette faille »).

### 2.10 Phases & livrables

| Phase | Durée | Livrables |
|---|---|---|
| **P1 — Pipeline** | 2 sem. | Collecte syslog + Filebeat, normalisation ECS, indexation. |
| **P2 — Moteur de règles** | 2 sem. | Exécuteur Sigma, 10 règles de base, mapping MITRE. |
| **P3 — Corrélation** | 1 sem. | Fenêtres glissantes, alertes multi-événements. |
| **P4 — UI triage** | 2 sem. | Dashboard, workflow alerte, webhook, email. |
| **P5 — Intégration CVE Tracker** | 1 sem. | Enrichissement bidirectionnel, webhook publication CVE. |
| **P6 — Durcissement** | 1 sem. | RBAC, TLS, rétention, observabilité, tests. |

### 2.11 Critères d'acceptation

- Ingestion soutenue à 2 000 EPS sur 1 nœud sans perte d'événements.
- Détection effective d'un brute-force SSH simulé en < 30 s.
- 10 règles préchargées fonctionnelles, chacune avec son mapping MITRE.
- Triage d'une alerte (ouvrir → commenter → résoudre) en < 4 clics.
- Enrichissement CVE visible sur ≥ 90 % des alertes concernant un hôte connu.

### 2.12 Risques & mitigations

| Risque | Mitigation |
|---|---|
| Tempête d'alertes (faux positifs) | Seuils de corrélation, tuning continu, marquage faux positif → feedback au moteur. |
| Volumétrie de logs explosive | Rétention configurable, sampling intelligent, alertes EPS. |
| CVE Tracker indisponible | Mode dégradé : alerter sans enrichissement, retry asynchrone. |
| Couverture MITRE incomplète | Démarrer sur 10 techniques prioritaires (top OWASP + ransomware), étendre par sprint. |

---

## Partie 3 — Vision d'ensemble

### 3.1 Bénéfice combiné

| Sans la chaîne | Avec la chaîne complète |
|---|---|
| Inventaire manuel, partiel, vite obsolète | Inventaire vivant, mis à jour en continu. |
| Liste de CVE déconnectée du SI réel | Chaque CVE rattachée à un actif concret et son service. |
| Logs en silos, détections génériques | Détections priorisées par exposition réelle (CVE × asset critique × technique MITRE). |
| Réponse réactive : « il y a eu une intrusion » | Réponse proactive : « cet hôte expose la CVE X, on surveille les tentatives ». |

### 3.2 Calendrier global indicatif

| Mois | Network Scanner Pro | SIEM Léger | CVE Tracker (existant) |
|---|---|---|---|
| M1 | P1–P2 | P1 | Endpoint CPE matching à ajouter |
| M2 | P3–P4 | P2–P3 | Webhook publication CVE à ajouter |
| M3 | P5 + recette | P4–P5 | Section « Discovery » à ajouter |
| M4 | — | P6 + recette | Intégration finale + dashboard unifié |

### 3.3 Réutilisation de la stack CVE Tracker

| Composant existant | Réutilisé pour | Gain |
|---|---|---|
| PostgreSQL | Données Scanner + alertes SIEM | Une seule DB à exploiter |
| Redis | Queue Celery + cache | Pas de nouveau service |
| Elasticsearch | Index ECS du SIEM | Pas de cluster supplémentaire |
| Nginx gateway | Reverse-proxy unifié | Une seule URL d'accès SOC |
| Système d'auth admin | Compte unique pour les 3 outils | Onboarding utilisateur simplifié |

### 3.4 Coût humain estimé

- Network Scanner Pro : ≈ **8 semaines homme** (1 développeur).
- SIEM Léger : ≈ **9 semaines homme** (1 développeur).
- Adaptations CVE Tracker (endpoints + webhooks + section Discovery) : ≈ **2 semaines homme**.
- **Total : ≈ 19 semaines homme** pour la chaîne complète, idéalement 4 mois calendaires avec 2 développeurs en parallèle.

---

## Annexe — Glossaire

| Terme | Définition |
|---|---|
| **CPE** | *Common Platform Enumeration* — identifiant standardisé d'un produit logiciel/matériel (ex. `cpe:2.3:a:apache:http_server:2.4.49`). Clé qui permet de relier un service détecté à sa liste de CVE. |
| **ECS** | *Elastic Common Schema* — convention de nommage des champs de logs proposée par Elastic, devenue standard de fait. |
| **EPS** | *Events Per Second* — métrique principale d'un SIEM. |
| **MITRE ATT&CK** | Référentiel mondial des tactiques et techniques d'attaque, structuré en *kill chain* étendue. |
| **Sigma** | Format ouvert de règles de détection portable entre SIEM. |
| **SOAR** | *Security Orchestration, Automation, and Response* — automatisation de la réponse, hors-périmètre v1. |
| **Stealth scan** | Scan réseau réalisé pour minimiser les chances de détection par un IDS. |
| **UEBA** | *User and Entity Behaviour Analytics* — détection par modélisation du comportement normal, hors-périmètre v1. |
