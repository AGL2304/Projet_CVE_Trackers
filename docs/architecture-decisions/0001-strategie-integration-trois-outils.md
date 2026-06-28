# ADR-0001 — Stratégie d'intégration CVE Tracker / Scanner / SIEM

**Statut** : accepté
**Date** : 2026-05-22
**Auteurs** : équipe SOC platform

## Contexte

CVE Tracker est déjà déployé et opérationnel. Deux projets complémentaires doivent s'y greffer (Network Scanner Pro, SIEM Léger). Trois questions ont besoin d'une réponse stable avant tout code :

1. Où vivent les données partagées (assets, services, CVE, alertes) ?
2. Comment les trois services s'authentifient entre eux ?
3. Quel est le contrat de communication (sync ou async, REST ou queue, push ou pull) ?

## Décision

### D1 — CVE Tracker reste la source de vérité « inventaire + vulnérabilités »

Le schéma Prisma actuel a déjà les modèles nécessaires : `Asset`, `Product` (avec champ `cpe`), `AssetProduct`, `ProductCVE`. Pas de duplication de cet inventaire dans le Scanner ou le SIEM. Le Scanner **pousse** des assets vers CVE Tracker via HTTP. Le SIEM **lit** ces assets via HTTP.

### D2 — Bus d'événements minimal en HTTP webhooks, pas de Kafka

Volumétrie cible : quelques dizaines d'événements par minute aux pires moments (publication d'un lot de CVE, fin de scan). Un bus message complet est disproportionné pour ce volume. CVE Tracker publie via webhooks signés HMAC ; les abonnés s'enregistrent via une API admin. Cette décision sera réévaluée si on dépasse > 1000 événements/seconde de manière soutenue.

### D3 — Auth inter-services par clé d'API partagée + rotation manuelle

OAuth2 entre 3 services internes serait sur-ingénié. On utilise :
- Un en-tête `X-Internal-Auth` portant un secret partagé (déjà supporté par `frontend/src/lib/v2/auth.ts`).
- Une clé par paire de services (Scanner→Tracker, SIEM→Tracker), rotables indépendamment.
- Stockage dans `.env` et secrets Docker, jamais dans le code.

### D4 — Bases de données séparées sur la même instance Postgres

Pas de schéma partagé entre les trois apps (couplage trop fort). Trois bases logiques : `cve_tracker`, `network_scanner`, `siem`. Cela permet de :
- garder les schémas Prisma de CVE Tracker propres ;
- backuper et restaurer indépendamment ;
- migrer un seul service vers une instance dédiée si la volumétrie l'exige.

Les communications inter-bases passent **uniquement par HTTP**, jamais par requêtes SQL cross-database.

### D5 — Elasticsearch partagé avec préfixes d'index

Une seule instance ES dans la stack (`elastic-data` déjà provisionné). Les index sont préfixés :
- `cve-tracker-*` pour les exports CVE indexés (recherche full-text).
- `siem-events-*` et `siem-alerts-*` pour le SIEM.
- `scanner-history-*` pour les diff inter-scans.

### D6 — Format d'événements ECS (Elastic Common Schema)

Le SIEM produira nativement de l'ECS. CVE Tracker émet ses webhooks au format ECS étendu pour permettre une corrélation directe :
- `event.kind` = `state`
- `event.category` = `vulnerability` | `host`
- `event.action` = `cve.created` | `cve.severity.changed` | `asset.created`

### D7 — Pas de duplication d'auth utilisateur

Les trois interfaces web partagent le compte admin de CVE Tracker via un proxy d'auth. Le SIEM et le Scanner ne gèrent pas leurs propres comptes utilisateurs en v1.

## Conséquences

### Positives

- Réutilisation maximale de l'infra existante (Postgres, Redis, Elasticsearch, Nginx).
- Un seul endroit où administrer les assets.
- Tracé d'audit centralisé : tous les événements transitent par les APIs CVE Tracker.
- Déploiement progressif possible : on peut lancer le Scanner avant que le SIEM soit prêt.

### Négatives

- CVE Tracker devient point de défaillance unique (SPOF) pour l'inventaire. Mitigé par `restart: unless-stopped` Docker et un mode dégradé côté SIEM.
- Latence ajoutée pour le SIEM (un appel HTTP supplémentaire par alerte pour enrichir).
- Coordination des migrations Prisma de CVE Tracker doit être anticipée par les deux autres équipes.

### Risques résiduels

- Si un jour le SIEM dépasse 5 000 EPS sustained, le bus webhooks ne suffira plus. Plan B : Redis Streams (déjà déployé).
- Si les schémas dérivent (Scanner crée des champs custom dans Asset que Tracker ne connaît pas), prévoir un test de contrat (Pact ou équivalent) dans la CI commune.

## Alternatives considérées et rejetées

| Alternative | Raison du rejet |
|---|---|
| Kafka comme bus central | Sur-ingéniérie pour la volumétrie cible. |
| Schéma Postgres partagé | Couplage fort, migrations coordonnées casse-gueule. |
| Auth OAuth2 service-à-service (Keycloak) | Trop lourd pour 3 services internes. |
| Chaque outil gère ses propres assets | Désynchronisation garantie, mauvaise UX. |
| gRPC entre les services | Pas de gain mesurable vs REST, plus de friction outillage. |
