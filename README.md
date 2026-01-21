# CVE Tracker - Docker Deployment

Système de gestion des vulnérabilités et CVEs (Common Vulnerabilities and Exposures) construit avec Next.js 15, TypeScript, Prisma et SQLite.

## 📋 Table des matières

- [Prérequis](#prérequis)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Docker Development](#docker-development)
- [Docker Production](#docker-production)
- [Commandes utiles](#commandes-utiles)
- [Dépannage](#dépannage)

## 🚀 Prérequis

Avant de commencer, assurez-vous d'avoir installé :
- [Docker](https://docs.docker.com/get-docker/) (version 20.10 ou supérieure)
- [Docker Compose](https://docs.docker.com/compose/install/) (version 2.0 ou supérieure)

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│     CVE Tracker Application        │
│     (Next.js 15 + TypeScript)     │
│     Port: 3000                     │
└──────────────┬──────────────────────┘
               │
               ├──────────────┐
               │              │
        ┌──────▼──────┐  ┌───▼─────────┐
        │  Database   │  │   Logs     │
        │  (SQLite)   │  │   Volume   │
        └─────────────┘  └────────────┘
```

## 📦 Installation

### 1. Cloner le projet

```bash
git clone <repository-url>
cd cve-tracker
```

### 2. Configuration de l'environnement

Copiez le fichier d'exemple de configuration :

```bash
cp .env.example .env
```

### 3. Build de l'image Docker

```bash
docker build -t cve-tracker:latest .
```

## 🔧 Configuration

Variables d'environnement disponibles (`.env`) :

```env
# Environment
NODE_ENV=production

# Database (SQLite)
DATABASE_URL=file:./db/dev.db

# Application
PORT=3000
HOSTNAME=0.0.0.0
```

## 🐳 Docker Development

Pour le développement avec hot reload :

### 1. Démarrer en mode développement

```bash
docker-compose -f docker-compose.dev.yml up --build
```

### 2. Accéder à l'application

Ouvrez votre navigateur sur : http://localhost:3000

### 3. Arrêter les conteneurs

```bash
docker-compose -f docker-compose.dev.yml down
```

### 4. Nettoyer les volumes

```bash
docker-compose -f docker-compose.dev.yml down -v
```

## 🏭 Docker Production

### 1. Build et démarrage en production

```bash
# Build et démarrage
docker-compose up --build -d

# Voir les logs
docker-compose logs -f app

# Vérifier l'état
docker-compose ps
```

### 2. Seed des données de test

```bash
curl -X POST http://localhost:3000/api/seed
```

### 3. Vérifier l'application

```bash
# Vérifier que l'application fonctionne
curl http://localhost:3000/api/seed

# Vérifier les logs
docker-compose logs app
```

### 4. Arrêter en production

```bash
docker-compose down

# Avec suppression des volumes (attention : cela supprime la base de données)
docker-compose down -v
```

## 🎯 Commandes utiles

### Gestion des conteneurs

```bash
# Démarrer les conteneurs en arrière-plan
docker-compose up -d

# Voir les logs en temps réel
docker-compose logs -f

# Voir les logs d'un service spécifique
docker-compose logs -f app

# Redémarrer les conteneurs
docker-compose restart

# Arrêter les conteneurs
docker-compose down

# Arrêter et supprimer les conteneurs, réseaux et volumes
docker-compose down -v
```

### Gestion des images

```bash
# Lister les images
docker images

# Supprimer les images non utilisées
docker image prune -a

# Supprimer l'image de l'application
docker rmi cve-tracker:latest
```

### Débogage

```bash
# Entrer dans un conteneur en cours d'exécution
docker-compose exec app sh

# Voir les processus dans le conteneur
docker-compose exec app ps aux

# Voir l'utilisation des ressources
docker stats
```

### Base de données

```bash
# Entrer dans le conteneur pour accéder à la base de données
docker-compose exec app sh

# Vérifier la base de données
ls -la db/

# Backup de la base de données
docker-compose exec app tar czf /tmp/backup.tar.gz db/
docker-compose cp app:/tmp/backup.tar.gz ./backup.tar.gz

# Restaurer la base de données
docker-compose cp ./backup.tar.gz app:/tmp/backup.tar.gz
docker-compose exec app tar xzf /tmp/backup.tar.gz -C /
```

## 🔍 Dépannage

### Problème : Le port 3000 est déjà utilisé

**Solution :** Changez le port mappé dans `docker-compose.yml` :

```yaml
ports:
  - "3001:3000"  # Utilisez un autre port sur l'hôte
```

### Problème : Erreur de build

**Solution :** Nettoyez le cache Docker :

```bash
docker-compose down
docker system prune -a
docker-compose up --build
```

### Problème : La base de données n'est pas persistée

**Solution :** Assurez-vous que les volumes sont correctement définis :

```bash
# Vérifier les volumes
docker volume ls

# Recréer les conteneurs avec les volumes
docker-compose down -v
docker-compose up --build
```

### Problème : L'application ne répond pas

**Solution :** Vérifiez les logs et l'état de santé :

```bash
# Voir les logs
docker-compose logs app

# Vérifier l'état des conteneurs
docker-compose ps

# Vérifier les processus dans le conteneur
docker-compose exec app ps aux
```

### Problème : Erreur de permissions sur les volumes

**Solution :** Ajustez les permissions des volumes :

```bash
docker-compose down
docker volume rm cve-tracker_db-data
docker-compose up --build
```

## 📊 Monitoring

### Vérifier les logs

```bash
# Tous les logs
docker-compose logs

# Logs en temps réel
docker-compose logs -f app

# Dernières 100 lignes
docker-compose logs --tail=100 app
```

### Surveillance des ressources

```bash
# Statistiques en temps réel
docker stats cve-tracker-app
```

### Health check

L'application est configurée avec un health check automatique. Pour vérifier :

```bash
docker inspect --format='{{json .State.Health}}' cve-tracker-app | jq
```

## 🚀 Déploiement

### Pull depuis un registre Docker

```bash
# Pull de l'image
docker pull your-registry/cve-tracker:latest

# Lancer avec docker-compose
docker-compose up -d
```

### Push vers un registre Docker

```bash
# Tag de l'image
docker tag cve-tracker:latest your-registry/cve-tracker:latest

# Push de l'image
docker push your-registry/cve-tracker:latest
```

## 🔒 Sécurité

### Bonnes pratiques

1. **Ne commitez jamais `.env`** dans le contrôle de version
2. **Utilisez des secrets Docker** pour les données sensibles
3. **Limitez les ressources** avec les options Docker
4. **Mettez à jour régulièrement** les images de base

### Variables sensibles

```bash
# Créer un secret Docker
echo "your-secret-value" | docker secret create db_secret -

# Utiliser dans docker-compose (swarm mode)
secrets:
  db_secret:
    external: true
```

## 📚 Ressources additionnelles

- [Documentation Next.js](https://nextjs.org/docs)
- [Documentation Docker](https://docs.docker.com/)
- [Documentation Docker Compose](https://docs.docker.com/compose/)
- [Documentation Prisma](https://www.prisma.io/docs)

## 📝 License

Ce projet est sous license MIT.

## 🤝 Support

Pour toute question ou problème, veuillez ouvrir une issue sur le repository du projet.
