#!/bin/bash

# Script de déploiement pour CVE Tracker
# Ce script automatise le processus de déploiement Docker

set -e

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Vérifier si Docker est installé
check_docker() {
    log_info "Vérification de Docker..."
    if ! command -v docker &> /dev/null; then
        log_error "Docker n'est pas installé. Veuillez l'installer d'abord."
        exit 1
    fi
    log_info "Docker est installé : $(docker --version)"
}

# Vérifier si Docker Compose est installé
check_docker_compose() {
    log_info "Vérification de Docker Compose..."
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose n'est pas installé. Veuillez l'installer d'abord."
        exit 1
    fi
    log_info "Docker Compose est installé"
}

# Créer le fichier .env s'il n'existe pas
setup_env() {
    if [ ! -f .env ]; then
        log_warn "Fichier .env non trouvé. Création à partir de .env.example..."
        cp .env.example .env
        log_info "Fichier .env créé. Veuillez le modifier selon vos besoins."
    else
        log_info "Fichier .env trouvé"
    fi
}

# Build de l'image Docker
build_image() {
    log_info "Construction de l'image Docker..."
    docker build -t cve-tracker:latest .
    log_info "Image Docker construite avec succès"
}

# Démarrer les conteneurs
start_containers() {
    log_info "Démarrage des conteneurs..."
    docker-compose up -d
    log_info "Conteneurs démarrés"
}

# Attendre que l'application soit prête
wait_for_app() {
    log_info "Attente de démarrage de l'application..."
    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -sf http://localhost:3000 > /dev/null 2>&1; then
            log_info "Application prête !"
            return 0
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done

    log_error "L'application n'a pas démarré dans le délai imparti"
    log_error "Veuillez vérifier les logs avec : docker-compose logs app"
    exit 1
}

# Seed des données de test
seed_database() {
    if [ "$SKIP_SEED" = "true" ]; then
        log_info "Seed de la base de données ignoré (SKIP_SEED=true)"
        return
    fi

    log_info "Seed de la base de données avec les données de test..."
    response=$(curl -s -X POST http://localhost:3000/api/seed)

    if echo "$response" | grep -q "assetsCreated"; then
        log_info "Base de données peuplée avec succès"
        echo "$response" | jq -r '.message, .assetsCreated, .vulnerabilitiesCreated' 2>/dev/null || echo "$response"
    else
        log_warn "Le seed a peut-être échoué ou les données existent déjà"
        log_warn "Exécutez manuellement : curl -X POST http://localhost:3000/api/seed"
    fi
}

# Afficher les informations de déploiement
show_info() {
    echo ""
    log_info "=========================================="
    log_info "Déploiement terminé avec succès !"
    log_info "=========================================="
    echo ""
    log_info "Application accessible à : http://localhost:3000"
    echo ""
    log_info "Commandes utiles :"
    echo "  - Voir les logs : docker-compose logs -f app"
    echo "  - Arrêter : docker-compose down"
    echo "  - Redémarrer : docker-compose restart"
    echo "  - Shell : docker-compose exec app sh"
    echo ""
    log_info "Documentation : make help"
    echo ""
}

# Fonction principale
main() {
    log_info "=========================================="
    log_info "CVE Tracker - Script de déploiement"
    log_info "=========================================="
    echo ""

    check_docker
    check_docker_compose
    setup_env
    build_image
    start_containers
    wait_for_app
    seed_database
    show_info
}

# Exécuter les fonctions
main "$@"
