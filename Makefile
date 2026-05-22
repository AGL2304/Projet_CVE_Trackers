.PHONY: help build dev prod up down logs restart clean seed backup restore

.DEFAULT_GOAL := help

help: ## Affiche cette aide
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets disponibles :"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build l'image Docker de production
	docker build -t cve-tracker:latest .

build-dev: ## Build l'image Docker de développement
	docker build -f Dockerfile.dev -t cve-tracker:dev .

dev: build-dev ## Démarre en mode développement
	docker-compose -f docker-compose.dev.yml up --build

dev-d: build-dev ## Démarre en mode développement (detached)
	docker-compose -f docker-compose.dev.yml up -d --build

prod: build ## Démarre en mode production
	docker-compose up --build -d

up: ## Démarre les conteneurs (production)
	docker-compose up -d

down: ## Arrête les conteneurs
	docker-compose down

down-dev: ## Arrête les conteneurs de développement
	docker-compose -f docker-compose.dev.yml down

logs: ## Affiche les logs en temps réel
	docker-compose logs -f

logs-app: ## Affiche les logs de l'application
	docker-compose logs -f app

restart: ## Redémarre les conteneurs
	docker-compose restart

ps: ## Affiche l'état des conteneurs
	docker-compose ps

clean: ## Nettoie les conteneurs et les volumes
	docker-compose down -v
	docker system prune -f

clean-all: clean ## Nettoie tout y compris les images
	docker system prune -a -f

seed: ## Seed la base de données avec les données de test
	curl -X POST http://localhost:3000/api/seed

seed-status: ## Vérifie l'état du seed
	curl http://localhost:3000/api/seed

backup: ## Backup de la base de données
	docker-compose exec app tar czf /tmp/backup.tar.gz backend/db/
	docker-compose cp app:/tmp/backup.tar.gz ./backup-$(shell date +%Y%m%d-%H%M%S).tar.gz
	docker-compose exec app rm /tmp/backup.tar.gz
	@echo "Backup terminé"

restore: ## Restaure la base de données (usage: make restore BACKUP=backup-file.tar.gz)
ifndef BACKUP
	@echo "Erreur: Spécifiez le fichier de backup avec BACKUP=backup-file.tar.gz"
	@exit 1
endif
	docker-compose cp $(BACKUP) app:/tmp/backup.tar.gz
	docker-compose exec app tar xzf /tmp/backup.tar.gz -C /
	docker-compose exec app rm /tmp/backup.tar.gz
	docker-compose restart
	@echo "Restauration terminée"

stats: ## Affiche les statistiques des conteneurs
	docker stats

shell: ## Ouvre un shell dans le conteneur
	docker-compose exec app sh

install: ## Installe les dépendances locales
	bun install

db-push: ## Pousse le schéma Prisma vers la base de données
	bun run db:push

lint: ## Vérifie le code avec ESLint
	bun run lint
