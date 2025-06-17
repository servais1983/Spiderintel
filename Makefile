# SpiderIntel v2.0.0 - Makefile pour Kali Linux

# Variables
PYTHON := python3
VENV := venv
PIP := $(VENV)/bin/pip
PYTHON_VENV := $(VENV)/bin/python
VERSION := 2.0.0

# Commandes principales
.PHONY: all install clean test update check-deps status

all: check-kali install

# Vérification de Kali Linux
check-kali:
	@echo "Vérification de l'environnement Kali Linux..."
	@if [ ! -f "/etc/os-release" ]; then \
		echo "ERREUR: Système d'exploitation non supporté"; \
		exit 1; \
	fi
	@if ! grep -q "kali" /etc/os-release; then \
		echo "ERREUR: Cet outil est exclusivement compatible avec Kali Linux"; \
		exit 1; \
	fi

# Installation
install: check-kali
	@echo "Installation de SpiderIntel..."
	@chmod +x install.sh
	@./install.sh

# Nettoyage
clean:
	@echo "Nettoyage des fichiers temporaires..."
	@rm -rf build/ dist/ *.egg-info/ __pycache__/ .pytest_cache/ .coverage htmlcov/
	@find . -type d -name "__pycache__" -exec rm -rf {} +
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name "*.pyo" -delete
	@find . -type f -name "*.pyd" -delete
	@find . -type f -name ".coverage" -delete
	@find . -type d -name "*.egg-info" -exec rm -rf {} +
	@find . -type d -name "*.egg" -exec rm -rf {} +
	@find . -type d -name ".pytest_cache" -exec rm -rf {} +
	@find . -type d -name "htmlcov" -exec rm -rf {} +
	@find . -type d -name "logs" -exec rm -rf {} +
	@find . -type d -name "reports" -exec rm -rf {} +
	@find . -type d -name "temp" -exec rm -rf {} +

# Tests
test: check-kali
	@echo "Exécution des tests..."
	@$(PYTHON_VENV) -m pytest tests/ -v

# Mise à jour
update: check-kali
	@echo "Mise à jour de SpiderIntel..."
	@git pull
	@$(PIP) install --upgrade -r requirements.txt
	@chmod +x install.sh
	@./install.sh

# Vérification des dépendances
check-deps: check-kali
	@echo "Vérification des dépendances Kali..."
	@./spiderintel.sh check-deps

# Statut
status: check-kali
	@echo "Vérification du statut de SpiderIntel..."
	@./spiderintel.sh status

# Aide
help:
	@echo "SpiderIntel v$(VERSION) - Makefile"
	@echo ""
	@echo "Commandes disponibles:"
	@echo "  make install    - Installation de SpiderIntel"
	@echo "  make clean      - Nettoyage des fichiers temporaires"
	@echo "  make test       - Exécution des tests"
	@echo "  make update     - Mise à jour de SpiderIntel"
	@echo "  make check-deps - Vérification des dépendances"
	@echo "  make status     - Vérification du statut"
	@echo "  make help       - Affichage de cette aide" 