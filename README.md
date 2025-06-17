# SpiderIntel v2.0.0

![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

## Description

SpiderIntel est un outil d'analyse de sécurité professionnel exclusivement conçu pour Kali Linux. Il combine des capacités avancées d'OSINT et d'analyse de vulnérabilités pour fournir une évaluation complète de la sécurité des systèmes.

## ⚠️ Avertissement Légal

Cet outil est conçu pour être utilisé UNIQUEMENT sur des systèmes pour lesquels vous avez une autorisation écrite explicite. L'utilisation non autorisée de cet outil est illégale et peut entraîner des poursuites judiciaires.

## Prérequis

- Kali Linux 2023.1 ou supérieur
- Python 3.8 ou supérieur
- Outils Kali Linux requis :
  - nmap
  - whatweb
  - theharvester
  - dnsrecon
  - dirb
  - nikto
  - sqlmap
  - metasploit-framework

## Installation

1. Clonez le dépôt :
```bash
git clone https://github.com/votre-repo/SpiderIntel.git
cd SpiderIntel
```

2. Installez SpiderIntel :
```bash
chmod +x install.sh
./install.sh
```

## Utilisation

### Commandes de base

```bash
# Vérifier les dépendances
./spiderintel.sh check-deps

# Lancer une analyse
./spiderintel.sh example.com

# Vérifier le statut
./spiderintel.sh status

# Mettre à jour
./spiderintel.sh update
```

### Options d'analyse

```bash
# Mode furtif
./spiderintel.sh example.com --stealth

# Analyse OSINT uniquement
./spiderintel.sh example.com --osint-only

# Format de sortie spécifique
./spiderintel.sh example.com --format json

# Dossier de sortie personnalisé
./spiderintel.sh example.com --output /chemin/vers/rapports
```

## Fonctionnalités

### Analyse OSINT
- Collecte d'informations sur les domaines
- Analyse des sous-domaines
- Recherche d'emails et de noms d'utilisateurs
- Analyse des technologies utilisées

### Analyse de Vulnérabilités
- Scan de ports et services
- Détection de vulnérabilités web
- Test d'injection SQL
- Analyse de configuration

### Rapports
- Génération de rapports détaillés
- Formats multiples (Markdown, JSON, HTML)
- Visualisation des résultats
- Export des données

## Structure des Répertoires

```
SpiderIntel/
├── reports/          # Rapports générés
├── logs/            # Fichiers de logs
├── temp/            # Fichiers temporaires
├── spiderintel.py   # Script principal
├── spiderintel.sh   # Script de lancement
├── install.sh       # Script d'installation
├── config.yaml      # Configuration
└── requirements.txt # Dépendances Python
```

## Configuration

Le fichier `config.yaml` permet de personnaliser le comportement de SpiderIntel :

```yaml
# Configuration générale
general:
  version: "2.0.0"
  platform: "kali"
  debug: false
  stealth_mode: true

# Configuration des scans
scans:
  nmap:
    enabled: true
    options: "-sV -sC"
    timeout: 300
```

## Sécurité

- Vérification stricte de l'environnement Kali Linux
- Validation des entrées utilisateur
- Nettoyage sécurisé des fichiers temporaires
- Gestion des permissions

## Contribution

Les contributions sont les bienvenues ! Veuillez suivre ces étapes :

1. Fork le projet
2. Créez une branche pour votre fonctionnalité
3. Committez vos changements
4. Poussez vers la branche
5. Ouvrez une Pull Request

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## Support

Pour toute question ou problème :
- Ouvrez une issue sur GitHub
- Consultez la documentation
- Contactez l'équipe de support

## Remerciements

- Équipe Kali Linux
- Communauté open source
- Tous les contributeurs
