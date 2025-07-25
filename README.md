![image](spiderintel.png)


# 🕷️ SpiderIntel v2.0.0

<div align="center">

![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0.0-orange.svg?style=for-the-badge)

[![Security](https://img.shields.io/badge/Security-OSINT-red.svg?style=for-the-badge)](https://github.com/servais1983/Spiderintel)
[![Documentation](https://img.shields.io/badge/Documentation-Wiki-blue.svg?style=for-the-badge)](https://github.com/servais1983/Spiderintel/wiki)
[![Issues](https://img.shields.io/badge/Issues-Tracker-yellow.svg?style=for-the-badge)](https://github.com/servais1983/Spiderintel/issues)

</div>

## 📋 Description

SpiderIntel est un outil d'analyse de sécurité professionnel conçu pour Kali Linux. Il combine des capacités avancées d'OSINT et d'analyse de vulnérabilités pour fournir une évaluation complète de la sécurité des systèmes.

### 🌟 Caractéristiques principales

- 🔍 Analyse OSINT complète
- 🛡️ Détection de vulnérabilités avancée
- 📊 Rapports détaillés en temps réel
- 🎯 Interface utilisateur intuitive
- 🔐 Mode furtif intégré

## ⚠️ Avertissement Légal

> **IMPORTANT** : Cet outil est conçu pour être utilisé UNIQUEMENT sur des systèmes pour lesquels vous avez une autorisation écrite explicite. L'utilisation non autorisée de cet outil est illégale et peut entraîner des poursuites judiciaires.

## 🚀 Installation Rapide

### 1. Préparation de l'environnement

```bash
# Mettre à jour le système
sudo apt update && sudo apt upgrade -y

# Installer les dépendances système
sudo apt install -y python3-pip python3-venv git

# Cloner le dépôt
git clone https://github.com/servais1983/Spiderintel.git
cd Spiderintel
```

### 2. Création de l'environnement virtuel

```bash
# Créer l'environnement virtuel
python3 -m venv venv

# Activer l'environnement virtuel
# Sur Linux/Mac :
source venv/bin/activate

```

### 3. Installation des dépendances

```bash
# Mettre à jour pip
pip install --upgrade pip

# Installer les dépendances Python
pip install -r requirements.txt

# Installer les outils Kali Linux requis
sudo apt install -y nmap whatweb theharvester dnsrecon dirb nikto sqlmap metasploit-framework

# Configuration de Metasploit
sudo msfdb init
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Vérifier l'installation de Metasploit
msfconsole --version
```

### 4. Configuration de Metasploit

Metasploit est un composant essentiel pour le scan de vulnérabilités. Assurez-vous qu'il est correctement configuré :

1. **Vérification de l'installation** :
   ```bash
   msfconsole --version
   ```

2. **Si Metasploit n'est pas installé** :
   ```bash
   sudo apt update
   sudo apt install metasploit-framework
   ```

3. **Initialisation de la base de données** :
   ```bash
   sudo msfdb init
   ```

4. **Démarrage des services** :
   ```bash
   sudo systemctl start postgresql
   sudo systemctl enable postgresql
   ```

5. **Vérification du statut** :
   ```bash
   sudo systemctl status postgresql
   ```

### 5. Configuration

```bash
# Rendre les scripts exécutables
chmod +x install.sh spiderintel.sh

# Lancer l'installation
./install.sh
```

### 6. Vérification de l'installation

```bash
# Vérifier que tout est bien installé
./spiderintel.sh check-deps

# Tester l'installation
./spiderintel.sh --version
```

### Désinstallation

Si vous souhaitez désinstaller SpiderIntel :

```bash
# Désactiver l'environnement virtuel
deactivate

# Supprimer le répertoire du projet
cd ..
rm -rf Spiderintel
```

### Mise à jour

Pour mettre à jour SpiderIntel :

```bash
# Activer l'environnement virtuel
source venv/bin/activate  # Linux/Mac
# ou
.\venv\Scripts\activate   # Windows

# Mettre à jour le code
git pull origin main

# Mettre à jour les dépendances
pip install -r requirements.txt --upgrade

# Relancer l'installation
./install.sh
```

## 💻 Prérequis

- 🐧 Kali Linux 2023.1+
- 🐍 Python 3.8+
- 🛠️ Outils Kali Linux :
  - nmap
  - whatweb
  - theharvester
  - dnsrecon
  - dirb
  - nikto
  - sqlmap
  - metasploit-framework

## 🎮 Utilisation

### Scan Complet et Génération des Rapports

Pour effectuer une analyse complète et générer automatiquement tous les rapports :

```bash
python3 spiderintel.py example.com
```

Cette commande va :
- 🔍 Effectuer une analyse OSINT complète
- 🛡️ Scanner les vulnérabilités
- 📊 Générer les rapports dans différents formats :
  - Markdown (rapport détaillé)
  - JSON (pour l'intégration)
  - Résumé exécutif (synthèse des résultats)

Les rapports seront générés dans le dossier `reports/` par défaut.

### Commandes de base

```bash
# Vérifier les dépendances
python3 spiderintel.py --check-deps

# Lancer une analyse
python3 spiderintel.py example.com

# Vérifier le statut
python3 spiderintel.py --status

# Mettre à jour
python3 spiderintel.py --update
```

### Options avancées

```bash
# Mode furtif
python3 spiderintel.py example.com --stealth

# Analyse OSINT uniquement
python3 spiderintel.py example.com --osint-only

# Format de sortie spécifique
python3 spiderintel.py example.com --format json

# Dossier de sortie personnalisé
python3 spiderintel.py example.com --output /chemin/vers/rapports
```

### Exemples d'utilisation

```bash
# Analyse complète d'un domaine
python3 spiderintel.py example.com

# Analyse avec mode furtif et sortie JSON
python3 spiderintel.py example.com --stealth --format json

# Analyse OSINT avec dossier de sortie personnalisé
python3 spiderintel.py example.com --osint-only --output /tmp/reports

# Vérification des dépendances
python3 spiderintel.py --check-deps
```

## 📊 Fonctionnalités

### 🔍 Analyse OSINT
- Collecte d'informations sur les domaines
- Analyse des sous-domaines
- Recherche d'emails et de noms d'utilisateurs
- Analyse des technologies utilisées
- Détection des réseaux sociaux associés

### 🛡️ Analyse de Vulnérabilités
- Scan de ports et services
- Détection de vulnérabilités web
- Test d'injection SQL
- Analyse de configuration SSL/TLS
- Détection des versions de services

### 📝 Rapports
- Génération de rapports détaillés
- Formats multiples (Markdown, JSON)
- Visualisation interactive des résultats
- Export des données
- Résumé exécutif automatique

## 📁 Structure du Projet

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

## ⚙️ Configuration

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

## 🔒 Sécurité

- Vérification stricte de l'environnement Kali Linux
- Validation des entrées utilisateur
- Nettoyage sécurisé des fichiers temporaires
- Gestion des permissions
- Chiffrement des données sensibles

## 🤝 Contribution

Les contributions sont les bienvenues ! Voici comment contribuer :

1. Fork le projet
2. Créez une branche pour votre fonctionnalité
3. Committez vos changements
4. Poussez vers la branche
5. Ouvrez une Pull Request

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 💬 Support

Pour toute question ou problème :
- 📝 Ouvrez une issue sur GitHub
- 📚 Consultez la documentation
- 📧 Contactez l'équipe de support

## 🙏 Remerciements

- Équipe Kali Linux
- Communauté open source
- Tous les contributeurs

## Niveaux de Scan

SpiderIntel propose trois niveaux de scan pour adapter l'analyse à vos besoins :

### 1. Scan Rapide (Quick) - Par défaut
```bash
python3 spiderintel.py example.com
```
- Scan des ports essentiels (80, 443, 22, 21, 25)
- Vérification des vulnérabilités de base
- Analyse OSINT standard
- Durée estimée : 5-10 minutes

### 2. Scan Normal
```bash
python3 spiderintel.py example.com --scan-depth normal
```
- Scan de ports étendu
- Vérification approfondie des vulnérabilités
- Analyse OSINT complète
- Durée estimée : 15-30 minutes

### 3. Scan Approfondi (Deep)
```bash
python3 spiderintel.py example.com --scan-depth deep
```
- Scan exhaustif de tous les ports
- Analyse complète des vulnérabilités avec Metasploit
- Analyse OSINT approfondie
- Durée estimée : 30-60 minutes

## Optimisation de Metasploit

Le scan Metasploit a été optimisé pour être plus efficace :
- Timeout global de 5 minutes pour éviter les scans trop longs
- Timeout de 30 secondes par module
- Parallélisation des scans avec `THREADS`
- Limitation intelligente des ports scannés selon le niveau

## Rapports Générés

Tous les rapports sont générés dans le dossier `reports/` (ou le dossier spécifié avec l'option `--output`). Pour chaque analyse, vous trouverez :

### Structure des Rapports
```
reports/
├── example.com/
│   ├── rapport_complet.md        # Rapport détaillé en Markdown
│   ├── rapport_executif.md       # Résumé exécutif
│   ├── rapport_technique.json    # Données techniques au format JSON
│   └── rapport_metasploit.txt    # Résultats du scan Metasploit
```

### Formats Disponibles
- **Markdown** (`rapport_complet.md`) : Rapport complet et détaillé
- **JSON** (`rapport_technique.json`) : Données brutes pour analyse technique
- **Résumé Exécutif** (`rapport_executif.md`) : Vue d'ensemble pour les décideurs
- **Rapport Metasploit** (`rapport_metasploit.txt`) : Résultats détaillés des scans Metasploit

### Personnalisation de l'Emplacement
Pour changer l'emplacement des rapports, utilisez l'option `--output` :
```bash
python3 spiderintel.py example.com --output /chemin/vers/dossier
```

---

<div align="center">
  <sub>Built with ❤️ by the SpiderIntel Team</sub>
</div>
