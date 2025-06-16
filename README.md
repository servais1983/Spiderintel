# SpiderIntel 🕷️

SpiderIntel est un outil de collecte d'informations OSINT (Open Source Intelligence) automatisé qui permet d'effectuer une analyse approfondie d'un domaine cible.

## 🚀 Fonctionnalités

- Collecte d'informations WHOIS
- Analyse DNS avec dnsenum
- Recherche d'informations avec TheHarvester
- Analyse des technologies web avec WhatWeb
- Crawling web avec Photon
- Recherche de certificats SSL sur crt.sh
- Intégration avec Shodan (nécessite un abonnement)
- Génération de rapports au format Markdown et HTML

## 📋 Prérequis

- Python 3.x
- Outils système :
  - whois
  - dnsenum
  - theHarvester
  - whatweb
  - photon
  - pandoc (optionnel, pour la génération de rapports HTML)

## 🛠️ Installation

1. Clonez le dépôt :
```bash
git clone https://github.com/servais1983/SpiderIntel.git
cd SpiderIntel
```

2. Installez les dépendances Python :
```bash
pip install -r requirements.txt
```

3. Installez les outils système (sur Linux) :
```bash
sudo apt update && sudo apt install -y whois dnsenum theharvester whatweb photon pandoc
```

## 💻 Utilisation

```bash
python3 spiderintel.py <domain>
```

Exemple :
```bash
python3 spiderintel.py example.com
```

## 📊 Exemple de sortie

Le script génère un dossier `osint_<domain>_<date>` contenant :
- whois.txt : Informations WHOIS
- dnsenum.txt : Résultats de l'énumération DNS
- harvester.txt : Résultats de TheHarvester
- whatweb.txt : Informations sur les technologies web
- photon/ : Résultats du crawling web
- crtsh.json : Certificats SSL trouvés
- shodan.json : Informations Shodan (si disponible)
- report.md : Rapport complet au format Markdown
- report.html : Rapport complet au format HTML (si pandoc est installé)

## ⚠️ Note importante

L'utilisation de Shodan nécessite un abonnement payant. Pour utiliser cette fonctionnalité :
1. Créez un compte sur https://account.shodan.io/
2. Souscrivez à un abonnement payant
3. Configurez votre clé API dans le fichier spiderintel.py

## 📝 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 👥 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
1. Fork le projet
2. Créer une branche pour votre fonctionnalité
3. Commiter vos changements
4. Pousser vers la branche
5. Ouvrir une Pull Request 