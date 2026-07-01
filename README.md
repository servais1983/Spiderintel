# SpiderIntel

SpiderIntel est un outil en ligne de commande destiné aux missions autorisées de reconnaissance OSINT et d’évaluation de vulnérabilités. Il orchestre plusieurs outils disponibles sous Kali Linux, consolide leurs résultats et génère des rapports Markdown et JSON.

Le projet doit uniquement être utilisé sur des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez d’une autorisation écrite explicite.

## Statut du projet

Version actuelle : `2.1.1`

Statut : bêta opérationnelle. Le cœur du projet est testable et installable, mais une validation dans votre environnement Kali, avec vos procédures de sécurité et vos contraintes réseau, reste nécessaire avant un usage professionnel régulier.

## Fonctionnalités

- Découverte de sous-domaines via `crt.sh`, résolution DNS et TheHarvester
- Identification de technologies avec WhatWeb
- Détection de ports et vulnérabilités avec Nmap
- Contrôle des en-têtes HTTP de sécurité
- Recherche limitée de fichiers sensibles exposés
- Vérification de la validité des certificats TLS
- Modules auxiliaires Metasploit selon la profondeur choisie
- Génération de rapports Markdown, JSON et d’un résumé exécutif
- Validation stricte des cibles
- Vérification TLS activée par défaut
- Confirmation explicite d’autorisation avant tout scan
- Tests automatisés et intégration continue sur Python 3.10 à 3.12

## Architecture

Le projet est organisé autour de :

- `spiderintel.py` : CLI, orchestration des scans, validation, collecte et rapports
- `report_generator.py` : générateur de rapports historique conservé pour compatibilité
- `spiderintel_ext/` : paquet des fonctionnalités avancées (cache, enrichissement via APIs externes, notifications, intégrations de suivi, wordlists, plugins, exports CSV/PDF)

Les résultats sont enregistrés par cible dans `reports/<cible>/`.

## Prérequis

- Kali Linux récent
- Python 3.10, 3.11 ou 3.12
- Git
- Accès réseau vers les services OSINT utilisés
- Autorisation écrite couvrant la cible et les techniques exécutées

Outils système utilisés :

- `nmap`
- `whatweb`
- `theHarvester`
- `dig`
- `metasploit-framework`

Certains scénarios ou extensions peuvent également nécessiter `dnsrecon`, `nikto`, `dirb`, `sqlmap`, `gobuster`, `wpscan`, `hydra`, `sslscan` ou `testssl.sh`.

## Installation

```bash
git clone https://github.com/servais1983/Spiderintel.git
cd Spiderintel

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Pour installer les dépendances de développement :

```bash
python -m pip install -e ".[dev]"
```

Installation assistée sous Kali Linux :

```bash
chmod +x install.sh spiderintel.sh
./install.sh
```

## Vérification

```bash
spiderintel --check-deps
python -m pytest
python -m ruff check spiderintel.py report_generator.py tests
```

## Utilisation

La confirmation `--authorized` est obligatoire pour lancer une analyse.

```bash
spiderintel example.com --authorized
```

Choisir le répertoire de sortie :

```bash
spiderintel example.com --authorized --output ./reports
```

Utiliser une configuration spécifique :

```bash
spiderintel example.com --authorized --config ./config.yaml
```

Choisir la profondeur :

```bash
spiderintel example.com --authorized --scan-depth quick
spiderintel example.com --authorized --scan-depth normal
spiderintel example.com --authorized --scan-depth deep
```

Activer les journaux détaillés :

```bash
spiderintel example.com --authorized --verbose
```

Afficher l’aide :

```bash
spiderintel --help
```

Afficher la version :

```bash
spiderintel --version
```

## Profondeurs de scan

| Niveau | Usage recommandé | Effet |
|---|---|---|
| `quick` | Validation initiale | Ports courants et contrôles auxiliaires limités |
| `normal` | Audit standard autorisé | Ajoute TheHarvester, réseaux sociaux, TLS et modules Metasploit supplémentaires |
| `deep` | Environnement de test maîtrisé | Ajoute les fichiers sensibles et davantage de modules Metasploit |

Le niveau `deep` peut être intrusif et générer une charge importante. Il ne doit pas être utilisé sans fenêtre de tir, supervision et procédure d’arrêt.

## Rapports et journaux

Une exécution crée un dossier tel que :

```text
reports/
└── example.com/
    ├── spiderintel_analysis_YYYY-MM-DD_HH-MM-SS.md
    ├── spiderintel_analysis_YYYY-MM-DD_HH-MM-SS.json
    └── spiderintel_summary_YYYY-MM-DD_HH-MM-SS.md
```

Les journaux applicatifs sont écrits dans `logs/spiderintel.log`.

Chaque rapport contient l’état global de l’analyse et le statut des sous-scans : `completed`, `skipped` ou `failed`. Une analyse partiellement exécutée est signalée avec l’état `partial`.

Les rapports peuvent contenir des domaines, adresses IP, adresses électroniques, versions logicielles et détails de vulnérabilités. Ils doivent être stockés avec des permissions restrictives et selon la politique de conservation de votre organisation.

## Sécurité opérationnelle

Avant chaque utilisation :

1. Définir précisément le périmètre autorisé.
2. Valider les plages horaires, limites de débit et procédures d’escalade.
3. Vérifier les dépendances et leurs versions.
4. Utiliser un compte avec le minimum de privilèges nécessaire.
5. Surveiller la cible pendant les scans actifs.
6. Examiner manuellement chaque résultat avant de conclure à une vulnérabilité.

SpiderIntel ne remplace pas une méthodologie d’audit, une validation humaine ni un scanner certifié. Les résultats peuvent contenir des faux positifs ou être incomplets.

## Configuration

`config.yaml` pilote les délais HTTP, les tentatives, la vérification TLS, les limites de parallélisme et de cibles, l’activation des scans OSINT, Nmap, web et Metasploit ainsi que les formats de rapport. Le fichier du répertoire courant est chargé automatiquement lorsqu’il existe; `--config` permet d’en choisir un autre.

`config.ini` et `logging.conf` sont conservés pour compatibilité historique et ne pilotent pas encore le flux principal.

Les secrets et clés API ne doivent jamais être commités. Utilisez des variables d’environnement ou un gestionnaire de secrets.

## Développement

```bash
python -m pip install -e ".[dev]"
python -m pytest --cov=spiderintel --cov-report=term-missing
python -m ruff check spiderintel.py report_generator.py tests
```

La CI GitHub exécute les contrôles sur Python 3.10, 3.11 et 3.12.

Un smoke test Kali reproductible installe et exécute réellement Nmap, WhatWeb, TheHarvester et `dig` contre une cible HTTP locale :

```bash
docker build --target kali-integration -f docker/kali-integration.Dockerfile -t spiderintel-kali .
docker run --rm --cap-add=NET_RAW --add-host=example.test:127.0.0.1 spiderintel-kali
```

Ce test ne contacte aucune cible de scan externe. Les accès réseau pendant la construction servent uniquement à installer les paquets Kali et Python.

Une cible séparée valide Metasploit contre un service HTTP local :

```bash
docker build --target kali-metasploit -f docker/kali-integration.Dockerfile -t spiderintel-kali-metasploit .
docker run --rm --cap-add=NET_RAW spiderintel-kali-metasploit
```

La validation Metasploit est disponible comme workflow GitHub manuel en raison de la taille du paquet et de son temps d’installation.

## Fonctionnalités avancées

Les options « avancées » de `config.yaml` sont désormais réellement implémentées
dans le paquet `spiderintel_ext`. Elles sont toutes **désactivées par défaut** et
ne s’activent que si elles sont explicitement activées dans la configuration et,
le cas échéant, si des identifiants sont fournis. Aucun secret n’est jamais lu
depuis le dépôt : les clés sont attendues via des variables d’environnement.

| Fonctionnalité | Activation (`config.yaml`) | Identifiants (variables d’environnement) |
|---|---|---|
| Enrichissement Shodan | `apis.shodan.enabled: true` | `SPIDERINTEL_SHODAN_API_KEY` |
| Enrichissement VirusTotal | `apis.virustotal.enabled: true` | `SPIDERINTEL_VIRUSTOTAL_API_KEY` |
| Enrichissement Censys | `apis.censys.enabled: true` | `SPIDERINTEL_CENSYS_API_ID`, `SPIDERINTEL_CENSYS_API_SECRET` |
| Comptes compromis (HIBP) | `apis.have_i_been_pwned.enabled: true` | `SPIDERINTEL_HIBP_API_KEY` |
| Notification e-mail | `notifications.email.enabled: true` | `SPIDERINTEL_SMTP_PASSWORD` |
| Notification webhook | `notifications.webhook.enabled: true` | `SPIDERINTEL_WEBHOOK_URL` |
| Notification Slack | `notifications.slack.enabled: true` | `SPIDERINTEL_SLACK_WEBHOOK_URL` |
| Ticket Jira | `integrations.jira.enabled: true` | `SPIDERINTEL_JIRA_API_TOKEN` |
| Issue GitLab | `integrations.gitlab.enabled: true` | `SPIDERINTEL_GITLAB_TOKEN` |
| Événements Splunk | `integrations.splunk.enabled: true` | `SPIDERINTEL_SPLUNK_TOKEN` |

- **Cache disque** (`caching.enabled`) : met en cache les réponses des APIs
  externes avec expiration (TTL) et limite de taille.
- **Wordlists** (`wordlists.subdomains`, `wordlists.directories`) : brute force de
  sous-domaines (DNS) et de répertoires (HTTP), exécuté uniquement en profondeur
  `deep`.
- **Plugins** (`plugins.custom_plugins_dir`) : chargement dynamique de plugins
  Python exposant un hook `on_scan_complete(context)` (voir
  `spiderintel_ext/plugins.py`).
- **Exports** : CSV des découvertes (`reporting.export.csv_data`) et PDF via
  `wkhtmltopdf` (`reporting.export.pdf_report`).

## Limites connues

- Le support principal vise Kali Linux.
- Plusieurs outils externes produisent des sorties textuelles susceptibles de changer.
- Le moteur historique `spiderintel.py` reste volumineux et gagnerait à être séparé en adaptateurs par outil.
- Les options `advanced.experimental` (analyse assistée par IA, détection par apprentissage automatique) restent des marqueurs non implémentés et sans effet.
- Les rapports HTML chargent Bootstrap et Chart.js depuis des CDN externes.
- Les smoke tests Kali couvrent une cible locale contrôlée; ils ne remplacent pas une recette opérationnelle sur l’infrastructure et les politiques réseau de l’organisation.

## Contribution

Les contributions doivent rester limitées à des usages défensifs et autorisés. Consultez `CONTRIBUTING.md` pour les règles et vérifications attendues.

Les vulnérabilités doivent être signalées de manière privée selon `SECURITY.md`.

## Licence

SpiderIntel est distribué sous licence MIT. Consultez le fichier `LICENSE`.

## Responsabilité

Les auteurs et contributeurs ne sont pas responsables d’un usage illégal, non autorisé ou dommageable. L’utilisateur est seul responsable de la légalité de ses actions, du périmètre analysé et des conséquences opérationnelles.
