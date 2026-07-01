"""SpiderIntel extension modules.

Ce paquet contient les fonctionnalités « avancées » de SpiderIntel qui étaient
auparavant seulement déclarées dans ``config.yaml`` et sont désormais réellement
implémentées :

- :mod:`spiderintel_ext.cache` : cache disque avec expiration (TTL).
- :mod:`spiderintel_ext.enrichment` : enrichissement OSINT via APIs externes
  (Shodan, VirusTotal, Censys, Have I Been Pwned).
- :mod:`spiderintel_ext.notifications` : notifications e-mail / webhook / Slack.
- :mod:`spiderintel_ext.integrations` : création de tickets Jira / GitLab et
  envoi d'événements Splunk.
- :mod:`spiderintel_ext.wordlists` : brute force de répertoires et de
  sous-domaines à partir de wordlists.
- :mod:`spiderintel_ext.plugins` : chargement dynamique de plugins.
- :mod:`spiderintel_ext.exports` : export CSV et PDF des résultats.

Toutes ces fonctionnalités sont désactivées par défaut et ne s'activent que si
elles sont explicitement configurées (et, le cas échéant, si des identifiants
sont fournis via des variables d'environnement). Chaque module dégrade
proprement — il renvoie un statut plutôt que de lever une exception — lorsque le
réseau, un outil système ou un identifiant est absent.
"""

from spiderintel_ext.cache import CacheManager
from spiderintel_ext.enrichment import (
    CensysClient,
    HaveIBeenPwnedClient,
    OSINTEnrichment,
    ShodanClient,
    VirusTotalClient,
)
from spiderintel_ext.exports import ReportExporter
from spiderintel_ext.integrations import IntegrationManager
from spiderintel_ext.notifications import NotificationManager
from spiderintel_ext.plugins import PluginManager, SpiderIntelPlugin
from spiderintel_ext.wordlists import DirectoryBruteforcer, SubdomainBruteforcer

__all__ = [
    "CacheManager",
    "CensysClient",
    "DirectoryBruteforcer",
    "HaveIBeenPwnedClient",
    "IntegrationManager",
    "NotificationManager",
    "OSINTEnrichment",
    "PluginManager",
    "ReportExporter",
    "ShodanClient",
    "SpiderIntelPlugin",
    "SubdomainBruteforcer",
    "VirusTotalClient",
]
