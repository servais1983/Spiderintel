"""Enrichissement OSINT via des APIs externes.

Ce module implémente de vrais clients HTTP pour Shodan, VirusTotal, Censys et
Have I Been Pwned. Chaque client :

- lit sa clé d'API depuis une variable d'environnement (recommandé) ou depuis la
  configuration ;
- est considéré comme *disponible* uniquement si une clé est présente ;
- renvoie un dictionnaire de résultats normalisé, ou ``{"error": ...}`` en cas de
  problème réseau/API, sans lever d'exception ;
- utilise optionnellement le cache disque pour éviter des appels répétés.

Aucune clé n'est jamais stockée dans le dépôt : les valeurs de ``config.yaml``
restent vides et servent uniquement de repli local.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15


def _env(*names: str) -> Optional[str]:
    """Renvoie la première variable d'environnement non vide parmi ``names``."""
    for name in names:
        value = os.environ.get(name)
        if value:
            return value.strip()
    return None


class _BaseClient:
    """Fonctionnalités partagées : session, cache, gestion d'erreurs."""

    name = "base"

    def __init__(self, cache=None, timeout: int = DEFAULT_TIMEOUT):
        self.cache = cache
        self.timeout = timeout
        self.session = requests.Session()

    @property
    def available(self) -> bool:  # pragma: no cover - surchargé
        return False

    def _cached(self, key: str) -> Optional[Any]:
        if self.cache is not None:
            return self.cache.get(key)
        return None

    def _store(self, key: str, value: Any) -> None:
        if self.cache is not None:
            self.cache.set(key, value)

    def _request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        kwargs.setdefault("timeout", self.timeout)
        try:
            response = self.session.request(method, url, **kwargs)
        except requests.RequestException as exc:
            return {"error": f"requête {self.name} échouée: {exc}"}
        if response.status_code == 404:
            return {"not_found": True}
        if response.status_code in (401, 403):
            return {"error": f"{self.name}: authentification refusée (HTTP {response.status_code})"}
        if response.status_code == 429:
            return {"error": f"{self.name}: quota dépassé (HTTP 429)"}
        if response.status_code >= 400:
            return {"error": f"{self.name}: HTTP {response.status_code}"}
        try:
            return {"data": response.json()}
        except ValueError:
            return {"data": response.text}


class ShodanClient(_BaseClient):
    """Client Shodan (informations d'hôte et de domaine)."""

    name = "shodan"

    def __init__(self, api_key: Optional[str] = None, cache=None, timeout: int = DEFAULT_TIMEOUT):
        super().__init__(cache=cache, timeout=timeout)
        self.api_key = _env("SPIDERINTEL_SHODAN_API_KEY", "SHODAN_API_KEY") or api_key

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def host(self, ip: str) -> Dict[str, Any]:
        if not self.available:
            return {"error": "clé Shodan absente"}
        cache_key = f"shodan:host:{ip}"
        cached = self._cached(cache_key)
        if cached is not None:
            return cached
        result = self._request(
            "GET",
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": self.api_key},
        )
        if "data" in result and isinstance(result["data"], dict):
            data = result["data"]
            result = {
                "ip": data.get("ip_str", ip),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "organization": data.get("org"),
                "operating_system": data.get("os"),
                "vulns": sorted(data.get("vulns", []) or []),
                "tags": data.get("tags", []),
            }
        self._store(cache_key, result)
        return result

    def domain(self, domain: str) -> Dict[str, Any]:
        if not self.available:
            return {"error": "clé Shodan absente"}
        cache_key = f"shodan:domain:{domain}"
        cached = self._cached(cache_key)
        if cached is not None:
            return cached
        result = self._request(
            "GET",
            f"https://api.shodan.io/dns/domain/{domain}",
            params={"key": self.api_key},
        )
        if "data" in result and isinstance(result["data"], dict):
            data = result["data"]
            result = {
                "subdomains": data.get("subdomains", []),
                "tags": data.get("tags", []),
            }
        self._store(cache_key, result)
        return result


class VirusTotalClient(_BaseClient):
    """Client VirusTotal API v3 (réputation de domaine)."""

    name = "virustotal"

    def __init__(self, api_key: Optional[str] = None, cache=None, timeout: int = DEFAULT_TIMEOUT):
        super().__init__(cache=cache, timeout=timeout)
        self.api_key = _env("SPIDERINTEL_VIRUSTOTAL_API_KEY", "VIRUSTOTAL_API_KEY", "VT_API_KEY") or api_key

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def domain(self, domain: str) -> Dict[str, Any]:
        if not self.available:
            return {"error": "clé VirusTotal absente"}
        cache_key = f"virustotal:domain:{domain}"
        cached = self._cached(cache_key)
        if cached is not None:
            return cached
        result = self._request(
            "GET",
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": self.api_key},
        )
        if "data" in result and isinstance(result["data"], dict):
            attributes = result["data"].get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            result = {
                "reputation": attributes.get("reputation"),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "categories": attributes.get("categories", {}),
            }
        self._store(cache_key, result)
        return result


class CensysClient(_BaseClient):
    """Client Censys Search API v2 (vue d'hôte)."""

    name = "censys"

    def __init__(
        self,
        api_id: Optional[str] = None,
        api_secret: Optional[str] = None,
        cache=None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        super().__init__(cache=cache, timeout=timeout)
        self.api_id = _env("SPIDERINTEL_CENSYS_API_ID", "CENSYS_API_ID") or api_id
        self.api_secret = _env("SPIDERINTEL_CENSYS_API_SECRET", "CENSYS_API_SECRET") or api_secret

    @property
    def available(self) -> bool:
        return bool(self.api_id and self.api_secret)

    def host(self, ip: str) -> Dict[str, Any]:
        if not self.available:
            return {"error": "identifiants Censys absents"}
        cache_key = f"censys:host:{ip}"
        cached = self._cached(cache_key)
        if cached is not None:
            return cached
        result = self._request(
            "GET",
            f"https://search.censys.io/api/v2/hosts/{ip}",
            auth=(self.api_id, self.api_secret),
        )
        if "data" in result and isinstance(result["data"], dict):
            host = result["data"].get("result", {})
            services = host.get("services", [])
            result = {
                "ip": host.get("ip", ip),
                "services": [
                    {
                        "port": svc.get("port"),
                        "service_name": svc.get("service_name"),
                        "transport": svc.get("transport_protocol"),
                    }
                    for svc in services
                ],
                "autonomous_system": (host.get("autonomous_system") or {}).get("name"),
            }
        self._store(cache_key, result)
        return result


class HaveIBeenPwnedClient(_BaseClient):
    """Client Have I Been Pwned v3 (comptes compromis)."""

    name = "hibp"

    def __init__(self, api_key: Optional[str] = None, cache=None, timeout: int = DEFAULT_TIMEOUT):
        super().__init__(cache=cache, timeout=timeout)
        self.api_key = _env("SPIDERINTEL_HIBP_API_KEY", "HIBP_API_KEY") or api_key

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def breaches(self, account: str) -> Dict[str, Any]:
        if not self.available:
            return {"error": "clé HIBP absente"}
        cache_key = f"hibp:{account}"
        cached = self._cached(cache_key)
        if cached is not None:
            return cached
        result = self._request(
            "GET",
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{account}",
            params={"truncateResponse": "true"},
            headers={
                "hibp-api-key": self.api_key,
                "user-agent": "SpiderIntel",
            },
        )
        if result.get("not_found"):
            normalized: Dict[str, Any] = {"account": account, "breaches": []}
        elif "data" in result and isinstance(result["data"], list):
            normalized = {
                "account": account,
                "breaches": [item.get("Name") for item in result["data"] if isinstance(item, dict)],
            }
        else:
            normalized = result
        self._store(cache_key, normalized)
        return normalized


class OSINTEnrichment:
    """Orchestre les clients d'API disponibles pour enrichir une cible.

    ``config`` est un objet exposant ``get(path, default)`` (le ``RuntimeConfig``
    de SpiderIntel). Les APIs ne sont interrogées que lorsqu'elles sont activées
    dans la configuration *et* que leurs identifiants sont présents.
    """

    def __init__(self, config, cache=None):
        self.config = config
        self.cache = cache
        self.shodan = ShodanClient(config.get("apis.shodan.api_key"), cache=cache)
        self.virustotal = VirusTotalClient(config.get("apis.virustotal.api_key"), cache=cache)
        self.censys = CensysClient(
            config.get("apis.censys.api_id"),
            config.get("apis.censys.api_secret"),
            cache=cache,
        )
        self.hibp = HaveIBeenPwnedClient(config.get("apis.have_i_been_pwned.api_key"), cache=cache)

    def _enabled(self, api: str) -> bool:
        return bool(self.config.get(f"apis.{api}.enabled", False))

    @property
    def any_enabled(self) -> bool:
        return any(
            self._enabled(api) and client.available
            for api, client in (
                ("shodan", self.shodan),
                ("virustotal", self.virustotal),
                ("censys", self.censys),
                ("have_i_been_pwned", self.hibp),
            )
        )

    def enrich(
        self,
        domain: str,
        ips: Optional[List[str]] = None,
        emails: Optional[List[str]] = None,
        max_ips: int = 10,
        max_emails: int = 10,
    ) -> Dict[str, Any]:
        """Renvoie les données d'enrichissement pour la cible.

        Le dictionnaire renvoyé contient au plus les clés ``shodan``,
        ``virustotal``, ``censys`` et ``hibp`` lorsque les services
        correspondants sont actifs.
        """
        results: Dict[str, Any] = {}
        ips = list(ips or [])[:max_ips]
        emails = list(emails or [])[:max_emails]

        if self._enabled("virustotal") and self.virustotal.available:
            results.setdefault("virustotal", {})["domain"] = self.virustotal.domain(domain)

        if self._enabled("shodan") and self.shodan.available:
            shodan_section: Dict[str, Any] = {"domain": self.shodan.domain(domain), "hosts": {}}
            for ip in ips:
                shodan_section["hosts"][ip] = self.shodan.host(ip)
            results["shodan"] = shodan_section

        if self._enabled("censys") and self.censys.available:
            censys_hosts = {ip: self.censys.host(ip) for ip in ips}
            results["censys"] = {"hosts": censys_hosts}

        if self._enabled("have_i_been_pwned") and self.hibp.available:
            results["hibp"] = {email: self.hibp.breaches(email) for email in emails}

        return results
