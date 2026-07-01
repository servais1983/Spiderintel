"""Brute force de répertoires (HTTP) et de sous-domaines (DNS) via wordlists.

Ces scanners consomment les wordlists déclarées dans ``config.yaml``. Ils sont
volontairement bornés (nombre d'entrées, threads, délai) pour rester utilisables
dans le cadre d'un test autorisé. Les wordlists absentes sont ignorées
proprement.
"""

from __future__ import annotations

import concurrent.futures
import logging
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 8


def load_wordlist(paths: List[str], max_entries: int = 2000) -> List[str]:
    """Charge et fusionne des wordlists, sans doublons, bornée à ``max_entries``."""
    words: List[str] = []
    seen = set()
    for raw_path in paths or []:
        path = Path(raw_path).expanduser()
        if not path.exists():
            logger.debug("Wordlist introuvable: %s", path)
            continue
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    word = line.strip()
                    if not word or word.startswith("#") or word in seen:
                        continue
                    seen.add(word)
                    words.append(word)
                    if len(words) >= max_entries:
                        return words
        except OSError as exc:
            logger.debug("Lecture wordlist %s impossible: %s", path, exc)
    return words


class DirectoryBruteforcer:
    """Découvre des chemins existants sur un hôte web à partir d'une wordlist."""

    def __init__(
        self,
        base_url: str,
        wordlist_paths: Optional[List[str]] = None,
        threads: int = 10,
        timeout: int = DEFAULT_TIMEOUT,
        exclude_status: Optional[List[int]] = None,
        verify_tls: bool = True,
        max_entries: int = 2000,
        session: Optional[requests.Session] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.words = load_wordlist(wordlist_paths or [], max_entries=max_entries)
        self.threads = max(1, int(threads))
        self.timeout = timeout
        self.exclude_status = set(exclude_status or [404, 400])
        self.verify_tls = verify_tls
        self.session = session or requests.Session()

    def _check(self, word: str) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}/{word.lstrip('/')}"
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_tls,
            )
        except requests.RequestException:
            return None
        if response.status_code in self.exclude_status:
            return None
        return {
            "url": url,
            "status_code": response.status_code,
            "content_length": len(response.content or b""),
        }

    def run(self) -> List[Dict[str, Any]]:
        if not self.words:
            return []
        found: List[Dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            for result in executor.map(self._check, self.words):
                if result is not None:
                    found.append(result)
        found.sort(key=lambda item: item["url"])
        return found


class SubdomainBruteforcer:
    """Résout des sous-domaines candidats issus d'une wordlist."""

    def __init__(
        self,
        domain: str,
        wordlist_paths: Optional[List[str]] = None,
        threads: int = 20,
        max_entries: int = 2000,
    ):
        self.domain = domain
        self.words = load_wordlist(wordlist_paths or [], max_entries=max_entries)
        self.threads = max(1, int(threads))

    def _resolve(self, prefix: str) -> Optional[Dict[str, Any]]:
        candidate = f"{prefix}.{self.domain}"
        try:
            infos = socket.getaddrinfo(candidate, None)
        except (socket.gaierror, UnicodeError):
            return None
        addresses = sorted({info[4][0] for info in infos})
        if not addresses:
            return None
        return {"subdomain": candidate, "addresses": addresses}

    def run(self) -> List[Dict[str, Any]]:
        if not self.words:
            return []
        found: List[Dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            for result in executor.map(self._resolve, self.words):
                if result is not None:
                    found.append(result)
        found.sort(key=lambda item: item["subdomain"])
        return found
