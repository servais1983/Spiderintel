"""Cache disque simple avec expiration (TTL) et limite de taille.

Le cache stocke des valeurs JSON-sérialisables sur le disque. Chaque entrée est
identifiée par une clé arbitraire (par exemple ``"shodan:8.8.8.8"``) hachée en
nom de fichier. Les entrées expirées sont ignorées à la lecture et supprimées
paresseusement. Une limite de taille globale évince les entrées les plus
anciennes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_SIZE_UNITS = {
    "b": 1,
    "kb": 1024,
    "mb": 1024 ** 2,
    "gb": 1024 ** 3,
}


def parse_size(value: Any, default: int = 100 * 1024 ** 2) -> int:
    """Convertit une taille lisible (« 100MB », « 512kb », 2048) en octets."""
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip().lower().replace(" ", "")
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([a-z]*)", text)
    if not match:
        return default
    number, unit = match.groups()
    factor = _SIZE_UNITS.get(unit or "b", 1)
    return int(float(number) * factor)


class CacheManager:
    """Cache clé/valeur persistant sur disque."""

    def __init__(
        self,
        cache_dir: str = "cache",
        ttl: int = 3600,
        enabled: bool = True,
        size_limit: Any = "100MB",
    ):
        self.enabled = bool(enabled)
        self.ttl = int(ttl)
        self.cache_dir = Path(cache_dir).expanduser()
        self.size_limit_bytes = parse_size(size_limit)
        if self.enabled:
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                logger.warning("Cache désactivé (répertoire inaccessible): %s", exc)
                self.enabled = False

    def _path_for(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def get(self, key: str) -> Optional[Any]:
        """Renvoie la valeur mise en cache ou ``None`` si absente/expirée."""
        if not self.enabled:
            return None
        path = self._path_for(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        expires = payload.get("expires", 0)
        if expires and time.time() > expires:
            path.unlink(missing_ok=True)
            return None
        return payload.get("value")

    def set(self, key: str, value: Any) -> None:
        """Enregistre une valeur JSON-sérialisable dans le cache."""
        if not self.enabled:
            return
        path = self._path_for(key)
        payload = {
            "key": key,
            "stored_at": time.time(),
            "expires": time.time() + self.ttl if self.ttl > 0 else 0,
            "value": value,
        }
        try:
            path.write_text(json.dumps(payload), encoding="utf-8")
        except (OSError, TypeError) as exc:
            logger.debug("Impossible d'écrire l'entrée de cache %s: %s", key, exc)
            return
        self._enforce_size_limit()

    def clear(self) -> int:
        """Supprime toutes les entrées et renvoie le nombre supprimé."""
        if not self.enabled:
            return 0
        removed = 0
        for entry in self.cache_dir.glob("*.json"):
            entry.unlink(missing_ok=True)
            removed += 1
        return removed

    def _enforce_size_limit(self) -> None:
        entries = list(self.cache_dir.glob("*.json"))
        total = sum(entry.stat().st_size for entry in entries if entry.exists())
        if total <= self.size_limit_bytes:
            return
        # Éviction FIFO par date de modification (plus ancien d'abord).
        for entry in sorted(entries, key=lambda p: p.stat().st_mtime):
            if total <= self.size_limit_bytes:
                break
            try:
                size = entry.stat().st_size
                entry.unlink(missing_ok=True)
                total -= size
            except OSError:
                continue
