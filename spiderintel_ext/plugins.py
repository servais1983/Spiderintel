"""Système de plugins dynamique.

Un plugin est un fichier Python placé dans le répertoire des plugins (par défaut
``plugins/``) qui expose soit une fonction ``register()`` renvoyant une instance
de :class:`SpiderIntelPlugin`, soit une sous-classe de ``SpiderIntelPlugin``
directement importable.

Après une analyse, SpiderIntel appelle le hook ``on_scan_complete(context)`` de
chaque plugin activé. Le ``context`` contient le domaine, les découvertes et les
chemins de rapports. Un plugin qui échoue est isolé : son erreur est capturée et
n'interrompt pas l'analyse.
"""

from __future__ import annotations

import importlib.util
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SpiderIntelPlugin:
    """Classe de base pour les plugins SpiderIntel."""

    #: Nom lisible du plugin (utilisé pour l'activation/désactivation).
    name: str = "plugin"

    def on_scan_complete(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Appelé à la fin d'une analyse. Peut renvoyer des données arbitraires."""
        return None


class PluginManager:
    """Découvre, charge et exécute les plugins."""

    def __init__(
        self,
        plugin_dir: str = "plugins",
        enabled: Optional[List[str]] = None,
        disabled: Optional[List[str]] = None,
    ):
        self.plugin_dir = Path(plugin_dir).expanduser()
        self.enabled = set(enabled or [])
        self.disabled = set(disabled or [])
        self.plugins: List[SpiderIntelPlugin] = []

    def _is_active(self, name: str) -> bool:
        if name in self.disabled:
            return False
        if self.enabled and name not in self.enabled:
            return False
        return True

    def discover(self) -> List[SpiderIntelPlugin]:
        """Charge les plugins depuis le répertoire configuré."""
        self.plugins = []
        if not self.plugin_dir.is_dir():
            return self.plugins

        for path in sorted(self.plugin_dir.glob("*.py")):
            if path.name.startswith("_"):
                continue
            instance = self._load_module(path)
            if instance is None:
                continue
            if not self._is_active(getattr(instance, "name", path.stem)):
                continue
            self.plugins.append(instance)
        return self.plugins

    def _load_module(self, path: Path) -> Optional[SpiderIntelPlugin]:
        try:
            spec = importlib.util.spec_from_file_location(f"spiderintel_plugin_{path.stem}", path)
            if spec is None or spec.loader is None:
                return None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:  # pragma: no cover - dépend du plugin
            logger.warning("Chargement du plugin %s échoué: %s", path.name, exc)
            return None

        register = getattr(module, "register", None)
        if callable(register):
            try:
                instance = register()
            except Exception as exc:  # pragma: no cover - dépend du plugin
                logger.warning("register() du plugin %s a échoué: %s", path.name, exc)
                return None
            if isinstance(instance, SpiderIntelPlugin):
                return instance

        for value in vars(module).values():
            if (
                isinstance(value, type)
                and issubclass(value, SpiderIntelPlugin)
                and value is not SpiderIntelPlugin
            ):
                try:
                    return value()
                except Exception as exc:  # pragma: no cover - dépend du plugin
                    logger.warning("Instanciation du plugin %s échouée: %s", path.name, exc)
                    return None
        return None

    def run_scan_complete(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Exécute le hook ``on_scan_complete`` de chaque plugin chargé."""
        outputs: Dict[str, Any] = {}
        for plugin in self.plugins:
            plugin_name = getattr(plugin, "name", plugin.__class__.__name__)
            try:
                outputs[plugin_name] = {
                    "status": "completed",
                    "result": plugin.on_scan_complete(context),
                }
            except Exception as exc:  # pragma: no cover - dépend du plugin
                logger.warning("Plugin %s a échoué: %s", plugin_name, exc)
                outputs[plugin_name] = {"status": "failed", "error": str(exc)}
        return outputs
