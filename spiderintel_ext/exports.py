"""Exports de rapports : CSV des découvertes et PDF depuis le rapport HTML.

- L'export CSV est réalisé avec la bibliothèque standard et fonctionne toujours.
- L'export PDF s'appuie sur ``wkhtmltopdf`` s'il est installé ; sinon il renvoie
  un statut ``skipped`` sans échouer.
"""

from __future__ import annotations

import csv
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def _as_dict(vuln: Any) -> Dict[str, Any]:
    if isinstance(vuln, dict):
        return vuln
    return {
        "name": getattr(vuln, "name", ""),
        "severity": getattr(vuln, "severity", ""),
        "description": getattr(vuln, "description", ""),
        "cvss_score": getattr(vuln, "cvss_score", ""),
        "cve_id": getattr(vuln, "cve_id", ""),
        "affected_url": getattr(vuln, "affected_url", ""),
        "mitigation": getattr(vuln, "mitigation", ""),
    }


class ReportExporter:
    """Exporte les découvertes de SpiderIntel vers CSV et PDF."""

    CSV_FIELDS = [
        "name",
        "severity",
        "cvss_score",
        "cve_id",
        "affected_url",
        "description",
        "mitigation",
    ]

    def export_csv(self, vulnerabilities: List[Any], destination: Path) -> Path:
        """Écrit les vulnérabilités dans un fichier CSV et renvoie son chemin."""
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for vuln in vulnerabilities:
                writer.writerow(_as_dict(vuln))
        return destination

    def export_pdf(self, html_path: Path, destination: Path) -> Dict[str, Any]:
        """Convertit un rapport HTML en PDF via ``wkhtmltopdf`` si disponible."""
        html_path = Path(html_path)
        destination = Path(destination)
        if not html_path.exists():
            return {"status": "failed", "error": "rapport HTML source introuvable"}
        binary = shutil.which("wkhtmltopdf")
        if binary is None:
            return {"status": "skipped", "error": "wkhtmltopdf non installé"}
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                [binary, "--quiet", str(html_path), str(destination)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return {"status": "failed", "error": str(exc)}
        if result.returncode != 0 or not destination.exists():
            return {"status": "failed", "error": result.stderr.strip() or "échec wkhtmltopdf"}
        return {"status": "created", "path": str(destination)}
