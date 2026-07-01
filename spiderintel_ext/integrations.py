"""Intégrations de suivi : Jira, GitLab et Splunk.

À partir d'une liste de découvertes (vulnérabilités), ce module peut :

- créer un ticket Jira récapitulatif ;
- ouvrir une issue GitLab récapitulative ;
- envoyer les découvertes en tant qu'événements vers un collecteur Splunk HEC.

Les jetons et mots de passe sont lus depuis des variables d'environnement en
priorité. Chaque intégration renvoie un statut structuré et ne lève jamais.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 20


def _env(*names: str) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _summarize(domain: str, findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return f"SpiderIntel n'a détecté aucune vulnérabilité pour {domain}."
    lines = [f"SpiderIntel a détecté {len(findings)} découverte(s) pour {domain} :", ""]
    for finding in findings[:50]:
        name = finding.get("name", "Inconnu")
        severity = finding.get("severity", "N/A")
        lines.append(f"- [{severity}] {name}")
    if len(findings) > 50:
        lines.append(f"- ... et {len(findings) - 50} autres")
    return "\n".join(lines)


class IntegrationManager:
    """Pousse les découvertes vers les systèmes de suivi configurés."""

    def __init__(self, config, timeout: int = DEFAULT_TIMEOUT):
        self.config = config
        self.timeout = timeout

    def _enabled(self, system: str) -> bool:
        return bool(self.config.get(f"integrations.{system}.enabled", False))

    @property
    def any_enabled(self) -> bool:
        return any(self._enabled(system) for system in ("jira", "gitlab", "splunk"))

    def dispatch(self, domain: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Envoie les découvertes vers toutes les intégrations activées."""
        statuses: Dict[str, Any] = {}
        summary = _summarize(domain, findings)
        if self._enabled("jira"):
            statuses["jira"] = self.create_jira_issue(domain, summary)
        if self._enabled("gitlab"):
            statuses["gitlab"] = self.create_gitlab_issue(domain, summary)
        if self._enabled("splunk"):
            statuses["splunk"] = self.send_to_splunk(domain, findings)
        return statuses

    def create_jira_issue(self, domain: str, description: str) -> Dict[str, Any]:
        server = self.config.get("integrations.jira.server_url")
        username = self.config.get("integrations.jira.username")
        token = _env("SPIDERINTEL_JIRA_API_TOKEN") or self.config.get("integrations.jira.api_token")
        project_key = self.config.get("integrations.jira.project_key")

        if not server or not project_key or not token:
            return {"status": "skipped", "error": "configuration Jira incomplète"}

        url = f"{server.rstrip('/')}/rest/api/2/issue"
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"SpiderIntel - Découvertes pour {domain}",
                "description": description,
                "issuetype": {"name": "Task"},
            }
        }
        try:
            response = requests.post(
                url,
                json=payload,
                auth=(username, token) if username else None,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {"status": "failed", "error": str(exc)}
        if response.status_code >= 400:
            return {"status": "failed", "error": f"HTTP {response.status_code}"}
        try:
            key = response.json().get("key")
        except ValueError:
            key = None
        return {"status": "created", "issue": key}

    def create_gitlab_issue(self, domain: str, description: str) -> Dict[str, Any]:
        server = self.config.get("integrations.gitlab.server_url")
        token = _env("SPIDERINTEL_GITLAB_TOKEN") or self.config.get("integrations.gitlab.private_token")
        project_id = self.config.get("integrations.gitlab.project_id")

        if not server or not project_id or not token:
            return {"status": "skipped", "error": "configuration GitLab incomplète"}

        url = f"{server.rstrip('/')}/api/v4/projects/{project_id}/issues"
        params = {
            "title": f"SpiderIntel - Découvertes pour {domain}",
            "description": description,
        }
        try:
            response = requests.post(
                url,
                params=params,
                headers={"PRIVATE-TOKEN": token},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {"status": "failed", "error": str(exc)}
        if response.status_code >= 400:
            return {"status": "failed", "error": f"HTTP {response.status_code}"}
        try:
            iid = response.json().get("iid")
        except ValueError:
            iid = None
        return {"status": "created", "issue": iid}

    def send_to_splunk(self, domain: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        server = self.config.get("integrations.splunk.server_url")
        token = _env("SPIDERINTEL_SPLUNK_TOKEN") or self.config.get("integrations.splunk.auth_token")
        index = self.config.get("integrations.splunk.index", "security")

        if not server or not token:
            return {"status": "skipped", "error": "configuration Splunk incomplète"}

        url = f"{server.rstrip('/')}/services/collector/event"
        events = "".join(
            _splunk_event_line(domain, index, finding) for finding in findings
        ) or _splunk_event_line(domain, index, {"name": "no_findings", "severity": "Info"})
        try:
            response = requests.post(
                url,
                data=events,
                headers={"Authorization": f"Splunk {token}"},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {"status": "failed", "error": str(exc)}
        if response.status_code >= 400:
            return {"status": "failed", "error": f"HTTP {response.status_code}"}
        return {"status": "sent", "events": len(findings)}


def _splunk_event_line(domain: str, index: str, finding: Dict[str, Any]) -> str:
    import json

    return json.dumps(
        {
            "index": index,
            "sourcetype": "spiderintel:finding",
            "event": {
                "domain": domain,
                "name": finding.get("name"),
                "severity": finding.get("severity"),
                "description": finding.get("description"),
            },
        }
    )
