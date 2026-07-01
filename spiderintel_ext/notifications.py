"""Notifications de fin d'analyse : e-mail (SMTP), webhook générique, Slack.

Chaque canal :

- n'est actif que s'il est activé dans la configuration ;
- lit les secrets (mot de passe SMTP, URL de webhook) depuis des variables
  d'environnement en priorité, puis depuis la configuration ;
- renvoie un statut structuré plutôt que de lever une exception.
"""

from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15


def _env(*names: str) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


class NotificationManager:
    """Envoie un résumé d'analyse sur les canaux configurés."""

    def __init__(self, config, timeout: int = DEFAULT_TIMEOUT):
        self.config = config
        self.timeout = timeout

    def _enabled(self, channel: str) -> bool:
        return bool(self.config.get(f"notifications.{channel}.enabled", False))

    @property
    def any_enabled(self) -> bool:
        return any(self._enabled(channel) for channel in ("email", "webhook", "slack"))

    def notify(self, subject: str, message: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Diffuse ``message`` sur tous les canaux activés."""
        statuses: Dict[str, Any] = {}
        if self._enabled("email"):
            statuses["email"] = self.send_email(subject, message)
        if self._enabled("webhook"):
            statuses["webhook"] = self.send_webhook(subject, message, details or {})
        if self._enabled("slack"):
            statuses["slack"] = self.send_slack(f"*{subject}*\n{message}")
        return statuses

    def send_email(self, subject: str, body: str) -> Dict[str, Any]:
        server = self.config.get("notifications.email.smtp_server")
        port = int(self.config.get("notifications.email.smtp_port", 587) or 587)
        username = self.config.get("notifications.email.username")
        password = _env("SPIDERINTEL_SMTP_PASSWORD") or self.config.get("notifications.email.password")
        recipients: List[str] = list(self.config.get("notifications.email.recipients", []) or [])

        if not server or not recipients:
            return {"status": "skipped", "error": "serveur SMTP ou destinataires manquants"}

        email = EmailMessage()
        email["Subject"] = subject
        email["From"] = username or "spiderintel@localhost"
        email["To"] = ", ".join(recipients)
        email.set_content(body)

        try:
            with smtplib.SMTP(server, port, timeout=self.timeout) as smtp:
                smtp.ehlo()
                if smtp.has_extn("starttls"):
                    smtp.starttls()
                    smtp.ehlo()
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(email)
        except (smtplib.SMTPException, OSError) as exc:
            return {"status": "failed", "error": str(exc)}
        return {"status": "sent", "recipients": len(recipients)}

    def send_webhook(self, subject: str, message: str, details: Dict[str, Any]) -> Dict[str, Any]:
        url = _env("SPIDERINTEL_WEBHOOK_URL") or self.config.get("notifications.webhook.url")
        if not url:
            return {"status": "skipped", "error": "URL de webhook manquante"}
        headers = dict(self.config.get("notifications.webhook.headers", {}) or {})
        payload = {"subject": subject, "message": message, "details": details}
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            return {"status": "failed", "error": str(exc)}
        if response.status_code >= 400:
            return {"status": "failed", "error": f"HTTP {response.status_code}"}
        return {"status": "sent", "http_status": response.status_code}

    def send_slack(self, text: str) -> Dict[str, Any]:
        url = _env("SPIDERINTEL_SLACK_WEBHOOK_URL") or self.config.get("notifications.slack.webhook_url")
        if not url:
            return {"status": "skipped", "error": "webhook Slack manquant"}
        payload = {"text": text}
        channel = self.config.get("notifications.slack.channel")
        if channel:
            payload["channel"] = channel
        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
        except requests.RequestException as exc:
            return {"status": "failed", "error": str(exc)}
        if response.status_code >= 400:
            return {"status": "failed", "error": f"HTTP {response.status_code}"}
        return {"status": "sent", "http_status": response.status_code}
