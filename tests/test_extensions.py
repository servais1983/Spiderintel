#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests des modules d'extension SpiderIntel (cache, APIs, notifications,
intégrations, wordlists, plugins, exports)."""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spiderintel import RuntimeConfig  # noqa: E402
from spiderintel_ext.cache import CacheManager, parse_size  # noqa: E402
from spiderintel_ext.enrichment import (  # noqa: E402
    OSINTEnrichment,
    ShodanClient,
    VirusTotalClient,
)
from spiderintel_ext.exports import ReportExporter  # noqa: E402
from spiderintel_ext.integrations import IntegrationManager  # noqa: E402
from spiderintel_ext.notifications import NotificationManager  # noqa: E402
from spiderintel_ext.plugins import PluginManager, SpiderIntelPlugin  # noqa: E402
from spiderintel_ext.wordlists import (  # noqa: E402
    DirectoryBruteforcer,
    SubdomainBruteforcer,
    load_wordlist,
)


class TestCacheManager(unittest.TestCase):
    def test_set_get_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = CacheManager(cache_dir=tmp, ttl=100)
            cache.set("k", {"a": 1})
            self.assertEqual(cache.get("k"), {"a": 1})

    def test_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = CacheManager(cache_dir=tmp, ttl=1)
            cache.set("k", "v")
            # Forcer l'expiration en réécrivant une entrée déjà expirée.
            path = cache._path_for("k")
            payload = json.loads(path.read_text())
            payload["expires"] = time.time() - 10
            path.write_text(json.dumps(payload))
            self.assertIsNone(cache.get("k"))

    def test_disabled_cache_returns_none(self):
        cache = CacheManager(enabled=False)
        cache.set("k", "v")
        self.assertIsNone(cache.get("k"))

    def test_parse_size(self):
        self.assertEqual(parse_size("1KB"), 1024)
        self.assertEqual(parse_size("2MB"), 2 * 1024 ** 2)
        self.assertEqual(parse_size(4096), 4096)


class TestEnrichment(unittest.TestCase):
    def test_client_unavailable_without_key(self):
        client = ShodanClient(api_key=None)
        # S'assurer qu'aucune variable d'environnement ne fausse le test.
        client.api_key = None
        self.assertFalse(client.available)
        self.assertIn("error", client.host("8.8.8.8"))

    def test_virustotal_parses_stats(self):
        client = VirusTotalClient(api_key="dummy")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {"attributes": {"reputation": -5, "last_analysis_stats": {"malicious": 3}}}
        }
        with patch.object(client.session, "request", return_value=mock_response):
            result = client.domain("example.com")
        self.assertEqual(result["malicious"], 3)
        self.assertEqual(result["reputation"], -5)

    def test_orchestrator_skips_disabled(self):
        config = RuntimeConfig({"apis": {"shodan": {"enabled": False}}})
        enricher = OSINTEnrichment(config)
        self.assertFalse(enricher.any_enabled)
        self.assertEqual(enricher.enrich("example.com"), {})


class TestNotifications(unittest.TestCase):
    def test_slack_disabled_by_default(self):
        config = RuntimeConfig({})
        notifier = NotificationManager(config)
        self.assertFalse(notifier.any_enabled)

    def test_slack_send_posts_payload(self):
        config = RuntimeConfig({
            "notifications": {"slack": {"enabled": True, "webhook_url": "https://hooks.example/x"}}
        })
        notifier = NotificationManager(config)
        mock_response = MagicMock(status_code=200)
        with patch("spiderintel_ext.notifications.requests.post", return_value=mock_response) as post:
            result = notifier.send_slack("hello")
        self.assertEqual(result["status"], "sent")
        post.assert_called_once()

    def test_webhook_missing_url_skips(self):
        config = RuntimeConfig({"notifications": {"webhook": {"enabled": True}}})
        notifier = NotificationManager(config)
        self.assertEqual(notifier.send_webhook("s", "m", {})["status"], "skipped")


class TestIntegrations(unittest.TestCase):
    def test_gitlab_creates_issue(self):
        config = RuntimeConfig({
            "integrations": {
                "gitlab": {
                    "enabled": True,
                    "server_url": "https://gitlab.example",
                    "project_id": "42",
                    "private_token": "tok",
                }
            }
        })
        manager = IntegrationManager(config)
        mock_response = MagicMock(status_code=201)
        mock_response.json.return_value = {"iid": 7}
        with patch("spiderintel_ext.integrations.requests.post", return_value=mock_response):
            result = manager.create_gitlab_issue("example.com", "desc")
        self.assertEqual(result, {"status": "created", "issue": 7})

    def test_jira_incomplete_config_skips(self):
        config = RuntimeConfig({"integrations": {"jira": {"enabled": True}}})
        manager = IntegrationManager(config)
        self.assertEqual(manager.create_jira_issue("example.com", "d")["status"], "skipped")


class TestWordlists(unittest.TestCase):
    def test_load_wordlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            wl = Path(tmp) / "w.txt"
            wl.write_text("admin\n# comment\nlogin\nadmin\n", encoding="utf-8")
            words = load_wordlist([str(wl)])
            self.assertEqual(words, ["admin", "login"])

    def test_directory_bruteforce_filters_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            wl = Path(tmp) / "w.txt"
            wl.write_text("found\nmissing\n", encoding="utf-8")
            brute = DirectoryBruteforcer("https://example.com", [str(wl)], threads=2)

            def fake_get(url, **kwargs):
                resp = MagicMock()
                resp.status_code = 200 if url.endswith("found") else 404
                resp.content = b"x"
                return resp

            brute.session.get = MagicMock(side_effect=fake_get)
            results = brute.run()
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0]["url"].endswith("found"))

    def test_subdomain_bruteforce_resolves(self):
        with tempfile.TemporaryDirectory() as tmp:
            wl = Path(tmp) / "w.txt"
            wl.write_text("www\nnope\n", encoding="utf-8")
            brute = SubdomainBruteforcer("example.com", [str(wl)], threads=2)

            def fake_getaddrinfo(host, *args, **kwargs):
                if host.startswith("www."):
                    return [(2, 1, 6, "", ("93.184.216.34", 0))]
                raise __import__("socket").gaierror("nope")

            with patch("spiderintel_ext.wordlists.socket.getaddrinfo", side_effect=fake_getaddrinfo):
                results = brute.run()
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["subdomain"], "www.example.com")


class TestPlugins(unittest.TestCase):
    def test_discover_and_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_file = Path(tmp) / "demo.py"
            plugin_file.write_text(
                "from spiderintel_ext.plugins import SpiderIntelPlugin\n"
                "class Demo(SpiderIntelPlugin):\n"
                "    name = 'demo'\n"
                "    def on_scan_complete(self, context):\n"
                "        return {'domain': context['domain']}\n",
                encoding="utf-8",
            )
            manager = PluginManager(plugin_dir=tmp)
            loaded = manager.discover()
            self.assertEqual(len(loaded), 1)
            outputs = manager.run_scan_complete({"domain": "example.com"})
            self.assertEqual(outputs["demo"]["result"], {"domain": "example.com"})

    def test_disabled_plugin_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_file = Path(tmp) / "demo.py"
            plugin_file.write_text(
                "from spiderintel_ext.plugins import SpiderIntelPlugin\n"
                "class Demo(SpiderIntelPlugin):\n"
                "    name = 'demo'\n",
                encoding="utf-8",
            )
            manager = PluginManager(plugin_dir=tmp, disabled=["demo"])
            self.assertEqual(manager.discover(), [])

    def test_base_plugin_default_hook(self):
        self.assertIsNone(SpiderIntelPlugin().on_scan_complete({}))


class TestExports(unittest.TestCase):
    def test_csv_export(self):
        from spiderintel import VulnerabilityResult

        vulns = [
            VulnerabilityResult(name="X", severity="High", description="d", cvss_score=8.0, cve_id="CVE-1"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.csv"
            ReportExporter().export_csv(vulns, dest)
            content = dest.read_text(encoding="utf-8")
            self.assertIn("name,severity", content)
            self.assertIn("CVE-1", content)

    def test_pdf_export_skips_without_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            html = Path(tmp) / "r.html"
            html.write_text("<html></html>", encoding="utf-8")
            with patch("spiderintel_ext.exports.shutil.which", return_value=None):
                result = ReportExporter().export_pdf(html, Path(tmp) / "r.pdf")
            self.assertEqual(result["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
