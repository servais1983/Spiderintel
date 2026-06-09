#!/usr/bin/env python3

import json
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from spiderintel import (
    OSINTScanner,
    RuntimeConfig,
    SpiderIntelMain,
)


class LocalTargetHandler(BaseHTTPRequestHandler):
    server_version = "SpiderIntelIntegration/1.0"

    def do_GET(self):
        body = b"<html><title>SpiderIntel integration target</title></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def require_tools():
    required = ["dig", "nmap", "theHarvester", "whatweb"]
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        raise RuntimeError(f"Outils Kali absents: {', '.join(missing)}")


def run():
    require_tools()
    subprocess.run(
        ["theHarvester", "-h"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    server = ThreadingHTTPServer(("127.0.0.1", 80), LocalTargetHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    config = RuntimeConfig({
        "osint": {
            "passive": {
                "crtsh_enabled": False,
                "dns_enumeration": False,
                "social_media_search": False,
            },
            "active": {
                "whatweb_scan": True,
                "harvester_scan": False,
            },
            "limits": {"max_ips_scan": 1, "max_subdomains_scan": 1},
        },
        "vulnerability_scanning": {
            "nmap": {"enabled": True, "max_scan_time": 120},
            "web": {
                "security_headers": True,
                "sensitive_files": False,
                "ssl_configuration": False,
            },
        },
        "exploitation": {"enabled": False, "auto_generate": False},
        "reporting": {
            "formats": ["markdown", "json"],
            "executive_summary": True,
        },
    })

    try:
        osint_scanner = OSINTScanner("example.test", config, "quick")
        osint_scanner.results.subdomains.add("example.test")
        osint_scanner.scan_whatweb()
        if not osint_scanner.results.technologies:
            raise AssertionError("WhatWeb n'a identifié aucune technologie")

        with tempfile.TemporaryDirectory() as output_dir:
            analysis = SpiderIntelMain(
                "example.test",
                output_dir,
                "quick",
                authorized=True,
                config=config,
            )
            analysis_result = analysis.run_complete_analysis()
            if analysis_result["status"] not in {"completed", "partial"}:
                raise AssertionError(f"État inattendu: {analysis_result['status']}")

            json_path = Path(analysis_result["reports"]["json"])
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            if "scan_metadata" not in payload:
                raise AssertionError("Les métadonnées de scan sont absentes du rapport JSON")
            ports = payload["collected_assets"]["ports"].get("127.0.0.1", [])
            if 80 not in ports:
                raise AssertionError("Le flux complet n'a pas enregistré le port HTTP local")

        print("Kali integration smoke test passed")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    run()
