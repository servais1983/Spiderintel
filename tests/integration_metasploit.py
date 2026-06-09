#!/usr/bin/env python3

import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from spiderintel import MetasploitScanner


class LocalTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"SpiderIntel Metasploit integration target"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def run():
    if shutil.which("msfconsole") is None:
        raise RuntimeError("msfconsole est absent du PATH")

    server = ThreadingHTTPServer(("127.0.0.1", 80), LocalTargetHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        scanner = MetasploitScanner("127.0.0.1", "quick")
        scanner.timeout = 180
        results = scanner.scan_with_metasploit()
        if scanner.last_error:
            raise AssertionError(f"Metasploit a échoué: {scanner.last_error}")
        if results:
            raise AssertionError(
                "Le service HTTP local sain a produit de fausses vulnérabilités Metasploit"
            )
        print("Kali Metasploit integration smoke test passed")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    run()
