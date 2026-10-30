"""Local capture receiver (stdlib http.server) and replay client (urllib)."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core import CapturedRequest, verify_signature


class Receiver:
    """Capture webhooks to a list (and optionally stream them to an .ndjson file).

    When a secret is provided, every request's signature header is verified and
    the verdict is recorded alongside the payload."""

    def __init__(self, port: int = 8080, secret: str | None = None,
                 signature_header: str = "X-Signature",
                 timestamp_header: str | None = None,
                 require_timestamp: bool = False,
                 fixture_path: str | None = None):
        self.port = port
        self.secret = secret
        self.signature_header = signature_header.lower()
        self.timestamp_header = (timestamp_header or "").lower()
        self.require_timestamp = require_timestamp
        self.fixture_path = fixture_path
        self.captured: list[CapturedRequest] = []
        self._server = None
        self._thread = None

    def _handler(self):
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(length).decode("utf-8", "replace")
                valid = None
                if receiver.secret:
                    verdict = verify_signature(
                        body.encode("utf-8"),
                        self.headers.get(receiver.signature_header, ""),
                        receiver.secret,
                        timestamp_header_value=(
                            self.headers.get(receiver.timestamp_header)
                            if receiver.timestamp_header else None),
                        require_timestamp=receiver.require_timestamp,
                    )
                    valid = verdict["valid"]
                receiver.captured.append(CapturedRequest(
                    timestamp=time.time(), method="POST", path=self.path,
                    headers={k: v for k, v in self.headers.items()},
                    body=body, signature_valid=valid))
                status = 200 if valid is not False else 400
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"received": True, "signature_valid": valid}).encode())

            def log_message(self, *args):  # silence default stderr logging
                pass

        return Handler

    def start(self) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), self._handler())
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self.fixture_path and self.captured:
            from .core import save_fixtures
            save_fixtures(self.fixture_path, self.captured)

    def __enter__(self) -> "Receiver":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def replay(fixtures_path: str, target_url: str, secret: str | None = None,
           signature_header: str = "X-Signature",
           timestamp_header: str | None = None,
           fresh_signatures: bool = True) -> list[dict]:
    """Re-send captured webhooks to a target, re-signing with a fresh timestamp
    so replay-protection does not eat your own test traffic."""
    from .core import compute_signature, load_fixtures

    results = []
    for i, captured in enumerate(load_fixtures(fixtures_path), 1):
        payload = captured.body.encode("utf-8")
        headers = {"Content-Type": captured.headers.get("content-type", "application/json")}
        if secret:
            ts = str(int(time.time())) if fresh_signatures else captured.headers.get(timestamp_header or "", "")
            use_ts = ts if (timestamp_header and ts) else None
            headers[signature_header] = compute_signature(payload, secret, use_ts)
            if timestamp_header and use_ts:
                headers[timestamp_header] = use_ts
        elif captured.headers.get(signature_header):
            headers[signature_header] = captured.headers[signature_header]
        request = urllib.request.Request(target_url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                status, body = response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status, body = exc.code, exc.read().decode("utf-8", "replace")
        results.append({"run": i, "path": captured.path, "status": status,
                        "response": body[:200]})
    return results
