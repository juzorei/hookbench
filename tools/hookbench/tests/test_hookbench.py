import json
import threading
import urllib.request

import pytest

from hookbench.cli import main
from hookbench.core import (
    CapturedRequest, compute_signature, load_fixtures, save_fixtures, verify_signature)
from hookbench.server import Receiver, replay

SECRET = "whsec_test123"
PAYLOAD = json.dumps({"event": "payment.succeeded", "id": 7})


def test_compute_and_verify_roundtrip():
    sig = compute_signature(PAYLOAD.encode(), SECRET)
    assert sig.startswith("sha256=")
    assert verify_signature(PAYLOAD.encode(), sig, SECRET)["valid"]


def test_wrong_secret_fails():
    verdict = verify_signature(PAYLOAD.encode(), compute_signature(PAYLOAD.encode(), "nope"), SECRET)
    assert not verdict["valid"] and "mismatch" in verdict["error"]


def test_tampered_payload_fails():
    sig = compute_signature(PAYLOAD.encode(), SECRET)
    assert not verify_signature(b"{\"event\": \"payment.succeeded\", \"id\": 8}", sig, SECRET)["valid"]


def test_timestamped_scheme_and_replay_detection():
    import time
    ts = str(int(time.time()))
    sig = compute_signature(PAYLOAD.encode(), SECRET, ts)
    ok = verify_signature(PAYLOAD.encode(), sig, SECRET, timestamp_header_value=ts,
                          require_timestamp=True)
    assert ok["valid"] and ok["replayed"] is False
    old = str(int(time.time()) - 9999)
    stale_sig = compute_signature(PAYLOAD.encode(), SECRET, old)
    stale = verify_signature(PAYLOAD.encode(), stale_sig, SECRET, timestamp_header_value=old,
                             require_timestamp=True)
    assert not stale["valid"] and stale["replayed"] and "replay" in stale["error"]


def test_missing_and_malformed_signatures():
    assert verify_signature(PAYLOAD.encode(), "", SECRET)["error"] == "missing signature header"
    assert verify_signature(PAYLOAD.encode(), "garbage", SECRET)["error"].startswith(
        "signature header is not")
    v = verify_signature(PAYLOAD.encode(), "", SECRET, require_timestamp=True)
    assert not v["valid"]


def test_fixtures_roundtrip(tmp_path):
    captured = [CapturedRequest(timestamp=1.5, method="POST", path="/hook",
                                headers={"X-Signature": "sha256=abc", "Content-Type": "application/json"},
                                body=PAYLOAD, signature_valid=True)]
    path = tmp_path / "hooks.ndjson"
    save_fixtures(path, captured)
    loaded = load_fixtures(path)
    assert loaded[0].body == PAYLOAD and loaded[0].signature_valid is True


def test_receiver_captures_and_verifies(tmp_path):
    fixtures = tmp_path / "captured.ndjson"
    with Receiver(port=0, secret=SECRET, fixture_path=str(fixtures)) as receiver:
        url = f"http://127.0.0.1:{receiver.port}/hook"
        good = compute_signature(PAYLOAD.encode(), SECRET)
        req = urllib.request.Request(url, data=PAYLOAD.encode(), headers={
            "Content-Type": "application/json", "X-Signature": good})
        with urllib.request.urlopen(req, timeout=10) as resp:
            assert resp.status == 200
            assert json.load(resp)["signature_valid"] is True
        bad = urllib.request.Request(url, data=PAYLOAD.encode(), headers={
            "X-Signature": "sha256=" + "0" * 64})
        try:
            urllib.request.urlopen(bad, timeout=10)
            raised = False
        except urllib.error.HTTPError as exc:
            raised, code = True, exc.code
        assert raised and code == 400
        assert len(receiver.captured) == 2
        assert receiver.captured[0].signature_valid is True
        assert receiver.captured[1].signature_valid is False
    assert fixtures.is_file()
    loaded = load_fixtures(fixtures)
    assert len(loaded) == 2 and loaded[1].signature_valid is False


def test_replay_hits_local_handler(tmp_path):
    received = []

    class Collect(Receiver):
        def __init__(self):
            super().__init__(port=0)

        def start(self):
            super().start()
            original = self._server
            # wrap handler capture
        def capture(self):
            return self.captured

    # simpler: run a Receiver as the target handler and replay into it
    with Receiver(port=0) as target:
        url = f"http://127.0.0.1:{target.port}/hook"
        fixtures = tmp_path / "f.ndjson"
        captured = [CapturedRequest(timestamp=0, method="POST", path="/hook",
                                    headers={"X-Signature": compute_signature(PAYLOAD.encode(), SECRET)},
                                    body=PAYLOAD)]
        save_fixtures(fixtures, captured)
        results = replay(str(fixtures), url, secret=SECRET)
        assert results[0]["status"] == 200
        assert len(target.captured) == 1
        assert target.captured[0].body == PAYLOAD


def test_cli_verify(tmp_path, capsys):
    body = tmp_path / "body.bin"
    body.write_bytes(PAYLOAD.encode())
    sig = compute_signature(PAYLOAD.encode(), SECRET)
    assert main(["verify", "--payload", str(body), "--signature", sig, "--secret", SECRET]) == 0
    assert "VALID" in capsys.readouterr().out
    assert main(["verify", "--payload", str(body), "--signature", sig, "--secret", "wrong"]) == 1
    assert "INVALID" in capsys.readouterr().out
    assert main(["verify", "--payload", str(body), "--signature", sig, "--secret", "wrong",
                 "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["valid"] is False
