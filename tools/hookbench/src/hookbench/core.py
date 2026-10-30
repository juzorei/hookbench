"""hookbench core: HMAC verification, local capture receiver, fixture replay."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SIGNATURE_HEADER = "X-Signature"
DEFAULT_TIMESTAMP_HEADER = "X-Timestamp"
DEFAULT_TOLERANCE_SECONDS = 300
DEFAULT_SCHEME = "sha256"


class SignatureError(ValueError):
    pass


def compute_signature(payload: bytes, secret: str, timestamp: str | None = None,
                      scheme: str = DEFAULT_SCHEME) -> str:
    """Sign like GitHub/Stripe style receivers: HMAC-SHA256 over `timestamp.payload`
    when a timestamp is part of the scheme, else over the raw payload."""
    if timestamp is not None:
        message = timestamp.encode() + b"." + payload
    else:
        message = payload
    return f"{scheme}=" + hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def verify_signature(payload: bytes, signature_header: str, secret: str,
                     timestamp: str | None = None,
                     timestamp_header_value: str | None = None,
                     tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
                     require_timestamp: bool = False) -> dict:
    """Verify a `scheme=<hex>` signature header. Constant-time compare. When the
    signature was computed over a timestamped message, the timestamp comes from
    ``timestamp_header_value`` and its freshness is checked."""
    result = {"valid": False, "error": None, "scheme": None, "replayed": None}
    if not signature_header:
        result["error"] = "missing signature header"
        return result
    if "=" not in signature_header:
        result["error"] = "signature header is not in 'scheme=<hex>' form"
        return result
    scheme, _, provided = signature_header.partition("=")
    result["scheme"] = scheme
    ts = timestamp_header_value
    if require_timestamp and not ts:
        result["error"] = f"missing timestamp (needed for the {scheme} scheme freshness check)"
        return result
    expected = compute_signature(payload, secret, ts if ts is not None else None, scheme)
    if not hmac.compare_digest(expected, signature_header.strip()):
        result["error"] = "signature mismatch (wrong secret, or the payload bytes differ)"
        return result
    result["valid"] = True
    if ts is not None:
        try:
            age = abs(time.time() - float(ts))
            result["replayed"] = age > tolerance_seconds
            if result["replayed"]:
                result["error"] = (
                    f"signature valid but timestamp is {int(age)}s old "
                    f"(tolerance {tolerance_seconds}s) — possible replay")
                result["valid"] = False
        except ValueError:
            result["error"] = f"non-numeric timestamp {ts!r}"
            result["valid"] = False
    return result


@dataclass
class CapturedRequest:
    timestamp: float
    method: str
    path: str
    headers: dict[str, str]
    body: str
    signature_valid: bool | None = None


def save_fixtures(path: str | Path, captured: list[CapturedRequest]) -> None:
    Path(path).write_text(
        json.dumps([c.__dict__ for c in captured], indent=2), encoding="utf-8")


def load_fixtures(path: str | Path) -> list[CapturedRequest]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("requests", [])
    return [CapturedRequest(
        timestamp=c.get("timestamp", 0), method=c.get("method", "POST"),
        path=c.get("path", "/"), headers=c.get("headers", {}),
        body=c.get("body", ""), signature_valid=c.get("signature_valid")) for c in data]
