"""hookbench CLI: capture webhooks, verify signatures, replay them at your handler."""

from __future__ import annotations

import argparse
import json
import sys
import time

from . import __version__
from .core import DEFAULT_SIGNATURE_HEADER, DEFAULT_TIMESTAMP_HEADER, verify_signature
from .server import Receiver, replay


def cmd_receive(args) -> int:
    secret = open(args.secret_file, encoding="utf-8").read().strip() if args.secret_file else None
    receiver = Receiver(port=args.port, secret=secret,
                        signature_header=args.signature_header,
                        timestamp_header=args.timestamp_header,
                        require_timestamp=args.require_timestamp,
                        fixture_path=args.out)
    receiver.start()
    print(f"receiver listening on http://127.0.0.1:{receiver.port}/ "
          f"(Ctrl+C to stop)")
    if secret:
        print(f"verifying {args.signature_header} against the provided secret"
              + (f", freshness via {args.timestamp_header}" if args.timestamp_header else ""))
    if args.out:
        print(f"capturing to {args.out}")
    print("point your sender at the URL above; captured requests are printed below\n")
    try:
        last = 0
        while True:
            time.sleep(0.3)
            while last < len(receiver.captured):
                c = receiver.captured[last]
                last += 1
                verdict = ("signature_valid=?" if c.signature_valid is None
                           else f"signature_valid={c.signature_valid}")
                print(f"[{last}] {c.path} ({verdict}) body: {c.body[:160]}")
    except KeyboardInterrupt:
        print("\nstopping…")
    finally:
        receiver.stop()
        if receiver.captured:
            print(f"captured {len(receiver.captured)} request(s)"
                  + (f" -> {args.out}" if args.out else ""))
    return 0


def cmd_replay(args) -> int:
    secret = open(args.secret_file, encoding="utf-8").read().strip() if args.secret_file else None
    results = replay(args.fixtures, args.url, secret=secret,
                     signature_header=args.signature_header,
                     timestamp_header=args.timestamp_header,
                     fresh_signatures=not args.keep_original_signatures)
    for r in results:
        print(f"  #{r['run']} {r['path']} -> {r['status']}  {r['response'][:120]}")
    print(f"{len(results)} webhook(s) replayed to {args.url}")
    return 0


def cmd_verify(args) -> int:
    payload = open(args.payload, "rb").read()
    verdict = verify_signature(payload, args.signature, args.secret,
                               timestamp_header_value=args.timestamp,
                               require_timestamp=args.require_timestamp,
                               tolerance_seconds=args.tolerance)
    if args.json:
        print(json.dumps(verdict, indent=2))
    else:
        print("VALID" if verdict["valid"] else "INVALID")
        if verdict["error"]:
            print(f"  {verdict['error']}")
    return 0 if verdict["valid"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hookbench", description=__doc__)
    parser.add_argument("--version", action="version", version=f"hookbench {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("receive", help="run a local capture receiver")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--secret-file", help="file with the HMAC secret (raw string)")
    p.add_argument("--signature-header", default=DEFAULT_SIGNATURE_HEADER)
    p.add_argument("--timestamp-header", default=None,
                   help="set when signatures cover '<timestamp>.<payload>'")
    p.add_argument("--require-timestamp", action="store_true",
                   help="reject signatures older than --tolerance")
    p.add_argument("--tolerance", type=int, default=300)
    p.add_argument("--out", help="save captures as a fixture .ndjson for replay")
    p.set_defaults(func=cmd_receive)

    p = sub.add_parser("replay", help="re-send captured webhooks to a handler URL")
    p.add_argument("fixtures")
    p.add_argument("--url", required=True)
    p.add_argument("--secret-file")
    p.add_argument("--signature-header", default=DEFAULT_SIGNATURE_HEADER)
    p.add_argument("--timestamp-header", default=DEFAULT_TIMESTAMP_HEADER)
    p.add_argument("--keep-original-signatures", action="store_true",
                   help="do not re-sign; replay the captured signature bytes as-is")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("verify", help="check one payload/signature pair offline")
    p.add_argument("--payload", required=True, help="file with the raw body")
    p.add_argument("--signature", required=True, help="signature header value, e.g. sha256=…")
    p.add_argument("--secret", required=True)
    p.add_argument("--timestamp", help="timestamp header value, when the scheme covers it")
    p.add_argument("--require-timestamp", action="store_true")
    p.add_argument("--tolerance", type=int, default=300)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except OSError as exc:
        print(f"hookbench: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
