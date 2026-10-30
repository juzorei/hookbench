# hookbench

Capture webhooks as fixtures, verify HMAC signatures the way each vendor means them, and replay captures at your handler while developing.

```text
$ hookbench receive --port 8080 --secret-file secret.txt --out captured.ndjson
receiver listening on http://127.0.0.1:8080/ (Ctrl+C to stop)
verifying X-Signature against the provided secret
[1] /hook (signature_valid=True) body: {"event": "payment.succeeded", "id": 7}

$ hookbench replay captured.ndjson --url http://localhost:9000/handler --secret-file secret.txt
  #1 /hook -> 200  {"received": true}
1 webhook(s) replayed to http://localhost:9000/handler

$ hookbench verify --payload body.bin --signature "sha256=abc…" --secret whsec_test123
VALID
```

A webhook integration fails in exactly three ways — handler never called (exposure), signature doesn't verify (secret/serialization), handler is wrong (logic). `hookbench` separates them mechanically:

- `receive` — a local capture receiver; when a secret is given, every request's signature verdict is recorded with the payload, and an invalid signature answers 400.
- `verify` — offline single-payload check. Constant-time comparison, raw-payload and timestamped schemes (Stripe-style `t=…,v1=…`), freshness tolerance against replay.
- `replay` — re-signs fixtures with a fresh timestamp (so your own replay doesn't trip replay protection) and POSTs them at your handler; `--keep-original-signatures` compares against the captured bytes as-is.

**The serialization trap:** signatures cover exact bytes. A proxy pretty-printing the body breaks the signature while the payload "looks the same" — fixtures store raw bodies, and verification must read the raw request body, never a parsed-and-re-dumped copy.

Python 3.11+, stdlib only.

Install: `pip install hookbench` — or from this repo:
`pip install "git+https://github.com/juzorei/hookbench#subdirectory=tools/hookbench"`

The companion agent skill lives in [skills/webhook-integration-testing](../skills/webhook-integration-testing). Skills: `npx skills add juzorei/hookbench`.
