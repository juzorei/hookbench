# hookbench

[English](README.md) | [Русский](README.ru.md)

[![CI](https://github.com/juzorei/hookbench/actions/workflows/ci.yml/badge.svg)](https://github.com/juzorei/hookbench/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/juzorei/hookbench)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/hookbench)](https://pypi.org/project/hookbench/)

An agent skill and a CLI that separate the three ways webhook integrations fail: handler never called (exposure), signature doesn't verify (secret/serialization), handler is wrong (logic).

```text
$ hookbench receive --port 8080 --secret-file secret.txt --out captured.ndjson
[1] /hook (signature_valid=True) body: {"event": "payment.succeeded", "id": 7}

$ hookbench replay captured.ndjson --url http://localhost:9000/handler --secret-file secret.txt
  #1 /hook -> 200  {"received": true}
```

Real payloads become fixtures; fixtures become the integration's test suite; replay re-signs with a fresh timestamp so your own replay doesn't trip replay protection. Verification is constant-time, covers raw-payload and timestamped (Stripe-style) schemes, and flags stale timestamps as possible replays even when the signature itself is valid.

## What's in the repo

- **[skills/webhook-integration-testing](skills/webhook-integration-testing)** — capture → verify → replay, the serialization trap (signatures cover exact bytes; a pretty-printing proxy breaks them), vendor scheme differences, and the scope line: never forge a signature for a secret you don't hold.
- **tools/hookbench** — the CLI ([README](tools/hookbench/README.md)): `receive` / `verify` / `replay`, stdlib only (http.server + urllib + hmac).

## Install

```bash
pip install hookbench
npx skills add juzorei/hookbench
```

## Scope

Capture and replay webhooks for integrations you own or are authorized to test. This tool verifies signatures; it never helps forge one for a secret you don't hold.

MIT licensed.
