---
name: webhook-integration-testing
description: Build and test webhook integrations locally — capture real webhooks as fixtures, verify HMAC signatures correctly (including timestamp freshness against replay), replay captures at your handler while developing. Use whenever the user integrates with webhooks (Stripe, GitHub, Shopify, payment systems, CRMs), says "webhook", "callback", "signature verification fails", "how do I test webhooks locally", "is my webhook handler working", sets up a webhook endpoint, or a production webhook integration is dropping events. Not for intercepting other people's webhooks or bypassing signature checks.
---

# Webhook integration testing

A webhook integration fails in exactly three ways: your handler never gets called (exposure/tunnel problem), the signature doesn't verify (secret/serialization problem), or the handler is wrong (logic problem). This skill separates them mechanically instead of guessing — capture real traffic, verify signatures with the exact bytes, replay on demand.

Install the CLI:

```bash
pip install hookbench
```

## 1. Capture real webhooks as fixtures

Run the local receiver and point the sender at it (or at a tunnel to it):

```bash
hookbench receive --port 8080 --secret-file secret.txt --out captured.ndjson
```

Every incoming request is printed live with its signature verdict and stored as a fixture (timestamp, path, headers, body, verdict). The fixture file is the ground truth for everything that follows: real payloads, real headers, exactly the bytes the sender sent.

**Serialization is the classic trap:** signature verification is over *exact bytes*. If anything between sender and your code re-serializes the JSON (a proxy pretty-printing the body, a framework re-ordering keys), the signature breaks while the payload "looks the same". That's why fixtures store raw bytes-as-text, and why verification must use the raw request body — never a parsed-and-re-dumped copy.

## 2. Verify signatures the way the sender means them

```bash
hookbench verify --payload body.bin --signature "sha256=abc…" --secret-file secret.txt
```

Schemes differ across vendors, and each mistake has a name:

- **raw payload** (`X-Signature: sha256=hex(payload)`) — GitHub style;
- **timestamped** (`t=<ts>,v1=hex(ts.payload)`) — Stripe style: the signature covers `<timestamp>.<body>`, and an old timestamp must be rejected even with a valid signature, otherwise anyone who once captured a payload can replay it forever;
- custom headers (a vendor prefix like `Stripe-Signature` vs `X-Hub-Signature-256`) — the algorithm is the same, the header name and message layout differ.

`hookbench verify` covers raw and timestamped schemes with a constant-time comparison and a freshness tolerance (`--require-timestamp`, `--tolerance 300`). If verification fails while the payload looks right, the usual suspects in order: comparing the *parsed-then-re-serialized* body instead of raw bytes; wrong secret (test vs prod keys); header name mismatch; including the `sha256=` prefix in the digest input (or not).

## 3. Develop the handler against fixtures, not live traffic

```bash
hookbench replay captured.ndjson --url http://localhost:9000/handler --secret-file secret.txt
```

Replay re-signs each fixture with a fresh timestamp (so your own replay doesn't trip your replay protection; `--keep-original-signatures` replays the captured bytes as-is for comparison) and POSTs them to your handler. Failing one fixture now is a test failure with a name, not a 2 a.m. page.

This is also the correct way to test rare events: capture the real "payment.succeeded" once, replay it a hundred times while developing, and keep the fixtures in the repo as the integration's test suite.

## 4. The exposure problem (handler never gets called)

Localhost isn't reachable from the internet; expose the receiver through a tunnel only when the *sender* must be real. For everything else, fixtures + replay are enough — no tunnel, no third party seeing your payloads. When a tunnel is needed (verifying the sender's own retries, or testing TLS-termination behavior), the receiver still verifies signatures, so a misconfigured tunnel shows up as a verdict you can read.

## 5. Report

```text
exposure:  receiver on :8080 behind tunnel X; sender reachable, 3 events captured
signatures: 3/3 valid (sha256, raw payload); vendor docs say Stripe-style v1 — NOT used by this sender
handler:   replay of 3 fixtures: 2 processed, 1 raised KeyError on "data.object.customer"
next:      fix the handler for the missing-field case; keep captured.ndjson as the test fixture
```

## Scope

Capture and replay webhooks for integrations the user owns or is authorized to test. Verifying signatures is exactly how receivers defend themselves — this skill never helps *forge* a signature for a secret you don't hold, and fixtures with real customer payloads stay on the user's machine.
