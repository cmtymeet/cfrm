# Anonymous first-contact permits

A test-driven experiment using RFC 9474 blind RSA signatures and a SQLite ledger. The issuer spends a trusted allocation while seeing only a blinded request. Redemption supplies a random permit and signature, without an account or recipient ID. Real cryptographic and concurrency tests come before implementation.

This is not a complete private reciprocity protocol. Network timing, anonymous redemption transport, malicious-recipient behavior, token transfer, allocation authentication and receipt/reward semantics remain separate. Cryptographic blindness does not imply traffic-analysis resistance. Each scope/epoch uses a fresh signing key shared across its members; never issue per-person identifying keys.

Run `npm ci --ignore-scripts` and `npm test` in this directory on a permitted test runner. Only synthetic data belongs in these tests.

Dependency: [Cloudflare blindrsa-ts](https://github.com/cloudflare/blindrsa-ts), Apache-2.0; protocol [RFC 9474](https://www.rfc-editor.org/rfc/rfc9474.html). Repository-authored experiment code uses the root license.
