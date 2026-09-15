# Browser permit client contract

Build the library with the `browser` feature for `wasm32-unknown-unknown`, then
generate web bindings into `browser/pkg` with the matching wasm-bindgen version.
`contract.mjs` exports `runBrowserContract(callFixture)`. The authorized CI harness
serves the generated module and Wasm, and supplies a callback forwarding bounded
JSON objects to the native `browser_fixture` example's stdin. The fixture replies
with one JSON line: `{ "ok": true, "value": ... }` or an explicit error.
The contract initializes bindings with an explicit Wasm URL using
`init({ module_or_path: new URL('./pkg/cfrm_bg.wasm', import.meta.url) })`.

The example has synthetic identities, hard-coded **test-only** funding and
ephemeral SQLite databases. It binds no sockets and is not an operator service.
Real cmsg device/root authorization is tested separately by the native component
composition tests. This browser contract exercises Rust blind/unblind operations,
encrypted checkpoints, recipient-bound claims, native signatures, idempotent
retry, copied permits and exhausted allowance in an actual browser.

The Crow workflow selects this check with `CHECK_SUITE=browser`, an existing
`BROWSER_BIN`, and `WASM_LINKER`. It builds the native fixture and browser Wasm,
generates bindings, and runs the contract in Chromium. The test runner accepts
only bounded public protocol requests on its temporary loopback fixture bridge.
Build logs, generated bindings, browser evidence and hashes are saved even if
the browser contract fails. This browser gate is separate from native core tests.

## Binding boundary

- `BrowserPreparedPermit(epochJson, expectedContextId)` prepares a permit using
  a pinned shared epoch. Save `seal(key, storageContext)` before sending
  `issuanceRequest()`. `finalize(blindSignature)` returns verified public permit
  JSON. The private blinding state never has a JavaScript export method.
- `BrowserRecipientClaim(epochJson, expectedContextId, permitJson, introductionJson)`
  takes the authenticated sender ID, local recipient ID, and base64url 32-byte
  introduction ID and challenge. `anonymousRequest()` exports only the public
  permit, hiding commitment and claim ID. `verifyStamp(stampJson)` must succeed
  before admission.
- Claim `seal` exports only encrypted state. `restore` requires the same pinned
  epoch, storage key/context and independently expected introduction fields.
  Save the ciphertext durably before redemption; retry the same restored claim.
  Never put private claim data or checkpoints in operator requests or logs.

Checkpoints use XChaCha20Poly1305 with a fresh random 24-byte nonce and associated
data binding type, pinned epoch and caller storage context. Call `free()` on the
Wasm wrappers and erase JavaScript key copies when finished. Wasm memory remains
accessible to same-origin JavaScript; trustworthy client distribution is required.

This is the aggregate bearer gate documented in [the Rust core](../docs/rust-core.md).
It does not implement private member-bound answer/close accounting. The fixture
and tests do not establish Tor-in-browser transport or production anonymity.
