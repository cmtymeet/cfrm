# Private accounting proof spike

**Isolated feasibility experiment. No production private-accounting backend,
audit, Tor transport test or mobile performance claim.** Production
`AllocationLedger::resolve_private` still fails closed. See the
[required full proof relation](../../docs/private-accounting.md).

## What this proves

The [Noir circuit](circuit/src/main.nr) checks a single transition from an existing
reserved obligation to its settlement. A common four-member synthetic enrollment
checkpoint contains each member's permanent identity, delegated P-256 key,
accounting-secret commitment and validity interval. Both membership paths remain
private. The updating owner proves knowledge of its registered secret.

The old commitment binds that owner's available balance, reserved amount, role,
counterpart, introduction nonce and group. The receipt's signature must cover
the exact same members, nonce, group, decision and time. The signature authority
is selected by role:

- Outgoing reservation: the counterpart signs an answer or closure.
- Incoming reservation: the owner signs its own closure. A self-declared answer
  is rejected; authenticated evidence for incoming answer credit remains work.

The successor releases exactly the existing reserved units, clears the single
pending entry and uses fresh commitment randomness. Checked `u32` arithmetic
constrains overflow. A secret-bound event marker stops reuse in the named-owner
ledger fixture; the marker does not depend on a signature's encoding or renewal
time and is independent between owners. The `7` available / `2` reserved example
is synthetic witness data, **not** the product's `n`, `x` or reward policy.

This does not prove how the previous reservation was created. The Node ledger
fixture explicitly begins at the scenarios' already reserved commitments and
tests compare-and-swap/replay behavior only after real proof verification. It
does not implement production genesis, recovery or durable storage. Duplicate
identity rejection in the native fixture tests enrollment uniqueness, not a
zero-knowledge genesis proof.

## Root-owned enrollment bridge

[native/src/main.rs](native/src/main.rs) is a test-only JSON-lines executable
with four fixed synthetic Ed25519 roots/devices and a synthetic eligibility
issuer. It signs the existing cmsg root/device wire and verifies that wire with
cfrm's real strict Ed25519 verifiers. It separately verifies the device's
signature over this experimental delegation:

```text
["cfrm.accounting-enrollment.spike.v1", community, member,
 accountKeyHex, accountingSecretHashHex, issuedAt, expiresAt]
```

Eligibility and device authority are checked at the current fixture time and
the delegation's signed time. The member identity is derived from the root.
The fixture checks its independently pinned four roots and computes the Merkle
root from the verified original entries; a supplied root is never authoritative.
Changing the delegated key, member or secret commitment, copying an issuer's
signature into root authorization, and duplicating an enrollment are rejected.

The browser generates the P-256 signing keys and random accounting secrets.
Only their public keys and secret commitments cross the enrollment bridge.
The native fixture has no accounting private keys or proof witnesses. Its fixed
Ed25519 seeds and root-signing command are intentionally synthetic: **do not
expose this executable as a production enrollment endpoint**.

The delegated signature is an explicit protocol extension. The proof does not
verify an unchanged cmsg `ContactResolution` Ed25519 signature. Production cmsg
would have to authenticate this additional versioned receipt authority and its
semantics. The fixture does not establish roster completeness or global
consistency for a suspicious real operator.

The tiny circuit assumes both entries belong to the current synthetic cohort.
Full accounting must allow an admitted recipient to close after its silent
counterpart expires, using historical reservation provenance and current owner
authority. Requiring the silent peer to renew would incorrectly trap that
recipient's capacity; this experiment does not implement that historical path.

## Existing primitives and exact pins

- Noir compiler/JS `1.0.0-beta.26` and Barretenberg `5.0.0`, the exact pair used
  by the [upstream Noir browser example](https://github.com/noir-lang/noir/blob/v1.0.0-beta.26/examples/browser/package.json).
- Noir's [built-in constrained P-256 verifier](https://github.com/noir-lang/noir/blob/v1.0.0-beta.26/noir_stdlib/src/ecdsa_secp256r1.nr),
  with WebCrypto signatures and its required standard low-S normalization.
  This smaller integration replaced the design review's initial BabyJubJub
  candidate; no curve arithmetic is implemented here.
- [Noir SHA-256](https://github.com/noir-lang/sha256/tree/9442e5b6856f98b2ec029882d7e90199ecff91ba)
  pinned by commit. Typed fixed-width byte encodings use distinct hash tags;
  those protocol encodings and their composition still need review.
- Barretenberg's
  [`verifierTarget: 'noir-recursive'`](https://github.com/AztecProtocol/aztec-packages/blob/v5.0.0/barretenberg/ts/src/barretenberg/backend.ts)
  explicitly enables zero knowledge. No non-ZK mode, development verifier or
  successful mock is accepted.

Initial dependency resolution uses `RESOLVE_DEPENDENCIES=1`; initial setup
bootstrap separately uses `RESOLVE_SETUP=1`. Retain the generated npm lock,
native Cargo lock and `setup-lock.json`. Subsequent CI uses those exact locks.
[build.mjs](build.mjs) downloads only the bounded compressed
G1 prefix and G2 file from the
[upstream setup host](https://github.com/AztecProtocol/aztec-packages/blob/v5.0.0/barretenberg/ts/src/crs/net_crs.ts),
records source/size/SHA-256, and checks those pins on subsequent builds.
Initial hash bootstrap trusts the official HTTPS source; it is not a ceremony
audit. The circuit, verification key and setup files are served locally to the
browser. Automatic backend SRS downloading is disabled.
The installed backend's WASM files are also copied, hashed and served locally;
an explicit `wasmPath` avoids its default embedded `data:` URL fetch.

On the known GNU Linux CI host, npm receives `--libc=glibc`. Only the final
bundling phase uses `CFRM_BUNDLER_BINDING` to select the installed GNU Rolldown
binding through its supported `NAPI_RS_NATIVE_LIBRARY_PATH` override, which is
restored afterward. The proof backend is destroyed before this scoped override.
No host libraries or dependency package files are patched.

## Running and interpreting the evidence

Run on the existing Crow worker, with project-local dependencies and the
preinstalled browser. No host tool or browser installation is needed.

```sh
npm ci --ignore-scripts --no-audit --no-fund
cargo build --manifest-path native/Cargo.toml --release --locked
npm run build
ACCOUNTING_FIXTURE="$CARGO_TARGET_DIR/release/cfrm-private-accounting-fixture" \
  BROWSER_BIN="/path/to/existing/chromium" \
  BROWSER_EVIDENCE="/path/to/evidence.json" npm test
```

The [driver](browser-check.mjs) runs a temporary loopback server, a bounded public
enrollment bridge and a temporary Chromium profile. Browser scripts have a
same-origin connection policy. The proof worker runs with **one thread** and a
**2 GiB maximum WASM allocation**. The
[pinned backend takes memory settings in 64 KiB pages](https://github.com/AztecProtocol/aztec-packages/blob/v5.0.0/barretenberg/ts/src/barretenberg_wasm/barretenberg_wasm_main/index.ts),
not bytes. Browser proving has an eight-minute deadline. Cleanup and partial
failure evidence are retained.

The browser runs adversarial witness cases, including authentic signatures from
the wrong enrolled signer or crediting the wrong owner; altered membership,
role, nonce, group and state; invalid signatures; and a genuinely signed
backdated receipt. It then generates and verifies two actual proofs, one for
each supported role. This result bundle is **test reporting**, not a proposed
multi-owner operator request format.

[verify.mjs](verify.mjs) verifies those public proofs in the separate Node runtime
using its local pinned verification key and the Rust fixture's independently
verified checkpoint. It receives no witness. It also tests changed public
inputs/proof bytes and replay/stale-successor rejection in the synthetic ledger.
Both verifiers use Barretenberg, so this is not implementation diversity.

Evidence records source/setup hashes, browser/runtime versions, witness/proving/
verification times, proof bytes, served/download bytes, and failure stages.
The two proofs share a warmed backend; they are not repeated measurements of
one identical circuit witness. End-of-run JS heap is only a sample. **Peak WASM
memory, peak process memory, iOS and Android performance remain unmeasured.**
No result is a pass until the actual CI run succeeds.

## Required work beyond this spike

Full accounting still needs authorized dual-role reservation before protected
release; one durable genesis/recovery; all concurrent pending obligations;
refill/cap/decay policy; lifetime pair history; directional block/expiry/consent
proofs; safe acknowledgment semantics; and atomic/recoverable private release.
The four-entry checkpoint is not a realistic anonymity set. Low traffic,
timing, malicious checkpoint forks, collusion and voluntary secret sharing are
not resolved by this circuit. No private witness may be outsourced to make
browser performance appear acceptable.
