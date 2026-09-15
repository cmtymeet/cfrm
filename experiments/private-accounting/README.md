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

The JavaScript compiler's dependency resolver reads exact Git references from
[`tag`, not `rev`](https://github.com/noir-lang/noir/blob/v1.0.0-beta.26/compiler/wasm/src/noir/dependencies/github-dependency-resolver.ts).
The `sha2lib` alias also avoids its virtual `sha256/sha256.nr` path triggering
the compiler's [same-name parent-directory module rule](https://github.com/noir-lang/noir/blob/v1.0.0-beta.26/compiler/noirc_frontend/src/hir/def_collector/dc_mod.rs).
The pinned hash library is unchanged.

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
The selected backend WASM binary is also copied, hashed and served locally;
an explicit `wasmPath` avoids its default embedded `data:` URL fetch.
The exact 5.0.0 package embeds both browser binaries in
[generated JavaScript literals](https://github.com/AztecProtocol/aztec-packages/blob/v5.0.0/barretenberg/ts/scripts/browser_postprocess.sh);
the build extracts the selected literal without evaluating it, validates its
encoding and WASM header, and leaves the installed package unchanged. The
[pinned loader](https://github.com/AztecProtocol/aztec-packages/blob/v5.0.0/barretenberg/ts/src/barretenberg_wasm/index.ts)
selects the shared-memory binary when SharedArrayBuffer and cross-origin
isolation are available, even with one prover thread. This experiment requires
those browser capabilities; it does not establish support in every browser.

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
The cloned-proof rejection is a synchronous in-memory compare-and-swap test,
not concurrent independent device proving or distributed ledger testing. The
two proofs concern different random events. Their unequal markers, and a
separate same-nonce/opposite-owner hash comparison, do not measure traffic
unlinkability or constitute two proofs of one shared event.

Evidence records source/setup hashes, browser/runtime versions, witness/proving/
verification times, proof bytes, served/download bytes, and failure stages.
The two proofs share a warmed backend; they are not repeated measurements of
one identical circuit witness. End-of-run JS heap is only a sample. **Exact peak
WASM memory, iOS and Android performance remain unmeasured.** The harness's
process-family samples are a separate, incomplete estimate of resident memory.
No result is a pass until the actual CI run succeeds.

### Measured baseline: Crow 9/37

On 2026-09-15, source `310bd23086f0978b5ffe3f7492dcb28e30786eb9`
passed **40 browser checks and 19 independent-verifier checks**, using
Chrome `152.0.7977.64` on Linux x86-64 and Node `v24.19.0`.
The source and artifact hashes were verified before recording this result.
Artifacts are retained under
`/workspaces/component-releases/cfrm/310bd23086f0978b5ffe3f7492dcb28e30786eb9/private-accounting`.

| Measurement | Outgoing peer answer | Incoming owner closure |
| --- | ---: | ---: |
| Witness generation | 42.15 ms | 34.68 ms |
| Browser proving | 18.10 s | 17.62 s |
| Browser verification, including recomputed key | 4.63 s | 4.56 s |
| Binary proof, excluding public inputs/JSON | 14,656 bytes | 14,656 bytes |

The circuit had 200,214 gates, padded to 262,144. Both proofs used the same
warmed, one-thread backend. The harness recorded 52,414,774 loaded bytes and
no forbidden requests or browser errors. End-of-run JS heap was 65,131,076
bytes; actual peak WASM/process memory was unmeasured, with a 2 GiB WASM cap.
The independent verifier's complete timed check batch took 144.81 ms; that
number is not a per-proof verification benchmark.

This baseline downloaded both browser binaries. Its browser verification also
[recomputed the verification key each time](https://github.com/AztecProtocol/aztec-packages/blob/v5.0.0/barretenberg/ts/src/barretenberg/backend.ts).
The follow-up source selects one binary and uses the hash-checked build key
with `UltraHonkVerifierBackend`; its measured result follows below.
This desktop synthetic result proves neither mobile feasibility, full private
accounting, distributed concurrency nor anonymity against traffic observation.

### Measured follow-up: Crow 9/38

Source `36fc44b427a3cf7702d30d45fd0cc9aa212c5f25` passed **41 browser checks
and 19 independent-verifier checks** on the same recorded browser/runtime
versions. The circuit, setup and cryptographic relation were unchanged.
Hash-verified artifacts are retained under
`/workspaces/component-releases/cfrm/36fc44b427a3cf7702d30d45fd0cc9aa212c5f25/private-accounting`.

| Measurement | Outgoing peer answer | Incoming owner closure |
| --- | ---: | ---: |
| Witness generation | 38.72 ms | 31.34 ms |
| Browser proving | 18.20 s | 17.28 s |
| Browser verification with pinned key | 38.07 ms | 32.10 ms |
| Binary proof, excluding public inputs/JSON | 14,656 bytes | 14,656 bytes |

The harness recorded **41,849,684 loaded bytes**. Across 219 process-family
samples, the largest complete PSS sum was **1,011,635,200 bytes (964.8 MiB)**;
the largest complete RSS sum was 1,460,424,704 bytes. PSS apportions shared
pages; summed RSS double-counts them. This covers Chromium and discovered
descendants, up to ten processes, excluding the native fixture and Node verifier.
There were 217 complete samples and two incomplete samples caused by exited or
unreadable processes. Maximum sample gap was 200.54 ms and sample duration
118.62 ms. Sequential reads are not atomic; short peaks and descendants
reparented before discovery can be missed. These are sampled process estimates,
**not exact peak WASM allocation**. End-of-run JS heap was 65,004,298 bytes.

Roughly 1 GB of sampled browser memory for one obligation warrants further
measurement and circuit optimization before mobile feasibility can be accepted.
The faster verifier does not remove the prover's memory or latency costs.

## Required work beyond this spike

Full accounting still needs authorized dual-role reservation before protected
release; one durable genesis/recovery; all concurrent pending obligations;
refill/cap/decay policy; lifetime pair history; directional block/expiry/consent
proofs; safe acknowledgment semantics; and atomic/recoverable private release.
The four-entry checkpoint is not a realistic anonymity set. Low traffic,
timing, malicious checkpoint forks, collusion and voluntary secret sharing are
not resolved by this circuit. No private witness may be outsourced to make
browser performance appear acceptable.
