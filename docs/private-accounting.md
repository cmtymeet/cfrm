# Private reciprocal accounting: backend decision review

**2026-09-15 — proposed proof contract, not an implemented protocol or audit.**
Inspected cfrm `2c4fa47` and the current cmsg identity, receipt and directional
Inbox work. No local builds or proving benchmarks were run for this review.
Eligibility remains an external verified input; provider selection is outside scope.

## What exists and what is missing

[AllocationLedger](../src/allocation.rs) conserves an aggregate named-member
allowance across devices. [Permits](../src/permits.rs) and the
[native issuer](../src/permit_issuer.rs) implement blind issuance and atomic
one-use redemption. These transferable permits do not prove which member owns
a hidden receipt, prevent credit pooling, or enforce reciprocal accounting.
`resolve_private` correctly returns `UnsupportedCapability`.

cmsg authenticates member-controlled roots, independently authorized devices,
private answer/close receipts, conversation nonces and directional block history.
These supply witnesses for a future proof. A mutable client journal, even when
encrypted and signed, is not an operator-verifiable balance proof.

The required budget is **one per permanent community member**, affected by both
unanswered outgoing introductions and received introductions left unanswered.
An answer or recipient-owned closure resolves the appropriate obligation under
the eventual public policy. Sender cancellation cannot refund an outgoing
obligation or reset the recipient's first-message limit. Established traffic
and reconnection require no conversation-specific operator call. Amounts,
refill/decay formulas, deadlines and repeated-pair reward rules remain unselected.

## The statement a verifier must actually check

The following is an acceptance relation, not a new cryptographic primitive.
Commitments, pseudorandom functions, signatures and proof systems must come from
reviewed implementations. `P` denotes the complete, pinned public policy.

### Public inputs and private witnesses

The smallest ledger need not hide the account performing an update: individual
membership and agreed numerical state are already permitted operator knowledge.
Keep a named account's latest hiding state commitment and authenticate every
update. Hide its contacts and the openings of that state.

| Public to cfrm | Private witness, never operator input |
| --- | --- |
| Community, policy/version digest, circuit/verifying-key digest, common eligibility checkpoint, accepted time interval | Eligibility and device/root credentials for any hidden counterpart, authenticated roster paths |
| Updating owner ID, previous accepted state commitment/version, proposed next commitment | Owner's registered accounting secret/delegation; both state openings; balance, refill frontier, pending obligations, private pair/block maps |
| Domain-separated owner-specific spent markers, independently randomized operation/retry ID | Counterpart ID, introduction nonce, group binding, receipt bytes and signatures, commitment randomness, private paths |
| Only explicitly permitted numerical outputs | Relationship between this update and the other endpoint's update |

There must be **no common pair hash, nonce, commitment, request hash or nullifier
in both named endpoints' operator requests**. Equality of such public values
would join the accounts. Owner-specific markers can stop reuse within an owner;
the proof must bind their hidden pair input. Fully anonymous state-note updates
are another route, with more genesis, recovery and ledger machinery. Zcash is
a concrete reference for commitment membership, nullifiers and value conservation,
not a drop-in social accounting implementation. [Zcash protocol](https://zips.z.cash/protocol/protocol.pdf)

### Required constraints

1. **Owner and eligibility.** The public owner equals the permanent
   community-scoped root-derived ID. Prove possession of its registered accounting
   authority and valid delegation, not merely knowledge of somebody's public
   credential. New reservations require a currently eligible, distinct permanent
   counterpart under the pinned common checkpoint. Later recipient-owned closure
   uses the authenticated reservation's historical peer eligibility: a silent
   peer's expired membership must not prevent the recipient resolving its own
   obligation. Verify the actual receipt signer's authority as specified below.
   An eligibility issuer's
   signature alone cannot register a replacement device/accounting key under
   an existing member root.

2. **One genesis; no recovery refill.** A root-authorized registration creates
   exactly one initial state for that member. Enforce a lifetime genesis marker
   independently of credential expiry, device count and epoch. Recovery consumes
   or resumes that same state and retains spent-pair markers and obligations.
   Changing the accounting/nullifier key requires continuity, not fresh genesis.
   Loss of all opening/recovery material has no proven balance-reset escape hatch.

3. **One successor and conserved state.** Open the actual last accepted state;
   apply exactly one permitted transition; close it with fresh randomness.
   Constrain integer ranges and overflow, refill frontiers, caps, all touched
   map paths and unchanged state. The balance changes only by `P`'s authorized
   refill, debit, settlement and any separately specified numerical adjustment.
   Pending outgoing **and incoming** obligations consume/reserve capacity in
   this same state. Replaying a period or dropping an archived obligation cannot
   increase available capacity. Missing formulas mean the full circuit is not
   ready to freeze; they cannot be replaced by sender-only counters.

4. **Both reservations precede protected release.** S authorizes its outgoing
   obligation and R explicitly authorizes its incoming obligation for the same
   hidden pair/nonce and agreed bounds. An unsolicited preflight cannot debit R.
   Honest cmsg endpoints release the protected introduction only after verifying
   committed state evidence for both roles, privately bound to that introduction.
   One possible split is operator acceptance of each owner's state commitment,
   followed by a separate proof **to the peer** that the accepted state contains
   the expected reservation. That peer proof and the other owner's commitment
   must never be forwarded in a named operator update. This composition still
   needs an executable protocol and atomicity/recovery review.

5. **Exact receipt authority and event.** For current cmsg `ContactResolution`,
   reconstruct `cmsg.contact-resolution.v1` exactly: community, responder, peer,
   introduction nonce, kind, issued time, device key and hash of the embedded
   credential bytes. Verify strict Ed25519 and root/device/eligibility bindings,
   including validity at the signed time and required current authorization.
   Outgoing settlement requires the *counterpart* as responder and owner as peer;
   a recipient's own closure resolves its incoming decision, not the sender's
   self-cancellation. Refreshing an expired receipt is the same settlement event.
   An `Answered` declaration does not prove delivery or sincere engagement;
   incoming answer rewards require a defined authenticated peer acknowledgment
   or other explicitly selected protocol event, not the prover's assertion that
   its UI sent something. That additional evidence contract is unfinished.

6. **Unique pair, unique event.** Prove the same permanent pair in reservation,
   receipt, private history and settlement. Event markers bind owner, original
   introduction and settlement purpose; pair-history markers survive epochs,
   roles and devices. Keep them independent across owners. Prevent swapping
   direction or choosing another nonce from turning one encounter into repeated
   rewards. Whether a reopened pair can earn anything again remains policy work;
   a fresh nonce alone cannot authorize another lifetime first-pair reward.

7. **Recipient-owned restrictions.** Preserve both owners' authenticated block
   chains, latest accepted tips and exact consent fields. An active recipient
   block is not removed by sender cancellation. Configured expiry permits only
   a fresh initiative; old queued data stays invalid. A counterproposal with a
   changed role/nonce/policy is not consent. Clearing a transport restriction
   does not itself create budget credit or delete an unresolved obligation.

The ledger must atomically compare the previous commitment, consume markers,
save its successor and cache the exact accepted response. Device races have one
winner. A malicious operator can still censor or fork its view: preventing forks
requires an independently consistent checkpoint/log assumption or additional
witnessing, not just a valid proof. Proofs do not establish human uniqueness,
stop voluntary sharing of all owner secrets, or prove reading. Confidentiality
also requires common configurations, Tor, careful scheduling and trusted browser
code; low traffic and correlated named updates remain identifying metadata.
[Privacy Pass architecture](https://www.rfc-editor.org/rfc/rfc9576.html)

## Can the directional blind-receipt experiment be repaired directly?

The [experiment](../experiments/directional-receipts/README.md) already demonstrates
real membership proofs, authorized named debits, blind receipts, atomic retry and
conditional MLS release. Its affirmative pooling cases deliberately succeed:
the hidden qualified prover can prepare a receipt naming another hidden owner.
Three colluders concentrate six directional receipts on one account.

Adding a signature around that blind request does not prove equality between
the membership witness and hidden receipt owner. Proving that the sender debited
*some* issuance and the receiver redeemed *some* receipt also does not prove
same-token/same-pair provenance. Revealing the blinded message's identities or
sharing a public correlation field repairs equality by disclosing the graph.

RFC 9474 supplies blind signatures, not predicates about hidden message fields.
Retain the real transactional/release scaffolding, but the missing equality,
ownership, pair uniqueness and state-transition proofs require a richer proof
relation or different credential protocol. The experiment cannot become full
reciprocal accounting through field validation alone. [RSA blind signatures](https://www.rfc-editor.org/rfc/rfc9474.html)

## Reuse routes and evidence

| Route | Concrete reuse and remaining work | Browser evidence for this accounting relation |
| --- | --- | --- |
| Anonymous credentials / proof-friendly signatures | Blind BBS credentials can hide holder attributes; Dock exposes Rust/Wasm signatures, equality/composite proofs and range checks. A circuit-friendly delegated accounting key could instead use Noir's BabyJubJub EdDSA and Merkle libraries. Both still need the complete owner/state/pair relation and root-authorized enrollment. | **Unmeasured.** Dock documents browser tests; its listed BBS+ encoding is `368 + 32 × hidden_messages` bytes, not a measurement of a composite accounting proof. No target-browser accounting time, memory or proof size is established. |
| Circuit verification of existing Ed25519 objects | Preserves current receipt authority/encoding. Must constrain SHA-512, strict Ed25519, canonical JSON/base64, credential hashes, root derivation and all state logic. No suitable maintained full verifier was selected in this review. Noir's library called `eddsa` uses BabyJubJub, **not Ed25519**. | **Unmeasured** for these objects. The benchmark below concerns another curve and cannot justify a cmsg estimate. |
| zkVM executing the existing Rust verifier | RISC Zero proves Rust guest execution, making reuse of parsing and verification semantics attractive; guest compatibility, cycle/memory cost and genuine zero-knowledge settings still need checking. Never upload private witnesses to a remote prover. | **Unmeasured.** Current RISC Zero docs recommend at least 16 GB for local proving. Native/GPU datasheets and browser verification do not establish browser proof generation. |

Primary implementation/specification sources: [Dock Rust/Wasm](https://github.com/docknetwork/crypto-wasm),
[blind BBS draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures),
[actual Noir EdDSA source](https://github.com/noir-lang/eddsa/blob/master/src/lib.nr),
[RISC Zero execution and hardware guidance](https://dev.risczero.com/api/zkvm/).
Blind BBS's modular committed disclosures are useful building blocks; the draft
explicitly leaves further range/pseudonym extensions outside its scope.

There is relevant **actual browser** evidence, with narrow limits: Hyli's
2025-03-20 P-256 benchmark reports UltraHonk proving at 2.06 seconds on an M1
MacBook, about 6 seconds on a Galaxy A23, and out-of-memory on tested iPhones.
The article supplies no proof-byte measurement for our relation. These are
historical results for one P-256 verification, not Ed25519, complete accounting,
current versions or all-platform suitability. [Benchmark authors' report](https://blog.hyli.org/benchmarking-in-browser-p256-ecdsa-proving-systems/)

Barretenberg supplies a real browser prover/verifier and documented thread/memory
controls. Its deployment documentation alone is not a benchmark or an audit of
our constraints. Pin the exact compiler/backend pair, zero-knowledge mode,
setup parameters and verifier; review transitive licensing before adoption.
[Browser API](https://barretenberg.aztec.network/docs/how_to_guides/on-the-browser/)

## Recommended next executable spike

**Start with a root-bound delegated accounting-receipt experiment using an
existing proof-friendly signature and Noir/Barretenberg**, isolated from production
`resolve_private`. This tests the hidden-owner/receipt equality bottleneck with
available browser proving machinery before building a complete controller.

The [isolated executable spike](../experiments/private-accounting/README.md)
now selects Noir's built-in P-256 verifier and browser WebCrypto signing for
the smallest supported signature integration. It retains the explicit delegated
authority boundary; successful compilation or proving must still be evidenced
by CI, and does not complete this acceptance relation.

1. Add an experimental public enrollment binding from the actual cmsg
   root-authorized device to an accounting public key. Verify every original
   signature in Rust and derive/pin a common enrollment root; an operator-provided
   Merkle root alone is insufficient. Signature checks establish authenticity,
   not roster completeness or consistent views: those need the checkpoint/log
   assumption above. Enforce unique root-owned registrations. No per-member roots.
   This is an explicit protocol extension. It cannot silently convert existing
   Ed25519 receipts: cmsg must itself authenticate the versioned accounting
   receipt and its exact peer/nonce/role fields under that delegated authority.

2. Prove a single owner-state successor and a single consumed receipt: private
   signer enrollment membership, correct owner/peer equality, preserved pending
   record, exact declared settlement and owner-specific replay marker. Use a
   clearly synthetic fixed transition only for measuring the mechanism; retain
   every unresolved production policy parameter as unresolved.

3. Run a real browser prover and an independent verifier on existing CI.
   Test changed hidden owner, receipt/prover substitution, self-receipt,
   opposite-role reuse, backdating, stale successor, parallel devices,
   duplicate genesis and altered public input. Exercise an issuer-created
   enrollment substitution against root verification. Fail every unsupported
   production operation; never substitute a successful mock verifier.

4. Capture exact source/setup hashes, cold/warm proving and verification time,
   proof and download bytes, peak memory, thread settings and browser/device
   versions. Label desktop-only results accordingly; iOS and Android remain
   unknown until measured. Inspect both named envelopes for shared identifiers.

Continue only if the authenticated-key bridge, constraints and browser resources
are convincing. Otherwise measure the unchanged-Ed25519/zkVM route as a separate
experiment; do not trade away owner binding or send witnesses to a server to
make a benchmark pass. None of these routes yet constitutes the full backend.
