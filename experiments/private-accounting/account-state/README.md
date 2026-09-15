# Account-state foundation

**Version 2 source candidate; validation pending.** Archived version 1 evidence
below does not validate this policy. This does not enable production
`AllocationLedger::resolve_private`, choose product credit rules, or establish
complete private release, recovery or mobile feasibility.

## Relation

One named permanent owner opens its last accepted hiding commitment and proves
one successor. Its registered accounting-secret commitment, owner, community,
policy and state version are bound throughout. The current enrollment path
contains the actual root/device-authorized P256 delegation digest. An operator
cannot replace the secret through a renewed enrollment and still open the old
state. Lifetime genesis uniqueness and competing-device acceptance additionally
require the durable Rust ledger; a valid genesis proof alone proves no uniqueness.

Genesis commits exactly the configured initial available credit, zero reserved
credit, three empty authenticated maps, permanent creation time and refill
frontier conservatively anchored at `validUntil`, and zero admissions in the
current window. Outgoing and
incoming reservations debit **one available balance**. Each map entry records
the role, full original peer/nonce/group/contact policy, amount, admission time,
historical peer and owner authority and Prepared/Active/Settled/Canceled/Expired phase. Every terminal transition retains
the entry as a tombstone. New reservations prove event absence in both role
maps, preventing role changes from resetting an event. A third map retains
lifetime pair membership; repeated pairs receive no invented extra reward.

Reservation moves configured units from available to reserved and consumes one
shared admission in the fixed time window. Refunds never restore that count.
Activation changes only Prepared to Active. Answer restores both reservations;
recipient Close restores its own reservation while leaving the sender's cost
spent. Prepared cancellation refunds capacity and retains a counted admission
and permanent tombstone. Active outgoing expiry spends the reservation without
resolving the recipient's inbox or refunding the sender.

Total `available + reserved` cannot exceed `initialCredit` while young or
`maximumAvailable` after `newcomerPeriod` since permanent genesis. Maturity
creates headroom, not credit. A due refill grants exactly
`min(refillUnits, capacity - available - reserved)` once and sets its committed
frontier to `validUntil`, including zero grants. Due time is measured from that
frontier; backdated proofs cannot collect repeated grants in one window. Offline
time never multiplies the grant. Conservation permits
only that issuance and exact outgoing Close/expiry burns. Other paths, genesis
age and admission counters remain fixed.

The immutable slot `admittedAt` means the common introduction **opened-at**,
not the receiver's reserve time. Incoming reserve requires it explicitly.
Reserve/activate/Answer must fit inside the shared lease. Close can clear an
incoming obligation after the deadline; late Answer cannot revive a tombstone.

The public policy supplies initial credit, maximum available, per-role amounts,
revision and validity interval, plus `newcomerPeriod:u64`, `rateWindow:u64`,
`newcomerAdmissions:u32`, `maximumAdmissions:u32`, `refillPeriod:u64`,
`refillUnits:u32`, `abandonAfter:u64`. Its 140-byte SHA256 transcript is ASCII
`cfrm.account-policy.v2\0`, community digest32, the original four u32 amounts and
three u64 values, those seven new fields in listed order, then byte32. Integers
are big-endian; every field is required.
`ACCOUNT_POLICY_JSON` is required at build time; the manifest pins its exact
contents. Synthetic CI values are test configuration, not product defaults.

Protocol2 statement signing uses `cfrm.account.statement.v2\0`. Public
`validUntil`, immediately after `now`, is the common
`min(next rate-window boundary, policyValidUntil)`. The ledger requires request
expiry within it and rechecks after proof verification. Reserve/activate/Answer
fit the entire proof interval within the lease; reproving near a boundary may
be necessary. No contact deadline, private action or role enters the named wire.

## Maps and retained authority

The depth32 map follows the
[Aztec indexed Merkle construction](https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/indexed_merkle_tree).
Leaves contain a full field key, payload and successor index/key. An authenticated
ordered gap proves absence. Insertion updates the predecessor, then proves the
append position empty against that intermediate root. Updates preserve the full
key and both pointers. Genesis anchors the sentinel and count1; inserts increment
the authenticated counter, and other updates preserve it. There is no arbitrary
root import. Map capacity is an implementation bound, not a contact allowance.

The hash primitive remains the exact upstream fixed-length Poseidon2 sponge.
Arbitrary bytes32 IDs/keys/nonces retain two checked u128 limbs. Ordering compares
canonical full field representatives, never truncated path prefixes. The owner
secret and event-marker domains remain the measured P2 domains; account-state
and delegation-leaf encodings are separately versioned. This is not a migration
proof for existing single-slot commitments or a key-rotation/reset mechanism.

Current owner eligibility is required throughout the common proof horizon;
the owner and any new/renewed counterpart delegation must expire no earlier
than `validUntil`. For a counterpart signature, an exact
match to the slot's reservation-time authority permits an archived receipt or
acknowledgment signed during that authority's validity. A different delegated
key requires current independently verified enrollment. Receipt and acknowledgment
times must match the original event's ordering. A recipient can close after its
silent counterpart expires.

The slot also retains the exact reservation-time owner delegation leaf. An
incoming receipt may use that original authority or the owner's currently
proved authority, while current account authorization remains independently
mandatory. The acknowledgment hashes the original receipt and original signer
delegation. A bounded ACVM case uses a synthetic renewed checkpoint with a real
original receipt; actual native renewal interoperability remains untested.

## Actual cmsg signatures

The fixture constructs real cmsg root/device delegations and durable MLS
Answer/Close events. Private accounting/P256 keys remain in the browser. cmsg
returns the exact unsigned versioned receipt; the browser signs it, and the
fixture verifies the resulting original object.

The receipt357 transcript binds community, responder, peer, original initiator,
nonce, group, delegation, contact policy, history, original Ed25519 receipt
digest, decision, recipient role and time. Outgoing settlement requires the
recipient's receipt. Incoming Close uses the owner's receipt. Incoming Answer
also verifies the original sender's P256 acknowledgment of the exact signed
Answer digest. Both signatures require low-S P1363 encoding. The acknowledgment
cannot swap peer, nonce, group, delegation or answer.

Signed history and original-receipt digests authenticate context. The circuit
does not parse those original Ed25519 objects or prove their Inbox history.
Cryptography cannot prove sincere engagement or prevent consenting members
from exchanging valid signatures. Private peer reservation evidence and cmsg
block/consent enforcement remain necessary for protected release.

## Browser and host boundary

Select `ACCOUNTING_MODE=account-state-v2` and
`HASH_SCHEME=poseidon2-bn254-fixed-128-v1`. Separate `ACCOUNT_SCENARIO=answer`
and `close` runs use fresh actual cmsg fixtures and the same compiled circuit/VK.
The current candidate submits every proof to a real persistent Rust ledger
before advancing the page-local opening. Two separate Active peer proofs then
feed the native cmsg gate through its trusted verifier; see the
[peer bridge contract](../peer-reservation/README.md#live-fixture-bridge).
This integration and v2 policy await their full validation run.
Setup hashes live in `account-state/setup-lock.json`; only explicit initial
`RESOLVE_SETUP=1` may create it. No browser witness is sent for remote proving.

BB5's [compressed setup initializer](https://github.com/AztecProtocol/aztec-packages/blob/v5.0.0/barretenberg/cpp/src/barretenberg/bbapi/bbapi_srs.cpp)
requires complete [131,072-point /4MiB chunks](https://github.com/AztecProtocol/aztec-packages/blob/v5.0.0/barretenberg/cpp/src/barretenberg/srs/factories/bn254_g1_chunk_hashes.hpp).
The build rounds the required padded circuit size plus one upward to this chunk
size, retaining the existing 524,288-point floor. A padded size of 524,288 thus
uses 655,360 points (20MiB compressed), not a power-of-two doubling. The
[memory CRS factory](https://github.com/AztecProtocol/aztec-packages/blob/v5.0.0/barretenberg/cpp/src/barretenberg/srs/factories/mem_bn254_crs_factory.cpp)
requires enough points for the requested degree. `public/circuit-stats.json`
is written before setup initialization so a later failure retains circuit
identity, gate counts and the setup plan. A new lock is written only after the
backend accepts the setup; run9/45's rejected partial-chunk lock is not a pin.

The browser proves both genesis states, both initial reservations and activations,
and an additional outgoing obligation for the recipient. Answer then proves
outgoing settlement and incoming settlement with the archived sender acknowledgment.
Close proves sender expenditure and incoming settlement after sender expiry.
Answer adds Prepared cancellation. Close adds activation of the other outgoing
slot, its expiry and one refill. Times 100/300/600 are synthetic fixture controls.

After each proof, while the actual device is still authorized, cmsg signs its
exact named request hashes and two independent random retry IDs. Reports contain
public statements/proofs and these signatures; private state openings and map
paths remain in the browser. Batched synthetic reporting is not an operator
request format or evidence of traffic unlinkability.

`verify-request.mjs` takes trusted manifest and native-verified enrollment paths,
then only `{statement, proof, proofScope}` on stdin. It reconstructs all243 public
inputs, independently derives the checkpoint and pins policy/time/circuit/VK
before actual Barretenberg verification. Rust's durable ledger independently
checks the real device authorization, lifetime genesis, exact retry and CAS.
The common checkpoint and accepted test times come from retained native data,
not browser claims. Both proof verifiers use Barretenberg; this is not independent
implementation diversity.

## Executed version 1 evidence

These runs predate the current lifecycle/rate/refill policy. No v2 proof result
is claimed yet. There is no v1 state import or migration; changing scope must
not permit a second lifetime genesis.

Crow 9/46 at `79708b7251e6a983b3478bd9530068778940a436` passed nine actual
Answer-flow browser proofs, 85 browser checks and 19 independently pinned Node
checks. The Rust integration then exposed a SQLite lock timeout during slow
verifier startup. The corrected ledger passed 13 native storage/authorization
tests on Crow 9/48 at `524956395852696c1d3f6ac4bd57ef5f8652c261`.

Crow 9/49 at that corrected source reused the hash-verified run 46 public proofs
and retained native enrollment. All 18 real Rust integration checks passed,
including independent-process contention, durable acceptance, process exit
after commit, expired exact retry and malformed-proof rejection. This replay
did not rerun the browser or receive private witnesses.

Crow 9/50 at `1b404017b9bde8cffe9c27efff76bb8c275057b7` passed the separate
Close flow: eight real browser proofs, 69 browser checks, 18 independent Node
checks and 17 real Rust ledger checks. The recipient settled after the silent
sender's credentials expired. The additional outgoing obligation remained
reserved. This run measured 26.4–27.5 seconds per proof and sampled PSS of
1,203,539,968 bytes (~1.12 GiB), with 1212/1238 complete samples and a maximum
271 ms sampling gap. It used the same circuit/VK and synthetic policy as Answer.

The circuit has 319,319 gates, padded to 524,288. Run 46 measured 26.4–27.4 seconds
per proof, 14,656 bytes per proof and 46,599,980 loaded bytes. Sampled Chromium-family
PSS reached 1,192,218,624 bytes (~1.11 GiB), with 1352/1379 complete samples and a
maximum 238 ms sampling gap. This is a desktop, single-thread measurement;
sampling can miss peaks and shared-host load affects timing. The cost prevents
claiming readiness for the intended browser experience. Mobile viability and
exact peak Wasm memory remain unverified.

Rewards/disapproval, private matching Active proof integration, recovery/opening
synchronization, authenticated policy/key migration, block/expiry/consent proofs,
operator consistency and target-browser measurements remain outside this
foundation. This evidence is neither a complete release nor a cryptographic audit.
