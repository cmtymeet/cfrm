# Account-state foundation

**Source candidate; runtime evidence pending.** This extends the separately
measured settlement experiments. It does not enable production
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
credit, three empty authenticated maps and a zero refill frontier. Outgoing and
incoming reservations debit **one available balance**. Each map entry records
the role, full original peer/nonce/group/contact policy, amount, admission time,
historical peer authority and Prepared/Active/Settled phase. Settlement retains
the entry as a tombstone. New reservations prove event absence in both role
maps, preventing role changes from resetting an event. A third map retains
lifetime pair membership; repeated pairs receive no invented extra reward.

Reservation moves configured units from available to reserved. Activation
changes only Prepared to Active. Settlement returns exactly the reserved units;
all untouched roots, pointers, counts and fields remain fixed. No sender-cancel
or timeout-refund operation exists. Available is `u32`, aggregate reserved is
`u128`; their sum is conserved and is **not** capped by maximum available.
There is no refill transition yet. Future periodic allowance must define what
happens if later settlement would exceed the available cap; this relation does
not silently clamp or destroy units.

The public policy supplies initial credit, maximum available, per-role amounts,
revision and validity interval. Its SHA256 transcript is the 23-byte ASCII
`cfrm.account-policy.v1\0`, community digest32, four big-endian u32 amounts in
that order, revision/from/until as three big-endian u64s, then byte32 (map depth).
`ACCOUNT_POLICY_JSON` is required at build time; the manifest pins its exact
contents. Synthetic CI values are test configuration, not product defaults.

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

Current owner eligibility is required. For a counterpart signature, an exact
match to the slot's reservation-time authority permits an archived receipt or
acknowledgment signed during that authority's validity. A different delegated
key requires current independently verified enrollment. Receipt and acknowledgment
times must match the original event's ordering. A recipient can close after its
silent counterpart expires.

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

Select `ACCOUNTING_MODE=account-state-v1` and
`HASH_SCHEME=poseidon2-bn254-fixed-128-v1`. Separate `ACCOUNT_SCENARIO=answer`
and `close` runs use fresh actual cmsg fixtures and the same compiled circuit/VK.
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
Close proves incoming settlement after the silent sender expires. The additional
outgoing obligation stays outstanding. The 100/300 times and early sender expiry
are synthetic fixture controls.

After each proof, while the actual device is still authorized, cmsg signs its
exact named request hashes and two independent random retry IDs. Reports contain
public statements/proofs and these signatures; private state openings and map
paths remain in the browser. Batched synthetic reporting is not an operator
request format or evidence of traffic unlinkability.

`verify-request.mjs` takes trusted manifest and native-verified enrollment paths,
then only `{statement, proof, proofScope}` on stdin. It reconstructs all235 public
inputs, independently derives the checkpoint and pins policy/time/circuit/VK
before actual Barretenberg verification. Rust's durable ledger independently
checks the real device authorization, lifetime genesis, exact retry and CAS.
The common checkpoint and accepted test times come from retained native data,
not browser claims. Both proof verifiers use Barretenberg; this is not independent
implementation diversity.

Full refill/reward/disapproval, private matching Active proofs, recovery/opening
synchronization, authenticated policy/key migration, block/expiry/consent proofs,
operator consistency and target-browser measurements remain outside this
foundation. New source has no passing-runtime or audit claim until the recorded
Crow checks actually succeed.
