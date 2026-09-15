# Browser account proof cost

The [account-state foundation](../experiments/private-accounting/account-state/README.md)
passes real Answer and Close flows, including Rust ledger concurrency and retry.
Its current browser cost is a release blocker: roughly 27 seconds per proof and
more than 1 GiB of sampled Chromium memory on the measured desktop. Multiple
owner transitions are required before releasing a first introduction. Mobile
viability is unverified.

The following are implementation proposals, not measured improvements. The
current accepted relation, receipt formats and production capability flags are
unchanged.

## First implementation to evaluate

Keep existing cmsg signatures and account-state encodings. Separate the circuit
classes that the current public statement already reveals:

| Class | Existing public distinction | Required private behavior |
| --- | --- | --- |
| Genesis | `genesis == true` | Exact initial state and current owner enrollment |
| Reservation/activation | Non-genesis, zero settlement marker | Both roles, one balance, all maps and private phase selection |
| Settlement | Non-genesis, nonzero settlement marker | Both roles, exact receipt/ACK authority, conservation and tombstones |

Reservation and activation must share a circuit and format. Outgoing and incoming
must also share them. Splitting either pair would expose information the current
public statement hides. Each circuit must enforce its class, not merely rely on
a label supplied by the caller.

This could remove signature and receipt-hash constraints from the path before
an introduction. It requires a common pinned registry of circuit/VK digests in
the Rust ledger and verifiers, selected from the validated public statement.
Device signatures must bind the selected proof scope. Every class must preserve
the exact state commitment encoding, owner-secret continuity, common policy,
version rules and unchanged map invariants. A second genesis or alternate class
must never reset credit or skip a required transition.

Acceptance tests must cross class boundaries with real proofs and adversarial
scope substitution, expired authority, stale states, duplicate settlement and
independent-process contention. Measure the complete first-introduction sequence
and settlement separately. A smaller gate count alone establishes no browser
latency or memory guarantee.

## Additional candidates

- Share duplicate authority/path computations before changing their semantics.
- Incoming Answer can potentially use the original sender's acknowledgment as
  its sole P-256 check. Retain current owner enrollment/secret/device authority,
  the accepted active slot, full receipt context and time checks, historical
  sender authority, exact signed-receipt digest and one-time consumption. One
  selected signature check could cover outgoing receipt, incoming ACK and
  incoming Close receipt. This narrows the proof claim: it would no longer
  independently verify the embedded recipient signature for incoming Answer.
  Native/Wasm cmsg must retain full receipt and ACK validation.
- A separately versioned compact commitment-signing transcript could reduce
  SHA-256 constraints. It must retain every field, canonical encoding, all bits
  of existing byte identifiers, domain separation and exact ACK meaning. Native,
  WebCrypto and circuit interoperability would need new evidence. No new hash
  implementation or transcript is selected here.

Neither outsourcing private witnesses nor exposing recipient identifiers is an
approved way to reduce cost. Private peer presentations, protected release,
durable client recovery and the unselected refill/reward/disapproval policy
remain necessary beyond this performance work.
