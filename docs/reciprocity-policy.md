# Live introductions and reciprocal capacity

This policy limits first introductions. Established conversation traffic has no
per-message operator accounting. Members may modify their clients, disconnect,
withhold acknowledgments, coordinate with other members and use several devices.
All devices share one permanent community account and one accepted state chain.

## State machine

Transport availability and account state are separate. Losing a connection
cancels that session's pending application delivery. It neither proves that a
message was never received nor authorizes an account refund.

| Account state | Permitted transition | Capacity effect |
|---|---|---|
| Absent event | Reserve as outgoing or incoming | Move the configured amount from available to reserved; consume one admission turn |
| Prepared | Activate within the agreed live lease | No balance change |
| Prepared | Cancel | Return reserved units; retain event tombstone and consumed turn |
| Active | Confirmed Answer within its proof validity window | Return the owner's reservation, with role-specific signed evidence |
| Active incoming | Explicit recipient Close | Return the recipient's reservation |
| Active outgoing | Authenticated recipient Close | Remove the reservation with its cost spent |
| Active outgoing | Lease expires | Remove the reservation with its cost spent |
| Active incoming | Silence, expiry or disconnect | Remain reserved until Answer or explicit Close |
| Terminal event | Retry or another outcome | Exact accepted requests are idempotent; new settlement or reuse is rejected |

An outgoing Active proof is required before an honest recipient authorizes its
incoming reservation. Both matching Active proofs are required before either
side releases first-contact plaintext. Prepared evidence never authorizes
payload release. Thus cancelling Prepared cannot erase an already authorized
delivery. Local flags such as “never sent” are not cancellation evidence.

Both slots bind the same community, members, introduction nonce, group, contact
policy and opening time. The opening time plus the common `abandonAfter` defines
the lease. It is immutable after reservation. Peer-only presentations expose
this context to the counterpart; named operator updates must not contain it.

A pending introduction belongs to the devices that reserved it. Its peer proof
binds the reservation-time device authority; a sibling device cannot substitute
its own welcome or first payload. Other devices may synchronize accepted history
and participate after the conversation is established. Moving an unresolved
introduction to another device requires closure and fresh admission. Concurrent
instances of one device must use a durable storage version check; copying or
rolling back all trusted device storage is outside that guarantee.

## One budget and one rate counter

Let `A` be available units, `R` all reserved units across both directions, and
`C` the account's current capacity. Every reachable state satisfies:

```
0 <= A; 0 <= R; A + R <= C
```

New accounts start with `initialCredit` available units and that same total
capacity. After `newcomerPeriod` from their permanent genesis time, capacity
becomes `maximumAvailable`. The permanent genesis age anchor is the end of the
genesis proof's validity window, so backdating that proof cannot shorten the
newcomer period. That field bounds available **plus reserved** units
in protocol v2. Graduation raises the ceiling and does not issue units. Device
enrollment, renewal, profile edits and reconnects cannot restart account age.

Every reservation consumes one turn from the root account's fixed time window,
regardless of direction. The limit is `newcomerAdmissions` or
`maximumAdmissions`. Answer, Close and cancellation never return that turn.
This is a rate counter, not a separate spendable or transferable budget. A fixed
window permits a boundary burst across two adjacent windows; it is not a claim
of a rolling-window limit. Unauthenticated handshake traffic additionally needs
transport resource limits.

After at least `refillPeriod` beyond the previous refill's proof horizon, a
refill issues:

```
grant = min(refillUnits, C - A - R)
```

The refill frontier advances to `validUntil`, even for a zero grant; genesis
initializes it to that same horizon. This prevents multiple backdated proofs
from collecting missed grants during a single current window.
Only one grant is available after an absence; missed periods do not accumulate.
Full unresolved capacity leaves no refill headroom. Close and recovery do not
need new admission turns. All amounts and durations are mandatory configuration;
synthetic fixture values are not product defaults.

## Time and atomicity

Each proof has a public `validUntil` at the end of the common rate window,
clipped to policy expiry. All members proving in that window use the same
horizon, avoiding a per-contact public expiry tag. The signed request cannot
outlive it. The ledger rechecks expiry after proof verification and atomically
accepts one successor with its exact response and event marker.
Current accounting enrollment must remain valid through that horizon. Historical
receipt authority is checked at its signature time against the exact authority
committed in the reservation; it cannot replace current owner authorization.

Reservation, activation and Answer require the entire proof validity window to
fit inside the private lease. Configuration rejects `abandonAfter < rateWindow`.
A final partial window may nevertheless be unusable;
clients must leave enough time for proving and acceptance. Outgoing expiry is
available at or after the lease deadline. Unclaimed late Answer evidence cannot
become a stored refund coupon after expiry. An already accepted Answer cannot
be reversed or settled again by a later Close.

Atomic owner updates do not establish simultaneous settlement of both accounts
or simultaneous network delivery. A peer can withhold the last acknowledgment.
Incoming Answer requires the sender's authenticated acknowledgment; locally
signing or queuing an Answer earns no refund. The recipient can explicitly Close
to clear the obligation. This is a defined escape from withholding, not proof of
perfect fair exchange. Protocols that guarantee stronger recovery commonly add
a trusted recovery party ([Asokan et al., 1997](https://research.ibm.com/publications/optimistic-protocols-for-fair-exchange)).

A fresh peer challenge proves possession of an accepted Active opening, not
that the accepted state has never been superseded. The honest endpoint therefore
also enforces its own current obligation, exact encounter context, expiry and
durable first-payload/closure history. An old certificate cannot authorize a new
encounter. The own-state query is a snapshot; it is not a cross-account lock held
through network delivery.

## Incentive bounds and limits

- Disconnecting yields no accounting benefit. A successful “send then disappear”
  consumes capacity and an admission turn.
- Ignoring admitted messages fills the same budget used to initiate contacts.
  Refill cannot empty the inbox. Explicit Close clears it without rewarding the
  unsuccessful sender.
- Refund loops cannot create units. Colluding members can exchange valid
  receipts, but their admission counts still bound the number of new encounters.
  No bonus is awarded for apparent sincerity, message length or distinct peers.
- A sender must commit its own scarce capacity before an honest recipient
  accepts an obligation. This bounds inbox exhaustion per sender; it does not
  make denial of service impossible for a large coalition.
- Persistent roots prevent a device reset from restoring allowances. Obtaining
  many distinct admitted roots is an eligibility problem; per-account accounting
  cannot solve Sybil attacks by itself.
- Returning refunds and replenishing capacity provide mechanical incentives,
  not a proof that all humans prefer cooperative behavior. An adversary who
  values harming others may willingly pay the bounded cost.

Correctness assumes sound signatures/proofs and a consistent account ledger
with trusted monotonic time. Privacy excludes explicit peer identifiers and
shared event tags from named updates; timing correlation and operator
equivocation require separate defenses. Model tests establish properties of
the stated model; actual circuit, ledger and browser tests establish their own
implementation boundaries.
