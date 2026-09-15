# Durable private account ledger

The experimental [Rust ledger](../src/accounting_ledger.rs) accepts one opaque
state per permanent member and atomically records each verified successor.
It stores no peer, conversation tuple, private receipt, balance or map opening.
The updating owner, update timing, state versions and owner-specific markers
remain visible. This does not hide timing correlations or operator equivocation.

## Trust and scope

The host configures a complete `AccountProofVerifier`, common independently
verified enrollment checkpoints, an eligibility authority, an operator signing
key, trusted time and durable SQLite storage. There is no successful default
verifier. A verifier that merely checks a signature or returns success defeats
the accounting relation; the storage API cannot turn it into a proof verifier.

Policy values are mandatory. The versioned account-state foundation covers
genesis, reservations, activation and settlement. It does not yet implement
periodic issuance, answer rewards, disapproval, private reservation presentations
or protected cmsg release. `AllocationLedger::resolve_private` remains closed.
The older blind-permit allocation ledger is a separate mechanism.

One common checkpoint root can be admitted per configured time slot. Publishing
a root is a trusted local operation and requires independently verifying its
root/device/accounting delegations. Member-supplied roots are not authoritative.
The current database configuration is pinned on first open; changing policy or
proof scopes without an implemented continuity transition fails closed.

## Updates and recovery

Each request signs a domain-separated transcript binding the owner statement,
proof digest, circuit/VK digests, independent random request ID, authorizing
device and validity interval. Statements use canonical BN254 field encodings
and bounded integers. Unknown serialized fields are rejected. Neither named
endpoint's request contains a shared conversation identifier.

A short SQLite transaction checks whether the request is already accepted or
eligible for verification. Proof verification runs with all database locks
released. A final immediate transaction rechecks current authorization, time,
checkpoint, cached response, lifetime genesis or exact previous state, and
settlement markers before committing the successor and signed acceptance.
Another owner can commit while a slow proof is being checked. WAL with
`synchronous=FULL` protects commits under SQLite's filesystem durability assumptions.

Exact signed retries recover the cached acceptance without another proof or
debit, including after the original request expires when the caller supplies
current root/device authority. A newly authorized device can request the latest
acceptance or an earlier request's result. The signed status response binds a
fresh challenge and observation time; an old acceptance alone does not prove
that it is current. A status lookup returns no private opening and permits no
second genesis. The client must preserve openings and exact pending requests.

An operator acceptance certifies an accepted opaque state. A peer still needs
the separate proof of a matching active reservation and current cmsg consent
before releasing an introduction. Lost private recovery material, rollback of
all replicas and a malicious operator's inconsistent histories remain limits.

## Executed evidence

At `f68f6f3f30f3804d87a8f0a7b5c453cbd7d3db7c`, Crow run 9/43 passed nine new
storage/authorization tests, the existing 21 native and 55 historical JavaScript
tests, and the portable Wasm check. The new suite exercises strict signatures,
device continuity, expired exact retry, checkpoint and proof rejection, time
changes during verification, challenge-bound recovery, and rollback after marker
insertion. Two separate child processes race independent requests against the
same database; one successor commits and its exact response survives reopening.

Those nine tests deliberately use a synthetic verifier to isolate the storage
contract. They are not cryptographic acceptance evidence. The separate browser
account-state integration invokes the real pinned proof backend through
[account_ledger_fixture](../examples/account_ledger_fixture.rs); its execution
and measurements must be recorded independently before claiming it passed.
