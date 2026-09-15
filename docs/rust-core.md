# Rust meeting board and introduction allocations

The Rust library provides independently authenticated public presence and a
durable operator-side allocation ledger. Its default feature set contains only
portable verification and board code. `--features sqlite` adds the native
operator ledger. It contains no message transport, profile payloads, provider
integration or browser-specific networking.

## Identity and presence

An externally signed eligibility grant is necessary but insufficient. Every
device also needs a member-owned root signature using the shared
`cmsg.device.v1` format. The permanent member ID is a community-scoped hash of
the root public key (`cmsg.member.v1`). A suspicious eligibility issuer can
deny service or qualify extra identities, but its signing key cannot authorize
a new device as an existing member.

`MeetingBoard::apply` verifies both credentials and the device's signed
`cfrm.presence.v1` update. It accepts only canonical checksum-valid v3 onion
endpoints and explicit ports. Member/device capacity, lease duration and replay
storage limits are supplied by the host. Device sequences prevent old online
updates undoing a newer disconnect during the lifetime of this board instance.
Disconnect markers remain until older authorized leases must have expired.

`snapshot` returns the same full roster shape without a target-member argument.
Every row retains the original eligibility, root authorization and signed
update. Clients use `verify_presence` against their own pinned trust to reject
operator route substitution. The operator can still omit rows, observe presence
and correlate request timing. Full snapshots have a bandwidth cost; they are
not PIR. Profile content stays with the member endpoint.

The board is deliberately ephemeral. A restart loses its sequence floors; a
previously signed, still-valid presence lease may be replayed until expiry.
Durable immediate revocation requires a separate persisted device-revocation
mechanism and is not established by this board. Losing presence never resets
the separate durable allowance.

## Durable allocation boundary

`AllocationLedger::reserve` requires current eligibility, root device
authorization and a device signature over the exact blinded request, member,
community, immutable policy digest, nonce and expiry. A SQLite immediate
transaction performs expiry/clock checks, initial or periodic funding and one
debit together. Repeated identical requests recover their original reservation;
the same nonce with different content rejects. Different devices and database
connections share one member balance. Clock floors and configuration bindings
survive restarts. SQLite uses WAL and FULL synchronous mode; deployment storage
and backup integrity remain the operator's responsibility.

All policy values are explicit. No product allowance or deadline is selected.
Periods are fixed-duration intervals from Unix epoch; the host must choose the
intended schedule before deployment. Periodic funding is capped, and the first
registration does not retroactively earn earlier grants. Nonces are retained;
there is no pruning or administrative balance-reset endpoint.

A reservation authorizes issuance for an exact blinded request. It is **not** a
recipient-bound spend permit or proof of message delivery. A trusted issuance
adapter must atomically/idempotently consume this allocation when returning
the matching blind signature. Such an adapter is not implemented in the Rust
crate. Existing Node blind-RSA and Semaphore experiments remain separate and
are not silently promoted into this library.

## Answer or close forever

cmsg owns permanent member-pair closure and signed private resolution receipts.
Private answer/close accounting must prove that the correct member fulfilled
the obligation without exposing the pair or permitting borrowed/poolable
receipts. The old blind receipt experiment does not establish that binding.

Consequently `resolve_private` returns `UnsupportedCapability` for every input.
It cannot mint credits from an asserted answer, close flag, encrypted counter
or copied receipt. This is an explicit missing capability, not a completed
reciprocity implementation. Initial/periodic allocation tests do not establish
the unanswered-receive rule, permanent pair accounting or resistance to collusive
credit farming. A nontransferable private proof backend and its adversarial
composition remain necessary.

## Verification

The Rust behavioral tests use real independently constructed Ed25519 signatures,
hostile-issuer substitution attempts and real SQLite transactions/restarts.
They exercise expiry inside a transaction, concurrent devices, nonce replay,
immutable policy, signed directory rows, and rejection of unsupported private
resolution. Run on an authorized test runner:

```sh
cargo test --features sqlite
cargo check --no-default-features --target wasm32-unknown-unknown
```

These checks establish their stated library boundaries, not Tor-in-browser
availability or a complete private messaging product.
