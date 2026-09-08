# Authenticated complete eligibility checkpoints

This is a design contract, not an implemented transparency system. The current proof experiment receives its complete eligibility snapshot through a trusted host argument. A signature can authenticate a checkpoint; it cannot prove that the checkpoint issuer told the truth or showed everyone the same checkpoint.

## Inputs and lifecycle

An epoch publisher must read two trusted complete inputs at the epoch boundary:

- The immutable enrollment ledger containing each community member's Semaphore commitment.
- A cvld checkpoint of all account IDs that satisfy the community's current gate policy at that boundary, with its policy digest and validity interval.

The published members are the complete intersection, sorted by canonical member ID. A currently eligible account that has not enrolled a Semaphore identity cannot participate in anonymous acknowledgements yet. Old admission certificates are insufficient to assert present eligibility. The publisher's public request API must not accept a caller-selected member list, predicate or subset. Reading the eligibility checkpoint and enrollment ledger requires a consistent boundary; independent mutable reads are insufficient.

Membership is frozen for the checkpoint interval. New enrollments and gate changes affect the next interval. The existing experiment needs at least 17 members so each sender-excluded proof has at least 16 other commitments. A smaller community can still use its base allowance, but cannot obtain an anonymous acknowledgement through this experiment.

The publisher stores exactly one serialized checkpoint and digest per `(communityId, sequence)` in durable storage. Conflicting attempts at that sequence fail atomically, including across independent processes. Repeating the same request returns the exact committed checkpoint. This controls accidental or request-driven forks within the service; it does not constrain a malicious holder of the signing key outside that service.

## Signed portable envelope

The proposed envelope contains `version`, `issuerKeyId`, `policyDigest`, `sequence`, `previousDigest`, `snapshot`, and `signature`. `snapshot` is the existing canonical `freezeEligibility` result, including its complete ordered members, epoch label, interval, depth, minimum anonymity and digest. `sequence` is a positive safe integer. Sequence one uses `previousDigest=null`; later sequences refer to the previous signed checkpoint's digest.

The domain-separated Ed25519 signing bytes are UTF-8 JSON with this fixed order:

```text
["cfrm.eligibility.checkpoint.v1", issuerKeyId, policyDigest, sequence,
 previousDigest, snapshot.communityId, snapshot.epoch,
 snapshot.notBefore, snapshot.expiresAt, snapshot.minAnonymity,
 snapshot.depth, snapshot.members.map(m => [m.memberId, m.commitment]),
 snapshot.digest]
```

`issuerKeyId` is SHA256 of the raw 32-byte trusted signing public key; hashes and signatures use the established unpadded base64url encoding. The checkpoint digest is SHA256 of these canonical signing bytes. The signer is pinned by community configuration; a key supplied by the fetched envelope is never a trust anchor. A cfrm checkpoint key is a separate purpose from a member's chat key. Key rollover requires an explicit authenticated trust update and preserved sequence history.

## Client acceptance and limitations

A client verifies the pinned signature, community, policy, exact field encodings, canonical ordering, duplicate-free members, snapshot digest, current interval and local checkpoint continuity before using the list. It stores the highest accepted sequence and digest in its encrypted local wallet. The same sequence with different bytes, a lower sequence or a broken prior link is rejected. A reconnecting client that missed epochs needs the intervening signed checkpoint chain. A newly provisioned client needs a trusted starting checkpoint; a chain supplied solely by a malicious issuer does not provide independent truth.

The client derives every sender's proof group from this entire accepted snapshot and removes exactly that sender's enrolled commitment. It rejects a sender-proposed subset, changed interval, different policy or different membership digest. These local checks require a trusted complete starting view. The current acknowledgement wrapper implements the exact-whole-input check but does not yet authenticate network-fetched checkpoints.

Independent checkpoint witnessing or exchange between clients is needed to expose issuer equivocation. It can reveal conflicting signed digests without submitting allegations or conversation content, but cannot guarantee detection for isolated clients. This design does not invent a transparency protocol, custom circuit, blockchain or claim that signatures solve completeness. Reusing an existing append-only transparency implementation is the next step if this threat must be covered operationally.

The current snapshot exposes the stable IDs and commitments of qualified accounts, including offline accounts. It contains no profiles, endpoints, current-presence flags or contact edges, but durable eligibility membership itself is disclosed to its readers. A future commitment-only list plus an authenticated sender-to-commitment binding could reduce that disclosure; it would change the present proof context contract. Neither format proves that the other commitments belong to independent honest people.
