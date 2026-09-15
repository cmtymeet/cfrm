import { fieldBytes, fieldValue } from '../hashes.mjs';
import { cat, be, random, zeros } from '../common.mjs';
import { IndexedMap, policyDigest, integer, SAFE } from './hashes.mjs';

const emptyMapWitness = () => ({ leaf: [0n, 0n, 0n, 0n], index: 0n,
  path: Array(32).fill(0n), append_path: Array(32).fill(0n) });
const enrollmentInput = entry => ({ key: entry.key, secret_hash: entry.secretHash, start: entry.start,
  end: entry.end, delegation_digest: entry.delegationDigest, path: entry.path, index: entry.index });
const openingInput = s => ({ available: s.available, reserved: s.reserved,
  outgoing_root: s.outgoingRoot, outgoing_count: s.outgoingCount,
  incoming_root: s.incomingRoot, incoming_count: s.incomingCount,
  pair_root: s.pairRoot, pair_count: s.pairCount, frontier: s.frontier, blind: s.blind });
const slotInput = s => ({ role: s.role, peer: s.peer, nonce: s.nonce, group: s.group,
  contact_policy: s.contactPolicy, amount: s.amount, phase: s.phase,
  admitted_at: s.admittedAt, peer_authority: s.peerAuthority });
const resolutionInput = r => ({ kind: r.kind, issued_at: r.issuedAt, history_digest: r.historyDigest,
  ed25519_receipt_digest: r.ed25519ReceiptDigest, signature: r.signature });
const emptyResolution = now => ({ kind: 2, issuedAt: now, historyDigest: zeros(), ed25519ReceiptDigest: zeros(), signature: new Uint8Array(64) });
const policyInput = p => ({ initial_credit: p.initialCredit, maximum_available: p.maximumAvailable,
  outgoing_reservation: p.outgoingReservation, incoming_reservation: p.incomingReservation,
  policy_revision: p.policyRevision, policy_valid_from: p.policyValidFrom, policy_valid_until: p.policyValidUntil });

export function statementFromInput(input) {
  return { protocolVersion: 1, community: Array.from(input.community), owner: Array.from(input.owner),
    policyDigest: Array.from(input.policy_digest), enrollmentRoot: Array.from(input.enrollment_root), now: Number(input.now),
    genesis: input.genesis, previousVersion: Number(input.previous_version), nextVersion: Number(input.next_version),
    previousState: Array.from(input.previous_state), nextState: Array.from(input.next_state), settlementMarker: Array.from(input.settlement_marker),
    policy: { initialCredit: Number(input.initial_credit), maximumAvailable: Number(input.maximum_available),
      outgoingReservation: Number(input.outgoing_reservation), incomingReservation: Number(input.incoming_reservation),
      policyRevision: Number(input.policy_revision), policyValidFrom: Number(input.policy_valid_from), policyValidUntil: Number(input.policy_valid_until) } };
}

export function publicInputValues(statement) {
  const bytes = value => {
    if (!Array.isArray(value) || value.length !== 32 || value.some(v => !Number.isInteger(v) || v < 0 || v > 255)) throw new Error('Noncanonical statement bytes');
    return value.map(BigInt);
  };
  const safe = value => { const n = integer(value, 64); if (n > SAFE) throw new Error('Statement integer'); return n; };
  if (statement.protocolVersion !== 1 || typeof statement.genesis !== 'boolean') throw new Error('Statement version/boolean');
  const p = statement.policy;
  return [...bytes(statement.community), ...bytes(statement.owner), ...bytes(statement.policyDigest), ...bytes(statement.enrollmentRoot),
    safe(statement.now), statement.genesis ? 1n : 0n, safe(statement.previousVersion), safe(statement.nextVersion),
    ...bytes(statement.previousState), ...bytes(statement.nextState), ...bytes(statement.settlementMarker),
    integer(p.initialCredit, 32), integer(p.maximumAvailable, 32), integer(p.outgoingReservation, 32), integer(p.incomingReservation, 32),
    safe(p.policyRevision), safe(p.policyValidFrom), safe(p.policyValidUntil)];
}

export function statementBytes(statement) {
  publicInputValues(statement); // Validate fixed byte/integer widths first.
  const s = statement, p = s.policy;
  return cat(new TextEncoder().encode('cfrm.account.statement.v1\0'), be(s.protocolVersion, 4),
    ...[s.community, s.owner, s.policyDigest, s.enrollmentRoot].map(value => Uint8Array.from(value)),
    be(s.now, 8), new Uint8Array([s.genesis ? 1 : 0]), be(s.previousVersion, 8), be(s.nextVersion, 8),
    ...[s.previousState, s.nextState, s.settlementMarker].map(value => Uint8Array.from(value)),
    ...[p.initialCredit, p.maximumAvailable, p.outgoingReservation, p.incomingReservation].map(n => be(n, 4)),
    ...[p.policyRevision, p.policyValidFrom, p.policyValidUntil].map(n => be(n, 8)));
}

// Local witness state. It is never accepted by an operator without a real proof
// plus a durable accepted-state comparison. Returned candidates do not mutate it.
export class AccountWitness {
  static async genesis({ hashes, community, policy, checkpoint, ownerIndex, ownerSecret, now }) {
    const value = new AccountWitness();
    Object.assign(value, { hashes, community, policy, checkpoint, ownerIndex, ownerSecret, now: BigInt(now), version: 0n });
    value.owner = checkpoint.entries[ownerIndex];
    value.policyHash = await policyDigest(community, policy);
    if (fieldValue(await hashes.secretHash(community, ownerSecret)) !== fieldValue(value.owner.secretHash)) throw new Error('Owner secret differs from verified enrollment');
    const empty = await IndexedMap.create(hashes);
    value.outgoing = empty; value.incoming = empty.clone(); value.pairs = empty.clone();
    value.slots = new Map();
    value.opening = { available: BigInt(policy.initialCredit), reserved: 0n,
      outgoingRoot: empty.root, outgoingCount: 1n, incomingRoot: empty.root, incomingCount: 1n,
      pairRoot: empty.root, pairCount: 1n, frontier: 0n, blind: random() };
    value.commitment = await value.commit(value.opening, 0n);
    const input = value.input(value.opening.blind, now);
    Object.assign(input, { genesis: true, previous_state: zeros(), next_state: fieldBytes(value.commitment),
      previous_version: 0n, next_version: 0n });
    return { input, statement: statementFromInput(input), next: value };
  }
  async commit(opening, version) {
    return this.hashes.state(this.community, this.owner.member, this.policyHash, this.owner.secretHash, version, opening);
  }
  clone() {
    const copy = new AccountWitness(); Object.assign(copy, this);
    copy.slots = new Map(Array.from(this.slots, ([k, v]) => [k, structuredClone(v)]));
    copy.opening = structuredClone(this.opening); return copy;
  }
  input(newBlind, now) {
    return { community: this.community, owner: this.owner.member, policy_digest: this.policyHash,
      enrollment_root: fieldBytes(this.checkpoint.root), now: BigInt(now), genesis: false,
      previous_version: this.version, next_version: this.version + 1n,
      previous_state: fieldBytes(this.commitment), next_state: zeros(), settlement_marker: zeros(), ...policyInput(this.policy),
      owner_secret: this.ownerSecret, owner_enrollment: enrollmentInput(this.owner), peer_enrollment: enrollmentInput(this.owner),
      old: openingInput(this.opening), new_blind: newBlind, action: 1,
      slot: slotInput({ role: 0, peer: zeros(), nonce: zeros(), group: zeros(), contactPolicy: zeros(), amount: 0,
        phase: 1, admittedAt: BigInt(now), peerAuthority: 0n }),
      own_map: emptyMapWitness(), opposite_map: emptyMapWitness(), pair_map: emptyMapWitness(), pair_exists: false,
      resolution: resolutionInput(emptyResolution(now)), acknowledgment: { issued_at: BigInt(now), signature: new Uint8Array(64) } };
  }
  async finish(next, input) {
    next.version = this.version + 1n;
    next.opening.outgoingRoot = next.outgoing.root; next.opening.outgoingCount = next.outgoing.count;
    next.opening.incomingRoot = next.incoming.root; next.opening.incomingCount = next.incoming.count;
    next.opening.pairRoot = next.pairs.root; next.opening.pairCount = next.pairs.count;
    next.opening.blind = input.new_blind;
    next.commitment = await next.commit(next.opening, next.version);
    input.next_state = fieldBytes(next.commitment);
    return { input, statement: statementFromInput(input), next };
  }
  async reserve({ peerIndex, role, nonce, group, contactPolicy, now = this.now }) {
    if (role !== 0 && role !== 1) throw new Error('Reservation role');
    const peer = this.checkpoint.entries[peerIndex];
    const event = await this.hashes.marker(this.community, this.ownerSecret, this.owner.member, peer.member, nonce);
    const pair = await this.hashes.pairKey(this.community, this.owner.member, this.ownerSecret, peer.member);
    const amount = BigInt(role === 0 ? this.policy.outgoingReservation : this.policy.incomingReservation);
    if (this.opening.available < amount) throw new Error('Insufficient shared available capacity');
    const slot = { peerIndex, role, peer: peer.member, nonce, group, contactPolicy, amount, phase: 1,
      admittedAt: BigInt(now), peerAuthority: peer.leaf };
    const own = role === 0 ? this.outgoing : this.incoming, opposite = role === 0 ? this.incoming : this.outgoing;
    const inserted = await own.insert(event, await this.hashes.obligation(event, slot, 1));
    const input = this.input(random(), now), next = this.clone();
    Object.assign(input, { action: 1, slot: slotInput(slot), peer_enrollment: enrollmentInput(peer),
      own_map: inserted.witness, opposite_map: opposite.absence(event) });
    const existing = this.pairs.find(pair);
    if (existing) { input.pair_exists = true; input.pair_map = this.pairs.witness(existing[0]); }
    else { const added = await this.pairs.insert(pair, 1n); input.pair_map = added.witness; next.pairs = added.next; }
    if (role === 0) next.outgoing = inserted.next; else next.incoming = inserted.next;
    next.opening.available -= amount; next.opening.reserved += amount;
    next.slots.set(event.toString(), slot);
    const result = await this.finish(next, input); result.event = event; return result;
  }
  async change(event, action, resolution, acknowledgment, now = this.now, peerEnrollment) {
    const oldSlot = this.slots.get(event.toString()); if (!oldSlot) throw new Error('Unknown private obligation');
    if ((action === 2 && oldSlot.phase !== 1) || (action === 3 && oldSlot.phase !== 2)) throw new Error('Invalid obligation phase');
    const slot = structuredClone(oldSlot), next = this.clone(), input = this.input(random(), now);
    Object.assign(input, { action, slot: slotInput(slot),
      peer_enrollment: enrollmentInput(peerEnrollment ?? this.checkpoint.entries[slot.peerIndex]) });
    const changed = await (slot.role === 0 ? this.outgoing : this.incoming).update(event,
      await this.hashes.obligation(event, slot, action === 2 ? 2 : 3));
    input.own_map = changed.witness;
    if (slot.role === 0) next.outgoing = changed.next; else next.incoming = changed.next;
    slot.phase = action === 2 ? 2 : 3; next.slots.set(event.toString(), slot);
    if (action === 3) {
      if (!resolution) throw new Error('Authenticated receipt required');
      input.resolution = resolutionInput(resolution);
      if (acknowledgment) input.acknowledgment = { issued_at: acknowledgment.issuedAt, signature: acknowledgment.signature };
      next.opening.available += slot.amount; next.opening.reserved -= slot.amount;
      input.settlement_marker = fieldBytes(event);
    }
    return this.finish(next, input);
  }
  activate(event, now) { return this.change(event, 2, undefined, undefined, now); }
  settle(event, resolution, acknowledgment, now, peerEnrollment) {
    return this.change(event, 3, resolution, acknowledgment, now, peerEnrollment);
  }
}
