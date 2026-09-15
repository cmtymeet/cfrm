import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend, UltraHonkVerifierBackend } from '@aztec/bb.js';
import { OPTIONS, hex, unhex, random, sha, canonicalSignature, be } from '../common.mjs';
import { fieldBytes, FR_MODULUS } from '../hashes.mjs';
import { ACCOUNT_MODE, accountHashes, checkpointFromVerified, noirInput, receiptBytes, receiptDigest, ackBytes } from './hashes.mjs';
import { AccountWitness, statementBytes } from './witness.mjs';

const ECDSA_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const highS = signature => {
  const result = signature.slice();
  result.set(be(ECDSA_ORDER - BigInt('0x' + hex(result.slice(32))), 32), 32); return result;
};
const uint = bytes => BigInt('0x' + hex(bytes));
const equal = (a, b) => hex(a) === hex(b);

export async function runAccountState({ api, circuit, manifest, verificationKey, post, bytes, metrics, assert, stage }) {
  metrics.accountingMode = ACCOUNT_MODE;
  const configuration = await (await fetch('/test-config.json')).json();
  if (!['answer','close'].includes(configuration.accountScenario)) throw new Error('Explicit synthetic scenario required');
  metrics.accountScenario = configuration.accountScenario;
  const hashes = accountHashes(api), policy = manifest.accountPolicy;
  if (!policy) throw new Error('No independently pinned account policy');
  // Fixture scope and times, not product parameters. The native response must
  // agree and is retained separately by the trusted driver for verification.
  const community = await sha(new TextEncoder().encode('synthetic-community'));
  const holders = [];
  for (let i = 0; i < 2; i++) {
    const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key.publicKey));
    const secret = random(); holders.push({ key, raw: raw.slice(1), secret, secretHash: await hashes.secretHash(community, secret) });
  }
  stage('actual-cmsg-enrollment');
  const response = await post({ command: 'enroll', keys: holders.map(h => ({ accountKey: hex(h.raw), secretHash: hex(h.secretHash) })), peerExpires: 200 });
  assert(response.ok, 'actual cmsg root/device delegations accepted');
  const enrolled = response.value;
  assert(enrolled.community === hex(community) && enrolled.context.communityId === 'synthetic-community', 'actual cmsg fixture community is pinned');
  assert(enrolled.entries.length === 2 && enrolled.acceptedTimes.join(',') === '100,300', 'independent fixture roster and times');
  for (let i = 0; i < 2; i++) assert(enrolled.entries[i].accountKey === hex(holders[i].raw)
    && enrolled.entries[i].secretHash === hex(holders[i].secretHash), 'actual delegation binds browser key and secret ' + i);
  const verified = await post({ command: 'verify', delegations: enrolled.entries.map(e => e.originalDelegation) });
  assert(verified.ok && verified.value.entries.every((e, i) => e.delegationDigest === enrolled.entries[i].delegationDigest), 'Rust re-verifies original delegation digests');
  const alteredDelegations = structuredClone(enrolled.entries.map(e => e.originalDelegation));
  alteredDelegations[1].stateSecretCommitment = enrolled.entries[0].secretHash;
  assert(!(await post({ command: 'verify', delegations: alteredDelegations })).ok, 'Rust rejects changed registered secret');
  const checkpoint = await checkpointFromVerified(community, enrolled.entries, hashes);
  assert(enrolled.context.contact.initiatorId === enrolled.entries[0].memberId
    && enrolled.context.responderId === enrolled.entries[1].memberId, 'actual original sender and recipient are bound');
  const context = { nonce: Uint8Array.from(enrolled.context.introductionId), group: unhex(enrolled.groupBinding),
    contactPolicy: unhex(enrolled.contactPolicyDigest) };
  const noir = new Noir(circuit);
  const rejected = async (input, label) => {
    let failed = false; try { await noir.execute(noirInput(input)); } catch { failed = true; }
    assert(failed, label);
  };
  const mutate = async (candidate, label, change) => { const input = structuredClone(candidate.input); await change(input); await rejected(input, label); };
  const setup = {};
  for (const record of manifest.setup) {
    const data = await bytes('/setup/' + record.name);
    assert(data.length === record.bytes && hex(await sha(data)) === record.sha256, 'pinned account setup ' + record.name);
    setup[record.name] = data;
  }
  await api.srsInitSrs({ pointsBuf: setup['g1.dat'], numPoints: manifest.numPoints, g2Point: setup['g2.dat'] });
  const backend = new UltraHonkBackend(circuit.bytecode, api), verifier = new UltraHonkVerifierBackend(api);
  async function prove(candidate, ownerIndex, label) {
    stage(label);
    const executionStart = performance.now();
    const executed = await noir.execute(noirInput(candidate.input));
    const witnessMs = performance.now() - executionStart, started = performance.now();
    const proof = await backend.generateProof(executed.witness, OPTIONS);
    const provingMs = performance.now() - started, verifyingAt = performance.now();
    assert(await verifier.verifyProof({ ...proof, verificationKey }, OPTIONS), label);
    const verificationMs = performance.now() - verifyingAt;
    const original = enrolled.entries[ownerIndex].originalDelegation;
    const requestId = random(), issuedAt = candidate.statement.now;
    const expiresAt = Math.min(issuedAt + 100, original.admission.expiresAt, original.authorization.expiresAt);
    const authorized = await post({ command: 'authorize', owner: ownerIndex, requestId: hex(requestId),
      circuitDigest: manifest.circuitSha256, verifyingKeyDigest: manifest.vkSha256,
      statementDigest: hex(await sha(statementBytes(candidate.statement))), proofDigest: hex(await sha(proof.proof)),
      issuedAt, expiresAt });
    assert(authorized.ok, 'actual current cmsg device authorizes exact proof request ' + label);
    const alternate = await post({ command: 'authorize', owner: ownerIndex, requestId: hex(random()),
      circuitDigest: manifest.circuitSha256, verifyingKeyDigest: manifest.vkSha256,
      statementDigest: hex(await sha(statementBytes(candidate.statement))), proofDigest: hex(await sha(proof.proof)),
      issuedAt, expiresAt });
    assert(alternate.ok, 'independent request ID receives actual owner signature ' + label);
    metrics.proofs.push({ statement: candidate.statement, ownerIndex, proof: hex(proof.proof), publicInputs: proof.publicInputs,
      requestAuthorization: authorized.value.authorization,
      alternateRequestAuthorization: alternate.value.authorization,
      proofBytes: proof.proof.length, witnessMs, provingMs, verificationMs,
      verificationIncludesKeyGeneration: false });
    return candidate.next;
  }
  const genesis = [];
  for (let i = 0; i < 2; i++) genesis.push(await AccountWitness.genesis({ hashes, community, policy,
    checkpoint, ownerIndex: i, ownerSecret: holders[i].secret, now: 100 }));
  await mutate(genesis[0], 'genesis rejects unproved initial credit', async input => {
    const opening = structuredClone(genesis[0].next.opening); opening.available += 1n;
    input.next_state = fieldBytes(await genesis[0].next.commit(opening, 0n));
  });
  await mutate(genesis[0], 'genesis rejects a populated obligation map', async input => {
    const opening = structuredClone(genesis[0].next.opening);
    const inserted = await genesis[0].next.outgoing.insert(7n, 11n);
    opening.outgoingRoot = inserted.next.root; opening.outgoingCount = inserted.next.count;
    input.next_state = fieldBytes(await genesis[0].next.commit(opening, 0n));
  });
  await mutate(genesis[0], 'genesis rejects an existing-state shape', input => { input.previous_state = fieldBytes(genesis[0].next.commitment); });
  let sender = await prove(genesis[0], 0, 'proved sender lifetime genesis');
  let recipient = await prove(genesis[1], 1, 'proved recipient lifetime genesis');
  const outgoing = await sender.reserve({ peerIndex: 1, role: 0, ...context, now: 100 });
  await mutate(outgoing, 'reservation cannot inflate its configured amount', input => { input.slot.amount += 1n; });
  await mutate(outgoing, 'reservation cannot hide negative available credit', input => { input.old.available = 0n; });
  await mutate(outgoing, 'reservation rejects changed registered owner secret', input => { input.owner_secret = holders[1].secret; });
  await mutate(outgoing, 'insertion rejects append path from before predecessor update', input => {
    input.own_map.append_path = sender.outgoing.tree.path(sender.outgoing.count);
  });
  await mutate(outgoing, 'insertion rejects a truncated next pointer', input => { input.own_map.leaf[2] += 1n << 32n; });
  await mutate(outgoing, 'insertion rejects an exhausted append counter', input => { input.old.outgoing_count = 1n << 32n; });
  await mutate(outgoing, 'insertion rejects zero-key sentinel reuse', input => { input.own_map.leaf[0] = 1n; });
  await mutate(outgoing, 'enrollment rejects a noncanonical secret encoding', input => { input.owner_enrollment.secret_hash = be(FR_MODULUS, 32); });
  sender = await prove(outgoing, 0, 'proved outgoing reservation');
  const incoming = await recipient.reserve({ peerIndex: 0, role: 1, ...context, now: 100 });
  recipient = await prove(incoming, 1, 'proved incoming reservation');
  // A second pending obligation in the other role exercises one shared balance
  // and preservation of unrelated paths. No payload is released for this slot.
  const secondary = await recipient.reserve({ peerIndex: 0, role: 0,
    nonce: random(), group: random(), contactPolicy: context.contactPolicy, now: 100 });
  await mutate(secondary, 'both roles cannot use separate available balances', input => { input.old.available = BigInt(policy.initialCredit); });
  recipient = await prove(secondary, 1, 'proved second role shares available capacity');
  assert(recipient.opening.reserved === BigInt(policy.incomingReservation) + BigInt(policy.outgoingReservation), 'both role amounts remain reserved together');
  const activeSender = await sender.activate(outgoing.event, 100);
  await mutate(activeSender, 'activation cannot replace an obligation peer', input => { input.slot.peer = input.owner; });
  await mutate(activeSender, 'activation cannot change its original group', input => { input.slot.group[0] ^= 1; });
  await mutate(activeSender, 'payload update cannot alter linked pointers', input => { input.own_map.leaf[3] = 1n; });
  await mutate(activeSender, 'sender cancellation has no refund action', input => { input.action = 4; });
  sender = await prove(activeSender, 0, 'proved sender activation');
  const activeRecipient = await recipient.activate(incoming.event, 100);
  recipient = await prove(activeRecipient, 1, 'proved recipient activation preserves other role');
  const secondaryRoot = recipient.outgoing.root;
  stage('actual-cmsg-' + configuration.accountScenario);
  // Produce the actual decision while both owners can authorize their named
  // updates. Recipient settlement still runs after the sender expires.
  const prepared = await post(configuration.accountScenario === 'answer' ? { command: 'answer' } : { command: 'close', now: 100 });
  assert(prepared.ok, 'actual durable cmsg recipient decision exists');
  const message = unhex(prepared.value.signingBytes);
  assert(message.length === 357, 'real cmsg receipt has exact versioned357 encoding');
  const resolution = { kind: message[347], issuedAt: uint(message.slice(349)), historyDigest: message.slice(283, 315),
    ed25519ReceiptDigest: message.slice(315, 347), signature: new Uint8Array(64) };
  const slot = recipient.slots.get(incoming.event.toString());
  assert(equal(message, receiptBytes(community, checkpoint.entries[1].member, checkpoint.entries[0].member,
    slot, checkpoint.entries[1].delegationDigest, resolution)), 'browser encoding matches real cmsg receipt authority and context');
  resolution.signature = canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holders[1].key.privateKey, message));
  const completeReceipt = { ...prepared.value.receipt, signature: Array.from(resolution.signature) };
  assert((await post({ command: 'verifyReceipt', receipt: completeReceipt, now: Number(resolution.issuedAt) })).ok, 'Rust verifies browser-signed actual cmsg receipt');
  let acknowledgment, completeAck;
  if (configuration.accountScenario === 'answer') {
    const preparedAck = await post({ command: 'ack', answer: completeReceipt });
    assert(preparedAck.ok, 'actual cmsg original sender acknowledges delivered answer');
    const ackMessage = unhex(preparedAck.value.signingBytes);
    const issuedAt = uint(ackMessage.slice(247));
    assert(ackMessage.length === 255 && equal(ackMessage, ackBytes(community, checkpoint.entries[0].member,
      checkpoint.entries[1].member, slot, await receiptDigest(message, resolution.signature),
      checkpoint.entries[0].delegationDigest, issuedAt)), 'browser encoding matches exact nested-answer acknowledgment');
    acknowledgment = { issuedAt, signature: canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holders[0].key.privateKey, ackMessage)) };
    completeAck = { ...preparedAck.value.acknowledgment, signature: Array.from(acknowledgment.signature) };
    assert((await post({ command: 'verifyAcknowledgment', acknowledgment: completeAck, now: 100 })).ok, 'Rust verifies browser-signed sender acknowledgment');
  }
  const settledSender = await sender.settle(outgoing.event, resolution, undefined, 100);
  const senderAmount = BigInt(policy.outgoingReservation);
  const senderRefund = configuration.accountScenario === 'answer' ? senderAmount : 0n;
  assert(settledSender.next.opening.available === sender.opening.available + senderRefund
    && settledSender.next.opening.reserved === sender.opening.reserved - senderAmount,
  'actual ' + configuration.accountScenario + ' has the exact sender refund/burn');
  await mutate(settledSender, 'sender cannot self-sign a recipient resolution', async input => {
    input.resolution.signature = canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holders[0].key.privateKey, message));
  });
  await mutate(settledSender, 'settlement rejects high-S receipt signatures', input => { input.resolution.signature = highS(input.resolution.signature); });
  await mutate(settledSender, 'coherent successor cannot swap Answer refund and Close burn', async input => {
    const opening = structuredClone(settledSender.next.opening);
    opening.available += configuration.accountScenario === 'close' ? senderAmount : -senderAmount;
    input.next_state = fieldBytes(await settledSender.next.commit(opening, settledSender.next.version));
  });
  await mutate(settledSender, 'settlement cannot retain the resolved reservation amount', async input => {
    const opening = structuredClone(settledSender.next.opening); opening.reserved += senderAmount;
    input.next_state = fieldBytes(await settledSender.next.commit(opening, settledSender.next.version));
  });
  if (configuration.accountScenario === 'close' && settledSender.next.opening.available > 0n) {
    await mutate(settledSender, 'Close burn cannot exceed the exact policy reservation', async input => {
      const opening = structuredClone(settledSender.next.opening); opening.available -= 1n;
      input.next_state = fieldBytes(await settledSender.next.commit(opening, settledSender.next.version));
    });
  }
  sender = await prove(settledSender, 0, 'proved outgoing actual-' + configuration.accountScenario + ' settlement');
  let secondDecisionRejected = false;
  try { await sender.settle(outgoing.event, { ...resolution, kind: resolution.kind === 1 ? 2 : 1 }, undefined, 100); }
  catch { secondDecisionRejected = true; }
  assert(secondDecisionRejected, 'settled Answer/Close cannot be replaced by a later decision');
  await mutate(settledSender, 'proved settled state rejects a freshly recipient-signed later decision', async input => {
    const later = { ...resolution, kind: resolution.kind === 1 ? 2 : 1 };
    const senderSlot = sender.slots.get(outgoing.event.toString());
    later.signature = canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holders[1].key.privateKey,
      receiptBytes(community, checkpoint.entries[1].member, checkpoint.entries[0].member,
        senderSlot, checkpoint.entries[1].delegationDigest, later)));
    const current = sender.input(random(), 100);
    input.old = current.old; input.new_blind = current.new_blind;
    input.previous_state = current.previous_state; input.previous_version = current.previous_version;
    input.next_version = current.next_version; input.slot.phase = 3;
    input.own_map = sender.outgoing.witness(sender.outgoing.find(outgoing.event)[0]);
    input.resolution.kind = later.kind; input.resolution.signature = later.signature;
    const opening = structuredClone(sender.opening); opening.blind = current.new_blind;
    input.next_state = fieldBytes(await sender.commit(opening, current.next_version));
  });
  assert((await post({ command: 'advance', now: 300 })).ok, 'native fixture advances its trusted test clock');
  if (completeAck) {
    assert((await post({ command: 'verifyHistoricalAcknowledgment', acknowledgment: completeAck, now: 300 })).ok, 'native historical acknowledgment retains exact expired sender authority');
    assert(!(await post({ command: 'verifyAcknowledgment', acknowledgment: completeAck, now: 300 })).ok, 'current verifier does not silently authorize expired sender');
  }
  const settledRecipient = await recipient.settle(incoming.event, resolution, acknowledgment, 300);
  assert(settledRecipient.next.opening.available === recipient.opening.available + BigInt(policy.incomingReservation)
    && settledRecipient.next.opening.reserved === recipient.opening.reserved - BigInt(policy.incomingReservation),
  'recipient actual Answer/Close restores exactly its own reservation');
  await mutate(settledRecipient, 'recipient settlement cannot silently burn its refundable capacity', async input => {
    const opening = structuredClone(settledRecipient.next.opening); opening.available -= BigInt(policy.incomingReservation);
    input.next_state = fieldBytes(await settledRecipient.next.commit(opening, settledRecipient.next.version));
  });
  await mutate(settledRecipient, 'settlement cannot change a saved historical peer', input => { input.slot.peer_authority += 1n; });
  await mutate(settledRecipient, 'coherent successor cannot mint extra available credit', async input => {
    const opening = structuredClone(settledRecipient.next.opening); opening.available += 1n;
    input.next_state = fieldBytes(await settledRecipient.next.commit(opening, settledRecipient.next.version));
  });
  await mutate(settledRecipient, 'coherent successor cannot erase other reserved credit', async input => {
    const opening = structuredClone(settledRecipient.next.opening); opening.reserved -= 1n;
    input.next_state = fieldBytes(await settledRecipient.next.commit(opening, settledRecipient.next.version));
  });
  await mutate(settledRecipient, 'settlement cannot discard another pending role', async input => {
    const opening = structuredClone(settledRecipient.next.opening); opening.outgoingRoot = genesis[1].next.outgoing.root; opening.outgoingCount = 1n;
    input.next_state = fieldBytes(await settledRecipient.next.commit(opening, settledRecipient.next.version));
  });
  await mutate(settledRecipient, 'settlement cannot reset its event marker', input => { input.settlement_marker[0] ^= 1; });
  await mutate(settledRecipient, 're-signed or reopened group cannot reuse old obligation', input => { input.slot.group[0] ^= 1; });
  if (acknowledgment) {
    await mutate(settledRecipient, 'incoming answer cannot omit sender acknowledgment', input => { input.acknowledgment.signature.fill(0); });
    await mutate(settledRecipient, 'incoming answer rejects high-S sender acknowledgment', input => { input.acknowledgment.signature = highS(input.acknowledgment.signature); });
    await mutate(settledRecipient, 'historical acknowledgment cannot replace the original delegated key', input => { input.peer_enrollment.key = holders[1].raw; });
    await mutate(settledRecipient, 'historical acknowledgment cannot invent renewed delegation validity', input => { input.peer_enrollment.end = 10000n; });
    await mutate(settledRecipient, 'genuinely signed different-group acknowledgment cannot settle this obligation', async input => {
      const wrong = ackMessageForWrongGroup();
      input.acknowledgment.signature = canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holders[0].key.privateKey, await wrong));
    });
    async function ackMessageForWrongGroup() {
      const wrongSlot = structuredClone(slot); wrongSlot.group[0] ^= 1;
      return ackBytes(community, checkpoint.entries[0].member, checkpoint.entries[1].member, wrongSlot,
        await receiptDigest(message, resolution.signature), checkpoint.entries[0].delegationDigest, acknowledgment.issuedAt);
    }
  }
  recipient = await prove(settledRecipient, 1, 'proved incoming actual-' + configuration.accountScenario + ' settlement after peer expiry');
  assert(recipient.outgoing.root === secondaryRoot && recipient.opening.reserved === BigInt(policy.outgoingReservation), 'unrelated outgoing obligation survives recipient settlement');
  let duplicateRejected = false;
  try { await recipient.reserve({ peerIndex: 0, role: 0, ...context, now: 300 }); } catch { duplicateRejected = true; }
  assert(duplicateRejected, 'settled event cannot re-enter under opposite role');
  await mutate(settledRecipient, 'settled tombstone cannot be credited again', input => {
    input.previous_state = fieldBytes(recipient.commitment); input.previous_version = recipient.version;
    input.next_version = recipient.version + 1n;
  });
  // Real proofs form the only exported account chain; openings, map witnesses,
  // signing secrets and contact receipts stay in this browser test process.
  metrics.endJsHeapBytes = performance.memory?.usedJSHeapSize ?? null;
  metrics.memoryMeasurement = 'Local JS heap at end; exact peak WASM unknown; harness process samples are separate';
  metrics.manifest = manifest;
  return { ok: true, ...metrics };
}
