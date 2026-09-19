// Real WebCrypto contract, shared by Node and Chromium CI. Eligibility and
// ticket adapters below are explicitly synthetic Ed25519 test authorities;
// these tests do not claim cvld AnonCreds or deployed ticket interoperability.
import { admissionBytes, authorizationBytes, createDiscoveryClient, createHolderKeyOffer,
  createProfilePublisher, createProfileReader, createSeededProfileHolder, discoveryRequestBytes,
  profileAssociatedData, profileEnvelopeBytes, verifyCachedProfile, wrappingKeyPair } from './index.js';
import { decode, digest, encode, json, random, verifySignature } from './crypto.js';

const NOW = 1_800_000_000;
const LIMITS = { maxProfileBytes: 2048, maxEnvelopeBytes: 8192, maxProfileSeconds: 300,
  maxFrameBytes: 16384, maxProofBytes: 2048, maxChallengeSeconds: 30, maxKeySeconds: 60,
  maxReplayEntries: 64, maxConcurrentProofs: 4, maxRequestsPerWindow: 100, requestWindowSeconds: 60 };
const check = (condition, message) => { if (!condition) throw new Error(`Profile contract: ${message}`); };
async function rejects(operation, message) {
  let rejected = false;
  try { await operation(); } catch { rejected = true; }
  check(rejected, message);
}
const signing = async (key, bytes) => encode(new Uint8Array(await crypto.subtle.sign('Ed25519', key.privateKey, bytes)));
const keyPair = () => crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']);
const raw = async key => encode(new Uint8Array(await crypto.subtle.exportKey('raw', key.publicKey)));
async function encoded(rawValue) {
  return BigInt(`0x${Array.from(decode(await digest(new TextEncoder().encode(rawValue)), 32), x => x.toString(16).padStart(2, '0')).join('')}`).toString(10);
}
async function fixture() {
  let now = NOW, sequence = 0, checkpoint = null, stored = null, publishFailure = false,
    saveFailure = false, saves = 0, publications = 0, opens = 0, closes = 0, proofs = 0, ticketChecks = 0;
  const issuer = await keyPair(), eligibilityKey = await keyPair(), ticketKey = await keyPair();
  const trust = { communityId: 'test.community', policyDigest: encode(random(32)), issuerPublicKey: await raw(issuer) };
  const clock = () => now, publicIssuer = { schemaId: 'test-schema', credentialDefinitionId: 'test-definition' };
  const config = { trust, clock, limits: { ...LIMITS }, publicIssuer };
  async function identity() {
    const root = await keyPair(), device = await keyPair(), rootPublicKey = await raw(root), chatPublicKey = await raw(device);
    const memberId = await digest(json(['cmsg.member.v1', trust.communityId, rootPublicKey]));
    const admission = { version: 1, issuerKeyId: await digest(decode(trust.issuerPublicKey, 32)), communityId: trust.communityId,
      memberId, chatPublicKey, policyDigest: trust.policyDigest, issuedAt: NOW - 1, expiresAt: NOW + 1000, signature: '' };
    admission.signature = await signing(issuer, admissionBytes(admission));
    const authorization = { version: 1, communityId: trust.communityId, memberId, rootPublicKey,
      devicePublicKey: chatPublicKey, issuedAt: NOW - 1, expiresAt: NOW + 1000, signature: '' };
    authorization.signature = await signing(root, authorizationBytes(authorization));
    return { authority: { admission, authorization }, sign: bytes => signing(device, bytes) };
  }
  const owner = await identity();
  const cache = {
    async publish(value) { publications++; stored = structuredClone(value); if (publishFailure) throw new Error('test lost response'); },
    async fetch() { return structuredClone(stored); },
  };
  const publisherOptions = { ...config, identity: owner, cache,
    reserveSequence: async () => ++sequence,
    saveCheckpoint: async value => { saves++; if (saveFailure) throw new Error('test storage failure'); checkpoint = structuredClone(value); } };
  const publisher = await createProfilePublisher(publisherOptions);
  const tickets = new Set();
  const access = { ...config,
    async verifyEligibilityProof(request, presentation) {
      proofs++;
      try { await verifySignature(await raw(eligibilityKey), presentation.proof.signature, json(request)); return true; }
      catch { return false; }
    },
    async verifyTicket({ ticket, challengeDigest, expiresAt }) {
      ticketChecks++;
      if (ticket.challengeDigest !== challengeDigest || ticket.expiresAt !== expiresAt || tickets.has(ticket.signature)) return false;
      try { await verifySignature(await raw(ticketKey), ticket.signature, json(['test-ticket', challengeDigest, expiresAt])); }
      catch { return false; }
      tickets.add(ticket.signature); return true;
    },
    authorizeAccess: async () => true,
  };
  const service = publisher.createKeyService(access), frames = [];
  const readerOptions = { ...config, cache,
    memberTransport: { async open() { opens++; return {
      async exchange(bytes) { frames.push(JSON.parse(new TextDecoder().decode(bytes))); return service.handle(bytes); },
      async close() { closes++; },
    }; } },
    acceptPublication: async () => true,
    async proveEligibility(request) {
      return { proof: { signature: await signing(eligibilityKey, json(request)) }, requested_proof: {
        revealed_attrs: Object.fromEntries(await Promise.all([['community_id', trust.communityId], ['policy', trust.policyDigest]]
          .map(async ([name, value]) => [name, { sub_proof_index: 0, raw: value, encoded: await encoded(value) }]))),
        self_attested_attrs: {}, unrevealed_attrs: {}, predicates: { eligible: { sub_proof_index: 0 }, valid_until: { sub_proof_index: 0 } },
      }, identifiers: [{ schema_id: publicIssuer.schemaId, cred_def_id: publicIssuer.credentialDefinitionId, rev_reg_id: null, timestamp: null }] };
    },
    async acquireTicket({ challengeDigest, expiresAt }) {
      return { challengeDigest, expiresAt, signature: await signing(ticketKey, json(['test-ticket', challengeDigest, expiresAt])) };
    },
  };
  const memberId = owner.authority.admission.memberId;
  return { config, owner, identity, cache, publisher, publisherOptions, service, access, readerOptions, frames,
    target: { memberId, holderMemberId: memberId },
    publish: (changes = {}) => publisher.publish({ text: 'Member-owned private profile 🌍', discriminators: { ageBand: 6, region: 2 }, expiresAt: NOW + 200, ...changes }),
    read: (changes = {}) => createProfileReader({ ...readerOptions, ...changes }).read({ memberId, holderMemberId: memberId }),
    advance(value) { now = value; }, failPublish(value) { publishFailure = value; }, failSave(value) { saveFailure = value; },
    get stored() { return structuredClone(stored); }, get checkpoint() { return structuredClone(checkpoint); },
    counts: () => ({ saves, publications, opens, closes, proofs, ticketChecks }),
  };
}

export const profileContractCases = [
  ['encrypt, authenticate, grant and decrypt with no keys in operator traffic', async () => {
    const f = await fixture(); const publication = await f.publish(); const profile = await f.read();
    check(profile.text === 'Member-owned private profile 🌍', 'plaintext round trip');
    check(profile.memberId === f.target.memberId && profile.discriminators.ageBand === 6, 'identity/filter continuity');
    check(!JSON.stringify(publication).includes('Member-owned') && !JSON.stringify(publication).includes(f.checkpoint.active.secret), 'operator gets ciphertext only');
    check(f.counts().proofs === 1 && f.counts().ticketChecks === 1 && f.counts().closes === 1, 'all gates and closure ran');
    const read = f.frames.find(frame => frame.read).read;
    check(!Object.hasOwn(read, 'admission') && !Object.hasOwn(read, 'memberId'), 'anonymous reader has no named admission');
    check(Object.keys(read.presentation.requested_proof.revealed_attrs).join(',') === 'community_id,policy', 'only shared attributes disclosed');
  }],
  ['cached signature binds filters, owner, version, epoch, nonce and ciphertext', async () => {
    const f = await fixture(); await f.publish();
    const changes = [value => value.envelope.discriminators.ageBand++, value => value.envelope.sequence++,
      value => value.envelope.profileEpoch = encode(random(32)), value => value.envelope.nonce = encode(random(12)),
      value => value.envelope.expiresAt++, value => value.envelope.memberId = encode(random(32)),
      value => value.envelope.ciphertext = encode(random(48)), value => value.envelope.extra = true,
      value => value.authorization.rootPublicKey = encode(random(32)), value => value.admission.policyDigest = encode(random(32))];
    for (const change of changes) {
      const value = f.stored; change(value);
      await rejects(() => f.read({ cache: { fetch: async () => value } }), 'tampered publication rejected');
    }
    check(f.counts().opens === 0, 'tampering rejected before peer I/O');
  }],
  ['profile canonical bytes match the independent Rust wire contract', async () => {
    const f = await fixture(), { envelope: p } = await f.publish();
    const expected = ['cfrm.cached-profile.v1', p.communityId, p.memberId, p.chatPublicKey, p.profileEpoch,
      p.sequence, p.issuedAt, p.expiresAt, p.nonce, p.profileDigest, [['ageBand', 6], ['region', 2]]];
    check(new TextDecoder().decode(profileEnvelopeBytes(p)) === JSON.stringify(expected), 'signature array order');
    const aad = ['cfrm.cached-profile.aad.v1', ...expected.slice(1, 9), expected[10]];
    check(new TextDecoder().decode(profileAssociatedData(p)) === JSON.stringify(aad), 'AAD omits only ciphertext digest');
    const unsorted = { ...p, discriminators: { region: 2, ageBand: 6 } };
    check(encode(profileEnvelopeBytes(unsorted)) === encode(profileEnvelopeBytes(p)), 'insertion order cannot change signatures');
  }],
  ['uncertain publication persists its DEK and retries exact ciphertext after restore', async () => {
    const f = await fixture(); f.failPublish(true);
    await rejects(() => f.publish(), 'lost response is surfaced');
    const first = f.stored, checkpoint = f.checkpoint;
    check(checkpoint.pending.secret && checkpoint.active === null, 'private pending key saved before I/O');
    check(f.publisher.currentPublication() === null, 'uncertain publication is not locally active');
    await rejects(() => f.publish(), 'second publish refused while uncertain');
    f.failPublish(false);
    const restored = await createProfilePublisher({ ...f.publisherOptions, checkpoint });
    await restored.retryPending();
    check(JSON.stringify(f.stored) === JSON.stringify(first), 'retry preserves signed bytes');
    check(f.checkpoint.active.secret === checkpoint.pending.secret && f.checkpoint.pending === null, 'same secret committed');
    const service = restored.createKeyService(f.access);
    const result = await f.read({ memberTransport: { open: async () => ({ exchange: service.handle, close: async () => {} }) } });
    check(result.text.includes('Member-owned'), 'restored DEK decrypts actual ciphertext');
    restored.close();
  }],
  ['failed local durability prevents cache publication and preserves retry intent', async () => {
    const f = await fixture(); f.failSave(true);
    await rejects(() => f.publish(), 'wallet failure surfaced');
    check(f.counts().publications === 0, 'no cache write before durable key');
    f.failSave(false); await f.publisher.retryPending();
    check((await f.read()).sequence === 1, 'durable retry uses initial sequence');
  }],
  ['fresh publication rotates the key and invalidates in-flight old grants', async () => {
    const f = await fixture(); await f.publish(); const before = f.stored;
    let started, release;
    const waiting = new Promise(resolve => started = resolve), blocked = new Promise(resolve => release = resolve);
    const delayed = f.publisher.createKeyService({ ...f.access, async verifyEligibilityProof(request, presentation) {
      started(); await blocked; return f.access.verifyEligibilityProof(request, presentation);
    } });
    const pendingRead = f.read({ memberTransport: { open: async () => ({ exchange: delayed.handle, close: async () => {} }) } });
    const rejectedRead = rejects(() => pendingRead, 'rotated snapshot cannot release a key');
    await waiting; await f.publish({ text: 'Changed profile' }); release(); await rejectedRead;
    check(before.envelope.profileEpoch !== f.stored.envelope.profileEpoch && before.envelope.nonce !== f.stored.envelope.nonce, 'fresh epoch and nonce');
    check((await f.read()).text === 'Changed profile', 'new profile remains readable');
  }],
  ['simultaneous replay consumes a signed challenge only once', async () => {
    const f = await fixture(); await f.publish(); let results;
    await f.read({ memberTransport: { open: async () => ({ async exchange(bytes) {
      if (!JSON.parse(new TextDecoder().decode(bytes)).read) return f.service.handle(bytes);
      results = await Promise.allSettled([f.service.handle(bytes), f.service.handle(bytes)]);
      return results.find(result => result.status === 'fulfilled').value;
    }, close: async () => {} }) } });
    check(results.filter(result => result.status === 'fulfilled').length === 1 && f.counts().proofs === 1, 'one proof and one grant for race');
    const replay = f.frames.find(frame => frame.read);
    // The custom transport intentionally bypasses the fixture frame recorder.
    check(replay === undefined, 'test did not depend on default transport');
  }],
  ['expired proof work and backward clocks cannot release profile keys', async () => {
    const f = await fixture(); await f.publish();
    const service = f.publisher.createKeyService({ ...f.access, async verifyEligibilityProof(request, proof) {
      const accepted = await f.access.verifyEligibilityProof(request, proof); f.advance(NOW + 30); return accepted;
    } });
    await rejects(() => f.read({ memberTransport: { open: async () => ({ exchange: service.handle, close: async () => {} }) } }), 'deadline checked after proof');
    f.advance(NOW - 1); await rejects(() => f.read(), 'clock rollback rejected');
  }],
  ['access policy, eligibility and resource tickets each fail closed', async () => {
    for (const gate of ['verifyEligibilityProof', 'authorizeAccess', 'verifyTicket']) {
      const f = await fixture(); await f.publish();
      const service = f.publisher.createKeyService({ ...f.access, [gate]: async () => false });
      await rejects(() => f.read({ memberTransport: { open: async () => ({ exchange: service.handle, close: async () => {} }) } }), `${gate} denial`);
    }
    const f = await fixture();
    await rejects(() => Promise.resolve(f.publisher.createKeyService({ ...f.access, verifyTicket: undefined })), 'missing ticket verifier');
    await rejects(() => Promise.resolve(createProfileReader({ ...f.readerOptions, acquireTicket: undefined })), 'missing ticket acquisition');
  }],
  ['reader rejects unsolicited stable identity disclosures', async () => {
    const f = await fixture(); await f.publish();
    await rejects(() => f.read({ async proveEligibility(request) {
      const proof = await f.readerOptions.proveEligibility(request);
      proof.requested_proof.revealed_attrs.member_id = { raw: f.target.memberId, encoded: '1', sub_proof_index: 0 };
      return proof;
    } }), 'extra stable disclosure refused');
    check(f.counts().proofs === 0, 'oversharing stopped before holder verifier');
  }],
  ['owner delegates an exact publication to an authenticated eligible holder', async () => {
    const f = await fixture(); await f.publish(); const holder = await f.identity(), wrappingKeys = await wrappingKeyPair();
    const holderOffer = await createHolderKeyOffer({ identity: holder, wrappingKeys, expiresAt: NOW + 50 }, f.config);
    const seed = await f.publisher.seedHolder({ holderOffer, expiresAt: NOW + 40 });
    check(!JSON.stringify(seed).includes(f.checkpoint.active.secret), 'seed wraps the DEK');
    const service = await createSeededProfileHolder({ ...f.access, identity: holder, wrappingKeys, seed });
    const reader = createProfileReader({ ...f.readerOptions, memberTransport: { open: async () => ({ exchange: service.handle, close: async () => {} }) } });
    const result = await reader.read({ ...f.target, holderMemberId: holder.authority.admission.memberId });
    check(result.text.includes('Member-owned'), 'delegated holder grants working key');
    await rejects(async () => createSeededProfileHolder({ ...f.access, identity: holder, wrappingKeys: await wrappingKeyPair(), seed }), 'wrong wrapping private key');
    const altered = structuredClone(seed); altered.delegation.expiresAt++;
    await rejects(() => createSeededProfileHolder({ ...f.access, identity: holder, wrappingKeys, seed: altered }), 'delegation extension rejected');
    await f.publish({ text: 'Rotated' });
    await rejects(() => reader.read({ ...f.target, holderMemberId: holder.authority.admission.memberId }), 'old holder cannot serve new epoch');
    service.close();
  }],
  ['holder wrapping offers cannot be substituted or impersonated', async () => {
    const f = await fixture(); await f.publish(); const holder = await f.identity(), wrappingKeys = await wrappingKeyPair();
    const holderOffer = await createHolderKeyOffer({ identity: holder, wrappingKeys, expiresAt: NOW + 50 }, f.config);
    holderOffer.offer.publicKey = encode(new Uint8Array(await crypto.subtle.exportKey('raw', (await wrappingKeyPair()).publicKey)));
    await rejects(() => f.publisher.seedHolder({ holderOffer, expiresAt: NOW + 40 }), 'unsigned wrapping-key substitution');
  }],
  ['identity and signature weak-point forgeries are rejected', async () => {
    const weak = new Uint8Array(32); weak[0] = 1;
    const forged = new Uint8Array(64); forged[0] = 1;
    await rejects(() => verifySignature(encode(weak), encode(forged), json(['forged'])), 'small-order identity key');
    const pair = await keyPair(), message = json(['message']), signature = decode(await signing(pair, message), 64);
    signature.fill(255, 32);
    await rejects(async () => verifySignature(await raw(pair), encode(signature), message), 'noncanonical scalar');
  }],
  ['byte bounds, Unicode and unknown wire fields reject before disclosure', async () => {
    const f = await fixture();
    await rejects(() => f.publish({ text: '\ud800' }), 'unpaired surrogate');
    await rejects(() => f.publish({ text: 'x'.repeat(LIMITS.maxProfileBytes + 1) }), 'profile byte ceiling');
    await f.publish();
    await rejects(() => f.service.handle(new Uint8Array(LIMITS.maxFrameBytes + 1)), 'oversized frame');
    await rejects(() => f.service.handle(json({ hello: { version: 1, extra: true } })), 'unknown hello fields');
    await rejects(() => f.read({ acceptPublication: async () => false }), 'durable rollback guard denial');
  }],
  ['disconnect invalidates outstanding challenges and erases serving state', async () => {
    const f = await fixture(); await f.publish();
    await rejects(() => f.read({ async proveEligibility(request) {
      const proof = await f.readerOptions.proveEligibility(request); f.publisher.close(); return proof;
    } }), 'publisher close invalidates pending request');
    await rejects(() => f.publisher.retryPending(), 'closed publisher cannot resurrect');
  }],
  ['discovery client signs exact Rust-compatible requests and carries no DEK', async () => {
    const f = await fixture(); await f.publish(); const requests = [], sessionId = encode(random(32));
    const client = createDiscoveryClient({ ...f.config, identity: f.owner, sessionId, requestSeconds: 10,
      maxResponseBytes: 16384, lease: async () => ({ leaseId: sessionId, sequence: 1, expiresAt: NOW + 20 }),
      async send(request) {
        requests.push(request);
        await verifySignature(f.owner.authority.admission.chatPublicKey, request.signature, discoveryRequestBytes(request));
        return request.operation.kind === 'fetch' ? { kind: 'profile', publication: f.stored } : { kind: 'updated' };
      } });
    await client.publish(f.stored); const fetched = await client.fetch(f.target.memberId);
    check(fetched.envelope.profileDigest === f.stored.envelope.profileDigest, 'cache adapter round trip');
    const value = requests[1];
    const expected = ['cfrm.discovery-request.v1', f.config.trust.communityId, f.config.trust.policyDigest, f.target.memberId,
      f.owner.authority.admission.chatPublicKey, sessionId, value.requestId, NOW, NOW + 10,
      { kind: 'fetch', memberId: f.target.memberId }];
    check(new TextDecoder().decode(discoveryRequestBytes(value)) === JSON.stringify(expected), 'independent request byte vector');
    check(!JSON.stringify(requests).includes(f.checkpoint.active.secret), 'cache adapter sees no secret');
  }],
];

export async function runProfileClientContract() {
  const checks = [];
  for (const [name, run] of profileContractCases) { await run(); checks.push(name); }
  return { checks, count: checks.length, crypto: 'WebCrypto', eligibility: 'synthetic Ed25519 adapter; not AnonCreds', transport: 'in-memory capability; not Tor' };
}
