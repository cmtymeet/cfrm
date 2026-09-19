import { authorityExpiry, decode, encode, exact, fresh, json, monotonicClock, positive,
  random, reject, signing, trustCopy, verifyAuthority } from './crypto.js';
import { identityCopy } from './access.js';

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])]));
  return value;
}
/** Canonical request bytes match Rust discovery::request_signing_bytes. */
export function discoveryRequestBytes(value) {
  exact(value, ['version', 'admission', 'authorization', 'sessionId', 'requestId', 'issuedAt', 'expiresAt', 'operation', 'signature']);
  if (value.version !== 1 || value.expiresAt <= value.issuedAt) reject();
  positive(value.issuedAt); positive(value.expiresAt); decode(value.sessionId, 32); decode(value.requestId, 32);
  return json(['cfrm.discovery-request.v1', value.admission.communityId, value.admission.policyDigest,
    value.admission.memberId, value.admission.chatPublicKey, value.sessionId, value.requestId,
    value.issuedAt, value.expiresAt, sorted(value.operation)]);
}
/** send receives the signed public request only. An HTTP adapter posts it to
 * /v1/discovery as application/json and must bound bytes before JSON parsing.
 * The caller owns URLs/authenticated transport; no endpoint is guessed here. */
export function createDiscoveryClient(options) {
  const trust = trustCopy(options.trust), identity = identityCopy(options.identity), clock = monotonicClock(options.clock);
  const requestSeconds = positive(options.requestSeconds), maxResponseBytes = positive(options.maxResponseBytes);
  decode(options.sessionId, 32);
  if (typeof options.send !== 'function' || typeof options.lease !== 'function') reject();
  const send = options.send, lease = options.lease, sessionId = options.sessionId;
  async function request(operation) {
    const authority = await verifyAuthority(identity.authority, trust, clock());
    const issuedAt = clock(), expiresAt = Math.min(issuedAt + requestSeconds, authorityExpiry(authority));
    const value = { version: 1, ...authority, sessionId, requestId: encode(random(32)), issuedAt, expiresAt,
      operation: structuredClone(operation), signature: '' };
    value.signature = await signing(identity, discoveryRequestBytes(value));
    fresh(value, clock());
    const response = await send(value);
    if (!response || typeof response !== 'object' || json(response).length > maxResponseBytes) reject();
    return response;
  }
  return Object.freeze({
    async publish(publication) {
      const response = await request({ kind: 'publish', publication: structuredClone(publication), lease: await lease() });
      exact(response, ['kind']); if (response.kind !== 'updated') reject();
    },
    async fetch(memberId) {
      decode(memberId, 32);
      const response = await request({ kind: 'fetch', memberId });
      exact(response, ['kind', 'publication']); if (response.kind !== 'profile' || !response.publication) reject();
      return response.publication;
    },
    async query({ filters, limit, after = null }) {
      positive(limit);
      const response = await request({ kind: 'query', filters: structuredClone(filters), limit, after });
      exact(response, ['kind', 'entries', 'nextCursor']); if (response.kind !== 'page' || !Array.isArray(response.entries)) reject();
      return response;
    },
    async heartbeat() {
      const response = await request({ kind: 'heartbeat', lease: await lease() });
      exact(response, ['kind']); if (response.kind !== 'updated') reject();
    },
    async disconnect(sequence) {
      positive(sequence);
      const response = await request({ kind: 'disconnect', leaseId: sessionId, sequence });
      exact(response, ['kind']); if (response.kind !== 'updated') reject();
    },
  });
}
