import { hex, sha } from './encoding.mjs';

export const DEFAULT_LIMITS = Object.freeze({ maxArtifactBytes: 64 * 1024 * 1024,
  maxTotalBytes: 128 * 1024 * 1024, maxProofBytes: 1024 * 1024, memoryPages: 32768 });
export function resourceLimits(input = {}) {
  const value = { ...DEFAULT_LIMITS, ...input };
  if (Object.keys(value).some(key => !Object.hasOwn(DEFAULT_LIMITS, key))
      || Object.entries(value).some(([key, n]) => !Number.isSafeInteger(n) || n <= 0 || n > DEFAULT_LIMITS[key])
      || value.memoryPages < 2048) throw new Error('Invalid account resource limits');
  return Object.freeze(value);
}

// manifestSha256 comes from the application release pin, not the download.
// readArtifact sees only these fixed names. No artifact contains a private witness.
export async function loadArtifacts({ manifestBytes, manifestSha256, readArtifact, limits = {} }) {
  const bound = resourceLimits(limits);
  if (!(manifestBytes instanceof Uint8Array) || manifestBytes.length > 1024 * 1024
      || !/^[0-9a-f]{64}$/.test(manifestSha256)
      || hex(await sha(manifestBytes)) !== manifestSha256) throw new Error('Manifest pin mismatch');
  const manifest = JSON.parse(new TextDecoder().decode(manifestBytes));
  if (manifest.accountingMode !== 'account-state-v2' || manifest.hashScheme !== 'poseidon2-bn254-fixed-128-v1'
      || !Number.isSafeInteger(manifest.numPoints) || manifest.numPoints <= 0 || manifest.numPoints > 9 * 131072
      || !Array.isArray(manifest.setup) || manifest.setup.length !== 2) throw new Error('Unsupported account artifacts');
  let total = manifestBytes.length;
  async function read(name, digest, length) {
    if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error('Missing artifact pin');
    const data = await readArtifact(name, bound.maxArtifactBytes);
    if (!(data instanceof Uint8Array) || data.length > bound.maxArtifactBytes
        || (length !== undefined && data.length !== length)) throw new Error('Artifact size bound');
    total += data.length;
    if (total > bound.maxTotalBytes || hex(await sha(data)) !== digest) throw new Error('Artifact digest/total bound');
    return data.slice();
  }
  const circuitBytes = await read('circuit.json', manifest.circuitSha256);
  const verificationKey = await read('vk.bin', manifest.vkSha256);
  const circuit = JSON.parse(new TextDecoder().decode(circuitBytes));
  if (typeof circuit.bytecode !== 'string' || !circuit.bytecode.length) throw new Error('Missing compiled circuit');
  const setup = {};
  for (const item of manifest.setup) {
    if (!['g1.dat', 'g2.dat'].includes(item.name) || Object.hasOwn(setup, item.name)
        || !Number.isSafeInteger(item.bytes) || item.bytes <= 0) throw new Error('Invalid setup manifest');
    setup[item.name] = await read('setup/' + item.name, item.sha256, item.bytes);
  }
  if (setup['g1.dat'].length !== manifest.numPoints * 32) throw new Error('Setup point count mismatch');
  return { manifest, circuit, verificationKey, setup, limits: bound };
}

/** Explicit caller-selected artifact URL; enforces streaming bounds before allocation. */
export function artifactFetcher(base, fetchImpl = globalThis.fetch) {
  const root = new URL(base);
  return async (name, maximum) => {
    if (!['manifest.json','circuit.json','vk.bin','setup/g1.dat','setup/g2.dat'].includes(name)) throw new Error('Artifact name');
    const response = await fetchImpl(new URL(name, root), { redirect: 'error', credentials: 'omit' });
    if (!response.ok || !response.body) throw new Error('Artifact fetch failed');
    const reader = response.body.getReader(), chunks = []; let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read(); if (done) break;
        size += value.length; if (size > maximum) throw new Error('Artifact download bound'); chunks.push(value);
      }
    } catch (error) { await reader.cancel(); throw error; }
    const data = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.length; }
    return data;
  };
}
