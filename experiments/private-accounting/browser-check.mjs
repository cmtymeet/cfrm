// Dedicated bounded CI runner. Existing Chromium, temporary loopback server.
import { createServer } from 'node:http';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { resolve, join, extname, sep } from 'node:path';
import { tmpdir } from 'node:os';

const binary = process.env.BROWSER_BIN;
const fixtureBinary = process.env.ACCOUNTING_FIXTURE;
const evidencePath = process.env.BROWSER_EVIDENCE;
if (!binary || !fixtureBinary || !evidencePath) throw new Error('BROWSER_BIN, ACCOUNTING_FIXTURE, BROWSER_EVIDENCE required');
const root = resolve('dist');
const profile = await mkdtemp(join(tmpdir(), 'cfrm-accounting-'));
const evidence = { source: process.env.CI_COMMIT_SHA, runtime: process.version, ok: false,
  fixtureRequests: 0, forbiddenRequests: [], loadedBytes: 0, browserErrors: [] };
let fixture, browser, socket, origin, fixtureWaiting, fixtureTimer, deadline;
let fixtureOutput = '', fixtureStderr = '', stderr = '', enrolled;
const pending = new Map(); let nextId = 1;
const loaded = new Set();
const closed = new WeakMap();
function captureClose(child) { closed.set(child, new Promise(resolve => child.once('close', resolve))); return child; }
function failFixture(error) { fixtureWaiting?.reject(error); fixtureWaiting = undefined; clearTimeout(fixtureTimer); }
function publicCommand(value) {
  const exact = (v, keys) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
  if (value?.action === 'enroll') return exact(value, ['action', 'keys']) && value.keys?.length === 4 && value.keys.every(k =>
    exact(k, ['accountKey', 'secretHash']) && /^[0-9a-f]{128}$/.test(k.accountKey) && /^[0-9a-f]{64}$/.test(k.secretHash));
  if (value?.action !== 'verify' || !exact(value, ['action', 'entries']) || value.entries?.length !== 4) return false;
  return value.entries.every(e => exact(e, ['admission', 'authorization', 'accountKey', 'secretHash', 'issuedAt', 'expiresAt', 'signature'])
    && exact(e.admission, ['version', 'issuerKeyId', 'communityId', 'memberId', 'chatPublicKey', 'policyDigest', 'issuedAt', 'expiresAt', 'signature'])
    && exact(e.authorization, ['version', 'communityId', 'memberId', 'rootPublicKey', 'devicePublicKey', 'issuedAt', 'expiresAt', 'signature']));
}
async function callFixture(value) {
  if (!publicCommand(value) || fixtureWaiting || ++evidence.fixtureRequests > 16) throw new Error('Public fixture request bound');
  const result = new Promise((resolve, reject) => { fixtureWaiting = { resolve, reject }; });
  fixtureTimer = setTimeout(() => failFixture(new Error('Enrollment fixture deadline')), 15_000);
  fixture.stdin.write(JSON.stringify(value) + '\n');
  const response = await result;
  if (value.action === 'enroll' && response.ok) {
    if (enrolled) throw new Error('Enrollment genesis already created');
    enrolled = response.value;
  }
  return response;
}
const server = createServer(async (request, response) => {
  try {
    response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    response.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Security-Policy', "default-src 'none'; connect-src 'self'; worker-src 'self' blob:; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'");
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (pathname === '/fixture') {
      if (request.method !== 'POST' || request.headers.origin !== origin || !request.headers['content-type']?.startsWith('application/json')) { response.writeHead(400).end(); return; }
      const chunks = []; let size = 0;
      for await (const chunk of request) { size += chunk.length; if (size > 65536) { response.writeHead(413).end(); return; } chunks.push(chunk); }
      const result = await callFixture(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(result)); return;
    }
    if (request.method !== 'GET') { response.writeHead(405).end(); return; }
    const file = resolve(root, '.' + (pathname === '/' ? '/index.html' : pathname));
    if (!file.startsWith(root + sep)) { response.writeHead(404).end(); return; }
    const mime = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.json': 'application/json', '.wasm': 'application/wasm', '.bin': 'application/octet-stream', '.dat': 'application/octet-stream' };
    if (!mime[extname(file)]) { response.writeHead(404).end(); return; }
    const data = await readFile(file); evidence.loadedBytes += data.length;
    response.writeHead(200, { 'Content-Type': mime[extname(file)] }).end(data);
  } catch { if (!response.headersSent) response.writeHead(500); response.end(); }
});
server.requestTimeout = 20_000; server.headersTimeout = 20_000;
const command = (method, params = {}) => {
  const id = nextId++; const result = new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
  socket.send(JSON.stringify({ id, method, params })); return result;
};
async function stop(child) {
  if (!child) return;
  let force, bound;
  if (child?.pid && child.exitCode === null && child.signalCode === null) {
    child.kill('SIGTERM'); force = setTimeout(() => child.kill('SIGKILL'), 3000);
  }
  // Even a child with exitCode set can still own its profile until 'close'.
  try { await Promise.race([closed.get(child), new Promise((_, reject) => { bound = setTimeout(() => reject(new Error('Child close deadline')), 10_000); })]); }
  finally { clearTimeout(force); clearTimeout(bound); }
}
try {
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); origin = `http://127.0.0.1:${server.address().port}`;
  fixture = captureClose(spawn(fixtureBinary, [], { stdio: ['pipe', 'pipe', 'pipe'] }));
  fixture.on('error', error => failFixture(error)); fixture.stdin.on('error', error => failFixture(error));
  fixture.stderr.on('data', chunk => { fixtureStderr = (fixtureStderr + chunk).slice(-4096); });
  fixture.stdout.on('data', chunk => {
    fixtureOutput += chunk;
    if (fixtureOutput.length > 65536) { failFixture(new Error('Fixture output bound')); return; }
    const newline = fixtureOutput.indexOf('\n'); if (newline < 0) return;
    try {
      const reply = JSON.parse(fixtureOutput.slice(0, newline)); fixtureOutput = fixtureOutput.slice(newline + 1);
      if (!fixtureWaiting || typeof reply.ok !== 'boolean') throw new Error('Unexpected fixture reply');
      clearTimeout(fixtureTimer); const waiting = fixtureWaiting; fixtureWaiting = undefined; waiting.resolve(reply);
    } catch (error) { failFixture(error); }
  });
  browser = captureClose(spawn(binary, ['--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking',
    '--disable-component-update', '--no-first-run', '--no-default-browser-check', '--disable-extensions',
    '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'],
  { stdio: ['ignore', 'ignore', 'pipe'] }));
  let launchError; browser.on('error', error => { launchError = error; });
  browser.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-8000); });
  let port;
  for (let attempt = 0; attempt < 300; attempt++) {
    if (launchError) throw launchError;
    if (browser.exitCode !== null) throw new Error('Browser exited during startup');
    try { port = Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); break; }
    catch { await new Promise(resolve => setTimeout(resolve, 100)); }
  }
  if (!port) throw new Error('Browser startup deadline');
  evidence.browser = (await (await fetch(`http://127.0.0.1:${port}/json/version`)).json()).Browser;
  const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  socket = new WebSocket(pages.find(p => p.type === 'page').webSocketDebuggerUrl); await once(socket, 'open');
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const waiting = pending.get(message.id); if (!waiting) return; pending.delete(message.id);
      if (message.error) waiting.reject(new Error(JSON.stringify(message.error))); else waiting.resolve(message.result);
    } else if (message.method === 'Page.lifecycleEvent' && message.params.name === 'load') {
      loaded.add(message.params.loaderId);
    } else if (message.method === 'Fetch.requestPaused') {
      const { requestId, request } = message.params;
      if (request.url.startsWith(origin + '/') || request.url.startsWith('blob:' + origin + '/')) command('Fetch.continueRequest', { requestId }).catch(() => {});
      else { evidence.forbiddenRequests.push(request.url); command('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' }).catch(() => {}); }
    } else if (message.method === 'Runtime.exceptionThrown') evidence.browserErrors.push(message.params.exceptionDetails.text);
  });
  await command('Runtime.enable'); await command('Page.enable');
  await command('Page.setLifecycleEventsEnabled', { enabled: true });
  await command('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  const navigation = await command('Page.navigate', { url: origin });
  for (let attempt = 0; attempt < 300 && !loaded.has(navigation.loaderId); attempt++) {
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  if (!loaded.has(navigation.loaderId)) throw new Error('Browser navigation deadline');
  const running = command('Runtime.evaluate', { expression: '(async () => { while (!window.accountingDone) await new Promise(r => setTimeout(r, 100)); return await window.accountingDone; })()', awaitPromise: true, returnByValue: true });
  const result = await Promise.race([running, new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('Browser proving deadline (8 minutes)')), 480_000); })]);
  clearTimeout(deadline);
  if (result.exceptionDetails || !result.result?.value) throw new Error('No browser result');
  evidence.contract = result.result.value;
  if (!evidence.contract.ok || evidence.contract.proofs?.length !== 2 || evidence.contract.checks.length < 30) throw new Error('Browser proof contract incomplete');
  if (evidence.forbiddenRequests.length) throw new Error('Unlisted browser network traffic');
  socket.close(); await stop(browser);
  // A separate runtime verifies local pinned VK + public inputs, never witnesses.
  const { verifyResults } = await import('./verify.mjs');
  evidence.independent = await verifyResults(evidence.contract, enrolled);
  evidence.ok = true;
} catch (error) {
  evidence.error = String(error); evidence.stderr = stderr; evidence.fixtureStderr = fixtureStderr;
  if (socket?.readyState === WebSocket.OPEN) {
    try {
      const progress = await Promise.race([command('Runtime.evaluate', { expression: 'window.accountingProgress', returnByValue: true }),
        new Promise(resolve => setTimeout(() => resolve(undefined), 1000))]);
      evidence.partial = progress?.result?.value;
    } catch { /* Failure evidence still retained if renderer crashed. */ }
  }
} finally {
  clearTimeout(deadline); failFixture(new Error('Fixture closed')); socket?.close();
  const cleanupErrors = [];
  for (const child of [browser, fixture]) { try { await stop(child); } catch (error) { cleanupErrors.push(String(error)); } }
  try { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  catch (error) { cleanupErrors.push(String(error)); }
  try { await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); }
  catch (error) { cleanupErrors.push(String(error)); }
  if (cleanupErrors.length) { evidence.ok = false; evidence.cleanupErrors = cleanupErrors; }
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + '\n');
}
process.stdout.write(JSON.stringify({ ok: evidence.ok, checks: evidence.contract?.checks.length, proofBytes: evidence.contract?.proofs.map(p => p.proofBytes), evidence: evidencePath, error: evidence.error }) + '\n');
if (!evidence.ok) process.exitCode = 1;
