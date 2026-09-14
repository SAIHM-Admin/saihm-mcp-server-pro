// The client's share events transport against a mock endpoint: a rejected token is renewed once, and not again within
// the renewal interval, so a token that keeps failing does not keep the onboarding route busy. Stopping the feed ends
// the poll in flight.
//
// Runner: npx tsx --test tests/client_share_events_transport.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const HOME = mkdtempSync(join(tmpdir(), 'saihm-home-'));
process.env.SAIHM_HOME = HOME;
process.env.SAIHM_ERASURE_FEED_DIR = mkdtempSync(join(tmpdir(), 'saihm-feed-'));
process.on('exit', () => { rmSync(HOME, { recursive: true, force: true }); rmSync(process.env.SAIHM_ERASURE_FEED_DIR!, { recursive: true, force: true }); });

const { SaihmProClient } = await import('../src/client.js');
const { deriveIdentity, sealCell, shareCell, encodeEnvelope, encodeShareEnvelope, encodeIdentityRecord, toHex } = await import('@saihm/client-pro');
const CAPS = { v: [1], path: '/mcp/events', operator: '0f'.repeat(16), maxWaitMs: 25000, maxEvents: 256, maxResponseBytes: 262144, retentionS: 604800, maxPollsPerIdentity: 4, minEmptyPollMs: 5000, maxCellIdBytes: 256 };
const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');

test('a 401 from the events route renews the token once, then not again within the interval', async () => {
  let onboards = 0, polls = 0;
  const server: Server = createServer((req, res) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => {
      const send = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
      if (req.method === 'GET' && req.url === '/api/onboard/challenge') return send(200, { nonce: randomBytes(32).toString('hex') });
      if (req.method === 'POST' && req.url === '/api/onboard') {
        onboards++;
        return send(201, { jwt: `${b64url({ alg: 'EdDSA' })}.${b64url({ sub: '00'.repeat(32), tier: 'PRO', exp: Math.floor(Date.now() / 1000) + 3600 })}.s${onboards}` });
      }
      if (req.method === 'GET' && req.url === '/mcp/info') return send(200, { events: CAPS });
      if (req.method === 'POST' && req.url === '/mcp/events') { polls++; return send(401, { error: 'unauthorized' }); }
      return send(200, []);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const client = new SaihmProClient(base + '/mcp', undefined, new Uint8Array(32).fill(71), { tier: 'PRO', paymentMethod: 'stripe' });
  try {
    client.startShareEvents();
    const end = Date.now() + 8000;
    while (polls < 3 && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
    assert.ok(polls >= 3, `polls ${polls}`);
    // Time for a renewal and its retry, well inside the feed's own backoff before the next poll.
    await new Promise((r) => setTimeout(r, 500));
    assert.deepEqual([onboards, polls], [2, 3], 'the first token, and one renewal after its 401; the next 401 waits for the interval');
    const t0 = Date.now();
    await client.stopShareEvents();
    assert.ok(Date.now() - t0 < 1000);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test('a shared read that fails to open marks the share stale; a verified read marks its sender verified', async () => {
  const A = deriveIdentity(new Uint8Array(32).fill(91)), B_SEED = new Uint8Array(32).fill(92), B = deriveIdentity(B_SEED);
  const seal = (seq: bigint, text: string) => sealCell({ plaintext: new TextEncoder().encode(text), kek: A.kek, mldsaSecretKey: A.mldsaSecretKey, mldsaPubKey: A.mldsaPubKey, agentIdHash: A.agentIdHash, cellId: 'doc', seq, tier: 'PRO' });
  const v1 = seal(1n, 'one'), v2 = seal(2n, 'two');
  const shareV1 = encodeShareEnvelope(shareCell({ envelope: v1, sharerKek: A.kek, sharerMldsaSecretKey: A.mldsaSecretKey, sharerAgentIdHash: A.agentIdHash, recipientRecord: B.identityRecord, recipientPinnedAgentIdHash: B.agentIdHash }));
  const sharer = toHex(A.agentIdHash), grant = 'a1'.repeat(32);
  let content = encodeEnvelope(v2);   // the key envelope wraps version 1, the stored cell is version 2
  const server: Server = createServer((req, res) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => {
      const send = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
      if (req.method === 'GET' && req.url === '/mcp/info') return send(200, { events: CAPS });
      if (req.method === 'POST' && req.url === '/mcp/events') {
        const b = JSON.parse(buf) as { cursor: string | null; waitMs: number };
        if (b.cursor === null) return send(200, { v: 1, operator: CAPS.operator, events: [], cursor: 'c0', more: false, gap: true });
        if (b.cursor === 'c0') return send(200, { v: 1, operator: CAPS.operator, cursor: 'c1', more: false, gap: false, events: [{ id: '01'.repeat(32), kind: 'share-created', at: '2026-09-14T09:00:00.000Z', sharer, cellId: 'doc', grant, scope: 'read', expiryEpoch: null }] });
        const t = setTimeout(() => send(200, { v: 1, operator: CAPS.operator, events: [], cursor: 'c1', more: false, gap: false }), b.waitMs);
        res.on('close', () => clearTimeout(t));
        return;
      }
      const m = JSON.parse(buf) as { method?: string; params?: Record<string, unknown> };
      if (m.method === 'saihm_recall' && m.params?.sharesOnly === true) return send(200, { mode: 'shares', added: [{ shared: true, sharer, cellId: 'doc', scope: 'read', expiryEpoch: null, grant }], liveSharedKeys: [`${sharer}:doc`] });
      if (m.method === 'saihm_recall' && m.params?.sharer === sharer) return send(200, { found: true, wire: shareV1, contentWire: content });
      return send(200, []);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const client = new SaihmProClient(`http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`, 'Bearer t', B_SEED, { tier: 'PRO' });
  const entry = () => client.shareStates()?.entries.find((e) => e.cellId === 'doc');
  try {
    client.startShareEvents();
    const end = Date.now() + 8000;
    while (entry()?.grant !== grant && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
    assert.equal(entry()?.status, 'live');
    const read = { sharerPinnedAgentIdHashHex: sharer, sharerRecord: encodeIdentityRecord(A.identityRecord), cellId: 'doc' };
    await assert.rejects(client.recallShared(read), (e: unknown) => (e as { code?: string }).code === 'undecryptable');
    assert.deepEqual([entry()?.status, entry()?.senderVerified], ['stale', false]);
    // The file follows the map: wait until it shows the stale share, so no write is still pending.
    const mapFile = join(process.env.SAIHM_ERASURE_FEED_DIR!, 'tenants', toHex(B.agentIdHash), 'share-states.json');
    const fileEntry = () => { try { return JSON.parse(readFileSync(mapFile, 'utf8')).entries.find((e: { cellId: string }) => e.cellId === 'doc'); } catch { return undefined; } };
    const until = Date.now() + 5000;
    while (fileEntry()?.status !== 'stale' && Date.now() < until) await new Promise((r) => setTimeout(r, 20));
    assert.equal(fileEntry()?.status, 'stale');
    content = encodeEnvelope(v1);
    const cell = await client.recallShared(read);
    assert.equal(cell?.plaintext, 'one');
    assert.equal(entry()?.senderVerified, true);
    // Stopping right after a change still writes it.
    await client.stopShareEvents();
    assert.equal(fileEntry()?.senderVerified, true);
  } finally {
    await client.stopShareEvents();
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test('the info route: a non-success answer is tried again within seconds; a route that does not exist parks the feed', async () => {
  for (const status of [503, 404]) {
    let infos = 0;
    const server: Server = createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        if (req.method === 'GET' && req.url === '/mcp/info') {
          infos++;
          if (infos === 1 || status === 404) { res.writeHead(status, { 'content-type': 'application/json' }); return res.end('{}'); }
          res.writeHead(200, { 'content-type': 'application/json' });
          return res.end(JSON.stringify({ events: CAPS }));
        }
        res.writeHead(503, { 'content-type': 'application/json' });
        res.end('{}');
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const client = new SaihmProClient(base + '/mcp', 'Bearer t', new Uint8Array(32).fill(73), { tier: 'PRO', paymentMethod: 'stripe' });
    try {
      client.startShareEvents();
      if (status === 503) {
        const end = Date.now() + 6000;
        while (infos < 2 && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
        assert.equal(infos, 2, 'retried after the 503, well within a day');
        assert.equal(client.shareStates()?.stopped, null);
      } else {
        await new Promise((r) => setTimeout(r, 300));
        assert.deepEqual([infos, client.shareStates()?.stopped, client.shareStates()?.complete], [1, 'unsupported', false]);
      }
    } finally {
      await client.stopShareEvents();
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    }
  }
});
