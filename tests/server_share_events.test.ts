// The share events feed through the real stdio server: with SAIHM_EVENTS=1 the recall result carries `shareStates`
// beside `shared`, the text an agent reads does not change, and the process still exits when the host closes stdin.
// Without it, nothing polls and the key is absent.
//
// Runner: npx tsx --test tests/server_share_events.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const SHARER = 'aa'.repeat(32), GRANT = 'a1'.repeat(32), OPERATOR = '0f'.repeat(16);
// The advertised path, not a guess from the endpoint URL, is what gets polled.
const CAPS = { v: [1], path: '/mcp/events-v1', operator: OPERATOR, maxWaitMs: 25000, maxEvents: 256, maxResponseBytes: 262144, retentionS: 604800, maxPollsPerIdentity: 4, minEmptyPollMs: 5000, maxCellIdBytes: 256 };
const ANN = { shared: true, sharer: SHARER, cellId: 'c1', scope: 'read', expiryEpoch: null };

interface Seen { info: number; polls: Array<string | null>; sharesOnly: number; held: boolean }

/** An operator that offers the feed: a start poll, one share-created event, then a poll that waits. */
function startMock(): { server: Server; seen: Seen; base: () => string } {
  const seen: Seen = { info: 0, polls: [], sharesOnly: 0, held: false };
  const json = (res: import('node:http').ServerResponse, v: unknown) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(v)); };
  const server = createServer((req, res) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => {
      if (req.method === 'GET' && req.url === '/mcp/info') { seen.info++; return json(res, { events: CAPS }); }
      if (req.method === 'POST' && req.url === CAPS.path) {
        const b = JSON.parse(buf) as { cursor: string | null; waitMs: number };
        seen.polls.push(b.cursor);
        if (b.cursor === null) return json(res, { v: 1, operator: OPERATOR, events: [], cursor: 'c0', more: false, gap: true });
        if (b.cursor === 'c0') {
          return json(res, { v: 1, operator: OPERATOR, cursor: 'c1', more: false, gap: false, events: [
            { id: '01'.repeat(32), kind: 'share-created', at: '2026-09-14T09:00:00.000Z', sharer: SHARER, cellId: 'c1', grant: GRANT, scope: 'read', expiryEpoch: null },
          ] });
        }
        seen.held = true;
        const t = setTimeout(() => json(res, { v: 1, operator: OPERATOR, events: [], cursor: 'c1', more: false, gap: false }), b.waitMs);
        res.on('close', () => clearTimeout(t));
        return;
      }
      const m = JSON.parse(buf) as { method?: string; params?: { sharesOnly?: unknown } };
      if (m.method === 'saihm_recall' && m.params?.sharesOnly === true) {
        seen.sharesOnly++;
        return json(res, { mode: 'shares', added: [{ ...ANN, grant: GRANT, seq: '1', commitment: '44'.repeat(32), stale: false }], liveSharedKeys: [`${SHARER}:c1`] });
      }
      return json(res, m.method === 'saihm_recall' ? [ANN] : { error: 'unused' });
    });
  });
  return { server, seen, base: () => `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

function startServer(endpoint: string, home: string, extra: Record<string, string>) {
  const proc: ChildProcess = spawn(TSX, [SERVER], {
    env: { ...process.env, SAIHM_ENDPOINT_URL: endpoint, SAIHM_MASTER_SECRET_HEX: '44'.repeat(32), SAIHM_HOME: home, SAIHM_AUTH_HEADER: 'Bearer test', SAIHM_TIER: 'PRO', SAIHM_SELF_JOIN: '0', SAIHM_EVENTS: '', ...extra },
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: resolve(HERE, '..'),
  });
  let buf = '', stderr = '';
  const waiters = new Map<number, (m: any) => void>();
  proc.stderr!.on('data', (d) => (stderr += d));
  proc.stdout!.on('data', (d) => {
    buf += d;
    for (let nl = buf.indexOf('\n'); nl >= 0; nl = buf.indexOf('\n')) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      try { const m = JSON.parse(line); if (waiters.has(m.id)) { waiters.get(m.id)!(m); waiters.delete(m.id); } } catch { /* not a message */ }
    }
  });
  const rpc = (id: number, method: string, params: unknown): Promise<any> => new Promise((res, rej) => {
    waiters.set(id, res);
    proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    setTimeout(() => { if (waiters.delete(id)) rej(new Error(`rpc timeout ${method}; stderr=${stderr}`)); }, 15000);
  });
  const exited = new Promise<number | null>((r) => proc.on('exit', (code) => r(code)));
  return { proc, rpc, exited, notify: (method: string) => proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method }) + '\n') };
}

async function until(cond: () => boolean, ms: number, what: string): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 25)); }
}

async function session(extra: Record<string, string>, afterFirst: (seen: Seen) => Promise<void>) {
  const mock = startMock();
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-home-'));
  const d = startServer(mock.base() + '/mcp', home, extra);
  try {
    await d.rpc(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '0' } });
    d.notify('notifications/initialized');
    await d.rpc(2, 'tools/call', { name: 'saihm_recall', arguments: {} });
    await afterFirst(mock.seen);
    const r = await d.rpc(3, 'tools/call', { name: 'saihm_recall', arguments: {} });
    // The host closes stdin; the process must end by itself.
    const t0 = Date.now();
    d.proc.stdin!.end();
    const code = await Promise.race([d.exited, new Promise<'hung'>((res) => setTimeout(() => res('hung'), 5000))]);
    return { text: r.result.content[0].text as string, structured: r.result.structuredContent, seen: mock.seen, code, exitMs: Date.now() - t0 };
  } finally {
    d.proc.kill('SIGKILL');
    mock.server.closeAllConnections();
    await new Promise<void>((r) => mock.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
}

test('SAIHM_EVENTS=1: recall carries shareStates, the text is unchanged, and the process exits when stdin closes', async () => {
  const on = await session({ SAIHM_EVENTS: '1' }, (seen) => until(() => seen.held && seen.sharesOnly > 0, 10000, 'the feed to apply the event and wait'));
  const off = await session({}, async () => { await new Promise((r) => setTimeout(r, 300)); });

  assert.equal(on.text, off.text, 'the feed adds nothing to the text an agent reads');
  assert.deepEqual(on.structured.shared, off.structured.shared, '`shared` keeps its meaning and shape');
  const s = on.structured.shareStates;
  assert.ok(typeof s.since === 'string' && s.complete === true, JSON.stringify(s));
  assert.deepEqual(s.entries, [{
    sharer: SHARER, cellId: 'c1', status: 'live', grant: GRANT, scope: 'read', expiryEpoch: null, seq: null, commitment: null,
    senderVerified: false, endedAt: null, endedBy: null, copiesInvalidBefore: null,
  }]);
  assert.deepEqual([on.seen.info, on.seen.polls.slice(0, 3)], [1, [null, 'c0', 'c1']]);
  assert.equal(on.code, 0, `exit ${on.code} after ${on.exitMs} ms`);

  assert.equal('shareStates' in off.structured, false, 'absent when the feed is not running');
  assert.deepEqual([off.seen.info, off.seen.polls.length, off.seen.sharesOnly], [0, 0, 0], 'nothing polls without the switch');
  assert.equal(off.code, 0);
});
