// The share events feed through the real stdio server: with SAIHM_EVENTS=1 the feed starts with the server, every recall
// carries the `shareStates` summary beside `shared` (its entries only when asked for), the share map file is left for
// other processes, the text an agent reads does not change, and the process still exits when the host closes stdin.
// Without it, nothing polls, the key is absent and no file is written.
//
// Runner: npx tsx --test tests/server_share_events.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const SHARER = 'aa'.repeat(32), GRANT = 'a1'.repeat(32), OPERATOR = '0f'.repeat(16);
// The advertised path, not a guess from the endpoint URL, is what gets polled.
const CAPS = { v: [1], path: '/mcp/events-v1', operator: OPERATOR, maxWaitMs: 25000, maxEvents: 256, maxResponseBytes: 262144, retentionS: 604800, maxPollsPerIdentity: 4, minEmptyPollMs: 5000, maxCellIdBytes: 256 };
const ANN = { shared: true, sharer: SHARER, cellId: 'c1', scope: 'read', expiryEpoch: null };
const ISO_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

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

/** The share map file after the process ended, with its mode, its directory's mode and what else that directory holds. */
function shareMapFile(home: string) {
  try {
    const tenants = join(home, 'tenants');
    const dir = join(tenants, readdirSync(tenants)[0]);
    const f = join(dir, 'share-states.json');
    return { doc: JSON.parse(readFileSync(f, 'utf8')), mode: statSync(f).mode & 0o777, dirMode: statSync(dir).mode & 0o777, names: readdirSync(dir) };
  } catch {
    return null;
  }
}

async function session(extra: Record<string, string>, hooks: { beforeFirst?: (seen: Seen) => Promise<void>; afterFirst: (seen: Seen) => Promise<void> }) {
  const mock = startMock();
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-home-'));
  const d = startServer(mock.base() + '/mcp', home, extra);
  try {
    await d.rpc(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '0' } });
    d.notify('notifications/initialized');
    await hooks.beforeFirst?.(mock.seen);
    const early = { info: mock.seen.info, polls: mock.seen.polls.length, tenants: existsSync(join(home, 'tenants')) };
    await d.rpc(2, 'tools/call', { name: 'saihm_recall', arguments: {} });
    await hooks.afterFirst(mock.seen);
    // With the feed on, the file follows the map while the process runs, not only when it stops.
    let during: ReturnType<typeof shareMapFile> = null;
    if (extra.SAIHM_EVENTS === '1') {
      await until(() => (during = shareMapFile(home))?.doc.counts.live === 1, 5000, 'the share map file to show the share');
    }
    const r = await d.rpc(3, 'tools/call', { name: 'saihm_recall', arguments: {} });
    const withEntries = await d.rpc(4, 'tools/call', { name: 'saihm_recall', arguments: { shareEntries: true } });
    // The host closes stdin; the process must end by itself.
    const t0 = Date.now();
    d.proc.stdin!.end();
    const code = await Promise.race([d.exited, new Promise<'hung'>((res) => setTimeout(() => res('hung'), 5000))]);
    return {
      text: r.result.content[0].text as string, structured: r.result.structuredContent, withEntries: withEntries.result.structuredContent,
      early, during, file: shareMapFile(home), seen: mock.seen, code, exitMs: Date.now() - t0,
    };
  } finally {
    d.proc.kill('SIGKILL');
    mock.server.closeAllConnections();
    await new Promise<void>((r) => mock.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
}

test('SAIHM_EVENTS=1: the feed starts with the server, recall carries the summary, entries on request, and the map file stays', async () => {
  const on = await session({ SAIHM_EVENTS: '1' }, {
    beforeFirst: (seen) => until(() => seen.polls.length > 0, 10000, 'the feed to start before any tool call'),
    afterFirst: (seen) => until(() => seen.held && seen.sharesOnly > 0, 10000, 'the feed to apply the event and wait'),
  });
  const off = await session({}, { afterFirst: async () => { await new Promise((r) => setTimeout(r, 300)); } });

  assert.equal(on.text, off.text, 'the feed adds nothing to the text an agent reads');
  assert.deepEqual(on.structured.shared, off.structured.shared, '`shared` keeps its meaning and shape');
  assert.ok(on.early.polls > 0 && on.early.info === 1, `the feed polled before the first tool call: ${JSON.stringify(on.early)}`);
  const ENTRY = {
    sharer: SHARER, cellId: 'c1', status: 'live', grant: GRANT, scope: 'read', expiryEpoch: null, seq: null, commitment: null,
    senderVerified: false, endedAt: null, endedBy: null, copiesInvalidBefore: null,
  };
  const h = on.structured.shareStates;
  assert.deepEqual(Object.keys(h).sort(), ['asOf', 'complete', 'counts', 'since', 'startedAt', 'stopped'], 'no entries unless asked for');
  assert.deepEqual([h.complete, h.stopped, h.counts], [true, null, { live: 1, stale: 0, ended: 0, erased: 0 }], JSON.stringify(h));
  for (const t of [h.since, h.asOf, h.startedAt]) assert.match(t, ISO_MS);
  assert.ok(h.startedAt <= h.since && h.since <= h.asOf, JSON.stringify(h));
  const { entries, ...header } = on.withEntries.shareStates;
  assert.deepEqual(entries, [ENTRY]);
  assert.deepEqual(header, h, 'the same summary, with the entries added');
  assert.deepEqual([on.seen.info, on.seen.polls.slice(0, 3)], [1, [null, 'c0', 'c1']]);
  assert.equal(on.code, 0, `exit ${on.code} after ${on.exitMs} ms`);

  assert.equal(on.during?.doc.entries.length, 1, 'written while the process ran');
  assert.ok(on.file, 'the share map file is there after the process ended');
  assert.deepEqual([on.file.mode, on.file.dirMode, on.file.names], [0o600, 0o700, ['share-states.json']], 'owner-only, and no lock or temporary file left');
  assert.deepEqual(Object.keys(on.file.doc), ['v', 'since', 'complete', 'asOf', 'stopped', 'startedAt', 'counts', 'entries']);
  assert.deepEqual([on.file.doc.v, on.file.doc.since, on.file.doc.counts, on.file.doc.entries], [1, h.since, h.counts, [ENTRY]]);

  assert.equal('shareStates' in off.structured || 'shareStates' in off.withEntries, false, 'absent when the feed is not running');
  assert.deepEqual([off.seen.info, off.seen.polls.length, off.seen.sharesOnly], [0, 0, 0], 'nothing polls without the switch');
  assert.equal(off.file, null, 'no feed, no file');
  assert.equal(off.early.tenants, false, 'without the switch nothing is built before the first tool call');
  assert.equal(off.code, 0);
});
