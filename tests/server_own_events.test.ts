// End to end through the real stdio server, against a local endpoint that speaks the own-cell event wire: the feed asks
// for the own-cell kinds, a write's receipt and its change line agree on seq and commitment, a cell is read back by id,
// the version listing pages, this process's own erasure is recorded once with its anchor, another device's erasure
// arrives as a feed line with its arrival time, the share map's asOf moves, and the lease is held while the process runs
// and gone after it exits. Against an endpoint without the own-cell kinds, the polls and files are as before.
//
// Runner: npx tsx --test tests/server_own_events.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { deriveIdentity, fromHex, toHex } from '@saihm/client-pro';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const MASTER = '5d'.repeat(32);
const H = toHex(deriveIdentity(fromHex(MASTER)).agentIdHash);
const OPERATOR = '0f'.repeat(16);
const ANCHOR = 'ledger:7f.a_1-x';
const SHARE_KINDS = ['share-created', 'shared-cell-updated', 'share-stale', 'share-revoked', 'share-expired', 'shared-cell-erased', 'resync'];
const ISO_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const caps = (own: boolean) => ({
  v: [1], path: '/mcp/events-v1', operator: OPERATOR, maxWaitMs: 25000, maxEvents: 256, maxResponseBytes: 262144, retentionS: 604800,
  maxPollsPerIdentity: 4, minEmptyPollMs: 5000, maxCellIdBytes: 256, kinds: own ? [...SHARE_KINDS, 'cell-written', 'cell-erased'] : SHARE_KINDS,
});

interface Wire { cellId: string; seq: string; publicMeta: { commitmentHash: string } }
interface Ev { pos: number; own: boolean; body: Record<string, unknown> }

/** An endpoint with one identity's log: own-cell events for polls that ask for them, receipts with `at`, the listing. */
function startMock(opts: { own: boolean; receiptsCarryAt: boolean }) {
  const cells = new Map<string, Wire>();
  const log: Ev[] = [];
  const polls: Array<Record<string, unknown>> = [];
  const calls: Array<{ method: string; params: Record<string, unknown> }> = [];
  let subscribed = false, idn = 0;
  const waiting = new Set<() => void>();
  const append = (own: boolean, body: Record<string, unknown>): void => {
    log.push({ pos: log.length + 1, own, body: { id: (++idn).toString(16).padStart(64, '0'), ...body } });
    for (const w of waiting) w();
  };
  const json = (res: ServerResponse, v: unknown, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(v)); };
  const server: Server = createServer((req, res) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => {
      if (req.method === 'GET' && req.url === '/mcp/info') return json(res, { events: caps(opts.own) });
      if (req.method === 'POST' && req.url === '/mcp/events-v1') {
        const b = JSON.parse(buf) as { cursor: string | null; waitMs: number; max: number; kinds?: string[] };
        polls.push(b);
        const wantsOwn = Array.isArray(b.kinds) && b.kinds.includes('cell-written') && b.kinds.includes('cell-erased');
        const head = () => `p${log.length}`;
        if (b.cursor === null) return json(res, { v: 1, operator: OPERATOR, events: [], cursor: head(), more: false, gap: true });
        const from = Number(b.cursor.slice(1));
        // The poll that first names an own-cell kind starts the subscription and answers with a gap.
        const startsSubscription = wantsOwn && !subscribed;
        if (wantsOwn) subscribed = true;
        const answer = () => {
          const events = log.filter((e) => e.pos > from && (wantsOwn || !e.own)).map((e) => e.body);
          json(res, { v: 1, operator: OPERATOR, events, cursor: head(), more: false, gap: startsSubscription });
        };
        if (startsSubscription || log.some((e) => e.pos > from && (wantsOwn || !e.own))) return answer();
        // Hold briefly, answering at once when something is appended.
        let done = false;
        const fire = () => { if (done) return; done = true; waiting.delete(fire); clearTimeout(t); answer(); };
        const t = setTimeout(fire, Math.min(b.waitMs, 250));
        waiting.add(fire);
        res.on('close', () => { done = true; waiting.delete(fire); clearTimeout(t); });
        return;
      }
      const { method, params = {} } = JSON.parse(buf) as { method: string; params?: Record<string, unknown> };
      calls.push({ method, params });
      const at = new Date().toISOString();
      if (method === 'saihm_remember') {
        const wire = params.wire as Wire;
        cells.set(wire.cellId, wire);
        append(true, { kind: 'cell-written', at, cellId: wire.cellId, seq: String(wire.seq), commitment: wire.publicMeta.commitmentHash });
        return json(res, { cellId: wire.cellId, shardId: 'ab'.repeat(32), seq: wire.seq, commitmentHash: wire.publicMeta.commitmentHash, ...(opts.receiptsCarryAt ? { at } : {}) });
      }
      if (method === 'saihm_recall') {
        if (params.sharesOnly === true) return json(res, { mode: 'shares', added: [], liveSharedKeys: [] });
        if (params.listOnly === true) {
          const ids = [...cells.keys()].sort();
          const start = typeof params.after === 'string' ? ids.findIndex((x) => x > (params.after as string)) : 0;
          const page = start < 0 ? [] : ids.slice(start, start + 2);
          const more = start >= 0 && start + 2 < ids.length;
          return json(res, {
            mode: 'list', cells: page.map((id) => ({ cellId: id, seq: String(cells.get(id)!.seq), commitment: cells.get(id)!.publicMeta.commitmentHash })),
            next: more ? page.at(-1) : null, asOf: at,
          });
        }
        if (typeof params.cellId === 'string') {
          const wire = cells.get(params.cellId);
          return json(res, wire ? { found: true, wire } : { found: false });
        }
        return json(res, [...cells.values()].map((wire) => ({ cellId: wire.cellId, found: true, wire })));
      }
      if (method === 'saihm_forget') {
        const id = params.id as string;
        const existed = cells.delete(id);
        const event = { kind: 'cell-erased', at, cellId: id, ...(opts.receiptsCarryAt ? { complete: true, destructionAnchor: ANCHOR } : { complete: false }) };
        json(res, { cellId: id, shardId: 'ab'.repeat(32), complete: true, ...(opts.receiptsCarryAt ? { destructionAnchor: ANCHOR } : {}), sharesPurged: 0, steps: [], epoch: '1' });
        // The event after the receipt, so the client has recorded its own line before the feed reports the erasure. (An
        // event that wins the race against the receipt is written as well: a duplicate line, which a consumer applies
        // twice safely - never a missing one.)
        if (existed) setTimeout(() => append(true, event), 500);
        return;
      }
      return json(res, { error: 'unused' }, 400);
    });
  });
  return {
    server, polls, calls, append, base: () => `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    /** The log position after the latest event (cursors here are `p<position>`). */
    head: () => log.length,
    // Another device of the same identity erases a cell this process never touched.
    remoteErase: (cellId: string) => append(true, { kind: 'cell-erased', at: new Date().toISOString(), cellId, complete: true, destructionAnchor: ANCHOR }),
  };
}

function startServer(endpoint: string, home: string, extra: Record<string, string>) {
  const proc: ChildProcess = spawn(TSX, [SERVER], {
    env: {
      ...process.env, SAIHM_IDENTITY: undefined, SAIHM_IDENTITY_PASSPHRASE: undefined, SAIHM_ERASURE_FEED_DIR: undefined, SAIHM_ERASURE_FEED: undefined,
      SAIHM_ENDPOINT_URL: endpoint, SAIHM_MASTER_SECRET_HEX: MASTER, SAIHM_HOME: home, HOME: home, SAIHM_AUTH_HEADER: 'Bearer test', SAIHM_TIER: 'PRO',
      SAIHM_SELF_JOIN: '0', SAIHM_EVENTS: '', ...extra,
    },
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
  let next = 1;
  const rpc = (method: string, params: unknown): Promise<any> => new Promise((res, rej) => {
    const id = next++;
    waiters.set(id, res);
    proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    // Generous: a server started under a loaded machine takes seconds to answer its first message.
    setTimeout(() => { if (waiters.delete(id)) rej(new Error(`rpc timeout ${method}; stderr=${stderr}`)); }, 90_000);
  });
  const call = async (name: string, args: Record<string, unknown>) => (await rpc('tools/call', { name, arguments: args })).result;
  const exited = new Promise<number | null>((r) => proc.on('exit', (code) => r(code)));
  return { proc, rpc, call, exited, notify: (method: string) => proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method }) + '\n') };
}

/**
 * End a server and wait until the server itself is gone, before its home is removed. SIGTERM: tsx passes it on to the
 * server it runs and exits only once that server has. A SIGKILL ends tsx alone: MEASURED, the server it ran is still
 * running when tsx's exit is reported, and a feed writer that writes in that moment re-creates what the removal is
 * deleting (ENOTEMPTY). SIGKILL only when SIGTERM is not enough.
 */
async function stop(d: ReturnType<typeof startServer>): Promise<void> {
  const ended = (ms: number): Promise<boolean> =>
    Promise.race([d.exited.then(() => true), new Promise<boolean>((r) => setTimeout(() => r(false), ms))]);
  if (d.proc.exitCode !== null || d.proc.signalCode !== null) return;
  d.proc.kill('SIGTERM');
  if (await ended(15_000)) return;
  d.proc.kill('SIGKILL');
  await ended(10_000);
}

async function until(cond: () => boolean, ms: number, what: string): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 25)); }
}
const lines = (path: string): Record<string, unknown>[] => {
  try { return readFileSync(path, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; }
};

async function session(opts: { own: boolean; receiptsCarryAt: boolean; extra?: Record<string, string> }, body: (s: {
  d: ReturnType<typeof startServer>; mock: ReturnType<typeof startMock>; dir: string;
}) => Promise<void>) {
  const mock = startMock(opts);
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-own-e2e-'));
  const d = startServer(mock.base() + '/mcp', home, opts.extra ?? { SAIHM_EVENTS: '1' });
  try {
    await d.rpc('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '0' } });
    d.notify('notifications/initialized');
    await body({ d, mock, dir: join(home, 'tenants', H) });
  } finally {
    // Wait for the process to be gone before removing its home: a write still in flight makes the removal fail.
    await stop(d);
    mock.server.closeAllConnections();
    await new Promise<void>((r) => mock.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
}

test('own-cell events end to end: receipts, change lines, read by id, listing, erasures, liveness and the lease', async () => {
  await session({ own: true, receiptsCarryAt: true }, async ({ d, mock, dir }) => {
    const changes = join(dir, 'changes.ndjson'), erasures = join(dir, 'erasures.ndjson'), map = join(dir, 'share-states.json');
    // The first tool call starts the feed; it asks for the two own-cell kinds and nothing else.
    const a = await d.call('saihm_remember', { content: 'alpha', cellId: 'note-a' });
    assert.equal(a.isError, undefined, JSON.stringify(a));
    await until(() => mock.polls.some((p) => Array.isArray(p.kinds)), 30_000, 'a poll asking for the own-cell kinds');
    for (const p of mock.polls.filter((x) => x.kinds !== undefined)) assert.deepEqual(p.kinds, ['cell-written', 'cell-erased']);
    // The receipt: commitment beside the deprecated commitmentHash, and the origin's commit time.
    const ra = a.structuredContent;
    assert.equal(ra.commitment, ra.commitmentHash);
    assert.match(ra.at, ISO_MS);
    // Its change line carries the same seq and commitment: how a consumer recognises its own write.
    await until(() => lines(changes).some((l) => l.cellId === 'note-a'), 30_000, 'the change line for the write');
    const wa = lines(changes).find((l) => l.cellId === 'note-a')!;
    assert.deepEqual([wa.kind, wa.seq, wa.commitment, wa.at, wa.agentIdHash, wa.source], ['cell-written', ra.seq, ra.commitment, ra.at, H, 'server-event']);
    assert.ok(existsSync(join(dir, 'feed.lock')), 'the lease is held while the process runs');
    // A read by id: the own cell, with its commitment.
    const r = await d.call('saihm_recall', { cellId: 'note-a' });
    assert.equal(r.isError, undefined, JSON.stringify(r));
    assert.match(r.content[0].text, /^RECALL 1 memories\n {2}\[note-a\] seq=1 \| alpha$/);
    assert.deepEqual(r.structuredContent.memories, [{ cellId: 'note-a', seq: ra.seq, plaintext: 'alpha', commitment: ra.commitment }]);
    // A full recall carries the commitment on every own memory too.
    await d.call('saihm_remember', { content: 'beta', cellId: 'note-b' });
    await d.call('saihm_remember', { content: 'gamma', cellId: 'note-c' });
    const all = await d.call('saihm_recall', {});
    assert.equal(all.structuredContent.memories.length, 3);
    for (const m of all.structuredContent.memories) assert.match(m.commitment, /^[0-9a-f]{64}$/);
    // The version listing, in two pages; no content read, and the text lines are marked claims.
    const p1 = await d.call('saihm_recall', { listOnly: true });
    assert.equal(p1.isError, undefined, JSON.stringify(p1));
    assert.deepEqual(p1.structuredContent.cells.map((c: { cellId: string }) => c.cellId), ['note-a', 'note-b']);
    assert.equal(p1.structuredContent.next, 'note-b');
    assert.match(p1.structuredContent.asOf, ISO_MS);
    assert.deepEqual([p1.structuredContent.count, p1.structuredContent.memories], [0, []]);
    assert.match(p1.content[0].text, /^LIST 2 cell version\(s\), no content — more pages follow\n {2}! VERSION cell=note-a seq=1 commit=/);
    const p2 = await d.call('saihm_recall', { listOnly: true, after: p1.structuredContent.next });
    assert.deepEqual([p2.structuredContent.cells.map((c: { cellId: string }) => c.cellId), p2.structuredContent.next], [['note-c'], null]);
    assert.deepEqual(mock.calls.filter((c) => c.params.listOnly === true).map((c) => c.params), [{ listOnly: true }, { listOnly: true, after: 'note-b' }]);
    // Refusals before any network call: a listing travels alone, and `after` pages only a listing.
    for (const args of [{ listOnly: true, cellId: 'note-a' }, { listOnly: true, query: 'x' }, { after: 'note-a' }]) {
      const before = mock.calls.length;
      const x = await d.call('saihm_recall', args);
      assert.equal(x.isError, true, JSON.stringify(args));
      assert.equal(mock.calls.length, before, JSON.stringify(args));
    }
    // This process's own erasure: one line, its own, complete with the receipt's anchor; the feed's echo is not written.
    const before = mock.head();
    const f = await d.call('saihm_forget', { id: 'note-c' });
    assert.equal(f.isError, undefined, JSON.stringify(f));
    // The feed's report of the erasure follows the receipt; wait until a position marker covers it.
    await until(() => mock.head() === before + 1, 30_000, 'the erasure event');
    const covered = (pos: number) => lines(changes).some((l) => l.kind === 'position' && Number(String(l.cursor).slice(1)) >= pos);
    await until(() => covered(before + 1), 30_000, 'a position marker past the erasure');
    // Another device erases a cell: a feed line, with the time it arrived.
    mock.remoteErase('note-remote');
    await until(() => lines(erasures).some((l) => l.cellId === 'note-remote'), 30_000, 'the remote erasure line');
    const er = lines(erasures);
    // One line for this process's erasure, its own, complete with the receipt's anchor: the feed's report of it was
    // recognised and not written again. One feed line for the other device's.
    assert.deepEqual(er.map((l) => [l.cellId, l.source, l.complete, l.destructionAnchor]), [
      ['note-c', 'mcp-client', true, ANCHOR],
      ['note-remote', 'server-event', true, ANCHOR],
    ]);
    const remote = er[1];
    assert.match(String(remote.receivedAt), ISO_MS);
    assert.ok(String(remote.receivedAt) >= String(remote.at));
    // Liveness: the map's asOf moves with the answers even when nothing changes.
    const asOf1 = JSON.parse(readFileSync(map, 'utf8')).asOf;
    await until(() => JSON.parse(readFileSync(map, 'utf8')).asOf > asOf1, 30_000, 'the share map asOf to move on empty answers');
    // The change file: a fresh-start gap first (no saved position), every line this identity's, markers carry cursors.
    const ch = lines(changes);
    assert.deepEqual([ch[0].kind, ch[0].reason], ['gap', 'fresh-start']);
    for (const l of ch) assert.equal(l.agentIdHash, H);
    assert.deepEqual(ch.filter((l) => l.kind === 'cell-written').map((l) => l.cellId), ['note-a', 'note-b', 'note-c']);
    // Exit: the process ends by itself, the lease is given up, and nothing temporary is left behind.
    d.proc.stdin!.end();
    const code = await Promise.race([d.exited, new Promise<'hung'>((r) => setTimeout(() => r('hung'), 15_000))]);
    assert.equal(code, 0);
    assert.deepEqual(readdirSync(dir).sort(), ['changes.ndjson', 'erasures.ndjson', 'feed-state.json', 'share-states.json']);
    const state = JSON.parse(readFileSync(join(dir, 'feed-state.json'), 'utf8'));
    assert.equal(state.ownCells, true, `the saved position is covered, so the next process resumes without a gap: ${JSON.stringify({ ...state, entries: undefined, seen: (state.seen ?? []).length })}`);
  });
});

test('an endpoint without the own-cell kinds: polls and files as before; receipts still say what they can', async () => {
  await session({ own: false, receiptsCarryAt: false }, async ({ d, mock, dir }) => {
    const w = await d.call('saihm_remember', { content: 'alpha', cellId: 'note-a' });
    assert.equal(w.structuredContent.commitment, w.structuredContent.commitmentHash);
    assert.equal(w.structuredContent.at, null, 'no time stated, none invented');
    await until(() => mock.polls.length >= 3, 30_000, 'the feed to poll');
    for (const p of mock.polls) assert.deepEqual(Object.keys(p), ['v', 'cursor', 'waitMs', 'max'], 'not one poll names a kind');
    const f = await d.call('saihm_forget', { id: 'note-a' });
    assert.equal(f.isError, undefined);
    const er = lines(join(dir, 'erasures.ndjson'));
    assert.deepEqual(er.map((l) => [l.cellId, l.source, l.complete, 'destructionAnchor' in l]), [['note-a', 'mcp-client', false, false]]);
    d.proc.stdin!.end();
    const code = await Promise.race([d.exited, new Promise<'hung'>((r) => setTimeout(() => r('hung'), 15_000))]);
    assert.equal(code, 0);
    assert.deepEqual(readdirSync(dir).sort(), ['erasures.ndjson', 'feed-state.json', 'share-states.json'], 'no change file, no lease');
    assert.equal('ownCells' in JSON.parse(readFileSync(join(dir, 'feed-state.json'), 'utf8')), false);
  });
});

test('without SAIHM_EVENTS=1 nothing polls, even against an endpoint offering the own-cell kinds', async () => {
  await session({ own: true, receiptsCarryAt: true, extra: {} }, async ({ d, mock, dir }) => {
    const w = await d.call('saihm_remember', { content: 'alpha', cellId: 'note-a' });
    assert.match(w.structuredContent.at, ISO_MS);
    await new Promise((r) => setTimeout(r, 1_000));
    assert.equal(mock.polls.length, 0);
    assert.equal(existsSync(join(dir, 'changes.ndjson')) || existsSync(join(dir, 'feed.lock')), false);
    d.proc.stdin!.end();
    await Promise.race([d.exited, new Promise((r) => setTimeout(r, 15_000))]);
  });
});

test('a second process of the identity waits: it reports the writer\'s map, records its own erasures, and takes over', async () => {
  const mockA = startMock({ own: true, receiptsCarryAt: true });
  const mockB = startMock({ own: true, receiptsCarryAt: true });
  for (const m of [mockA, mockB]) await new Promise<void>((r) => m.server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-own-two-'));
  const dir = join(home, 'tenants', H);
  const a = startServer(mockA.base() + '/mcp', home, { SAIHM_EVENTS: '1' });
  let b: ReturnType<typeof startServer> | undefined;
  try {
    for (const d of [a]) {
      await d.rpc('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '0' } });
      d.notify('notifications/initialized');
    }
    await a.call('saihm_remember', { content: 'from a', cellId: 'note-a' });
    await until(() => existsSync(join(dir, 'feed.lock')) && lines(join(dir, 'changes.ndjson')).some((l) => l.cellId === 'note-a'), 30_000, 'the first process to write');
    b = startServer(mockB.base() + '/mcp', home, { SAIHM_EVENTS: '1' });
    await b.rpc('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '0' } });
    b.notify('notifications/initialized');
    await b.call('saihm_remember', { content: 'from b', cellId: 'note-b' });
    // The second process reads the offer, finds the lease held, and waits: no poll reaches its endpoint.
    await new Promise((r) => setTimeout(r, 2_000));
    assert.equal(mockB.polls.length, 0, 'the waiting process does not poll');
    // Its share map is the writer's, read from the file the writer keeps current.
    const fromB = (await b.call('saihm_recall', {})).structuredContent.shareStates;
    const file = JSON.parse(readFileSync(join(dir, 'share-states.json'), 'utf8'));
    assert.ok(file.asOf !== null);
    assert.ok(fromB.asOf <= file.asOf && fromB.asOf !== null, `the writer's map, not an empty one: ${JSON.stringify(fromB)}`);
    assert.equal(fromB.startedAt, file.startedAt, 'the writer\'s, not this process\'s');
    // Its own erasure is still recorded by itself, at once.
    const f = await b.call('saihm_forget', { id: 'note-b' });
    assert.equal(f.isError, undefined);
    assert.deepEqual(lines(join(dir, 'erasures.ndjson')).filter((l) => l.cellId === 'note-b').map((l) => [l.source, l.complete]), [['mcp-client', true]]);
    // The writer stops; the waiting process takes over from the position the writer saved, with no fresh-start gap.
    a.proc.stdin!.end();
    assert.equal(await Promise.race([a.exited, new Promise<'hung'>((r) => setTimeout(() => r('hung'), 15_000))]), 0);
    const saved = JSON.parse(readFileSync(join(dir, 'feed-state.json'), 'utf8'));
    assert.equal(saved.ownCells, true);
    await until(() => mockB.polls.length > 0, 45_000, 'the second process to take over');
    assert.equal(mockB.polls[0].cursor, saved.cursor, 'it resumes from the saved position');
    assert.deepEqual(mockB.polls[0].kinds, ['cell-written', 'cell-erased']);
    assert.equal(lines(join(dir, 'changes.ndjson')).filter((l) => l.reason === 'fresh-start').length, 1, 'only the first writer started fresh');
  } finally {
    // Both gone before the home is removed: the second process is the feed's writer by now (see stop).
    await stop(a);
    if (b) await stop(b);
    for (const m of [mockA, mockB]) { m.server.closeAllConnections(); await new Promise<void>((r) => m.server.close(() => r())); }
    rmSync(home, { recursive: true, force: true });
  }
});

test('with the erasure feed off, the own-cell kinds are never asked for, and neither a change file nor the share map is written', async () => {
  // The share map is the own-cell files' heartbeat while the endpoint offers those kinds: only their writer writes it.
  await session({ own: true, receiptsCarryAt: true, extra: { SAIHM_EVENTS: '1', SAIHM_ERASURE_FEED: '0' } }, async ({ d, mock, dir }) => {
    await d.call('saihm_remember', { content: 'alpha', cellId: 'note-a' });
    await until(() => mock.polls.length >= 3, 30_000, 'the feed to poll');
    for (const p of mock.polls) assert.deepEqual(Object.keys(p), ['v', 'cursor', 'waitMs', 'max']);
    d.proc.stdin!.end();
    await Promise.race([d.exited, new Promise((r) => setTimeout(r, 15_000))]);
    assert.deepEqual(readdirSync(dir).sort(), ['feed-state.json']);
  });
});

test('an own erasure whose line could not be written is not mistaken for one already recorded: the feed\'s report is written', async () => {
  await session({ own: true, receiptsCarryAt: true }, async ({ d, mock, dir }) => {
    const erasures = join(dir, 'erasures.ndjson');
    await d.call('saihm_remember', { content: 'x', cellId: 'note-x' });
    await until(() => lines(join(dir, 'changes.ndjson')).some((l) => l.cellId === 'note-x'), 30_000, 'the write to be reported');
    // The own line cannot be written: its path is a directory for the moment.
    mkdirSync(erasures);
    const before = mock.head();
    const f = await d.call('saihm_forget', { id: 'note-x' });
    assert.match(f.content[0].text, /erasure feed line could not be written/);
    rmSync(erasures, { recursive: true });
    // The feed's report of the erasure arrives after the receipt. With no own line it is not this process's echo: it
    // becomes a feed line, or, if the path is still a directory when it arrives, a gap marker. Never nothing.
    await until(() => mock.head() === before + 1, 30_000, 'the erasure event');
    const covered = () => lines(join(dir, 'changes.ndjson')).some((l) => l.kind === 'position' && Number(String(l.cursor).slice(1)) >= before + 1);
    await until(covered, 30_000, 'a position marker past the erasure');
    const fed = lines(erasures).filter((l) => l.cellId === 'note-x').map((l) => [l.source, l.complete]);
    const gapped = lines(join(dir, 'changes.ndjson')).some((l) => l.kind === 'gap' && l.reason === 'unwritable-event' && Number(String(l.cursor).slice(1)) >= before + 1);
    assert.ok((fed.length === 1 && fed[0][0] === 'server-event' && fed[0][1] === true) || gapped, `recorded neither as a line nor as a gap: ${JSON.stringify({ fed, gapped })}`);
  });
});
