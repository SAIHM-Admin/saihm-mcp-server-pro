// The client half of the own-cell reads and receipts: a write's receipt carries the origin's commit time, an erasure's
// own line carries the destruction anchor only when the receipt proves it, the version listing is taken whole or not at
// all, and an erasure recorded in the rotated predecessor still keeps a cached copy off the disk.
//
// Runner: npx tsx --test tests/client_own_reads.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { closeSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WireEnvelope } from '@saihm/client-pro';
import { deriveIdentity, toHex } from '@saihm/client-pro';
import { SaihmProClient, SaihmEndpointError, versionListingFrom, MAX_LISTING_PAGE } from '../src/client.ts';

const SEED = new Uint8Array(32).fill(71);
const H = toHex(deriveIdentity(SEED).agentIdHash);
const C1 = '44'.repeat(32);
const ANCHOR = 'A-z.0_9:x';

interface Rig {
  client: SaihmProClient;
  calls: Array<{ method: string; params: Record<string, unknown> }>;
  set: (k: 'rememberAt' | 'forget' | 'list', v: unknown) => void;
  root: string;
  done: () => Promise<void>;
}

async function rig(opts: { recallCachePath?: string } = {}): Promise<Rig> {
  const cells = new Map<string, WireEnvelope>();
  const calls: Rig['calls'] = [];
  const conf: Record<string, unknown> = { rememberAt: undefined, forget: { complete: false }, list: () => ({ mode: 'list', cells: [], next: null }) };
  const server: Server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const { method, params = {} } = JSON.parse(body) as { method: string; params?: Record<string, unknown> };
      calls.push({ method, params });
      const send = (o: unknown) => { const t = JSON.stringify(o); res.writeHead(200, { 'content-type': 'application/json' }).end(t); };
      if (method === 'saihm_remember') {
        const wire = params.wire as WireEnvelope;
        cells.set(wire.cellId, wire);
        return send({ cellId: wire.cellId, shardId: 'ab'.repeat(32), seq: wire.seq, ...(conf.rememberAt !== undefined ? { at: conf.rememberAt } : {}) });
      }
      if (method === 'saihm_recall' && params.listOnly === true) return send((conf.list as (p: unknown) => unknown)(params));
      if (method === 'saihm_recall' && typeof params.cellId === 'string') {
        const wire = cells.get(params.cellId);
        return send(wire ? { found: true, wire } : { found: false });
      }
      if (method === 'saihm_recall') return send([...cells.values()].map((wire) => ({ cellId: wire.cellId, found: true, wire })));
      if (method === 'saihm_forget') return send({ cellId: params.id, shardId: 'ab'.repeat(32), sharesPurged: 0, steps: [], epoch: '1', ...(conf.forget as object) });
      res.writeHead(400).end('{}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const root = mkdtempSync(join(tmpdir(), 'saihm-own-reads-'));
  const client = new SaihmProClient(`http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`, 'Bearer test', SEED, {
    tier: 'PRO', seqStatePath: join(root, 'seq.json'), ...(opts.recallCachePath ? { recallCachePath: opts.recallCachePath } : {}),
  });
  return {
    client, calls, root, set: (k, v) => { conf[k] = v; },
    done: async () => { server.closeAllConnections(); await new Promise<void>((r) => server.close(() => r())); rmSync(root, { recursive: true, force: true }); },
  };
}

/** Run with the erasure feed rooted in `root`, restoring the environment whatever happens. */
async function withFeedRoot<T>(root: string, fn: () => Promise<T>): Promise<T> {
  const was = process.env.SAIHM_ERASURE_FEED_DIR;
  process.env.SAIHM_ERASURE_FEED_DIR = root;
  try { return await fn(); } finally { if (was === undefined) delete process.env.SAIHM_ERASURE_FEED_DIR; else process.env.SAIHM_ERASURE_FEED_DIR = was; }
}

test('a write receipt carries the origin\'s commit time when it is a zoned time, in one UTC form; otherwise null', async () => {
  const r = await rig();
  try {
    const cases: Array<[unknown, string | null]> = [
      ['2026-10-03T09:00:00.000Z', '2026-10-03T09:00:00.000Z'],
      ['2026-10-03T11:00:00.000+02:00', '2026-10-03T09:00:00.000Z'],
      [undefined, null], ['yesterday', null], ['2026-10-03T09:00:00', null], [1759482000000, null], [{}, null], ['x'.repeat(100), null],
    ];
    for (const [given, want] of cases) {
      r.set('rememberAt', given);
      const out = await r.client.remember('hello');
      assert.equal(out.at, want, JSON.stringify(given));
      assert.match(out.commitmentHash, /^[0-9a-f]{64}$/);
    }
  } finally { await r.done(); }
});

test('an own erasure line says complete:true, with the anchor, only when the receipt proves the destruction', async () => {
  const r = await rig();
  try {
    await withFeedRoot(r.root, async () => {
      const cases: Array<[Record<string, unknown>, boolean]> = [
        [{ complete: true, destructionAnchor: ANCHOR }, true],
        [{ complete: true }, false],
        [{ complete: false, destructionAnchor: ANCHOR }, false],
        [{ complete: true, destructionAnchor: 'has space' }, false],
        [{ complete: true, destructionAnchor: '' }, false],
        [{ complete: true, destructionAnchor: 'a'.repeat(257) }, false],
        [{ complete: 'true', destructionAnchor: ANCHOR }, false],
      ];
      for (const [receipt, proven] of cases) {
        r.set('forget', receipt);
        const cellId = `cell-${Math.random().toString(16).slice(2, 10)}`;
        const out = await r.client.forget(cellId);
        assert.equal(out.feedResidual, undefined, JSON.stringify(receipt));
        const lines = readFileSync(join(r.root, 'tenants', H, 'erasures.ndjson'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
        const line = lines.find((l) => l.cellId === cellId);
        assert.ok(line, JSON.stringify(receipt));
        assert.equal(line.complete, proven, JSON.stringify(receipt));
        assert.equal(line.destructionAnchor, proven ? ANCHOR : undefined, JSON.stringify(receipt));
        assert.equal(line.source, 'mcp-client');
      }
    });
  } finally { await r.done(); }
});

test('the version listing: requested alone, paged with after, a null seq kept; a recall answer is not a listing', async () => {
  const r = await rig();
  try {
    r.set('list', (p: { after?: string }) => (p.after === undefined
      ? { mode: 'list', cells: [{ cellId: 'a', seq: '4', commitment: C1 }, { cellId: 'b', seq: null, commitment: C1 }], next: 'b', asOf: '2026-10-03T11:00:00+02:00' }
      : { mode: 'list', cells: [{ cellId: 'c', seq: '1', commitment: C1 }], next: null }));
    const one = await r.client.listVersions();
    assert.deepEqual(one, { cells: [{ cellId: 'a', seq: '4', commitment: C1 }, { cellId: 'b', seq: null, commitment: C1 }], next: 'b', asOf: '2026-10-03T09:00:00.000Z' });
    const two = await r.client.listVersions(one.next!);
    assert.deepEqual(two, { cells: [{ cellId: 'c', seq: '1', commitment: C1 }], next: null });
    assert.deepEqual(r.calls.map((c) => c.params), [{ listOnly: true }, { listOnly: true, after: 'b' }], 'nothing else travels with it');
    r.set('list', () => [{ cellId: 'a', found: false }]);
    await assert.rejects(r.client.listVersions(), (e: unknown) => e instanceof SaihmEndpointError && e.code === 'listing_unsupported');
    r.set('list', () => ({ mode: 'delta', added: [], liveCellIds: [] }));
    await assert.rejects(r.client.listVersions(), (e: unknown) => e instanceof SaihmEndpointError && e.code === 'listing_unsupported');
  } finally { await r.done(); }
});

test('a listing page with anything this client cannot read is refused whole: nothing skipped, nothing cut', () => {
  const ok = { mode: 'list', cells: [{ cellId: 'a', seq: '1', commitment: C1 }], next: null };
  assert.deepEqual(versionListingFrom(ok), { cells: [{ cellId: 'a', seq: '1', commitment: C1 }], next: null });
  const bad: Array<[string, unknown]> = [
    ['no cells', { mode: 'list', next: null }],
    ['cells not a list', { mode: 'list', cells: {}, next: null }],
    ['an entry not an object', { ...ok, cells: ['a'] }],
    ['an empty id', { ...ok, cells: [{ cellId: '', seq: '1', commitment: C1 }] }],
    ['an id too long', { ...ok, cells: [{ cellId: 'x'.repeat(4097), seq: '1', commitment: C1 }] }],
    ['a seq not digits', { ...ok, cells: [{ cellId: 'a', seq: 1, commitment: C1 }] }],
    ['a seq missing', { ...ok, cells: [{ cellId: 'a', commitment: C1 }] }],
    ['a commitment missing', { ...ok, cells: [{ cellId: 'a', seq: '1' }] }],
    ['a commitment null', { ...ok, cells: [{ cellId: 'a', seq: '1', commitment: null }] }],
    ['a commitment upper case', { ...ok, cells: [{ cellId: 'a', seq: '1', commitment: 'AB'.repeat(32) }] }],
    ['a cell twice', { ...ok, cells: [{ cellId: 'a', seq: '1', commitment: C1 }, { cellId: 'a', seq: '2', commitment: C1 }] }],
    ['next missing', { mode: 'list', cells: [] }],
    ['next empty', { mode: 'list', cells: [], next: '' }],
    ['next a number', { mode: 'list', cells: [], next: 5 }],
    ['a page too long', { mode: 'list', cells: Array.from({ length: MAX_LISTING_PAGE + 1 }, (_, i) => ({ cellId: `c${i}`, seq: '1', commitment: C1 })), next: null }],
  ];
  for (const [what, page] of bad) {
    assert.throws(() => versionListingFrom(page), (e: unknown) => e instanceof SaihmEndpointError && e.code === 'malformed_response', what);
  }
  // Boundaries that are fine: the longest id, the longest page, an asOf that is not a time is left out.
  assert.equal(versionListingFrom({ ...ok, cells: [{ cellId: 'x'.repeat(4096), seq: '1', commitment: C1 }] }).cells.length, 1);
  assert.equal(versionListingFrom({ mode: 'list', cells: Array.from({ length: MAX_LISTING_PAGE }, (_, i) => ({ cellId: `c${i}`, seq: null, commitment: C1 })), next: 'c9' }).cells.length, MAX_LISTING_PAGE);
  assert.equal('asOf' in versionListingFrom({ ...ok, asOf: 'soon' }), false);
  assert.throws(() => versionListingFrom('list'), (e: unknown) => e instanceof SaihmEndpointError && e.code === 'malformed_response');
  assert.throws(() => versionListingFrom(null), (e: unknown) => e instanceof SaihmEndpointError && e.code === 'malformed_response');
});

test('an own cell read by id opens and authenticates it; a missing one is null', async () => {
  const r = await rig();
  try {
    const w = await r.client.remember('by id', { cellId: 'note-1' });
    const c = await r.client.recallOne('note-1');
    assert.deepEqual([c?.cellId, c?.plaintext, c?.seq, c?.commitmentHash], ['note-1', 'by id', w.seq, w.commitmentHash]);
    assert.equal(await r.client.recallOne('nothing-here'), null);
  } finally { await r.done(); }
});

test('an erasure recorded only in the rotated predecessor still keeps that cell\'s cached plaintext off the disk', async () => {
  for (const where of ['erasures.ndjson.1', 'nowhere'] as const) {
    const dir = mkdtempSync(join(tmpdir(), 'saihm-own-cache-'));
    try {
      const cachePath = join(dir, 'cache.json');
      const cell = (cellId: string) => ({ cellId, plaintext: `secret ${cellId}`, seq: '1', commitmentHash: 'ab'.repeat(32) });
      writeFileSync(cachePath, JSON.stringify({ gone: cell('gone'), kept: cell('kept') }));
      const feedDir = join(dir, 'tenants', H);
      mkdirSync(feedDir, { recursive: true });
      if (where !== 'nowhere') writeFileSync(join(feedDir, where), `${JSON.stringify({ v: 1, cellId: 'gone', agentIdHash: H, at: '2026-10-03T09:00:00.000Z', complete: false, source: 'server-event' })}\n`);
      await withFeedRoot(dir, async () => {
        const r = await rig({ recallCachePath: cachePath });
        try {
          await r.client.remember('new', { cellId: 'fresh' });
          const onDisk = JSON.parse(readFileSync(cachePath, 'utf8')) as Record<string, unknown>;
          assert.equal('gone' in onDisk, where === 'nowhere', where);
          assert.equal('kept' in onDisk, true, where);
          assert.equal('fresh' in onDisk, true, where);
        } finally { await r.done(); }
      });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
});

test('a feed file rewritten in place to the same inode, size and time is still read again: its first line differs', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-own-reuse-'));
  try {
    const cachePath = join(dir, 'cache.json');
    const cell = (cellId: string) => ({ cellId, plaintext: `secret ${cellId}`, seq: '1', commitmentHash: 'ab'.repeat(32) });
    writeFileSync(cachePath, JSON.stringify({ pp: cell('pp'), kept: cell('kept') }));
    const feedDir = join(dir, 'tenants', H);
    mkdirSync(feedDir, { recursive: true });
    const feed = join(feedDir, 'erasures.ndjson');
    const line = (cellId: string) => `${JSON.stringify({ v: 1, cellId, agentIdHash: H, at: '2026-10-03T09:00:00.000Z', complete: false, source: 'server-event' })}\n`;
    writeFileSync(feed, line('aa'));
    // Whole seconds: the time a coarse clock gives two versions of a file written within one tick.
    const T = 1_759_482_000;
    utimesSync(feed, T, T);
    const before = statSync(feed);
    await withFeedRoot(dir, async () => {
      const r = await rig({ recallCachePath: cachePath });
      try {
        // Another session's erasure lands in a file that looks the same by inode, size and time: what a reused inode
        // after a rotation or a delete looks like to a reader that does not open the file.
        const fd = openSync(feed, 'r+');
        writeSync(fd, line('pp'), 0);
        closeSync(fd);
        utimesSync(feed, T, T);
        const after = statSync(feed);
        assert.deepEqual([after.ino, after.size, after.mtimeMs], [before.ino, before.size, before.mtimeMs], 'the simulation holds');
        await r.client.remember('new', { cellId: 'fresh' });   // a save reads the feed again first
        const onDisk = JSON.parse(readFileSync(cachePath, 'utf8')) as Record<string, unknown>;
        assert.equal('pp' in onDisk, false, 'the erasure in the rewritten file was seen');
        assert.equal('kept' in onDisk, true);
      } finally { await r.done(); }
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
