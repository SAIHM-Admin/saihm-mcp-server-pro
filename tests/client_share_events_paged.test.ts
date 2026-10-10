// The share events feed reconciling by pages: a complete pass ends the keys it does not hold, an incomplete one ends
// nothing, a pass is dated when its first page was requested, events that happen during a pass are applied after it, a
// mismatched end asks for one more pass spaced by the last one's length, and where the endpoint does not page (or stops
// paging mid-pass, or its status cannot be read) the one-answer listing is read as before.
//
// Runner: npx tsx --test tests/client_share_events_paged.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const HOME = mkdtempSync(join(tmpdir(), 'saihm-home-'));
process.env.SAIHM_HOME = HOME;
process.env.SAIHM_ERASURE_FEED_DIR = mkdtempSync(join(tmpdir(), 'saihm-feed-'));
process.env.SAIHM_SHARE_MAP_STORE = 'off';
process.on('exit', () => { rmSync(HOME, { recursive: true, force: true }); rmSync(process.env.SAIHM_ERASURE_FEED_DIR!, { recursive: true, force: true }); });

const { ShareEventsFeed } = await import('../src/share-events.js');
const { SaihmProClient, sharesPass } = await import('../src/client.js');
type EventsCapability = import('../src/share-events.js').EventsCapability;
type PollAnswer = import('../src/share-events.js').PollAnswer;
type PollBody = import('../src/share-events.js').PollBody;
type SharesPass = import('../src/share-events.js').SharesPass;
type ListingEntry = import('../src/share-events.js').ListingEntry;
type SharesPage = import('../src/client.js').SharesPage;

const S = '11'.repeat(32), S2 = '12'.repeat(32), G1 = 'a1'.repeat(32), G2 = 'a2'.repeat(32), G9 = 'a9'.repeat(32);
const CAPS: EventsCapability = { v: [1], path: '/mcp/events', operator: '0f'.repeat(16), maxWaitMs: 25000, maxEvents: 256, maxResponseBytes: 262144, retentionS: 604800, maxPollsPerIdentity: 4, minEmptyPollMs: 5000, maxCellIdBytes: 256 };
let idn = 0;
const id = (): string => (++idn).toString(16).padStart(64, '0');
const ev = (kind: string, extra: Record<string, unknown> = {}) => ({ id: id(), kind, at: '2026-10-09T09:00:00.000Z', sharer: S, cellId: 'doc', grant: G1, ...extra });
const ok = (events: unknown[], extra: Record<string, unknown> = {}): PollAnswer => ({ status: 200, body: { v: 1, operator: CAPS.operator, events, cursor: `c${++idn}`, more: false, gap: false, ...extra } });
const entry = (sharer: string, cellId: string, grant: string | null = G1): ListingEntry =>
  ({ sharer, cellId, scope: 'read', expiryEpoch: null, grant, seq: null, commitment: null, stale: null });
const T0 = Date.UTC(2026, 9, 9, 9);
const iso = (t: number): string => new Date(t).toISOString();

type PassStep = { entries: ListingEntry[]; complete: boolean; pages?: number; incomplete?: SharesPass['incomplete']; tookMs?: number } | null
  | ((bounds: { maxEntries: number; now: () => number }, signal: AbortSignal) => Promise<SharesPass | null>);

/** A scripted operator: poll answers in turn, and a pass (or null, for "not offered") for each reconciliation. */
function scripted(answers: PollAnswer[], passes: PassStep[], listings: unknown[] = [], opts: { step?: number } = {}) {
  const passAt: number[] = [];
  const passStarts: number[] = [];
  let listingCalls = 0;
  let clock = T0;
  let done!: () => void;
  const finished = new Promise<void>((r) => (done = r));
  const transport = {
    info: async () => CAPS,
    poll: async (_path: string, _body: PollBody) => {
      await new Promise((r) => setImmediate(r));
      clock += opts.step ?? 30_000;
      const a = answers.shift();
      if (!a) { done(); throw new Error('script over'); }
      return a;
    },
    listing: async () => { listingCalls++; return listings.length ? listings.shift() : null; },
    pass: async (signal: AbortSignal, bounds: { maxEntries: number; now: () => number }): Promise<SharesPass | null> => {
      passAt.push(clock);
      const step = passes.shift();
      if (typeof step === 'function') return step(bounds, signal);
      if (!step) return null;
      // A pass dated at its start, which then takes `tookMs` of the feed's clock.
      const startedAt = bounds.now();
      passStarts.push(startedAt);
      clock += step.tookMs ?? 0;
      return {
        complete: step.complete, entries: step.entries, pages: step.pages ?? 1, startedAt,
        ...(step.complete ? {} : { incomplete: step.incomplete ?? 'pages' }),
      };
    },
  };
  const sleeps: number[] = [];
  return {
    transport, passAt, passStarts, finished, listingCalls: () => listingCalls,
    make: (extra: Record<string, unknown> = {}) => new ShareEventsFeed({
      transport, now: () => clock, random: () => 0.5, minWaitMs: 1,
      sleep: async (ms: number, signal: AbortSignal) => { sleeps.push(ms); await new Promise((r) => setImmediate(r)); if (!signal.aborted && answers.length === 0 && sleeps.length > 50) done(); },
      ...extra,
    }),
  };
}
async function run(feed: InstanceType<typeof ShareEventsFeed>, finished: Promise<void>) { feed.start(); await finished; await feed.stop(); }
const byCell = (feed: InstanceType<typeof ShareEventsFeed>) => Object.fromEntries(feed.snapshot().entries.map((e) => [e.cellId, e]));

test('a complete pass ends the keys it does not hold, dated at its first page; an incomplete pass ends nothing', async () => {
  const sc = scripted(
    [ok([], { gap: true }), ok([], { gap: true }), ok([])],
    [
      { entries: [entry(S, 'a'), entry(S, 'b')], complete: true },
      { entries: [entry(S, 'a')], complete: false, incomplete: 'pages' },
      { entries: [entry(S, 'a')], complete: true, pages: 3, tookMs: 300_000 },
    ],
    [],
    { step: 200_000 },
  );
  const feed = sc.make();
  let afterSecond: Record<string, unknown> | undefined;
  const orig = sc.transport.pass;
  let n = 0;
  sc.transport.pass = async (signal, bounds) => {
    if (++n === 3) afterSecond = { b: byCell(feed).b?.status, complete: feed.snapshot().complete };
    return orig(signal, bounds);
  };
  await run(feed, sc.finished);
  assert.equal(sc.passAt.length, 3);
  assert.equal(sc.listingCalls(), 0, 'the one-answer listing is not read while the endpoint pages');
  assert.deepEqual(afterSecond, { b: 'live', complete: false }, 'the incomplete pass ended nothing and left the map incomplete');
  const b = byCell(feed).b!;
  assert.deepEqual([b.status, b.endedBy], ['ended', 'reconciliation']);
  const started = sc.passStarts[2]!;
  assert.equal(b.endedAt, iso(started), 'dated when the first page was requested...');
  assert.equal(b.copiesInvalidBefore, iso(started));
  assert.notEqual(b.endedAt, iso(started + 300_000), '...not when the pass ended');
  assert.equal(feed.snapshot().complete, true);
  assert.equal(byCell(feed).a!.status, 'live');
});

test('no pass (not offered, or paging switched off mid-pass): the one-answer listing, in the same reconciliation', async () => {
  const listing = { mode: 'shares', added: [{ shared: true, sharer: S, cellId: 'a', scope: 'read', expiryEpoch: null }], liveSharedKeys: [`${S}:a`] };
  const sc = scripted([ok([], { gap: true })], [null], [listing]);
  const feed = sc.make();
  await run(feed, sc.finished);
  assert.deepEqual([sc.passAt.length, sc.listingCalls()], [1, 1]);
  assert.equal(feed.snapshot().complete, true);
  assert.equal(byCell(feed).a!.status, 'live');
});

test('events after the pass: a revoke and a re-share during it apply after it; a mismatched end asks for one more pass, spaced by its length', async () => {
  const sc = scripted(
    [
      ok([], { gap: true }),
      // During/after the first pass: k revoked (its grant), l re-shared under a new grant, then an end naming no grant held.
      ok([ev('share-revoked', { cellId: 'k' }), ev('share-created', { cellId: 'l', grant: G2, scope: 'read', expiryEpoch: null }), ev('share-revoked', { cellId: 'l', grant: G9 })]),
      ok([]),
      ok([]),
    ],
    [
      { entries: [entry(S, 'k'), entry(S, 'l')], complete: true, pages: 20 },
      { entries: [entry(S, 'l', G2)], complete: true },
    ],
  );
  const feed = sc.make();
  await run(feed, sc.finished);
  const first = sc.passAt[0]!;
  // 20 pages: the next pass waits 40 s. The answer 30 s later carries the mismatched end; the one 60 s later reconciles.
  assert.deepEqual(sc.passAt.map((t) => t - first), [0, 60_000], 'one more pass, after the spacing of a 20-page pass, not at once');
  const m = byCell(feed);
  assert.deepEqual([m.k!.status, m.k!.endedBy], ['ended', 'event'], 'the revoke during the pass applied after it');
  assert.deepEqual([m.l!.status, m.l!.grant], ['live', G2], 'the re-share during the pass carries its new grant');
});

test('the spacing: 10 s after a short pass, 2 s a page after a long one, at most 10 minutes; an incomplete pass waits at least as long', async () => {
  for (const [pages, complete, expected] of [[1, true, 10_000], [5, true, 10_000], [30, true, 60_000], [400, true, 600_000], [100, false, 200_000]] as const) {
    const answers = Array.from({ length: Math.ceil(expected / 5_000) + 5 }, () => ok([], { gap: true }));
    const sc = scripted(answers, [{ entries: [], complete, pages }, { entries: [], complete: true }], [], { step: 5_000 });
    const feed = sc.make();
    await run(feed, sc.finished);
    const gap = sc.passAt[1]! - sc.passAt[0]!;
    // Polls come every 5 s, so the second pass comes at the first poll at or past the wait.
    assert.ok(gap >= expected && gap < expected + 5_000, `${pages} pages, complete ${complete}: ${gap} ms, expected ${expected}`);
  }
});

// ── the pass the client runs, in the feed ─────────────────────────────────────────────────────────────────────────────

/** A transport pass running the client's own pass over scripted pages, timed and dated by the feed's clock. */
const realPass = (pagesOf: (n: number) => SharesPage[]) => {
  let n = 0;
  return async (bounds: { maxEntries: number; now: () => number }, signal: AbortSignal): Promise<SharesPass | null> => {
    const pages = pagesOf(n++);
    let i = 0;
    return sharesPass(async () => pages[i++]!, { maxEntries: bounds.maxEntries, maxPages: 64, deadlineMs: 600_000, now: bounds.now, signal });
  };
};
const page = (cellIds: string[], next: string | null, sharer = S): SharesPage =>
  ({ rows: cellIds.map((cellId) => ({ sharer, cellId, scope: 'read', expiryEpoch: null, grant: G1, seq: null, commitment: null, stale: null })), next });

test('a held key whose cell id is over 64 characters (and within 4,096 bytes) stays live through a complete pass', async () => {
  const long = 'L'.repeat(100);
  // The key is held from an event first; a pass that left it out would END it as possibly erased.
  const sc = scripted([ok([ev('share-created', { cellId: long, scope: 'read', expiryEpoch: null })], { gap: true })], [
    realPass(() => [page([long], 'c1'), page(['z'], null, S2)]),
  ]);
  const feed = sc.make();
  await run(feed, sc.finished);
  const m = byCell(feed);
  assert.equal(sc.passAt.length, 1);
  assert.deepEqual([m[long]?.status, m[long]?.endedBy, m.z?.status], ['live', null, 'live'], 'the field cap of the recall tool never applies to the pass');
  assert.equal(feed.snapshot().complete, true);
});

test('a row over 4,096 bytes, or more keys than the map holds, makes the pass incomplete: nothing is ended', async () => {
  for (const [label, second, maxEntries] of [
    ['a cell id over 4,096 bytes', [page(['a'], 'c1'), page(['y'.repeat(4_097)], null)], undefined],
    ['more keys than the map holds', [page(['a', 'c'], 'c1'), page(['d'], null)], 2],
  ] as const) {
    const sc = scripted([ok([], { gap: true }), ok([], { gap: true })], [
      realPass(() => [page(['a'], 'c1'), page(['b'], null)]),
      realPass(() => second as unknown as SharesPage[]),
    ], [], { step: 200_000 });
    const feed = sc.make(maxEntries !== undefined ? { maxEntries } : {});
    await run(feed, sc.finished);
    const m = byCell(feed);
    assert.equal(sc.passAt.length, 2, label);
    assert.equal(feed.snapshot().entries.some((e) => e.endedBy === 'reconciliation'), false, `${label}: the incomplete pass ended nothing`);
    assert.equal(feed.snapshot().complete, false, label);
    // Over the map's bound, the map itself drops the oldest entry, as an over-sized one-answer listing makes it do; that
    // is the cap (the map then says it is incomplete), not an end. Within it, the key missing from the pass stays live.
    if (maxEntries === undefined) assert.deepEqual([m.a?.status, m.b?.status], ['live', 'live'], `${label}: the key missing from the incomplete pass is not ended`);
  }
});

// ── the client's feed transport, against an endpoint ──────────────────────────────────────────────────────────────────

test('the client pages the reconciliation where the status offers it, and falls back to the one-answer listing when paging stops mid-pass', async () => {
  const keys = ['a', 'b', 'c'];
  let paging = true;
  const recalls: Array<Record<string, unknown>> = [];
  let statuses = 0;
  const server: Server = createServer((req, res) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => {
      const send = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
      if (req.method === 'GET' && req.url === '/mcp/info') return send(200, { events: CAPS });
      if (req.method === 'POST' && req.url === '/mcp/events') {
        const b = JSON.parse(buf) as { cursor: string | null; waitMs: number };
        if (b.cursor === null) return send(200, { v: 1, operator: CAPS.operator, events: [], cursor: 'c0', more: false, gap: true });
        const t = setTimeout(() => send(200, { v: 1, operator: CAPS.operator, events: [], cursor: 'c0', more: false, gap: false }), Math.min(b.waitMs, 200));
        res.on('close', () => clearTimeout(t));
        return;
      }
      const { method, params = {} } = JSON.parse(buf) as { method: string; params?: Record<string, unknown> };
      if (method === 'saihm_status') { statuses++; return send(200, { agentIdHashHex: '00'.repeat(32), tier: 'PRO', features: { sharesPaged: { v: [1], max: 1000 } } }); }
      if (method !== 'saihm_recall') return send(400, { error: 'unused' });
      recalls.push(params);
      const rows = (ks: string[]) => ks.map((k) => ({ shared: true, sharer: S, cellId: k, scope: 'read', expiryEpoch: null }));
      const unpaged = { mode: 'shares', added: rows(keys), liveSharedKeys: keys.map((k) => `${S}:${k}`) };
      if (params.paged === true) {
        // Two keys a page; the switch goes off after the first page.
        if (!paging) return send(200, unpaged);
        if (params.after === undefined) { paging = false; return send(200, { mode: 'shares', added: rows(keys.slice(0, 2)), next: 's1.b', asOf: new Date().toISOString() }); }
        return send(200, { mode: 'shares', added: rows(keys.slice(2)), next: null });
      }
      if (params.sharesOnly === true) return send(200, unpaged);
      return send(200, []);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const client = new SaihmProClient(`http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`, 'Bearer t', new Uint8Array(32).fill(93), { tier: 'PRO' });
  try {
    client.startShareEvents();
    const end = Date.now() + 8000;
    while (client.shareStates()?.complete !== true && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
    assert.equal(client.shareStates()?.complete, true);
    assert.deepEqual(recalls.map((p) => [p.paged === true, p.after ?? null]), [[true, null], [true, 's1.b'], [false, null]],
      'page one, page two answered unpaged (switched off), then the one-answer listing at once');
    assert.deepEqual(recalls[2], { sharesOnly: true });
    assert.equal(statuses, 1);
    assert.deepEqual(client.shareStates()?.entries.map((e) => [e.cellId, e.status]).sort(), [['a', 'live'], ['b', 'live'], ['c', 'live']]);
  } finally {
    await client.stopShareEvents();
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test('a status that cannot be read: the reconciliation reads the one-answer listing at once, as before paging, and asks for no page', async () => {
  const keys = ['a', 'b'];
  const recalls: Array<Record<string, unknown>> = [];
  let statuses = 0;
  const server: Server = createServer((req, res) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => {
      const send = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
      if (req.method === 'GET' && req.url === '/mcp/info') return send(200, { events: CAPS });
      if (req.method === 'POST' && req.url === '/mcp/events') {
        const b = JSON.parse(buf) as { cursor: string | null; waitMs: number };
        if (b.cursor === null) return send(200, { v: 1, operator: CAPS.operator, events: [], cursor: 'c0', more: false, gap: true });
        const t = setTimeout(() => send(200, { v: 1, operator: CAPS.operator, events: [], cursor: 'c0', more: false, gap: false }), Math.min(b.waitMs, 200));
        res.on('close', () => clearTimeout(t));
        return;
      }
      const { method, params = {} } = JSON.parse(buf) as { method: string; params?: Record<string, unknown> };
      // The status cannot be read: whether the endpoint pages is unknown, which is not an offer.
      if (method === 'saihm_status') { statuses++; return send(503, { error: 'unavailable' }); }
      if (method !== 'saihm_recall') return send(400, { error: 'unused' });
      recalls.push(params);
      const rows = keys.map((k) => ({ shared: true, sharer: S, cellId: k, scope: 'read', expiryEpoch: null }));
      if (params.paged === true) return send(200, { mode: 'shares', added: rows, next: null });
      if (params.sharesOnly === true) return send(200, { mode: 'shares', added: rows, liveSharedKeys: keys.map((k) => `${S}:${k}`) });
      return send(200, []);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const client = new SaihmProClient(`http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`, 'Bearer t', new Uint8Array(32).fill(94), { tier: 'PRO' });
  try {
    client.startShareEvents();
    const end = Date.now() + 8000;
    while (client.shareStates()?.complete !== true && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
    assert.equal(client.shareStates()?.complete, true, 'reconciled from the one-answer listing in the same reconciliation');
    assert.deepEqual(recalls, [{ sharesOnly: true }], 'the one-answer listing only: no page was asked for');
    assert.ok(statuses >= 1);
    assert.deepEqual(client.shareStates()?.entries.map((e) => [e.cellId, e.status]).sort(), [['a', 'live'], ['b', 'live']]);
  } finally {
    await client.stopShareEvents();
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
});
