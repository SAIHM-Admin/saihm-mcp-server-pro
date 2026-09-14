// The share events feed against a scripted operator: events applied in order, reconciliation, tombstones, errors,
// persistence, bounds and the cap.
//
// Runner: npx tsx --test tests/client_share_events.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { getEventListeners } from 'node:events';
import {
  ShareEventsFeed, capabilityFrom, listingFrom, type EventsCapability, type PersistedFeed, type PollAnswer, type PollBody,
} from '../src/share-events.ts';

const S = '11'.repeat(32), S2 = '12'.repeat(32), G1 = 'a1'.repeat(32), G2 = 'a2'.repeat(32), C = '44'.repeat(32);
const CAPS: EventsCapability = { v: [1], path: '/mcp/events', operator: '0f'.repeat(16), maxWaitMs: 25000, maxEvents: 256, maxResponseBytes: 262144, retentionS: 604800, maxPollsPerIdentity: 4, minEmptyPollMs: 5000, maxCellIdBytes: 256 };
let idn = 0;
const id = (): string => (++idn).toString(16).padStart(64, '0');
const at = (m: number): string => new Date(Date.UTC(2026, 8, 14, 9, m)).toISOString();
const ev = (kind: string, extra: Record<string, unknown> = {}) => ({ id: id(), kind, at: at(0), sharer: S, cellId: 'doc', grant: G1, ...extra });
const ok = (events: unknown[], extra: Record<string, unknown> = {}): PollAnswer => ({ status: 200, body: { v: 1, operator: CAPS.operator, events, cursor: `c${++idn}`, more: false, gap: false, ...extra } });

type Row = { sharer: string; cellId: string; scope?: string; expiryEpoch?: string | null; grant?: string; seq?: string; commitment?: string; stale?: boolean };
/** The shares-only listing as the operator sends it; `complete: false` leaves out `liveSharedKeys`, which vouches for nothing. */
const listing = (rows: Row[], complete = true): unknown => ({
  mode: 'shares',
  added: rows.map((r) => ({ shared: true, scope: 'read', expiryEpoch: null, ...r })),
  ...(complete ? { liveSharedKeys: rows.map((r) => `${r.sharer}:${r.cellId}`) } : {}),
});

function scripted(answers: PollAnswer[], listings: unknown[], opts: { caps?: unknown; step?: number } = {}) {
  const polls: Array<{ path: string; cursor: string | null; waitMs: number }> = [];
  const sleeps: number[] = [];
  let listingCalls = 0, infoCalls = 0;
  // Each poll moves the clock on, as a long poll would, so reconciliations are not held back by their spacing.
  let clock = Date.UTC(2026, 8, 14, 10);
  let done!: () => void;
  const finished = new Promise<void>((r) => (done = r));
  const transport = {
    info: async () => { infoCalls++; return opts.caps === undefined ? CAPS : opts.caps; },
    poll: async (path: string, body: PollBody) => {
      await new Promise((r) => setImmediate(r));
      clock += opts.step ?? 30_000;
      polls.push({ path, cursor: body.cursor, waitMs: body.waitMs });
      const a = answers.shift();
      if (!a) { done(); throw new Error('script over'); }
      return a;
    },
    listing: async () => { listingCalls++; return listings.length ? listings.shift() : null; },
  };
  return {
    transport, polls, sleeps, finished,
    listingCalls: () => listingCalls,
    infoCalls: () => infoCalls,
    advance: (ms: number) => { clock += ms; },
    make: (extra: Record<string, unknown> = {}) => new ShareEventsFeed({
      transport, now: () => clock, random: () => 0.5,
      // Yields to the event loop, so a spinning loop never starves the timers the tests wait on.
      sleep: async (ms, signal) => { sleeps.push(ms); await new Promise((r) => setImmediate(r)); if (!signal.aborted && answers.length === 0 && sleeps.length > 50) done(); },
      ...extra,
    }),
  };
}
async function run(feed: ShareEventsFeed, finished: Promise<void>) { feed.start(); await finished; await feed.stop(); }

test('start, reconcile, then created, stale and updated in order', async () => {
  const sc = scripted([
    ok([], { gap: true }),
    ok([ev('share-created', { scope: 'read', expiryEpoch: null }), ev('share-stale', { seq: '2', commitment: C })]),
    ok([ev('shared-cell-updated', { seq: '2', commitment: C })]),
  ], [listing([])]);
  const feed = sc.make();
  await run(feed, sc.finished);
  assert.deepEqual(sc.polls.slice(0, 2).map((p) => [p.path, p.cursor === null, p.waitMs]), [['/mcp/events', true, 0], ['/mcp/events', false, 25000]]);
  const s = feed.snapshot();
  assert.equal(s.complete, true);
  assert.ok(s.since);
  assert.deepEqual(s.entries.map((e) => [e.sharer, e.cellId, e.status, e.grant, e.seq, e.commitment, e.senderVerified]), [[S, 'doc', 'live', G1, '2', C, false]]);
});

test('an end event naming the recorded grant ends the key; one naming another grant reconciles instead', async () => {
  const sc = scripted([
    ok([], { gap: true }),
    ok([ev('share-created', { scope: 'read', expiryEpoch: null }), ev('share-created', { cellId: 'b', scope: 'read', expiryEpoch: null })]),
    ok([ev('share-revoked'), ev('share-revoked', { cellId: 'b', grant: G2 })]),
  ], [listing([]), listing([])]);
  const feed = sc.make();
  await run(feed, sc.finished);
  const byCell = Object.fromEntries(feed.snapshot().entries.map((e) => [e.cellId, e]));
  assert.deepEqual([byCell.doc.status, byCell.doc.endedBy, byCell.doc.copiesInvalidBefore], ['ended', 'event', null]);
  assert.deepEqual([byCell.b.status, byCell.b.endedBy], ['ended', 'reconciliation'], 'the mismatched end reconciled, and the complete listing ended the key');
  assert.ok(byCell.b.copiesInvalidBefore, 'a reconciliation cannot tell an erasure from a revocation');
  assert.equal(sc.listingCalls(), 2);
});

test('keys learned from the listing carry their grant, so a later end event applies without another reconciliation', async () => {
  const sc = scripted([
    ok([], { gap: true }),
    ok([ev('share-revoked')]),
  ], [listing([{ sharer: S, cellId: 'doc', grant: G1, seq: '3', commitment: C, stale: false }])]);
  const feed = sc.make();
  await run(feed, sc.finished);
  const [e] = feed.snapshot().entries;
  assert.deepEqual([e.status, e.endedBy, e.grant, e.seq, e.commitment, e.copiesInvalidBefore], ['ended', 'event', G1, '3', C, null]);
  assert.equal(sc.listingCalls(), 1);
});

test('a grant change seen only by reconciliation invalidates earlier copies', async () => {
  const sc = scripted([
    ok([], { gap: true }),
    ok([], { gap: true }),
  ], [listing([{ sharer: S, cellId: 'doc', grant: G1 }]), listing([{ sharer: S, cellId: 'doc', grant: G2 }])]);
  const feed = sc.make();
  await run(feed, sc.finished);
  const [e] = feed.snapshot().entries;
  assert.deepEqual([e.status, e.grant], ['live', G2]);
  assert.ok(e.copiesInvalidBefore, 'the cell may have been erased and shared again under the same id');
});

test('a live share that fails to open is stale until the next update; senders are verified only by a read', async () => {
  const sc = scripted([
    ok([], { gap: true }),
    ok([ev('share-created', { scope: 'read', expiryEpoch: null }), ev('share-created', { cellId: 'gone', scope: 'read', expiryEpoch: null }), ev('share-revoked', { cellId: 'gone' })]),
  ], [listing([])]);
  const feed = sc.make();
  await run(feed, sc.finished);
  feed.markOpenFailed(S, 'doc');
  feed.markOpenFailed(S, 'gone');
  feed.markSenderVerified(S, 'doc');
  const byCell = Object.fromEntries(feed.snapshot().entries.map((e) => [e.cellId, e]));
  assert.deepEqual([byCell.doc.status, byCell.doc.senderVerified, byCell.gone.status], ['stale', true, 'ended'], 'only a live entry becomes stale');

  const t = scripted([
    ok([], { gap: true }),
    ok([ev('share-created', { scope: 'read', expiryEpoch: null })]),
  ], [listing([])]);
  const f2 = t.make();
  await run(f2, t.finished);
  f2.markOpenFailed(S, 'doc');
  (f2 as unknown as { apply(events: unknown[]): void }).apply([ev('shared-cell-updated', { seq: '5', commitment: C })]);
  const [e] = f2.snapshot().entries;
  assert.deepEqual([e.status, e.seq], ['live', '5']);
});

test('erasure marks copies invalid, and the mark survives a later share of the same id', async () => {
  const sc = scripted([
    ok([], { gap: true }),
    ok([ev('share-created', { scope: 'read', expiryEpoch: null }), ev('shared-cell-erased', { at: at(5) })]),
    ok([ev('share-created', { grant: G2, scope: 'read', expiryEpoch: null, at: at(9) })]),
  ], [listing([])]);
  const feed = sc.make();
  await run(feed, sc.finished);
  const [e] = feed.snapshot().entries;
  assert.deepEqual([e.status, e.grant, e.copiesInvalidBefore], ['live', G2, at(5)]);
});

test('a gap stays incomplete until a listing that can end keys; an incomplete listing ends nothing and is retried later, not at every poll', async () => {
  const sc = scripted([
    ok([], { gap: true }),
    ok([ev('share-created', { scope: 'read', expiryEpoch: null })]),
    ok([], { gap: true }),
    ok([]), ok([]),
  ], [listing([]), listing([], false), listing([])]);
  const feed = sc.make();
  await run(feed, sc.finished);
  const s = feed.snapshot();
  assert.equal(s.complete, false);
  assert.equal(s.entries[0].status, 'live', 'an incomplete listing ends nothing');
  assert.equal(sc.listingCalls(), 2, 'two more answers within the retry interval ask for no listing');
});

test('failed or incomplete reconciliations back off, doubling; a complete one is followed by a short spacing', async () => {
  const polls = Array.from({ length: 20 }, () => ok([]));
  const sc = scripted([ok([], { gap: true }), ...polls], Array.from({ length: 20 }, () => listing([], false)));
  const feed = sc.make();
  await run(feed, sc.finished);
  // One answer every 30 s for 10 minutes: tries at 0, 90 s and 270 s (60 s, then 120 s, each plus half again as jitter).
  assert.equal(sc.listingCalls(), 3);

  const t = scripted([
    ok([], { gap: true }),
    ok([ev('share-revoked', { cellId: 'x' })]),
    ok([ev('share-revoked', { cellId: 'y' })]),
  ], [listing([]), listing([]), listing([])], { step: 1_000 });
  const f2 = t.make();
  await run(f2, t.finished);
  assert.equal(t.listingCalls(), 1, 'two unmatched end events a second after a reconciliation wait for its spacing');
  assert.equal(f2.snapshot().complete, false);
});

test('duplicates, shrunk events and unknown kinds are skipped; resync reconciles', async () => {
  const dup = ev('share-created', { scope: 'read', expiryEpoch: null });
  const sc = scripted([
    ok([], { gap: true }),
    ok([dup, dup, { id: id(), kind: 'share-created', shrunk: true }, { ...ev('share-future'), kind: 'share-future' }, { id: id(), kind: 'resync', at: at(1), reason: 'dropped' }]),
  ], [listing([]), listing([{ sharer: S, cellId: 'doc', grant: G1, seq: '7', commitment: C, stale: true }])]);
  const feed = sc.make();
  await run(feed, sc.finished);
  const s = feed.snapshot();
  assert.equal(s.entries.length, 1);
  assert.deepEqual([s.entries[0].status, s.entries[0].seq], ['stale', '7'], 'the resync reconciliation applied the listing fields');
  assert.equal(sc.listingCalls(), 2);
});

test('an expiry event without its epoch keeps the one recorded', async () => {
  const sc = scripted([
    ok([], { gap: true }),
    ok([ev('share-created', { scope: 'read', expiryEpoch: '493000' }), ev('share-expired')]),
  ], [listing([])]);
  const feed = sc.make();
  await run(feed, sc.finished);
  const [e] = feed.snapshot().entries;
  assert.deepEqual([e.status, e.expiryEpoch], ['ended', '493000']);
});

test('operator answers: bad cursor restarts, 429 waits what it asked plus jitter, 402 stops for the tier, 410 ends the loop', async () => {
  const sc = scripted([
    ok([], { gap: true }),
    { status: 400, body: { error: 'bad_cursor' } },
    ok([], { gap: true }),
    { status: 429, body: { error: 'poll_too_soon', retryAfterMs: 3000 }, retryAfterS: 3 },
    ok([], { retryAfterMs: 5100 }),
    { status: 410, body: { error: 'tenant_erased' } },
  ], [listing([]), listing([])]);
  const feed = sc.make();
  feed.start();
  await new Promise((r) => setTimeout(r, 50));
  await feed.stop();
  assert.equal(sc.polls[2].cursor, null, 'bad_cursor goes back to the start poll');
  assert.ok(sc.sleeps.includes(4500), `429: retryAfterMs plus jitter, got ${sc.sleeps}`);
  assert.ok(sc.sleeps.includes(5100), 'retryAfterMs on a 200 is honoured');
  assert.equal(feed.stopped, 'erased');

  const t = scripted([{ status: 402, body: { error: 'share_tier_required' } }], []);
  const f2 = t.make();
  f2.start();
  await new Promise((r) => setTimeout(r, 20));
  await f2.stop();
  assert.ok(t.sleeps.includes(86_400_000), '402: polling stops and discovery is tried again a day later');
  assert.equal(t.polls.length >= 1 && t.sleeps.indexOf(86_400_000) === 0, true, 'nothing polls before that day passes');
});

test('a feed the operator stopped offering is discovered again, and left alone once it is gone', async () => {
  let offered = true;
  const sc = scripted([
    ok([], { gap: true }),
    { status: 503, body: { error: 'events_unavailable', retryAfterMs: 10000 }, retryAfterS: 10 },
  ], [listing([])]);
  (sc.transport as { info: () => Promise<unknown> }).info = async () => { const c = offered ? CAPS : null; offered = false; return c; };
  const feed = sc.make();
  feed.start();
  await new Promise((r) => setTimeout(r, 50));
  await feed.stop();
  assert.equal(feed.stopped, 'unsupported');
  assert.equal(sc.polls.length, 2, 'no poll after the operator withdrew the feed');
});

test('an answer without a usable cursor is not applied', async () => {
  const sc = scripted([
    ok([], { gap: true }),
    ok([ev('share-created', { scope: 'read', expiryEpoch: null })], { cursor: 'x'.repeat(513) }),
    ok([ev('share-created', { cellId: 'b', scope: 'read', expiryEpoch: null })], { cursor: 7 }),
  ], [listing([])]);
  const feed = sc.make();
  await run(feed, sc.finished);
  assert.equal(feed.snapshot().entries.length, 0);
  assert.ok(sc.sleeps.filter((ms) => ms === 10_000).length >= 2);
  assert.deepEqual(sc.polls.slice(1, 4).map((p) => p.cursor === 'x'.repeat(513)), [false, false, false], 'the long cursor is never sent back');
});

test('an answer from another operator restarts from the head without asking the info route again', async () => {
  const other = '0e'.repeat(16);
  const sc = scripted([
    ok([], { gap: true }),
    ok([ev('share-created', { scope: 'read', expiryEpoch: null })], { operator: other }),
    { status: 200, body: { v: 1, operator: other, events: [], cursor: 'h', more: false, gap: true } },
  ], [listing([]), listing([])]);
  const feed = sc.make();
  await run(feed, sc.finished);
  assert.deepEqual(sc.polls.slice(0, 3).map((p) => p.cursor === null), [true, false, true]);
  assert.equal(sc.infoCalls(), 1);
  assert.equal(feed.snapshot().entries.length, 0, "the other operator's events were not applied");
});

test('persisted state reloads, stays incomplete until it reconciles, and keeps since', async () => {
  let saved: PersistedFeed | undefined;
  const store = { load: () => saved, save: (p: PersistedFeed) => { saved = JSON.parse(JSON.stringify(p)); } };
  const sc = scripted([ok([], { gap: true }), ok([ev('share-created', { scope: 'read', expiryEpoch: null })])], [listing([])]);
  const feed = sc.make({ store });
  await run(feed, sc.finished);
  assert.ok(saved?.cursor);
  const since = feed.snapshot().since;
  const sc2 = scripted([], []);
  const again = sc2.make({ store });
  const s = again.snapshot();
  assert.deepEqual([s.since, s.complete, s.entries.length], [since, false, 1]);
});

test('the cap keeps erasures and invalidated copies first and marks the map incomplete', async () => {
  const sc = scripted([
    ok([], { gap: true }),
    ok([
      ev('share-created', { cellId: 'l1', scope: 'read', expiryEpoch: null }),
      ev('share-created', { cellId: 'l2', scope: 'read', expiryEpoch: null }),
      ev('share-created', { cellId: 'e1', sharer: S2, scope: 'read', expiryEpoch: null }),
      ev('shared-cell-erased', { cellId: 'e1', sharer: S2 }),
      ev('share-created', { cellId: 'l3', scope: 'read', expiryEpoch: null }),
    ]),
  ], [listing([])]);
  const feed = sc.make({ maxEntries: 2 });
  await run(feed, sc.finished);
  const s = feed.snapshot();
  assert.equal(s.complete, false);
  assert.equal(s.entries.length, 2);
  assert.ok(s.entries.some((e) => e.cellId === 'e1' && e.status === 'erased'));
});

test('event ids are remembered up to a bound, oldest first', async () => {
  const many = Array.from({ length: 65_600 }, () => ({ id: id(), kind: 'share-future', at: at(0), sharer: S, cellId: 'doc', grant: G1 }));
  const sc = scripted([ok([], { gap: true }), ok(many)], [listing([])]);
  const feed = sc.make();
  await run(feed, sc.finished);
  const seen = (feed as unknown as { seen: Map<string, number> }).seen;
  assert.equal(seen.size, 65_536);
  assert.ok(!seen.has(many[0].id) && seen.has(many[65_599].id));
});

test('an operator that offers no feed, or a malformed capability, is left alone', async () => {
  for (const caps of [null, { ...CAPS, path: '//elsewhere.example/mcp/events' }, { ...CAPS, operator: 'nothex' }, { ...CAPS, v: [2] }]) {
    const sc = scripted([], [], { caps });
    const feed = sc.make();
    feed.start();
    await new Promise((r) => setTimeout(r, 20));
    await feed.stop();
    assert.equal(feed.stopped, 'unsupported', JSON.stringify(caps));
    assert.equal(sc.polls.length, 0);
  }
});

test('stop ends a poll in flight, and waits leave no listener behind', async () => {
  let aborted = false;
  const transport = {
    info: async () => CAPS,
    poll: (_p: string, _b: PollBody, _t: number, signal: AbortSignal) => new Promise<PollAnswer>((_resolve, reject) => {
      signal.addEventListener('abort', () => { aborted = true; reject(new Error('aborted')); }, { once: true });
    }),
    listing: async () => null,
  };
  const feed = new ShareEventsFeed({ transport });
  feed.start();
  await new Promise((r) => setTimeout(r, 20));
  const t0 = Date.now();
  await feed.stop();
  assert.ok(aborted && Date.now() - t0 < 1000);

  // The real wait: many short waits on one feed's signal, then a count of what is still attached to it.
  let n = 0;
  const busy = new ShareEventsFeed({
    transport: { info: async () => CAPS, poll: async () => ({ status: 503, body: { retryAfterMs: 1 } }), listing: async () => null },
    random: () => 0,
  });
  busy.start();
  while (n++ < 40) await new Promise((r) => setTimeout(r, 2));
  const signal = (busy as unknown as { abort: AbortController }).abort.signal;
  assert.ok(getEventListeners(signal, 'abort').length <= 1, `listeners: ${getEventListeners(signal, 'abort').length}`);
  await busy.stop();
});

test('capabilityFrom bounds every limit and accepts only a path on the endpoint origin', () => {
  assert.deepEqual(capabilityFrom(CAPS), CAPS);
  for (const path of ['//evil.example/x', 'https://evil.example/mcp/events', 'events', '/mcp\\events', '/mcp//events', '/', '/mcp/events?x=1']) {
    assert.equal(capabilityFrom({ ...CAPS, path }), null, path);
  }
  const wild = capabilityFrom({ ...CAPS, maxWaitMs: 1e9, maxEvents: 0, maxResponseBytes: 'x', retentionS: -1, maxPollsPerIdentity: 1.5, minEmptyPollMs: 1e12, maxCellIdBytes: 1e9 });
  assert.deepEqual(wild && [wild.maxWaitMs, wild.maxEvents, wild.maxResponseBytes, wild.retentionS, wild.maxPollsPerIdentity, wild.minEmptyPollMs, wild.maxCellIdBytes],
    [25000, 1, 262144, 3600, 4, 60000, 4096]);
});

test('listingFrom vouches only for what it holds', () => {
  const long = 'x'.repeat(4096), tooLong = 'x'.repeat(4097);
  const full = listingFrom(listing([{ sharer: S, cellId: 'a:b', grant: G1, seq: '1', commitment: C, stale: false }, { sharer: S, cellId: long }]), 4096)!;
  assert.equal(full.complete, true, 'ids up to the client bound, including colons, are held');
  assert.deepEqual(full.entries.map((e) => [e.cellId.length, e.grant, e.seq, e.commitment, e.stale]), [[3, G1, '1', C, false], [4096, null, null, null, null]]);
  assert.equal(listingFrom(listing([{ sharer: S, cellId: tooLong }]), 4096)!.complete, false, 'an id this client cannot hold');
  const unheld = { mode: 'shares', added: [{ shared: true, sharer: S, cellId: tooLong, scope: 'read', expiryEpoch: null }], liveSharedKeys: [] };
  assert.equal(listingFrom(unheld, 4096)!.complete, false, 'an entry it could not hold, even when no live key names it');
  assert.equal(listingFrom(listing([]), 4096)!.complete, true);
  assert.equal(listingFrom(listing([], false), 4096)!.complete, false, 'without liveSharedKeys the listing vouches for nothing');
  assert.equal(listingFrom([{ shared: true, sharer: S, cellId: 'a', scope: 'read', expiryEpoch: null }], 4096)!.complete, false, 'the array form carries no liveSharedKeys');
  const unannounced = { mode: 'shares', added: [], liveSharedKeys: [`${S}:a`] };
  assert.equal(listingFrom(unannounced, 4096)!.complete, false, 'a live key without its entry');
  assert.equal(listingFrom(listing([{ sharer: S, cellId: 'a' }, { sharer: S, cellId: 'b' }]), 1)!.complete, false, 'more than the map holds');
  const mixed = listingFrom({ mode: 'delta', added: [{ cellId: 'own', found: true, wire: {} }, { shared: true, sharer: S, cellId: 'own2', wire: {} }, { shared: true, sharer: S, cellId: 'c', scope: 'write', expiryEpoch: '12x', grant: 'G', seq: '-1', commitment: 'zz', stale: 'no' }], liveCellIds: ['own'], liveSharedKeys: [`${S}:c`] }, 4096)!;
  assert.deepEqual(mixed, { complete: true, entries: [{ sharer: S, cellId: 'c', scope: null, expiryEpoch: null, grant: null, seq: null, commitment: null, stale: null }] });
  assert.equal(listingFrom({ error: 'x' }, 4096), null);
});
