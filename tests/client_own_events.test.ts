// The share events feed with the own-cell kinds: when it asks for them, the order of lines, markers, the share map and
// the cursor for each answer, fresh starts, resuming, refused writes, one writer per tenant directory (and what a second
// process does), and that an operator without the own-cell kinds sees exactly the polls and files it saw before.
//
// Runner: npx tsx --test tests/client_own_events.test.ts
import { afterEach, test } from 'node:test';
import { strict as assert } from 'node:assert';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { ShareEventsFeed, type OwnCellWriter, type PollAnswer, type PollBody, type FeedStore } from '../src/share-events.ts';
import { ChangeFeedWriter } from '../src/change-feed.ts';
import { appendFeedLines } from '../src/erasure-feed.ts';
import { FileFeedStore, feedStatePath } from '../src/feed-state-file.ts';

const H = 'ab'.repeat(32), S = '11'.repeat(32), G1 = 'a1'.repeat(32), C1 = '44'.repeat(32), OP = '0f'.repeat(16);
const SHARE_KINDS = ['share-created', 'shared-cell-updated', 'share-stale', 'share-revoked', 'share-expired', 'shared-cell-erased', 'resync'];
const ALL_KINDS = [...SHARE_KINDS, 'cell-written', 'cell-erased'];
const caps = (kinds?: unknown, operator = OP) => ({
  v: [1], path: '/mcp/events', operator, maxWaitMs: 25000, maxEvents: 256, maxResponseBytes: 262144, retentionS: 604800,
  maxPollsPerIdentity: 4, minEmptyPollMs: 5000, maxCellIdBytes: 256, ...(kinds !== undefined ? { kinds } : {}),
});
let idn = 0;
const id = (): string => (++idn).toString(16).padStart(64, '0');
const AT = '2026-10-03T09:00:00.000Z';
const written = (cellId: string) => ({ id: id(), kind: 'cell-written', at: AT, cellId, seq: '1', commitment: C1 });
const erased = (cellId: string) => ({ id: id(), kind: 'cell-erased', at: AT, cellId, complete: false });
const ok = (events: unknown[], extra: Record<string, unknown> = {}): PollAnswer =>
  ({ status: 200, body: { v: 1, operator: OP, events, cursor: `k${++idn}`, more: false, gap: false, ...extra } });
const EMPTY_LISTING = { mode: 'shares', added: [], liveSharedKeys: [] };

interface Opts {
  root: string;
  clock: { t: number };
  script: PollAnswer[];
  caps?: unknown;
  store?: boolean;
  own?: boolean;
  log?: string[];
  fail?: { appends: number };
  step?: number;
  /** Called as each poll is answered, with how many polls came before it: a test changes the directory between polls. */
  onPoll?: (n: number) => void;
  /** Called as each wait begins, with its length: a test reads the directory at the moment the feed starts to wait. */
  onSleep?: (ms: number) => void;
  /** Keep the feed in a day-long wait until it is stopped, as a host that stops during that wait does. */
  holdDay?: boolean;
}

/** Every feed a test started: stopped after each test, so a failed assertion never leaves a loop running. */
const live = new Set<ShareEventsFeed>();
afterEach(async () => {
  for (const f of live) await f.stop();
  live.clear();
});

/** One process's feed over a real tenant directory, its operator scripted, every write it makes logged in order. */
function makeFeed(o: Opts) {
  const env = { SAIHM_ERASURE_FEED_DIR: o.root };
  const polls: PollBody[] = [];
  const sleeps: number[] = [];
  let infoCalls = 0, listingCalls = 0, exhausted = false;
  const log = o.log ?? [];
  const now = () => o.clock.t;
  const kindsOf = (lines: readonly string[]) => lines.map((l) => { const j = JSON.parse(l); return j.kind === 'gap' ? `gap:${j.reason}` : j.kind ?? `erasure:${j.cellId}`; }).join(',');
  const writer = new ChangeFeedWriter({
    agentIdHash: H, env, now,
    append: (p, lines) => {
      if (lines.length === 0) return;
      if (o.fail && o.fail.appends > 0) { o.fail.appends--; throw new Error('ENOSPC'); }
      log.push(`append ${basename(p)} ${kindsOf(lines)}`);
      appendFeedLines(p, lines);
    },
  });
  const own: OwnCellWriter = {
    lead: () => writer.lead(), holds: () => writer.holds(), writeAnswer: (a) => writer.writeAnswer(a), release: () => writer.release(),
    committed: (s) => { log.push(`map ${s.asOf}`); writer.committed(s); },
  };
  const file = new FileFeedStore(feedStatePath(H, env));
  const store: FeedStore = { load: () => file.load(), save: (st) => { log.push(`save ${st.cursor}${st.ownCells ? ' own' : ''}`); file.save(st); } };
  const feed = new ShareEventsFeed({
    transport: {
      info: async () => { infoCalls++; return o.caps === undefined ? caps(ALL_KINDS) : o.caps; },
      poll: async (_path: string, body: PollBody) => {
        await new Promise((r) => setImmediate(r));
        o.clock.t += o.step ?? 30_000;
        o.onPoll?.(polls.length);
        polls.push(body);
        const a = o.script.shift();
        if (!a) { exhausted = true; throw new Error('script over'); }
        return a;
      },
      listing: async () => { listingCalls++; return EMPTY_LISTING; },
    },
    ...(o.store === false ? {} : { store }),
    ...(o.own === false ? {} : { own }),
    now, random: () => 0.5, minWaitMs: 1,
    sleep: async (ms, signal) => {
      o.onSleep?.(ms);
      sleeps.push(ms);
      if (o.holdDay && ms === 86_400_000) {
        await new Promise<void>((r) => { if (signal.aborted) r(); else signal.addEventListener('abort', () => r(), { once: true }); });
        return;
      }
      await new Promise((r) => setImmediate(r));
    },
  });
  live.add(feed);
  return {
    feed, writer, polls, sleeps, log, env,
    infoCalls: () => infoCalls, listingCalls: () => listingCalls, exhausted: () => exhausted,
    lines: (name: string) => { try { return readFileSync(join(writer.dir, name), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } },
    state: () => { try { return JSON.parse(readFileSync(feedStatePath(H, env), 'utf8')); } catch { return undefined; } },
  };
}
const tick = () => new Promise((r) => setImmediate(r));
async function until(cond: () => boolean, what: string, max = 20_000): Promise<void> {
  for (let i = 0; i < max; i++) { if (cond()) return; await tick(); }
  throw new Error(`timed out waiting for ${what}`);
}
async function runToEnd(f: ReturnType<typeof makeFeed>): Promise<void> {
  f.feed.start();
  await until(f.exhausted, 'the script to end');
  await f.feed.stop();
}
const tmpRoot = () => mkdtempSync(join(tmpdir(), 'saihm-own-'));
const markers = (lines: Record<string, unknown>[]) => lines.map((l) => (l.kind === 'gap' ? `gap:${l.reason}` : l.kind === 'cell-written' ? `w:${l.cellId}` : String(l.kind)));

test('own-cell kinds are asked for only when the operator lists both, and only those two', async () => {
  const root = tmpRoot();
  try {
    const f = makeFeed({ root, clock: { t: Date.UTC(2026, 9, 3, 10) }, caps: caps([...ALL_KINDS, 'some-future-kind', 7, 'x'.repeat(65)]), script: [ok([], { gap: true }), ok([written('a')])] });
    await runToEnd(f);
    assert.deepEqual(f.polls.slice(0, 2).map((p) => Object.keys(p)), [['v', 'cursor', 'waitMs', 'max', 'kinds'], ['v', 'cursor', 'waitMs', 'max', 'kinds']]);
    for (const p of f.polls) assert.deepEqual(p.kinds, ['cell-written', 'cell-erased']);
    assert.deepEqual(markers(f.lines('changes.ndjson')), ['gap:fresh-start', 'position', 'w:a', 'position']);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('an operator without both own-cell kinds sees the polls and files it saw before they existed', async () => {
  const variants: Array<[string, unknown, boolean]> = [
    ['no kinds listed', caps(), true],
    ['the share kinds only', caps(SHARE_KINDS), true],
    ['one own-cell kind', caps([...SHARE_KINDS, 'cell-written']), true],
    ['the other one', caps([...SHARE_KINDS, 'cell-erased']), true],
    ['kinds that is not a list', caps('cell-written,cell-erased'), true],
    ['both, but no writer in this process', caps(ALL_KINDS), false],
  ];
  for (const [what, c, own] of variants) {
    const root = tmpRoot();
    try {
      const f = makeFeed({ root, clock: { t: Date.UTC(2026, 9, 3, 10) }, caps: c, own, script: [ok([], { gap: true }), ok([written('a'), erased('b')]), ok([])] });
      await runToEnd(f);
      for (const p of f.polls) assert.deepEqual(Object.keys(p), ['v', 'cursor', 'waitMs', 'max'], what);
      const dir = join(root, 'tenants', H);
      assert.deepEqual(readdirSync(dir), ['feed-state.json'], `${what}: no lease, no change file, no feed lines`);
      assert.equal('ownCells' in f.state(), false, `${what}: the saved state has the shape it had`);
      // An own-cell event no poll asked for is handled as before: it names no sharer, so the map reconciles.
      assert.equal(f.listingCalls(), 2, `${what}: start, then the unasked event`);
      assert.equal(f.feed.role, 'solo');
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('the order holds for every answer: no save before its map, no map before its markers', async () => {
  const root = tmpRoot();
  try {
    const f = makeFeed({ root, clock: { t: Date.UTC(2026, 9, 3, 10) }, script: [ok([], { gap: true }), ok([written('a'), erased('b')]), ok([]), ok([erased('c')], { gap: true })] });
    await runToEnd(f);
    // Split the log into answers at each map write; within each, every append comes first and the save last.
    const answers: string[][] = [];
    let cur: string[] = [];
    for (const entry of f.log) {
      cur.push(entry);
      if (entry.startsWith('save')) { answers.push(cur); cur = []; }
    }
    const perAnswer = answers.map((a) => a.map((x) => x.split(' ')[0] + (x.startsWith('append') ? ` ${x.split(' ')[1]}` : '')));
    assert.deepEqual(perAnswer, [
      ['append changes.ndjson', 'append changes.ndjson', 'map', 'save'],                             // start: fresh-start gap, position
      ['append erasures.ndjson', 'append changes.ndjson', 'map', 'save'],                            // b's line; a's line and the position
      ['append changes.ndjson', 'map', 'save'],                                                     // an empty answer that moved the cursor: its position
      ['append changes.ndjson', 'append erasures.ndjson', 'append changes.ndjson', 'map', 'save'],   // a server gap first
      ['save'],                                                                                     // stop: the last save
    ]);
    assert.deepEqual(markers(f.lines('changes.ndjson')), ['gap:fresh-start', 'position', 'w:a', 'position', 'position', 'gap:server-gap', 'position']);
    assert.ok(cur.length === 0);
    // Every save after the first own answer says the cursor is covered.
    assert.ok(f.log.filter((x) => x.startsWith('save')).every((x) => x.endsWith(' own')), f.log.join('\n'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a fresh start writes fresh-start first, with the first answer\'s cursor: no state, memory only, or an uncovered state', async () => {
  const start = Date.UTC(2026, 9, 3, 10);
  // A state saved by a poll that did not ask for own-cell events: its cursor is used, and it is not covered.
  const shareOnlyState = (root: string) => {
    const p = feedStatePath(H, { SAIHM_ERASURE_FEED_DIR: root });
    mkdirSync(join(root, 'tenants', H), { recursive: true, mode: 0o700 });
    writeFileSync(p, JSON.stringify({ v: 1, savedAt: new Date(start).toISOString(), reconciledAt: new Date(start).toISOString(), capped: false, operator: OP, cursor: 'saved-1', since: AT, entries: [], seen: [] }));
  };
  const cases: Array<[string, (root: string) => void, Partial<Opts>, string | null, string]> = [
    ['no saved state', () => undefined, {}, null, 'fresh-start'],
    ['memory only', () => undefined, { store: false }, null, 'fresh-start'],
    // A REAL restored cursor without own-cell coverage is the upgrade path ('kinds-changed'), distinct from a true cold
    // start — the other three cases here, which have no cursor to have moved past anything.
    ['a state saved without own-cell coverage', shareOnlyState, {}, 'saved-1', 'kinds-changed'],
    ['an unreadable state', (root) => { mkdirSync(join(root, 'tenants', H), { recursive: true }); writeFileSync(feedStatePath(H, { SAIHM_ERASURE_FEED_DIR: root }), '{"v":1,'); }, {}, null, 'fresh-start'],
  ];
  for (const [what, prepare, extra, firstCursor, reason] of cases) {
    const root = tmpRoot();
    try {
      prepare(root);
      const first = ok([written('a')]);
      const f = makeFeed({ root, clock: { t: start }, script: [first, ok([])], ...extra });
      await runToEnd(f);
      assert.equal(f.polls[0].cursor, firstCursor, `${what}: the first poll's cursor`);
      const ch = f.lines('changes.ndjson');
      assert.deepEqual(markers(ch), [`gap:${reason}`, 'w:a', 'position', 'position'], what);
      assert.equal(ch[0].cursor, (first.body as { cursor: string }).cursor, `${what}: the marker carries the first answer's cursor`);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('kinds-changed is named once, by the uncovered cursor itself: a later bad_cursor reset is a fresh start', async () => {
  const start = Date.UTC(2026, 9, 3, 10);
  const root = tmpRoot();
  try {
    const p = feedStatePath(H, { SAIHM_ERASURE_FEED_DIR: root });
    mkdirSync(join(root, 'tenants', H), { recursive: true, mode: 0o700 });
    // The exact 'uncovered state' fixture from the case above: owes 'kinds-changed' once.
    writeFileSync(p, JSON.stringify({
      v: 1, savedAt: new Date(start).toISOString(), reconciledAt: new Date(start).toISOString(), capped: false,
      operator: OP, cursor: 'saved-1', since: AT, entries: [], seen: [],
    }));
    const script: PollAnswer[] = [
      ok([written('a')]),                             // 1st own-kinds poll: owed 'kinds-changed', spent here
      { status: 400, body: { error: 'bad_cursor' } },  // unrelated reset: ownCovered false again, cursor cleared
      ok([written('b')]),                              // a true fresh start now -- NOT 'kinds-changed' a second time
    ];
    const f = makeFeed({ root, clock: { t: start }, script });
    await runToEnd(f);
    assert.deepEqual(markers(f.lines('changes.ndjson')), [
      'gap:kinds-changed', 'w:a', 'position',
      'gap:fresh-start', 'w:b', 'position',
    ]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a refused cursor or another operator\'s state starts fresh too, covered or not', async () => {
  const start = Date.UTC(2026, 9, 3, 10);
  // Uncovered as well as covered: a cursor that is not presented moved past nothing here, so the gap is fresh-start
  // even when the state was saved without own-cell coverage.
  for (const [what, covered] of [['bad_cursor', true], ['another operator', true], ['bad_cursor', false], ['another operator', false]] as const) {
    const root = tmpRoot();
    try {
      // A state, then the operator refuses it, or the state names another operator.
      mkdirSync(join(root, 'tenants', H), { recursive: true, mode: 0o700 });
      writeFileSync(feedStatePath(H, { SAIHM_ERASURE_FEED_DIR: root }), JSON.stringify({
        v: 1, savedAt: new Date(start).toISOString(), reconciledAt: new Date(start).toISOString(), capped: false,
        operator: what === 'another operator' ? 'ee'.repeat(16) : OP, cursor: 'saved-1', since: AT, entries: [], seen: [],
        ...(covered ? { ownCells: true } : {}),
      }));
      const head = ok([], { gap: true });
      const script = what === 'bad_cursor'
        ? [{ status: 400, body: { error: 'bad_cursor' } }, head, ok([written('a')])]
        : [head, ok([written('a')])];
      const f = makeFeed({ root, clock: { t: start }, script });
      await runToEnd(f);
      const headCursor = (head.body as { cursor: string }).cursor;
      assert.deepEqual(f.polls.slice(0, 2).map((p) => p.cursor), what === 'bad_cursor' ? ['saved-1', null] : [null, headCursor]);
      assert.deepEqual(markers(f.lines('changes.ndjson')), ['gap:fresh-start', 'position', 'w:a', 'position'], `${what}, covered=${covered}`);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('a cursor this process moved without asking for own-cell events names kinds-changed when it starts asking', async () => {
  // Memory only, so nothing is restored: the cursor the writer presents is the one its own polls moved while the
  // directory held another store's file and no process could write it. Those polls did not ask for own-cell events,
  // so the cursor moved past events no line records - the case kinds-changed names, wherever the cursor came from.
  const root = tmpRoot();
  try {
    const foreign = join(root, 'tenants', H, 'someone-elses.db');
    mkdirSync(join(root, 'tenants', H), { recursive: true, mode: 0o700 });
    writeFileSync(foreign, 'x');
    const f = makeFeed({
      root, clock: { t: Date.UTC(2026, 9, 3, 10) }, store: false,
      script: [ok([]), ok([written('a')]), ok([])],
      onPoll: (n) => { if (n === 0) rmSync(foreign); },   // the directory is free once the first poll is answered
    });
    await runToEnd(f);
    assert.deepEqual(f.polls.slice(0, 3).map((p) => p.kinds !== undefined), [false, true, true], 'asked once the directory was writable');
    assert.notEqual(f.polls[1]?.cursor, null, 'the writer presented the cursor its own earlier poll moved');
    assert.deepEqual(markers(f.lines('changes.ndjson')), ['gap:kinds-changed', 'w:a', 'position', 'position']);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a covered state older than the operator keeps events for starts from the head, behind a fresh-start gap', async () => {
  // Its cursor is certainly refused, so it is dropped unasked; what it covered says nothing about the head.
  const start = Date.UTC(2026, 9, 3, 10);
  const root = tmpRoot();
  try {
    mkdirSync(join(root, 'tenants', H), { recursive: true, mode: 0o700 });
    const old = new Date(start - 8 * 86_400_000).toISOString(); // retention is 7 days
    writeFileSync(feedStatePath(H, { SAIHM_ERASURE_FEED_DIR: root }), JSON.stringify({
      v: 1, savedAt: old, reconciledAt: old, capped: false, operator: OP, cursor: 'saved-1', since: AT, entries: [], seen: [], ownCells: true,
    }));
    const first = ok([written('a')]);
    const f = makeFeed({ root, clock: { t: start }, script: [first, ok([])] });
    await runToEnd(f);
    assert.equal(f.polls[0].cursor, null, 'the expired cursor is not presented');
    assert.deepEqual(markers(f.lines('changes.ndjson')), ['gap:fresh-start', 'w:a', 'position', 'position']);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a covered state resumes without a gap; the operator\'s gap (a new subscription) is still written', async () => {
  const start = Date.UTC(2026, 9, 3, 10);
  for (const gap of [false, true]) {
    const root = tmpRoot();
    try {
      mkdirSync(join(root, 'tenants', H), { recursive: true, mode: 0o700 });
      writeFileSync(feedStatePath(H, { SAIHM_ERASURE_FEED_DIR: root }), JSON.stringify({
        v: 1, savedAt: new Date(start).toISOString(), reconciledAt: new Date(start).toISOString(), capped: false,
        operator: OP, cursor: 'saved-1', since: AT, entries: [], seen: [], ownCells: true,
      }));
      const f = makeFeed({ root, clock: { t: start }, script: [ok([written('a')], { gap }), ok([])] });
      await runToEnd(f);
      assert.equal(f.polls[0].cursor, 'saved-1');
      assert.equal(f.polls[0].waitMs, 0, 'a resumed position catches up at once');
      assert.deepEqual(markers(f.lines('changes.ndjson')), gap ? ['gap:server-gap', 'w:a', 'position', 'position'] : ['w:a', 'position', 'position']);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('a refused write moves nothing: the same position is asked for again, and nothing is applied or saved meanwhile', async () => {
  const root = tmpRoot();
  try {
    const fail = { appends: 0 };
    const share = { id: id(), kind: 'share-created', at: AT, sharer: S, cellId: 'doc', grant: G1, scope: 'read', expiryEpoch: null };
    const own = written('a');
    const answer = (): PollAnswer => ({ status: 200, body: { v: 1, operator: OP, events: [own, share], cursor: 'k-after', more: false, gap: false } });
    const script: PollAnswer[] = [ok([], { gap: true }), ...Array.from({ length: 8 }, answer), ok([])];
    const f = makeFeed({ root, clock: { t: Date.UTC(2026, 9, 3, 10) }, fail, script });
    f.feed.start();
    await until(() => f.polls.length === 1 && f.log.some((x) => x.startsWith('save')), 'the start');
    fail.appends = 1e9;   // from here no line, not even a gap marker, can be appended
    const savesBefore = f.log.filter((x) => x.startsWith('save')).length;
    const mapsBefore = f.log.filter((x) => x.startsWith('map')).length;
    const asOfBefore = f.feed.snapshot().asOf;
    await until(() => f.polls.length >= 3, 'two refused answers');
    fail.appends = 0;
    assert.equal(f.log.filter((x) => x.startsWith('save')).length, savesBefore, 'nothing saved');
    assert.equal(f.log.filter((x) => x.startsWith('map')).length, mapsBefore, 'the share map file is not rewritten');
    assert.equal(f.feed.snapshot().asOf, asOfBefore, 'asOf does not move');
    assert.equal(f.feed.snapshot().entries.length, 0, 'the share event is not applied');
    assert.deepEqual(f.polls.slice(1, 3).map((p) => p.cursor), [f.polls[1].cursor, f.polls[1].cursor], 'the same position, asked again');
    await until(f.exhausted, 'the script to end');
    await f.feed.stop();
    const firstWritten = f.polls.findIndex((p, i) => i > 0 && p.cursor !== f.polls[1].cursor);
    assert.ok(firstWritten > 2, 'every attempt before the first written one asked for the same position');
    assert.ok(f.sleeps.includes(1_000) && f.sleeps.includes(2_000), `the write retry backs off: ${f.sleeps.slice(0, 12)}`);
    // Written once the appends work: the line once (the ids were not marked seen by the refused attempts), the share
    // entry, and a saved position past the answer. Later copies of the answer are duplicates at the same position and
    // write nothing; the last answer moves the cursor and writes its position.
    assert.deepEqual(markers(f.lines('changes.ndjson')), ['gap:fresh-start', 'position', 'w:a', 'position', 'position']);
    assert.equal(f.feed.snapshot().entries.length, 1);
    assert.notEqual(f.state().cursor, null);
    assert.equal(f.state().ownCells, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a second process waits: it neither polls nor writes, reads as waiting, and takes over from the persisted position', async () => {
  const root = tmpRoot();
  const clock = { t: Date.UTC(2026, 9, 3, 10) };
  try {
    const a = makeFeed({ root, clock, script: [ok([], { gap: true }), ok([written('a')]), ok([])] });
    a.feed.start();
    await until(() => a.polls.length >= 2 && a.feed.role === 'writer', 'the first writer');
    const b = makeFeed({ root, clock, script: [ok([written('b')]), ok([])] });
    b.feed.start();
    await until(() => b.feed.role === 'waiting', 'the second process to wait');
    for (let i = 0; i < 200; i++) await tick();
    assert.equal(b.polls.length, 0, 'the waiting process does not poll');
    assert.equal(b.feed.mayWriteMap(), false, 'nor write the map');
    await until(a.exhausted, 'the first writer\'s script');
    const lastA = a.state().cursor;
    await a.feed.stop();
    assert.equal(existsSync(join(root, 'tenants', H, 'feed.lock')), false, 'the stopped writer gave the lease up');
    await until(b.exhausted, 'the second process to take over');
    await b.feed.stop();
    assert.equal(b.polls[0].cursor, lastA, 'it continues from the position the first writer saved');
    assert.equal(b.infoCalls(), 2, 'it read the offer again before polling: its own was older than a minute');
    // One file, one writer at a time, and no fresh-start gap at the takeover.
    assert.deepEqual(markers(b.lines('changes.ndjson')), ['gap:fresh-start', 'position', 'w:a', 'position', 'position', 'w:b', 'position', 'position']);
    // Saves of the waiting period: none.
    assert.equal(b.log.filter((x) => x.startsWith('save')).length, b.polls.length - 1 + 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a writer whose lease was taken stops writing and saving, and waits', async () => {
  const root = tmpRoot();
  const clock = { t: Date.UTC(2026, 9, 3, 10) };
  try {
    const script = [ok([], { gap: true }), ok([written('a')])];
    const a = makeFeed({ root, clock, script });
    a.feed.start();
    await until(() => a.polls.length === 2 && a.log.filter((x) => x.startsWith('save')).length === 2, 'two answers');
    // Another process takes the lease (as after this one stalled past 30 s).
    const lock = join(root, 'tenants', H, 'feed.lock');
    rmSync(lock);
    writeFileSync(lock, `${process.pid} ${Date.now()} 0011223344556677 ${hostname()}`);
    const saved = readFileSync(feedStatePath(H, a.env), 'utf8');
    script.push(ok([written('late')]));
    await until(() => a.feed.role === 'waiting', 'the writer to notice');
    await a.feed.stop();
    assert.equal(readFileSync(feedStatePath(H, a.env), 'utf8'), saved, 'the position is the new writer\'s now: not saved again');
    assert.equal(markers(a.lines('changes.ndjson')).includes('w:late'), false, 'the answer after the loss was not written');
    assert.equal(readFileSync(lock, 'utf8').includes('0011223344556677'), true, 'and the new holder\'s lease is untouched');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('own-cell events reconcile nothing in the share map, nor does an own resync; a resync naming no one does', async () => {
  const root = tmpRoot();
  try {
    const f = makeFeed({
      root, clock: { t: Date.UTC(2026, 9, 3, 10) },
      script: [
        ok([], { gap: true }),
        ok([written('a'), erased('b'), { id: id(), kind: 'resync', at: AT, reason: 'unappended', own: true }]),
        ok([]),
        ok([{ id: id(), kind: 'resync', at: AT, reason: 'dropped' }]),
        ok([]),
      ],
    });
    await runToEnd(f);
    assert.equal(f.listingCalls(), 2, 'the start, and the resync naming no one');
    assert.deepEqual(markers(f.lines('changes.ndjson')), ['gap:fresh-start', 'position', 'gap:server-gap', 'w:a', 'position', 'position', 'gap:server-gap', 'position', 'position']);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('the offer is read again daily, whether or not own-cell events are followed', async () => {
  // At least daily (an operator that starts offering the own-cell kinds is seen within a day by a share-only poller too).
  for (const [kinds, expected] of [[ALL_KINDS, 2], [SHARE_KINDS, 2]] as const) {
    const root = tmpRoot();
    try {
      const f = makeFeed({ root, clock: { t: Date.UTC(2026, 9, 3, 10) }, caps: caps(kinds), step: 13 * 3_600_000, script: [ok([], { gap: true }), ok([]), ok([])] });
      await runToEnd(f);
      assert.equal(f.infoCalls(), expected, JSON.stringify(kinds));
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('while the operator offers the own-cell kinds, only the lease holder writes the share map; without them, every process does', async () => {
  // The map is then the heartbeat of the own-cell files too: a process that cannot follow own cells (here: no writer,
  // as with the erasure feed off) polls share events only, and its fresh asOf must not vouch for files nobody writes.
  for (const [kinds, own, may] of [[ALL_KINDS, false, false], [SHARE_KINDS, false, true], [ALL_KINDS, true, true]] as const) {
    const root = tmpRoot();
    try {
      const f = makeFeed({ root, clock: { t: Date.UTC(2026, 9, 3, 10) }, caps: caps(kinds), own, script: [ok([], { gap: true }), ok([])] });
      f.feed.start();
      await until(f.exhausted, 'the script to end');
      assert.equal(f.feed.mayWriteMap(), may, `kinds ${kinds.length}, writer ${own}: while running`);
      await f.feed.stop();
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('with own-cell kinds asked for, an answer naming no events array is asked for again, never applied', async () => {
  const root = tmpRoot();
  try {
    const first = ok([], { gap: true });
    const eventless: PollAnswer = { status: 200, body: { v: 1, operator: OP, cursor: 'k-eventless', more: false, gap: false } };
    const f = makeFeed({ root, clock: { t: Date.UTC(2026, 9, 3, 10) }, script: [first, eventless, ok([written('a')])] });
    await runToEnd(f);
    const firstCursor = (first.body as { cursor: string }).cursor;
    assert.deepEqual(f.polls.slice(0, 3).map((p) => p.cursor), [null, firstCursor, firstCursor], 'the same position is asked for again');
    assert.ok(f.sleeps.includes(10_000), 'after a pause');
    assert.deepEqual(markers(f.lines('changes.ndjson')), ['gap:fresh-start', 'position', 'w:a', 'position']);
    assert.equal(f.lines('changes.ndjson').some((l) => l.cursor === 'k-eventless'), false, 'its cursor is never a position');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a listing run while the events route holds the writer back does not make the own-cell files read live', async () => {
  // Restart with a covered state, and the first poll answered 503: the share map is reconciled from the listing in the
  // meantime. For the writer that proves the share map only, so its heartbeat asOf waits for an answer naming the
  // own-cell kinds. Share-only polling (the control) keeps advancing it after the listing, as before.
  const start = Date.UTC(2026, 9, 3, 10);
  for (const [kinds, liveBeforeAnswer] of [[ALL_KINDS, false], [SHARE_KINDS, true]] as const) {
    const root = tmpRoot();
    try {
      mkdirSync(join(root, 'tenants', H), { recursive: true, mode: 0o700 });
      writeFileSync(feedStatePath(H, { SAIHM_ERASURE_FEED_DIR: root }), JSON.stringify({
        v: 1, savedAt: new Date(start).toISOString(), reconciledAt: new Date(start).toISOString(), capped: false,
        operator: OP, cursor: 'saved-1', since: AT, entries: [], seen: [], ownCells: true,
      }));
      const asOfAtSecondPoll: (string | null)[] = [];
      let f: ReturnType<typeof makeFeed> | undefined;
      f = makeFeed({
        root, clock: { t: start }, caps: caps(kinds), step: 1_000,
        script: [{ status: 503, body: { error: 'events_unavailable' } }, ok([])],
        onPoll: (n) => { if (n === 1) asOfAtSecondPoll.push(f!.feed.snapshot().asOf); },
      });
      await runToEnd(f);
      assert.equal(f.listingCalls() >= 1, true, `kinds ${kinds.length}: setup, the listing ran while held back`);
      assert.equal(asOfAtSecondPoll[0] !== null, liveBeforeAnswer, `kinds ${kinds.length}: asOf before any answer = ${String(asOfAtSecondPoll[0])}`);
      assert.notEqual(f.feed.snapshot().asOf, null, `kinds ${kinds.length}: the answer itself advances it`);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('a status that offers the own-cell kinds the read offer lacks: the map stops at once, the offer is read again, the writer starts', async () => {
  // The operator turns the kinds on while this process polls for share events alone (its offer, read at start, lacks
  // them). The status says so first; the share map must stop vouching for own-cell files nobody writes yet.
  const root = tmpRoot();
  try {
    const o: Opts = { root, clock: { t: Date.UTC(2026, 9, 3, 10) }, caps: caps(SHARE_KINDS), script: [ok([]), ok([]), ok([written('a')]), ok([])] };
    const mapAllowed: boolean[] = [];
    let f: ReturnType<typeof makeFeed> | undefined;
    o.onPoll = (n) => {
      if (n !== 1) return;
      o.caps = caps(ALL_KINDS);                                   // the server's offer now has them
      f!.feed.noteStatusOffer(['cell-written', 'cell-erased']);   // and the status says so
      mapAllowed.push(f!.feed.mayWriteMap());
    };
    f = makeFeed(o);
    await runToEnd(f);
    assert.deepEqual(mapAllowed, [false], 'no share map from a share-only poller once the status offers own cells');
    assert.equal(f.infoCalls(), 2, 'the offer was read again at once, not a day later');
    assert.deepEqual(f.polls.slice(0, 3).map((p) => p.kinds !== undefined), [false, false, true]);
    assert.deepEqual(markers(f.lines('changes.ndjson')).slice(0, 2), ['gap:kinds-changed', 'w:a'], 'its cursor moved past own-cell events');
    // Control: a status that offers nothing new changes nothing.
    const r2 = tmpRoot();
    try {
      const g = makeFeed({ root: r2, clock: { t: Date.UTC(2026, 9, 3, 10) }, caps: caps(SHARE_KINDS), script: [ok([]), ok([])] });
      g.feed.noteStatusOffer(['share-created']);
      await runToEnd(g);
      assert.equal(g.infoCalls(), 1);
      assert.equal(g.feed.mayWriteMap(), true);
    } finally { rmSync(r2, { recursive: true, force: true }); }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a status offer holds ten minutes: after that the offer read here decides who writes the share map again', () => {
  const root = tmpRoot();
  try {
    const o: Opts = { root, clock: { t: Date.UTC(2026, 9, 3, 10) }, caps: caps(SHARE_KINDS), script: [] };
    const f = makeFeed(o);
    assert.equal(f.feed.mayWriteMap(), true);
    f.feed.noteStatusOffer(['cell-written', 'cell-erased']);
    assert.equal(f.feed.mayWriteMap(), false, 'while the status word is fresh');
    o.clock.t += 600_001;
    assert.equal(f.feed.mayWriteMap(), true, 'an operator that withdrew the kinds since is not followed for ever');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a writer whose offer reads as no feed gives the lease up before it waits a day', async () => {
  const root = tmpRoot();
  try {
    const o: Opts = { root, clock: { t: Date.UTC(2026, 9, 3, 10) }, step: 25 * 3_600_000, script: [ok([], { gap: true }), ok([])] };
    const f = makeFeed(o);
    f.feed.start();
    await until(() => f.writer.holds(), 'the lease');
    o.caps = {};   // the next (daily) read of the offer finds no feed
    await until(() => f.infoCalls() >= 3, 'the offer read again');
    assert.equal(f.writer.holds(), false, 'no lease held through a day of not polling');
    await f.feed.stop();
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a writer that stops following (a 402, or an offer that reads as no feed) writes why to the map, then gives the lease up', async () => {
  const cases: [string, PollAnswer, string][] = [
    ['402', { status: 402, body: { error: 'share_tier_required' } }, 'tier'],
    ['no feed', ok([]), 'unsupported'],
  ];
  for (const [label, second, stopped] of cases) {
    const root = tmpRoot();
    try {
      // What the directory says at the moment the feed begins its day-long wait. No other process writes the map then:
      // the offer last read named the own-cell kinds, so this writer's last word is the only one a reader gets.
      let seen: { holds: boolean; map: Record<string, unknown> | undefined } | undefined;
      const map = join(root, 'tenants', H, 'share-states.json');
      const o: Opts = {
        root, clock: { t: Date.UTC(2026, 9, 3, 10) }, script: [ok([], { gap: true }), second],
        // The 'no feed' case: the first answer comes a day after the offer was read, which is read again and is gone.
        ...(stopped === 'unsupported' ? { step: 25 * 3_600_000, onPoll: (n: number) => { if (n === 0) o.caps = {}; } } : {}),
        onSleep: (ms) => {
          if (ms !== 86_400_000 || seen !== undefined) return;
          let m: Record<string, unknown> | undefined;
          try { m = JSON.parse(readFileSync(map, 'utf8')) as Record<string, unknown>; } catch { m = undefined; }
          seen = { holds: f.writer.holds(), map: m };
        },
      };
      const f = makeFeed(o);
      f.feed.start();
      await until(() => seen !== undefined, `${label}: the day-long wait`);
      await f.feed.stop();
      assert.equal(seen!.holds, false, `${label}: no lease held through a day of not polling`);
      assert.equal(seen!.map?.stopped, stopped, `${label}: the map says why following stopped`);
      assert.equal(seen!.map?.complete, false, `${label}: and that it is not complete`);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('a writer that gives the lease up saves its position at the hand-over, and none after it: the next writer\'s stands', async () => {
  const root = tmpRoot();
  try {
    // Answers half a second apart: the second answer's position is inside the save interval, so only the hand-over saves it.
    const second = ok([]);
    let atDay: { saves: string[]; role: string } | undefined;
    const o: Opts = {
      root, clock: { t: Date.UTC(2026, 9, 3, 10) }, step: 500, holdDay: true,
      script: [ok([], { gap: true }), second, { status: 402, body: { error: 'share_tier_required' } }],
      onSleep: (ms) => {
        if (ms === 86_400_000 && atDay === undefined) atDay = { saves: f.log.filter((l) => l.startsWith('save ')), role: f.feed.role };
      },
    };
    const f = makeFeed(o);
    f.feed.start();
    await until(() => atDay !== undefined, 'the day-long wait');
    assert.equal(atDay!.saves.at(-1), `save ${(second.body as { cursor: string }).cursor} own`, 'the hand-over saved the latest covered position');
    assert.equal(atDay!.role, 'waiting', 'it waits like any process that does not hold the lease');
    await f.feed.stop();   // a host that stops during the wait, after another process may have saved a later position
    assert.deepEqual(f.log.filter((l) => l.startsWith('save ')), atDay!.saves, 'no position saved after the lease was given up');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('an event time the map cannot hold (a year past 9999) is stored as this client\'s time, never as given', async () => {
  const root = tmpRoot();
  try {
    const created = { id: id(), kind: 'share-created', at: AT, sharer: S, cellId: 'c', grant: G1, scope: 'read', expiryEpoch: null };
    const revoked = { id: id(), kind: 'share-revoked', at: '+020000-01-01T00:00:00.000Z', sharer: S, cellId: 'c', grant: G1 };
    const f = makeFeed({ root, clock: { t: Date.UTC(2026, 9, 3, 10) }, caps: caps(SHARE_KINDS), script: [ok([created]), ok([revoked])] });
    await runToEnd(f);
    const ended = f.feed.snapshot().entries.find((e) => e.cellId === 'c');
    assert.ok(ended && ended.endedAt !== null && /^\d{4}-/.test(ended.endedAt), String(ended?.endedAt));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('stop: the writer saves a covered position, writes the map last while it still holds the lease, then gives it up', async () => {
  const root = tmpRoot();
  try {
    const f = makeFeed({ root, clock: { t: Date.UTC(2026, 9, 3, 10) }, script: [ok([], { gap: true }), ok([written('a')])] });
    f.feed.start();
    await until(f.exhausted, 'the script');
    const lock = join(root, 'tenants', H, 'feed.lock');
    let heldAtFinal = false;
    await f.feed.stop(() => { heldAtFinal = existsSync(lock) && f.writer.holds(); });
    assert.equal(heldAtFinal, true);
    assert.equal(existsSync(lock), false);
    assert.equal(f.state().ownCells, true);
    assert.equal(f.feed.role, 'solo');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a directory no process can write leaves the feed polling as before', async () => {
  const root = tmpRoot();
  try {
    mkdirSync(join(root, 'tenants', H), { recursive: true, mode: 0o700 });
    writeFileSync(join(root, 'tenants', H, 'someone-elses.db'), 'x');
    const f = makeFeed({ root, clock: { t: Date.UTC(2026, 9, 3, 10) }, store: false, script: [ok([], { gap: true }), ok([written('a')])] });
    await runToEnd(f);
    for (const p of f.polls) assert.deepEqual(Object.keys(p), ['v', 'cursor', 'waitMs', 'max']);
    assert.deepEqual(readdirSync(join(root, 'tenants', H)), ['someone-elses.db']);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('the share map is rewritten with a later asOf on every answer, empty ones included; positions only when the cursor moved', async () => {
  const root = tmpRoot();
  try {
    const same = (c: string): PollAnswer => ({ status: 200, body: { v: 1, operator: OP, events: [], cursor: c, more: false, gap: false } });
    const first = ok([], { gap: true });
    const c0 = (first.body as { cursor: string }).cursor;
    const f = makeFeed({ root, clock: { t: Date.UTC(2026, 9, 3, 10) }, script: [first, same(c0), same(c0), same(c0)] });
    await runToEnd(f);
    const maps = f.log.filter((x) => x.startsWith('map ')).map((x) => x.slice(4));
    assert.equal(maps.length, 4);
    for (let i = 1; i < maps.length; i++) assert.ok(maps[i] > maps[i - 1], `${maps}`);
    const file = JSON.parse(readFileSync(join(root, 'tenants', H, 'share-states.json'), 'utf8'));
    assert.equal(file.asOf, maps.at(-1));
    assert.deepEqual(markers(f.lines('changes.ndjson')), ['gap:fresh-start', 'position'], 'empty answers that keep the cursor write no marker');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a second stop saves nothing: the position is no longer this process\'s once the lease is given up', async () => {
  const root = tmpRoot();
  try {
    const f = makeFeed({ root, clock: { t: Date.UTC(2026, 9, 3, 10) }, script: [ok([], { gap: true }), ok([written('a')])] });
    f.feed.start();
    await until(f.exhausted, 'the script');
    await Promise.all([f.feed.stop(), f.feed.stop()]);
    const saved = readFileSync(feedStatePath(H, f.env), 'utf8');
    assert.equal(JSON.parse(saved).ownCells, true);
    // Another process takes the lease and saves a later position; a late third stop here must not overwrite it.
    const later = JSON.stringify({ ...JSON.parse(saved), cursor: 'theirs' });
    writeFileSync(feedStatePath(H, f.env), later);
    await f.feed.stop();
    assert.equal(readFileSync(feedStatePath(H, f.env), 'utf8'), later);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
