// The paged share listing in the client: a page is read whole or refused whole, an answer that is not a page is not
// supported and nothing of it is kept, the offer gates every page request, and a pass is complete only when every rule
// holds. Against a scripted hostile endpoint, each way a pass can go wrong ends it incomplete, within its bounds.
//
// Runner: npx tsx --test tests/client_shares_paged.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const HOME = mkdtempSync(join(tmpdir(), 'saihm-home-'));
process.env.SAIHM_HOME = HOME;
process.on('exit', () => rmSync(HOME, { recursive: true, force: true }));

const {
  SaihmProClient, SaihmEndpointError, sharesPageFrom, sharesPagedOffer, sharesPass, SHARES_PAGE_MAX, MAX_TOOL_SHARES_CURSOR_CHARS,
  SHARES_PASS_MAX_PAGES, SHARES_TOOL_PAGE_MAX, MAX_ANNOUNCEMENT_FIELD_CHARS, MAX_ANNOUNCEMENT_TOTAL_CHARS, SHARES_PAGED_ABSENT_MS,
} = await import('../src/client.js');
const { MAX_ENTRIES } = await import('../src/share-events.js');
type SharesPage = import('../src/client.js').SharesPage;

const S1 = '11'.repeat(32), S2 = '22'.repeat(32), S3 = '33'.repeat(32), G = 'a1'.repeat(32), C = 'c3'.repeat(32);
const row = (sharer: string, cellId: string, extra: Record<string, unknown> = {}) => ({ shared: true, sharer, cellId, scope: 'read', expiryEpoch: null, ...extra });
const answer = (rows: unknown[], next: string | null, extra: Record<string, unknown> = {}) => ({ mode: 'shares', added: rows, next, ...extra });
const code = (c: string, status?: number) => (e: unknown): boolean =>
  e instanceof SaihmEndpointError && e.code === c && (status === undefined || e.status === status);

// ── a page, checked whole ────────────────────────────────────────────────────────────────────────────────────────────

test('not a page: a legacy array, the one-answer listing, a full recall, a delta, a version listing are not supported', () => {
  const MARK = 'own-plaintext-marker';
  const notPages: unknown[] = [
    [],
    [row(S1, 'a')],
    { mode: 'shares', added: [row(S1, 'a')], liveSharedKeys: [`${S1}:a`] },
    [{ cellId: MARK, found: true, wire: { cellId: MARK } }, row(S1, 'a')],
    { mode: 'delta', added: [row(S1, 'a')], liveCellIds: [], liveSharedKeys: [] },
    { mode: 'list', cells: [], next: null },
    { added: [], next: null },
    null, 'shares', 7,
  ];
  for (const r of notPages) {
    assert.throws(() => sharesPageFrom(r, SHARES_PAGE_MAX), (e: unknown) => {
      assert.ok(code('shares_paging_unsupported', 501)(e), JSON.stringify(r));
      assert.ok(!(e as Error).message.includes(MARK), 'nothing of the answer is carried on');
      return true;
    });
  }
});

test('a bad next, a page over max, a next after no row, or a row this client cannot read refuses the page whole', () => {
  const ok1 = [row(S1, 'a')];
  const malformed: [string, unknown, number?][] = [
    ['next blank', answer(ok1, '')],
    ['next with a space', answer(ok1, 'a b')],
    ['next with =', answer(ok1, 'czE=')],
    ['next non-ASCII', answer(ok1, 'café')],
    ['next a number', answer(ok1, 5)],
    ['next over the wire bound', answer(ok1, 'a'.repeat(65_537))],
    ['next over the tool bound', answer(ok1, 'a'.repeat(MAX_TOOL_SHARES_CURSOR_CHARS + 1)), MAX_TOOL_SHARES_CURSOR_CHARS],
    ['rows not a list', answer({} as unknown as unknown[], null)],
    ['page over max', answer([row(S1, 'a'), row(S1, 'b'), row(S1, 'c')], null), undefined],
    ['next after no row', answer([], 'czE')],
    ['row not shared', answer([{ ...row(S1, 'a'), shared: false }], null)],
    ['row with an envelope', answer([row(S1, 'a', { wire: {} })], null)],
    ['sharer not a string', answer([row(S1, 'a', { sharer: 7 })], null)],
    ['cellId not a string', answer([row(S1, 'a', { cellId: null })], null)],
    ['scope missing', answer([{ shared: true, sharer: S1, cellId: 'a', expiryEpoch: null }], null)],
    ['expiry a number', answer([row(S1, 'a', { expiryEpoch: 5 })], null)],
    ['row not an object', answer([`${S1}:a`], null)],
    ['rows out of order', answer([row(S1, 'b'), row(S1, 'a')], null)],
    ['a key twice', answer([row(S1, 'a'), row(S1, 'a')], null)],
    ['sharer order', answer([row(S2, 'a'), row(S1, 'z')], null)],
  ];
  for (const [label, r, maxNext] of malformed) {
    const max = label === 'page over max' ? 2 : SHARES_PAGE_MAX;
    assert.throws(() => sharesPageFrom(r, max, maxNext), code('malformed_response', 502), label);
  }
  // Positive controls: the same shapes within the rules are pages.
  assert.equal(sharesPageFrom(answer(ok1, 'a'.repeat(65_536)), SHARES_PAGE_MAX).next?.length, 65_536);
  assert.equal(sharesPageFrom(answer(ok1, 'a'.repeat(MAX_TOOL_SHARES_CURSOR_CHARS)), SHARES_PAGE_MAX, MAX_TOOL_SHARES_CURSOR_CHARS).next?.length, MAX_TOOL_SHARES_CURSOR_CHARS);
  assert.equal(sharesPageFrom(answer([row(S1, 'a'), row(S1, 'b')], null), 2).rows.length, 2);
  assert.equal(sharesPageFrom(answer([], null), SHARES_PAGE_MAX).rows.length, 0, 'an empty last page is a page');
  assert.equal(sharesPageFrom(answer([{ shared: true, sharer: S1, cellId: 'a', scope: 'read' }], null), 1).rows[0]?.expiryEpoch, null, 'no expiry is none');
});

test('a page in key order by UTF-16 code units: colons, astral characters and U+FFxx; its helpers read or left out', () => {
  // U+1F600 is the pair D83D DE00, below U+FFFD as code units though above it as a code point.
  const rows = [row(S1, 'a'), row(S1, 'a:b'), row(S1, 'b'), row(S2, '\u{1F600}'), row(S2, '�'), row(S3, 'z', { grant: G, seq: '7', commitment: C, stale: true, expiryEpoch: '512' })];
  const p = sharesPageFrom(answer(rows, 's1.eA', { asOf: '2026-10-09T01:02:03.456Z', total: 9 }), SHARES_PAGE_MAX);
  assert.deepEqual(p.rows.map((r) => [r.sharer.slice(0, 2), r.cellId]), [['11', 'a'], ['11', 'a:b'], ['11', 'b'], ['22', '\u{1F600}'], ['22', '�'], ['33', 'z']]);
  assert.deepEqual(p.rows[5], { sharer: S3, cellId: 'z', scope: 'read', expiryEpoch: '512', grant: G, seq: '7', commitment: C, stale: true });
  assert.deepEqual([p.next, p.asOf, p.total], ['s1.eA', '2026-10-09T01:02:03.456Z', 9]);
  const loose = sharesPageFrom(answer([row(S1, 'a', { grant: 'x', seq: 7, commitment: 'C3', stale: 'no' })], null, { asOf: 'yesterday', total: -1 }), 1);
  assert.deepEqual([loose.rows[0]?.grant, loose.rows[0]?.seq, loose.rows[0]?.commitment, loose.rows[0]?.stale], [null, null, null, null]);
  assert.equal('asOf' in loose, false);
  assert.equal('total' in loose, false);
  for (const total of [1.5, '9', 2 ** 53, null]) assert.equal('total' in sharesPageFrom(answer([], null, { total }), 1), false, String(total));
});

test('the offer: sharesPaged with v 1, its max taken up to the wire ceiling; anything else offers nothing', () => {
  assert.equal(sharesPagedOffer(null), null);
  assert.equal(sharesPagedOffer({}), null);
  assert.equal(sharesPagedOffer({ sharesPaged: true }), null);
  assert.equal(sharesPagedOffer({ sharesPaged: [1] }), null);
  assert.equal(sharesPagedOffer({ sharesPaged: { v: [2], max: 10 } }), null);
  assert.equal(sharesPagedOffer({ sharesPaged: { v: 1, max: 10 } }), null);
  assert.equal(sharesPagedOffer({ sharesPaged: { v: [1] } }), SHARES_PAGE_MAX);
  assert.equal(sharesPagedOffer({ sharesPaged: { v: [2, 1], max: 500 } }), 500);
  assert.equal(sharesPagedOffer({ sharesPaged: { v: [1], max: 5000 } }), SHARES_PAGE_MAX);
  for (const max of [0, -1, 1.5, '10', null]) assert.equal(sharesPagedOffer({ sharesPaged: { v: [1], max } }), null, String(max));
});

// ── a pass, against a scripted endpoint ──────────────────────────────────────────────────────────────────────────────

/** Pages from a script; each page call moves the clock by `stepMs`. A thrown entry is thrown as the page's failure. */
function scripted(script: Array<SharesPage | Error | ((after: string | undefined) => SharesPage)>, stepMs = 1_000) {
  const afters: (string | undefined)[] = [];
  let clock = Date.UTC(2026, 9, 9, 8);
  let i = 0;
  const page = async (after: string | undefined): Promise<SharesPage> => {
    afters.push(after);
    clock += stepMs;
    const s = script[Math.min(i++, script.length - 1)]!;
    if (s instanceof Error) throw s;
    return typeof s === 'function' ? s(after) : s;
  };
  return { page, afters, now: () => clock, at: () => clock };
}
const pg = (rows: Array<[string, string]>, next: string | null): SharesPage =>
  ({ rows: rows.map(([sharer, cellId]) => ({ sharer, cellId, scope: 'read', expiryEpoch: null, grant: null, seq: null, commitment: null, stale: null })), next });
const BOUNDS = { maxEntries: 4_096, maxPages: 64, deadlineMs: 600_000 };

test('a complete pass: every page in turn, each next passed back exactly, dated at its first page', async () => {
  const sc = scripted([pg([[S1, 'a'], [S1, 'b']], 'c1'), pg([[S2, 'a']], 'c2'), pg([[S3, 'a']], null)]);
  const t0 = sc.now();
  const p = await sharesPass(sc.page, { ...BOUNDS, now: sc.now });
  assert.equal(p.complete, true);
  assert.equal('incomplete' in p, false);
  assert.deepEqual(sc.afters, [undefined, 'c1', 'c2']);
  assert.deepEqual(p.entries.map((e) => [e.sharer.slice(0, 2), e.cellId]), [['11', 'a'], ['11', 'b'], ['22', 'a'], ['33', 'a']]);
  assert.equal(p.pages, 3);
  assert.equal(p.startedAt, t0, 'dated when the first page was requested, not when the pass ended');
});

test('a hostile endpoint: the same next forever, keys that go back or repeat, endless 1-row pages, oversize and slow answers', async () => {
  const cases: [string, Parameters<typeof scripted>[0], Partial<typeof BOUNDS>, string, number?][] = [
    ['the same next forever', Array.from({ length: 70 }, (_, i) => pg([[S1, `k${String(i).padStart(3, '0')}`]], 'same')), {}, 'repeated', 2],
    ['decreasing keys across pages', [pg([[S2, 'a']], 'c1'), pg([[S1, 'z']], null)], {}, 'order', 2],
    ['a key twice across pages', [pg([[S1, 'a']], 'c1'), pg([[S1, 'a']], null)], {}, 'order', 2],
    ['endless 1-row pages', (Array.from({ length: 200 }, (_, i) => pg([[S1, `k${String(i).padStart(3, '0')}`]], `c${i}`))), {}, 'pages', 64],
    ['more keys than the map holds', [pg([[S1, 'a'], [S1, 'b']], 'c1'), pg([[S1, 'c'], [S1, 'd']], null)], { maxEntries: 3 }, 'entries', 2],
    ['an answer that is not a page (paging switched off)', [pg([[S1, 'a']], 'c1'), new SaihmEndpointError(501, 'shares_paging_unsupported', 'x')], {}, 'unsupported', 2],
    ['an oversize or unreadable page', [pg([[S1, 'a']], 'c1'), new SaihmEndpointError(502, 'malformed_response', 'x')], {}, 'malformed', 2],
    ['no answer', [new SaihmEndpointError(0, 'network', 'x')], {}, 'refused', 1],
    ['a tier that can no longer receive', [pg([[S1, 'a']], 'c1'), new SaihmEndpointError(402, 'share_tier_required', 'x')], {}, 'refused', 2],
  ];
  for (const [label, script, bounds, why, pages] of cases) {
    const sc = scripted(script);
    const p = await sharesPass(sc.page, { ...BOUNDS, ...bounds, now: sc.now });
    assert.deepEqual([p.complete, p.incomplete], [false, why], label);
    if (pages !== undefined) assert.equal(p.pages, pages, `${label}: pages`);
  }
  // Slow: each page takes four minutes, so the third ends past the ten-minute deadline.
  const slow = scripted(Array.from({ length: 5 }, (_, i) => pg([[S1, `k${i}`]], `c${i}`)), 240_000);
  const late = await sharesPass(slow.page, { ...BOUNDS, now: slow.now });
  assert.deepEqual([late.complete, late.incomplete, late.pages], [false, 'deadline', 3]);
  // Stopped between pages.
  const ctrl = new AbortController();
  const stop = scripted([(): SharesPage => { ctrl.abort(); return pg([[S1, 'a']], 'c1'); }, pg([[S1, 'b']], null)]);
  const stopped = await sharesPass(stop.page, { ...BOUNDS, now: stop.now, signal: ctrl.signal });
  assert.deepEqual([stopped.complete, stopped.incomplete, stopped.pages], [false, 'stopped', 1]);
});

test('bad_cursor starts the pass over once, dated at the new start; a second one ends it incomplete', async () => {
  const bad = new SaihmEndpointError(400, 'bad_cursor', 'x');
  const once = scripted([pg([[S1, 'a']], 'c1'), bad, pg([[S1, 'a']], 'c1'), pg([[S2, 'b']], null)]);
  const p = await sharesPass(once.page, { ...BOUNDS, now: once.now });
  assert.equal(p.complete, true, p.incomplete);
  assert.deepEqual(once.afters, [undefined, 'c1', undefined, 'c1']);
  assert.equal(p.pages, 4);
  assert.deepEqual(p.entries.map((e) => e.cellId), ['a', 'b'], 'the first attempt\'s rows are not kept twice');
  assert.equal(p.startedAt, Date.UTC(2026, 9, 9, 8) + 2_000, 'dated at the first page of the pass that completed');
  const twice = scripted([pg([[S1, 'a']], 'c1'), bad, pg([[S1, 'a']], 'c1'), bad]);
  const q = await sharesPass(twice.page, { ...BOUNDS, now: twice.now });
  assert.deepEqual([q.complete, q.incomplete, q.pages], [false, 'bad_cursor', 4]);
  // A cursor refused other than as a 400 is not started over.
  const other = scripted([pg([[S1, 'a']], 'c1'), new SaihmEndpointError(409, 'bad_cursor', 'x')]);
  const r = await sharesPass(other.page, { ...BOUNDS, now: other.now });
  assert.deepEqual([r.incomplete, r.pages], ['bad_cursor', 2]);
});

test('the bounds hold for the whole call, a pass started over included: its pages and its time are not counted afresh', async () => {
  const bad = new SaihmEndpointError(400, 'bad_cursor', 'x');
  const run = (n: number, from = 0) => Array.from({ length: n }, (_, i) => pg([[S1, `k${String(from + i).padStart(4, '0')}`]], `c${from + i}`));
  // Forty pages, a refused cursor, then a fresh start: the page bound counts every page the call asked for.
  const long = scripted([...run(40), bad, ...run(100)]);
  const p = await sharesPass(long.page, { ...BOUNDS, now: long.now });
  assert.deepEqual([p.complete, p.incomplete, p.pages, long.afters.length], [false, 'pages', BOUNDS.maxPages, BOUNDS.maxPages]);
  // Four minutes a page: the refusal comes at eight minutes, and the fresh start's first page ends past the call's ten.
  const slow = scripted([pg([[S1, 'a']], 'c1'), bad, pg([[S1, 'a']], null)], 240_000);
  const q = await sharesPass(slow.page, { ...BOUNDS, now: slow.now });
  assert.deepEqual([q.complete, q.incomplete, q.pages], [false, 'deadline', 3]);
});

test('a bound that is not a number is the default bound, never none', async () => {
  const run = (n: number, perPage = 1) =>
    Array.from({ length: n }, (_, i) => pg(Array.from({ length: perPage }, (_, j) => [S1, `k${String(i * perPage + j).padStart(6, '0')}`] as [string, string]), i === n - 1 ? null : `c${i}`));
  const NAN = { maxEntries: NaN, maxPages: NaN, deadlineMs: NaN };
  const pages = scripted(run(SHARES_PASS_MAX_PAGES + 10));
  const a = await sharesPass(pages.page, { ...NAN, now: pages.now });
  assert.deepEqual([a.complete, a.incomplete, a.pages], [false, 'pages', SHARES_PASS_MAX_PAGES]);
  const entries = scripted(run(Math.ceil(MAX_ENTRIES / SHARES_PAGE_MAX) + 1, SHARES_PAGE_MAX));
  const b = await sharesPass(entries.page, { ...NAN, now: entries.now });
  assert.deepEqual([b.complete, b.incomplete, b.entries.length], [false, 'entries', MAX_ENTRIES]);
  const slow = scripted(run(5), 240_000);
  const c = await sharesPass(slow.page, { ...NAN, now: slow.now });
  assert.deepEqual([c.complete, c.incomplete], [false, 'deadline']);
});

test('a tool page fits the announcement budget whole: its rows times four fields at the field cap', () => {
  assert.ok(SHARES_TOOL_PAGE_MAX * 4 * MAX_ANNOUNCEMENT_FIELD_CHARS <= MAX_ANNOUNCEMENT_TOTAL_CHARS);
});

test('keys the map cannot hold make the pass incomplete and are read past; a long cell id it can hold does not', async () => {
  const long = 'x'.repeat(100), big = 'y'.repeat(4_097), max = 'é'.repeat(2_048);
  const held = scripted([pg([[S1, long], [S1, max]], 'c1'), pg([[S2, 'a']], null)]);
  const p = await sharesPass(held.page, { ...BOUNDS, now: held.now });
  assert.equal(p.complete, true, 'a cell id over the 64-character field cap and within 4,096 bytes is a key the map holds');
  assert.deepEqual(p.entries.map((e) => e.cellId.length), [100, 2_048, 1]);
  for (const [label, bad] of [['a cell id over 4,096 bytes', [S1, big]], ['a sharer that is not 64 lowercase hex', ['0A'.repeat(32), 'a']]] as const) {
    const sc = scripted([pg([bad as [string, string]], 'c1'), pg([[S2, 'a']], null)]);
    const q = await sharesPass(sc.page, { ...BOUNDS, now: sc.now });
    assert.deepEqual([q.complete, q.incomplete], [false, 'unheld'], label);
    assert.deepEqual(q.entries.map((e) => e.cellId), ['a'], `${label}: read past, the rest kept`);
  }
});

// ── the client against an endpoint ───────────────────────────────────────────────────────────────────────────────────

interface Grant { sharer: string; cellId: string }
const enc = (g: Grant): string => 's1.' + Buffer.from(JSON.stringify([g.sharer, g.cellId])).toString('base64url');
const dec = (c: string): Grant => { const [sharer, cellId] = JSON.parse(Buffer.from(c.slice(3), 'base64url').toString('utf8')) as [string, string]; return { sharer, cellId }; };
const before = (a: Grant, b: Grant): boolean => a.sharer < b.sharer || (a.sharer === b.sharer && a.cellId < b.cellId);

/** An endpoint with a set of grants: the status's offer, pages in key order, and the one-answer listing. */
async function endpoint() {
  const st = {
    grants: [] as Grant[],
    offer: { v: [1], max: 1000 } as unknown,
    paging: true,
    /** What a page request gets while paging is off. */
    off: 'unpaged' as 'unpaged' | 'full',
    /** Answer a recall otherwise: a status and body, or undefined to answer as the wire says. */
    hook: undefined as undefined | ((params: Record<string, unknown>) => { status: number; body: unknown } | undefined),
    /** When set, the status answers this HTTP status and no features: a status that cannot be read. */
    statusFail: undefined as number | undefined,
    calls: [] as Array<{ method: string; params: Record<string, unknown> }>,
  };
  const sorted = (): Grant[] => [...st.grants].sort((a, b) => (before(a, b) ? -1 : before(b, a) ? 1 : 0));
  const rows = (gs: Grant[]) => gs.map((g) => ({ shared: true, sharer: g.sharer, cellId: g.cellId, scope: 'read', expiryEpoch: null }));
  const server: Server = createServer((req, res) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => {
      const send = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
      const { method, params = {} } = JSON.parse(buf) as { method: string; params?: Record<string, unknown> };
      st.calls.push({ method, params });
      if (method === 'saihm_status') {
        if (st.statusFail !== undefined) return send(st.statusFail, { error: 'unavailable' });
        return send(200, { agentIdHashHex: '00'.repeat(32), tier: 'PRO', ...(st.offer === undefined ? {} : { features: { sharesPaged: st.offer } }) });
      }
      if (method !== 'saihm_recall') return send(400, { error: 'unused' });
      const hooked = st.hook?.(params);
      if (hooked !== undefined) return send(hooked.status, hooked.body);
      const all = sorted();
      if (params.paged === true) {
        if (!st.paging) {
          return send(200, st.off === 'unpaged'
            ? { mode: 'shares', added: rows(all), liveSharedKeys: all.map((g) => `${g.sharer}:${g.cellId}`) }
            : [{ cellId: 'own', found: true, wire: { cellId: 'own' } }, ...rows(all)]);
        }
        let from = 0;
        if (typeof params.after === 'string') {
          let a: Grant;
          try { a = dec(params.after); } catch { return send(400, { error: 'bad_cursor' }); }
          from = all.findIndex((g) => before(a, g));
          if (from < 0) from = all.length;
        }
        const max = typeof params.max === 'number' ? params.max : 1000;
        const page = all.slice(from, from + max);
        const more = from + max < all.length;
        return send(200, { mode: 'shares', added: rows(page), next: more ? enc(page[page.length - 1]!) : null, asOf: new Date().toISOString(), total: all.length });
      }
      if (params.sharesOnly === true) return send(200, { mode: 'shares', added: rows(all), liveSharedKeys: all.map((g) => `${g.sharer}:${g.cellId}`) });
      return send(200, []);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`;
  const close = async () => { server.closeAllConnections(); await new Promise<void>((r) => server.close(() => r())); };
  return {
    st, url, close,
    recalls: () => st.calls.filter((c) => c.method === 'saihm_recall').map((c) => c.params),
    statuses: () => st.calls.filter((c) => c.method === 'saihm_status').length,
  };
}
const client = (url: string) => new SaihmProClient(url, 'Bearer t', new Uint8Array(32).fill(81), { tier: 'PRO' });

test('the offer gates every page request: none is sent without it, and the status is read once while pages come back', async () => {
  const ep = await endpoint();
  try {
    ep.st.grants = [{ sharer: S1, cellId: 'a' }, { sharer: S2, cellId: 'b' }];
    ep.st.offer = undefined;
    const c = client(ep.url);
    await assert.rejects(c.listSharesPage(), code('shares_paging_unsupported', 501));
    const pass = await c.listAllShares();
    assert.deepEqual([pass.complete, pass.incomplete], [false, 'unsupported']);
    assert.equal(ep.recalls().length, 0, 'no page request reached the endpoint');
    assert.equal(ep.statuses(), 1, 'the word that there is no offer is kept: one status read for both calls');
    // Offered, to a client not told otherwise: the request travels alone, asking the smaller of what was asked and what
    // is offered.
    ep.st.offer = { v: [1], max: 1 };
    const c1 = client(ep.url);
    const p1 = await c1.listSharesPage(undefined, 128);
    const p2 = await c1.listSharesPage(p1.next!, 128);
    assert.deepEqual(ep.recalls(), [{ sharesOnly: true, paged: true, max: 1 }, { sharesOnly: true, paged: true, after: p1.next, max: 1 }]);
    assert.deepEqual([p1.rows[0]?.cellId, p2.rows[0]?.cellId, p2.next], ['a', 'b', null]);
    assert.equal(ep.statuses(), 2, 'the offer was read once for both pages');
    ep.st.offer = { v: [1], max: 1000 };
    const c2 = client(ep.url);
    await c2.listSharesPage(undefined, 128);
    assert.deepEqual(ep.recalls().at(-1), { sharesOnly: true, paged: true, max: 128 }, 'never more than asked');
    // A size that is not a number asks what is offered, never a size the endpoint must refuse.
    await c2.listSharesPage(undefined, NaN);
    assert.deepEqual(ep.recalls().at(-1), { sharesOnly: true, paged: true, max: 1000 }, 'NaN asks the offer');
  } finally {
    await ep.close();
  }
});

test('the word that no paged listing is offered is kept for SHARES_PAGED_ABSENT_MS: no status read, no page asked for, until it runs out', async () => {
  const ep = await endpoint();
  const realNow = Date.now;
  let now = realNow();
  Date.now = () => now;
  try {
    ep.st.grants = [{ sharer: S1, cellId: 'a' }];
    ep.st.offer = undefined;
    const c = client(ep.url);
    for (let i = 0; i < 3; i++) {
      await assert.rejects(c.listSharesPage(), code('shares_paging_unsupported', 501));
      assert.equal((await c.listAllShares()).incomplete, 'unsupported');
    }
    assert.deepEqual([ep.statuses(), ep.recalls().length], [1, 0], 'one status read stands for every call while it is kept');
    // Switched on meanwhile: found once the word has run out, and not before.
    ep.st.offer = { v: [1], max: 1000 };
    now += SHARES_PAGED_ABSENT_MS - 1;
    await assert.rejects(c.listSharesPage(), code('shares_paging_unsupported', 501));
    assert.equal(ep.statuses(), 1);
    now += 1;
    const p = await c.listAllShares();
    assert.deepEqual([p.complete, p.entries.length, ep.statuses()], [true, 1, 2]);
  } finally {
    Date.now = realNow;
    await ep.close();
  }
});

test('a status that cannot be read is neither an offer nor an absence: the pass ends unread, no page is asked for, and it is read again', async () => {
  const ep = await endpoint();
  try {
    ep.st.grants = [{ sharer: S1, cellId: 'a' }];
    ep.st.statusFail = 503;
    const c = client(ep.url);
    const p = await c.listAllShares();
    assert.deepEqual([p.complete, p.incomplete, ep.recalls().length], [false, 'unread', 0]);
    // The page call (the tool's) surfaces the status's own failure, not a word that paging is off.
    await assert.rejects(c.listSharesPage(), (e: unknown) => e instanceof SaihmEndpointError && e.status === 503);
    assert.deepEqual([ep.statuses(), ep.recalls().length], [2, 0], 'not kept: read again, and still no page asked for');
    ep.st.statusFail = undefined;
    const q = await c.listAllShares();
    assert.deepEqual([q.complete, q.entries.length, ep.statuses()], [true, 1, 3]);
  } finally {
    await ep.close();
  }
});

test('an answer that is not a page is not supported, nothing of it is opened or kept, and the offer is read again', async () => {
  const ep = await endpoint();
  try {
    ep.st.grants = [{ sharer: S1, cellId: 'a' }];
    const c = client(ep.url);
    for (const off of ['unpaged', 'full'] as const) {
      await c.listSharesPage();   // a page: the offer is now held
      const statuses = ep.statuses();
      ep.st.paging = false;
      ep.st.off = off;
      // A full recall carries an own row whose envelope cannot open: had it been opened, the error would say so.
      await assert.rejects(c.listSharesPage(), code('shares_paging_unsupported', 501), off);
      assert.equal(ep.statuses(), statuses, `${off}: the held offer sent the request without reading the status`);
      ep.st.paging = true;
      const p = await c.listSharesPage();
      assert.equal(p.rows.length, 1, off);
      assert.equal(ep.statuses(), statuses + 1, `${off}: the offer was read again after the answer that was not a page`);
    }
    // A refusal is not a page either: the offer is read again after it too.
    for (const hooked of [{ status: 200, body: { error: 'x' } }, { status: 503, body: { error: 'busy' } }]) {
      const statuses = ep.statuses();
      ep.st.hook = (params) => (params.paged === true ? hooked : undefined);
      await assert.rejects(c.listSharesPage(), (e: unknown) => e instanceof SaihmEndpointError, String(hooked.status));
      ep.st.hook = undefined;
      await c.listSharesPage();
      assert.equal(ep.statuses(), statuses + 1, `${hooked.status}: read again once, before the next page`);
    }
  } finally {
    await ep.close();
  }
});

test('oversize and malformed pages from the endpoint end a pass incomplete; a page over the size asked is refused whole', async () => {
  const ep = await endpoint();
  try {
    ep.st.grants = Array.from({ length: 5 }, (_, i) => ({ sharer: S1, cellId: `k${i}` }));
    ep.st.offer = { v: [1], max: 2 };
    const c = client(ep.url);
    ep.st.hook = (params) => (params.paged === true ? { status: 200, body: { mode: 'shares', added: Array.from({ length: 3 }, (_, i) => row(S1, `k${i}`)), next: null } } : undefined);
    await assert.rejects(c.listSharesPage(), code('malformed_response', 502));
    const bad = await c.listAllShares();
    assert.deepEqual([bad.complete, bad.incomplete, bad.entries.length], [false, 'malformed', 0]);
    ep.st.hook = undefined;
    const p = await c.listAllShares();
    assert.deepEqual([p.complete, p.pages, p.entries.length], [true, 3, 5]);
  } finally {
    await ep.close();
  }
});

test('the library pass: 600 grants, the one at row 500 found, complete and never cut; a refused cursor starts it over once', async () => {
  const ep = await endpoint();
  try {
    const sharers = [S1, S2, S3, '44'.repeat(32), '55'.repeat(32), '66'.repeat(32)];
    ep.st.grants = Array.from({ length: 600 }, (_, i) => ({ sharer: sharers[Math.floor(i / 100)]!, cellId: `cell-${String(i % 100).padStart(3, '0')}` }));
    ep.st.grants[500] = { sharer: sharers[5]!, cellId: 'beacon-0500' };
    ep.st.offer = { v: [1], max: 100 };
    const c = client(ep.url);
    const p = await c.listAllShares();
    assert.equal(p.complete, true, p.incomplete);
    assert.equal(p.entries.length, 600, 'every grant, where a recall keeps a capped view');
    assert.ok(p.entries.some((e) => e.sharer === sharers[5] && e.cellId === 'beacon-0500'), 'the beacon is found');
    assert.equal(p.pages, 6);
    // The endpoint refuses a cursor once (a restart, say): the pass starts over and still completes.
    let refusals = 0;
    ep.st.hook = (params) => (params.paged === true && typeof params.after === 'string' && refusals++ === 0 ? { status: 400, body: { error: 'bad_cursor' } } : undefined);
    const again = await c.listAllShares();
    assert.deepEqual([again.complete, again.pages, again.entries.length], [true, 8, 600], 'one page, its refused successor, then six');
    // Refused every time: incomplete after one start-over.
    ep.st.hook = (params) => (params.paged === true && typeof params.after === 'string' ? { status: 400, body: { error: 'bad_cursor' } } : undefined);
    const never = await c.listAllShares();
    assert.deepEqual([never.complete, never.incomplete, never.pages], [false, 'bad_cursor', 4]);
  } finally {
    await ep.close();
  }
});
