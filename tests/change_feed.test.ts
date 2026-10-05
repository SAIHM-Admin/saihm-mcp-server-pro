// The writer of a tenant directory's own-cell event files: line shapes, the order of lines and markers, gap markers
// for every reason, fail-closed writing, rotation, the echo of this process's own erasures, and the lease that makes
// one process the writer. Every refusal is paired with the identical call corrected, asserted to succeed.
//
// Runner: npx tsx --test tests/change_feed.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ChangeFeedWriter, isoTime } from '../src/change-feed.ts';
import { FileLease, withFileLock } from '../src/file-lock.ts';
import { buildFeedLine, tenantDirIsOurs, PREDECESSOR_SUFFIX } from '../src/erasure-feed.ts';
import { readShareStates, writeShareStates } from '../src/share-states-file.ts';
import type { OwnAnswer, ShareStates } from '../src/share-events.ts';

const H = 'ab'.repeat(32);
const C1 = '44'.repeat(32), C2 = '55'.repeat(32);
const AT = '2026-10-03T09:00:00.000Z';
const ANCHOR = 'A-z.0_9:x';
let idn = 0;
const id = (): string => (++idn).toString(16).padStart(64, '0');
const written = (cellId: string, extra: Record<string, unknown> = {}) => ({ id: id(), kind: 'cell-written', at: AT, cellId, seq: '4', commitment: C1, ...extra });
const erased = (cellId: string, extra: Record<string, unknown> = {}) => ({ id: id(), kind: 'cell-erased', at: AT, cellId, complete: false, ...extra });

function setup(opts: { rotateBytes?: number; append?: (path: string, lines: readonly string[]) => void } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'saihm-changes-'));
  let clock = Date.UTC(2026, 9, 3, 9, 0, 1);
  const w = new ChangeFeedWriter({ agentIdHash: H, env: { SAIHM_ERASURE_FEED_DIR: root }, now: () => clock, ...opts });
  const lines = (p: string): Record<string, unknown>[] => {
    try { return readFileSync(p, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; }
  };
  return {
    root, w, advance: (ms: number) => { clock += ms; }, nowIso: () => new Date(clock).toISOString(),
    changes: () => lines(w.changesPath), erasures: () => lines(w.erasuresPath),
    raw: (p: string) => { try { return readFileSync(p, 'utf8'); } catch { return ''; } },
    done: () => { w.release(); rmSync(root, { recursive: true, force: true }); },
  };
}
const answer = (events: unknown[], extra: Partial<OwnAnswer> = {}): OwnAnswer => ({
  events, seen: () => false, cursor: `c${++idn}`, moved: true, gap: false, fresh: false, from: null,
  receivedAt: '2026-10-03T09:00:00.180Z', ...extra,
});

test('an answer: its lines in both files, then its position marker; exact keys, the identity on every line', () => {
  const t = setup();
  try {
    assert.equal(t.w.lead(), 'held');
    const a = answer([
      written('note-a'),
      erased('note-b', { complete: true, destructionAnchor: ANCHOR }),
      { id: id(), kind: 'share-created', at: AT, sharer: '11'.repeat(32), cellId: 'x', grant: 'a1'.repeat(32) },
      { id: id(), kind: 'some-future-kind', at: AT },
    ]);
    assert.equal(t.w.writeAnswer(a), 'written');
    const ch = t.changes();
    assert.deepEqual(ch.map((l) => Object.keys(l)), [
      ['v', 'kind', 'cellId', 'agentIdHash', 'at', 'seq', 'commitment', 'source'],
      ['v', 'kind', 'agentIdHash', 'at', 'cursor'],
    ]);
    assert.deepEqual(ch[0], { v: 1, kind: 'cell-written', cellId: 'note-a', agentIdHash: H, at: AT, seq: '4', commitment: C1, source: 'server-event' });
    assert.deepEqual(ch[1], { v: 1, kind: 'position', agentIdHash: H, at: t.nowIso(), cursor: a.cursor });
    const er = t.erasures();
    assert.deepEqual(er, [{ v: 1, cellId: 'note-b', agentIdHash: H, at: AT, receivedAt: a.receivedAt, complete: true, destructionAnchor: ANCHOR, source: 'server-event' }]);
    assert.deepEqual(Object.keys(er[0]), ['v', 'cellId', 'agentIdHash', 'at', 'receivedAt', 'complete', 'destructionAnchor', 'source']);
    for (const raw of [t.raw(t.w.changesPath), t.raw(t.w.erasuresPath)]) {
      assert.ok(raw.endsWith('\n'));
      for (const l of raw.split('\n').filter(Boolean)) assert.ok(Buffer.byteLength(l) + 1 <= 1024);
    }
    // Owner-only, like every file in the directory.
    assert.equal(statSync(t.w.changesPath).mode & 0o777, 0o600);
    assert.equal(statSync(t.w.dir).mode & 0o777, 0o700);
  } finally { t.done(); }
});

test('a gap the operator reports opens the answer; a fresh writer says fresh-start instead, once', () => {
  const t = setup();
  try {
    t.w.lead();
    const g = answer([written('a')], { gap: true });
    assert.equal(t.w.writeAnswer(g), 'written');
    const f = answer([], { gap: true, fresh: true });
    assert.equal(t.w.writeAnswer(f), 'written');
    assert.deepEqual(t.changes().map((l) => [l.kind, l.reason ?? null, l.cursor ?? l.cellId]), [
      ['gap', 'server-gap', g.cursor], ['cell-written', null, 'a'], ['position', null, g.cursor],
      ['gap', 'fresh-start', f.cursor], ['position', null, f.cursor],
    ]);
    // Positive control: the same answer without either reason writes no gap.
    const p = answer([written('b')]);
    t.w.writeAnswer(p);
    assert.deepEqual(t.changes().slice(5).map((l) => l.kind), ['cell-written', 'position']);
  } finally { t.done(); }
});

test('a writer owing coverage names its gap by the cursor it presented: kinds-changed for one, fresh-start for none', () => {
  const t = setup();
  try {
    t.w.lead();
    // A cursor presented without coverage moved past own-cell events no line records: the upgrade path.
    const a = answer([written('a')], { fresh: true, from: 'saved-1' });
    assert.equal(t.w.writeAnswer(a), 'written');
    assert.deepEqual(t.changes().map((l) => [l.kind, l.reason ?? null, l.cursor ?? l.cellId]), [
      ['gap', 'kinds-changed', a.cursor], ['cell-written', null, 'a'], ['position', null, a.cursor],
    ]);
    // Asking from the head is a fresh start, whatever came before; and the operator's own gap does not rename either.
    const b = answer([written('b')], { fresh: true, from: null, gap: true });
    assert.equal(t.w.writeAnswer(b), 'written');
    // Covered, the presented cursor names nothing: no gap at all.
    const c = answer([written('c')], { from: 'k9' });
    assert.equal(t.w.writeAnswer(c), 'written');
    assert.deepEqual(t.changes().slice(3).map((l) => [l.kind, l.reason ?? null]), [
      ['gap', 'fresh-start'], ['cell-written', null], ['position', null], ['cell-written', null], ['position', null],
    ]);
  } finally { t.done(); }
});

test('an answer that does not move the cursor writes no position marker', () => {
  const t = setup();
  try {
    t.w.lead();
    assert.equal(t.w.writeAnswer(answer([], { moved: false })), 'written');
    assert.equal(existsSync(t.w.changesPath), false, 'nothing to write, nothing created');
    assert.equal(t.w.writeAnswer(answer([], { moved: true })), 'written');
    assert.deepEqual(t.changes().map((l) => l.kind), ['position']);
  } finally { t.done(); }
});

test('an event that cannot be a line is covered by an unwritable-event gap, never cut or dropped', () => {
  const cases: Array<[string, Record<string, unknown>]> = [
    ['an own id over 64 characters', written('x'.repeat(65))],
    ['an empty id', written('')],
    ['a seq that is not digits', written('a', { seq: '4a' })],
    ['a missing commitment', written('a', { commitment: undefined })],
    ['an upper-case commitment', written('a', { commitment: 'ab'.repeat(32).toUpperCase() })],
    ['a time with no zone', written('a', { at: '2026-10-03T09:00:00' })],
    ['an event with no id', { ...written('a'), id: undefined }],
    ['an erasure with an id over 64 characters', erased('y'.repeat(65))],
    ['an erasure with no time', erased('a', { at: 'yesterday' })],
    ['an entry that is not an event: null', null as unknown as Record<string, unknown>],
    ['an entry that is not an event: a number', 5 as unknown as Record<string, unknown>],
    ['an entry that is not an event: an array', [written('a')] as unknown as Record<string, unknown>],
  ];
  for (const [what, ev] of cases) {
    const t = setup();
    try {
      t.w.lead();
      const a = answer([written('ok'), ev, erased('gone')]);
      assert.equal(t.w.writeAnswer(a), 'written', what);
      assert.deepEqual(t.changes().map((l) => [l.kind, l.reason ?? null]), [
        ['gap', 'unwritable-event'], ['cell-written', null], ['position', null],
      ], what);
      assert.equal(t.changes()[0].cursor, a.cursor, `${what}: the gap carries the answer's cursor`);
      assert.deepEqual(t.erasures().map((l) => l.cellId), ['gone'], `${what}: the other lines are still written`);
    } finally { t.done(); }
  }
  // Positive control: the boundary id of 64 characters is a line, and a time with an offset is normalised to UTC.
  const t = setup();
  try {
    t.w.lead();
    t.w.writeAnswer(answer([written('x'.repeat(64), { at: '2026-10-03T11:00:00+02:00' })]));
    assert.deepEqual(t.changes().map((l) => [l.kind, l.cellId ?? null, l.at]), [['cell-written', 'x'.repeat(64), AT], ['position', null, t.nowIso()]]);
  } finally { t.done(); }
});

test('an own resync is a gap marker, with or without an id; a seen one is not repeated; a sharer\'s is not one', () => {
  const run = (events: unknown[], seen: string[] = []) => {
    const t = setup();
    try {
      t.w.lead();
      t.w.writeAnswer(answer(events, { seen: (x) => seen.includes(x) }));
      return t.changes().map((l) => [l.kind, l.reason ?? null]);
    } finally { t.done(); }
  };
  const ownId = id();
  assert.deepEqual(run([{ id: ownId, kind: 'resync', reason: 'unappended', own: true }]), [['gap', 'server-gap'], ['position', null]]);
  assert.deepEqual(run([{ kind: 'resync', reason: 'unappended', own: true }]), [['gap', 'server-gap'], ['position', null]], 'no id: still a gap');
  assert.deepEqual(run([{ id: id(), kind: 'resync', reason: 'dropped' }]), [['gap', 'server-gap'], ['position', null]], 'no sharer: every kind');
  assert.deepEqual(run([{ id: ownId, kind: 'resync', own: true }], [ownId]), [['position', null]], 'seen: its gap was written');
  assert.deepEqual(run([{ id: id(), kind: 'resync', reason: 'dropped', sharer: '11'.repeat(32) }]), [['position', null]], 'one sharer: shares only');
});

test('duplicates, events already seen and shrunk events write nothing', () => {
  const t = setup();
  try {
    t.w.lead();
    const dup = written('a');
    const old = written('b');
    t.w.writeAnswer(answer([dup, dup, old, { id: id(), kind: 'cell-written', shrunk: true }, { id: id(), kind: 'cell-erased', shrunk: true }], { seen: (x) => x === old.id }));
    assert.deepEqual(t.changes().map((l) => [l.kind, l.cellId ?? null]), [['cell-written', 'a'], ['position', null]]);
    assert.deepEqual(t.erasures(), []);
  } finally { t.done(); }
});

test("this process's own erasure is recognised by its anchor alone: that report is not written twice, any other is", () => {
  const t = setup();
  try {
    t.w.lead();
    t.w.noteOwnErasure('a', null);      // no anchor: nothing to recognise its report by, so nothing is recorded
    t.w.noteOwnErasure('c', ANCHOR);
    t.w.noteOwnErasure('d', ANCHOR);
    t.w.noteOwnErasure('x', 'x-anchor'); // its report never comes (lost in a gap, say)
    t.w.writeAnswer(answer([
      erased('a'),                                                   // anchor-less: written (a second line, safe to apply twice)
      erased('c', { complete: true, destructionAnchor: ANCHOR }),    // the same anchor: this process's own, skipped
      erased('d', { complete: true, destructionAnchor: 'other' }),   // another anchor: another erasure, written
      erased('e'),                                                   // never recorded here: written
    ]));
    assert.deepEqual(t.erasures().map((l) => [l.cellId, l.complete]), [['a', false], ['d', true], ['e', false]]);
    // A record whose report never came must not swallow a LATER erasure of the same id (the id written again, then
    // erased elsewhere with no anchor): only the very anchor it recorded is its report.
    t.w.writeAnswer(answer([erased('x')]));
    assert.deepEqual(t.erasures().map((l) => l.cellId).slice(-1), ['x']);
    // A report is recognised once: a second report of that same anchor (another event id) is written.
    t.w.writeAnswer(answer([erased('c', { complete: true, destructionAnchor: ANCHOR })]));
    assert.deepEqual(t.erasures().map((l) => l.cellId).slice(-1), ['c']);
    // A record expires with the event window.
    t.w.noteOwnErasure('f', 'f-anchor');
    t.advance(604_800_001);
    t.w.writeAnswer(answer([erased('f', { complete: true, destructionAnchor: 'f-anchor' })]));
    assert.deepEqual(t.erasures().map((l) => l.cellId).slice(-1), ['f']);
  } finally { t.done(); }
});

test('an answer refused as a whole does not consume the record of an own erasure', () => {
  let fail = true;
  const t = setup({ append: (p, lines) => { if (fail) throw new Error('disk full'); if (lines.length) writeFileSync(p, lines.join(''), { flag: 'a' }); } });
  try {
    t.w.lead();
    t.w.noteOwnErasure('a', ANCHOR);
    assert.equal(t.w.writeAnswer(answer([erased('a', { complete: true, destructionAnchor: ANCHOR })])), 'refused');
    fail = false;
    assert.equal(t.w.writeAnswer(answer([erased('a', { complete: true, destructionAnchor: ANCHOR })])), 'written');
    assert.deepEqual(t.erasures(), [], 'still recognised as this process\'s own after the refused answer');
  } finally { t.done(); }
});

test('complete:true without an anchor of the agreed shape is written as complete:false, with no anchor', () => {
  const t = setup();
  try {
    t.w.lead();
    const bad = [undefined, '', 'a'.repeat(257), 'has space', 'semi;colon', 7];
    t.w.writeAnswer(answer(bad.map((destructionAnchor, i) => erased(`c${i}`, { complete: true, destructionAnchor }))));
    for (const l of t.erasures()) {
      assert.equal(l.complete, false, JSON.stringify(l));
      assert.equal('destructionAnchor' in l, false);
    }
    assert.equal(t.erasures().length, bad.length);
    // Positive control: the longest anchor of the agreed shape is kept verbatim.
    t.w.writeAnswer(answer([erased('ok', { complete: true, destructionAnchor: 'a'.repeat(256) })]));
    assert.deepEqual(t.erasures().slice(-1).map((l) => [l.complete, l.destructionAnchor]), [[true, 'a'.repeat(256)]]);
    // An anchor without complete:true is not a statement of completion either.
    t.w.writeAnswer(answer([erased('half', { complete: false, destructionAnchor: ANCHOR })]));
    assert.deepEqual(t.erasures().slice(-1).map((l) => [l.complete, 'destructionAnchor' in l]), [[false, false]]);
  } finally { t.done(); }
});

test("an erasure event's reason is carried as a forget's is: beside its own complete:false, one of the two values, else none", () => {
  const t = setup();
  try {
    t.w.lead();
    // [cellId, the event's fields beyond `at` and `cellId`, the line's `complete`, `reason` and `destructionAnchor`]
    const cases: [string, Record<string, unknown>, boolean, string | undefined, string | undefined][] = [
      ['nf', { complete: false, reason: 'not-found' }, false, 'not-found', undefined],        // nothing (more) to erase
      ['na', { complete: false, reason: 'not-attested' }, false, 'not-attested', undefined],  // forget again later
      ['old', { complete: false }, false, undefined, undefined],                              // an older server: none
      ['done', { complete: true, destructionAnchor: ANCHOR, reason: 'not-found' }, true, undefined, ANCHOR],
      // complete:true without an anchor is written as false, but the event did not say false: no reason either.
      ['bare', { complete: true, reason: 'not-attested' }, false, undefined, undefined],
      ['nocomp', { complete: undefined, reason: 'not-found' }, false, undefined, undefined],
      ['strcomp', { complete: 'false', reason: 'not-found' }, false, undefined, undefined],
      // Outside the two values: omitted, never mapped onto the nearest one.
      ['other', { complete: false, reason: 'because' }, false, undefined, undefined],
      ['case', { complete: false, reason: 'Not-Found' }, false, undefined, undefined],
      ['space', { complete: false, reason: 'not-found ' }, false, undefined, undefined],
      ['empty', { complete: false, reason: '' }, false, undefined, undefined],
      ['num', { complete: false, reason: 7 }, false, undefined, undefined],
      ['arr', { complete: false, reason: ['not-found'] }, false, undefined, undefined],
      ['obj', { complete: false, reason: { reason: 'not-attested' } }, false, undefined, undefined],
    ];
    const a = answer(cases.map(([cellId, extra]) => erased(cellId, extra)));
    assert.equal(t.w.writeAnswer(a), 'written');
    assert.deepEqual(
      t.erasures(),
      cases.map(([cellId, , complete, reason, anchor]) => ({
        v: 1, cellId, agentIdHash: H, at: AT, receivedAt: a.receivedAt, complete,
        ...(reason !== undefined ? { reason } : {}), ...(anchor !== undefined ? { destructionAnchor: anchor } : {}),
        source: 'server-event',
      })),
    );
    // Every event became a line: none was turned into a gap.
    assert.deepEqual(t.changes().map((l) => l.kind), ['position']);
    assert.deepEqual(Object.keys(t.erasures()[0]!), ['v', 'cellId', 'agentIdHash', 'at', 'receivedAt', 'complete', 'reason', 'source']);
  } finally { t.done(); }
});

test('rotation: a file past the size moves to .1, replacing the last one, and a rotation gap opens the fresh file', () => {
  const t = setup({ rotateBytes: 300 });
  try {
    t.w.lead();
    t.w.writeAnswer(answer([written('a'), written('b')]));   // > 300 bytes
    const first = t.raw(t.w.changesPath);
    assert.ok(Buffer.byteLength(first) > 300);
    const a = answer([written('c')]);
    t.w.writeAnswer(a);
    assert.equal(t.raw(`${t.w.changesPath}.1`), first, 'the whole old file is the predecessor');
    assert.deepEqual(t.changes().map((l) => [l.kind, l.reason ?? null, l.cursor ?? l.cellId]), [
      ['gap', 'rotation', a.cursor], ['cell-written', null, 'c'], ['position', null, a.cursor],
    ]);
    // Grow both files past the size; the next answer rotates both: two rotation gaps, in the fresh changes file.
    t.w.writeAnswer(answer([written('d'), erased('e1'), erased('e2')]));
    const second = t.raw(t.w.changesPath);
    const b = answer([erased('f')]);
    t.w.writeAnswer(b);
    assert.equal(t.raw(`${t.w.changesPath}.1`), second, 'the previous predecessor is replaced');
    assert.deepEqual(t.changes().map((l) => [l.kind, l.reason ?? null]), [['gap', 'rotation'], ['gap', 'rotation'], ['position', null]]);
    assert.deepEqual(t.erasures().map((l) => l.cellId), ['f']);
    assert.deepEqual(readFileSync(`${t.w.erasuresPath}.1`, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l).cellId), ['e1', 'e2']);
  } finally { t.done(); }
  // Positive control: under the size, nothing moves and no rotation gap is written.
  const u = setup({ rotateBytes: 100_000 });
  try {
    u.w.lead();
    for (let i = 0; i < 3; i++) u.w.writeAnswer(answer([written(`k${i}`), erased(`k${i}`)]));
    assert.equal(existsSync(`${u.w.changesPath}.1`) || existsSync(`${u.w.erasuresPath}.1`), false);
    assert.equal(u.changes().some((l) => l.kind === 'gap'), false);
  } finally { u.done(); }
});

function failing(rotateBytes: number) {
  const ctl = { erasures: false, changes: 0 };
  const t = setup({
    rotateBytes,
    append: (p, lines) => {
      const which = p.endsWith('changes.ndjson') ? 'changes' : 'erasures';
      if (which === 'erasures' && ctl.erasures && lines.length) throw new Error('EIO');
      if (which === 'changes' && ctl.changes > 0 && lines.length) { ctl.changes--; throw new Error('ENOSPC'); }
      if (lines.length) writeFileSync(p, lines.join(''), { flag: 'a', mode: 0o600 });
    },
  });
  return { t, ctl };
}

test('fail closed: a failed line is covered by a gap and the position follows; with no marker possible the answer is refused', () => {
  const { t, ctl } = failing(100_000);
  try {
    t.w.lead();
    // An erasure line that cannot be appended: a gap covers it, and the position still follows.
    ctl.erasures = true;
    const a = answer([erased('x'), written('w')]);
    assert.equal(t.w.writeAnswer(a), 'written');
    assert.deepEqual(t.changes().map((l) => [l.kind, l.reason ?? null, l.cursor ?? null]), [['gap', 'unwritable-event', a.cursor], ['cell-written', null, null], ['position', null, a.cursor]]);
    ctl.erasures = false;
    // The lines-and-position append fails once: a gap, then the position, each appended alone.
    ctl.changes = 1;
    const b = answer([written('v')]);
    assert.equal(t.w.writeAnswer(b), 'written');
    assert.deepEqual(t.changes().slice(3).map((l) => [l.kind, l.reason ?? null]), [['gap', 'unwritable-event'], ['position', null]]);
    // A gap already in place for the answer covers a failed line: no second gap is written.
    ctl.changes = 1;
    const g = answer([written('t')], { gap: true });
    ctl.changes = 0;
    assert.equal(t.w.writeAnswer(g), 'written');
    ctl.erasures = true;
    const h = answer([erased('s')], { gap: true });
    assert.equal(t.w.writeAnswer(h), 'written');
    ctl.erasures = false;
    assert.deepEqual(t.changes().slice(5).map((l) => [l.kind, l.reason ?? null]), [
      ['gap', 'server-gap'], ['cell-written', null], ['position', null], ['gap', 'server-gap'], ['position', null],
    ]);
    // The gap itself cannot be appended: refused.
    ctl.changes = 1;
    assert.equal(t.w.writeAnswer(answer([written('r')], { gap: true })), 'refused');
    // Positions only when the cursor moved, and an unmoved refused answer still refuses.
    ctl.changes = 2;
    assert.equal(t.w.writeAnswer(answer([written('q')])), 'refused', 'lines fail, then the gap fails');
    ctl.changes = 0;
  } finally { t.done(); }
});

test('a rotation whose marker cannot be appended owes that marker to the next answer', () => {
  // One answer's line and position pass this size; a rotation gap and a position alone do not.
  const { t, ctl } = failing(350);
  try {
    t.w.lead();
    t.w.writeAnswer(answer([written('a')]));
    assert.ok(statSync(t.w.changesPath).size > 350);
    ctl.changes = 99;
    assert.equal(t.w.writeAnswer(answer([written('u')])), 'refused');
    assert.ok(existsSync(`${t.w.changesPath}.1`), 'the rename happened');
    assert.equal(existsSync(t.w.changesPath), false);
    ctl.changes = 0;
    const d = answer([]);
    assert.equal(t.w.writeAnswer(d), 'written');
    assert.deepEqual(t.changes().map((l) => [l.kind, l.reason ?? null, l.cursor]), [['gap', 'rotation', d.cursor], ['position', null, d.cursor]]);
    // Paid once: the answer after it owes nothing.
    assert.ok(statSync(t.w.changesPath).size <= 350);
    const e = answer([]);
    t.w.writeAnswer(e);
    assert.deepEqual(t.changes().slice(2).map((l) => l.kind), ['position']);
  } finally { t.done(); }
});

test('a crash between moving changes.ndjson and writing its marker is recovered by the next lead()', () => {
  // The crash window is between the move of changes.ndjson and this SAME writeAnswer call's marker append —
  // both synchronous, so nothing in this package can await across it to reproduce it by timing. Reproduced instead
  // by constructing the disk state that window leaves directly: make the move the writer would have made, and
  // nothing else, then start a SECOND writer (as a restart constructs one) over the same directory.
  for (const state of ['absent', 'empty'] as const) {
    // 'empty': the marker append failed through the real append, which creates the file and takes the failed line
    // back to the size before it - nothing - so the move left an EMPTY file rather than none.
    const root = mkdtempSync(join(tmpdir(), 'saihm-changes-'));
    try {
      const clock = { t: Date.UTC(2026, 9, 4, 8) };
      const w1 = new ChangeFeedWriter({ agentIdHash: H, env: { SAIHM_ERASURE_FEED_DIR: root }, now: () => clock.t, rotateBytes: 300 });
      assert.equal(w1.lead(), 'held');
      assert.equal(w1.writeAnswer(answer([written('a'), written('b')])), 'written'); // > 300 bytes
      assert.ok(statSync(w1.changesPath).size > 300, 'premise: the file is over the rotate size');
      renameSync(w1.changesPath, `${w1.changesPath}${PREDECESSOR_SUFFIX}`); // exactly the writer's move; no marker follows
      if (state === 'empty') writeFileSync(w1.changesPath, '', { mode: 0o600 });
      assert.equal(existsSync(w1.changesPath), state === 'empty', `premise: the crash state — current ${state}, predecessor present`);
      w1.release();
      const w2 = new ChangeFeedWriter({ agentIdHash: H, env: { SAIHM_ERASURE_FEED_DIR: root }, now: () => clock.t, rotateBytes: 300 });
      assert.equal(w2.lead(), 'held', 'a fresh writer still takes the lease: the crashed one released nothing to contend');
      const c = answer([written('c')]);
      assert.equal(w2.writeAnswer(c), 'written');
      const lines = (p: string): Record<string, unknown>[] => readFileSync(p, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
      assert.deepEqual(lines(w2.changesPath).map((l) => [l.kind, l.reason ?? null, l.cursor ?? l.cellId]), [
        ['gap', 'rotation', c.cursor], ['cell-written', null, 'c'], ['position', null, c.cursor],
      ], 'the owed rotation marker surfaces on the new writer\'s first answer, never lost');
      w2.release();
      // Positive control: a THIRD writer taking the lease after w2's clean recovery finds the current file present
      // again (w2's answer recreated it) and owes nothing -- crashedRotation must not fire on an ordinary
      // restart just because a (long since marked) predecessor file still exists from the earlier rotation. A large
      // (default) rotateBytes here, deliberately NOT 300: w3's own tiny answer must not ALSO cross the size on its
      // own, which would be a second genuine rotation and confound the question this control asks.
      const w3 = new ChangeFeedWriter({ agentIdHash: H, env: { SAIHM_ERASURE_FEED_DIR: root }, now: () => clock.t });
      assert.equal(w3.lead(), 'held');
      const d = answer([written('d')]);
      assert.equal(w3.writeAnswer(d), 'written');
      assert.deepEqual(lines(w3.changesPath).slice(3).map((l) => [l.kind, l.reason ?? null]), [
        ['cell-written', null], ['position', null],
      ], 'no spurious rotation gap on a normal restart');
      w3.release();
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('erasures.ndjson moves only after its marker is in, and a restart after a clean move owes nothing', () => {
  // Every process of the identity appends to erasures.ndjson, so its absence proves nothing about a crash: its marker
  // must be durable BEFORE it moves, and a crash between the two then leaves a spare marker, never a missing one.
  const root = mkdtempSync(join(tmpdir(), 'saihm-changes-'));
  try {
    const env = { SAIHM_ERASURE_FEED_DIR: root };
    const seenAtMarker: boolean[] = [];
    const w1 = new ChangeFeedWriter({
      agentIdHash: H, env, rotateBytes: 300,
      append: (p, lines) => {
        if (!lines.length) return;
        // At the moment a rotation marker is appended, the erasures file must still be where it was.
        if (p.endsWith('changes.ndjson') && lines.some((l) => l.includes('"reason":"rotation"')))
          seenAtMarker.push(existsSync(`${w1.erasuresPath}${PREDECESSOR_SUFFIX}`));
        writeFileSync(p, lines.join(''), { flag: 'a', mode: 0o600 });
      },
    });
    assert.equal(w1.lead(), 'held');
    assert.equal(w1.writeAnswer(answer([erased('a'), erased('b')], { moved: false })), 'written');
    assert.ok(statSync(w1.erasuresPath).size > 300, 'premise: erasures.ndjson is past the size');
    const c = answer([written('c')]);
    assert.equal(w1.writeAnswer(c), 'written');
    assert.deepEqual(seenAtMarker, [false], 'the marker went in while erasures.ndjson was still in place');
    assert.ok(existsSync(`${w1.erasuresPath}${PREDECESSOR_SUFFIX}`) && !existsSync(w1.erasuresPath), 'then it moved');
    const lines = (p: string): Record<string, unknown>[] => readFileSync(p, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    assert.deepEqual(lines(w1.changesPath).map((l) => [l.kind, l.reason ?? null, l.cursor ?? l.cellId]), [
      ['gap', 'rotation', c.cursor], ['cell-written', null, 'c'], ['position', null, c.cursor],
    ]);
    w1.release();
    // A restart before any erasure line recreates erasures.ndjson: the move was marked, so nothing is owed.
    const w2 = new ChangeFeedWriter({ agentIdHash: H, env, rotateBytes: 1_000_000 });
    assert.equal(w2.lead(), 'held');
    const d = answer([written('d')]);
    assert.equal(w2.writeAnswer(d), 'written');
    assert.deepEqual(lines(w2.changesPath).slice(3).map((l) => [l.kind, l.reason ?? null]), [['cell-written', null], ['position', null]],
      'no spurious rotation gap on a restart after a clean erasures move');
    w2.release();
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('erasures.ndjson that cannot move yet is marked once: the moves that fail retry under that marker', () => {
  const root = mkdtempSync(join(tmpdir(), 'saihm-changes-'));
  try {
    const w = new ChangeFeedWriter({ agentIdHash: H, env: { SAIHM_ERASURE_FEED_DIR: root }, rotateBytes: 300 });
    assert.equal(w.lead(), 'held');
    w.writeAnswer(answer([erased('a'), erased('b')], { moved: false }));
    mkdirSync(`${w.erasuresPath}${PREDECESSOR_SUFFIX}/held`, { recursive: true }); // a predecessor the move cannot replace
    const rotations = () => readFileSync(w.changesPath, 'utf8').split('\n').filter((l) => l.includes('"reason":"rotation"')).length;
    for (let i = 0; i < 3; i++) assert.equal(w.writeAnswer(answer([written(`k${i}`)])), 'written');
    assert.equal(rotations(), 1, 'one marker for one rotation, however often its move fails');
    assert.ok(existsSync(w.erasuresPath), 'premise: the move kept failing');
    rmSync(`${w.erasuresPath}${PREDECESSOR_SUFFIX}`, { recursive: true, force: true });
    w.writeAnswer(answer([written('k3')]));
    assert.ok(!existsSync(w.erasuresPath) && statSync(`${w.erasuresPath}${PREDECESSOR_SUFFIX}`).isFile(), 'then it moved');
    assert.equal(rotations(), 1, 'under the marker already in');
    // A later rotation is marked anew.
    w.writeAnswer(answer([erased('c'), erased('d')], { moved: false }));
    w.writeAnswer(answer([written('k4')]));
    assert.equal(rotations(), 2);
    w.release();
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a cursor too large for a marker line refuses the answer and writes nothing', () => {
  const t = setup();
  try {
    t.w.lead();
    // 200 control characters escape to 1,200 bytes: no marker can carry this cursor.
    assert.equal(t.w.writeAnswer(answer([written('a')], { cursor: '\u0001'.repeat(200) })), 'refused');
    assert.equal(existsSync(t.w.changesPath), false);
    // Positive control: the longest printable cursor the feed accepts (512) still fits.
    assert.equal(t.w.writeAnswer(answer([written('a')], { cursor: 'c'.repeat(512) })), 'written');
  } finally { t.done(); }
});

test('a writer without the lease writes nothing: never held, or taken over', () => {
  const t = setup();
  try {
    assert.equal(t.w.writeAnswer(answer([written('a')])), 'lost', 'never led');
    t.w.lead();
    const lock = join(t.w.dir, 'feed.lock');
    rmSync(lock);
    writeFileSync(lock, `${process.pid} ${Date.now()} other ${hostname()}`);
    assert.equal(t.w.holds(), false);
    assert.equal(t.w.writeAnswer(answer([written('a')])), 'lost');
    assert.equal(existsSync(t.w.changesPath), false);
  } finally { t.done(); }
});

test('the lease: one holder; a stale or dead holder is replaced; another host waits out staleness', () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-lease-'));
  try {
    const path = join(dir, 'feed.lock');
    const a = new FileLease(path), b = new FileLease(path);
    assert.equal(a.acquire(), 'held');
    assert.equal(a.acquire(), 'held', 'keeping it is taking it again');
    assert.equal(b.acquire(), 'busy');
    const token = readFileSync(path, 'utf8');
    assert.match(token, new RegExp(`^${process.pid} \\d+ [0-9a-f]{16} `));
    assert.ok(token.endsWith(` ${hostname()}`));
    // Refresh touches the file and never rewrites it.
    utimesSync(path, new Date(Date.now() - 20_000), new Date(Date.now() - 20_000));
    assert.equal(a.refresh(), true);
    assert.equal(readFileSync(path, 'utf8'), token);
    assert.ok(Date.now() - statSync(path).mtimeMs < 5_000);
    // Stale: untouched for more than 30 s, whoever it names (here a live process, this one).
    utimesSync(path, new Date(Date.now() - 31_000), new Date(Date.now() - 31_000));
    assert.equal(b.acquire(), 'held');
    assert.equal(a.holds(), false);
    assert.equal(a.refresh(), false, 'the old holder learns it lost the lease');
    assert.equal(a.held, false);
    a.release();
    assert.equal(b.holds(), true, 'releasing a lost lease leaves the new holder\'s file alone');
    b.release();
    assert.equal(existsSync(path), false);
    // A dead holder on this host: replaced at once.
    const dead = spawnSync(process.execPath, ['-e', 'console.log(process.pid)'], { encoding: 'utf8' });
    const deadPid = Number(dead.stdout.trim());
    writeFileSync(path, `${deadPid} ${Date.now()} 0011223344556677 ${hostname()}`);
    assert.equal(a.acquire(), 'held');
    a.release();
    // A dead pid named by ANOTHER host proves nothing here: it waits until stale.
    writeFileSync(path, `${deadPid} ${Date.now()} 0011223344556677 some-other-host`);
    assert.equal(a.acquire(), 'busy');
    utimesSync(path, new Date(Date.now() - 31_000), new Date(Date.now() - 31_000));
    assert.equal(a.acquire(), 'held');
    a.release();
    // A three-field token (the per-operation lock's) is still judged by its process, as before.
    writeFileSync(path, `${deadPid} ${Date.now()} 0011223344556677`);
    assert.equal(a.acquire(), 'held');
    a.release();
    // A directory that cannot hold the file: unavailable, which waiting does not change.
    assert.equal(new FileLease(join(dir, 'missing', 'feed.lock')).acquire(), 'unavailable');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a lease taken over for a dead process only once it has also gone a refresh period untouched', () => {
  // The process id is checked in THIS process's namespace: a container sharing the host's name but not its process ids
  // would see a live holder, refreshing every 10 s, as dead. Untouched for the refresh period as well, it is not live.
  const dir = mkdtempSync(join(tmpdir(), 'saihm-lease-'));
  try {
    const path = join(dir, 'feed.lock');
    const dead = spawnSync(process.execPath, ['-e', 'console.log(process.pid)'], { encoding: 'utf8' });
    writeFileSync(path, `${Number(dead.stdout.trim())} ${Date.now()} 0011223344556677 ${hostname()}`);
    const lease = new FileLease(path, 10_000);
    assert.equal(lease.acquire(), 'busy', 'touched just now: perhaps a holder whose process this one cannot see');
    utimesSync(path, new Date(Date.now() - 11_000), new Date(Date.now() - 11_000));
    assert.equal(lease.acquire(), 'held', 'untouched for a refresh period, and its process gone');
    lease.release();
    // The writer of the own-cell files waits TWO refresh periods: one would catch a live holder between two touches.
    const w = new ChangeFeedWriter({ agentIdHash: H, env: { SAIHM_ERASURE_FEED_DIR: dir } });
    mkdirSync(w.dir, { recursive: true });
    writeFileSync(join(w.dir, 'feed.lock'), `${Number(dead.stdout.trim())} ${Date.now()} 0011223344556677 ${hostname()}`);
    assert.equal(w.lead(), 'busy');
    utimesSync(join(w.dir, 'feed.lock'), new Date(Date.now() - 11_000), new Date(Date.now() - 11_000));
    assert.equal(w.lead(), 'busy', 'one period untouched: perhaps between two touches of a live holder');
    utimesSync(join(w.dir, 'feed.lock'), new Date(Date.now() - 21_000), new Date(Date.now() - 21_000));
    assert.equal(w.lead(), 'held');
    w.release();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the per-operation lock keeps its rule: a dead holder is taken over at once, a live fresh one is waited for', () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-lock-'));
  try {
    const lock = join(dir, 'x.lock');
    const dead = spawnSync(process.execPath, ['-e', 'console.log(process.pid)'], { encoding: 'utf8' });
    writeFileSync(lock, `${Number(dead.stdout.trim())} ${Date.now()} 0011223344556677`);
    assert.equal(withFileLock(lock, 0, () => 'ran'), 'ran');
    writeFileSync(lock, `${process.pid} ${Date.now()} 0011223344556677`);
    assert.throws(() => withFileLock(lock, 50, () => 'ran'), new RegExp(`locked by process ${process.pid}`));
    writeFileSync(lock, 'not a token');
    utimesSync(lock, new Date(Date.now() - 2_000), new Date(Date.now() - 2_000));
    assert.equal(withFileLock(lock, 0, () => 'ran'), 'ran', 'a malformed lock past its grace');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a lock that is there but cannot be read is held: the per-operation lock gives up at its deadline, the lease waits', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-lock-'));
  try {
    const lock = join(dir, 'x.lock');
    writeFileSync(lock, `${process.pid} ${Date.now()} 0011223344556677`);
    chmodSync(lock, 0o000);
    let readable = true;
    try { readFileSync(lock); } catch { readable = false; }
    if (readable) { t.skip('this user reads a mode-000 file (root): the unreadable lock cannot be made here'); return; }
    // In a child, with a time limit: the defect this pins was a loop that never returned.
    const TSX_BIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'node_modules', '.bin', 'tsx');
    const script = join(dir, 'probe.ts');
    const lockModule = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'file-lock.ts');
    writeFileSync(script, `import { withFileLock, FileLease } from ${JSON.stringify(lockModule)};
try { withFileLock(${JSON.stringify(lock)}, 200, () => 'ran'); console.log('ran'); } catch (e) { console.log('threw: ' + (e as Error).message); }
console.log('lease: ' + new FileLease(${JSON.stringify(lock)}).acquire());`);
    const r = spawnSync(TSX_BIN, [script], { encoding: 'utf8', timeout: 20_000 });
    assert.equal(r.signal, null, `the probe was killed (${String(r.signal)}): the lock was retried past its deadline`);
    assert.match(r.stdout, /threw: .*is locked by process unknown/, r.stdout + r.stderr);
    assert.match(r.stdout, /lease: busy/, r.stdout + r.stderr);
    assert.ok(existsSync(lock), 'an unreadable lock is never removed: whose it is cannot be checked');
  } finally {
    try { chmodSync(join(dir, 'x.lock'), 0o600); } catch { /* gone */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

test('lead: a directory holding another store\'s files, or one that cannot be created, is unavailable', () => {
  const t = setup();
  try {
    mkdirSync(t.w.dir, { recursive: true });
    writeFileSync(join(t.w.dir, 'someone-elses.db'), 'x');
    assert.equal(t.w.lead(), 'unavailable');
    rmSync(join(t.w.dir, 'someone-elses.db'));
    assert.equal(t.w.lead(), 'held', 'positive control');
    t.w.release();
    rmSync(t.w.dir, { recursive: true });
    const parent = join(t.root, 'tenants');
    chmodSync(parent, 0o500);
    try {
      if (process.getuid?.() !== 0) assert.equal(t.w.lead(), 'unavailable');
    } finally {
      chmodSync(parent, 0o700);
    }
    assert.equal(t.w.lead(), 'held', 'positive control: writable again');
  } finally { t.done(); }
});

test('the own-file list: a directory holding only the new files is this package\'s', () => {
  for (const names of [['changes.ndjson'], ['feed.lock'], ['erasures.ndjson.1'], ['changes.ndjson.1'], ['changes.ndjson.1', 'feed.lock']]) {
    assert.equal(tenantDirIsOurs(names), true, JSON.stringify(names));
  }
  assert.equal(tenantDirIsOurs(['index.db']), false);
  assert.equal(tenantDirIsOurs(['index.db', 'feed.lock']), true, 'one of this package\'s files makes the directory ours');
});

test('an erasure line with receivedAt keeps the agreed key order; without it the line is as before', () => {
  const base = { cellId: 'c', agentIdHash: H, at: AT, complete: true, destructionAnchor: ANCHOR } as const;
  assert.equal(
    buildFeedLine({ ...base, receivedAt: '2026-10-03T09:00:00.180Z', source: 'server-event' }),
    `{"v":1,"cellId":"c","agentIdHash":"${H}","at":"${AT}","receivedAt":"2026-10-03T09:00:00.180Z","complete":true,"destructionAnchor":"${ANCHOR}","source":"server-event"}\n`,
  );
  assert.equal(
    buildFeedLine({ ...base, source: 'mcp-client' }),
    `{"v":1,"cellId":"c","agentIdHash":"${H}","at":"${AT}","complete":true,"destructionAnchor":"${ANCHOR}","source":"mcp-client"}\n`,
  );
});

test('isoTime: a zoned ISO-8601 time in the one UTC form; anything else is no time', () => {
  assert.equal(isoTime(AT), AT);
  assert.equal(isoTime('2026-10-03T09:00:00Z'), AT);
  assert.equal(isoTime('2026-10-03T11:00:00.000+02:00'), AT);
  assert.equal(isoTime('2026-10-03T09:00Z'), AT);
  for (const bad of ['2026-10-03T09:00:00', '2026-10-03', 'Oct 3 2026', '', `${AT} `, `${AT}x`, '2026-13-45T99:99:99Z', 1759482000000, null, {}]) {
    assert.equal(isoTime(bad), null, JSON.stringify(bad));
  }
  // A time that cannot exist is no time, never the plausible one Date.parse rolls it over into (measured: 2026-02-30
  // became 2026-03-02, T24:00 the next day).
  for (const impossible of ['2026-02-30T00:00:00Z', '2026-02-29T00:00:00Z', '2026-04-31T10:00:00+02:00', '2026-10-03T24:00:00Z',
    '2026-10-03T09:60:00Z', '2026-10-03T09:00:60Z', '2026-10-03T09:00:00+24:00', '2026-10-03T09:00:00+02:60', '2026-00-10T09:00:00Z', '2026-10-00T09:00:00Z']) {
    assert.equal(isoTime(impossible), null, impossible);
  }
  // Positive controls at the edges: a leap day, the last day of a month, the last second of a day, the largest offsets.
  assert.equal(isoTime('2028-02-29T00:00:00Z'), '2028-02-29T00:00:00.000Z');
  assert.equal(isoTime('2026-04-30T23:59:59.999Z'), '2026-04-30T23:59:59.999Z');
  assert.equal(isoTime('2026-10-03T23:59:00+23:59'), '2026-10-03T00:00:00.000Z');
  // An offset that carries the time past the line form's four-digit years is no time either.
  assert.equal(isoTime('9999-12-31T23:59:59.999-23:59'), null);
  assert.equal(isoTime('0000-01-01T00:00:00+01:00'), null);
});

test('the share map file reads back exactly as written, and anything else reads as no map', () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-map-read-'));
  try {
    const path = join(dir, 'tenants', H, 'share-states.json');
    const m: ShareStates = {
      since: AT, complete: true, asOf: AT, stopped: null, startedAt: AT, counts: { live: 1, stale: 0, ended: 0, erased: 0 },
      entries: [{
        sharer: '11'.repeat(32), cellId: 'doc', status: 'live', grant: 'a1'.repeat(32), scope: 'read', expiryEpoch: null, seq: '2',
        commitment: C2, senderVerified: true, endedAt: null, endedBy: null, copiesInvalidBefore: null,
      }],
    };
    assert.equal(readShareStates(path), undefined, 'no file');
    writeShareStates(path, m);
    assert.deepEqual(readShareStates(path), m);
    const doc = JSON.parse(readFileSync(path, 'utf8'));
    const bad: Array<[string, unknown]> = [
      ['v', { ...doc, v: 2 }], ['stopped', { ...doc, stopped: 'paused' }], ['counts', { ...doc, counts: { ...doc.counts, live: -1 } }],
      ['status', { ...doc, entries: [{ ...doc.entries[0], status: 'gone' }] }], ['endedBy', { ...doc, entries: [{ ...doc.entries[0], endedBy: 'x' }] }],
      ['sharer', { ...doc, entries: [{ ...doc.entries[0], sharer: 'zz' }] }], ['complete', { ...doc, complete: 'yes' }],
      ['entries', { ...doc, entries: Array.from({ length: 4097 }, () => doc.entries[0]) }],
      // Within the writer's bounds, field by field: a value the feed could never have written is no map.
      ['grant', { ...doc, entries: [{ ...doc.entries[0], grant: 'not hex' }] }], ['scope', { ...doc, entries: [{ ...doc.entries[0], scope: 'admin' }] }],
      ['expiryEpoch', { ...doc, entries: [{ ...doc.entries[0], expiryEpoch: '1e9' }] }], ['seq', { ...doc, entries: [{ ...doc.entries[0], seq: '-2' }] }],
      ['commitment', { ...doc, entries: [{ ...doc.entries[0], commitment: 'C2' }] }], ['cellId', { ...doc, entries: [{ ...doc.entries[0], cellId: 'x'.repeat(4097) }] }],
      ['endedAt', { ...doc, entries: [{ ...doc.entries[0], endedAt: 'yesterday' }] }], ['asOf', { ...doc, asOf: 'now' }],
    ];
    for (const [what, d] of bad) {
      writeFileSync(path, JSON.stringify(d));
      assert.equal(readShareStates(path), undefined, what);
    }
    writeFileSync(path, '{"v":1');
    assert.equal(readShareStates(path), undefined, 'torn');
    writeFileSync(path, JSON.stringify(doc));
    assert.deepEqual(readShareStates(path), m, 'positive control');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('nothing is left behind but the files themselves: no temporary or lock file after a write', () => {
  const t = setup({ rotateBytes: 100 });
  try {
    t.w.lead();
    for (let i = 0; i < 3; i++) t.w.writeAnswer(answer([written(`n${i}`), erased(`e${i}`)]));
    t.w.release();
    assert.deepEqual(readdirSync(t.w.dir).sort(), ['changes.ndjson', 'changes.ndjson.1', 'erasures.ndjson', 'erasures.ndjson.1']);
  } finally { t.done(); }
});
