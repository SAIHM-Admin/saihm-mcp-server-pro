// The feed's own state file: its path, owner-only modes, atomic replacement, what it refuses to restore, and the
// tenant directory it now shares with the erasure feed and the share map.
//
// Runner: npx tsx --test tests/feed_state_file.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { FileFeedStore, feedStatePath, readFeedState, writeFeedState } from '../src/feed-state-file.ts';
import { assertTenantDirUnshared, emitErasureLine } from '../src/erasure-feed.ts';
import { shareStatesPath } from '../src/share-states-file.ts';
import type { PersistedFeed } from '../src/share-events.ts';

const ID = 'ab'.repeat(32);
const SHARER = '11'.repeat(32);
const tmp = (): string => mkdtempSync(join(tmpdir(), 'saihm-feed-state-'));
const state = (extra: Partial<PersistedFeed> = {}): PersistedFeed => ({
  v: 1, savedAt: '2026-09-17T10:00:00.000Z', reconciledAt: '2026-09-17T09:59:00.000Z',
  capped: false, operator: '0f'.repeat(16), cursor: 'c7', since: '2026-09-17T09:59:00.000Z',
  entries: [{
    sharer: SHARER, cellId: 'doc', status: 'live', grant: 'a1'.repeat(32), scope: 'read', expiryEpoch: null, seq: '2',
    commitment: '44'.repeat(32), senderVerified: false, endedAt: null, endedBy: null, copiesInvalidBefore: null,
    changedAt: '2026-09-17T09:59:30.000Z',
  }],
  seen: [['0'.repeat(63) + '1', 1_758_100_000_000]],
  ...extra,
});

test('the path follows the erasure feed root and refuses a relative root or a bad id', () => {
  assert.equal(feedStatePath(ID, { SAIHM_ERASURE_FEED_DIR: '/r', SAIHM_HOME: '/h' }), `/r/tenants/${ID}/feed-state.json`);
  assert.equal(feedStatePath(ID.toUpperCase(), { SAIHM_HOME: '/h' }), `/h/tenants/${ID}/feed-state.json`);
  assert.equal(feedStatePath(ID, {}), join(homedir(), '.saihm', 'tenants', ID, 'feed-state.json'));
  assert.throws(() => feedStatePath(ID, { SAIHM_HOME: 'relative' }), /ABSOLUTE/);
  assert.throws(() => feedStatePath('ab', { SAIHM_HOME: '/h' }), /64 lowercase hex/);
});

test('a write is owner-only and whole, and reads back as what was written', () => {
  const root = tmp();
  try {
    const p = feedStatePath(ID, { SAIHM_ERASURE_FEED_DIR: root });
    writeFeedState(p, state());
    assert.equal(statSync(p).mode & 0o777, 0o600);
    assert.equal(statSync(dirname(p)).mode & 0o777, 0o700);
    assert.deepEqual(readFeedState(p), state());
    assert.deepEqual(readdirSync(dirname(p)), ['feed-state.json'], 'no lock or temporary file left');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('nothing this package did not write is restored, and a state it cannot read simply is not one', () => {
  const root = tmp();
  try {
    const p = feedStatePath(ID, { SAIHM_ERASURE_FEED_DIR: root });
    assert.equal(readFeedState(p), undefined, 'a file that is not there');
    writeFeedState(p, state());
    for (const bad of ['', 'not json', '[]', '"s"', 'null', JSON.stringify({ ...state(), v: 2 }),
      JSON.stringify({ ...state(), cursor: 7 }), JSON.stringify({ ...state(), since: {} }),
      JSON.stringify({ ...state(), entries: 'many' }), JSON.stringify({ ...state(), seen: {} })]) {
      writeFileSync(p, bad);
      assert.equal(readFeedState(p), undefined, bad.slice(0, 40));
    }
    // A state larger than this package writes is refused unread, so a doctored file cannot be paid for.
    writeFileSync(p, JSON.stringify({ ...state(), pad: 'x'.repeat(9 * 1024 * 1024) }));
    assert.equal(readFeedState(p), undefined, 'too large to be ours');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a restore is bounded: no file makes a process hold more than the feed itself would', () => {
  const root = tmp();
  try {
    const p = feedStatePath(ID, { SAIHM_ERASURE_FEED_DIR: root });
    mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
    const many = Array.from({ length: 5_000 }, (_, i) => ({ ...state().entries[0], cellId: `doc${i}` }));
    const seen: [string, number][] = Array.from({ length: 5_000 }, (_, i) => [i.toString(16).padStart(64, '0'), 1]);
    writeFileSync(p, JSON.stringify({ ...state(), entries: many, seen: [[1, 1], ['x'], ['id', 'soon'], ...seen] }), { mode: 0o600 });
    const back = readFeedState(p);
    // 4093, not 4096: the bound is applied to what the file says, and the three malformed pairs inside that window are
    // then dropped. Counting 4096 here would mean the bound had been applied after the filter, which a file could game.
    assert.deepEqual([back?.entries.length, back?.seen.length], [4096, 4093]);
    assert.equal(back?.seen.every(([id, at]) => typeof id === 'string' && typeof at === 'number' && Number.isFinite(at)), true,
      'pairs that are not pairs were dropped, and they were at the front where the bound could not hide them');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('the store swallows what the feed must not be interrupted by, and returns nothing rather than throwing', () => {
  const root = tmp();
  try {
    const p = feedStatePath(ID, { SAIHM_ERASURE_FEED_DIR: root });
    const store = new FileFeedStore(p);
    assert.equal(store.load(), undefined);
    store.save(state());
    assert.equal(store.load()?.cursor, 'c7');
    // A directory that is not ours: the write is refused inside, and the feed never hears about it.
    const other = join(root, 'tenants', 'ff'.repeat(32));
    const foreign = new FileFeedStore(join(other, 'feed-state.json'));
    mkdirSync(other, { recursive: true, mode: 0o700 });
    writeFileSync(join(other, 'their-store.db'), 'x');
    assert.throws(() => writeFeedState(join(other, 'feed-state.json'), state()), /another store/);
    foreign.save(state());
    assert.equal(foreign.load(), undefined, 'nothing was written where it does not belong');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('the erasure feed, the share map and the feed state live in one tenant directory, in any order', () => {
  for (const first of ['state', 'map', 'feed'] as const) {
    const root = tmp();
    try {
      const env = { SAIHM_ERASURE_FEED_DIR: root };
      const p = feedStatePath(ID, env);
      if (first === 'state') writeFeedState(p, state());
      if (first === 'map') { mkdirSync(dirname(p), { recursive: true, mode: 0o700 }); writeFileSync(shareStatesPath(ID, env), '{}', { mode: 0o600 }); }
      if (first === 'feed') emitErasureLine({ cellId: 'doc', agentIdHash: ID, at: '2026-09-17T10:00:00.000Z', complete: false, source: 'mcp-client' }, env);
      // Whichever arrived first, the erasure feed still owns the directory and the state can still be written.
      assertTenantDirUnshared(root, ID);
      writeFeedState(p, state());
      assert.equal(readFeedState(p)?.cursor, 'c7');
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('a rename that cannot happen leaves no temporary file, and a lock a live process holds is not walked past', () => {
  const root = tmp();
  try {
    const p = feedStatePath(ID, { SAIHM_ERASURE_FEED_DIR: root });
    writeFeedState(p, state());
    // Nothing can be renamed over a directory, which is how a failed replacement reaches this code.
    rmSync(p, { force: true });
    mkdirSync(p, { recursive: true });
    assert.throws(() => writeFeedState(p, state()));
    assert.deepEqual(readdirSync(dirname(p)).filter((n) => n.endsWith('.tmp')), [], 'its own temporary file was taken away');
    rmSync(p, { recursive: true, force: true });

    // A lock held by a process that is alive (this one) is waited for and then refused, not ignored.
    writeFileSync(`${p}.lock`, `${process.pid} ${Date.now()} held`, { mode: 0o600 });
    const t = Date.now();
    assert.throws(() => writeFeedState(p, state()), /locked by process/);
    assert.ok(Date.now() - t >= 400, `waited ${Date.now() - t} ms for the lock before giving up`);
    assert.equal(readFeedState(p), undefined, 'and nothing was written behind the lock');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
