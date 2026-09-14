// The share map file another process reads: its path, owner-only modes, atomic replacement, the asOf rule for several
// writers, the lock, and the tenant directory it shares with the erasure feed.
//
// Runner: npx tsx --test tests/share_states_file.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { shareStatesDocument, shareStatesPath, writeShareStates } from '../src/share-states-file.ts';
import { assertTenantDirUnshared, emitErasureLine } from '../src/erasure-feed.ts';
import type { ShareStates } from '../src/share-events.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const ID = 'ab'.repeat(32);
const tmp = (): string => mkdtempSync(join(tmpdir(), 'saihm-share-map-'));
const map = (asOf: string | null, extra: Partial<ShareStates> = {}): ShareStates => ({
  since: '2026-09-14T10:00:00.000Z', complete: true, asOf, stopped: null, startedAt: '2026-09-14T09:59:00.000Z',
  counts: { live: 1, stale: 0, ended: 0, erased: 0 },
  entries: [{
    sharer: '11'.repeat(32), cellId: 'doc', status: 'live', grant: 'a1'.repeat(32), scope: 'read', expiryEpoch: null, seq: null,
    commitment: null, senderVerified: false, endedAt: null, endedBy: null, copiesInvalidBefore: null,
  }],
  ...extra,
});
const read = (p: string): Record<string, unknown> => JSON.parse(readFileSync(p, 'utf8'));

test('the path follows the erasure feed root and refuses a relative root or a bad id', () => {
  assert.equal(shareStatesPath(ID, { SAIHM_ERASURE_FEED_DIR: '/r', SAIHM_HOME: '/h' }), `/r/tenants/${ID}/share-states.json`);
  assert.equal(shareStatesPath(ID.toUpperCase(), { SAIHM_HOME: '/h' }), `/h/tenants/${ID}/share-states.json`);
  assert.equal(shareStatesPath(ID, {}), join(homedir(), '.saihm', 'tenants', ID, 'share-states.json'));
  assert.throws(() => shareStatesPath(ID, { SAIHM_HOME: 'relative' }), /ABSOLUTE/);
  assert.throws(() => shareStatesPath('ab', { SAIHM_HOME: '/h' }), /64 lowercase hex/);
});

test('a write is owner-only and whole, and holds the summary and every entry in a fixed key order', () => {
  const root = tmp();
  try {
    const p = shareStatesPath(ID, { SAIHM_ERASURE_FEED_DIR: root });
    assert.equal(writeShareStates(p, map('2026-09-14T10:01:00.000Z')), 'written');
    assert.equal(statSync(p).mode & 0o777, 0o600);
    assert.equal(statSync(dirname(p)).mode & 0o777, 0o700);
    assert.deepEqual(readdirSync(dirname(p)), ['share-states.json'], 'no lock or temporary file left');
    assert.equal(readFileSync(p, 'utf8'), shareStatesDocument(map('2026-09-14T10:01:00.000Z')));
    assert.deepEqual(Object.keys(read(p)), ['v', 'since', 'complete', 'asOf', 'stopped', 'startedAt', 'counts', 'entries']);
    assert.equal(read(p).v, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('only a map whose asOf is not older replaces the file, and a map without asOf never replaces one with it', () => {
  const root = tmp();
  try {
    const p = shareStatesPath(ID, { SAIHM_ERASURE_FEED_DIR: root });
    assert.equal(writeShareStates(p, map(null)), 'written', 'no file: a starting map is written');
    assert.equal(writeShareStates(p, map(null, { complete: false })), 'written', 'neither has an asOf');
    assert.equal(writeShareStates(p, map('2026-09-14T10:01:00.000Z')), 'written');
    assert.equal(writeShareStates(p, map(null)), 'kept');
    assert.equal(writeShareStates(p, map('2026-09-14T10:00:59.999Z')), 'kept');
    assert.equal(read(p).asOf, '2026-09-14T10:01:00.000Z');
    assert.equal(writeShareStates(p, map('2026-09-14T10:01:00.000Z', { since: '2026-09-14T10:00:30.000Z' })), 'written', 'an equal asOf');
    assert.equal(read(p).since, '2026-09-14T10:00:30.000Z', 'since belongs to the writer');
    writeFileSync(p, 'not json');
    assert.equal(writeShareStates(p, map(null)), 'written', 'an unreadable file');
    writeFileSync(p, JSON.stringify({ asOf: 'not a time' }));
    assert.equal(writeShareStates(p, map(null)), 'written', 'a file whose asOf is not a time');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a write that cannot rename leaves no temporary file and no lock', () => {
  const root = tmp();
  try {
    const p = shareStatesPath(ID, { SAIHM_ERASURE_FEED_DIR: root });
    mkdirSync(join(p, 'occupied'), { recursive: true });   // a directory where the file goes: the rename fails
    assert.throws(() => writeShareStates(p, map('2026-09-14T10:01:00.000Z')));
    assert.deepEqual(readdirSync(dirname(p)), ['share-states.json']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a lock held by a live process makes a write give up after waiting; an abandoned one is taken over', () => {
  const root = tmp();
  try {
    const p = shareStatesPath(ID, { SAIHM_ERASURE_FEED_DIR: root });
    mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
    const lock = `${p}.lock`;
    writeFileSync(lock, `${process.pid} ${Date.now()} held`);
    const t0 = Date.now();
    assert.throws(() => writeShareStates(p, map('2026-09-14T10:01:00.000Z')), /locked by process/);
    assert.ok(Date.now() - t0 >= 450, 'it waited for the holder first');
    const age = (lockFile: string, ms: number): void => { const t = (Date.now() - ms) / 1000; utimesSync(lockFile, t, t); };
    // The holder is gone.
    const gone = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))']).stdout.toString();
    writeFileSync(lock, `${gone} ${Date.now()} held`);
    assert.equal(writeShareStates(p, map('2026-09-14T10:01:00.000Z')), 'written');
    // A live holder, but the lock is past its stale age.
    writeFileSync(lock, `${process.pid} 0 held`);
    age(lock, 31_000);
    assert.equal(writeShareStates(p, map('2026-09-14T10:02:00.000Z')), 'written');
    // A lock with no holder in it, past the grace for one still being written.
    writeFileSync(lock, '');
    age(lock, 1_500);
    assert.equal(writeShareStates(p, map('2026-09-14T10:03:00.000Z')), 'written');
    assert.deepEqual(readdirSync(dirname(p)), ['share-states.json']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('several processes writing at once leave a whole file with the latest asOf, and nothing else', async () => {
  const root = tmp();
  try {
    const p = shareStatesPath(ID, { SAIHM_ERASURE_FEED_DIR: root });
    const script = join(root, 'writer.ts');
    writeFileSync(script, [
      `import { writeShareStates } from ${JSON.stringify(resolve(HERE, '../src/share-states-file.ts'))};`,
      'const [p, k] = process.argv.slice(2);',
      'const base = Date.UTC(2026, 8, 14, 10);',
      'for (let i = 0; i < 150; i++) {',
      '  const asOf = new Date(base + i * 1000 + Number(k)).toISOString();',
      '  writeShareStates(p, { since: asOf, complete: true, asOf, stopped: null, startedAt: asOf, counts: { live: 0, stale: 0, ended: 0, erased: 0 }, entries: [] });',
      '}',
    ].join('\n'));
    const runs = [0, 1, 2, 3].map((k) => new Promise<number | null>((done) => spawn(TSX, [script, p, String(k)], { stdio: 'ignore' }).on('exit', done)));
    let reads = 0, partial = 0;
    const reader = setInterval(() => {
      try { JSON.parse(readFileSync(p, 'utf8')); reads++; } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') partial++; }
    }, 1);
    const codes = await Promise.all(runs);
    clearInterval(reader);
    assert.deepEqual(codes, [0, 0, 0, 0], 'no writer gave up on the lock');
    assert.equal(partial, 0, `a reader saw a partial file (${reads} whole reads)`);
    assert.equal(read(p).asOf, new Date(Date.UTC(2026, 8, 14, 10) + 149_000 + 3).toISOString());
    assert.deepEqual(readdirSync(dirname(p)), ['share-states.json']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('the share map and the erasure feed share a tenant directory in either order; another store\'s directory is refused', () => {
  const root = tmp();
  const env = { SAIHM_ERASURE_FEED_DIR: root };
  const erasure = (id: string) => emitErasureLine({ cellId: 'cell-1', agentIdHash: id, at: '2026-09-14T10:00:00.000Z', complete: false, source: 'mcp-client' }, env);
  try {
    // The map first: an erasure line still lands beside it.
    const p = shareStatesPath(ID, env);
    writeShareStates(p, map(null));
    erasure(ID);
    assert.deepEqual(readdirSync(dirname(p)).sort(), ['erasures.ndjson', 'share-states.json']);

    // The feed first: the map lands beside it.
    const id2 = 'cd'.repeat(32);
    erasure(id2);
    assert.equal(writeShareStates(shareStatesPath(id2, env), map(null)), 'written');

    // What a map write leaves while it runs, alone in the directory, does not make it another store's.
    const id3 = 'ef'.repeat(32);
    mkdirSync(join(root, 'tenants', id3), { recursive: true });
    writeFileSync(join(root, 'tenants', id3, 'share-states.json.lock'), '');
    writeFileSync(join(root, 'tenants', id3, 'share-states.json.123.abcdef.tmp'), '');
    assertTenantDirUnshared(root, id3);

    // Another store's directory: neither writes, and nothing is added to it.
    const other = '99'.repeat(32);
    mkdirSync(join(root, 'tenants', other), { recursive: true });
    writeFileSync(join(root, 'tenants', other, 'store1.json'), '{}');
    assert.throws(() => writeShareStates(shareStatesPath(other, env), map(null)), /another store/);
    assert.throws(() => erasure(other), /other store/);
    assert.deepEqual(readdirSync(join(root, 'tenants', other)), ['store1.json']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
