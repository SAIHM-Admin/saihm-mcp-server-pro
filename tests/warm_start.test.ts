// Warm start's own module, without a server: the token statement on the offer, the route, sealing and opening a
// snapshot (every part bound to its place, the key bound to the snapshot and kept apart from cell keys), the answers'
// shapes, and the payload files SHM and this client exchange.
// Runner: npx tsx --test tests/warm_start.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodeEnvelope, deriveIdentity, encodeEnvelope, fromHex, sealCell, toHex, unwrapDek } from '@saihm/client-pro';
import {
  WARM_START_TOKEN,
  begunUpload,
  committedSnapshot,
  contentDigestOf,
  contentDigestSha256,
  dropLatestPayload,
  dropPutPayload,
  latestFileName,
  listedSnapshots,
  openSnapshotKey,
  openSnapshotParts,
  partsDigest,
  putFileName,
  sealSnapshot,
  sweepWarmStart,
  takePutPayload,
  warmStartFolder,
  warmStartLimits,
  warmStartRoute,
  withWarmStartToken,
  writeLatestPayload,
  WarmStartFileError,
} from '../src/warm-start.js';
import { tenantDirIsOurs } from '../src/erasure-feed.js';

const ME = deriveIdentity(new Uint8Array(32).fill(91));
const OTHER = deriveIdentity(new Uint8Array(32).fill(92));
const ID = toHex(ME.agentIdHash);
const AT = 'AbCdEf0123456789-_AbCdEf0123456789-_AbCdEf0123';
const BIND = { kek: ME.kek, agentIdHash: ME.agentIdHash, coversThrough: AT };
const TOKEN = 'abcdefghij0123456789';

const code = (fn: () => unknown): string => {
  try {
    fn();
  } catch (e) {
    return e instanceof WarmStartFileError ? e.code : `other:${(e as Error).name}`;
  }
  return 'none';
};

/** A tenant folder with its warm-start folder, as SHM creates it (0700). */
function rig(): { root: string; dir: string; env: NodeJS.ProcessEnv; done: () => void } {
  const root = mkdtempSync(join(tmpdir(), 'saihm-ws-'));
  const env = { SAIHM_ERASURE_FEED_DIR: root } as NodeJS.ProcessEnv;
  const dir = warmStartFolder(ID, env).dir;
  return { root, dir, env, done: () => rmSync(root, { recursive: true, force: true }) };
}
const shmFolder = (dir: string): void => mkdirSync(dir, { recursive: true, mode: 0o700 });
const shmWrite = (dir: string, name: string, bytes: Uint8Array, mode = 0o600): string => {
  const p = join(dir, name);
  writeFileSync(p, bytes, { mode });
  chmodSync(p, mode);
  return p;
};

test('the token statement: set by this client exactly when it serves the offer, in one place, never the endpoint\'s', () => {
  assert.deepEqual(WARM_START_TOKEN, { member: 'token', value: 'required' }, 'the member and its value, one place');
  const served = { v: [1], maxBytes: 8_388_608, maxSnapshots: 2, retentionS: 604_800 };
  const events = { v: [1], kinds: ['cell-written', 'cell-erased'] };
  assert.deepEqual(withWarmStartToken({ events, warmStart: served }), { events, warmStart: { ...served, token: 'required' } });
  assert.deepEqual(
    withWarmStartToken({ warmStart: { ...served, token: 'optional' } }),
    { warmStart: { ...served, token: 'required' } },
    'an endpoint-sent member is replaced',
  );
  for (const [label, offer] of [
    ['v without 1', { ...served, v: [2] }],
    ['no v', { maxBytes: 1 }],
    ['maxBytes 0', { ...served, maxBytes: 0 }],
    ['maxBytes not whole', { ...served, maxBytes: 1.5 }],
    ['maxBytes a string', { ...served, maxBytes: '8388608' }],
  ] as const) {
    assert.deepEqual(withWarmStartToken({ warmStart: { ...offer, token: 'required' } }), { warmStart: offer }, `${label}: no statement, and the endpoint's is dropped`);
    assert.equal(warmStartLimits({ warmStart: offer }), null, label);
  }
  for (const offer of [null, 'x', 7, true, [served]]) {
    const f = { warmStart: offer };
    assert.deepEqual(withWarmStartToken(f), f, `${JSON.stringify(offer)} passes as sent`);
  }
  assert.equal(withWarmStartToken(null), null);
  assert.deepEqual(withWarmStartToken({ events }), { events }, 'no offer, nothing added');
  assert.deepEqual(warmStartLimits({ warmStart: served }), { maxBytes: 8_388_608 });
  assert.equal(warmStartLimits(null), null);
});

test('the route: the info document\'s path on the endpoint\'s own origin, with a part size this client can fill', () => {
  const base = 'https://saihm.net/mcp/';
  const cap = (o: Record<string, unknown>): unknown => ({ warmStart: { v: [1], path: '/mcp/warm-start', partBytes: 524_288, ...o } });
  assert.deepEqual(warmStartRoute(cap({}), base), { url: 'https://saihm.net/mcp/warm-start', partBytes: 524_288 });
  for (const [label, info] of [
    ['absent', {}],
    ['v without 1', cap({ v: [2] })],
    ['another origin', cap({ path: 'https://elsewhere.example/mcp/warm-start' })],
    ['a protocol-relative path', cap({ path: '//elsewhere.example/x' })],
    // A URL parser reads a backslash after the first slash as a second slash: this path names another host.
    ['a backslash read as a host', cap({ path: '/\\elsewhere.example/x' })],
    ['a relative path', cap({ path: 'warm-start' })],
    ['a query', cap({ path: '/mcp/warm-start?x=1' })],
    ['parts too small', cap({ partBytes: 1023 })],
    ['parts too large', cap({ partBytes: 16_777_217 })],
    ['parts not whole', cap({ partBytes: 1024.5 })],
    ['not an object', 'warmStart'],
  ] as const)
    assert.equal(warmStartRoute(info, base), null, label);
});

test('sealing: parts of exactly the part size but the last, the count and digest the wire expects, and a whole round trip', () => {
  const partBytes = 1024;
  const chunk = partBytes - 16;
  for (const n of [0, 1, chunk - 1, chunk, chunk + 1, 3 * chunk, 3 * chunk + 5]) {
    const payload = new Uint8Array(n).map((_, i) => (i * 7 + 3) & 0xff);
    const s = sealSnapshot(payload, partBytes, BIND);
    const bytes = s.parts.reduce((a, p) => a + p.length, 0);
    assert.equal(s.bytes, bytes, `${n}: bytes is the sealed size`);
    assert.equal(s.parts.length, Math.ceil(s.bytes / partBytes), `${n}: parts = ceil(bytes / partBytes)`);
    s.parts.forEach((p, i) => {
      if (i < s.parts.length - 1) assert.equal(p.length, partBytes, `${n}: part ${i} is exactly the part size`);
    });
    assert.equal(s.parts.at(-1)!.length, s.bytes - partBytes * (s.parts.length - 1), `${n}: the last part`);
    assert.equal(s.digest, createHash('sha256').update(Buffer.concat(s.parts)).digest('hex'));
    assert.match(s.nonce, /^[0-9a-f]{32}$/);
    assert.match(s.keyEnvelope, /^[A-Za-z0-9_-]+$/);
    const key = openSnapshotKey(s.keyEnvelope, s.nonce, BIND);
    assert.ok(key, `${n}: the key opens`);
    assert.deepEqual(openSnapshotParts(key, s.parts, s.nonce, BIND), payload, `${n}: the payload comes back whole`);
  }
  // No nonce repeats under a snapshot's key: parts holding the same bytes never share a keystream.
  const same = sealSnapshot(new Uint8Array(3 * chunk), partBytes, BIND);
  const bodies = same.parts.map((x) => Buffer.from(x.subarray(0, x.length - 16)).toString('hex'));
  assert.equal(new Set(bodies).size, 3, 'three equal chunks seal to three different bodies');
  const a = sealSnapshot(new Uint8Array(10), partBytes, BIND);
  const b = sealSnapshot(new Uint8Array(10), partBytes, BIND);
  assert.notEqual(a.nonce, b.nonce, 'a fresh nonce per snapshot');
  assert.notDeepEqual(a.parts[0], b.parts[0], 'and a fresh key: the same payload never seals the same');
  assert.throws(() => sealSnapshot(new Uint8Array(1), 16, BIND), RangeError);
  assert.throws(() => sealSnapshot(new Uint8Array(1), partBytes, { ...BIND, coversThrough: '' }), RangeError);
});

test('every part opens only at its own place in its own snapshot, under its own identity and position', () => {
  const partBytes = 1024;
  const payload = new Uint8Array(4000).map((_, i) => i & 0xff);
  const s = sealSnapshot(payload, partBytes, BIND);
  const other = sealSnapshot(payload, partBytes, BIND);
  const key = openSnapshotKey(s.keyEnvelope, s.nonce, BIND)!;
  const otherKey = openSnapshotKey(other.keyEnvelope, other.nonce, BIND)!;
  const p = [...s.parts];
  const cases: [string, Uint8Array[]][] = [
    ['two parts moved', [p[1]!, p[0]!, p[2]!, p[3]!]],
    ['the last part dropped', p.slice(0, -1)],
    ['a part repeated', [p[0]!, p[0]!, p[2]!, p[3]!]],
    ['a part from another snapshot', [other.parts[0]!, p[1]!, p[2]!, p[3]!]],
    ['a part cut short', [p[0]!, p[1]!, p[2]!, p[3]!.subarray(0, p[3]!.length - 1)]],
    ['one bit flipped', [p[0]!, p[1]!, Uint8Array.from(p[2]!, (x, i) => (i === 5 ? x ^ 1 : x)), p[3]!]],
    ['a part longer by a byte', [p[0]!, p[1]!, p[2]!, Buffer.concat([p[3]!, Buffer.from([0])])]],
  ];
  for (const [label, parts] of cases) assert.equal(openSnapshotParts(key, parts, s.nonce, BIND), null, label);
  assert.equal(openSnapshotParts(otherKey, s.parts, s.nonce, BIND), null, 'another snapshot\'s key');
  assert.equal(openSnapshotParts(key, s.parts, other.nonce, BIND), null, 'another snapshot\'s nonce');
  assert.equal(openSnapshotParts(key, s.parts, s.nonce, { ...BIND, coversThrough: AT + 'x' }), null, 'another position');
  assert.equal(openSnapshotParts(key, s.parts, s.nonce, { ...BIND, agentIdHash: OTHER.agentIdHash }), null, 'another identity');
  assert.equal(openSnapshotParts(key, [], s.nonce, BIND), null, 'no parts');
  // The key: bound to the identity's key-encryption key, its hash, the position and the nonce.
  assert.equal(openSnapshotKey(s.keyEnvelope, s.nonce, { ...BIND, kek: OTHER.kek }), null, 'another identity\'s key-encryption key');
  assert.equal(openSnapshotKey(s.keyEnvelope, s.nonce, { ...BIND, agentIdHash: OTHER.agentIdHash }), null, 'another identity hash');
  assert.equal(openSnapshotKey(s.keyEnvelope, s.nonce, { ...BIND, coversThrough: 'x' }), null, 'another position');
  assert.equal(openSnapshotKey(s.keyEnvelope, other.nonce, BIND), null, 'another snapshot\'s nonce');
  assert.equal(openSnapshotKey(other.keyEnvelope, s.nonce, BIND), null, 'another snapshot\'s envelope');
  const raw = Buffer.from(s.keyEnvelope, 'base64url');
  for (const [label, env] of [
    ['a padded spelling', s.keyEnvelope + '='],
    // 61 bytes leave four unused bits in the last character: another character with the same high bits decodes to the
    // same bytes, and only the canonical spelling is the envelope.
    ['a spelling that is not canonical', s.keyEnvelope.slice(0, -1) + (() => {
      const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
      return A[A.indexOf(s.keyEnvelope.at(-1)!) ^ 1]!;
    })()],
    ['a layout byte of 2', Buffer.concat([Buffer.from([2]), raw.subarray(1)]).toString('base64url')],
    ['one byte short', raw.subarray(0, -1).toString('base64url')],
    ['one byte long', Buffer.concat([raw, Buffer.from([0])]).toString('base64url')],
    ['empty', ''],
  ] as const)
    assert.equal(openSnapshotKey(env, s.nonce, BIND), null, label);
});

test('a cell key envelope never opens as a snapshot key, and a snapshot key envelope never as a cell key', () => {
  const env = sealCell({
    plaintext: new TextEncoder().encode('a memory'),
    kek: ME.kek,
    mldsaSecretKey: ME.mldsaSecretKey,
    mldsaPubKey: ME.mldsaPubKey,
    agentIdHash: ME.agentIdHash,
    cellId: 'c1',
    seq: 1n,
    tier: 'PRO',
  });
  assert.equal(unwrapDek(env, ME.kek).length, 32, 'positive control: the cell key opens as a cell key');
  const s = sealSnapshot(new Uint8Array(100), 1024, BIND);
  // Same key-encryption key, same nonce-then-ciphertext layout after the layout byte: only the associated data differs.
  const cellAsSnapshot = Buffer.concat([Buffer.from([1]), Buffer.from(env.wrappedDek)]).toString('base64url');
  assert.equal(Buffer.from(cellAsSnapshot, 'base64url').length, Buffer.from(s.keyEnvelope, 'base64url').length, 'fixture: the same size');
  for (const coversThrough of [AT, 'c1'])
    assert.equal(openSnapshotKey(cellAsSnapshot, s.nonce, { ...BIND, coversThrough }), null, `a cell key envelope offered as a snapshot's (${coversThrough})`);
  assert.equal(openSnapshotKey(Buffer.from(env.wrappedDek).toString('base64url'), s.nonce, BIND), null, 'without the layout byte too');
  const snapshotAsCell = decodeEnvelope({ ...encodeEnvelope(env), wrappedDek: toHex(Buffer.from(s.keyEnvelope, 'base64url').subarray(1)) });
  assert.throws(() => unwrapDek(snapshotAsCell, ME.kek), 'a snapshot key envelope offered as a cell\'s');
});

test('Content-Digest: exactly one sha-256 member of padded standard base64, other members allowed', () => {
  // A part whose digest spells a `+` or `/` in standard base64, so its base64url spelling differs.
  let i = 0;
  while (!/[+/]/.test(createHash('sha256').update(`a part ${i}`).digest('base64'))) i++;
  const part = Buffer.from(`a part ${i}`);
  const digest = createHash('sha256').update(part).digest();
  const b64 = digest.toString('base64');
  assert.equal(contentDigestOf(part), `sha-256=:${b64}:`);
  assert.deepEqual(contentDigestSha256(contentDigestOf(part)), digest);
  assert.deepEqual(contentDigestSha256(`sha-512=:${'A'.repeat(86)}==:, sha-256=:${b64}:`), digest, 'beside another member');
  assert.deepEqual(contentDigestSha256(`sha-256=:${b64}:;x=1`), digest, 'with a parameter');
  for (const [label, h] of [
    ['absent', undefined],
    ['unpadded', `sha-256=:${b64.replace(/=+$/, '')}:`],
    ['base64url', `sha-256=:${digest.toString('base64url')}=:`],
    ['twice', `sha-256=:${b64}:, sha-256=:${b64}:`],
    ['no colons', `sha-256=${b64}`],
    ['another algorithm only', `sha-512=:${b64}:`],
    ['too long', `x=${'a'.repeat(5000)}, sha-256=:${b64}:`],
  ] as const)
    assert.equal(contentDigestSha256(h), null, label);
  assert.equal(partsDigest([Buffer.from('a'), Buffer.from('b')]), createHash('sha256').update('ab').digest('hex'));
});

test('answers: a listing is read whole or refused whole; a begin and a commit are taken only in their shapes', () => {
  const entry = {
    snapshotId: 'ab'.repeat(32),
    createdAt: '2026-10-05T07:00:00.000+02:00',
    bytes: 1040,
    parts: 2,
    digest: 'cd'.repeat(32),
    coversThrough: AT,
    keyEnvelope: 'AbC-_',
    nonce: 'ef'.repeat(16),
  };
  assert.deepEqual(listedSnapshots({ v: 1, snapshots: [entry] }), [{ ...entry, createdAt: '2026-10-05T05:00:00.000Z' }], 'the time in one UTC form');
  assert.deepEqual(listedSnapshots({ v: 1, snapshots: [] }), []);
  for (const [label, bad] of [
    ['an id in capitals', { snapshotId: 'AB'.repeat(32) }],
    ['a time that is not one', { createdAt: 'yesterday' }],
    ['no bytes', { bytes: 0 }],
    ['parts that cannot each hold a tag', { parts: 66 }],
    ['a digest too short', { digest: 'cd' }],
    ['a nonce in capitals', { nonce: 'EF'.repeat(16) }],
    ['a position with a space', { coversThrough: 'a b' }],
    ['a position too long', { coversThrough: 'a'.repeat(65) }],
    ['a padded envelope', { keyEnvelope: 'AbC=' }],
    ['an envelope too long', { keyEnvelope: 'a'.repeat(4097) }],
  ] as const) {
    assert.equal(listedSnapshots({ v: 1, snapshots: [entry, { ...entry, ...bad }] }), null, `${label}: the whole listing is refused`);
  }
  for (const body of [null, [], { v: 1 }, { snapshots: 'x' }]) assert.equal(listedSnapshots(body), null, JSON.stringify(body));
  assert.deepEqual(begunUpload({ v: 1, uploadId: 'ab'.repeat(16), partBytes: 1024, expiresAt: 'x' }), { uploadId: 'ab'.repeat(16), partBytes: 1024 });
  assert.equal(begunUpload({ uploadId: '../x', partBytes: 1024 }), null, 'an upload id is never a path');
  const sent = { bytes: 1040, parts: 2, coversThrough: AT };
  const commit = { v: 1, snapshotId: 'ab'.repeat(32), createdAt: '2026-10-05T05:00:00.000Z', bytes: 1040, parts: 2, coversThrough: AT };
  assert.deepEqual(committedSnapshot(commit, sent), { snapshotId: commit.snapshotId, createdAt: commit.createdAt, bytes: 1040, coversThrough: AT });
  for (const k of ['bytes', 'parts', 'coversThrough', 'snapshotId', 'createdAt'] as const)
    assert.equal(committedSnapshot({ ...commit, [k]: k === 'coversThrough' ? 'other' : k === 'bytes' || k === 'parts' ? 3 : 'x' }, sent), null, `${k} other than sent or shaped`);
});

test('the folder: a tenant folder holding only the warm-start folder is this package\'s; beside anything foreign it is not', () => {
  assert.equal(tenantDirIsOurs(['warm-start']), true, 'SHM may create it before any file of ours exists');
  assert.equal(tenantDirIsOurs(['warm-start', 'erasures.ndjson.lock']), true);
  assert.equal(tenantDirIsOurs(['warm-start', 'erasures.ndjson']), true);
  assert.equal(tenantDirIsOurs(['warm-start', 'store1.json']), false, 'another store can use a folder of that name');
  const r = rig();
  try {
    assert.equal(sweepWarmStart(warmStartFolder(ID, r.env)), 0, 'no folder: nothing to sweep, nothing created');
    assert.equal(existsSync(r.dir), false);
    // A tenant folder that is another store's: its warm-start folder is never touched.
    shmFolder(r.dir);
    const stale = shmWrite(r.dir, putFileName(TOKEN), Buffer.from('x'));
    utimesSync(stale, new Date(Date.now() - 3_600_000), new Date(Date.now() - 3_600_000));
    writeFileSync(join(r.dir, '..', 'store1.json'), '{}');
    assert.equal(code(() => sweepWarmStart(warmStartFolder(ID, r.env))), 'warm_start_file_unsafe');
    assert.equal(code(() => takePutPayload(warmStartFolder(ID, r.env), TOKEN, 100)), 'warm_start_file_unsafe');
    assert.ok(existsSync(stale), 'nothing removed in another store\'s folder');
    rmSync(join(r.dir, '..', 'store1.json'));
    // A folder open to other users, one that is a link, one that holds a folder: refused untouched.
    chmodSync(r.dir, 0o755);
    assert.equal(code(() => sweepWarmStart(warmStartFolder(ID, r.env))), 'warm_start_file_unsafe');
    chmodSync(r.dir, 0o700);
    mkdirSync(join(r.dir, 'parts'));
    assert.equal(code(() => sweepWarmStart(warmStartFolder(ID, r.env))), 'warm_start_file_unsafe');
    assert.ok(existsSync(stale), 'nothing removed beside a folder');
    rmSync(join(r.dir, 'parts'), { recursive: true });
    const elsewhere = mkdtempSync(join(tmpdir(), 'saihm-ws-target-'));
    try {
      rmSync(r.dir, { recursive: true });
      symlinkSync(elsewhere, r.dir);
      writeFileSync(join(elsewhere, putFileName(TOKEN)), 'not ours', { mode: 0o600 });
      assert.equal(code(() => sweepWarmStart(warmStartFolder(ID, r.env))), 'warm_start_file_unsafe');
      assert.equal(code(() => takePutPayload(warmStartFolder(ID, r.env), TOKEN, 100)), 'warm_start_file_unsafe');
      dropPutPayload(warmStartFolder(ID, r.env), TOKEN);
      assert.equal(readFileSync(join(elsewhere, putFileName(TOKEN)), 'utf8'), 'not ours', 'nothing removed through a link');
    } finally {
      rmSync(elsewhere, { recursive: true, force: true });
    }
  } finally {
    r.done();
  }
});

test('leftovers: every file past the age goes, temporary ones and links included; fresh ones stay', () => {
  const r = rig();
  try {
    shmFolder(r.dir);
    const old = new Date(Date.now() - 301_000);
    const names = [putFileName(TOKEN), latestFileName(TOKEN), '.put-abc.tmp', 'anything'];
    for (const n of names) utimesSync(shmWrite(r.dir, n, Buffer.from(n)), old, old);
    symlinkSync('/nonexistent', join(r.dir, 'a-link'));
    const fresh = [putFileName('freshfreshfresh123'), '.fresh.tmp'];
    for (const n of fresh) shmWrite(r.dir, n, Buffer.from(n));
    const target = join(r.root, 'target');
    writeFileSync(target, 'kept');
    symlinkSync(target, join(r.dir, 'old-link'));
    execFileSync('touch', ['-h', '-d', '@' + Math.floor(old.getTime() / 1000), join(r.dir, 'old-link')]);
    const removed = sweepWarmStart(warmStartFolder(ID, r.env));
    assert.equal(removed, names.length + 1, 'the old files and the old link');
    assert.deepEqual(readdirSync(r.dir).sort(), [...fresh, 'a-link'].sort(), 'fresh files, and a link made just now, stay');
    assert.equal(readFileSync(target, 'utf8'), 'kept', 'a link is removed, never what it points at');
    // `keep`: the calling put's own payload file stays, however old; a call without it sweeps that file too.
    const own = putFileName('ownownownown1234');
    utimesSync(shmWrite(r.dir, own, Buffer.from(own)), old, old);
    assert.equal(sweepWarmStart(warmStartFolder(ID, r.env), Date.now(), own), 0);
    assert.ok(existsSync(join(r.dir, own)), 'kept for the put that takes it');
    assert.equal(sweepWarmStart(warmStartFolder(ID, r.env)), 1);
    assert.equal(existsSync(join(r.dir, own)), false);
  } finally {
    r.done();
  }
});

test('a put\'s payload file: read whole and removed; refused untouched when missing, a link, not regular, linked twice, open to others or too large', () => {
  const r = rig();
  try {
    const folder = warmStartFolder(ID, r.env);
    assert.equal(code(() => takePutPayload(folder, TOKEN, 100)), 'warm_start_file_missing', 'no folder yet');
    shmFolder(r.dir);
    assert.equal(code(() => takePutPayload(folder, TOKEN, 100)), 'warm_start_file_missing');
    assert.match(code(() => takePutPayload(folder, '../../etc/passwd', 100)), /^other:RangeError/, 'no path from a token outside the grammar');
    const p = shmWrite(r.dir, putFileName(TOKEN), Buffer.from('payload!'));
    assert.deepEqual(Buffer.from(takePutPayload(folder, TOKEN, 8)), Buffer.from('payload!'), 'at exactly the bound');
    assert.equal(existsSync(p), false, 'removed once read');
    shmWrite(r.dir, putFileName(TOKEN), Buffer.from('payload!!'));
    assert.equal(code(() => takePutPayload(folder, TOKEN, 8)), 'snapshot_too_large');
    rmSync(p);
    const secret = join(r.root, 'secret');
    writeFileSync(secret, 'secret', { mode: 0o600 });
    symlinkSync(secret, p);
    assert.equal(code(() => takePutPayload(folder, TOKEN, 100)), 'warm_start_file_unsafe', 'a link');
    rmSync(p);
    shmWrite(r.dir, putFileName(TOKEN), Buffer.from('x'), 0o644);
    assert.equal(code(() => takePutPayload(folder, TOKEN, 100)), 'warm_start_file_unsafe', 'readable by others');
    assert.ok(existsSync(p), 'refused untouched');
    dropPutPayload(folder, TOKEN);
    assert.equal(existsSync(p), false, 'and removed by the drop every put ends with');
    shmWrite(r.dir, putFileName(TOKEN), Buffer.from('x'));
    linkSync(p, join(r.root, 'second-name'));
    assert.equal(code(() => takePutPayload(folder, TOKEN, 100)), 'warm_start_file_unsafe', 'a second name');
    rmSync(p);
    execFileSync('mkfifo', ['-m', '600', p]);
    assert.equal(code(() => takePutPayload(folder, TOKEN, 100)), 'warm_start_file_unsafe', 'a pipe, opened without blocking');
    rmSync(p);
    mkdirSync(p, { mode: 0o700 });
    assert.notEqual(code(() => takePutPayload(folder, TOKEN, 100)), 'none', 'a folder in its place');
    dropPutPayload(folder, TOKEN);
    assert.ok(lstatSync(p).isDirectory(), 'never removed as a file');
  } finally {
    r.done();
  }
});

test('a restored payload: written whole through a private temporary file, the folder created private, and nothing left when the rename fails', () => {
  const r = rig();
  try {
    const folder = warmStartFolder(ID, r.env);
    const payload = Buffer.from('restored payload');
    writeLatestPayload(folder, TOKEN, payload);
    const dest = join(r.dir, latestFileName(TOKEN));
    assert.deepEqual(readFileSync(dest), payload);
    assert.equal(statSync(dest).mode & 0o777, 0o600);
    assert.equal(statSync(r.dir).mode & 0o777, 0o700, 'the folder is created private');
    assert.equal(statSync(join(r.dir, '..')).mode & 0o777, 0o700, 'and the tenant folder');
    writeLatestPayload(folder, TOKEN, Buffer.from('newer'));
    assert.equal(readFileSync(dest, 'utf8'), 'newer', 'an older file of the token is replaced');
    dropLatestPayload(folder, TOKEN);
    assert.equal(existsSync(dest), false);
    dropLatestPayload(folder, TOKEN);
    // The rename fails when the name is a folder that is not empty: the temporary file goes with the failure.
    mkdirSync(join(dest, 'x'), { recursive: true });
    assert.throws(() => writeLatestPayload(folder, TOKEN, payload));
    assert.deepEqual(readdirSync(r.dir), [latestFileName(TOKEN)], 'no temporary file is left behind');
    assert.throws(() => writeLatestPayload(folder, 'BAD', payload), RangeError, 'no path from a token outside the grammar');
  } finally {
    r.done();
  }
});
