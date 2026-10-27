// The sign-in kept between sessions (0.14.3): the file itself. What these tests hold it to: a token is used only from a
// regular file of this user's, with one name, mode 600, small, holding exactly what this package writes for this
// endpoint, agent ID, plan and payment method; anything else is ignored and replaced by the next keep; a refused token
// is removed only while the file still holds it; nothing here ever throws; and several processes writing and reading
// at once never see a part of a file, only a whole one.
// Runner: npx tsx --test tests/session_token_file.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { execFileSync, spawn } from 'node:child_process';
import { chmodSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { MAX_SESSION_FILE_BYTES, MAX_SESSION_TOKEN_CHARS, SessionTokenFile, type SessionBinding } from '../src/session-token-file.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const MODULE = resolve(HERE, '../src/session-token-file.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const POSIX = process.platform !== 'win32';
const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');

/** A token shaped as the endpoint signs one, distinct each time. */
const jwt = (expS = Math.floor(Date.now() / 1000) + 3600): string =>
  `${b64url({ alg: 'EdDSA' })}.${b64url({ sub: 'x', exp: expS, jti: randomBytes(8).toString('hex') })}.${randomBytes(16).toString('base64url')}`;

const BINDING: SessionBinding = { endpoint: 'https://saihm.example/mcp', agentIdHash: 'ab'.repeat(32), tier: 'PRO', paymentMethod: 'stripe' };

function scratch(): { dir: string; path: string } {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-session-'));
  return { dir, path: join(dir, `session.${'ab'.repeat(8)}.json`) };
}

const fileFor = (path: string, b: Partial<SessionBinding> = {}, uid?: number): SessionTokenFile =>
  new SessionTokenFile(path, () => ({ ...BINDING, ...b }), ...(uid === undefined ? [] : [uid]));

test('a kept token is read back for the same binding, from a file of mode 600 holding exactly the binding and the token', () => {
  const { dir, path } = scratch();
  try {
    const f = fileFor(path);
    assert.equal(f.read(), undefined, 'nothing kept yet');
    const t = jwt();
    f.keep(t);
    assert.equal(f.read(), t);
    if (POSIX) assert.equal(statSync(path).mode & 0o777, 0o600);
    const doc = JSON.parse(readFileSync(path, 'utf8'));
    assert.deepEqual(doc, { kind: 'saihm-session-token', version: 1, ...BINDING, token: t });
    assert.deepEqual(readdirSync(dir), [`session.${'ab'.repeat(8)}.json`], 'no temporary or lock file is left');
    // A second keep replaces it.
    const t2 = jwt();
    f.keep(t2);
    assert.equal(f.read(), t2);
    // A plan without a payment method is kept as null, and read back for the same binding only.
    const free = fileFor(path, { tier: 'FREE', paymentMethod: undefined });
    free.keep(t);
    assert.equal(JSON.parse(readFileSync(path, 'utf8')).paymentMethod, null);
    assert.equal(free.read(), t);
    assert.equal(fileFor(path, { tier: 'FREE', paymentMethod: 'stripe' }).read(), undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a token kept for another endpoint, agent ID, plan or payment method is not used', () => {
  const { dir, path } = scratch();
  try {
    const t = jwt();
    fileFor(path).keep(t);
    for (const other of [
      { endpoint: 'https://other.example/mcp' },
      { endpoint: 'https://saihm.example/mcp/' },
      { agentIdHash: 'cd'.repeat(32) },
      { tier: 'PRO_FAST' },
      { tier: undefined },
      { paymentMethod: 'stablecoin' },
      { paymentMethod: undefined },
    ]) {
      assert.equal(fileFor(path, other).read(), undefined, JSON.stringify(other));
    }
    assert.equal(fileFor(path).read(), t, 'positive control: the same binding reads it');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a corrupt, empty, oversized or foreign file is ignored, and the next keep replaces it', () => {
  const { dir, path } = scratch();
  try {
    const f = fileFor(path);
    const t = jwt();
    const good = { kind: 'saihm-session-token', version: 1, ...BINDING, token: t };
    const bodies: [string, string][] = [
      ['empty', ''],
      ['not JSON', `token=${t}`],
      ['cut short', JSON.stringify(good).slice(0, 60)],
      ['a list', JSON.stringify([good])],
      ['null', 'null'],
      ['oversized', JSON.stringify(good) + ' '.repeat(MAX_SESSION_FILE_BYTES)],
      ['another kind', JSON.stringify({ ...good, kind: 'saihm-other' })],
      ['version 2', JSON.stringify({ ...good, version: 2 })],
      ['an extra field', JSON.stringify({ ...good, exp: 1 })],
      ['a field missing', JSON.stringify({ kind: good.kind, version: 1, endpoint: good.endpoint, agentIdHash: good.agentIdHash, tier: 'PRO', token: t })],
      ['not a token', JSON.stringify({ ...good, token: 'not a token' })],
      ['a token too long', JSON.stringify({ ...good, token: `${'a'.repeat(MAX_SESSION_TOKEN_CHARS)}.b.c` })],
      ['a token of another type', JSON.stringify({ ...good, token: 7 })],
    ];
    for (const [label, body] of bodies) {
      writeFileSync(path, body, { mode: 0o600 });
      assert.equal(f.read(), undefined, label);
      const fresh = jwt();
      f.keep(fresh);
      assert.equal(f.read(), fresh, `${label}: replaced by the next keep`);
    }
    // Positive control: the same document, well formed, is read.
    writeFileSync(path, JSON.stringify(good), { mode: 0o600 });
    assert.equal(f.read(), t);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a file other users can reach, another user\'s file, a link, a second name, a folder or a pipe is not used', { skip: !POSIX }, () => {
  const { dir, path } = scratch();
  try {
    const f = fileFor(path);
    for (const mode of [0o644, 0o640, 0o604, 0o660, 0o602, 0o666]) {
      const t = jwt();
      f.keep(t);
      chmodSync(path, mode);
      assert.equal(f.read(), undefined, `mode ${mode.toString(8)}`);
      const fresh = jwt();
      f.keep(fresh);
      assert.equal(statSync(path).mode & 0o777, 0o600, 'replaced as a new file of mode 600');
      assert.equal(f.read(), fresh);
    }
    // Owned by someone else: only the superuser can make such a file, so the reader is told to expect another user.
    const t = jwt();
    f.keep(t);
    assert.equal(fileFor(path, {}, (process.getuid?.() ?? 0) + 1).read(), undefined, 'another user\'s file');
    assert.equal(f.read(), t, 'positive control: this user\'s file');
    // A second name (a hard link) and a link to a good file.
    const other = join(dir, 'elsewhere.json');
    linkSync(path, other);
    assert.equal(f.read(), undefined, 'a file with two names');
    rmSync(other);
    assert.equal(f.read(), t);
    const target = join(dir, 'target.json');
    writeFileSync(target, readFileSync(path), { mode: 0o600 });
    rmSync(path);
    symlinkSync(target, path);
    assert.equal(f.read(), undefined, 'a link, even to a good file');
    // keep replaces the link itself, never the file it points at.
    const fresh = jwt();
    f.keep(fresh);
    assert.equal(f.read(), fresh);
    assert.equal(JSON.parse(readFileSync(target, 'utf8')).token, t, 'the link target is untouched');
    rmSync(path);
    mkdirSync(path);
    assert.equal(f.read(), undefined, 'a folder');
    f.keep(jwt());
    assert.ok(statSync(path).isDirectory(), 'a folder in its place is left alone');
    rmSync(path, { recursive: true });
    execFileSync('mkfifo', ['-m', '600', path]);
    const t0 = Date.now();
    assert.equal(f.read(), undefined, 'a pipe');
    assert.ok(Date.now() - t0 < 2000, 'a pipe is not opened, so it cannot block');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('drop removes the file only while it holds the refused token; nothing here throws', () => {
  const { dir, path } = scratch();
  try {
    const f = fileFor(path);
    const t = jwt();
    f.keep(t);
    f.drop(jwt());
    assert.equal(f.read(), t, 'a token another session kept since is not removed');
    f.drop(t);
    assert.throws(() => statSync(path), /ENOENT/);
    f.drop(t);
    // A token of another shape, or too long, is not kept.
    f.keep('not a token');
    f.keep(`${'a'.repeat(MAX_SESSION_TOKEN_CHARS)}.b.c`);
    assert.throws(() => statSync(path), /ENOENT/);
    // Nowhere to write: nothing throws, nothing is read.
    const nowhere = fileFor(join(dir, 'missing', 'session.json'));
    nowhere.keep(jwt());
    assert.equal(nowhere.read(), undefined);
    nowhere.drop(t);
    // A lock another live process holds: keep gives up after its short wait, without throwing.
    writeFileSync(`${path}.lock`, `${process.pid} ${Date.now()} held`, { mode: 0o600 });
    const t0 = Date.now();
    f.keep(jwt());
    assert.ok(Date.now() - t0 >= 900, 'it waited for the lock');
    assert.equal(f.read(), undefined, 'and wrote nothing under a lock it does not hold');
    rmSync(`${path}.lock`);
    f.keep(t);
    assert.equal(f.read(), t);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('discard (SAIHM_SESSION_CACHE=0) removes only a sign-in kept for this agent ID: never another document, a link, a folder or the key beside it', () => {
  const { dir, path } = scratch();
  try {
    const keyPath = join(dir, 'free-identity.key');
    const keyHex = randomBytes(32).toString('hex');
    writeFileSync(keyPath, keyHex, { mode: 0o600 });
    const f = fileFor(path);
    // Nothing there: nothing removed, and nothing created, not even the lock.
    assert.equal(f.discard(), false);
    assert.deepEqual(readdirSync(dir), ['free-identity.key']);
    // A sign-in kept for this agent ID under another endpoint, plan and payment method is still this identity's.
    fileFor(path, { endpoint: 'https://other.example/mcp', tier: 'FREE', paymentMethod: undefined }).keep(jwt());
    assert.equal(f.discard(), true);
    assert.deepEqual(readdirSync(dir), ['free-identity.key'], 'removed, and no lock or temporary file is left');
    // One that other users can read is this package's sign-in all the same: the first one to remove.
    if (POSIX) {
      f.keep(jwt());
      chmodSync(path, 0o644);
      assert.equal(f.discard(), true, 'mode 644');
      assert.throws(() => lstatSync(path), /ENOENT/);
    }
    // Left exactly as it is: anything at this name that is not this package's sign-in for this agent ID.
    for (const [label, body] of [
      ['another agent ID', JSON.stringify({ kind: 'saihm-session-token', version: 1, ...BINDING, agentIdHash: 'cd'.repeat(32), token: jwt() })],
      ['another kind of document', JSON.stringify({ kind: 'other', version: 1, ...BINDING, token: jwt() })],
      ['another version', JSON.stringify({ kind: 'saihm-session-token', version: 2, ...BINDING, token: jwt() })],
      ['key-shaped text', keyHex],
      ['a file larger than a sign-in', JSON.stringify({ kind: 'saihm-session-token', version: 1, ...BINDING, token: 'x'.repeat(MAX_SESSION_FILE_BYTES) })],
    ] as const) {
      writeFileSync(path, body, { mode: 0o600 });
      assert.equal(f.discard(), false, label);
      assert.equal(readFileSync(path, 'utf8'), body, `${label}: untouched`);
    }
    rmSync(path);
    if (POSIX) {
      // A link at this name, even to this agent ID's sign-in, and a link to the key: neither the link nor its target.
      const target = join(dir, 'target.json');
      fileFor(target).keep(jwt());
      for (const to of [target, keyPath]) {
        symlinkSync(to, path);
        assert.equal(f.discard(), false, `a link to ${to}`);
        assert.ok(lstatSync(path).isSymbolicLink());
        assert.ok(statSync(to).isFile());
        rmSync(path);
      }
      // Another user's file (only the superuser can make one), then a folder at this name.
      f.keep(jwt());
      assert.equal(fileFor(path, {}, (process.getuid?.() ?? 0) + 1).discard(), false, "another user's file");
      assert.equal(f.discard(), true, "positive control: this user's file");
      mkdirSync(path);
      assert.equal(f.discard(), false, 'a folder');
      assert.ok(statSync(path).isDirectory());
      rmSync(path, { recursive: true });
    }
    // Through all of the above, the key beside it is what it was.
    assert.equal(readFileSync(keyPath, 'utf8'), keyHex);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('several processes keeping and reading at once: every read is a whole token one of them kept, or nothing', async () => {
  const { dir, path } = scratch();
  try {
    const writers = 4;
    const rounds = 60;
    const script = (id: number): string => `
      import { SessionTokenFile } from ${JSON.stringify(MODULE)};
      const binding = ${JSON.stringify(BINDING)};
      const f = new SessionTokenFile(${JSON.stringify(path)}, () => binding);
      const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
      const seen = [];
      for (let i = 0; i < ${rounds}; i++) {
        f.keep(b64({ alg: 'EdDSA' }) + '.' + b64({ w: ${id}, i, exp: 4102444800 }) + '.sig${id}x' + i);
        const r = f.read();
        if (r !== undefined) seen.push(r);
      }
      process.stdout.write(JSON.stringify(seen));
    `;
    const runs = await Promise.all(
      Array.from({ length: writers }, (_, id) =>
        new Promise<string[]>((res, rej) => {
          const p = spawn(TSX, ['-e', script(id)], { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
          let out = '';
          let err = '';
          p.stdout.on('data', (d) => (out += d));
          p.stderr.on('data', (d) => (err += d));
          p.on('close', (code) => (code === 0 ? res(JSON.parse(out) as string[]) : rej(new Error(`writer ${id} exit ${code}: ${err}`))));
        }),
      ),
    );
    const shape = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.sig[0-9]+x[0-9]+$/;
    let reads = 0;
    for (const seen of runs) {
      for (const r of seen) {
        reads++;
        assert.match(r, shape, 'a whole token, never part of a file');
      }
    }
    assert.ok(reads > 0, 'the readers read');
    const last = fileFor(path).read();
    assert.ok(last !== undefined && shape.test(last), 'the file left is whole');
    if (POSIX) assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(dir), [`session.${'ab'.repeat(8)}.json`], 'no temporary or lock file is left');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
