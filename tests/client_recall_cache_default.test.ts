/**
 * PC-RECALL-CACHE-DEFAULT — where the MCP server's boot path turns the recall cache on by itself.
 *
 * The cache holds plaintext at rest. From 0.14.3 it is ON for an identity that boots from a key FILE: the
 * self-join key file in SAIHM_HOME, or the file SAIHM_MASTER_SECRET_FILE names wherever it is (the copy
 * then still lives in SAIHM_HOME, beside the sequence marks). It is OFF for an identity token or an inline
 * secret, and OFF everywhere when SAIHM_RECALL_CACHE=0 — an explicit SAIHM_RECALL_CACHE_PATH included. A
 * client constructed directly writes nothing unless it asks.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { appendFileSync, chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { SaihmProClient, defaultRecallCachePath, DEFAULT_ENDPOINT } from '../src/client.js';
import { generatePassphrase, sealIdentityToken } from '../src/identity-token.js';
import { deriveIdentity, fromHex, toHex } from '@saihm/client-pro';

const KEYS = [
  'SAIHM_SELF_JOIN',
  'SAIHM_HOME',
  'SAIHM_MASTER_SECRET_FILE',
  'SAIHM_MASTER_SECRET_HEX',
  'SAIHM_TIER',
  'SAIHM_ENDPOINT_URL',
  'SAIHM_AUTH_HEADER',
  'SAIHM_SEQ_STATE_PATH',
  'SAIHM_RECALL_CACHE',
  'SAIHM_RECALL_CACHE_PATH',
  'SAIHM_ERASURE_FEED',
  'SAIHM_ERASURE_FEED_DIR',
  'SAIHM_IDENTITY',
  'SAIHM_IDENTITY_PASSPHRASE',
  // The signals of a temporary or shared home (0.14.3 review): cleared, so a runner that sets them (GitHub Actions sets
  // CI and GITHUB_ACTIONS) does not decide these tests; the tests that are about them set them.
  'SAIHM_EPHEMERAL_HOME',
  'CI',
  'GITHUB_ACTIONS',
  'CLAUDE_CODE_REMOTE',
  'SAIHM_SESSION_CACHE',
] as const;

function withEnv<T>(overrides: Record<string, string | undefined>, fn: () => T): T {
  const saved: Record<string, string | undefined> = {};
  for (const k of KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  for (const [k, v] of Object.entries(overrides)) if (v !== undefined) process.env[k] = v;
  try {
    return fn();
  } finally {
    for (const k of KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

/** A SAIHM_HOME holding a self-join key file, as `saihm_join` leaves it. */
function homeWithDefaultKey(): { home: string; keyPath: string } {
  const home = mkdtempSync(join(tmpdir(), 'saihm-rc-default-'));
  const keyPath = join(home, 'free-identity.key');
  writeFileSync(keyPath, randomBytes(32).toString('hex'), { mode: 0o600 });
  return { home, keyPath };
}

const cachePathOf = (c: SaihmProClient): string | undefined =>
  (c as unknown as { recallCache: { cachePath?: string } }).recallCache.cachePath;

test('booted from the self-join key file in SAIHM_HOME: the cache is on, beside the key, named by the identity', () => {
  const { home } = homeWithDefaultKey();
  try {
    withEnv({ SAIHM_HOME: home }, () => {
      const c = SaihmProClient.bootFromEnv();
      const want = join(home, `recall.${c.agentIdHash.slice(0, 16)}.json`);
      assert.equal(cachePathOf(c), want);
      assert.equal(defaultRecallCachePath(c.agentIdHash), want);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('the same key reached through SAIHM_MASTER_SECRET_FILE (as a join leaves the env) is still the default key', () => {
  const { home, keyPath } = homeWithDefaultKey();
  try {
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_FILE: keyPath }, () => {
      const c = SaihmProClient.bootFromEnv();
      assert.equal(cachePathOf(c), join(home, `recall.${c.agentIdHash.slice(0, 16)}.json`));
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('0.14.3 review: no default copy where the home is temporary or kept for later jobs, whichever signal says so', () => {
  const { home, keyPath } = homeWithDefaultKey();
  const elsewhere = mkdtempSync(join(tmpdir(), 'saihm-rc-key-'));
  try {
    const keyFile = join(elsewhere, 'agent.key');
    writeFileSync(keyFile, randomBytes(32).toString('hex'), { mode: 0o600 });
    const signals: Record<string, string>[] = [
      { GITHUB_ACTIONS: 'true' },
      { CI: 'true' },
      { CI: '1' },
      { CLAUDE_CODE_REMOTE: 'true' },
      { SAIHM_EPHEMERAL_HOME: '1' },
      { SAIHM_EPHEMERAL_HOME: 'yes' },
    ];
    for (const signal of signals) {
      for (const keyEnv of [{}, { SAIHM_MASTER_SECRET_FILE: keyPath }, { SAIHM_MASTER_SECRET_FILE: keyFile }]) {
        withEnv({ SAIHM_HOME: home, ...keyEnv, ...signal }, () => {
          const c = SaihmProClient.bootFromEnv();
          assert.equal(cachePathOf(c), undefined, `${JSON.stringify(signal)} ${JSON.stringify(keyEnv)}: no default copy`);
          const kept = (c as unknown as { sessionTokens?: unknown }).sessionTokens;
          assert.equal(kept, undefined, `${JSON.stringify(signal)}: no kept sign-in either`);
        });
      }
      // A path set on purpose is still honoured there.
      withEnv({ SAIHM_HOME: home, ...signal, SAIHM_RECALL_CACHE_PATH: join(elsewhere, 'chosen.json') }, () => {
        assert.equal(cachePathOf(SaihmProClient.bootFromEnv()), join(elsewhere, 'chosen.json'), `${JSON.stringify(signal)}: a chosen path`);
      });
    }
    // SAIHM_EPHEMERAL_HOME=0 declares the home kept, over the host's own signal; and with no signal, the default stands.
    for (const kept of [{ CI: 'true', SAIHM_EPHEMERAL_HOME: '0' }, { GITHUB_ACTIONS: 'true', SAIHM_EPHEMERAL_HOME: 'false' }, { CI: 'false' }, { CI: '0' }, {}]) {
      withEnv({ SAIHM_HOME: home, ...kept }, () => {
        const c = SaihmProClient.bootFromEnv();
        assert.equal(cachePathOf(c), join(home, `recall.${c.agentIdHash.slice(0, 16)}.json`), `${JSON.stringify(kept)}: the default copy`);
        assert.notEqual((c as unknown as { sessionTokens?: unknown }).sessionTokens, undefined, `${JSON.stringify(kept)}: and the kept sign-in`);
      });
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(elsewhere, { recursive: true, force: true });
  }
});

test('SAIHM_RECALL_CACHE=0 turns the default off', () => {
  const { home } = homeWithDefaultKey();
  try {
    withEnv({ SAIHM_HOME: home, SAIHM_RECALL_CACHE: '0' }, () => {
      assert.equal(cachePathOf(SaihmProClient.bootFromEnv()), undefined);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('0.14.3: a key file somewhere else turns the cache on too, in SAIHM_HOME and not beside that key', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-rc-default-'));
  const elsewhere = mkdtempSync(join(tmpdir(), 'saihm-rc-key-'));
  try {
    const keyFile = join(elsewhere, 'agent.key');
    writeFileSync(keyFile, randomBytes(32).toString('hex'), { mode: 0o600 });
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_FILE: keyFile }, () => {
      const c = SaihmProClient.bootFromEnv();
      assert.equal(cachePathOf(c), join(home, `recall.${c.agentIdHash.slice(0, 16)}.json`));
    });
    // The opt-out is unchanged.
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_FILE: keyFile, SAIHM_RECALL_CACHE: '0' }, () => {
      assert.equal(cachePathOf(SaihmProClient.bootFromEnv()), undefined);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(elsewhere, { recursive: true, force: true });
  }
});

test('0.14.3: a key file whose SAIHM_HOME cannot be written keeps no copy, so recall goes on working', { skip: (process.platform === 'win32' || process.getuid?.() === 0) && 'permissions are not enforced here' }, () => {
  // A copy that cannot be written fails the recall it belongs to. A key kept elsewhere is how a container mounts a
  // secret beside a home nobody may write; the standard key in a home mounted read-only is the same case. Measured on
  // 0.14.2: the standard key there failed every recall EACCES. The default now asks first whether the folder can be
  // written, or made.
  const base = mkdtempSync(join(tmpdir(), 'saihm-rc-ro-'));
  const home = join(base, 'home');
  const elsewhere = join(base, 'secrets');
  mkdirSync(home, { mode: 0o700 });
  mkdirSync(elsewhere, { mode: 0o700 });
  try {
    const keyFile = join(elsewhere, 'agent.key');
    writeFileSync(keyFile, randomBytes(32).toString('hex'), { mode: 0o600 });
    writeFileSync(join(home, 'free-identity.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
    chmodSync(home, 0o500);
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_FILE: keyFile }, () => {
      assert.equal(cachePathOf(SaihmProClient.bootFromEnv()), undefined, 'a key kept elsewhere');
    });
    withEnv({ SAIHM_HOME: home }, () => {
      assert.equal(cachePathOf(SaihmProClient.bootFromEnv()), undefined, 'the standard key');
    });
    // Positive controls: the same homes, writable, or not made yet under a writable folder, turn it on.
    chmodSync(home, 0o700);
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_FILE: keyFile }, () => {
      assert.ok(cachePathOf(SaihmProClient.bootFromEnv())?.startsWith(join(home, 'recall.')));
    });
    withEnv({ SAIHM_HOME: join(base, 'not-made-yet'), SAIHM_MASTER_SECRET_FILE: keyFile }, () => {
      assert.ok(cachePathOf(SaihmProClient.bootFromEnv())?.startsWith(join(base, 'not-made-yet', 'recall.')));
    });
    // An explicit path is the operator's: it is used whatever the folder, as before.
    chmodSync(home, 0o500);
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_FILE: keyFile, SAIHM_RECALL_CACHE_PATH: join(elsewhere, 'c.json') }, () => {
      assert.equal(cachePathOf(SaihmProClient.bootFromEnv()), join(elsewhere, 'c.json'));
    });
  } finally {
    chmodSync(home, 0o700);
    rmSync(base, { recursive: true, force: true });
  }
});

test('an inline secret, or an identity token, leaves the cache off', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-rc-default-'));
  try {
    const hex = randomBytes(32).toString('hex');
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex }, () => {
      assert.equal(cachePathOf(SaihmProClient.bootFromEnv()), undefined);
    });
    const passphrase = generatePassphrase();
    const token = sealIdentityToken({ secretHex: hex, tier: 'FREE', paymentMethod: undefined }, toHex(deriveIdentity(fromHex(hex)).agentIdHash), passphrase);
    withEnv({ SAIHM_HOME: home, SAIHM_IDENTITY: token, SAIHM_IDENTITY_PASSPHRASE: passphrase }, () => {
      const c = SaihmProClient.bootFromEnv();
      assert.equal(c.agentIdHash, toHex(deriveIdentity(fromHex(hex)).agentIdHash), 'setup: the token opened');
      assert.equal(cachePathOf(c), undefined);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('an explicit SAIHM_RECALL_CACHE_PATH turns it on for any identity source, and SAIHM_RECALL_CACHE=0 still wins', () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-rc-explicit-'));
  try {
    mkdirSync(join(dir, 'home'));
    const explicit = join(dir, 'cache.json');
    const hex = randomBytes(32).toString('hex');
    withEnv({ SAIHM_HOME: join(dir, 'home'), SAIHM_MASTER_SECRET_HEX: hex, SAIHM_RECALL_CACHE_PATH: explicit }, () => {
      assert.equal(cachePathOf(SaihmProClient.bootFromEnv()), explicit);
    });
    withEnv(
      { SAIHM_HOME: join(dir, 'home'), SAIHM_MASTER_SECRET_HEX: hex, SAIHM_RECALL_CACHE_PATH: explicit, SAIHM_RECALL_CACHE: '0' },
      () => assert.equal(cachePathOf(SaihmProClient.bootFromEnv()), undefined),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a client constructed directly writes nothing unless it asks for the default', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-rc-library-'));
  try {
    withEnv({ SAIHM_HOME: home }, () => {
      const master = randomBytes(32);
      const plain = new SaihmProClient(DEFAULT_ENDPOINT, 'Bearer x', Uint8Array.from(master), {});
      assert.equal(cachePathOf(plain), undefined);
      const asked = new SaihmProClient(DEFAULT_ENDPOINT, 'Bearer x', Uint8Array.from(master), { persistRecallCache: true });
      assert.equal(cachePathOf(asked), join(home, `recall.${asked.agentIdHash.slice(0, 16)}.json`));
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// ── A cell erased in one session must not come back to disk from another ───────────────────────────
const cell = (cellId: string, plaintext: string) => ({ cellId, plaintext, seq: '1', commitmentHash: 'ab'.repeat(32) });
type CacheView = { upsert(c: unknown): void; all(): Array<{ cellId: string }> };
const cacheOf = (c: SaihmProClient): CacheView => (c as unknown as { recallCache: CacheView }).recallCache;

test('a cell erased by another session is never written back, and a loaded file drops it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-rc-erased-'));
  try {
    withEnv({ SAIHM_HOME: join(dir, 'home'), SAIHM_ERASURE_FEED_DIR: join(dir, 'feed') }, () => {
      const master = randomBytes(32);
      const cachePath = join(dir, 'cache.json');
      const b = new SaihmProClient(DEFAULT_ENDPOINT, 'Bearer x', Uint8Array.from(master), { recallCachePath: cachePath });
      cacheOf(b).upsert(cell('x', 'erased elsewhere'));
      assert.ok(JSON.parse(readFileSync(cachePath, 'utf8')).x, 'x is on disk before the erasure');
      // Another session forgets x: this identity's feed gains a line naming it.
      const feed = join(dir, 'feed', 'tenants', b.agentIdHash, 'erasures.ndjson');
      mkdirSync(dirname(feed), { recursive: true });
      appendFileSync(feed, JSON.stringify({ v: 1, cellId: 'x' }) + '\n');
      cacheOf(b).upsert(cell('y', 'written after'));
      const onDisk = JSON.parse(readFileSync(cachePath, 'utf8'));
      assert.equal(onDisk.x, undefined, 'the erased plaintext was not written back');
      assert.equal(onDisk.y.plaintext, 'written after');
      writeFileSync(cachePath, JSON.stringify({ x: cell('x', 'stale'), y: cell('y', 'kept') }));
      const c = new SaihmProClient(DEFAULT_ENDPOINT, 'Bearer x', Uint8Array.from(master), { recallCachePath: cachePath });
      assert.deepEqual(cacheOf(c).all().map((r) => r.cellId), ['y'], 'dropped at load');
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('with the erasure feed turned off the feed is not consulted; the next recall is what evicts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-rc-erased-off-'));
  try {
    withEnv({ SAIHM_HOME: join(dir, 'home'), SAIHM_ERASURE_FEED_DIR: join(dir, 'feed'), SAIHM_ERASURE_FEED: '0' }, () => {
      const cachePath = join(dir, 'cache.json');
      const b = new SaihmProClient(DEFAULT_ENDPOINT, 'Bearer x', randomBytes(32), { recallCachePath: cachePath });
      cacheOf(b).upsert(cell('x', 'kept without a feed'));
      const feed = join(dir, 'feed', 'tenants', b.agentIdHash, 'erasures.ndjson');
      mkdirSync(dirname(feed), { recursive: true });
      appendFileSync(feed, JSON.stringify({ v: 1, cellId: 'x' }) + '\n');
      cacheOf(b).upsert(cell('y', 'y'));
      assert.ok(JSON.parse(readFileSync(cachePath, 'utf8')).x);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a cell dropped at load still leaves the file when it is forgotten, though memory no longer holds it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-rc-erased-load-'));
  try {
    withEnv({ SAIHM_HOME: join(dir, 'home'), SAIHM_ERASURE_FEED_DIR: join(dir, 'feed') }, () => {
      const master = randomBytes(32);
      const cachePath = join(dir, 'cache.json');
      const probe = new SaihmProClient(DEFAULT_ENDPOINT, 'Bearer x', Uint8Array.from(master), {});
      const feed = join(dir, 'feed', 'tenants', probe.agentIdHash, 'erasures.ndjson');
      mkdirSync(dirname(feed), { recursive: true });
      appendFileSync(feed, JSON.stringify({ v: 1, cellId: 'x' }) + '\n');
      writeFileSync(cachePath, JSON.stringify({ x: cell('x', 'still on disk') }), { mode: 0o600 });
      const c = new SaihmProClient(DEFAULT_ENDPOINT, 'Bearer x', Uint8Array.from(master), { recallCachePath: cachePath });
      assert.deepEqual(cacheOf(c).all(), [], 'dropped from memory at load');
      assert.ok(JSON.parse(readFileSync(cachePath, 'utf8')).x, 'no write happened at construction');
      (c as unknown as { recallCache: { remove(id: string): void } }).recallCache.remove('x');
      assert.equal(JSON.parse(readFileSync(cachePath, 'utf8')).x, undefined, 'the forget rewrote the file');
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** Capture what the client writes to stderr while `fn` runs. The notice is written synchronously at the top of a
 *  recall, before any network work, so a recall that then fails still proves whether it was said. */
function stderrDuring(fn: () => void): string {
  const orig = process.stderr.write.bind(process.stderr);
  let out = '';
  (process.stderr as unknown as { write: (c: string) => boolean }).write = (c: string) => { out += c; return true; };
  try { fn(); } finally { (process.stderr as unknown as { write: typeof orig }).write = orig; }
  return out;
}

test('an identity with no cache is TOLD so, once, and only when it did not choose that', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-rc-notice-'));
  const elsewhere = mkdtempSync(join(tmpdir(), 'saihm-rc-notice-key-'));
  try {
    const hex = randomBytes(32).toString('hex');
    const keyFile = join(elsewhere, 'agent.key');
    writeFileSync(keyFile, hex, { mode: 0o600 });

    // Off by default because the key is inline (from 0.14.3 a key file anywhere turns the cache on): the subscriber
    // is paying a full fetch on every recall and had no way to know. Said once — a line per recall would be noise,
    // and noise is ignored.
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex }, () => {
      const c = SaihmProClient.bootFromEnv();
      const first = stderrDuring(() => { void c.recall().catch(() => undefined); });
      const second = stderrDuring(() => { void c.recall().catch(() => undefined); });
      assert.match(first, /^saihm: recall fetches every memory on each call here, because this identity keeps no local copy/);
      assert.match(first, /SAIHM_RECALL_CACHE_PATH/);
      assert.match(first, /plaintext at rest/, 'the trade is stated, not buried');
      assert.equal(second, '', 'said twice');
    });

    // Nothing to tell: a cache is configured, by its path or by the key file's default.
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_RECALL_CACHE_PATH: join(elsewhere, 'c.json') }, () => {
      const c = SaihmProClient.bootFromEnv();
      assert.equal(stderrDuring(() => { void c.recall().catch(() => undefined); }), '');
    });
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_FILE: keyFile }, () => {
      const c = SaihmProClient.bootFromEnv();
      assert.equal(stderrDuring(() => { void c.recall().catch(() => undefined); }), '');
    });

    // Turned off deliberately: someone who chose this does not need telling, and a notice they cannot act on
    // teaches them to ignore the next one.
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_RECALL_CACHE: '0' }, () => {
      const c = SaihmProClient.bootFromEnv();
      assert.equal(stderrDuring(() => { void c.recall().catch(() => undefined); }), '');
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(elsewhere, { recursive: true, force: true });
  }
});
