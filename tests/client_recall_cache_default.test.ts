/**
 * PC-RECALL-CACHE-DEFAULT — where the MCP server's boot path turns the recall cache on by itself.
 *
 * The cache holds plaintext at rest, so the default is deliberately narrow: ON only for an identity that
 * boots from the self-join key file in SAIHM_HOME (the installation that already keeps its key and its
 * sequence marks in that directory), OFF for an inline secret or a key file placed anywhere else, and
 * OFF everywhere when SAIHM_RECALL_CACHE=0 — an explicit SAIHM_RECALL_CACHE_PATH included. A client
 * constructed directly writes nothing unless it asks.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { appendFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { SaihmProClient, defaultRecallCachePath, DEFAULT_ENDPOINT } from '../src/client.js';

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

test('a key file somewhere else, or an inline secret, leaves the cache off', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-rc-default-'));
  const elsewhere = mkdtempSync(join(tmpdir(), 'saihm-rc-key-'));
  try {
    const keyFile = join(elsewhere, 'agent.key');
    writeFileSync(keyFile, randomBytes(32).toString('hex'), { mode: 0o600 });
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_FILE: keyFile }, () => {
      assert.equal(cachePathOf(SaihmProClient.bootFromEnv()), undefined);
    });
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: randomBytes(32).toString('hex') }, () => {
      assert.equal(cachePathOf(SaihmProClient.bootFromEnv()), undefined);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(elsewhere, { recursive: true, force: true });
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
