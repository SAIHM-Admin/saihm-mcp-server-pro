/**
 * Recall cache: two sessions of one identity on one cache file. A forget appends its erasure line and removes the cell
 * under the cache's cross-process write lock, and every cache save reads the erasure feed and renames under the same
 * lock. Before this, a save by another session landing between the removal and the erasure line wrote the forgotten
 * cell's plaintext back to disk while the forget reported nothing (reproduced with two real processes on 0.7.0).
 *
 * These tests use real child processes for the other session and a local stub endpoint for `forget`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { SaihmProClient } from '../src/client.js';

const MASTER = new Uint8Array(32).fill(7);
const cell = (cellId: string, plaintext: string) => ({ cellId, plaintext, seq: '1', commitmentHash: 'ab'.repeat(32) });
type CacheView = { withWriteLock<T>(fn: () => T): T; upsert(c: unknown): void };

async function withStack(run: (s: { client: SaihmProClient; dir: string; cachePath: string; env: NodeJS.ProcessEnv }) => Promise<void>) {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-rc-lock-'));
  const server: Server = createServer((req, res) => {
    void (async () => {
      let body = '';
      for await (const chunk of req) body += chunk;
      const { method, params = {} } = JSON.parse(body) as { method: string; params?: Record<string, unknown> };
      const out =
        method === 'saihm_forget'
          ? { cellId: params.id, shardId: 's', complete: true, sharesPurged: 0, steps: [], epoch: '1' }
          : { error: 'unused' };
      const txt = JSON.stringify(out);
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(txt)) }).end(txt);
    })();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const saved = { home: process.env.SAIHM_HOME, feed: process.env.SAIHM_ERASURE_FEED_DIR, off: process.env.SAIHM_ERASURE_FEED };
  process.env.SAIHM_HOME = join(dir, 'home');
  process.env.SAIHM_ERASURE_FEED_DIR = join(dir, 'feed');
  delete process.env.SAIHM_ERASURE_FEED;
  const cachePath = join(dir, 'cache.json');
  writeFileSync(cachePath, JSON.stringify({ x: cell('x', 'PLAINTEXT-OF-X'), y: cell('y', 'kept') }), { mode: 0o600 });
  const endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`;
  const client = new SaihmProClient(endpoint, 'Bearer test', Uint8Array.from(MASTER), { tier: 'PRO', recallCachePath: cachePath });
  try {
    await run({ client, dir, cachePath, env: { ...process.env } });
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    for (const [k, v] of [['SAIHM_HOME', saved.home], ['SAIHM_ERASURE_FEED_DIR', saved.feed], ['SAIHM_ERASURE_FEED', saved.off]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Run `body` in a child process that has `client` (same identity, same cache file) and `signal(name)`. */
function child(dir: string, env: NodeJS.ProcessEnv, body: string) {
  const script = join(dir, `child-${Math.random().toString(16).slice(2)}.mts`);
  writeFileSync(
    script,
    `import { writeFileSync, existsSync, mkdirSync, appendFileSync } from 'node:fs';
import { SaihmProClient } from ${JSON.stringify(pathToFileURL(resolve('src/client.ts')).href)};
const dir = ${JSON.stringify(dir)};
const signal = (n: string) => writeFileSync(dir + '/' + n, '');
const sleep = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const client = new SaihmProClient('http://127.0.0.1:1/mcp', 'Bearer test', new Uint8Array(32).fill(7), { tier: 'PRO', recallCachePath: dir + '/cache.json' });
const cache = (client as any).recallCache;
${body}
`,
  );
  const p = spawn(process.execPath, [...process.execArgv.filter((a) => !a.startsWith('--test')), script], { env, stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  p.stderr.on('data', (d) => (stderr += d));
  return { exited: new Promise<number | null>((r) => p.on('exit', (code) => r(code))), stderr: () => stderr, pid: p.pid };
}

const waitFor = async (path: string, ms = 20_000) => {
  const end = Date.now() + ms;
  while (!existsSync(path)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${path}`);
    await new Promise((r) => setTimeout(r, 5));
  }
};
const onDisk = (p: string) => Object.keys(JSON.parse(readFileSync(p, 'utf-8'))).sort();

test('a save by another session that holds the lock lands first; the forget then removes the cell from disk', { timeout: 60_000 }, async () => {
  await withStack(async ({ client, dir, cachePath, env }) => {
    // The other session holds the lock, writes its map (which still has x), and keeps the lock a little longer.
    const b = child(dir, env, `cache.withWriteLock(() => { cache.upsert({ cellId: 'z', plaintext: 'from B', seq: '1', commitmentHash: 'ab'.repeat(32) }); signal('B-saved'); sleep(300); });`);
    await waitFor(join(dir, 'B-saved'));
    assert.deepEqual(onDisk(cachePath), ['x', 'y', 'z'], 'the other session wrote x back while holding the lock');
    const started = Date.now();
    const r = await client.forget('x');
    assert.ok(Date.now() - started >= 150, 'the forget waited for the other session to release the lock');
    assert.equal(await b.exited, 0, b.stderr());
    assert.equal(r.localCacheResidual, undefined);
    assert.equal(onDisk(cachePath).includes('x'), false, 'the forgotten plaintext is not on disk');
  });
});

test('a save by another session after the forget reads the erasure line and drops the cell', { timeout: 60_000 }, async () => {
  await withStack(async ({ client, dir, cachePath, env }) => {
    // The other session loads x now, before the forget, and saves only after it.
    const b = child(dir, env, `signal('B-loaded'); while (!existsSync(dir + '/A-forgot')) sleep(5); cache.upsert({ cellId: 'z', plaintext: 'from B', seq: '1', commitmentHash: 'ab'.repeat(32) }); signal('B-saved');`);
    await waitFor(join(dir, 'B-loaded'));
    const r = await client.forget('x');
    assert.equal(r.localCacheResidual, undefined);
    writeFileSync(join(dir, 'A-forgot'), '');
    await waitFor(join(dir, 'B-saved'));
    assert.equal(await b.exited, 0, b.stderr());
    assert.deepEqual(onDisk(cachePath), ['y', 'z'], 'the other session did not write x back');
  });
});

test('a lock left by a process that has exited is taken over at once', { timeout: 60_000 }, async () => {
  await withStack(async ({ client, dir, cachePath, env }) => {
    const gone = child(dir, env, `signal('up');`);
    await gone.exited;
    writeFileSync(`${cachePath}.lock`, `${gone.pid} ${Date.now()} deadbeef`);
    const started = Date.now();
    const r = await client.forget('x');
    assert.ok(Date.now() - started < 2_000, 'no wait on a dead holder');
    assert.equal(r.localCacheResidual, undefined);
    assert.equal(existsSync(`${cachePath}.lock`), false, 'the lock was released');
    assert.deepEqual(onDisk(cachePath), ['y']);
  });
});

test('an empty lock is treated as being written until it is a second old, then taken over', { timeout: 60_000 }, async () => {
  await withStack(async ({ client, cachePath }) => {
    writeFileSync(`${cachePath}.lock`, '');
    const old = (Date.now() - 5_000) / 1000;
    utimesSync(`${cachePath}.lock`, old, old);
    const r = await client.forget('x');
    assert.equal(r.localCacheResidual, undefined);
    assert.deepEqual(onDisk(cachePath), ['y']);
  });
});

test('a lock held by a live process past the wait: the forget writes the erasure line, reports the plaintext may remain, and the next save drops it', { timeout: 60_000 }, async () => {
  await withStack(async ({ client, dir, cachePath, env }) => {
    const holder = child(dir, env, `writeFileSync(${JSON.stringify(cachePath)} + '.lock', process.pid + ' ' + Date.now() + ' feedface'); signal('held'); sleep(8000);`);
    await waitFor(join(dir, 'held'));
    const started = Date.now();
    const r = await client.forget('x');
    assert.ok(Date.now() - started < 8_000, 'one wait, not one per step');
    assert.match(String(r.localCacheResidual), /recall cache lock could not be taken, so the local plaintext cache was not purged/);
    assert.ok(readFileSync(join(dir, 'feed', 'tenants', client.agentIdHash, 'erasures.ndjson'), 'utf-8').includes('"x"'), 'the erasure line was written');
    await holder.exited;
    // Once the holder is gone, this session's next save drops the erased cell from disk.
    (client as unknown as { recallCache: CacheView }).recallCache.upsert(cell('w', 'later'));
    assert.deepEqual(onDisk(cachePath), ['w', 'y']);
  });
});

test('a save while another session is inside a forget waits for it, and does not put the cell back', { timeout: 60_000 }, async () => {
  await withStack(async ({ client, dir, cachePath, env }) => {
    // The client below loaded x at construction. The other session runs a forget's two steps under the lock and pauses
    // between them; a save from this session must wait for the lock and then read the erasure line.
    const feed = join(dir, 'feed', 'tenants', client.agentIdHash, 'erasures.ndjson');
    const a = child(dir, env, `cache.withWriteLock(() => { mkdirSync(${JSON.stringify(join(dir, 'feed', 'tenants', client.agentIdHash))}, { recursive: true }); appendFileSync(${JSON.stringify(feed)}, JSON.stringify({ v: 1, cellId: 'x' }) + '\\n'); signal('A-inside'); sleep(400); cache.remove('x'); });`);
    await waitFor(join(dir, 'A-inside'));
    const started = Date.now();
    (client as unknown as { recallCache: CacheView }).recallCache.upsert(cell('z', 'from this session'));
    assert.ok(Date.now() - started >= 250, 'the save waited for the other session to release the lock');
    assert.equal(onDisk(cachePath).includes('x'), false, "the save neither ran inside the other session's forget nor wrote x back");
    assert.equal(await a.exited, 0, a.stderr());
    assert.equal(onDisk(cachePath).includes('x'), false);
  });
});
