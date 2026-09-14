/**
 * The share map for other processes (SHARE_EVENTS_FORMAT_2026-09-14 §12): `<root>/tenants/<agentIdHash>/share-states.json`,
 * beside the erasure feed and under the same root. Written, never loaded: each process keeps its own cursor and map in
 * memory, and the file says only what its writer last knew. A missing file asserts nothing.
 *
 * Several processes of one identity can run the feed. The file is replaced under a lock, and only by a map whose `asOf`
 * is not older than the file's, so a process that has not had an answer yet never overwrites one that has.
 */
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join as pathJoin } from 'node:path';
import { ErasureFeedError, SHARE_STATES_FILENAME, resolveFeedRoot, tenantDirIsOurs } from './erasure-feed.js';
import type { ShareStates } from './share-events.js';

const HEX64 = /^[0-9a-f]{64}$/;
/** Short: a write runs on the server's event loop, and one that gives up is made again at the next change or minute. */
const LOCK_WAIT_MS = 500;
const LOCK_STALE_MS = 30_000;
const LOCK_MALFORMED_GRACE_MS = 1_000;
const WAIT_CELL = new Int32Array(new SharedArrayBuffer(4));

/** `<root>/tenants/<agentIdHash>/share-states.json`, with the erasure feed's root. Throws on a relative root or a bad id. */
export function shareStatesPath(agentIdHashHex: string, env: NodeJS.ProcessEnv = process.env): string {
  const id = agentIdHashHex.toLowerCase();
  if (!HEX64.test(id)) throw new ErasureFeedError('agentIdHash must be 64 lowercase hex characters');
  return pathJoin(resolveFeedRoot(env), 'tenants', id, SHARE_STATES_FILENAME);
}

/** The file's content, keys in a fixed order. */
export function shareStatesDocument(s: ShareStates): string {
  return JSON.stringify({
    v: 1, since: s.since, complete: s.complete, asOf: s.asOf, stopped: s.stopped, startedAt: s.startedAt, counts: s.counts, entries: s.entries,
  });
}

/**
 * Replace the file with `s`, unless the file holds a map with a later `asOf` (or any `asOf` while `s` has none).
 * Throws when the tenant directory belongs to another store, or the lock stays held by a live process.
 */
export function writeShareStates(path: string, s: ShareStates): 'written' | 'kept' {
  const dir = dirname(path);
  let entries: string[] | undefined;
  try { entries = readdirSync(dir); } catch { entries = undefined; }
  if (entries !== undefined && !tenantDirIsOurs(entries)) {
    throw new ErasureFeedError(`the tenant directory ${JSON.stringify(dir)} holds another store's files; the share map is not written there`);
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return withLock(`${path}.lock`, () => {
    if (!replaces(s.asOf, fileAsOf(path))) return 'kept';
    const tmp = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
    writeFileSync(tmp, shareStatesDocument(s), { mode: 0o600, flag: 'wx' });
    try {
      renameSync(tmp, path);
    } catch (e) {
      try { unlinkSync(tmp); } catch { /* already gone */ }
      throw e;
    }
    return 'written';
  });
}

/** The `asOf` in the file as milliseconds: undefined when there is no readable file, null when it has no `asOf`. */
function fileAsOf(path: string): number | null | undefined {
  let doc: unknown;
  try { doc = JSON.parse(readFileSync(path, 'utf8')); } catch { return undefined; }
  const asOf = doc && typeof doc === 'object' ? (doc as { asOf?: unknown }).asOf : undefined;
  if (typeof asOf !== 'string') return null;
  const t = Date.parse(asOf);
  return Number.isNaN(t) ? null : t;
}

function replaces(asOf: string | null, current: number | null | undefined): boolean {
  if (current === undefined || current === null) return true;
  return asOf !== null && Date.parse(asOf) >= current;
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** The recall cache's lock, for one file: created with `wx`, taken over when its holder is gone or it is stale. */
function withLock<T>(lock: string, fn: () => T): T {
  const token = `${process.pid} ${Date.now()} ${randomBytes(8).toString('hex')}`;
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      writeFileSync(lock, token, { mode: 0o600, flag: 'wx' });
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    }
    let holder: string;
    let age: number;
    try {
      holder = readFileSync(lock, 'utf8');
      age = Date.now() - statSync(lock).mtimeMs;
    } catch {
      continue;   // released between the create and the read
    }
    const pid = Number(holder.split(' ')[0]);
    const wellFormed = Number.isInteger(pid) && pid > 0;
    if (age > LOCK_STALE_MS || (wellFormed ? !processAlive(pid) : age > LOCK_MALFORMED_GRACE_MS)) {
      try { if (readFileSync(lock, 'utf8') === holder) unlinkSync(lock); } catch { /* its owner or another waiter got there first */ }
      continue;
    }
    if (Date.now() > deadline) throw new Error(`the share map is locked by process ${wellFormed ? pid : 'unknown'}`);
    Atomics.wait(WAIT_CELL, 0, 0, 5);
  }
  try {
    return fn();
  } finally {
    try { if (readFileSync(lock, 'utf8') === token) unlinkSync(lock); } catch { /* already gone */ }
  }
}
