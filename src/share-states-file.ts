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
import { withFileLock } from './file-lock.js';
import type { FeedStopped, ShareStateEntry, ShareStates, ShareStatus } from './share-events.js';

const HEX64 = /^[0-9a-f]{64}$/;
/** Short: a write runs on the server's event loop, and one that gives up is made again at the next change or minute. */
const LOCK_WAIT_MS = 500;

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
  return withFileLock(`${path}.lock`, LOCK_WAIT_MS, () => {
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

/** Above this the file is not a map this package wrote (4,096 entries are well under it). */
const MAX_SHARE_STATES_BYTES = 8 * 1024 * 1024;
const MAX_READ_ENTRIES = 4_096;
const STATUSES: readonly ShareStatus[] = ['live', 'stale', 'ended', 'erased'];
const STOPPED: readonly FeedStopped[] = ['unsupported', 'tier', 'erased'];
/** The bounds the feed holds every value it writes to, so a map read back carries no value the writer could not have. */
const DIGITS = /^[0-9]{1,20}$/;
const SCOPE = /^(read|readwrite)$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_CELL_ID_BYTES = 4_096;
const matchOrNull = (v: unknown, re: RegExp): v is string | null => v === null || (typeof v === 'string' && re.test(v));
const count = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0;

/** One entry exactly as {@link shareStatesDocument} writes it, field by field and within its bounds; undefined for anything else. */
function entryOf(raw: unknown): ShareStateEntry | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;
  const status = STATUSES.find((x) => x === r.status);
  if (typeof r.sharer !== 'string' || !HEX64.test(r.sharer) || status === undefined) return undefined;
  if (typeof r.cellId !== 'string' || Buffer.byteLength(r.cellId, 'utf8') > MAX_CELL_ID_BYTES) return undefined;
  if (!matchOrNull(r.grant, HEX64) || !matchOrNull(r.scope, SCOPE) || !matchOrNull(r.expiryEpoch, DIGITS)) return undefined;
  if (!matchOrNull(r.seq, DIGITS) || !matchOrNull(r.commitment, HEX64)) return undefined;
  if (typeof r.senderVerified !== 'boolean' || !matchOrNull(r.endedAt, TIME) || !matchOrNull(r.copiesInvalidBefore, TIME)) return undefined;
  if (!(r.endedBy === null || r.endedBy === 'event' || r.endedBy === 'reconciliation')) return undefined;
  return {
    sharer: r.sharer, cellId: r.cellId, status, grant: r.grant, scope: r.scope, expiryEpoch: r.expiryEpoch, seq: r.seq,
    commitment: r.commitment, senderVerified: r.senderVerified, endedAt: r.endedAt, endedBy: r.endedBy, copiesInvalidBefore: r.copiesInvalidBefore,
  };
}

/**
 * The share map another process of this identity wrote: what a process that is not the writer of the tenant directory
 * reports as its own. Undefined when there is no file, or when it says anything this package would not have written.
 */
export function readShareStates(path: string): ShareStates | undefined {
  let doc: unknown;
  try {
    if (statSync(path).size > MAX_SHARE_STATES_BYTES) return undefined;
    doc = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return undefined;
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return undefined;
  const d = doc as Record<string, unknown>;
  if (d.v !== 1 || !matchOrNull(d.since, TIME) || typeof d.complete !== 'boolean' || !matchOrNull(d.asOf, TIME) || !matchOrNull(d.startedAt, TIME)) return undefined;
  const stopped = d.stopped === null ? null : STOPPED.find((x) => x === d.stopped);
  if (stopped === undefined) return undefined;
  const c = d.counts as Record<string, unknown> | null;
  if (!c || typeof c !== 'object' || !count(c.live) || !count(c.stale) || !count(c.ended) || !count(c.erased)) return undefined;
  if (!Array.isArray(d.entries) || d.entries.length > MAX_READ_ENTRIES) return undefined;
  const entries: ShareStateEntry[] = [];
  for (const raw of d.entries) {
    const e = entryOf(raw);
    if (!e) return undefined;
    entries.push(e);
  }
  return {
    since: d.since, complete: d.complete, asOf: d.asOf, stopped, startedAt: d.startedAt,
    counts: { live: c.live, stale: c.stale, ended: c.ended, erased: c.erased }, entries,
  };
}
