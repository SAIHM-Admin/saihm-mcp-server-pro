/**
 * Where a share feed's position and map survive a restart: `<root>/tenants/<agentIdHash>/feed-state.json`, beside
 * the erasure feed and the share map, under the same root and the same discipline (0600 in 0700, a temporary file
 * renamed over it under a lock).
 *
 * This file is READ, which `share-states.json` is not: it holds the cursor, so a process that starts again asks the
 * operator for what it missed instead of for the whole listing. What it cannot do is make the restored map
 * complete — only an answer in THIS process does that (see `ShareEventsFeed`).
 *
 * Nothing here trusts the file. A state that is missing, unreadable, too large or malformed simply yields
 * `undefined`, and the feed takes the cold path it would have taken anyway.
 */
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join as pathJoin } from 'node:path';
import { ErasureFeedError, FEED_STATE_FILENAME, resolveFeedRoot, tenantDirIsOurs } from './erasure-feed.js';
import { withFileLock } from './file-lock.js';
import type { FeedStore, PersistedFeed, ShareStateEntry } from './share-events.js';

const HEX64 = /^[0-9a-f]{64}$/;
/** Short, like the share map's: a save runs on the server's event loop and the next answer saves again. */
const LOCK_WAIT_MS = 500;
/**
 * Ceilings for what a state file may restore, matching the feed's own: it caps its map and its seen ids as it runs,
 * and a file is input like any other, so a doctored one must not make this process hold more than the feed would.
 */
const MAX_RESTORED_ENTRIES = 4_096;
const MAX_RESTORED_SEEN = 4_096;
/** Above this the file is not a state this package wrote; reading it is refused rather than paid for. */
const MAX_STATE_BYTES = 8 * 1024 * 1024;

/** `<root>/tenants/<agentIdHash>/feed-state.json`. Throws on a relative root or a bad id, as the feed's path does. */
export function feedStatePath(agentIdHashHex: string, env: NodeJS.ProcessEnv = process.env): string {
  const id = agentIdHashHex.toLowerCase();
  if (!HEX64.test(id)) throw new ErasureFeedError('agentIdHash must be 64 lowercase hex characters');
  return pathJoin(resolveFeedRoot(env), 'tenants', id, FEED_STATE_FILENAME);
}

function stringOrNull(v: unknown): string | null | undefined {
  return v === null || typeof v === 'string' ? (v as string | null) : undefined;
}

/** The parsed state, or undefined when the file says anything this package would not have written. */
export function readFeedState(path: string): PersistedFeed | undefined {
  let raw: string;
  try {
    if (statSync(path).size > MAX_STATE_BYTES) return undefined;
    raw = readFileSync(path, 'utf8');
  } catch { return undefined; }
  let doc: unknown;
  try { doc = JSON.parse(raw); } catch { return undefined; }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return undefined;
  const d = doc as Record<string, unknown>;
  if (d.v !== 1) return undefined;
  const operator = stringOrNull(d.operator);
  const cursor = stringOrNull(d.cursor);
  const since = stringOrNull(d.since);
  if (operator === undefined || cursor === undefined || since === undefined) return undefined;
  if (!Array.isArray(d.entries) || !Array.isArray(d.seen)) return undefined;
  const entries = d.entries.slice(0, MAX_RESTORED_ENTRIES).filter((e) => !!e && typeof e === 'object' && !Array.isArray(e));
  const seen: [string, number][] = [];
  for (const pair of d.seen.slice(0, MAX_RESTORED_SEEN)) {
    if (!Array.isArray(pair) || pair.length !== 2) continue;
    const [id, at] = pair as [unknown, unknown];
    if (typeof id === 'string' && typeof at === 'number' && Number.isFinite(at)) seen.push([id, at]);
  }
  // Entries are checked field by field by the feed itself, which drops any it cannot read. Everything above only
  // bounds what reaches it.
  return {
    v: 1, ...(typeof d.savedAt === 'string' ? { savedAt: d.savedAt } : {}),
    ...(typeof d.reconciledAt === 'string' ? { reconciledAt: d.reconciledAt } : {}),
    ...(typeof d.capped === 'boolean' ? { capped: d.capped } : {}),
    operator, cursor, since,
    entries: entries as unknown as readonly (ShareStateEntry & { readonly changedAt: string })[],
    seen,
  };
}

/** Replace the state file. Throws when the tenant directory belongs to another store, or the lock stays held. */
export function writeFeedState(path: string, state: PersistedFeed): void {
  const dir = dirname(path);
  let entries: string[] | undefined;
  try { entries = readdirSync(dir); } catch { entries = undefined; }
  if (entries !== undefined && !tenantDirIsOurs(entries)) {
    throw new ErasureFeedError(`the tenant directory ${JSON.stringify(dir)} holds another store's files; the feed state is not written there`);
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  withFileLock(`${path}.lock`, LOCK_WAIT_MS, () => {
    const tmp = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
    writeFileSync(tmp, JSON.stringify(state), { mode: 0o600, flag: 'wx' });
    try {
      renameSync(tmp, path);
    } catch (e) {
      try { unlinkSync(tmp); } catch { /* already gone */ }
      throw e;
    }
  });
}

/**
 * The feed's store over one file. Both halves are forgiving on purpose: a load that fails costs a reconciliation,
 * and a save that fails costs the next restart a reconciliation. Neither is worth an exception into the feed loop.
 */
export class FileFeedStore implements FeedStore {
  constructor(private readonly path: string) {}

  load(): PersistedFeed | undefined {
    return readFeedState(this.path);
  }

  save(state: PersistedFeed): void {
    try { writeFeedState(this.path, state); } catch { /* a lost lock, a full disk, or a directory that is not ours */ }
  }
}
