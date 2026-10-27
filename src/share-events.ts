/**
 * Share events feed (wire format v1): keeps a map of the shares made to this identity, so a caller learns about new,
 * updated, stale, ended and erased shares without listing them on every recall.
 *
 * The feed is a hint; the listing is authoritative. Every gap and resync, the start, and at least one read a day
 * reconcile against the listing. Nothing here opens content: entries carry public identifiers only, and a sender stays
 * unverified until the cell is read and its signature checked.
 */
import { isoTime } from './change-feed.js';

export interface EventsCapability {
  readonly v: readonly number[];
  readonly path: string;
  readonly operator: string;
  readonly maxWaitMs: number;
  readonly maxEvents: number;
  readonly maxResponseBytes: number;
  readonly retentionS: number;
  readonly maxPollsPerIdentity: number;
  readonly minEmptyPollMs: number;
  readonly maxCellIdBytes: number;
  /** The kinds the operator can send, when it lists them; absent means the v1 share kinds only. */
  readonly kinds?: readonly string[];
}

export interface PollAnswer {
  readonly status: number;
  readonly body: unknown;
  readonly retryAfterS?: number;
}

export interface PollBody {
  readonly v: 1;
  readonly cursor: string | null;
  readonly waitMs: number;
  readonly max: number;
  /** The additional kinds this poll asks for: the own-cell kinds, only from the writer of the tenant directory. */
  readonly kinds?: readonly string[];
}

export interface ListingEntry {
  readonly sharer: string;
  readonly cellId: string;
  readonly scope: string | null;
  readonly expiryEpoch: string | null;
  readonly grant: string | null;
  readonly seq: string | null;
  readonly commitment: string | null;
  readonly stale: boolean | null;
}

/** A listing that can end keys only when `complete`: it vouches for every live key. */
export interface ListingSnapshot {
  readonly complete: boolean;
  readonly entries: readonly ListingEntry[];
}

/** Why a pass over the paged share listing is not complete. */
export type SharesPassEnd =
  /** The endpoint does not offer the paged listing, or a page answer was not a page (paging was switched off). */
  | 'unsupported'
  /** The status that says whether the endpoint pages the listing could not be read: never taken for an offer. */
  | 'unread'
  /** The endpoint refused a cursor again after the pass had started over once. */
  | 'bad_cursor'
  /** A page this client cannot read. */
  | 'malformed'
  /** Keys did not strictly increase across the pass. */
  | 'order'
  /** A `next` named twice. */
  | 'repeated'
  /** More keys than the map holds. */
  | 'entries'
  /** A key the map cannot hold: a sharer that is not 64 lowercase hex, or a cell id over 4,096 bytes. */
  | 'unheld'
  /** More pages than a pass may take. */
  | 'pages'
  /** The pass ran past its time. */
  | 'deadline'
  /** Any other failure: no answer, or a refusal. */
  | 'refused'
  /** The caller stopped it. */
  | 'stopped';

/**
 * A pass over the paged share listing: every page from the first until one names no next page, in key order (sharer,
 * then cell id). Like a one-answer listing, it can end keys only when `complete`; an incomplete pass ends nothing.
 */
export interface SharesPass extends ListingSnapshot {
  /** The pages requested, a pass started over included. */
  readonly pages: number;
  /** When the first page of the pass was requested, on the clock the pass was given: the time the pass is dated by. */
  readonly startedAt: number;
  /** Why the pass is not complete; absent when it is. */
  readonly incomplete?: SharesPassEnd;
}

export interface ShareEventsTransport {
  /**
   * The `events` object from the info route as sent, or null when the route answered without one. The feed validates
   * it. Throws when there is no answer to go by: a network error, or a non-success status other than 404.
   */
  info(signal: AbortSignal): Promise<unknown>;
  /** One poll of the events route at `path`, which the transport resolves against the endpoint's own origin. */
  poll(path: string, body: PollBody, timeoutMs: number, signal: AbortSignal): Promise<PollAnswer>;
  /** The share listing response as sent. The feed bounds and parses it. */
  listing(signal: AbortSignal): Promise<unknown>;
  /**
   * The whole share listing by pages, when the endpoint offers the paged listing; null when it does not, when a page
   * answer shows it no longer does, or when whether it does could not be read: the feed then reads `listing`, as before
   * paging. Optional: without it, the feed always reads `listing`.
   */
  pass?(signal: AbortSignal, bounds: { readonly maxEntries: number; readonly now: () => number }): Promise<SharesPass | null>;
}

export type ShareStatus = 'live' | 'stale' | 'ended' | 'erased';

export interface ShareStateEntry {
  readonly sharer: string;
  readonly cellId: string;
  readonly status: ShareStatus;
  readonly grant: string | null;
  readonly scope: string | null;
  readonly expiryEpoch: string | null;
  readonly seq: string | null;
  readonly commitment: string | null;
  readonly senderVerified: boolean;
  readonly endedAt: string | null;
  readonly endedBy: 'event' | 'reconciliation' | null;
  readonly copiesInvalidBefore: string | null;
}

/** Why the feed stopped polling: the operator offers no feed, the tier has none, or the identity was erased. */
export type FeedStopped = 'unsupported' | 'tier' | 'erased';

export interface ShareStateCounts {
  readonly live: number;
  readonly stale: number;
  readonly ended: number;
  readonly erased: number;
}

export interface ShareStates {
  readonly since: string | null;
  readonly complete: boolean;
  /** When the map was last known current: the latest answered poll or completed reconciliation. Null until the first. */
  readonly asOf: string | null;
  /** Why the feed stopped polling, or null while it follows or is starting. */
  readonly stopped: FeedStopped | null;
  /** When this process started the feed; null before it started. */
  readonly startedAt: string | null;
  readonly counts: ShareStateCounts;
  readonly entries: readonly ShareStateEntry[];
}

export interface PersistedFeed {
  readonly v: 1;
  /** When the state was written. Absent in a state written before 0.11.0, which only costs the age check below. */
  readonly savedAt?: string;
  /** When the map was last reconciled, so a restart does not read as a day since the last one. */
  readonly reconciledAt?: string;
  /** Whether the saved map had already dropped entries at the cap; such a map is not one to resume from. */
  readonly capped?: boolean;
  readonly operator: string | null;
  readonly cursor: string | null;
  readonly since: string | null;
  readonly entries: readonly (ShareStateEntry & { readonly changedAt: string })[];
  readonly seen: readonly [string, number][];
  /**
   * True when every own-cell event before `cursor` has a line in the tenant directory's files, or a gap marker covers
   * it: only then may a writer resume from this cursor without a gap marker. Absent from a state saved by a poll that
   * did not ask for own-cell events.
   */
  readonly ownCells?: boolean;
}

export interface FeedStore {
  load(): PersistedFeed | undefined;
  save(state: PersistedFeed): void;
}

/** The own-cell event kinds a poll can ask for. */
export const OWN_CELL_KINDS: readonly string[] = ['cell-written', 'cell-erased'];

/** One poll answer, as the writer of the own-cell files receives it. */
export interface OwnAnswer {
  /** Every event of the answer, as sent; the writer picks the own-cell kinds and resyncs. */
  readonly events: readonly unknown[];
  /** Whether this process has already applied an event id (its line was written then). */
  readonly seen: (id: string) => boolean;
  /** The answer's cursor. */
  readonly cursor: string;
  /** Whether the answer moved the cursor (a `position` marker is owed). */
  readonly moved: boolean;
  /** The operator reported a gap. */
  readonly gap: boolean;
  /** This writer does not continue from a cursor whose own-cell events are all covered: a gap marker is owed. */
  readonly fresh: boolean;
  /**
   * The cursor this poll presented, or null when it asked from the head. With `fresh`, it names the gap: a cursor
   * presented without coverage moved past own-cell events no line records — minted by polls that did not ask for them
   * (an upgraded device's saved cursor, or this process's own while it polled without them): `kinds-changed`; asking
   * from the head (no state, a state refused, discarded or another operator's): `fresh-start`.
   */
  readonly from: string | null;
  /** This client's clock when the answer arrived. */
  readonly receivedAt: string;
}

/** The writer of a tenant directory's own-cell files and its lease (see change-feed.ts). */
export interface OwnCellWriter {
  /** Become, or stay, the one writer of the directory. */
  lead(): 'held' | 'busy' | 'unavailable';
  /** Whether this process still holds the lease. */
  holds(): boolean;
  /** Write one answer's lines and markers. Nothing of the answer may be applied unless this says `written`. */
  writeAnswer(answer: OwnAnswer): 'written' | 'refused' | 'lost';
  /** Rewrite the share map file, after the answer's lines and markers and before the cursor is persisted. */
  committed(states: ShareStates): void;
  release(): void;
}

export interface ShareEventsFeedOptions {
  readonly transport: ShareEventsTransport;
  /** Where the cursor and the map persist; absent = memory only (a new map and `since` at each start). */
  readonly store?: FeedStore;
  readonly maxEntries?: number;
  readonly now?: () => number;
  readonly random?: () => number;
  readonly sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
  /** The shortest wait after a 429, a 503 or another refusal, whatever the endpoint asks for (default one second). */
  readonly minWaitMs?: number;
  /** Called after any change to the map (for a host that surfaces resource updates). */
  readonly onChange?: () => void;
  /**
   * The writer of the tenant directory's own-cell files. Used only while the operator lists both own-cell kinds: then
   * the process holding the writer's lease polls for them and writes the files, and any other process waits for the
   * lease instead of polling. Without it, or without those kinds, the feed polls exactly as before they existed.
   */
  readonly own?: OwnCellWriter;
}

const DAY_MS = 86_400_000;
const DEFAULT_RETENTION_S = 604_800;
/** Entries the map keeps, and the size of a listing (or a pass) it accepts. */
export const MAX_ENTRIES = 4_096;
/** The largest cell id this client holds, whatever an operator advertises. */
const MAX_CELL_ID_BYTES = 4_096;
/** Event ids remembered for deduplication, oldest dropped first. */
const MAX_SEEN = 65_536;
/** A failed or incomplete reconciliation is retried after this, doubling up to the maximum, plus jitter. */
const RECONCILE_RETRY_MS = 60_000;
const RECONCILE_RETRY_MAX_MS = 3_600_000;
/** Reconciliations are coalesced: after a complete one, the next waits at least this long. */
const RECONCILE_SPACING_MS = 10_000;
/** After a pass of k pages, the next reconciliation waits at least k times this (and at least the spacing above)... */
const RECONCILE_SPACING_PER_PAGE_MS = 2_000;
/** ...and never more than this, whatever the pass's length. */
const RECONCILE_SPACING_MAX_MS = 600_000;
/** The least wait after a reconciliation of `pages` pages (1 for a one-answer listing): 10 s, or 2 s a page, at most 10 min. */
const reconcileSpacing = (pages: number): number =>
  Math.min(RECONCILE_SPACING_MAX_MS, Math.max(RECONCILE_SPACING_MS, RECONCILE_SPACING_PER_PAGE_MS * pages));
/** An info request that got no answer is retried after this, doubling up to the maximum, with jitter. */
/**
 * How long the client waits out a held-back poll while a catch-up is owed, before asking for the listing instead.
 * An operator holds a poll back by its minimum interval between polls of one identity, most often right after a
 * quick restart. Waiting it out would make a restored position SLOWER than the cold start it replaced, and would
 * leave a map that owes a catch-up owing it for the whole interval. The listing is the cold path's own cost, so
 * falling back to it is never worse than not having the position at all.
 */
const HELD_POLL_BUDGET_MS = 1_000;
/**
 * The least time between two saves of the state. Every answer moves the cursor, so without this a busy feed would
 * rewrite the whole state on each one. What a save skips is never lost: the events after the saved position arrive
 * again and the ids already seen discard them.
 */
const PERSIST_MIN_INTERVAL_MS = 1_000;
const INFO_RETRY_MS = 5_000;
const INFO_RETRY_MAX_MS = 900_000;
/** How often a process that is not the writer tries for the lease (the holder's lease goes stale at 30 s). */
const LEASE_RETRY_MS = 10_000;
/** A process that just became the writer reads the info document again when what it holds is older than this. */
const LEAD_INFO_MAX_AGE_MS = 60_000;
/** How long a status's word that the own-cell kinds are offered holds, when the offer read here disagrees with it. */
const STATUS_OFFER_MS = 600_000;
/** A refused write is retried after this, doubling up to the maximum. */
const WRITE_RETRY_MS = 1_000;
const WRITE_RETRY_MAX_MS = 60_000;

type Mutable<T> = { -readonly [K in keyof T]: T[K] };
type Entry = Mutable<ShareStateEntry> & { changedAt: string };

const keyOf = (sharer: string, cellId: string): string => JSON.stringify([sharer, cellId]);
const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const DIGITS = /^[0-9]{1,20}$/;
const SCOPE = /^(read|readwrite)$/;
/** An absolute path on the endpoint's own origin: non-empty segments, no scheme, host or backslash. */
const EVENTS_PATH = /^(\/[A-Za-z0-9._~-]+){1,16}$/;

const intIn = (v: unknown, lo: number, hi: number, def: number): number =>
  typeof v === 'number' && Number.isInteger(v) ? Math.min(hi, Math.max(lo, v)) : def;
const matching = (v: unknown, re: RegExp): string | null => (typeof v === 'string' && re.test(v) ? v : null);

/** The capability as this client uses it, every limit bounded; null when it is not a v1 feed this client can poll. */
export function capabilityFrom(raw: unknown): EventsCapability | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (!Array.isArray(r.v) || !r.v.includes(1)) return null;
  if (typeof r.path !== 'string' || r.path.length > 256 || !EVENTS_PATH.test(r.path)) return null;
  if (typeof r.operator !== 'string' || !HEX32.test(r.operator)) return null;
  // Names only, bounded: the list says what may be asked for, and a kind this client does not know is never asked for.
  const kinds = Array.isArray(r.kinds)
    ? r.kinds.slice(0, 64).filter((k): k is string => typeof k === 'string' && k.length <= 64)
    : undefined;
  return withOperator(r, r.path, r.operator, kinds);
}

function withOperator(
  r: Record<string, unknown> | EventsCapability, path: string, operator: string, kinds: readonly string[] | undefined,
): EventsCapability {
  return {
    v: [1], path, operator,
    maxWaitMs: intIn(r.maxWaitMs, 0, 25_000, 25_000),
    maxEvents: intIn(r.maxEvents, 1, 256, 256),
    maxResponseBytes: intIn(r.maxResponseBytes, 65_536, 1_048_576, 262_144),
    retentionS: intIn(r.retentionS, 3_600, 7_776_000, DEFAULT_RETENTION_S),
    maxPollsPerIdentity: intIn(r.maxPollsPerIdentity, 1, 64, 4),
    minEmptyPollMs: intIn(r.minEmptyPollMs, 0, 60_000, 5_000),
    maxCellIdBytes: intIn(r.maxCellIdBytes, 1, MAX_CELL_ID_BYTES, 256),
    ...(kinds !== undefined ? { kinds } : {}),
  };
}

/** Whether the operator lists BOTH own-cell kinds: one without the other would leave changes it cannot report. */
export function offersOwnCells(caps: EventsCapability): boolean {
  return caps.kinds !== undefined && OWN_CELL_KINDS.every((k) => caps.kinds!.includes(k));
}

/**
 * The share listing in a recall response, bounded. It is complete only when it vouches for every live key: the response
 * carries `liveSharedKeys`, every key there has its entry, and nothing was left out for size. Own cells in the response
 * are skipped, never opened. Null when the response has neither shape.
 */
export function listingFrom(resp: unknown, maxEntries: number): ListingSnapshot | null {
  let rows: unknown[];
  let liveKeys: unknown[] | undefined;
  if (Array.isArray(resp)) {
    rows = resp;
  } else if (resp && typeof resp === 'object' && Array.isArray((resp as { added?: unknown }).added)) {
    rows = (resp as { added: unknown[] }).added;
    const lk = (resp as { liveSharedKeys?: unknown }).liveSharedKeys;
    liveKeys = Array.isArray(lk) ? lk : undefined;
  } else {
    return null;
  }
  let complete = liveKeys !== undefined;
  const entries: ListingEntry[] = [];
  const keys = new Set<string>();
  for (const raw of rows) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const r = raw as Record<string, unknown>;
    if (r.shared !== true || r.wire !== undefined) continue;
    // A key this client cannot hold is not refused: the listing just cannot vouch for it.
    const entry = listingEntryFrom(r);
    if (entry === null) {
      complete = false;
      continue;
    }
    const k = keyOf(entry.sharer, entry.cellId);
    if (keys.has(k)) continue;
    if (entries.length >= maxEntries) { complete = false; break; }
    keys.add(k);
    entries.push(entry);
  }
  if (complete && liveKeys) {
    for (const lk of liveKeys) {
      // `<sharer>:<cellId>`, split at the first colon: a cell id may itself contain colons.
      const i = typeof lk === 'string' ? lk.indexOf(':') : -1;
      if (i < 0 || !keys.has(keyOf((lk as string).slice(0, i), (lk as string).slice(i + 1)))) { complete = false; break; }
    }
  }
  return { complete, entries };
}

/**
 * One share row of a listing or of a page, as the map holds it; null when the map cannot hold its key (a sharer that is
 * not 64 lowercase hex, or a cell id over 4,096 UTF-8 bytes), which the listing or pass then cannot vouch for. The one
 * reader of a row for both, so the two cannot come to hold keys differently.
 */
export function listingEntryFrom(r: { readonly [K in keyof ListingEntry]?: unknown }): ListingEntry | null {
  if (typeof r.sharer !== 'string' || !HEX64.test(r.sharer) || typeof r.cellId !== 'string' || Buffer.byteLength(r.cellId, 'utf8') > MAX_CELL_ID_BYTES) {
    return null;
  }
  return {
    sharer: r.sharer, cellId: r.cellId, scope: matching(r.scope, SCOPE), expiryEpoch: matching(r.expiryEpoch, DIGITS),
    grant: matching(r.grant, HEX64), seq: matching(r.seq, DIGITS), commitment: matching(r.commitment, HEX64),
    stale: typeof r.stale === 'boolean' ? r.stale : null,
  };
}

/** Priority when the map is capped (lower keeps first): erased or copies to delete, then ended, stale, live. */
function capClass(e: Entry): number {
  if (e.status === 'erased' || e.copiesInvalidBefore !== null) return 0;
  if (e.status === 'ended') return 1;
  if (e.status === 'stale') return 2;
  return 3;
}

const STATUSES: readonly ShareStatus[] = ['live', 'stale', 'ended', 'erased'];
const strOrNull = (v: unknown): string | null => (typeof v === 'string' ? v : null);

/** A persisted entry, field by field; undefined when it does not have the shape of one. */
function entryFrom(raw: unknown): Entry | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const r = raw as Record<string, unknown>;
  if (typeof r.sharer !== 'string' || !HEX64.test(r.sharer) || typeof r.cellId !== 'string' || typeof r.changedAt !== 'string') return undefined;
  const status = STATUSES.find((x) => x === r.status);
  if (!status) return undefined;
  return {
    sharer: r.sharer, cellId: r.cellId, status, grant: strOrNull(r.grant), scope: strOrNull(r.scope), expiryEpoch: strOrNull(r.expiryEpoch),
    seq: strOrNull(r.seq), commitment: strOrNull(r.commitment), senderVerified: r.senderVerified === true, endedAt: strOrNull(r.endedAt),
    endedBy: r.endedBy === 'event' || r.endedBy === 'reconciliation' ? r.endedBy : null, copiesInvalidBefore: strOrNull(r.copiesInvalidBefore),
    changedAt: r.changedAt,
  };
}

/** The entry a consumer sees: named fields only. */
function publicEntry(e: Entry): ShareStateEntry {
  return {
    sharer: e.sharer, cellId: e.cellId, status: e.status, grant: e.grant, scope: e.scope, expiryEpoch: e.expiryEpoch, seq: e.seq,
    commitment: e.commitment, senderVerified: e.senderVerified, endedAt: e.endedAt, endedBy: e.endedBy, copiesInvalidBefore: e.copiesInvalidBefore,
  };
}

/** Waits `ms`, or less when `signal` aborts. The timer does not hold the process open, and no listener outlives the wait. */
function defaultSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise<void>((resolve) => {
    if (signal.aborted) { resolve(); return; }
    const done = (): void => { clearTimeout(timer); signal.removeEventListener('abort', done); resolve(); };
    const timer = setTimeout(done, ms);
    timer.unref?.();
    signal.addEventListener('abort', done, { once: true });
  });
}

export class ShareEventsFeed {
  private readonly transport: ShareEventsTransport;
  private readonly store: FeedStore | undefined;
  private readonly maxEntries: number;
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly sleep: (ms: number, signal: AbortSignal) => Promise<void>;
  private readonly minWaitMs: number;
  private readonly onChange: (() => void) | undefined;
  private readonly own: OwnCellWriter | undefined;

  private caps: EventsCapability | null = null;
  private operator: string | null = null;
  private cursor: string | null = null;
  private since: string | null = null;
  private capped = false;
  private pendingReconcile = true;
  private lastReconcile = -Infinity;
  private nextReconcileAt = 0;
  private reconcileRetryMs = RECONCILE_RETRY_MS;
  private readonly entries = new Map<string, Entry>();
  private readonly seen = new Map<string, number>();
  private abort: AbortController | undefined;
  private running: Promise<void> | undefined;
  private asOf: string | null = null;
  private startedAt: string | null = null;
  /** A restored map this process has not confirmed yet: usable to answer from, not yet a complete map. */
  private warm = false;
  private restoredAt: number | null = null;
  private lastPersistAt = -Infinity;
  private headerKey = '';
  /** When the capability was last read from the info document. */
  private capsAt = -Infinity;
  /** Every own-cell event before `cursor` has a line, or a gap marker covers it (see `PersistedFeed.ownCells`). */
  private ownCovered = false;
  /** This process holds the writer's lease: it polls for the own-cell kinds and writes the tenant directory's files. */
  private leading = false;
  /**
   * Another process holds the lease, or this one gave it up while it does not poll: it neither polls nor writes, and
   * tries for the lease from time to time.
   */
  private waiting = false;
  /** The operator offered both own-cell kinds when the offer was last read: the share map is then the writer's alone. */
  private ownOffered = false;
  /** Until when the last status's word that this identity may use both own-cell kinds holds (see noteStatusOffer). */
  private statusOwnUntil = -Infinity;
  /**
   * This process gave the lease up when it stopped. A host can stop the feed twice (stdin's `end`, then `close`); a
   * second stop must not save again, because the position is no longer this process's: another process may already
   * have taken the lease and saved a later one.
   */
  private gaveUpLead = false;
  /** Why the loop stopped, when it did: `unsupported`, `tier`, `erased`. */
  stopped: FeedStopped | null = null;

  constructor(opts: ShareEventsFeedOptions) {
    this.transport = opts.transport;
    this.store = opts.store;
    this.maxEntries = opts.maxEntries ?? MAX_ENTRIES;
    this.now = opts.now ?? Date.now;
    this.random = opts.random ?? Math.random;
    this.sleep = opts.sleep ?? defaultSleep;
    this.minWaitMs = opts.minWaitMs ?? 1_000;
    this.onChange = opts.onChange;
    this.own = opts.own;
    this.restore(this.store?.load());
  }

  /** Take up a persisted state: the one this process starts from, or the one a previous writer left. */
  private restore(saved: PersistedFeed | undefined): void {
    if (saved && saved.v === 1) {
      this.operator = saved.operator;
      this.cursor = saved.cursor;
      this.since = saved.since;
      // Fields are named one by one: a state file is input like any other, and an extra field must not reach a caller.
      for (const e of saved.entries) {
        const entry = entryFrom(e);
        if (entry) this.entries.set(keyOf(entry.sharer, entry.cellId), entry);
      }
      for (const [id, at] of saved.seen) this.rememberId(id, at);
      // A cursor saved by a poll that did not ask for own-cell events has moved past events no line records.
      this.ownCovered = saved.ownCells === true && saved.cursor !== null;
      // A restored cursor is a position in this operator's log, so the listing can wait for the first answer instead
      // of being fetched again. The map is NOT complete until that answer comes: a previous process's map must not
      // read as one this process confirmed.
      // A map that had already dropped entries at the cap is not one to resume from: it is incomplete in a way no
      // catch-up repairs, so it reconciles like a cold start and keeps its entries meanwhile.
      this.capped = saved.capped === true;
      if (this.since !== null && this.cursor !== null && !this.capped) {
        this.pendingReconcile = false;
        this.warm = true;
        const t = typeof saved.savedAt === 'string' ? Date.parse(saved.savedAt) : NaN;
        this.restoredAt = Number.isNaN(t) ? null : t;
        // Without this the daily reconciliation is due at once — `lastReconcile` starts at minus infinity — and the
        // restored cursor buys nothing. A state that does not say when it reconciled (one written before 0.11.0)
        // therefore still reconciles, which is the safe way round.
        const r = typeof saved.reconciledAt === 'string' ? Date.parse(saved.reconciledAt) : NaN;
        if (!Number.isNaN(r)) this.lastReconcile = r;
      }
    }
  }

  /**
   * This process just became the writer: it continues from what the previous writer persisted, not from its own
   * position, which stopped moving when it began to wait. Without a state to continue from it starts cold, and its
   * first answer is preceded by a fresh-start gap marker.
   */
  private reloadForLead(): void {
    this.ownCovered = false;
    if (!this.store) return;
    this.entries.clear();
    this.seen.clear();
    this.operator = null;
    this.cursor = null;
    this.since = null;
    this.capped = false;
    this.pendingReconcile = true;
    this.warm = false;
    this.restoredAt = null;
    this.lastReconcile = -Infinity;
    this.asOf = null;
    this.restore(this.store.load());
    this.changed();
  }

  /** The map as a consumer reads it. */
  snapshot(): ShareStates {
    this.expireTombstones();
    const entries: ShareStateEntry[] = [];
    let live = 0, stale = 0, ended = 0, erased = 0;
    this.entries.forEach((e) => {
      entries.push(publicEntry(e));
      if (e.status === 'live') live++;
      else if (e.status === 'stale') stale++;
      else if (e.status === 'ended') ended++;
      else erased++;
    });
    return {
      since: this.since, complete: this.isComplete(), asOf: this.asOf, stopped: this.stopped, startedAt: this.startedAt,
      counts: { live, stale, ended, erased }, entries,
    };
  }

  private isComplete(): boolean {
    return !this.capped && !this.pendingReconcile && !this.warm && this.since !== null;
  }

  /** The client read the cell and checked the sharer's signatures with the key its pinned agent ID binds. */
  markSenderVerified(sharer: string, cellId: string): void {
    const e = this.entries.get(keyOf(sharer, cellId));
    if (e && !e.senderVerified) { e.senderVerified = true; this.changed(); }
  }

  /** A live share could not be opened with the key it carries: it is stale until the next update names it. */
  markOpenFailed(sharer: string, cellId: string): void {
    const e = this.entries.get(keyOf(sharer, cellId));
    if (e && e.status === 'live') { e.status = 'stale'; e.changedAt = new Date(this.now()).toISOString(); this.changed(); }
  }

  start(): void {
    if (this.running) return;
    this.gaveUpLead = false;
    if (this.startedAt === null) this.startedAt = new Date(this.now()).toISOString();
    this.abort = new AbortController();
    this.running = this.loop(this.abort.signal).catch(() => undefined).finally(() => { this.running = undefined; });
  }

  /**
   * Ends the loop, including a poll in flight. `final` runs before the writer's lease is given up, so a last write of
   * the share map is still the writer's.
   */
  async stop(final?: () => void): Promise<void> {
    this.abort?.abort();
    await this.running;
    // The last position, whatever the interval above would have said: this is the save a restart reads.
    this.persist(true);
    final?.();
    if (this.leading) { this.leading = false; this.gaveUpLead = true; this.own?.release(); }
  }

  /**
   * `solo`: the feed polls as before own-cell events existed (one of possibly several processes doing so). `writer`:
   * this process holds the lease and writes the tenant directory's files. `waiting`: another process does; this one
   * reads the share map from the file.
   */
  get role(): 'solo' | 'writer' | 'waiting' {
    return this.waiting ? 'waiting' : this.leading ? 'writer' : 'solo';
  }

  /**
   * Whether this process may write the share map file. While the operator offers the own-cell kinds, the file is the
   * heartbeat of the own-cell files as well (its `asOf` says nothing changed that no line records), so only the holder
   * of the writer's lease writes it — not a process waiting for the lease, and not one that cannot follow own cells at
   * all (its erasure feed off, or a directory it cannot write): its polls carry share events only, and a fresh `asOf`
   * from it would vouch for own-cell files nobody is writing. Without those kinds every process writes it, as before.
   */
  mayWriteMap(): boolean {
    if (this.leading) return this.own!.holds();
    return !this.ownOffered && !this.statusOwn();
  }

  /** Whether a status within the last STATUS_OFFER_MS offered both own-cell kinds: a status's word is fresh, not lasting. */
  private statusOwn(): boolean {
    return this.now() < this.statusOwnUntil;
  }

  /**
   * Stop being the writer, where this process is it, so another process may lead while this one does not poll. First,
   * as at a stop, while the lease is still held: the position a successor resumes from, then the map, which is how a
   * reader learns why following stopped (`stopped`, and `complete` false); once the lease is given up no process writes
   * the map while the offer last read names the own-cell kinds. From then on the position and the map are the next
   * writer's: this process saves neither, as one waiting for the lease does, until it leads again.
   */
  private giveUpLead(): void {
    if (!this.leading) return;
    this.persist(true);
    if (this.own!.holds()) this.own!.committed(this.snapshot());
    this.leading = false;
    this.waiting = true;
    this.own!.release();
  }

  /**
   * What the identity's status says it may use (`features.events.kinds`), as it says it. This feed reads the server's
   * offer only at start and daily, so when the status offers both own-cell kinds and the offer last read does not (the
   * operator has just turned them on, or the offer was read stale), the offer is read again at once — and every minute
   * while the two disagree — and meanwhile only the writer of the own-cell files writes the share map: a reader that
   * decides from the status must not take a share-only poller's fresh asOf for own-cell files nobody writes yet.
   */
  noteStatusOffer(kinds: readonly unknown[] | undefined): void {
    const offered = kinds !== undefined && OWN_CELL_KINDS.every((k) => kinds.includes(k));
    // Its word holds for STATUS_OFFER_MS: an operator that withdraws the kinds later is then followed by the offer alone.
    this.statusOwnUntil = offered ? this.now() + STATUS_OFFER_MS : -Infinity;
    if (offered && this.own !== undefined && this.caps !== null && !offersOwnCells(this.caps)) this.caps = null;
  }

  // ── the loop ──

  private async loop(signal: AbortSignal): Promise<void> {
    let networkBackoff = 1_000;
    let authBackoff = 1_000;
    let infoBackoff = INFO_RETRY_MS;
    let writeBackoff = WRITE_RETRY_MS;
    while (!signal.aborted) {
      this.noteHeader();
      if (!this.caps) {
        let raw: unknown;
        try {
          raw = await this.transport.info(signal);
        } catch {
          // No answer to go by (network, or an operator not answering yet): try again soon, not in a day.
          if (signal.aborted) break;
          await this.sleep(infoBackoff / 2 + Math.floor(this.random() * (infoBackoff / 2)), signal);
          infoBackoff = Math.min(INFO_RETRY_MAX_MS, infoBackoff * 2);
          continue;
        }
        if (signal.aborted) break;
        infoBackoff = INFO_RETRY_MS;
        this.caps = capabilityFrom(raw);
        this.capsAt = this.now();
        if (!this.caps) {
          // An answer that offers no feed: the map is not followed until a later reconciliation completes.
          this.stopped = 'unsupported';
          this.pendingReconcile = true;
          this.noteHeader();
          // A day without polling is no day to hold the writer's lease: another process may find a feed sooner.
          this.giveUpLead();
          await this.sleep(DAY_MS, signal);
          continue;
        }
        this.stopped = null;
        this.adoptCaps(this.caps);
        this.noteHeader();   // before the first poll, which can wait the whole long poll
      }
      const caps = this.caps;
      // Own-cell events: asked for only while the operator offers both kinds, and only by the writer of the tenant
      // directory. Anything else polls exactly as before those kinds existed.
      let own = this.own !== undefined && offersOwnCells(caps);
      if (own) {
        const lead = this.own!.lead();
        if (lead === 'busy') {
          // Another process writes this directory and polls for it: this one does neither until the lease is free.
          this.leading = false;
          this.waiting = true;
          await this.sleep(LEASE_RETRY_MS + Math.floor(this.random() * LEASE_RETRY_MS), signal);
          if (this.now() - this.capsAt >= DAY_MS) this.caps = null;
          continue;
        }
        if (lead === 'unavailable') {
          own = false;   // no process can write this directory's files: poll as before
        } else if (!this.leading) {
          this.leading = true;
          this.waiting = false;
          this.reloadForLead();
          // What this process read may predate the writer it replaces by a day: read the offer again first.
          if (this.now() - this.capsAt > LEAD_INFO_MAX_AGE_MS) { this.caps = null; continue; }
          this.adoptCaps(caps);
        }
      }
      if (!own) {
        if (this.leading) { this.leading = false; this.own!.release(); }
        this.waiting = false;
      }
      // A warm process asks for what it missed and gets it at once; only a confirmed map waits on a long poll.
      const waitMs = this.cursor === null || this.warm ? 0 : caps.maxWaitMs;
      const pollBody: PollBody = own
        ? { v: 1, cursor: this.cursor, waitMs, max: caps.maxEvents, kinds: OWN_CELL_KINDS }
        : { v: 1, cursor: this.cursor, waitMs, max: caps.maxEvents };
      let answer: PollAnswer;
      try {
        answer = await this.transport.poll(caps.path, pollBody, waitMs + 10_000, signal);
        networkBackoff = 1_000;
      } catch {
        if (signal.aborted) break;
        await this.sleep(Math.floor(this.random() * networkBackoff), signal);
        networkBackoff = Math.min(60_000, networkBackoff * 2);
        continue;
      }
      if (signal.aborted) break;
      const body = (answer.body && typeof answer.body === 'object' ? answer.body : {}) as Record<string, unknown>;
      const retryAfterMs = typeof body.retryAfterMs === 'number' && Number.isFinite(body.retryAfterMs) && body.retryAfterMs > 0
        ? Math.min(body.retryAfterMs, DAY_MS) : undefined;
      if (answer.status === 200) {
        // A cursor is sent back in a body the operator caps at 1 KiB; one that could not fit is not a cursor.
        if (typeof body.cursor !== 'string' || body.cursor.length > 512) { await this.sleep(10_000, signal); continue; }
        if (typeof body.operator === 'string' && body.operator !== caps.operator) {
          // The operator's event data changed under this URL. Its answer says so; the info route may still be cached.
          if (!HEX32.test(body.operator)) { await this.sleep(10_000, signal); continue; }
          this.caps = withOperator(caps, caps.path, body.operator, caps.kinds);
          this.restartFor(body.operator);
          continue;
        }
        // An answer that names no events array cannot say what it moved past: with own-cell kinds asked for it is asked
        // for again rather than applied, as one without a cursor is; a share-only poll reconciles the map instead.
        if (own && !Array.isArray(body.events)) { await this.sleep(10_000, signal); continue; }
        const events = Array.isArray(body.events) ? body.events : [];
        if (own) {
          // Lines and markers first: nothing of an answer is applied, and no cursor moves, before they are written.
          const written = this.own!.writeAnswer({
            events, seen: (id) => this.seen.has(id), cursor: body.cursor, moved: body.cursor !== pollBody.cursor,
            gap: body.gap === true, fresh: !this.ownCovered, from: pollBody.cursor,
            receivedAt: new Date(this.now()).toISOString(),
          });
          if (written === 'lost') { this.leading = false; this.own!.release(); continue; }
          if (written === 'refused') {
            // Not even a gap marker could be written: ask for the same position again once one can be.
            await this.sleep(writeBackoff, signal);
            writeBackoff = Math.min(WRITE_RETRY_MAX_MS, writeBackoff * 2);
            continue;
          }
          writeBackoff = WRITE_RETRY_MS;
          this.ownCovered = true;
        } else {
          this.ownCovered = false;
        }
        this.apply(events, own);
        this.cursor = body.cursor;
        this.asOf = new Date(this.now()).toISOString();
        this.warm = false;
        if (body.gap === true) this.pendingReconcile = true;
        const due = this.pendingReconcile || this.now() - this.lastReconcile >= DAY_MS;
        if (due && this.now() >= this.nextReconcileAt) await this.reconcile(signal);
        // The share map after the lines and markers, the cursor last: its `asOf` moves with every answer, and a restart
        // never resumes from a cursor ahead of what the files cover.
        if (own && this.own!.holds()) this.own!.committed(this.snapshot());
        this.persist();
        // The info document, at least daily, whatever is followed: an operator that starts or stops offering the
        // own-cell kinds is seen within a day, by a process polling for share events alone too; and every minute while
        // the identity's status offers own-cell kinds the offer read here does not (see noteStatusOffer).
        const disagrees = this.statusOwn() && this.own !== undefined && !offersOwnCells(caps);
        if (this.now() - this.capsAt >= (disagrees ? LEAD_INFO_MAX_AGE_MS : DAY_MS)) this.caps = null;
        // A wait named in a 200 answer gets the same floor as one named in a refusal.
        if (retryAfterMs !== undefined) await this.sleep(Math.max(this.minWaitMs, retryAfterMs), signal);
        continue;
      }
      if (answer.status === 400 && body.error === 'bad_cursor') { this.cursor = null; this.ownCovered = false; this.pendingReconcile = true; continue; }
      if (answer.status === 402) {
        this.stopped = 'tier'; this.caps = null; this.pendingReconcile = true; this.noteHeader();
        this.giveUpLead();
        await this.sleep(DAY_MS, signal);
        continue;
      }
      if (answer.status === 410) { this.stopped = 'erased'; this.pendingReconcile = true; break; }
      if (answer.status === 401) {
        // The transport renews the token; a token that keeps failing backs off to a minute.
        await this.sleep(authBackoff + Math.floor(this.random() * authBackoff), signal);
        authBackoff = Math.min(60_000, authBackoff * 2);
        continue;
      }
      authBackoff = 1_000;
      // 429, 503 and anything else: wait what the operator asked for (or 10 s), plus jitter up to the same amount.
      // Never less than `minWaitMs`: a wait of zero, in the body or in `retry-after`, polled as fast as answers came back.
      const base = Math.max(
        this.minWaitMs,
        retryAfterMs ?? (answer.retryAfterS !== undefined ? Math.min(answer.retryAfterS * 1000, DAY_MS) : 10_000),
      );
      // The spacing is the same one the answered path respects, so a client that keeps being held back does not ask
      // for the listing every time.
      if ((this.warm || this.pendingReconcile) && base > HELD_POLL_BUDGET_MS && this.now() >= this.nextReconcileAt) {
        // `pendingReconcile` first: a listing that does not arrive must leave the map incomplete, not complete by
        // the mere fact that the warm flag was dropped.
        this.warm = false;
        this.pendingReconcile = true;
        await this.reconcile(signal);
        this.noteHeader();
        if (signal.aborted) break;
      }
      await this.sleep(base + Math.floor(this.random() * base), signal);
      // The operator stopped offering the feed: discover again, so a feed that was switched off is not polled forever.
      if (answer.status === 503 && body.error === 'events_unavailable') this.caps = null;
    }
    this.noteHeader();
  }

  /** Tells the host when `since`, `complete` or `stopped` changed, as it is told of map changes. */
  private noteHeader(): void {
    const key = `${this.since}|${this.isComplete()}|${this.stopped}`;
    if (key === this.headerKey) return;
    this.headerKey = key;
    this.changed();
  }

  /** Another operator's events for this URL: its cursor means nothing here, so start over and reconcile. */
  private restartFor(operator: string): void {
    this.operator = operator;
    this.cursor = null;
    this.ownCovered = false;
    this.warm = false;
    this.pendingReconcile = true;
  }

  /**
   * What follows a read of the offer: whether it offers own cells (which decides who writes the share map), and that
   * another operator's position is no position here, nor is one past retention.
   */
  private adoptCaps(caps: EventsCapability): void {
    this.ownOffered = offersOwnCells(caps);
    if (this.operator !== caps.operator) this.restartFor(caps.operator);
    // A restore older than the operator keeps events for holds a cursor it will certainly refuse. One rejected
    // poll per restart is nothing here and a great deal in aggregate, so reconcile without asking.
    if (this.warm && this.restoredAt !== null && this.now() - this.restoredAt > caps.retentionS * 1000) {
      this.cursor = null;
      this.ownCovered = false;
      this.warm = false;
      this.pendingReconcile = true;
    }
    this.restoredAt = null;
  }

  // ── events ──

  private rememberId(id: string, at: number): void {
    this.seen.set(id, at);
    if (this.seen.size > MAX_SEEN) {
      const oldest = this.seen.keys().next();
      if (!oldest.done) this.seen.delete(oldest.value);
    }
  }

  private apply(events: readonly unknown[], own = false): void {
    const window = (this.caps?.retentionS ?? DEFAULT_RETENTION_S) * 1000;
    let changed = false;
    for (const raw of events) {
      if (!raw || typeof raw !== 'object') continue;
      const ev = raw as Record<string, unknown>;
      const id = matching(ev.id, HEX64);
      if (id === null || this.seen.has(id)) continue;
      this.rememberId(id, this.now());
      if (ev.shrunk === true) continue;
      // Asked for by this poll and already written to the own-cell files: they name no sharer and change no share.
      if (own && (ev.kind === 'cell-written' || ev.kind === 'cell-erased')) continue;
      // In the one form the map holds (and a map read back is checked against): a time it cannot be is this client's.
      const at = isoTime(ev.at) ?? new Date(this.now()).toISOString();
      if (ev.kind === 'resync') {
        // An own-cell resync is the writer's gap marker; the share map lost nothing.
        if (!(own && ev.own === true)) this.pendingReconcile = true;
        continue;
      }
      const sharer = matching(ev.sharer, HEX64);
      // Every field is bounded here, whatever the endpoint sends: a cell id within the operator's advertised bound
      // (never more than 4,096 bytes), digit strings, a hex commitment and a known scope.
      const maxId = this.caps?.maxCellIdBytes ?? MAX_CELL_ID_BYTES;
      const cellId = typeof ev.cellId === 'string' && Buffer.byteLength(ev.cellId, 'utf8') <= maxId ? ev.cellId : null;
      const grant = matching(ev.grant, HEX64);
      if (sharer === null || cellId === null) { this.pendingReconcile = true; continue; }
      const k = keyOf(sharer, cellId);
      const cur = this.entries.get(k);
      switch (ev.kind) {
        case 'share-created':
          this.entries.set(k, {
            sharer, cellId, status: 'live', grant, scope: matching(ev.scope, SCOPE), expiryEpoch: matching(ev.expiryEpoch, DIGITS), seq: null,
            commitment: null, senderVerified: false, endedAt: null, endedBy: null, copiesInvalidBefore: cur?.copiesInvalidBefore ?? null, changedAt: at,
          });
          changed = true;
          break;
        case 'share-stale':
        case 'shared-cell-updated':
          if (!cur || (cur.grant !== null && grant !== null && cur.grant !== grant) || cur.status === 'ended' || cur.status === 'erased') {
            this.pendingReconcile = true;
            break;
          }
          cur.status = ev.kind === 'share-stale' ? 'stale' : 'live';
          {
            // The pair moves together or not at all: a new sequence stated under the old commitment would read as a
            // version a consumer could compare, and it is not one. Both are required on these kinds (format §4), so
            // a conforming operator never takes this branch; when one does, the write is not lost, it is reconciled.
            const seq = matching(ev.seq, DIGITS);
            const commitment = matching(ev.commitment, HEX64);
            if (seq !== null && commitment !== null) { cur.seq = seq; cur.commitment = commitment; }
            else this.pendingReconcile = true;
          }
          if (cur.grant === null) cur.grant = grant;
          cur.changedAt = at;
          changed = true;
          break;
        case 'share-revoked':
        case 'share-expired':
          if (!cur || cur.grant === null || cur.grant !== grant) { this.pendingReconcile = true; break; }
          cur.status = 'ended';
          cur.endedAt = at;
          cur.endedBy = 'event';
          if (ev.kind === 'share-expired') cur.expiryEpoch = matching(ev.expiryEpoch, DIGITS) ?? cur.expiryEpoch;
          cur.changedAt = at;
          changed = true;
          break;
        case 'shared-cell-erased': {
          const e: Entry = cur ?? {
            sharer, cellId, status: 'erased', grant, scope: null, expiryEpoch: null, seq: null, commitment: null,
            senderVerified: false, endedAt: null, endedBy: null, copiesInvalidBefore: null, changedAt: at,
          };
          e.status = 'erased';
          e.endedAt = at;
          e.endedBy = 'event';
          e.copiesInvalidBefore = at;
          e.changedAt = at;
          this.entries.set(k, e);
          changed = true;
          break;
        }
        default:
          break;   // an unknown kind is ignored; the cursor still advances
      }
    }
    // Ids are remembered in arrival order, so the ones past the window are at the front.
    for (const [id, t] of this.seen) {
      if (this.now() - t <= window) break;
      this.seen.delete(id);
    }
    if (changed) { this.enforceCap(); this.changed(); }
  }

  // ── reconciliation ──

  private async reconcile(signal: AbortSignal): Promise<void> {
    // The whole list by pages where the endpoint offers paging. Where it does not, or a page answer shows it no longer
    // does, the one-answer listing, exactly as before paging. Either goes through the entry logic below.
    let pass: SharesPass | null = null;
    if (this.transport.pass) {
      try { pass = await this.transport.pass(signal, { maxEntries: this.maxEntries, now: this.now }); } catch { pass = null; }
    }
    let listing: ListingSnapshot | null = pass;
    if (pass === null) {
      try { listing = listingFrom(await this.transport.listing(signal), this.maxEntries); } catch { listing = null; }
    }
    const now = this.now();
    // A pass is dated when its first page was requested, not when it ends; a one-answer listing when it answered.
    const dated = pass !== null ? pass.startedAt : now;
    const pages = pass !== null ? pass.pages : 1;
    if (!listing) { this.retryReconcileLater(now, pages); return; }   // stays incomplete
    const nowIso = new Date(dated).toISOString();
    const live = new Set<string>();
    for (const l of listing.entries) {
      const k = keyOf(l.sharer, l.cellId);
      live.add(k);
      const cur = this.entries.get(k);
      const grantChanged = cur !== undefined && l.grant !== null && cur.grant !== null && cur.grant !== l.grant;
      const status: ShareStatus = l.stale === true ? 'stale' : 'live';
      if (!cur || cur.status === 'ended' || cur.status === 'erased' || grantChanged) {
        this.entries.set(k, {
          sharer: l.sharer, cellId: l.cellId, status, grant: l.grant, scope: l.scope, expiryEpoch: l.expiryEpoch, seq: l.seq,
          commitment: l.commitment, senderVerified: false, endedAt: null, endedBy: null,
          // Another grant went live in between, and what happened to the cell meanwhile is unknown: earlier copies are invalid.
          copiesInvalidBefore: grantChanged ? nowIso : cur?.copiesInvalidBefore ?? null, changedAt: nowIso,
        });
      } else {
        cur.scope = l.scope;
        cur.expiryEpoch = l.expiryEpoch;
        if (l.grant !== null) cur.grant = l.grant;
        if (l.seq !== null) cur.seq = l.seq;
        if (l.commitment !== null) cur.commitment = l.commitment;
        if (l.stale !== null) cur.status = status;
      }
    }
    if (listing.complete) {
      // A reconciliation cannot tell an erasure from a revocation: the key ended, and copies made before now are invalid.
      for (const [k, e] of this.entries) {
        if (live.has(k) || e.status === 'ended' || e.status === 'erased') continue;
        e.status = 'ended';
        e.endedAt = nowIso;
        e.endedBy = 'reconciliation';
        e.copiesInvalidBefore = nowIso;
        e.changedAt = nowIso;
      }
      this.pendingReconcile = false;
      if (this.since === null) this.since = nowIso;
      // A completed listing proves the SHARE map current, and in share-only polling that is all the heartbeat vouches
      // for. The writer of the own-cell files is different: its `asOf` also says no own-cell change is missing from
      // those files, which only a poll answer naming the own-cell kinds can say. A listing run while the events route
      // holds the writer back (a 429 or 503 at a restart or takeover) must not make the files read live meanwhile.
      if (!this.leading) this.asOf = nowIso;
      this.reconcileRetryMs = RECONCILE_RETRY_MS;
      // Spaced by the pass's length: a sharer cycling revoke and re-share sends end events that each ask for one more.
      this.nextReconcileAt = now + reconcileSpacing(pages);
    } else {
      this.retryReconcileLater(now, pages);
    }
    this.lastReconcile = dated;
    this.enforceCap();
    this.changed();
  }

  /** An incomplete reconciliation: tried again after the backoff, and never sooner than a pass of its length is spaced. */
  private retryReconcileLater(now: number, pages: number): void {
    this.nextReconcileAt = now + Math.max(reconcileSpacing(pages), this.reconcileRetryMs + Math.floor(this.random() * this.reconcileRetryMs));
    this.reconcileRetryMs = Math.min(RECONCILE_RETRY_MAX_MS, this.reconcileRetryMs * 2);
  }

  private expireTombstones(): void {
    const window = (this.caps?.retentionS ?? DEFAULT_RETENTION_S) * 1000;
    for (const [k, e] of this.entries) {
      if ((e.status === 'ended' || e.status === 'erased') && this.now() - Date.parse(e.changedAt) > window) this.entries.delete(k);
    }
  }

  private enforceCap(): void {
    this.expireTombstones();
    if (this.entries.size <= this.maxEntries) { this.capped = false; return; }
    const ordered = [...this.entries.entries()].sort((a, b) => capClass(a[1]) - capClass(b[1]) || Date.parse(b[1].changedAt) - Date.parse(a[1].changedAt));
    for (const [k] of ordered.slice(this.maxEntries)) this.entries.delete(k);
    this.capped = true;
  }

  private persist(force = false): void {
    if (!this.store) return;
    // The cursor is the writer's: a process waiting for the lease, one that has just lost it, or one that gave it up
    // when it stopped, never moves it.
    if (this.waiting || this.gaveUpLead || (this.leading && !this.own!.holds())) return;
    const now = this.now();
    if (!force && now - this.lastPersistAt < PERSIST_MIN_INTERVAL_MS) return;
    this.lastPersistAt = now;
    this.store.save({
      v: 1, savedAt: new Date(now).toISOString(), capped: this.capped,
      ...(Number.isFinite(this.lastReconcile) ? { reconciledAt: new Date(this.lastReconcile).toISOString() } : {}),
      operator: this.operator, cursor: this.cursor, since: this.since,
      entries: [...this.entries.values()], seen: [...this.seen.entries()],
      ...(this.leading && this.ownCovered ? { ownCells: true } : {}),
    });
  }

  private changed(): void { this.onChange?.(); }
}
