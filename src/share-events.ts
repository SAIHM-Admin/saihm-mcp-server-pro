/**
 * Share events feed (wire format v1): keeps a map of the shares made to this identity, so a caller learns about new,
 * updated, stale, ended and erased shares without listing them on every recall.
 *
 * The feed is a hint; the listing is authoritative. Every gap and resync, the start, and at least one read a day
 * reconcile against the listing. Nothing here opens content: entries carry public identifiers only, and a sender stays
 * unverified until the cell is read and its signature checked.
 */

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
  readonly operator: string | null;
  readonly cursor: string | null;
  readonly since: string | null;
  readonly entries: readonly (ShareStateEntry & { readonly changedAt: string })[];
  readonly seen: readonly [string, number][];
}

export interface FeedStore {
  load(): PersistedFeed | undefined;
  save(state: PersistedFeed): void;
}

export interface ShareEventsFeedOptions {
  readonly transport: ShareEventsTransport;
  /** Where the cursor and the map persist; absent = memory only (a new map and `since` at each start). */
  readonly store?: FeedStore;
  readonly maxEntries?: number;
  readonly now?: () => number;
  readonly random?: () => number;
  readonly sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
  /** Called after any change to the map (for a host that surfaces resource updates). */
  readonly onChange?: () => void;
}

const DAY_MS = 86_400_000;
const DEFAULT_RETENTION_S = 604_800;
/** Entries the map keeps, and the size of a listing it accepts. */
const MAX_ENTRIES = 4_096;
/** The largest cell id this client holds, whatever an operator advertises. */
const MAX_CELL_ID_BYTES = 4_096;
/** Event ids remembered for deduplication, oldest dropped first. */
const MAX_SEEN = 65_536;
/** A failed or incomplete reconciliation is retried after this, doubling up to the maximum, plus jitter. */
const RECONCILE_RETRY_MS = 60_000;
const RECONCILE_RETRY_MAX_MS = 3_600_000;
/** Reconciliations are coalesced: after a complete one, the next waits at least this long. */
const RECONCILE_SPACING_MS = 10_000;
/** An info request that got no answer is retried after this, doubling up to the maximum, with jitter. */
const INFO_RETRY_MS = 5_000;
const INFO_RETRY_MAX_MS = 900_000;

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
  return withOperator(r, r.path, r.operator);
}

function withOperator(r: Record<string, unknown> | EventsCapability, path: string, operator: string): EventsCapability {
  return {
    v: [1], path, operator,
    maxWaitMs: intIn(r.maxWaitMs, 0, 25_000, 25_000),
    maxEvents: intIn(r.maxEvents, 1, 256, 256),
    maxResponseBytes: intIn(r.maxResponseBytes, 65_536, 1_048_576, 262_144),
    retentionS: intIn(r.retentionS, 3_600, 7_776_000, DEFAULT_RETENTION_S),
    maxPollsPerIdentity: intIn(r.maxPollsPerIdentity, 1, 64, 4),
    minEmptyPollMs: intIn(r.minEmptyPollMs, 0, 60_000, 5_000),
    maxCellIdBytes: intIn(r.maxCellIdBytes, 1, MAX_CELL_ID_BYTES, 256),
  };
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
    if (typeof r.sharer !== 'string' || !HEX64.test(r.sharer) || typeof r.cellId !== 'string' || Buffer.byteLength(r.cellId, 'utf8') > MAX_CELL_ID_BYTES) {
      complete = false;
      continue;
    }
    const k = keyOf(r.sharer, r.cellId);
    if (keys.has(k)) continue;
    if (entries.length >= maxEntries) { complete = false; break; }
    keys.add(k);
    entries.push({
      sharer: r.sharer, cellId: r.cellId, scope: matching(r.scope, SCOPE), expiryEpoch: matching(r.expiryEpoch, DIGITS),
      grant: matching(r.grant, HEX64), seq: matching(r.seq, DIGITS), commitment: matching(r.commitment, HEX64),
      stale: typeof r.stale === 'boolean' ? r.stale : null,
    });
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
  private readonly onChange: (() => void) | undefined;

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
  private headerKey = '';
  /** Why the loop stopped, when it did: `unsupported`, `tier`, `erased`. */
  stopped: FeedStopped | null = null;

  constructor(opts: ShareEventsFeedOptions) {
    this.transport = opts.transport;
    this.store = opts.store;
    this.maxEntries = opts.maxEntries ?? MAX_ENTRIES;
    this.now = opts.now ?? Date.now;
    this.random = opts.random ?? Math.random;
    this.sleep = opts.sleep ?? defaultSleep;
    this.onChange = opts.onChange;
    const saved = this.store?.load();
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
    }
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
    return !this.capped && !this.pendingReconcile && this.since !== null;
  }

  /** The client read the cell and checked the sharer's signature against a pinned record. */
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
    if (this.startedAt === null) this.startedAt = new Date(this.now()).toISOString();
    this.abort = new AbortController();
    this.running = this.loop(this.abort.signal).catch(() => undefined).finally(() => { this.running = undefined; });
  }

  /** Ends the loop, including a poll in flight. */
  async stop(): Promise<void> {
    this.abort?.abort();
    await this.running;
  }

  // ── the loop ──

  private async loop(signal: AbortSignal): Promise<void> {
    let networkBackoff = 1_000;
    let authBackoff = 1_000;
    let infoBackoff = INFO_RETRY_MS;
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
        if (!this.caps) {
          // An answer that offers no feed: the map is not followed until a later reconciliation completes.
          this.stopped = 'unsupported';
          this.pendingReconcile = true;
          this.noteHeader();
          await this.sleep(DAY_MS, signal);
          continue;
        }
        this.stopped = null;
        if (this.operator !== this.caps.operator) this.restartFor(this.caps.operator);
        this.noteHeader();   // before the first poll, which can wait the whole long poll
      }
      const caps = this.caps;
      const waitMs = this.cursor === null ? 0 : caps.maxWaitMs;
      let answer: PollAnswer;
      try {
        answer = await this.transport.poll(caps.path, { v: 1, cursor: this.cursor, waitMs, max: caps.maxEvents }, waitMs + 10_000, signal);
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
          this.caps = withOperator(caps, caps.path, body.operator);
          this.restartFor(body.operator);
          continue;
        }
        this.apply(Array.isArray(body.events) ? body.events : []);
        this.cursor = body.cursor;
        this.asOf = new Date(this.now()).toISOString();
        if (body.gap === true) this.pendingReconcile = true;
        const due = this.pendingReconcile || this.now() - this.lastReconcile >= DAY_MS;
        if (due && this.now() >= this.nextReconcileAt) await this.reconcile(signal);
        this.persist();
        if (retryAfterMs !== undefined) await this.sleep(retryAfterMs, signal);
        continue;
      }
      if (answer.status === 400 && body.error === 'bad_cursor') { this.cursor = null; this.pendingReconcile = true; continue; }
      if (answer.status === 402) {
        this.stopped = 'tier'; this.caps = null; this.pendingReconcile = true; this.noteHeader();
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
      const base = retryAfterMs ?? (answer.retryAfterS !== undefined ? Math.min(answer.retryAfterS * 1000, DAY_MS) : 10_000);
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
    this.pendingReconcile = true;
  }

  // ── events ──

  private rememberId(id: string, at: number): void {
    this.seen.set(id, at);
    if (this.seen.size > MAX_SEEN) {
      const oldest = this.seen.keys().next();
      if (!oldest.done) this.seen.delete(oldest.value);
    }
  }

  private apply(events: readonly unknown[]): void {
    const window = (this.caps?.retentionS ?? DEFAULT_RETENTION_S) * 1000;
    let changed = false;
    for (const raw of events) {
      if (!raw || typeof raw !== 'object') continue;
      const ev = raw as Record<string, unknown>;
      const id = matching(ev.id, HEX64);
      if (id === null || this.seen.has(id)) continue;
      this.rememberId(id, this.now());
      if (ev.shrunk === true) continue;
      const at = typeof ev.at === 'string' && !Number.isNaN(Date.parse(ev.at)) ? new Date(Date.parse(ev.at)).toISOString() : new Date(this.now()).toISOString();
      if (ev.kind === 'resync') { this.pendingReconcile = true; continue; }
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
          cur.seq = matching(ev.seq, DIGITS);
          cur.commitment = matching(ev.commitment, HEX64);
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
    let listing: ListingSnapshot | null;
    try { listing = listingFrom(await this.transport.listing(signal), this.maxEntries); } catch { listing = null; }
    const now = this.now();
    if (!listing) { this.retryReconcileLater(now); return; }   // stays incomplete
    const nowIso = new Date(now).toISOString();
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
      this.asOf = nowIso;
      this.reconcileRetryMs = RECONCILE_RETRY_MS;
      this.nextReconcileAt = now + RECONCILE_SPACING_MS;
    } else {
      this.retryReconcileLater(now);
    }
    this.lastReconcile = now;
    this.enforceCap();
    this.changed();
  }

  private retryReconcileLater(now: number): void {
    this.nextReconcileAt = now + this.reconcileRetryMs + Math.floor(this.random() * this.reconcileRetryMs);
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

  private persist(): void {
    if (!this.store) return;
    this.store.save({
      v: 1, operator: this.operator, cursor: this.cursor, since: this.since,
      entries: [...this.entries.values()], seen: [...this.seen.entries()],
    });
  }

  private changed(): void { this.onChange?.(); }
}
