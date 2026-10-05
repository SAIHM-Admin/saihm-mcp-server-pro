/**
 * The writer of a tenant directory's event files, when the endpoint offers events for this identity's OWN cells:
 *
 * - `changes.ndjson`: a `cell-written` line for each new version of an own cell, written by any process or device of
 *   this identity (this one included), and `position` and `gap` markers;
 * - `erasures.ndjson`: a `server-event` line for each erasure the feed reports, except one this process recorded itself
 *   under the same destruction anchor, carrying the event's `reason` beside `complete: false` as a forget's line does;
 * - their predecessors, `changes.ndjson.1` and `erasures.ndjson.1`, after a rotation;
 * - `feed.lock`, the lease that makes ONE process the writer of the directory.
 *
 * ORDER, per poll answer: every line the answer produces, in both files, then its `position` marker. A `gap` marker the
 * answer needs is written first, carrying the answer's cursor. The share map file and the persisted cursor come after
 * this, in that order, so a marker covers every line above it and a crash can repeat lines but never lose them.
 *
 * FAIL CLOSED: an event that cannot be written as a line is covered by a `gap` marker, and when not even a marker can
 * be appended the whole answer is refused, so the caller moves nothing (cursor, map, seen ids) and asks again.
 *
 * DISCIPLINE, as for the erasure feed: one JSON object per line, at most 1 KiB, each line one append, never rewritten
 * or truncated in place; a file that grows past {@link ROTATE_BYTES} moves to its one predecessor name.
 */
import { existsSync, mkdirSync, readdirSync, renameSync, statSync } from 'node:fs';
import { dirname, join as pathJoin } from 'node:path';
import {
  CHANGES_FILENAME, FEED_LOCK_FILENAME, FEED_VERSION, MAX_FEED_CELL_ID_CHARS, MAX_FEED_LINE_BYTES, PREDECESSOR_SUFFIX,
  appendFeedLines, buildFeedLine, feedPathFor, resolveFeedRoot, tenantDirIsOurs,
} from './erasure-feed.js';
import { FileLease } from './file-lock.js';
import type { OwnAnswer, OwnCellWriter, ShareStates } from './share-events.js';
import { shareStatesPath, writeShareStates } from './share-states-file.js';

/** Why a `gap` marker was written. For diagnosis only: a consumer treats every gap the same way. */
export type GapReason = 'rotation' | 'unwritable-event' | 'fresh-start' | 'server-gap' | 'kinds-changed';

/** A line file larger than this moves to its predecessor name before the next answer is written. */
export const ROTATE_BYTES = 4 * 1024 * 1024;
/** How often the holder touches its lease; a lease untouched for 30 s is taken over. */
export const LEASE_REFRESH_MS = 10_000;
/** Erasures this process recorded itself, remembered so the feed's report of them is not written twice. */
const MAX_OWN_ERASURES = 4_096;
const DEFAULT_OWN_ERASURE_MS = 604_800_000;

const HEX64 = /^[0-9a-f]{64}$/;
const DIGITS = /^[0-9]{1,20}$/;
/** The agreed shape of a destruction anchor: stored verbatim, never interpreted. */
export const DESTRUCTION_ANCHOR = /^[A-Za-z0-9._:-]{1,256}$/;
/** ISO-8601 with an explicit zone; a time without one would be read in this machine's zone. */
const ISO_ZONED = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?(?:Z|[+-](\d{2}):(\d{2}))$/;

/**
 * An endpoint's time in the one form every line uses (UTC, milliseconds, `Z`), or null when it is not a zoned time.
 * EVERY FIELD IN ITS RANGE, the day within its month: `Date.parse` rolls `2026-02-30` over into March and `T24:00` into
 * the next day, which would put a plausible time where the endpoint sent one that cannot exist.
 */
export function isoTime(v: unknown): string | null {
  if (typeof v !== 'string' || v.length > 40) return null;
  const m = ISO_ZONED.exec(v);
  if (m === null) return null;
  const [y, mo, d, h, mi, s, oh, om] = m.slice(1).map((x) => (x === undefined ? 0 : Number(x))) as number[];
  if (mo! < 1 || mo! > 12 || d! < 1 || d! > new Date(Date.UTC(y!, mo!, 0)).getUTCDate()) return null;
  if (h! > 23 || mi! > 59 || s! > 59 || oh! > 23 || om! > 59) return null;
  const t = Date.parse(v);
  if (!Number.isFinite(t)) return null;
  // An offset can carry a time past the four-digit years the line form holds: `9999-12-31T23:59-23:59` is year 10000.
  const year = new Date(t).getUTCFullYear();
  return year >= 1 && year <= 9999 ? new Date(t).toISOString() : null;
}

/** An own cell id that fits a line: 1 to 64 characters, as on the erasure feed. Longer ids are a gap, never a cut. */
const lineCellId = (v: unknown): string | null =>
  typeof v === 'string' && v.length > 0 && v.length <= MAX_FEED_CELL_ID_CHARS ? v : null;

export interface ChangeFeedWriterOptions {
  readonly agentIdHash: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly rotateBytes?: number;
  readonly now?: () => number;
  /** How long an erasure this process recorded is remembered, to skip the feed's report of it (the event window). */
  readonly ownErasureMs?: number;
  /** For tests: the append every line goes through. */
  readonly append?: (path: string, lines: readonly string[]) => void;
}

export class ChangeFeedWriter implements OwnCellWriter {
  readonly dir: string;
  readonly changesPath: string;
  readonly erasuresPath: string;
  readonly shareStatesPath: string;
  private readonly lease: FileLease;
  private readonly agentIdHash: string;
  private readonly rotateBytes: number;
  private readonly now: () => number;
  private readonly ownErasureMs: number;
  private readonly append: (path: string, lines: readonly string[]) => void;
  /** Moves of `changes.ndjson` whose `gap` marker is not in the fresh file yet: owed until an append succeeds. */
  private owedRotations = 0;
  /** A `rotation` marker for `erasures.ndjson` is in, but its move failed: the next try moves under that marker. */
  private erasuresMarked = false;
  private readonly ownErasures = new Map<string, { anchor: string; until: number }>();
  private refreshTimer: ReturnType<typeof setInterval> | undefined;

  /** Throws when the feed root cannot be resolved or the id is not one: the caller then runs without these files. */
  constructor(opts: ChangeFeedWriterOptions) {
    const root = resolveFeedRoot(opts.env);
    this.agentIdHash = opts.agentIdHash.toLowerCase();
    this.erasuresPath = feedPathFor(root, this.agentIdHash);
    this.dir = dirname(this.erasuresPath);
    this.changesPath = pathJoin(this.dir, CHANGES_FILENAME);
    this.shareStatesPath = shareStatesPath(this.agentIdHash, opts.env);
    // A holder refreshes the lease every LEASE_REFRESH_MS: one untouched for TWO of those, and whose process is gone, is
    // gone (one period would catch a live holder between two touches; the 30 s staleness rule still applies to all).
    this.lease = new FileLease(pathJoin(this.dir, FEED_LOCK_FILENAME), 2 * LEASE_REFRESH_MS);
    this.rotateBytes = opts.rotateBytes ?? ROTATE_BYTES;
    this.now = opts.now ?? Date.now;
    this.ownErasureMs = opts.ownErasureMs ?? DEFAULT_OWN_ERASURE_MS;
    this.append = opts.append ?? appendFeedLines;
  }

  /**
   * Become, or stay, the one writer of the directory. `busy`: another live process writes it. `unavailable`: the
   * directory holds another store's files, or the lease cannot be created at all, so no process here can write it.
   */
  lead(): 'held' | 'busy' | 'unavailable' {
    let entries: string[] | undefined;
    try { entries = readdirSync(this.dir); } catch { entries = undefined; }
    if (entries !== undefined && !tenantDirIsOurs(entries)) return 'unavailable';
    try { mkdirSync(this.dir, { recursive: true, mode: 0o700 }); } catch { return 'unavailable'; }
    const was = this.lease.held;
    const r = this.lease.acquire();
    if (r === 'held' && !was) {
      this.startRefresh();
      // BECOMING the writer, not merely staying it: the one moment to pick up, from the disk, a rotation a crashed
      // writer moved but never marked. A marker this process wrote before it last lost the lease vouches for nothing now.
      this.owedRotations = this.crashedRotation();
      this.erasuresMarked = false;
    }
    if (r !== 'held') this.stopRefresh();
    return r;
  }

  /**
   * 1 when a writer stopped between moving `changes.ndjson` to its predecessor and writing the marker that opens the
   * fresh file, else 0. Only then is the file ABSENT or EMPTY while its predecessor EXISTS: only the writer creates
   * `changes.ndjson`, the first line it writes after a move is always that marker, and a marker append that fails is
   * taken back to the size before it — nothing, in a file that append itself created. (`erasures.ndjson` needs no such
   * check, and could not have one: every process of the identity appends to it, so its absence proves nothing; its
   * marker is written BEFORE it moves.) Read when this process becomes the writer, from the disk, so a rotation this or
   * an earlier writer already marked is never counted again.
   */
  private crashedRotation(): number {
    if (!existsSync(`${this.changesPath}${PREDECESSOR_SUFFIX}`)) return 0;
    try {
      return statSync(this.changesPath).size === 0 ? 1 : 0;
    } catch {
      return 1; // absent
    }
  }

  holds(): boolean {
    return this.lease.holds();
  }

  release(): void {
    this.stopRefresh();
    this.lease.release();
  }

  /**
   * An erasure this process made and recorded on its own line. The feed's report of it is recognised by its destruction
   * anchor ALONE — one anchor names one erasure — and is then not written again. An erasure without an anchor cannot be
   * recognised: a cell id is no name for one erasure (the id may be written again and erased elsewhere, and a report
   * may even arrive before this receipt), so its report is written too, a second line every reader applies twice
   * safely. Call only after the own line was written: a failed own line must leave the feed's report to record it.
   */
  noteOwnErasure(cellId: string, anchor: string | null): void {
    this.ownErasures.delete(cellId);
    if (anchor === null) return;
    this.ownErasures.set(cellId, { anchor, until: this.now() + this.ownErasureMs });
    while (this.ownErasures.size > MAX_OWN_ERASURES) {
      const oldest = this.ownErasures.keys().next();
      if (oldest.done) break;
      this.ownErasures.delete(oldest.value);
    }
  }

  /** The share map file: rewritten after each answer's lines and markers, and before the cursor is persisted. */
  committed(states: ShareStates): void {
    try { writeShareStates(this.shareStatesPath, states); } catch { /* its `asOf` stays behind, which says the feed is not proven live */ }
  }

  /**
   * Write one answer. `written`: every event has a line or a `gap` marker covers it, and the `position` marker is in
   * when the cursor moved. `refused`: not even a marker could be appended; nothing may move. `lost`: another process
   * holds the lease now, and this answer is not this process's to write.
   */
  writeAnswer(a: OwnAnswer): 'written' | 'refused' | 'lost' {
    if (!this.lease.holds()) return 'lost';
    const nowMs = this.now();
    const nowIso = new Date(nowMs).toISOString();
    // Why the answer opens with a gap, when it does. A writer owing coverage names how (see `OwnAnswer.from`): the
    // cursor it presented moved past own-cell events no line records, or it asked from the head.
    let reason: GapReason | null = a.fresh ? (a.from !== null ? 'kinds-changed' : 'fresh-start') : a.gap ? 'server-gap' : null;
    const changes: string[] = [];
    const erasures: string[] = [];
    const echoes: string[] = [];
    const ids = new Set<string>();
    for (const raw of a.events) {
      // An entry that is not even an event may have been one of this identity's: covered by a gap, never dropped.
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) { reason ??= 'unwritable-event'; continue; }
      const ev = raw as Record<string, unknown>;
      const id = typeof ev.id === 'string' && HEX64.test(ev.id) ? ev.id : null;
      if (ev.kind === 'resync') {
        // Own-cell events were lost (`own: true`), or events of every kind were (no sharer named): reconcile. Never
        // dropped for a missing id: the share path skips id-less events, this one must not.
        if ((ev.own === true || ev.sharer === undefined || ev.sharer === null) && (id === null || !a.seen(id))) reason ??= 'server-gap';
        continue;
      }
      if (ev.kind !== 'cell-written' && ev.kind !== 'cell-erased') continue;
      if (id !== null && (a.seen(id) || ids.has(id))) continue;   // a duplicate: its line is already written
      if (id !== null) ids.add(id);
      if (ev.shrunk === true) continue;   // superseded by a later event for the same cell
      if (id === null) { reason ??= 'unwritable-event'; continue; }
      if (ev.kind === 'cell-written') {
        const line = this.writtenLine(ev);
        if (line === null) reason ??= 'unwritable-event';
        else changes.push(line);
        continue;
      }
      const line = this.erasedLine(ev, a.receivedAt, nowMs, echoes);
      if (line === null) reason ??= 'unwritable-event';
      else if (line !== undefined) erasures.push(line);
    }
    const position = a.moved ? this.marker('position', a.cursor, null, nowIso) : null;
    const unwritable = this.marker('gap', a.cursor, 'unwritable-event', nowIso);
    // ROTATION, ordered so that no crash loses a rotation's marker. `changes.ndjson` moves FIRST and its marker opens
    // the fresh file: a crash between the two leaves exactly what `crashedRotation` finds. `erasures.ndjson` moves only
    // AFTER its marker is in: other processes append to it, so a crash between the two must leave a spare marker
    // rather than a missing one.
    if (this.pastSize(this.changesPath) && this.toPredecessor(this.changesPath)) this.owedRotations++;
    const erasuresDue = this.pastSize(this.erasuresPath);
    const head: string[] = [];
    const markers = this.owedRotations + (erasuresDue && !this.erasuresMarked ? 1 : 0);
    for (let i = 0; i < markers; i++) head.push(this.marker('gap', a.cursor, 'rotation', nowIso));
    if (reason !== null) head.push(this.marker('gap', a.cursor, reason, nowIso));
    // A marker that cannot be a line (a cursor the size limit will not hold) leaves nothing that could cover the answer.
    if ([...head, unwritable, ...(position ? [position] : [])].some((l) => Buffer.byteLength(l, 'utf8') > MAX_FEED_LINE_BYTES)) return 'refused';
    try { this.append(this.changesPath, head); } catch { return 'refused'; }
    this.owedRotations = 0;
    // Marked (now, or by an earlier answer whose move failed): now it moves. A move that fails (a reader holding the
    // file open on some systems) is tried again at the next answer under the marker already in, so a file that cannot
    // move yet does not open every answer with a gap.
    if (erasuresDue) this.erasuresMarked = !this.toPredecessor(this.erasuresPath);
    let covered = head.length > 0;
    const cover = (): boolean => {
      if (covered) return true;
      try { this.append(this.changesPath, [unwritable]); } catch { return false; }
      covered = true;
      return true;
    };
    try { this.append(this.erasuresPath, erasures); } catch { if (!cover()) return 'refused'; }
    try {
      this.append(this.changesPath, position ? [...changes, position] : changes);
    } catch {
      if (!cover()) return 'refused';
      if (position) {
        try { this.append(this.changesPath, [position]); } catch { return 'refused'; }
      }
    }
    for (const c of echoes) this.ownErasures.delete(c);
    return 'written';
  }

  private writtenLine(ev: Record<string, unknown>): string | null {
    const cellId = lineCellId(ev.cellId);
    const at = isoTime(ev.at);
    const seq = typeof ev.seq === 'string' && DIGITS.test(ev.seq) ? ev.seq : null;
    const commitment = typeof ev.commitment === 'string' && HEX64.test(ev.commitment) ? ev.commitment : null;
    if (cellId === null || at === null || seq === null || commitment === null) return null;
    const line = JSON.stringify({
      v: FEED_VERSION, kind: 'cell-written', cellId, agentIdHash: this.agentIdHash, at, seq, commitment, source: 'server-event',
    }) + '\n';
    return Buffer.byteLength(line, 'utf8') <= MAX_FEED_LINE_BYTES ? line : null;
  }

  /** The erasure's line; undefined for this process's own erasure, already recorded; null when it cannot be a line. */
  private erasedLine(ev: Record<string, unknown>, receivedAt: string, nowMs: number, echoes: string[]): string | null | undefined {
    const cellId = lineCellId(ev.cellId);
    if (cellId === null) return null;
    // `complete: true` without an anchor of the agreed shape is stated as false: the consumer refuses true without one.
    const anchor = ev.complete === true && typeof ev.destructionAnchor === 'string' && DESTRUCTION_ANCHOR.test(ev.destructionAnchor)
      ? ev.destructionAnchor : null;
    const own = this.ownErasures.get(cellId);
    if (anchor !== null && own !== undefined && own.until >= nowMs && anchor === own.anchor) {
      echoes.push(cellId);
      return undefined;
    }
    const at = isoTime(ev.at);
    if (at === null) return null;
    // The event's reason, narrowed as a forget's is: only beside the event's own `complete: false`, and only as one of
    // the two it may be. An event that names none, or anything else, gets none; never the nearest plausible one.
    const reason = ev.complete === false && (ev.reason === 'not-found' || ev.reason === 'not-attested') ? ev.reason : undefined;
    try {
      return buildFeedLine({
        cellId, agentIdHash: this.agentIdHash, at, receivedAt, complete: anchor !== null,
        ...(reason !== undefined ? { reason } : {}),
        ...(anchor !== null ? { destructionAnchor: anchor } : {}), source: 'server-event',
      });
    } catch {
      return null;
    }
  }

  private marker(kind: 'position' | 'gap', cursor: string, reason: GapReason | null, at: string): string {
    return JSON.stringify({
      v: FEED_VERSION, kind, agentIdHash: this.agentIdHash, at, cursor, ...(reason !== null ? { reason } : {}),
    }) + '\n';
  }

  /** Whether a line file has grown past the rotation size; a file that is not there has not. */
  private pastSize(path: string): boolean {
    try { return statSync(path).size > this.rotateBytes; } catch { return false; }
  }

  /** Move a line file to its one predecessor name, replacing the last; false when it did not move (tried again later). */
  private toPredecessor(path: string): boolean {
    try { renameSync(path, `${path}${PREDECESSOR_SUFFIX}`); return true; } catch { return false; }
  }

  private startRefresh(): void {
    this.stopRefresh();
    this.refreshTimer = setInterval(() => { if (!this.lease.refresh()) this.stopRefresh(); }, LEASE_REFRESH_MS);
    this.refreshTimer.unref?.();
  }

  private stopRefresh(): void {
    if (this.refreshTimer !== undefined) clearInterval(this.refreshTimer);
    this.refreshTimer = undefined;
  }
}
