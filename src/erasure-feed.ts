/**
 * SAIHM — erasure feed writer (GDPR Art.17 cascade).
 *
 * An erasure that stops at this substrate is not an erasure. Downstream consumers derive artifacts
 * from cells — indexes, mirrors, extracted facts — and those survive a `saihm_forget` unless they
 * are TOLD. This module writes the one-line-per-erasure NDJSON feed a consumer watches, so a delete
 * here becomes a delete there.
 *
 * ── WHY THE ROOT FOLLOWS THE *IDENTITY* CHAIN ──────────────────────────────────────────────────
 * `SAIHM_ERASURE_FEED_DIR` -> `SAIHM_HOME` -> `~/.saihm`. `SAIHM_STATE_DIR` is DELIBERATELY SKIPPED,
 * and the omission is the load-bearing part: a feed is IDENTITY-scoped (one feed per identity; a
 * consumer refuses a foreign line as a wiring fault), so it must move with the identity or not at
 * all. `defaultIdentityPath()` in `client.ts` refuses `SAIHM_STATE_DIR` for exactly this reason —
 * honouring it would relocate an EXISTING identity file out from under its owner, and a join that
 * cannot find its identity mints a new one, which reads as empty memory. `SAIHM_STATE_DIR` is a
 * narrow, undeclared, single-artifact knob (it governs where a hosted-checkout URL is written); a
 * caller who sets it is relocating relocatable state, NOT re-homing an identity. Two variables, two
 * jobs. Reading it here would silently split one identity's feed across two roots the first time an
 * operator set it, and the consumer would refuse the lines as foreign.
 *
 * ── WHY ABSOLUTE-OR-REFUSE ────────────────────────────────────────────────────────────────────
 * A relative root resolves against CWD, so the same identity writes to a different file depending on
 * where the process was launched from. That does not throw and does not corrupt anything — it just
 * scatters the feed, and the consumer reports `present:false` on a feed that is being written three
 * directories away. Refusing at resolve time is the only failure mode that is visible.
 *
 * ── WHY A TENANT DIRECTORY THAT IS ALREADY SOMEBODY ELSE'S IS REFUSED ────────────────────────
 * `<root>/tenants/<identity>/` is this feed's own directory, but the `tenants/<identity>` shape is
 * not unique to it - another store can use the same layout under a DIFFERENT root. An operator who
 * points the feed root at that store's base directory lands the feed INSIDE a tree whose owner
 * deletes it wholesale when that identity is erased, so the feed would vanish together with the
 * thing it existed to record. A directory that already holds state and does NOT hold this feed is
 * therefore not ours, and appending into it is refused. Once the feed file is present the directory
 * IS ours and later neighbours are tolerated, so a rotated or backed-up line file never blocks an
 * erasure. RESIDUAL, written down rather than hidden: if the other store creates its files AFTER
 * the feed already exists, this check has passed and cannot re-fire.
 *
 * ── WHY OVERSIZE IS REFUSED, NEVER TRUNCATED ──────────────────────────────────────────────────
 * A truncated NDJSON line is not a short line, it is a CORRUPT line, and it corrupts the line after
 * it too once the newline is lost. The consumer counts malformed lines and purges nothing for them,
 * so truncating converts "this erasure was not recorded" into "this erasure was recorded wrongly and
 * so was the next one". Refusing keeps the damage to one line and reports it.
 */

import {
  closeSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  mkdirSync,
  openSync,
  readdirSync,
  writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join as pathJoin } from 'node:path';
import { homedir } from 'node:os';

/** The feed's own filename inside a tenant directory. Not exported: the consumer hard-codes it. */
const FEED_FILENAME = 'erasures.ndjson';

/** The share map another process reads (share-states-file.ts), in the same tenant directory. */
export const SHARE_STATES_FILENAME = 'share-states.json';

/**
 * Whether a tenant directory's entries make it this package's: empty, holding the erasure feed or the share map, or
 * holding only what a share map write leaves while it runs (its lock and temporary file). The share map lives beside
 * the feed, so a directory it created first must not read as some other store's.
 */
export function tenantDirIsOurs(entries: readonly string[]): boolean {
  return entries.length === 0 || entries.includes(FEED_FILENAME) || entries.includes(SHARE_STATES_FILENAME)
    || entries.every((e) => e.startsWith(`${SHARE_STATES_FILENAME}.`));
}

/** Max bytes for one serialized line INCLUDING its terminating newline. */
export const MAX_FEED_LINE_BYTES = 1024;

/** Feed schema version. Bump only for a shape change a consumer must branch on. */
export const FEED_VERSION = 1;

/**
 * Character ceiling for `cellId` — the ONE caller-chosen field on this wire.
 *
 * 64, which is this package's own ceiling for a cellId used as a POINTER: a full sha256 hex id is
 * exactly 64, `MAX_ANNOUNCEMENT_FIELD_CHARS` in `client.ts` is 64 for that reason, and it is set
 * equal to the server's per-field render budget precisely so a kept cellId always renders at FULL
 * length rather than as a cut, actionable-looking pointer that is not actionable. Duplicated here as
 * a literal rather than imported because `client.ts` imports THIS module; a test pins the two equal
 * so the duplication cannot drift silently.
 *
 * It bounds the LINE, but the reason it exists is the RENDER. `cellId` is free-form and arrives from
 * a tool argument, so without it the only variable-length field on this wire is one a caller picks -
 * and a caller who picks a long enough one makes `buildFeedLine` refuse, which makes the MCP client
 * report a residual, which mints a LINE in a tool result whose structure is pinned at one. That is a
 * caller-controlled lever over render shape, which this package does not give away anywhere else.
 * Bounding the field here means the budget above can only be exceeded by a programming error.
 */
export const MAX_FEED_CELL_ID_CHARS = 64;

/** Which emit site produced a line. Consumers use it to explain an INCOMPLETE in a report. */
export type ErasureFeedSource = 'mcp-client' | 'blind-endpoint-pre' | 'blind-endpoint-post';

export interface ErasureFeedRecord {
  readonly cellId: string;
  readonly agentIdHash: string;
  /**
   * ISO-8601 UTC with milliseconds and a trailing `Z` — `new Date().toISOString()` exactly.
   *
   * NOTE the field that is NOT here: `epoch`. Both `ForgetResult` types carry one and it is the
   * wrong unit for this wire — the consumer's `epoch` is HOURS since 1970 and it derives time from
   * `at`. A seconds- or millisecond-valued `epoch` is off by orders of magnitude, is a perfectly
   * well-formed number, and therefore NEVER ERRORS. It is omitted rather than converted so there is
   * nothing to convert wrongly.
   */
  readonly at: string;
  /**
   * TRUE only where the per-cell key is actually destroyed. On an access-control-erasure runtime
   * this is permanently `false` and that is not a defect — the consumer records INCOMPLETE with the
   * reason and purges its derived artifacts regardless. Never forward an endpoint's `complete`
   * blindly: a `true` without a `destructionAnchor` is refused as malformed by the consumer, so a
   * site that cannot produce an anchor must state `false`.
   */
  readonly complete: boolean;
  /** Verbatim from the erasure receipt. REQUIRED when `complete` is true; omitted otherwise. */
  readonly destructionAnchor?: string;
  readonly source: ErasureFeedSource;
}

export class ErasureFeedError extends Error {
  override readonly name = 'ErasureFeedError';
}

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Resolve the feed root, or throw. Reads `env` explicitly rather than `process.env` so a test can
 * exercise every branch without mutating global state — a suite that sets `process.env` and restores
 * it in a `finally` still leaks on the one path that matters, the throwing one.
 */
export function resolveFeedRoot(env: NodeJS.ProcessEnv = process.env): string {
  const explicit = env['SAIHM_ERASURE_FEED_DIR'];
  const home = env['SAIHM_HOME'];
  const root = explicit ?? home ?? pathJoin(homedir(), '.saihm');
  if (!isAbsolute(root)) {
    const which = explicit !== undefined ? 'SAIHM_ERASURE_FEED_DIR' : 'SAIHM_HOME';
    throw new ErasureFeedError(
      `${which} must be an ABSOLUTE path; got ${JSON.stringify(root)}. A relative feed root ` +
        `resolves against the current working directory, so the same identity would write to a ` +
        `different file depending on where the process was started, and a consumer would report the ` +
        `feed absent while lines were being written elsewhere.`,
    );
  }
  return root;
}

/** `<root>/tenants/<agentIdHash>/erasures.ndjson`. Identity partitioning is NOT optional. */
export function feedPathFor(root: string, agentIdHashHex: string): string {
  const id = agentIdHashHex.toLowerCase();
  if (!HEX64.test(id)) {
    throw new ErasureFeedError(
      `agentIdHash must be 64 lowercase hex characters; got ${JSON.stringify(agentIdHashHex)}. ` +
        `The feed is partitioned by identity because two identities can share one home today ` +
        `(point SAIHM_MASTER_SECRET_FILE elsewhere while SAIHM_HOME stays default), and a consumer ` +
        `refuses a foreign line as a wiring fault rather than applying it.`,
    );
  }
  return pathJoin(root, 'tenants', id, FEED_FILENAME);
}

/**
 * Create `tenants/<agentIdHash>/` at JOIN, not at the first erasure.
 *
 * A consumer can arm a directory watch on a directory that EXISTS; a missing one leaves it polling
 * until something appears. Creating the directory when the identity is loaded makes the consumer's
 * arm-time immediate and costs one `mkdir` per process start. It deliberately does NOT create the
 * file: an empty `erasures.ndjson` and a never-written one are indistinguishable to a reader, and
 * the directory alone carries the "this identity is wired" signal without asserting an erasure
 * history that does not exist.
 */
export function assertTenantDirUnshared(root: string, agentIdHashHex: string): void {
  const dir = pathJoin(root, 'tenants', agentIdHashHex.toLowerCase());
  let entries: readonly string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return; // No directory yet - this feed is the one about to create it.
  }
  if (tenantDirIsOurs(entries)) return;
  throw new ErasureFeedError(
    `the feed directory ${JSON.stringify(dir)} already holds ${entries.length} other ` +
      `entr${entries.length === 1 ? 'y' : 'ies'} and no ${FEED_FILENAME}, so it belongs to some ` +
      `other store. Writing the feed here would place it inside a tree whose owner deletes the ` +
      `whole directory when this identity is erased, taking the record of that erasure with it. ` +
      `Point SAIHM_ERASURE_FEED_DIR at a root this feed owns.`,
  );
}

export function ensureTenantDir(agentIdHashHex: string, env: NodeJS.ProcessEnv = process.env): string {
  const root = resolveFeedRoot(env);
  const path = feedPathFor(root, agentIdHashHex);
  assertTenantDirUnshared(root, agentIdHashHex);
  mkdirSync(pathJoin(root, 'tenants', agentIdHashHex.toLowerCase()), { recursive: true, mode: 0o700 });
  return path;
}

/**
 * Serialize one record, or throw if it will not fit.
 *
 * Key order is fixed and explicit so a line is byte-stable across runs — a consumer that fingerprints
 * or de-duplicates on the raw line should not see two spellings of the same erasure.
 */
export function buildFeedLine(rec: ErasureFeedRecord): string {
  if (rec.cellId.length === 0 || rec.cellId.length > MAX_FEED_CELL_ID_CHARS) {
    throw new ErasureFeedError(
      `cellId is ${rec.cellId.length} characters; it must be 1..${MAX_FEED_CELL_ID_CHARS}. It is ` +
        `REFUSED, never truncated: a truncated cellId is not a shorter pointer, it is a DIFFERENT ` +
        `one, and a consumer that matches it purges an artifact derived from some other cell. No ` +
        `pointer is recoverable; a wrong pointer is a second erasure nobody asked for.`,
    );
  }
  if (rec.complete && (rec.destructionAnchor === undefined || rec.destructionAnchor === '')) {
    throw new ErasureFeedError(
      `complete:true requires a non-empty destructionAnchor — the consumer refuses the line ` +
        `otherwise, and a refused line purges nothing. Emit complete:false where no anchor exists.`,
    );
  }
  const obj: Record<string, unknown> = {
    v: FEED_VERSION,
    cellId: rec.cellId,
    agentIdHash: rec.agentIdHash.toLowerCase(),
    at: rec.at,
    complete: rec.complete,
  };
  if (rec.destructionAnchor !== undefined) obj['destructionAnchor'] = rec.destructionAnchor;
  obj['source'] = rec.source;

  const line = JSON.stringify(obj) + '\n';
  const bytes = Buffer.byteLength(line, 'utf8');
  if (bytes > MAX_FEED_LINE_BYTES) {
    throw new ErasureFeedError(
      `feed line is ${bytes} bytes, over the ${MAX_FEED_LINE_BYTES}-byte limit. It is REFUSED, not ` +
        `truncated: a truncated NDJSON line is a corrupt line, and it corrupts its successor once ` +
        `the newline is lost.`,
    );
  }
  return line;
}

/**
 * Append one line and fsync it. Append-only: never rewrite, truncate, or rotate in place.
 *
 * `fsync` is the point of the exercise. The contract is that the line is DURABLE before the erasure
 * is reported, so a crash between the append and the erase must leave the line present — that
 * direction is recoverable (the consumer purges a cell that is still live, discloses it, and the
 * next build re-admits it). The other direction is not: an erased cell whose line never reached disk
 * leaves a derived artifact alive with nothing left to point at it.
 */
export function appendFeedLine(path: string, line: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const buf = Buffer.from(line, 'utf8');
  const fd = openSync(path, 'a', 0o600);
  const sizeBefore = fstatSync(fd).size;
  let off = 0;
  try {
    // Node's own `writeFileSync` loops here, and this file needs the loop for a sharper reason than
    // tidiness: `writeSync` is permitted to write fewer bytes than it was handed, and a short write
    // on THIS file leaves exactly the artefact `buildFeedLine` refuses to construct — a half-record
    // whose missing newline takes its successor down with it. Refusing to build one and then writing
    // one anyway would be a guarantee made in the error message and broken in the syscall.
    //
    // The loop trades one property for a better one. A single append under `O_APPEND` is indivisible
    // against a second writer; a retried one is not, so a concurrent writer to the SAME identity's
    // feed could interleave between iterations. That is the right trade: the interleave needs two
    // processes on one identity AND a short write, while the corruption it replaces needs only the
    // short write, and a short write on a file this small effectively means the disk is full.
    while (off < buf.length) {
      const n = writeSync(fd, buf, off, buf.length - off);
      if (n <= 0) {
        throw new ErasureFeedError(
          `the erasure feed line could not be written in full: the write returned ${n} with ` +
            `${buf.length - off} of ${buf.length} bytes still owed. Refusing to spin: a partial ` +
            `line is a corrupt record, and the caller is told rather than left believing the ` +
            `downstream feed was notified.`,
        );
      }
      off += n;
    }
    fsyncSync(fd);
  } catch (e) {
    // Put the file back the way it was found. Without this the guarantee in the error messages above
    // is a guarantee about the RECORD and not about the FILE: a write that fails after placing bytes
    // — part-way through the loop, or when the flush that follows it fails — has already put those
    // bytes on the disk, and they are the half-record this module refuses to construct.
    // The rollback is conditional on the file still ending exactly where our own bytes ended, so a
    // second writer that appended in the meantime is never truncated away — losing somebody else's
    // erasure line to tidy up our own would be the more expensive mistake.
    try {
      if (off > 0 && fstatSync(fd).size === sizeBefore + off) ftruncateSync(fd, sizeBefore);
    } catch {
      /* The line stays partial and the caller is told; nothing better is available here. */
    }
    throw e;
  } finally {
    closeSync(fd);
  }
}

/**
 * Build + append in one call. Throws on any failure; the CALLER decides whether that is fatal.
 *
 * That split is deliberate and the two sites use it differently, because the same failure means
 * different things depending on whether the erasure has already happened:
 *   - Before the erase (blind endpoint): a failure MUST fail the forget. The alternative is an
 *     erasure nothing downstream was told about, which produces a false "erased".
 *   - After the erase (MCP client): the erasure is already irreversible, so throwing would report a
 *     FAILED forget on a cell that is gone — the worst direction to be wrong in on this tool, and a
 *     bug this file's sibling has already paid to fix once. Use {@link emitErasureLineReporting}.
 */
export function emitErasureLine(rec: ErasureFeedRecord, env: NodeJS.ProcessEnv = process.env): string {
  const root = resolveFeedRoot(env);
  const path = feedPathFor(root, rec.agentIdHash);
  assertTenantDirUnshared(root, rec.agentIdHash);
  appendFeedLine(path, buildFeedLine(rec));
  return path;
}

/**
 * Non-throwing variant for post-erasure sites: returns `undefined` on success, or a sentence
 * describing what was NOT recorded.
 *
 * Silence is not an option here and neither is an exception. Swallowing the error reports a plain
 * success while a downstream consumer still holds artifacts derived from an erased cell — the
 * opposite lie about the one promise the tool makes. Both halves get reported instead.
 */
export function emitErasureLineReporting(
  rec: ErasureFeedRecord,
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  try {
    emitErasureLine(rec, env);
    return undefined;
  } catch (e) {
    const why = e instanceof Error ? e.message : String(e);
    return (
      `the erasure is complete and irreversible, but the downstream erasure feed line could not be ` +
      `written, so nothing derived from this cell has been told to purge it: ${why}`
    );
  }
}
