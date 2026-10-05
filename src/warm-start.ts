/**
 * Warm start: the payload files beside the client, and the sealing of a snapshot.
 *
 * SHM and this client exchange one opaque payload per call through `<root>/tenants/<agentIdHash>/warm-start/` (the
 * erasure feed's root), in files named by a token SHM chooses for that call: `put-<token>.bin`, which SHM writes and a
 * put reads and removes, and `latest-<token>.bin`, which a restore writes and SHM reads and removes. The token keeps two
 * SHM processes of one identity from ever reading each other's payload. The token is checked against its grammar
 * before any path is built from it, and every file is opened without following a link and checked for what it is.
 *
 * The payload is sealed here and nowhere else. Each snapshot gets one fresh key; the payload is cut into the parts it is
 * uploaded in and each part is sealed on its own, its associated data binding the snapshot domain, the identity, the
 * position the snapshot covers, the snapshot's nonce, the part's index and the part count. The key is wrapped under
 * the identity's key-encryption key with the same domain, identity, position and nonce. The endpoint stores bytes it
 * cannot open, and this module never keeps the unwrapped key past the call that used it.
 *
 * DOMAIN SEPARATION from cells is structural: a cell's associated data starts with the identity's 32-byte hash, a
 * snapshot's with the domain label, whose length is not 32, so the two encodings never coincide and neither key can be
 * unwrapped as the other.
 *
 * NOTHING HERE TALKS TO THE ENDPOINT. The client makes the calls; this module seals, opens, checks answers' shapes and
 * handles the files.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { dirname, join as pathJoin } from 'node:path';
import { concat, concatLP, fromHex, u32be, utf8 } from '@saihm/client-pro';
import { WARM_START_FOLDER, assertTenantDirUnshared, ensureTenantDir, feedPathFor, resolveFeedRoot } from './erasure-feed.js';
import { isoTime } from './change-feed.js';

/**
 * The statement this client adds to the offer it passes on in `saihm_status`: `features.warmStart.<member>` set to
 * `<value>`. Set here and only here, and never taken from the endpoint, whose own member of that name is dropped.
 */
export const WARM_START_TOKEN = { member: 'token', value: 'required' } as const;

/** A warm-start call's token: 16 to 32 characters from a-z and 0-9, chosen at random by SHM for that call. */
export const WARM_START_TOKEN_PATTERN = /^[a-z0-9]{16,32}$/;

/** A snapshot id, as the endpoint names one: 64 lowercase hex characters. */
export const SNAPSHOT_ID_PATTERN = /^[0-9a-f]{64}$/;

/** The position a snapshot covers: a cursor of the identity's event feed, 1 to 64 printable ASCII characters. */
export const COVERS_THROUGH_PATTERN = /^[!-~]{1,64}$/;

/**
 * How old a file in the warm-start folder must be before any warm-start call removes it. Long enough for the moment
 * between SHM writing a payload and calling, or a restore writing one and SHM reading it; short enough that a crash
 * never leaves a plaintext payload behind for long.
 */
const LEFTOVER_AGE_MS = 300_000;

/** The domain every snapshot's associated data starts with. Its length is not 32 (see the module note). */
const SNAPSHOT_DOMAIN = 'saihm-warm-start/1';
/** The first byte of a key envelope: its layout. */
const KEY_ENVELOPE_VERSION = 1;
const SNAPSHOT_KEY_BYTES = 32;
const SNAPSHOT_NONCE_BYTES = 16;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
/** The bounds this client accepts for the endpoint's part size: anything a part and its tag fit in, and no larger. */
const MIN_PART_BYTES = 1024;
const MAX_PART_BYTES = 16_777_216;
/** The longest key envelope the endpoint stores. */
const MAX_KEY_ENVELOPE_CHARS = 4096;

/** Owner and mode bits are checked where the platform keeps them; on Windows neither applies, as elsewhere here. */
const POSIX_MODES = process.platform !== 'win32';

const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const KEY_ENVELOPE_BYTES = 1 + GCM_IV_BYTES + SNAPSHOT_KEY_BYTES + GCM_TAG_BYTES;

// ── the offer ───────────────────────────────────────────────────────────────────────────────────────────────────────

/** What this client needs from an identity's offer: the most ciphertext one snapshot may hold. */
export interface WarmStartLimits {
  readonly maxBytes: number;
}

/**
 * The offer this client serves, from `features` as `saihm_status` reads it, or null: an object whose `v` lists 1 and
 * whose `maxBytes` is a positive whole number. Anything else is no offer, and every warm-start call is refused.
 */
export function warmStartLimits(features: Readonly<Record<string, unknown>> | null): WarmStartLimits | null {
  const offer = features?.['warmStart'];
  if (typeof offer !== 'object' || offer === null || Array.isArray(offer)) return null;
  const { v, maxBytes } = offer as { v?: unknown; maxBytes?: unknown };
  if (!Array.isArray(v) || !v.includes(1)) return null;
  if (typeof maxBytes !== 'number' || !Number.isSafeInteger(maxBytes) || maxBytes < 1) return null;
  return { maxBytes };
}

/**
 * `features` as `saihm_status` passes it on: unchanged, except that an offer of warm start carries this client's
 * statement that it names payload files by a token (`WARM_START_TOKEN`) exactly when it serves that offer, and never
 * a member of that name the endpoint sent. Every other member of the offer, and every other feature, passes as sent.
 */
export function withWarmStartToken(features: Record<string, unknown> | null): Record<string, unknown> | null {
  if (features === null) return null;
  const offer = features['warmStart'];
  if (typeof offer !== 'object' || offer === null || Array.isArray(offer)) return features;
  const asSent: Record<string, unknown> = { ...(offer as Record<string, unknown>) };
  delete asSent[WARM_START_TOKEN.member];
  return {
    ...features,
    warmStart: warmStartLimits(features) === null ? asSent : { ...asSent, [WARM_START_TOKEN.member]: WARM_START_TOKEN.value },
  };
}

/** Where the endpoint serves warm start and the part size it takes, from its info document's `warmStart`, or null. */
export interface WarmStartRoute {
  readonly url: string;
  readonly partBytes: number;
}

/**
 * The info document's `warmStart` read against the endpoint: its path on the endpoint's own origin (the requests carry
 * the credential) and its part size. Anything this client cannot use is null: no warm start there now.
 */
export function warmStartRoute(info: unknown, endpointBase: string): WarmStartRoute | null {
  if (typeof info !== 'object' || info === null || Array.isArray(info)) return null;
  const cap = (info as { warmStart?: unknown }).warmStart;
  if (typeof cap !== 'object' || cap === null || Array.isArray(cap)) return null;
  const { v, path, partBytes } = cap as { v?: unknown; path?: unknown; partBytes?: unknown };
  if (!Array.isArray(v) || !v.includes(1)) return null;
  if (typeof partBytes !== 'number' || !Number.isSafeInteger(partBytes) || partBytes < MIN_PART_BYTES || partBytes > MAX_PART_BYTES)
    return null;
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || path.length > 256) return null;
  let url: URL;
  try {
    url = new URL(path, endpointBase);
  } catch {
    return null;
  }
  if (url.origin !== new URL(endpointBase).origin || url.search !== '' || url.hash !== '') return null;
  return { url: url.toString().replace(/\/+$/, ''), partBytes };
}

// ── answers ─────────────────────────────────────────────────────────────────────────────────────────────────────────

/** A snapshot as the tools report it. */
export interface WarmStartSnapshot {
  readonly snapshotId: string;
  readonly createdAt: string;
  readonly bytes: number;
  readonly coversThrough: string;
}

/** A listed snapshot with what a restore needs. */
export interface ListedSnapshot extends WarmStartSnapshot {
  readonly parts: number;
  readonly digest: string;
  readonly keyEnvelope: string;
  readonly nonce: string;
}

const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 1;
const isText = (v: unknown, re: RegExp, max: number): v is string => typeof v === 'string' && v.length <= max && re.test(v);

/** One entry of the listing, or null when any field is not of its shape. Every part holds at least its tag. */
function listedSnapshot(e: unknown): ListedSnapshot | null {
  if (typeof e !== 'object' || e === null || Array.isArray(e)) return null;
  const s = e as Record<string, unknown>;
  const createdAt = isoTime(s['createdAt']);
  const { snapshotId, bytes, parts, digest, coversThrough, keyEnvelope, nonce } = s;
  if (!isText(snapshotId, SNAPSHOT_ID_PATTERN, 64) || createdAt === null) return null;
  if (!isCount(bytes) || !isCount(parts) || parts * GCM_TAG_BYTES > bytes) return null;
  if (!isText(digest, HEX64, 64) || !isText(nonce, HEX32, 32)) return null;
  if (!isText(coversThrough, COVERS_THROUGH_PATTERN, 64) || !isText(keyEnvelope, B64URL, MAX_KEY_ENVELOPE_CHARS)) return null;
  return { snapshotId, createdAt, bytes, coversThrough, parts, digest, keyEnvelope, nonce };
}

/** The listing's snapshots in the endpoint's order (newest first), or null: a listing with any entry it cannot read is refused whole. */
export function listedSnapshots(body: unknown): ListedSnapshot[] | null {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return null;
  const list = (body as { snapshots?: unknown }).snapshots;
  if (!Array.isArray(list)) return null;
  const out: ListedSnapshot[] = [];
  for (const e of list) {
    const s = listedSnapshot(e);
    if (s === null) return null;
    out.push(s);
  }
  return out;
}

/** A begin's answer: the upload's id and the part size it takes, or null. */
export function begunUpload(body: unknown): { readonly uploadId: string; readonly partBytes: number } | null {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return null;
  const { uploadId, partBytes } = body as { uploadId?: unknown; partBytes?: unknown };
  if (!isText(uploadId, HEX32, 32) || !isCount(partBytes)) return null;
  return { uploadId, partBytes };
}

/** A commit's answer, or null unless it names a snapshot of exactly what was sent. */
export function committedSnapshot(body: unknown, sent: { readonly bytes: number; readonly parts: number; readonly coversThrough: string }): WarmStartSnapshot | null {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return null;
  const b = body as Record<string, unknown>;
  const createdAt = isoTime(b['createdAt']);
  const snapshotId = b['snapshotId'];
  if (!isText(snapshotId, SNAPSHOT_ID_PATTERN, 64) || createdAt === null) return null;
  if (b['bytes'] !== sent.bytes || b['parts'] !== sent.parts || b['coversThrough'] !== sent.coversThrough) return null;
  return { snapshotId, createdAt, bytes: sent.bytes, coversThrough: sent.coversThrough };
}

/** `Content-Digest` (RFC 9530) for a part: its SHA-256, standard base64 with padding. */
export const contentDigestOf = (part: Uint8Array): string => `sha-256=:${createHash('sha256').update(part).digest('base64')}:`;

/**
 * The SHA-256 a `Content-Digest` header states, or null: exactly one `sha-256` member, a byte sequence of standard
 * base64 with its padding. Other members may accompany it.
 */
export function contentDigestSha256(header: string | undefined): Buffer | null {
  if (header === undefined || header.length > 4096) return null;
  let found: Buffer | null = null;
  for (const member of header.split(',')) {
    const m = /^\s*sha-256=:([A-Za-z0-9+/]{43}=):(?:;[^,]*)?\s*$/.exec(member);
    if (m === null) {
      if (/^\s*sha-256\s*=/.test(member)) return null;
      continue;
    }
    if (found !== null) return null;
    found = Buffer.from(m[1] as string, 'base64');
  }
  return found !== null && found.length === 32 ? found : null;
}

/** SHA-256 of the parts in order, as lowercase hex: a snapshot's `digest`. */
export function partsDigest(parts: readonly Uint8Array[]): string {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest('hex');
}

// ── sealing ─────────────────────────────────────────────────────────────────────────────────────────────────────────

/** What a snapshot is bound to besides its own nonce. */
export interface SnapshotBinding {
  readonly kek: Uint8Array;
  readonly agentIdHash: Uint8Array;
  readonly coversThrough: string;
}

/** A sealed snapshot, ready to upload. */
export interface SealedSnapshot {
  readonly parts: readonly Uint8Array[];
  readonly bytes: number;
  readonly digest: string;
  readonly keyEnvelope: string;
  readonly nonce: string;
}

const partAad = (agentIdHash: Uint8Array, coversThrough: string, nonce: Uint8Array, index: number, count: number): Uint8Array =>
  concatLP(utf8(SNAPSHOT_DOMAIN), agentIdHash, utf8(coversThrough), nonce, u32be(index), u32be(count));
const keyAad = (agentIdHash: Uint8Array, coversThrough: string, nonce: Uint8Array): Uint8Array =>
  concatLP(utf8(SNAPSHOT_DOMAIN), agentIdHash, utf8(coversThrough), nonce);
/** A part's nonce under its snapshot's key: its index, so no two parts of one key share one. */
const partIv = (index: number): Uint8Array => concat(new Uint8Array(GCM_IV_BYTES - 4), u32be(index));

function gcmSeal(key: Uint8Array, iv: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const c = createCipheriv('aes-256-gcm', key, iv, { authTagLength: GCM_TAG_BYTES });
  c.setAAD(aad);
  return concat(c.update(plaintext), c.final(), c.getAuthTag());
}

/** Opens a sealed value, or null when it does not authenticate. */
function gcmOpen(key: Uint8Array, iv: Uint8Array, aad: Uint8Array, sealed: Uint8Array): Uint8Array | null {
  if (sealed.length < GCM_TAG_BYTES) return null;
  try {
    const d = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: GCM_TAG_BYTES });
    d.setAAD(aad);
    d.setAuthTag(sealed.subarray(sealed.length - GCM_TAG_BYTES));
    return concat(d.update(sealed.subarray(0, sealed.length - GCM_TAG_BYTES)), d.final());
  } catch {
    return null;
  }
}

/**
 * Seal a payload for upload in parts of `partBytes` sealed bytes (the last may be shorter). An empty payload is one
 * part holding only its tag. Throws only on arguments no caller in this package passes.
 */
export function sealSnapshot(payload: Uint8Array, partBytes: number, b: SnapshotBinding): SealedSnapshot {
  if (!Number.isSafeInteger(partBytes) || partBytes <= GCM_TAG_BYTES) throw new RangeError('part size too small');
  if (!COVERS_THROUGH_PATTERN.test(b.coversThrough)) throw new RangeError('coversThrough is not a feed position');
  const chunk = partBytes - GCM_TAG_BYTES;
  const count = Math.max(1, Math.ceil(payload.length / chunk));
  const nonce = randomBytes(SNAPSHOT_NONCE_BYTES);
  const key = randomBytes(SNAPSHOT_KEY_BYTES);
  try {
    const parts: Uint8Array[] = [];
    for (let i = 0; i < count; i++) {
      const piece = payload.subarray(i * chunk, Math.min(payload.length, (i + 1) * chunk));
      parts.push(gcmSeal(key, partIv(i), partAad(b.agentIdHash, b.coversThrough, nonce, i, count), piece));
    }
    const wrapIv = randomBytes(GCM_IV_BYTES);
    const wrapped = gcmSeal(b.kek, wrapIv, keyAad(b.agentIdHash, b.coversThrough, nonce), key);
    const keyEnvelope = Buffer.from(concat(new Uint8Array([KEY_ENVELOPE_VERSION]), wrapIv, wrapped)).toString('base64url');
    let bytes = 0;
    for (const p of parts) bytes += p.length;
    return { parts, bytes, digest: partsDigest(parts), keyEnvelope, nonce: nonce.toString('hex') };
  } finally {
    key.fill(0);
  }
}

/**
 * The snapshot key a listing entry's envelope wraps, or null when this identity cannot open it for that entry: another
 * identity's, another snapshot's, a cell's key envelope offered as a snapshot's, or bytes of any other shape.
 */
export function openSnapshotKey(keyEnvelope: string, nonceHex: string, b: SnapshotBinding): Uint8Array | null {
  if (!isText(keyEnvelope, B64URL, MAX_KEY_ENVELOPE_CHARS) || !HEX32.test(nonceHex)) return null;
  const raw = Buffer.from(keyEnvelope, 'base64url');
  if (raw.toString('base64url') !== keyEnvelope || raw.length !== KEY_ENVELOPE_BYTES || raw[0] !== KEY_ENVELOPE_VERSION) return null;
  const key = gcmOpen(b.kek, raw.subarray(1, 1 + GCM_IV_BYTES), keyAad(b.agentIdHash, b.coversThrough, fromHex(nonceHex)), raw.subarray(1 + GCM_IV_BYTES));
  return key !== null && key.length === SNAPSHOT_KEY_BYTES ? key : null;
}

/**
 * The payload, or null unless EVERY part opens at its own place: a part that is moved, dropped, repeated or taken from
 * another snapshot fails, and so does the whole restore. Nothing of a failed restore is returned.
 */
export function openSnapshotParts(
  key: Uint8Array,
  parts: readonly Uint8Array[],
  nonceHex: string,
  b: Omit<SnapshotBinding, 'kek'>,
): Uint8Array | null {
  if (!HEX32.test(nonceHex) || parts.length === 0) return null;
  const nonce = fromHex(nonceHex);
  const pieces: Uint8Array[] = [];
  for (let i = 0; i < parts.length; i++) {
    const piece = gcmOpen(key, partIv(i), partAad(b.agentIdHash, b.coversThrough, nonce, i, parts.length), parts[i] as Uint8Array);
    if (piece === null) {
      for (const p of pieces) p.fill(0);
      return null;
    }
    pieces.push(piece);
  }
  const payload = concat(...pieces);
  for (const p of pieces) p.fill(0);
  return payload;
}

// ── the files ───────────────────────────────────────────────────────────────────────────────────────────────────────

/** Why a payload file was refused. Each code is the one a tool result names. */
export type WarmStartFileCode = 'warm_start_file_missing' | 'warm_start_file_unsafe' | 'snapshot_too_large';

/** A refusal of a payload file or of the folder; its message names no path. */
export class WarmStartFileError extends Error {
  override readonly name = 'WarmStartFileError';
  constructor(
    readonly code: WarmStartFileCode,
    message: string,
  ) {
    super(message);
  }
}

const unsafe = (why: string): WarmStartFileError => new WarmStartFileError('warm_start_file_unsafe', why);
const errCode = (e: unknown): string | undefined => {
  const c = (e as { code?: unknown } | null)?.code;
  return typeof c === 'string' ? c : undefined;
};

/** The payload file a put reads. */
export const putFileName = (token: string): string => `put-${token}.bin`;
/** The payload file a restore writes. */
export const latestFileName = (token: string): string => `latest-${token}.bin`;

/** Refuses a token outside the grammar: no path is ever built from one. */
function checkedToken(token: string): string {
  if (!WARM_START_TOKEN_PATTERN.test(token)) throw new RangeError('a warm-start token is 16 to 32 characters from a-z and 0-9');
  return token;
}

/** One identity's warm-start folder. Resolving it touches nothing. */
export interface WarmStartFolder {
  readonly agentIdHash: string;
  readonly root: string;
  readonly dir: string;
  /** Where the root was read from, so creating the tenant folder resolves the same place. */
  readonly env: NodeJS.ProcessEnv;
}

/** Resolve the folder from the erasure feed's root (`SAIHM_ERASURE_FEED_DIR`, else `SAIHM_HOME`, else `~/.saihm`). */
export function warmStartFolder(agentIdHashHex: string, env: NodeJS.ProcessEnv = process.env): WarmStartFolder {
  const root = resolveFeedRoot(env);
  const tenantDir = dirname(feedPathFor(root, agentIdHashHex));
  return { agentIdHash: agentIdHashHex.toLowerCase(), root, dir: pathJoin(tenantDir, WARM_START_FOLDER), env };
}

/**
 * Whether the folder exists, refusing one this client must not read or write: one inside a tenant folder that belongs
 * to another store, anything but a directory (a link included), one owned by another user, or one other users can
 * reach (it is created 0700).
 */
function folderPresent(folder: WarmStartFolder): boolean {
  try {
    assertTenantDirUnshared(folder.root, folder.agentIdHash);
  } catch {
    throw unsafe('the tenant folder holds another store\'s files, so its warm-start folder is not this client\'s');
  }
  const dir = folder.dir;
  let st;
  try {
    st = lstatSync(dir);
  } catch (e) {
    if (errCode(e) === 'ENOENT') return false;
    throw unsafe('the warm-start folder could not be examined');
  }
  if (st.isSymbolicLink() || !st.isDirectory()) throw unsafe('the warm-start folder is not a folder');
  if (POSIX_MODES && st.uid !== process.getuid?.()) throw unsafe('the warm-start folder belongs to another user');
  if (POSIX_MODES && (st.mode & 0o077) !== 0) throw unsafe('the warm-start folder is open to other users: it must be private to this user (0700)');
  return true;
}

/**
 * Remove every file in the warm-start folder older than LEFTOVER_AGE_MS, temporary files included: what a crash left
 * behind. Run first by every warm-start call. A folder holding a folder is refused untouched: SHM keeps nothing but
 * payload files there, so such a folder is not the one SHM and this client share. Returns how many were removed.
 *
 * `keep` names the one file the calling put takes itself, its own `put-<token>.bin`: not a leftover, however long the
 * call took to arrive after SHM wrote it (a host waiting for approval, a process paused), and removed by that put
 * itself, whether or not its upload succeeds. Swept, it would turn the put into `warm_start_file_missing`.
 *
 * RESIDUAL, stated: a folder of another store laid out the same way, holding files only, passes this check; the tenant
 * folder's own check (that it holds this package's files or nothing foreign) is what stands in front of it.
 */
export function sweepWarmStart(folder: WarmStartFolder, nowMs: number = Date.now(), keep?: string): number {
  if (!folderPresent(folder)) return 0;
  const old: string[] = [];
  for (const name of readdirSync(folder.dir)) {
    let st;
    try {
      st = lstatSync(pathJoin(folder.dir, name));
    } catch {
      continue;
    }
    if (st.isDirectory()) throw unsafe('the warm-start folder holds a folder, so it is not the one SHM and this client share');
    if (name !== keep && nowMs - st.mtimeMs > LEFTOVER_AGE_MS) old.push(name);
  }
  let removed = 0;
  for (const name of old) {
    try {
      unlinkSync(pathJoin(folder.dir, name));
      removed++;
    } catch {
      /* gone already, or not ours to remove: the next call tries again */
    }
  }
  return removed;
}

/**
 * Read `put-<token>.bin` whole, then remove it. Refused, untouched, unless it is a regular file of this user's, with
 * one name, that no other user can read; refused as too large past `maxBytes` (the payload only grows when sealed).
 */
export function takePutPayload(folder: WarmStartFolder, token: string, maxBytes: number): Uint8Array {
  const name = putFileName(checkedToken(token));
  if (!folderPresent(folder)) throw new WarmStartFileError('warm_start_file_missing', 'no payload file for this token');
  const path = pathJoin(folder.dir, name);
  // Opening without following a link is POSIX's; elsewhere the name is examined first.
  if (!POSIX_MODES && lstatSync(path, { throwIfNoEntry: false })?.isSymbolicLink() === true) throw unsafe('the payload file is a link');
  let fd: number;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  } catch (e) {
    if (errCode(e) === 'ENOENT') throw new WarmStartFileError('warm_start_file_missing', 'no payload file for this token');
    throw unsafe(errCode(e) === 'ELOOP' ? 'the payload file is a link' : 'the payload file could not be opened');
  }
  const chunks: Buffer[] = [];
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw unsafe('the payload file is not a regular file');
    if (st.nlink !== 1) throw unsafe('the payload file has another name (a hard link)');
    if (POSIX_MODES && st.uid !== process.getuid?.()) throw unsafe('the payload file belongs to another user');
    if (POSIX_MODES && (st.mode & 0o077) !== 0) throw unsafe('the payload file is open to other users: it must be private to this user (0600)');
    if (st.size > maxBytes) throw new WarmStartFileError('snapshot_too_large', 'the payload is larger than this identity\'s snapshots may be');
    let total = 0;
    for (;;) {
      const buf = Buffer.alloc(Math.min(1_048_576, maxBytes + 1 - total));
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      total += n;
      chunks.push(buf.subarray(0, n));
      if (total > maxBytes) throw new WarmStartFileError('snapshot_too_large', 'the payload is larger than this identity\'s snapshots may be');
    }
  } catch (e) {
    for (const c of chunks) c.fill(0);
    throw e;
  } finally {
    closeSync(fd);
  }
  dropPayload(folder, name);
  const payload = Buffer.concat(chunks);
  for (const c of chunks) c.fill(0);
  return payload;
}

/** Remove one payload file by name, if the folder may be touched and the file is there. */
function dropPayload(folder: WarmStartFolder, name: string): void {
  try {
    if (!folderPresent(folder)) return;
    unlinkSync(pathJoin(folder.dir, name));
  } catch {
    /* absent, or the folder may not be touched: nothing to remove here */
  }
}

/** Remove `put-<token>.bin`: every put does, whether or not its upload succeeded. */
export const dropPutPayload = (folder: WarmStartFolder, token: string): void => dropPayload(folder, putFileName(checkedToken(token)));

/** Remove `latest-<token>.bin`, so a restore that fails, or finds no snapshot, leaves none behind for its token. */
export const dropLatestPayload = (folder: WarmStartFolder, token: string): void => dropPayload(folder, latestFileName(checkedToken(token)));

/**
 * Write a restored payload to `latest-<token>.bin`: a temporary file of this user's alone (0600), written and synced,
 * then renamed over the name, so SHM never reads a partial file. The folder is created private (0700) when absent, in
 * a tenant folder this package may write.
 */
export function writeLatestPayload(folder: WarmStartFolder, token: string, payload: Uint8Array): void {
  const name = latestFileName(checkedToken(token));
  if (!folderPresent(folder)) {
    ensureTenantDir(folder.agentIdHash, folder.env);
    try {
      mkdirSync(folder.dir, { mode: 0o700 });
    } catch (e) {
      if (errCode(e) !== 'EEXIST') throw e;
    }
    if (!folderPresent(folder)) throw unsafe('the warm-start folder could not be created');
  }
  const tmpName = `.${name}.${randomBytes(6).toString('hex')}.tmp`;
  const tmp = pathJoin(folder.dir, tmpName);
  const tmpFd = openSync(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
  try {
    for (let off = 0; off < payload.length; ) off += writeSync(tmpFd, payload, off, payload.length - off);
    fsyncSync(tmpFd);
  } catch (e) {
    closeSync(tmpFd);
    dropPayload(folder, tmpName);
    throw e;
  }
  closeSync(tmpFd);
  try {
    renameSync(tmp, pathJoin(folder.dir, name));
  } catch (e) {
    try {
      unlinkSync(tmp);
    } catch {
      /* already gone */
    }
    throw e;
  }
}
