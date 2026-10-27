// The recipient's identity record as a FILE (0.14.3): `saihm_share` takes the full path of the JSON document that
// `identity-record` writes, so an agent never copies the record's ~13 KB of hex into a call.
//
// The path is chosen by the agent, so it may name anything this user can read: a key, a token, an environment file.
// Nothing read from the file is ever rendered. Every refusal is one of the fixed sentences below, naming neither the
// path nor a byte of the content (a JSON parser's own message quotes the text it stopped at, so it is never passed on).
// Only a regular file is opened, and it is opened without blocking: a pipe, a device, a socket or a folder, named
// directly or through a link, is refused from its metadata and never read. A file larger than an identity record can
// be is refused unread, and the read itself stops one byte past the bound, so a file that reports no size (as files
// in /proc do) cannot make it read more.
import { closeSync, constants as fsConstants, fstatSync, openSync, readSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { decodeIdentityRecord, fromHex, verifyIdentityRecord, type WireIdentityRecord } from '@saihm/client-pro';
import { SaihmEndpointError } from './client.js';

/** The largest record file read: a record is about 13 KB, so this leaves room for any indentation and nothing more. */
export const MAX_RECORD_FILE_BYTES = 64 * 1024;

/** The code of every refusal of the file itself. */
export const RECORD_FILE_REFUSED = 'bad_recipient_record_file';

/** The record and agent ID a record file holds, exactly as written there. */
export interface RecordFile {
  agentIdHash: string;
  identityRecord: WireIdentityRecord;
}

const refuse = (why: string): SaihmEndpointError =>
  new SaihmEndpointError(0, RECORD_FILE_REFUSED, `Nothing was shared: recipientRecordFile ${why}.`);

const NOT_A_RECORD = 'is not a SAIHM identity record (the JSON file the identity-record command writes)';
const TOO_LARGE = `is larger than an identity record can be (${MAX_RECORD_FILE_BYTES / 1024} KB)`;
const NOT_REGULAR = 'is not a regular file';

/** A system error code, as Node names it (ENOENT, EACCES, ...), or nothing: never a message, which can quote the path. */
function errnoOf(e: unknown): string {
  const c = (e as { code?: unknown } | null)?.code;
  return typeof c === 'string' && /^E[A-Z0-9_]{1,31}$/.test(c) ? ` (${c})` : '';
}

const HASH_HEX = /^[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]+$/;

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;

/** True when `o` has exactly these keys as its own: no more, no fewer. */
const hasExactly = (o: Record<string, unknown>, keys: readonly string[]): boolean => {
  const own = Object.keys(o);
  return own.length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(o, k));
};

/** The record a parsed document holds when it is exactly what `identity-record` writes, in canonical lowercase hex. */
function recordOf(doc: unknown): RecordFile | undefined {
  if (!isPlainObject(doc) || !hasExactly(doc, ['kind', 'version', 'agentIdHash', 'identityRecord'])) return undefined;
  if (doc.kind !== 'saihm-identity-record' || doc.version !== 1) return undefined;
  const { agentIdHash, identityRecord: r } = doc;
  if (typeof agentIdHash !== 'string' || !HASH_HEX.test(agentIdHash)) return undefined;
  if (!isPlainObject(r) || !hasExactly(r, ['mldsaPubKey', 'mlkemPubKey', 'mlkemPubKeySelfSig'])) return undefined;
  const { mldsaPubKey, mlkemPubKey, mlkemPubKeySelfSig } = r;
  for (const f of [mldsaPubKey, mlkemPubKey, mlkemPubKeySelfSig]) if (typeof f !== 'string' || !HEX.test(f)) return undefined;
  const identityRecord = { mldsaPubKey, mlkemPubKey, mlkemPubKeySelfSig } as WireIdentityRecord;
  try {
    // Each key and the signature at its exact length, by the same decoder the share uses.
    decodeIdentityRecord(identityRecord);
  } catch {
    return undefined;
  }
  return { agentIdHash, identityRecord };
}

/**
 * Read and check the record file at `path`: a regular file named by its full path, at most MAX_RECORD_FILE_BYTES,
 * holding exactly the document `identity-record` writes, whose keys hash to its agent ID and whose self-signature
 * verifies. Asks nothing of the endpoint. Throws a SaihmEndpointError (status 0) carrying only a fixed reason.
 *
 * The check here is the file's own; the share checks the record again, against the agent ID it is given, before it
 * binds anything to it.
 */
export function readRecordFile(path: string): RecordFile {
  // A relative path resolves against the server's working directory, which the agent naming it does not know: it
  // could read a different file of the same name, and share with whoever that file names.
  if (!isAbsolute(path)) throw refuse('must be the full path of the file (a relative path, or one starting with ~, is not used)');
  let st;
  try {
    st = statSync(path);
  } catch (e) {
    throw refuse(`could not be read${errnoOf(e)}`);
  }
  if (!st.isFile()) throw refuse(NOT_REGULAR);
  if (st.size > MAX_RECORD_FILE_BYTES) throw refuse(TOO_LARGE);
  let fd: number;
  try {
    // Without blocking, and never as a controlling terminal: what was a regular file a moment ago may not be now.
    fd = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0) | (fsConstants.O_NOCTTY ?? 0));
  } catch (e) {
    throw refuse(`could not be read${errnoOf(e)}`);
  }
  const buf = Buffer.alloc(MAX_RECORD_FILE_BYTES + 1);
  let total = 0;
  let doc: unknown;
  try {
    try {
      if (!fstatSync(fd).isFile()) throw refuse(NOT_REGULAR);
      while (total < buf.length) {
        const n = readSync(fd, buf, total, buf.length - total, null);
        if (n === 0) break;
        total += n;
      }
    } catch (e) {
      throw e instanceof SaihmEndpointError ? e : refuse(`could not be read${errnoOf(e)}`);
    } finally {
      closeSync(fd);
    }
    if (total > MAX_RECORD_FILE_BYTES) throw refuse(TOO_LARGE);
    try {
      doc = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buf.subarray(0, total)));
    } catch {
      doc = undefined;
    }
  } finally {
    // What was read may be anything this user can read; the copy here is not kept.
    buf.fill(0);
  }
  const record = recordOf(doc);
  if (record === undefined) throw refuse(NOT_A_RECORD);
  try {
    verifyIdentityRecord(decodeIdentityRecord(record.identityRecord), fromHex(record.agentIdHash));
  } catch {
    throw refuse('holds a record that does not verify (its agent ID, keys and signature do not match): ask your colleague for a new one');
  }
  return record;
}
