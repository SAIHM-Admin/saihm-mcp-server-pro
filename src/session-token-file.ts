/**
 * The sign-in kept between sessions (0.14.3): `$SAIHM_HOME/session.<first 16 of the agent ID>.json`, beside the default
 * key file. A session that starts on this device while an earlier session's sign-in is still good uses it instead of
 * signing in again: one sign-in per device per hour, instead of one per session, for a team behind one office address.
 *
 * Kept for the default key only, which is why it may sit here: that key can mint any number of these tokens, so reading
 * this file gives nothing that reading the key beside it does not. The token lives as long as the endpoint says (an hour
 * on the hosted service). SAIHM_SESSION_CACHE=0 keeps it in memory only, as before 0.14.3, and removes the file this
 * identity kept earlier when the identity loads (see `discard`), so the setting leaves no sign-in on disk.
 *
 * NOTHING HERE TRUSTS THE FILE. It is used only when it is a regular file of this user's, with one name, that no other
 * user can read or write (0600), no larger than a sign-in could make it, holding exactly what this package writes, for
 * this endpoint, this agent ID, this plan and this payment method. Anything else is ignored, never repaired or reported,
 * and the next sign-in replaces it. Whether the token is still good is the caller's to decide, from the token's own
 * expiry. A token the endpoint refuses is removed, by a writer holding the same lock as every other writer. The token
 * is never printed, logged or put in a result: every failure here is silent and costs one sign-in.
 */
import { randomBytes } from 'node:crypto';
import { closeSync, constants as fsConstants, fstatSync, lstatSync, openSync, readSync, renameSync, unlinkSync, writeFileSync, type Stats } from 'node:fs';
import { withFileLock } from './file-lock.js';

const POSIX_MODES = process.platform !== 'win32';
/** A token longer than this is not one this package keeps. */
export const MAX_SESSION_TOKEN_CHARS = 8 * 1024;
/** Above this the file is not one this package wrote: refused unread. */
export const MAX_SESSION_FILE_BYTES = 16 * 1024;
/** Short, as for the share map: the critical section is one small write, and a lost turn costs one sign-in. */
const LOCK_WAIT_MS = 1_000;
const KIND = 'saihm-session-token';
/** A compact JWS, as the endpoint signs one: three base64url parts. Anything else is not kept or used. */
const TOKEN_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/** What a kept sign-in is for. A file kept for anything else is not used. */
export interface SessionBinding {
  endpoint: string;
  agentIdHash: string;
  tier: string | undefined;
  paymentMethod: string | undefined;
}

const KEYS = ['kind', 'version', 'endpoint', 'agentIdHash', 'tier', 'paymentMethod', 'token'] as const;

export class SessionTokenFile {
  /**
   * `uid` is whose file it must be: this process's user. A test names another to stand for a file of another user's,
   * which only the superuser could make.
   */
  constructor(
    readonly path: string,
    private readonly binding: () => SessionBinding,
    private readonly uid: number | undefined = process.getuid?.(),
  ) {}

  /** A file this package may read: a regular file of this user's, with one name, private to this user, small. */
  private acceptable(st: Stats): boolean {
    if (!st.isFile() || st.nlink !== 1 || st.size > MAX_SESSION_FILE_BYTES) return false;
    return !POSIX_MODES || (st.uid === this.uid && (st.mode & 0o077) === 0);
  }

  /**
   * A file `discard` may examine: a regular file of this user's, small. Its mode and any other name it has do not
   * matter there: a sign-in another user could read is the first one to remove, and unlinking removes only this name.
   */
  private removable(st: Stats): boolean {
    if (!st.isFile() || st.size > MAX_SESSION_FILE_BYTES) return false;
    return !POSIX_MODES || st.uid === this.uid;
  }

  /** The file parsed as JSON, when `fits` holds for it before and after it is opened; else undefined. Throws. */
  private parsed(fits: (st: Stats) => boolean): unknown {
    // Examined before it is opened, so a pipe or a device is never opened; opened without following a link and
    // without blocking; examined again once open, since the name may have been replaced in between.
    if (POSIX_MODES && !fits(lstatSync(this.path))) return undefined;
    const fd = openSync(this.path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0));
    const buf = Buffer.alloc(MAX_SESSION_FILE_BYTES + 1);
    let text: string | undefined;
    try {
      if (!fits(fstatSync(fd))) return undefined;
      let total = 0;
      while (total < buf.length) {
        const n = readSync(fd, buf, total, buf.length - total, null);
        if (n === 0) break;
        total += n;
      }
      if (total <= MAX_SESSION_FILE_BYTES) text = buf.subarray(0, total).toString('utf8');
    } finally {
      buf.fill(0);
      closeSync(fd);
    }
    return text === undefined ? undefined : JSON.parse(text);
  }

  /** The token kept for this binding, or undefined. Never throws. */
  read(): string | undefined {
    try {
      return this.tokenOf(this.parsed((st) => this.acceptable(st)));
    } catch {
      return undefined;
    }
  }

  /** The token a parsed file holds, when it is exactly what `keep` writes for this binding. */
  private tokenOf(doc: unknown): string | undefined {
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return undefined;
    const d = doc as Record<string, unknown>;
    const own = Object.keys(d);
    if (own.length !== KEYS.length || !KEYS.every((k) => Object.prototype.hasOwnProperty.call(d, k))) return undefined;
    const b = this.binding();
    if (d.kind !== KIND || d.version !== 1) return undefined;
    if (d.endpoint !== b.endpoint || d.agentIdHash !== b.agentIdHash) return undefined;
    if (d.tier !== (b.tier ?? null) || d.paymentMethod !== (b.paymentMethod ?? null)) return undefined;
    const t = d.token;
    return typeof t === 'string' && t.length <= MAX_SESSION_TOKEN_CHARS && TOKEN_SHAPE.test(t) ? t : undefined;
  }

  /** Keep `token` for this binding, replacing whatever the file held. Never throws: a sign-in not kept costs one more. */
  keep(token: string): void {
    if (token.length > MAX_SESSION_TOKEN_CHARS || !TOKEN_SHAPE.test(token)) return;
    const b = this.binding();
    const doc = JSON.stringify({
      kind: KIND,
      version: 1,
      endpoint: b.endpoint,
      agentIdHash: b.agentIdHash,
      tier: b.tier ?? null,
      paymentMethod: b.paymentMethod ?? null,
      token,
    });
    try {
      withFileLock(`${this.path}.lock`, LOCK_WAIT_MS, () => {
        // A new file, 0600 from its first byte, renamed over the old one: a reader sees the old file or the new one,
        // never part of either, and a file of the wrong mode or owner is replaced rather than written into.
        const tmp = `${this.path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
        writeFileSync(tmp, doc, { mode: 0o600, flag: 'wx' });
        try {
          renameSync(tmp, this.path);
        } catch (e) {
          try {
            unlinkSync(tmp);
          } catch {
            /* already gone */
          }
          throw e;
        }
      });
    } catch {
      /* a held lock, a full disk or a folder that cannot be written: this session keeps its sign-in in memory */
    }
  }

  /**
   * Remove the file when it holds a sign-in this package kept for this binding's agent ID, for any endpoint, plan or
   * payment method (SAIHM_SESSION_CACHE=0, 0.14.3): a regular file of this user's, no larger than a sign-in could make
   * it, holding this package's document for that agent ID. Anything else at this name - another document, a link, a
   * folder - is left as it is, and no other file is touched, the key beside it included. With no file there, nothing
   * is created, not even the lock. Returns whether it removed the file. Never throws.
   */
  discard(): boolean {
    try {
      lstatSync(this.path);
    } catch {
      return false;
    }
    let removed = false;
    try {
      withFileLock(`${this.path}.lock`, LOCK_WAIT_MS, () => {
        // Read under the writers' lock, so a sign-in another session keeps at this moment is either the one examined
        // here or one written after the removal, never one swapped in between the check and the removal.
        const d = this.parsed((st) => this.removable(st));
        if (typeof d !== 'object' || d === null || Array.isArray(d)) return;
        const doc = d as Record<string, unknown>;
        if (doc.kind !== KIND || doc.version !== 1 || doc.agentIdHash !== this.binding().agentIdHash) return;
        unlinkSync(this.path);
        removed = true;
      });
    } catch {
      /* a held lock, an unreadable file or a folder that cannot be written: the file stays, and this setting never uses it */
    }
    return removed;
  }

  /** Remove the file while it still holds `token`: one another session has since replaced it with is kept. */
  drop(token: string): void {
    try {
      withFileLock(`${this.path}.lock`, LOCK_WAIT_MS, () => {
        if (this.read() === token) unlinkSync(this.path);
      });
    } catch {
      /* the next sign-in replaces it, and a refused token is never used again by this process */
    }
  }
}
