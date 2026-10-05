/**
 * One small cross-process lock, used by every file this package replaces in a tenant directory.
 *
 * It exists once because two copies of a lock drift: a fix to one leaves the other holding a file the first has
 * already taken over. Callers bring their own waiting time — a writer on a server's event loop gives up quickly and
 * writes again at its next change, while a writer that must not lose its turn waits longer.
 */
import { randomBytes } from 'node:crypto';
import { readFileSync, statSync, unlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';

/** A lock whose holder has not touched it for this long is taken over, whoever it names. */
export const LOCK_STALE_MS = 30_000;
/** A lock file that does not name a process is given this long before it is treated as abandoned. */
export const LOCK_MALFORMED_GRACE_MS = 1_000;
const WAIT_CELL = new Int32Array(new SharedArrayBuffer(4));

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/**
 * The rule every lock here is taken over by, in one place: a lock whose holder has not touched it for
 * {@link LOCK_STALE_MS}, or whose holder process is gone, is removed (only if it still names the same holder). A token
 * that names a host (the lease's does) is judged by its process only on that host: a process id means nothing across
 * hosts or containers sharing a directory, so such a lock waits out its staleness instead.
 * Returns null when the lock is gone or was removed, else the holder as a message names it.
 */
function clearIfAbandoned(lock: string, deadAfterMs = 0): string | null {
  let holder: string;
  let age: number;
  try {
    holder = readFileSync(lock, 'utf8');
    age = Date.now() - statSync(lock).mtimeMs;
  } catch (e) {
    // Gone between the create and the read: free. THERE BUT UNREADABLE (another user's file, say): held by a holder
    // no one here can name, and never removed, since whose it is cannot be checked. A caller with a deadline gives up
    // at it; taking "unreadable" for "gone" retried such a lock for ever, past every deadline.
    return (e as NodeJS.ErrnoException).code === 'ENOENT' ? null : 'unknown';
  }
  const parts = holder.split(' ');
  const pid = Number(parts[0]);
  const wellFormed = Number.isInteger(pid) && pid > 0;
  const here = parts.length < 4 || parts.slice(3).join(' ') === hostname();
  // A dead process counts only once the lock has also gone `deadAfterMs` without a touch: a process id is checked in
  // this process's namespace, and a container that shares this host's name but not its process ids would otherwise
  // see a live, refreshing holder as dead.
  if (age > LOCK_STALE_MS || (wellFormed ? here && (deadAfterMs === 0 || age >= deadAfterMs) && !processAlive(pid) : age > LOCK_MALFORMED_GRACE_MS)) {
    try { if (readFileSync(lock, 'utf8') === holder) unlinkSync(lock); } catch { /* its owner or another waiter got there first */ }
    return null;
  }
  return wellFormed ? String(pid) : 'unknown';
}

/** Run `fn` holding `lock`: created with `wx`, taken over when its holder is gone or it is stale. */
export function withFileLock<T>(lock: string, waitMs: number, fn: () => T): T {
  const token = `${process.pid} ${Date.now()} ${randomBytes(8).toString('hex')}`;
  const deadline = Date.now() + waitMs;
  for (;;) {
    try {
      writeFileSync(lock, token, { mode: 0o600, flag: 'wx' });
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    }
    const held = clearIfAbandoned(lock);
    if (held === null) continue;   // released between the create and the read, or abandoned and removed
    if (Date.now() > deadline) throw new Error(`${lock} is locked by process ${held}`);
    Atomics.wait(WAIT_CELL, 0, 0, 5);
  }
  try {
    return fn();
  } finally {
    try { if (readFileSync(lock, 'utf8') === token) unlinkSync(lock); } catch { /* already gone */ }
  }
}

/**
 * A lock HELD across operations: one holder for as long as it keeps the file fresh. The share feed's writer holds one
 * per tenant directory (`feed.lock`), so one process polls and writes that directory's event files.
 *
 * Same takeover rule as {@link withFileLock}. The holder refreshes by touching the file, never by writing it: after a
 * takeover the file is the NEW holder's, and a write would replace that holder's token with this one, leaving two
 * processes each believing it holds the lease. A touch at worst keeps the new holder's lease fresh, and the next check
 * finds the token is not ours.
 */
export class FileLease {
  private token: string | null = null;

  /** `deadAfterMs`: a holder whose process is gone is taken over only once the lease is this long untouched as well. */
  constructor(readonly path: string, private readonly deadAfterMs = 0) {}

  /** Whether this process holds the lease, as of the last check. */
  get held(): boolean {
    return this.token !== null;
  }

  /**
   * Take the lease, or confirm it is still ours. `busy` when another live holder has it; `unavailable` when the file
   * cannot be created at all (a missing or read-only directory), which waiting will not change.
   */
  acquire(): 'held' | 'busy' | 'unavailable' {
    if (this.token !== null) {
      if (this.holds()) return 'held';
      this.token = null;
    }
    const token = `${process.pid} ${Date.now()} ${randomBytes(8).toString('hex')} ${hostname()}`;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        writeFileSync(this.path, token, { mode: 0o600, flag: 'wx' });
        this.token = token;
        return 'held';
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') return 'unavailable';
      }
      if (clearIfAbandoned(this.path, this.deadAfterMs) !== null) return 'busy';
    }
    return 'busy';
  }

  /** Whether the file still names this holder. */
  holds(): boolean {
    if (this.token === null) return false;
    try {
      return readFileSync(this.path, 'utf8') === this.token;
    } catch {
      return false;
    }
  }

  /** Keep the lease fresh; false (and no longer held) when it was lost. */
  refresh(): boolean {
    if (!this.holds()) {
      this.token = null;
      return false;
    }
    try {
      const t = new Date();
      utimesSync(this.path, t, t);
    } catch { /* checked below */ }
    if (this.holds()) return true;
    this.token = null;
    return false;
  }

  /** Give the lease up, removing the file only while it is still ours. */
  release(): void {
    try { if (this.holds()) unlinkSync(this.path); } catch { /* already gone */ }
    this.token = null;
  }
}
