/**
 * One small cross-process lock, used by every file this package replaces in a tenant directory.
 *
 * It exists once because two copies of a lock drift: a fix to one leaves the other holding a file the first has
 * already taken over. Callers bring their own waiting time — a writer on a server's event loop gives up quickly and
 * writes again at its next change, while a writer that must not lose its turn waits longer.
 */
import { randomBytes } from 'node:crypto';
import { readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';

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
    let holder: string;
    let age: number;
    try {
      holder = readFileSync(lock, 'utf8');
      age = Date.now() - statSync(lock).mtimeMs;
    } catch {
      continue;   // released between the create and the read
    }
    const pid = Number(holder.split(' ')[0]);
    const wellFormed = Number.isInteger(pid) && pid > 0;
    if (age > LOCK_STALE_MS || (wellFormed ? !processAlive(pid) : age > LOCK_MALFORMED_GRACE_MS)) {
      try { if (readFileSync(lock, 'utf8') === holder) unlinkSync(lock); } catch { /* its owner or another waiter got there first */ }
      continue;
    }
    if (Date.now() > deadline) throw new Error(`${lock} is locked by process ${wellFormed ? pid : 'unknown'}`);
    Atomics.wait(WAIT_CELL, 0, 0, 5);
  }
  try {
    return fn();
  } finally {
    try { if (readFileSync(lock, 'utf8') === token) unlinkSync(lock); } catch { /* already gone */ }
  }
}
