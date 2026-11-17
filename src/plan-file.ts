/**
 * The plan saved from the server (0.15.0): `$SAIHM_HOME/plan.<first 16 of the agent ID>.json`, beside the key file, the
 * sequence marks and the kept sign-in. When a free sign-in's answer says this identity holds an active paid
 * subscription, the client switches to that plan and saves it here, so the next session starts on it: one sign-in, not
 * a free one and then the paid one. It holds no secret: a plan name, a payment method, and when it was saved.
 *
 * It applies only where the plan would otherwise be FREE: a paid SAIHM_TIER, or an identity token that carries a paid
 * plan, always wins (see `bootFromEnv`). A paid sign-in the endpoint refuses for want of an active subscription removes
 * it, and the client goes back to the free plan.
 *
 * NOTHING HERE TRUSTS THE FILE, as for the kept sign-in: it is used only when it is a regular file of this user's, with
 * one name, that no other user can read or write (0600), small, holding exactly what this package writes, for this
 * agent ID, naming a plan and a payment method from the closed sets below. Anything else is ignored, never repaired or
 * reported, and the next save replaces it. The worst a planted file can do is name a plan this identity does not hold,
 * which costs one refused sign-in and removes the file. Every failure here is silent.
 */
import { randomBytes } from 'node:crypto';
import { closeSync, constants as fsConstants, fstatSync, lstatSync, mkdirSync, openSync, readSync, renameSync, unlinkSync, writeFileSync, type Stats } from 'node:fs';
import { dirname } from 'node:path';
import { withFileLock } from './file-lock.js';

const POSIX_MODES = process.platform !== 'win32';
/** Above this the file is not one this package wrote: refused unread. */
export const MAX_PLAN_FILE_BYTES = 4 * 1024;
/** Short, as for the kept sign-in: the critical section is one small write. */
const LOCK_WAIT_MS = 1_000;
const KIND = 'saihm-plan';
const KEYS = ['kind', 'version', 'agentIdHash', 'tier', 'paymentMethod', 'source', 'savedAt'] as const;

/** The paid plans a server's answer may name (the monthly plans `upgrade` sells). */
export const PAID_PLAN_TIERS: readonly string[] = ['PRO', 'PRO_FAST', 'ENTERPRISE', 'ENTERPRISE_FAST'];
/** The subscription rails a server's answer may name. Stablecoin is not a subscription, so it is never reported. */
export const PAID_PLAN_METHODS: readonly string[] = ['stripe', 'paypal', 'paystack'];

/** A paid plan, as a free sign-in's answer reports it: both fields from the closed sets above. */
export interface PaidPlan {
  tier: string;
  paymentMethod: string;
}

/**
 * The plan `v` names, when it is a plain object whose `tier` and `paymentMethod` are in the closed sets above; else
 * undefined. A fresh object of exactly those two fields: nothing else the endpoint sent is carried on.
 */
export function paidPlanOf(v: unknown): PaidPlan | undefined {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return undefined;
  const { tier, paymentMethod } = v as Record<string, unknown>;
  if (typeof tier !== 'string' || !PAID_PLAN_TIERS.includes(tier)) return undefined;
  if (typeof paymentMethod !== 'string' || !PAID_PLAN_METHODS.includes(paymentMethod)) return undefined;
  return { tier, paymentMethod };
}

export class PlanFile {
  /**
   * `uid` is whose file it must be: this process's user. A test names another to stand for a file of another user's,
   * which only the superuser could make.
   */
  constructor(
    readonly path: string,
    private readonly agentIdHash: string,
    private readonly uid: number | undefined = process.getuid?.(),
  ) {}

  /** A file this package may read: a regular file of this user's, with one name, private to this user, small. */
  private acceptable(st: Stats): boolean {
    if (!st.isFile() || st.nlink !== 1 || st.size > MAX_PLAN_FILE_BYTES) return false;
    return !POSIX_MODES || (st.uid === this.uid && (st.mode & 0o077) === 0);
  }

  /** A file `discard` may remove: a regular file of this user's, small, whatever its mode. */
  private removable(st: Stats): boolean {
    if (!st.isFile() || st.size > MAX_PLAN_FILE_BYTES) return false;
    return !POSIX_MODES || st.uid === this.uid;
  }

  /** The file parsed as JSON, when `fits` holds for it before and after it is opened; else undefined. Throws. */
  private parsed(fits: (st: Stats) => boolean): unknown {
    // Examined before it is opened, so a pipe or a device is never opened; opened without following a link and without
    // blocking; examined again once open, since the name may have been replaced in between.
    if (POSIX_MODES && !fits(lstatSync(this.path))) return undefined;
    const fd = openSync(this.path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0));
    const buf = Buffer.alloc(MAX_PLAN_FILE_BYTES + 1);
    let total = 0;
    try {
      if (!fits(fstatSync(fd))) return undefined;
      while (total < buf.length) {
        const n = readSync(fd, buf, total, buf.length - total, null);
        if (n === 0) break;
        total += n;
      }
    } finally {
      closeSync(fd);
    }
    return total > MAX_PLAN_FILE_BYTES ? undefined : JSON.parse(buf.subarray(0, total).toString('utf8'));
  }

  /** The plan saved for this agent ID, or undefined. Never throws. */
  read(): PaidPlan | undefined {
    try {
      const doc = this.parsed((st) => this.acceptable(st));
      if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return undefined;
      const d = doc as Record<string, unknown>;
      const own = Object.keys(d);
      if (own.length !== KEYS.length || !KEYS.every((k) => Object.prototype.hasOwnProperty.call(d, k))) return undefined;
      if (d.kind !== KIND || d.version !== 1 || d.agentIdHash !== this.agentIdHash || d.source !== 'server') return undefined;
      if (typeof d.savedAt !== 'string' || Number.isNaN(Date.parse(d.savedAt))) return undefined;
      return paidPlanOf(d);
    } catch {
      return undefined;
    }
  }

  /** Save `plan` for this agent ID, replacing whatever the file held. Returns whether it was written. Never throws. */
  keep(plan: PaidPlan): boolean {
    const valid = paidPlanOf(plan);
    if (valid === undefined) return false;
    const doc = JSON.stringify({
      kind: KIND,
      version: 1,
      agentIdHash: this.agentIdHash,
      tier: valid.tier,
      paymentMethod: valid.paymentMethod,
      source: 'server',
      savedAt: new Date().toISOString(),
    });
    try {
      // The folder the sequence marks already use: made 0700 if an identity token or an inline secret booted here first.
      mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
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
      return true;
    } catch {
      return false; // a held lock, a full disk or a folder that cannot be written: the plan holds for this session only
    }
  }

  /**
   * Remove the file when it holds this package's plan for this agent ID, whatever plan it names. Anything else at this
   * name is left as it is, and no other file is touched. With no file there, nothing is created, not even the lock.
   * Returns whether it removed the file. Never throws.
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
        const d = this.parsed((st) => this.removable(st));
        if (typeof d !== 'object' || d === null || Array.isArray(d)) return;
        const doc = d as Record<string, unknown>;
        if (doc.kind !== KIND || doc.agentIdHash !== this.agentIdHash) return;
        unlinkSync(this.path);
        removed = true;
      });
    } catch {
      /* a held lock or a folder that cannot be written: the file stays, and a refused sign-in on its plan tries again */
    }
    return removed;
  }
}
