/**
 * PC-RECALL-MODEL - a model-based check of edits, reads, erasures and the recall copy across devices.
 *
 * A reference model of the hosted store (one current version per cell id; a write at or below the cell's high-water
 * sequence refused 409 BLIND_STALE_SEQ; an erasure deletes the version and keeps the mark, so a write past it stores the
 * memory again; the version listing reads the key records, so a storage fault never hides a cell from it, while a read
 * of a faulted cell fails and recall-all and the delta leave it out) is driven by seeded random sequences of operations,
 * in two worlds: this device with the recall copy on, and with it off. Each world is judged against its own store:
 *
 * - I1 lost update: a stored edit replaced a version, written by another device, that this process never saw.
 * - I2 false refusal: the endpoint refused an edit while the store held exactly the version this process last saw.
 * - I4 recall: a recall answers exactly the versions the store holds (a faulted cell may be missing; with the copy on, a
 *   cell this device erased stays out of the copy, the documented limitation).
 * - I5 text: a refusal says what is true now (changed / erased / cellId used).
 * - I9 a refusal made on this device with nothing asked is the erased text, and true: the memory was gone at some point
 *   since this process last saw it live.
 * - I8R an edit saved an erased memory again although this process knew it erased (its own read found it gone, or a
 *   forget, the feed, a read or a copy-on recall had shown it). Without any such record (the same session, erased
 *   elsewhere, nothing read since) only the endpoint can refuse it: counted, not failed.
 *
 * Copy on and copy off are also compared (counted only): they may differ where the copy knows more (its listing shows
 * a memory gone) or less (a memory this device erased and another device saved again is kept out of the copy).
 *
 * The suite runs a short deterministic campaign. MODEL_SEQS, MODEL_LEN, MODEL_SEED, MODEL_PAGE and MODEL_MIX
 * (`plain` | `erasures`) scale it; MODEL_TEXTS=0 judges only I1 and I4, for running it against an older client.
 */
import { after, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deriveIdentity, encodeIdentityRecord, toHex, type WireEnvelope } from '@saihm/client-pro';
import { SaihmProClient, SaihmEndpointError, type RecalledCell } from '../src/client.js';
import { failText } from '../src/render_fence.js';

const ROOT = mkdtempSync(join(tmpdir(), 'saihm-model-'));
after(() => rmSync(ROOT, { recursive: true, force: true }));
const MASTER = new Uint8Array(32).fill(41);
const RECIPIENT = deriveIdentity(new Uint8Array(32).fill(42));
const CHANGED = 'This memory has changed since this device last read or saved it, so your edit was not saved.';
const ERASED = 'This memory was erased, so your edit was not saved.';
const USED = 'This cellId was already used by a memory saved earlier';
const TEXTS = process.env.MODEL_TEXTS !== '0';

// ── the reference store ─────────────────────────────────────────────────────────────────────────────────────────────
interface Ver { wire: WireEnvelope; seq: bigint; commitment: string; writer: 'A' | 'B'; acked: boolean }
type Answer = { status: number; body: unknown } | 'drop';
class Store {
  s1 = new Map<string, Ver>();
  hwm = new Map<string, bigint>();
  history = new Map<string, Ver[]>();
  faulted = new Set<string>();
  writer: 'A' | 'B' = 'A';
  dropNextA = false;
  page = 3;
  log: string[] = [];
  handle(method: string, p: Record<string, unknown>): Answer {
    if (method === 'saihm_remember') {
      const w = p.wire as WireEnvelope;
      const c = createHash('sha256').update(Buffer.from(w.ciphertext, 'hex')).digest('hex');
      if (w.publicMeta.commitmentHash.toLowerCase() !== c) return { status: 400, body: { error: 'BLIND_VERIFY_FAILED' } };
      const seq = BigInt(w.seq);
      this.log.push(`remember ${this.writer}`);
      const mark = this.hwm.get(w.cellId);
      if (mark !== undefined && seq <= mark) return { status: 409, body: { error: 'BLIND_STALE_SEQ', reason: 'seq <= high-water mark' } };
      const drop = this.writer === 'A' && this.dropNextA;
      this.dropNextA = false;
      const v: Ver = { wire: w, seq, commitment: c, writer: this.writer, acked: !drop };
      this.s1.set(w.cellId, v);
      this.hwm.set(w.cellId, seq);
      this.history.set(w.cellId, [...(this.history.get(w.cellId) ?? []), v]);
      if (drop) return 'drop';
      return { status: 200, body: { cellId: w.cellId, shardId: 's', seq: w.seq, commitmentHash: c } };
    }
    if (method === 'saihm_share') return { status: 200, body: { cellId: p.cellId, shared: true } };
    if (method === 'saihm_forget') {
      const id = p.id as string;
      this.log.push('forget');
      const existed = this.s1.delete(id);
      return { status: 200, body: { cellId: id, shardId: 's', complete: existed, ...(existed ? { destructionAnchor: `a-${this.log.length}` } : { reason: 'not-found' }), sharesPurged: 0, steps: [], epoch: '1' } };
    }
    if (method !== 'saihm_recall') return { status: 400, body: { error: 'unknown_method' } };
    if (p.listOnly === true) {
      this.log.push('list');
      const after = typeof p.after === 'string' ? p.after : undefined;
      const ids = [...this.s1.keys()].sort().filter((id) => after === undefined || id > after);
      const take = ids.slice(0, this.page);
      return {
        status: 200,
        body: {
          mode: 'list',
          cells: take.map((id) => ({ cellId: id, seq: String(this.hwm.get(id)), commitment: this.s1.get(id)!.commitment })),
          next: ids.length > take.length ? take[take.length - 1]! : null,
          asOf: new Date().toISOString(),
        },
      };
    }
    if (typeof p.cellId === 'string') {
      this.log.push('one');
      if (this.faulted.has(p.cellId)) return { status: 503, body: { error: 'BLIND_SHARD_UNAVAILABLE' } };
      const v = this.s1.get(p.cellId);
      return { status: 200, body: v ? { found: true, wire: v.wire } : { found: false } };
    }
    const rows = (ids: string[]): unknown[] =>
      ids.filter((id) => !this.faulted.has(id)).map((id) => ({ cellId: id, found: true, wire: this.s1.get(id)!.wire }));
    if (Array.isArray(p.knownCellIds)) {
      this.log.push('delta');
      const known = new Set(p.knownCellIds as string[]);
      return { status: 200, body: { mode: 'delta', added: rows([...this.s1.keys()].filter((id) => !known.has(id))), liveCellIds: [...this.s1.keys()] } };
    }
    this.log.push('all');
    return { status: 200, body: rows([...this.s1.keys()]) };
  }
}
async function serve(store: Store): Promise<{ url: string; close: () => Promise<void> }> {
  const sockets = new Set<Socket>();
  const server: Server = createServer((req, res) => {
    void (async () => {
      let body = '';
      for await (const c of req) body += c;
      const { method, params = {} } = JSON.parse(body) as { method: string; params?: Record<string, unknown> };
      const a = store.handle(method, params);
      if (a === 'drop') return void req.socket.destroy();
      const t = JSON.stringify(a.body);
      res.writeHead(a.status, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(t)) }).end(t);
    })();
  });
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`,
    close: () => new Promise<void>((r) => {
      for (const s of sockets) s.destroy();
      server.close(() => r());
    }),
  };
}

// ── one world: this device, with the copy on or off, against its own store ─────────────────────────────────────────
type Priv = { seq: { current(id: string): bigint | undefined; observedLiveThisRun(id: string): boolean } };
const P = (c: SaihmProClient): Priv => c as unknown as Priv;
interface Obs { seq: bigint; commitment: string }
class World {
  store = new Store();
  url = '';
  close: () => Promise<void> = async () => {};
  readonly dir: string;
  readonly feedDir: string;
  A!: SaihmProClient;
  obs = new Map<string, Obs>(); // what A's process last saw live of each cell
  goneSince = new Set<string>(); // gone at some point since A's process last saw it live (or since it started)
  recordable = new Set<string>(); // since then, A's process was shown or told it was erased
  feedNamed = new Set<string>(); // erased by this device: kept out of the copy for the rest of the run
  /** a memory saved as new gets its id from the client: the sequence's name for it, to that id */
  alias = new Map<string, string>();
  bad: string[] = [];
  a1 = 0;
  local = 0;
  constructor(readonly on: boolean, tag: string) {
    this.dir = mkdtempSync(join(ROOT, `${tag}-`));
    this.feedDir = join(this.dir, 'feed');
    mkdirSync(this.feedDir);
  }
  opts() {
    return { tier: 'PRO', seqStatePath: join(this.dir, 'seq.json'), ...(this.on ? { recallCachePath: join(this.dir, 'copy.json') } : {}) };
  }
  async start(): Promise<void> {
    const s = await serve(this.store);
    this.url = s.url;
    this.close = s.close;
    this.restart();
  }
  restart(): void {
    this.A = new SaihmProClient(this.url, 'Bearer test', MASTER, this.opts());
    this.obs.clear();
    this.recordable.clear();
    this.goneSince = new Set([...this.store.history.keys()].filter((id) => !this.store.s1.has(id)));
  }
  see(id: string, v: Obs | undefined): void {
    if (!v) return;
    this.obs.set(id, v);
    this.goneSince.delete(id);
    this.recordable.delete(id);
  }
}

const outcome = (e: unknown): string => (e instanceof SaihmEndpointError ? `ERR ${e.status}/${e.code}` : `ERR ${String((e as Error)?.message ?? e).slice(0, 40)}`);
const verOf = (v: Ver | undefined): Obs | undefined => (v ? { seq: v.seq, commitment: v.commitment } : undefined);

async function bWrite(w: World, id: string, text: string): Promise<string> {
  w.store.writer = 'B';
  try {
    await new SaihmProClient(w.url, 'Bearer test', MASTER, { tier: 'PRO' }).remember(text, { cellId: id });
    return 'stored';
  } catch (e) {
    return outcome(e);
  } finally {
    w.store.writer = 'A';
  }
}

type Op =
  | { k: 'recall' | 'restart' | 'aDrop' }
  | { k: 'edit' | 'create' | 'createNew' | 'one' | 'share' | 'bEdit' | 'bErase' | 'bRecreate' | 'aForget' | 'a2Forget' | 'fault'; id: string };

async function apply(w: World, op0: Op, n: number): Promise<string> {
  const op = 'id' in op0 && w.alias.has(op0.id) ? ({ ...op0, id: w.alias.get(op0.id)! } as Op) : op0;
  process.env.SAIHM_ERASURE_FEED_DIR = w.feedDir;
  const st = w.store;
  const before = st.log.length;
  let out: string;
  switch (op.k) {
    case 'recall': {
      const copyHeld = w.on && (w.A as unknown as { recallCache: { size: number } }).recallCache.size > 0;
      const faulted = new Set(st.faulted);
      try {
        const cells: RecalledCell[] = await w.A.recall();
        for (const c of cells) w.see(c.cellId, { seq: BigInt(c.seq), commitment: c.commitmentHash });
        // I4: exactly the store's versions; a faulted cell may be missing, and with the copy on one this device erased
        const got = new Map(cells.map((c) => [c.cellId, c.commitmentHash]));
        for (const [id, v] of st.s1) {
          const skip = faulted.has(id) || (w.on && w.feedNamed.has(id));
          if (got.has(id) ? got.get(id) !== v.commitment : !skip) w.bad.push(`I4 recall: ${id.slice(0, 4)} ${got.has(id) ? 'at another version' : 'left out'}`);
        }
        for (const id of got.keys()) if (!st.s1.has(id)) w.bad.push(`I4 recall answered ${id.slice(0, 4)}, which is gone`);
        if (copyHeld && faulted.size === 0) for (const id of st.history.keys()) if (!st.s1.has(id) && P(w.A).seq.current(id) !== undefined) w.recordable.add(id);
        out = 'ok ' + cells.filter((c) => !w.feedNamed.has(c.cellId)).map((c) => `${c.cellId.slice(0, 4)}@${c.seq}`).sort().join(',');
      } catch (e) {
        out = outcome(e);
      }
      st.faulted.clear();
      break;
    }
    case 'edit':
    case 'create': {
      const id = op.id;
      const observed = w.obs.get(id);
      const replaced = st.s1.get(id);
      const hwmBefore = st.hwm.get(id);
      const preRead = !P(w.A).seq.observedLiveThisRun(id);
      const mark = P(w.A).seq.current(id);
      const wasGone = w.goneSince.has(id);
      try {
        await w.A.remember(`#${n} ${op.k} ${id.slice(0, 4)}`, { cellId: id });
        out = 'stored';
      } catch (e) {
        out = outcome(e);
        const reqs = st.log.slice(before);
        const stale = e instanceof SaihmEndpointError && e.code === 'BLIND_STALE_SEQ';
        const t = failText(e);
        if (stale && reqs.length === 0) {
          w.local++;
          if (TEXTS && (!t.includes(ERASED) || t.includes('SAIHM endpoint'))) w.bad.push(`I5 local refusal text: ${t}`);
          if (!wasGone) w.bad.push(`I9 FALSE LOCAL REFUSAL of ${id.slice(0, 4)}: live throughout since this process last saw it`);
          if (st.s1.has(id)) w.goneSince.add(id); // a refused edit sees nothing
          break;
        }
        if (stale) {
          const wrote = reqs.some((r) => r.startsWith('remember'));
          const live = st.s1.has(id);
          // I2: refused although the store holds the version this process saw (a pre-read sees the live one)
          if (wrote && replaced !== undefined && hwmBefore === replaced.seq && (preRead || observed?.commitment === replaced.commitment)) {
            w.bad.push(`I2 FALSE REFUSAL of ${id.slice(0, 4)}: store @${replaced.seq} is what this process saw`);
          }
          const want = !preRead ? (live ? CHANGED : ERASED) : live ? CHANGED : mark !== undefined ? ERASED : USED;
          if (TEXTS && !t.includes(want)) w.bad.push(`I5 text for ${id.slice(0, 4)} (preRead=${preRead} live=${live}): ${t}`);
          if (preRead && replaced) w.see(id, verOf(replaced));
          if (!live) w.recordable.add(id);
        } else if (preRead && replaced) w.see(id, verOf(replaced)); // the write failed after its read of the live version
        break;
      }
      // I1: a stored edit replaced only the version this process last saw (or one nobody was told of)
      if (observed && replaced && replaced.commitment !== observed.commitment && replaced.acked) {
        w.bad.push(`I1 LOST UPDATE: ${id.slice(0, 4)} replaced ${replaced.writer}'s @${replaced.seq}, this process saw @${observed.seq}`);
      }
      if (op.k === 'edit' && !replaced && (st.history.get(id)?.length ?? 0) > 1 && (observed || mark !== undefined)) {
        if (TEXTS && (preRead || w.recordable.has(id))) w.bad.push(`I8R ERASURE UNDONE: ${id.slice(0, 4)} saved again although this process knew it erased`);
        else w.a1++;
      }
      w.see(id, verOf(st.s1.get(id)));
      break;
    }
    case 'one': {
      try {
        const c = await w.A.recallOne(op.id);
        if (c) w.see(c.cellId, { seq: BigInt(c.seq), commitment: c.commitmentHash });
        else w.recordable.add(op.id);
        out = c ? `ok @${c.seq}` : 'null';
      } catch (e) {
        out = outcome(e);
      }
      break;
    }
    case 'share': {
      try {
        await w.A.share({ cellId: op.id, recipientRecord: encodeIdentityRecord(RECIPIENT.identityRecord), recipientPinnedAgentIdHashHex: toHex(RECIPIENT.agentIdHash) });
        w.see(op.id, verOf(st.s1.get(op.id)));
        out = 'shared';
      } catch (e) {
        if (e instanceof SaihmEndpointError && e.code === 'cell_not_found') w.recordable.add(op.id);
        out = outcome(e);
      }
      break;
    }
    case 'createNew': {
      // saved as a new memory (no cellId): the client draws the id, and the memory is seen with no read
      try {
        const r = await w.A.remember(`#${n} new`);
        w.alias.set(op.id, r.cellId);
        w.see(r.cellId, verOf(st.s1.get(r.cellId)));
        out = 'stored';
      } catch (e) {
        out = outcome(e);
      }
      break;
    }
    case 'restart':
      w.restart();
      out = 'restarted';
      break;
    case 'aDrop':
      st.dropNextA = true;
      out = 'armed';
      break;
    case 'bEdit':
      out = 'B ' + (await bWrite(w, op.id, `B #${n}`));
      break;
    case 'bErase':
      out = st.s1.delete(op.id) ? 'erased' : 'none';
      break;
    case 'bRecreate': {
      // a device that read the last version before its erasure edits it by id: the memory is saved again
      const h = st.history.get(op.id) ?? [];
      const last = h[h.length - 1];
      if (st.s1.has(op.id) || !last) {
        out = 'B ' + (await bWrite(w, op.id, `B #${n}`));
        break;
      }
      st.s1.set(op.id, last);
      const r = await bWrite(w, op.id, `B again #${n}`);
      if (r !== 'stored') st.s1.delete(op.id);
      out = 'B again ' + r;
      break;
    }
    case 'aForget': {
      try {
        await w.A.forget(op.id);
        w.obs.delete(op.id);
        w.recordable.add(op.id);
        w.feedNamed.add(op.id);
        out = 'forgot';
      } catch (e) {
        out = outcome(e);
      }
      break;
    }
    case 'a2Forget': {
      // another session on this device: the same marks, copy and erasure feed
      try {
        await new SaihmProClient(w.url, 'Bearer test', MASTER, w.opts()).forget(op.id);
        w.feedNamed.add(op.id);
        w.recordable.add(op.id); // the feed's baseline is taken when the process starts
        out = 'A2 forgot';
      } catch (e) {
        out = outcome(e);
      }
      break;
    }
    case 'fault':
      if (st.s1.has(op.id)) st.faulted.add(op.id);
      out = 'fault';
      break;
  }
  for (const id of st.history.keys()) if (!st.s1.has(id)) w.goneSince.add(id);
  return out!;
}

// ── sequences ────────────────────────────────────────────────────────────────────────────────────────────────────────
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function genOps(seed: number, len: number, mix: string): Op[] {
  const r = rng(seed);
  const ids: string[] = [];
  let made = 0;
  const fresh = (): string => {
    const id = createHash('sha256').update(`${seed}:${made++}`).digest('hex').slice(0, 32);
    ids.push(id);
    return id;
  };
  const pick = (): string => ids[Math.floor(r() * ids.length)]!;
  const ops: Op[] = [{ k: 'create', id: fresh() }, { k: 'create', id: fresh() }, { k: 'bEdit', id: fresh() }, { k: 'recall' }];
  while (ops.length < len) {
    if (mix === 'erasures' && r() < 0.2) {
      const id = pick();
      const m = r();
      if (m < 0.2) ops.push({ k: 'aForget', id }, { k: 'bRecreate', id }, { k: 'edit', id }, { k: 'recall' }, { k: 'edit', id }, { k: 'one', id }, { k: 'edit', id });
      else if (m < 0.35) ops.push({ k: 'a2Forget', id }, { k: 'edit', id }, { k: 'bRecreate', id }, { k: 'one', id }, { k: 'edit', id }, { k: 'a2Forget', id }, { k: 'edit', id });
      else if (m < 0.5) ops.push({ k: 'bErase', id }, { k: 'recall' }, { k: 'edit', id }, { k: 'bRecreate', id }, { k: 'recall' }, { k: 'edit', id });
      else if (m < 0.65) ops.push({ k: 'bErase', id }, { k: r() < 0.5 ? 'one' : 'share', id }, { k: 'edit', id }, { k: 'bRecreate', id }, { k: 'edit', id });
      else if (m < 0.8) ops.push({ k: 'restart' }, { k: 'bErase', id }, { k: 'edit', id }, { k: 'edit', id }, { k: 'recall' });
      else if (m < 0.92) ops.push({ k: 'aForget', id }, { k: 'bRecreate', id }, { k: 'one', id }, { k: 'edit', id }, { k: 'restart' }, { k: 'edit', id });
      else {
        // R17-M1: a session's first call saves a new memory, another session here forgets it, this one edits it
        const f = fresh();
        ops.push({ k: 'restart' }, { k: 'createNew', id: f }, { k: 'a2Forget', id: f }, { k: 'edit', id: f }, { k: 'recall' });
      }
      continue;
    }
    const x = r();
    if (x < 0.2) ops.push({ k: 'recall' });
    else if (x < 0.42) ops.push({ k: 'edit', id: pick() });
    else if (x < 0.46) ops.push({ k: 'create', id: fresh() });
    else if (x < 0.52) ops.push({ k: 'one', id: pick() });
    else if (x < 0.55) ops.push({ k: 'share', id: pick() });
    else if (x < 0.63) ops.push({ k: 'restart' });
    else if (x < 0.8) ops.push({ k: 'bEdit', id: pick() });
    else if (x < 0.84) ops.push({ k: 'bErase', id: pick() });
    else if (x < 0.87) ops.push({ k: 'bRecreate', id: pick() });
    else if (x < 0.9) ops.push({ k: 'fault', id: pick() }, { k: 'recall' });
    else if (x < 0.92) ops.push({ k: 'aDrop' }, { k: 'edit', id: pick() });
    else if (x < 0.94) ops.push({ k: 'aForget', id: pick() });
    else ops.push({ k: 'edit', id: pick() });
  }
  return ops;
}

export interface ModelResult { sequences: number; ops: number; failing: number; first?: string; local: number; a1: number; differ: number }
export async function runCampaign(seqs: number, len: number, seed0: number, page: number, mix: string): Promise<ModelResult> {
  const res: ModelResult = { sequences: 0, ops: 0, failing: 0, local: 0, a1: 0, differ: 0 };
  for (let s = seed0; s < seed0 + seqs; s++) {
    const ops = genOps(s, len, mix);
    const on = new World(true, `s${s}-on`);
    const off = new World(false, `s${s}-off`);
    on.store.page = off.store.page = page;
    await on.start();
    await off.start();
    const trace: string[] = [];
    try {
      for (let i = 0; i < ops.length; i++) {
        const ro = await apply(on, ops[i]!, i);
        const rf = await apply(off, ops[i]!, i);
        trace.push(`${i} ${JSON.stringify(ops[i]).replace(/"([0-9a-f]{4})[0-9a-f]{28}"/g, '"$1"')} ON=${ro} OFF=${rf}`);
        res.ops++;
        if (ro !== rf) res.differ++;
        if (on.bad.length + off.bad.length > 0) break;
      }
    } finally {
      await on.close();
      await off.close();
    }
    res.sequences++;
    res.local += on.local + off.local;
    res.a1 += on.a1 + off.a1;
    const bad = [...on.bad.map((b) => `ON ${b}`), ...off.bad.map((b) => `OFF ${b}`)];
    if (bad.length > 0) {
      res.failing++;
      res.first ??= `seed ${s}: ${bad[0]}\n  ${trace.join('\n  ')}`;
    }
  }
  return res;
}

describe('PC-RECALL-MODEL: edits, reads, erasures and the copy across devices, against a reference store', () => {
  const seqs = Number(process.env.MODEL_SEQS ?? 12);
  const len = Number(process.env.MODEL_LEN ?? 30);
  const seed = Number(process.env.MODEL_SEED ?? 1);
  const page = Number(process.env.MODEL_PAGE ?? 3);
  for (const mix of (process.env.MODEL_MIX ?? 'plain,erasures').split(',')) {
    it(`${mix}: ${seqs} sequences of ${len} operations from seed ${seed}, listing pages of ${page}`, { timeout: 3_600_000 }, async () => {
      const r = await runCampaign(seqs, len, seed, page, mix);
      console.log(`MODEL ${mix} sequences=${r.sequences} ops=${r.ops} failing=${r.failing} refusedHere=${r.local} a1=${r.a1} onOffDiffer=${r.differ}`);
      assert.equal(r.failing, 0, r.first);
      assert.equal(r.sequences, seqs, 'every sequence ran');
    });
  }
});
