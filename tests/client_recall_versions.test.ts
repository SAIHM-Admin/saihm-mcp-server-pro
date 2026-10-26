/**
 * PC-RECALL-VERSIONS - a memory changed on another computer reaches this computer's recall copy.
 *
 * THE DEFECT (0.14.2 before this file). With the local recall copy on, a recall sent the ids of every cell the copy
 * held, and the endpoint's delta returns only cells whose id it was NOT sent. A memory updated in place on another
 * computer (`remember` with its `cellId`) keeps its id, so it never came back: this computer answered the old text
 * for good, an edit made here in the same session was refused as a stale write, and an edit made here in a later
 * session stored the stale text over the newer version. New memories and erasures did reach the copy.
 *
 * THE FIX. Before a fast recall the client reads the complete version listing of its own cells (`listOnly`, paged),
 * and sends as known only the cells whose listed commitment equals the copy's. Everything else comes back from the
 * delta. Only an answer showing the endpoint has no listing is a full recall; a listing that cannot be used fails the
 * recall with its error, and never ends in the unversioned delta.
 *
 * THE MOCK mirrors the hosted service's rules: one current version per cell id;
 * a write at or below the cell's high-water sequence refused 409 BLIND_STALE_SEQ; a write whose commitment is not
 * sha256(ciphertext) refused; the delta reads only cells whose id was not sent and lists every live id; recall-all
 * reads every cell; the listing pages cells in id order with {cellId, seq, commitment}, `seq` the high-water mark;
 * a cell read and a listing page each charge one recall, and over the hard cap both are refused 429 quota_hard_cap; a
 * single read of a cell with no key held is `found: false` and is not charged; with the listing switched off a
 * `listOnly` request is answered as a recall-all.
 */
import { after, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { createServer as createNetServer, connect as netConnect, type AddressInfo, type Socket } from 'node:net';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deriveIdentity, encodeIdentityRecord, toHex, type WireEnvelope } from '@saihm/client-pro';
import {
  SaihmProClient,
  SaihmEndpointError,
  MAX_COPY_LISTING_PAGES,
  COPY_RECALL_ATTEMPTS,
  SHARES_PASS_DEADLINE_MS,
  type RecalledCell,
} from '../src/client.js';
import { failText } from '../src/render_fence.js';

// A forget appends to the identity's erasure feed: pinned to a scratch directory so no real feed is touched.
const feedDir = mkdtempSync(join(tmpdir(), 'saihm-feed-'));
process.env.SAIHM_ERASURE_FEED_DIR = feedDir;

type Answer = { status: number; body: unknown };

interface Hosted {
  url: string;
  /** One entry per saihm_recall request, in arrival order. */
  log: string[];
  /** Recalls charged (cell reads and listing pages). */
  charged: () => number;
  /** Requests of every method that reached the endpoint. */
  calls: () => number;
  /** Set the hard cap on recalls charged from now on (Infinity = none). */
  setCap: (n: number) => void;
  /** 'off' answers a listing request as the hosted service does with the switch off: a recall-all. */
  listing: 'on' | 'off';
  pageSize: number;
  /** Cells listed with seq null (no high-water mark held). */
  seqNull: Set<string>;
  /** Cells kept in the index whose wrapped key is gone: not listed, and a read of one is found:false. */
  unkeyed: Set<string>;
  /** Cells listed as usual whose storage read fails now: charged, then left out of the answer. */
  unreadable: Set<string>;
  /** When set, a listing answer is computed when its request arrives and only then held until this resolves. */
  holdList?: Promise<void>;
  /** Called once a listing answer is computed and held (the moment a concurrent write may start). */
  onListHeld?: () => void;
  /**
   * Awaited once a delta answer is COMPUTED (cells read, live ids taken) and before it is sent: a slow endpoint answers
   * from the state it saw, so a write made meanwhile is not in the answer.
   */
  holdDelta?: () => Promise<void>;
  /** Rewrites the rows of a delta (`added`) or recall-all answer before it is sent. */
  rowsFault?: (kind: 'delta' | 'all', rows: unknown[]) => unknown[];
  /** Replaces the answer to a remember, before anything is stored. */
  rememberFault?: () => Answer | undefined;
  /** Awaited once a remember is stored and before its answer is sent. */
  holdRemember?: () => Promise<void>;
  /** Awaited once a recall-all answer is computed and before it is sent. */
  holdAll?: () => Promise<void>;
  /** Replaces the answer to the n-th listing request (0-based, counted over the mock's life). */
  pageFault?: (n: number, page: { mode: 'list'; cells: unknown[]; next: string | null; asOf: string }) => Answer | undefined;
  /** Awaited when a delta request arrives, before its answer is computed. */
  beforeDelta?: () => Promise<void>;
  /** Replaces the answer to a read of one cell by id, before anything is read. */
  oneFault?: (id: string) => Answer | undefined;
  /** Awaited once the answer to a read of one cell by id is computed and before it is sent. */
  holdOne?: () => Promise<void>;
  /** The current plaintext-free state of one cell, for assertions: its wire as stored. */
  wireOf: (id: string) => WireEnvelope | undefined;
  /** Serve `w` as the cell's stored version from now on (a rollback), leaving its high-water mark where it is. */
  setWire: (id: string, w: WireEnvelope) => void;
  close: () => Promise<void>;
}

const commitmentOf = (w: WireEnvelope): string => createHash('sha256').update(Buffer.from(w.ciphertext, 'hex')).digest('hex');

async function hosted(): Promise<Hosted> {
  const store = new Map<string, WireEnvelope>();
  const hwm = new Map<string, bigint>();
  let charged = 0;
  let calls = 0;
  let cap = Infinity;
  let listings = 0;
  const h = {} as Hosted;
  const charge = (): Answer | undefined => {
    if (charged >= cap) return { status: 429, body: { error: 'quota_hard_cap', reason: 'SAIHM_QUOTA_HARD_CAP: cap reached' } };
    charged++;
    return undefined;
  };
  const readCell = (id: string): Answer | { found: boolean; wire?: WireEnvelope } => {
    const w = store.get(id);
    if (!w || h.unkeyed.has(id)) return { found: false }; // no key held: not charged
    const refused = charge();
    if (refused) return refused;
    if (h.unreadable.has(id)) return { found: false }; // the shard read failed: isolated, left out
    return { found: true, wire: w };
  };
  const isAnswer = (x: unknown): x is Answer => typeof x === 'object' && x !== null && 'status' in x;
  const ids = (): string[] => [...store.keys()];
  const handle = async (method: string, params: Record<string, unknown>): Promise<Answer> => {
    if (method === 'saihm_remember') {
      const faulted = h.rememberFault?.();
      if (faulted) return faulted;
      const wire = params.wire as WireEnvelope;
      if (wire.publicMeta.commitmentHash.toLowerCase() !== commitmentOf(wire)) return { status: 400, body: { error: 'verify_failed' } };
      const seq = BigInt(wire.seq);
      if (seq <= (hwm.get(wire.cellId) ?? 0n)) return { status: 409, body: { error: 'BLIND_STALE_SEQ', reason: 'seq <= high-water mark' } };
      hwm.set(wire.cellId, seq);
      store.set(wire.cellId, wire);
      await h.holdRemember?.();
      return { status: 200, body: { cellId: wire.cellId, shardId: 's', seq: wire.seq, commitmentHash: commitmentOf(wire) } };
    }
    if (method === 'saihm_share') return { status: 200, body: { cellId: params.cellId, shared: true } };
    if (method === 'saihm_forget') {
      const id = params.id as string;
      store.delete(id);
      return { status: 200, body: { cellId: id, shardId: 's', complete: true, destructionAnchor: 'anchor-1', sharesPurged: 0, steps: [], epoch: '1' } };
    }
    if (method !== 'saihm_recall') return { status: 400, body: { error: 'unknown_method' } };
    if (h.listing === 'on' && params.listOnly === true) {
      for (const k of ['cellId', 'sharer', 'knownCellIds', 'knownSharedKeys', 'sharesOnly']) {
        if (params[k] !== undefined) return { status: 400, body: { error: 'bad_request' } };
      }
      const n = listings++;
      const after = typeof params.after === 'string' ? params.after : undefined;
      h.log.push(after === undefined ? 'list' : `list>${after}`);
      const refused = charge();
      if (refused) return refused;
      const sorted = ids().filter((id) => !h.unkeyed.has(id)).sort();
      const from = after === undefined ? 0 : sorted.findIndex((id) => id > after);
      const rest = from < 0 ? [] : sorted.slice(from);
      const take = rest.slice(0, h.pageSize);
      const page = {
        mode: 'list' as const,
        cells: take.map((id) => ({
          cellId: id,
          seq: h.seqNull.has(id) ? null : String(hwm.get(id)),
          commitment: store.get(id)!.publicMeta.commitmentHash.toLowerCase(),
        })),
        next: rest.length > take.length ? take[take.length - 1]! : null,
        asOf: new Date().toISOString(),
      };
      const answer = h.pageFault?.(n, page) ?? { status: 200, body: page };
      if (h.holdList) {
        h.onListHeld?.();
        await h.holdList;
      }
      return answer;
    }
    if (typeof params.cellId === 'string') {
      h.log.push(`one:${params.cellId}`);
      const faulted = h.oneFault?.(params.cellId);
      if (faulted) return faulted;
      const r = readCell(params.cellId);
      await h.holdOne?.();
      return isAnswer(r) ? r : { status: 200, body: r };
    }
    if (Array.isArray(params.knownCellIds)) {
      await h.beforeDelta?.();
      const known = new Set(params.knownCellIds as string[]);
      const added: unknown[] = [];
      for (const id of ids()) {
        if (known.has(id)) continue;
        const r = readCell(id);
        if (isAnswer(r)) {
          h.log.push(`delta(${params.knownCellIds.length})refused`);
          return r;
        }
        if (r.found) added.push({ cellId: id, ...r });
      }
      h.log.push(`delta(${params.knownCellIds.length})+${added.map((a) => (a as { cellId: string }).cellId).join(',')}`);
      const live = ids();
      await h.holdDelta?.();
      return { status: 200, body: { mode: 'delta', added: h.rowsFault?.('delta', added) ?? added, liveCellIds: live } };
    }
    const rows: unknown[] = [];
    for (const id of ids()) {
      const r = readCell(id);
      if (isAnswer(r)) {
        h.log.push('all:refused');
        return r;
      }
      if (r.found) rows.push({ cellId: id, ...r });
    }
    h.log.push(`all:${rows.length}`);
    await h.holdAll?.();
    return { status: 200, body: h.rowsFault?.('all', rows) ?? rows };
  };
  const server = createServer((req, res) => {
    void (async () => {
      let body = '';
      for await (const c of req) body += c;
      const { method, params = {} } = JSON.parse(body) as { method: string; params?: Record<string, unknown> };
      calls++;
      const a = await handle(method, params);
      const t = JSON.stringify(a.body);
      res.writeHead(a.status, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(t)) }).end(t);
    })();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  Object.assign(h, {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`,
    log: [],
    charged: () => charged,
    calls: () => calls,
    setCap: (n: number) => {
      cap = charged + n;
    },
    listing: 'on',
    pageSize: 1000,
    seqNull: new Set<string>(),
    unkeyed: new Set<string>(),
    unreadable: new Set<string>(),
    wireOf: (id: string) => store.get(id),
    setWire: (id: string, w: WireEnvelope) => void store.set(id, w),
    close: () => new Promise<void>((r) => server.close(() => r())),
  });
  return h;
}

/** One key, as two computers of one person hold it. */
const MASTER = new Uint8Array(32).fill(7);
const dir = mkdtempSync(join(tmpdir(), 'saihm-recall-versions-'));
after(() => {
  rmSync(dir, { recursive: true, force: true });
  rmSync(feedDir, { recursive: true, force: true });
});
const copyPath = (name: string): string => join(dir, `${name}-${randomBytes(4).toString('hex')}.json`);
/** A computer: its own copy file (and its own sequence marks, in memory, as a separate install keeps them). */
const computer = (h: Hosted, path: string | undefined): SaihmProClient =>
  new SaihmProClient(h.url, 'Bearer test', MASTER, { tier: 'PRO', ...(path ? { recallCachePath: path } : {}) });
const text = (cells: RecalledCell[], id: string): string | undefined => cells.find((c) => c.cellId === id)?.plaintext;
const newId = (): string => randomBytes(16).toString('hex');
/** What the endpoint holds now, read by a computer with no copy (a full recall). */
const truth = async (h: Hosted, id: string): Promise<string | undefined> => text(await computer(h, undefined).recall(), id);

describe('PC-RECALL-VERSIONS reproducer: an edit made on computer B reaches computer A', () => {
  it('A, whose copy holds the old version, recalls the version B wrote', async () => {
    const h = await hosted();
    try {
      const pathA = copyPath('A');
      const A = computer(h, pathA);
      const B = computer(h, copyPath('B'));
      const id = newId();
      await A.remember('checklist v1', { cellId: id });
      assert.equal(text(await A.recall(), id), 'checklist v1', 'setup: A holds v1');
      assert.equal(text(await B.recall(), id), 'checklist v1', 'setup: B holds v1');
      await B.remember('checklist v2, edited on B', { cellId: id });
      assert.equal(await truth(h, id), 'checklist v2, edited on B', 'setup: the endpoint holds v2');
      assert.equal(text(await A.recall(), id), 'checklist v2, edited on B', 'A answered its old copy');
      assert.ok(readFileSync(pathA, 'utf-8').includes('checklist v2, edited on B'), "A's copy file holds v2");
    } finally {
      await h.close();
    }
  });

  it('after a restart, A recalls the version B wrote while A was not running', async () => {
    const h = await hosted();
    try {
      const pathA = copyPath('A');
      const A = computer(h, pathA);
      const B = computer(h, copyPath('B'));
      const id = newId();
      await A.remember('checklist v1', { cellId: id });
      await A.recall();
      await B.recall();
      await B.remember('checklist v2, edited on B', { cellId: id });
      assert.ok(readFileSync(pathA, 'utf-8').includes('checklist v1'), 'setup: the copy on disk holds v1');
      const A2 = computer(h, pathA); // the next session on A: a new process, the same copy file
      assert.equal(text(await A2.recall(), id), 'checklist v2, edited on B', 'A answered its old copy after a restart');
    } finally {
      await h.close();
    }
  });

  it("A's edit after that recall, in the same session, is stored and keeps B's change", async () => {
    const h = await hosted();
    try {
      const A = computer(h, copyPath('A'));
      const B = computer(h, copyPath('B'));
      const id = newId();
      await A.remember('checklist v1', { cellId: id });
      await A.recall();
      await B.recall();
      await B.remember('checklist v2, edited on B', { cellId: id });
      const seen = text(await A.recall(), id);
      // The edit A makes is built from what A's recall showed, as an agent's edit is.
      await A.remember(`${seen} + added on A`, { cellId: id });
      assert.equal(await truth(h, id), 'checklist v2, edited on B + added on A');
    } finally {
      await h.close();
    }
  });

  it("A's edit in a later session keeps B's change, and B's copy then holds A's edit", async () => {
    const h = await hosted();
    try {
      const pathA = copyPath('A');
      const A = computer(h, pathA);
      const B = computer(h, copyPath('B'));
      const id = newId();
      await A.remember('checklist v1', { cellId: id });
      await A.recall();
      await B.recall();
      await B.remember('checklist v2, edited on B', { cellId: id });
      const A2 = computer(h, pathA);
      const seen = text(await A2.recall(), id);
      await A2.remember(`${seen} + added on A`, { cellId: id });
      assert.equal(await truth(h, id), 'checklist v2, edited on B + added on A', "B's change was overwritten");
      assert.equal(text(await B.recall(), id), 'checklist v2, edited on B + added on A', "B's copy holds A's edit");
    } finally {
      await h.close();
    }
  });

  it("as the server boots it: two computers' homes holding one self-join key, the copy on by default", async () => {
    const h = await hosted();
    const key = randomBytes(32).toString('hex');
    const home = (): string => {
      const d = mkdtempSync(join(tmpdir(), 'saihm-rv-home-'));
      writeFileSync(join(d, 'free-identity.key'), key, { mode: 0o600 });
      return d;
    };
    const homeA = home();
    const homeB = home();
    const boot = (saihmHome: string): SaihmProClient => {
      const keys = Object.keys(process.env).filter((k) => k.startsWith('SAIHM_'));
      const saved = new Map(keys.map((k) => [k, process.env[k]]));
      for (const k of keys) delete process.env[k];
      Object.assign(process.env, {
        SAIHM_HOME: saihmHome,
        SAIHM_ENDPOINT_URL: h.url,
        SAIHM_AUTH_HEADER: 'Bearer test',
        SAIHM_TIER: 'PRO',
        SAIHM_ERASURE_FEED_DIR: saved.get('SAIHM_ERASURE_FEED_DIR'),
      });
      try {
        return SaihmProClient.bootFromEnv();
      } finally {
        for (const k of Object.keys(process.env)) if (k.startsWith('SAIHM_')) delete process.env[k];
        for (const [k, v] of saved) if (v !== undefined) process.env[k] = v;
      }
    };
    try {
      const A = boot(homeA);
      const B = boot(homeB);
      const copyA = join(homeA, `recall.${A.agentIdHash.slice(0, 16)}.json`);
      const id = newId();
      await A.remember('checklist v1', { cellId: id });
      await A.recall();
      await B.recall();
      assert.ok(readFileSync(copyA, 'utf-8').includes('checklist v1'), 'setup: the copy is on, in A\'s home');
      await B.remember('checklist v2, edited on B', { cellId: id });
      assert.equal(text(await A.recall(), id), 'checklist v2, edited on B');
      await B.remember('checklist v3, edited on B while A was off', { cellId: id });
      const A2 = boot(homeA);
      const seen = text(await A2.recall(), id);
      assert.equal(seen, 'checklist v3, edited on B while A was off');
      await A2.remember(`${seen} + added on A`, { cellId: id });
      // What the endpoint holds, read with the same key and no copy.
      const noCopy = new SaihmProClient(h.url, 'Bearer test', new Uint8Array(Buffer.from(key, 'hex')), { tier: 'PRO' });
      assert.equal(text(await noCopy.recall(), id), 'checklist v3, edited on B while A was off + added on A');
    } finally {
      await h.close();
      rmSync(homeA, { recursive: true, force: true });
      rmSync(homeB, { recursive: true, force: true });
    }
  });
});

/**
 * A computer elsewhere: its own copy and marks, and its own erasure feed, which names nothing erased on this one. One
 * process plays both computers here, and the feed is a file of this identity's on the one machine, so a computer
 * elsewhere is one that reads no feed (its own forgets still write one, as a forget on that computer would).
 */
const elsewhere = (h: Hosted, path: string | undefined): SaihmProClient => {
  const was = process.env.SAIHM_ERASURE_FEED;
  process.env.SAIHM_ERASURE_FEED = '0';
  try {
    return computer(h, path);
  } finally {
    if (was === undefined) delete process.env.SAIHM_ERASURE_FEED;
    else process.env.SAIHM_ERASURE_FEED = was;
  }
};

/** Two computers whose copies both hold `n` memories that A wrote, each at its first version. */
async function twoComputers(h: Hosted, n = 3): Promise<{ A: SaihmProClient; B: SaihmProClient; pathA: string; ids: string[] }> {
  const pathA = copyPath('A');
  const A = computer(h, pathA);
  const B = elsewhere(h, copyPath('B'));
  const ids = Array.from({ length: n }, () => newId()).sort();
  for (const [i, id] of ids.entries()) await A.remember(`memory ${i} v1`, { cellId: id });
  await A.recall();
  await B.recall();
  return { A, B, pathA, ids };
}
/** The recall requests one call makes, how many requests of any method, and the recalls it was charged. */
async function measured<T>(h: Hosted, fn: () => Promise<T>): Promise<{ value: T; requests: string[]; charged: number; calls: number }> {
  const from = h.log.length;
  const c0 = h.charged();
  const n0 = h.calls();
  const value = await fn();
  return { value, requests: h.log.slice(from), charged: h.charged() - c0, calls: h.calls() - n0 };
}
const fault = (status: number, body: unknown) => (): Answer => ({ status, body });

describe('PC-RECALL-VERSIONS: what a recall with the copy on reads', () => {
  it('unchanged cells are not read again: one listing page and an empty delta, also after an own edit', async () => {
    const h = await hosted();
    try {
      const { A, ids } = await twoComputers(h);
      const r = await measured(h, () => A.recall());
      assert.deepEqual(r.requests, ['list', 'delta(3)+'], 'a listing, then a delta that reads nothing');
      assert.equal(r.charged, 1, 'one listing page, no cell read');
      assert.deepEqual(r.value.map((c) => c.plaintext).sort(), ['memory 0 v1', 'memory 1 v1', 'memory 2 v1']);
      await A.remember('memory 1 v2, edited here', { cellId: ids[1]! });
      const own = await measured(h, () => A.recall());
      assert.deepEqual(own.requests, ['list', 'delta(3)+'], "this computer's own edit is in the copy at the listed version");
      assert.equal(text(own.value, ids[1]!), 'memory 1 v2, edited here');
    } finally {
      await h.close();
    }
  });

  it('a changed, a new and an erased cell: only the changed and the new are read, the erased is dropped', async () => {
    const h = await hosted();
    try {
      const { A, B, ids } = await twoComputers(h);
      const [x, y, z] = ids as [string, string, string];
      const w = `${'f'.repeat(31)}0`;
      await B.remember('memory 0 v2, edited on B', { cellId: x });
      await B.remember('a new memory from B', { cellId: w });
      await B.forget(z);
      const r = await measured(h, () => A.recall());
      assert.deepEqual(r.requests, ['list', `delta(1)+${x},${w}`], 'Y alone is known; X and W are read');
      assert.equal(r.charged, 3, 'one listing page and two cell reads');
      assert.equal(text(r.value, x), 'memory 0 v2, edited on B');
      assert.equal(text(r.value, y), 'memory 1 v1');
      assert.equal(text(r.value, w), 'a new memory from B');
      assert.equal(text(r.value, z), undefined, 'the erased cell is dropped');
    } finally {
      await h.close();
    }
  });

  it('a cell listed with seq null is read at every recall, as the version it is (no mark to check it against)', async () => {
    const h = await hosted();
    try {
      const { A, B, ids } = await twoComputers(h);
      for (const id of ids) h.seqNull.add(id);
      const same = await measured(h, () => A.recall());
      assert.deepEqual(same.requests, ['list', `delta(0)+${ids.join(',')}`], 'seq null: never known, so read');
      assert.equal(same.charged, 4, 'the listing page and each cell read');
      await B.remember('memory 2 v2, edited on B', { cellId: ids[2]! });
      const changed = await measured(h, () => A.recall());
      assert.deepEqual(changed.requests, ['list', `delta(0)+${ids.join(',')}`]);
      assert.equal(text(changed.value, ids[2]!), 'memory 2 v2, edited on B');
    } finally {
      await h.close();
    }
  });

  it('a version written after the listing was read is fetched by the next recall', async () => {
    const h = await hosted();
    try {
      const { A, B, ids } = await twoComputers(h);
      h.beforeDelta = async () => {
        h.beforeDelta = undefined;
        await B.remember('memory 0 v2, written between the listing and the delta', { cellId: ids[0]! });
      };
      const first = await A.recall();
      assert.equal(h.beforeDelta, undefined, 'setup: the write landed between the listing and the delta');
      assert.equal(text(first, ids[0]!), 'memory 0 v1', 'this recall checked the version the listing stated');
      const next = await measured(h, () => A.recall());
      assert.deepEqual(next.requests, ['list', `delta(2)+${ids[0]}`]);
      assert.equal(text(next.value, ids[0]!), 'memory 0 v2, written between the listing and the delta');
    } finally {
      await h.close();
    }
  });

  it('pages: every page is read in id order before the delta, each charged once', async () => {
    const h = await hosted();
    try {
      const { A, B, ids } = await twoComputers(h, 5);
      h.pageSize = 2;
      await B.remember('memory 4 v2, edited on B', { cellId: ids[4]! });
      const r = await measured(h, () => A.recall());
      assert.deepEqual(r.requests, ['list', `list>${ids[1]}`, `list>${ids[3]}`, `delta(4)+${ids[4]}`]);
      assert.equal(r.charged, 4, 'three pages and one cell read');
      assert.equal(text(r.value, ids[4]!), 'memory 4 v2, edited on B');
    } finally {
      await h.close();
    }
  });

  it('an empty copy asks for everything without a listing', async () => {
    const h = await hosted();
    try {
      const { ids } = await twoComputers(h);
      const C = computer(h, copyPath('C'));
      const r = await measured(h, () => C.recall());
      assert.deepEqual(r.requests, ['delta(0)+' + ids.join(',')]);
      assert.equal(r.charged, 3);
    } finally {
      await h.close();
    }
  });
});

/** The plain opening of the error a recall fails with when the copy could not be checked; the cause follows it. */
const CHECK_FAILED =
  "Recall stopped: this device's copy of your memories could not be checked for changes made elsewhere, so it was " +
  'not used. Nothing was lost. ';

describe('PC-RECALL-VERSIONS: a listing that cannot be read fails the recall, and nothing more is asked', () => {
  /** A copy on A that is behind B. */
  async function behind(h: Hosted, n = 3): Promise<{ A: SaihmProClient; pathA: string; ids: string[] }> {
    const t = await twoComputers(h, n);
    await t.B.remember('memory 0 v2, edited on B', { cellId: t.ids[0]! });
    return t;
  }
  const answersB = (cells: RecalledCell[], ids: string[]): void => {
    assert.equal(text(cells, ids[0]!), 'memory 0 v2, edited on B', "B's version");
    assert.equal(cells.length, ids.length);
  };
  /**
   * The recall fails with the cause's status and code, its message after the plain opening, asks nothing after the
   * failing page (`pages` listing requests in all), and leaves the copy as it was.
   */
  async function failsWith(
    h: Hosted,
    A: SaihmProClient,
    pathA: string,
    want: { status: number; code: string | undefined; cause: RegExp; pages: number },
  ): Promise<void> {
    const before = readFileSync(pathA, 'utf-8');
    const r = await measured(h, () => A.recall().then(() => 'answered', (e: unknown) => e));
    assert.ok(r.value instanceof SaihmEndpointError, `the recall must fail, got ${String(r.value)}`);
    assert.deepEqual([r.value.status, r.value.code], [want.status, want.code]);
    assert.ok(r.value.message.startsWith(CHECK_FAILED), r.value.message);
    assert.match(r.value.message.slice(CHECK_FAILED.length), want.cause);
    assert.deepEqual(r.requests.length, want.pages, `only the listing: ${r.requests.join(' | ')}`);
    assert.ok(r.requests.every((q) => q.startsWith('list')), `nothing after the listing: ${r.requests.join(' | ')}`);
    assert.equal(readFileSync(pathA, 'utf-8'), before, 'the copy is left as it was');
  }

  it('listing switched off: the recall-all it is answered with is the full recall, asked once', async () => {
    const h = await hosted();
    try {
      const { A, pathA, ids } = await behind(h);
      h.listing = 'off';
      const r = await measured(h, () => A.recall());
      assert.deepEqual(r.requests, ['all:3'], 'one request: the listing request, answered as a recall-all');
      assert.equal(r.charged, 3);
      answersB(r.value, ids);
      assert.ok(readFileSync(pathA, 'utf-8').includes('memory 0 v2, edited on B'), 'the copy is rebuilt from it');
    } finally {
      await h.close();
    }
  });

  for (const [name, f, want] of [
    ['refused (503)', fault(503, { error: 'busy' }), { status: 503, code: 'busy', cause: /503/ }],
    ['refused (400)', fault(400, { error: 'bad_request' }), { status: 400, code: 'bad_request', cause: /400/ }],
    ['refused (429)', fault(429, { error: 'rate_limited' }), { status: 429, code: 'rate_limited', cause: /429/ }],
    // Not a listing, and not the recall-all an endpoint without one answers with: the listing could not be read.
    ['answered with a delta', fault(200, { mode: 'delta', added: [], liveCellIds: [] }), { status: 502, code: 'malformed_response', cause: /^Endpoint returned a malformed version listing \(not a listing\)$/ }],
    ['not an object', fault(200, 'nope'), { status: 502, code: 'malformed_response', cause: /malformed version listing \(not an object\)/ }],
  ] as const) {
    it(`first page ${name}: the recall fails with that error, and nothing more is asked`, async () => {
      const h = await hosted();
      try {
        const { A, pathA, ids } = await behind(h);
        let armed = true;
        h.pageFault = () => (armed ? ((armed = false), f()) : undefined);
        await failsWith(h, A, pathA, { ...want, pages: 1 });
        answersB(await A.recall(), ids); // and the next recall, with the listing back, answers B's version
      } finally {
        await h.close();
      }
    });
  }

  it('a page with an unreadable entry, a cell listed twice, a next that does not move, a later page refused', async () => {
    const one: Array<[string, (n: number, page: { cells: unknown[]; next: string | null }) => Answer | undefined, RegExp]> = [
      ['unreadable commitment', (_n, p) => ({ status: 200, body: { ...p, mode: 'list', cells: [{ ...(p.cells[0] as object), commitment: 'zz' }, ...p.cells.slice(1)] } }), /malformed version listing \(commitment\)/],
      ['unreadable seq', (_n, p) => ({ status: 200, body: { ...p, mode: 'list', cells: [{ ...(p.cells[0] as object), seq: 7 }, ...p.cells.slice(1)] } }), /malformed version listing \(seq\)/],
      ['an entry that is not an object', (_n, p) => ({ status: 200, body: { ...p, mode: 'list', cells: [...p.cells, 'x'] } }), /malformed version listing \(entry\)/],
    ];
    for (const [name, pf, cause] of one) {
      const h = await hosted();
      try {
        const { A, pathA } = await behind(h);
        let first = true;
        h.pageFault = (n, p) => (first ? ((first = false), pf(n, p)) : undefined);
        await failsWith(h, A, pathA, { status: 502, code: 'malformed_response', cause, pages: 1 });
      } catch (e) {
        throw new Error(`${name}: ${(e as Error).message}`);
      } finally {
        await h.close();
      }
    }
    {
      const h = await hosted();
      try {
        const { A, pathA } = await behind(h);
        h.pageSize = 2;
        let seen: unknown[] = [];
        let k = 0;
        h.pageFault = (_n, p) => {
          if (k++ === 0) {
            seen = p.cells;
            return undefined;
          }
          return { status: 200, body: { ...p, cells: [seen[0], ...p.cells] } }; // page 2 repeats page 1's first cell
        };
        await failsWith(h, A, pathA, { status: 502, code: 'malformed_response', cause: /named one twice/, pages: 2 });
      } finally {
        await h.close();
      }
    }
    {
      const h = await hosted();
      try {
        const { A, pathA, ids } = await behind(h);
        h.pageSize = 1;
        let k = 0;
        h.pageFault = (_n, p) => (k++ === 1 ? { status: 200, body: { ...p, next: ids[0] } } : undefined); // back to page 1's cursor
        await failsWith(h, A, pathA, { status: 502, code: 'malformed_response', cause: /did not move forward/, pages: 2 });
      } finally {
        await h.close();
      }
    }
    {
      const h = await hosted();
      try {
        const { A, pathA } = await behind(h);
        h.pageSize = 2;
        let k = 0;
        h.pageFault = () => (k++ === 1 ? { status: 503, body: { error: 'busy' } } : undefined);
        await failsWith(h, A, pathA, { status: 503, code: 'busy', cause: /503/, pages: 2 });
      } finally {
        await h.close();
      }
    }
  });

  it('a listing that never ends: given up after MAX_COPY_LISTING_PAGES pages, and nothing more is asked', async () => {
    const h = await hosted();
    try {
      const { A, pathA } = await behind(h);
      h.pageFault = (n) => ({ status: 200, body: { mode: 'list', cells: [], next: `~${String(n).padStart(6, '0')}`, asOf: new Date().toISOString() } });
      await failsWith(h, A, pathA, { status: 502, code: 'malformed_response', cause: new RegExp(`ran past ${MAX_COPY_LISTING_PAGES} pages`), pages: MAX_COPY_LISTING_PAGES });
    } finally {
      await h.close();
    }
  });

  it('a listing that takes longer than the share pass may: given up when a page arrives late, nothing more asked', async () => {
    const h = await hosted();
    const realNow = Date.now;
    try {
      const { A, pathA } = await behind(h);
      let skew = 0;
      Date.now = () => realNow() + skew;
      let k = 0;
      // The listing's one and last page arrives 600 s and a moment after the pass began: the check is when it arrives.
      h.pageFault = () => {
        if (k++ === 0) skew += SHARES_PASS_DEADLINE_MS + 1_000;
        return undefined;
      };
      await failsWith(h, A, pathA, { status: 408, code: 'timeout', cause: /took more than 10 minutes/, pages: 1 });
    } finally {
      Date.now = realNow;
      await h.close();
    }
  });
});

/** What a tool shows for an error after its `SAIHM error [code] (status n): ` lead. */
const shown = (e: unknown): string => failText(e).replace(/^SAIHM error \[[^\]]*\] \(status -?\d+\): /, '');
const haveOpenssl = (): boolean => {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
};
const PROXY_VARS = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY', 'no_proxy', 'NO_PROXY'] as const;
/** Run `fn` with exactly these proxy variables set (none by default), as the transport reads them on every request. */
async function withProxyEnv<T>(env: Partial<Record<(typeof PROXY_VARS)[number], string>>, fn: () => Promise<T>): Promise<T> {
  const saved = PROXY_VARS.map((k) => [k, process.env[k]] as const);
  for (const k of PROXY_VARS) delete process.env[k];
  Object.assign(process.env, env);
  try {
    return await fn();
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}
/** Listen on loopback; `close` also ends every connection still open, so a held one cannot keep the test waiting. */
async function serve(s: Server): Promise<{ port: number; close: () => Promise<void> }> {
  const sockets = new Set<Socket>();
  s.on('connection', (c: Socket) => {
    sockets.add(c);
    c.on('close', () => sockets.delete(c));
  });
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', () => r()));
  return {
    port: (s.address() as AddressInfo).port,
    close: () => {
      for (const c of sockets) c.destroy();
      return new Promise<void>((r) => s.close(() => r()));
    },
  };
}

/**
 * R14-F1. The error a recall fails with when its copy could not be checked is this package's opening and then the cause.
 * Fenced as one message, the opening took the room the cause needed: a certificate this machine does not trust rendered
 * "...(DEPTH_ZERO_SELF_SIGNED_CERT). Never…", without the warning never to turn certificate checks off or the
 * NODE_EXTRA_CA_CERTS remedy, while the same failure with the copy off rendered whole. Each class of cause below must
 * render whole after the opening, exactly as the copy-off recall shows it.
 */
describe('PC-RECALL-VERSIONS: a failed version check shows its cause whole, as the copy-off recall does', () => {
  const work = mkdtempSync(join(tmpdir(), 'saihm-rv-cause-'));
  after(() => rmSync(work, { recursive: true, force: true }));
  /** A copy file that holds a memory, so a recall with the copy on reads the listing first. */
  async function heldCopy(): Promise<string> {
    const h = await hosted();
    try {
      const p = copyPath('held');
      await computer(h, p).remember('a memory in the copy', { cellId: newId() });
      assert.ok(readFileSync(p, 'utf-8').includes('a memory in the copy'), 'setup: the copy holds a memory');
      return p;
    } finally {
      await h.close();
    }
  }
  /** A certificate for `localhost` signed by itself, made for this run: one this machine does not trust. */
  const selfSigned = (): { key: string; cert: string } => {
    const d = mkdtempSync(join(work, 'tls-'));
    execFileSync(
      'openssl',
      ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', 'k.pem', '-out', 'c.pem',
        '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
      { cwd: d, stdio: 'ignore' },
    );
    return { key: readFileSync(join(d, 'k.pem'), 'utf-8'), cert: readFileSync(join(d, 'c.pem'), 'utf-8') };
  };
  /**
   * One failure, met by a recall with the copy on and by one with it off. With it off the cause is shown whole (the
   * control); with it on the opening comes first and then that same cause, whole, with the remedies `keep` names.
   */
  async function sameCauseWhole(url: string, signIn: boolean, keep: RegExp[], requestTimeoutMs = 10_000): Promise<string> {
    const p = await heldCopy();
    const opts = { tier: 'PRO', requestTimeoutMs, ...(signIn ? { paymentMethod: 'stripe' } : {}) };
    const auth = signIn ? undefined : 'Bearer test';
    const off = await new SaihmProClient(url, auth, MASTER, opts).recall().then(() => 'answered', (e: unknown) => e);
    const on = await new SaihmProClient(url, auth, MASTER, { ...opts, recallCachePath: p }).recall().then(() => 'answered', (e: unknown) => e);
    assert.ok(off instanceof SaihmEndpointError && on instanceof SaihmEndpointError, `both recalls fail: ${String(off)} | ${String(on)}`);
    const cause = shown(off);
    assert.ok(!cause.endsWith('…'), `control: with the copy off the cause is shown whole: ${cause}`);
    for (const k of keep) assert.match(cause, k, 'control: the cause names its remedy');
    assert.ok(shown(on).endsWith(` ${cause}`), `the cause is cut after the opening: ${shown(on)}`);
    assert.equal(shown(on), `${CHECK_FAILED}${cause}`);
    assert.deepEqual([on.status, on.code], [off.status, off.code], "the cause's status and code");
    return cause;
  }

  it('an endpoint answering every request with 503, 429 (with and without a code) or nothing at all', async () => {
    const cases: Array<[string, (res: import('node:http').ServerResponse) => void, RegExp, number?]> = [
      ['503', (res) => void res.writeHead(503, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'upstream_unavailable' })), /^SAIHM endpoint saihm_recall failed: 503 Service Unavailable \(upstream_unavailable\)$/],
      ['429 without a code', (res) => void res.writeHead(429, { 'retry-after': '7', 'content-length': '0' }).end(), /Wait 7 seconds, then try again\.$/],
      ['429 at the hard cap', (res) => void res.writeHead(429, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'quota_hard_cap' })), /429 Too Many Requests \(quota_hard_cap\)$/],
      ['no answer (timeout)', () => undefined, /^SAIHM endpoint saihm_recall timed out after 700ms$/, 700],
    ];
    for (const [name, answer, want, limit] of cases) {
      const s = await serve(createServer((req, res) => {
        req.resume();
        req.on('end', () => answer(res));
      }));
      try {
        await withProxyEnv({}, () => sameCauseWhole(`http://127.0.0.1:${s.port}/mcp`, false, [want], limit));
      } catch (e) {
        throw new Error(`${name}: ${(e as Error).message}`);
      } finally {
        await s.close();
      }
    }
  });

  it('a connection reset before any answer (ECONNRESET): the remedy about the host and the proxy', async () => {
    const s = await serve(createNetServer((c) => c.on('data', () => c.resetAndDestroy())) as unknown as Server);
    try {
      await withProxyEnv({}, () =>
        sameCauseWhole(`http://127.0.0.1:${s.port}/mcp`, false, [
          /\(ECONNRESET\)\. If hosted, allow that host in its network settings; to use a proxy, set HTTPS_PROXY and check NO_PROXY\.$/,
        ]),
      );
    } finally {
      await s.close();
    }
  });

  it('a certificate this machine does not trust, at the recall and at the sign-in inside it', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
    const tls = await serve(createHttpsServer(selfSigned(), (_q, r) => void r.writeHead(500).end('{}')) as unknown as Server);
    try {
      await withProxyEnv({}, async () => {
        const url = `https://localhost:${tls.port}/mcp`;
        await sameCauseWhole(url, false, [
          /\(DEPTH_ZERO_SELF_SIGNED_CERT\)\. Never disable certificate checks; if TLS is inspected here, set NODE_EXTRA_CA_CERTS to a file of the network admin's CA certificate\.$/,
        ]);
        await sameCauseWhole(url, true, [
          /certificate is not trusted here\. Never turn certificate checks off: if this network inspects TLS, get its CA certificate from its administrator, set NODE_EXTRA_CA_CERTS to that file and restart\.$/,
        ]);
      });
    } finally {
      await tls.close();
    }
  });

  it('the hosted address through HTTPS_PROXY: a proxy that refuses, and one whose network inspects TLS', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
    // Nothing leaves this machine: the client dials only the proxy on loopback, which refuses the tunnel or joins it to a
    // local server whose certificate this machine does not trust, as a network that inspects TLS presents one.
    const tls = await serve(createHttpsServer(selfSigned(), (_q, r) => void r.writeHead(500).end('{}')) as unknown as Server);
    const tunnels: string[] = [];
    const proxy = (refuse: boolean) =>
      createServer().on('connect', (req: import('node:http').IncomingMessage, c: Socket, head: Buffer) => {
        tunnels.push(String(req.url));
        if (refuse) return void c.end('HTTP/1.1 403 Forbidden\r\n\r\n');
        const up = netConnect(tls.port, '127.0.0.1', () => {
          c.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          if (head.length > 0) up.write(head);
          up.pipe(c);
          c.pipe(up);
        });
        up.on('error', () => c.destroy());
        c.on('error', () => up.destroy());
      });
    const refusing = await serve(proxy(true));
    const joining = await serve(proxy(false));
    try {
      const hosted = 'https://saihm.net/mcp';
      await withProxyEnv({ HTTPS_PROXY: `http://127.0.0.1:${refusing.port}` }, () =>
        sameCauseWhole(hosted, false, [
          /^SAIHM endpoint saihm_recall could not reach https:\/\/saihm\.net\/mcp \(PROXY_CONNECT_403\)\. Via HTTPS_PROXY: if hosted, allow this host in its network settings; else check the proxy and NO_PROXY\.$/,
        ]),
      );
      await withProxyEnv({ HTTPS_PROXY: `http://127.0.0.1:${joining.port}` }, async () => {
        await sameCauseWhole(hosted, false, [
          /^SAIHM endpoint saihm_recall could not reach https:\/\/saihm\.net\/mcp \(DEPTH_ZERO_SELF_SIGNED_CERT\)\. Never disable certificate checks; if TLS is inspected here, set NODE_EXTRA_CA_CERTS to a file of the network admin's CA certificate\.$/,
        ]);
        await sameCauseWhole(hosted, true, [/^SAIHM onboard transport error: the SAIHM endpoint's certificate is not trusted here\. Never turn certificate checks off/]);
      });
      assert.ok(tunnels.length >= 6 && tunnels.every((t) => t === 'saihm.net:443'), `every request went to the proxy: ${tunnels.join(' ')}`);
    } finally {
      await refusing.close();
      await joining.close();
      await tls.close();
    }
  });
});

/** What the refused edit says when this device had read or saved the memory: what happened, and the way back. */
const CHANGED_SINCE =
  'This memory has changed since this device last read or saved it, so your edit was not saved. Recall it to see ' +
  'the newer version, then make your edit again.';
/** ...when the memory this device had read or saved is gone: it was erased, so the user decides on saving it again. */
const ERASED =
  'This memory was erased, so your edit was not saved. Ask the user before saving this text again as a new memory ' +
  'without a cellId.';
/** ...and when the cellId named no memory this device ever read: the id was used, and the memory may have been erased. */
const ID_USED =
  'This cellId was already used by a memory saved earlier, which may since have been erased, so this one was not ' +
  'saved under it. Ask the user before saving this text as a new memory without a cellId.';
/** The edit an agent makes from what a recall showed it. */
const editFrom = (c: SaihmProClient, cells: RecalledCell[], id: string, add: string) =>
  c.remember(`${text(cells, id)} + ${add}`, { cellId: id }).then(
    () => 'stored',
    (e: unknown) => (e instanceof SaihmEndpointError ? `refused ${e.status} ${e.code}` : `threw ${String(e)}`),
  );

/**
 * R14 lost update. With the copy on, a memory the copy answered carried no sequence mark, so an edit built on it
 * re-read the live version and was stored over another device's newer one; with the copy off the same edit is
 * refused. Now the listing's sequence number, when it states the very version the copy holds, is that memory's mark.
 */
describe('PC-RECALL-VERSIONS: an edit built on an older version is refused with the copy on, as with it off', () => {
  for (const copy of ['on', 'off'] as const) {
    it(`copy ${copy}: next session, B edits after this recall; the edit here is refused, B's kept, and recall then edit works`, async () => {
      const h = await hosted();
      try {
        const { B, pathA, ids } = await twoComputers(h);
        const A2 = computer(h, copy === 'on' ? pathA : undefined); // the next session on A
        const seen = await A2.recall();
        await B.remember('memory 1 v2, edited on B after the recall', { cellId: ids[1]! });
        const e = await A2.remember(`${text(seen, ids[1]!)} + added on A`, { cellId: ids[1]! }).then(() => 'stored', (x: unknown) => x);
        assert.ok(e instanceof SaihmEndpointError, `the edit was ${String(e)}`);
        assert.deepEqual([e.status, e.code], [409, 'BLIND_STALE_SEQ']);
        assert.equal(await truth(h, ids[1]!), 'memory 1 v2, edited on B after the recall', "B's version is kept");
        assert.equal(
          failText(e),
          `SAIHM error [BLIND_STALE_SEQ] (status 409): ${CHANGED_SINCE} SAIHM endpoint saihm_remember failed: 409 Conflict (BLIND_STALE_SEQ)`,
        );
        // The way back the text gives: recall, then make the edit again.
        assert.equal(await editFrom(A2, await A2.recall(), ids[1]!, 'added on A'), 'stored');
        assert.equal(await truth(h, ids[1]!), 'memory 1 v2, edited on B after the recall + added on A');
      } finally {
        await h.close();
      }
    });
  }

  it('no false refusal on one device: answered from the copy, then edited, in the same and later sessions, as a chain', async () => {
    const h = await hosted();
    try {
      const { A, pathA, ids } = await twoComputers(h);
      assert.equal(await editFrom(A, await A.recall(), ids[0]!, 'a'), 'stored', 'the same session');
      const A2 = computer(h, pathA);
      const first = await measured(h, () => A2.recall());
      assert.deepEqual(first.requests, ['list', 'delta(3)+'], 'answered from the copy');
      assert.equal(await editFrom(A2, first.value, ids[0]!, 'b'), 'stored', 'a later session');
      assert.equal(await editFrom(A2, await A2.recall(), ids[0]!, 'c'), 'stored', 'again in it');
      assert.equal(await A2.remember('memory 0, written over without a read', { cellId: ids[0]! }).then(() => 'stored'), 'stored');
      const A3 = computer(h, pathA);
      assert.equal(await editFrom(A3, await A3.recall(), ids[0]!, 'd'), 'stored', 'and the session after');
      assert.equal(await truth(h, ids[0]!), 'memory 0, written over without a read + d');
    } finally {
      await h.close();
    }
  });

  it('no false refusal: a session that edits before any recall (as after a warm start), a read by id, a share', async () => {
    const h = await hosted();
    try {
      const { pathA, ids } = await twoComputers(h);
      // A warm start reads a snapshot and touches neither the copy nor the marks; its session edits as one that read nothing.
      const W = computer(h, pathA);
      assert.equal(await W.remember('memory 0 v2, the first call of a session', { cellId: ids[0]! }).then(() => 'stored'), 'stored');
      const R = computer(h, pathA);
      const one = await R.recallOne(ids[1]!);
      assert.equal(await R.remember(`${one!.plaintext} + after a read by id`, { cellId: ids[1]! }).then(() => 'stored'), 'stored');
      const S = computer(h, pathA);
      const recipient = deriveIdentity(new Uint8Array(32).fill(91));
      await S.share({ cellId: ids[2]!, recipientRecord: encodeIdentityRecord(recipient.identityRecord), recipientPinnedAgentIdHashHex: toHex(recipient.agentIdHash) });
      assert.equal(await editFrom(S, await S.recall(), ids[2]!, 'after a share'), 'stored');
      assert.equal(await truth(h, ids[2]!), 'memory 2 v1 + after a share');
    } finally {
      await h.close();
    }
  });

  for (const first of ['P', 'Q'] as const) {
    it(`two processes sharing one copy, ${first} writing first: each edit made after a recall that saw the other's is stored`, async () => {
      const h = await hosted();
      try {
        const { pathA, ids } = await twoComputers(h);
        const P = computer(h, pathA);
        const Q = computer(h, pathA);
        const [one, two] = first === 'P' ? [P, Q] : [Q, P];
        await one.recall();
        const before = await two.recall();
        assert.equal(await editFrom(one, await one.recall(), ids[0]!, `${first} first`), 'stored');
        // The control: an edit built on the recall from before the other process's edit is a real conflict.
        assert.equal(await editFrom(two, before, ids[0]!, 'from before'), 'refused 409 BLIND_STALE_SEQ');
        assert.equal(await editFrom(two, await two.recall(), ids[0]!, 'then'), 'stored');
        assert.equal(await editFrom(one, await one.recall(), ids[0]!, 'and back'), 'stored');
        assert.equal(await truth(h, ids[0]!), `memory 0 v1 + ${first} first + then + and back`);
      } finally {
        await h.close();
      }
    });
  }

  it('a cell listed with no sequence number, or a lower one than the copy holds, is read and marked from its own version', async () => {
    const h = await hosted();
    try {
      const { pathA, ids } = await twoComputers(h);
      h.seqNull.add(ids[0]!);
      h.pageFault = (_n, p) => ({
        status: 200,
        body: { ...p, cells: p.cells.map((c) => ((c as { cellId: string }).cellId === ids[1] ? { ...(c as object), seq: '0' } : c)) },
      });
      const A2 = computer(h, pathA);
      const r = await measured(h, () => A2.recall());
      assert.deepEqual(r.requests, ['list', `delta(1)+${ids[0]},${ids[1]}`], 'both are read, the other is known');
      assert.equal(await editFrom(A2, r.value, ids[0]!, 'no change between'), 'stored', 'no false refusal (null seq)');
      assert.equal(await editFrom(A2, r.value, ids[1]!, 'no change between'), 'stored', 'no false refusal (lower seq)');
      const A3 = computer(h, pathA);
      const seen = await A3.recall();
      // Another device that has read nothing: it writes over the live version, so the mark here falls behind.
      await computer(h, undefined).remember('memory 0 v3, edited on B after the recall', { cellId: ids[0]! });
      assert.equal(await editFrom(A3, seen, ids[0]!, 'added on A'), 'refused 409 BLIND_STALE_SEQ', 'and refused after B edits');
      assert.equal(await truth(h, ids[0]!), 'memory 0 v3, edited on B after the recall');
    } finally {
      await h.close();
    }
  });

  it('an endpoint rolled back below a mark held here, with the copy restored to match, is read again and refused', async () => {
    const h = await hosted();
    try {
      const marks = join(dir, `marks-${randomBytes(4).toString('hex')}.json`);
      const pathA = copyPath('A');
      const at = (): SaihmProClient => new SaihmProClient(h.url, 'Bearer test', MASTER, { tier: 'PRO', recallCachePath: pathA, seqStatePath: marks });
      const A = at();
      const id = newId();
      await A.remember('checklist v1', { cellId: id });
      const copyAtV1 = readFileSync(pathA, 'utf-8');
      const wireV1 = h.wireOf(id)!;
      await A.remember('checklist v2', { cellId: id }); // the mark this identity holds is 2, on disk
      // The copy restored from before v2, and the endpoint rolled back to v1, its listed number with it.
      writeFileSync(pathA, copyAtV1, { mode: 0o600 });
      h.setWire(id, wireV1);
      h.pageFault = (_n, p) => ({ status: 200, body: { ...p, cells: p.cells.map((c) => ((c as { cellId: string }).cellId === id ? { ...(c as object), seq: '1' } : c)) } });
      const e = await at().recall().then(() => 'answered from the copy', (x: unknown) => x);
      assert.ok(e instanceof SaihmEndpointError && e.code === 'stale_cell', `the rollback was ${String(e)}`);
    } finally {
      await h.close();
    }
  });

  it('a memory erased elsewhere between the listing and the delta is dropped and gets no mark: its id stays spent', async () => {
    const h = await hosted();
    try {
      const { B, pathA, ids } = await twoComputers(h);
      const A2 = computer(h, pathA);
      h.beforeDelta = async () => {
        h.beforeDelta = undefined;
        await B.forget(ids[0]!);
      };
      const cells = await A2.recall();
      assert.equal(h.beforeDelta, undefined, 'setup: the erasure landed between the listing and the delta');
      assert.equal(text(cells, ids[0]!), undefined, 'dropped, as the delta says it is gone');
      // No mark was taken for it, so the edit reads the live version first, finds nothing, and the id is spent.
      const e = await A2.remember('memory 0, resurrected?', { cellId: ids[0]! }).then(() => 'stored', (x: unknown) => x);
      assert.ok(e instanceof SaihmEndpointError, `the write was ${String(e)}`);
      assert.equal(failText(e), `SAIHM error [BLIND_STALE_SEQ] (status 409): ${ID_USED} SAIHM endpoint saihm_remember failed: 409 Conflict (BLIND_STALE_SEQ)`);
      assert.equal(await truth(h, ids[0]!), undefined);
    } finally {
      await h.close();
    }
  });

  it('an erased memory: its cellId cannot be saved again from a device that never saw it, and the text says so', async () => {
    const h = await hosted();
    try {
      const { A, ids } = await twoComputers(h);
      await A.forget(ids[2]!);
      const C = computer(h, copyPath('C'));
      const e = await C.remember('reusing an erased id', { cellId: ids[2]! }).then(() => 'stored', (x: unknown) => x);
      assert.ok(e instanceof SaihmEndpointError, `the write was ${String(e)}`);
      assert.equal(failText(e), `SAIHM error [BLIND_STALE_SEQ] (status 409): ${ID_USED} SAIHM endpoint saihm_remember failed: 409 Conflict (BLIND_STALE_SEQ)`);
      assert.equal(await C.remember('reusing an erased id').then(() => 'stored'), 'stored', 'saved without a cellId it is a new memory');
    } finally {
      await h.close();
    }
  });
});

/** The refusal as rendered: its own text, then the endpoint's, each whole. */
const refusal = (opening: string): string =>
  `SAIHM error [BLIND_STALE_SEQ] (status 409): ${opening} SAIHM endpoint saihm_remember failed: 409 Conflict (BLIND_STALE_SEQ)`;
/** A refusal made on this device, before anything was asked of the endpoint: its text alone, with the same code. */
const refusedHere = (text: string): string => `SAIHM error [BLIND_STALE_SEQ] (status 409): ${text}`;
/** `p`, or a failure naming `what` when it has not settled within `ms` (a read that never comes fails, never hangs). */
const within = <T>(p: Promise<T>, ms: number, what: string): Promise<T> =>
  Promise.race([p, new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`${what} did not arrive within ${ms} ms`)), ms).unref())]);
const attempt = (c: SaihmProClient, content: string, cellId: string): Promise<unknown> =>
  c.remember(content, { cellId }).then(
    () => 'stored',
    (e: unknown) => e,
  );
/**
 * An erasure made on another device, sent to the endpoint as that device's forget is. Not `B.forget`: one process plays
 * both devices here, and a forget also writes this identity's erasure feed on the device that made it, which the copy on
 * THIS one would then read as its own (and drop the cell for that reason, not the one under test).
 */
const eraseElsewhere = async (h: Hosted, id: string): Promise<void> => {
  const r = await fetch(h.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ method: 'saihm_forget', params: { id } }) });
  assert.equal(r.status, 200, 'setup: erased at the endpoint');
};
/** A computer whose sequence marks persist in `marks`, as the MCP server keeps them across restarts. */
const markedComputer = (h: Hosted, marks: string, path?: string): SaihmProClient =>
  new SaihmProClient(h.url, 'Bearer test', MASTER, { tier: 'PRO', seqStatePath: marks, ...(path ? { recallCachePath: path } : {}) });

/**
 * R15-L1. A memory this session had read or saved, edited and then erased on another device: an edit here was refused
 * "Recall it to see the newer version", the recall showed no such memory, and the same edit got the same text until a
 * restart. Now a refused edit with no read before it reads the memory once, moving no mark, to say which is true.
 */
describe('PC-RECALL-VERSIONS: an edit of a memory erased elsewhere says so, and never replaces what it has not seen', () => {
  for (const copy of ['on', 'off'] as const) {
    it(`copy ${copy}: edited and then erased elsewhere, the edit here says it was erased, at once and after a recall`, async () => {
      const h = await hosted();
      try {
        const path = copy === 'on' ? copyPath('A') : undefined;
        const A = computer(h, path);
        const id = newId();
        await A.remember('plan v1', { cellId: id });
        assert.equal(text(await A.recall(), id), 'plan v1', 'setup: A read it');
        const B = computer(h, undefined);
        await B.remember('plan v2, edited on B', { cellId: id });
        await eraseElsewhere(h, id);
        const first = await measured(h, () => attempt(A, 'plan v1 + added on A', id));
        assert.ok(first.value instanceof SaihmEndpointError, `the edit was ${String(first.value)}`);
        assert.equal(failText(first.value), refusal(ERASED));
        assert.deepEqual(first.requests, [`one:${id}`], 'one read after the refusal tells which text is true');
        assert.equal(first.charged, 0, 'an erased memory is read without a charge');
        if (path) assert.ok(!readFileSync(path, 'utf-8').includes('plan v1'), "the erased memory's text has left the copy");
        assert.equal(text(await A.recall(), id), undefined, 'the recall shows it gone');
        const again = await measured(h, () => attempt(A, 'plan v1 + added on A', id));
        assert.equal(failText(again.value), refusedHere(ERASED), 'the same edit again gets the same, true text');
        assert.deepEqual([again.requests, again.charged], [[], 0], 'refused here: the read found it gone, so nothing is asked');
        assert.equal(await truth(h, id), undefined, 'nothing was stored under it');
        assert.equal(await A.remember('plan v1 + added on A').then(() => 'stored'), 'stored', 'saved as a new memory it is kept');
      } finally {
        await h.close();
      }
    });

    it(`copy ${copy}: written again elsewhere after this device saw it erased, an edit here is refused, never stored over it`, async () => {
      const h = await hosted();
      try {
        const A = computer(h, copy === 'on' ? copyPath('A') : undefined);
        const id = newId();
        await A.remember('note v1', { cellId: id });
        await A.recall();
        const B = computer(h, undefined);
        assert.equal(text(await B.recall(), id), 'note v1', 'setup: B read it');
        await eraseElsewhere(h, id);
        assert.equal(text(await A.recall(), id), undefined, 'setup: A recalled it gone');
        // B read it before its erasure, so B's edit goes at the next number and is stored: the memory is back.
        await B.remember('note written again on B', { cellId: id });
        const e = await attempt(A, 'note v1 + added on A', id);
        assert.ok(e instanceof SaihmEndpointError, `the edit was ${String(e)}: it replaced a version A never saw`);
        // With the copy on, the recall's version listing showed it gone, so A knows it was erased and asks nothing; with
        // the copy off a recall cannot tell gone from unreadable, so the endpoint refuses it and a read tells the text.
        assert.equal(failText(e), copy === 'on' ? refusedHere(ERASED) : refusal(CHANGED_SINCE), 'what A last saw is true');
        assert.equal(await truth(h, id), 'note written again on B', "B's version is kept");
        assert.equal(await editFrom(A, await A.recall(), id, 'added on A'), 'stored', 'recalled, then edited: stored');
        assert.equal(await truth(h, id), 'note written again on B + added on A');
      } finally {
        await h.close();
      }
    });
  }

  for (const how of ['no copy', 'the copy on, the listing off'] as const) {
    it(`${how}: a memory a failed read left out of a recall keeps its mark, so a later edit elsewhere is not replaced`, async () => {
      const h = await hosted();
      try {
        if (how !== 'no copy') h.listing = 'off';
        const A = computer(h, how === 'no copy' ? undefined : copyPath('A'));
        const id = newId();
        await A.remember('list v1', { cellId: id });
        await A.remember('another memory');
        await A.recall();
        h.unreadable.add(id); // the hosted service leaves a cell whose stored copy cannot be read out of a recall
        assert.equal(text(await A.recall(), id), undefined, 'setup: left out of this recall, not erased');
        h.unreadable.delete(id);
        await computer(h, undefined).remember('list v2, edited on B', { cellId: id });
        const e = await attempt(A, 'list v1 + added on A', id);
        assert.ok(e instanceof SaihmEndpointError, `the edit was ${String(e)}: it replaced B's edit`);
        assert.equal(failText(e), refusal(CHANGED_SINCE));
        assert.equal(await truth(h, id), 'list v2, edited on B', "B's version is kept");
      } finally {
        await h.close();
      }
    });
  }

  it('in a later session: the device that had read it says it was erased, one that never read it says the id was used', async () => {
    const h = await hosted();
    try {
      const marks = join(dir, `marks-${randomBytes(4).toString('hex')}`, 'seq.json');
      const id = newId();
      await markedComputer(h, marks).remember('todo v1', { cellId: id });
      const B = computer(h, undefined);
      await B.remember('todo v2, edited on B', { cellId: id });
      await eraseElsewhere(h, id);
      const A2 = markedComputer(h, marks); // the next session on A: its marks file says it saved this memory
      const later = await measured(h, () => attempt(A2, 'todo v1 + added on A', id));
      assert.equal(failText(later.value), refusedHere(ERASED), 'refused after its own read, before its write');
      assert.deepEqual(later.requests, [`one:${id}`], 'only the read made before every such write: nothing more is asked');
      const C = computer(h, undefined); // a device that never read it
      const never = await measured(h, () => attempt(C, 'something else', id));
      assert.equal(failText(never.value), refusal(ID_USED));
      assert.deepEqual(never.requests, [`one:${id}`]);
      assert.equal(await truth(h, id), undefined);
    } finally {
      await h.close();
    }
  });

  it('a read by id, a share and an edit that find a memory gone take it out of the copy', async () => {
    const h = await hosted();
    try {
      const pathA = copyPath('A');
      const A = computer(h, pathA);
      const [one, two, three] = [newId(), newId(), newId()];
      await A.remember('first private note', { cellId: one });
      await A.remember('second private note', { cellId: two });
      await A.remember('third private note', { cellId: three });
      await A.recall();
      for (const id of [one, two]) await eraseElsewhere(h, id);
      await computer(h, undefined).remember('third note v2 on B', { cellId: three });
      await eraseElsewhere(h, three);
      assert.equal(await A.recallOne(one), null);
      assert.ok(!readFileSync(pathA, 'utf-8').includes('first private note'), 'gone from the copy after the read');
      const recipient = deriveIdentity(new Uint8Array(32).fill(92));
      const shared = await A.share({ cellId: two, recipientRecord: encodeIdentityRecord(recipient.identityRecord), recipientPinnedAgentIdHashHex: toHex(recipient.agentIdHash) }).then(
        () => 'shared',
        (e: { code?: string }) => e.code,
      );
      assert.equal(shared, 'cell_not_found');
      assert.ok(!readFileSync(pathA, 'utf-8').includes('second private note'), 'gone from the copy after the share');
      // A later session, whose copy still holds the third: its edit's first read finds nothing.
      const A2 = computer(h, pathA);
      assert.equal(failText(await attempt(A2, 'third note + added on A', three)), refusal(ID_USED));
      assert.ok(!readFileSync(pathA, 'utf-8').includes('third private note'), "gone from the copy after the edit's read");
    } finally {
      await h.close();
    }
  });

  it('a write refused after its own read found the memory says a newer version is there, and asks nothing more', async () => {
    const h = await hosted();
    try {
      const id = newId();
      await computer(h, undefined).remember('rota v1', { cellId: id });
      const v1 = h.wireOf(id)!;
      await computer(h, undefined).remember('rota v2, edited on B', { cellId: id });
      h.setWire(id, v1); // the endpoint serves v1 again, its number already past it
      const A2 = computer(h, undefined); // a new session: it reads the live version first
      const r = await measured(h, () => attempt(A2, 'rota v1 + added on A', id));
      assert.equal(failText(r.value), refusal(CHANGED_SINCE));
      assert.deepEqual(r.requests, [`one:${id}`], 'what that read found tells the text');
    } finally {
      await h.close();
    }
  });

  it('a read of the live version this client cannot read: a refused write says the id was used, and asks nothing more', async () => {
    const h = await hosted();
    try {
      const id = newId();
      await computer(h, undefined).remember('menu v1', { cellId: id });
      h.oneFault = () => ({ status: 200, body: { found: true } }); // no envelope
      const r = await measured(h, () => attempt(computer(h, undefined), 'menu v1 + added on A', id));
      assert.equal(failText(r.value), refusal(ID_USED));
      assert.deepEqual(r.requests, [`one:${id}`]);
    } finally {
      await h.close();
    }
  });

  it('a read that finds a memory gone while this device writes it again leaves the new version in the copy', async () => {
    const h = await hosted();
    try {
      const pathA = copyPath('A');
      const A = computer(h, pathA);
      const id = newId();
      await A.remember('recipe v1', { cellId: id });
      await eraseElsewhere(h, id);
      let release!: () => void;
      let held!: () => void;
      const arrived = new Promise<void>((r) => (held = r));
      h.holdOne = () => {
        h.holdOne = undefined;
        held();
        return new Promise<void>((r) => (release = r));
      };
      const read = A.recallOne(id);
      await within(arrived, 5_000, 'the read'); // its answer is computed: no such cell
      // This device writes it again meanwhile (its number is past the erased version's), and the copy takes it.
      assert.equal(await A.remember('recipe written again on A', { cellId: id }).then(() => 'stored'), 'stored');
      release();
      assert.equal(await read, null, 'the read answers what it found');
      assert.ok(readFileSync(pathA, 'utf-8').includes('recipe written again on A'), 'the version written meanwhile stays in the copy');
    } finally {
      await h.close();
    }
  });

  it('an answer this client cannot read is not taken for "gone": the copy keeps the memory', async () => {
    const h = await hosted();
    try {
      const pathA = copyPath('A');
      const A = computer(h, pathA);
      const id = newId();
      await A.remember('contacts v1', { cellId: id });
      h.oneFault = () => ({ status: 200, body: { found: true } }); // no envelope
      await assert.rejects(A.recallOne(id), (e: unknown) => e instanceof SaihmEndpointError && e.code === 'malformed_response');
      const recipient = deriveIdentity(new Uint8Array(32).fill(94));
      const shared = await A.share({ cellId: id, recipientRecord: encodeIdentityRecord(recipient.identityRecord), recipientPinnedAgentIdHashHex: toHex(recipient.agentIdHash) }).then(
        () => 'shared',
        (e: { code?: string }) => e.code,
      );
      assert.equal(shared, 'cell_not_found', 'setup: the share is refused');
      assert.equal(failText(await attempt(computer(h, pathA), 'contacts + added', id)), refusal(ID_USED), 'a new session');
      assert.ok(readFileSync(pathA, 'utf-8').includes('contacts v1'), 'the copy still holds it');
    } finally {
      await h.close();
    }
  });

  for (const via of ['a share', 'a refused edit'] as const) {
    it(`${via} whose read finds a memory gone while a newer version reaches the copy leaves that version there`, async () => {
      const h = await hosted();
      try {
        const pathA = copyPath('A');
        const A = computer(h, pathA);
        const id = newId();
        await A.remember('log v1', { cellId: id });
        const B = computer(h, undefined);
        assert.equal(text(await B.recall(), id), 'log v1', 'setup: B read it');
        if (via === 'a refused edit') await B.remember('log v2, edited on B', { cellId: id }); // A's edit is then refused
        await eraseElsewhere(h, id);
        let release!: () => void;
        let held!: () => void;
        const arrived = new Promise<void>((r) => (held = r));
        h.holdOne = () => {
          h.holdOne = undefined;
          held();
          return new Promise<void>((r) => (release = r));
        };
        const recipient = deriveIdentity(new Uint8Array(32).fill(95));
        const first =
          via === 'a share'
            ? A.share({ cellId: id, recipientRecord: encodeIdentityRecord(recipient.identityRecord), recipientPinnedAgentIdHashHex: toHex(recipient.agentIdHash) }).then(
                () => 'shared',
                (e: { code?: string }) => e.code,
              )
            : attempt(A, 'log v1 + added on A', id).then((e) => failText(e));
        await within(arrived, 5_000, 'the read'); // its answer is computed: no such cell
        await B.remember('log written again on B', { cellId: id }); // B read it before, so its edit is stored: back again
        assert.equal((await A.recallOne(id))?.plaintext, 'log written again on B', 'setup: a read puts it in the copy');
        release();
        assert.equal(await first, via === 'a share' ? 'cell_not_found' : refusal(ERASED), 'each answers what its read found');
        assert.ok(readFileSync(pathA, 'utf-8').includes('log written again on B'), 'the newer version stays in the copy');
      } finally {
        await h.close();
      }
    });
  }

  it('a copy that cannot be written: a read, a share and an edit that find a memory gone still answer as they should', async () => {
    const h = await hosted();
    const ro = mkdtempSync(join(dir, 'ro-'));
    try {
      const pathA = join(ro, 'copy.json');
      const A = computer(h, pathA);
      const [one, two, three] = [newId(), newId(), newId()];
      for (const id of [one, two, three]) await A.remember(`note ${id.slice(0, 4)}`, { cellId: id });
      await A.recall();
      for (const id of [one, two]) await eraseElsewhere(h, id);
      await computer(h, undefined).remember('note v2 on B', { cellId: three });
      await eraseElsewhere(h, three);
      chmodSync(ro, 0o500);
      assert.equal(await A.recallOne(one), null);
      const recipient = deriveIdentity(new Uint8Array(32).fill(93));
      const shared = await A.share({ cellId: two, recipientRecord: encodeIdentityRecord(recipient.identityRecord), recipientPinnedAgentIdHashHex: toHex(recipient.agentIdHash) }).then(
        () => 'shared',
        (e: { code?: string }) => e.code,
      );
      assert.equal(shared, 'cell_not_found');
      assert.equal(failText(await attempt(A, 'note + added on A', three)), refusal(ERASED));
    } finally {
      chmodSync(ro, 0o700);
      await h.close();
    }
  });

  it("a new memory refused as stale (its id was drawn here, so no endpoint should) is passed on in the endpoint's words", async () => {
    const h = await hosted();
    try {
      h.rememberFault = () => ({ status: 409, body: { error: 'BLIND_STALE_SEQ', reason: 'seq <= high-water mark' } });
      const r = await measured(h, () => computer(h, copyPath('A')).remember('a new memory').then(() => 'stored', (e: unknown) => e));
      assert.equal(failText(r.value), 'SAIHM error [BLIND_STALE_SEQ] (status 409): SAIHM endpoint saihm_remember failed: 409 Conflict (BLIND_STALE_SEQ)');
      assert.deepEqual(r.requests, [], 'nothing more asked');
    } finally {
      await h.close();
    }
  });

  it('a write that fails for another reason is passed on as it was, with nothing more asked', async () => {
    const h = await hosted();
    try {
      const A = computer(h, copyPath('A'));
      const id = newId();
      await A.remember('agenda v1', { cellId: id });
      h.rememberFault = () => ({ status: 503, body: { error: 'busy' } });
      const r = await measured(h, () => attempt(A, 'agenda v2', id));
      assert.deepEqual([(r.value as SaihmEndpointError).status, (r.value as SaihmEndpointError).code], [503, 'busy']);
      assert.deepEqual(r.requests, [], 'no read: only a refusal as stale has a text to choose');
    } finally {
      await h.close();
    }
  });

  it('at the hard cap: the read after a refusal is refused too, and the refusal stands; an erased memory is read free', async () => {
    const h = await hosted();
    try {
      const A = computer(h, undefined);
      const id = newId();
      await A.remember('budget v1', { cellId: id });
      await computer(h, undefined).remember('budget v2, edited on B', { cellId: id });
      h.setCap(0);
      const capped = await measured(h, () => attempt(A, 'budget v1 + added on A', id));
      assert.deepEqual([(capped.value as SaihmEndpointError).status, (capped.value as SaihmEndpointError).code], [409, 'BLIND_STALE_SEQ']);
      assert.equal(failText(capped.value), refusal(CHANGED_SINCE), 'what the refusal itself shows');
      assert.deepEqual([capped.requests, capped.charged], [[`one:${id}`], 0]);
      await eraseElsewhere(h, id);
      const gone = await measured(h, () => attempt(A, 'budget v1 + added on A', id));
      assert.equal(failText(gone.value), refusal(ERASED), 'a memory gone is read without a charge, so even at the cap');
      assert.deepEqual([gone.requests, gone.charged], [[`one:${id}`], 0]);
    } finally {
      await h.close();
    }
  });

  it('a sequence number written with a leading zero is not one: listed as "01", the memory the copy holds as "1" is read again', async () => {
    const h = await hosted();
    try {
      const pathA = copyPath('A');
      const A = computer(h, pathA);
      const id = newId();
      await A.remember('memo v1', { cellId: id });
      h.pageFault = (_n, page) => ({
        status: 200,
        body: { ...page, cells: page.cells.map((c) => ((c as { cellId: string }).cellId === id ? { ...(c as object), seq: '01' } : c)) },
      });
      const r = await measured(h, () => A.recall());
      assert.equal(text(r.value, id), 'memo v1');
      assert.deepEqual(r.requests, ['list', `delta(0)+${id}`], 'not the number the copy holds, so it is read again');
      h.pageFault = undefined;
      // The copy's own entry, and a mark in the marks file, follow the same rule: neither "01" nor "007" is a number.
      const copy = JSON.parse(readFileSync(pathA, 'utf-8')) as Record<string, { seq: string }>;
      copy[id]!.seq = '01';
      writeFileSync(pathA, JSON.stringify(copy));
      const r2 = await measured(h, () => computer(h, pathA).recall());
      assert.deepEqual(r2.requests, ['list', `delta(0)+${id}`], 'a copy entry at "01" is not the listed "1"');
      const marks = join(dir, `marks-${randomBytes(4).toString('hex')}`, 'seq.json');
      mkdirSync(join(marks, '..'), { recursive: true });
      writeFileSync(marks, JSON.stringify({ [id]: { seq: '007' } })); // the file is this identity's: keyed by cell id
      // Read as 7, the mark would stand above the live version 1, and the edit's read of it would be refused as a rollback.
      assert.equal(await markedComputer(h, marks).remember('memo v2', { cellId: id }).then(() => 'stored', (e: { code?: string }) => e.code), 'stored');
      assert.equal(h.wireOf(id)?.seq, '2', 'written at the number after the live one');
    } finally {
      await h.close();
    }
  });
});

describe('PC-RECALL-VERSIONS: the copy file, cells that cannot be read, and the hard cap', () => {
  it('a copy file written before the fix: a cell at another version or without one is read once, then known', async () => {
    const h = await hosted();
    try {
      const { pathA, ids } = await twoComputers(h);
      // The file as every release since the copy began writes it: {cellId: {cellId, plaintext, seq, commitmentHash}}.
      const file = JSON.parse(readFileSync(pathA, 'utf-8')) as Record<string, Record<string, unknown>>;
      assert.deepEqual(Object.keys(file[ids[0]!]!).sort(), ['cellId', 'commitmentHash', 'plaintext', 'seq'], 'setup: the shape');
      delete file[ids[1]!]!.commitmentHash; // an entry without a version is not loaded
      file[ids[2]!]!.commitmentHash = 'a'.repeat(64); // a version the endpoint does not hold
      file[ids[2]!]!.plaintext = 'a stale text';
      writeFileSync(pathA, JSON.stringify(file), { mode: 0o600 });
      const A2 = computer(h, pathA);
      const r = await measured(h, () => A2.recall());
      assert.deepEqual(r.requests, ['list', `delta(1)+${ids[1]},${ids[2]}`]);
      assert.equal(text(r.value, ids[2]!), 'memory 2 v1');
      const again = await measured(h, () => A2.recall());
      assert.deepEqual(again.requests, ['list', 'delta(3)+'], 'read once, then known');
    } finally {
      await h.close();
    }
  });

  it('a changed cell that cannot be read now is left out, not served at its old version, and comes back later', async () => {
    const h = await hosted();
    try {
      const { A, B, pathA, ids } = await twoComputers(h);
      await B.remember('memory 0 v2, edited on B', { cellId: ids[0]! });
      h.unreadable.add(ids[0]!);
      const r = await measured(h, () => A.recall());
      assert.deepEqual(r.requests, ['list', 'delta(2)+'], 'asked for, nothing came back');
      assert.equal(text(r.value, ids[0]!), undefined, 'left out, as a full recall leaves it out');
      assert.equal(text(await computer(h, undefined).recall(), ids[0]!), undefined, 'control: the full recall leaves it out');
      assert.ok(!readFileSync(pathA, 'utf-8').includes('memory 0 v1'), 'the old version is not kept');
      h.unreadable.clear();
      assert.equal(text(await A.recall(), ids[0]!), 'memory 0 v2, edited on B');
    } finally {
      await h.close();
    }
  });

  it('a cached cell the listing leaves out (no key held) is asked for and dropped, as from a full recall', async () => {
    const h = await hosted();
    try {
      const { A, ids } = await twoComputers(h);
      h.unkeyed.add(ids[1]!);
      const r = await measured(h, () => A.recall());
      assert.deepEqual(r.requests, ['list', 'delta(2)+']);
      assert.equal(r.charged, 1, 'a read of a cell with no key held is not charged');
      assert.equal(text(r.value, ids[1]!), undefined);
      assert.equal(text(await computer(h, undefined).recall(), ids[1]!), undefined, 'control: the full recall');
    } finally {
      await h.close();
    }
  });

  it('at the hard cap the recall is refused with the endpoint quota error, and the copy is left as it was', async () => {
    const h = await hosted();
    try {
      const { A, pathA } = await twoComputers(h);
      const before = readFileSync(pathA, 'utf-8');
      h.setCap(0);
      const r = await measured(h, () => A.recall().then(() => 'answered', (e: unknown) => e));
      assert.deepEqual(r.requests, ['list'], 'the refused listing, and nothing after it');
      assert.ok(r.value instanceof SaihmEndpointError);
      assert.deepEqual([r.value.status, r.value.code], [429, 'quota_hard_cap']);
      assert.ok(r.value.message.startsWith(CHECK_FAILED), r.value.message);
      assert.equal(r.charged, 0);
      assert.equal(readFileSync(pathA, 'utf-8'), before);
    } finally {
      await h.close();
    }
  });

  it('the cap reached by the delta: refused as a delta that must read a new cell is, and the copy is left as it was', async () => {
    const h = await hosted();
    try {
      const { A, B, pathA, ids } = await twoComputers(h);
      await B.remember('memory 0 v2, edited on B', { cellId: ids[0]! });
      const before = readFileSync(pathA, 'utf-8');
      h.setCap(1); // the listing page, and no cell read
      const r = await measured(h, () => A.recall().then(() => 'answered', (e: unknown) => e));
      assert.deepEqual(r.requests, ['list', 'delta(2)refused']);
      assert.ok(r.value instanceof SaihmEndpointError);
      assert.deepEqual([r.value.status, r.value.code], [429, 'quota_hard_cap']);
      assert.equal(readFileSync(pathA, 'utf-8'), before);
    } finally {
      await h.close();
    }
  });
});

describe('PC-RECALL-VERSIONS: a local write while the listing is in flight', () => {
  for (const what of ['remember', 'forget'] as const) {
    it(`a ${what} that lands while the listing is held is kept`, async () => {
      const h = await hosted();
      try {
        const { A, B, pathA, ids } = await twoComputers(h);
        await B.remember('memory 1 v2, edited on B', { cellId: ids[1]! });
        let open!: () => void;
        h.holdList = new Promise<void>((r) => (open = r));
        const held = new Promise<void>((r) => (h.onListHeld = r));
        const inFlight = A.recall();
        await held; // the listing answer is computed (before the write) and held
        const z = `${'e'.repeat(31)}0`;
        if (what === 'remember') await A.remember('written while the listing was held', { cellId: z });
        else await A.forget(ids[0]!);
        const disk = readFileSync(pathA, 'utf-8');
        assert.ok(what === 'remember' ? disk.includes('written while the listing was held') : !disk.includes('memory 0 v1'), 'positive control');
        h.holdList = undefined;
        const lists = h.log.length;
        open();
        const cells = await inFlight;
        // The write landed before the delta's snapshot was taken, so the recall did not have to run again.
        assert.deepEqual(h.log.slice(lists).filter((q) => q.startsWith('list')), [], 'one listing for this recall');
        const after = readFileSync(pathA, 'utf-8');
        // The write landed before the snapshot the delta is checked against, so this recall still applies it.
        assert.equal(text(cells, ids[1]!), 'memory 1 v2, edited on B', "B's edit reaches this very recall");
        assert.ok(after.includes('memory 1 v2, edited on B'));
        if (what === 'remember') {
          assert.equal(text(cells, z), 'written while the listing was held');
          assert.ok(after.includes('written while the listing was held'));
        } else {
          assert.equal(text(cells, ids[0]!), undefined);
          assert.ok(!after.includes('memory 0 v1'));
        }
      } finally {
        await h.close();
      }
    });
  }
});

/** Hold the next `times` delta answers once each is computed; `during(i)` runs while the i-th is held. */
function holdDeltas(h: Hosted, times: number, during: (i: number) => Promise<void>): void {
  let i = 0;
  h.holdDelta = async () => {
    if (i >= times) return;
    await during(i++);
  };
}
/** The exact error a recall fails with when every attempt was overtaken by a write on this computer. */
const INTERRUPTED =
  'Recall stopped: your memories on this device kept changing while it was reading them. Nothing was lost. Try ' +
  'again once they stop changing.';

describe('PC-RECALL-VERSIONS: a local write while the delta answer is in flight', () => {
  for (const session of ['same', 'next'] as const) {
    it(`${session} session: the recall runs again and answers B's version, and an edit built on it keeps B's change`, async () => {
      const h = await hosted();
      try {
        const { A, B, pathA, ids } = await twoComputers(h);
        await B.remember('memory 0 v2, edited on B', { cellId: ids[0]! });
        const C = session === 'same' ? A : computer(h, pathA);
        const z = newId();
        holdDeltas(h, 1, async () => {
          await C.remember('an unrelated memory written meanwhile', { cellId: z });
        });
        const r = await measured(h, () => C.recall());
        assert.deepEqual(
          r.requests,
          ['list', `delta(2)+${ids[0]}`, `one:${z}`, 'list', `delta(3)+${ids[0]}`],
          'the overtaken answer is dropped and the recall runs again',
        );
        assert.equal(text(r.value, ids[0]!), 'memory 0 v2, edited on B', "B's version, not the copy's old one");
        assert.equal(text(r.value, z), 'an unrelated memory written meanwhile', 'and the write made meanwhile');
        await C.remember(`${text(r.value, ids[0]!)} + added on A`, { cellId: ids[0]! });
        assert.equal(await truth(h, ids[0]!), 'memory 0 v2, edited on B + added on A');
      } finally {
        await h.close();
      }
    });
  }

  it('overtaken on every attempt: the recall fails plainly, no mark moved, and an edit from older text is refused', async () => {
    const h = await hosted();
    try {
      const { A, B, pathA, ids } = await twoComputers(h);
      await B.remember('memory 0 v2, edited on B', { cellId: ids[0]! });
      holdDeltas(h, COPY_RECALL_ATTEMPTS, async (i) => {
        await A.remember(`unrelated memory ${i}`, { cellId: newId() });
      });
      const r = await measured(h, () => A.recall().then(() => 'answered', (e: unknown) => e));
      assert.ok(r.value instanceof SaihmEndpointError, String(r.value));
      assert.deepEqual([r.value.status, r.value.code, r.value.message], [409, 'recall_interrupted', INTERRUPTED]);
      assert.equal(r.requests.filter((q) => q === 'list').length, COPY_RECALL_ATTEMPTS, 'tried exactly that often');
      assert.ok(readFileSync(pathA, 'utf-8').includes('memory 0 v1'), 'the copy still holds what it held');
      // A's mark for the cell is where its copy and its last answer are: an edit of the old text is refused as stale.
      const edit = await A.remember('memory 0 v1 + added on A', { cellId: ids[0]! }).then(() => 'stored', (e: { code?: string }) => e.code);
      assert.equal(edit, 'BLIND_STALE_SEQ');
      assert.equal(await truth(h, ids[0]!), 'memory 0 v2, edited on B', "B's version kept");
      assert.equal(text(await A.recall(), ids[0]!), 'memory 0 v2, edited on B', 'and the next recall answers it');
    } finally {
      await h.close();
    }
  });

  it('an EMPTY copy: a remember that lands while its first recall is held stays in the copy and in the answer', async () => {
    const h = await hosted();
    try {
      const B = computer(h, copyPath('B'));
      const x = newId();
      await B.remember('a memory written elsewhere', { cellId: x });
      const pathC = copyPath('C');
      const C = computer(h, pathC);
      const z = newId();
      holdDeltas(h, 1, async () => {
        assert.equal(h.log.at(-1), `delta(0)+${x}`, 'setup: the held answer is the empty copy delta');
        await C.remember('WRITTEN WHILE THE FIRST RECALL WAS IN FLIGHT', { cellId: z });
        assert.ok(readFileSync(pathC, 'utf-8').includes('WRITTEN WHILE THE FIRST RECALL WAS IN FLIGHT'), 'positive control');
      });
      const cells = await C.recall();
      assert.ok(readFileSync(pathC, 'utf-8').includes('WRITTEN WHILE THE FIRST RECALL WAS IN FLIGHT'), 'the write stays in the copy');
      assert.equal(text(cells, z), 'WRITTEN WHILE THE FIRST RECALL WAS IN FLIGHT');
      assert.equal(text(cells, x), 'a memory written elsewhere');
    } finally {
      await h.close();
    }
  });
});

describe('PC-RECALL-VERSIONS: a seq mark moves only with the content this computer holds and answers', () => {
  it('no copy: a recall-all refused part way moves no mark, so an edit built on older text is still refused', async () => {
    const h = await hosted();
    try {
      const A = computer(h, undefined);
      const B = computer(h, copyPath('B'));
      const id = newId();
      await A.remember('v1', { cellId: id });
      await B.recall();
      await B.remember('v2 from B', { cellId: id });
      h.rowsFault = (kind, rows) => (kind === 'all' ? [...rows, rows[0]] : rows); // the cell twice: refused whole
      const r = await A.recall().then(() => 'answered', (e: { code?: string }) => e.code);
      assert.equal(r, 'malformed_response', 'setup: the answer is refused after its first row was opened');
      h.rowsFault = undefined;
      const edit = await A.remember('v1 + added on A', { cellId: id }).then(() => 'stored', (e: { code?: string }) => e.code);
      assert.equal(edit, 'BLIND_STALE_SEQ');
      assert.equal(await truth(h, id), 'v2 from B');
    } finally {
      await h.close();
    }
  });

  it('with the copy: a delta refused part way moves no mark, so an edit built on older text is still refused', async () => {
    const h = await hosted();
    try {
      const { A, B, ids } = await twoComputers(h);
      await B.remember('memory 0 v2, edited on B', { cellId: ids[0]! });
      h.rowsFault = (kind, rows) => (kind === 'delta' ? [...rows, rows[0]] : rows);
      const r = await A.recall().then(() => 'answered', (e: { code?: string }) => e.code);
      assert.equal(r, 'malformed_response', 'setup: the delta is refused after its first row was opened');
      h.rowsFault = undefined;
      const edit = await A.remember('memory 0 v1 + added on A', { cellId: ids[0]! }).then(() => 'stored', (e: { code?: string }) => e.code);
      assert.equal(edit, 'BLIND_STALE_SEQ');
      assert.equal(await truth(h, ids[0]!), 'memory 0 v2, edited on B');
    } finally {
      await h.close();
    }
  });

  it('a read of one cell by id puts the version it answers into the copy', async () => {
    const h = await hosted();
    try {
      const { A, B, pathA, ids } = await twoComputers(h);
      await B.remember('memory 0 v2, edited on B', { cellId: ids[0]! });
      assert.equal((await A.recallOne(ids[0]!))?.plaintext, 'memory 0 v2, edited on B');
      assert.ok(readFileSync(pathA, 'utf-8').includes('memory 0 v2, edited on B'), 'the copy holds the answered version');
      const r = await measured(h, () => A.recall());
      assert.deepEqual(r.requests, ['list', 'delta(3)+'], 'so the next recall reads nothing again');
      const mtime = statSync(pathA, { bigint: true }).mtimeNs;
      await A.recallOne(ids[0]!);
      assert.equal(statSync(pathA, { bigint: true }).mtimeNs, mtime, 'a version the copy already holds is not written again');
    } finally {
      await h.close();
    }
  });

  it('a cell erased here and written again elsewhere: the recall leaves it out and its mark does not move', async () => {
    const h = await hosted();
    try {
      const { A, B, pathA, ids } = await twoComputers(h);
      await A.forget(ids[0]!); // this identity's erasure feed now names it
      await B.remember('written again on B after the erasure', { cellId: ids[0]! });
      const cells = await A.recall();
      assert.equal(text(cells, ids[0]!), undefined, 'the erasure keeps winning here');
      assert.ok(!readFileSync(pathA, 'utf-8').includes('written again on B'), 'and the copy does not hold it');
      // A erased it, and has not read B's version since: a write of its own is refused as stale (here, see the R16 tests).
      const edit = await A.remember('written on A', { cellId: ids[0]! }).then(() => 'stored', (e: { code?: string }) => e.code);
      assert.equal(edit, 'BLIND_STALE_SEQ');
      assert.equal(await truth(h, ids[0]!), 'written again on B after the erasure');
    } finally {
      await h.close();
    }
  });

  it('a copy that cannot be written while the listing is off, then on again: the next recall still reads the change', async () => {
    const h = await hosted();
    const sub = mkdtempSync(join(dir, 'unwritable-'));
    try {
      const pathA = join(sub, 'copy.json');
      const A = computer(h, pathA);
      const B = computer(h, copyPath('B'));
      const id = newId();
      await A.remember('v1', { cellId: id });
      await A.recall();
      await B.recall();
      await B.remember('v2 from B', { cellId: id });
      rmSync(sub, { recursive: true, force: true });
      writeFileSync(sub, 'not a directory');
      h.listing = 'off'; // the full recall's copy write fails: the copy is put back as it was
      const r = await A.recall().then(() => 'answered', (e: unknown) => e);
      assert.ok(r instanceof Error && /EEXIST|ENOTDIR/.test(r.message), `setup: the full recall fails on the copy write: ${String(r)}`);
      h.listing = 'on';
      // The copy was put back as it was, so with the listing on the change is asked for again, and its write fails again.
      const again = await A.recall().then(() => 'answered', (e: unknown) => e);
      assert.ok(again instanceof Error && /EEXIST|ENOTDIR/.test(again.message), `the copy kept what it failed to write: ${String(again)}`);
      rmSync(sub, { force: true });
      mkdirSync(sub);
      const seen = text(await A.recall(), id);
      assert.equal(seen, 'v2 from B', 'the listing shows the change against the copy as it was');
      await A.remember(`${seen} + added on A`, { cellId: id });
      assert.equal(await truth(h, id), 'v2 from B + added on A', 'and the mark moved with it, so the edit is stored');
    } finally {
      await h.close();
      rmSync(sub, { recursive: true, force: true });
    }
  });

  it('a copy that cannot be written: the recall fails, the copy and the marks stay as they were, then it recovers', async () => {
    const h = await hosted();
    const sub = mkdtempSync(join(dir, 'unwritable-'));
    try {
      const pathA = join(sub, 'copy.json');
      const A = computer(h, pathA);
      const B = computer(h, copyPath('B'));
      const id = newId();
      await A.remember('v1', { cellId: id });
      await A.recall();
      await B.recall();
      await B.remember('v2 from B', { cellId: id });
      // The directory becomes a regular file, so every write of the copy fails (mkdir EEXIST), unprivileged.
      rmSync(sub, { recursive: true, force: true });
      writeFileSync(sub, 'not a directory');
      const r = await A.recall().then(() => 'answered', (e: unknown) => e);
      assert.ok(r instanceof Error && /EEXIST|ENOTDIR/.test(r.message) && r.message.includes(sub), `setup: the recall fails on the copy write: ${String(r)}`);
      // The copy was put back as it was, so the next recall asks for the change again, and its write fails again.
      const again = await A.recall().then(() => 'answered', (e: unknown) => e);
      assert.ok(again instanceof Error && /EEXIST|ENOTDIR/.test(again.message), `the copy kept what it failed to write: ${String(again)}`);
      // Nothing moved: an edit built on the old text is refused as stale, so B's version is not overwritten...
      const stale = await A.remember('v1 + added on A', { cellId: id }).then(() => 'stored', (e: { code?: string }) => e.code);
      assert.equal(stale, 'BLIND_STALE_SEQ');
      // ...and once the copy can be written again, the next recall reads B's version and an edit on it is stored.
      rmSync(sub, { force: true });
      mkdirSync(sub);
      const seen = text(await A.recall(), id);
      assert.equal(seen, 'v2 from B');
      await A.remember(`${seen} + added on A`, { cellId: id });
      assert.equal(await truth(h, id), 'v2 from B + added on A');
    } finally {
      await h.close();
      rmSync(sub, { recursive: true, force: true });
    }
  });

  it("a share's read of the cell puts the version it read into the copy, even when the share is then refused", async () => {
    const h = await hosted();
    try {
      const { A, B, pathA, ids } = await twoComputers(h);
      await B.remember('memory 0 v2, edited on B', { cellId: ids[0]! });
      const bad = { mldsaPubKey: 'zz', mlkemPubKey: 'zz', mlkemPubKeySelfSig: 'zz' };
      const r = await A.share({ cellId: ids[0]!, recipientRecord: bad, recipientPinnedAgentIdHashHex: 'zz' }).then(() => 'shared', (e: { code?: string }) => e.code);
      assert.equal(r, 'bad_recipient', 'setup: refused after the read');
      assert.ok(readFileSync(pathA, 'utf-8').includes('memory 0 v2, edited on B'), 'the copy holds the version read');
    } finally {
      await h.close();
    }
  });

  it("a remember's read of the live version puts it into the copy, even when the write is then refused", async () => {
    const h = await hosted();
    try {
      const { B, pathA, ids } = await twoComputers(h);
      await B.remember('memory 0 v2, edited on B', { cellId: ids[0]! });
      const A2 = computer(h, pathA); // a new session: it has not seen the cell, so its write reads the live one first
      h.rememberFault = () => ({ status: 503, body: { error: 'busy' } });
      const r = await A2.remember('memory 0 v3 from A', { cellId: ids[0]! }).then(() => 'stored', (e: { code?: string }) => e.code);
      assert.equal(r, 'busy', 'setup: the write is refused after its read');
      assert.ok(readFileSync(pathA, 'utf-8').includes('memory 0 v2, edited on B'), 'the copy holds the version read');
    } finally {
      await h.close();
    }
  });
});

/** `fn` with `name` set to `value` in the environment, as it was afterwards. */
async function withEnv<T>(name: string, value: string, fn: () => Promise<T>): Promise<T> {
  const was = process.env[name];
  process.env[name] = value;
  try {
    return await fn();
  } finally {
    if (was === undefined) delete process.env[name];
    else process.env[name] = was;
  }
}
/** The first read of one cell by id from now on is answered as computed, then held until `release` (see holdOne). */
function holdNextRead(h: Hosted): { arrived: Promise<void>; release: () => void } {
  let release!: () => void;
  let held!: () => void;
  const arrived = new Promise<void>((r) => (held = r));
  const gate = new Promise<void>((r) => (release = r));
  h.holdOne = () => {
    h.holdOne = undefined;
    held();
    return gate;
  };
  return { arrived: within(arrived, 5_000, 'the read'), release: () => release() };
}
/** The next answer `set` installs a hold for is computed, then held until `release`. */
function holdNext(set: (hold: (() => Promise<void>) | undefined) => void, what: string): { arrived: Promise<void>; release: () => void } {
  let release!: () => void;
  let held!: () => void;
  const arrived = new Promise<void>((r) => (held = r));
  const gate = new Promise<void>((r) => (release = r));
  set(() => {
    set(undefined);
    held();
    return gate;
  });
  return { arrived: within(arrived, 5_000, what), release: () => release() };
}
const recipientOf = (fill: number) => {
  const r = deriveIdentity(new Uint8Array(32).fill(fill));
  return { recipientRecord: encodeIdentityRecord(r.identityRecord), recipientPinnedAgentIdHashHex: toHex(r.agentIdHash) };
};

/**
 * R16-L1 and its class. The endpoint keeps an erased memory's sequence number, refuses a write at or below it, and
 * stores one past it: a device whose mark is the last version's saves the memory again with an edit, and nobody is
 * asked. On the device that erased it, with the copy on, the edit was refused "Recall it to see the newer version"
 * while every recall there leaves the memory out (its erasure feed names it): the same refusal on every try, one
 * charged read each. In a later session, an edit whose own read found the memory gone wrote it anyway. Now a memory
 * this process knows to be erased (this device's erasure feed, its own forget, or an answer showing it gone) is final
 * here: an edit of it from this device, which had read or saved it, is refused with the erased text and nothing asked,
 * until a read here shows the memory live again.
 */
describe('PC-RECALL-VERSIONS R16: an edit of a memory this device knows erased is refused here, and asks nothing', () => {
  it('copy on: erased on this device, saved again elsewhere: every edit here is refused here, before and after a recall', async () => {
    const h = await hosted();
    try {
      const A = computer(h, copyPath('A'));
      const id = newId();
      await A.remember('plan v1', { cellId: id });
      await A.recall();
      const B = elsewhere(h, undefined);
      assert.equal(text(await B.recall(), id), 'plan v1', 'setup: B read it');
      await A.forget(id);
      // B read it before the erasure, so its edit goes at the next number and the endpoint stores it: the memory is back.
      assert.equal(await attempt(B, 'plan written again on B', id), 'stored', 'setup: saved again elsewhere');
      for (const when of ['at once', 'after a recall', 'again after another']) {
        if (when !== 'at once') assert.equal(text(await A.recall(), id), undefined, "this device's erasure keeps winning in its recall");
        const r = await measured(h, () => attempt(A, 'plan v1 + added on A', id));
        assert.equal(failText(r.value), refusedHere(ERASED), when);
        assert.deepEqual([r.calls, r.charged], [0, 0], `${when}: nothing asked, nothing charged`);
      }
      assert.equal(await truth(h, id), 'plan written again on B', "nothing of A's was stored");
    } finally {
      await h.close();
    }
  });

  it('copy off: erased on this device, saved again elsewhere: refused here until a recall shows the newer version', async () => {
    const h = await hosted();
    try {
      const A = computer(h, undefined);
      const id = newId();
      await A.remember('plan v1', { cellId: id });
      const B = elsewhere(h, undefined);
      await B.recall();
      await A.forget(id);
      assert.equal(await attempt(B, 'plan written again on B', id), 'stored', 'setup: saved again elsewhere');
      const r = await measured(h, () => attempt(A, 'plan v1 + added on A', id));
      assert.equal(failText(r.value), refusedHere(ERASED));
      assert.deepEqual([r.calls, r.charged], [0, 0]);
      // A recall here shows the version B saved: from then on an edit of it is checked as any other.
      assert.equal(await editFrom(A, await A.recall(), id, 'added on A'), 'stored');
      assert.equal(await truth(h, id), 'plan written again on B + added on A');
    } finally {
      await h.close();
    }
  });

  for (const copy of ['on', 'off'] as const) {
    it(`copy ${copy}: a later session whose edit's own read finds the memory erased is refused before its write`, async () => {
      const h = await hosted();
      try {
        const marks = join(dir, `marks-${randomBytes(4).toString('hex')}`, 'seq.json');
        const path = copy === 'on' ? copyPath('A') : undefined;
        const id = newId();
        await markedComputer(h, marks, path).remember('todo v1', { cellId: id });
        // Nothing written since this device saved it, so a write at its next number would be stored as the memory again.
        await eraseElsewhere(h, id);
        // The next session, with no tier named: a write would read the status first, so any request but the read shows.
        const A2 = new SaihmProClient(h.url, 'Bearer test', MASTER, { seqStatePath: marks, ...(path ? { recallCachePath: path } : {}) });
        const first = await measured(h, () => attempt(A2, 'todo v1 + added on A', id));
        assert.equal(failText(first.value), refusedHere(ERASED), 'refused after its own read');
        assert.deepEqual([first.requests, first.calls, first.charged], [[`one:${id}`], 1, 0], 'that read alone, free');
        const again = await measured(h, () => attempt(A2, 'todo v1 + added on A', id));
        assert.equal(failText(again.value), refusedHere(ERASED));
        assert.deepEqual([again.calls, again.charged], [0, 0], 'then nothing is asked');
        assert.equal(await truth(h, id), undefined, 'the erasure stands');
        if (path) assert.ok(!readFileSync(path, 'utf-8').includes('todo v1'), 'and its text has left the copy');
      } finally {
        await h.close();
      }
    });

    it(`copy ${copy}: refused because another device changed it, the same edit again without a recall is refused again`, async () => {
      const h = await hosted();
      try {
        const path = copy === 'on' ? copyPath('A') : undefined;
        const A = computer(h, path);
        const id = newId();
        await A.remember('rota v1', { cellId: id });
        const seen = await A.recall();
        assert.equal(await attempt(elsewhere(h, undefined), 'rota v2, edited on B', id), 'stored', 'setup: edited elsewhere');
        for (const n of [1, 2]) {
          const r = await attempt(A, `${text(seen, id)} + added on A`, id);
          assert.equal(failText(r), refusal(CHANGED_SINCE), `try ${n}`);
        }
        // The read after the first refusal moved no mark and put nothing in the copy: B's version was never seen here.
        assert.equal(await truth(h, id), 'rota v2, edited on B', "B's version is kept");
        if (path) assert.ok(!readFileSync(path, 'utf-8').includes('rota v2'), 'the copy holds only what A saw');
        assert.equal(await editFrom(A, await A.recall(), id, 'added on A'), 'stored', 'recalled, then edited: stored');
      } finally {
        await h.close();
      }
    });

    it(`copy ${copy}: a read by id and a share that found the memory gone: the next edit of each is refused here`, async () => {
      const h = await hosted();
      try {
        const A = computer(h, copy === 'on' ? copyPath('A') : undefined);
        const [one, two] = [newId(), newId()];
        await A.remember('first note', { cellId: one });
        await A.remember('second note', { cellId: two });
        for (const id of [one, two]) await eraseElsewhere(h, id);
        assert.equal(await A.recallOne(one), null);
        const shared = await A.share({ cellId: two, ...recipientOf(95) }).then(() => 'shared', (e: { code?: string }) => e.code);
        assert.equal(shared, 'cell_not_found');
        for (const id of [one, two]) {
          const r = await measured(h, () => attempt(A, 'note + added on A', id));
          assert.equal(failText(r.value), refusedHere(ERASED));
          assert.deepEqual([r.calls, r.charged], [0, 0]);
          assert.equal(await truth(h, id), undefined, 'the erasure stands');
        }
      } finally {
        await h.close();
      }
    });

    it(`copy ${copy}: a memory known erased that a read by id then shows saved again elsewhere is edited as any other`, async () => {
      const h = await hosted();
      try {
        const A = computer(h, copy === 'on' ? copyPath('A') : undefined);
        const id = newId();
        await A.remember('list v1', { cellId: id });
        const B = elsewhere(h, undefined);
        await B.recall();
        await A.forget(id);
        assert.equal(await attempt(B, 'list written again on B', id), 'stored', 'setup: saved again elsewhere');
        const seen = await A.recallOne(id);
        assert.equal(seen?.plaintext, 'list written again on B', 'setup: A reads the version B saved');
        assert.equal(await attempt(A, `${seen!.plaintext} + added on A`, id), 'stored', 'no false refusal');
        assert.equal(await truth(h, id), 'list written again on B + added on A');
      } finally {
        await h.close();
      }
    });

    it(`copy ${copy}: a memory known erased that a share's read then shows saved again elsewhere is edited as any other`, async () => {
      const h = await hosted();
      try {
        const A = computer(h, copy === 'on' ? copyPath('A') : undefined);
        const id = newId();
        await A.remember('list v1', { cellId: id });
        const B = elsewhere(h, undefined);
        await B.recall();
        await A.forget(id);
        assert.equal(await attempt(B, 'list written again on B', id), 'stored', 'setup: saved again elsewhere');
        await A.share({ cellId: id, ...recipientOf(96) });
        assert.equal(await attempt(A, 'list written again on B + added on A', id), 'stored', 'the share read it: no false refusal');
        assert.equal(await truth(h, id), 'list written again on B + added on A');
      } finally {
        await h.close();
      }
    });

    it(`copy ${copy}: a cellId a read found unused, then saved as a new memory, is edited as any other`, async () => {
      const h = await hosted();
      try {
        const A = computer(h, copy === 'on' ? copyPath('A') : undefined);
        const id = newId();
        assert.equal(await A.recallOne(id), null, 'setup: no such memory');
        assert.equal(await attempt(A, 'new under a chosen id', id), 'stored');
        assert.equal(await attempt(A, 'new under a chosen id, edited', id), 'stored', 'no false refusal');
        assert.equal(await truth(h, id), 'new under a chosen id, edited');
      } finally {
        await h.close();
      }
    });

    it(`copy ${copy}: erased here, saved again elsewhere, then read and edited here: a later session edits it as any other`, async () => {
      const h = await hosted();
      try {
        const marks = join(dir, `marks-${randomBytes(4).toString('hex')}`, 'seq.json');
        const path = copy === 'on' ? copyPath('A') : undefined;
        const A = markedComputer(h, marks, path);
        const id = newId();
        await A.remember('recipe v1', { cellId: id });
        const B = elsewhere(h, undefined);
        await B.recall();
        await A.forget(id); // this device's erasure feed names it from now on
        assert.equal(await attempt(B, 'recipe written again on B', id), 'stored', 'setup: saved again elsewhere');
        const seen = await A.recallOne(id);
        assert.equal(await attempt(A, `${seen!.plaintext} + edited on A`, id), 'stored', 'setup: read here, then edited');
        // The feed still names it, but that erasure is older than the version this device has since read and written.
        const A2 = markedComputer(h, marks, path);
        const r = await measured(h, () => attempt(A2, 'recipe written again on B + edited on A + again', id));
        assert.equal(r.value, 'stored', 'no false refusal in a later session');
        assert.equal(await truth(h, id), 'recipe written again on B + edited on A + again');
      } finally {
        await h.close();
      }
    });
  }

  it('copy on: erased elsewhere after this session read it, then a recall: its listing showed it gone, so the edit is refused here', async () => {
    const h = await hosted();
    try {
      const A = computer(h, copyPath('A'));
      const id = newId();
      await A.remember('notes v1', { cellId: id });
      await A.recall();
      await eraseElsewhere(h, id);
      assert.equal(text(await A.recall(), id), undefined, 'setup: the recall shows it gone');
      const r = await measured(h, () => attempt(A, 'notes v1 + added on A', id));
      assert.equal(failText(r.value), refusedHere(ERASED));
      assert.deepEqual([r.calls, r.charged], [0, 0]);
      assert.equal(await truth(h, id), undefined, 'the erasure stands');
    } finally {
      await h.close();
    }
  });

  it('copy off, the erasure feed off: an edit after this process erased the memory is refused here', async () => {
    const h = await hosted();
    try {
      const A = computer(h, undefined);
      const id = newId();
      await A.remember('draft v1', { cellId: id });
      await withEnv('SAIHM_ERASURE_FEED', '0', () => A.forget(id));
      const r = await measured(h, () => attempt(A, 'draft v1 + added', id));
      assert.equal(failText(r.value), refusedHere(ERASED));
      assert.deepEqual([r.calls, r.charged], [0, 0]);
      assert.equal(await truth(h, id), undefined, 'the erasure stands');
    } finally {
      await h.close();
    }
  });

  it("copy off: another session on this device erased it: the device's erasure feed names it, so an edit here is refused here", async () => {
    const h = await hosted();
    try {
      const marks = join(dir, `marks-${randomBytes(4).toString('hex')}`, 'seq.json');
      const S1 = markedComputer(h, marks);
      const id = newId();
      await S1.remember('memo v1', { cellId: id });
      await markedComputer(h, marks).forget(id);
      const r = await measured(h, () => attempt(S1, 'memo v1 + added', id));
      assert.equal(failText(r.value), refusedHere(ERASED));
      assert.deepEqual([r.calls, r.charged], [0, 0]);
      assert.equal(await truth(h, id), undefined, 'the erasure stands');
    } finally {
      await h.close();
    }
  });

  it('copy off: erased again by that session after a read here showed it saved again: the second erasure is final here too', async () => {
    const h = await hosted();
    try {
      const marks = join(dir, `marks-${randomBytes(4).toString('hex')}`, 'seq.json');
      const S1 = markedComputer(h, marks);
      const id = newId();
      await S1.remember('memo v1', { cellId: id });
      const B = elsewhere(h, undefined);
      await B.recall();
      const S2 = markedComputer(h, marks);
      await S2.forget(id);
      assert.equal(await attempt(B, 'memo written again on B', id), 'stored', 'setup: saved again elsewhere');
      assert.equal((await S1.recallOne(id))?.plaintext, 'memo written again on B', 'setup: read here');
      assert.equal(await attempt(S1, 'memo written again on B + edited on S1', id), 'stored', 'read here after the erasure: editable');
      await S2.forget(id); // a second erasure of the same id: a second line on the feed
      const r = await measured(h, () => attempt(S1, 'memo written again on B + edited on S1 + added', id));
      assert.equal(failText(r.value), refusedHere(ERASED));
      assert.deepEqual([r.calls, r.charged], [0, 0]);
      assert.equal(await truth(h, id), undefined, 'the second erasure stands');
    } finally {
      await h.close();
    }
  });

  it('a read whose answer was on its way before this process erased the memory leaves it known erased', async () => {
    const h = await hosted();
    try {
      const A = computer(h, undefined);
      const id = newId();
      await A.remember('agenda v1', { cellId: id });
      const hold = holdNextRead(h);
      const read = A.recallOne(id);
      await hold.arrived; // its answer is computed: the memory as it was
      await withEnv('SAIHM_ERASURE_FEED', '0', () => A.forget(id)); // no feed line: the order of the answers alone decides
      hold.release();
      assert.equal((await read)?.plaintext, 'agenda v1', 'the read answers what it found');
      const r = await measured(h, () => attempt(A, 'agenda v1 + added', id));
      assert.equal(failText(r.value), refusedHere(ERASED), 'an answer from before the erasure ends nothing');
      assert.deepEqual([r.calls, r.charged], [0, 0]);
      assert.equal(await truth(h, id), undefined, 'the erasure stands');
    } finally {
      await h.close();
    }
  });

  it("an edit's read that finds a memory gone while a read by id brings a newer version: the copy keeps it, the doubt is settled by a read", async () => {
    const h = await hosted();
    try {
      const pathA = copyPath('A');
      const id = newId();
      await computer(h, pathA).remember('rules v1', { cellId: id }); // the copy holds v1; that session ends
      const B = elsewhere(h, undefined);
      await B.recall();
      await eraseElsewhere(h, id);
      const A2 = computer(h, pathA); // a later session: no marks, so its edit reads the live version first
      const hold = holdNextRead(h);
      const edit = attempt(A2, 'rules v1 + added', id);
      await hold.arrived; // the edit's read is computed: no such cell
      assert.equal(await attempt(B, 'rules written again on B', id), 'stored', 'setup: saved again elsewhere');
      assert.equal((await A2.recallOne(id))?.plaintext, 'rules written again on B');
      hold.release();
      // The answers crossed: the one that found it gone arrived last, so it is taken as erased until a read settles it.
      assert.equal(failText(await edit), refusedHere(ERASED));
      assert.ok(readFileSync(pathA, 'utf-8').includes('rules written again on B'), 'the version read meanwhile stays in the copy');
      const settled = await A2.recallOne(id);
      assert.equal(await attempt(A2, `${settled!.plaintext} + added on A`, id), 'stored');
    } finally {
      await h.close();
    }
  });

  it('copy on: a memory this process saves while a recall reads the listing, then left out of its delta, is not taken for gone', async () => {
    const h = await hosted();
    try {
      const A = computer(h, copyPath('A'));
      await A.remember('an older memory');
      await A.recall(); // the copy holds one, so the next recall reads the listing
      const id = newId();
      let release!: () => void;
      const listed = new Promise<void>((r) => {
        h.onListHeld = () => {
          h.onListHeld = undefined;
          r();
        };
      });
      h.holdList = new Promise<void>((r) => (release = r));
      const rec = A.recall();
      await within(listed, 5_000, 'the listing'); // computed before the new memory existed
      assert.equal(await attempt(A, 'saved during the recall', id), 'stored');
      h.unreadable.add(id); // and its stored copy cannot be read just now: the delta leaves it out
      h.holdList = undefined;
      release();
      await rec;
      h.unreadable.delete(id);
      assert.equal(await attempt(A, 'saved during the recall, edited', id), 'stored', 'no false refusal');
      assert.equal(await truth(h, id), 'saved during the recall, edited');
    } finally {
      await h.close();
    }
  });

  it('the read after a refusal answered with something this client cannot read: a newer version is said, the copy keeps the memory', async () => {
    const h = await hosted();
    try {
      const pathA = copyPath('A');
      const A = computer(h, pathA);
      const id = newId();
      await A.remember('budget v1', { cellId: id });
      await A.recall();
      assert.equal(await attempt(elsewhere(h, undefined), 'budget v2 on B', id), 'stored', 'setup: edited elsewhere');
      h.oneFault = () => ({ status: 200, body: { found: true } }); // no envelope
      assert.equal(failText(await attempt(A, 'budget v1 + added', id)), refusal(CHANGED_SINCE));
      h.oneFault = undefined;
      assert.ok(readFileSync(pathA, 'utf-8').includes('budget v1'), 'not taken for gone: the copy keeps what it held');
      assert.equal(await editFrom(A, await A.recall(), id, 'added on A'), 'stored', 'nor known erased: recalled, then edited');
    } finally {
      await h.close();
    }
  });

  it("an edit whose own read was on its way when this process erased the memory is refused before its write", async () => {
    const h = await hosted();
    try {
      const id = newId();
      await computer(h, undefined).remember('ledger v1', { cellId: id });
      const A = computer(h, undefined); // it has not seen the memory: its edit reads the live version first
      const hold = holdNextRead(h);
      const edit = attempt(A, 'ledger v1 + added', id);
      await hold.arrived; // the read is computed: the memory as it was
      await withEnv('SAIHM_ERASURE_FEED', '0', () => A.forget(id));
      hold.release();
      assert.equal(failText(await edit), refusedHere(ERASED), 'its read showed it live, but the erasure came after that read was sent');
      assert.equal(await truth(h, id), undefined, 'the erasure stands');
    } finally {
      await h.close();
    }
  });

  it('a write whose answer was on its way when this process erased the memory leaves it known erased', async () => {
    const h = await hosted();
    try {
      const A = computer(h, undefined);
      const id = newId();
      await A.remember('minutes v1', { cellId: id });
      const hold = holdNext((x) => (h.holdRemember = x), 'the write');
      const edit = attempt(A, 'minutes v2', id);
      await hold.arrived; // stored, its answer held
      await withEnv('SAIHM_ERASURE_FEED', '0', () => A.forget(id));
      hold.release();
      assert.equal(await edit, 'stored', 'the write was stored before the erasure');
      const r = await measured(h, () => attempt(A, 'minutes v3', id));
      assert.equal(failText(r.value), refusedHere(ERASED), 'an answer from before the erasure ends nothing');
      assert.equal(await truth(h, id), undefined, 'the erasure stands');
    } finally {
      await h.close();
    }
  });

  it('copy off: a recall whose answer was on its way when this process erased the memory leaves it known erased', async () => {
    const h = await hosted();
    try {
      const A = computer(h, undefined);
      const id = newId();
      await A.remember('index v1', { cellId: id });
      const hold = holdNext((x) => (h.holdAll = x), 'the recall');
      const rec = A.recall();
      await hold.arrived; // its answer is computed: the memory as it was
      await withEnv('SAIHM_ERASURE_FEED', '0', () => A.forget(id));
      hold.release();
      assert.equal(text(await rec, id), 'index v1', 'the recall answers what it found');
      const r = await measured(h, () => attempt(A, 'index v1 + added', id));
      assert.equal(failText(r.value), refusedHere(ERASED), 'an answer from before the erasure ends nothing');
      assert.equal(await truth(h, id), undefined, 'the erasure stands');
    } finally {
      await h.close();
    }
  });

  it('copy on: a recall whose answer was on its way when an edit here found the memory erased leaves it known erased', async () => {
    const h = await hosted();
    try {
      const marks = join(dir, `marks-${randomBytes(4).toString('hex')}`, 'seq.json');
      const id = newId();
      await markedComputer(h, marks).remember('roster v1', { cellId: id });
      const A2 = markedComputer(h, marks, copyPath('A2')); // a later session, its copy empty: the recall asks for everything
      const hold = holdNext((x) => (h.holdDelta = x), 'the recall');
      const rec = A2.recall();
      await hold.arrived; // its answer is computed: the memory as it was
      await eraseElsewhere(h, id);
      assert.equal(failText(await attempt(A2, 'roster v1 + added', id)), refusedHere(ERASED), 'setup: its own read found it gone');
      hold.release();
      assert.equal(text(await rec, id), 'roster v1', 'the recall answers what it found');
      const r = await measured(h, () => attempt(A2, 'roster v1 + added', id));
      assert.equal(failText(r.value), refusedHere(ERASED), 'an answer to a request sent before the record ends nothing');
      assert.equal(await truth(h, id), undefined, 'the erasure stands');
    } finally {
      await h.close();
    }
  });

  it('a cellId a read found unused, then saved elsewhere: an edit here reads it, and a write failing for another reason leaves it editable', async () => {
    const h = await hosted();
    try {
      const A = computer(h, undefined);
      const id = newId();
      assert.equal(await A.recallOne(id), null, 'setup: no such memory yet');
      assert.equal(await attempt(elsewhere(h, undefined), 'saved elsewhere under that id', id), 'stored');
      h.rememberFault = () => {
        h.rememberFault = undefined;
        return { status: 503, body: { error: 'busy' } };
      };
      const failed = await attempt(A, 'saved elsewhere under that id + added', id);
      assert.ok(failed instanceof SaihmEndpointError && failed.code === 'busy', `setup: the write failed: ${String(failed)}`);
      assert.equal(await attempt(A, 'saved elsewhere under that id + added', id), 'stored', 'its own read showed it live: no false refusal');
    } finally {
      await h.close();
    }
  });

  it('copy on: erased, then saved again elsewhere between the listing and the delta: the delta brings it, so it is edited as any other', async () => {
    const h = await hosted();
    try {
      const A = computer(h, copyPath('A'));
      const id = newId();
      await A.remember('plan v1', { cellId: id });
      await A.remember('another memory');
      await A.recall();
      const B = elsewhere(h, undefined);
      await B.recall();
      await eraseElsewhere(h, id);
      h.beforeDelta = async () => {
        h.beforeDelta = undefined;
        await B.remember('plan written again on B', { cellId: id });
      };
      const cells = await A.recall();
      assert.equal(h.beforeDelta, undefined, 'setup: saved again between the listing and the delta');
      assert.equal(text(cells, id), 'plan written again on B', 'the delta brought it');
      assert.equal(await editFrom(A, cells, id, 'added on A'), 'stored', 'no false refusal');
    } finally {
      await h.close();
    }
  });
});
