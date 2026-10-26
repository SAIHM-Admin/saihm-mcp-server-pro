/**
 * PC-RECALL-CACHE — a recall response may never undo a local write that landed while it was in flight.
 *
 * WHY THIS FILE EXISTS. The recall cache is the one client-side store that holds cell PLAINTEXT at
 * rest, and `remember` / `forget` write to it directly so a client stays coherent with its own writes
 * (see `RecallCache`'s docblock). A recall rewrites that same store from a snapshot the ENDPOINT took
 * when it received the request. Those two facts are only compatible while nothing writes during a
 * recall — and something can: the MCP SDK does not serialise tool handlers and the client is a
 * process-wide singleton, so the endpoint selects the interleaving simply by choosing when to answer.
 * `src/server.ts` already records that reachability argument for a sibling defect in the same client.
 *
 * WHAT WAS MEASURED before the guard, on both reply shapes:
 *   - `forget` during an in-flight FULL recall: the erased cell's plaintext was written BACK to the
 *     on-disk cache after the tool had returned `complete: true` with no residual — the endpoint's
 *     crypto-shred is irreversible, so the local copy was the only surviving plaintext.
 *   - `remember` during an in-flight recall, EITHER shape: the new cell was dropped from the cache.
 *     The delta path cannot resurrect (the endpoint omits a known cellId from `added`) but prunes
 *     against a stale `liveCellIds`, so it loses the write exactly as the full path does.
 *
 * THE POSITIVE CONTROL IS LOAD-BEARING. Each case asserts the local write reached the cache BEFORE
 * releasing the response. Without it a harness that silently stopped writing — a changed reply shape,
 * a cache that never configured — would satisfy the "nothing was undone" assertion vacuously and this
 * file would pass while testing nothing. Assert the setup, then assert the property.
 */
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { WireEnvelope } from '@saihm/client-pro';
import { SaihmProClient } from '../src/client.js';

// The erasure feed's root derives from the IDENTITY's directory - `SAIHM_ERASURE_FEED_DIR`, then
// `SAIHM_HOME`, then `~/.saihm` - so a `forget()` in an unpinned test appends a REAL erasure line to
// whoever runs this suite. Pin the FEED alone rather than `SAIHM_HOME`: nothing else in this file
// reads this variable, so what is under test is unchanged and the sequence-state default is left
// exactly where each harness already put it.
process.env.SAIHM_ERASURE_FEED_DIR = mkdtempSync(join(tmpdir(), 'saihm-feed-'));

type Shape = 'full' | 'delta';

interface Stack {
  client: SaihmProClient;
  /** Raw cache file as it currently sits on disk — '' when the file does not exist yet. */
  onDisk: () => string;
  /** Let the held `saihm_recall` response through. */
  release: () => void;
  /** The params of the request the hold caught, once caught. */
  heldParams: () => Record<string, unknown> | undefined;
  /** Arm the hold for the NEXT `saihm_recall`; resolves once that request's reply is computed and held. */
  hold: () => Promise<void>;
  done: () => Promise<void>;
}

/**
 * A blind endpoint that stores what the client seals and hands it straight back, with one addition:
 * a held `saihm_recall`. The reply is COMPUTED when the request arrives and only then held, which is
 * what makes it a faithful model — a slow or hostile endpoint answers from the state it saw, not from
 * the state that exists when the answer is finally delivered. Holding after computing is the whole
 * mechanism; holding before it would test nothing, since the reply would see the concurrent write.
 */
async function stack(shape: Shape): Promise<Stack> {
  const store = new Map<string, WireEnvelope>();
  let holding = false;
  let open: (() => void) | null = null;
  let arrived: (() => void) | null = null;
  let heldParams: Record<string, unknown> | undefined;
  let gate: Promise<void> = Promise.resolve();

  const server: Server = createServer((req, res) => {
    void (async () => {
      let body = '';
      for await (const chunk of req) body += chunk;
      const { method, params = {} } = JSON.parse(body) as {
        method: string;
        params?: Record<string, unknown>;
      };
      let out: unknown;
      if (method === 'saihm_remember') {
        const wire = params.wire as WireEnvelope;
        store.set(wire.cellId, wire);
        out = { stored: true, cellId: wire.cellId };
      } else if (method === 'saihm_forget') {
        const id = params.id as string;
        store.delete(id);
        out = { cellId: id, shardId: 's', complete: true, destructionAnchor: 'anchor-1', sharesPurged: 0, steps: [], epoch: '1' };
      } else if (method === 'saihm_recall' && typeof params.cellId === 'string') {
        // Single-cell form, used by `remember` to read back what it wrote. Never held.
        const wire = store.get(params.cellId);
        out = wire ? { found: true, wire } : { found: false };
      } else if (method === 'saihm_recall' && shape === 'delta' && params.listOnly === true) {
        // The version listing a delta endpoint serves beside the delta (0.14.2: read before every recall with the
        // cache). Never held: the hold is on the request whose answer rewrites the cache. The full shape has no
        // listing, so there the listing request is answered as a recall-all, and that request is the one held. Each
        // cell is listed at its stored version's number, as the endpoint states it: a cell is known only at its number.
        out = {
          mode: 'list',
          cells: [...store.keys()].sort().map((cellId) => ({
            cellId,
            seq: String(store.get(cellId)!.seq),
            commitment: store.get(cellId)!.publicMeta.commitmentHash.toLowerCase(),
          })),
          next: null,
        };
      } else if (method === 'saihm_recall') {
        const rows = [...store.entries()].map(([cellId, wire]) => ({ cellId, found: true, wire }));
        const known = new Set((params.knownCellIds as string[] | undefined) ?? []);
        out =
          shape === 'delta'
            ? {
                mode: 'delta',
                added: rows.filter((r) => !known.has(r.cellId)),
                liveCellIds: [...store.keys()],
              }
            : rows;
        if (holding) {
          holding = false;
          heldParams = params;
          arrived?.();
          await gate;
        }
      } else {
        out = { error: 'unused' };
      }
      const txt = JSON.stringify(out);
      res
        .writeHead(200, {
          'content-type': 'application/json',
          'content-length': String(Buffer.byteLength(txt)),
        })
        .end(txt);
    })();
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const dir = mkdtempSync(join(tmpdir(), 'saihm-recall-cache-'));
  const cachePath = join(dir, 'recall_cache.json');

  return {
    client: new SaihmProClient(
      `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`,
      'Bearer test',
      new Uint8Array(32).fill(9),
      { tier: 'PRO', recallCachePath: cachePath },
    ),
    onDisk: () => (existsSync(cachePath) ? readFileSync(cachePath, 'utf-8') : ''),
    hold: () => {
      holding = true;
      gate = new Promise<void>((r) => (open = r));
      return new Promise<void>((r) => (arrived = r));
    },
    release: () => open?.(),
    heldParams: () => heldParams,
    done: async () => {
      await new Promise<void>((r) => server.close(() => r()));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

// The concurrent write starts only once the held reply is COMPUTED and blocked (`hold` resolves then). A fixed sleep
// used to stand in for that, and under load the write could land first: the reply then saw it, and the case passed
// while testing nothing. Measured in 0.14.2, where a recall's first request is the version listing.

// Fresh cell ids for every case. The cases share one identity and one erasure feed, so an id one case erased is
// dropped from a later case's cache at every save (the erasure keeps winning, by design), and that case then ran on an
// EMPTY cache, which since 0.14.2 skips the version listing: a different request was the one held. Measured.
const uid = (name: string): string => `${name}-${randomBytes(6).toString('hex')}`;

/** The request the hold caught is the one whose answer rewrites the cache: for the full shape the version listing,
 *  which an endpoint without one answers with every cell; for the delta shape the delta, sent with known ids. */
function assertHeldTheDataRequest(shape: Shape, p: Record<string, unknown> | undefined): void {
  if (shape === 'full') assert.equal(p?.listOnly, true, 'setup: the listing request, answered as a recall-all, is held');
  else assert.ok(Array.isArray(p?.knownCellIds) && p.knownCellIds.length > 0, 'setup: the delta, sent with known ids, is held');
}

describe('PC-RECALL-CACHE: an in-flight recall never undoes a concurrent local write', () => {
  for (const shape of ['full', 'delta'] as const) {
    it(`${shape}: a forget during an in-flight recall does not resurrect the erased plaintext`, async () => {
      const s = await stack(shape);
      try {
        const secret = 'PLAINTEXT-THAT-MUST-NOT-SURVIVE-ERASURE';
        const X = uid('X');
        await s.client.remember(secret, { cellId: X });
        await s.client.remember('an unrelated memory', { cellId: uid('Y') });

        const held = s.hold();
        const inFlight = s.client.recall();
        await held;

        assertHeldTheDataRequest(shape, s.heldParams());
        const r = await s.client.forget(X);
        assert.equal(r.complete, true, 'setup: the endpoint must report the erasure complete');
        assert.equal(
          r.localCacheResidual,
          undefined,
          'setup: the purge must SUCCEED here — a residual would mean this case never removed anything',
        );
        assert.ok(
          !s.onDisk().includes(secret),
          'positive control: the purge must actually have removed the plaintext before the response lands',
        );

        s.release();
        await inFlight;
        assert.ok(
          !s.onDisk().includes(secret),
          'a recall captured before the forget wrote the erased plaintext back to disk',
        );
      } finally {
        await s.done();
      }
    });

    it(`${shape}: a remember during an in-flight recall is not dropped from the cache`, async () => {
      const s = await stack(shape);
      try {
        await s.client.remember('an existing memory', { cellId: uid('X') });

        const held = s.hold();
        const inFlight = s.client.recall();
        await held;

        const written = 'WRITTEN-DURING-AN-IN-FLIGHT-RECALL';
        assertHeldTheDataRequest(shape, s.heldParams());
        await s.client.remember(written, { cellId: uid('Z') });
        assert.ok(
          s.onDisk().includes(written),
          'positive control: the write must reach the cache before the response lands',
        );

        s.release();
        await inFlight;
        assert.ok(
          s.onDisk().includes(written),
          'a recall captured before the remember deleted the newly written cell from the cache',
        );
      } finally {
        await s.done();
      }
    });
  }
});
