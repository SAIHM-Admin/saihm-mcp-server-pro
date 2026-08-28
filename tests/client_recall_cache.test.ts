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
import type { WireEnvelope } from '@saihm/client-pro';
import { SaihmProClient } from '../src/client.js';

type Shape = 'full' | 'delta';

interface Stack {
  client: SaihmProClient;
  /** Raw cache file as it currently sits on disk — '' when the file does not exist yet. */
  onDisk: () => string;
  /** Let the held `saihm_recall` response through. */
  release: () => void;
  /** Arm the hold for the NEXT `saihm_recall`. */
  hold: () => void;
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
        out = { cellId: id, shardId: 's', complete: true, sharesPurged: 0, steps: [], epoch: '1' };
      } else if (method === 'saihm_recall' && typeof params.cellId === 'string') {
        // Single-cell form, used by `remember` to read back what it wrote. Never held.
        const wire = store.get(params.cellId);
        out = wire ? { found: true, wire } : { found: false };
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
    },
    release: () => open?.(),
    done: async () => {
      await new Promise<void>((r) => server.close(() => r()));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** Give the held recall time to reach the endpoint and block before the concurrent write starts. */
const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 60));

describe('PC-RECALL-CACHE: an in-flight recall never undoes a concurrent local write', () => {
  for (const shape of ['full', 'delta'] as const) {
    it(`${shape}: a forget during an in-flight recall does not resurrect the erased plaintext`, async () => {
      const s = await stack(shape);
      try {
        const secret = 'PLAINTEXT-THAT-MUST-NOT-SURVIVE-ERASURE';
        await s.client.remember(secret, { cellId: 'X' });
        await s.client.remember('an unrelated memory', { cellId: 'Y' });

        s.hold();
        const inFlight = s.client.recall();
        await settle();

        const r = await s.client.forget('X');
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
        await s.client.remember('an existing memory', { cellId: 'X' });

        s.hold();
        const inFlight = s.client.recall();
        await settle();

        const written = 'WRITTEN-DURING-AN-IN-FLIGHT-RECALL';
        await s.client.remember(written, { cellId: 'Z' });
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
