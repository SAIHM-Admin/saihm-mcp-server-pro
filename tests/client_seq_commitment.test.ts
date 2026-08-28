/**
 * PC-SEQ-COMMITMENT — a sequence number alone cannot close rollback, because a sequence can repeat.
 *
 * `remember` advances the high-water mark only AFTER the endpoint accepts the write. So a write the
 * endpoint COMMITS but whose response is lost leaves the mark unadvanced, and the next write reuses
 * that seq. Two envelopes, both genuinely signed by this identity, then exist at one (cellId, seq).
 * Every other check on the read path passes for both, and the `<`-only rollback guard admits both:
 * measured before the pin, the endpoint served two DIFFERENT plaintexts at the same seq, alternately,
 * with no error. Pinning the envelope's commitment alongside the seq is what makes the pair
 * distinguishable.
 *
 * THE SECOND CASE IS A FOOTGUN GUARD. The obvious-looking fix is to tighten the guard from `<` to
 * `<=`. That is wrong -- it rejects every legitimate re-read of a cell at its current seq, which is
 * the ordinary case -- and it looks correct enough to be applied by someone who never saw this
 * analysis. That case fails on exactly that edit.
 */
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WireEnvelope } from '@saihm/client-pro';
import { SaihmProClient, SaihmEndpointError } from '../src/client.js';

interface Rig {
  client: SaihmProClient;
  /** Every wire the endpoint has committed, in order — including one it never acknowledged. */
  versions: WireEnvelope[];
  /** Drop the response to the next `saihm_remember` AFTER committing it. */
  loseNextResponse: () => void;
  /** Which committed version recall hands back; -1 is the newest. */
  serve: (index: number) => void;
  done: () => Promise<void>;
}

async function rig(seqStatePath: string): Promise<Rig> {
  const versions: WireEnvelope[] = [];
  let lose = false;
  let index = -1;

  const server: Server = createServer((req, res) => {
    void (async () => {
      let body = '';
      for await (const chunk of req) body += chunk;
      const { method, params = {} } = JSON.parse(body) as {
        method: string;
        params?: Record<string, unknown>;
      };
      const send = (o: unknown): void => {
        const t = JSON.stringify(o);
        res
          .writeHead(200, {
            'content-type': 'application/json',
            'content-length': String(Buffer.byteLength(t)),
          })
          .end(t);
      };
      if (method === 'saihm_remember') {
        const wire = params.wire as WireEnvelope;
        versions.push(wire); // COMMITTED — this happens before the response is decided
        if (lose) {
          lose = false;
          res.destroy(); // committed, but the client never learns it
          return;
        }
        send({ stored: true, cellId: wire.cellId });
        return;
      }
      if (method === 'saihm_recall') {
        const wire = versions[index === -1 ? versions.length - 1 : index]!;
        send(
          typeof params.cellId === 'string'
            ? { found: true, wire }
            : [{ cellId: wire.cellId, found: true, wire }],
        );
        return;
      }
      send({ error: 'unused' });
    })();
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  return {
    client: new SaihmProClient(
      `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`,
      'Bearer test',
      new Uint8Array(32).fill(3),
      { tier: 'PRO', seqStatePath },
    ),
    versions,
    loseNextResponse: () => (lose = true),
    serve: (i) => (index = i),
    done: () => new Promise<void>((r) => server.close(() => r())),
  };
}

describe('PC-SEQ-COMMITMENT: two envelopes at one seq are distinguishable', () => {
  it('a second envelope at the SAME seq is refused, even though it is validly signed', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'saihm-seq-'));
    const r = await rig(join(dir, 'seq.json'));
    try {
      await r.client.remember('v1', { cellId: 'X' });
      r.loseNextResponse();
      await assert.rejects(
        r.client.remember('v2 — committed, response lost', { cellId: 'X' }),
        'setup: the lost response must surface as a failure, or the mark would advance',
      );
      await r.client.remember('v3 — reuses the seq', { cellId: 'X' });

      // The whole precondition in one assertion: the endpoint holds three committed versions and the
      // last two share a sequence number. If the client ever stops reusing the seq this is no longer
      // the scenario under test, and this fails rather than passing for the wrong reason.
      const seqs = r.versions.map((w) => String((w as unknown as { seq: unknown }).seq));
      assert.deepEqual(seqs, ['1', '2', '2'], 'setup: the lost response must cause a seq reuse');

      r.serve(2); // the version this client last wrote
      const newest = await r.client.recallOne('X');
      assert.equal(newest?.seq, '2', 'setup: the newest version must be readable at its own seq');

      r.serve(1); // the OTHER envelope at that same seq
      await assert.rejects(
        r.client.recallOne('X'),
        (e: unknown) => {
          assert.ok(e instanceof SaihmEndpointError, `wrong error type: ${String(e)}`);
          assert.equal(e.code, 'stale_cell');
          return true;
        },
        'the endpoint served a different envelope at an already-observed seq and it was accepted',
      );
    } finally {
      await r.done();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('re-reading the SAME envelope at its current seq still works — `<=` would break this', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'saihm-seq-'));
    const r = await rig(join(dir, 'seq.json'));
    try {
      await r.client.remember('only version', { cellId: 'X' });
      const first = await r.client.recallOne('X');
      const second = await r.client.recallOne('X');
      assert.equal(first?.plaintext, 'only version');
      assert.equal(second?.plaintext, 'only version', 'a repeated read at the current seq must succeed');
      assert.equal(second?.seq, first?.seq);
    } finally {
      await r.done();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a legacy seq-state file (bare decimal, no commitment) still loads and does not regress', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'saihm-seq-'));
    const path = join(dir, 'seq.json');
    // The shape written before commitments were pinned. Refusing it would reset an existing agent's
    // whole sequence state to zero, which is worse than an unpinned first read.
    writeFileSync(path, JSON.stringify({ X: '7' }), { mode: 0o600 });
    const r = await rig(path);
    try {
      await r.client.remember('after a legacy load', { cellId: 'X' });
      const seqs = r.versions.map((w) => String((w as unknown as { seq: unknown }).seq));
      assert.deepEqual(seqs, ['8'], 'the legacy high-water mark must still be honoured');
    } finally {
      await r.done();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
