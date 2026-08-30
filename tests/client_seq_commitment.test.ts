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
 * THE PIN MUST BE LOCALLY DERIVED, which is the third and fourth cases. `publicMeta` is outside
 * both AEAD AADs -- `cellAad` and `wrapAad` cover agentIdHash, cellId, seq and schemaVer, nothing
 * else -- and the ML-DSA signature that does cover it is only checked on the SHARED read path, where
 * a foreign envelope has no other source of provenance. So a commitment read off `publicMeta` on the
 * own-memory path is the endpoint's own choice of value, and comparing it to a pin taken the same way
 * compares the endpoint to itself. Recomputing `sha256(ciphertext)` is what makes the pin mean
 * anything: the ciphertext is authenticated by the AEAD open under this identity's KEK.
 *
 * THE SECOND CASE IS A FOOTGUN GUARD. The obvious-looking fix is to tighten the guard from `<` to
 * `<=`. That is wrong -- it rejects every legitimate re-read of a cell at its current seq, which is
 * the ordinary case -- and it looks correct enough to be applied by someone who never saw this
 * analysis. That case fails on exactly that edit.
 */
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import { createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WireEnvelope } from '@saihm/client-pro';
import { deriveIdentity, encodeIdentityRecord, toHex } from '@saihm/client-pro';
import { SaihmProClient, SaihmEndpointError } from '../src/client.js';

interface Rig {
  client: SaihmProClient;
  /** Every wire the endpoint has committed, in order — including one it never acknowledged. */
  versions: WireEnvelope[];
  /** Drop the response to the next `saihm_remember` AFTER committing it. */
  loseNextResponse: () => void;
  /** Which committed version recall hands back; -1 is the newest. */
  serve: (index: number) => void;
  /** Serve the next recall wearing this `publicMeta.commitmentHash`; `null` restores the real one. */
  forgeCommitment: (hex: string | null) => void;
  /** Every `saihm_share` the endpoint received — a re-wrap that reached the wire is a leak. */
  shared: unknown[];
  done: () => Promise<void>;
}

async function rig(seqStatePath: string): Promise<Rig> {
  const versions: WireEnvelope[] = [];
  const shared: unknown[] = [];
  let lose = false;
  let index = -1;
  let forged: string | null = null;

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
        const base = versions[index === -1 ? versions.length - 1 : index]!;
        // Serve a COPY when forging, so the tamper never mutates what the endpoint actually committed
        // -- otherwise a later honest read would replay the forgery and prove nothing.
        const wire: WireEnvelope =
          forged === null
            ? base
            : { ...base, publicMeta: { ...base.publicMeta, commitmentHash: forged } };
        send(
          typeof params.cellId === 'string'
            ? { found: true, wire }
            : [{ cellId: wire.cellId, found: true, wire }],
        );
        return;
      }
      if (method === 'saihm_share') {
        shared.push(params);
        send({ cellId: 'X', sharer: 'aa'.repeat(16), recipient: 'bb'.repeat(16) });
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
    shared,
    loseNextResponse: () => (lose = true),
    serve: (i) => (index = i),
    forgeCommitment: (hex) => (forged = hex),
    done: () => new Promise<void>((r) => server.close(() => r())),
  };
}

describe('PC-SEQ-DEFAULT: constructing this class directly writes NOTHING', () => {
  it('a library caller who did not ask for persistence gets no file under SAIHM_HOME', async () => {
    // The MCP server defaults a sequence-state path so the rollback guard survives a restart. That
    // default is opt-IN and lives on the boot path, not in the constructor, and this is the test that
    // says so. Putting it in the constructor was measured first: it made `new SaihmProClient(...)`
    // write into the caller's real `$HOME`, which is intrusive on its own and also makes an
    // embedder's tests order-dependent through a file they never named - a second client in one
    // process silently inherited the first one's marks.
    const home = mkdtempSync(join(tmpdir(), 'saihm-home-'));
    const prev = process.env.SAIHM_HOME;
    process.env.SAIHM_HOME = home;
    const seqDir = mkdtempSync(join(tmpdir(), 'saihm-seq-'));
    try {
      const r = await rig(join(seqDir, 'explicit.json'));
      try {
        // POSITIVE CONTROL. An EXPLICIT path is honoured, so this rig demonstrably persists when
        // asked - without it, an empty SAIHM_HOME would prove only that nothing ran.
        await r.client.remember('x', { cellId: 'a' });
        assert.ok(
          readdirSync(seqDir).length > 0,
          'positive control: the explicit path wrote nothing, so the empty SAIHM_HOME below is vacuous',
        );
        assert.deepEqual(readdirSync(home), [], 'a directly-constructed client must not touch $HOME');
      } finally {
        await r.done();
      }
    } finally {
      if (prev === undefined) delete process.env.SAIHM_HOME;
      else process.env.SAIHM_HOME = prev;
      rmSync(home, { recursive: true, force: true });
      rmSync(seqDir, { recursive: true, force: true });
    }
  });
});

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

  it('SHARE refuses the equivocating envelope too, and does not re-wrap it to the grantee', async () => {
    // The sibling of the case above, on the path where the consequence lands on SOMEONE ELSE.
    // `share` re-wraps the DEK of whatever envelope the endpoint returns and grants it away. It used
    // to validate that envelope with a LOCAL COPY of part of the read path - structural decode,
    // agentIdHash, cellId, `seq <` - and the copy never grew the commitment check that the read path
    // grew. At equal seq, `seq <` is false for BOTH envelopes, so the endpoint chose which version
    // the grantee received, the sharer was told it succeeded, and the grantee has no pin, no history
    // and no way to tell. A guard duplicated is a guard that can be missing from one copy.
    //
    // The assertion that matters is `r.shared.length === 0`. Rejecting is not enough on its own: a
    // re-wrap that reached the wire before the throw would already have handed the endpoint a
    // grantee-openable copy of the superseded cell, and the exception would be cosmetic.
    const dir = mkdtempSync(join(tmpdir(), 'saihm-seq-'));
    const r = await rig(join(dir, 'seq.json'));
    const grantee = deriveIdentity(new Uint8Array(32).fill(9));
    const to = {
      recipientRecord: encodeIdentityRecord(grantee.identityRecord),
      recipientPinnedAgentIdHashHex: toHex(grantee.agentIdHash),
    };
    try {
      await r.client.remember('v1', { cellId: 'X' });
      r.loseNextResponse();
      await assert.rejects(
        r.client.remember('v2 — committed, response lost', { cellId: 'X' }),
        'setup: the lost response must surface as a failure, or the mark would advance',
      );
      await r.client.remember('v3 — reuses the seq', { cellId: 'X' });
      const seqs = r.versions.map((w) => String((w as unknown as { seq: unknown }).seq));
      assert.deepEqual(seqs, ['1', '2', '2'], 'setup: the lost response must cause a seq reuse');

      // POSITIVE CONTROL, and it is doing two jobs. It proves this rig can complete a share at all -
      // without it, a throw below would be indistinguishable from `share` being broken outright -
      // and it is what ESTABLISHES the pin at seq 2, since a share on a cell with no pin has nothing
      // to compare against and would pass whatever the endpoint served.
      r.serve(2); // the version this client last wrote
      await r.client.share({ cellId: 'X', ...to });
      assert.equal(r.shared.length, 1, 'positive control: an honest share must reach the endpoint');

      r.serve(1); // the OTHER envelope at that same seq
      await assert.rejects(
        r.client.share({ cellId: 'X', ...to }),
        (e: unknown) => {
          assert.ok(e instanceof SaihmEndpointError, `wrong error type: ${String(e)}`);
          assert.equal(e.code, 'stale_cell');
          return true;
        },
        'share accepted a different envelope at an already-observed seq and re-wrapped it out',
      );
      assert.equal(
        r.shared.length,
        1,
        'the superseded envelope was re-wrapped to the grantee before the throw - the throw is cosmetic',
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

  it('a forged commitment on an otherwise honest envelope cannot poison the pin', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'saihm-seq-'));
    const r = await rig(join(dir, 'seq.json'));
    try {
      await r.client.remember('only version', { cellId: 'X' });
      const committed = r.versions[0]!;
      const trueCommitment = createHash('sha256')
        .update(Buffer.from(committed.ciphertext, 'hex'))
        .digest('hex');
      assert.equal(
        committed.publicMeta.commitmentHash,
        trueCommitment,
        'setup: an honestly sealed envelope commits to its own ciphertext',
      );
      const FORGERY = 'a'.repeat(64); // valid hex of the right length, or `decodeEnvelope` rejects it
      assert.notEqual(trueCommitment, FORGERY, 'setup: the forgery must differ from the real value');

      r.forgeCommitment(FORGERY);
      const first = await r.client.recallOne('X');
      assert.equal(first?.plaintext, 'only version');
      assert.equal(
        first?.commitmentHash,
        trueCommitment,
        'the commitment must be recomputed from the ciphertext, never echoed from publicMeta',
      );

      // The denial of service the echo enables: had the forgery been pinned, this honest re-read --
      // same cell, same seq, same bytes -- would mismatch it and keep mismatching it across restarts.
      r.forgeCommitment(null);
      const second = await r.client.recallOne('X');
      assert.equal(second?.plaintext, 'only version', 'an honest re-read must not be refused');
      assert.equal(second?.commitmentHash, trueCommitment);
    } finally {
      await r.done();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('wearing the pinned commitment does not smuggle a DIFFERENT envelope past the guard', async () => {
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
      const seqs = r.versions.map((w) => String((w as unknown as { seq: unknown }).seq));
      assert.deepEqual(seqs, ['1', '2', '2'], 'setup: the lost response must cause a seq reuse');

      r.serve(2);
      const pinned = await r.client.recallOne('X');
      assert.equal(pinned?.plaintext, 'v3 — reuses the seq', 'setup: the pin comes from v3');

      // The endpoint now serves the OTHER envelope at that seq wearing v3's commitment. If the pin
      // and the served value are both read off `publicMeta`, this compares the endpoint to itself,
      // they agree, and the first case's whole guard is reinstated as a no-op.
      r.serve(1);
      r.forgeCommitment(pinned!.commitmentHash);
      await assert.rejects(
        r.client.recallOne('X'),
        (e: unknown) => {
          assert.ok(e instanceof SaihmEndpointError, `wrong error type: ${String(e)}`);
          assert.equal(e.code, 'stale_cell');
          return true;
        },
        'a substituted envelope wearing the pinned commitment was accepted',
      );
    } finally {
      await r.done();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
