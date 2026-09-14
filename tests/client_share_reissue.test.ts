/**
 * Share re-issue after a write — the client half, against an endpoint that is lying.
 *
 * Every write seals a cell under a new key, and a grant carries the key of one version, so a grant made before a
 * write cannot open the cell after it. An endpoint that supports re-issue lists those grants in the write's response
 * (`staleShares`), and the client builds a new share for each. The list is the endpoint's, so nothing in it is
 * trusted: the cases below give the client entries naming a recipient this identity never granted, a share that does
 * not verify, a share of another cell, and a recipient record carrying someone else's keys, and assert that no share
 * is built for any of them. The rest pin the reporting: a failed re-issue never fails the write, and a count is the
 * client's own.
 */
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WireEnvelope, WireShareEnvelope } from '@saihm/client-pro';
import {
  deriveIdentity,
  decodeEnvelope,
  decodeShareEnvelope,
  encodeIdentityRecord,
  encodeShareEnvelope,
  openCellWithDek,
  sealCell,
  serializeShareForSigning,
  shareCell,
  toHex,
  unwrapSharedDek,
  verifyShareSig,
} from '@saihm/client-pro';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { SaihmProClient } from '../src/client.js';

const A_SEED = new Uint8Array(32).fill(91);
const A = deriveIdentity(A_SEED);
const B = deriveIdentity(new Uint8Array(32).fill(92));
const C = deriveIdentity(new Uint8Array(32).fill(93));
const hex = (id: { agentIdHash: Uint8Array }): string => toHex(id.agentIdHash);

type Grant = { recipient: string; scope: string; expiryEpoch: null; share: unknown; recipientRecord: unknown };
type Page = { count: number; grants: Grant[]; after: string | null };

interface Rig {
  client: SaihmProClient;
  /** Every `saihm_share` params object, in order. */
  shares: Array<Record<string, unknown>>;
  /** The latest stored wire per cell. */
  cells: Map<string, WireEnvelope>;
  /** What the NEXT write of a cell reports; called with the cell and the wire just stored. */
  onWrite: (fn: (cellId: string, wire: WireEnvelope) => Page | undefined) => void;
  /** How a re-issue request is answered; default: every envelope accepted, no further page. */
  onRewrap: (fn: (params: Record<string, unknown>) => { status: number; body: unknown }) => void;
  done: () => Promise<void>;
}

async function rig(): Promise<Rig> {
  const shares: Array<Record<string, unknown>> = [];
  const cells = new Map<string, WireEnvelope>();
  let writeFn: (cellId: string, wire: WireEnvelope) => Page | undefined = () => undefined;
  let rewrapFn = (params: Record<string, unknown>): { status: number; body: unknown } => ({
    status: 200,
    body: {
      cellId: params.cellId,
      results: (params.shareWires as WireShareEnvelope[]).map((w) => ({ recipient: w.recipientAgentIdHash, ok: true })),
      staleShares: { count: 0, grants: [], after: null },
    },
  });
  const server: Server = createServer((req, res) => {
    void (async () => {
      let body = '';
      for await (const chunk of req) body += chunk;
      const { method, params = {} } = JSON.parse(body) as { method: string; params?: Record<string, unknown> };
      const send = (status: number, o: unknown): void => {
        const t = JSON.stringify(o);
        res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(t)) }).end(t);
      };
      if (method === 'saihm_remember') {
        const wire = params.wire as WireEnvelope;
        cells.set(wire.cellId, wire);
        const page = writeFn(wire.cellId, wire);
        send(200, { cellId: wire.cellId, shardId: 'ab'.repeat(32), seq: wire.seq, commitmentHash: wire.publicMeta.commitmentHash, ...(page ? { staleShares: page } : {}) });
        return;
      }
      if (method === 'saihm_recall') {
        const wire = cells.get(params.cellId as string);
        send(200, wire ? { found: true, wire } : { found: false });
        return;
      }
      if (method === 'saihm_revoke_share') {
        send(200, { cellId: params.cellId, recipient: params.recipient, revoked: true });
        return;
      }
      if (method === 'saihm_share') {
        shares.push(params);
        if (params.rewrap === true) {
          const r = rewrapFn(params);
          send(r.status, r.body);
          return;
        }
        send(200, { cellId: params.cellId, sharer: hex(A), recipient: 'x' });
        return;
      }
      send(400, { error: 'unused' });
    })();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const dir = mkdtempSync(join(tmpdir(), 'saihm-reissue-'));
  return {
    client: new SaihmProClient(`http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`, 'Bearer test', A_SEED, {
      tier: 'PRO',
      seqStatePath: join(dir, 'seq.json'),
    }),
    shares,
    cells,
    onWrite: (fn) => { writeFn = fn; },
    onRewrap: (fn) => { rewrapFn = fn; },
    done: async () => {
      await new Promise<void>((r) => server.close(() => r()));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** A share of `cellId`'s stored version from `from` to `to`, as the endpoint would hold it. */
function shareOf(rg: Rig, cellId: string, from: typeof A, to: typeof B): WireShareEnvelope {
  return encodeShareEnvelope(
    shareCell({
      envelope: decodeEnvelope(rg.cells.get(cellId)!),
      sharerKek: from.kek,
      sharerMldsaSecretKey: from.mldsaSecretKey,
      sharerAgentIdHash: from.agentIdHash,
      recipientRecord: to.identityRecord,
      recipientPinnedAgentIdHash: to.agentIdHash,
    }),
  );
}
const grant = (recipient: string, share: unknown, record: unknown): Grant => ({ recipient, scope: 'read', expiryEpoch: null, share, recipientRecord: record });
const rewraps = (rg: Rig) => rg.shares.filter((p) => p.rewrap === true);

describe('share re-issue after a write', () => {
  it("re-issues a listed grant for the version just written, and the recipient opens that version", async () => {
    const rg = await rig();
    try {
      const { cellId } = await rg.client.remember('version one');
      const old = shareOf(rg, cellId, A, B);
      rg.onWrite(() => ({ count: 1, grants: [grant(hex(B), old, encodeIdentityRecord(B.identityRecord))], after: null }));
      const w = await rg.client.remember('version two', { cellId });
      assert.deepEqual(w.shares, { reissued: 1, notReissued: [], incomplete: false });
      const [req] = rewraps(rg);
      assert.equal(req.cellId, cellId);
      assert.equal(req.commitment, w.commitmentHash);
      const wires = req.shareWires as WireShareEnvelope[];
      assert.equal(wires.length, 1);
      const issued = decodeShareEnvelope(wires[0]);
      assert.ok(verifyShareSig(issued, A.mldsaPubKey), 'the new share is signed by the sharer');
      assert.equal(toHex(issued.recipientAgentIdHash), hex(B));
      const dek = unwrapSharedDek({ share: issued, recipientMlkemSecretKey: B.mlkemSecretKey, recipientAgentIdHash: B.agentIdHash, sharerPinnedMldsaPubKey: A.mldsaPubKey });
      assert.equal(new TextDecoder().decode(openCellWithDek(decodeEnvelope(rg.cells.get(cellId)!), dek)), 'version two');
    } finally { await rg.done(); }
  });

  it('share() sends the recipient record, so an endpoint can keep it for a later re-issue', async () => {
    const rg = await rig();
    try {
      const { cellId } = await rg.client.remember('one');
      await rg.client.share({ cellId, recipientRecord: encodeIdentityRecord(B.identityRecord), recipientPinnedAgentIdHashHex: hex(B) });
      assert.deepEqual(rg.shares[0].recipientRecord, encodeIdentityRecord(B.identityRecord));
    } finally { await rg.done(); }
  });

  it('builds nothing for a grant this identity never made, a share that does not verify, another cell, or substituted keys', async () => {
    const rg = await rig();
    try {
      const { cellId } = await rg.client.remember('one');
      const { cellId: other } = await rg.client.remember('another cell');
      // A valid share by C of C's own cell with the same id: signed, but not by this identity.
      const cCell = sealCell({ plaintext: new TextEncoder().encode('C'), kek: C.kek, mldsaSecretKey: C.mldsaSecretKey, mldsaPubKey: C.mldsaPubKey, agentIdHash: C.agentIdHash, cellId, seq: 1n, tier: 'PRO' });
      const fromC = encodeShareEnvelope(shareCell({ envelope: cCell, sharerKek: C.kek, sharerMldsaSecretKey: C.mldsaSecretKey, sharerAgentIdHash: C.agentIdHash, recipientRecord: B.identityRecord, recipientPinnedAgentIdHash: B.agentIdHash }));
      const tampered = { ...shareOf(rg, cellId, A, B), recipientAgentIdHash: hex(C) };  // A's signature over B, relabelled C
      const otherCell = shareOf(rg, other, A, B);                      // A's valid grant of ANOTHER cell
      const toB = shareOf(rg, cellId, A, B);
      const claimsC = (() => {
        const d = decodeShareEnvelope(toB);
        const unsigned = { ...d, sharerAgentIdHash: C.agentIdHash };
        return encodeShareEnvelope({ ...unsigned, sharerSig: ml_dsa65.sign(serializeShareForSigning(unsigned), A.mldsaSecretKey) });
      })();
      rg.onWrite(() => ({
        count: 6,
        grants: [
          grant(hex(B), fromC, encodeIdentityRecord(B.identityRecord)),
          grant(hex(C), tampered, encodeIdentityRecord(C.identityRecord)),
          grant(hex(B), otherCell, encodeIdentityRecord(B.identityRecord)),
          grant(hex(C), toB, encodeIdentityRecord(C.identityRecord)),   // listed recipient does not match the share
          grant(hex(B), toB, encodeIdentityRecord(C.identityRecord)),   // B's grant carrying C's keys
          grant(hex(B), claimsC, encodeIdentityRecord(B.identityRecord)), // signed with this identity's key, naming C as sharer
        ],
        after: null,
      }));
      const w = await rg.client.remember('two', { cellId });
      assert.equal(rewraps(rg).length, 0, 'a share was built from an entry that does not verify');
      assert.deepEqual(w.shares, {
        reissued: 0,
        notReissued: [
          { recipient: null, reason: 'unverified' },
          { recipient: null, reason: 'unverified' },
          { recipient: null, reason: 'unverified' },
          { recipient: null, reason: 'unverified' },
          { recipient: hex(B), reason: 'unverified' },
          { recipient: null, reason: 'unverified' },
        ],
        incomplete: false,
      });
    } finally { await rg.done(); }
  });

  it('reports a grant without a record, and does not re-issue a grant this process revoked until it shares again', async () => {
    const rg = await rig();
    try {
      const { cellId } = await rg.client.remember('one');
      const toB = shareOf(rg, cellId, A, B);
      const toC = shareOf(rg, cellId, A, C);
      rg.onWrite(() => ({ count: 2, grants: [grant(hex(B), toB, null), grant(hex(C), toC, encodeIdentityRecord(C.identityRecord))], after: null }));
      await rg.client.revokeShare(cellId, hex(C).toUpperCase());
      const w = await rg.client.remember('two', { cellId });
      assert.deepEqual(w.shares, { reissued: 0, notReissued: [{ recipient: hex(B), reason: 'no_record' }, { recipient: hex(C), reason: 'revoked' }], incomplete: false });
      assert.equal(rewraps(rg).length, 0);

      await rg.client.share({ cellId, recipientRecord: encodeIdentityRecord(C.identityRecord), recipientPinnedAgentIdHashHex: hex(C) });
      const toC2 = shareOf(rg, cellId, A, C);
      rg.onWrite(() => ({ count: 1, grants: [grant(hex(C), toC2, encodeIdentityRecord(C.identityRecord))], after: null }));
      assert.deepEqual((await rg.client.remember('three', { cellId })).shares, { reissued: 1, notReissued: [], incomplete: false });
    } finally { await rg.done(); }
  });

  it('a refused re-issue request is reported and the write still succeeds', async () => {
    const rg = await rig();
    try {
      const { cellId } = await rg.client.remember('one');
      const toB = shareOf(rg, cellId, A, B);
      rg.onWrite(() => ({ count: 1, grants: [grant(hex(B), toB, encodeIdentityRecord(B.identityRecord))], after: null }));
      rg.onRewrap(() => ({ status: 409, body: { error: 'BLIND_REWRAP_STALE' } }));
      const w = await rg.client.remember('two', { cellId });
      assert.equal(w.seq, '2');
      assert.deepEqual(w.shares, { reissued: 0, notReissued: [{ recipient: hex(B), reason: 'unavailable' }], incomplete: false });
    } finally { await rg.done(); }
  });

  it("counts only acceptances of shares it sent: an unsent recipient marked ok is ignored, a missing result is refused", async () => {
    const rg = await rig();
    try {
      const { cellId } = await rg.client.remember('one');
      const toB = shareOf(rg, cellId, A, B);
      const toC = shareOf(rg, cellId, A, C);
      rg.onWrite(() => ({ count: 2, grants: [grant(hex(B), toB, encodeIdentityRecord(B.identityRecord)), grant(hex(C), toC, encodeIdentityRecord(C.identityRecord))], after: null }));
      rg.onRewrap(() => ({ status: 200, body: { results: [{ recipient: hex(B), ok: true }, { recipient: 'ff'.repeat(32), ok: true }, { recipient: hex(C), ok: 'yes' }] } }));
      const w = await rg.client.remember('two', { cellId });
      assert.deepEqual(w.shares, { reissued: 1, notReissued: [{ recipient: hex(C), reason: 'refused' }], incomplete: false });
    } finally { await rg.done(); }
  });

  it('follows pages with `after`, and stops when an endpoint repeats a page', async () => {
    const rg = await rig();
    try {
      const { cellId } = await rg.client.remember('one');
      const recipients = Array.from({ length: 17 }, (_, i) => deriveIdentity(new Uint8Array(32).fill(120 + i)));
      recipients.sort((x, y) => (hex(x) < hex(y) ? -1 : 1));
      const grants = recipients.map((r) => grant(hex(r), shareOf(rg, cellId, A, r), encodeIdentityRecord(r.identityRecord)));
      rg.onWrite(() => ({ count: 17, grants: grants.slice(0, 16), after: hex(recipients[15]) }));
      rg.onRewrap((p) => ({
        status: 200,
        body: {
          results: (p.shareWires as WireShareEnvelope[]).map((w) => ({ recipient: w.recipientAgentIdHash, ok: true })),
          staleShares: p.after === hex(recipients[15]) ? { count: 1, grants: grants.slice(16), after: null } : { count: 0, grants: [], after: null },
        },
      }));
      const w = await rg.client.remember('two', { cellId });
      assert.deepEqual(w.shares, { reissued: 17, notReissued: [], incomplete: false });
      assert.deepEqual(rewraps(rg).map((p) => [(p.shareWires as unknown[]).length, p.after ?? null]), [[16, hex(recipients[15])], [1, null]]);

      // An endpoint whose next page does not move past `after` ends the walk, even when that page lists a grant not seen yet.
      rg.shares.length = 0;
      rg.onWrite(() => ({ count: 17, grants: grants.slice(0, 16), after: hex(recipients[15]) }));
      rg.onRewrap((p) => ({
        status: 200,
        body: { results: (p.shareWires as WireShareEnvelope[]).map((x) => ({ recipient: x.recipientAgentIdHash, ok: true })), staleShares: { count: 17, grants: grants.slice(16), after: hex(recipients[15]) } },
      }));
      const again = await rg.client.remember('three', { cellId });
      assert.equal(rewraps(rg).length, 1, 'a page that did not move forward was followed');
      assert.equal(again.shares!.reissued, 16);
      assert.equal(again.shares!.incomplete, true, 'a walk that stopped at a page it could not continue from reads as complete');
    } finally { await rg.done(); }
  });

  it('an endpoint cannot inflate the work: one share per recipient, 16 grants per page, 64 pages per write', async () => {
    const rg = await rig();
    try {
      const { cellId } = await rg.client.remember('one');
      const recipients = Array.from({ length: 17 }, (_, i) => deriveIdentity(new Uint8Array(32).fill(160 + i)));
      const grants = recipients.map((r) => grant(hex(r), shareOf(rg, cellId, A, r), encodeIdentityRecord(r.identityRecord)));
      // The same recipient twice in one page, and 17 grants where a page holds 16.
      rg.onWrite(() => ({ count: 18, grants: [grants[0], ...grants], after: null }));
      await rg.client.remember('two', { cellId });
      const sent = (rewraps(rg)[0].shareWires as WireShareEnvelope[]).map((w) => w.recipientAgentIdHash);
      assert.equal(sent.length, 15, 'the first 16 listed entries hold 15 distinct recipients');
      assert.equal(new Set(sent).size, sent.length, 'a recipient was sent twice');

      // An endpoint whose every page names a later `after` and a new recipient is followed for exactly 64 pages.
      rg.shares.length = 0;
      const many = Array.from({ length: 70 }, (_, i) => deriveIdentity(Uint8Array.from({ length: 32 }, (_, j) => (j === 0 ? 7 : i + 1))));
      let k = 0;
      const pageAt = (i: number): Page => ({
        count: many.length,
        grants: [grant(hex(many[i]), shareOf(rg, cellId, A, many[i]), encodeIdentityRecord(many[i].identityRecord))],
        after: (i + 1).toString(16).padStart(64, '0'),
      });
      rg.onWrite(() => pageAt(k++));
      rg.onRewrap((p) => ({
        status: 200,
        body: { results: (p.shareWires as WireShareEnvelope[]).map((w) => ({ recipient: w.recipientAgentIdHash, ok: true })), staleShares: k < many.length ? pageAt(k++) : { count: 0, grants: [], after: null } },
      }));
      const w = await rg.client.remember('three', { cellId });
      assert.equal(rewraps(rg).length, 64);
      assert.equal(w.shares!.reissued, 64);
      assert.equal(w.shares!.incomplete, true, 'a walk stopped by the page bound reads as complete');
    } finally { await rg.done(); }
  });

  it('reports an incomplete walk: a page with nothing to send, a failed request, or a long page without a cursor', async () => {
    const rg = await rig();
    try {
      const { cellId } = await rg.client.remember('one');
      const toB = shareOf(rg, cellId, A, B);
      const toC = shareOf(rg, cellId, A, C);
      // Only grants without a record on this page, and the endpoint says more follow.
      rg.onWrite(() => ({ count: 20, grants: [grant(hex(B), toB, null)], after: hex(B) }));
      const noSend = await rg.client.remember('two', { cellId });
      assert.deepEqual(noSend.shares, { reissued: 0, notReissued: [{ recipient: hex(B), reason: 'no_record' }], incomplete: true });

      // The request fails while more pages are listed.
      rg.onWrite(() => ({ count: 20, grants: [grant(hex(C), toC, encodeIdentityRecord(C.identityRecord))], after: hex(C) }));
      rg.onRewrap(() => ({ status: 503, body: { error: 'upstream_unavailable' } }));
      const failed = await rg.client.remember('three', { cellId });
      assert.deepEqual(failed.shares, { reissued: 0, notReissued: [{ recipient: hex(C), reason: 'unavailable' }], incomplete: true });
    } finally { await rg.done(); }
  });

  it('a page longer than 16 continues after the last grant handled, never after the endpoint\'s cursor', async () => {
    const rg = await rig();
    try {
      const { cellId } = await rg.client.remember('one');
      const recipients = Array.from({ length: 20 }, (_, i) => deriveIdentity(new Uint8Array(32).fill(200 + i)));
      recipients.sort((x, y) => (hex(x) < hex(y) ? -1 : 1));
      const grants = recipients.map((r) => grant(hex(r), shareOf(rg, cellId, A, r), encodeIdentityRecord(r.identityRecord)));
      // One page of 20 whose cursor points past all of them: following it would skip grants 17-20.
      rg.onWrite(() => ({ count: 20, grants, after: hex(recipients[19]) }));
      rg.onRewrap((p) => ({
        status: 200,
        body: {
          results: (p.shareWires as WireShareEnvelope[]).map((w) => ({ recipient: w.recipientAgentIdHash, ok: true })),
          staleShares: p.after === hex(recipients[15]) ? { count: 4, grants: grants.slice(16), after: null } : { count: 0, grants: [], after: null },
        },
      }));
      const w = await rg.client.remember('two', { cellId });
      assert.deepEqual(rewraps(rg).map((p) => p.after ?? null), [hex(recipients[15]), null]);
      assert.deepEqual(w.shares, { reissued: 20, notReissued: [], incomplete: false });

      // The same long page whose 16th grant names no usable recipient: the 16 are handled and the walk says it stopped.
      rg.shares.length = 0;
      const broken = [...grants.slice(0, 15), { ...grants[15], recipient: 'not-a-recipient' }, ...grants.slice(16)];
      rg.onWrite(() => ({ count: 20, grants: broken, after: null }));
      const stuck = await rg.client.remember('three', { cellId });
      assert.equal(rewraps(rg).length, 1);
      assert.equal(stuck.shares!.incomplete, true);
      assert.equal(stuck.shares!.reissued, 15);
    } finally { await rg.done(); }
  });

  it('a write that leaves no grant behind carries no report', async () => {
    const rg = await rig();
    try {
      const { cellId } = await rg.client.remember('one');
      const w = await rg.client.remember('two', { cellId });
      assert.equal('shares' in w, false);
      assert.equal(rg.shares.length, 0);
    } finally { await rg.done(); }
  });
});
