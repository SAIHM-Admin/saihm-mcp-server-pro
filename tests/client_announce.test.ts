/**
 * PC-SHARED-ANNOUNCE — the CLIENT's share-announcement PARSING contract, run in CI.
 *
 * WHY THIS FILE EXISTS SEPARATELY. These cases used to live in `tests/client_pro.test.ts`, which is
 * gitignored and omitted from `npm test` because it imports the blind operator endpoint — a package
 * that does not ship. That left every announcement case local-only and absent from release CI, while
 * client-side parsing is precisely where the class of bug these tests exist to catch has actually
 * occurred. So the parsing cases moved here, where they run on every release, and the real-endpoint
 * end-to-end (PA-E2E) stayed behind with the endpoint it needs.
 *
 * FIDELITY, AND ITS LIMIT — stated plainly because a mock that quietly pins the author's beliefs is
 * the exact failure mode this suite guards against. Split by half:
 *   - The OWN-CELL half is REAL. Every own row below is sealed by the real client (`sealCell` +
 *     `encodeEnvelope`, real ML-DSA, real AEAD) and echoed back byte-for-byte by the bridge. Nothing
 *     about an own cell is hand-written, so the client must genuinely open what it genuinely sealed.
 *   - The reply ENVELOPE is hand-written: whether `saihm_recall` answers with the legacy array or the
 *     delta object, and what an announcement row looks like on the wire. That is an assumption, and
 *     no assertion in this file can confirm it. PA-E2E in `tests/client_pro.test.ts` is what pins it,
 *     by taking its rows from the endpoint itself. If the two ever disagree, PA-E2E is right.
 *
 * The load-bearing case is the COLLISION: a cellId shared to this agent may equal one it owns, since
 * cellIds are chosen per-writer and share no namespace. Both must survive, and the own-cell
 * all-or-nothing duplicate rejection must NOT fire on the pair.
 */
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WireEnvelope } from '@saihm/client-pro';
import {
  SaihmProClient,
  SaihmEndpointError,
  MAX_ANNOUNCEMENT_FIELD_CHARS,
  MAX_ANNOUNCEMENT_TOTAL_CHARS,
  MAX_SHARED_ANNOUNCEMENTS,
} from '../src/client.js';

/**
 * What ONE announcement spends against the total budget — the same four fields, counted the same way
 * the client counts them. Derived here rather than restated as a number so a test cannot drift from
 * the implementation it is measuring; the VALUES of the caps are pinned separately and deliberately.
 */
const rowChars = (a: {
  sharer: string;
  cellId: string;
  scope: string;
  expiryEpoch: string | null;
}): number => a.sharer.length + a.cellId.length + a.scope.length + (a.expiryEpoch?.length ?? 0);

/**
 * Distinct, individually-legal announcements whose sizes sum to EXACTLY the total budget, plus
 * `extra` characters on the final row.
 *
 * Built from the caps rather than from arithmetic done once and written down: `extra: 0` lands on the
 * boundary and `extra: 1` steps one character past it, which is what pins a `>` comparison from both
 * sides. Every row is under the per-field cap, so nothing is dropped for the wrong reason.
 */
const budgetFillingRows = (extra: number): Record<string, unknown>[] => {
  const sharer = 'ba'.repeat(32); // exactly the 64-char shape a real sharer has
  const out: Record<string, unknown>[] = [];
  let spent = 0;
  for (let i = 0; ; i++) {
    const cellLen = Math.min(
      MAX_ANNOUNCEMENT_FIELD_CHARS,
      MAX_ANNOUNCEMENT_TOTAL_CHARS - spent - sharer.length - 'read'.length,
    );
    if (cellLen < 1) break;
    out.push(announce(String(i).padStart(cellLen, 'f'), sharer, 'read', null));
    spent += sharer.length + cellLen + 'read'.length;
  }
  // One final row spends whatever is left, plus `extra`. Sharer and scope are empty so its whole cost
  // is the cellId, which keeps the arithmetic exact whatever remainder the loop leaves.
  const left = MAX_ANNOUNCEMENT_TOTAL_CHARS - spent + extra;
  if (left > 0) out.push(announce('z'.repeat(left), '', '', null));
  return out;
};

const masterOf = (b: number): Uint8Array => new Uint8Array(32).fill(b);

interface Ctx {
  bridgeUrl: string;
}

/**
 * A minimal blind endpoint: it stores whatever the client seals and hands it straight back.
 *
 * The delta branch is gated on `SAIHM_BLIND_RECALL_DELTA` read PER REQUEST, mirroring the real
 * endpoint — the client always sends `knownCellIds` once a cache is configured and never decides the
 * shape itself, so a test that flips the env var flips which reply shape the client must cope with.
 */
async function withStack(
  fn: (ctx: Ctx) => Promise<void>,
  opts: { transform?: (method: string, responseText: string) => string } = {},
): Promise<void> {
  const store = new Map<string, WireEnvelope>();

  const reply = (method: string, params: Record<string, unknown>): unknown => {
    if (method === 'saihm_remember') {
      const wire = params.wire as WireEnvelope;
      store.set(wire.cellId, wire);
      return { stored: true, cellId: wire.cellId };
    }
    if (method !== 'saihm_recall') return { error: 'unused' };
    const rows = [...store.entries()].map(([cellId, wire]) => ({ cellId, found: true, wire }));
    if (typeof params.cellId === 'string') {
      const wire = store.get(params.cellId);
      return wire ? { found: true, wire } : { found: false };
    }
    if (Array.isArray(params.knownCellIds) && process.env.SAIHM_BLIND_RECALL_DELTA === '1') {
      const known = new Set(params.knownCellIds as string[]);
      return {
        mode: 'delta',
        added: rows.filter((r) => !known.has(r.cellId)),
        liveCellIds: [...store.keys()],
      };
    }
    return rows;
  };

  const bridge: Server = createServer((req, res) => {
    void (async () => {
      try {
        let body = '';
        for await (const c of req) body += c;
        const parsed = JSON.parse(body) as { method: string; params?: Record<string, unknown> };
        const raw = JSON.stringify(reply(parsed.method, parsed.params ?? {}));
        const txt = opts.transform ? opts.transform(parsed.method, raw) : raw;
        res
          .writeHead(200, {
            'content-type': 'application/json',
            'content-length': String(Buffer.byteLength(txt)),
          })
          .end(txt);
      } catch {
        const j = JSON.stringify({ error: 'bridge_error' });
        res
          .writeHead(500, {
            'content-type': 'application/json',
            'content-length': String(Buffer.byteLength(j)),
          })
          .end(j);
      }
    })();
  });
  await new Promise<void>((r) => bridge.listen(0, '127.0.0.1', () => r()));
  const bridgeUrl = `http://127.0.0.1:${(bridge.address() as AddressInfo).port}/mcp`;

  try {
    await fn({ bridgeUrl });
  } finally {
    await new Promise<void>((r) => bridge.close(() => r()));
  }
}

const announce = (
  cellId: string,
  sharer: string,
  scope = 'read',
  // DECIMAL STRING or null — the shapes the endpoint can actually emit, with null (no expiry) as its
  // DEFAULT. An earlier cut of this helper hardcoded the NUMBER 999, a value no endpoint can produce;
  // six tests passed green against it while the real client silently skipped every real announcement.
  // A fixture that cannot occur on the wire pins the author's belief, not the contract. Hence PA-E2E,
  // which takes its rows from the real endpoint and would have caught it on its own.
  expiryEpoch: string | null = null,
): Record<string, unknown> => ({ cellId, sharer, shared: true, scope, expiryEpoch });

/** The five keys an announcement is allowed to carry — nothing from the wire may widen it. */
const ANN_KEYS = ['cellId', 'expiryEpoch', 'scope', 'sharer', 'verified'];

/** Append rows to whatever the endpoint returned for saihm_recall (array form or delta `added`). */
const inject =
  (...rows: Record<string, unknown>[]) =>
  (method: string, text: string): string => {
    if (method !== 'saihm_recall') return text;
    const body = JSON.parse(text) as unknown;
    if (Array.isArray(body)) return JSON.stringify([...body, ...rows]);
    if (body && typeof body === 'object' && Array.isArray((body as { added?: unknown }).added)) {
      const b = body as { added: unknown[] };
      return JSON.stringify({ ...b, added: [...b.added, ...rows] });
    }
    return text;
  };

const SHARER_A = 'aa'.repeat(32);
const SHARER_B = 'bb'.repeat(32);

const mkClient = (ctx: Ctx, master: Uint8Array, extra: Record<string, unknown> = {}) =>
  new SaihmProClient(ctx.bridgeUrl, 'Bearer test', master, { tier: 'PRO', ...extra });

describe('PC-SHARED-ANNOUNCE: announcements are pointers, never memories', () => {
  it('an own cell and an announcement with the SAME cellId both survive — no 502', async () => {
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(70));
        await c.remember("B's own notes", { cellId: 'notes' });

        const { cells, announcements, announcementsTruncated } = await c.recallWithShared();
        assert.equal(cells.length, 1, 'the own cell must not be displaced by the announcement');
        assert.equal(cells[0].cellId, 'notes');
        assert.equal(cells[0].plaintext, "B's own notes");

        assert.equal(announcements.length, 1, 'the announcement must not be displaced by the own cell');
        assert.equal(announcements[0].cellId, 'notes');
        assert.equal(announcements[0].sharer, SHARER_A);
        assert.equal(announcements[0].scope, 'read');
        assert.equal(announcements[0].expiryEpoch, '5000000000');
        assert.equal(announcements[0].verified, false, 'an announcement is never authenticated');
        assert.equal(announcementsTruncated, false);
      },
      { transform: inject(announce('notes', SHARER_A, 'read', '5000000000')) },
    );
  });

  it('recall() is UNCHANGED: it still returns only own cells, announcements or not', async () => {
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(76));
        await c.remember('only mine', { cellId: 'mine' });

        const cells = await c.recall();
        assert.ok(Array.isArray(cells), 'recall() must still return a bare array');
        assert.equal(cells.length, 1, 'two announcements must add nothing to the memory count');
        assert.equal(cells[0].cellId, 'mine');
        // Announcements are bound to the RESPONSE, never held on the client. Asserting one chosen
        // name is `undefined` proves nothing — every name that was never defined is undefined. So
        // sweep instead: `private` is erased at runtime, so a re-introduced `lastAnnouncements` field
        // would be a plain own property here, and an accessor would sit on the prototype. Either
        // revives the cross-attribution bug, where two concurrent recalls read each other's set.
        const surface = [
          ...Object.getOwnPropertyNames(c),
          ...Object.getOwnPropertyNames(Object.getPrototypeOf(c)),
        ];
        assert.deepEqual(
          surface.filter((k) => /announce/i.test(k)),
          [],
          'no announcement state or accessor may live on the client',
        );
      },
      { transform: inject(announce('x', SHARER_A), announce('y', SHARER_B)) },
    );
  });

  it('an announcement carries EXACTLY the five declared keys — no content, no wire leakage', async () => {
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(71));
        await c.remember('only mine', { cellId: 'mine' });

        const { announcements } = await c.recallWithShared();
        assert.equal(announcements.length, 1);
        // Asserted against the object the CLIENT built from a row carrying extra fields, so this
        // discriminates: pass the row through and `plaintext`/`wire`/`found` would appear here.
        assert.deepEqual(Object.keys(announcements[0]).sort(), ANN_KEYS);
      },
      {
        transform: inject({
          ...announce('x', SHARER_A),
          plaintext: 'FORGED CONTENT',
          found: true,
          seq: '9',
        }),
      },
    );
  });

  it('a MALFORMED announcement is skipped, not thrown on — own memories still resolve', async () => {
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(72));
        await c.remember('survives', { cellId: 'ok' });

        const { cells, announcements } = await c.recallWithShared();
        assert.equal(cells.length, 1, 'a hostile endpoint must not deny this agent its OWN memories');
        assert.equal(cells[0].plaintext, 'survives');
        assert.equal(announcements.length, 2, 'only the well-formed announcements are kept');
        assert.deepEqual(announcements.map((a) => a.cellId).sort(), ['absent-epoch', 'good']);
        // An ABSENT epoch normalises to null rather than being dropped: an endpoint predating the
        // field must still be able to announce.
        assert.equal(announcements.find((a) => a.cellId === 'absent-epoch')!.expiryEpoch, null);
      },
      {
        transform: inject(
          { cellId: 'bad1', shared: true, scope: 'read', expiryEpoch: null }, // no sharer
          { cellId: 'bad2', sharer: SHARER_A, shared: true, expiryEpoch: null }, // no scope
          { cellId: 7, sharer: SHARER_A, shared: true, scope: 'read', expiryEpoch: null }, // cellId not a string
          { cellId: 'bad4', sharer: 7, shared: true, scope: 'read', expiryEpoch: null }, // sharer not a string
          // A NUMBER epoch is not a shape the endpoint can emit; reject it rather than silently
          // widening the type the rest of the client (and the MCP outputSchema) depends on.
          { cellId: 'bad5', sharer: SHARER_A, shared: true, scope: 'read', expiryEpoch: 999 },
          { cellId: 'absent-epoch', sharer: SHARER_A, shared: true, scope: 'read' },
          announce('good', SHARER_B, 'read', '5000000000'),
        ),
      },
    );
  });

  it('dedup is by (sharer, cellId): one sharer granting TWO cells yields TWO pointers', async () => {
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(73));
        await c.remember('mine', { cellId: 'mine' });
        const { announcements } = await c.recallWithShared();
        // The discriminating case a sharer-only key would collapse — and the ORDINARY one: an agent
        // that grants two cells is the common grant, not an edge case.
        assert.equal(announcements.length, 3);
        assert.deepEqual(
          announcements.map((a) => `${a.sharer.slice(0, 2)}/${a.cellId}`).sort(),
          ['aa/dup', 'aa/other', 'bb/dup'],
        );
      },
      {
        transform: inject(
          announce('dup', SHARER_A),
          announce('dup', SHARER_A), // exact repeat — collapsed
          announce('other', SHARER_A), // SAME sharer, DIFFERENT cell — kept
          announce('dup', SHARER_B), // different sharer — kept
        ),
      },
    );
  });

  it('the dedup key is injective: ("a:b","c") and ("a","b:c") are distinct pointers', async () => {
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(77));
        await c.remember('mine', { cellId: 'mine' });
        const { announcements } = await c.recallWithShared();
        assert.equal(
          announcements.length,
          2,
          'a naive `${sharer}:${cellId}` key collapses these two, letting the endpoint suppress one',
        );
      },
      { transform: inject(announce('c', 'a:b'), announce('b:c', 'a')) },
    );
  });

  it('a `shared:true` row that ALSO carries a real envelope stays an OWN cell — it cannot be hidden', async () => {
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(78));
        await c.remember('do not lose me', { cellId: 'keep' });

        const { cells, announcements } = await c.recallWithShared();
        assert.equal(cells.length, 1, 'an authenticated own cell must not be divertible by a flag');
        assert.equal(cells[0].plaintext, 'do not lose me');
        assert.equal(announcements.length, 0, 'a row bearing an envelope is not an announcement');
      },
      {
        // Take the endpoint's GENUINE own-cell row and bolt announcement fields onto it. Without the
        // `wire === undefined` guard the cell vanishes silently — and on a cached path replaceAll then
        // deletes it from disk, driving unauthenticated input into persisted own-cell state.
        transform: (method, text) => {
          if (method !== 'saihm_recall') return text;
          const body = JSON.parse(text) as unknown;
          if (!Array.isArray(body) || body.length === 0) return text;
          const row = body[0] as Record<string, unknown>;
          return JSON.stringify([
            { ...row, shared: true, sharer: SHARER_A, scope: 'read', expiryEpoch: null },
          ]);
        },
      },
    );
  });

  it('the keyword filter applies to memories only — announcements are unfiltered', async () => {
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(79));
        await c.remember('alpha note', { cellId: 'a' });
        await c.remember('beta note', { cellId: 'b' });

        const { cells, announcements } = await c.recallWithShared('alpha');
        assert.equal(cells.length, 1, 'the query still filters own cells');
        assert.equal(cells[0].plaintext, 'alpha note');
        assert.equal(
          announcements.length,
          1,
          'an announcement has no plaintext to match, so a query must not silently drop it',
        );
      },
      { transform: inject(announce('shared-one', SHARER_A)) },
    );
  });

  it('the announcement list is CAPPED and truncation is reported, never silent', async () => {
    const flood = Array.from({ length: 300 }, (_, i) => announce(`c${i}`, SHARER_A));
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(80));
        await c.remember('mine', { cellId: 'mine' });

        const { cells, announcements, announcementsTruncated } = await c.recallWithShared();
        assert.equal(cells.length, 1, 'a flood must not cost this agent its own memories');
        assert.equal(announcements.length, 256, 'kept set is capped');
        assert.equal(announcementsTruncated, true, 'a cut list must say so');
      },
      { transform: inject(...flood) },
    );
  });

  it('REGRESSION: a duplicated OWN cell still rejects the whole response (all-or-nothing intact)', async () => {
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(74));
        await c.remember('mine', { cellId: 'mine' });
        await assert.rejects(
          () => c.recall(),
          (e: unknown) =>
            e instanceof SaihmEndpointError && /more than once/.test((e as Error).message),
          'announcement handling must not have weakened the own-cell cardinality guard',
        );
      },
      {
        transform: (method, text) => {
          if (method !== 'saihm_recall') return text;
          const body = JSON.parse(text) as unknown;
          if (!Array.isArray(body) || body.length === 0) return text;
          return JSON.stringify([...body, body[0]]); // echo the own row back a second time
        },
      },
    );
  });

  it('announcements are replaced wholesale by each recall — never accumulated', async () => {
    let on = true;
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(75));
        await c.remember('mine', { cellId: 'mine' });

        assert.equal((await c.recallWithShared()).announcements.length, 1, 'first recall sees it');

        on = false; // grant revoked / discovery switched off between calls
        assert.equal(
          (await c.recallWithShared()).announcements.length,
          0,
          'a stale pointer must not outlive the response that carried it',
        );
      },
      {
        transform: (method, text) =>
          on ? inject(announce('ghost', SHARER_A))(method, text) : text,
      },
    );
  });

  it('DELTA PATH: announcements ride the `added` list and reach the caller', async () => {
    const prev = process.env.SAIHM_BLIND_RECALL_DELTA;
    process.env.SAIHM_BLIND_RECALL_DELTA = '1';
    const cacheDir = mkdtempSync(join(tmpdir(), 'saihm-ann-delta-'));
    try {
      await withStack(
        async (ctx) => {
          const c = mkClient(ctx, masterOf(81), {
            recallCachePath: join(cacheDir, 'recall_cache.json'),
            seqStatePath: join(cacheDir, 'seq.json'),
          });
          await c.remember('cached memory', { cellId: 'dm' });

          const r = await c.recallWithShared();
          // Delta really is the path under test: the cache file is the delta cache, not the full one.
          const cached = JSON.parse(
            readFileSync(join(cacheDir, 'recall_cache.json'), 'utf-8'),
          ) as Record<string, unknown>;
          assert.equal(Object.keys(cached).length, 1, 'delta cache populated => delta path taken');
          assert.equal(r.cells.length, 1);
          assert.equal(
            r.announcements.length,
            1,
            'deleting the delta branch assignment must not leave this suite green',
          );
          assert.equal(r.announcements[0].cellId, 'via-delta');
          // A pointer must never be written into the on-disk own-cell cache.
          assert.ok(!Object.keys(cached).includes('via-delta'), 'announcements are never cached');
        },
        { transform: inject(announce('via-delta', SHARER_A, 'read', '5000000000')) },
      );
    } finally {
      if (prev === undefined) delete process.env.SAIHM_BLIND_RECALL_DELTA;
      else process.env.SAIHM_BLIND_RECALL_DELTA = prev;
      rmSync(cacheDir, { recursive: true, force: true });
    }
  });

  it('LEGACY-ARRAY FALLBACK with a cache configured: announcements still reach the caller', async () => {
    // The third recall path, and the one easiest to leave behind: a DELTA-configured client talking to
    // an endpoint whose delta gate is OFF. It takes the cache branch (so it sends knownCellIds and
    // writes the cache) but gets the legacy ARRAY back, and must open that array for announcements
    // exactly as the uncached full path does. Dropping them here fails silently — the caller sees a
    // well-formed, complete-looking recall with no pointers in it.
    const prev = process.env.SAIHM_BLIND_RECALL_DELTA;
    delete process.env.SAIHM_BLIND_RECALL_DELTA; // gate OFF => endpoint answers with the legacy array
    const cacheDir = mkdtempSync(join(tmpdir(), 'saihm-ann-legacy-'));
    const cachePath = join(cacheDir, 'recall_cache.json');
    let sawArrayReply = false;
    try {
      await withStack(
        async (ctx) => {
          const c = mkClient(ctx, masterOf(82), {
            recallCachePath: cachePath,
            seqStatePath: join(cacheDir, 'seq.json'),
          });
          await c.remember('legacy memory', { cellId: 'lm' });

          const r = await c.recallWithShared();
          // Both halves of the path are pinned, so neither can drift out from under the assertion:
          // the reply really was the legacy array, and the cache branch really was the one that ran.
          assert.equal(sawArrayReply, true, 'the endpoint must have answered with the legacy array');
          const cached = JSON.parse(readFileSync(cachePath, 'utf-8')) as Record<string, unknown>;
          assert.equal(Object.keys(cached).length, 1, 'cache written => the cache branch ran');
          assert.equal(r.cells.length, 1);
          assert.equal(r.cells[0].cellId, 'lm');
          assert.equal(r.announcements.length, 1, 'the legacy-array branch must not drop announcements');
          assert.equal(r.announcements[0].cellId, 'via-legacy');
          assert.equal(r.announcements[0].expiryEpoch, null);
          assert.equal(r.announcementsTruncated, false);
          // replaceAll must not have persisted the pointer alongside the own cell.
          assert.ok(!Object.keys(cached).includes('via-legacy'), 'announcements are never cached');
        },
        {
          transform: (method, text) => {
            if (method === 'saihm_recall' && Array.isArray(JSON.parse(text))) sawArrayReply = true;
            return inject(announce('via-legacy', SHARER_A))(method, text);
          },
        },
      );
    } finally {
      if (prev !== undefined) process.env.SAIHM_BLIND_RECALL_DELTA = prev;
      rmSync(cacheDir, { recursive: true, force: true });
    }
  });

  it('DELTA PATH: the cap and its truncation flag apply to `added` too', async () => {
    // The cap is enforced inside openRecallRows, which both paths share — but "shared code" is a claim
    // about today's factoring, not a guarantee, and the flag is the only signal that a listing is
    // partial. A delta client silently capped at 256 would report a complete set of grants that isn't.
    const prev = process.env.SAIHM_BLIND_RECALL_DELTA;
    process.env.SAIHM_BLIND_RECALL_DELTA = '1';
    const cacheDir = mkdtempSync(join(tmpdir(), 'saihm-ann-cap-'));
    const flood = Array.from({ length: 300 }, (_, i) => announce(`cap-${i}`, SHARER_A));
    try {
      await withStack(
        async (ctx) => {
          const c = mkClient(ctx, masterOf(83), {
            recallCachePath: join(cacheDir, 'recall_cache.json'),
            seqStatePath: join(cacheDir, 'seq.json'),
          });
          await c.remember('capped memory', { cellId: 'cm' });

          const r = await c.recallWithShared();
          assert.equal(r.announcements.length, 256, 'the cap bounds the delta list at 256');
          assert.equal(r.announcementsTruncated, true, 'a cut listing must say so');
          // The cap must not cost the caller its own cells — they travel in the same response.
          assert.equal(r.cells.length, 1);
          assert.equal(r.cells[0].cellId, 'cm');
          // Kept in arrival order, so the caller can reason about WHICH 256 survived.
          assert.equal(r.announcements[0].cellId, 'cap-0');
          assert.equal(r.announcements[255].cellId, 'cap-255');
        },
        { transform: inject(...flood) },
      );
    } finally {
      if (prev === undefined) delete process.env.SAIHM_BLIND_RECALL_DELTA;
      else process.env.SAIHM_BLIND_RECALL_DELTA = prev;
      rmSync(cacheDir, { recursive: true, force: true });
    }
  });

  it('`shared` must be the BOOLEAN true — a truthy lookalike announces nothing', async () => {
    // The strict `=== true` is what stops a JSON-typed near-miss from minting a pointer. Each row below
    // is truthy under `if (row.shared)`, so a loosened check would admit all four; none carries an
    // envelope, so under the strict check they fall through and are skipped as own cells. Neither
    // stream may take them.
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(84));
        await c.remember('real memory', { cellId: 'rm' });

        const r = await c.recallWithShared();
        assert.equal(r.announcements.length, 0, 'only `shared: true` announces');
        assert.equal(r.announcementsTruncated, false);
        assert.equal(r.cells.length, 1, 'the own cell survives the rejected rows');
        assert.equal(r.cells[0].cellId, 'rm');
      },
      {
        transform: inject(
          { ...announce('str-true', SHARER_A), shared: 'true' },
          { ...announce('num-one', SHARER_A), shared: 1 },
          { ...announce('obj', SHARER_A), shared: {} },
          { ...announce('arr', SHARER_A), shared: ['true'] },
        ),
      },
    );
  });

  it('a BYTE-BUDGET flood before the own cells must not cost the caller its memories', async () => {
    // The sibling of the row-cap case below, and the reason both exist: the two caps are independent
    // paths, and the test below cannot reach this one. Its 300 rows are ~75 characters each (~22 KB),
    // so they trip the 256-ROW cap long before the 32 KiB BYTE budget — leaving `break`-instead-of-
    // `continue` on the budget path undetectable. These rows are maximal (64-char cellId + 64-char
    // sharer + `readwrite`), so the budget trips at row ~239, BEFORE the row cap is reached, and the
    // own cell arrives after it. A `break` there silently drops every own cell that follows and then
    // writes the truncated set through to disk.
    const cacheDir = mkdtempSync(join(tmpdir(), 'saihm-ann-bytes-'));
    const cachePath = join(cacheDir, 'recall_cache.json');
    const bigSharer = 'ab'.repeat(32); // 64 chars
    const flood = Array.from({ length: 250 }, (_, i) =>
      announce(String(i).padStart(64, '0'), bigSharer, 'readwrite'),
    );
    try {
      await withStack(
        async (ctx) => {
          const c = mkClient(ctx, masterOf(86), {
            recallCachePath: cachePath,
            seqStatePath: join(cacheDir, 'seq.json'),
          });
          await c.remember('survives the byte flood', { cellId: 'byte-survivor' });

          const r = await c.recallWithShared();
          assert.equal(r.cells.length, 1, 'the own cell must survive a budget-tripping flood');
          assert.equal(r.cells[0].cellId, 'byte-survivor');
          assert.equal(r.cells[0].plaintext, 'survives the byte flood');
          assert.equal(r.announcementsTruncated, true, 'a budget-cut listing must say so');
          // The BUDGET is what stopped it, not the row cap — otherwise this duplicates the test below
          // and the branch it exists for stays uncovered.
          //
          // This used to read `r.announcements.length < 256` with 250 rows injected, so it held
          // whatever the client did and could not fail. The mutation it was written to catch WAS
          // caught, but by the `announcementsTruncated` assertion above, not by the line whose message
          // claimed to catch it — which is worse than an absent test, because the message asserts
          // coverage that is not there. Both statements below are falsifiable: rows were dropped, and
          // the scan stopped where one more would not have fit rather than early.
          assert.ok(
            r.announcements.length < flood.length,
            `expected rows to be dropped, kept all ${r.announcements.length}`,
          );
          assert.ok(
            r.announcements.length < MAX_SHARED_ANNOUNCEMENTS,
            `the byte budget must bite BEFORE the ${MAX_SHARED_ANNOUNCEMENTS}-row cap, kept ${r.announcements.length}`,
          );
          const spent = r.announcements.reduce((n, a) => n + rowChars(a), 0);
          assert.ok(
            spent <= MAX_ANNOUNCEMENT_TOTAL_CHARS,
            `kept set must fit the budget, spent ${spent}`,
          );
          assert.ok(
            spent + rowChars(r.announcements[0]) > MAX_ANNOUNCEMENT_TOTAL_CHARS,
            `the budget must be the binding constraint — one more row of the same shape still fits (spent ${spent})`,
          );
          const cached = JSON.parse(readFileSync(cachePath, 'utf-8')) as Record<string, unknown>;
          assert.deepEqual(Object.keys(cached), ['byte-survivor'], 'the cache keeps exactly the own cell');
        },
        {
          transform: (method, text) => {
            if (method !== 'saihm_recall') return text;
            const body = JSON.parse(text) as unknown;
            if (Array.isArray(body)) return JSON.stringify([...flood, ...body]);
            return text;
          },
        },
      );
    } finally {
      rmSync(cacheDir, { recursive: true, force: true });
    }
  });

  it('a REPEATED announcement is free: it neither spends budget nor claims the list was cut', async () => {
    // Two distinct properties, and being precise about which is which matters, because only one of
    // them was ever a live defect.
    //
    // THIS test covers the budget: a repeat must not CONSUME it. That was never broken — the `+=` has
    // always sat after the dedup check — but nothing asserted it, so moving one statement above one
    // line turned it into real suppression: repeat a single legal announcement, exhaust the 32 KiB
    // budget, and every GENUINE grant arriving later is dropped behind a `LIST TRUNCATED` banner the
    // agent reads as the endpoint having more to offer rather than as the endpoint hiding something.
    // A one-line refactor away from a suppression primitive is not a property to leave unpinned.
    //
    // The sibling test below covers the FLAG, which was genuinely wrong.
    //
    // The fixture is the attack, not an analogue of it: one row repeated enough times to spend the
    // budget several times over, then one real grant that must still arrive.
    const dupSharer = 'cd'.repeat(32);
    const dupCell = 'D'.repeat(MAX_ANNOUNCEMENT_FIELD_CHARS);
    const one = announce(dupCell, dupSharer, 'read', '9'.repeat(20));
    const perRow = dupSharer.length + dupCell.length + 'read'.length + 20;
    const copies = Math.ceil((MAX_ANNOUNCEMENT_TOTAL_CHARS / perRow) * 3);
    const real = announce('e'.repeat(64), 'ef'.repeat(32), 'readwrite', null);
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(94));
        await c.remember('unaffected by the repeat flood', { cellId: 'dup-survivor' });

        const r = await c.recallWithShared();
        assert.ok(
          copies * perRow > MAX_ANNOUNCEMENT_TOTAL_CHARS,
          'the fixture must actually exceed the budget if repeats were charged for',
        );
        assert.equal(r.announcements.length, 2, `the duplicate collapses to one, and the real grant survives`);
        assert.deepEqual(
          r.announcements.map((a) => a.cellId).sort(),
          [dupCell, 'e'.repeat(64)].sort(),
          'the genuine grant announced LAST must not be suppressed by the repeats before it',
        );
        // Nothing was withheld, so the flag must not claim otherwise. A truncation flag that a hostile
        // endpoint can raise at will is a lie it gets to tell in the trusted channel.
        assert.equal(
          r.announcementsTruncated,
          false,
          'a duplicate withholds nothing — it must not set the truncation flag',
        );
        assert.equal(r.cells.length, 1, 'own cells are unaffected');
      },
      {
        transform: (method, text) => {
          if (method !== 'saihm_recall') return text;
          const body = JSON.parse(text) as unknown;
          if (Array.isArray(body))
            return JSON.stringify([...Array.from({ length: copies }, () => one), real, ...body]);
          return text;
        },
      },
    );
  });

  it('a repeat arriving on a FULL budget must not raise the truncation flag', async () => {
    // The flag half, and the half that was genuinely wrong. Fill the budget exactly, then send an
    // exact repeat of a row already kept. The budget comparison used to run before the dedup check,
    // so the repeat's size was weighed against a full budget, the comparison tripped, and
    // `announcementsTruncated` was set — on a listing from which NOTHING was withheld.
    //
    // A truncation flag a hostile endpoint can raise at will is a lie it gets to tell in the trusted
    // channel: the server renders `(LIST TRUNCATED: the endpoint announced more)` from it, which is
    // an assertion to the agent that grants exist beyond what it can see.
    const flood = budgetFillingRows(0);
    const withRepeat = [...flood, flood[0]];
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(97));
        const r = await c.recallWithShared();
        assert.equal(r.announcements.length, flood.length, 'the repeat collapses; every real row stays');
        assert.equal(
          r.announcements.reduce((n, a) => n + rowChars(a), 0),
          MAX_ANNOUNCEMENT_TOTAL_CHARS,
          'the budget is exactly full — the repeat is tested against the hardest case',
        );
        assert.equal(
          r.announcementsTruncated,
          false,
          'nothing was withheld, so the listing must not claim it was cut',
        );
      },
      {
        transform: (method, text) => {
          if (method !== 'saihm_recall') return text;
          const body = JSON.parse(text) as unknown;
          if (Array.isArray(body)) return JSON.stringify([...withRepeat, ...body]);
          return text;
        },
      },
    );
  });

  it('a kept set landing EXACTLY on the byte budget is kept, and one character more is not', async () => {
    // The boundary the `>` comparison turns on, unexercised until now: `+1` and `>=` both survived a
    // mutation pass because every fixture overshot the budget by hundreds of characters. Two runs of
    // the same shape, differing by ONE character, pin the comparison from both sides.
    for (const [extra, shouldFit] of [
      [0, true],
      [1, false],
    ] as const) {
      const flood = budgetFillingRows(extra);
      await withStack(
        async (ctx) => {
          const c = mkClient(ctx, masterOf(95 + extra));
          const r = await c.recallWithShared();
          const spent = r.announcements.reduce((n, a) => n + rowChars(a), 0);
          if (shouldFit) {
            assert.equal(
              spent,
              MAX_ANNOUNCEMENT_TOTAL_CHARS,
              'a set landing exactly ON the budget must be kept whole',
            );
            assert.equal(r.announcements.length, flood.length, 'no row may be dropped at the boundary');
            assert.equal(r.announcementsTruncated, false, 'nothing was withheld at exactly the budget');
          } else {
            assert.ok(spent < MAX_ANNOUNCEMENT_TOTAL_CHARS, `one char over must not be admitted: ${spent}`);
            assert.equal(r.announcements.length, flood.length - 1, 'exactly the over-budget row is cut');
            assert.equal(r.announcementsTruncated, true, 'and the cut must be reported');
          }
        },
        {
          transform: (method, text) => {
            if (method !== 'saihm_recall') return text;
            const body = JSON.parse(text) as unknown;
            if (Array.isArray(body)) return JSON.stringify([...flood, ...body]);
            return text;
          },
        },
      );
    }
  });

  it('the announcement caps are PINNED, not merely self-consistent', () => {
    // Every other test in this file derives its expectations from these constants — deliberately, so
    // the client and the server's render budget cannot drift apart. The cost of that choice is that
    // nothing pins the VALUES: a mutation pass widened MAX_ANNOUNCEMENT_FIELD_CHARS from 64 to 4096
    // with this entire suite green, and 4096 turns 16 rendered pointers into ~66 KB of endpoint-chosen
    // prose per recall. Coupling and value are two different properties and each needs its own test.
    assert.equal(MAX_ANNOUNCEMENT_FIELD_CHARS, 64);
    assert.equal(MAX_SHARED_ANNOUNCEMENTS, 256);
    assert.equal(MAX_ANNOUNCEMENT_TOTAL_CHARS, 32 * 1024);
  });

  it('a row claiming found:true with NO envelope is skipped, not fatal to the whole recall', async () => {
    // `!row.found || !row.wire` reads as one guard but is two, and no fixture had ever supplied this
    // half. Drop it and the row reaches openRow(null, undefined) -> decodeEnvelope(undefined), which
    // throws 502 malformed_envelope and aborts the ENTIRE recall: one crafted row would deny the agent
    // every memory it owns. That is precisely the denial capability the announcement branch is
    // documented not to grant, arriving through the own-cell branch instead.
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(87));
        await c.remember('must survive a wireless row', { cellId: 'real' });

        const { cells, announcements } = await c.recallWithShared();
        assert.equal(cells.length, 1, 'a found-but-empty row must not cost the agent its memories');
        assert.equal(cells[0].cellId, 'real');
        assert.equal(cells[0].plaintext, 'must survive a wireless row');
        assert.equal(announcements.length, 0, 'it is not an announcement either — it is just dropped');
      },
      { transform: inject({ cellId: 'no-wire', found: true }) },
    );
  });

  it('a row carrying an envelope but found:false is skipped — the flag still gates', async () => {
    // The other half. Without it the endpoint's own "this cell exists" flag stops gating anything, so
    // it could serve a cell it simultaneously reports as absent. Envelope authentication and the seq
    // guard bound what that achieves, which is why this is the narrower of the pair — but an
    // unprotected guard is one refactor from being deleted as redundant.
    await withStack(
      async (ctx) => {
        const c = mkClient(ctx, masterOf(88));
        await c.remember('the live one', { cellId: 'live' });

        const { cells } = await c.recallWithShared();
        assert.equal(cells.length, 1, 'only the row the endpoint admits is live may open');
        assert.equal(cells[0].cellId, 'live');
      },
      {
        // Re-serve the GENUINE own row with found flipped to false — a real envelope, so only the
        // flag distinguishes it.
        transform: (method, text) => {
          if (method !== 'saihm_recall') return text;
          const body = JSON.parse(text) as unknown;
          if (!Array.isArray(body) || body.length === 0) return text;
          const row = body[0] as Record<string, unknown>;
          return JSON.stringify([...body, { ...row, cellId: 'ghost', found: false }]);
        },
      },
    );
  });

  it('a flood arriving BEFORE the own cells must not cost the caller its memories', async () => {
    // Row ORDER is the adversarial variable, and every other flood test here appends announcements
    // AFTER the own rows, so none of them can see it. Once the cap is reached the loop must keep
    // scanning: `break` instead of `continue` silently drops every own cell that arrives later — and
    // on the cached path replaceAll then writes that truncated set through to disk, which is exactly
    // the route from this unauthenticated branch into PERSISTED own-cell state that the cap exists
    // to prevent. Both the returned set and the cache file are asserted, because they fail together.
    const cacheDir = mkdtempSync(join(tmpdir(), 'saihm-ann-order-'));
    const cachePath = join(cacheDir, 'recall_cache.json');
    const flood = Array.from({ length: 300 }, (_, i) => announce(`pre-${i}`, SHARER_A));
    try {
      await withStack(
        async (ctx) => {
          const c = mkClient(ctx, masterOf(85), {
            recallCachePath: cachePath,
            seqStatePath: join(cacheDir, 'seq.json'),
          });
          await c.remember('survives the flood', { cellId: 'survivor' });

          const r = await c.recallWithShared();
          assert.equal(r.cells.length, 1, 'an own cell after 300 announcements must still be opened');
          assert.equal(r.cells[0].cellId, 'survivor');
          assert.equal(r.cells[0].plaintext, 'survives the flood');
          assert.equal(r.announcements.length, 256, 'the row cap still bounds the listing');
          assert.equal(r.announcementsTruncated, true);
          const cached = JSON.parse(readFileSync(cachePath, 'utf-8')) as Record<string, unknown>;
          assert.deepEqual(Object.keys(cached), ['survivor'], 'the cache keeps exactly the own cell');
        },
        {
          // PREPEND, unlike `inject` — the own rows must come last for this to test anything.
          transform: (method, text) => {
            if (method !== 'saihm_recall') return text;
            const body = JSON.parse(text) as unknown;
            if (Array.isArray(body)) return JSON.stringify([...flood, ...body]);
            if (body && typeof body === 'object' && Array.isArray((body as { added?: unknown }).added)) {
              const b = body as { added: unknown[] };
              return JSON.stringify({ ...b, added: [...flood, ...b.added] });
            }
            return text;
          },
        },
      );
    } finally {
      rmSync(cacheDir, { recursive: true, force: true });
    }
  });
});
