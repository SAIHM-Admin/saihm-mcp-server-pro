// What the endpoint says ABOUT an answer reaches a tool result intact, bounded, or as a marker, and never as a plausible
// value it did not send (the server features contract): `features` on saihm_status, `servedBy` and `asOf`
// on saihm_recall, `timing` on every structured result, and `sharedKept` beside a cut shared list. Every case also
// passes the tool's own output schema: an undeclared or mistyped key would replace the whole result with an
// output-validation error, which is why each call below asserts `isError: false` first.
// Runner: npx tsx --test tests/server_features_passthrough.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import {
  decodeEnvelope,
  deriveIdentity,
  encodeEnvelope,
  encodeIdentityRecord,
  encodeShareEnvelope,
  fromHex,
  sealCell,
  shareCell,
  toHex,
  utf8,
  type WireEnvelope,
} from '@saihm/client-pro';
import { endpointTiming, featuresOf, saihmServerMs } from '../src/client.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const MASTER_HEX = '5a'.repeat(32);
const ME = deriveIdentity(fromHex(MASTER_HEX));
const SHARER = deriveIdentity(new Uint8Array(32).fill(71));
const RECIPIENT = deriveIdentity(new Uint8Array(32).fill(72));
const MARK = '(malformed)';

interface Answer {
  status?: number;
  body: unknown;
  /** The body as text, for one this test process could not serialise itself (JSON.stringify has a depth limit too). */
  raw?: string;
  headers?: Record<string, string>;
  delayMs?: number;
}
type Route = (method: string, params: Record<string, unknown>) => Answer;

/** An endpoint whose answers the test swaps between calls: `route.current` answers each `/mcp` request. */
function startMock(route: { current: Route }): Server {
  return createServer((req, res) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => {
      if (req.method !== 'POST' || req.url !== '/mcp') {
        res.writeHead(404, { 'content-type': 'application/json' }).end('{"error":"not_found"}');
        return;
      }
      let method = '';
      let params: Record<string, unknown> = {};
      try {
        const j = JSON.parse(buf) as { method?: string; params?: Record<string, unknown> };
        method = j.method ?? '';
        params = j.params ?? {};
      } catch {
        /* the caller's problem, not this mock's */
      }
      const a = route.current(method, params);
      setTimeout(() => {
        res.writeHead(a.status ?? 200, { 'content-type': 'application/json', ...(a.headers ?? {}) });
        res.end(a.raw ?? JSON.stringify(a.body));
      }, a.delayMs ?? 0);
    });
  });
}

interface Result {
  text: string;
  isError: boolean;
  structured: Record<string, any>;
}
interface Driver {
  proc: ChildProcess;
  call: (name: string, args: unknown) => Promise<Result>;
  list: () => Promise<any[]>;
}

async function startServer(endpoint: string, home: string, extra: Record<string, string> = {}): Promise<Driver> {
  const proc = spawn(TSX, [SERVER], {
    env: {
      ...process.env,
      SAIHM_IDENTITY: undefined,
      SAIHM_IDENTITY_PASSPHRASE: undefined,
      SAIHM_MASTER_SECRET_FILE: undefined,
      SAIHM_STATE_DIR: undefined,
      SAIHM_ERASURE_FEED_DIR: undefined,
      SAIHM_EVENTS: undefined,
      SAIHM_RECALL_CACHE: undefined,
      SAIHM_RECALL_CACHE_PATH: undefined,
      SAIHM_ENDPOINT_URL: endpoint,
      SAIHM_AUTH_HEADER: 'Bearer passthrough-test',
      SAIHM_MASTER_SECRET_HEX: MASTER_HEX,
      SAIHM_HOME: home,
      SAIHM_TIER: 'PRO',
      SAIHM_PAYMENT_METHOD: 'stripe',
      SAIHM_SELF_JOIN: '0',
      ...extra,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: home,
  });
  let buf = '';
  let stderr = '';
  let next = 1;
  const waiters = new Map<number, (m: any) => void>();
  proc.stderr!.on('data', (d) => (stderr += d));
  proc.stdout!.on('data', (d) => {
    buf += d;
    let nl: number;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let m: any;
      try {
        m = JSON.parse(line);
      } catch {
        continue;
      }
      if (m.id != null && waiters.has(m.id)) {
        waiters.get(m.id)!(m);
        waiters.delete(m.id);
      }
    }
  });
  const rpc = (method: string, params: unknown): Promise<any> => {
    const id = next++;
    return new Promise((res, rej) => {
      waiters.set(id, res);
      proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      setTimeout(() => {
        if (waiters.delete(id)) rej(new Error(`rpc timeout ${method}; stderr=${stderr}`));
      }, 20_000).unref();
    });
  };
  await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  return {
    proc,
    call: async (name, args) => {
      const m = await rpc('tools/call', { name, arguments: args });
      assert.ok(m.result, `tools/call ${name} answered no result: ${JSON.stringify(m.error)}`);
      return {
        text: String(m.result.content?.[0]?.text ?? ''),
        isError: m.result.isError === true,
        structured: (m.result.structuredContent ?? {}) as Record<string, any>,
      };
    },
    list: async () => (await rpc('tools/list', {})).result.tools as any[],
  };
}

/** One mock and one server per test; the server's home and working directory are a fresh temporary directory. */
async function withServer(
  route: { current: Route },
  extra: Record<string, string>,
  body: (d: Driver, home: string) => Promise<void>,
): Promise<void> {
  const home = mkdtempSync(join(tmpdir(), 'saihm-pass-'));
  const mock = startMock(route);
  await new Promise<void>((r) => mock.listen(0, '127.0.0.1', () => r()));
  const d = await startServer(`http://127.0.0.1:${(mock.address() as AddressInfo).port}/mcp`, home, extra);
  try {
    await body(d, home);
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
}

const STATUS = {
  agentIdHashHex: 'ab'.repeat(32),
  tier: 'PRO',
  activeShardCount: 1,
  activeSharingContracts: 0,
  bfsi: 1,
  bfsi_R: '0',
  bfsi_M: '0',
  prsInstrumented: false,
  snapshotEpoch: '7',
  custody: 'non-custodial',
};

/** `d` levels of nested objects around a number. */
const nest = (d: number): unknown => {
  let v: unknown = 1;
  for (let i = 0; i < d; i++) v = { a: v };
  return v;
};
/** An object whose JSON is exactly `n` characters. */
const ofChars = (n: number): Record<string, string> => ({ k: 'x'.repeat(n - '{"k":""}'.length) });

/** Stands for a `features` nested 5,000 deep, sent as text: this process cannot serialise it either. */
const DEEP_5000 = Symbol('5,000 levels');

const FEATURES_EXAMPLE = {
  events: { v: [1], kinds: ['cell-written', 'cell-erased'] },
  warmStart: { v: [1], maxBytes: 0, maxSnapshots: 0, retentionS: 0 },
  replicas: { v: [1], maxStalenessMs: 0, erasureFence: 'synchronous' },
  capacity: { v: [1], reserved: true, unit: 'requests-per-second', rate: 0, burst: 0, objectiveApplies: true, attainment: null },
};

test('saihm_status: features absent or null is null; a plain object within the bounds passes whole; anything else is null and named in the text', async () => {
  assert.equal(JSON.stringify(ofChars(16_384)).length, 16_384, 'fixture: the at-bound object');
  const route = { current: ((): Answer => ({ body: STATUS })) as Route };
  await withServer(route, {}, async (d) => {
    const status = (await d.list()).find((t) => t.name === 'saihm_status');
    assert.ok(status.outputSchema.properties.features, 'features is declared on the published schema');
    assert.ok(status.outputSchema.properties.timing, 'timing is declared on the published schema');
    const cases: [string, unknown, unknown, boolean][] = [
      ['absent', undefined, null, false],
      ['null', null, null, false],
      ['the four features defined today', FEATURES_EXAMPLE, FEATURES_EXAMPLE, false],
      ['an empty object (a tier with no feature)', {}, {}, false],
      ['sixteen levels deep', nest(16), nest(16), false],
      ['exactly 16,384 JSON characters', ofChars(16_384), ofChars(16_384), false],
      ['an array', [{ events: { v: [1] } }], null, true],
      ['a string', 'events', null, true],
      ['a number', 1, null, true],
      ['a boolean', true, null, true],
      ['seventeen levels deep', nest(17), null, true],
      ['5,000 levels deep (JSON.stringify throws near 4,000)', DEEP_5000, null, true],
      ['16,385 JSON characters', ofChars(16_385), null, true],
    ];
    for (const [label, sent, want, marked] of cases) {
      route.current = () =>
        sent === DEEP_5000
          ? { body: null, raw: `${JSON.stringify(STATUS).slice(0, -1)},"features":${'{"a":'.repeat(5_000)}1${'}'.repeat(5_000)}}` }
          : { body: sent === undefined ? STATUS : { ...STATUS, features: sent } };
      const r = await d.call('saihm_status', {});
      assert.equal(r.isError, false, `${label}: ${r.text}`);
      assert.ok('features' in r.structured, `${label}: features is always present`);
      assert.deepEqual(r.structured.features, want, label);
      assert.equal(r.text.includes(`\n  features=${MARK}`), marked, `${label}: the marker line:\n${r.text}`);
      assert.equal(r.text.includes('events'), false, `${label}: a valid object is structured output alone`);
    }
  });
});

test('timing: totalMs measured here, serverMs and admission from the answer headers; absent without them; a malformed header withholds the whole and is named', async () => {
  const route = { current: ((): Answer => ({ body: STATUS })) as Route };
  await withServer(route, {}, async (d) => {
    const pad = (n: number): string => {
      const head = 'saihm;dur=4, pad;desc="';
      return head + 'p'.repeat(n - head.length - 1) + '"';
    };
    assert.equal(pad(4_096).length, 4_096, 'fixture: the at-bound header');
    const ok: [string, Record<string, string>, number | null, string | null][] = [
      ['both headers', { 'server-timing': 'saihm;dur=12.5', 'saihm-admission': 'reserved' }, 12.5, 'reserved'],
      ['admission alone', { 'saihm-admission': 'shared' }, null, 'shared'],
      ['Server-Timing alone', { 'server-timing': 'saihm;dur=7' }, 7, null],
      ['quoted separators in another metric, a quoted dur', { 'server-timing': 'cdn;desc="a, b; c", saihm;dur="3.25"' }, 3.25, null],
      ['a header of exactly 4,096 characters', { 'server-timing': pad(4_096) }, 4, null],
    ];
    for (const [label, headers, serverMs, admission] of ok) {
      route.current = () => ({ body: STATUS, headers, delayMs: 60 });
      const before = performance.now();
      const r = await d.call('saihm_status', {});
      const wall = performance.now() - before;
      assert.equal(r.isError, false, `${label}: ${r.text}`);
      const t = r.structured.timing;
      assert.ok(t, `${label}: timing present`);
      assert.deepEqual([t.serverMs, t.admission], [serverMs, admission], label);
      assert.equal(typeof t.totalMs, 'number', label);
      // Measured across the request: the endpoint held the answer 60 ms, and the call as a whole took longer still.
      assert.ok(t.totalMs >= 50 && t.totalMs <= wall, `${label}: totalMs ${t.totalMs} against a 60 ms answer and ${wall} ms wall`);
      assert.equal(r.text.includes('timing='), false, `${label}: no marker`);
    }
    const absent: [string, Record<string, string>][] = [
      ['neither header', {}],
      ["only an intermediary's metrics", { 'server-timing': 'cdn-cache;desc=HIT, edge;dur=2' }],
    ];
    for (const [label, headers] of absent) {
      route.current = () => ({ body: STATUS, headers });
      const r = await d.call('saihm_status', {});
      assert.equal(r.isError, false, `${label}: ${r.text}`);
      assert.equal('timing' in r.structured, false, `${label}: no timing is stated for an answer that states none`);
      assert.equal(r.text.includes('timing='), false, label);
    }
    const malformed: [string, Record<string, string>][] = [
      ['a dur that is not a number', { 'server-timing': 'saihm;dur=abc', 'saihm-admission': 'reserved' }],
      ['no dur (never read as 0)', { 'server-timing': 'saihm;desc=x' }],
      ['two durs', { 'server-timing': 'saihm;dur=1;dur=2' }],
      ['two saihm metrics', { 'server-timing': 'saihm;dur=1, saihm;dur=2' }],
      ['a negative dur', { 'server-timing': 'saihm;dur=-1' }],
      ['an exponent', { 'server-timing': 'saihm;dur=1e3' }],
      ['an unterminated quote', { 'server-timing': 'cdn;desc="open, saihm;dur=1' }],
      ['a header past 4,096 characters', { 'server-timing': pad(4_097) }],
      ['an admission outside the closed set', { 'server-timing': 'saihm;dur=1', 'saihm-admission': 'burst' }],
      ['an empty admission', { 'saihm-admission': '' }],
    ];
    for (const [label, headers] of malformed) {
      route.current = () => ({ body: STATUS, headers });
      const r = await d.call('saihm_status', {});
      assert.equal(r.isError, false, `${label}: ${r.text}`);
      assert.equal('timing' in r.structured, false, `${label}: withheld whole`);
      assert.ok(r.text.endsWith(`\n  timing=${MARK}`), `${label}: named in the text:\n${r.text}`);
      assert.equal(r.text.includes('burst') || r.text.includes('abc'), false, `${label}: no byte of the header is rendered`);
    }
  });
});

test('timing reaches saihm_remember and every saihm_recall branch, and a write reports its OWN answer, not the re-issue after it', async () => {
  const writes = new Map<string, WireEnvelope[]>();
  const HEADERS: Record<string, string> = { 'server-timing': 'saihm;dur=11', 'saihm-admission': 'shared' };
  const route = {
    current: ((method: string, params: Record<string, unknown>): Answer => {
      if (method === 'saihm_remember') {
        const wire = params.wire as WireEnvelope;
        const list = writes.get(wire.cellId) ?? [];
        list.push(wire);
        writes.set(wire.cellId, list);
        // The second write of a cell leaves one grant on the previous version, so the client re-issues it.
        const prev = list.length > 1 ? decodeEnvelope(list[list.length - 2] as WireEnvelope) : undefined;
        const staleShares = prev && {
          count: 1,
          after: null,
          grants: [
            {
              recipient: toHex(RECIPIENT.agentIdHash),
              scope: 'read',
              expiryEpoch: null,
              share: encodeShareEnvelope(
                shareCell({
                  envelope: prev,
                  sharerKek: ME.kek,
                  sharerMldsaSecretKey: ME.mldsaSecretKey,
                  sharerAgentIdHash: ME.agentIdHash,
                  recipientRecord: RECIPIENT.identityRecord,
                  recipientPinnedAgentIdHash: RECIPIENT.agentIdHash,
                }),
              ),
              recipientRecord: encodeIdentityRecord(RECIPIENT.identityRecord),
            },
          ],
        };
        return { body: { shardId: 'cd'.repeat(32), ...(staleShares ? { staleShares } : {}) }, headers: HEADERS };
      }
      if (method === 'saihm_share')
        return {
          body: {
            results: (params.shareWires as { recipientAgentIdHash: string }[]).map((w) => ({ recipient: w.recipientAgentIdHash, ok: true })),
            staleShares: { count: 0, grants: [], after: null },
          },
          headers: { 'server-timing': 'saihm;dur=999', 'saihm-admission': 'reserved' },
        };
      if (method === 'saihm_recall') {
        if (params.listOnly === true) return { body: { mode: 'list', cells: [], next: null }, headers: HEADERS };
        if (typeof params.sharer === 'string') return { body: { found: false }, headers: HEADERS };
        if (typeof params.cellId === 'string') {
          const list = writes.get(params.cellId);
          return { body: list ? { found: true, wire: list[list.length - 1] } : { found: false }, headers: HEADERS };
        }
        return { body: [], headers: HEADERS };
      }
      return { status: 404, body: { error: 'unknown_method' } };
    }) as Route,
  };
  await withServer(route, {}, async (d) => {
    const first = await d.call('saihm_remember', { content: 'one' });
    assert.equal(first.isError, false, first.text);
    assert.deepEqual([first.structured.timing?.serverMs, first.structured.timing?.admission], [11, 'shared']);
    const cellId = first.structured.cellId as string;
    const second = await d.call('saihm_remember', { content: 'two', cellId });
    assert.equal(second.isError, false, second.text);
    assert.equal(second.structured.sharesReissued, 1, 'setup: the write was followed by a re-issue call');
    assert.deepEqual(
      [second.structured.timing?.serverMs, second.structured.timing?.admission],
      [11, 'shared'],
      'the write reports the timing of the saihm_remember answer, not of the saihm_share call that followed it',
    );
    const branches: [string, Record<string, unknown>, boolean | undefined][] = [
      ['own read, found', { cellId }, true],
      ['own read, not found', { cellId: 'nope' }, false],
      ['version listing', { listOnly: true }, undefined],
      [
        'shared read, not found',
        { sharerPinnedAgentIdHashHex: toHex(SHARER.agentIdHash), sharerRecord: encodeIdentityRecord(SHARER.identityRecord), cellId: 'x' },
        undefined,
      ],
      ['full recall', {}, undefined],
    ];
    for (const [label, args, found] of branches) {
      const r = await d.call('saihm_recall', args);
      assert.equal(r.isError, false, `${label}: ${r.text}`);
      assert.deepEqual([r.structured.timing?.serverMs, r.structured.timing?.admission], [11, 'shared'], label);
      // found is true/false ONLY on the own-read-by-id branch; every other branch answers without it.
      assert.equal('found' in r.structured, found !== undefined, label);
      assert.equal(r.structured.found, found, label);
    }
    // And the marker: a malformed header is named in the text of every branch, and withheld from its structure.
    HEADERS['saihm-admission'] = 'later';
    for (const [label, args] of branches) {
      const r = await d.call('saihm_recall', args);
      assert.equal(r.isError, false, `${label}: ${r.text}`);
      assert.equal('timing' in r.structured, false, label);
      assert.ok(r.text.endsWith(`\n  timing=${MARK}`), `${label}:\n${r.text}`);
    }
    const bad = await d.call('saihm_remember', { content: 'three' });
    assert.equal(bad.isError, false, bad.text);
    assert.equal('timing' in bad.structured, false);
    assert.ok(bad.text.endsWith(`\n  timing=${MARK}`), bad.text);
  });
});

test('saihm_forget: reason, at and destructionAnchor are resolved once, and the result states what the erasure line states', async () => {
  const route = { current: ((): Answer => ({ body: {} })) as Route };
  await withServer(route, {}, async (d, home) => {
    const forget = (await d.list()).find((t) => t.name === 'saihm_forget');
    assert.ok(forget.outputSchema.properties.reason, 'reason is declared on the published schema');
    assert.ok(forget.outputSchema.properties.timing, 'timing is declared on the published schema');
    assert.ok(forget.outputSchema.properties.error, 'error is declared on the published schema');
    const HEADERS = { 'server-timing': 'saihm;dur=22', 'saihm-admission': 'reserved' };
    const ANCHOR = 'anchor-opaque-1';
    const T = '2026-10-04T00:00:00.000Z';
    const base = { sharesPurged: 0, epoch: '9' };
    const cases: [string, Record<string, unknown>, Record<string, unknown>][] = [
      ['durable, with an anchor', { complete: true, destructionAnchor: ANCHOR, sharesPurged: 2, epoch: '9', at: T }, { complete: true, destructionAnchor: ANCHOR, sharesPurged: 2, epoch: '9', at: T }],
      ['not-found, and a zoned time in another form is re-serialised', { ...base, complete: false, reason: 'not-found', at: '2026-10-04T02:00:00+02:00' }, { ...base, complete: false, reason: 'not-found', at: T }],
      ['not-attested: the store could not persist the deletion durably', { ...base, complete: false, reason: 'not-attested' }, { ...base, complete: false, reason: 'not-attested', at: null }],
      ['an older server: no reason, no at, no anchor', { ...base, complete: false }, { ...base, complete: false, at: null }],
      ['a reason outside the closed set is no reason', { ...base, complete: false, reason: 'because' }, { ...base, complete: false, at: null }],
      ['a reason beside complete:true is no reason', { ...base, complete: true, destructionAnchor: ANCHOR, reason: 'not-found', at: T }, { ...base, complete: true, destructionAnchor: ANCHOR, at: T }],
      // Written as complete:false for want of an anchor, but the endpoint did not say false: it gave no reason for one.
      ['a reason beside complete:true without an anchor is no reason either', { ...base, complete: true, reason: 'not-attested', at: T }, { ...base, complete: false, at: T }],
      ['a reason near an agreed one is no reason: never mapped onto it', { ...base, complete: false, reason: 'Not-Found' }, { ...base, complete: false, at: null }],
      ['a reason that is not a string is no reason', { ...base, complete: false, reason: ['not-found'] }, { ...base, complete: false, at: null }],
      ['an at that is not a time is no time', { ...base, complete: false, at: 'yesterday, honest' }, { ...base, complete: false, at: null }],
      ['an at of 5,000 characters is no time', { ...base, complete: false, at: 'Z'.repeat(5_000) }, { ...base, complete: false, at: null }],
      ['an anchor off the agreed shape is no anchor, and complete without one is not attested', { ...base, complete: true, destructionAnchor: 'has spaces / and a slash', at: T }, { ...base, complete: false, at: T }],
      ['complete:true with no anchor (own-cell events off: a post-condition) is not attested', { ...base, complete: true, at: T }, { ...base, complete: false, at: T }],
      ['complete as a string is malformed in every channel', { ...base, complete: 'true', at: T }, { ...base, complete: null, at: T }],
      ['an anchor beside complete:false is no anchor', { ...base, complete: false, destructionAnchor: ANCHOR, at: T }, { ...base, complete: false, at: T }],
      [
        // MEASURED regression: before boolOrNull/countOrNull existed, this exact shape made the WHOLE result fail output
        // validation (server_render_hostile.test.ts sends every forget field as one adversarial string), discarding the
        // fenced text along with every other field.
        'hostile types: complete/sharesPurged/at wrong type, epoch/destructionAnchor over-length, never guessed',
        { complete: 'YES', sharesPurged: 'lots', epoch: 'e'.repeat(300), at: 12345, destructionAnchor: 'a'.repeat(300) },
        { complete: null, sharesPurged: null, epoch: MARK, at: null },
      ],
    ];
    const feedLines = (): string[] => {
      const tenants = join(home, 'tenants');
      try {
        const [tenant] = readdirSync(tenants);
        return readFileSync(join(tenants, tenant as string, 'erasures.ndjson'), 'utf8').split('\n').filter(Boolean);
      } catch {
        return []; // no forget has written yet
      }
    };
    const lastLine = (): Record<string, unknown> => {
      const lines = feedLines();
      return JSON.parse(lines[lines.length - 1] as string);
    };
    for (const [label, body, want] of cases) {
      route.current = () => ({ body: { cellId: 'c1', shardId: 'sh1', steps: [], ...body }, headers: HEADERS });
      const before = feedLines().length;
      const r = await d.call('saihm_forget', { id: 'c1' });
      // Every forget writes its line, a `not-found` one included; the line read below is this forget's, not the last's.
      assert.equal(feedLines().length, before + 1, `${label}: one line per forget`);
      assert.equal(r.isError, false, `${label}: ${r.text}`);
      const { timing, ...rest } = r.structured;
      assert.deepEqual(rest, want, label);
      assert.deepEqual([timing?.serverMs, timing?.admission], [22, 'reserved'], `${label}: timing`);
      assert.equal(typeof timing?.totalMs, 'number', label);
      // The agent's channel names the reason too, as fixed text; nothing else says reason=.
      const named = r.text.split('\n').filter((l: string) => l.includes('reason='));
      assert.deepEqual(named.length, want.reason === undefined ? 0 : 1, `${label}: the reason line\n${r.text}`);
      if (want.reason !== undefined) assert.ok(named[0].includes(`reason=${want.reason as string} (`), `${label}: ${named[0]}`);
      // ONE resolution: the erasure line written for this receipt carries exactly the anchor and the reason the result
      // does (a `not-found` forget included: it is still recorded), and the same `complete` wherever the endpoint stated
      // a boolean - in the structure and in the text.
      const line = lastLine();
      assert.equal(line.cellId, 'c1', label);
      assert.deepEqual(
        [line.complete, line.destructionAnchor, line.reason, 'reason' in line],
        [want.destructionAnchor !== undefined, want.destructionAnchor, want.reason, want.reason !== undefined],
        `${label}: the line agrees`,
      );
      if (want.reason !== undefined)
        assert.deepEqual(Object.keys(line), ['v', 'cellId', 'agentIdHash', 'at', 'complete', 'reason', 'source'], `${label}: the line's keys`);
      if (typeof want.complete === 'boolean') {
        assert.equal(want.complete, line.complete, `${label}: the result's complete is the line's`);
        assert.ok(r.text.startsWith(`FORGOTTEN [c1] complete=${String(want.complete)} `), `${label}: the text agrees: ${r.text}`);
      } else {
        assert.ok(r.text.startsWith(`FORGOTTEN [c1] complete=${MARK} `), `${label}: a malformed complete is the marker in the text too: ${r.text}`);
      }
      assert.ok(r.text.includes(` sharesPurged=${want.sharesPurged === null ? MARK : String(want.sharesPurged)} `), `${label}: sharesPurged, one value in both channels: ${r.text}`);
      // complete=false with no reason says, in fixed text, that no destruction was attested (not that the erasure failed).
      assert.equal(r.text.includes('no key destruction is attested'), want.complete === false && want.reason === undefined, `${label}: the attestation note`);
    }
  });
});

test('servedBy and asOf: passed on every recall branch whose answer is an object; servedBy that is not a name is the marker; asOf that is not a time is left out', async () => {
  let said: Record<string, unknown> = {};
  const cell = encodeEnvelope(
    sealCell({
      plaintext: utf8('mine'),
      kek: ME.kek,
      mldsaSecretKey: ME.mldsaSecretKey,
      mldsaPubKey: ME.mldsaPubKey,
      agentIdHash: ME.agentIdHash,
      cellId: 'c1',
      seq: 1n,
      tier: 'PRO',
    }),
  );
  const route = {
    current: ((method: string, params: Record<string, unknown>): Answer => {
      if (method !== 'saihm_recall') return { status: 404, body: { error: 'unknown_method' } };
      if (params.listOnly === true) return { body: { mode: 'list', cells: [], next: null, ...said } };
      if (typeof params.sharer === 'string') return { body: { found: false, ...said } };
      if (params.cellId === 'c1') return { body: { found: true, wire: cell, ...said } };
      if (typeof params.cellId === 'string') return { body: { found: false, ...said } };
      // The full recall without a cache is a JSON array: it carries neither field, whatever the endpoint meant.
      return { body: [] };
    }) as Route,
  };
  await withServer(route, {}, async (d) => {
    const recall = (await d.list()).find((t) => t.name === 'saihm_recall');
    for (const k of ['servedBy', 'asOf', 'sharedKept', 'timing']) assert.ok(recall.outputSchema.properties[k], `${k} is declared`);
    const branches: [string, Record<string, unknown>][] = [
      ['own read, found', { cellId: 'c1' }],
      ['own read, not found', { cellId: 'gone' }],
      ['version listing', { listOnly: true }],
      [
        'shared read, not found',
        { sharerPinnedAgentIdHashHex: toHex(SHARER.agentIdHash), sharerRecord: encodeIdentityRecord(SHARER.identityRecord), cellId: 'x' },
      ],
    ];
    const cases: [string, Record<string, unknown>, unknown, unknown][] = [
      ['absent', {}, undefined, undefined],
      ['the origin, a UTC time', { servedBy: 'origin', asOf: '2026-10-04T01:02:03.456Z' }, 'origin', '2026-10-04T01:02:03.456Z'],
      ['a region, a zoned time', { servedBy: 'eu-west.1:a_b', asOf: '2026-10-04T01:02:03+02:00' }, 'eu-west.1:a_b', '2026-10-03T23:02:03.000Z'],
      ['a 64-character region', { servedBy: 'r'.repeat(64) }, 'r'.repeat(64), undefined],
      ['a 65-character region', { servedBy: 'r'.repeat(65) }, MARK, undefined],
      ['a region with a space', { servedBy: 'eu west' }, MARK, undefined],
      ['an empty region', { servedBy: '' }, MARK, undefined],
      ['a number', { servedBy: 7 }, MARK, undefined],
      ['null (never read as absent)', { servedBy: null }, MARK, undefined],
      ['a time that is not one', { servedBy: 'origin', asOf: 'yesterday' }, 'origin', undefined],
      ['a time without a zone', { asOf: '2026-10-04T01:02:03' }, undefined, undefined],
      ['a time that is a number', { asOf: 1_759_539_723_456 }, undefined, undefined],
    ];
    for (const [label, sent, servedBy, asOf] of cases) {
      said = sent;
      for (const [branch, args] of branches) {
        const r = await d.call('saihm_recall', args);
        assert.equal(r.isError, false, `${label} / ${branch}: ${r.text}`);
        assert.equal(r.structured.servedBy, servedBy, `${label} / ${branch}: servedBy`);
        assert.equal('servedBy' in r.structured, servedBy !== undefined, `${label} / ${branch}: absent stays absent`);
        assert.equal(r.structured.asOf, asOf, `${label} / ${branch}: asOf`);
        assert.equal(r.text.includes('eu-west') || r.text.includes('origin'), false, `${label} / ${branch}: structured output only`);
      }
    }
    said = { servedBy: 'origin', asOf: '2026-10-04T01:02:03.456Z' };
    const full = await d.call('saihm_recall', {});
    assert.equal(full.isError, false, full.text);
    assert.equal('servedBy' in full.structured || 'asOf' in full.structured, false, 'an array answer states neither');
  });
});

/** A share announcement row of `chars` summed field characters (sharer + cellId + scope + expiry), each field <= 64. */
const announcement = (id: number, chars: number): Record<string, unknown> => {
  const sharer = 'ab'.repeat(32);
  const cellId = `c${id}`.padEnd(64, 'c');
  const expiryEpoch = '9'.repeat(64);
  return { shared: true, sharer, cellId, scope: 'r'.repeat(chars - 192), expiryEpoch };
};

test('sharedKept names the end a cut shared list kept, only when the answer declared its order; a cap keeps one end', async () => {
  // 131 rows of 250 characters leave 18 of the 32,768-character budget; the 132nd (250) is cut. The 133rd is small
  // enough to fit what is left, and must NOT be kept: once cut, the list keeps the front of the endpoint's order.
  const big = Array.from({ length: 132 }, (_, i) => announcement(i, 250));
  const small = { shared: true, sharer: 'a', cellId: 'small', scope: 'read', expiryEpoch: null };
  const rows = [...big, small];
  let order: unknown;
  let added: unknown[] = rows;
  let array = false;
  const route = {
    current: ((method: string): Answer => {
      if (method !== 'saihm_recall') return { status: 404, body: { error: 'unknown_method' } };
      if (array) return { body: added };
      return {
        body: {
          mode: 'delta',
          added,
          liveCellIds: [],
          servedBy: 'eu-west-1',
          asOf: '2026-10-04T05:06:07.890Z',
          ...(order === undefined ? {} : { sharedOrder: order }),
        },
      };
    }) as Route,
  };
  const home = mkdtempSync(join(tmpdir(), 'saihm-pass-cache-'));
  try {
    await withServer(route, { SAIHM_RECALL_CACHE_PATH: join(home, 'recall-cache.json') }, async (d) => {
      const cases: [string, unknown, string | undefined, string][] = [
        ['newest-first', 'newest-first', 'newest', '; this list keeps the newest)'],
        ['grant order', 'grant-order', 'oldest', '; this list keeps the oldest)'],
        ['no order declared', undefined, undefined, '(LIST TRUNCATED: the endpoint announced more)'],
        ['an order this client does not know', 'oldest-first', undefined, '(LIST TRUNCATED: the endpoint announced more)'],
        ['an order that is not a string', 1, undefined, '(LIST TRUNCATED: the endpoint announced more)'],
      ];
      for (const [label, sent, kept, banner] of cases) {
        order = sent;
        const r = await d.call('saihm_recall', {});
        assert.equal(r.isError, false, `${label}: ${r.text}`);
        assert.equal(r.structured.sharedTruncated, true, `${label}: setup, the list was cut`);
        assert.equal(r.structured.shared.length, 131, `${label}: the cut keeps the front, and nothing after it`);
        assert.equal(r.structured.shared.some((a: { cellId: string }) => a.cellId === 'small'), false, `${label}: no row after the cut`);
        assert.equal(r.structured.sharedKept, kept, label);
        assert.deepEqual([r.structured.servedBy, r.structured.asOf], ['eu-west-1', '2026-10-04T05:06:07.890Z'], `${label}: a delta answer is an object`);
        assert.equal('sharedKept' in r.structured, kept !== undefined, `${label}: never guessed`);
        assert.ok(r.text.includes(banner), `${label}: the banner:\n${r.text.split('\n')[1]}`);
      }
      // Not cut: nothing to name, whatever the order.
      order = 'newest-first';
      added = rows.slice(0, 3);
      const uncut = await d.call('saihm_recall', {});
      assert.equal(uncut.isError, false, uncut.text);
      assert.deepEqual([uncut.structured.sharedTruncated, uncut.structured.shared.length, 'sharedKept' in uncut.structured], [false, 3, false]);
      added = rows;
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
  // Without a cache the full recall is a JSON array, which cannot declare an order: cut, and no end named.
  array = true;
  await withServer(route, {}, async (d) => {
    const r = await d.call('saihm_recall', {});
    assert.equal(r.isError, false, r.text);
    assert.deepEqual([r.structured.sharedTruncated, r.structured.shared.length, 'sharedKept' in r.structured], [true, 131, false]);
  });
});

test('sharedKept is withheld when a row the client cannot carry was skipped before the cut, and only then', async () => {
  // An end can be named only when the kept list IS one end of the endpoint's order. A row skipped before the cut leaves
  // a hole no end describes: a field over 64 characters (a sharer's cell id may be longer) or of the wrong type.
  const big = Array.from({ length: 132 }, (_, i) => announcement(i, 250)); // 131 fit; the 132nd is cut, as above
  const long = { shared: true, sharer: 'ab'.repeat(32), cellId: 'L'.repeat(65), scope: 'read', expiryEpoch: null };
  const typed = { shared: true, sharer: 'ab'.repeat(32), cellId: 7, scope: 'read', expiryEpoch: null };
  const wired = { shared: true, sharer: 'ab'.repeat(32), cellId: 'w', scope: 'read', expiryEpoch: null, wire: null };
  let added: unknown[] = [];
  const route = {
    current: ((method: string): Answer =>
      method !== 'saihm_recall'
        ? { status: 404, body: { error: 'unknown_method' } }
        : { body: { mode: 'delta', added, liveCellIds: [], sharedOrder: 'newest-first' } }) as Route,
  };
  const home = mkdtempSync(join(tmpdir(), 'saihm-pass-cache-'));
  try {
    await withServer(route, { SAIHM_RECALL_CACHE_PATH: join(home, 'recall-cache.json') }, async (d) => {
      const cases: [string, unknown[], string | undefined][] = [
        ['an over-long cell id before the cut', [...big.slice(0, 5), long, ...big.slice(5)], undefined],
        ['a field of the wrong type before the cut', [...big.slice(0, 5), typed, ...big.slice(5)], undefined],
        ['a shared row carrying a wire before the cut (neither pointer nor own cell)', [...big.slice(0, 5), wired, ...big.slice(5)], undefined],
        ['the same rows after the cut are part of the end it dropped', [...big, long, typed, wired], 'newest'],
        ['a repeat of a kept pointer before the cut withholds nothing', [...big.slice(0, 5), big[2], ...big.slice(5)], 'newest'],
      ];
      for (const [label, rows, kept] of cases) {
        added = rows;
        const r = await d.call('saihm_recall', {});
        assert.equal(r.isError, false, `${label}: ${r.text}`);
        assert.deepEqual([r.structured.sharedTruncated, r.structured.shared.length], [true, 131], `${label}: setup, the list was cut`);
        assert.equal(r.structured.sharedKept, kept, label);
        assert.equal('sharedKept' in r.structured, kept !== undefined, `${label}: never guessed`);
        assert.equal(r.text.includes('this list keeps the newest'), kept === 'newest', `${label}: the banner`);
      }
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a listing page whose next is blank is refused by name: a blank after would start the listing over for ever', async () => {
  const C = 'ab'.repeat(32);
  let next: string | null = ' ';
  const route = {
    current: ((method: string): Answer =>
      method === 'saihm_recall'
        ? { body: { mode: 'list', cells: [{ cellId: ' ', seq: '1', commitment: C }], next } }
        : { status: 404, body: { error: 'unknown_method' } }) as Route,
  };
  await withServer(route, {}, async (d) => {
    const r = await d.call('saihm_recall', { listOnly: true });
    assert.equal(r.isError, true, r.text);
    assert.match(r.text, /cannot be continued through this tool/);
    // A next the text cannot show exactly (over the scalar budget, or holding a character a fence changes) is not shown
    // at all: the model pages from what it reads, and a changed id would skip or repeat cells.
    for (const odd of ['n'.repeat(65), 'a=b', 'x|y']) {
      next = odd;
      const r2 = await d.call('saihm_recall', { listOnly: true });
      assert.equal(r2.isError, false, r2.text);
      assert.equal(r2.structured.next, odd, 'the structured next is exact');
      assert.match(r2.text, /NEXT: this id cannot be shown exactly here/, odd);
      assert.equal(r2.text.includes('NEXT after='), false, odd);
    }
    next = 'note-b';
    const plain = await d.call('saihm_recall', { listOnly: true });
    assert.match(plain.text, /! NEXT after=note-b$/m, 'an id shown exactly is shown');
    // Positive control: the same page as the last one (next null) lists its blank-named cell like any other.
    next = null;
    const last = await d.call('saihm_recall', { listOnly: true });
    assert.equal(last.isError, false, last.text);
    assert.match(last.text, /^LIST 1 cell version\(s\), no content — the last page: no more follow$/m, 'the last page says so, and only that');
    assert.deepEqual(last.structured.cells, [{ cellId: ' ', seq: '1', commitment: C }]);
  });
});

test('an own read by id: found:false is "no such cell"; an answer with no envelope otherwise is malformed, never "not found"', async () => {
  let body: unknown = { found: false };
  const route = { current: ((method: string): Answer => (method === 'saihm_recall' ? { body } : { status: 404, body: { error: 'unknown_method' } })) as Route };
  await withServer(route, {}, async (d) => {
    const missing = await d.call('saihm_recall', { cellId: 'gone' });
    assert.equal(missing.isError, false, missing.text);
    assert.equal(missing.structured.found, false);
    for (const [label, sent] of [['an empty object', {}], ['found:true with no envelope', { found: true }], ['found as a string', { found: 'false' }]] as const) {
      body = sent;
      const r = await d.call('saihm_recall', { cellId: 'x' });
      assert.equal(r.isError, true, `${label}: ${r.text}`);
      assert.match(r.text, /^SAIHM error \[malformed_response\] \(status 502\)/, label);
      assert.deepEqual(r.structured, { error: { code: 'malformed_response', status: 502 } }, label);
    }
  });
});

test('unit: the Server-Timing reader and the features bounds, at their edges', () => {
  assert.equal(saihmServerMs('saihm;dur=0'), 0, 'a zero duration is a duration');
  assert.equal(saihmServerMs('saihm;DUR=5'), 5, 'parameter names are case-insensitive');
  assert.equal(saihmServerMs(' saihm ; dur = 5 '), 5, 'optional white space');
  assert.equal(saihmServerMs('saihm;dur=123456789.123456'), 123456789.123456);
  assert.equal(saihmServerMs('saihm;dur=1234567890'), 'malformed', 'ten integer digits');
  // Any number of decimals, as Server-Timing allows: an unrounded measurement is a measurement, not a malformed one.
  assert.equal(saihmServerMs('saihm;dur=1.1234567'), 1.1234567, 'seven decimals');
  assert.equal(saihmServerMs('saihm;dur=12.345678901234'), 12.345678901234, 'twelve decimals');
  assert.equal(saihmServerMs('saihm;dur=12.'), 'malformed', 'a point with no decimals');
  assert.equal(saihmServerMs('other;dur=5'), null);
  assert.equal(saihmServerMs('cdn;desc="saihm;dur=5"'), null, 'a quoted metric is not a metric');
  assert.equal(saihmServerMs('cdn;desc="a\\"b", saihm;dur=6'), 6, 'an escaped quote stays inside the string');
  assert.equal(saihmServerMs('saihm;dur=""'), 'malformed');
  assert.equal(endpointTiming(undefined, 5), undefined);
  assert.equal(endpointTiming({ serverTiming: undefined, admission: undefined }, 5), undefined);
  assert.deepEqual(endpointTiming({ serverTiming: undefined, admission: ' reserved ' }, 1.23456789), { serverMs: null, totalMs: 1.235, admission: 'reserved' });
  assert.equal(endpointTiming({ serverTiming: 'saihm;dur=1', admission: 'Reserved' }, 1), 'malformed', 'the closed set is exact');
  assert.deepEqual(featuresOf(undefined), { features: null, malformed: false });
  assert.deepEqual(featuresOf([]), { features: null, malformed: true });
  assert.deepEqual(featuresOf(nest(16)), { features: nest(16), malformed: false });
  assert.deepEqual(featuresOf(nest(17)), { features: null, malformed: true });
  assert.deepEqual(featuresOf({ a: [[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]] }), { features: null, malformed: true }, 'arrays nest too');
  // COUNTED before it is serialised: a value holding more values than its JSON could at the size bound is refused at
  // once. The probe makes "serialised first" observable: its toJSON would shrink it to nothing and pass the size check.
  let serialised = false;
  const huge = { many: Array.from({ length: 20_000 }, () => 0), toJSON: () => { serialised = true; return {}; } };
  assert.deepEqual(featuresOf(huge), { features: null, malformed: true });
  assert.equal(serialised, false, 'refused on its count, never serialised');
  const within = Array.from({ length: 4_000 }, () => 0);
  assert.deepEqual(featuresOf({ many: within }), { features: { many: within }, malformed: false }, 'a count under the bound passes');
  // Never a throw: a value JSON cannot serialise (not one JSON.parse makes, but the function is exported) is refused.
  assert.deepEqual(featuresOf({ n: 10n }), { features: null, malformed: true }, 'refused, not thrown');
});
