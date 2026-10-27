// saihm_recall's paged share listing through the real stdio server: one page of every pointer shared with you, never
// cut, with `next`, `sharedSkipped`, `total` and `asOf`, and no `sharedTruncated` or `sharedKept`; the fenced NEXT line;
// `shares_paging_unsupported` where the endpoint does not page; the rules for `after` and for travelling alone; and the
// one fixed hint on a cut default recall. Every result is checked against the tool's PUBLISHED output schema.
//
// Runner: npx tsx --test tests/server_recall_shares_paged.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/ajv';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const MASTER_HEX = '7c'.repeat(32);
const AUTH = 'Bearer paged-test';
const S1 = '11'.repeat(32), S2 = '22'.repeat(32);
const STATUS = { agentIdHashHex: '00'.repeat(32), tier: 'PRO', activeShardCount: 0, activeSharingContracts: 0, bfsi: 1, bfsi_R: '0', bfsi_M: '0', snapshotEpoch: '1', custody: 'non-custodial' };

interface Row { shared: true; sharer: string; cellId: string; scope: string; expiryEpoch: string | null }
const row = (sharer: string, cellId: string, extra: Partial<Row> = {}): Row => ({ shared: true, sharer, cellId, scope: 'read', expiryEpoch: null, ...extra });
const enc = (r: Row): string => 's1.' + Buffer.from(JSON.stringify([r.sharer, r.cellId])).toString('base64url');
const before = (a: Row, b: Row): boolean => a.sharer < b.sharer || (a.sharer === b.sharer && a.cellId < b.cellId);

interface Mock {
  rows: Row[];
  offer: unknown;
  paging: boolean;
  /** What the default recall answers (the full recall without a cache: a list). */
  recallAll: unknown[];
  hook: ((params: Record<string, unknown>) => { status: number; body: unknown } | undefined) | undefined;
  recalls: Array<Record<string, unknown>>;
  /** How many status reads the endpoint answered. */
  statuses: number;
  server: Server;
  url: string;
}

async function startMock(): Promise<Mock> {
  const m = { rows: [], offer: { v: [1], max: 1000 }, paging: true, recallAll: [], hook: undefined, recalls: [], statuses: 0 } as unknown as Mock;
  m.server = createServer((req, res) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => {
      const send = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
      if (req.method !== 'POST' || req.url !== '/mcp') return send(404, { error: 'not_found' });
      const { method, params = {} } = JSON.parse(buf) as { method: string; params?: Record<string, unknown> };
      if (method === 'saihm_status') {
        m.statuses++;
        return send(200, { ...STATUS, ...(m.offer === undefined ? {} : { features: { sharesPaged: m.offer } }) });
      }
      if (method !== 'saihm_recall') return send(400, { error: 'not_in_this_test' });
      m.recalls.push(params);
      const hooked = m.hook?.(params);
      if (hooked !== undefined) return send(hooked.status, hooked.body);
      const all = [...m.rows].sort((a, b) => (before(a, b) ? -1 : before(b, a) ? 1 : 0));
      if (params.paged === true) {
        if (!m.paging) return send(200, { mode: 'shares', added: all, liveSharedKeys: all.map((r) => `${r.sharer}:${r.cellId}`) });
        let from = 0;
        if (typeof params.after === 'string') {
          const [sharer, cellId] = JSON.parse(Buffer.from(params.after.slice(3), 'base64url').toString('utf8')) as [string, string];
          from = all.findIndex((r) => before({ ...r, sharer, cellId }, r));
          if (from < 0) from = all.length;
        }
        const max = params.max as number;
        const page = all.slice(from, from + max);
        const more = from + max < all.length;
        return send(200, { mode: 'shares', added: page, next: more ? enc(page[page.length - 1]!) : null, asOf: '2026-10-09T08:00:00.000Z', total: all.length, servedBy: 'origin' });
      }
      return send(200, m.recallAll);
    });
  });
  await new Promise<void>((r) => m.server.listen(0, '127.0.0.1', () => r()));
  m.url = `http://127.0.0.1:${(m.server.address() as AddressInfo).port}/mcp`;
  return m;
}

interface Result { text: string; isError: boolean; structured: Record<string, any> }
async function startServer(endpoint: string, home: string) {
  const proc: ChildProcess = spawn(TSX, [SERVER], {
    env: {
      ...process.env, SAIHM_IDENTITY: undefined, SAIHM_IDENTITY_PASSPHRASE: undefined, SAIHM_MASTER_SECRET_FILE: undefined, SAIHM_STATE_DIR: undefined,
      SAIHM_ERASURE_FEED_DIR: undefined, SAIHM_EVENTS: undefined, SAIHM_RECALL_CACHE: undefined, SAIHM_RECALL_CACHE_PATH: undefined,
      SAIHM_ENDPOINT_URL: endpoint, SAIHM_AUTH_HEADER: AUTH, SAIHM_MASTER_SECRET_HEX: MASTER_HEX, SAIHM_HOME: home, HOME: home,
      SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe', SAIHM_SELF_JOIN: '0',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: home,
  });
  let buf = '', stderr = '', next = 1;
  const waiters = new Map<number, (m: any) => void>();
  proc.stderr!.on('data', (d) => (stderr += d));
  proc.stdout!.on('data', (d) => {
    buf += d;
    let nl: number;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let msg: any;
      try { msg = JSON.parse(line); } catch { continue; }
      if (msg.id != null && waiters.has(msg.id)) { waiters.get(msg.id)!(msg); waiters.delete(msg.id); }
    }
  });
  const rpc = (method: string, params: unknown): Promise<any> => {
    const id = next++;
    return new Promise((res, rej) => {
      waiters.set(id, res);
      proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      setTimeout(() => { if (waiters.delete(id)) rej(new Error(`rpc timeout ${method}; stderr=${stderr}`)); }, 60_000).unref();
    });
  };
  await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const tools = (await rpc('tools/list', {})).result.tools as any[];
  const validator = new AjvJsonSchemaValidator();
  const checks = new Map(tools.filter((t) => t.outputSchema).map((t) => [t.name as string, validator.getValidator(t.outputSchema)]));
  const call = async (name: string, args: unknown): Promise<Result> => {
    const msg = await rpc('tools/call', { name, arguments: args });
    assert.ok(msg.result, `tools/call ${name} answered no result: ${JSON.stringify(msg.error)}`);
    const structured = msg.result.structuredContent;
    if (structured !== undefined) {
      const v = checks.get(name)!(structured);
      assert.ok(v.valid, `${name}: the result does not match its published output schema: ${v.errorMessage}\n${JSON.stringify(structured)}`);
    }
    return { text: String(msg.result.content?.[0]?.text ?? ''), isError: msg.result.isError === true, structured: (structured ?? {}) as Record<string, any> };
  };
  return { proc, tools, call };
}

async function withRig(body: (d: Awaited<ReturnType<typeof startServer>>, m: Mock) => Promise<void>): Promise<void> {
  const home = mkdtempSync(join(tmpdir(), 'saihm-paged-srv-'));
  const m = await startMock();
  const d = await startServer(m.url, home);
  try {
    await body(d, m);
  } finally {
    d.proc.kill();
    m.server.closeAllConnections();
    await new Promise<void>((r) => m.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
}

test('the tool declares the mode: sharesOnly in, sharedSkipped and total out; still eight protocol tools', async () => {
  await withRig(async (d) => {
    const recall = d.tools.find((t) => t.name === 'saihm_recall');
    assert.ok(recall.inputSchema.properties.sharesOnly, 'sharesOnly is an input');
    for (const k of ['shared', 'next', 'sharedSkipped', 'total', 'asOf']) assert.ok(recall.outputSchema.properties[k], `${k} is declared`);
    assert.equal(d.tools.length, 8);
  });
});

test('a page: shared, next, sharedSkipped, total, asOf; sharedTruncated and sharedKept ABSENT; the NEXT fence; then the last page', async () => {
  await withRig(async (d, m) => {
    m.rows = Array.from({ length: 25 }, (_, i) => row(i < 20 ? S1 : S2, `cell-${String(i).padStart(2, '0')}`));
    m.offer = { v: [1], max: 20 };
    const first = await d.call('saihm_recall', { sharesOnly: true });
    assert.equal(first.isError, false, first.text);
    assert.deepEqual(m.recalls.at(-1), { sharesOnly: true, paged: true, max: 20 }, 'the tool asks 128, never more than offered');
    const s = first.structured;
    assert.deepEqual([s.count, s.memories, s.shared.length, s.sharedSkipped, s.total, s.asOf, s.servedBy], [0, [], 20, 0, 25, '2026-10-09T08:00:00.000Z', 'origin']);
    assert.equal('sharedTruncated' in s, false, 'a page never says the list is complete: sharedTruncated is absent, never false');
    assert.equal('sharedKept' in s, false);
    assert.deepEqual(s.shared[0], { sharer: S1, cellId: 'cell-00', scope: 'read', expiryEpoch: null, verified: false });
    assert.equal(typeof s.next, 'string');
    assert.ok(s.next.length > 64, 'a cursor longer than a scalar budget...');
    const lines = first.text.split('\n');
    assert.match(lines[0]!, /^SHARED WITH YOU, ONE PAGE: 20 unverified pointer\(s\) — no content, nothing below is authenticated; more pages follow$/);
    assert.equal(lines.filter((l) => l.startsWith('  ! POINTER ')).length, 16);
    assert.ok(lines.includes('  ! …and 4 more withheld from this list.'));
    // The two footer lines (0.14.3): a read takes the sharer's agent ID as the user gave it, and the cellId; no record.
    assert.match(first.text, /^ {2}! To read one, pass sharerPinnedAgentIdHashHex \+ cellId, with the sharer's agent ID as your user\n {2}! gave it, not as listed here\. Until then these are claims, not memories\.$/m);
    assert.equal(lines.at(-1), `  ! NEXT after=${s.next}`, '...is shown exactly, on the fenced NEXT line');
    assert.ok(lines.slice(1).every((l) => l.startsWith('  ! ')), 'every line but the banner is fenced as the endpoint\'s claim');
    const last = await d.call('saihm_recall', { sharesOnly: true, after: s.next });
    assert.deepEqual(m.recalls.at(-1), { sharesOnly: true, paged: true, after: s.next, max: 20 });
    assert.deepEqual([last.structured.shared.map((x: { cellId: string }) => x.cellId), last.structured.next], [['cell-20', 'cell-21', 'cell-22', 'cell-23', 'cell-24'], null]);
    assert.match(last.text.split('\n')[0]!, /the last page: no more follow$/);
    assert.equal(last.text.includes('NEXT'), false);
    assert.equal('sharedTruncated' in last.structured, false);
  });
});

test('rows with a field over 64 characters are skipped and counted; a cursor over 4,096 characters fails the page; 4,096 is shown whole', async () => {
  await withRig(async (d, m) => {
    m.rows = [row(S1, 'a'), row(S1, 'b'.repeat(65)), row(S1, 'c', { scope: 's'.repeat(65) }), row(S1, 'd', { expiryEpoch: '9'.repeat(65) }), row('AB'.repeat(32), 'e'), row(S2, 'f')];
    const r = await d.call('saihm_recall', { sharesOnly: true });
    assert.equal(r.isError, false, r.text);
    // Key order by code units: '1' and '2' sort before 'A', so the uppercase sharer's row comes last.
    assert.deepEqual([r.structured.shared.map((x: { cellId: string }) => x.cellId), r.structured.sharedSkipped], [['a', 'f', 'e'], 3]);
    assert.ok(r.text.includes('  ! 3 more skipped: a field longer than this client carries.'));
    assert.ok(r.text.includes('sharer=(malformed)'), 'an off-contract sharer within the cap is kept, rendered as malformed');
    m.hook = (params) => (params.paged === true ? { status: 200, body: { mode: 'shares', added: [row(S1, 'a')], next: 'n'.repeat(4_097) } } : undefined);
    const long = await d.call('saihm_recall', { sharesOnly: true });
    assert.deepEqual(long.structured, { error: { code: 'malformed_response', status: 502 } }, long.text);
    m.hook = (params) => (params.paged === true ? { status: 200, body: { mode: 'shares', added: [row(S1, 'a')], next: 'n'.repeat(4_096) } } : undefined);
    const whole = await d.call('saihm_recall', { sharesOnly: true });
    assert.equal(whole.isError, false, whole.text);
    assert.equal(whole.text.split('\n').at(-1), `  ! NEXT after=${'n'.repeat(4_096)}`);
  });
});

test('where the endpoint does not page: shares_paging_unsupported, and no page request without an offer', async () => {
  await withRig(async (d, m) => {
    m.rows = [row(S1, 'a')];
    const unsupported = { error: { code: 'shares_paging_unsupported', status: 501 } };
    // Offered, then switched off: the page request is answered with something that is not a page.
    m.paging = false;
    const off = await d.call('saihm_recall', { sharesOnly: true });
    assert.deepEqual(off.structured, unsupported, off.text);
    assert.deepEqual([m.recalls.length, m.statuses], [1, 1]);
    // No longer offered: the offer is read again, nothing is asked of the listing, and the word that there is no offer
    // is kept, so the next call reads no status either.
    m.offer = undefined;
    const r = await d.call('saihm_recall', { sharesOnly: true });
    assert.deepEqual(r.structured, unsupported, r.text);
    const again = await d.call('saihm_recall', { sharesOnly: true });
    assert.deepEqual(again.structured, unsupported, again.text);
    assert.deepEqual([m.recalls.length, m.statuses], [1, 2], 'nothing more asked of the listing, and the status read once for both');
  });
});

test('the rules: after only with listOnly or sharesOnly; sharesOnly travels alone; warm start takes token only', async () => {
  await withRig(async (d, m) => {
    m.rows = [row(S1, 'a')];
    const refused: [unknown, RegExp][] = [
      [{ after: 's1.x' }, /after pages a listing: pass it together with listOnly or sharesOnly/],
      [{ sharesOnly: false, after: 's1.x' }, /after pages a listing/],
      [{ sharesOnly: true, query: 'x' }, /A share listing takes sharesOnly and after only/],
      [{ sharesOnly: true, cellId: 'x' }, /A share listing takes sharesOnly and after only/],
      [{ sharesOnly: true, listOnly: true }, /A share listing takes sharesOnly and after only/],
      [{ sharesOnly: true, shareEntries: true }, /A share listing takes sharesOnly and after only/],
      [{ sharesOnly: true, sharerPinnedAgentIdHashHex: S1 }, /A share listing takes sharesOnly and after only/],
      [{ sharesOnly: true, warmStart: 'list', token: 'abcdefghijklmnop' }, /warmStart takes token only/],
    ];
    for (const [args, message] of refused) {
      const r = await d.call('saihm_recall', args);
      assert.equal(r.isError, true, JSON.stringify(args));
      assert.match(r.text, message, JSON.stringify(args));
    }
    assert.equal(m.recalls.length, 0, 'no refused call reached the endpoint');
    // Fields a host fills without choosing them: blanks and explicit false are absent.
    const filled = await d.call('saihm_recall', { sharesOnly: true, after: '', query: '', listOnly: false, shareEntries: false, cellId: null });
    assert.equal(filled.isError, false, filled.text);
    assert.deepEqual(m.recalls.at(-1), { sharesOnly: true, paged: true, max: 128 }, 'a blank after is the first page');
  });
});

test('the default recall: a cut list carries one fixed hint pointing at the paged mode; an uncut one does not', async () => {
  await withRig(async (d, m) => {
    m.recallAll = Array.from({ length: 300 }, (_, i) => row(S1, `c${i}`));
    const cut = await d.call('saihm_recall', {});
    assert.equal(cut.isError, false, cut.text);
    assert.equal(cut.structured.sharedTruncated, true);
    const banner = cut.text.split('\n').find((l) => l.startsWith('SHARED WITH YOU:'))!;
    assert.ok(banner.endsWith('(LIST TRUNCATED: the endpoint announced more) Where the endpoint offers it, saihm_recall with sharesOnly lists them all, a page at a time.'), banner);
    m.recallAll = [row(S1, 'a')];
    const whole = await d.call('saihm_recall', {});
    assert.equal(whole.structured.sharedTruncated, false);
    assert.equal(whole.text.includes('sharesOnly'), false);
  });
});
