// Warm start through the tools, against an endpoint that speaks the warm-start wire: the offer as saihm_status passes it
// on (with this client's token statement), a put from `put-<token>.bin`, a restore into `latest-<token>.bin`, the list
// and the delete; the gate on the offer, the input rules, the payload files' rules and the leftovers sweep; a restore
// that is all or nothing; and an upload that survives a limit. Every result is checked against the tool's PUBLISHED
// output schema with the MCP SDK's own validator, as a validating host checks it.
// Runner: npx tsx --test tests/server_warm_start.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/ajv';
import { deriveIdentity, fromHex, sealCell, toHex } from '@saihm/client-pro';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const MASTER_HEX = '6b'.repeat(32);
const ME = deriveIdentity(fromHex(MASTER_HEX));
const ID = toHex(ME.agentIdHash);
const AUTH = 'Bearer warm-start-test';
const AT = 'AbCdEf0123456789-_AbCdEf0123456789-_AbCdEf0123';
const token = (): string => randomBytes(12).toString('hex');
const OFFER = { v: [1], maxBytes: 65_536, maxSnapshots: 2, retentionS: 604_800 };
const STATUS = {
  agentIdHashHex: ID,
  tier: 'PRO',
  activeShardCount: 0,
  activeSharingContracts: 0,
  bfsi: 1,
  bfsi_R: '0',
  bfsi_M: '0',
  snapshotEpoch: '1',
  custody: 'non-custodial',
};

// ── the endpoint ───────────────────────────────────────────────────────────────────────────────────────────────────

interface Stored {
  snapshotId: string;
  createdAt: string;
  bytes: number;
  parts: Buffer[];
  digest: string;
  coversThrough: string;
  keyEnvelope: string;
  nonce: string;
}
interface Answer {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
}
interface Mock {
  server: Server;
  url: string;
  features: Record<string, unknown> | undefined;
  info: Record<string, unknown> | null;
  partBytes: number;
  snapshots: Stored[];
  /** Every request under /mcp/warm-start, in order. */
  requests: string[];
  /** Every request this endpoint received, the status and info reads included. */
  all: string[];
  begins: Record<string, unknown>[];
  /** Answer one warm-start request otherwise: an answer to send (status 0 drops the connection), or undefined to answer as the wire says. */
  hook: (route: string, count: number) => Answer | undefined;
  /** What a listing serves, from what is stored. */
  list: (s: Stored[]) => unknown;
  /** What a part read serves. */
  read: (s: Stored, n: number) => { bytes: Buffer; digest: string | null };
  /**
   * After the `count`th commit is stored: drop its connection (null), or send this answer in its place (an answer lost
   * or replaced on its way back), or undefined to answer as the wire says.
   */
  afterCommit: (count: number) => Answer | null | undefined;
}

const sha = (b: Uint8Array): Buffer => createHash('sha256').update(b).digest();
const digestHeader = (b: Uint8Array): string => `sha-256=:${sha(b).toString('base64')}:`;
const listed = (s: Stored): Record<string, unknown> => ({
  snapshotId: s.snapshotId,
  createdAt: s.createdAt,
  bytes: s.bytes,
  parts: s.parts.length,
  digest: s.digest,
  coversThrough: s.coversThrough,
  keyEnvelope: s.keyEnvelope,
  nonce: s.nonce,
});

async function startMock(): Promise<Mock> {
  const uploads = new Map<string, { begin: Record<string, any>; got: Map<number, Buffer> }>();
  const counts = new Map<string, number>();
  const m: Mock = {
    server: undefined as unknown as Server,
    url: '',
    features: { warmStart: OFFER },
    info: null,
    partBytes: 1024,
    snapshots: [],
    requests: [],
    all: [],
    begins: [],
    hook: () => undefined,
    list: (s) => ({ v: 1, snapshots: s.map(listed) }),
    read: (s, n) => ({ bytes: s.parts[n] as Buffer, digest: digestHeader(s.parts[n] as Buffer) }),
    afterCommit: () => undefined,
  };
  const send = (res: import('node:http').ServerResponse, a: Answer): void => {
    const raw = a.body === undefined ? '' : JSON.stringify(a.body);
    res.writeHead(a.status, { ...(a.body !== undefined ? { 'content-type': 'application/json' } : {}), ...(a.headers ?? {}) });
    res.end(raw);
  };
  const route = (req: IncomingMessage, body: Buffer, res: import('node:http').ServerResponse): void => {
    const path = (req.url ?? '').split('?')[0] as string;
    m.all.push(`${req.method} ${path}`);
    if (req.method === 'GET' && path === '/mcp/info') {
      if (m.info === null) return send(res, { status: 404, body: { error: 'not_found' } });
      return send(res, { status: 200, body: m.info });
    }
    if (req.method === 'POST' && path === '/mcp') {
      const j = JSON.parse(body.toString('utf8')) as { method?: string };
      if (j.method === 'saihm_status') return send(res, { status: 200, body: m.features === undefined ? STATUS : { ...STATUS, features: m.features } });
      return send(res, { status: 400, body: { error: 'not_in_this_test' } });
    }
    if (!path.startsWith('/mcp/warm-start')) return send(res, { status: 404, body: { error: 'not_found' } });
    const key = `${req.method} ${path.replace(/[0-9a-f]{64}/g, '<snap>').replace(/[0-9a-f]{32}/g, '<up>')}`;
    m.requests.push(key);
    const count = (counts.get(key) ?? 0) + 1;
    counts.set(key, count);
    if (req.headers.authorization !== AUTH) return send(res, { status: 401, body: { error: 'unauthorized' } });
    const hooked = m.hook(key, count);
    if (hooked !== undefined && hooked.status === 0) {
      req.socket.destroy();
      return;
    }
    if (hooked !== undefined) return send(res, hooked);
    let g: RegExpExecArray | null;
    if (req.method === 'POST' && path === '/mcp/warm-start') {
      const b = JSON.parse(body.toString('utf8')) as Record<string, any>;
      m.begins.push(b);
      if (b.v !== 1 || !Number.isInteger(b.bytes) || b.bytes < 1 || b.parts !== Math.ceil(b.bytes / m.partBytes))
        return send(res, { status: 400, body: { error: 'bad_request', reason: 'bytes, parts' } });
      if (!/^[0-9a-f]{64}$/.test(b.digest) || !/^[0-9a-f]{32}$/.test(b.nonce) || !/^[A-Za-z0-9_-]{1,4096}$/.test(b.keyEnvelope))
        return send(res, { status: 400, body: { error: 'bad_request', reason: 'fields' } });
      if (b.bytes > OFFER.maxBytes) return send(res, { status: 413, body: { error: 'snapshot_too_large' } });
      const uploadId = randomBytes(16).toString('hex');
      uploads.set(uploadId, { begin: b, got: new Map() });
      return send(res, { status: 201, body: { v: 1, uploadId, partBytes: m.partBytes, expiresAt: new Date(Date.now() + 3_600_000).toISOString() } });
    }
    if (req.method === 'PUT' && (g = /^\/mcp\/warm-start\/uploads\/([0-9a-f]{32})\/parts\/(0|[1-9][0-9]*)$/.exec(path))) {
      const up = uploads.get(g[1] as string);
      if (!up) return send(res, { status: 404, body: { error: 'upload_not_found' } });
      const n = Number(g[2]);
      const last = n === up.begin.parts - 1;
      const want = last ? up.begin.bytes - m.partBytes * (up.begin.parts - 1) : m.partBytes;
      if (n >= up.begin.parts || body.length !== want) return send(res, { status: 400, body: { error: 'bad_request', reason: 'part size' } });
      if (req.headers['content-digest'] !== digestHeader(body)) return send(res, { status: 400, body: { error: 'digest_mismatch' } });
      if (req.headers['content-type'] !== 'application/octet-stream') return send(res, { status: 400, body: { error: 'bad_request', reason: 'type' } });
      up.got.set(n, Buffer.from(body));
      return send(res, { status: 204 });
    }
    if (req.method === 'POST' && (g = /^\/mcp\/warm-start\/uploads\/([0-9a-f]{32})\/commit$/.exec(path))) {
      const up = uploads.get(g[1] as string);
      if (!up) return send(res, { status: 404, body: { error: 'upload_not_found' } });
      const parts: Buffer[] = [];
      for (let n = 0; n < up.begin.parts; n++) {
        const p = up.got.get(n);
        if (!p) return send(res, { status: 400, body: { error: 'bad_request', reason: `part ${n} missing` } });
        parts.push(p);
      }
      if (sha(Buffer.concat(parts)).toString('hex') !== up.begin.digest) return send(res, { status: 400, body: { error: 'digest_mismatch' } });
      uploads.delete(g[1] as string);
      const s: Stored = {
        snapshotId: randomBytes(32).toString('hex'),
        createdAt: new Date().toISOString(),
        bytes: up.begin.bytes,
        parts,
        digest: up.begin.digest,
        coversThrough: up.begin.coversThrough,
        keyEnvelope: up.begin.keyEnvelope,
        nonce: up.begin.nonce,
      };
      m.snapshots.unshift(s);
      const after = m.afterCommit(count);
      if (after === null) {
        req.socket.destroy();
        return;
      }
      if (after !== undefined) return send(res, after);
      return send(res, { status: 201, body: { v: 1, snapshotId: s.snapshotId, createdAt: s.createdAt, bytes: s.bytes, parts: parts.length, coversThrough: s.coversThrough } });
    }
    if (req.method === 'GET' && path === '/mcp/warm-start') return send(res, { status: 200, body: m.list(m.snapshots) });
    if (req.method === 'GET' && (g = /^\/mcp\/warm-start\/([0-9a-f]{64})\/parts\/(0|[1-9][0-9]*)$/.exec(path))) {
      const s = m.snapshots.find((x) => x.snapshotId === g![1]);
      if (!s || Number(g[2]) >= s.parts.length) return send(res, { status: 404, body: { error: 'snapshot_not_found' } });
      const { bytes, digest } = m.read(s, Number(g[2]));
      res.writeHead(200, { 'content-type': 'application/octet-stream', ...(digest !== null ? { 'content-digest': digest } : {}) });
      res.end(bytes);
      return;
    }
    if (req.method === 'DELETE' && (g = /^\/mcp\/warm-start\/([0-9a-f]{64})$/.exec(path))) {
      const i = m.snapshots.findIndex((x) => x.snapshotId === g![1]);
      if (i < 0) return send(res, { status: 404, body: { error: 'snapshot_not_found' } });
      m.snapshots.splice(i, 1);
      return send(res, { status: 204 });
    }
    return send(res, { status: 404, body: { error: 'not_found' } });
  };
  m.server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => route(req, Buffer.concat(chunks), res));
  });
  await new Promise<void>((r) => m.server.listen(0, '127.0.0.1', () => r()));
  m.url = `http://127.0.0.1:${(m.server.address() as AddressInfo).port}`;
  m.info = { warmStart: { v: [1], path: '/mcp/warm-start', partBytes: m.partBytes } };
  return m;
}

// ── the server ─────────────────────────────────────────────────────────────────────────────────────────────────────

interface Result {
  text: string;
  isError: boolean;
  structured: Record<string, any>;
  raw: any;
}
interface Driver {
  proc: ChildProcess;
  call: (name: string, args: unknown) => Promise<Result>;
  tools: any[];
}

async function startServer(endpoint: string, home: string): Promise<Driver> {
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
      SAIHM_AUTH_HEADER: AUTH,
      SAIHM_MASTER_SECRET_HEX: MASTER_HEX,
      SAIHM_HOME: home,
      HOME: home,
      SAIHM_TIER: 'PRO',
      SAIHM_PAYMENT_METHOD: 'stripe',
      SAIHM_SELF_JOIN: '0',
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
      let msg: any;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (msg.id != null && waiters.has(msg.id)) {
        waiters.get(msg.id)!(msg);
        waiters.delete(msg.id);
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
      }, 60_000).unref();
    });
  };
  await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const tools = (await rpc('tools/list', {})).result.tools as any[];
  const validator = new AjvJsonSchemaValidator();
  const checks = new Map(tools.filter((t) => t.outputSchema).map((t) => [t.name as string, validator.getValidator(t.outputSchema)]));
  return {
    proc,
    tools,
    call: async (name, args) => {
      const msg = await rpc('tools/call', { name, arguments: args });
      assert.ok(msg.result, `tools/call ${name} answered no result: ${JSON.stringify(msg.error)}`);
      const structured = msg.result.structuredContent;
      // As a validating host: every structured result, an error's included, against the published schema.
      if (structured !== undefined) {
        const v = checks.get(name)!(structured);
        assert.ok(v.valid, `${name}: the result does not match its published output schema: ${v.errorMessage}\n${JSON.stringify(structured)}`);
      }
      return {
        text: String(msg.result.content?.[0]?.text ?? ''),
        isError: msg.result.isError === true,
        structured: (structured ?? {}) as Record<string, any>,
        raw: msg.result,
      };
    },
  };
}

interface Rig {
  d: Driver;
  m: Mock;
  home: string;
  dir: string;
}

async function withRig(body: (r: Rig) => Promise<void>, setup: (m: Mock) => void = () => {}): Promise<void> {
  const home = mkdtempSync(join(tmpdir(), 'saihm-ws-srv-'));
  const m = await startMock();
  setup(m);
  const d = await startServer(`${m.url}/mcp`, home);
  try {
    await body({ d, m, home, dir: join(home, 'tenants', ID, 'warm-start') });
  } finally {
    d.proc.kill();
    m.server.closeAllConnections();
    await new Promise<void>((r) => m.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
}

/** What SHM does before a put: the folder (0700), a temporary file (0600), then a rename. */
function shmPut(dir: string, tok: string, payload: Uint8Array): string {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (let p = dir; p.includes('/tenants'); p = dirname(p)) chmodSync(p, 0o700);
  const tmp = join(dir, `.shm-${tok}.tmp`);
  writeFileSync(tmp, payload, { mode: 0o600 });
  const dest = join(dir, `put-${tok}.bin`);
  renameSync(tmp, dest);
  return dest;
}

const PAYLOAD = Buffer.from(Array.from({ length: 3000 }, (_, i) => `row ${i};`).join('')).subarray(0, 3000);

// ── the cases ──────────────────────────────────────────────────────────────────────────────────────────────────────

test('saihm_status: an offer this client serves carries token "required", in place of any the endpoint sent; declared on the published schema', async () => {
  await withRig(async ({ d, m }) => {
    const status = d.tools.find((t) => t.name === 'saihm_status');
    const declared = status.outputSchema.properties.features.anyOf[0].properties.warmStart;
    assert.deepEqual(
      declared.anyOf[0].properties.token,
      { type: 'string', const: 'required' },
      `the member and its one value are declared: ${JSON.stringify(declared)}`,
    );
    m.features = { events: { v: [1], kinds: ['cell-written', 'cell-erased'] }, warmStart: { ...OFFER, token: 'optional' } };
    let r = await d.call('saihm_status', {});
    assert.equal(r.isError, false, r.text);
    assert.deepEqual(r.structured.features, { events: m.features.events, warmStart: { ...OFFER, token: 'required' } });
    for (const offer of [{ ...OFFER, v: [2], token: 'required' }, { ...OFFER, maxBytes: 0 }, 'warm start', null]) {
      m.features = { warmStart: offer };
      r = await d.call('saihm_status', {});
      assert.equal(r.isError, false, r.text);
      const want = typeof offer === 'object' && offer !== null ? Object.fromEntries(Object.entries(offer).filter(([k]) => k !== 'token')) : offer;
      assert.deepEqual(r.structured.features, { warmStart: want }, `${JSON.stringify(offer)}: passed on without a statement`);
    }
    m.features = undefined;
    r = await d.call('saihm_status', {});
    assert.equal(r.structured.features, null);
  });
});

test('put, list, latest, delete: the payload travels sealed and comes back whole into latest-<token>.bin, and the put file is gone', async () => {
  await withRig(async ({ d, m, dir }) => {
    const t1 = token();
    const putFile = shmPut(dir, t1, PAYLOAD);
    const put = await d.call('saihm_remember', { warmStart: 'put', coversThrough: AT, token: t1 });
    assert.equal(put.isError, false, put.text);
    assert.deepEqual(Object.keys(put.structured).sort(), ['bytes', 'coversThrough', 'createdAt', 'snapshotId']);
    const stored = m.snapshots[0]!;
    assert.equal(put.structured.snapshotId, stored.snapshotId);
    assert.equal(put.structured.coversThrough, AT);
    assert.equal(put.structured.bytes, stored.bytes);
    assert.match(put.text, /^SNAPSHOT STORED \[[0-9a-f]{16}…\] bytes=\d+$/);
    assert.equal(existsSync(putFile), false, 'the put file is removed');
    // The endpoint holds ciphertext it cannot read: no run of the payload appears in what it stores or was sent.
    const sealed = Buffer.concat(stored.parts);
    assert.equal(sealed.includes(PAYLOAD.subarray(100, 132)), false);
    assert.equal(JSON.stringify(m.begins[0]).includes('row 1'), false);
    assert.equal(stored.parts.length, Math.ceil(stored.bytes / m.partBytes), 'cut at the part size the endpoint gave');
    assert.match(String(m.begins[0]!.nonce), /^[0-9a-f]{32}$/);

    const list = await d.call('saihm_recall', { warmStart: 'list', token: token() });
    assert.equal(list.isError, false, list.text);
    // Not a share listing: no `shared` and no `sharedTruncated`, which SHM reads together as the whole list of shares.
    assert.deepEqual(list.structured, { count: 0, memories: [], snapshots: [put.structured] });
    assert.match(list.text, /^SNAPSHOTS 1, newest first, no content\n {2}! SNAPSHOT \[[0-9a-f]{16}…\] bytes=\d+ created=\S+$/);

    const t2 = token();
    const latest = await d.call('saihm_recall', { warmStart: 'latest', token: t2 });
    assert.equal(latest.isError, false, latest.text);
    assert.deepEqual(latest.structured, { count: 0, memories: [], snapshot: put.structured });
    const out = join(dir, `latest-${t2}.bin`);
    assert.deepEqual(readFileSync(out), PAYLOAD, 'the payload comes back whole');
    assert.equal(statSync(out).mode & 0o777, 0o600);
    assert.equal(statSync(dir).mode & 0o777, 0o700);
    assert.deepEqual(readdirSync(dir), [`latest-${t2}.bin`], 'nothing else is left in the folder');

    const del = await d.call('saihm_forget', { warmStart: 'delete', snapshotId: stored.snapshotId, token: token() });
    assert.equal(del.isError, false, del.text);
    assert.deepEqual(del.structured, { deleted: true });
    const again = await d.call('saihm_forget', { warmStart: 'delete', snapshotId: stored.snapshotId, token: token() });
    assert.equal(again.isError, true);
    assert.deepEqual(again.structured, { error: { code: 'snapshot_not_found', status: 404 } });

    const t3 = token();
    writeFileSync(join(dir, `latest-${t3}.bin`), 'stale', { mode: 0o600 });
    const none = await d.call('saihm_recall', { warmStart: 'latest', token: t3 });
    assert.equal(none.isError, false, none.text);
    assert.deepEqual(none.structured, { count: 0, memories: [], snapshot: null });
    assert.equal(none.text, 'No snapshot to restore: start cold.');
    assert.equal(existsSync(join(dir, `latest-${t3}.bin`)), false, 'no file for a token with nothing to restore');
    const empty = await d.call('saihm_recall', { warmStart: 'list', token: token() });
    assert.deepEqual(empty.structured, { count: 0, memories: [], snapshots: [] });
  });
});

test('no offer, or an endpoint that does not describe warm start: every mode is refused warm_start_unavailable, and nothing reaches the routes', async () => {
  for (const [label, setup] of [
    ['no offer in status', (m: Mock) => { m.features = { events: { v: [1], kinds: [] } }; }],
    ['status without features', (m: Mock) => { m.features = undefined; }],
    ['an offer of another version', (m: Mock) => { m.features = { warmStart: { ...OFFER, v: [2] } }; }],
    ['no info document', (m: Mock) => { m.info = null; }],
    ['info without warmStart', (m: Mock) => { m.info = { events: { v: [1] } }; }],
  ] as const) {
    await withRig(async ({ d, m, dir }) => {
      const t = token();
      const putFile = shmPut(dir, t, PAYLOAD);
      const calls: [string, Record<string, unknown>][] = [
        ['saihm_remember', { warmStart: 'put', coversThrough: AT, token: t }],
        ['saihm_recall', { warmStart: 'latest', token: token() }],
        ['saihm_recall', { warmStart: 'list', token: token() }],
        ['saihm_forget', { warmStart: 'delete', snapshotId: 'ab'.repeat(32), token: token() }],
      ];
      for (const [name, args] of calls) {
        const r = await d.call(name, args);
        assert.equal(r.isError, true, `${label}: ${name}`);
        assert.deepEqual(r.structured, { error: { code: 'warm_start_unavailable', status: 0 } }, `${label}: ${name}`);
        assert.match(r.text, /^SAIHM error \[warm_start_unavailable\]/);
      }
      assert.deepEqual(m.requests, [], `${label}: no request reached the warm-start routes`);
      assert.equal(existsSync(putFile), false, `${label}: the put file is removed all the same`);
      assert.deepEqual(readdirSync(dir), [], `${label}: and no restore file is written`);
    }, setup);
  }
});

test('input: token required and in its grammar, one mode per call, refused before any file is touched or request sent', async () => {
  await withRig(async ({ d, m, dir }) => {
    const t = token();
    const putFile = shmPut(dir, t, PAYLOAD);
    const asked = m.all.length;
    const invalid: [string, Record<string, unknown>][] = [
      ['saihm_remember', { warmStart: 'put', coversThrough: AT }],
      ['saihm_remember', { warmStart: 'put', token: t }],
      ['saihm_remember', { warmStart: 'put', coversThrough: AT, token: t, content: 'a memory' }],
      ['saihm_remember', { warmStart: 'put', coversThrough: AT, token: t, cellId: 'c1' }],
      ['saihm_remember', { coversThrough: AT, token: t }],
      ['saihm_remember', { token: t, content: 'a memory' }],
      ['saihm_recall', { warmStart: 'latest' }],
      ['saihm_recall', { token: t }],
      ['saihm_recall', { warmStart: 'latest', token: t, query: 'x' }],
      ['saihm_recall', { warmStart: 'latest', token: t, cellId: 'c1' }],
      ['saihm_recall', { warmStart: 'list', token: t, listOnly: true }],
      ['saihm_recall', { warmStart: 'list', token: t, shareEntries: false }],
      ['saihm_forget', { warmStart: 'delete', token: t }],
      ['saihm_forget', { warmStart: 'delete', snapshotId: 'ab'.repeat(32) }],
      ['saihm_forget', { warmStart: 'delete', snapshotId: 'ab'.repeat(32), token: t, id: 'c1' }],
      ['saihm_forget', { snapshotId: 'ab'.repeat(32), token: t }],
    ];
    for (const [name, args] of invalid) {
      const r = await d.call(name, args);
      assert.equal(r.isError, true, `${name} ${JSON.stringify(args)}`);
      assert.deepEqual(r.structured, { error: { code: 'invalid_input', status: 0 } }, `${name} ${JSON.stringify(args)}: ${r.text}`);
    }
    // Outside the grammar: refused by the schema before the tool runs.
    const bad: [string, Record<string, unknown>][] = [
      ['saihm_remember', { warmStart: 'put', coversThrough: AT, token: '../../../tmp/x' }],
      ['saihm_remember', { warmStart: 'put', coversThrough: AT, token: 'a'.repeat(15) }],
      ['saihm_remember', { warmStart: 'put', coversThrough: AT, token: 'a'.repeat(33) }],
      ['saihm_remember', { warmStart: 'put', coversThrough: AT, token: 'ABCDEFGHIJKLMNOPQR' }],
      ['saihm_remember', { warmStart: 'put', coversThrough: 'a b', token: t }],
      ['saihm_remember', { warmStart: 'put', coversThrough: 'a'.repeat(65), token: t }],
      ['saihm_remember', { warmStart: 'latest', coversThrough: AT, token: t }],
      ['saihm_recall', { warmStart: 'put', token: t }],
      ['saihm_recall', { warmStart: 'latest', token: 'x/y' }],
      ['saihm_forget', { warmStart: 'delete', snapshotId: 'AB'.repeat(32), token: t }],
      ['saihm_forget', { warmStart: 'erase', snapshotId: 'ab'.repeat(32), token: t }],
    ];
    for (const [name, args] of bad) {
      const r = await d.call(name, args);
      assert.equal(r.isError, true, `${name} ${JSON.stringify(args)}`);
      assert.match(r.text, /Input validation error/, `${name} ${JSON.stringify(args)}`);
    }
    // Off warm start, a missing content or id is refused in the tool; a blank one is still a value, as it always was.
    const noContent = await d.call('saihm_remember', {});
    assert.deepEqual(noContent.structured, { error: { code: 'content_required', status: 0 } });
    const noId = await d.call('saihm_forget', {});
    assert.deepEqual(noId.structured, { error: { code: 'id_required', status: 0 } });
    assert.deepEqual(m.requests, [], 'no request reached the warm-start routes');
    assert.equal(m.all.length, asked, 'nor any other: not even the offer was asked for');
    assert.ok(existsSync(putFile), 'and the payload file was never touched');
    assert.deepEqual(readdirSync(dir), [`put-${t}.bin`]);
    // Blank fields a host fills in read as absent: this is a put.
    const put = await d.call('saihm_remember', { warmStart: 'put', coversThrough: AT, token: t, content: '', cellId: null });
    assert.equal(put.isError, false, put.text);
    assert.equal(existsSync(putFile), false);
  });
});

test('payload files: missing, a link, open to others or too large are refused; the put file goes whatever happens; another token\'s file is never read', async () => {
  await withRig(async ({ d, m, dir, home }) => {
    const call = (t: string) => d.call('saihm_remember', { warmStart: 'put', coversThrough: AT, token: t });
    let r = await call(token());
    assert.deepEqual(r.structured, { error: { code: 'warm_start_file_missing', status: 0 } });
    // Two processes of one identity: each put reads its own token's file and nothing else.
    const [ta, tb] = [token(), token()];
    shmPut(dir, ta, Buffer.from('payload of process A'));
    const fileB = shmPut(dir, tb, Buffer.from('payload of process B'));
    r = await call(ta);
    assert.equal(r.isError, false, r.text);
    assert.equal(readFileSync(fileB, 'utf8'), 'payload of process B', 'B\'s file untouched');
    const tl = token();
    await d.call('saihm_recall', { warmStart: 'latest', token: tl });
    assert.equal(readFileSync(join(dir, `latest-${tl}.bin`), 'utf8'), 'payload of process A');
    rmSync(fileB);
    // A link, even to a private file of this user's: refused, and what it points at is never read or removed.
    const tlink = token();
    const secret = join(home, 'secret.txt');
    writeFileSync(secret, 'never uploaded', { mode: 0o600 });
    symlinkSync(secret, join(dir, `put-${tlink}.bin`));
    const before = m.begins.length;
    r = await call(tlink);
    assert.deepEqual(r.structured, { error: { code: 'warm_start_file_unsafe', status: 0 } });
    assert.equal(readFileSync(secret, 'utf8'), 'never uploaded');
    assert.equal(existsSync(join(dir, `put-${tlink}.bin`)), false, 'the link itself is removed with the call');
    // Open to other users: refused, and removed.
    const topen = token();
    const open = shmPut(dir, topen, PAYLOAD);
    chmodSync(open, 0o644);
    r = await call(topen);
    assert.deepEqual(r.structured, { error: { code: 'warm_start_file_unsafe', status: 0 } });
    assert.equal(existsSync(open), false);
    // Larger than this identity's snapshots may be: refused before anything is sent, and removed.
    const tbig = token();
    const big = shmPut(dir, tbig, Buffer.alloc(OFFER.maxBytes + 1));
    r = await call(tbig);
    assert.deepEqual(r.structured, { error: { code: 'snapshot_too_large', status: 0 } });
    assert.equal(existsSync(big), false);
    // Small enough to read, too large once sealed: refused before begin.
    const tseal = token();
    shmPut(dir, tseal, Buffer.alloc(OFFER.maxBytes - 10));
    r = await call(tseal);
    assert.deepEqual(r.structured, { error: { code: 'snapshot_too_large', status: 0 } });
    assert.equal(m.begins.length, before, 'no upload began for any refused file');
  });
});

test('leftovers: files past the age, temporary ones included, go at the next warm-start call of any mode; fresh ones stay', async () => {
  await withRig(async ({ d, dir }) => {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    for (let p = dir; p.includes('/tenants'); p = dirname(p)) chmodSync(p, 0o700);
    const old = new Date(Date.now() - 10 * 60_000);
    const stale = [`put-${token()}.bin`, `latest-${token()}.bin`, '.shm-crashed.tmp', `.latest-${token()}.bin.0a1b2c3d4e5f.tmp`];
    for (const n of stale) {
      writeFileSync(join(dir, n), 'plaintext left by a crash', { mode: 0o600 });
      utimesSync(join(dir, n), old, old);
    }
    const fresh = `put-${token()}.bin`;
    writeFileSync(join(dir, fresh), 'in flight', { mode: 0o600 });
    const r = await d.call('saihm_recall', { warmStart: 'list', token: token() });
    assert.equal(r.isError, false, r.text);
    assert.deepEqual(readdirSync(dir), [fresh]);
    // A put's own payload file is no leftover, however late its call arrives (a host waiting for approval, a paused
    // process): the put stores it, then removes it. Another old file goes as before.
    const late = token();
    utimesSync(shmPut(dir, late, PAYLOAD), old, old);
    const other = `put-${token()}.bin`;
    writeFileSync(join(dir, other), 'plaintext left by a crash', { mode: 0o600 });
    utimesSync(join(dir, other), old, old);
    const put = await d.call('saihm_remember', { warmStart: 'put', coversThrough: AT, token: late });
    assert.equal(put.isError, false, put.text);
    assert.deepEqual(readdirSync(dir), [fresh], 'the late payload stored and removed, the other old file swept');
  });
});

test('a restore is all or nothing: a moved, dropped, foreign or altered part, a cell key envelope, or a part gone after the listing writes nothing', async () => {
  const cell = sealCell({
    plaintext: new TextEncoder().encode('a memory'),
    kek: ME.kek,
    mldsaSecretKey: ME.mldsaSecretKey,
    mldsaPubKey: ME.mldsaPubKey,
    agentIdHash: ME.agentIdHash,
    cellId: 'c1',
    seq: 1n,
    tier: 'PRO',
  });
  const cellEnvelope = Buffer.concat([Buffer.from([1]), Buffer.from(cell.wrappedDek)]).toString('base64url');
  await withRig(async ({ d, m, dir }) => {
    // Two snapshots, so a part can come from the other one.
    for (const payload of [PAYLOAD, Buffer.from(PAYLOAD).reverse()]) {
      const t = token();
      shmPut(dir, t, payload);
      const r = await d.call('saihm_remember', { warmStart: 'put', coversThrough: AT, token: t });
      assert.equal(r.isError, false, r.text);
    }
    const [newest, older] = [m.snapshots[0]!, m.snapshots[1]!];
    assert.ok(newest.parts.length >= 3, 'fixture: several parts');
    const withParts = (parts: Buffer[]): Stored => ({ ...newest, parts, bytes: parts.reduce((a, p) => a + p.length, 0), digest: sha(Buffer.concat(parts)).toString('hex') });
    const p = newest.parts;
    const cases: [string, () => void, string][] = [
      ['two parts moved, every digest made to match', () => { m.list = () => ({ v: 1, snapshots: [listed(withParts([p[1]!, p[0]!, ...p.slice(2)]))] }); m.read = (_s, n) => { const q = [p[1]!, p[0]!, ...p.slice(2)][n]!; return { bytes: q, digest: digestHeader(q) }; }; }, 'undecryptable'],
      ['the last part dropped, every digest made to match', () => { m.list = () => ({ v: 1, snapshots: [listed(withParts(p.slice(0, -1)))] }); m.read = (_s, n) => ({ bytes: p[n]!, digest: digestHeader(p[n]!) }); }, 'undecryptable'],
      ['a part from the other snapshot, every digest made to match', () => { const q = [older.parts[0]!, ...p.slice(1)]; m.list = () => ({ v: 1, snapshots: [listed(withParts(q))] }); m.read = (_s, n) => ({ bytes: q[n]!, digest: digestHeader(q[n]!) }); }, 'undecryptable'],
      ['a part altered, its own digest made to match', () => { m.list = (s) => ({ v: 1, snapshots: s.map(listed) }); m.read = (s, n) => { const q = Buffer.from(s.parts[n]!); if (n === 1) q[7] ^= 1; return { bytes: q, digest: digestHeader(q) }; }; }, 'digest_mismatch'],
      ['a part whose Content-Digest does not match it', () => { m.read = (s, n) => ({ bytes: s.parts[n]!, digest: n === 2 ? digestHeader(Buffer.from('other')) : digestHeader(s.parts[n]!) }); }, 'digest_mismatch'],
      ['a part with no Content-Digest', () => { m.read = (s, n) => ({ bytes: s.parts[n]!, digest: n === 0 ? null : digestHeader(s.parts[n]!) }); }, 'digest_mismatch'],
      ['a cell key envelope offered as the snapshot key', () => { m.read = (s, n) => ({ bytes: s.parts[n]!, digest: digestHeader(s.parts[n]!) }); m.list = (s) => ({ v: 1, snapshots: [{ ...listed(s[0]!), keyEnvelope: cellEnvelope }] }); }, 'undecryptable'],
      ['the snapshot destroyed between the listing and a read', () => { m.list = (s) => ({ v: 1, snapshots: s.map(listed) }); m.hook = (route) => (route.includes('/parts/') && route.startsWith('GET') ? { status: 404, body: { error: 'snapshot_not_found' } } : undefined); }, 'snapshot_not_found'],
      ['a listing with an entry this client cannot read', () => { m.hook = () => undefined; m.list = (s) => ({ v: 1, snapshots: [...s.map(listed), { snapshotId: 'x' }] }); }, 'malformed_response'],
    ];
    for (const [label, arrange, want] of cases) {
      arrange();
      const t = token();
      const r = await d.call('saihm_recall', { warmStart: 'latest', token: t });
      assert.equal(r.isError, true, `${label}: ${r.text}`);
      assert.equal(r.structured.error?.code, want, `${label}: ${r.text}`);
      assert.deepEqual(readdirSync(dir), [], `${label}: nothing is written`);
    }
    m.list = (s) => ({ v: 1, snapshots: s.map(listed) });
    m.read = (s, n) => ({ bytes: s.parts[n]!, digest: digestHeader(s.parts[n]!) });
    const t = token();
    const ok = await d.call('saihm_recall', { warmStart: 'latest', token: t });
    assert.equal(ok.isError, false, `positive control: the same snapshot restores untouched: ${ok.text}`);
    assert.deepEqual(readFileSync(join(dir, `latest-${t}.bin`)), Buffer.from(PAYLOAD).reverse());
  });
});

test('an upload once begun survives a limit and a busy commit; other refusals arrive typed, superseded included', async () => {
  await withRig(async ({ d, m, dir }) => {
    const put = async (): Promise<Result> => {
      const t = token();
      shmPut(dir, t, PAYLOAD);
      return d.call('saihm_remember', { warmStart: 'put', coversThrough: AT, token: t });
    };
    m.hook = (route, count) =>
      route.startsWith('PUT') && route.endsWith('/parts/1') && count === 1
        ? { status: 429, headers: { 'retry-after': '1' } }
        : route.startsWith('PUT') && route.endsWith('/parts/2') && count === 1
          ? { status: 0 }
        : route.endsWith('/commit') && count === 1
          ? { status: 503, body: { error: 'warm_start_unavailable', reason: 'busy', retryAfterMs: 1000 }, headers: { 'retry-after': '1' } }
          : undefined;
    let r = await put();
    assert.equal(r.isError, false, r.text);
    assert.equal(m.requests.filter((x) => x.endsWith('/parts/1')).length, 2, 'the limited part was sent again');
    assert.equal(m.requests.filter((x) => x.endsWith('/parts/2')).length, 2, 'the part whose connection dropped was sent again');
    assert.equal(m.requests.filter((x) => x.endsWith('/commit')).length, 2, 'the busy commit was sent again');
    // A limit that does not lift: the refusal is the answer, after a bounded number of tries.
    m.hook = (route) => (route.startsWith('PUT') ? { status: 429, headers: { 'retry-after': '1' } } : undefined);
    const tries = m.requests.length;
    r = await put();
    assert.deepEqual(r.structured, { error: { code: 'rate_limited', status: 429 } });
    assert.equal(m.requests.length - tries, 1 + 3, 'begin, then three tries of the first part');
    const refusals: [Answer, string, number][] = [
      [{ status: 409, body: { error: 'snapshot_superseded' } }, 'snapshot_superseded', 409],
      [{ status: 503, body: { error: 'warm_start_unavailable', reason: 'capacity', retryAfterMs: 60000 }, headers: { 'retry-after': '60' } }, 'warm_start_unavailable', 503],
      [{ status: 402, body: { error: 'tier_required' } }, 'tier_required', 402],
      [{ status: 410, body: { error: 'tenant_erased' } }, 'tenant_erased', 410],
    ];
    for (const [answer, code, status] of refusals) {
      m.hook = (route) => (route.endsWith('/commit') || (route === 'POST /mcp/warm-start' && code === 'tier_required') ? answer : undefined);
      const before = m.requests.length;
      r = await put();
      assert.deepEqual(r.structured, { error: { code, status } }, `${code}: ${r.text}`);
      assert.ok(m.requests.length - before <= m.snapshots[0]!.parts.length + 2, `${code}: refused once, not retried`);
    }
    // An endpoint whose answers do not fit what was sent: a part size other than the info's, a commit of other bytes.
    m.hook = (route) => (route === 'POST /mcp/warm-start' ? { status: 201, body: { v: 1, uploadId: 'ab'.repeat(16), partBytes: 2048, expiresAt: 'x' } } : undefined);
    r = await put();
    assert.deepEqual(r.structured, { error: { code: 'malformed_response', status: 502 } }, r.text);
    m.hook = (route) => (route.endsWith('/commit') ? { status: 201, body: { v: 1, snapshotId: 'ab'.repeat(32), createdAt: new Date().toISOString(), bytes: 1, parts: 1, coversThrough: AT } } : undefined);
    r = await put();
    assert.deepEqual(r.structured, { error: { code: 'malformed_response', status: 502 } }, r.text);
    assert.deepEqual(readdirSync(dir), [], 'every put file is gone');
  });
});

test('an empty payload is one sealed part and restores to an empty file; a refusal of a small part keeps its own code', async () => {
  await withRig(async ({ d, m, dir }) => {
    const t = token();
    shmPut(dir, t, new Uint8Array(0));
    const put = await d.call('saihm_remember', { warmStart: 'put', coversThrough: AT, token: t });
    assert.equal(put.isError, false, put.text);
    assert.equal(put.structured.bytes, 16, 'one part holding only its tag');
    const tl = token();
    const latest = await d.call('saihm_recall', { warmStart: 'latest', token: tl });
    assert.equal(latest.isError, false, latest.text);
    assert.equal(readFileSync(join(dir, `latest-${tl}.bin`)).length, 0);
    m.hook = (route) => (route.startsWith('GET') && route.includes('/parts/') ? { status: 404, body: { error: 'snapshot_not_found' } } : undefined);
    const gone = await d.call('saihm_recall', { warmStart: 'latest', token: token() });
    assert.deepEqual(gone.structured, { error: { code: 'snapshot_not_found', status: 404 } }, gone.text);
  });
});

test('a commit whose answer is lost on its way back is the stored snapshot all the same: the listing says so', async () => {
  await withRig(async ({ d, m, dir }) => {
    const put = async (): Promise<Result> => {
      const t = token();
      shmPut(dir, t, PAYLOAD);
      return d.call('saihm_remember', { warmStart: 'put', coversThrough: AT, token: t });
    };
    // The connection drops after the commit is stored: sent again, the commit finds its upload gone (upload_not_found).
    m.afterCommit = (count) => (count === 1 ? null : undefined);
    let r = await put();
    assert.equal(r.isError, false, r.text);
    assert.equal(m.requests.filter((x) => x.endsWith('/commit')).length, 2, 'sent again after the dropped connection');
    assert.equal(m.snapshots.length, 1, 'stored once');
    assert.deepEqual(r.structured, { snapshotId: m.snapshots[0]!.snapshotId, createdAt: m.snapshots[0]!.createdAt, bytes: m.snapshots[0]!.bytes, coversThrough: AT });
    // The front could not relay the operator's answer (upstream_unavailable), which stored it all the same: not sent again.
    m.afterCommit = () => ({ status: 503, body: { error: 'upstream_unavailable' } });
    r = await put();
    assert.equal(r.isError, false, r.text);
    assert.equal(m.snapshots.length, 2);
    assert.equal(r.structured.snapshotId, m.snapshots[0]!.snapshotId);
    // Positive controls: the same refusals of a commit that was NOT stored stay refusals.
    m.afterCommit = () => undefined;
    for (const [answer, code, status] of [
      [{ status: 404, body: { error: 'upload_not_found' } }, 'upload_not_found', 404],
      [{ status: 503, body: { error: 'upstream_unavailable' } }, 'upstream_unavailable', 503],
    ] as const) {
      m.hook = (route) => (route.endsWith('/commit') ? answer : undefined);
      r = await put();
      assert.deepEqual(r.structured, { error: { code, status } }, r.text);
    }
    assert.equal(m.snapshots.length, 2, 'nothing more was stored');
    assert.deepEqual(readdirSync(dir), [], 'every put file is gone');
  });
});
