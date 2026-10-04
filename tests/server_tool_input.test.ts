// Tool arguments as hosts send them (src/tool-input.ts). A host that fills every field of a schema sends null, a blank
// string or an object of blank strings for each optional field the model did not choose, and a client SDK may leave
// `arguments` out of a call to a tool that takes none. Each must do exactly what the call does with the field left out.
// The oracle is the same call with the field omitted, against a mock bridge that verifies the onboard signature and
// records every method the client sends: equal response, equal methods.
// Runner: npx tsx --test tests/server_tool_input.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { z } from 'zod';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { fromHex } from '@saihm/client-pro';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { acceptAbsentToolArguments, isBlankInput, optionalInput, withToolArguments } from '../src/tool-input.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');

test('isBlankInput: null, undefined and blank strings are blank; an object of only those, only where the field takes an object', () => {
  for (const v of [null, undefined, '', ' ', '\t\n', '\u00a0']) {
    assert.equal(isBlankInput(v), true, JSON.stringify(v));
    assert.equal(isBlankInput(v, true), true, JSON.stringify(v));
  }
  for (const v of [{}, { a: '' }, { a: null, b: '  ', c: undefined }]) {
    assert.equal(isBlankInput(v, true), true, JSON.stringify(v));
    assert.equal(isBlankInput(v), false, `an object for a field that takes none is a value, and the wrong type: ${JSON.stringify(v)}`);
  }
  for (const v of ['x', ' x ', '0', 0, false, true, [], [''], { a: 'x' }, { a: '', b: 'x' }, { a: '', b: {} }, { a: false }]) {
    assert.equal(isBlankInput(v, true), false, JSON.stringify(v));
  }
});

test('optionalInput reads a blank value as absent, keeps every value including false, and still refuses a wrong type', () => {
  const s = optionalInput(z.string());
  for (const v of [null, undefined, '', '   ']) assert.equal(s.parse(v), undefined, JSON.stringify(v));
  assert.equal(s.parse('abc'), 'abc');
  assert.equal(s.parse(' abc '), ' abc ', 'a value is passed through as given, never trimmed');
  assert.throws(() => s.parse(5));
  assert.throws(() => s.parse({}), 'an empty object is not a blank string: it is the wrong type');
  assert.throws(() => s.parse({ a: '' }));

  const b = optionalInput(z.boolean());
  assert.equal(b.parse(null), undefined);
  assert.equal(b.parse(''), undefined);
  assert.equal(b.parse(false), false, 'false is a value, not a blank');
  assert.equal(b.parse(true), true);
  assert.throws(() => b.parse('true'), 'a string is not coerced to a boolean');
  assert.throws(() => b.parse({}));

  const e = optionalInput(z.enum(['read', 'write']));
  assert.equal(e.parse(''), undefined);
  assert.equal(e.parse(null), undefined);
  assert.equal(e.parse('write'), 'write');
  assert.throws(() => e.parse('bogus'));
  assert.throws(() => e.parse({}));

  const o = optionalInput(z.object({ k: z.string(), m: z.string() }));
  assert.equal(o.parse({ k: '', m: '' }), undefined);
  assert.equal(o.parse(null), undefined);
  assert.deepEqual(o.parse({ k: 'a', m: 'b' }), { k: 'a', m: 'b' });
  assert.deepEqual(o.parse({ k: 'a', m: '' }), { k: 'a', m: '' }, 'a partly filled object is a value');

  const r = optionalInput(z.string().regex(/^[0-9]+$/));
  assert.equal(r.parse(''), undefined, 'a blank never reaches the pattern');
  assert.throws(() => r.parse('12a'));

  const shape = z.object({ q: optionalInput(z.string()) });
  assert.deepEqual(shape.parse({}), {}, 'an omitted field stays omitted');
  assert.deepEqual(shape.parse({ q: null }), { q: undefined });
});

const req = (params: unknown, method = 'tools/call'): JSONRPCMessage =>
  ({ jsonrpc: '2.0', id: 1, method, ...(params === undefined ? {} : { params }) }) as JSONRPCMessage;

test('withToolArguments gives a tools/call without arguments, or with null, an empty object; anything else passes as it came', () => {
  for (const params of [{ name: 'saihm_status' }, { name: 'saihm_status', arguments: null }]) {
    const m = req(params);
    const before = JSON.stringify(m);
    assert.deepEqual(withToolArguments(m), req({ name: 'saihm_status', arguments: {} }));
    assert.equal(JSON.stringify(m), before, 'the message received is not mutated');
  }
  const unchanged: JSONRPCMessage[] = [
    req({ name: 'saihm_recall', arguments: { query: 'x' } }),
    req({ name: 'saihm_recall', arguments: {} }),
    req({ name: 'saihm_recall', arguments: 'not an object' }),
    req(undefined),
    req({}, 'tools/list'),
    req(undefined, 'tools/list'),
    { jsonrpc: '2.0', method: 'tools/call', params: { name: 'x' } } as JSONRPCMessage,
    { jsonrpc: '2.0', id: 1, result: {} } as JSONRPCMessage,
  ];
  for (const m of unchanged) assert.equal(withToolArguments(m), m, JSON.stringify(m));
});

test('acceptAbsentToolArguments wraps the handler the server set before start, and delivers everything through it', async () => {
  const seen: JSONRPCMessage[] = [];
  let started = 0;
  const t: Transport = {
    start: async () => {
      started++;
    },
    send: async () => {},
    close: async () => {},
  };
  assert.equal(acceptAbsentToolArguments(t), t);
  t.onmessage = (m) => void seen.push(m);
  await t.start();
  assert.equal(started, 1, 'the transport still starts');
  t.onmessage!(req({ name: 'saihm_status' }));
  const other = req({}, 'tools/list');
  t.onmessage!(other);
  assert.deepEqual(seen[0], req({ name: 'saihm_status', arguments: {} }));
  assert.equal(seen[1], other);
});

// ---- integration: the real stdio server against a mock bridge ----

function childEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const keep: NodeJS.ProcessEnv = {};
  for (const k of ['PATH', 'SYSTEMROOT', 'TEMP', 'TMP', 'TMPDIR']) if (process.env[k] !== undefined) keep[k] = process.env[k];
  return { ...keep, ...extra };
}

/** A bridge that verifies the onboard signature, answers own recall with no cells, and records every /mcp method. */
function startMock(): { server: Server; base: () => string; methods: string[]; recalls: Record<string, unknown>[] } {
  let lastNonce = '';
  const methods: string[] = [];
  const recalls: Record<string, unknown>[] = [];
  const server = createServer((req, res) => {
    const url = req.url ?? '';
    const send = (s: number, b: unknown): void => {
      res.writeHead(s, { 'content-type': 'application/json' });
      res.end(JSON.stringify(b));
    };
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      if (req.method === 'GET' && url === '/api/onboard/challenge') {
        lastNonce = Buffer.from(new Uint8Array(32).map(() => Math.floor(Math.random() * 256))).toString('hex');
        return send(200, { nonce: lastNonce });
      }
      let j: Record<string, any> = {};
      try {
        j = JSON.parse(body);
      } catch {
        /* not JSON */
      }
      if (req.method === 'POST' && url === '/api/onboard') {
        let ok = false;
        try {
          ok = j.nonce === lastNonce && ml_dsa65.verify(fromHex(j.signature ?? ''), fromHex(j.nonce ?? ''), fromHex(j.pubkey ?? ''));
        } catch {
          ok = false;
        }
        if (!ok) return send(401, { error: 'bad_signature' });
        const jwt = `${b64url({ alg: 'EdDSA' })}.${b64url({ sub: j.pubkey, tier: 'PRO', exp: Math.floor(Date.now() / 1000) + 3600 })}.sig`;
        return send(201, { jwt });
      }
      if (req.method === 'POST' && url === '/mcp') {
        methods.push(String(j.method));
        if (j.method === 'saihm_recall') {
          recalls.push(j.params ?? {});
          return send(200, []);
        }
        return send(404, { error: 'unknown_method' });
      }
      return send(404, { error: 'not_found' });
    });
  });
  return { server, base: () => `http://127.0.0.1:${(server.address() as AddressInfo).port}`, methods, recalls };
}

interface Reply {
  error?: { code: number; message: string };
  text?: string;
  isError?: boolean;
}
interface Driver {
  proc: ChildProcess;
  rpc: (method: string, params?: unknown) => Promise<any>;
  call: (name: string, args?: unknown, omitArguments?: boolean) => Promise<Reply>;
}

async function startServer(extra: Record<string, string>): Promise<Driver> {
  const proc = spawn(TSX, [SERVER], { env: childEnv(extra), stdio: ['pipe', 'pipe', 'pipe'], cwd: resolve(HERE, '..') });
  let buf = '';
  let stderr = '';
  let nextId = 1;
  const waiters = new Map<number, (m: any) => void>();
  proc.stderr!.on('data', (d) => (stderr += d));
  proc.stdout!.on('data', (d) => {
    buf += d;
    let nl: number;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      try {
        const m = JSON.parse(line);
        if (m.id != null && waiters.has(m.id)) {
          waiters.get(m.id)!(m);
          waiters.delete(m.id);
        }
      } catch {
        /* not a protocol line */
      }
    }
  });
  const rpc = (method: string, params?: unknown): Promise<any> =>
    new Promise((res, rej) => {
      const id = nextId++;
      waiters.set(id, res);
      proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) }) + '\n');
      setTimeout(() => {
        if (waiters.delete(id)) rej(new Error(`rpc timeout ${method}; stderr=${stderr}`));
      }, 20000);
    });
  await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const call = async (name: string, args?: unknown, omitArguments = false): Promise<Reply> => {
    const m = await rpc('tools/call', omitArguments ? { name } : { name, arguments: args });
    if (m.error) return { error: m.error };
    return { text: String(m.result?.content?.[0]?.text ?? ''), isError: m.result?.isError === true };
  };
  return { proc, rpc, call };
}

const HEX = (b: string): string => b.repeat(32);
/** Values for the REQUIRED fields only; everything optional is what each style varies. */
const REQUIRED: Record<string, unknown> = {
  content: 'remember this',
  id: HEX('aa'),
  cellId: HEX('aa'),
  recipientHex: HEX('bb'),
  recipientPinnedAgentIdHashHex: HEX('bb'),
  recipientRecord: { mldsaPubKey: 'cc', mlkemPubKey: 'dd', mlkemPubKeySelfSig: 'ee' },
  scope: 'protocol_upgrade',
  proposalId: HEX('ff'),
  approve: true,
};

const blankFor = (schema: { type?: string; properties?: Record<string, unknown> }): unknown =>
  schema.type === 'object' ? Object.fromEntries(Object.keys(schema.properties ?? {}).map((k) => [k, ''])) : schema.type === 'boolean' ? '' : '';

test('every optional field of every tool reads null and blank values as absent, and a call without arguments reads as none', async () => {
  const m = startMock();
  await new Promise<void>((r) => m.server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-toolinput-'));
  const d = await startServer({
    HOME: home,
    SAIHM_HOME: home,
    SAIHM_ENDPOINT_URL: m.base() + '/mcp',
    SAIHM_MASTER_SECRET_HEX: HEX('5a'),
    SAIHM_TIER: 'PRO',
    SAIHM_PAYMENT_METHOD: 'stripe',
    SAIHM_SELF_JOIN: '1',
  });
  try {
    const tools: { name: string; inputSchema: { properties?: Record<string, any>; required?: string[] } }[] = (await d.rpc('tools/list', {})).result.tools;
    assert.equal(tools.length, 9, 'the eight protocol tools and saihm_join');
    let covered = 0;
    for (const t of tools) {
      const props = t.inputSchema.properties ?? {};
      const required = t.inputSchema.required ?? [];
      const optional = Object.keys(props).filter((k) => !required.includes(k));
      const base = Object.fromEntries(required.map((k) => [k, REQUIRED[k]]));
      for (const k of required) assert.notEqual(REQUIRED[k], undefined, `${t.name}.${k} needs a value in REQUIRED`);
      const styles: [string, unknown, boolean][] = [
        ['null', { ...base, ...Object.fromEntries(optional.map((k) => [k, null])) }, false],
        ['blank', { ...base, ...Object.fromEntries(optional.map((k) => [k, blankFor(props[k])])) }, false],
        ['whitespace', { ...base, ...Object.fromEntries(optional.map((k) => [k, props[k].type === 'object' ? { [Object.keys(props[k].properties)[0]]: ' ' } : ' \t'])) }, false],
      ];
      if (required.length === 0) styles.push(['arguments left out', undefined, true], ['arguments null', null, false]);
      await d.call(t.name, base); // first-call notes (onboard, cache) land here, not in the comparison
      const methodsBefore = m.methods.length;
      const omitted = await d.call(t.name, base);
      const omittedMethods = m.methods.slice(methodsBefore);
      assert.equal(omitted.error, undefined, `${t.name} omitted: ${JSON.stringify(omitted.error)}`);
      for (const [label, args, omitArguments] of styles) {
        const at = m.methods.length;
        const r = await d.call(t.name, args, omitArguments);
        assert.equal(r.error, undefined, `${t.name} ${label}: JSON-RPC error ${JSON.stringify(r.error)}`);
        assert.equal(r.text, omitted.text, `${t.name} ${label}`);
        assert.equal(r.isError, omitted.isError, `${t.name} ${label}`);
        assert.deepEqual(m.methods.slice(at), omittedMethods, `${t.name} ${label}: the bridge saw a different call`);
        covered++;
      }
    }
    assert.ok(covered >= 9 * 3, `covered ${covered}`);
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => m.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
});

test('a host that fills every field loads its own memories: recall with every field null or blank is an own recall', async () => {
  const m = startMock();
  await new Promise<void>((r) => m.server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-toolinput-'));
  const d = await startServer({
    HOME: home,
    SAIHM_HOME: home,
    SAIHM_ENDPOINT_URL: m.base() + '/mcp',
    SAIHM_MASTER_SECRET_HEX: HEX('5b'),
    SAIHM_TIER: 'PRO',
    SAIHM_PAYMENT_METHOD: 'stripe',
    SAIHM_SELF_JOIN: '0',
  });
  try {
    const record = { mldsaPubKey: '', mlkemPubKey: '', mlkemPubKeySelfSig: '' };
    for (const args of [
      { query: '', sharerPinnedAgentIdHashHex: '', sharerRecord: record, cellId: '', shareEntries: false },
      { query: null, sharerPinnedAgentIdHashHex: null, sharerRecord: null, cellId: null, shareEntries: null },
    ]) {
      const n = m.recalls.length;
      const r = await d.call('saihm_recall', args);
      assert.equal(r.error, undefined, JSON.stringify(r.error));
      assert.equal(r.isError, false, r.text);
      assert.equal(m.recalls.length, n + 1, 'one recall reached the bridge');
      assert.equal(m.recalls[n]!.sharer, undefined, 'an own recall, not a shared read');
    }
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => m.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
});

test('a partly given shared read still fails loud, and a value of the wrong type is still refused', async () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-toolinput-'));
  const d = await startServer({
    HOME: home,
    SAIHM_HOME: home,
    SAIHM_ENDPOINT_URL: 'http://127.0.0.1:9/mcp',
    SAIHM_MASTER_SECRET_HEX: HEX('5c'),
    SAIHM_TIER: 'PRO',
    SAIHM_PAYMENT_METHOD: 'stripe',
    SAIHM_SELF_JOIN: '0',
  });
  try {
    const together = /provide sharerPinnedAgentIdHashHex, sharerRecord, and cellId together/;
    for (const args of [
      { sharerPinnedAgentIdHashHex: '', sharerRecord: { mldsaPubKey: 'aa', mlkemPubKey: '', mlkemPubKeySelfSig: '' }, cellId: '' },
      { sharerPinnedAgentIdHashHex: null, sharerRecord: null, cellId: HEX('ab') },
      { sharerPinnedAgentIdHashHex: HEX('cd'), sharerRecord: { mldsaPubKey: '', mlkemPubKey: '', mlkemPubKeySelfSig: '' }, cellId: HEX('ab') },
      { sharerPinnedAgentIdHashHex: HEX('cd'), sharerRecord: null, cellId: '  ' },
    ]) {
      const r = await d.call('saihm_recall', args);
      assert.equal(r.isError, true, JSON.stringify(args));
      assert.match(r.text ?? '', together, JSON.stringify(args));
    }
    for (const [name, args] of [
      ['saihm_recall', { query: 5 }],
      ['saihm_recall', { shareEntries: 'yes' }],
      ['saihm_remember', { content: 'x', cellId: 7 }],
      ['saihm_share', { ...REQUIRED, scope: 'everything' }],
      ['saihm_share', { ...REQUIRED, scope: 'read', expiryEpoch: 'soon' }],
      ['saihm_share', { ...REQUIRED, scope: 'read', expiryEpoch: {} }],
      ['saihm_share', { ...REQUIRED, scope: {} }],
      ['saihm_recall', { query: {} }],
      ['saihm_remember', { content: null }],
    ] as const) {
      const r = await d.call(name, args);
      const refused = r.error !== undefined || (r.isError === true && /Input validation error/.test(r.text ?? ''));
      assert.ok(refused, `${name} ${JSON.stringify(args)} -> ${JSON.stringify(r)}`);
    }
  } finally {
    d.proc.kill();
    rmSync(home, { recursive: true, force: true });
  }
});

test('the schemas a host is shown are the plain ones: every optional field has its type and no null branch', async () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-toolinput-'));
  const d = await startServer({ HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: 'http://127.0.0.1:9/mcp', SAIHM_SELF_JOIN: '1' });
  try {
    const tools: { name: string; inputSchema: { properties?: Record<string, any>; required?: string[] } }[] = (await d.rpc('tools/list', {})).result.tools;
    const required = Object.fromEntries(tools.map((t) => [t.name, [...(t.inputSchema.required ?? [])].sort()]));
    assert.deepEqual(required, {
      saihm_remember: ['content'],
      saihm_recall: [],
      saihm_forget: ['id'],
      saihm_status: [],
      saihm_share: ['cellId', 'recipientPinnedAgentIdHashHex', 'recipientRecord'],
      saihm_revoke_share: ['cellId', 'recipientHex'],
      saihm_governance_propose: ['scope'],
      saihm_governance_vote: ['approve', 'proposalId'],
      saihm_join: [],
    });
    const types: Record<string, string> = {};
    for (const t of tools) {
      for (const [k, s] of Object.entries(t.inputSchema.properties ?? {})) {
        assert.equal(s.anyOf, undefined, `${t.name}.${k}`);
        assert.equal(typeof s.type, 'string', `${t.name}.${k} advertises one type: ${JSON.stringify(s)}`);
        if (!(t.inputSchema.required ?? []).includes(k)) types[`${t.name}.${k}`] = s.enum ? `${s.type}:${s.enum.join('|')}` : s.pattern ? `${s.type}:${s.pattern}` : s.type;
      }
    }
    assert.deepEqual(types, {
      'saihm_remember.cellId': 'string',
      'saihm_recall.query': 'string',
      'saihm_recall.sharerPinnedAgentIdHashHex': 'string',
      'saihm_recall.sharerRecord': 'object',
      'saihm_recall.cellId': 'string',
      'saihm_recall.shareEntries': 'boolean',
      'saihm_share.scope': 'string:read|write|readwrite',
      'saihm_share.expiryEpoch': 'string:^[0-9]+$',
      'saihm_governance_propose.paramKey': 'string',
      'saihm_governance_propose.proposedValue': 'string',
      'saihm_join.newIdentity': 'boolean',
    });
  } finally {
    d.proc.kill();
    rmSync(home, { recursive: true, force: true });
  }
});

test('saihm_join without an identity: a null or blank newIdentity, or no arguments, asks first and creates nothing', async () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-toolinput-'));
  const d = await startServer({ HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: 'http://127.0.0.1:9/mcp', SAIHM_SELF_JOIN: '1' });
  try {
    const asked = await d.call('saihm_join', {});
    assert.match(asked.text ?? '', /newIdentity: true/);
    for (const [args, omit] of [[{ newIdentity: null }, false], [{ newIdentity: '' }, false], [{ newIdentity: '  ' }, false], [undefined, true], [null, false]] as const) {
      const r = await d.call('saihm_join', args, omit);
      assert.equal(r.error, undefined, JSON.stringify(r.error));
      assert.equal(r.text, asked.text, JSON.stringify(args));
      assert.equal(r.isError, asked.isError);
    }
    assert.deepEqual(readdirSync(home), [], 'nothing was written: no key, no tenant directory');
    assert.ok(!existsSync(join(home, 'free-identity.key')));
  } finally {
    d.proc.kill();
    rmSync(home, { recursive: true, force: true });
  }
});
