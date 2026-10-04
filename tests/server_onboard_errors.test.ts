// What a subscriber reads when the endpoint refuses for a reason that is not a configuration error: a limit (429) and
// a join still waiting for the human's approval. A 429 that carries no code - the edge's own limit sends only
// `retry-after` - is `rate_limited`, with the wait; one that carries a code keeps it. While this server's join waits,
// the memory tools give the join's own steps and do not onboard, which would be refused and would count against the
// endpoint's onboard limit.
// Runner: npx tsx --test tests/server_onboard_errors.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SaihmEndpointError, SaihmProClient } from '../src/client.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const seg = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
const PROXY_VARS = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY', 'no_proxy', 'NO_PROXY'];

async function listen(handler: (url: string, body: string, res: import('node:http').ServerResponse) => void): Promise<{ server: Server; base: string }> {
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => handler(`${req.method} ${req.url}`, body, res));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  return { server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

const jwt = (): string => `${seg({ alg: 'EdDSA' })}.${seg({ sub: 'x', tier: 'PRO', exp: Math.floor(Date.now() / 1000) + 3600 })}.sig`;

async function statusError(base: string): Promise<SaihmEndpointError> {
  const saved = PROXY_VARS.map((k) => [k, process.env[k]] as const);
  for (const k of PROXY_VARS) delete process.env[k];
  try {
    const c = new SaihmProClient(`${base}/mcp`, undefined, new Uint8Array(32).fill(9), { tier: 'PRO', paymentMethod: 'stripe' });
    const e = await c.status().then(() => null, (err: unknown) => err);
    assert.ok(e instanceof SaihmEndpointError, String(e));
    return e;
  } finally {
    for (const [k, v] of saved) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

test('a 429 with no code is rate_limited, with the wait it asks for; a 429 with a code keeps it', async () => {
  for (const [headers, wait] of [
    [{ 'retry-after': '10' }, '10 seconds'],
    [{ 'retry-after': ' 3 ' }, '3 seconds'],
    [{}, 'a minute'],
    [{ 'retry-after': 'Wed, 21 Oct 2026 07:28:00 GMT' }, 'a minute'],
    [{ 'retry-after': '1234567' }, 'a minute'],
    [{ 'retry-after': '1' }, '1 second'],
    [{ 'retry-after': '0' }, 'a moment'],
  ] as const) {
    const m = await listen((route, _b, res) => {
      if (route === 'GET /api/onboard/challenge') return void res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ nonce: '00'.repeat(32) }));
      res.writeHead(429, { 'content-length': '0', ...headers }).end();
    });
    try {
      const e = await statusError(m.base);
      assert.equal(e.status, 429);
      assert.equal(e.code, 'rate_limited');
      assert.equal(e.message, `SAIHM onboard failed: 429 Too Many Requests. Wait ${wait}, then try again.`);
    } finally {
      await new Promise<void>((r) => m.server.close(() => r()));
    }
  }
  // A coded 429 is the endpoint's own answer (the free tier's lifetime cap, for one), and keeps its code.
  const coded = await listen((route, _b, res) => {
    if (route === 'GET /api/onboard/challenge') return void res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ nonce: '00'.repeat(32) }));
    res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '10' }).end(JSON.stringify({ error: 'quota_hard_cap' }));
  });
  try {
    const e = await statusError(coded.base);
    assert.equal(e.code, 'quota_hard_cap');
    assert.equal(e.message, 'SAIHM onboard failed: 429 Too Many Requests (quota_hard_cap)');
  } finally {
    await new Promise<void>((r) => coded.server.close(() => r()));
  }
  // The call path, after a good onboard: the same naming.
  const call = await listen((route, _b, res) => {
    if (route === 'GET /api/onboard/challenge') return void res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ nonce: '00'.repeat(32) }));
    if (route === 'POST /api/onboard') return void res.writeHead(201, { 'content-type': 'application/json' }).end(JSON.stringify({ jwt: jwt() }));
    res.writeHead(429, { 'content-length': '0', 'retry-after': '7' }).end();
  });
  try {
    const e = await statusError(call.base);
    assert.equal(e.code, 'rate_limited');
    assert.equal(e.message, 'SAIHM endpoint saihm_status failed: 429 Too Many Requests. Wait 7 seconds, then try again.');
  } finally {
    await new Promise<void>((r) => call.server.close(() => r()));
  }
});

// ---- the server: memory tools while its join waits ----

function childEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const keep: NodeJS.ProcessEnv = {};
  for (const k of ['PATH', 'SYSTEMROOT', 'TEMP', 'TMP', 'TMPDIR']) if (process.env[k] !== undefined) keep[k] = process.env[k];
  return { ...keep, ...extra };
}

async function startServer(extra: Record<string, string>) {
  const proc: ChildProcess = spawn(TSX, [SERVER], { env: childEnv(extra), stdio: ['pipe', 'pipe', 'pipe'], cwd: resolve(HERE, '..') });
  let buf = '';
  let nextId = 1;
  const waiters = new Map<number, (m: any) => void>();
  proc.stdout!.on('data', (d) => {
    buf += d;
    let nl: number;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      try {
        const m = JSON.parse(line);
        waiters.get(m.id)?.(m);
      } catch {
        /* not a protocol line */
      }
    }
  });
  const rpc = (method: string, params: unknown): Promise<any> =>
    new Promise((res, rej) => {
      const id = nextId++;
      waiters.set(id, res);
      proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      setTimeout(() => rej(new Error(`rpc timeout ${method}`)), 30000);
    });
  await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const call = async (name: string, args: unknown) => {
    const m = await rpc('tools/call', { name, arguments: args });
    return { text: String(m.result.content[0].text), isError: m.result.isError === true };
  };
  return { proc, call };
}

test('while the join waits for approval, the memory tools give its steps and do not onboard; once approved they work', async () => {
  let grant = false;
  const seen: string[] = [];
  const m = await listen((route, body, res) => {
    seen.push(route);
    const send = (s: number, b: unknown) => void res.writeHead(s, { 'content-type': 'application/json' }).end(JSON.stringify(b));
    if (route === 'GET /api/onboard/challenge') return send(200, { nonce: '11'.repeat(32) });
    if (route === 'POST /api/free-onboard/start')
      return send(200, { flowId: 'flow-1', userCode: 'WXYZ-9876', verificationUri: 'https://device.test/activate', expiresIn: 900, interval: 1 });
    if (route === 'POST /api/free-onboard/claim') {
      const pubkey = (JSON.parse(body) as { pubkey?: string }).pubkey ?? '';
      return send(200, grant ? { status: 'granted', agentIdHash: 'ab'.repeat(32), pubkey } : { status: 'pending' });
    }
    if (route === 'POST /api/onboard') return send(201, { jwt: jwt() });
    if (route === 'POST /mcp') return send(200, []);
    return send(404, { error: 'not_found' });
  });
  const home = mkdtempSync(join(tmpdir(), 'saihm-oberr-'));
  const d = await startServer({ HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: `${m.base}/mcp` });
  try {
    const started = await d.call('saihm_join', { newIdentity: true });
    assert.match(started.text, /WXYZ-9876/, started.text);
    const before = seen.filter((r) => r === 'POST /api/onboard' || r === 'POST /mcp').length;
    for (const [name, args] of [['saihm_status', {}], ['saihm_recall', {}], ['saihm_remember', { content: 'x' }]] as const) {
      const r = await d.call(name, args);
      assert.equal(r.isError, true, `${name}: ${r.text}`);
      assert.match(r.text, /^SAIHM memory is not active yet: the join is waiting for approval\.\nTo activate your free SAIHM memory, in a browser:\n {2}1\. open {3}https:\/\/device\.test\/activate\n {2}2\. enter {2}WXYZ-9876\n/, `${name}: ${r.text}`);
    }
    assert.equal(seen.filter((r) => r === 'POST /api/onboard' || r === 'POST /mcp').length, before, 'no onboard and no call while the join waits');
    // Approved: the join finishes, and the memory tools reach the endpoint.
    grant = true;
    let done = '';
    for (let i = 0; i < 20 && !/You're in/.test(done); i++) {
      await new Promise((r) => setTimeout(r, 500));
      done = (await d.call('saihm_join', {})).text;
    }
    assert.match(done, /You're in/, done);
    const recall = await d.call('saihm_recall', {});
    assert.equal(recall.isError, false, recall.text);
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => m.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
});

async function joinAndRecall(onboardStatus: number, onboardBody: unknown): Promise<{ joined: string; recall: { text: string; isError: boolean }; onboards: number }> {
  let onboards = 0;
  const m = await listen((route, _body, res) => {
    const send = (s: number, b: unknown) => void res.writeHead(s, { 'content-type': 'application/json' }).end(JSON.stringify(b));
    if (route === 'GET /api/onboard/challenge') return send(200, { nonce: '33'.repeat(32) });
    if (route === 'POST /api/free-onboard/start')
      return send(200, { flowId: 'flow-2', userCode: 'AGIN-2222', verificationUri: 'https://device.test/activate', expiresIn: 900, interval: 1 });
    if (route === 'POST /api/free-onboard/claim') return send(200, { status: 'pending' });
    if (route === 'POST /api/onboard') {
      onboards++;
      return send(onboardStatus, onboardBody);
    }
    if (route === 'POST /mcp') return send(200, []);
    return send(404, { error: 'not_found' });
  });
  const home = mkdtempSync(join(tmpdir(), 'saihm-oberr-'));
  // A key from an earlier join on this machine: this join activates it and creates nothing.
  writeFileSync(join(home, 'free-identity.key'), 'ab'.repeat(32), { mode: 0o600 });
  const d = await startServer({ HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: `${m.base}/mcp` });
  try {
    const joined = (await d.call('saihm_join', {})).text;
    const recall = await d.call('saihm_recall', {});
    return { joined, recall, onboards };
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => m.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
}

test('a second join of an identity that is already active leaves its memory tools working', async () => {
  const r = await joinAndRecall(201, { jwt: jwt() });
  assert.match(r.joined, /AGIN-2222/, r.joined);
  assert.equal(r.recall.isError, false, r.recall.text);
  assert.ok(r.onboards >= 1, 'the memory tool onboarded as usual');
});

test('an identity with no free memory yet, while its join waits, answers with the join steps instead of the refusal', async () => {
  const r = await joinAndRecall(401, { error: 'verification_failed', reason: 'no_free_entitlement' });
  assert.equal(r.recall.isError, true);
  assert.match(r.recall.text, /^SAIHM memory is not active yet: the join is waiting for approval\.\nTo activate your free SAIHM memory, in a browser:\n/, r.recall.text);
  assert.match(r.recall.text, /AGIN-2222/);
});

test('before the join has its steps, and after it has failed, the memory tools say which', async () => {
  let startDelayMs = 20_000;
  let onboards = 0;
  const m = await listen((route, _body, res) => {
    const send = (s: number, b: unknown) => void res.writeHead(s, { 'content-type': 'application/json' }).end(JSON.stringify(b));
    if (route === 'GET /api/onboard/challenge') return send(200, { nonce: '44'.repeat(32) });
    if (route === 'POST /api/free-onboard/start') {
      if (startDelayMs === 0) return send(500, { error: 'start_failed' });
      return void setTimeout(() => send(500, { error: 'start_failed' }), startDelayMs);
    }
    if (route === 'POST /api/onboard') {
      onboards++;
      return send(401, { error: 'verification_failed', reason: 'no_free_entitlement' });
    }
    return send(404, { error: 'not_found' });
  });
  const home = mkdtempSync(join(tmpdir(), 'saihm-oberr-'));
  const d = await startServer({ HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: `${m.base}/mcp` });
  try {
    // No steps yet: the join answers after its own wait, and a memory tool asks for patience, without the endpoint.
    const first = await d.call('saihm_join', { newIdentity: true });
    assert.match(first.text, /Starting your free activation|Still getting your activation ready/, first.text);
    const early = await d.call('saihm_status', {});
    assert.equal(early.isError, true);
    assert.equal(early.text, 'SAIHM memory is not active yet: the join is waiting for approval.\nAsk me to "Join SAIHM" again in a few seconds for the steps.');
    assert.equal(onboards, 0, 'no onboard while the join has no steps yet');
    // The start fails: the join is over, and the memory tools report the endpoint's answer, not a wait.
    const until = Date.now() + 30_000;
    let after = await d.call('saihm_status', {});
    while (after.text.startsWith('SAIHM memory is not active yet') && Date.now() < until) {
      await new Promise((r) => setTimeout(r, 500));
      after = await d.call('saihm_status', {});
    }
    assert.ok(!after.text.startsWith('SAIHM memory is not active yet'), after.text);
    assert.ok(onboards >= 1, 'once the join has ended, the memory tools reach the endpoint again');
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => m.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
});

test('a join retried after its first attempt failed asks the endpoint once about the key, then answers with the steps', async () => {
  let starts = 0;
  let onboards = 0;
  const m = await listen((route, _body, res) => {
    const send = (s: number, b: unknown) => void res.writeHead(s, { 'content-type': 'application/json' }).end(JSON.stringify(b));
    if (route === 'GET /api/onboard/challenge') return send(200, { nonce: '66'.repeat(32) });
    if (route === 'POST /api/free-onboard/start') {
      starts++;
      if (starts === 1) return send(500, { error: 'start_failed' });
      return send(200, { flowId: 'flow-3', userCode: 'RETR-3333', verificationUri: 'https://device.test/activate', expiresIn: 900, interval: 1 });
    }
    if (route === 'POST /api/free-onboard/claim') return send(200, { status: 'pending' });
    if (route === 'POST /api/onboard') {
      onboards++;
      return send(401, { error: 'verification_failed', reason: 'no_free_entitlement' });
    }
    return send(404, { error: 'not_found' });
  });
  const home = mkdtempSync(join(tmpdir(), 'saihm-oberr-'));
  const d = await startServer({ HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: `${m.base}/mcp` });
  try {
    await d.call('saihm_join', { newIdentity: true });
    let second = '';
    for (let i = 0; i < 20 && !/RETR-3333/.test(second); i++) {
      await new Promise((r) => setTimeout(r, 300));
      second = (await d.call('saihm_join', {})).text;
    }
    assert.match(second, /RETR-3333/, second);
    const before = onboards;
    const r = await d.call('saihm_status', {});
    assert.match(r.text, /^SAIHM memory is not active yet: the join is waiting for approval\./, r.text);
    assert.equal(onboards, before + 1, 'a key left by the failed first join is asked about once: it may have been granted');
    const again = await d.call('saihm_status', {});
    assert.match(again.text, /^SAIHM memory is not active yet/, again.text);
    assert.equal(onboards, before + 1, 'and not again for the rest of this join');
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => m.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
});

test('while a join waits, a 401 for another reason is reported as itself, not as the wait', async () => {
  const r = await joinAndRecall(401, { error: 'verification_failed', reason: 'bad_signature' });
  assert.equal(r.recall.isError, true);
  assert.doesNotMatch(r.recall.text, /SAIHM memory is not active yet/, r.recall.text);
  assert.match(r.recall.text, /bad_signature/, r.recall.text);
});

async function joinThenCalls(onboard: (n: number) => { status: number; body?: unknown; headers?: Record<string, string> }, calls: number) {
  let onboards = 0;
  const m = await listen((route, _body, res) => {
    const send = (s: number, b: unknown) => void res.writeHead(s, { 'content-type': 'application/json' }).end(JSON.stringify(b));
    if (route === 'GET /api/onboard/challenge') return send(200, { nonce: '77'.repeat(32) });
    if (route === 'POST /api/free-onboard/start')
      return send(200, { flowId: 'flow-4', userCode: 'LATE-4444', verificationUri: 'https://device.test/activate', expiresIn: 900, interval: 1 });
    if (route === 'POST /api/free-onboard/claim') return send(200, { status: 'pending' });
    if (route === 'POST /api/onboard') {
      const a = onboard(++onboards);
      if (a.body === undefined) return void res.writeHead(a.status, { 'content-length': '0', ...(a.headers ?? {}) }).end();
      return send(a.status, a.body);
    }
    return send(404, { error: 'not_found' });
  });
  const home = mkdtempSync(join(tmpdir(), 'saihm-oberr-'));
  // A key left by an earlier session: this process did not create it.
  writeFileSync(join(home, 'free-identity.key'), 'cd'.repeat(32), { mode: 0o600 });
  const d = await startServer({ HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: `${m.base}/mcp` });
  try {
    await d.call('saihm_join', {});
    const texts: string[] = [];
    for (let i = 0; i < calls; i++) texts.push((await d.call('saihm_status', {})).text);
    return { texts, onboards };
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => m.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
}

test('a key from an earlier session: after the first "no free memory yet" during the join, later calls do not ask the endpoint again', async () => {
  const r = await joinThenCalls(() => ({ status: 401, body: { error: 'verification_failed', reason: 'no_free_entitlement' } }), 3);
  for (const t of r.texts) assert.match(t, /^SAIHM memory is not active yet: the join is waiting for approval\.\nTo activate/, t);
  assert.equal(r.onboards, 1, 'one onboard, then the join answers for itself');
});

test('a rate limit during a join answers with the join steps, then the wait', async () => {
  const r = await joinThenCalls(() => ({ status: 429, headers: { 'retry-after': '10' } }), 1);
  assert.match(r.texts[0]!, /^SAIHM memory is not active yet: the join is waiting for approval\.\nTo activate/, r.texts[0]);
  assert.match(r.texts[0]!, /rate_limited/, r.texts[0]);
  assert.match(r.texts[0]!, /Wait 10 seconds, then try again\./, r.texts[0]);
});

type Answer = { status: number; body?: unknown; headers?: Record<string, string> };

// A join against an endpoint scripted per route (`answer` returns undefined for the default): of a key left by an
// earlier session, or of a new one (`newKey`); `run` drives the memory tools and may approve the join.
async function earlierKeyJoin(
  answer: (route: string, n: { onboard: number; mcp: number; start: number }) => Answer | undefined,
  run: (d: { call: (name: string, args: unknown) => Promise<{ text: string; isError: boolean }>; grant: () => void; n: { onboard: number; mcp: number; start: number } }) => Promise<void>,
  opts: { newKey?: boolean } = {},
) {
  let granted = false;
  const n = { onboard: 0, mcp: 0, start: 0 };
  const m = await listen((route, body, res) => {
    const reply = (a: Answer) =>
      a.body === undefined
        ? void res.writeHead(a.status, { 'content-length': '0', ...(a.headers ?? {}) }).end()
        : void res.writeHead(a.status, { 'content-type': 'application/json', ...(a.headers ?? {}) }).end(JSON.stringify(a.body));
    if (route === 'POST /api/onboard') n.onboard++;
    if (route === 'POST /mcp') n.mcp++;
    if (route === 'POST /api/free-onboard/start') n.start++;
    const scripted = answer(route, n);
    if (scripted) return reply(scripted);
    if (route === 'GET /api/onboard/challenge') return reply({ status: 200, body: { nonce: '88'.repeat(32) } });
    if (route === 'POST /api/free-onboard/start')
      return reply({ status: 200, body: { flowId: 'flow-5', userCode: 'NEXT-5555', verificationUri: 'https://device.test/activate', expiresIn: 900, interval: 1 } });
    if (route === 'POST /api/free-onboard/claim') {
      const pubkey = (JSON.parse(body) as { pubkey?: string }).pubkey ?? '';
      return reply({ status: 200, body: granted ? { status: 'granted', agentIdHash: 'ab'.repeat(32), pubkey } : { status: 'pending' } });
    }
    if (route === 'POST /api/onboard') return reply({ status: 201, body: { jwt: jwt() } });
    if (route === 'POST /mcp') return reply({ status: 200, body: [] });
    return reply({ status: 404, body: { error: 'not_found' } });
  });
  const home = mkdtempSync(join(tmpdir(), 'saihm-oberr-'));
  if (opts.newKey !== true) writeFileSync(join(home, 'free-identity.key'), 'ef'.repeat(32), { mode: 0o600 });
  const d = await startServer({ HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: `${m.base}/mcp` });
  try {
    await d.call('saihm_join', opts.newKey === true ? { newIdentity: true } : {});
    await run({ call: d.call, grant: () => void (granted = true), n });
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => m.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
}

const notActive = /^SAIHM memory is not active yet/;

test('an active identity joined again: a rate limit on a memory call is reported as itself, not as the join', async () => {
  await earlierKeyJoin(
    (route) => (route === 'POST /mcp' ? { status: 429, headers: { 'retry-after': '7' } } : undefined),
    async ({ call }) => {
      const r = await call('saihm_status', {});
      assert.equal(r.isError, true, r.text);
      assert.doesNotMatch(r.text, notActive, r.text);
      assert.match(r.text, /rate_limited/, r.text);
      assert.match(r.text, /Wait 7 seconds, then try again\./, r.text);
    },
  );
});

test('refused once during the join, then approved: the memory tools work again', async () => {
  await earlierKeyJoin(
    (route, n) => (route === 'POST /api/onboard' && n.onboard === 1 ? { status: 401, body: { error: 'verification_failed', reason: 'no_free_entitlement' } } : undefined),
    async ({ call, grant }) => {
      const waiting = await call('saihm_status', {});
      assert.match(waiting.text, notActive, waiting.text);
      grant();
      let done = '';
      for (let i = 0; i < 20 && !/You're in/.test(done); i++) {
        await new Promise((r) => setTimeout(r, 500));
        done = (await call('saihm_join', {})).text;
      }
      assert.match(done, /You're in/, done);
      const recall = await call('saihm_recall', {});
      assert.equal(recall.isError, false, recall.text);
      assert.doesNotMatch(recall.text, notActive, recall.text);
    },
  );
});

test('after a join has finished, a rate limit on the onboard is reported as itself, not as the join', async () => {
  let joined = false;
  await earlierKeyJoin(
    (route) => (route === 'POST /api/onboard' && joined ? { status: 429, headers: { 'retry-after': '9' } } : undefined),
    async ({ call, grant, n }) => {
      grant();
      let done = '';
      for (let i = 0; i < 20 && !/You're in/.test(done); i++) {
        await new Promise((r) => setTimeout(r, 500));
        done = (await call('saihm_join', {})).text;
      }
      assert.match(done, /You're in/, done);
      joined = true;
      const before = n.onboard;
      const r = await call('saihm_status', {});
      assert.ok(n.onboard > before, 'the call after the join onboards, so the limit is the onboard one');
      assert.equal(r.isError, true, r.text);
      assert.doesNotMatch(r.text, notActive, r.text);
      assert.match(r.text, /rate_limited/, r.text);
      assert.match(r.text, /Wait 9 seconds, then try again\./, r.text);
    },
    { newKey: true },
  );
});

test('a key from a failed first join that was granted after all: on the retried join, the memory tools work', async () => {
  let starts = 0;
  const m = await listen((route, _body, res) => {
    const send = (s: number, b: unknown) => void res.writeHead(s, { 'content-type': 'application/json' }).end(JSON.stringify(b));
    if (route === 'GET /api/onboard/challenge') return send(200, { nonce: '99'.repeat(32) });
    if (route === 'POST /api/free-onboard/start') {
      starts++;
      if (starts === 1) return send(500, { error: 'start_failed' });
      return send(200, { flowId: 'flow-6', userCode: 'GRNT-6666', verificationUri: 'https://device.test/activate', expiresIn: 900, interval: 1 });
    }
    if (route === 'POST /api/free-onboard/claim') return send(200, { status: 'pending' });
    if (route === 'POST /api/onboard') return send(201, { jwt: jwt() });
    if (route === 'POST /mcp') return send(200, []);
    return send(404, { error: 'not_found' });
  });
  const home = mkdtempSync(join(tmpdir(), 'saihm-oberr-'));
  const d = await startServer({ HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: `${m.base}/mcp` });
  try {
    await d.call('saihm_join', { newIdentity: true });
    let second = '';
    for (let i = 0; i < 20 && !/GRNT-6666/.test(second); i++) {
      await new Promise((r) => setTimeout(r, 300));
      second = (await d.call('saihm_join', {})).text;
    }
    assert.match(second, /GRNT-6666/, second);
    const recall = await d.call('saihm_recall', {});
    assert.equal(recall.isError, false, recall.text);
    assert.doesNotMatch(recall.text, /^SAIHM memory is not active yet/, recall.text);
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => m.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
});
