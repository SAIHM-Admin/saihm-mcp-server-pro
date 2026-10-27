// One sign-in per device per hour (0.14.3), through the real stdio server against a mock bridge that verifies every
// sign-in and records the token each memory call carries. With the default key file, a session keeps its sign-in in
// SAIHM_HOME and the next session on this device uses it while it is good: one sign-in, not one per session. A token
// kept for another endpoint, plan or identity, an expired one, and one the endpoint refuses are never used again; a
// refused one is removed. SAIHM_SESSION_CACHE=0, an inline secret and a key file elsewhere sign in each session, as
// before. The token never appears in a result, an error or the server's log.
// Runner: npx tsx --test tests/server_session_token.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { deriveIdentity, fromHex, toHex } from '@saihm/client-pro';
import { SessionTokenFile } from '../src/session-token-file.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const POSIX = process.platform !== 'win32';
const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');

function childEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const keep: NodeJS.ProcessEnv = {};
  for (const k of ['PATH', 'SYSTEMROOT', 'TEMP', 'TMP', 'TMPDIR']) if (process.env[k] !== undefined) keep[k] = process.env[k];
  return { ...keep, ...extra };
}

interface Mock {
  server: Server;
  url: () => string;
  /** Sign-ins completed (a POST /api/onboard answered with a token). */
  signIns: () => number;
  /** Every token the bridge issued, in order. */
  issued: string[];
  /** The token each memory call carried, in order. */
  used: string[];
  /** Tokens this bridge now refuses with a 401. */
  refuse: Set<string>;
  /** The lifetime of the tokens it issues, in seconds. */
  ttlS: { value: number };
  /** Refuse every token, issued or not (an ended plan, say). */
  refuseAll: { value: boolean };
}

/** A bridge that verifies each sign-in, issues a distinct token each time, and answers saihm_status. */
function startMock(): Mock {
  let lastNonce = '';
  let signIns = 0;
  const issued: string[] = [];
  const used: string[] = [];
  const refuse = new Set<string>();
  const ttlS = { value: 3600 };
  const refuseAll = { value: false };
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
        lastNonce = randomBytes(32).toString('hex');
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
          ok = ml_dsa65.verify(fromHex(j.signature ?? ''), fromHex(j.nonce ?? ''), fromHex(j.pubkey ?? ''));
        } catch {
          ok = false;
        }
        if (!ok) return send(401, { error: 'bad_signature' });
        signIns++;
        const token = `${b64url({ alg: 'EdDSA' })}.${b64url({ sub: j.pubkey, tier: j.tier, exp: Math.floor(Date.now() / 1000) + ttlS.value, jti: randomBytes(8).toString('hex') })}.${randomBytes(24).toString('base64url')}`;
        issued.push(token);
        return send(201, { jwt: token });
      }
      if (req.method === 'POST' && url === '/mcp') {
        const auth = String(req.headers.authorization ?? '');
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
        used.push(token);
        if (!issued.includes(token) || refuse.has(token) || refuseAll.value) return send(401, { error: 'invalid_token' });
        if (j.method === 'saihm_status')
          return send(200, { agentIdHashHex: 'deadbeefcafebabe0011', tier: 'PRO', activeShardCount: 1, activeSharingContracts: 0, bfsi: 0.5, snapshotEpoch: '495000', custody: 'SAIHM' });
        return send(404, { error: 'unknown_method' });
      }
      return send(404, { error: 'not_found' });
    });
  });
  return { server, url: () => `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`, signIns: () => signIns, issued, used, refuse, ttlS, refuseAll };
}

async function listen(m: Mock): Promise<void> {
  await new Promise<void>((r) => m.server.listen(0, '127.0.0.1', () => r()));
}

async function close(m: Mock): Promise<void> {
  await new Promise<void>((r) => m.server.close(() => r()));
}

interface Session {
  proc: ChildProcess;
  stderr: () => string;
  /** saihm_status: its text and whether it failed. */
  status: () => Promise<{ text: string; isError: boolean; raw: string }>;
  /** The names of the tools the server lists. */
  tools: () => Promise<string[]>;
  stop: () => Promise<void>;
}

async function session(env: Record<string, string>): Promise<Session> {
  const proc = spawn(TSX, [SERVER], { env: childEnv(env), stdio: ['pipe', 'pipe', 'pipe'], cwd: resolve(HERE, '..') });
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
          waiters.get(m.id)!({ ...m, raw: line });
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
      }, 60000);
    });
  await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  return {
    proc,
    stderr: () => stderr,
    status: async () => {
      const m = await rpc('tools/call', { name: 'saihm_status', arguments: {} });
      return { text: String(m.result?.content?.[0]?.text ?? ''), isError: m.result?.isError === true, raw: String(m.raw) };
    },
    tools: async () => ((await rpc('tools/list', {})).result?.tools ?? []).map((t: { name: string }) => t.name),
    stop: async () => {
      if (proc.exitCode === null) {
        const exited = new Promise<void>((r) => proc.once('exit', () => r()));
        proc.kill();
        await exited;
      }
    },
  };
}

interface Device {
  dir: string;
  home: string;
  agentIdHash: string;
  keptPath: string;
  env: (mock: Mock, extra?: Record<string, string>) => Record<string, string>;
  /** Everything the sessions printed and returned, for the search for a token. */
  shown: string[];
}

/** A device whose default key file is in SAIHM_HOME, as a join leaves it. */
function device(): Device {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-signin-'));
  const home = join(dir, 'home');
  mkdirSync(home, { mode: 0o700 });
  const secretHex = randomBytes(32).toString('hex');
  writeFileSync(join(home, 'free-identity.key'), secretHex, { mode: 0o600 });
  const agentIdHash = toHex(deriveIdentity(fromHex(secretHex)).agentIdHash);
  return {
    dir,
    home,
    agentIdHash,
    keptPath: join(home, `session.${agentIdHash.slice(0, 16)}.json`),
    env: (mock, extra = {}) => ({ HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: mock.url(), ...extra }),
    shown: [],
  };
}

/** One session: start, one memory call, stop. Returns the call's text. */
async function oneSession(d: Device, env: Record<string, string>): Promise<{ text: string; isError: boolean }> {
  const s = await session(env);
  try {
    const r = await s.status();
    d.shown.push(r.text, r.raw);
    return r;
  } finally {
    await s.stop();
    d.shown.push(s.stderr());
  }
}

const keptToken = (path: string): string | undefined => {
  try {
    return (JSON.parse(readFileSync(path, 'utf8')) as { token?: string }).token;
  } catch {
    return undefined;
  }
};

function assertNoTokenShown(d: Device, m: Mock): void {
  assert.ok(m.issued.length > 0, 'positive control: tokens were issued');
  const all = d.shown.join('\n');
  for (const t of m.issued) {
    assert.ok(!all.includes(t), 'no token in a result, an error or the log');
    assert.ok(!all.includes(t.split('.')[2]!), 'nor its signature');
  }
}

test('a second session on this device uses the first one\'s sign-in, kept in SAIHM_HOME at mode 600', async () => {
  const m = startMock();
  await listen(m);
  const d = device();
  try {
    const first = await oneSession(d, d.env(m));
    assert.equal(first.isError, false, first.text);
    assert.equal(m.signIns(), 1);
    assert.equal(keptToken(d.keptPath), m.issued[0]);
    if (POSIX) assert.equal(statSync(d.keptPath).mode & 0o777, 0o600);
    const doc = JSON.parse(readFileSync(d.keptPath, 'utf8'));
    assert.deepEqual(Object.keys(doc).sort(), ['agentIdHash', 'endpoint', 'kind', 'paymentMethod', 'tier', 'token', 'version']);
    assert.equal(doc.agentIdHash, d.agentIdHash);
    assert.equal(doc.endpoint, m.url());
    assert.equal(doc.tier, 'FREE');
    const second = await oneSession(d, d.env(m));
    assert.equal(second.isError, false, second.text);
    assert.equal(m.signIns(), 1, 'no second sign-in');
    assert.deepEqual(m.used, [m.issued[0], m.issued[0]], 'both sessions carried the one token');
    assert.equal(readdirSync(d.home).filter((n) => n.endsWith('.tmp') || n.endsWith('.lock')).length, 0);
    assertNoTokenShown(d, m);
  } finally {
    await close(m);
    rmSync(d.dir, { recursive: true, force: true });
  }
});

test('SAIHM_SESSION_CACHE=0 keeps the sign-in in memory only: nothing is written, nothing kept is read, and the one kept earlier is deleted', async () => {
  const m = startMock();
  await listen(m);
  const d = device();
  try {
    await oneSession(d, d.env(m, { SAIHM_SESSION_CACHE: '0' }));
    await oneSession(d, d.env(m, { SAIHM_SESSION_CACHE: '0' }));
    assert.equal(m.signIns(), 2, 'one sign-in per session, as before');
    assert.equal(existsSync(d.keptPath), false, 'no file');
    // A good kept sign-in is not read either, and the session deletes it (0.14.3 review 3): that file and nothing else.
    await oneSession(d, d.env(m));
    assert.equal(m.signIns(), 3);
    assert.equal(keptToken(d.keptPath), m.issued[2]);
    const key = readFileSync(join(d.home, 'free-identity.key'));
    const otherKept = join(d.home, `session.${'cd'.repeat(8)}.json`);
    const otherDoc = JSON.stringify({ kind: 'saihm-session-token', version: 1, endpoint: m.url(), agentIdHash: 'cd'.repeat(32), tier: 'FREE', paymentMethod: null, token: 'a.b.c' });
    writeFileSync(otherKept, otherDoc, { mode: 0o600 });
    const before = readdirSync(d.home).sort();
    await oneSession(d, d.env(m, { SAIHM_SESSION_CACHE: '0' }));
    assert.equal(m.signIns(), 4, 'switched off, the kept sign-in is not used');
    assert.equal(existsSync(d.keptPath), false, 'and it is deleted');
    assert.deepEqual(readdirSync(d.home).sort(), before.filter((n) => join(d.home, n) !== d.keptPath), 'nothing else in the home changed');
    assert.deepEqual(readFileSync(join(d.home, 'free-identity.key')), key, 'the key is untouched');
    assert.equal(readFileSync(otherKept, 'utf8'), otherDoc, "another identity's kept sign-in is untouched");
    // Positive control: switched back on, a session keeps a sign-in again, and the next one uses it.
    await oneSession(d, d.env(m));
    assert.equal(m.signIns(), 5);
    assert.equal(keptToken(d.keptPath), m.issued[4]);
    await oneSession(d, d.env(m));
    assert.equal(m.signIns(), 5);
    assertNoTokenShown(d, m);
  } finally {
    await close(m);
    rmSync(d.dir, { recursive: true, force: true });
  }
});

test('an expired or nearly expired kept sign-in is not used, and the new sign-in replaces it', async () => {
  const m = startMock();
  await listen(m);
  const d = device();
  try {
    // Tokens that live 30 s: inside the one-minute margin before expiry, so never reused.
    m.ttlS.value = 30;
    await oneSession(d, d.env(m));
    assert.equal(keptToken(d.keptPath), m.issued[0], 'kept, though no later session will use it');
    m.ttlS.value = 3600;
    await oneSession(d, d.env(m));
    assert.equal(m.signIns(), 2, 'a token about to expire is not used');
    assert.equal(keptToken(d.keptPath), m.issued[1], 'the new sign-in replaced it');
    assert.deepEqual(m.used, [m.issued[0], m.issued[1]]);
    // One that has expired, written as this package writes it.
    const expired = `${b64url({ alg: 'EdDSA' })}.${b64url({ exp: Math.floor(Date.now() / 1000) - 10 })}.x`;
    new SessionTokenFile(d.keptPath, () => ({ endpoint: m.url(), agentIdHash: d.agentIdHash, tier: 'FREE', paymentMethod: undefined })).keep(expired);
    assert.equal(keptToken(d.keptPath), expired);
    await oneSession(d, d.env(m));
    assert.equal(m.signIns(), 3);
    assert.ok(!m.used.includes(expired), 'never sent');
    assert.equal(keptToken(d.keptPath), m.issued[2]);
    // A corrupt file, and a good one other users can read: not used, and replaced by the next sign-in.
    writeFileSync(d.keptPath, '{"kind":"saihm-session-token",', { mode: 0o600 });
    await oneSession(d, d.env(m));
    assert.equal(m.signIns(), 4);
    assert.equal(keptToken(d.keptPath), m.issued[3]);
    if (POSIX) {
      chmodSync(d.keptPath, 0o644);
      await oneSession(d, d.env(m));
      assert.equal(m.signIns(), 5, 'a file of mode 644 is not used');
      assert.equal(statSync(d.keptPath).mode & 0o777, 0o600, 'its replacement is mode 600');
      assert.equal(keptToken(d.keptPath), m.issued[4]);
    }
    assertNoTokenShown(d, m);
  } finally {
    await close(m);
    rmSync(d.dir, { recursive: true, force: true });
  }
});

test('a sign-in kept for another plan, another endpoint or another identity is not used, and never sent elsewhere', async () => {
  const m = startMock();
  const other = startMock();
  await listen(m);
  await listen(other);
  const d = device();
  try {
    await oneSession(d, d.env(m));
    assert.equal(m.signIns(), 1);
    const freeToken = m.issued[0]!;
    // Another plan: the same key, configured for a paid plan.
    await oneSession(d, d.env(m, { SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' }));
    assert.equal(m.signIns(), 2, 'another plan signs in');
    assert.equal(JSON.parse(readFileSync(d.keptPath, 'utf8')).tier, 'PRO', 'and its sign-in replaces the kept one');
    // The same plan, another payment method.
    await oneSession(d, d.env(m, { SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stablecoin' }));
    assert.equal(m.signIns(), 3);
    // Another endpoint: a token issued by one is never sent to another.
    const proToken = keptToken(d.keptPath)!;
    await oneSession(d, d.env(other, { SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stablecoin' }));
    assert.equal(other.signIns(), 1, 'the other endpoint is signed in to');
    for (const t of [freeToken, proToken, ...m.issued]) assert.ok(!other.used.includes(t), 'no token of the first endpoint reaches the other');
    assert.deepEqual(other.used, [other.issued[0]]);
    // Another identity: a kept sign-in naming another agent ID, at this identity's file, is not used.
    new SessionTokenFile(d.keptPath, () => ({ endpoint: m.url(), agentIdHash: 'cd'.repeat(32), tier: 'FREE', paymentMethod: undefined })).keep(m.issued[0]!);
    const before = m.signIns();
    await oneSession(d, d.env(m));
    assert.equal(m.signIns(), before + 1, 'a file naming another agent ID is not used');
    assertNoTokenShown(d, m);
  } finally {
    await close(m);
    await close(other);
    rmSync(d.dir, { recursive: true, force: true });
  }
});

test('a kept token the endpoint refuses (401) is removed, a fresh sign-in follows, and it is never used again', async () => {
  const m = startMock();
  await listen(m);
  const d = device();
  try {
    await oneSession(d, d.env(m));
    const first = m.issued[0]!;
    m.refuse.add(first);
    const r = await oneSession(d, d.env(m));
    assert.equal(r.isError, false, r.text);
    assert.equal(m.signIns(), 2, 'one fresh sign-in after the refusal');
    assert.deepEqual(m.used, [first, first, m.issued[1]], 'the refused token was tried once, then the fresh one');
    assert.equal(keptToken(d.keptPath), m.issued[1], 'the refused token is gone from the file; the fresh one is kept');
    await oneSession(d, d.env(m));
    assert.equal(m.signIns(), 2);
    assert.equal(m.used.filter((t) => t === first).length, 2, 'never used again');
    // Every token refused (an ended plan, say): the call fails once the fresh sign-in is refused too, no refused token
    // is left kept for the next session, and none is shown in the error.
    m.refuseAll.value = true;
    const failed = await oneSession(d, d.env(m));
    assert.equal(failed.isError, true, failed.text);
    assert.equal(m.signIns(), 3, 'one fresh sign-in, as before');
    assert.equal(existsSync(d.keptPath), false, 'no refused token is left kept');
    assertNoTokenShown(d, m);
  } finally {
    await close(m);
    rmSync(d.dir, { recursive: true, force: true });
  }
});

test('a session whose token is refused signs in afresh, even when another session has since kept a newer one', async () => {
  const m = startMock();
  await listen(m);
  const d = device();
  try {
    await oneSession(d, d.env(m));
    const first = m.issued[0]!;
    const s = await session(d.env(m));
    try {
      const r1 = await s.status();
      d.shown.push(r1.text, r1.raw);
      assert.deepEqual(m.used, [first, first], 'the running session holds the kept token');
      // Another session on this device keeps a newer sign-in; then the endpoint refuses the running session's token.
      const newer = m.issued.length;
      await oneSession(d, d.env(m, { SAIHM_SESSION_CACHE: '0' }));
      const other = m.issued[newer]!;
      new SessionTokenFile(d.keptPath, () => ({ endpoint: m.url(), agentIdHash: d.agentIdHash, tier: 'FREE', paymentMethod: undefined })).keep(other);
      m.refuse.add(first);
      const r2 = await s.status();
      d.shown.push(r2.text, r2.raw);
      assert.equal(r2.isError, false, r2.text);
      const fresh = m.issued[m.issued.length - 1]!;
      assert.notEqual(fresh, other, 'a fresh sign-in, not the token another session kept');
      assert.deepEqual(m.used.slice(-2), [first, fresh], 'the refused token once, then the fresh one');
      assert.equal(m.used.filter((t) => t === other).length, 1, 'the other session\'s token was used only by that session');
      assert.equal(keptToken(d.keptPath), fresh, 'and the fresh sign-in is the one kept');
    } finally {
      await s.stop();
      d.shown.push(s.stderr());
    }
    assertNoTokenShown(d, m);
  } finally {
    await close(m);
    rmSync(d.dir, { recursive: true, force: true });
  }
});

test('an inline secret or a key file outside SAIHM_HOME signs in each session, as before, and keeps nothing', async () => {
  const m = startMock();
  await listen(m);
  const d = device();
  try {
    const inline = { HOME: d.home, SAIHM_HOME: d.home, SAIHM_ENDPOINT_URL: m.url(), SAIHM_MASTER_SECRET_HEX: randomBytes(32).toString('hex'), SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe', SAIHM_SELF_JOIN: '0' };
    await oneSession(d, inline);
    await oneSession(d, inline);
    assert.equal(m.signIns(), 2);
    const keyDir = join(d.dir, 'volume');
    mkdirSync(keyDir, { mode: 0o700 });
    const keyFile = join(keyDir, 'work.key');
    writeFileSync(keyFile, randomBytes(32).toString('hex'), { mode: 0o600 });
    const elsewhere = { HOME: d.home, SAIHM_HOME: d.home, SAIHM_ENDPOINT_URL: m.url(), SAIHM_MASTER_SECRET_FILE: keyFile, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe', SAIHM_SELF_JOIN: '0' };
    await oneSession(d, elsewhere);
    await oneSession(d, elsewhere);
    assert.equal(m.signIns(), 4);
    assert.deepEqual(readdirSync(d.home).filter((n) => n.startsWith('session.')), [], 'nothing kept for either');
    // Positive control: the default key file in the same home keeps its sign-in.
    await oneSession(d, d.env(m));
    assert.deepEqual(readdirSync(d.home).filter((n) => n.startsWith('session.')), [`session.${d.agentIdHash.slice(0, 16)}.json`]);
    assertNoTokenShown(d, m);
  } finally {
    await close(m);
    rmSync(d.dir, { recursive: true, force: true });
  }
});

test('where the home is temporary or kept for later jobs (CI, a hosted session), nothing is kept; SAIHM_EPHEMERAL_HOME=0 keeps it', async () => {
  const m = startMock();
  await listen(m);
  const d = device();
  try {
    for (const signal of [{ CI: 'true' }, { GITHUB_ACTIONS: 'true' }, { CLAUDE_CODE_REMOTE: 'true' }, { SAIHM_EPHEMERAL_HOME: '1' }]) {
      const before = m.signIns();
      const r = await oneSession(d, d.env(m, signal));
      assert.equal(r.isError, false, r.text);
      assert.equal(m.signIns(), before + 1, `${JSON.stringify(signal)}: a sign-in, as before`);
      assert.equal(existsSync(d.keptPath), false, `${JSON.stringify(signal)}: nothing kept`);
    }
    await oneSession(d, d.env(m, { CI: 'true', SAIHM_EPHEMERAL_HOME: '0' }));
    assert.equal(keptToken(d.keptPath), m.issued[m.issued.length - 1], 'a home declared kept keeps the sign-in');
    assertNoTokenShown(d, m);
  } finally {
    await close(m);
    rmSync(d.dir, { recursive: true, force: true });
  }
});

test('a paid plan without SAIHM_PAYMENT_METHOD: the server starts, and each memory call fails naming the setting', async () => {
  const m = startMock();
  await listen(m);
  const d = device();
  try {
    const s = await session(d.env(m, { SAIHM_TIER: 'PRO' }));
    try {
      const tools = await s.tools();
      assert.ok(tools.includes('saihm_status') && tools.includes('saihm_recall'), 'it starts and lists its tools');
      for (let i = 0; i < 2; i++) {
        const r = await s.status();
        assert.equal(r.isError, true, r.text);
        assert.match(r.text, /SAIHM_PAYMENT_METHOD/, 'the call names the setting');
      }
    } finally {
      await s.stop();
    }
    assert.equal(m.signIns(), 0, 'and it never signs in without it');
    assert.equal(existsSync(d.keptPath), false);
  } finally {
    await close(m);
    rmSync(d.dir, { recursive: true, force: true });
  }
});

test('several sessions starting at once: each works, the file left is whole, and the next session signs in to nothing', async () => {
  const m = startMock();
  await listen(m);
  const d = device();
  try {
    const n = 4;
    const sessions = await Promise.all(Array.from({ length: n }, () => session(d.env(m))));
    try {
      const results = await Promise.all(sessions.map((s) => s.status()));
      for (const r of results) {
        assert.equal(r.isError, false, r.text);
        d.shown.push(r.text, r.raw);
      }
    } finally {
      await Promise.all(sessions.map((s) => s.stop()));
      for (const s of sessions) d.shown.push(s.stderr());
    }
    assert.ok(m.signIns() >= 1 && m.signIns() <= n, `${m.signIns()} sign-ins for ${n} sessions`);
    const kept = keptToken(d.keptPath);
    assert.ok(kept !== undefined && m.issued.includes(kept), 'the file left holds one whole token the endpoint issued');
    if (POSIX) assert.equal(statSync(d.keptPath).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(d.home).filter((x) => x.endsWith('.tmp') || x.endsWith('.lock')), [], 'no temporary or lock file is left');
    const before = m.signIns();
    await oneSession(d, d.env(m));
    assert.equal(m.signIns(), before, 'the next session uses the kept sign-in');
    assertNoTokenShown(d, m);
  } finally {
    await close(m);
    rmSync(d.dir, { recursive: true, force: true });
  }
});
