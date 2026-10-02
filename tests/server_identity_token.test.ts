// Integration coverage for carrying an identity into a fresh, variable-only environment
// (`export-identity`, then SAIHM_IDENTITY + SAIHM_IDENTITY_PASSPHRASE) and for the join gates that
// keep a hosted agent's fresh session from minting a second identity. Spawns the real stdio server
// and the real CLI against a mock bridge that verifies the ML-DSA signature, so "the token booted
// identity X" is proven by the key that signed, not by a flag the server reports about itself.
// Runner: npx tsx --test tests/server_identity_token.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { generatePassphrase, sealIdentityToken } from '../src/identity-token.js';
import { tmpdir } from 'node:os';
import { createHash, randomBytes } from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { deriveIdentity, toHex, fromHex } from '@saihm/client-pro';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const sha256Hex = (hex: string): string => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const KEY = 'free-identity.key';

/**
 * The spawned process gets an ALLOWLIST, not the runner's environment minus a list: any SAIHM_*
 * variable the runner holds - an identity, a recall-cache path, a feed directory - would otherwise
 * boot, write or refuse on the runner's account, and a scrub list only covers the names it thought of.
 */
function childEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const keep: NodeJS.ProcessEnv = {};
  for (const k of ['PATH', 'SYSTEMROOT', 'TEMP', 'TMP', 'TMPDIR']) if (process.env[k] !== undefined) keep[k] = process.env[k];
  return { ...keep, ...extra };
}

interface Mock {
  server: Server;
  base: () => string;
  /** Every `/api/onboard` whose signature verified: who signed, and the tier and rail it asked for. */
  onboards: { pubkey: string; tier?: string; paymentMethod?: string }[];
  joinStarts: () => number;
}

function startMock(opts: { onboardReject?: Record<string, string>; onboardStatus?: number; grant?: boolean } = {}): Mock {
  let lastNonce = '';
  let joinStarts = 0;
  const onboards: Mock['onboards'] = [];
  const server = createServer((req, res) => {
    const url = req.url ?? '';
    const send = (s: number, b: unknown): void => {
      res.writeHead(s, { 'content-type': 'application/json' });
      res.end(JSON.stringify(b));
    };
    const read = (cb: (b: Record<string, string>) => void): void => {
      let buf = '';
      req.on('data', (c) => (buf += c));
      req.on('end', () => {
        try {
          cb(JSON.parse(buf) as Record<string, string>);
        } catch {
          send(400, { error: 'bad_json' });
        }
      });
    };
    const signed = (b: Record<string, string>): boolean => {
      try {
        return (
          b.nonce === lastNonce &&
          ml_dsa65.verify(fromHex(b.signature ?? ''), fromHex(b.nonce ?? ''), fromHex(b.pubkey ?? ''))
        );
      } catch {
        return false;
      }
    };
    if (req.method === 'GET' && url === '/api/onboard/challenge') {
      lastNonce = randomBytes(32).toString('hex');
      return send(200, { nonce: lastNonce });
    }
    if (req.method === 'POST' && url === '/api/free-onboard/start')
      return read(() => {
        joinStarts += 1;
        send(200, {
          flowId: 'flow-1',
          userCode: 'ABCD-1234',
          verificationUri: 'https://device.test/activate',
          expiresIn: 900,
          interval: 1,
        });
      });
    if (req.method === 'POST' && url === '/api/free-onboard/claim')
      return read((b) => {
        if (!signed(b)) return send(401, { error: 'bad_signature' });
        return send(200, opts.grant ? { status: 'granted', agentIdHash: sha256Hex(b.pubkey ?? '') } : { status: 'pending' });
      });
    if (req.method === 'POST' && url === '/api/onboard')
      return read((b) => {
        if (!signed(b)) return send(401, { error: 'bad_signature' });
        if (opts.onboardReject) return send(opts.onboardStatus ?? 401, opts.onboardReject);
        onboards.push({ pubkey: b.pubkey ?? '', tier: b.tier, paymentMethod: b.paymentMethod });
        const seg = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
        return send(201, {
          jwt: `${seg({ alg: 'EdDSA' })}.${seg({ sub: b.pubkey, tier: b.tier, exp: Math.floor(Date.now() / 1000) + 3600 })}.sig`,
        });
      });
    if (req.method === 'POST' && url === '/api/stripe/checkout')
      return read(() => send(200, { url: 'https://checkout.test/c/pay' }));
    if (req.method === 'POST' && url === '/mcp')
      return read((b) => (b.method === 'saihm_recall' ? send(200, []) : send(404, { error: 'unknown_method' })));
    return send(404, { error: 'not_found' });
  });
  return {
    server,
    base: () => `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    onboards,
    joinStarts: () => joinStarts,
  };
}

interface Driver {
  proc: ChildProcess;
  call: (name: string, args: unknown) => Promise<{ text: string; isError: boolean }>;
  instructions: string;
}

async function startServer(extra: Record<string, string>): Promise<Driver> {
  const proc = spawn(TSX, [SERVER], { env: childEnv(extra), stdio: ['pipe', 'pipe', 'pipe'], cwd: resolve(HERE, '..') });
  let buf = '';
  let stderr = '';
  let nextId = 1;
  const waiters = new Map<number, (m: { result?: any }) => void>();
  proc.stderr!.on('data', (d) => (stderr += d));
  proc.stdout!.on('data', (d) => {
    buf += d;
    let nl: number;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      try {
        const m = JSON.parse(line) as { id?: number; result?: any };
        if (m.id != null && waiters.has(m.id)) {
          waiters.get(m.id)!(m);
          waiters.delete(m.id);
        }
      } catch {
        /* not a protocol line */
      }
    }
  });
  const rpc = (method: string, params: unknown): Promise<{ result?: any }> =>
    new Promise((res, rej) => {
      const id = nextId++;
      waiters.set(id, res);
      proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      setTimeout(() => {
        if (waiters.delete(id)) rej(new Error(`rpc timeout ${method}; stderr=${stderr}`));
      }, 20000);
    });
  const init = await rpc('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const call = async (name: string, args: unknown) => {
    const r = await rpc('tools/call', { name, arguments: args });
    return { text: String(r.result.content[0].text), isError: r.result.isError === true };
  };
  return { proc, call, instructions: String(init.result.instructions ?? '') };
}

function runCli(args: string[], extra: Record<string, string>): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((res) => {
    const p = spawn(TSX, [SERVER, ...args], { env: childEnv(extra), stdio: ['ignore', 'pipe', 'pipe'], cwd: resolve(HERE, '..') });
    let stdout = '';
    let stderr = '';
    p.stdout!.on('data', (d) => (stdout += d));
    p.stderr!.on('data', (d) => (stderr += d));
    const t = setTimeout(() => p.kill(), 60000);
    p.on('close', (code) => {
      clearTimeout(t);
      res({ code, stdout, stderr });
    });
  });
}

async function withMock<T>(opts: Parameters<typeof startMock>[0], fn: (m: Mock) => Promise<T>): Promise<T> {
  const m = startMock(opts);
  await new Promise<void>((r) => m.server.listen(0, '127.0.0.1', () => r()));
  try {
    return await fn(m);
  } finally {
    await new Promise<void>((r) => m.server.close(() => r()));
  }
}

function tempHome(tag: string): string {
  return mkdtempSync(join(tmpdir(), `saihm-idtok-${tag}-`));
}

/** A disposable identity: a random secret and the agentIdHash it derives. */
function identity(): { secretHex: string; agentIdHash: string } {
  const secretHex = randomBytes(32).toString('hex');
  return { secretHex, agentIdHash: toHex(deriveIdentity(fromHex(secretHex)).agentIdHash) };
}

async function exportFrom(home: string, env: Record<string, string>) {
  const r = await runCli(['export-identity'], { SAIHM_HOME: home, ...env });
  assert.equal(r.code, 0, `export failed: ${r.stderr}`);
  const dir = join(home, 'exports');
  const files = readdirSync(dir);
  assert.equal(files.length, 1, 'one export, one file');
  const file = join(dir, files[0]!);
  const text = readFileSync(file, 'utf8');
  const token = /^SAIHM_IDENTITY=(.+)$/m.exec(text)?.[1] ?? '';
  const passphrase = /^SAIHM_IDENTITY_PASSPHRASE=(.+)$/m.exec(text)?.[1] ?? '';
  assert.ok(token && passphrase, 'the export file holds both lines');
  return { r, dir, file, token, passphrase };
}

test('export-identity: a fresh HOME boots the SAME identity from two variables, at its tier, minting nothing', async () => {
  const id = identity();
  const homeA = tempHome('a');
  const homeB = tempHome('b');
  try {
    const ex = await exportFrom(homeA, { SAIHM_MASTER_SECRET_HEX: id.secretHex, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    if (process.platform !== 'win32') {
      assert.equal(statSync(ex.file).mode & 0o777, 0o600, 'the export file is readable only by its owner');
      assert.equal(statSync(ex.dir).mode & 0o777, 0o700);
    }
    const printed = ex.r.stdout + ex.r.stderr;
    for (const secret of [id.secretHex, ex.passphrase, ex.token.split('.')[2]!.slice(0, 32)])
      assert.ok(!printed.includes(secret), 'neither the key, the token nor the passphrase is printed');
    assert.ok(printed.includes(`${id.agentIdHash.slice(0, 16)}…${id.agentIdHash.slice(-6)}`), 'the summary names the identity as status shows it, plus its tail');
    assert.match(printed, /tier PRO/);
    assert.match(printed, /from:\s+SAIHM_MASTER_SECRET_HEX/);

    await withMock({}, async (m) => {
      const d = await startServer({
        SAIHM_HOME: homeB,
        SAIHM_ENDPOINT_URL: m.base() + '/mcp',
        SAIHM_IDENTITY: ex.token,
        SAIHM_IDENTITY_PASSPHRASE: ex.passphrase,
      });
      try {
        const r = await d.call('saihm_recall', {});
        assert.equal(r.isError, false, r.text);
        assert.ok(m.onboards.length >= 1, 'the imported identity onboarded');
        assert.equal(sha256Hex(m.onboards[0]!.pubkey), id.agentIdHash, 'and it is the exported identity that signed');
        assert.equal(m.onboards[0]!.tier, 'PRO', 'the tier travelled in the token');
        assert.equal(m.onboards[0]!.paymentMethod, 'stripe', 'and so did the payment method');
        assert.ok(!existsSync(join(homeB, KEY)), 'no key file was minted in the fresh home');
      } finally {
        d.proc.kill();
      }
    });
  } finally {
    rmSync(homeA, { recursive: true, force: true });
    rmSync(homeB, { recursive: true, force: true });
  }
});

test('a token that does not open is a typed tool error: no onboard, no join, no key', async () => {
  const id = identity();
  const homeA = tempHome('c');
  const homeB = tempHome('d');
  try {
    const ex = await exportFrom(homeA, { SAIHM_MASTER_SECRET_HEX: id.secretHex });
    const other = await exportFrom(tempHome('e'), { SAIHM_MASTER_SECRET_HEX: identity().secretHex });
    await withMock({}, async (m) => {
      const d = await startServer({
        SAIHM_HOME: homeB,
        SAIHM_ENDPOINT_URL: m.base() + '/mcp',
        SAIHM_IDENTITY: ex.token,
        SAIHM_IDENTITY_PASSPHRASE: other.passphrase,
      });
      try {
        const r = await d.call('saihm_recall', {});
        assert.equal(r.isError, true);
        assert.match(r.text, /SAIHM_IDENTITY did not open with SAIHM_IDENTITY_PASSPHRASE/);
        assert.doesNotMatch(r.text, /Join SAIHM|saihm_join/, 'a broken token must not invite a join');
        assert.ok(!r.text.includes(other.passphrase) && !r.text.includes(id.secretHex));
        assert.equal(m.onboards.length, 0);
        assert.equal(m.joinStarts(), 0);
        assert.ok(!existsSync(join(homeB, KEY)));
      } finally {
        d.proc.kill();
      }
    });
    rmSync(dirname(other.dir), { recursive: true, force: true });
  } finally {
    rmSync(homeA, { recursive: true, force: true });
    rmSync(homeB, { recursive: true, force: true });
  }
});

test('export-identity with nothing configured exports nothing and mints nothing', async () => {
  const home = tempHome('f');
  try {
    const r = await runCli(['export-identity'], { SAIHM_HOME: home });
    assert.equal(r.code, 1);
    assert.match(r.stderr, /nothing to export/);
    assert.ok(!existsSync(join(home, KEY)), 'an export never creates the identity it was asked to export');
    assert.ok(!existsSync(join(home, 'exports')));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('no identity at all: the memory tools say what was checked and ask before suggesting a join', async () => {
  const home = tempHome('g');
  try {
    await withMock({}, async (m) => {
      const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', SAIHM_EPHEMERAL_HOME: '0' });
      try {
        assert.match(d.instructions, /installed but not active yet/);
        assert.match(d.instructions, /export-identity/);
        const r = await d.call('saihm_recall', {});
        assert.equal(r.isError, true);
        assert.match(r.text, /Checked SAIHM_IDENTITY, SAIHM_MASTER_SECRET_FILE and SAIHM_MASTER_SECRET_HEX/);
        assert.match(r.text, /Already have a SAIHM identity\? Do not join/);
        assert.match(r.text, /export-identity/);
        assert.match(r.text, /Join SAIHM/);
        assert.ok(!existsSync(join(home, KEY)));
      } finally {
        d.proc.kill();
      }
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('saihm_join asks before minting: without newIdentity it returns the question, with it the flow starts', async () => {
  const home = tempHome('h');
  try {
    await withMock({}, async (m) => {
      const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', SAIHM_EPHEMERAL_HOME: '0' });
      try {
        const q = await d.call('saihm_join', {});
        assert.equal(q.isError, false);
        assert.match(q.text, /Do you already have a SAIHM identity/);
        assert.match(q.text, /export-identity/);
        assert.match(q.text, /newIdentity: true/);
        assert.ok(!existsSync(join(home, KEY)), 'asking mints nothing');
        assert.equal(m.joinStarts(), 0, 'and starts no approval');
        const go = await d.call('saihm_join', { newIdentity: true });
        assert.equal(go.isError, false, go.text);
        assert.match(go.text, /ABCD-1234/);
        assert.ok(existsSync(join(home, KEY)), 'a confirmed join mints the key');
      } finally {
        d.proc.kill();
      }
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('saihm_join will not mint where the home is marked temporary, and only the operator can say otherwise', async () => {
  for (const [env, variable] of [
    [{ CLAUDE_CODE_REMOTE: 'true' }, 'CLAUDE_CODE_REMOTE'],
    [{ GITHUB_ACTIONS: 'true' }, 'GITHUB_ACTIONS'],
    [{ CI: '1' }, 'CI'],
    [{ SAIHM_EPHEMERAL_HOME: 'yes' }, 'SAIHM_EPHEMERAL_HOME'],
  ] as const) {
    const home = tempHome('i');
    try {
      await withMock({}, async (m) => {
        const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', ...env });
        try {
          // The refusal comes BEFORE the question: on such a machine the answer is "not here" either way.
          const first = await d.call('saihm_join', {});
          assert.match(first.text, new RegExp(`Not joining here: ${variable} is set`), first.text);
          // A flag the agent supplies cannot clear it - unknown inputs are dropped, and the gate stands.
          const pushed = await d.call('saihm_join', { newIdentity: true, allowEphemeral: true });
          assert.match(pushed.text, /Not joining here/);
          assert.match(pushed.text, /SAIHM_EPHEMERAL_HOME=0 in its settings/);
          assert.match(pushed.text, /never in this chat/);
          assert.ok(!existsSync(join(home, KEY)), `${variable}: nothing minted`);
          assert.equal(m.joinStarts(), 0);
        } finally {
          d.proc.kill();
        }
      });
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }
  // The operator's override wins over a host's signal, and blanks are not signals.
  for (const env of [
    { CI: 'true', SAIHM_EPHEMERAL_HOME: '0' },
    { CLAUDE_CODE_REMOTE: 'true', SAIHM_EPHEMERAL_HOME: 'false' },
    { CLAUDE_CODE_REMOTE: '', CI: '' },
  ]) {
    const home = tempHome('j');
    try {
      await withMock({}, async (m) => {
        const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', ...env });
        try {
          assert.match((await d.call('saihm_join', { newIdentity: true })).text, /ABCD-1234/, JSON.stringify(env));
        } finally {
          d.proc.kill();
        }
      });
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }
});

test('a join that ACTIVATES a key already here is not gated', async () => {
  const home = tempHome('o');
  try {
    writeFileSync(join(home, KEY), randomBytes(32).toString('hex'), { mode: 0o600 });
    await withMock({}, async (m) => {
      const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', CLAUDE_CODE_REMOTE: 'true' });
      try {
        const r = await d.call('saihm_join', {});
        assert.doesNotMatch(r.text, /Do you already have|Not joining here/);
        assert.match(r.text, /ABCD-1234/);
      } finally {
        d.proc.kill();
      }
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a configured token IS an identity: saihm_join asks nothing and mints nothing', async () => {
  const homeA = tempHome('k');
  const homeB = tempHome('l');
  try {
    const ex = await exportFrom(homeA, { SAIHM_MASTER_SECRET_HEX: identity().secretHex });
    await withMock({}, async (m) => {
      const d = await startServer({
        SAIHM_HOME: homeB,
        SAIHM_ENDPOINT_URL: m.base() + '/mcp',
        SAIHM_IDENTITY: ex.token,
        SAIHM_IDENTITY_PASSPHRASE: ex.passphrase,
        CLAUDE_CODE_REMOTE: 'true',
      });
      try {
        const r = await d.call('saihm_join', {});
        assert.doesNotMatch(r.text, /Do you already have|Not joining here/);
        assert.ok(!existsSync(join(homeB, KEY)), 'the token identity is activated, never replaced by a minted key');
        assert.match(r.text, /SAIHM_IDENTITY and SAIHM_IDENTITY_PASSPHRASE pair/, 'its key advice names what the user set');
        assert.doesNotMatch(r.text, /SAIHM_MASTER_SECRET_HEX/);
      } finally {
        d.proc.kill();
      }
    });
  } finally {
    rmSync(homeA, { recursive: true, force: true });
    rmSync(homeB, { recursive: true, force: true });
  }
});

test('free-join refuses in a temporary home; a flag cannot override it, the operator setting can', async () => {
  await withMock({ grant: true }, async (m) => {
    const home = tempHome('m');
    try {
      for (const args of [['free-join'], ['free-join', '--allow-ephemeral']]) {
        const no = await runCli(args, { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', CLAUDE_CODE_REMOTE: 'true' });
        assert.equal(no.code, 1, args.join(' '));
        assert.match(no.stderr, /Not joining here: CLAUDE_CODE_REMOTE is set/);
        assert.match(no.stderr, /SAIHM_EPHEMERAL_HOME=0/);
        assert.ok(!existsSync(join(home, KEY)));
        assert.equal(m.joinStarts(), 0);
      }
      const yes = await runCli(['free-join'], {
        SAIHM_HOME: home,
        SAIHM_ENDPOINT_URL: m.base() + '/mcp',
        CLAUDE_CODE_REMOTE: 'true',
        SAIHM_EPHEMERAL_HOME: '0',
      });
      assert.equal(yes.code, 0, yes.stderr);
      assert.match(yes.stdout, /FREE memory activated/);
      assert.ok(existsSync(join(home, KEY)));
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});

test('a refused onboard names its reason and, for the two configuration reasons, what to set', async () => {
  for (const [reason, remedy] of [
    ['no_free_entitlement', /Set SAIHM_TIER and SAIHM_PAYMENT_METHOD for its plan/],
    ['no_active_subscription', /Check that SAIHM_TIER names the plan this identity was bought on/],
  ] as const) {
    const home = tempHome('n');
    try {
      await withMock({ onboardReject: { error: 'verification_failed', reason } }, async (m) => {
        const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', SAIHM_MASTER_SECRET_HEX: identity().secretHex });
        try {
          const r = await d.call('saihm_recall', {});
          assert.equal(r.isError, true);
          assert.match(r.text, new RegExp(`verification_failed: ${reason}`), 'the reason is no longer dropped');
          assert.match(r.text, remedy);
        } finally {
          d.proc.kill();
        }
      });
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }
});

test('export-identity: says where the tier came from, refuses a directory that is not private, never collides', async () => {
  const home = tempHome('p');
  try {
    const secret = identity().secretHex;
    const r1 = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: secret });
    assert.equal(r1.code, 0, r1.stderr);
    assert.match(r1.stdout, /tier FREE/);
    assert.match(r1.stdout, /FREE only because SAIHM_TIER is not set here/);
    assert.match(r1.stdout, /a server started from THIS shell/);
    const r2 = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: secret, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(r2.code, 0, r2.stderr);
    assert.doesNotMatch(r2.stdout, /FREE only because/);
    assert.equal(readdirSync(join(home, 'exports')).length, 2, 'two exports, two files');
    if (process.platform !== 'win32') {
      chmodSync(join(home, 'exports'), 0o777);
      const loose = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: secret });
      assert.equal(loose.code, 1);
      assert.match(loose.stderr, /not private to you/);
      assert.equal(readdirSync(join(home, 'exports')).length, 2, 'nothing written into it');
      const other = tempHome('q');
      const linked = tempHome('r');
      try {
        symlinkSync(other, join(linked, 'exports'));
        const viaLink = await runCli(['export-identity'], { SAIHM_HOME: linked, SAIHM_MASTER_SECRET_HEX: secret });
        assert.equal(viaLink.code, 1);
        assert.match(viaLink.stderr, /not private to you/);
        assert.equal(readdirSync(other).length, 0, 'nothing written through the link');
      } finally {
        rmSync(other, { recursive: true, force: true });
        rmSync(linked, { recursive: true, force: true });
      }
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('export-identity under SAIHM_SELF_JOIN=0 with only a default key says how to export it', async () => {
  const home = tempHome('s');
  try {
    writeFileSync(join(home, KEY), randomBytes(32).toString('hex'), { mode: 0o600 });
    const r = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_SELF_JOIN: '0' });
    assert.equal(r.code, 1);
    assert.match(r.stderr, /nothing to export/);
    assert.match(r.stderr, /point SAIHM_MASTER_SECRET_FILE at it/);
    assert.ok(!existsSync(join(home, 'exports')));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a failed join never echoes a key pasted into SAIHM_MASTER_SECRET_FILE', async () => {
  const home = tempHome('t');
  try {
    const pasted = randomBytes(32).toString('hex');
    await withMock({}, async (m) => {
      const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', SAIHM_MASTER_SECRET_FILE: `SAIHM_MASTER_SECRET_FILE=${pasted}` });
      try {
        const r = await d.call('saihm_join', {});
        assert.ok(!r.text.includes(pasted), 'the pasted key must not appear anywhere in the join result');
        assert.match(r.text, /not shown/);
      } finally {
        d.proc.kill();
      }
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('with self-join off the server still tells every agent never to ask for or write the token', async () => {
  const home = tempHome('u');
  try {
    await withMock({}, async (m) => {
      const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', SAIHM_SELF_JOIN: '0' });
      try {
        assert.match(d.instructions, /Never ask for SAIHM_IDENTITY or its passphrase in the chat, and never write either into a file/);
        assert.doesNotMatch(d.instructions, /saihm_join/);
      } finally {
        d.proc.kill();
      }
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('an identity already on a paid plan is told there is nothing to join', async () => {
  const homeA = tempHome('v');
  const homeB = tempHome('w');
  try {
    const ex = await exportFrom(homeA, { SAIHM_MASTER_SECRET_HEX: identity().secretHex, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    await withMock({}, async (m) => {
      const d = await startServer({ SAIHM_HOME: homeB, SAIHM_ENDPOINT_URL: m.base() + '/mcp', SAIHM_IDENTITY: ex.token, SAIHM_IDENTITY_PASSPHRASE: ex.passphrase });
      try {
        const r = await d.call('saihm_join', {});
        // Reworded in batch 7: the plan is the one CONFIGURED here, which the join does not check with the endpoint
        // (correctness R6 F3, docs R6 below-Low 5). A normal result, not a tool error (correctness R6 F2).
        assert.match(r.text, /^This environment has a SAIHM identity, configured for the PRO plan\. /);
        assert.equal(r.isError, false, 'the tier answer is a normal result, not a tool error');
        // Ready: the payment method rides in the token, with none set here.
        assert.match(r.text, /There is nothing to join: the memory tools use it as it is\./);
        assert.doesNotMatch(r.text, /SAIHM_TIER=FREE|bring that identity here/);
        assert.equal(m.joinStarts(), 0, 'no free activation is started for it');
      } finally {
        d.proc.kill();
      }
    });
  } finally {
    rmSync(homeA, { recursive: true, force: true });
    rmSync(homeB, { recursive: true, force: true });
  }
});

test('export-identity flags a paid tier with no payment method, and tells agents not to open the file', async () => {
  const home = tempHome('x');
  try {
    const r = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: identity().secretHex, SAIHM_TIER: 'PRO' });
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /paid tier but no payment method/);
    assert.match(r.stdout, /Agents: do not open or print the file/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// ---- each of the following pins a behaviour a reviewer showed could change with the suite green ----

function tok(secretHex: string, hints: { tier?: string; paymentMethod?: string } = {}) {
  const passphrase = generatePassphrase();
  return { token: sealIdentityToken({ secretHex, ...hints }, toHex(deriveIdentity(fromHex(secretHex)).agentIdHash), passphrase), passphrase };
}
const CLOSED = 'http://127.0.0.1:9/mcp';

for (const kind of ['HEX', 'FILE'] as const)
  test(`saihm_join that ACTIVATES a configured ${kind} identity in a temporary home is neither refused nor questioned`, async () => {
    const home = tempHome('ac');
    try {
      const id = identity();
      const keyEnv: Record<string, string> = {};
      if (kind === 'HEX') keyEnv.SAIHM_MASTER_SECRET_HEX = id.secretHex;
      else {
        const kf = join(home, 'op.key');
        writeFileSync(kf, id.secretHex, { mode: 0o600 });
        keyEnv.SAIHM_MASTER_SECRET_FILE = kf;
      }
      await withMock({}, async (m) => {
        const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', CLAUDE_CODE_REMOTE: 'true', ...keyEnv });
        try {
          const r = await d.call('saihm_join', {});
          assert.doesNotMatch(r.text, /Not joining here|Do you already have/, r.text);
          assert.match(r.text, /ABCD-1234/);
        } finally {
          d.proc.kill();
        }
      });
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

test('free-join that ACTIVATES an existing key in a temporary home is not refused', async () => {
  const home = tempHome('fj');
  try {
    writeFileSync(join(home, KEY), identity().secretHex, { mode: 0o600 });
    await withMock({ grant: true }, async (m) => {
      const r = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', CLAUDE_CODE_REMOTE: 'true' });
      assert.equal(r.code, 0, r.stderr);
      assert.doesNotMatch(r.stderr, /Not joining here/);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('every key-advice line names the token pair for a token identity, never the inline secret', async () => {
  // saihm_join, to completion
  const homeA = tempHome('ka');
  try {
    const t = tok(identity().secretHex);
    await withMock({ grant: true }, async (m) => {
      const d = await startServer({ SAIHM_HOME: homeA, SAIHM_ENDPOINT_URL: m.base() + '/mcp', SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase });
      try {
        let r = await d.call('saihm_join', {});
        for (let i = 0; i < 6 && !/key: /.test(r.text); i++) {
          await new Promise((z) => setTimeout(z, 1200));
          r = await d.call('saihm_join', {});
        }
        assert.match(r.text, /key: the SAIHM_IDENTITY and SAIHM_IDENTITY_PASSPHRASE pair/, r.text);
        assert.doesNotMatch(r.text, /SAIHM_MASTER_SECRET_HEX/);
      } finally {
        d.proc.kill();
      }
    });
  } finally {
    rmSync(homeA, { recursive: true, force: true });
  }
  // the paid join verb, free-join, and a failed free-join
  const homeB = tempHome('kb');
  try {
    // A stray default key from an earlier join is not the identity in use: the advice names the token pair
    // (correctness R7 F3).
    writeFileSync(join(homeB, KEY), randomBytes(32).toString('hex') + '\n', { mode: 0o600 });
    const paid = tok(identity().secretHex, { tier: 'PRO', paymentMethod: 'stripe' });
    const free = tok(identity().secretHex);
    await withMock({ grant: true }, async (m) => {
      const j = await runCli(['join'], { SAIHM_HOME: homeB, SAIHM_STATE_DIR: join(homeB, 'st'), SAIHM_ENDPOINT_URL: m.base() + '/mcp', SAIHM_IDENTITY: paid.token, SAIHM_IDENTITY_PASSPHRASE: paid.passphrase });
      assert.equal(j.code, 0, j.stderr);
      assert.match(j.stdout, /Keep the SAIHM_IDENTITY and SAIHM_IDENTITY_PASSPHRASE pair safe/, j.stdout);
      const f = await runCli(['free-join'], { SAIHM_HOME: homeB, SAIHM_ENDPOINT_URL: m.base() + '/mcp', SAIHM_IDENTITY: free.token, SAIHM_IDENTITY_PASSPHRASE: free.passphrase });
      assert.equal(f.code, 0, f.stderr);
      assert.match(f.stdout, /Keep the SAIHM_IDENTITY and SAIHM_IDENTITY_PASSPHRASE pair safe/, f.stdout);
    });
    const failed = await runCli(['free-join'], { SAIHM_HOME: homeB, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_IDENTITY: free.token, SAIHM_IDENTITY_PASSPHRASE: free.passphrase });
    assert.equal(failed.code, 1);
    assert.match(failed.stderr, /This machine uses the identity in SAIHM_IDENTITY, so a join here activates that identity/, failed.stderr);
    assert.doesNotMatch(failed.stderr, /bring that identity here/, 'a token already here is not sent to be brought here');
  } finally {
    rmSync(homeB, { recursive: true, force: true });
  }
});

test('export-identity: a token-only or file-only shell exports; no FREE note unless the tier really defaulted; 0750 refused', async () => {
  const home = tempHome('ex');
  try {
    const t = tok(identity().secretHex, { tier: 'PRO', paymentMethod: 'stripe' });
    const byToken = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase });
    assert.equal(byToken.code, 0, byToken.stderr);
    assert.doesNotMatch(byToken.stdout, /FREE only because/);
    const kf = join(home, 'op.key');
    writeFileSync(kf, identity().secretHex, { mode: 0o600 });
    const byFile = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_FILE: kf });
    assert.equal(byFile.code, 0, byFile.stderr);
    const noTier = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_SELF_JOIN: '0', SAIHM_MASTER_SECRET_HEX: identity().secretHex });
    assert.equal(noTier.code, 0, noTier.stderr);
    assert.doesNotMatch(noTier.stdout, /FREE only because/);
    if (process.platform !== 'win32') {
      const group = tempHome('eg');
      try {
        mkdirSync(join(group, 'exports'), { mode: 0o700 });
        chmodSync(join(group, 'exports'), 0o750);
        const r = await runCli(['export-identity'], { SAIHM_HOME: group, SAIHM_MASTER_SECRET_HEX: identity().secretHex });
        assert.equal(r.code, 1, r.stdout);
        assert.match(r.stderr, /not private to you/);
      } finally {
        rmSync(group, { recursive: true, force: true });
      }
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('onboard refusals: the endpoint reason is cut at its budget, and the remedy follows only a 401', async () => {
  for (const [opts, check] of [
    [{ onboardReject: { error: 'verification_failed', reason: 'r'.repeat(200) } }, (t: string) => {
      const run = Math.max(0, ...(t.match(/r+/g) ?? []).map((x) => x.length));
      assert.ok(run <= 64, `reason run ${run}`);
    }],
    [{ onboardReject: { error: 'verification_failed', reason: 'no_free_entitlement' }, onboardStatus: 403 }, (t: string) =>
      assert.doesNotMatch(t, /Paid identity\?/)],
  ] as const) {
    const home = tempHome('ob');
    try {
      await withMock(opts, async (m) => {
        const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', SAIHM_MASTER_SECRET_HEX: identity().secretHex });
        try {
          const r = await d.call('saihm_recall', {});
          assert.equal(r.isError, true);
          check(r.text);
        } finally {
          d.proc.kill();
        }
      });
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }
});

test('an unreachable endpoint names the network remedy, on the onboard and on the call', async () => {
  for (const [extra, remedy] of [
    [{}, /allow the endpoint's host \(saihm\.net by default\) in its network settings; if traffic must go through a proxy, set HTTPS_PROXY/],
    [{ SAIHM_AUTH_HEADER: 'Bearer probe' }, /allow that host in its network settings; if traffic must go through a proxy, set HTTPS_PROXY/],
  ] as const) {
    const home = tempHome('nw');
    try {
      const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: identity().secretHex, ...extra });
      try {
        const r = await d.call('saihm_recall', {});
        assert.match(r.text, remedy, r.text);
      } finally {
        d.proc.kill();
      }
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }
});

// ---- round-3 review: each pins a behaviour a reviewer showed could change with the suite green ----

test('a passphrase without its token stops every path: a typed error, never the question, a key or "nothing to export"', async () => {
  const home = tempHome('pp');
  try {
    const pass = generatePassphrase();
    await withMock({ grant: true }, async (m) => {
      const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp', SAIHM_IDENTITY_PASSPHRASE: pass });
      try {
        const asked = await d.call('saihm_join', {});
        assert.ok(asked.isError, asked.text);
        assert.match(asked.text, /SAIHM_IDENTITY_PASSPHRASE is set but SAIHM_IDENTITY is not/);
        assert.doesNotMatch(asked.text, /Not joining yet/, 'the passphrase alone is an error, not a reason to ask');
        const forced = await d.call('saihm_join', { newIdentity: true });
        assert.ok(forced.isError, forced.text);
        assert.match(forced.text, /SAIHM_IDENTITY_PASSPHRASE is set but SAIHM_IDENTITY is not/);
        assert.ok(!existsSync(join(home, KEY)), 'newIdentity: true does not get a key past a passphrase alone');
        assert.equal(m.joinStarts(), 0);
        for (const r of [asked, forced]) assert.ok(!r.text.includes(pass));
      } finally {
        d.proc.kill();
      }
    });
    const ex = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_IDENTITY_PASSPHRASE: pass });
    assert.equal(ex.code, 1);
    assert.match(ex.stderr, /SAIHM_IDENTITY_PASSPHRASE is set but SAIHM_IDENTITY is not/);
    assert.doesNotMatch(ex.stderr, /nothing to export/);
    assert.ok(!existsSync(join(home, 'exports')) && !existsSync(join(home, KEY)));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a failed join with a passphrase beside a key file names the file, not a token', async () => {
  const home = tempHome('pf');
  try {
    const kf = join(home, 'op.key');
    writeFileSync(kf, identity().secretHex, { mode: 0o600 });
    const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_FILE: kf, SAIHM_IDENTITY_PASSPHRASE: generatePassphrase() });
    try {
      const r = await d.call('saihm_join', {});
      assert.ok(r.isError, r.text);
      assert.match(r.text, /This machine's key file: /);
      assert.doesNotMatch(r.text, /uses the identity (token )?in SAIHM_IDENTITY/);
    } finally {
      d.proc.kill();
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a FREE export carries no payment warning; one with no tier says so', async () => {
  const home = tempHome('fe');
  try {
    const free = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: identity().secretHex, SAIHM_TIER: 'FREE' });
    assert.equal(free.code, 0, free.stderr);
    assert.match(free.stdout, /tier FREE/);
    assert.doesNotMatch(free.stdout, /paid tier but no payment method|carries no tier/);
    const kf = join(home, 'op.key');
    writeFileSync(kf, identity().secretHex, { mode: 0o600 });
    const none = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_SELF_JOIN: '0', SAIHM_MASTER_SECRET_FILE: kf });
    assert.equal(none.code, 0, none.stderr);
    assert.match(none.stdout, /This token carries no tier/);
    assert.doesNotMatch(none.stdout, /, tier /);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a paid plan is named only when it is a plan; the free-join verb gives the same answer, as a success', async () => {
  const home = tempHome('pl');
  try {
    const hex = identity().secretHex;
    for (const tier of [randomBytes(32).toString('hex'), generatePassphrase()]) {
      const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: tier });
      try {
        const r = await d.call('saihm_join', {});
        assert.match(r.text, /SAIHM_TIER is not a plan name this version knows\. For the free plan set it to FREE/, r.text);
        assert.equal(r.isError, false, 'the tier answer is a normal result, not a tool error');
        assert.ok(!r.text.includes(tier), 'a value pasted into SAIHM_TIER is not repeated');
      } finally {
        d.proc.kill();
      }
      const ex = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: tier, SAIHM_PAYMENT_METHOD: 'stripe' });
      assert.ok(!(ex.stdout + ex.stderr).includes(tier), 'nor printed by an export');
      // Refused since batch 7 before anything is sealed, as a plan name this version does not know (docs R6 L2), with
      // the verb's prefix: the token's own refusals of these two values are no longer reached through SAIHM_TIER.
      assert.equal(ex.code, 1, ex.stdout);
      assert.match(ex.stderr, /^saihm: not exported - the tier is not a plan name this version knows: /);
    }
    // "configured for the PRO plan" since batch 7: the plan set here, not one the endpoint confirmed.
    for (const [tier, said] of [['PRO', /configured for the PRO plan\./]] as const) {
      const f = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: tier, SAIHM_PAYMENT_METHOD: 'stripe' });
      assert.equal(f.code, 0, f.stderr);
      assert.match(f.stdout, said);
      assert.match(f.stdout, /There is nothing to join/);
      assert.doesNotMatch(f.stdout + f.stderr, /SAIHM_TIER=FREE|not_free_tier/);
    }
    // NOT EXPORTED since batch 7 (docs R6 L2): sealed, an unknown name was called "a paid tier" here, and at the
    // destination the join blamed SAIHM_TIER, which is not set there. Still never named, and nothing is written.
    const ex = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PAYG_CUSTOM', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(ex.code, 1, ex.stdout);
    assert.match(ex.stderr, /^saihm: not exported - the tier is not a plan name this version knows: /);
    assert.ok(!(ex.stdout + ex.stderr).includes('PAYG_CUSTOM'));
    assert.ok(!existsSync(join(home, 'exports')), 'nothing is sealed or written');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a SAIHM_HOME with the shape of a key is never printed: boot refuses it by name, export refuses', async () => {
  const base = tempHome('hm');
  try {
    const pass = passphraseWithDigit();
    const home = join(base, pass);
    const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED });
    try {
      const r = await d.call('saihm_recall', {});
      assert.ok(r.isError);
      // Since batch 7 boot itself refuses such a home, before anything is written under it (security R6 F1); the
      // memory tools named "the default key file (not there)" here before.
      assert.match(r.text, /^SAIHM_HOME holds what looks like a key, passphrase or token rather than a directory, so nothing is written there\. Fix SAIHM_HOME, then start a new session\./, r.text);
      const q = await d.call('saihm_join', {});
      assert.match(q.text, /Does this environment keep its home directory between sessions\?/);
      for (const t of [r.text, q.text]) assert.ok(!t.includes(pass));
    } finally {
      d.proc.kill();
    }
    const ex = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: identity().secretHex, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(ex.code, 1);
    assert.match(ex.stderr, /not exported - SAIHM_HOME holds what looks like a key/);
    assert.ok(!(ex.stdout + ex.stderr).includes(pass));
    assert.ok(!existsSync(join(home, 'exports')), 'nothing is written under it');
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('a key split by whitespace in SAIHM_MASTER_SECRET_FILE is not echoed by the join tool or the verb', async () => {
  const home = tempHome('sp');
  try {
    const h = randomBytes(32).toString('hex');
    const [a, b] = [h.slice(0, 32), h.slice(32)];
    const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_FILE: `${a} ${b}` });
    try {
      const r = await d.call('saihm_join', {});
      assert.ok(!r.text.includes(a) && !r.text.includes(b), r.text);
      assert.match(r.text, /not shown/);
    } finally {
      d.proc.kill();
    }
    const f = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_FILE: `${a}\n${b}` });
    assert.equal(f.code, 1);
    assert.ok(!(f.stdout + f.stderr).includes(a) && !(f.stdout + f.stderr).includes(b), f.stderr);
    assert.ok(!existsSync(join(home, KEY)));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('an unexpanded token reference is not "the identity in SAIHM_IDENTITY"; a key-shaped key-file path is not printed by an export', async () => {
  const home = tempHome('ux');
  try {
    const f = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_IDENTITY: '${SAIHM_IDENTITY}', SAIHM_IDENTITY_PASSPHRASE: generatePassphrase() });
    assert.equal(f.code, 1);
    assert.match(f.stderr, /SAIHM_IDENTITY holds an unexpanded reference/);
    assert.doesNotMatch(f.stderr, /uses the identity in SAIHM_IDENTITY/);
    assert.ok(!existsSync(join(home, KEY)));
    const name = randomBytes(32).toString('hex');
    const kf = join(home, `${name}.key`);
    writeFileSync(kf, identity().secretHex, { mode: 0o600 });
    const ex = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_FILE: kf, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(ex.code, 0, ex.stderr);
    assert.match(ex.stdout, /from:\s+a key file whose path has the shape of a key \(not shown\)/);
    assert.ok(!ex.stdout.includes(name));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('FREE written in another case is not a paid plan, and a paid plan without its payment method is told what is missing', async () => {
  const home = tempHome('pc');
  try {
    const hex = identity().secretHex;
    for (const tier of ['free', 'Free', ' ', ' FREE ']) {
      const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: tier });
      try {
        const r = await d.call('saihm_join', {});
        assert.match(r.text, /not to a plan name: for the free plan set it to FREE exactly, or leave it unset/, r.text);
        assert.equal(r.isError, false, 'the tier answer is a normal result, not a tool error');
        assert.doesNotMatch(r.text, /paid plan|nothing to join/);
      } finally {
        d.proc.kill();
      }
      const f = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: tier });
      assert.equal(f.code, 1, 'not a success');
      assert.match(f.stderr, /set it to FREE exactly/);
      assert.doesNotMatch(f.stdout + f.stderr, /paid plan|nothing to join/);
    }
    const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PRO' });
    try {
      const r = await d.call('saihm_join', {});
      // "configured for", since batch 7.
      assert.match(r.text, /configured for the PRO plan\. There is nothing to join, but SAIHM_PAYMENT_METHOD is not set/, r.text);
      // Where to set it, not "beside SAIHM_TIER": a plan carried by a token has no SAIHM_TIER here (docs R7 bL1).
      assert.match(r.text, /need it on this plan: set it where this server's other SAIHM_\* values are set\.$/, r.text);
      assert.equal(r.isError, false, 'the tier answer is a normal result, not a tool error');
      assert.doesNotMatch(r.text, /use it as it is/);
    } finally {
      d.proc.kill();
    }
    const f = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PRO' });
    assert.equal(f.code, 1, 'a plan that cannot onboard as configured is not a success');
    assert.match(f.stderr, /SAIHM_PAYMENT_METHOD is not set/);
    assert.equal(f.stdout, '');
    const withAuth = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PRO', SAIHM_AUTH_HEADER: 'Bearer t' });
    assert.equal(withAuth.code, 0, 'a static auth header needs no payment method');
    assert.match(withAuth.stdout, /the memory tools use it as it is/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a SAIHM_HOME with the shape of a key is never joined into, not even where a key is already there, and never printed', async () => {
  const base = tempHome('hj');
  try {
    const pass = passphraseWithDigit();
    const home = join(base, pass);
    const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED });
    try {
      const r = await d.call('saihm_join', { newIdentity: true });
      assert.match(r.text, /SAIHM_HOME holds what looks like a key, passphrase or token rather than a directory/, r.text);
      assert.ok(!r.isError, 'a normal answer, like the temporary-home refusal: the gate, not the backstop behind it');
      assert.ok(!r.text.includes(pass));
    } finally {
      d.proc.kill();
    }
    const f = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED });
    assert.equal(f.code, 1);
    assert.match(f.stderr, /not joined - SAIHM_HOME holds what looks like a key/);
    assert.ok(!(f.stdout + f.stderr).includes(pass));
    assert.ok(!existsSync(join(home, 'free-identity.key')), 'no key is created under it');
    mkdirSync(home, { recursive: true, mode: 0o700 });
    writeFileSync(join(home, 'free-identity.key'), identity().secretHex, { mode: 0o600 });
    await withMock({}, async (m) => {
      const d2 = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp' });
      try {
        const j = await d2.call('saihm_join', {});
        // Since batch 7 a key already under such a home is not used either: boot refuses the home before anything is
        // written under it (security R6 F1), where this join used to go on with the key, its path withheld.
        assert.match(j.text, /^SAIHM_HOME holds what looks like a key, passphrase or token rather than a directory, so nothing is written there\./, j.text);
        assert.doesNotMatch(j.text, /Using your existing memory key/);
        assert.ok(!j.text.includes(pass));
        assert.equal(m.joinStarts(), 0, 'no activation is started under it');
        assert.equal(m.onboards.length, 0, 'and nothing is onboarded');
      } finally {
        d2.proc.kill();
      }
    });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('saihm_join with newIdentity false asks the question and creates nothing', async () => {
  const home = tempHome('nf');
  try {
    await withMock({}, async (m) => {
      const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: m.base() + '/mcp' });
      try {
        const r = await d.call('saihm_join', { newIdentity: false });
        assert.match(r.text, /Does this environment keep its home directory between sessions\?/, r.text);
        assert.ok(!existsSync(join(home, 'free-identity.key')), 'no key');
        assert.equal(m.joinStarts(), 0, 'no device flow');
      } finally {
        d.proc.kill();
      }
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a plan name written in another case or with spaces is a slip, and an unknown name is not said to work', async () => {
  const home = tempHome('sl');
  try {
    const hex = identity().secretHex;
    for (const tier of ['pro', 'Pro', ' PRO']) {
      const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: tier, SAIHM_PAYMENT_METHOD: 'stripe' });
      try {
        const r = await d.call('saihm_join', {});
        assert.match(r.text, /not exactly to a plan name: set it to PRO, as plan names are written\. There is nothing to join\./, r.text);
        assert.equal(r.isError, false, 'the tier answer is a normal result, not a tool error');
        assert.doesNotMatch(r.text, /use it as it is/);
      } finally {
        d.proc.kill();
      }
      const f = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: tier, SAIHM_PAYMENT_METHOD: 'stripe' });
      assert.equal(f.code, 1, 'a slip is not a success');
      assert.match(f.stderr, /set it to PRO/);
    }
    const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PR0', SAIHM_PAYMENT_METHOD: 'stripe' });
    try {
      const r = await d.call('saihm_join', {});
      assert.match(r.text, /SAIHM_TIER is not a plan name this version knows\. For the free plan set it to FREE, or leave it unset, then join again; if it names a plan you were given, there is nothing to join\./, r.text);
      assert.equal(r.isError, false, 'the tier answer is a normal result, not a tool error');
      assert.doesNotMatch(r.text, /use it as it is|PR0/);
    } finally {
      d.proc.kill();
    }
    for (const tier of ['PR0', 'FRE', 'PAYG_CUSTOM']) {
      const f = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: tier, SAIHM_PAYMENT_METHOD: 'stripe' });
      assert.equal(f.code, 1, `${tier}: an unknown name is not a success`);
      assert.match(f.stderr, /not a plan name this version knows/);
      assert.doesNotMatch(f.stdout + f.stderr, new RegExp(`\\b${tier}\\b`), 'the value is not repeated');
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('export-identity refuses a tier slip before sealing it, naming the plan meant and not the value', async () => {
  const home = tempHome('es');
  try {
    const hex = identity().secretHex;
    for (const [tier, said] of [['free', /the tier is not exactly a plan name: set SAIHM_TIER to FREE, then export again/], ['Pro', /set SAIHM_TIER to PRO/], [' ', /the tier is blank/], ['enterprise-fast', /set SAIHM_TIER to ENTERPRISE_FAST/]] as const) {
      const ex = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: tier, SAIHM_PAYMENT_METHOD: 'stripe' });
      assert.equal(ex.code, 1, JSON.stringify(tier));
      assert.match(ex.stderr, said);
      assert.ok(!existsSync(join(home, 'exports')), 'nothing is sealed or written');
    }
    // Positive control: the exact plan name exports.
    const ok = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(ok.code, 0, ok.stderr);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

/** A generated passphrase with a digit in it: the shape a REFUSAL keys on (all letters happens about once in 1,800). */
function passphraseWithDigit(): string {
  for (;;) {
    const p = generatePassphrase();
    if (/\d/.test(p)) return p;
  }
}

test('a folder that only looks like a passphrase is not refused: export works under it, as a join does', async () => {
  const base = tempHome('fp');
  try {
    const home = join(base, 'saihm-agent-state-store');
    const ex = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: identity().secretHex, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(ex.code, 0, ex.stderr);
    assert.doesNotMatch(ex.stderr, /holds what looks like a key/);
    const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_MASTER_SECRET_HEX: identity().secretHex, SAIHM_TIER: 'ENTERPRISE-FAST', SAIHM_PAYMENT_METHOD: 'stripe' });
    try {
      const r = await d.call('saihm_join', {});
      assert.match(r.text, /set it to ENTERPRISE_FAST, as plan names are written/, r.text);
      assert.equal(r.isError, false, 'the tier answer is a normal result, not a tool error');
    } finally {
      d.proc.kill();
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('export-identity refuses a plan name this version does not know, and every refusal reads "saihm: not exported - "', async () => {
  const home = tempHome('ek');
  try {
    const hex = identity().secretHex;
    // FRE and PROFAST were sealed (exit 0): one called "a paid tier", one with only a "not shown" note (docs R6 L2).
    // A passphrase in SAIHM_TIER is refused the same way, with the verb's prefix (correctness R6 B7).
    const pass = generatePassphrase();
    for (const tier of ['FRE', 'PROFAST', pass]) {
      const ex = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: tier, SAIHM_PAYMENT_METHOD: 'stripe' });
      assert.equal(ex.code, 1, tier);
      assert.equal(
        ex.stderr,
        'saihm: not exported - the tier is not a plan name this version knows: set SAIHM_TIER to FREE, PRO,\n' +
          'PRO_FAST, ENTERPRISE or ENTERPRISE_FAST, then export again.\n',
      );
      assert.doesNotMatch(ex.stdout + ex.stderr, new RegExp(`\\b${tier}\\b`), 'the value is not repeated');
      assert.ok(!existsSync(join(home, 'exports')), 'nothing is sealed or written');
    }
    // A passphrase in the payment method is refused by the token itself, which the verb relays with its prefix.
    const pm = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: pass });
    assert.equal(pm.code, 1);
    assert.equal(pm.stderr, 'saihm: not exported - SAIHM_PAYMENT_METHOD holds what looks like an identity passphrase, not a plan setting. Fix it, then export again.\n');
    assert.ok(!(pm.stdout + pm.stderr).includes(pass) && !(pm.stdout + pm.stderr).includes(pass.replace(/-/g, '')));
    assert.ok(!existsSync(join(home, 'exports')), 'nothing is sealed or written');
    // Positive control: a plan name this version knows exports.
    const ok = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PRO_FAST', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(ok.code, 0, ok.stderr);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('an export under a folder withheld from display names its file by its own name, in the exports folder under SAIHM_HOME', async () => {
  // A folder named in five-letter words is not refused, but its path is withheld wherever it would be printed; the
  // file line printed it whole (security R6 F2, docs R6 L3, correctness R6 F1). The file's own name has no shape.
  const base = tempHome('wx');
  try {
    const home = join(base, 'saihm-agent-state-store');
    const hex = identity().secretHex;
    const ex = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(ex.code, 0, ex.stderr);
    const files = readdirSync(join(home, 'exports'));
    assert.equal(files.length, 1, 'the export is written');
    const name = files[0] as string;
    assert.match(name, /^identity-[0-9a-f]{16}-\d{8}T\d{9}Z\.env$/);
    const line = ex.stdout.split('\n').find((l) => l.startsWith('  file:  '));
    assert.equal(line, `  file:  ${name} in the exports folder under SAIHM_HOME, whose path has the shape of a key, so it is not shown (readable only by you)`);
    assert.ok(!ex.stdout.includes(base) && !ex.stdout.includes('saihm-agent-state-store'), ex.stdout);
    // An exports folder that is not private is refused there too, without its path.
    chmodSync(join(home, 'exports'), 0o750);
    const open = await runCli(['export-identity'], { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(open.code, 1);
    assert.match(open.stderr, /the export directory is not private to you: the exports folder under SAIHM_HOME\. It must be a directory you own/);
    assert.ok(!(open.stdout + open.stderr).includes('saihm-agent-state-store'), open.stderr);
    assert.equal(readdirSync(join(home, 'exports')).length, 1, 'nothing more is written');
    // Positive control: an ordinary folder is named in full.
    const plain = join(base, 'state');
    const shown = await runCli(['export-identity'], { SAIHM_HOME: plain, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(shown.code, 0, shown.stderr);
    assert.ok(shown.stdout.includes(`  file:  ${join(plain, 'exports')}/identity-`), shown.stdout);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('an export that cannot be written under a folder withheld from display gives the error code, never the path', { skip: process.getuid?.() === 0 && 'root ignores directory modes' }, async () => {
  // Node names the path in its own error; relayed as it was, it printed the folder the file line now withholds.
  const base = tempHome('wr');
  try {
    chmodSync(base, 0o500);
    const hex = identity().secretHex;
    const ex = await runCli(['export-identity'], { SAIHM_HOME: join(base, 'saihm-agent-state-store'), SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(ex.code, 1);
    assert.match(ex.stderr, /the export could not be written \(EACCES\): its folder under SAIHM_HOME has the shape of a key, so it is not shown\. Nothing was exported\./);
    assert.ok(!(ex.stdout + ex.stderr).includes(base) && !(ex.stdout + ex.stderr).includes('saihm-agent-state-store'), ex.stderr);
    // Positive control: under an ordinary folder, Node's own error and its path come through.
    const ctl = await runCli(['export-identity'], { SAIHM_HOME: join(base, 'state'), SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(ctl.code, 1);
    assert.match(ctl.stderr, /EACCES/);
    assert.ok(ctl.stderr.includes(join(base, 'state')), ctl.stderr);
  } finally {
    chmodSync(base, 0o700);
    rmSync(base, { recursive: true, force: true });
  }
});

test('a token that carries a plan this version does not know says the plan came from SAIHM_IDENTITY, on the tool and the verb', async () => {
  // Blaming SAIHM_TIER, which is not set where the token is used, sent the reader to a variable that is not there
  // (docs R6 L2). Sealed directly, as an older or newer version could have.
  const home = tempHome('tt');
  try {
    const t = tok(identity().secretHex, { tier: 'TEAM', paymentMethod: 'stripe' });
    const said = /^The plan carried in SAIHM_IDENTITY is not one this version knows\. Export the identity again with SAIHM_TIER set to its plan, or set SAIHM_TIER here to override it; if it names a plan you were given, there is nothing to join\.$/;
    const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase });
    try {
      const r = await d.call('saihm_join', {});
      assert.match(r.text, said, r.text);
      assert.equal(r.isError, false, 'the tier answer is a normal result, not a tool error');
      assert.doesNotMatch(r.text, /TEAM/);
    } finally {
      d.proc.kill();
    }
    const f = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase });
    assert.equal(f.code, 1, 'not a success');
    assert.match(f.stderr.trim(), said, f.stderr);
    assert.equal(f.stdout, '');
    // Positive control: the same plan name in SAIHM_TIER here is blamed on SAIHM_TIER.
    const g = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase, SAIHM_TIER: 'TEAM' });
    assert.equal(g.code, 1);
    assert.match(g.stderr, /^SAIHM_TIER is not a plan name this version knows\./);
    assert.ok(!existsSync(join(home, KEY)), 'nothing is minted');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a paid SAIHM_TIER with no identity here is not joined free: nothing is minted, on the verb or the tool', async () => {
  // The free join minted a key under a paid tier, failed activation, and every retry then took that key for the
  // paid identity configured here: "nothing to join", exit 0 (correctness R6 F3).
  const home = tempHome('mt');
  try {
    const paid = { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' };
    const refusal = "SAIHM_TIER names a plan other than FREE, but there is no identity here yet, and a free join starts a FREE one. Leave SAIHM_TIER unset (or set FREE) to join free; for a paid plan, join free first, then run `npx -y @saihm/mcp-server-pro upgrade <plan>`. If your paid identity is on another machine, run `npx -y @saihm/mcp-server-pro export-identity` there instead and set the two values it writes in this environment's settings.";
    for (let i = 0; i < 2; i++) {
      const f = await runCli(['free-join'], paid);
      assert.equal(f.code, 1, `try ${i + 1}: ${f.stdout}`);
      assert.equal(f.stderr, `saihm: not joined - ${refusal}\n`);
      assert.doesNotMatch(f.stdout, /nothing to join/);
      assert.ok(!existsSync(join(home, KEY)), 'no key is minted');
    }
    const d = await startServer(paid);
    try {
      const r = await d.call('saihm_join', { newIdentity: true });
      assert.equal(r.text, refusal);
      assert.equal(r.isError, false, 'a normal answer, like the other join gates');
      assert.ok(!existsSync(join(home, KEY)), 'no key is minted by the tool either');
    } finally {
      d.proc.kill();
    }
    // FREE written in another case is named as such, on both.
    const slip = 'SAIHM_TIER is set, but not to FREE exactly: set it to FREE, or leave it unset, then join again.';
    const g = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_TIER: 'free' });
    assert.equal(g.code, 1);
    assert.equal(g.stderr, `saihm: not joined - ${slip}\n`);
    const d2 = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_TIER: 'free' });
    try {
      const r = await d2.call('saihm_join', { newIdentity: true });
      assert.equal(r.text, slip);
      assert.equal(r.isError, false);
    } finally {
      d2.proc.kill();
    }
    assert.ok(!existsSync(join(home, KEY)), 'no key is minted');
    // Padded FREE, or spaces only, is not FREE exactly either: the gate trimmed it, minted, and the client then
    // failed it as a paid tier with no payment method (security R7 B2).
    for (const padded of [' FREE ', 'FREE ', '  ']) {
      const gp = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_TIER: padded });
      assert.equal(gp.code, 1);
      assert.equal(gp.stderr, `saihm: not joined - ${slip}\n`);
      const dp = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_TIER: padded });
      try {
        const r = await dp.call('saihm_join', { newIdentity: true });
        assert.equal(r.text, slip);
        assert.equal(r.isError, false);
      } finally {
        dp.proc.kill();
      }
      assert.ok(!existsSync(join(home, KEY)), `a padded FREE (${JSON.stringify(padded)}) mints nothing`);
    }
    // Positive control: FREE exactly is joined - the key is minted, and only the closed endpoint fails it.
    const h = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_TIER: 'FREE' });
    assert.equal(h.code, 1);
    assert.doesNotMatch(h.stderr, /not joined/);
    assert.ok(existsSync(join(home, KEY)), 'FREE mints, then fails on the closed endpoint');
    // EMPTY is the default, as the client reads it: the README's hosted .mcp.json passes "${SAIHM_TIER:-}", empty
    // wherever SAIHM_TIER is not set, so the gate that refuses a padded FREE must still let it join free.
    const empty = tempHome('mt-empty');
    try {
      const e = await runCli(['free-join'], { SAIHM_HOME: empty, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_TIER: '' });
      assert.equal(e.code, 1);
      assert.doesNotMatch(e.stderr, /not joined/);
      assert.ok(existsSync(join(empty, KEY)), 'an empty SAIHM_TIER mints, then fails on the closed endpoint');
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a failed join under a folder withheld from display names free-identity.key there, never a variable nobody set', async () => {
  // The join set SAIHM_MASTER_SECRET_FILE to the key it minted, and the failure guidance then blamed that variable
  // as if the operator had pasted a key into it (correctness R6 F4).
  const base = tempHome('f4');
  try {
    const home = join(base, 'saihm-agent-state-store');
    const f = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED });
    assert.equal(f.code, 1);
    assert.ok(existsSync(join(home, KEY)), 'the join minted its key before the endpoint failed');
    assert.match(f.stderr, /\n  This machine's key file is free-identity\.key under SAIHM_HOME, whose path has the shape of a key, so it is not shown\.\n/, f.stderr);
    // The tool's failure text comes from the same place: this time it activates the key the verb minted.
    const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED });
    let tool = '';
    try {
      tool = (await d.call('saihm_join', {})).text;
    } finally {
      d.proc.kill();
    }
    assert.match(tool, /\n  This machine's key file is free-identity\.key under SAIHM_HOME, whose path has the shape of a key, so it is not shown\.\n/, tool);
    // With SAIHM_HOME unset the key is in ~/.saihm, and the line says so.
    const userHome = join(base, 'brand-north-ridge-quiet');
    mkdirSync(userHome);
    const u = await runCli(['free-join'], { HOME: userHome, SAIHM_ENDPOINT_URL: CLOSED });
    assert.equal(u.code, 1);
    assert.ok(existsSync(join(userHome, '.saihm', KEY)), 'minted in ~/.saihm');
    assert.match(u.stderr, /\n  This machine's key file is free-identity\.key in ~\/\.saihm, whose path has the shape of a key, so it is not shown\.\n/, u.stderr);
    for (const out of [f.stdout + f.stderr, tool, u.stdout + u.stderr]) {
      assert.doesNotMatch(out, /SAIHM_MASTER_SECRET_FILE holds/);
      assert.ok(!out.includes('saihm-agent-state-store') && !out.includes('brand-north-ridge-quiet'), out);
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('saihm_join reads newIdentity: null as unset, as clients that fill every field send it (correctness R7 F2)', async () => {
  const home = tempHome('nn');
  try {
    const d = await startServer({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED });
    try {
      const a = await d.call('saihm_join', {});
      const b = await d.call('saihm_join', { newIdentity: null });
      assert.equal(b.text, a.text);
      assert.equal(b.isError, a.isError);
      assert.ok(!existsSync(join(home, KEY)), 'null is not a yes: nothing is minted');
    } finally {
      d.proc.kill();
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('free-join with self-join off, a key and no SAIHM_TIER names the missing tier, never a TypeError (correctness R7 B4)', async () => {
  const home = tempHome('nt');
  try {
    const f = await runCli(['free-join'], { SAIHM_HOME: home, SAIHM_ENDPOINT_URL: CLOSED, SAIHM_SELF_JOIN: '0', SAIHM_MASTER_SECRET_HEX: randomBytes(32).toString('hex') });
    assert.equal(f.code, 1);
    assert.doesNotMatch(f.stderr, /TypeError/, f.stderr);
    assert.match(f.stderr, /set SAIHM_TIER/, f.stderr);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
