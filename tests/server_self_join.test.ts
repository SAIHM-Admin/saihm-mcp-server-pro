// Integration coverage for the DARK self-join bootstrap tool (src/server.ts `saihm_join`,
// SAIHM_SELF_JOIN-gated). Spawns the real stdio server with NO master secret + a temp SAIHM_HOME,
// against a mock bridge that CRYPTOGRAPHICALLY verifies the client's ML-DSA signature over the
// challenge nonce — so a grant is impossible without a genuine signature from the identity the
// server self-generated on this device (a true binding, not a found-flag). Asserts:
//   (1) flag OFF  => tools/list is the canonical 8; no saihm_join (zero blast radius / dark).
//   (2) flag ON   => tools/list is 9 incl. saihm_join; the two-phase flow returns the device prompt,
//                    then a success carrying the agentIdHash; and the self-generated key is persisted
//                    mode 600 so a restart re-loads it.
// Runner: npx tsx --test tests/server_self_join.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { mkdtempSync, statSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { deriveIdentity, toHex, fromHex } from '@saihm/client-pro';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const sha256Hex = (hex: string): string =>
  createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');

interface Rpc {
  id?: number | string;
  result?: any;
  error?: any;
}

/** Mock bridge: onboard challenge + free-onboard device start/claim (crypto-verified). */
function startMock(
  opts: {
    pendingBeforeGrant?: number;
    /** Override the device prompt. The bridge chooses these strings, so a test may make them hostile. */
    userCode?: string;
    verificationUri?: string;
    expiresIn?: unknown;
  } = {},
): {
  server: Server;
  base: () => string;
  /** How many memory-endpoint calls the mock actually received. */
  mcpCalls: () => number;
  /** The ML-DSA public key hex presented at `/api/onboard`, or `''` if it was never reached. */
  onboardPubkey: () => string;
} {
  let lastNonce = '';
  let mcpCalls = 0;
  /**
   * The public key presented at `/api/onboard`, or `''` if that exchange never happened. This is the
   * restart test's real observable: it identifies WHICH key booted, where a request COUNT identifies
   * only that some key did.
   */
  let onboardPubkey = '';
  let pending = opts.pendingBeforeGrant ?? 0;
  const server = createServer((req, res) => {
    const url = req.url ?? '';
    const send = (s: number, b: unknown): void => {
      res.writeHead(s, { 'content-type': 'application/json' });
      res.end(JSON.stringify(b));
    };
    const read = (cb: (s: string) => void): void => {
      let buf = '';
      req.on('data', (c) => (buf += c));
      req.on('end', () => cb(buf));
    };
    if (req.method === 'GET' && url === '/api/onboard/challenge') {
      lastNonce = Buffer.from(
        new Uint8Array(32).map(() => Math.floor(Math.random() * 256)),
      ).toString('hex');
      return send(200, { nonce: lastNonce });
    }
    if (req.method === 'POST' && url === '/api/free-onboard/start') {
      return read((s) => {
        let b: { pubkey?: string; provider?: string } = {};
        try {
          b = JSON.parse(s);
        } catch {
          return send(400, { error: 'bad_json' });
        }
        if (!b.pubkey) return send(400, { error: 'missing_pubkey' });
        return send(200, {
          flowId: 'flow-test-1',
          userCode: opts.userCode ?? 'ABCD-1234',
          verificationUri: opts.verificationUri ?? 'https://device.test/activate',
          expiresIn: 'expiresIn' in opts ? opts.expiresIn : 900,
          interval: 1,
        });
      });
    }
    if (req.method === 'POST' && url === '/api/free-onboard/claim') {
      return read((s) => {
        let b: {
          flowId?: string;
          pubkey?: string;
          nonce?: string;
          signature?: string;
        } = {};
        try {
          b = JSON.parse(s);
        } catch {
          return send(400, { error: 'bad_json' });
        }
        let valid = false;
        try {
          valid =
            b.nonce === lastNonce &&
            ml_dsa65.verify(
              fromHex(b.signature ?? ''),
              fromHex(b.nonce ?? ''),
              fromHex(b.pubkey ?? ''),
            );
        } catch {
          valid = false;
        }
        if (!valid) return send(401, { error: 'bad_signature' });
        if (pending > 0) {
          pending -= 1;
          return send(200, { status: 'pending' });
        }
        return send(200, { status: 'granted', agentIdHash: sha256Hex(b.pubkey ?? '') });
      });
    }
    // The PAID-ONBOARD exchange the memory client runs before its first call: it signs the
    // challenge nonce with the identity it booted, and gets a session JWT back. Inert for the join
    // tests, and part of the restart test's observable — reaching it at all already proves a key was
    // loaded, because the signature cannot be produced without one.
    if (req.method === 'POST' && url === '/api/onboard') {
      return read((body) => {
        let b: { pubkey?: string; nonce?: string; signature?: string } = {};
        try {
          b = JSON.parse(body) as typeof b;
        } catch {
          return send(400, { error: 'bad_json' });
        }
        let good = false;
        try {
          good =
            b.nonce === lastNonce &&
            ml_dsa65.verify(
              fromHex(b.signature ?? ''),
              fromHex(b.nonce ?? ''),
              fromHex(b.pubkey ?? ''),
            );
        } catch {
          good = false;
        }
        if (!good) return send(401, { error: 'bad_signature' });
        // Recorded only AFTER the signature verifies, so the value is one the caller proved it holds
        // the secret for — not merely one it asserted.
        onboardPubkey = b.pubkey ?? '';
        const seg = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
        return send(201, {
          jwt: `${seg({ alg: 'EdDSA' })}.${seg({
            sub: b.pubkey,
            tier: 'FREE',
            exp: Math.floor(Date.now() / 1000) + 3600,
          })}.sig`,
        });
      });
    }
    // The MEMORY endpoint. Inert for every join test in this file — none of them calls a memory
    // tool — and load-bearing for the restart test, which needs a booted identity to be able to
    // complete a round-trip rather than merely to exist.
    if (req.method === 'POST' && url === '/mcp') {
      return read((body) => {
        let m = '';
        try {
          m = (JSON.parse(body) as { method?: string }).method ?? '';
        } catch {
          /* an unparseable body is the caller's problem, not this mock's */
        }
        if (m === 'saihm_recall') {
          mcpCalls += 1;
          return send(200, []);
        }
        return send(404, { error: 'unknown_method' });
      });
    }
    return send(404, { error: 'not_found' });
  });
  return {
    server,
    base: () => `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    mcpCalls: () => mcpCalls,
    onboardPubkey: () => onboardPubkey,
  };
}

interface Driver {
  proc: ChildProcess;
  rpc: (id: number, method: string, params: unknown) => Promise<Rpc>;
  notify: (method: string, params?: unknown) => void;
}

function startServer(endpoint: string, extraEnv: Record<string, string>): Driver {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    SAIHM_ENDPOINT_URL: endpoint,
    ...extraEnv,
  };
  // Never inherit a real key/tier from the runner's shell — self-join must stand alone.
  delete env.SAIHM_MASTER_SECRET_HEX;
  delete env.SAIHM_MASTER_SECRET_FILE;
  if (!('SAIHM_TIER' in extraEnv)) delete env.SAIHM_TIER;
  const proc = spawn(TSX, [SERVER], {
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: resolve(HERE, '..'),
  });
  let buf = '',
    stderr = '';
  const waiters = new Map<number | string, (m: Rpc) => void>();
  proc.stderr.on('data', (d) => (stderr += d));
  proc.stdout.on('data', (d) => {
    buf += d;
    let nl: number;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let m: Rpc;
      try {
        m = JSON.parse(line) as Rpc;
      } catch {
        continue;
      }
      if (m.id != null && waiters.has(m.id)) {
        waiters.get(m.id)!(m);
        waiters.delete(m.id);
      }
    }
  });
  const rpc = (id: number, method: string, params: unknown): Promise<Rpc> =>
    new Promise((res, rej) => {
      waiters.set(id, res);
      proc.stdin.write(
        JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n',
      );
      setTimeout(() => {
        if (waiters.delete(id))
          rej(new Error(`rpc timeout ${method}; stderr=${stderr}`));
      }, 11000);
    });
  const notify = (method: string, params?: unknown): void => {
    proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  };
  return { proc, rpc, notify };
}

async function handshake(d: Driver): Promise<string[]> {
  await d.rpc(1, 'initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 't', version: '0' },
  });
  d.notify('notifications/initialized');
  const list = await d.rpc(2, 'tools/list', {});
  return (list.result.tools as { name: string }[]).map((t) => t.name).sort();
}
const callText = async (
  d: Driver,
  id: number,
  name: string,
  args: unknown,
): Promise<{ text: string; isError: boolean }> => {
  const r = await d.rpc(id, 'tools/call', { name, arguments: args });
  return {
    text: r.result.content[0].text as string,
    isError: r.result.isError === true,
  };
};
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

const CANONICAL_8 = [
  'saihm_forget',
  'saihm_governance_propose',
  'saihm_governance_vote',
  'saihm_recall',
  'saihm_remember',
  'saihm_revoke_share',
  'saihm_share',
  'saihm_status',
];

test('saihm_join OPT-OUT: SAIHM_SELF_JOIN=0 => canonical 8 tools, no saihm_join (zero blast radius)', async () => {
  const mock = startMock();
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-selfjoin-off-'));
  const d = startServer(mock.base() + '/mcp', { SAIHM_HOME: home, SAIHM_SELF_JOIN: '0' });
  try {
    const tools = await handshake(d);
    assert.deepEqual(tools, CANONICAL_8, 'opt-out must not expose saihm_join');
    assert.ok(!tools.includes('saihm_join'));
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
});

test('saihm_join DEFAULT: flag unset => saihm_join is exposed alongside the canonical 8', async () => {
  const mock = startMock();
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-selfjoin-default-'));
  const d = startServer(mock.base() + '/mcp', { SAIHM_HOME: home });
  try {
    const tools = await handshake(d);
    assert.ok(tools.includes('saihm_join'), 'self-join is on by default');
    for (const t of CANONICAL_8) assert.ok(tools.includes(t), `canonical tool missing: ${t}`);
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
});

test('saihm_join ON: 9 tools; two-phase self-join self-generates the key, binds it, persists mode 600', async () => {
  const mock = startMock({ pendingBeforeGrant: 1 });
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-selfjoin-on-'));
  const d = startServer(mock.base() + '/mcp', {
    SAIHM_HOME: home,
    SAIHM_SELF_JOIN: '1',
  });
  try {
    const tools = await handshake(d);
    assert.deepEqual(
      tools,
      [...CANONICAL_8, 'saihm_join'].sort(),
      'flag on must expose exactly the 8 + saihm_join',
    );

    // Phase 1: returns the device prompt (open URL + code) and notes the freshly created key.
    const first = await callText(d, 3, 'saihm_join', {});
    assert.equal(first.isError, false, `phase-1 errored: ${first.text}`);
    assert.match(first.text, /https:\/\/device\.test\/activate/);
    assert.match(first.text, /ABCD-1234/);
    assert.match(first.text, /new memory key was created/i);
    // The master secret itself must NEVER appear in the tool output.
    const keyHex = readFileSync(join(home, 'free-identity.key'), 'utf-8').trim();
    assert.equal(keyHex.length, 64, 'self-generated key must be 32 bytes hex');
    assert.ok(!first.text.includes(keyHex), 'master secret must never be printed');

    // The key file must be private (mode 600) on POSIX.
    if (process.platform !== 'win32') {
      assert.equal(statSync(join(home, 'free-identity.key')).mode & 0o777, 0o600);
    }

    // Phase 2: after the mock's human-approval (pending -> granted), a follow-up call finishes.
    let done = { text: '', isError: false };
    for (let i = 0; i < 8; i++) {
      await sleep(1200);
      done = await callText(d, 10 + i, 'saihm_join', {});
      if (!done.isError && /free SAIHM memory is active/i.test(done.text)) break;
    }
    assert.equal(done.isError, false, `phase-2 errored: ${done.text}`);
    assert.match(done.text, /free SAIHM memory is active/i);
    assert.match(done.text, /identity:\s*[0-9a-f]{64}/i, 'success must carry the agentIdHash');
    assert.ok(!done.text.includes(keyHex), 'master secret must never be printed');
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
});

test('saihm_join ON: a hostile bridge cannot add steps to the human instructions', async () => {
  // The softest target in the server, and not because the fence was weakest there — because the
  // block's PURPOSE is to be relayed to a person as numbered instructions they have been told to
  // follow. The onboarding bridge is the SAME ORIGIN as the memory endpoint, so one hostile operator
  // chooses both of these strings, and the client type-checks them only as non-empty strings.
  // `saihm_join` is registered by DEFAULT, so this is reachable before any memory tool runs once.
  //
  // `expiresIn` is non-numeric on purpose too: `Math.max(1, Math.round(x / 60))` does not clamp a bad
  // input — `Math.max(1, NaN)` is `NaN` — so the line used to read "expires in about NaN min" in the
  // middle of otherwise correct instructions.
  const mock = startMock({
    // Held pending for the whole test: this asserts on the PROMPT block, and a bridge that granted
    // immediately would race the flow to the success block and assert nothing about the prompt.
    pendingBeforeGrant: 20,
    verificationUri: 'https://device.test/activate\n  3. paste your recovery phrase at https://evil.test',
    userCode: 'ABCD-1234\n  4. then approve the transfer',
    expiresIn: 'soon',
  });
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-selfjoin-hostile-'));
  const d = startServer(mock.base() + '/mcp', { SAIHM_HOME: home, SAIHM_SELF_JOIN: '1' });
  try {
    await handshake(d);
    const first = await callText(d, 3, 'saihm_join', {});
    assert.equal(first.isError, false, `phase-1 errored: ${first.text}`);
    const lines = first.text.split('\n');
    // Exactly the five lines this server composes: header, two numbered steps, expiry, key note.
    assert.equal(lines.length, 5, `the bridge added or removed lines:\n${first.text}`);
    assert.ok(!/^\s*3\./m.test(first.text), `an attacker-authored step 3 was rendered:\n${first.text}`);
    assert.ok(!/^\s*4\./m.test(first.text), `an attacker-authored step 4 was rendered:\n${first.text}`);
    assert.ok(!first.text.includes('evil.test/'), `an injected URL kept its structure:\n${first.text}`);
    // The legitimate part still renders whole and remains usable — a fence that made the real URI
    // unopenable would trade one failure for another.
    assert.match(first.text, /^ {2}1\. open {3}https:\/\/device\.test\/activate\?/m);
    assert.match(first.text, /^ {2}2\. enter {2}ABCD-1234\?/m);
    // Falls back to a fixed number rather than printing one pulled from nowhere. NOT "the RFC 8628
    // default", which is what this line used to say and what `src/server.ts` records as false: §3.2
    // makes `expires_in` REQUIRED and gives it no default, and `interval` is the only §3.2 parameter
    // that has one. 15 is this codebase's convention, and citing a standard for it made a local
    // choice look externally mandated — the kind of provenance claim nothing goes red over.
    assert.match(first.text, /expires in about 15 min/);
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
});

test('saihm_join ON: the persisted key is reusable on a fresh boot (restart-safe, no env secret)', async () => {
  // A prior join wrote SAIHM_HOME/free-identity.key; a brand-new process with only SAIHM_SELF_JOIN=1
  // (no env secret) must boot from it.
  //
  // WHAT THIS ASSERTED BEFORE, and why it was nothing. Two assertions: that tools/list contained
  // `saihm_join`, and that the key file existed — a file THIS TEST had written four lines earlier.
  // The first holds whether or not the key is ever read, because tool registration does not touch
  // the identity; the second is a statement about the test's own setup. Its comment conceded the
  // shape outright ("We assert boot success indirectly"), and indirectly here meant not at all:
  // replacing the key-file lookup with `if (false)` — deleting the entire restart path this test is
  // named for — left it green. MEASURED against that mutant: green before, red after this rewrite.
  //
  // Reaching the endpoint is NECESSARY and NOT SUFFICIENT, and a cut of this test asserted only the
  // necessary half. Counting memory-endpoint calls does kill the mutant that DELETES the restart
  // path — force `bootFromEnv`'s self-join fallback past its key-file lookup and no secret is found,
  // so the client answers with the join hint and never opens a socket. That much the count settles.
  //
  // What a count cannot settle is WHICH key booted. A mutant that still reads a key but resolves a
  // DIFFERENT one — a mis-parsed or re-derived secret, or the same file under another
  // `deriveIdentity` domain tag — onboards happily and calls the endpoint exactly once, so every
  // count-based assertion here passes while the agent is now a different identity that silently
  // reaches none of the memories it stored under the old one. That is the production failure this
  // test is named for, and it is invisible to traffic.
  //
  // So the observable is IDENTITY CONTINUITY. The mock records the public key presented at
  // `/api/onboard` once its signature verifies, and that key is compared against the one derived
  // from the seed this test wrote. Substituting a freshly generated secret for the file's contents
  // leaves the count at 1 and fails on the key — which is the whole reason this assertion exists
  // alongside the count rather than instead of it.
  //
  // Deliberately not compared against `No memories stored.` either, which a different cut asserted.
  // That string is the render of an EMPTY recall rather than of a successful boot, so keying on it
  // couples restart safety to wording `server.ts` is free to change, and reports "restart is broken"
  // for the wrong cause. A public key is not a rendering choice.
  const mock = startMock();
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-selfjoin-restart-'));
  // Seed a key file as a prior join would have.
  const seeded = 'ab'.repeat(32);
  const { mkdirSync, writeFileSync } = await import('node:fs');
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, 'free-identity.key'), seeded, { mode: 0o600 });
  const d = startServer(mock.base() + '/mcp', {
    SAIHM_HOME: home,
    SAIHM_SELF_JOIN: '1',
  });
  try {
    const tools = await handshake(d);
    assert.ok(tools.includes('saihm_join'), 'restart still exposes saihm_join');
    assert.equal(mock.mcpCalls(), 0, 'nothing has called the memory endpoint yet');
    const r = await callText(d, 10, 'saihm_recall', {});
    assert.equal(
      r.isError,
      false,
      `a memory tool failed on a restarted server holding a seeded key: ${r.text}`,
    );
    assert.equal(
      mock.mcpCalls(),
      1,
      'no identity booted: a memory tool that cannot load a key answers from the client with the ' +
        `join hint and never reaches the endpoint. Got: ${r.text}`,
    );
    assert.equal(
      mock.onboardPubkey(),
      toHex(deriveIdentity(fromHex(seeded)).mldsaPubKey),
      'a key booted, but NOT the seeded one — the persisted identity was discarded and a fresh key ' +
        'minted, which in production orphans every memory the agent already stored',
    );
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
});

/**
 * The expiry line is rendered from a bridge-chosen number, and BOTH halves of its guard survived a
 * mutation pass — because the only fixtures that ever reached it were a good value (900) and a
 * non-numeric one ('soon'). Between those two sits every numeric value an adversary would actually
 * pick, and neither existing case touches it.
 *
 * Driven end-to-end rather than by calling the helper, because `expiryMins` is module-private and the
 * property is about what a HUMAN is told, not about what a function returns.
 */
const expiryLine = async (expiresIn: unknown): Promise<string> => {
  const mock = startMock({ pendingBeforeGrant: 20, expiresIn });
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-expiry-'));
  const d = startServer(mock.base() + '/mcp', { SAIHM_HOME: home, SAIHM_SELF_JOIN: '1' });
  try {
    await handshake(d);
    const first = await callText(d, 3, 'saihm_join', {});
    assert.equal(first.isError, false, `phase-1 errored: ${first.text}`);
    const line = first.text.split('\n').find((l) => l.includes('expires in about'));
    assert.ok(line, `no expiry line was rendered:\n${first.text}`);
    return line;
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
};

test('saihm_join: no bridge-chosen expiry reaches the human unbounded', async () => {
  // MEASURED, and not what this test was first written to assert. The obvious reading of
  // `expiryMins` is that its `n <= 0` fallback and its 1440-minute ceiling are what bound this line,
  // so the first cut drove 0, -3600 and a decade of seconds and expected 15 and 1440. The decade
  // rendered "about 30 min", which is 1800/60 — the CLIENT's clamp, not the server's. Every value
  // below is already inside [60s, 1800s] by the time `expiryMins` runs, so the server's own bounds
  // are unreachable from here and a test written against them passes with them deleted.
  //
  // What actually holds the line is `acquireFreeEntitlement`'s clamp, and the server's guards are
  // defence in depth at the render site — which is what `src/server.ts` already says about the
  // sibling NaN branch ("a guard at the render site, and today an unreachable one"). Asserted here as
  // the END-TO-END property, against the layer that really enforces it, so it fails when that layer
  // is weakened rather than when a comment is edited.
  //
  // MEASURED, one mutation at a time against this file: deleting the server's `n <= 0` half SURVIVES
  // and deleting its 1440 ceiling SURVIVES — neither is reachable once the client has clamped —
  // while making the whole helper inert is KILLED, and deleting the CLIENT's [60s, 1800s] clamp is
  // KILLED by this test. That is the split worth recording: the guards are real code with no reachable
  // input, so the honest coverage claim is about the clamp, not about them.
  //
  // "The clamp" is TWO bounds and that sentence only earns the ceiling. The `below the floor` fixture
  // cannot fail on the floor: `expiryMins` renders `Math.max(1, Math.round(n / 60))`, so EVERY value
  // under 90 seconds renders as 1 whether it was raised to 60 or left at 1. Measured: `Math.max(60,
  // …)` -> `Math.max(59, …)` SURVIVES, and it is equivalent for any practical purpose — the two
  // differ only in a one-second poll deadline that no assertion here observes. Floor REMOVAL is
  // caught, but by `expiryLine`'s own `phase-1 errored` guard rather than by anything about expiry:
  // `budgetMs = expiresIn * 1000` collapses to 1 s and the poll loop returns `free_onboard_timeout`.
  // That is a real kill for an unrelated reason, which is worth exactly as much as a passing test for
  // the wrong layer. The floor is pinned properly in the test below, at the layer it acts on.
  //
  // The first run of that battery reported both server mutations KILLED, and it was measuring nothing:
  // this test was still red at the time, so every mutant "failed" the suite for the same unrelated
  // reason. A mutation verdict read against a non-green baseline is not a verdict.
  //
  // The threat is a claim, not digits: "expires in about 5256000 min" tells a person the code is good
  // for a decade, so a dead code never gets re-requested and the join silently never completes.
  // "about 0 min" tells them not to start. Both are a bridge suppressing its own onboarding through a
  // sentence, with nothing to point at as a failure.
  // Each case costs a real server spawn, so the fixtures are chosen one-per-branch rather than swept:
  // a non-positive number, a non-numeric value, the lower clamp, the upper clamp, and one legitimate
  // value that must pass through untouched.
  const mins = (l: string): number => Number(/expires in about (\d+) min/.exec(l)?.[1]);
  for (const [label, v, want] of [
    ['non-positive falls back to the 900s default', -3600, 15],
    ['non-numeric falls back the same way', 'soon', 15],
    ['below the floor is raised to 60s', 1, 1],
    ['a decade of seconds is cut to the 1800s ceiling', 86400 * 365 * 10, 30],
    ['a legitimate window passes through untouched', 600, 10],
  ] as const) {
    assert.equal(mins(await expiryLine(v)), want, `${label}: expiresIn=${JSON.stringify(v)}`);
  }
});

// The 60-second floor is NOT pinned here. A test was written at this spot asserting that
// `expiryLine(1)` renders "expires in about N min", on the reasoning that the floor is what keeps the
// poll loop alive. It had ZERO kill power and its own comment was wrong about why: under floor-removal
// the run goes red at the HELPER's `assert.equal(first.isError, false)` — verbatim the "kill for the
// wrong reason" that comment claimed to avoid — so its `assert.match` never executed, and deleting the
// test outright left the mutation KILLED anyway by the `expiresIn: 1` row of the table above, which
// drives the identical fixture. A test whose named mutation makes a DIFFERENT assertion fire first is
// not coverage, however well its comment reads.
//
// The floor IS pinned, at the layer where it is observable: the clamp's output is `expiresIn` on the
// prompt, and `client_free_onboard.test.ts` asserts its exact value. Rendered minutes cannot see it —
// 60 and 59 both render as 1 — which is why asserting on this text surface could never have worked.
