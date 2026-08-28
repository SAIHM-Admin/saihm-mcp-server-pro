// Integration coverage for the runnable stdio MCP server (src/server.ts): spawn it, complete the MCP
// handshake, and drive tools/list + tools/call for every tool against a mock endpoint, asserting the
// output-wiring strings + the typed-error (fail) path + the `join` CLI. recall(non-empty) and share use
// a REAL sealed envelope (sealed with the server's own derived identity), so the open/attribution path
// is exercised for real, not stubbed. Complements client_pro.test.ts (which unit-tests SaihmProClient).
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, join as pathJoin, resolve } from 'node:path';
import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  deriveIdentity,
  sealCell,
  encodeEnvelope,
  encodeIdentityRecord,
  utf8,
  toHex,
  fromHex,
} from '@saihm/client-pro';
import {
  MAX_CHECKOUT_URL_CHARS,
  MAX_JOIN_FIELD_CHARS,
} from '../src/render_fence.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const MASTER_HEX = '33'.repeat(32); // the master secret the spawned server boots from

// `join` persists the checkout URL under SAIHM_STATE_DIR, defaulting to ~/.saihm. Left unset, every
// run of this suite writes into the operator's real home directory — test pollution that outlives
// the test. Point it at a throwaway dir instead, and remove it when the process exits.
const TEST_STATE_DIR = mkdtempSync(pathJoin(tmpdir(), 'saihm-pro-test-'));
process.on('exit', () => rmSync(TEST_STATE_DIR, { recursive: true, force: true }));

interface Rpc {
  id?: number | string;
  result?: any;
  error?: any;
}
const b64url = (o: unknown): string =>
  Buffer.from(JSON.stringify(o)).toString('base64url');

interface MockOpts {
  recallAll?: unknown[];
  recallOneWire?: unknown;
  checkoutUrl?: string;
}

/** Mock SAIHM operator endpoint: onboard challenge/verify, hosted checkout, + canned /mcp tool responses. */
function startMock(opts: MockOpts = {}): {
  server: Server;
  base: () => string;
} {
  let lastNonce = '';
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
    if (req.method === 'POST' && url === '/api/onboard') {
      return read((s) => {
        let b: { pubkey?: string; nonce?: string; signature?: string };
        try {
          b = JSON.parse(s);
        } catch {
          return send(400, { error: 'bad_json' });
        }
        let ok = false;
        try {
          ok =
            b.nonce === lastNonce &&
            ml_dsa65.verify(
              fromHex(b.signature ?? ''),
              fromHex(b.nonce ?? ''),
              fromHex(b.pubkey ?? ''),
            );
        } catch {
          ok = false;
        }
        if (!ok) return send(401, { error: 'bad_signature' });
        return send(201, {
          jwt: `${b64url({ alg: 'EdDSA' })}.${b64url({ sub: b.pubkey, tier: 'PRO', exp: Math.floor(Date.now() / 1000) + 3600 })}.sig`,
        });
      });
    }
    if (req.method === 'POST' && url === '/api/stripe/checkout') {
      return read(() =>
        send(200, {
          url:
            opts.checkoutUrl ?? 'https://checkout.stripe.com/c/pay/test_hosted',
          agentIdHash: 'x',
        }),
      );
    }
    if (req.method === 'POST' && url === '/mcp') {
      return read((s) => {
        let m = '',
          params: { cellId?: string } = {};
        try {
          const j = JSON.parse(s) as {
            method?: string;
            params?: { cellId?: string };
          };
          m = j.method ?? '';
          params = j.params ?? {};
        } catch {
          /* ignore */
        }
        if (m === 'saihm_status')
          return send(200, {
            agentIdHashHex: 'deadbeefcafebabe0011',
            tier: 'PRO',
            activeShardCount: 2,
            activeSharingContracts: 1,
            bfsi: 0.5,
            bfsi_R: '1',
            bfsi_M: '2',
            prsInstrumented: true,
            snapshotEpoch: '495000',
            custody: 'COTI',
          });
        if (m === 'saihm_remember')
          return send(200, {
            cellId: 'abc123',
            shardId: 'sh1',
            seq: '1',
            commitmentHash: 'de'.repeat(16),
          });
        if (m === 'saihm_forget')
          return send(200, {
            cellId: 'abc123',
            shardId: 'sh1',
            complete: true,
            sharesPurged: 0,
            steps: [],
            epoch: '495000',
          });
        if (m === 'saihm_revoke_share')
          return send(200, {
            cellId: 'abc123',
            recipient: 'feed'.repeat(8),
            revoked: true,
          });
        if (m === 'saihm_recall')
          return send(
            200,
            params.cellId
              ? { found: true, wire: opts.recallOneWire }
              : (opts.recallAll ?? []),
          );
        if (m === 'saihm_share')
          return send(200, {
            cellId: 'cellX',
            sharer: 'aa'.repeat(16),
            recipient: 'bb'.repeat(16),
          });
        if (m === 'saihm_governance_propose' || m === 'saihm_governance_vote')
          return send(403, { error: 'governance_unavailable' });
        return send(404, { error: 'unknown_method' });
      });
    }
    return send(404, { error: 'not_found' });
  });
  return {
    server,
    base: () => `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
  };
}

interface Driver {
  proc: ChildProcess;
  rpc: (id: number, method: string, params: unknown) => Promise<Rpc>;
  notify: (method: string, params?: unknown) => void;
}

function startServer(
  endpoint: string,
  args: string[] = [],
  extraEnv: NodeJS.ProcessEnv = {},
): Driver {
  const env = {
    ...process.env,
    SAIHM_ENDPOINT_URL: endpoint,
    SAIHM_MASTER_SECRET_HEX: MASTER_HEX,
    SAIHM_TIER: 'PRO',
    SAIHM_PAYMENT_METHOD: 'stripe',
    // This suite pins the core tool wiring; opt out of self-join (on by default)
    // so tools/list stays the canonical eight. Self-join has its own suite.
    SAIHM_SELF_JOIN: '0',
    SAIHM_STATE_DIR: TEST_STATE_DIR,
    ...extraEnv,
  };
  const proc = spawn(TSX, [SERVER, ...args], {
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
      }, 12000);
    });
  const notify = (method: string, params?: unknown): void => {
    proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  };
  return { proc, rpc, notify };
}

async function handshake(d: Driver): Promise<string[]> {
  const init = await d.rpc(1, 'initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 't', version: '0' },
  });
  // Must stay distinct from the standards client's `saihm`: two separately published packages
  // announcing one serverInfo.name lets directories that key on it conflate them.
  assert.equal(init.result.serverInfo.name, 'saihm-pro');
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

test('server.ts: handshake, tools/list, core tool wiring + fail() path', async () => {
  const mock = startMock(); // recall-all => [] (empty branch)
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const d = startServer(mock.base() + '/mcp');
  try {
    assert.deepEqual(await handshake(d), [
      'saihm_forget',
      'saihm_governance_propose',
      'saihm_governance_vote',
      'saihm_recall',
      'saihm_remember',
      'saihm_revoke_share',
      'saihm_share',
      'saihm_status',
    ]);
    const st = await callText(d, 3, 'saihm_status', {});
    assert.match(st.text, /SAIHM Session/);
    assert.match(st.text, /tier=PRO/);
    assert.match(st.text, /shards=2/);
    assert.equal(st.isError, false);
    // The mock echoes `cellId: 'abc123'` and `seq: 1`; this asserts the receipt shows NEITHER.
    // It used to assert the opposite — that the echo reached the agent — which is precisely the
    // defect: three of the four receipt fields have a local, authenticated source (the cellId this
    // client generated, its own monotonic seq, the commitment read off the envelope it sealed) and
    // taking them from the response let the endpoint name any cell it liked on a write the agent
    // explicitly asked for. `shardId` alone is still the endpoint's, because only the endpoint knows
    // where it stored the bytes.
    const rem = (await callText(d, 4, 'saihm_remember', { content: 'hello world' })).text;
    assert.match(rem, /^REMEMBERED \[[0-9a-f]{32}\] seq=1 shard=sh1 commit=[0-9a-f]{16}…$/);
    assert.ok(!rem.includes('abc123'), "the endpoint's echoed cellId must not reach the receipt");
    assert.match(
      (await callText(d, 5, 'saihm_forget', { id: 'abc123' })).text,
      /FORGOTTEN \[abc123\] complete=true/,
    );
    assert.match(
      (
        await callText(d, 6, 'saihm_revoke_share', {
          cellId: 'abc123',
          recipientHex: 'feed'.repeat(8),
        })
      ).text,
      /REVOKED cell=abc123 .*revoked=true/,
    );
    assert.match(
      (await callText(d, 7, 'saihm_recall', {})).text,
      /No memories stored\./,
    );
    const gp = await callText(d, 8, 'saihm_governance_propose', {
      scope: 'emission_param',
    });
    assert.equal(gp.isError, true);
    assert.match(gp.text, /governance_unavailable/);
    const gv = await callText(d, 9, 'saihm_governance_vote', {
      proposalId: 'p1',
      approve: true,
    });
    assert.equal(gv.isError, true);
    assert.match(gv.text, /governance_unavailable/);
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
  }
});

test('server.ts: recall(non-empty) + share over a REAL sealed envelope', async () => {
  const me = deriveIdentity(fromHex(MASTER_HEX));
  const env = sealCell({
    plaintext: utf8('shared secret'),
    kek: me.kek,
    mldsaSecretKey: me.mldsaSecretKey,
    mldsaPubKey: me.mldsaPubKey,
    agentIdHash: me.agentIdHash,
    cellId: 'cellX',
    seq: 1n,
    tier: 'PRO',
  });
  const wire = encodeEnvelope(env);
  const mock = startMock({
    recallAll: [{ cellId: 'cellX', found: true, wire }],
    recallOneWire: wire,
  });
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const recip = deriveIdentity(fromHex('44'.repeat(32)));
  const d = startServer(mock.base() + '/mcp');
  try {
    await handshake(d);
    const rc = await callText(d, 3, 'saihm_recall', {});
    assert.match(rc.text, /RECALL 1 memories/);
    assert.match(rc.text, /\[cellX\] seq=1 \| shared secret/);
    const sh = await callText(d, 4, 'saihm_share', {
      cellId: 'cellX',
      recipientRecord: encodeIdentityRecord(recip.identityRecord),
      recipientPinnedAgentIdHashHex: toHex(recip.agentIdHash),
    });
    assert.equal(sh.isError, false);
    assert.match(sh.text, /SHARED cell=cellX/);
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
  }
});

test('server.ts: `join` CLI prints the hosted Stripe checkout link', async () => {
  const URL_OUT = 'https://checkout.stripe.com/c/pay/server_test_join';
  const mock = startMock({ checkoutUrl: URL_OUT });
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  try {
    const out = await new Promise<string>((res, rej) => {
      const d = startServer(mock.base() + '/mcp', ['join']);
      let o = '';
      d.proc.stdout!.on('data', (c) => (o += c));
      d.proc.on('close', () => res(o));
      d.proc.on('error', rej);
      setTimeout(() => {
        d.proc.kill();
        rej(new Error('join timeout'));
      }, 12000);
    });
    assert.ok(
      out.includes(URL_OUT),
      'join output should contain the checkout URL; got: ' + out,
    );
  } finally {
    await new Promise<void>((r) => mock.server.close(() => r()));
  }
});

test('server.ts: `join` CLI cannot have extra instructions forged into it', async () => {
  // A terminal is a rendering surface too. This block is addressed to a HUMAN and tells them to open
  // a link and pay, so a newline in the endpoint-chosen checkout URL appends further instructions in
  // the tool's own voice — including a fabricated `identity (agentIdHash):` line, which the operator
  // may then publish for others to pin. `startsWith('https://')` was the only check, and a `\x1b[2K\r`
  // additionally erases the legitimate URL on a real terminal.
  //
  // Written because the fence for this went in with no test: removing it from BOTH call sites left
  // the whole suite green, which is the same "a fence indistinguishable from its own absence" this
  // branch has now hit three times.
  const HOSTILE =
    'https://checkout.example/pay\r\n\r\n  SAIHM — subscribe this identity to activate your memory:' +
    '\r\n\r\n  https://attacker.example/steal\r\n\r\n  identity (agentIdHash): ' +
    '0'.repeat(64);
  const mock = startMock({ checkoutUrl: HOSTILE });
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  try {
    const out = await new Promise<string>((res, rej) => {
      const d = startServer(mock.base() + '/mcp', ['join']);
      let o = '';
      d.proc.stdout!.on('data', (c) => (o += c));
      d.proc.on('close', () => res(o));
      d.proc.on('error', rej);
      setTimeout(() => {
        d.proc.kill();
        rej(new Error('join timeout'));
      }, 12000);
    });
    // Built with escapes: a literal U+2028 in this SOURCE file is itself a line terminator and
    // breaks the parse, which is the same property being asserted about the rendered output.
    const RENDERED = new RegExp('\\r\\n|[\\n\\r\\u2028\\u2029\\u0085\\u000b\\u000c]');
    const rendered = out.split(RENDERED);
    // STRUCTURE, not vocabulary — the same distinction the render-fence tests make. A URL is
    // free-form, so it can only be sanitised, never checked, and the attacker's text therefore
    // survives flattened into the one line it was interpolated into. That residue is by design and
    // is bounded. What must not survive is a LINE: a second instruction, in the tool's own voice,
    // that a human reads as the next step.
    assert.ok(
      !rendered.some((l) => /^\s*https?:\/\/attacker\.example/.test(l)),
      `an attacker-authored URL began a line of its own:\n${out}`,
    );
    assert.equal(
      rendered.filter((l) => l.trimStart().startsWith('identity (agentIdHash):')).length,
      1,
      `the endpoint forged an extra identity line:\n${out}`,
    );
    // The whole payload lands on ONE line, because that is what the fence guarantees: it cannot add
    // lines. Five separators went in; the block must still have the line count the server composed.
    assert.ok(
      rendered.filter((l) => l.includes('attacker.example')).length === 1,
      `the payload was spread across lines rather than flattened into one:\n${out}`,
    );
    assert.ok(!out.includes('\x1b'), `an ANSI escape survived to the terminal:\n${out}`);
    // The legitimate half still renders and is still usable — a fence that made the real URL
    // unopenable would trade one failure for another.
    assert.ok(out.includes('https://checkout.example/pay'), `the real URL was lost:\n${out}`);
  } finally {
    await new Promise<void>((r) => mock.server.close(() => r()));
  }
});

// --- hosted-checkout URL delivery (incident 2026-08-27) ---------------------
// A hosted checkout URL carries a MANDATORY `#fid…` fragment, and a copy that loses it is refused
// by Stripe with "This link is incomplete" — which, to the payer, is indistinguishable from a broken
// backend. The fixture below carries the shape MEASURED against the live API on 2026-08-27 and
// recorded in INCIDENT-stripe-checkout-fragment-2026-08-27.md: 523 characters total, of which the
// fragment is 422. The first 40 fragment characters are the measured ones verbatim; the rest is
// opaque padding to the measured length, drawn only from the alphabet that measurement attests
// (base64 plus percent-escapes).
//
// RESIDUAL, stated because it cannot be closed from here: only the first 40 characters of a live
// fragment were ever recorded, so the full alphabet is unattested. `safeField` replaces `[`, `]` and
// `|` with `?`, so a live fragment containing one of those unescaped would be delivered corrupt.
// Nothing observed suggests it does, and inventing such a character here would assert a premise no
// measurement supports.
const FRAGMENT = (
  "fidnandhYHdWcXxpYCc%2FJ2FgY2RwaXEnKSd2cG" +
  "Jyd2YGB3c2B2YFVrJz8nZGZmYHZxWjA0S0BLPWFEZ21NRlZQNTFXcXR3TktMNTNx%2F".repeat(
    6,
  )
).slice(0, 422);
const HOSTED_URL =
  "https://checkout.stripe.com/c/pay/" +
  ("cs_live_a1N8E8V7" + "kQ7mZ2pR9xT4vB6nL8cJ3wY5hD1gF0sA".repeat(2)).slice(
    0,
    66,
  ) +
  "#" +
  FRAGMENT;

/**
 * Run the server as a CLI subcommand and collect its stdout until it exits.
 *
 * The two cases below want what the `join` cases above build inline — spawn, accumulate stdout,
 * resolve on close — plus a state directory of their own, so they share one helper rather than a
 * third and fourth copy of the block.
 */
function runCli(
  endpoint: string,
  args: string[],
  extraEnv: NodeJS.ProcessEnv = {},
): Promise<string> {
  return new Promise<string>((res, rej) => {
    const d = startServer(endpoint, args, extraEnv);
    let o = "";
    d.proc.stdout!.on("data", (c) => (o += c));
    d.proc.on("close", () => res(o));
    d.proc.on("error", rej);
    setTimeout(() => {
      d.proc.kill();
      rej(new Error(`${args[0]} timeout`));
    }, 12000);
  });
}

/**
 * Both halves of the delivery: the URL a human reads, and the file they can open instead.
 *
 * Written as one helper over both call sites because they compose the same two functions from the
 * same two budgets. `render_fence.ts` records that both sites once fenced this URL with
 * {@link MAX_JOIN_FIELD_CHARS}, sized and documented for a device-flow URI of "well under 100
 * characters" — a hosted URL cut there is a link that looks actionable and opens nothing. Testing
 * only one site would leave half of that fix pinned by nothing. Each site was mutated in isolation
 * to confirm it: each failed only its own case, so neither is standing in for the other.
 */
function assertCheckoutDelivered(out: string, dir: string): void {
  // The fixture has to sit in the window where the two budgets DISAGREE, or neither assertion below
  // can tell them apart.
  assert.ok(
    HOSTED_URL.length > MAX_JOIN_FIELD_CHARS &&
      HOSTED_URL.length < MAX_CHECKOUT_URL_CHARS,
    "fixture must exceed the join-field budget and fit the checkout budget",
  );
  // The delimiters exist so that truncation in transit is VISIBLE. Match them, and the URL is
  // pinned to one line, byte for byte, with nothing else on it — which is the whole claim.
  const block =
    /--- BEGIN CHECKOUT URL \(one line, open unmodified\) ---\n {2}(.*)\n {2}--- END CHECKOUT URL ---/.exec(
      out,
    );
  assert.ok(block, `the delimited checkout block was not printed:\n${out}`);
  assert.equal(
    block[1],
    HOSTED_URL,
    "the printed URL must be the endpoint URL, whole",
  );
  assert.ok(
    block[1].endsWith("#" + FRAGMENT),
    "the #fid fragment is REQUIRED by Stripe — never strip or cut it",
  );
  // Where the block SAYS it saved the URL is where the URL must actually be. Asserting only that
  // the operator's home stayed clean would be satisfied just as well by the write silently failing.
  const saved = /Also written to: (\S+)/.exec(out);
  assert.ok(saved, `the block did not report where the URL was saved:\n${out}`);
  assert.equal(saved[1], pathJoin(dir, "checkout-url.txt"));
  // On disk it is one line and unreflowed: a file is the one delivery channel that cannot cut at
  // the `#`, which is why `persistCheckoutUrl` exists at all.
  assert.equal(readFileSync(saved[1], "utf8"), HOSTED_URL + "\n");
}

test("server.ts: `join` delivers a fragment-bearing checkout URL whole, printed and on disk", async () => {
  const dir = mkdtempSync(pathJoin(tmpdir(), "saihm-join-frag-"));
  const mock = startMock({ checkoutUrl: HOSTED_URL });
  await new Promise<void>((r) => mock.server.listen(0, "127.0.0.1", () => r()));
  try {
    assertCheckoutDelivered(
      await runCli(mock.base() + "/mcp", ["join"], { SAIHM_STATE_DIR: dir }),
      dir,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
    await new Promise<void>((r) => mock.server.close(() => r()));
  }
});

test("server.ts: `upgrade` delivers a fragment-bearing checkout URL whole, printed and on disk", async () => {
  // The second call site, and the reason this file covers it: `requestUpgradeUrl` refuses a paid
  // identity, so reaching it needs SAIHM_TIER=FREE — which is exactly why a `join`-only test would
  // never have exercised it.
  const dir = mkdtempSync(pathJoin(tmpdir(), "saihm-upgrade-frag-"));
  const mock = startMock({ checkoutUrl: HOSTED_URL });
  await new Promise<void>((r) => mock.server.listen(0, "127.0.0.1", () => r()));
  try {
    assertCheckoutDelivered(
      await runCli(mock.base() + "/mcp", ["upgrade", "PRO"], {
        SAIHM_TIER: "FREE",
        SAIHM_STATE_DIR: dir,
      }),
      dir,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
    await new Promise<void>((r) => mock.server.close(() => r()));
  }
});

test("server.ts: a planted symlink at checkout-url.txt cannot redirect the write", async () => {
  // The footgun this guards is a REVERSION, not a bug: writing the URL directly to a fixed path is
  // the obvious implementation, and `writeFileSync` follows symlinks. MEASURED on this deployment:
  // the default state dir `~/.saihm` is 0775 owned by a group with a second member, so a same-group
  // local user can plant that name as a link to `master_secret.hex` sitting beside it — destroying
  // the identity, and with it every cell, on the next `upgrade`. Two properties keep that shut and
  // the test needs both: the tmp write uses `wx` (O_EXCL) so it refuses any path that already
  // exists, and `renameSync` replaces the destination ENTRY rather than following a link at it.
  const dir = mkdtempSync(pathJoin(tmpdir(), "saihm-symlink-"));
  const victim = pathJoin(dir, "master_secret.hex");
  writeFileSync(victim, "SECRET-IDENTITY-DO-NOT-CLOBBER\n");
  symlinkSync(victim, pathJoin(dir, "checkout-url.txt"));
  const mock = startMock({ checkoutUrl: HOSTED_URL });
  await new Promise<void>((r) => mock.server.listen(0, "127.0.0.1", () => r()));
  try {
    const out = await runCli(mock.base() + "/mcp", ["join"], {
      SAIHM_STATE_DIR: dir,
    });
    assert.equal(
      readFileSync(victim, "utf8"),
      "SECRET-IDENTITY-DO-NOT-CLOBBER\n",
      "the symlink target must be untouched",
    );
    // Not just "the victim survived": the planted link must have been REPLACED by a real file
    // holding the URL. A write that silently failed would also leave the victim intact, so this is
    // what separates the fix from a regression into best-effort silence.
    const to = pathJoin(dir, "checkout-url.txt");
    assert.ok(!lstatSync(to).isSymbolicLink(), "the planted link is replaced, not followed");
    assert.equal(readFileSync(to, "utf8"), HOSTED_URL + "\n");
    assertCheckoutDelivered(out, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    await new Promise<void>((r) => mock.server.close(() => r()));
  }
});
