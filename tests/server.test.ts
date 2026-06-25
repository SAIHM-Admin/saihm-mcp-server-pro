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
import { dirname, resolve } from 'node:path';
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

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const MASTER_HEX = '33'.repeat(32); // the master secret the spawned server boots from

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

function startServer(endpoint: string, args: string[] = []): Driver {
  const env = {
    ...process.env,
    SAIHM_ENDPOINT_URL: endpoint,
    SAIHM_MASTER_SECRET_HEX: MASTER_HEX,
    SAIHM_TIER: 'PRO',
    SAIHM_PAYMENT_METHOD: 'stripe',
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
    assert.match(
      (await callText(d, 4, 'saihm_remember', { content: 'hello world' })).text,
      /REMEMBERED \[abc123\] seq=1 shard=sh1/,
    );
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
