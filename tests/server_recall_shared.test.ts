// Integration coverage for the widened `saihm_recall` tool (src/server.ts): the additive shared-read
// branch that routes {sharerPinnedAgentIdHashHex, sharerRecord, cellId} to client.recallShared while
// leaving the own-memories path (and the 8-tool count) unchanged. The recallShared CRYPTO open is
// already proven end-to-end at the client (client_pro.test.ts PC51); here we prove the TOOL WRAPPER:
//   - routing: sharer params (a real, pin-consistent sharer identity) reach recallShared, which calls
//     the endpoint with {sharer, cellId}; a no-grant endpoint reply surfaces as "No shared cell found".
//   - validation: a sharer pin without the record/cellId is rejected with a clear message (no network).
//   - regression: no sharer params => the base recall(query) path is unchanged; tool count stays 8.
// Runner: npx tsx --test tests/server_recall_shared.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { deriveIdentity, encodeIdentityRecord, toHex, fromHex } from '@saihm/client-pro';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const MASTER_HEX = '33'.repeat(32); // the recipient server boots from this
const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');

interface Rpc {
  id?: number | string;
  result?: any;
  error?: any;
}

/** Mock endpoint: onboard challenge/verify + a /mcp that records the last saihm_recall params. */
function startMock(): { server: Server; base: () => string; lastRecall: () => any } {
  let lastNonce = '';
  let lastRecallParams: any = null;
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
        let b: { pubkey?: string; nonce?: string; signature?: string } = {};
        try {
          b = JSON.parse(s);
        } catch {
          return send(400, { error: 'bad_json' });
        }
        let ok = false;
        try {
          ok =
            b.nonce === lastNonce &&
            ml_dsa65.verify(fromHex(b.signature ?? ''), fromHex(b.nonce ?? ''), fromHex(b.pubkey ?? ''));
        } catch {
          ok = false;
        }
        if (!ok) return send(401, { error: 'bad_signature' });
        return send(201, {
          jwt: `${b64url({ alg: 'EdDSA' })}.${b64url({ sub: b.pubkey, tier: 'PRO', exp: Math.floor(Date.now() / 1000) + 3600 })}.sig`,
        });
      });
    }
    if (req.method === 'POST' && url === '/mcp') {
      return read((s) => {
        let m = '',
          params: any = {};
        try {
          const j = JSON.parse(s);
          m = j.method ?? '';
          params = j.params ?? {};
        } catch {
          /* ignore */
        }
        if (m === 'saihm_recall') {
          lastRecallParams = params;
          // A shared-read carries {sharer, cellId}; report no live grant (null path).
          if (params.sharer) return send(200, { found: false });
          // Own recall-all => empty.
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
    lastRecall: () => lastRecallParams,
  };
}

interface Driver {
  proc: ChildProcess;
  rpc: (id: number, method: string, params: unknown) => Promise<Rpc>;
  notify: (method: string, params?: unknown) => void;
}
function startServer(endpoint: string): Driver {
  const env = {
    ...process.env,
    SAIHM_ENDPOINT_URL: endpoint,
    SAIHM_MASTER_SECRET_HEX: MASTER_HEX,
    SAIHM_TIER: 'PRO',
    SAIHM_PAYMENT_METHOD: 'stripe',
  };
  delete env.SAIHM_SELF_JOIN;
  const proc = spawn(TSX, [SERVER], { env, stdio: ['pipe', 'pipe', 'pipe'], cwd: resolve(HERE, '..') });
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
      let mm: Rpc;
      try {
        mm = JSON.parse(line) as Rpc;
      } catch {
        continue;
      }
      if (mm.id != null && waiters.has(mm.id)) {
        waiters.get(mm.id)!(mm);
        waiters.delete(mm.id);
      }
    }
  });
  const rpc = (id: number, method: string, params: unknown): Promise<Rpc> =>
    new Promise((res, rej) => {
      waiters.set(id, res);
      proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      setTimeout(() => {
        if (waiters.delete(id)) rej(new Error(`rpc timeout ${method}; stderr=${stderr}`));
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
const callText = async (d: Driver, id: number, name: string, args: unknown): Promise<{ text: string; isError: boolean }> => {
  const r = await d.rpc(id, 'tools/call', { name, arguments: args });
  return { text: r.result.content[0].text as string, isError: r.result.isError === true };
};

test('saihm_recall widened: tool count stays 8 (shared-read is additive, NOT a 9th tool)', async () => {
  const mock = startMock();
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const d = startServer(mock.base() + '/mcp');
  try {
    const tools = await handshake(d);
    assert.equal(tools.length, 8, `expected 8 tools, got ${tools.join(',')}`);
    assert.ok(tools.includes('saihm_recall'));
    assert.ok(!tools.includes('saihm_join'));
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
  }
});

test('saihm_recall shared-read routes to recallShared with {sharer, cellId}; no grant => not found', async () => {
  const mock = startMock();
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const d = startServer(mock.base() + '/mcp');
  try {
    await handshake(d);
    // A real, pin-consistent sharer identity so recallShared's verifyIdentityRecord pin check passes.
    const A = deriveIdentity(new Uint8Array(32).fill(60));
    const r = await callText(d, 3, 'saihm_recall', {
      sharerPinnedAgentIdHashHex: toHex(A.agentIdHash),
      sharerRecord: encodeIdentityRecord(A.identityRecord),
      cellId: 'cellShared1',
    });
    assert.equal(r.isError, false, `shared-read errored: ${r.text}`);
    assert.match(r.text, /No shared cell found/i);
    // The tool actually reached recallShared, which called the endpoint with the sharer + cellId.
    const p = mock.lastRecall();
    assert.equal(p.sharer, toHex(A.agentIdHash), 'endpoint must be queried with the sharer hash');
    assert.equal(p.cellId, 'cellShared1');
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
  }
});

test('saihm_recall shared-read: sharer pin without record/cellId is rejected clearly', async () => {
  const mock = startMock();
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const d = startServer(mock.base() + '/mcp');
  try {
    await handshake(d);
    const A = deriveIdentity(new Uint8Array(32).fill(61));
    const r = await callText(d, 3, 'saihm_recall', {
      sharerPinnedAgentIdHashHex: toHex(A.agentIdHash),
    });
    assert.equal(r.isError, true);
    assert.match(r.text, /sharerPinnedAgentIdHashHex, sharerRecord, and cellId together/);
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
  }
});

test('saihm_recall shared-read: record/cellId WITHOUT the sharer pin fails loud (no silent own-recall)', async () => {
  const mock = startMock();
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const d = startServer(mock.base() + '/mcp');
  try {
    await handshake(d);
    const r = await callText(d, 3, 'saihm_recall', { cellId: 'cellShared9' });
    assert.equal(r.isError, true);
    assert.match(r.text, /sharerPinnedAgentIdHashHex, sharerRecord, and cellId together/);
    // Must NOT have fallen through to an own-recall call.
    assert.equal(mock.lastRecall(), null, 'partial shared-read args must not trigger own recall');
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
  }
});

test('saihm_recall base path unchanged: no sharer params => own recall(query)', async () => {
  const mock = startMock();
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const d = startServer(mock.base() + '/mcp');
  try {
    await handshake(d);
    const r = await callText(d, 3, 'saihm_recall', { query: 'anything' });
    assert.equal(r.isError, false);
    assert.match(r.text, /No memories stored\./);
    // Own recall must NOT send a sharer field to the endpoint.
    const p = mock.lastRecall();
    assert.ok(!p || p.sharer === undefined, 'own recall must not carry a sharer param');
  } finally {
    d.proc.kill();
    await new Promise<void>((r) => mock.server.close(() => r()));
  }
});
