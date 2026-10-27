// saihm_share with recipientRecordFile (0.14.3), through the real stdio server against a mock bridge that verifies the
// sign-in and keeps a real sealed cell. The file `identity-record` writes is enough to share: the grant goes to the
// identity it names, and only that identity's own key opens it; the bridge receives exactly what an inline share sends.
// Every refusal (a pin that is not the file's, a file beside an inline record, no recipient, a file that is not a
// record) is made before anything is asked of the endpoint, and shows nothing of the file, in the result or the log.
// Runner: npx tsx --test tests/server_share_record_file.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  decodeShareEnvelope,
  deriveIdentity,
  encodeEnvelope,
  encodeIdentityRecord,
  fromHex,
  openCellWithDek,
  sealCell,
  toHex,
  unwrapSharedDek,
} from '@saihm/client-pro';

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
  /** Every request, sign-ins included. */
  requests: () => number;
  /** The params of every saihm_share the bridge received. */
  shares: Record<string, any>[];
}

/** A bridge that verifies the sign-in, serves one sealed cell by id, and keeps every share it is sent. */
function startMock(cellId: string, wire: unknown): Mock {
  let lastNonce = '';
  let n = 0;
  const shares: Record<string, any>[] = [];
  const server = createServer((req, res) => {
    n++;
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
          ok = j.nonce === lastNonce && ml_dsa65.verify(fromHex(j.signature ?? ''), fromHex(j.nonce ?? ''), fromHex(j.pubkey ?? ''));
        } catch {
          ok = false;
        }
        if (!ok) return send(401, { error: 'bad_signature' });
        return send(201, { jwt: `${b64url({ alg: 'EdDSA' })}.${b64url({ sub: j.pubkey, tier: 'PRO', exp: Math.floor(Date.now() / 1000) + 3600 })}.sig` });
      }
      if (req.method === 'POST' && url === '/mcp') {
        if (j.method === 'saihm_recall') return send(200, j.params?.cellId === cellId ? { found: true, wire } : j.params?.cellId ? { found: false } : []);
        if (j.method === 'saihm_share') {
          shares.push(j.params ?? {});
          return send(200, { cellId, sharer: 'aa'.repeat(32), recipient: 'bb'.repeat(32) });
        }
        return send(404, { error: 'unknown_method' });
      }
      return send(404, { error: 'not_found' });
    });
  });
  return { server, url: () => `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`, requests: () => n, shares };
}

interface Reply {
  text: string;
  isError: boolean;
  structuredContent?: unknown;
}

interface Driver {
  proc: ChildProcess;
  stderr: () => string;
  call: (name: string, args: unknown) => Promise<Reply>;
}

async function startServer(env: Record<string, string>): Promise<Driver> {
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
        if (waiters.delete(id)) rej(new Error(`rpc timeout ${method}`));
      }, 30000);
    });
  await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const call = async (name: string, args: unknown): Promise<Reply> => {
    const m = await rpc('tools/call', { name, arguments: args });
    assert.equal(m.error, undefined, `${name}: JSON-RPC error ${JSON.stringify(m.error)}`);
    return { text: String(m.result?.content?.[0]?.text ?? ''), isError: m.result?.isError === true, structuredContent: m.result?.structuredContent };
  };
  return { proc, stderr: () => stderr, call };
}

/** The real `identity-record` verb, for the identity whose key file is in `home`, writing `file`. */
function writeRecordWithCli(home: string, file: string): void {
  execFileSync(TSX, [SERVER, 'identity-record', file], { env: childEnv({ HOME: home, SAIHM_HOME: home }), cwd: home, stdio: 'pipe', timeout: 60_000 });
}

interface Setup {
  dir: string;
  cellId: string;
  sharer: ReturnType<typeof deriveIdentity>;
  sealed: ReturnType<typeof sealCell>;
  recipient: ReturnType<typeof deriveIdentity>;
  recordFile: string;
  doc: { agentIdHash: string; identityRecord: Record<string, string> };
  mock: Mock;
  d: Driver;
}

async function setup(): Promise<Setup> {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-share-recfile-'));
  const sharerHex = randomBytes(32).toString('hex');
  const sharer = deriveIdentity(fromHex(sharerHex));
  const cellId = randomBytes(16).toString('hex');
  const sealed = sealCell({
    plaintext: new TextEncoder().encode('release runbook'),
    kek: sharer.kek,
    mldsaSecretKey: sharer.mldsaSecretKey,
    mldsaPubKey: sharer.mldsaPubKey,
    agentIdHash: sharer.agentIdHash,
    cellId,
    seq: 1n,
    tier: 'PRO',
  });
  // The colleague: their own home and key file, from which the real verb writes the record they send.
  const recipHome = join(dir, 'colleague');
  mkdirSync(recipHome, { mode: 0o700 });
  const recipHex = randomBytes(32).toString('hex');
  writeFileSync(join(recipHome, 'free-identity.key'), recipHex, { mode: 0o600 });
  const recordFile = join(dir, 'qa-agent.json');
  writeRecordWithCli(recipHome, recordFile);
  const doc = JSON.parse(readFileSync(recordFile, 'utf8'));
  const mock = startMock(cellId, encodeEnvelope(sealed));
  await new Promise<void>((r) => mock.server.listen(0, '127.0.0.1', () => r()));
  const home = join(dir, 'home');
  mkdirSync(home, { mode: 0o700 });
  const d = await startServer({
    HOME: home,
    SAIHM_HOME: home,
    SAIHM_ENDPOINT_URL: mock.url(),
    SAIHM_MASTER_SECRET_HEX: sharerHex,
    SAIHM_TIER: 'PRO',
    SAIHM_PAYMENT_METHOD: 'stripe',
    SAIHM_SELF_JOIN: '0',
  });
  return { dir, cellId, sharer, sealed, recipient: deriveIdentity(fromHex(recipHex)), recordFile, doc, mock, d };
}

async function teardown(s: Setup): Promise<void> {
  s.d.proc.kill();
  await new Promise<void>((r) => s.mock.server.close(() => r()));
  rmSync(s.dir, { recursive: true, force: true });
}

test('a share to the record file goes to the identity it names: only that key opens it, and the bridge gets what an inline share sends', async () => {
  const s = await setup();
  try {
    assert.equal(s.doc.agentIdHash, toHex(s.recipient.agentIdHash), 'the file the verb wrote names the colleague');
    const r = await s.d.call('saihm_share', { cellId: s.cellId, recipientRecordFile: s.recordFile, scope: 'read' });
    assert.equal(r.isError, false, r.text);
    assert.equal(r.text, `SHARED cell=${s.cellId} sharer=${toHex(s.sharer.agentIdHash).slice(0, 16)}… recipient=${s.doc.agentIdHash.slice(0, 16)}…`);
    assert.equal(s.mock.shares.length, 1);
    const sent = s.mock.shares[0]!;
    assert.deepEqual(sent.recipientRecord, s.doc.identityRecord, 'the record sent is the file\'s');
    assert.equal(sent.scope, 'read');
    const share = decodeShareEnvelope(sent.shareWire);
    assert.equal(toHex(share.recipientAgentIdHash), s.doc.agentIdHash);
    // The grant opens with the colleague's own key, and with no other.
    const dek = unwrapSharedDek({
      share,
      recipientMlkemSecretKey: s.recipient.mlkemSecretKey,
      recipientAgentIdHash: s.recipient.agentIdHash,
      sharerPinnedMldsaPubKey: s.sharer.mldsaPubKey,
    });
    assert.equal(new TextDecoder().decode(openCellWithDek(s.sealed, dek)), 'release runbook');
    const stranger = deriveIdentity(randomBytes(32));
    assert.throws(() =>
      unwrapSharedDek({ share, recipientMlkemSecretKey: stranger.mlkemSecretKey, recipientAgentIdHash: s.recipient.agentIdHash, sharerPinnedMldsaPubKey: s.sharer.mldsaPubKey }),
    );

    // The pin checked out-of-band, in capitals as a person may copy it: the same agent ID, so the same share.
    const pinned = await s.d.call('saihm_share', {
      cellId: s.cellId,
      recipientRecordFile: s.recordFile,
      recipientPinnedAgentIdHashHex: s.doc.agentIdHash.toUpperCase(),
    });
    assert.equal(pinned.isError, false, pinned.text);
    assert.match(pinned.text, new RegExp(`recipient=${s.doc.agentIdHash.slice(0, 16)}…$`));

    // A host that fills every field (strict function calling) sends the inline pair blank beside the file.
    const strict = await s.d.call('saihm_share', {
      cellId: s.cellId,
      recipientRecordFile: s.recordFile,
      recipientRecord: { mldsaPubKey: '', mlkemPubKey: '', mlkemPubKeySelfSig: '' },
      recipientPinnedAgentIdHashHex: '',
      scope: '',
      expiryEpoch: '',
    });
    assert.equal(strict.isError, false, strict.text);
    assert.equal(s.mock.shares.length, 3);
    assert.deepEqual(s.mock.shares[2]!.recipientRecord, s.doc.identityRecord);

    // Nothing else about sharing changed: the same record given inline, with its pin, sends the bridge the same fields
    // and the same record. (The same record: each derivation signs afresh, so a re-derived one differs in its signature.)
    const inline = await s.d.call('saihm_share', {
      cellId: s.cellId,
      recipientRecord: s.doc.identityRecord,
      recipientPinnedAgentIdHashHex: s.doc.agentIdHash,
      scope: 'read',
    });
    assert.equal(inline.isError, false, inline.text);
    assert.equal(inline.text, r.text);
    assert.equal(s.mock.shares.length, 4);
    assert.deepEqual(Object.keys(s.mock.shares[3]!).sort(), Object.keys(sent).sort());
    assert.deepEqual(s.mock.shares[3]!.recipientRecord, sent.recipientRecord);
    assert.equal(s.mock.shares[3]!.scope, sent.scope);
  } finally {
    await teardown(s);
  }
});

test('every refusal is made before anything is asked of the endpoint, with a fixed reason that shows nothing of the file', async () => {
  const s = await setup();
  try {
    const secret = randomBytes(32).toString('hex');
    const envFile = join(s.dir, 'leaked.env');
    writeFileSync(envFile, `SAIHM_MASTER_SECRET_HEX=${secret}\n`);
    const forged = join(s.dir, 'forged.json');
    writeFileSync(forged, JSON.stringify({ ...s.doc, agentIdHash: secret }, null, 2) + '\n');
    const folder = join(s.dir, 'records');
    mkdirSync(folder);
    const cases: [string, Record<string, unknown>, string, RegExp][] = [
      [
        'a pin that is not the file\'s',
        { cellId: s.cellId, recipientRecordFile: s.recordFile, recipientPinnedAgentIdHashHex: toHex(s.sharer.agentIdHash) },
        'recipient_mismatch',
        /^SAIHM error \[recipient_mismatch\] \(status 0\): Nothing was shared: the agent ID in recipientRecordFile is not recipientPinnedAgentIdHashHex\./,
      ],
      [
        'a file beside an inline record',
        { cellId: s.cellId, recipientRecordFile: s.recordFile, recipientRecord: encodeIdentityRecord(s.recipient.identityRecord) },
        'invalid_input',
        /give the recipient once, as recipientRecordFile or as recipientRecord, not both\.$/,
      ],
      // A malformed pin beside the file is refused as malformed, before it is compared (0.14.3 review 2).
      ...[` ${s.doc.agentIdHash}`, `0x${s.doc.agentIdHash}`, s.doc.agentIdHash.slice(0, 63), `${s.doc.agentIdHash} `].map(
        (pin): [string, Record<string, unknown>, string, RegExp] => [
          `a malformed pin ${JSON.stringify(pin.slice(0, 4))}`,
          { cellId: s.cellId, recipientRecordFile: s.recordFile, recipientPinnedAgentIdHashHex: pin },
          'bad_recipient',
          /^SAIHM error \[bad_recipient\] \(status 0\): Nothing was shared: recipientPinnedAgentIdHashHex is not an agent ID, which is 64 hex characters with no spaces and no 0x\.$/,
        ],
      ),
      ['no recipient', { cellId: s.cellId }, 'recipient_required', /name the recipient with recipientRecordFile/],
      ['a record without its pin', { cellId: s.cellId, recipientRecord: encodeIdentityRecord(s.recipient.identityRecord) }, 'recipient_required', /together\.$/],
      ['a pin without a record', { cellId: s.cellId, recipientPinnedAgentIdHashHex: s.doc.agentIdHash }, 'recipient_required', /together\.$/],
      ['a file holding a secret', { cellId: s.cellId, recipientRecordFile: envFile }, 'bad_recipient_record_file', /is not a SAIHM identity record/],
      ['a forged record', { cellId: s.cellId, recipientRecordFile: forged }, 'bad_recipient_record_file', /does not verify/],
      ['a folder', { cellId: s.cellId, recipientRecordFile: folder }, 'bad_recipient_record_file', /is not a regular file\.$/],
      [
        'a relative path naming nothing in the working directory',
        { cellId: s.cellId, recipientRecordFile: 'qa-agent.json' },
        'bad_recipient_record_file',
        /could not be read \(ENOENT\); a relative path is read from the server's working directory, so give the full path\.$/,
      ],
    ];
    if (POSIX) {
      const fifo = join(s.dir, 'pipe.json');
      execFileSync('mkfifo', ['-m', '600', fifo]);
      cases.push(['a pipe', { cellId: s.cellId, recipientRecordFile: fifo }, 'bad_recipient_record_file', /is not a regular file\.$/]);
    }
    const before = s.mock.requests();
    for (const [label, args, code, reason] of cases) {
      const r = await s.d.call('saihm_share', args);
      assert.equal(r.isError, true, `${label}: ${r.text}`);
      assert.match(r.text, reason, label);
      assert.deepEqual(r.structuredContent, { error: { code, status: 0 } }, label);
      const shown = r.text + JSON.stringify(r.structuredContent);
      for (const hidden of [secret, secret.slice(0, 10), 'SAIHM_MASTER', envFile, forged, s.dir]) assert.ok(!shown.includes(hidden), `${label} shows nothing of the file or its path`);
    }
    assert.equal(s.mock.requests(), before, 'no refusal asked anything of the endpoint, a sign-in included');
    assert.equal(s.mock.shares.length, 0);
    // Positive control: the same server, with the record file, signs in and shares.
    const ok = await s.d.call('saihm_share', { cellId: s.cellId, recipientRecordFile: s.recordFile });
    assert.equal(ok.isError, false, ok.text);
    assert.ok(s.mock.requests() > before);
    assert.equal(s.mock.shares.length, 1);
    // Nor in the log.
    assert.ok(!s.d.stderr().includes(secret), 'the server log shows nothing of the file');
    assert.ok(!s.d.stderr().includes(secret.slice(0, 10)));
  } finally {
    await teardown(s);
  }
});
