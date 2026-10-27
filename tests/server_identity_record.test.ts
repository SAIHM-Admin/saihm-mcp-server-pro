// `identity-record` (0.14.3): the CLI verb that writes this identity's PUBLIC identity record, so a colleague's agent
// can share a memory with it (saihm_share takes the record as recipientRecord and the agent ID as
// recipientPinnedAgentIdHashHex) or read one it shared. Sharing had no way to reach that record from Claude Code.
//
// What these tests hold it to: the document carries the agent ID and the three public fields and nothing else; it
// verifies against its own agent ID as the share path checks it; nothing secret reaches the file, stdout or stderr;
// nothing is asked of the endpoint; an existing file is never overwritten; a file name with the shape of a key is
// refused unshown; with no identity there is no record, and none is created.
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  decodeIdentityRecord,
  deriveIdentity,
  fromHex,
  openCellWithDek,
  sealCell,
  shareCell,
  toHex,
  unwrapSharedDek,
  verifyIdentityRecord,
  type WireIdentityRecord,
} from '@saihm/client-pro';
import { generatePassphrase, sealIdentityToken } from '../src/identity-token.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');

interface Run {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** The CLI with only the variables given (plus PATH), in a scratch working directory. */
function runCli(args: string[], env: Record<string, string>, cwd: string): Promise<Run> {
  return new Promise<Run>((res) => {
    const keep: Record<string, string> = {};
    for (const k of ['PATH', 'SYSTEMROOT', 'TEMP', 'TMP', 'TMPDIR']) if (process.env[k] !== undefined) keep[k] = process.env[k]!;
    const proc = spawn(TSX, [SERVER, ...args], { env: { ...keep, ...env }, stdio: ['ignore', 'pipe', 'pipe'], cwd });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d) => (stdout += d));
    proc.stderr.on('data', (d) => (stderr += d));
    const timer = setTimeout(() => proc.kill('SIGKILL'), 30_000);
    proc.on('close', (code) => {
      clearTimeout(timer);
      res({ code, stdout, stderr });
    });
  });
}

/** A scratch SAIHM_HOME with a default key file, and an endpoint that counts every request it is sent. */
async function setup(): Promise<{ home: string; secretHex: string; env: Record<string, string>; requests: () => number; close: () => Promise<void> }> {
  const home = mkdtempSync(join(tmpdir(), 'saihm-idrec-'));
  const secretHex = randomBytes(32).toString('hex');
  writeFileSync(join(home, 'free-identity.key'), secretHex, { mode: 0o600 });
  let n = 0;
  const server = createServer((req, res) => {
    n++;
    req.resume();
    res.writeHead(500, { 'content-type': 'application/json' }).end('{"error":"unexpected"}');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`;
  return {
    home,
    secretHex,
    env: { HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: url },
    requests: () => n,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

interface RecordDoc {
  kind: string;
  version: number;
  agentIdHash: string;
  identityRecord: WireIdentityRecord;
}

/**
 * Values derived from the master secret that must never be written: the secret itself, the key-encryption key, and
 * SECRET parts of the two secret keys. Not their first bytes alone: an ML-DSA secret key opens with rho, which is also
 * the first 32 bytes of the public key (measured: a probe of those bytes "found" the public key), and an ML-KEM
 * decapsulation key carries the public encapsulation key inside it. So: ML-DSA's K (bytes 32-64), and the ML-KEM key's
 * first 32 bytes (its secret vector) and last 32 (its rejection value z).
 */
function secretsOf(secretHex: string): string[] {
  const id = deriveIdentity(fromHex(secretHex));
  const dsa = toHex(id.mldsaSecretKey);
  const kem = toHex(id.mlkemSecretKey);
  assert.ok(!toHex(id.mlkemPubKey).includes(kem.slice(0, 64)), 'the ML-KEM probe is not public');
  assert.ok(!toHex(id.mldsaPubKey).includes(dsa.slice(64, 128)), 'the ML-DSA probe is not public');
  return [secretHex, toHex(id.kek), dsa.slice(64, 128), kem.slice(0, 64), kem.slice(-64)];
}

function assertRecordOf(doc: RecordDoc, secretHex: string): void {
  const id = deriveIdentity(fromHex(secretHex));
  assert.deepEqual(Object.keys(doc).sort(), ['agentIdHash', 'identityRecord', 'kind', 'version']);
  assert.deepEqual(Object.keys(doc.identityRecord).sort(), ['mldsaPubKey', 'mlkemPubKey', 'mlkemPubKeySelfSig']);
  assert.equal(doc.kind, 'saihm-identity-record');
  assert.equal(doc.version, 1);
  assert.equal(doc.agentIdHash, toHex(id.agentIdHash));
  assert.equal(doc.identityRecord.mldsaPubKey, toHex(id.mldsaPubKey));
  assert.equal(doc.identityRecord.mlkemPubKey, toHex(id.mlkemPubKey));
  assert.equal(createHash('sha256').update(Buffer.from(doc.identityRecord.mldsaPubKey, 'hex')).digest('hex'), doc.agentIdHash);
  // As the share path checks a recipient: the record against the pinned agent ID, its self-signature included.
  verifyIdentityRecord(decodeIdentityRecord(doc.identityRecord), fromHex(doc.agentIdHash));
}

test('identity-record with no file writes the record to stdout, and what it is to stderr, asking the endpoint nothing', async () => {
  const s = await setup();
  try {
    const r = await runCli(['identity-record'], s.env, s.home);
    assert.equal(r.code, 0, r.stderr);
    const doc = JSON.parse(r.stdout) as RecordDoc;
    assertRecordOf(doc, s.secretHex);
    assert.match(r.stderr, new RegExp(`SAIHM identity record above, for agent ID ${doc.agentIdHash}\\.`));
    assert.match(
      r.stderr,
      /saihm_share\ntakes the file's full path as recipientRecordFile \(or identityRecord as recipientRecord and\nagentIdHash as recipientPinnedAgentIdHashHex\)\./,
    );
    assert.match(r.stderr, /This is not export-identity: never send that file to anyone\./);
    for (const secret of secretsOf(s.secretHex)) assert.ok(!(r.stdout + r.stderr).includes(secret), 'no secret is printed');
    // Positive control for the search: the secret is found where it is.
    assert.ok(readFileSync(join(s.home, 'free-identity.key'), 'utf8').includes(s.secretHex));
    assert.equal(s.requests(), 0, 'nothing is asked of the endpoint');
    // `-` is stdout too.
    const dash = await runCli(['identity-record', '-'], s.env, s.home);
    assert.equal(dash.code, 0, dash.stderr);
    assertRecordOf(JSON.parse(dash.stdout) as RecordDoc, s.secretHex);
  } finally {
    await s.close();
    rmSync(s.home, { recursive: true, force: true });
  }
});

test('identity-record FILE writes the record there, never over a file that exists, and holds no secret', async () => {
  const s = await setup();
  try {
    const before = readdirSync(s.home).sort();
    const r = await runCli(['identity-record', 'me.json'], s.env, s.home);
    assert.equal(r.code, 0, r.stderr);
    const file = join(s.home, 'me.json');
    const text = readFileSync(file, 'utf8');
    assertRecordOf(JSON.parse(text) as RecordDoc, s.secretHex);
    assert.equal(statSync(file).mode & 0o777 & ~0o644, 0, 'readable by others is fine, writable by others is not');
    for (const secret of secretsOf(s.secretHex)) assert.ok(!(text + r.stdout + r.stderr).includes(secret), 'no secret is written or printed');
    assert.match(r.stdout, /SAIHM identity record written: me\.json\n {2}agent ID \(agentIdHash\): [0-9a-f]{64}\n/);
    assert.deepEqual(readdirSync(s.home).sort(), [...before, 'me.json'].sort(), 'the record file is the only file written');
    // Never over a file that is there: the first record stays as it was.
    const again = await runCli(['identity-record', 'me.json'], s.env, s.home);
    assert.equal(again.code, 1);
    assert.match(again.stderr, /that file already exists\. Name a new file, or remove it first\./);
    assert.equal(readFileSync(file, 'utf8'), text);
    // A folder that is not there is not created.
    const missing = await runCli(['identity-record', join('no-such-folder', 'me.json')], s.env, s.home);
    assert.equal(missing.code, 1);
    assert.match(missing.stderr, /could not be written: ENOENT\. Check that its folder exists and is yours\./);
    assert.ok(!existsSync(join(s.home, 'no-such-folder')));
    // One argument at most, and it is a file name, not an option.
    const two = await runCli(['identity-record', 'a.json', 'b.json'], s.env, s.home);
    assert.equal(two.code, 2);
    assert.ok(!existsSync(join(s.home, 'a.json')) && !existsSync(join(s.home, 'b.json')));
    const opt = await runCli(['identity-record', '--help'], s.env, s.home);
    assert.equal(opt.code, 2);
    assert.match(opt.stderr, /takes no options: name the file to write, or - for stdout/);
    assert.ok(!existsSync(join(s.home, '--help')), 'no file named after the option');
    assert.equal(s.requests(), 0);
  } finally {
    await s.close();
    rmSync(s.home, { recursive: true, force: true });
  }
});

test('identity-record refuses a file name with the shape of a key, and does not show it', async () => {
  const s = await setup();
  try {
    const shaped = randomBytes(32).toString('hex');
    const r = await runCli(['identity-record', shaped], s.env, s.home);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /that file name has the shape of a key, passphrase or token, so it is not used/);
    assert.ok(!(r.stdout + r.stderr).includes(shaped), 'the name is not shown');
    assert.ok(!existsSync(join(s.home, shaped)), 'and no file is made under it');
  } finally {
    await s.close();
    rmSync(s.home, { recursive: true, force: true });
  }
});

test('identity-record with no identity configured writes nothing and creates no key', async () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-idrec-none-'));
  try {
    const r = await runCli(['identity-record', 'me.json'], { HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: 'http://127.0.0.1:9/mcp' }, home);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /no identity record - no SAIHM identity is configured here/);
    assert.deepEqual(readdirSync(home), [], 'no key and no record');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('identity-record reads the identity boot reads: a key file named by SAIHM_MASTER_SECRET_FILE, or an identity token', async () => {
  const s = await setup();
  try {
    const other = randomBytes(32).toString('hex');
    const keyFile = join(s.home, 'elsewhere.key');
    writeFileSync(keyFile, other, { mode: 0o600 });
    const viaFile = await runCli(['identity-record'], { ...s.env, SAIHM_MASTER_SECRET_FILE: keyFile }, s.home);
    assert.equal(viaFile.code, 0, viaFile.stderr);
    assertRecordOf(JSON.parse(viaFile.stdout) as RecordDoc, other);
    const passphrase = generatePassphrase();
    const token = sealIdentityToken({ secretHex: other, tier: 'FREE', paymentMethod: undefined }, toHex(deriveIdentity(fromHex(other)).agentIdHash), passphrase);
    const viaToken = await runCli(['identity-record'], { HOME: s.home, SAIHM_HOME: join(s.home, 'none'), SAIHM_ENDPOINT_URL: s.env.SAIHM_ENDPOINT_URL!, SAIHM_IDENTITY: token, SAIHM_IDENTITY_PASSPHRASE: passphrase }, s.home);
    assert.equal(viaToken.code, 0, viaToken.stderr);
    assertRecordOf(JSON.parse(viaToken.stdout) as RecordDoc, other);
    assert.ok(!(viaToken.stdout + viaToken.stderr).includes(passphrase), 'the passphrase is not printed');
    assert.equal(s.requests(), 0);
  } finally {
    await s.close();
    rmSync(s.home, { recursive: true, force: true });
  }
});

test('a share made to the record grants that identity: the grantee opens it with its own key', async () => {
  // The record as a colleague receives it is enough to share to its identity: the share binds the cell's key to the
  // record's ML-KEM key, and only that identity's own key opens it.
  const s = await setup();
  try {
    const r = await runCli(['identity-record'], s.env, s.home);
    assert.equal(r.code, 0, r.stderr);
    const doc = JSON.parse(r.stdout) as RecordDoc;
    const sharer = deriveIdentity(randomBytes(32));
    const envelope = sealCell({
      plaintext: new TextEncoder().encode('release runbook'),
      kek: sharer.kek,
      mldsaSecretKey: sharer.mldsaSecretKey,
      mldsaPubKey: sharer.mldsaPubKey,
      agentIdHash: sharer.agentIdHash,
      cellId: randomBytes(16).toString('hex'),
      seq: 1n,
      tier: 'PRO',
    });
    const share = shareCell({
      envelope,
      sharerKek: sharer.kek,
      sharerMldsaSecretKey: sharer.mldsaSecretKey,
      sharerAgentIdHash: sharer.agentIdHash,
      recipientRecord: decodeIdentityRecord(doc.identityRecord),
      recipientPinnedAgentIdHash: fromHex(doc.agentIdHash),
    });
    assert.equal(toHex(share.recipientAgentIdHash), doc.agentIdHash);
    const grantee = deriveIdentity(fromHex(s.secretHex));
    const dek = unwrapSharedDek({
      share,
      recipientMlkemSecretKey: grantee.mlkemSecretKey,
      recipientAgentIdHash: grantee.agentIdHash,
      sharerPinnedMldsaPubKey: sharer.mldsaPubKey,
    });
    assert.equal(new TextDecoder().decode(openCellWithDek(envelope, dek)), 'release runbook');
    // A record pinned to another agent ID is refused, as the share path refuses it.
    assert.throws(() =>
      shareCell({
        envelope,
        sharerKek: sharer.kek,
        sharerMldsaSecretKey: sharer.mldsaSecretKey,
        sharerAgentIdHash: sharer.agentIdHash,
        recipientRecord: decodeIdentityRecord(doc.identityRecord),
        recipientPinnedAgentIdHash: sharer.agentIdHash,
      }),
    );
  } finally {
    await s.close();
    rmSync(s.home, { recursive: true, force: true });
  }
});
