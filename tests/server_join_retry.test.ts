// An interrupted join is resumed, not repeated: `free-join` writes the key when the join starts, before the human
// approves, and a join stopped while it waits leaves that key in place. Joining again on the same machine uses that
// same key - the same identity - and writes no second one.
// Runner: npx tsx --test tests/server_join_retry.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const KEY = 'free-identity.key';
const seg = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');

function childEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const keep: NodeJS.ProcessEnv = {};
  for (const k of ['PATH', 'SYSTEMROOT', 'TEMP', 'TMP', 'TMPDIR']) if (process.env[k] !== undefined) keep[k] = process.env[k];
  return { ...keep, ...extra };
}

test('a join stopped while it waits for approval leaves its key, and joining again uses that key', { skip: process.platform === 'win32' && 'POSIX process groups' }, async () => {
  let grant = false;
  const claimed: string[] = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const send = (s: number, b: unknown) => void res.writeHead(s, { 'content-type': 'application/json' }).end(JSON.stringify(b));
      const route = `${req.method} ${req.url}`;
      if (route === 'GET /api/onboard/challenge') return send(200, { nonce: '22'.repeat(32) });
      if (route === 'POST /api/free-onboard/start')
        return send(200, { flowId: 'flow-r', userCode: 'RTRY-0001', verificationUri: 'https://device.test/activate', expiresIn: 900, interval: 1 });
      if (route === 'POST /api/free-onboard/claim') {
        const pubkey = (JSON.parse(body) as { pubkey?: string }).pubkey ?? '';
        claimed.push(pubkey);
        return send(200, grant ? { status: 'granted', agentIdHash: createHash('sha256').update(Buffer.from(pubkey, 'hex')).digest('hex') } : { status: 'pending' });
      }
      if (route === 'POST /api/onboard')
        return send(201, { jwt: `${seg({ alg: 'EdDSA' })}.${seg({ sub: 'x', tier: 'FREE', exp: Math.floor(Date.now() / 1000) + 3600 })}.sig` });
      return send(404, { error: 'not_found' });
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const home = mkdtempSync(join(tmpdir(), 'saihm-retry-'));
  const env = childEnv({ HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp` });
  try {
    // First join: wait for the steps and one claim, then stop it, as a closed terminal or a killed session does.
    // Its own process group, so the stop reaches the server under the tsx wrapper too, as closing a terminal does.
    const first = spawn(TSX, [SERVER, 'free-join'], { env, stdio: ['ignore', 'pipe', 'pipe'], cwd: resolve(HERE, '..'), detached: true });
    let out = '';
    first.stdout!.on('data', (d) => (out += d));
    const until = Date.now() + 30000;
    while ((!out.includes('RTRY-0001') || claimed.length === 0) && Date.now() < until) await new Promise((r) => setTimeout(r, 100));
    assert.ok(out.includes('RTRY-0001'), out);
    const exited = new Promise((r) => first.once('exit', r));
    process.kill(-first.pid!, 'SIGKILL');
    await exited;
    const keyFile = join(home, KEY);
    const keyHash = createHash('sha256').update(readFileSync(keyFile)).digest('hex');
    if (process.platform !== 'win32') assert.equal(statSync(keyFile).mode & 0o777, 0o600);
    const firstKey = claimed[0]!;

    // Approved now; joining again finishes with the key already there.
    grant = true;
    const second = await new Promise<{ code: number | null; stdout: string }>((res) => {
      const p = spawn(TSX, [SERVER, 'free-join'], { env, stdio: ['ignore', 'pipe', 'pipe'], cwd: resolve(HERE, '..') });
      let stdout = '';
      p.stdout!.on('data', (d) => (stdout += d));
      const t = setTimeout(() => p.kill(), 60000);
      p.on('close', (code) => {
        clearTimeout(t);
        res({ code, stdout });
      });
    });
    assert.equal(second.code, 0, second.stdout);
    assert.match(second.stdout, /FREE memory activated for this identity/);
    assert.ok(claimed.length >= 2);
    for (const k of claimed) assert.equal(k, firstKey, 'every claim, before and after the stop, is for the same key');
    assert.equal(createHash('sha256').update(readFileSync(keyFile)).digest('hex'), keyHash, 'the key file is unchanged');
    assert.deepEqual(readdirSync(home).filter((f) => f.endsWith('.key')), [KEY], 'no second key');
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    rmSync(home, { recursive: true, force: true });
  }
});
