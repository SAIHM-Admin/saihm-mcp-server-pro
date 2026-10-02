// Coverage for reaching the endpoint through an HTTP proxy (HTTPS_PROXY / NO_PROXY), the way hosted
// agent environments and corporate networks let traffic out. The selection rules are checked in
// process; the tunnel itself end to end, in a child process, through a real CONNECT proxy to a real
// TLS endpoint whose certificate is issued by a throwaway CA the child is told to trust - so the
// test proves the request arrives, that the proxy learns only the host, that its credentials go to
// it alone, and that the endpoint's certificate is still verified through the tunnel.
// Runner: npx tsx --test tests/client_proxy.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { execFileSync, spawn } from 'node:child_process';
import { createServer as createHttpServer, type Server } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { connect as netConnect, type AddressInfo } from 'node:net';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { proxyForTarget, SaihmProClient, untrustedCertificate, unusableProxy } from '../src/client.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const CLIENT = resolve(HERE, '../src/client.ts');

const VARS = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY', 'no_proxy', 'NO_PROXY'] as const;
function withEnv<T>(overrides: Partial<Record<(typeof VARS)[number], string>>, fn: () => T): T {
  const saved: Record<string, string | undefined> = {};
  for (const k of VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  Object.assign(process.env, overrides);
  try {
    return fn();
  } finally {
    for (const k of VARS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}
const pick = (url: string, env: Partial<Record<(typeof VARS)[number], string>>): string | null =>
  withEnv(env, () => proxyForTarget(new URL(url))?.host ?? null);

test('proxy selection: https_proxy, then HTTPS_PROXY, for https endpoints only', () => {
  assert.equal(pick('https://saihm.net/mcp', {}), null);
  assert.equal(pick('https://saihm.net/mcp', { HTTPS_PROXY: 'http://p1:3128' }), 'p1:3128');
  assert.equal(pick('https://saihm.net/mcp', { https_proxy: 'http://p0:1', HTTPS_PROXY: 'http://p1:2' }), 'p0:1');
  assert.equal(pick('https://saihm.net/mcp', { HTTP_PROXY: 'http://p2:8080', http_proxy: 'http://p2:8081' }), null, 'HTTP_PROXY is for http traffic: an https endpoint goes direct, as with npm and curl');
  assert.equal(pick('https://saihm.net/mcp', { HTTPS_PROXY: 'p3:3128' }), 'p3:3128', 'a bare host:port is read as http');
  assert.equal(pick('https://saihm.net/mcp', { HTTPS_PROXY: '   ' }), null, 'blank is unset');
  for (const loop of ['http://127.0.0.1:3000/mcp', 'https://127.0.0.1/mcp', 'https://localhost/mcp', 'https://[::1]/mcp'])
    assert.equal(pick(loop, { HTTPS_PROXY: 'http://p1:3128' }), null, `${loop} never goes through a proxy`);
});

test('NO_PROXY: star, exact, suffix with or without a dot or star, and ports', () => {
  const via = { HTTPS_PROXY: 'http://p1:3128' };
  const cases: [string, string, boolean][] = [
    ['*', 'https://saihm.net/mcp', false],
    ['saihm.net', 'https://saihm.net/mcp', false],
    ['saihm.net', 'https://api.saihm.net/mcp', false],
    ['.saihm.net', 'https://api.saihm.net/mcp', false],
    ['.saihm.net', 'https://saihm.net/mcp', false],
    ['*.saihm.net', 'https://api.saihm.net/mcp', false],
    ['saihm.net:443', 'https://saihm.net/mcp', false],
    ['saihm.net:8443', 'https://saihm.net/mcp', true],
    ['other.net, example.org', 'https://saihm.net/mcp', true],
    ['notsaihm.net', 'https://saihm.net/mcp', true],
    ['ihm.net', 'https://saihm.net/mcp', true],
  ];
  for (const [noProxy, url, proxied] of cases)
    assert.equal(pick(url, { ...via, NO_PROXY: noProxy }) !== null, proxied, `NO_PROXY=${noProxy} ${url}`);
  assert.equal(pick('https://saihm.net/mcp', { ...via, no_proxy: 'saihm.net', NO_PROXY: '' }), null, 'lowercase is read');
});

test('an unusable proxy setting is a coded error naming the variable, never its value', () => {
  for (const [env, code] of [
    [{ HTTPS_PROXY: 'http://us:er:pw@[bad' }, 'HTTPS_PROXY_NOT_A_URL'],
    [{ https_proxy: 'socks5://user:s3cr3t@p:1080' }, 'https_proxy_NOT_AN_HTTP_PROXY'],
    [{ HTTPS_PROXY: 'https://user:s3cr3t@p:443' }, 'HTTPS_PROXY_NOT_AN_HTTP_PROXY'],
  ] as const) {
    let caught: unknown;
    try {
      withEnv(env, () => proxyForTarget(new URL('https://saihm.net/mcp')));
    } catch (e) {
      caught = e;
    }
    assert.equal((caught as { code?: string })?.code, code);
    assert.ok(!(caught as Error).message.includes('s3cr3t'));
  }
});

// ---------- end to end through a real tunnel ----------

function haveOpenssl(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/** A throwaway CA and a leaf certificate for `name`, written under `dir`. */
function issue(dir: string, name: string): { ca: string; key: string; cert: string } {
  const run = (args: string[]): void => void execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' });
  run(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', 'ca.key',
    '-out', 'ca.pem', '-days', '2', '-subj', '/CN=saihm-test-ca', '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign']);
  run(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', 'leaf.key',
    '-out', 'leaf.csr', '-subj', `/CN=${name}`]);
  writeFileSync(join(dir, 'ext.cnf'), `subjectAltName=DNS:${name}\n`);
  run(['x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'leaf.pem',
    '-days', '2', '-extfile', 'ext.cnf']);
  return { ca: join(dir, 'ca.pem'), key: join(dir, 'leaf.key'), cert: join(dir, 'leaf.pem') };
}

interface Rig {
  proxyPort: number;
  connects: { authority: string; auth: string | undefined }[];
  requests: { url: string; auth: string | undefined }[];
  /** The server name each TLS connection to the endpoint asked for (SNI). */
  servernames: string[];
  close: () => Promise<void>;
}

async function rig(certName: string, dir: string, deny: string | null = null, proxyHost = '127.0.0.1'): Promise<Rig & { ca: string }> {
  const pem = issue(dir, certName);
  const requests: Rig['requests'] = [];
  const endpoint = createHttpsServer({ key: readFileSync(pem.key), cert: readFileSync(pem.cert) }, (req, res) => {
    requests.push({ url: req.url ?? '', auth: req.headers.authorization });
    req.resume();
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  await new Promise<void>((r) => endpoint.listen(0, '127.0.0.1', () => r()));
  const endpointPort = (endpoint.address() as AddressInfo).port;
  const servernames: string[] = [];
  endpoint.on('secureConnection', (s: import('node:tls').TLSSocket) => servernames.push(String(s.servername ?? '')));
  const connects: Rig['connects'] = [];
  // Tunnels are tracked and torn down at close: `closeAllConnections` does not reach a socket a CONNECT has
  // taken over, and a client that misbehaves must fail its test, not hold the file open.
  const tunnels = new Set<import('node:stream').Duplex>();
  const proxy: Server = createHttpServer((_req, res) => res.writeHead(405).end());
  proxy.on('connect', (req, socket, head) => {
    tunnels.add(socket);
    socket.on('close', () => tunnels.delete(socket));
    socket.on('error', () => {});
    connects.push({ authority: req.url ?? '', auth: req.headers['proxy-authorization'] });
    if (deny !== null || req.url !== 'saihm.test:443') {
      socket.end(`HTTP/1.1 ${deny ?? '403 Forbidden'}\r\nLocation: http://portal.test/\r\nContent-Length: 0\r\n\r\n`);
      // Drained, so whatever the client sends after a refusal cannot hold the socket open.
      socket.resume();
      return;
    }
    const upstream = netConnect(endpointPort, '127.0.0.1', () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length > 0) upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
  });
  await new Promise<void>((r) => proxy.listen(0, proxyHost, () => r()));
  return {
    ca: pem.ca,
    proxyPort: (proxy.address() as AddressInfo).port,
    connects,
    requests,
    servernames,
    close: async () => {
      for (const s of tunnels) s.destroy();
      proxy.closeAllConnections?.();
      endpoint.closeAllConnections?.();
      await new Promise<void>((r) => proxy.close(() => r()));
      await new Promise<void>((r) => endpoint.close(() => r()));
    },
  };
}

/**
 * Run client calls in a child (which trusts the throwaway CA when told to); return what it printed.
 * `onboard` makes it a self-onboarding client, so the first request is the onboard path's.
 */
function callThrough(dir: string, env: Record<string, string>, opts: { calls?: number; onboard?: boolean } = {}): Promise<string> {
  const script = join(dir, 'call.mts');
  const auth = opts.onboard ? 'undefined' : "'Bearer test-token'";
  const extra = opts.onboard ? ", paymentMethod: 'stripe'" : '';
  writeFileSync(
    script,
    `import { SaihmProClient } from ${JSON.stringify(CLIENT)};\n` +
      `const c = new SaihmProClient('https://saihm.test/mcp', ${auth}, new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 8000${extra} });\n` +
      `for (let i = 0; i < ${opts.calls ?? 1}; i++) {\n` +
      `  try { await c.status(); console.log('CALL_OK'); } catch (e) { console.log('CALL_ERR ' + String(e && e.message)); }\n` +
      `}\n` +
      `process.exit(0);\n`,
  );
  return new Promise((res) => {
    const p = spawn(TSX, [script], { env: { PATH: process.env.PATH ?? '', SAIHM_HOME: dir, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    p.stdout!.on('data', (d) => (out += d));
    p.stderr!.on('data', (d) => (out += d));
    const t = setTimeout(() => p.kill(), 30000);
    p.on('close', () => {
      clearTimeout(t);
      res(out);
    });
  });
}

test('end to end: the request reaches the endpoint through the proxy, which learns only the host', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-a-'));
  const r = await rig('saihm.test', dir);
  try {
    // A domain login, percent-encoded in the URL as it must be, reaches the proxy decoded.
    const out = await callThrough(dir, { HTTPS_PROXY: `http://DOMAIN%5Cuser:pa%40ss@127.0.0.1:${r.proxyPort}`, NODE_EXTRA_CA_CERTS: r.ca });
    assert.deepEqual(r.connects.map((c) => c.authority), ['saihm.test:443'], out);
    assert.equal(r.connects[0]!.auth, `Basic ${Buffer.from('DOMAIN\\user:pa@ss').toString('base64')}`, 'credentials go to the proxy');
    assert.deepEqual(r.servernames, ['saihm.test'], 'the endpoint is asked for by name (SNI), through the tunnel');
    assert.equal(r.requests.length >= 1, true, `the endpoint was not reached: ${out}`);
    assert.equal(r.requests[0]!.url, '/mcp');
    assert.equal(r.requests[0]!.auth, 'Bearer test-token', 'and the request arrives intact over TLS');
    assert.ok(!out.includes('pa@ss') && !out.includes('pa%40ss'), 'the proxy password never reaches the output');
  } finally {
    await r.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('end to end: NO_PROXY sends the endpoint direct, and the proxy hears nothing', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-b-'));
  const r = await rig('saihm.test', dir);
  try {
    const out = await callThrough(dir, { HTTPS_PROXY: `http://127.0.0.1:${r.proxyPort}`, NO_PROXY: 'saihm.test', NODE_EXTRA_CA_CERTS: r.ca });
    assert.equal(r.connects.length, 0, out);
    assert.match(out, /CALL_ERR/, 'saihm.test does not resolve, so a direct attempt fails');
  } finally {
    await r.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('end to end: a refusing proxy is named by code, with no credentials in the error', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-c-'));
  const r = await rig('saihm.test', dir, '403 Forbidden');
  try {
    const out = await callThrough(dir, { HTTPS_PROXY: `http://user:s3cr3t@127.0.0.1:${r.proxyPort}`, NODE_EXTRA_CA_CERTS: r.ca });
    assert.match(out, /PROXY_CONNECT_403/);
    assert.match(out, /Via the proxy in HTTPS_PROXY: if hosted, allow this host in its network settings; otherwise check the proxy and NO_PROXY\./);
    assert.ok(!out.includes('s3cr3t'));
    assert.equal(r.requests.length, 0);
  } finally {
    await r.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('end to end: the endpoint certificate is still verified through the tunnel', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-d-'));
  const r = await rig('other.test', dir);
  try {
    const out = await callThrough(dir, { HTTPS_PROXY: `http://127.0.0.1:${r.proxyPort}`, NODE_EXTRA_CA_CERTS: r.ca });
    assert.deepEqual(r.connects.map((c) => c.authority), ['saihm.test:443']);
    assert.equal(r.requests.length, 0, 'a certificate for another name must not be accepted');
    assert.match(out, /CALL_ERR/);
  } finally {
    await r.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('proxy selection: loopback by address, http never, lowercase NO_PROXY first, bracketed IPv6', () => {
  const via = { HTTPS_PROXY: 'http://p1:3128' };
  assert.equal(pick('http://saihm.net/mcp', via), null, 'an http hop - a redirect off https - goes direct');
  assert.equal(pick('https://app.localhost/mcp', via), null, 'a .localhost name is loopback');
  assert.equal(pick('https://127.8.9.10/mcp', via), null, 'all of 127/8 is loopback');
  assert.equal(pick('https://127.attacker.example/mcp', via), 'p1:3128', 'a NAME that starts with 127. is not');
  assert.equal(pick('https://saihm.net/mcp', { ...via, no_proxy: 'saihm.net', NO_PROXY: 'other.org' }), null, 'no_proxy is read first');
  assert.equal(pick('https://saihm.net/mcp', { ...via, no_proxy: '  ', NO_PROXY: 'saihm.net' }), null, 'a blank no_proxy does not hide NO_PROXY');
  assert.equal(pick('https://[2001:db8::1]/mcp', { ...via, NO_PROXY: '[2001:db8::1]' }), null, 'a bracketed IPv6 entry');
  assert.equal(pick('https://[2001:db8::1]:8443/mcp', { ...via, NO_PROXY: '[2001:db8::1]:443' }), 'p1:3128', 'and its port');
});

interface Stall {
  port: number;
  connects: number;
  open: () => number;
  first: Promise<void>;
  close: () => Promise<void>;
}

/** A proxy that accepts a CONNECT and never completes its reply: silent, or a header byte at a time. */
async function stallingProxy(trickle: boolean): Promise<Stall> {
  const sockets = new Set<import('node:stream').Duplex>();
  const timers = new Set<ReturnType<typeof setInterval>>();
  let firstSeen = (): void => {};
  const st: Stall = { port: 0, connects: 0, open: () => sockets.size, first: new Promise<void>((r) => (firstSeen = r)), close: async () => {} };
  const proxy = createHttpServer((_req, res) => res.writeHead(405).end());
  proxy.on('connect', (_req, socket) => {
    st.connects++;
    sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
    if (trickle) {
      socket.write('HTTP/1.1 200 Connection Established\r\nX-Pad: ');
      const iv = setInterval(() => void (socket.destroyed || socket.write('a')), 200);
      timers.add(iv);
      socket.on('close', () => clearInterval(iv));
    }
    firstSeen();
  });
  await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', () => r()));
  st.port = (proxy.address() as AddressInfo).port;
  st.close = async () => {
    for (const iv of timers) clearInterval(iv);
    for (const s of sockets) s.destroy();
    await new Promise<void>((r) => proxy.close(() => r()));
  };
  return st;
}

/** Run `body` in a child with NO exit call: it ends when nothing is left open, or is killed at `killMs`. */
function runAlone(dir: string, body: string, env: Record<string, string>, killMs: number): Promise<{ out: string; ms: number; killed: boolean }> {
  const script = join(dir, 'alone.mts');
  writeFileSync(script, `import { SaihmProClient } from ${JSON.stringify(CLIENT)};\n${body}\n`);
  return new Promise((res) => {
    const t0 = Date.now();
    const p = spawn(TSX, [script], { env: { PATH: process.env.PATH ?? '', SAIHM_HOME: dir, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let killed = false;
    p.stdout!.on('data', (d) => (out += d));
    p.stderr!.on('data', (d) => (out += d));
    const t = setTimeout(() => {
      killed = true;
      p.kill();
    }, killMs);
    p.on('close', () => {
      clearTimeout(t);
      res({ out, ms: Date.now() - t0, killed });
    });
  });
}

for (const trickle of [false, true])
  test(`a ${trickle ? 'trickling' : 'silent'} proxy cannot hold a call past its budget, nor the process past the call`, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-s-'));
    const p = await stallingProxy(trickle);
    try {
      const r = await runAlone(
        dir,
        `const c = new SaihmProClient('https://saihm.test/mcp', 'Bearer t', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 1500 });\n` +
          `const t0 = Date.now();\n` +
          `try { await c.status(); console.log('CALL_OK'); } catch (e) { console.log('CALL_ERR ' + (Date.now() - t0) + ' ' + String(e && e.message)); }`,
        { HTTPS_PROXY: `http://127.0.0.1:${p.port}` },
        25_000,
      );
      const m = /CALL_ERR (\d+) (.*)/.exec(r.out);
      assert.ok(m, r.out);
      assert.match(m[2]!, /timed out after 1500ms/, 'the caller budget ends it, as a timeout');
      assert.ok(Number(m[1]) < 6000, `settled after ${m[1]} ms`);
      assert.equal(r.killed, false, 'the abandoned CONNECT must not keep the process running');
      assert.equal(p.connects, 1);
    } finally {
      await p.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

test('stopping the share events feed does not wait for a stalled proxy', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-f-'));
  const p = await stallingProxy(false);
  try {
    const r = await runAlone(
      dir,
      `const c = new SaihmProClient('https://saihm.test/mcp', 'Bearer t', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 60000 });\n` +
        `c.startShareEvents();\n` +
        `await new Promise((r) => setTimeout(r, 800));\n` +
        `const t0 = Date.now();\n` +
        `await c.stopShareEvents();\n` +
        `console.log('STOPPED ' + (Date.now() - t0));`,
      { HTTPS_PROXY: `http://127.0.0.1:${p.port}` },
      25_000,
    );
    const m = /STOPPED (\d+)/.exec(r.out);
    assert.ok(m, r.out);
    assert.equal(p.connects, 1, 'the feed was waiting on the proxy when it was stopped');
    assert.ok(Number(m[1]) < 2000, `stop took ${m[1]} ms`);
    assert.equal(r.killed, false, 'and nothing it opened keeps the process running');
  } finally {
    await p.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the CONNECT phase has an absolute deadline of its own, whatever the caller allows', { timeout: 20_000 }, async (t) => {
  const p = await stallingProxy(true);
  const saved: Record<string, string | undefined> = {};
  for (const k of VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  process.env.HTTPS_PROXY = `http://127.0.0.1:${p.port}`;
  try {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const c = new SaihmProClient('https://saihm.test/mcp', 'Bearer t', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 600_000 });
    const settled = c.status().then(
      () => 'CALL_OK',
      (e: Error) => e.message,
    );
    await p.first;
    // A trickling reply re-arms any idle timer; only a deadline counted from the CONNECT ends it.
    t.mock.timers.tick(30_000);
    t.mock.timers.reset();
    // Real time from here: without the deadline the call never settles, and that must FAIL this test -
    // the proxy is closed below either way - rather than hang the file.
    let guard: ReturnType<typeof setTimeout> | undefined;
    const result = await Promise.race([
      settled,
      new Promise<string>((r) => (guard = setTimeout(() => r('STILL PENDING after the deadline'), 5000))),
    ]);
    clearTimeout(guard);
    assert.match(result, /PROXY_CONNECT_TIMEOUT/);
  } finally {
    t.mock.timers.reset();
    for (const k of VARS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await p.close();
  }
});

test('end to end: a proxy answering CONNECT with a redirect is refused by its code', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-r-'));
  const r = await rig('saihm.test', dir, '302 Found');
  try {
    const out = await callThrough(dir, { HTTPS_PROXY: `http://127.0.0.1:${r.proxyPort}`, NODE_EXTRA_CA_CERTS: r.ca });
    assert.match(out, /PROXY_CONNECT_302/, out);
    assert.equal(r.requests.length, 0);
  } finally {
    await r.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('end to end: calls share one tunnel, kept alive like a direct connection', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-k-'));
  const r = await rig('saihm.test', dir);
  try {
    const out = await callThrough(dir, { HTTPS_PROXY: `http://127.0.0.1:${r.proxyPort}`, NODE_EXTRA_CA_CERTS: r.ca }, { calls: 3 });
    assert.equal(out.match(/CALL_OK/g)?.length, 3, out);
    assert.equal(r.requests.length, 3);
    assert.equal(r.connects.length, 1, 'three calls, one CONNECT');
  } finally {
    await r.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('end to end: the remedy follows the failure - an untrusted certificate, or a proxy that refuses', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-m-'));
  const ok = await rig('saihm.test', dir);
  try {
    // No NODE_EXTRA_CA_CERTS: the endpoint's certificate is one this machine does not trust, as behind a
    // proxy that inspects TLS. Both paths say how to trust that network's CA, and never to stop checking.
    const call = await callThrough(dir, { HTTPS_PROXY: `http://127.0.0.1:${ok.proxyPort}` });
    assert.match(call, /UNABLE_TO_VERIFY_LEAF_SIGNATURE\)\. Never disable certificate checks; if TLS is inspected here, set NODE_EXTRA_CA_CERTS to a file of the network admin's CA certificate\./, call);
    // Within the render budget at its worst - the longest method, the old default host and the longest code -
    // and were it ever cut, the cut would take the end of the sentence, never "Never disable".
    const remedy = call.slice(call.indexOf('). ') + 3).trim();
    const worst = `SAIHM endpoint saihm_governance_propose could not reach https://saihm.coti.global/mcp (UNABLE_TO_GET_ISSUER_CERT_LOCALLY). ${remedy}`;
    assert.ok(worst.length <= 256, `${worst.length}: ${worst}`);
    const onboard = await callThrough(dir, { HTTPS_PROXY: `http://127.0.0.1:${ok.proxyPort}` }, { onboard: true });
    assert.match(onboard, /SAIHM endpoint's certificate is not trusted here\. Never turn certificate checks off: if this network inspects TLS, get its CA certificate from its administrator, set NODE_EXTRA_CA_CERTS to that file and restart\./, onboard);
    assert.equal(ok.requests.length, 0);
  } finally {
    await ok.close();
  }
  const refusing = await rig('saihm.test', dir, '403 Forbidden');
  try {
    const onboard = await callThrough(dir, { HTTPS_PROXY: `http://127.0.0.1:${refusing.proxyPort}`, NODE_EXTRA_CA_CERTS: refusing.ca }, { onboard: true });
    // An egress allowlist refuses the tunnel this way: the allowlist leads the remedy, on both paths.
    assert.match(onboard, /could not be reached through the proxy in HTTPS_PROXY\. In a hosted agent environment, allow its host \(saihm\.net by default\) in the network settings; else check the proxy and NO_PROXY\./, onboard);
    const call = await callThrough(dir, { HTTPS_PROXY: `http://127.0.0.1:${refusing.proxyPort}`, NODE_EXTRA_CA_CERTS: refusing.ca });
    assert.match(call, /\(PROXY_CONNECT_403\)\. Via the proxy in HTTPS_PROXY: if hosted, allow this host in its network settings/, call);
  } finally {
    await refusing.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a proxy setting that cannot be used is named in the remedy, on the call and on the onboard', async () => {
  const saved: Record<string, string | undefined> = {};
  for (const k of VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  process.env.https_proxy = 'socks5://user:s3cr3t@p:1080';
  try {
    const seed = new Uint8Array(32).fill(7);
    const call = await new SaihmProClient('https://saihm.test/mcp', 'Bearer t', seed, { tier: 'PRO' }).status().then(
      () => 'CALL_OK',
      (e: Error) => e.message,
    );
    assert.match(call, /\(https_proxy_NOT_AN_HTTP_PROXY\)\. Only an http proxy URL is supported: fix the variable named above, or add this host to NO_PROXY\./, call);
    const onboard = await new SaihmProClient('https://saihm.test/mcp', undefined, seed, { tier: 'PRO', paymentMethod: 'stripe' }).status().then(
      () => 'CALL_OK',
      (e: Error) => e.message,
    );
    assert.match(onboard, /the proxy in https_proxy \(read before HTTPS_PROXY\) is not an http URL, and only http proxies are supported\. Fix it, or add the endpoint's host to NO_PROXY\./, onboard);
    for (const m of [call, onboard]) assert.ok(!m.includes('s3cr3t'));
  } finally {
    for (const k of VARS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
});

/** Run a script body in a child that imports the client; return what it printed. No exit is added for it. */
function runScript(dir: string, env: Record<string, string>, body: string): Promise<string> {
  const script = join(dir, `run-${Math.random().toString(36).slice(2)}.mts`);
  writeFileSync(script, `import { SaihmProClient } from ${JSON.stringify(CLIENT)};\n${body}\n`);
  return new Promise((res) => {
    const p = spawn(TSX, [script], { env: { PATH: process.env.PATH ?? '', SAIHM_HOME: dir, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    p.stdout!.on('data', (d) => (out += d));
    p.stderr!.on('data', (d) => (out += d));
    const t = setTimeout(() => p.kill(), 40000);
    p.on('close', () => {
      clearTimeout(t);
      res(out);
    });
  });
}

/**
 * A proxy and endpoint for the queue tests. The first `holdFirst` requests are answered after `holdMs`
 * (with `close`, each on a connection the endpoint then closes), and from CONNECT number `silentFrom` on
 * the proxy accepts and never answers, recording when each such tunnel socket closed.
 * With `stagger`, only the first `stagger` of those held requests are answered, one every `holdMs`, and the
 * rest are held until the rig closes: the endpoint frees one socket at a time. CONNECT number `badGatewayAt`
 * is answered `502 Bad Gateway`, as a proxy answers when it cannot reach the endpoint: the call it was opened
 * for FAILS at once, by its own CONNECT, rather than giving up.
 */
async function queueRig(dir: string, o: { holdFirst: number; holdMs: number; close?: boolean; silentFrom?: number; slowFrom?: number; slowMs?: number; stagger?: number; badGatewayAt?: number }) {
  const pem = issue(dir, 'saihm.test');
  let seen = 0;
  const endpoint = createHttpsServer({ key: readFileSync(pem.key), cert: readFileSync(pem.cert) }, (req, res) => {
    const n = ++seen;
    req.resume();
    const answer = (): void => {
      if (res.destroyed || res.writableEnded) return;
      res.writeHead(200, { 'content-type': 'application/json', ...(o.close ? { connection: 'close' } : {}) });
      res.end('{}');
    };
    if (n > o.holdFirst) answer();
    else if (o.stagger === undefined) setTimeout(answer, o.holdMs);
    else if (n <= o.stagger) setTimeout(answer, o.holdMs * n);
  });
  await new Promise<void>((r) => endpoint.listen(0, '127.0.0.1', () => r()));
  const endpointPort = (endpoint.address() as AddressInfo).port;
  let connects = 0;
  const silentClosedAt: (number | undefined)[] = [];
  const tunnels = new Set<import('node:stream').Duplex>();
  const proxy: Server = createHttpServer((_req, res) => res.writeHead(405).end());
  proxy.on('connect', (_req, socket, head) => {
    tunnels.add(socket);
    socket.on('error', () => {});
    const n = ++connects;
    if (n === o.badGatewayAt) {
      socket.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n');
      socket.resume();
      return;
    }
    if (o.silentFrom !== undefined && n >= o.silentFrom) {
      const i = silentClosedAt.push(undefined) - 1;
      const gone = (): void => void (silentClosedAt[i] ??= Date.now());
      // An http server's sockets are half-open: the client's close arrives as 'end', and 'close' waits for ours.
      socket.on('end', () => {
        gone();
        socket.end();
      });
      socket.on('close', gone);
      socket.resume();
      return;
    }
    const open = (): void => {
      if (socket.destroyed) return;
      const upstream = netConnect(endpointPort, '127.0.0.1', () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length > 0) upstream.write(head);
        upstream.pipe(socket);
        socket.pipe(upstream);
      });
      upstream.on('error', () => socket.destroy());
      socket.on('error', () => upstream.destroy());
    };
    if (o.slowFrom !== undefined && n >= o.slowFrom) setTimeout(open, o.slowMs ?? 0);
    else open();
  });
  await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', () => r()));
  return {
    ca: pem.ca,
    proxyPort: (proxy.address() as AddressInfo).port,
    silentClosedAt,
    close: async () => {
      for (const s of tunnels) s.destroy();
      proxy.closeAllConnections?.();
      endpoint.closeAllConnections?.();
      await new Promise<void>((r) => proxy.close(() => r()));
      await new Promise<void>((r) => endpoint.close(() => r()));
    },
  };
}

const QUEUE_CALLS = (budgetMs: number, waitMs: number): string =>
  `const c = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: ${budgetMs} });\n` +
  `const one = (i) => c.status().then(() => console.log('R' + i + ' OK'), (e) => console.log('R' + i + ' ERR ' + e.message));\n` +
  `const first = Array.from({ length: 8 }, (_, i) => one(i + 1));\n` +
  `await new Promise((r) => setTimeout(r, ${waitMs}));\n` +
  `await Promise.all([...first, one(9)]);\n` +
  `console.log('SETTLED ' + Date.now());\n`;

test('a call queued behind busy tunnels is not failed by another call\'s abort', { skip: !haveOpenssl() && 'openssl not available', timeout: 60_000 }, async () => {
  // Eight calls hold the agent's eight sockets and time out; a ninth, queued meanwhile, is handed a
  // socket built from a timed-out call's options. It must run on its own signal and succeed.
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-q-'));
  const q = await queueRig(dir, { holdFirst: 8, holdMs: 4000 });
  try {
    const out = await runScript(dir, { HTTPS_PROXY: `http://127.0.0.1:${q.proxyPort}`, NODE_EXTRA_CA_CERTS: q.ca }, QUEUE_CALLS(2000, 1000) + 'process.exit(0);');
    assert.match(out, /R9 OK/, out);
    for (let i = 1; i <= 8; i++) assert.match(out, new RegExp(`R${i} ERR .*timed out after 2000ms`), out);
  } finally {
    await q.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a queued call\'s own abort ends its CONNECT, rather than the deadline', { skip: !haveOpenssl() && 'openssl not available', timeout: 60_000 }, async () => {
  // The eight answer and close, which hands the queued ninth its replacement sockets from THEIR options;
  // the proxy never answers those CONNECTs. When the ninth times out, every tunnel opened for it must close
  // then, not when the 30 s deadline would - the child stays alive four seconds after to tell them apart.
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-q2-'));
  const q = await queueRig(dir, { holdFirst: 8, holdMs: 1000, close: true, silentFrom: 9 });
  try {
    const out = await runScript(dir, { HTTPS_PROXY: `http://127.0.0.1:${q.proxyPort}`, NODE_EXTRA_CA_CERTS: q.ca }, QUEUE_CALLS(2500, 400) + 'await new Promise((r) => setTimeout(r, 4000));\nprocess.exit(0);');
    assert.match(out, /R9 ERR .*timed out after 2500ms/, out);
    const settled = Number(/SETTLED (\d+)/.exec(out)?.[1]);
    assert.ok(q.silentClosedAt.length >= 1, `no CONNECT was opened for the queued call: ${out}`);
    const late = q.silentClosedAt.map((t) => (t === undefined ? Infinity : t - settled));
    assert.ok(late.every((d) => d < 1500), `a CONNECT outlived its own request's abort (ms after it settled): ${JSON.stringify(late)}`);
  } finally {
    await q.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a process exits promptly after a call through the proxy: the CONNECT deadline goes with the tunnel', { skip: !haveOpenssl() && 'openssl not available', timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-x-'));
  const r = await rig('saihm.test', dir);
  try {
    const t0 = Date.now();
    const out = await runScript(
      dir,
      { HTTPS_PROXY: `http://127.0.0.1:${r.proxyPort}`, NODE_EXTRA_CA_CERTS: r.ca },
      `const c = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 8000 });\n` +
        `await c.status().then(() => console.log('CALL_OK'), (e) => console.log('CALL_ERR ' + e.message));`,
    );
    assert.match(out, /CALL_OK/, out);
    assert.ok(Date.now() - t0 < 15_000, `the process lingered: ${Date.now() - t0} ms`);
  } finally {
    await r.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a timed-out call closes its connection, so the process exits on its own', { timeout: 60_000 }, async () => {
  const hung = createHttpServer(() => {});
  await new Promise<void>((r) => hung.listen(0, '127.0.0.1', () => r()));
  const port = (hung.address() as AddressInfo).port;
  const dir = mkdtempSync(join(tmpdir(), 'saihm-hung-'));
  try {
    const t0 = Date.now();
    const out = await runScript(
      dir,
      {},
      `const c = new SaihmProClient('http://127.0.0.1:${port}/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 800 });\n` +
        `await c.status().then(() => console.log('CALL_OK'), (e) => console.log('CALL_ERR ' + e.message));`,
    );
    assert.match(out, /timed out after 800ms/, out);
    assert.ok(Date.now() - t0 < 15_000, `the process lingered: ${Date.now() - t0} ms`);
  } finally {
    hung.closeAllConnections?.();
    await new Promise<void>((r) => hung.close(() => r()));
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the remedies are chosen by error class: TLS inspection codes, unusable proxy settings, nothing else', () => {
  for (const code of ['SELF_SIGNED_CERT_IN_CHAIN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY'])
    assert.ok(untrustedCertificate(code), code);
  for (const code of ['CERT_HAS_EXPIRED', 'ERR_TLS_CERT_ALTNAME_INVALID', 'ECONNRESET', 'PROXY_CONNECT_403'])
    assert.ok(!untrustedCertificate(code), code);
  for (const code of ['HTTPS_PROXY_NOT_A_URL', 'HTTPS_PROXY_NOT_AN_HTTP_PROXY', 'https_proxy_NOT_A_URL', 'https_proxy_NOT_AN_HTTP_PROXY']) assert.ok(unusableProxy(code), code);
  for (const code of ['PROXY_CONNECT_403', 'PROXY_CONNECT_TIMEOUT', 'ECONNREFUSED', 'HTTPS_PROXY_NOT_A_URLX'])
    assert.ok(!unusableProxy(code), code);
});

test('a proxy at an IPv6 address is dialed without its brackets', { skip: !haveOpenssl() && 'openssl not available', timeout: 60_000 }, async (t) => {
  const v6 = await new Promise<boolean>((res) => {
    const s = createHttpServer();
    s.once('error', () => res(false));
    s.listen(0, '::1', () => s.close(() => res(true)));
  });
  if (!v6) return t.skip('no IPv6 loopback here');
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-6-'));
  const r = await rig('saihm.test', dir, null, '::1');
  try {
    const out = await callThrough(dir, { HTTPS_PROXY: `http://[::1]:${r.proxyPort}`, NODE_EXTRA_CA_CERTS: r.ca });
    assert.match(out, /CALL_OK/, out);
    assert.deepEqual(r.connects.map((c) => c.authority), ['saihm.test:443']);
  } finally {
    await r.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a queued call that gave up does not strand the calls queued behind it', { skip: !haveOpenssl() && 'openssl not available', timeout: 60_000 }, async () => {
  // Eight calls hold the sockets; a ninth on a short budget queues and gives up; a tenth queues behind it.
  // When the eight answer and close, the replacement socket opened for the head of the queue - the call
  // that gave up - must still be opened, so it can serve the tenth.
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-q3-'));
  const q = await queueRig(dir, { holdFirst: 8, holdMs: 1500, close: true });
  try {
    const out = await runScript(
      dir,
      { HTTPS_PROXY: `http://127.0.0.1:${q.proxyPort}`, NODE_EXTRA_CA_CERTS: q.ca },
      `const long = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 8000 });\n` +
        `const short = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 600 });\n` +
        `const t0 = Date.now();\n` +
        `const one = (c, i) => c.status().then(() => console.log('R' + i + ' OK ' + (Date.now() - t0)), (e) => console.log('R' + i + ' ERR ' + e.message));\n` +
        `const first = Array.from({ length: 8 }, (_, i) => one(long, i + 1));\n` +
        `await new Promise((r) => setTimeout(r, 200));\n` +
        `const gaveUp = one(short, 9);\n` +
        `await new Promise((r) => setTimeout(r, 100));\n` +
        `await Promise.all([...first, gaveUp, one(long, 10)]);\n` +
        `process.exit(0);`,
    );
    assert.match(out, /R9 ERR .*timed out after 600ms/, out);
    const r10 = /R10 OK (\d+)/.exec(out);
    assert.ok(r10 !== null && Number(r10[1]) < 5000, `the call queued behind it was stranded: ${out}`);
  } finally {
    await q.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a queued call that gives up while its tunnel is opening leaves that tunnel to the call behind it', { skip: !haveOpenssl() && 'openssl not available', timeout: 60_000 }, async () => {
  // The eight answer and close; the replacement tunnels opened for the head of the queue take 1.5 s to
  // connect, and the head gives up before they do. The call queued behind it must get one of them.
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-q4-'));
  const q = await queueRig(dir, { holdFirst: 8, holdMs: 1000, close: true, slowFrom: 9, slowMs: 1500 });
  try {
    const out = await runScript(
      dir,
      { HTTPS_PROXY: `http://127.0.0.1:${q.proxyPort}`, NODE_EXTRA_CA_CERTS: q.ca },
      `const long = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 8000 });\n` +
        `const short = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 1500 });\n` +
        `const t0 = Date.now();\n` +
        `const one = (c, i) => c.status().then(() => console.log('R' + i + ' OK ' + (Date.now() - t0)), (e) => console.log('R' + i + ' ERR ' + e.message));\n` +
        `const first = Array.from({ length: 8 }, (_, i) => one(long, i + 1));\n` +
        `await new Promise((r) => setTimeout(r, 200));\n` +
        `const gaveUp = one(short, 9);\n` +
        `await new Promise((r) => setTimeout(r, 100));\n` +
        `await Promise.all([...first, gaveUp, one(long, 10)]);\n` +
        `process.exit(0);`,
    );
    assert.match(out, /R9 ERR .*timed out after 1500ms/, out);
    const r10 = /R10 OK (\d+)/.exec(out);
    assert.ok(r10 !== null && Number(r10[1]) < 6000, `the call queued behind it lost the tunnel: ${out}`);
  } finally {
    await q.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an unusable proxy is named exactly: HTTPS_PROXY when that is the one read', async () => {
  const saved: Record<string, string | undefined> = {};
  for (const k of VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  process.env.HTTPS_PROXY = 'socks5://user:s3cr3t@p:1080';
  try {
    const seed = new Uint8Array(32).fill(7);
    const call = await new SaihmProClient('https://saihm.test/mcp', 'Bearer t', seed, { tier: 'PRO' }).status().then(
      () => 'CALL_OK',
      (e: Error) => e.message,
    );
    assert.match(call, /\(HTTPS_PROXY_NOT_AN_HTTP_PROXY\)\. Only an http proxy URL is supported/, call);
    const onboard = await new SaihmProClient('https://saihm.test/mcp', undefined, seed, { tier: 'PRO', paymentMethod: 'stripe' }).status().then(
      () => 'CALL_OK',
      (e: Error) => e.message,
    );
    assert.match(onboard, /the proxy in HTTPS_PROXY is not an http URL/, onboard);
    assert.doesNotMatch(onboard, /https_proxy/);
    for (const m of [call, onboard]) assert.ok(!m.includes('s3cr3t'));
  } finally {
    for (const k of VARS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
});

test('NO_PROXY as operators write it: spaces after the commas, any case', () => {
  assert.equal(pick('https://saihm.net/mcp', { HTTPS_PROXY: 'http://p1:3128', NO_PROXY: 'localhost, saihm.net' }), null);
  assert.equal(pick('https://saihm.net/mcp', { HTTPS_PROXY: 'http://p1:3128', NO_PROXY: 'SAIHM.NET' }), null);
  assert.equal(pick('https://saihm.net/mcp', { HTTPS_PROXY: 'http://p1:3128', NO_PROXY: 'other.test, example.org' }), 'p1:3128', 'positive control');
});

test('a CONNECT opened for a queue follows it: it ends only when every call waiting for it has given up', { skip: !haveOpenssl() && 'openssl not available', timeout: 60_000 }, async () => {
  // Two calls queue behind eight; their tunnels are never answered. The first gives up, then the second:
  // the tunnels must close when the SECOND does, not at the 30 s deadline - the child stays alive four
  // seconds after both, to tell the two apart.
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-q5-'));
  const q = await queueRig(dir, { holdFirst: 8, holdMs: 1000, close: true, silentFrom: 9 });
  try {
    const out = await runScript(
      dir,
      { HTTPS_PROXY: `http://127.0.0.1:${q.proxyPort}`, NODE_EXTRA_CA_CERTS: q.ca },
      `const long = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 8000 });\n` +
        `const r9 = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 1500 });\n` +
        `const r10 = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 2500 });\n` +
        `const one = (c, i) => c.status().then(() => console.log('R' + i + ' OK'), (e) => console.log('R' + i + ' ERR ' + e.message));\n` +
        `const first = Array.from({ length: 8 }, (_, i) => one(long, i + 1));\n` +
        `await new Promise((r) => setTimeout(r, 200));\n` +
        `const a = one(r9, 9);\n` +
        `await new Promise((r) => setTimeout(r, 100));\n` +
        `await Promise.all([...first, a, one(r10, 10)]);\n` +
        `console.log('SETTLED ' + Date.now());\n` +
        `await new Promise((r) => setTimeout(r, 4000));\n` +
        `process.exit(0);`,
    );
    assert.match(out, /R9 ERR .*timed out after 1500ms/, out);
    assert.match(out, /R10 ERR .*timed out after 2500ms/, out);
    const settled = Number(/SETTLED (\d+)/.exec(out)?.[1]);
    assert.ok(q.silentClosedAt.length >= 1, `no CONNECT was opened for the queue: ${out}`);
    const late = q.silentClosedAt.map((t) => (t === undefined ? Infinity : t - settled));
    assert.ok(late.every((d) => d < 1500), `a CONNECT outlived every call waiting for it (ms after they settled): ${JSON.stringify(late)}`);
  } finally {
    await q.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a CONNECT opened after its call gave up follows the call queued behind it', { skip: !haveOpenssl() && 'openssl not available', timeout: 60_000 }, async () => {
  // Two calls queue behind eight. The first gives up BEFORE the eight answer, so the tunnels that replace
  // theirs are opened for a call that is already gone; they are never answered. They must close when the
  // second call gives up, not at the 30 s deadline - the child stays alive four seconds after both.
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-q6-'));
  const q = await queueRig(dir, { holdFirst: 8, holdMs: 1500, close: true, silentFrom: 9 });
  try {
    const out = await runScript(
      dir,
      { HTTPS_PROXY: `http://127.0.0.1:${q.proxyPort}`, NODE_EXTRA_CA_CERTS: q.ca },
      `const long = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 8000 });\n` +
        `const r9 = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 600 });\n` +
        `const r10 = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 3000 });\n` +
        `const t0 = Date.now();\n` +
        `const one = (c, i) => c.status().then(() => console.log('R' + i + ' OK ' + (Date.now() - t0)), (e) => console.log('R' + i + ' ERR ' + (Date.now() - t0) + ' ' + e.message));\n` +
        `const first = Array.from({ length: 8 }, (_, i) => one(long, i + 1));\n` +
        `await new Promise((r) => setTimeout(r, 200));\n` +
        `const a = one(r9, 9);\n` +
        `await new Promise((r) => setTimeout(r, 100));\n` +
        `await Promise.all([...first, a, one(r10, 10)]);\n` +
        `console.log('SETTLED ' + Date.now());\n` +
        `await new Promise((r) => setTimeout(r, 4000));\n` +
        `process.exit(0);`,
    );
    assert.match(out, /R9 ERR \d+ .*timed out after 600ms/, out);
    assert.match(out, /R10 ERR \d+ .*timed out after 3000ms/, out);
    // The order this test is about: the first queued call had given up before any of the eight answered,
    // so every tunnel opened for the queue was opened for a call that was already gone.
    const answered = [...out.matchAll(/R[1-8] OK (\d+)/g)].map((m) => Number(m[1]));
    assert.equal(answered.length, 8, out);
    assert.ok(Number(/R9 ERR (\d+)/.exec(out)?.[1]) < Math.min(...answered), `the first queued call gave up only after the eight answered: ${out}`);
    const settled = Number(/SETTLED (\d+)/.exec(out)?.[1]);
    assert.ok(q.silentClosedAt.length >= 1, `no CONNECT was opened for the queue: ${out}`);
    const late = q.silentClosedAt.map((t) => (t === undefined ? Infinity : t - settled));
    assert.ok(late.every((d) => d < 1500), `a CONNECT outlived every call waiting for it (ms after they settled): ${JSON.stringify(late)}`);
  } finally {
    await q.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a proxy that cannot be reached is named as the variable read: https_proxy when that is the one set', async () => {
  // The lowercase variable is read first. Naming HTTPS_PROXY for it sent the reader to the one that was unset,
  // or that was fine (docs R6 L1, security R6 B2, correctness R6 B8). Nothing listens on port 9.
  const saved: Record<string, string | undefined> = {};
  for (const k of VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  const seed = new Uint8Array(32).fill(7);
  const both = async (): Promise<{ call: string; onboard: string }> => ({
    call: await new SaihmProClient('https://saihm.test/mcp', 'Bearer t', seed, { tier: 'PRO' }).status().then(
      () => 'CALL_OK',
      (e: Error) => e.message,
    ),
    onboard: await new SaihmProClient('https://saihm.test/mcp', undefined, seed, { tier: 'PRO', paymentMethod: 'stripe' }).status().then(
      () => 'CALL_OK',
      (e: Error) => e.message,
    ),
  });
  try {
    for (const env of [{ https_proxy: 'http://127.0.0.1:9' }, { https_proxy: 'http://127.0.0.1:9', HTTPS_PROXY: 'http://127.0.0.1:10' }]) {
      Object.assign(process.env, env);
      const lower = await both();
      assert.match(lower.call, /\)\. Via the proxy in https_proxy: if hosted, allow this host in its network settings; otherwise check the proxy and NO_PROXY\.$/, lower.call);
      assert.match(lower.onboard, /could not be reached through the proxy in https_proxy\. In a hosted agent environment, allow its host \(saihm\.net by default\) in the network settings; else check the proxy and NO_PROXY\./, lower.onboard);
      for (const m of [lower.call, lower.onboard]) assert.doesNotMatch(m, /HTTPS_PROXY/, m);
      for (const k of VARS) delete process.env[k];
    }
    // Positive control: with only HTTPS_PROXY set, both name it.
    process.env.HTTPS_PROXY = 'http://127.0.0.1:9';
    const upper = await both();
    assert.match(upper.call, /\)\. Via the proxy in HTTPS_PROXY: if hosted, allow this host in its network settings; otherwise check the proxy and NO_PROXY\.$/, upper.call);
    assert.match(upper.onboard, /could not be reached through the proxy in HTTPS_PROXY\./, upper.onboard);
    for (const m of [upper.call, upper.onboard]) assert.doesNotMatch(m, /https_proxy/, m);
  } finally {
    for (const k of VARS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
});

test('the remedy for an endpoint not reached directly fits the render budget at its worst', async () => {
  // Shortened in batch 7: at the longest code measured on this arm, the old default host and the longest method,
  // the old wording passed the budget and the cut took "(and check NO_PROXY)." (correctness R6 below-Low B2).
  const saved: Record<string, string | undefined> = {};
  for (const k of VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  try {
    // Loopback, so never proxied; nothing listens on port 9.
    const call = await new SaihmProClient('https://127.0.0.1:9/mcp', 'Bearer t', new Uint8Array(32).fill(7), { tier: 'PRO' }).status().then(
      () => 'CALL_OK',
      (e: Error) => e.message,
    );
    assert.match(call, /\(ECONNREFUSED\)\. If hosted, allow that host in its network settings; if traffic must go through a proxy, set HTTPS_PROXY and check NO_PROXY\.$/, call);
    const remedy = call.slice(call.indexOf('). ') + 3);
    const worst = `SAIHM endpoint saihm_governance_propose could not reach https://saihm.coti.global/mcp (ERR_TLS_CERT_ALTNAME_INVALID). ${remedy}`;
    assert.ok(worst.length <= 256, `${worst.length}: ${worst}`);
  } finally {
    for (const k of VARS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
});

test('a CONNECT opened for a queued call that already FAILED follows the queue: it ends when the call behind gives up', { skip: !haveOpenssl() && 'openssl not available', timeout: 60_000 }, async () => {
  // Eight calls hold the sockets; H (20 s budget) then B (4 s) queue behind them. The endpoint frees one socket:
  // the CONNECT opened for H is answered 502, so H fails at once - by its own CONNECT, not by giving up, so its
  // signal never fires. The endpoint frees a second: Node opens the replacement for H again, still at the head of
  // the queue, and that CONNECT is never answered. It must close when B gives up, not at the 30 s deadline - the
  // child stays alive four seconds after both, to tell the two apart (security R6 B1).
  const dir = mkdtempSync(join(tmpdir(), 'saihm-proxy-q7-'));
  const q = await queueRig(dir, { holdFirst: 8, holdMs: 1000, close: true, stagger: 2, badGatewayAt: 9, silentFrom: 10 });
  try {
    const out = await runScript(
      dir,
      { HTTPS_PROXY: `http://127.0.0.1:${q.proxyPort}`, NODE_EXTRA_CA_CERTS: q.ca },
      `const long = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 20000 });\n` +
        `const h = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 20000 });\n` +
        `const b = new SaihmProClient('https://saihm.test/mcp', 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 4000 });\n` +
        `const t0 = Date.now();\n` +
        `const one = (c, i) => c.status().then(() => console.log(i + ' OK ' + (Date.now() - t0)), (e) => console.log(i + ' ERR ' + (Date.now() - t0) + ' ' + e.message));\n` +
        `for (let i = 1; i <= 8; i++) void one(long, 'R' + i);\n` +
        `await new Promise((r) => setTimeout(r, 200));\n` +
        `const hDone = one(h, 'H');\n` +
        `await new Promise((r) => setTimeout(r, 100));\n` +
        `await Promise.all([hDone, one(b, 'B')]);\n` +
        `console.log('SETTLED ' + Date.now());\n` +
        `await new Promise((r) => setTimeout(r, 4000));\n` +
        `process.exit(0);`,
    );
    assert.match(out, /H ERR \d+ .*\(PROXY_CONNECT_502\)/, out);
    assert.match(out, /B ERR \d+ .*timed out after 4000ms/, out);
    // The order this test is about: H had failed before the endpoint freed the second socket, so the CONNECT
    // opened for it then was opened for a call that had already failed.
    const answered = [...out.matchAll(/R[1-8] OK (\d+)/g)].map((m) => Number(m[1]));
    assert.equal(answered.length, 2, out);
    assert.ok(Number(/H ERR (\d+)/.exec(out)?.[1]) < Math.max(...answered), `H failed only after the second socket was freed: ${out}`);
    const settled = Number(/SETTLED (\d+)/.exec(out)?.[1]);
    assert.ok(q.silentClosedAt.length >= 1, `no CONNECT was opened after H failed: ${out}`);
    const late = q.silentClosedAt.map((t) => (t === undefined ? Infinity : t - settled));
    assert.ok(late.every((d) => d < 1500), `a CONNECT opened for the failed call outlived the call behind it (ms after they settled): ${JSON.stringify(late)}`);
  } finally {
    await q.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('on the direct path, a call queued behind busy sockets settles at its own budget', { timeout: 30_000 }, async () => {
  // No proxy: eight calls with a 3 s budget hold the agent's eight sockets on an endpoint that never answers, and
  // a ninth with 500 ms queues behind them. Its own abort must settle it, not the first socket freed at 3 s
  // (correctness R6 F2).
  const dir = mkdtempSync(join(tmpdir(), 'saihm-direct-q-'));
  const endpoint = createHttpServer((req) => void req.resume());
  await new Promise<void>((r) => endpoint.listen(0, '127.0.0.1', () => r()));
  try {
    const url = `http://127.0.0.1:${(endpoint.address() as AddressInfo).port}/mcp`;
    const out = await runScript(
      dir,
      {},
      `const slow = new SaihmProClient(${JSON.stringify(url)}, 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 3000 });\n` +
        `const quick = new SaihmProClient(${JSON.stringify(url)}, 'Bearer test-token', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 500 });\n` +
        `const first = Array.from({ length: 8 }, () => slow.status().catch(() => undefined));\n` +
        `await new Promise((r) => setTimeout(r, 300));\n` +
        `const t9 = Date.now();\n` +
        `await quick.status().then(() => console.log('R9 OK'), (e) => console.log('R9 ERR ' + (Date.now() - t9) + ' ' + e.message));\n` +
        `await Promise.all(first);\n` +
        `process.exit(0);`,
    );
    const r9 = /R9 ERR (\d+) (.*)/.exec(out);
    assert.ok(r9 !== null, out);
    assert.match(r9[2] as string, /timed out after 500ms/, out);
    assert.ok(Number(r9[1]) < 2000, `the queued call settled only when a socket was freed: ${out}`);
  } finally {
    endpoint.closeAllConnections?.();
    await new Promise<void>((r) => endpoint.close(() => r()));
    rmSync(dir, { recursive: true, force: true });
  }
});
