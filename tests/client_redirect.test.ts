// A redirect from the endpoint to another origin never carries this client's credentials there; one on the same origin
// does, as before. The bearer token and any cookie are for the endpoint, not for wherever it points. A 307 or 308 to
// another origin, which would re-send the body, is refused; a malformed redirect or status is an error, not a crash.
// Runner: npx tsx --test tests/client_redirect.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { createServer, type IncomingHttpHeaders } from 'node:http';
import { createServer as createTcpServer, type AddressInfo } from 'node:net';
import { SaihmProClient } from '../src/client.js';

test('a cross-origin redirect drops the authorization header; a same-origin one keeps it', async () => {
  const seen: { path: string; headers: IncomingHttpHeaders }[] = [];
  const other = createServer((req, res) => {
    seen.push({ path: `other ${req.url}`, headers: req.headers });
    res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
  });
  await new Promise<void>((r) => other.listen(0, '127.0.0.1', () => r()));
  const otherBase = `http://127.0.0.1:${(other.address() as AddressInfo).port}`;
  const endpoint = createServer((req, res) => {
    seen.push({ path: `endpoint ${req.url}`, headers: req.headers });
    if (req.url === '/mcp') return void res.writeHead(302, { location: `${otherBase}/mcp` }).end();
    if (req.url === '/same') return void res.writeHead(307, { location: '/landed' }).end();
    res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
  });
  await new Promise<void>((r) => endpoint.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(endpoint.address() as AddressInfo).port}`;
  const saved = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'].map((k) => [k, process.env[k]] as const);
  for (const [k] of saved) delete process.env[k];
  try {
    await new SaihmProClient(`${base}/mcp`, 'Bearer redirect-test-credential', new Uint8Array(32).fill(5), { tier: 'PRO' }).status().catch(() => undefined);
    await new SaihmProClient(`${base}/same`, 'Bearer redirect-test-credential', new Uint8Array(32).fill(5), { tier: 'PRO' }).status().catch(() => undefined);
    const hop = seen.find((s) => s.path === 'other /mcp');
    assert.ok(hop, `the redirect was followed: ${seen.map((s) => s.path)}`);
    assert.equal(hop.headers.authorization, undefined, 'another origin never receives the credential');
    assert.equal(seen.find((s) => s.path === 'endpoint /mcp')?.headers.authorization, 'Bearer redirect-test-credential');
    const landed = seen.find((s) => s.path === 'endpoint /landed');
    assert.ok(landed, `the same-origin redirect was followed: ${seen.map((s) => s.path)}`);
    assert.equal(landed.headers.authorization, 'Bearer redirect-test-credential', 'the same origin keeps it');
  } finally {
    for (const [k, v] of saved) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    await new Promise<void>((r) => other.close(() => r()));
    await new Promise<void>((r) => endpoint.close(() => r()));
  }
});

test('a 307 or 308 to another origin is refused, as it would re-send the body; a malformed redirect or status is an error', async () => {
  const seen: string[] = [];
  const other = createServer((req, res) => {
    seen.push(`other ${req.method} ${req.url}`);
    res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
  });
  await new Promise<void>((r) => other.listen(0, '127.0.0.1', () => r()));
  const otherBase = `http://127.0.0.1:${(other.address() as AddressInfo).port}`;
  const endpoint = createServer((req, res) => {
    seen.push(`endpoint ${req.method} ${req.url}`);
    if (req.url === '/r307') return void res.writeHead(307, { location: `${otherBase}/mcp` }).end();
    if (req.url === '/r308') return void res.writeHead(308, { location: `${otherBase}/mcp` }).end();
    if (req.url === '/bad-location') return void res.writeHead(307, { location: 'http://[::1' }).end();
    if (req.url === '/status-600') return void res.writeHead(600).end();
    res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
  });
  await new Promise<void>((r) => endpoint.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(endpoint.address() as AddressInfo).port}`;
  const saved = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'].map((k) => [k, process.env[k]] as const);
  for (const [k] of saved) delete process.env[k];
  try {
    const cases: [string, string][] = [
      ['/r307', 'REDIRECT_CROSS_ORIGIN'],
      ['/r308', 'REDIRECT_CROSS_ORIGIN'],
      ['/bad-location', 'REDIRECT_LOCATION_INVALID'],
      ['/status-600', 'STATUS_OUT_OF_RANGE'],
    ];
    for (const [path, code] of cases) {
      // Bounded: a redirect that crashed the transport would otherwise leave this call waiting for ever.
      const answer = new SaihmProClient(`${base}${path}`, 'Bearer redirect-test-credential', new Uint8Array(32).fill(5), { tier: 'PRO' })
        .status()
        .then(() => null, (e: unknown) => e as Error);
      const late = new Promise<Error>((r) => setTimeout(() => r(new Error('no answer within 10 s')), 10_000).unref());
      const err = await Promise.race([answer, late]);
      assert.ok(err !== null && String(err.message).includes(code), `${path}: ${err === null ? 'no error' : err.message}`);
      // The endpoint WAS reached: the advice names the endpoint setting, never the network.
      assert.ok(String(err?.message).includes('SAIHM_ENDPOINT_URL') && !/could not (reach|be reached)/.test(String(err?.message)), `${path}: ${err?.message}`);
    }
    assert.ok(seen.includes('endpoint POST /r307') && seen.includes('endpoint POST /r308'), `the endpoint was asked: ${seen}`);
    assert.deepEqual(seen.filter((s) => s.startsWith('other')), [], 'nothing reaches the other origin');
  } finally {
    for (const [k, v] of saved) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    await new Promise<void>((r) => other.close(() => r()));
    await new Promise<void>((r) => endpoint.close(() => r()));
  }
});

test('an answer a Response cannot carry is an error, and a 204, 205 or 304 an answer with no body; never a crash', async () => {
  const endpoint = createServer((req, res) => {
    const [codeText, encoding] = (req.url ?? '').slice(2).split('-');
    const code = Number(codeText);
    res.writeHead([204, 205, 304].includes(code) ? code : 404, encoding ? { 'content-encoding': encoding } : {}).end();
  });
  await new Promise<void>((r) => endpoint.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(endpoint.address() as AddressInfo).port}`;
  // Raw bytes: a status text with DEL, which Node's own server would refuse to send.
  const raw = createTcpServer((sock) => {
    sock.once('data', () => sock.end('HTTP/1.1 200 O\x7fK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}'));
  });
  await new Promise<void>((r) => raw.listen(0, '127.0.0.1', () => r()));
  const rawBase = `http://127.0.0.1:${(raw.address() as AddressInfo).port}`;
  const saved = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'].map((k) => [k, process.env[k]] as const);
  for (const [k] of saved) delete process.env[k];
  const settle = (url: string) => {
    const answer = new SaihmProClient(url, 'Bearer redirect-test-credential', new Uint8Array(32).fill(5), { tier: 'PRO' })
      .status()
      .then(() => 'answered', (e: unknown) => String((e as Error).message));
    const late = new Promise<string>((r) => setTimeout(() => r('no answer within 10 s'), 10_000).unref());
    return Promise.race([answer, late]);
  };
  try {
    // Plain, and with each encoding the client decodes: an empty body is never handed to a decompressor.
    for (const code of [204, 205, 304])
      for (const enc of ['', 'gzip', 'deflate', 'br']) {
        const out = await settle(`${base}/s${code}${enc ? `-${enc}` : ''}`);
        assert.notEqual(out, 'no answer within 10 s', `${code} ${enc}`);
        assert.ok(!out.includes('RESPONSE_INVALID'), `${code} ${enc} is an answer with no body: ${out}`);
      }
    const del = await settle(`${rawBase}/mcp`);
    assert.ok(del.includes('RESPONSE_INVALID'), del);
    assert.ok(del.includes('SAIHM_ENDPOINT_URL') && !/could not (reach|be reached)/.test(del), del);
  } finally {
    for (const [k, v] of saved) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    await new Promise<void>((r) => endpoint.close(() => r()));
    await new Promise<void>((r) => raw.close(() => r()));
  }
});

test('a compressed answer cut off mid-way is an error, not a call that waits for ever', async () => {
  const { gzipSync } = await import('node:zlib');
  const whole = gzipSync(Buffer.from(JSON.stringify({ result: 'x'.repeat(200_000) })));
  const raw = createTcpServer((sock) => {
    sock.once('data', () => {
      sock.write(`HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-encoding: gzip\r\ncontent-length: ${whole.length}\r\n\r\n`);
      sock.write(whole.subarray(0, Math.floor(whole.length / 2)), () => sock.destroy());
    });
  });
  await new Promise<void>((r) => raw.listen(0, '127.0.0.1', () => r()));
  const saved = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'].map((k) => [k, process.env[k]] as const);
  for (const [k] of saved) delete process.env[k];
  try {
    const answer = new SaihmProClient(`http://127.0.0.1:${(raw.address() as AddressInfo).port}/mcp`, 'Bearer redirect-test-credential', new Uint8Array(32).fill(5), { tier: 'PRO' })
      .status()
      .then(() => 'answered', (e: unknown) => String((e as Error).message));
    const late = new Promise<string>((r) => setTimeout(() => r('no answer within 10 s'), 10_000).unref());
    const out = await Promise.race([answer, late]);
    assert.notEqual(out, 'no answer within 10 s', 'the cut-off answer ends the call');
    assert.notEqual(out, 'answered', out);
  } finally {
    for (const [k, v] of saved) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    await new Promise<void>((r) => raw.close(() => r()));
  }
});

test('signing in through a redirect to another host names SAIHM_ENDPOINT_URL, not the network', async () => {
  const seen: string[] = [];
  const other = createServer((req, res) => {
    seen.push(`other ${req.method} ${req.url}`);
    res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
  });
  await new Promise<void>((r) => other.listen(0, '127.0.0.1', () => r()));
  const otherBase = `http://127.0.0.1:${(other.address() as AddressInfo).port}`;
  const endpoint = createServer((req, res) => {
    if (req.method === 'GET' && (req.url ?? '').startsWith('/api/onboard/challenge'))
      return void res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ nonce: '12'.repeat(32) }));
    if (req.method === 'POST' && req.url === '/api/onboard') return void res.writeHead(307, { location: `${otherBase}/api/onboard` }).end();
    res.writeHead(404, { 'content-type': 'application/json' }).end('{}');
  });
  await new Promise<void>((r) => endpoint.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(endpoint.address() as AddressInfo).port}`;
  const saved = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'].map((k) => [k, process.env[k]] as const);
  for (const [k] of saved) delete process.env[k];
  try {
    const answer = new SaihmProClient(`${base}/mcp`, undefined, new Uint8Array(32).fill(7), { tier: 'FREE' })
      .status()
      .then(() => 'answered', (e: unknown) => String((e as Error).message));
    const late = new Promise<string>((r) => setTimeout(() => r('no answer within 10 s'), 10_000).unref());
    const out = await Promise.race([answer, late]);
    assert.ok(out.includes('redirects to another host') && out.includes('SAIHM_ENDPOINT_URL'), out);
    assert.ok(!/could not (reach|be reached)/.test(out), out);
    assert.deepEqual(seen.filter((x) => x.startsWith('other POST')), [], 'the signed sign-in proof never reaches the other host');
  } finally {
    for (const [k, v] of saved) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    await new Promise<void>((r) => other.close(() => r()));
    await new Promise<void>((r) => endpoint.close(() => r()));
  }
});

test('signing in, an answer that arrived but cannot be used names SAIHM_ENDPOINT_URL, never the network', async () => {
  const nonce = JSON.stringify({ nonce: '34'.repeat(32) });
  // One server per answer shape: the challenge is answered, then the sign-in POST gets the bad answer.
  const shapes: [string, (sock: import('node:net').Socket, isGet: boolean) => void][] = [
    ['600', (sock, isGet) => sock.end(isGet ? `HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${nonce.length}\r\nconnection: close\r\n\r\n${nonce}` : 'HTTP/1.1 600 Odd\r\ncontent-length: 0\r\nconnection: close\r\n\r\n')],
    ['bad Location', (sock, isGet) => sock.end(isGet ? `HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${nonce.length}\r\nconnection: close\r\n\r\n${nonce}` : 'HTTP/1.1 307 Temporary Redirect\r\nlocation: http://[::1\r\ncontent-length: 0\r\nconnection: close\r\n\r\n')],
    ['DEL status text', (sock, isGet) => sock.end(isGet ? `HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${nonce.length}\r\nconnection: close\r\n\r\n${nonce}` : 'HTTP/1.1 200 O\x7fK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}')],
  ];
  const saved = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'].map((k) => [k, process.env[k]] as const);
  for (const [k] of saved) delete process.env[k];
  try {
    for (const [name, answer] of shapes) {
      const raw = createTcpServer((sock) => sock.once('data', (d) => answer(sock, d.toString('latin1').startsWith('GET '))));
      await new Promise<void>((r) => raw.listen(0, '127.0.0.1', () => r()));
      try {
        const out = await Promise.race([
          new SaihmProClient(`http://127.0.0.1:${(raw.address() as AddressInfo).port}/mcp`, undefined, new Uint8Array(32).fill(8), { tier: 'FREE' })
            .status()
            .then(() => 'answered', (e: unknown) => String((e as Error).message)),
          new Promise<string>((r) => setTimeout(() => r('no answer within 10 s'), 10_000).unref()),
        ]);
        assert.ok(out.includes('SAIHM_ENDPOINT_URL') && out.includes('cannot use'), `${name}: ${out}`);
        assert.ok(!/could not (reach|be reached)/.test(out), `${name}: ${out}`);
      } finally {
        await new Promise<void>((r) => raw.close(() => r()));
      }
    }
  } finally {
    for (const [k, v] of saved) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

test('a 307 to another origin WITHOUT a body is followed, without credentials (the sign-in challenge GET)', async () => {
  const seen: { what: string; auth: string | undefined }[] = [];
  const other = createServer((req, res) => {
    seen.push({ what: `other ${req.method} ${req.url}`, auth: req.headers.authorization });
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ nonce: '56'.repeat(32) }));
  });
  await new Promise<void>((r) => other.listen(0, '127.0.0.1', () => r()));
  const otherBase = `http://127.0.0.1:${(other.address() as AddressInfo).port}`;
  const endpoint = createServer((req, res) => {
    if (req.method === 'GET' && (req.url ?? '').startsWith('/api/onboard/challenge'))
      return void res.writeHead(307, { location: `${otherBase}/api/onboard/challenge` }).end();
    res.writeHead(404, { 'content-type': 'application/json' }).end('{}');
  });
  await new Promise<void>((r) => endpoint.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(endpoint.address() as AddressInfo).port}`;
  const saved = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'].map((k) => [k, process.env[k]] as const);
  for (const [k] of saved) delete process.env[k];
  try {
    await Promise.race([
      new SaihmProClient(`${base}/mcp`, undefined, new Uint8Array(32).fill(9), { tier: 'FREE' }).status().catch(() => undefined),
      new Promise<void>((r) => setTimeout(r, 10_000).unref()),
    ]);
    const hop = seen.find((x) => x.what === 'other GET /api/onboard/challenge');
    assert.ok(hop, `the body-less redirect was followed: ${seen.map((x) => x.what)}`);
    assert.equal(hop.auth, undefined, 'without credentials');
  } finally {
    for (const [k, v] of saved) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    await new Promise<void>((r) => other.close(() => r()));
    await new Promise<void>((r) => endpoint.close(() => r()));
  }
});

test('a 307 with a body to the same host and port but another scheme is refused: the origin includes the scheme', async () => {
  const endpoint = createServer((req, res) => {
    const port = (endpoint.address() as AddressInfo).port;
    res.writeHead(307, { location: `https://127.0.0.1:${port}/mcp` }).end();
    void req;
  });
  await new Promise<void>((r) => endpoint.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(endpoint.address() as AddressInfo).port}`;
  const saved = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'].map((k) => [k, process.env[k]] as const);
  for (const [k] of saved) delete process.env[k];
  try {
    const out = await Promise.race([
      new SaihmProClient(`${base}/mcp`, 'Bearer redirect-test-credential', new Uint8Array(32).fill(5), { tier: 'PRO' })
        .status()
        .then(() => 'answered', (e: unknown) => String((e as Error).message)),
      new Promise<string>((r) => setTimeout(() => r('no answer within 10 s'), 10_000).unref()),
    ]);
    assert.ok(out.includes('REDIRECT_CROSS_ORIGIN'), out);
  } finally {
    for (const [k, v] of saved) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    await new Promise<void>((r) => endpoint.close(() => r()));
  }
});

test('a whole compressed answer is decoded, in every encoding the client asks for', async () => {
  const { gzipSync, deflateSync, brotliCompressSync } = await import('node:zlib');
  const body = Buffer.from(JSON.stringify({ result: 'ok', pad: 'y'.repeat(50_000) }));
  const enc: Record<string, Buffer> = { gzip: gzipSync(body), deflate: deflateSync(body), br: brotliCompressSync(body) };
  const endpoint = createServer((req, res) => {
    const e = (req.url ?? '').slice(1).split('/')[0] ?? '';
    res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': e, 'content-length': String(enc[e]!.length) }).end(enc[e]);
  });
  await new Promise<void>((r) => endpoint.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(endpoint.address() as AddressInfo).port}`;
  const saved = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'].map((k) => [k, process.env[k]] as const);
  for (const [k] of saved) delete process.env[k];
  try {
    for (const e of Object.keys(enc)) {
      const out = await Promise.race([
        new SaihmProClient(`${base}/${e}/mcp`, 'Bearer redirect-test-credential', new Uint8Array(32).fill(5), { tier: 'PRO' })
          .status()
          .then(() => 'answered', (err: unknown) => String((err as Error).message)),
        new Promise<string>((r) => setTimeout(() => r('no answer within 10 s'), 10_000).unref()),
      ]);
      // Whatever the status call makes of the JSON, the transport delivered the whole decoded body.
      assert.ok(!/ended before its body|could not reach|no answer within/.test(out), `${e}: ${out}`);
    }
  } finally {
    for (const [k, v] of saved) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    await new Promise<void>((r) => endpoint.close(() => r()));
  }
});

test('redirectHopHeaders keeps credentials only within the same scheme, host and port', async () => {
  const { redirectHopHeaders } = await import('../src/client.js');
  const h = { Authorization: 'Bearer x', COOKIE: 'c=1', 'content-type': 'application/json' };
  const stripped = { 'content-type': 'application/json' };
  const cases: [string, string, boolean][] = [
    ['https://saihm.example/mcp', 'http://saihm.example/landed', false],
    ['https://saihm.example/mcp', 'https://saihm.example:443/other', true],
    ['https://saihm.example/mcp', 'https://saihm.example:8443/other', false],
    ['http://127.0.0.1:1/mcp', 'http://127.0.0.1:2/mcp', false],
    ['https://a.example/mcp', 'https://b.example/mcp', false],
    ['https://saihm.example/mcp', 'https://saihm.example/v2/mcp', true],
  ];
  for (const [from, to, keeps] of cases)
    assert.deepEqual(redirectHopHeaders(new URL(from), new URL(to), h), keeps ? h : stripped, `${from} -> ${to}`);
});
