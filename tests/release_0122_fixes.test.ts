// The fixes 0.13.0 carries from the 0.12.x line: an endpoint URL that does not parse never
// prints a user name, password, query or fragment; a relative SAIHM_HOME or SAIHM_STATE_DIR is refused before anything
// lands under the working directory; a redirect to a scheme this transport does not speak is an unusable answer, not a
// network failure; a body that stalls past the limit reads as a timeout.
// Runner: npx tsx --test tests/release_0122_fixes.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, readdirSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { SaihmConfigError, SaihmProClient, ensureSelfJoinIdentityEnv } from '../src/client.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');

const KEYS = [
  'HOME', 'SAIHM_HOME', 'SAIHM_STATE_DIR', 'SAIHM_ENDPOINT_URL', 'SAIHM_AUTH_HEADER', 'SAIHM_MASTER_SECRET_FILE',
  'SAIHM_MASTER_SECRET_HEX', 'SAIHM_IDENTITY', 'SAIHM_IDENTITY_PASSPHRASE', 'SAIHM_TIER', 'SAIHM_PAYMENT_METHOD',
  'SAIHM_SELF_JOIN', 'SAIHM_ERASURE_FEED_DIR', 'SAIHM_RECALL_CACHE_PATH', 'SAIHM_EPHEMERAL_HOME', 'CI',
  'CLAUDE_CODE_REMOTE', 'GITHUB_ACTIONS',
  'JENKINS_URL', 'BUILD_ID', 'TF_BUILD', 'TEAMCITY_VERSION', 'CODEBUILD_BUILD_ARN', 'BUILDER_OUTPUT', 'bamboo_planKey',
] as const;

/** Run `fn` with exactly these SAIHM variables set (every other one in KEYS unset), restoring them after. */
function withEnv<T>(overrides: Record<string, string | undefined>, fn: () => T): T {
  const saved: Record<string, string | undefined> = {};
  for (const k of KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  for (const [k, v] of Object.entries(overrides)) if (v !== undefined) process.env[k] = v;
  try {
    return fn();
  } finally {
    for (const k of KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

/** The error `fn` throws (it must throw). */
function thrown(fn: () => unknown): Error {
  try {
    fn();
  } catch (e) {
    return e as Error;
  }
  assert.fail('expected a throw');
}

/** Run `fn` with the working directory set to `dir`. */
function inDir<T>(dir: string, fn: () => T): T {
  const before = process.cwd();
  process.chdir(dir);
  try {
    return fn();
  } finally {
    process.chdir(before);
  }
}

test('an endpoint URL that does not parse never shows a user name, a password, a query or a fragment', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-0122-url-'));
  try {
    const boot = (endpoint: string): Error =>
      withEnv({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: endpoint, SAIHM_MASTER_SECRET_HEX: 'ab'.repeat(32) }, () =>
        thrown(() => SaihmProClient.bootFromEnv()),
      );
    // The measured case (port out of range), and passwords holding the characters a guess would cut at.
    for (const [endpoint, secrets] of [
      ['https://admin:hunter2@host:99999/mcp', ['admin', 'hunter2']],
      ['https://admin:Zq7/Xk2?Wm#Vy@host:99999/mcp', ['admin', 'Zq7', 'Xk2', 'Wm', 'Vy']],
      ['https://Kq9Xv@host:99999/mcp', ['Kq9Xv']],
    ] as const) {
      const e = boot(endpoint);
      assert.ok(e instanceof SaihmConfigError, e.message);
      assert.equal(e.message, 'SAIHM_ENDPOINT_URL is not a valid URL, and it holds an @, so it may carry a user name or password and is not shown.');
      for (const s of secrets) assert.ok(!e.message.includes(s), `${endpoint}: ${s} is shown`);
    }
    // No `@`: shown, but cut before a query or a fragment, which may carry a token.
    const q = boot('https://host:99999/mcp?token=QSECRETVALUE');
    assert.equal(q.message, 'SAIHM_ENDPOINT_URL is not a valid URL: https://host:99999/mcp (its query and fragment are not shown)');
    const f = boot('https://host:99999/mcp#FSECRETVALUE');
    assert.equal(f.message, 'SAIHM_ENDPOINT_URL is not a valid URL: https://host:99999/mcp (its query and fragment are not shown)');
    // Positive control: an ordinary mistake is still shown whole.
    assert.equal(boot('saihm dot net').message, 'SAIHM_ENDPOINT_URL is not a valid URL: saihm dot net');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('boot refuses a relative or space-led SAIHM_HOME or SAIHM_STATE_DIR, naming it, before anything is written', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'saihm-0122-cwd-'));
  const abs = mkdtempSync(join(tmpdir(), 'saihm-0122-home-'));
  try {
    const boot = (env: Record<string, string>): unknown =>
      inDir(cwd, () =>
        withEnv({ SAIHM_MASTER_SECRET_HEX: 'cd'.repeat(32), SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe', ...env }, () => {
          try {
            return SaihmProClient.bootFromEnv();
          } catch (e) {
            return e;
          }
        }),
      );
    for (const [env, name] of [
      [{ SAIHM_HOME: 'saihm-state' }, 'SAIHM_HOME'],
      [{ SAIHM_HOME: '~/.saihm' }, 'SAIHM_HOME'],
      [{ SAIHM_HOME: ` ${abs}` }, 'SAIHM_HOME'],
      [{ SAIHM_HOME: abs, SAIHM_STATE_DIR: 'state' }, 'SAIHM_STATE_DIR'],
    ] as const) {
      const e = boot(env) as Error;
      assert.ok(e instanceof SaihmConfigError, `${JSON.stringify(env)}: ${String(e)}`);
      assert.equal(
        e.message,
        `${name} is not a full path, so nothing is written there: a relative path, or one that begins with a space, lands ` +
          `under the working directory. Set ${name} to the full path of a directory (JSON settings do not expand ~), then ` +
          `start a new session. Any files an earlier version wrote under this setting are in the folder it names inside the working directory of the run that wrote them (a leading ~ there is a folder named ~)` +
          (name === 'SAIHM_HOME' ? ', your key among them' : '') +
          `: move them into that directory first. This run's working directory: ${realpathSync(cwd)}`,
      );
      assert.deepEqual(readdirSync(cwd), [], `${JSON.stringify(env)}: nothing under the working directory`);
    }
    // Positive controls: a full path boots, and a blank one is unset (the default), as everywhere.
    // Every assertion here carries a message: without one, node builds it from the source, which under tsx was
    // measured holding a failing run at 100% CPU for over a minute.
    const full = boot({ SAIHM_HOME: abs, SAIHM_STATE_DIR: join(abs, 'state') });
    assert.ok(full instanceof SaihmProClient, `a full SAIHM_STATE_DIR boots: ${String(full)}`);
    const blank = boot({ SAIHM_HOME: abs, SAIHM_STATE_DIR: '   ' });
    assert.ok(blank instanceof SaihmProClient, `a blank SAIHM_STATE_DIR is unset and boots: ${String(blank)}`);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
    rmSync(abs, { recursive: true, force: true });
  }
});

test('a join never mints a key under a relative SAIHM_HOME', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'saihm-0122-mint-'));
  try {
    const e = inDir(cwd, () => withEnv({ SAIHM_HOME: 'saihm-state' }, () => thrown(() => ensureSelfJoinIdentityEnv())));
    assert.ok(e instanceof SaihmConfigError, e.message);
    assert.match(e.message, /^SAIHM_HOME is not a full path, so nothing is written there: .* then join again\. Any files an earlier version wrote under this setting are in the folder it names inside the working directory of the run that wrote them \(a leading ~ there is a folder named ~\), your key among them: move them into that directory first\. This run's working directory: .+$/);
    assert.deepEqual(readdirSync(cwd), [], 'no key, no folder, under the working directory');
    // Positive control: a full SAIHM_HOME mints there.
    const home = join(cwd, 'home');
    const ok = inDir(cwd, () => withEnv({ SAIHM_HOME: home }, () => ensureSelfJoinIdentityEnv()));
    assert.equal(ok.created, true);
    assert.deepEqual(readdirSync(home), ['free-identity.key']);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test('export-identity refuses a relative SAIHM_HOME before writing the token and passphrase anywhere', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'saihm-0122-export-'));
  try {
    const run = (home: string): Promise<{ code: number | null; stderr: string }> =>
      new Promise((res) => {
        const env: Record<string, string | undefined> = { ...process.env };
        for (const k of KEYS) delete env[k];
        Object.assign(env, {
          HOME: cwd,
          SAIHM_HOME: home,
          SAIHM_MASTER_SECRET_HEX: randomBytes(32).toString('hex'),
          SAIHM_TIER: 'PRO',
          SAIHM_PAYMENT_METHOD: 'stripe',
          SAIHM_ENDPOINT_URL: 'http://127.0.0.1:9/mcp',
        });
        const p = spawn(TSX, [SERVER, 'export-identity'], { env, cwd, stdio: ['ignore', 'pipe', 'pipe'] });
        let stderr = '';
        p.stderr!.on('data', (d) => (stderr += d));
        const t = setTimeout(() => p.kill(), 60_000);
        p.on('close', (code) => {
          clearTimeout(t);
          res({ code, stderr });
        });
      });
    const r = await run('saihm-state');
    assert.equal(r.code, 1);
    assert.equal(
      r.stderr,
      'saihm: not exported - SAIHM_HOME is not a full path, so nothing is written there: a relative path, or one that ' +
        'begins with a space, lands under the working directory. Set SAIHM_HOME to the full path of a directory (JSON ' +
        'settings do not expand ~), then export again. Any files an earlier version wrote under this setting are in the ' +
        `folder it names inside the working directory of the run that wrote them (a leading ~ there is a folder named ~), your key among them: move them into that directory first. This run's working directory: ${realpathSync(cwd)}\n`,
    );
    assert.deepEqual(readdirSync(cwd), [], 'nothing under the working directory');
    // Positive control: under a full SAIHM_HOME the same export is written there.
    const home = join(cwd, 'home');
    const good = await run(home);
    assert.equal(good.code, 0, good.stderr);
    assert.deepEqual(readdirSync(join(home, 'exports')).length, 1);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

/** A local endpoint answering every request with `handle`. */
async function endpoint(handle: Parameters<typeof createServer>[1]): Promise<{ server: Server; base: string }> {
  const server = createServer(handle);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  return { server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

test('a redirect to a scheme this transport does not speak is an answer it cannot use, not a network failure', async () => {
  const { server, base } = await endpoint((req, res) => {
    const to = (req.url ?? '').slice(1);
    res.writeHead(302, { location: decodeURIComponent(to) }).end();
  });
  const saved = ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'].map((k) => [k, process.env[k]] as const);
  for (const [k] of saved) delete process.env[k];
  try {
    for (const target of ['ftp://127.0.0.1/x', 'data:text/plain,hello', 'file:///etc/hostname']) {
      const c = new SaihmProClient(`${base}/${encodeURIComponent(target)}`, 'Bearer t', new Uint8Array(32).fill(6), { tier: 'PRO' });
      const e = await c.status().then(() => null, (err: Error) => err);
      assert.ok(e, `${target}: no error`);
      assert.match(e.message, /REDIRECT_SCHEME_UNSUPPORTED/, `${target}: ${e.message}`);
      assert.ok(e.message.includes('SAIHM_ENDPOINT_URL') && !/could not (reach|be reached)/.test(e.message), `${target}: ${e.message}`);
    }
  } finally {
    for (const [k, v] of saved) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test('a body that stalls past the time limit reads as a timeout, on a call and on the sign-in', async () => {
  const sockets = new Set<import('node:net').Socket>();
  const { server, base } = await endpoint((_req, res) => {
    // The head and part of the body, then nothing: the answer arrives, and stalls.
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write('{"nonce":');
  });
  server.on('connection', (s) => sockets.add(s));
  try {
    const call = new SaihmProClient(`${base}/mcp`, 'Bearer t', new Uint8Array(32).fill(7), { tier: 'PRO', requestTimeoutMs: 400 });
    const e1 = await call.status().then(() => null, (err: Error) => err);
    assert.ok(e1, 'the stalled call settled without an error');
    assert.equal(e1.message, 'SAIHM endpoint saihm_status timed out after 400ms');
    // Self-onboard: the challenge GET stalls the same way.
    const signIn = new SaihmProClient(`${base}/mcp`, undefined, new Uint8Array(32).fill(8), { tier: 'FREE', requestTimeoutMs: 400 });
    const e2 = await signIn.status().then(() => null, (err: Error) => err);
    assert.ok(e2, 'the stalled sign-in settled without an error');
    assert.match(e2.message, /timed out after 400ms/);
    assert.doesNotMatch(e2.message, /could not (reach|be reached)/);
  } finally {
    for (const s of sockets) s.destroy();
    await new Promise<void>((r) => server.close(() => r()));
  }
});
