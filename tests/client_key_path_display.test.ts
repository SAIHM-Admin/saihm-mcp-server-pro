// Key-file paths in messages (src/client.ts displayableKeyPath and the sites that name a key file). A path whose parts
// have the shape of a key, passphrase or token is withheld wherever a message would show it, by ONE test: the union of
// the test that withholds a value and the stricter one that refuses a folder, so no folder a refusal blocks is ever
// printed. A refusal names the folder actually in use: SAIHM_HOME when it is set, otherwise ~/.saihm.
// Runner: npx tsx --test tests/client_key_path_display.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import {
  displayableKeyPath,
  ensureSelfJoinIdentityEnv,
  keyShapedHomeRefusal,
  resolveIdentityFromEnv,
  SaihmConfigError,
} from '../src/client.js';
import { generatePassphrase, pathHoldsIdentitySecret } from '../src/identity-token.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const KEY = 'free-identity.key';
/** Passphrase symbols in a grouping this package never prints: refused as a folder, and before 0.12.1 still shown. */
const REGROUPED = 'K7M2Q9-XRTBH4-WZD1NPVC';
/** An ID-style user name: twenty capitals and digits, which reads as a dash-less passphrase. */
const ID_USER = 'JOHNSMITH2024ABCDEFG';

const KEYS = [
  'HOME', 'SAIHM_SELF_JOIN', 'SAIHM_HOME', 'SAIHM_MASTER_SECRET_FILE', 'SAIHM_MASTER_SECRET_HEX', 'SAIHM_TIER',
  'SAIHM_PAYMENT_METHOD', 'SAIHM_IDENTITY', 'SAIHM_IDENTITY_PASSPHRASE', 'SAIHM_EPHEMERAL_HOME', 'CLAUDE_CODE_REMOTE',
  'GITHUB_ACTIONS', 'CI', 'SAIHM_ENDPOINT_URL', 'SAIHM_STATE_DIR',
] as const;

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

function message(fn: () => unknown): { e: unknown; m: string } {
  try {
    fn();
  } catch (e) {
    return { e, m: (e as Error).message };
  }
  assert.fail('expected a throw');
}

/** stderr written while fn runs. */
function stderrOf(fn: () => unknown): string {
  const write = process.stderr.write;
  let out = '';
  process.stderr.write = ((chunk: string | Uint8Array) => {
    out += String(chunk);
    return true;
  }) as typeof process.stderr.write;
  try {
    try {
      fn();
    } catch {
      /* only the stream is under test */
    }
  } finally {
    process.stderr.write = write;
  }
  return out;
}

/** A fresh base folder holding a key-shaped folder; the base is what each message must never contain below it. */
function keyShapedHome(tag: string, part = REGROUPED): { base: string; home: string } {
  const base = mkdtempSync(join(tmpdir(), `saihm-kpd-${tag}-`));
  const home = join(base, part);
  mkdirSync(home, { recursive: true, mode: 0o700 });
  return { base, home };
}

const hex = (): string => randomBytes(32).toString('hex');
const withheld = (m: string, part: string) => {
  assert.ok(!m.includes(part), `the key-shaped part is printed: ${m}`);
};

test('every path a refusal blocks is withheld from display, and an ordinary path is shown', () => {
  const forms = (p: string): string[] => {
    const caps = p.toUpperCase();
    const bare = caps.replace(/-/g, '');
    return [caps, bare, `${bare.slice(0, 6)}-${bare.slice(6, 12)}-${bare.slice(12)}`, p];
  };
  let refused = 0;
  for (let i = 0; i < 200; i++) {
    for (const part of forms(generatePassphrase())) {
      for (const p of [`/home/${part}/.saihm/${KEY}`, `C:\\Users\\${part}\\saihm`, `/srv/x/${part}`]) {
        if (!pathHoldsIdentitySecret(p)) continue;
        refused++;
        assert.equal(displayableKeyPath(p), null, p);
      }
    }
  }
  assert.ok(refused >= 200 * 3 * 2, `refused samples: ${refused}`);
  for (const p of [`/tmp/x/${REGROUPED}/${KEY}`, `/home/${ID_USER}/.saihm/${KEY}`, `C:\\Users\\${ID_USER}\\saihm`, `/tmp/${'ab'.repeat(32)}/${KEY}`]) {
    assert.ok(pathHoldsIdentitySecret(p), p);
    assert.equal(displayableKeyPath(p), null, p);
  }
  for (const p of [`/home/alice/.saihm/${KEY}`, 'C:\\Users\\Alice\\saihm\\key', '/var/lib/saihm/state']) assert.equal(displayableKeyPath(p), p);
});

test('a key file under a key-shaped SAIHM_HOME is named by its folder at every read error, never by its path', () => {
  const { base, home } = keyShapedHome('read');
  try {
    // The join's exists-branch: a key path that cannot be read (a folder in its place), then one that holds nothing.
    mkdirSync(join(home, KEY));
    let r = message(() => withEnv({ SAIHM_HOME: home }, () => ensureSelfJoinIdentityEnv()));
    assert.ok(r.e instanceof SaihmConfigError, r.m);
    withheld(r.m, REGROUPED);
    assert.match(r.m, /^the self-join identity file could not be read: free-identity\.key under SAIHM_HOME \(EISDIR; its path has the shape of a key, so it is not shown\)\. Fix its permissions/);
    // Boot's self-join read: the same file, the same withholding.
    r = message(() => withEnv({ SAIHM_HOME: home }, () => resolveIdentityFromEnv()));
    withheld(r.m, REGROUPED);
    assert.match(r.m, /could not be read: free-identity\.key under SAIHM_HOME \(its path has the shape of a key, so it is not shown\)\. /);
    rmSync(join(home, KEY), { recursive: true });

    writeFileSync(join(home, KEY), '', { mode: 0o600 });
    r = message(() => withEnv({ SAIHM_HOME: home }, () => ensureSelfJoinIdentityEnv()));
    withheld(r.m, REGROUPED);
    assert.match(r.m, /^the self-join identity file holds no secret: free-identity\.key under SAIHM_HOME \(its path has the shape of a key, so it is not shown\)\. Restore/);
    r = message(() => withEnv({ SAIHM_HOME: home }, () => resolveIdentityFromEnv()));
    withheld(r.m, REGROUPED);
    assert.match(r.m, /holds no secret: free-identity\.key under SAIHM_HOME \(its path has the shape of a key, so it is not shown\)\. Restore/);

    // Content that is not a key: named by its folder.
    writeFileSync(join(home, KEY), 'not hex', { mode: 0o600 });
    r = message(() => withEnv({ SAIHM_HOME: home }, () => resolveIdentityFromEnv()));
    withheld(r.m, REGROUPED);
    assert.equal(r.m, 'the self-join identity file under SAIHM_HOME must hold canonical lowercase hex.');

    // SAIHM_MASTER_SECRET_FILE naming a file in such a folder: empty, then not a key.
    const named = join(home, 'k');
    writeFileSync(named, '', { mode: 0o600 });
    r = message(() => withEnv({ SAIHM_HOME: join(base, 'plain'), SAIHM_MASTER_SECRET_FILE: named }, () => resolveIdentityFromEnv()));
    withheld(r.m, REGROUPED);
    assert.match(r.m, /^SAIHM_MASTER_SECRET_FILE is set but holds no secret: the file it names \(its path has the shape of a key, so it is not shown\)\. /);
    writeFileSync(named, 'zz', { mode: 0o600 });
    r = message(() => withEnv({ SAIHM_HOME: join(base, 'plain'), SAIHM_MASTER_SECRET_FILE: named }, () => resolveIdentityFromEnv()));
    withheld(r.m, REGROUPED);
    assert.equal(r.m, 'the file SAIHM_MASTER_SECRET_FILE names must hold canonical lowercase hex.');

    // A setting that is itself shaped like a key, and names no readable file: refused without echoing it, and told
    // what to do either way, since a real path under such a folder lands here too.
    r = message(() => withEnv({ SAIHM_HOME: join(base, 'plain'), SAIHM_MASTER_SECRET_FILE: join(home, 'missing') }, () => resolveIdentityFromEnv()));
    withheld(r.m, REGROUPED);
    assert.equal(r.m, 'SAIHM_MASTER_SECRET_FILE could not be read, and what it holds looks like a key, passphrase or token, so it is not shown. If it is a key, put the path of your key file there instead; if it is a path, check that the file exists and that you can read it.');

    // Positive controls: an ordinary folder keeps every path in the same messages.
    const plain = join(base, 'plain');
    mkdirSync(join(plain, KEY), { recursive: true });
    r = message(() => withEnv({ SAIHM_HOME: plain }, () => ensureSelfJoinIdentityEnv()));
    assert.ok(r.m.includes(`could not be read: ${join(plain, KEY)} (EISDIR). Fix`), r.m);
    rmSync(join(plain, KEY), { recursive: true });
    writeFileSync(join(plain, KEY), 'not hex', { mode: 0o600 });
    r = message(() => withEnv({ SAIHM_HOME: plain }, () => resolveIdentityFromEnv()));
    assert.equal(r.m, `the self-join identity file ${join(plain, KEY)} must hold canonical lowercase hex.`);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('the group/world-readable key warning withholds a key-shaped path and is written once per file', { skip: process.platform === 'win32' && 'POSIX modes' }, () => {
  const { base, home } = keyShapedHome('perm');
  try {
    const shaped = join(home, 'k');
    writeFileSync(shaped, hex(), { mode: 0o600 });
    chmodSync(shaped, 0o644);
    const env = { SAIHM_HOME: join(base, 'plain'), SAIHM_MASTER_SECRET_FILE: shaped, SAIHM_TIER: 'PRO' };
    const first = stderrOf(() => withEnv(env, () => resolveIdentityFromEnv()));
    assert.equal(first, 'warning: the key file SAIHM_MASTER_SECRET_FILE names is group/world-accessible; chmod 600 it (its path has the shape of a key, so it is not shown).\n');
    assert.equal(stderrOf(() => withEnv(env, () => resolveIdentityFromEnv())), '', 'once per file per process');
    // Positive control: an ordinary path is named, also once; a second file is warned about in its own right.
    for (const name of ['a', 'b']) {
      const plainKey = join(base, `plain-${name}`);
      writeFileSync(plainKey, hex(), { mode: 0o644 });
      chmodSync(plainKey, 0o644);
      const penv = { ...env, SAIHM_MASTER_SECRET_FILE: plainKey };
      assert.equal(stderrOf(() => withEnv(penv, () => resolveIdentityFromEnv())), `warning: SAIHM_MASTER_SECRET_FILE ${plainKey} is group/world-accessible; chmod 600 it.\n`);
      assert.equal(stderrOf(() => withEnv(penv, () => resolveIdentityFromEnv())), '');
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('a refusal names SAIHM_HOME only when it is set; a key-shaped home folder is told to set it', () => {
  const { base, home } = keyShapedHome('home', ID_USER);
  try {
    const unset = message(() => withEnv({ HOME: home }, () => ensureSelfJoinIdentityEnv()));
    assert.ok(unset.e instanceof SaihmConfigError, unset.m);
    assert.equal(unset.m, withEnv({ HOME: home }, () => keyShapedHomeRefusal('join')));
    assert.match(unset.m, /^The path of your home folder, where ~\/\.saihm is, holds what looks like a key, passphrase or token, so no key is created there\. Set SAIHM_HOME to the full path of a directory whose path does not, then join again\.$/);
    withheld(unset.m, ID_USER);
    const set = message(() => withEnv({ HOME: join(base, 'x'), SAIHM_HOME: join(base, REGROUPED) }, () => ensureSelfJoinIdentityEnv()));
    assert.equal(set.m, 'SAIHM_HOME holds what looks like a key, passphrase or token rather than a directory, so no key is created there. Fix SAIHM_HOME, then join again.');
    // A key given inline, or a token, has no key file to name.
    assert.equal(withEnv({ SAIHM_IDENTITY: 'x' }, () => keyShapedHomeRefusal('export')), 'The path of your home folder, where ~/.saihm is, holds what looks like a key, passphrase or token. Set SAIHM_HOME to the full path of a directory whose path does not, then export again.');
    assert.equal(withEnv({ SAIHM_MASTER_SECRET_HEX: 'ab'.repeat(32) }, () => keyShapedHomeRefusal('export')), 'The path of your home folder, where ~/.saihm is, holds what looks like a key, passphrase or token. Set SAIHM_HOME to the full path of a directory whose path does not, then export again.');
    assert.equal(withEnv({ SAIHM_HOME: join(base, REGROUPED) }, () => keyShapedHomeRefusal('export')), 'SAIHM_HOME holds what looks like a key, passphrase or token rather than a directory. Fix SAIHM_HOME, set SAIHM_MASTER_SECRET_FILE to the full path of your key file, then export again.');
    assert.equal(withEnv({}, () => keyShapedHomeRefusal('export')), 'The path of your home folder, where ~/.saihm is, holds what looks like a key, passphrase or token. Set SAIHM_HOME to the full path of a directory whose path does not, and SAIHM_MASTER_SECRET_FILE to the full path of your key file, then export again.');
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('a key that cannot be created under ~/.saihm names ~/.saihm, not SAIHM_HOME', { skip: process.getuid?.() === 0 && 'root ignores directory modes' }, () => {
  const base = mkdtempSync(join(tmpdir(), 'saihm-kpd-ro-'));
  try {
    // A home folder in five-letter words: joinable, but withheld wherever a path is shown.
    const homeDir = join(base, 'saihm-agent-state-store');
    mkdirSync(homeDir, { mode: 0o500 });
    const r = message(() => withEnv({ HOME: homeDir }, () => ensureSelfJoinIdentityEnv()));
    assert.equal(r.m, 'the key could not be created under ~/.saihm (EACCES); its path has the shape of a key, so it is not shown.');
  } finally {
    chmodSync(join(base, 'saihm-agent-state-store'), 0o700);
    rmSync(base, { recursive: true, force: true });
  }
});

// ---- the verbs and the tool, as an operator meets them ----

function childEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const keep: NodeJS.ProcessEnv = {};
  for (const k of ['PATH', 'SYSTEMROOT', 'TEMP', 'TMP', 'TMPDIR']) if (process.env[k] !== undefined) keep[k] = process.env[k];
  return { ...keep, ...extra };
}

function runCli(args: string[], extra: Record<string, string>): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((res) => {
    const p = spawn(TSX, [SERVER, ...args], { env: childEnv(extra), stdio: ['ignore', 'pipe', 'pipe'], cwd: resolve(HERE, '..') });
    let stdout = '';
    let stderr = '';
    p.stdout!.on('data', (d) => (stdout += d));
    p.stderr!.on('data', (d) => (stderr += d));
    const t = setTimeout(() => p.kill(), 60000);
    p.on('close', (code) => {
      clearTimeout(t);
      res({ code, stdout, stderr });
    });
  });
}

async function joinText(extra: Record<string, string>): Promise<string> {
  const proc: ChildProcess = spawn(TSX, [SERVER], { env: childEnv(extra), stdio: ['pipe', 'pipe', 'pipe'], cwd: resolve(HERE, '..') });
  let buf = '';
  const waiters = new Map<number, (m: any) => void>();
  proc.stdout!.on('data', (d) => {
    buf += d;
    let nl: number;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      try {
        const m = JSON.parse(line);
        waiters.get(m.id)?.(m);
      } catch {
        /* not a protocol line */
      }
    }
  });
  const rpc = (id: number, method: string, params: unknown): Promise<any> =>
    new Promise((res, rej) => {
      waiters.set(id, res);
      proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      setTimeout(() => rej(new Error(`rpc timeout ${method}`)), 20000);
    });
  try {
    await rpc(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } });
    proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
    const r = await rpc(2, 'tools/call', { name: 'saihm_join', arguments: { newIdentity: true } });
    return String(r.result.content[0].text);
  } finally {
    proc.kill();
  }
}

test('join, free-join and export-identity under a key-shaped home folder tell the operator to set SAIHM_HOME', async () => {
  const { base, home } = keyShapedHome('verbs', ID_USER);
  try {
    const env = { HOME: home, SAIHM_ENDPOINT_URL: 'http://127.0.0.1:9/mcp' };
    const refusal = withEnv({}, () => keyShapedHomeRefusal('join'));
    assert.equal(await joinText(env), refusal);
    const fj = await runCli(['free-join'], env);
    assert.equal(fj.code, 1);
    assert.ok(fj.stderr.includes('saihm: not joined - ' + refusal), fj.stderr);
    // An identity to export, so the verb reaches the folder check (with none it says there is nothing to export).
    const ex = await runCli(['export-identity'], { ...env, SAIHM_MASTER_SECRET_HEX: hex(), SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' });
    assert.equal(ex.code, 1);
    assert.equal(ex.stderr, 'saihm: not exported - ' + withEnv({ SAIHM_MASTER_SECRET_HEX: 'ab'.repeat(32) }, () => keyShapedHomeRefusal('export')) + '\n');
    for (const out of [fj.stdout, fj.stderr, ex.stdout, ex.stderr]) withheld(out, ID_USER);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('export-identity under a home folder whose path is withheld names ~/.saihm, not SAIHM_HOME', async () => {
  // A home folder in five-letter words: export runs there, but the path is withheld wherever it would be shown.
  const base = mkdtempSync(join(tmpdir(), 'saihm-kpd-exp-'));
  const home = join(base, 'saihm-agent-state-store');
  try {
    mkdirSync(join(home, '.saihm'), { recursive: true, mode: 0o700 });
    const env = { HOME: home, SAIHM_MASTER_SECRET_HEX: hex(), SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' };
    const ok = await runCli(['export-identity'], env);
    assert.equal(ok.code, 0, ok.stderr);
    assert.match(ok.stdout, /in the exports folder under ~\/\.saihm, whose path has the shape of a key, so it is not shown/);
    withheld(ok.stdout + ok.stderr, 'saihm-agent-state-store');
    if (process.platform !== 'win32') {
      chmodSync(join(home, '.saihm', 'exports'), 0o755);
      const loose = await runCli(['export-identity'], env);
      assert.equal(loose.code, 1);
      assert.match(loose.stderr, /the export directory is not private to you: the exports folder under ~\/\.saihm\. /);
      withheld(loose.stdout + loose.stderr, 'saihm-agent-state-store');
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('an empty or blank SAIHM_HOME counts as unset: the key lives in ~/.saihm, never in the working directory', async () => {
  const { defaultIdentityPath, identityHomeName } = await import('../src/client.js');
  const { base, home } = keyShapedHome('blank', ID_USER);
  try {
    for (const blank of ['', '   ', '\t']) {
      const env = { HOME: home, SAIHM_HOME: blank };
      assert.equal(withEnv(env, () => defaultIdentityPath()), join(home, '.saihm', KEY), JSON.stringify(blank));
      assert.equal(withEnv(env, () => identityHomeName()), '~/.saihm', JSON.stringify(blank));
      assert.match(withEnv(env, () => keyShapedHomeRefusal('join')), /^The path of your home folder/, JSON.stringify(blank));
      const r = message(() => withEnv(env, () => ensureSelfJoinIdentityEnv()));
      assert.equal(r.m, withEnv(env, () => keyShapedHomeRefusal('join')));
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('a failed free-join names a key file in a key-shaped folder by its setting, never by its path', async () => {
  const { base, home } = keyShapedHome('fj');
  const { createServer } = await import('node:http');
  const server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      if (req.url === '/api/onboard/challenge') return void res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ nonce: '55'.repeat(32) }));
      res.writeHead(500, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'start_failed' }));
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  try {
    const keyFile = join(home, 'k');
    writeFileSync(keyFile, hex(), { mode: 0o600 });
    const port = (server.address() as import('node:net').AddressInfo).port;
    const fj = await runCli(['free-join'], { HOME: join(base, 'plain'), SAIHM_HOME: join(base, 'plain'), SAIHM_MASTER_SECRET_FILE: keyFile, SAIHM_ENDPOINT_URL: `http://127.0.0.1:${port}/mcp` });
    assert.equal(fj.code, 1, fj.stdout + fj.stderr);
    assert.ok(fj.stderr.includes('  SAIHM_MASTER_SECRET_FILE has the shape of a key, or names a folder that does, so it is not shown.\n'), fj.stderr);
    withheld(fj.stdout + fj.stderr, REGROUPED);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    rmSync(base, { recursive: true, force: true });
  }
});
