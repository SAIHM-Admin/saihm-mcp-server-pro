// Deterministic unit coverage for the DARK self-join client helpers (src/client.ts):
// selfJoinEnabled / defaultIdentityPath / ensureSelfJoinIdentityEnv + the bootFromEnv fallback.
// No network. Proves: the key self-generates + persists mode 600 (never returned), is idempotent,
// yields to a configured env secret, and that bootFromEnv (a) throws the friendly join hint when the
// flag is on with no identity, (b) is UNCHANGED (generic throw) when the flag is off, and (c) loads
// the persisted default-file identity on a bare restart.
// Runner: npx tsx --test tests/self_join.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, existsSync, statSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  SaihmProClient,
  selfJoinEnabled,
  defaultIdentityPath,
  ensureSelfJoinIdentityEnv,
  DEFAULT_ENDPOINT,
} from '../src/client.js';

const KEYS = [
  'SAIHM_SELF_JOIN',
  'SAIHM_HOME',
  'SAIHM_MASTER_SECRET_FILE',
  'SAIHM_MASTER_SECRET_HEX',
  'SAIHM_TIER',
  'SAIHM_ENDPOINT_URL',
] as const;

/** Run fn with a clean, isolated slice of the relevant env, restored afterwards. */
function withEnv(overrides: Record<string, string | undefined>, fn: () => void): void {
  const saved: Record<string, string | undefined> = {};
  for (const k of KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    fn();
  } finally {
    for (const k of KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

test('selfJoinEnabled defaults ON; only SAIHM_SELF_JOIN=0 opts out', () => {
  withEnv({ SAIHM_SELF_JOIN: '1' }, () => assert.equal(selfJoinEnabled(), true));
  withEnv({ SAIHM_SELF_JOIN: '0' }, () => assert.equal(selfJoinEnabled(), false));
  withEnv({}, () => assert.equal(selfJoinEnabled(), true));
  // Anything other than the exact opt-out string leaves self-join enabled.
  withEnv({ SAIHM_SELF_JOIN: '' }, () => assert.equal(selfJoinEnabled(), true));
  withEnv({ SAIHM_SELF_JOIN: 'false' }, () => assert.equal(selfJoinEnabled(), true));
});

test('defaultIdentityPath honours SAIHM_HOME, else ~/.saihm', () => {
  withEnv({ SAIHM_HOME: '/tmp/xyz-home' }, () =>
    assert.equal(defaultIdentityPath(), join('/tmp/xyz-home', 'free-identity.key')),
  );
  withEnv({}, () =>
    assert.equal(defaultIdentityPath(), join(homedir(), '.saihm', 'free-identity.key')),
  );
});

test('ensureSelfJoinIdentityEnv self-generates a 32-byte key mode 600, sets env, is idempotent', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-uj-'));
  try {
    withEnv({ SAIHM_HOME: home }, () => {
      const r1 = ensureSelfJoinIdentityEnv();
      assert.equal(r1.created, true);
      assert.equal(r1.keyPath, join(home, 'free-identity.key'));
      const hex = readFileSync(r1.keyPath, 'utf-8').trim();
      assert.equal(hex.length, 64, '32 bytes hex');
      assert.match(hex, /^[0-9a-f]{64}$/);
      if (process.platform !== 'win32')
        assert.equal(statSync(r1.keyPath).mode & 0o777, 0o600);
      // env set so the very next bootFromEnv self-onboards FREE
      assert.equal(process.env.SAIHM_MASTER_SECRET_FILE, r1.keyPath);
      assert.equal(process.env.SAIHM_TIER, 'FREE');
      // idempotent: second call does not regenerate; same key
      const before = process.env.SAIHM_MASTER_SECRET_FILE;
      delete process.env.SAIHM_MASTER_SECRET_FILE; // force the file-existence branch
      const r2 = ensureSelfJoinIdentityEnv();
      assert.equal(r2.created, false);
      assert.equal(readFileSync(r2.keyPath, 'utf-8').trim(), hex, 'key unchanged');
      assert.equal(process.env.SAIHM_MASTER_SECRET_FILE, before);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('ensureSelfJoinIdentityEnv yields to a configured env secret (no file written)', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-uj2-'));
  try {
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: 'ab'.repeat(32) }, () => {
      const r = ensureSelfJoinIdentityEnv();
      assert.equal(r.created, false);
      assert.equal(r.keyPath, '(SAIHM_MASTER_SECRET_HEX)');
      assert.ok(!existsSync(join(home, 'free-identity.key')), 'must not write a key file');
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('bootFromEnv: opted out + no secret => generic env error (pre-0.2 behaviour)', () => {
  withEnv({ SAIHM_ENDPOINT_URL: 'https://x.test/mcp', SAIHM_SELF_JOIN: '0' }, () => {
    assert.throws(() => SaihmProClient.bootFromEnv(), /SAIHM_MASTER_SECRET_HEX .*required/);
  });
});

test('bootFromEnv: DEFAULT (flag unset) + no identity => friendly "Join SAIHM" hint', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-uj0-'));
  try {
    withEnv({ SAIHM_ENDPOINT_URL: 'https://x.test/mcp', SAIHM_HOME: home }, () => {
      assert.throws(() => SaihmProClient.bootFromEnv(), /Join SAIHM.*saihm_join/);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('bootFromEnv: flag ON + no identity => friendly "Join SAIHM" hint', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-uj3-'));
  try {
    withEnv({ SAIHM_ENDPOINT_URL: 'https://x.test/mcp', SAIHM_SELF_JOIN: '1', SAIHM_HOME: home }, () => {
      assert.throws(() => SaihmProClient.bootFromEnv(), /Join SAIHM.*saihm_join/);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// ── SAIHM_ENDPOINT_URL defaulting ────────────────────────────────────────────
// Regression cover for the 0.2.0 first-run dead end: every test above pins
// SAIHM_ENDPOINT_URL, so the suite was green while a bare `npx -y
// @saihm/mcp-server-pro` (no env at all) failed with 'SAIHM_ENDPOINT_URL env var
// required' on the very first saihm_recall — never naming saihm_join, the free
// path the package advertises. These three pin the genuinely-unset state.

test('bootFromEnv: endpoint UNSET + no identity => join hint, NOT an endpoint error', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-ep0-'));
  try {
    withEnv({ SAIHM_HOME: home }, () => {
      assert.equal(process.env.SAIHM_ENDPOINT_URL, undefined, 'precondition: genuinely unset');
      assert.throws(() => SaihmProClient.bootFromEnv(), /Join SAIHM.*saihm_join/);
      assert.throws(() => SaihmProClient.bootFromEnv(), (e: unknown) => {
        assert.ok(e instanceof Error);
        assert.ok(
          !/SAIHM_ENDPOINT_URL env var required/.test(e.message),
          'must not resurrect the bare endpoint dead end',
        );
        return true;
      });
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('bootFromEnv: endpoint UNSET + valid secret => boots against the declared default', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-ep1-'));
  try {
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: 'ab'.repeat(32) }, () => {
      const c = SaihmProClient.bootFromEnv();
      assert.equal(
        (c as unknown as { endpoint: string }).endpoint,
        DEFAULT_ENDPOINT,
        'unset endpoint must resolve to the hosted operator server.json declares',
      );
      assert.equal(DEFAULT_ENDPOINT, 'https://saihm.coti.global/mcp');
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('bootFromEnv: a bad endpoint is reported even when no identity exists', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-ep4-'));
  try {
    // Both of these previously surfaced the join hint, masking the real fault:
    // boot threw on the missing identity before any client was constructed, and
    // assertEndpointUrl only ran in the constructor.
    withEnv({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: '   ' }, () => {
      assert.throws(() => SaihmProClient.bootFromEnv(), /is not a valid URL/);
    });
    withEnv({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: 'http://evil.example/mcp' }, () => {
      assert.throws(() => SaihmProClient.bootFromEnv(), /must use https:\/\//);
    });
    // Loopback http stays legal for local development.
    withEnv({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: 'http://127.0.0.1:3001/mcp' }, () => {
      assert.throws(() => SaihmProClient.bootFromEnv(), /Join SAIHM.*saihm_join/);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('setup hint: opted OUT must never name saihm_join (that tool is not registered)', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-ep3-'));
  try {
    // SAIHM_SELF_JOIN=0 => the server registers eight tools and NO saihm_join.
    // A hint naming it would send the agent after a tool that does not exist.
    withEnv({ SAIHM_HOME: home, SAIHM_SELF_JOIN: '0' }, () => {
      assert.throws(() => SaihmProClient.bootFromEnv(), (e: unknown) => {
        assert.ok(e instanceof Error);
        assert.match(e.message, /SAIHM_MASTER_SECRET_HEX .*required/);
        assert.ok(!/saihm_join/.test(e.message), 'must not name an unregistered tool');
        assert.match(e.message, /SAIHM_MASTER_SECRET_FILE or SAIHM_MASTER_SECRET_HEX/);
        return true;
      });
    });
    // Opted IN (default): the same class of error DOES name the join tool.
    withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: 'zz'.repeat(32) }, () => {
      assert.throws(() => SaihmProClient.bootFromEnv(), /lowercase hex\..*saihm_join/);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('bootFromEnv: endpoint set but EMPTY => configuration error (not silently defaulted)', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-ep2-'));
  try {
    withEnv({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: '', SAIHM_MASTER_SECRET_HEX: 'ab'.repeat(32) }, () => {
      assert.throws(() => SaihmProClient.bootFromEnv(), /SAIHM_ENDPOINT_URL is set but empty/);
      assert.throws(() => SaihmProClient.bootFromEnv(), /saihm_join/);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('bootFromEnv: flag ON + persisted default-file identity => boots FREE (restart-safe)', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-uj4-'));
  try {
    withEnv({ SAIHM_HOME: home }, () => {
      // A prior join persisted the identity here.
      ensureSelfJoinIdentityEnv();
      const keyPath = join(home, 'free-identity.key');
      assert.ok(existsSync(keyPath));
    });
    // Fresh boot with ONLY the flag + endpoint (no env secret): must load the default file.
    withEnv({ SAIHM_ENDPOINT_URL: 'https://x.test/mcp', SAIHM_SELF_JOIN: '1', SAIHM_HOME: home }, () => {
      const c = SaihmProClient.bootFromEnv();
      assert.equal(c.tier, 'FREE', 'self-join boot defaults tier FREE');
      assert.match(c.agentIdHash, /^[0-9a-f]{64}$/);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// The README promises `npx -y @saihm/mcp-server-pro free-join` is a COMPLETE join on a bare
// machine — no env, no card, no master secret to invent. That promise is a composition of three
// separate defaults (identity, tier, endpoint), each already covered alone above; nothing pinned
// them TOGETHER, which is the only form the user actually meets. runFreeJoin does exactly this
// pair of calls, so this fails if any one of the three stops carrying the zero-config case.
test('free-join composition: zero env is a complete join (identity + FREE tier + default endpoint)', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-uj5-'));
  try {
    // SAIHM_HOME only, to keep the generated key out of the real ~/.saihm. Every other variable
    // the CLI could read is unset by withEnv — no endpoint, no secret, no tier.
    withEnv({ SAIHM_HOME: home }, () => {
      assert.equal(selfJoinEnabled(), true, 'self-join is ON by default; the CLI relies on it');
      const identity = selfJoinEnabled() ? ensureSelfJoinIdentityEnv() : undefined;
      assert.equal(identity?.created, true, 'a bare machine has no key yet, so one is minted');
      assert.equal(identity?.keyPath, join(home, 'free-identity.key'));

      // Previously this threw `SAIHM_ENDPOINT_URL env var required`; DEFAULT_ENDPOINT is what
      // makes the command zero-config, so a boot that does NOT throw IS the endpoint assertion.
      const c = SaihmProClient.bootFromEnv();
      assert.equal(c.tier, 'FREE', 'the paid tiers must never be what an unconfigured join lands on');
      assert.match(c.agentIdHash, /^[0-9a-f]{64}$/);
      assert.match(DEFAULT_ENDPOINT, /^https:\/\//, 'the fallback operator is https, never cleartext');
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// Non-vacuity for the test above: it must not pass merely because bootFromEnv is lenient. Under
// the documented opt-out the CLI generates NOTHING and boot fails, which is the point of the flag.
test('free-join composition: SAIHM_SELF_JOIN=0 mints no key and refuses to boot', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-uj6-'));
  try {
    withEnv({ SAIHM_HOME: home, SAIHM_SELF_JOIN: '0' }, () => {
      const identity = selfJoinEnabled() ? ensureSelfJoinIdentityEnv() : undefined;
      assert.equal(identity, undefined, 'the opt-out must not silently mint an identity');
      assert.ok(!existsSync(join(home, 'free-identity.key')), 'no key file may appear');
      assert.throws(() => SaihmProClient.bootFromEnv());
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// The composition test above MIRRORS runFreeJoin rather than invoking it — runFreeJoin runs a
// device flow against a live bridge, so it cannot be called here. That leaves a real hole: drop
// `ensureSelfJoinIdentityEnv()` from the CLI and the mirror still passes while the shipped command
// regresses to demanding env. So re-derive the guarantee from the SOURCE, the same way the render
// fence re-derives its call-site list. server.ts is read as text, not imported, because `main()`
// sits at module scope and importing it would start a server.
test('free-join composition: the shipped CLI actually performs it (re-derived from source)', () => {
  const src = readFileSync(new URL('../src/server.ts', import.meta.url), 'utf-8')
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/\/\/[^\n]*/g, (m) => ' '.repeat(m.length));

  const start = src.indexOf('async function runFreeJoin(');
  assert.notEqual(start, -1, 'runFreeJoin must exist; renaming it silently voids this sweep');
  const end = src.indexOf('\n}', start);
  assert.notEqual(end, -1, 'could not find the end of runFreeJoin');
  const body = src.slice(start, end);

  // Comments are stripped above ON PURPOSE: runFreeJoin's own doc block names both symbols, so an
  // unstripped match would pass on prose alone while the code did nothing.
  assert.match(body, /ensureSelfJoinIdentityEnv\(\)/, 'zero-config join requires the CLI to mint an identity');
  assert.match(body, /selfJoinEnabled\(\)/, 'SAIHM_SELF_JOIN=0 must still suppress self-join in the CLI');
  assert.match(body, /bootFromEnv\(\)/);
  assert.ok(
    body.indexOf('ensureSelfJoinIdentityEnv()') < body.indexOf('bootFromEnv()'),
    'the identity must be ensured BEFORE boot, or boot throws on the bare machine this promises to serve',
  );
});
