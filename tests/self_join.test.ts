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

test('selfJoinEnabled reflects SAIHM_SELF_JOIN=1 exactly', () => {
  withEnv({ SAIHM_SELF_JOIN: '1' }, () => assert.equal(selfJoinEnabled(), true));
  withEnv({ SAIHM_SELF_JOIN: '0' }, () => assert.equal(selfJoinEnabled(), false));
  withEnv({}, () => assert.equal(selfJoinEnabled(), false));
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

test('bootFromEnv: flag OFF + no secret => generic env error (behaviour unchanged)', () => {
  withEnv({ SAIHM_ENDPOINT_URL: 'https://x.test/mcp' }, () => {
    assert.throws(() => SaihmProClient.bootFromEnv(), /SAIHM_MASTER_SECRET_HEX .*required/);
  });
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
