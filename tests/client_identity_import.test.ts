// In-process coverage of how an identity is RESOLVED once a token can be configured
// (src/client.ts resolveIdentityFromEnv / identityKeyFile / ephemeralHomeSignal): the exclusions,
// the precedence of explicit values over what a token carries, blank-means-absent, the label check,
// and the cases where a configured-but-broken identity must be named rather than replaced. Every
// case here is one a reviewer showed could be broken without any other test noticing.
// Runner: npx tsx --test tests/client_identity_import.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { deriveIdentity, toHex, fromHex } from '@saihm/client-pro';
import {
  resolveIdentityFromEnv,
  identityKeyFile,
  identityTokenConfigured,
  ephemeralHomeSignal,
  displayableKeyPath,
  displayablePlan,
  SaihmConfigError,
  SaihmProClient,
} from '../src/client.js';
import { generatePassphrase, sealIdentityToken, IdentityTokenError } from '../src/identity-token.js';

const KEYS = [
  'SAIHM_SELF_JOIN', 'SAIHM_HOME', 'SAIHM_MASTER_SECRET_FILE', 'SAIHM_MASTER_SECRET_HEX', 'SAIHM_TIER',
  'SAIHM_PAYMENT_METHOD', 'SAIHM_IDENTITY', 'SAIHM_IDENTITY_PASSPHRASE', 'SAIHM_EPHEMERAL_HOME',
  'CLAUDE_CODE_REMOTE', 'GITHUB_ACTIONS', 'CI', 'SAIHM_ENDPOINT_URL',
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

const idOf = (secretHex: string): string => toHex(deriveIdentity(fromHex(secretHex)).agentIdHash);
function tokenFor(secretHex: string, hints: { tier?: string; paymentMethod?: string } = {}, label = idOf(secretHex)) {
  const passphrase = generatePassphrase();
  return { token: sealIdentityToken({ secretHex, ...hints }, label, passphrase), passphrase };
}
function message(fn: () => unknown): { e: unknown; m: string } {
  try {
    fn();
  } catch (e) {
    return { e, m: (e as Error).message };
  }
  assert.fail('expected a throw');
}
const resolvedId = (overrides: Record<string, string | undefined>): string =>
  withEnv(overrides, () => {
    const r = resolveIdentityFromEnv();
    try {
      return toHex(deriveIdentity(r.master).agentIdHash);
    } finally {
      r.master.fill(0);
    }
  });

test('a token beside either secret variable is an error naming both - never a pick', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-imp-a-'));
  try {
    const t = tokenFor(randomBytes(32).toString('hex'));
    const file = join(home, 'k.hex');
    writeFileSync(file, randomBytes(32).toString('hex'), { mode: 0o600 });
    for (const [extra, name] of [
      [{ SAIHM_MASTER_SECRET_FILE: file }, 'SAIHM_MASTER_SECRET_FILE'],
      [{ SAIHM_MASTER_SECRET_HEX: randomBytes(32).toString('hex') }, 'SAIHM_MASTER_SECRET_HEX'],
    ] as const) {
      const { m } = message(() =>
        withEnv({ SAIHM_HOME: home, SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase, ...extra }, () =>
          resolveIdentityFromEnv(),
        ),
      );
      assert.match(m, new RegExp(`Two identities are configured: SAIHM_IDENTITY and ${name}`));
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a passphrase alone is named as itself - beside a secret, and beside a default key it must not replace', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-imp-b-'));
  try {
    writeFileSync(join(home, 'free-identity.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
    for (const extra of [{}, { SAIHM_MASTER_SECRET_HEX: randomBytes(32).toString('hex') }]) {
      const { e, m } = message(() =>
        withEnv({ SAIHM_HOME: home, SAIHM_IDENTITY_PASSPHRASE: generatePassphrase(), ...extra }, () => resolveIdentityFromEnv()),
      );
      assert.ok(e instanceof IdentityTokenError);
      assert.match(m, /SAIHM_IDENTITY_PASSPHRASE is set but SAIHM_IDENTITY is not/);
      assert.doesNotMatch(m, /Two identities/);
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('an unexpanded reference beside a secret is named as a reference, not as a second identity', () => {
  const { m } = message(() =>
    withEnv({ SAIHM_IDENTITY: '${SAIHM_IDENTITY}', SAIHM_MASTER_SECRET_HEX: randomBytes(32).toString('hex') }, () =>
      resolveIdentityFromEnv(),
    ),
  );
  assert.match(m, /SAIHM_IDENTITY holds an unexpanded reference/);
});

test('blank token variables mean absent: the configured secret boots as if they were not there', () => {
  const secret = randomBytes(32).toString('hex');
  for (const blank of ['', '   '])
    assert.equal(
      resolvedId({ SAIHM_IDENTITY: blank, SAIHM_IDENTITY_PASSPHRASE: blank, SAIHM_MASTER_SECRET_HEX: secret }),
      idOf(secret),
    );
});

test('explicit SAIHM_TIER / SAIHM_PAYMENT_METHOD override what the token carries; provenance is reported', () => {
  const secret = randomBytes(32).toString('hex');
  const t = tokenFor(secret, { tier: 'PRO', paymentMethod: 'stripe' });
  const base = { SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase };
  withEnv(base, () => {
    const r = resolveIdentityFromEnv();
    r.master.fill(0);
    assert.deepEqual([r.tier, r.paymentMethod, r.tierFrom], ['PRO', 'stripe', 'SAIHM_IDENTITY']);
  });
  withEnv({ ...base, SAIHM_TIER: 'ENTERPRISE', SAIHM_PAYMENT_METHOD: 'stablecoin' }, () => {
    const r = resolveIdentityFromEnv();
    r.master.fill(0);
    assert.deepEqual([r.tier, r.paymentMethod, r.tierFrom], ['ENTERPRISE', 'stablecoin', 'SAIHM_TIER']);
  });
  withEnv({ SAIHM_MASTER_SECRET_HEX: secret }, () => {
    const r = resolveIdentityFromEnv();
    r.master.fill(0);
    assert.deepEqual([r.tier, r.tierFrom], ['FREE', 'default']);
  });
});

test('a token labelled for another identity is refused before anything is booted under it', () => {
  const secret = randomBytes(32).toString('hex');
  const t = tokenFor(secret, {}, randomBytes(32).toString('hex'));
  const { e, m } = message(() =>
    withEnv({ SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase }, () => resolveIdentityFromEnv()),
  );
  assert.ok(e instanceof IdentityTokenError);
  assert.match(m, /labelled for a different identity/);
});

test('a token identity has no key file and no recall-cache default, even beside a default key', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-imp-c-'));
  try {
    writeFileSync(join(home, 'free-identity.key'), randomBytes(32).toString('hex'), { mode: 0o600 });
    const secret = randomBytes(32).toString('hex');
    const t = tokenFor(secret);
    withEnv({ SAIHM_HOME: home, SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase }, () => {
      assert.equal(identityKeyFile(), null);
      const r = resolveIdentityFromEnv();
      try {
        assert.equal(r.defaultKey, false);
        assert.equal(toHex(deriveIdentity(r.master).agentIdHash), idOf(secret), 'and the token wins over the default key');
      } finally {
        r.master.fill(0);
      }
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('an EMPTY default key file is named as holding no secret, never as absent', () => {
  for (const content of ['', '  \n']) {
    const home = mkdtempSync(join(tmpdir(), 'saihm-imp-d-'));
    try {
      writeFileSync(join(home, 'free-identity.key'), content, { mode: 0o600 });
      const { e, m } = message(() => withEnv({ SAIHM_HOME: home }, () => resolveIdentityFromEnv()));
      assert.ok(e instanceof SaihmConfigError);
      assert.match(m, /holds no secret/);
      assert.doesNotMatch(m, /not there|Join SAIHM/);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }
});

test('a key, passphrase or token pasted into SAIHM_MASTER_SECRET_FILE is never echoed back', () => {
  const t = tokenFor(randomBytes(32).toString('hex'));
  for (const pasted of [randomBytes(32).toString('hex'), generatePassphrase(), t.token]) {
    const { m } = message(() => withEnv({ SAIHM_MASTER_SECRET_FILE: pasted }, () => resolveIdentityFromEnv()));
    assert.ok(!m.includes(pasted), 'the pasted value must not appear');
    assert.match(m, /looks like a key, passphrase or token/);
  }
  // ...nor inside a pasted line: the shapes a key arrives in when it is pasted into the wrong field.
  const hexKey = randomBytes(32).toString('hex');
  const pass = generatePassphrase();
  for (const pasted of [
    `SAIHM_MASTER_SECRET_FILE=${hexKey}`,
    `export SAIHM_MASTER_SECRET_HEX=${hexKey}`,
    `"${hexKey}"`,
    `0x${hexKey}`,
    `${hexKey}.`,
    `SAIHM_IDENTITY_PASSPHRASE=${pass}`,
    `key ${pass.replace(/-/g, '')} here`,
    `x ${t.token} y`,
  ]) {
    const { m } = message(() => withEnv({ SAIHM_MASTER_SECRET_FILE: pasted }, () => resolveIdentityFromEnv()));
    assert.ok(!m.includes(hexKey) && !m.includes(pass) && !m.includes(pass.replace(/-/g, '')), `echoed: ${pasted.slice(0, 12)}`);
    assert.match(m, /looks like a key, passphrase or token/);
  }
  // A real path is still named, so it can be fixed - including one with a long alphanumeric segment.
  for (const path of ['/nonexistent/dir/key.hex', `/nonexistent/${'h'.repeat(40)}/key.hex`]) {
    const { m } = message(() => withEnv({ SAIHM_MASTER_SECRET_FILE: path }, () => resolveIdentityFromEnv()));
    assert.ok(m.includes(`could not be read: ${path}`), m);
  }
});

test('temporary-home signals: blanks and explicit noes do not count; any other declaration does', () => {
  const cases: [Record<string, string>, string | null][] = [
    [{}, null],
    [{ CLAUDE_CODE_REMOTE: '' }, null],
    [{ CLAUDE_CODE_REMOTE: 'false' }, null],
    [{ CLAUDE_CODE_REMOTE: 'true' }, 'CLAUDE_CODE_REMOTE'],
    [{ CLAUDE_CODE_REMOTE: 'TRUE' }, 'CLAUDE_CODE_REMOTE'],
    [{ GITHUB_ACTIONS: 'True' }, 'GITHUB_ACTIONS'],
    [{ GITHUB_ACTIONS: 'true' }, 'GITHUB_ACTIONS'],
    [{ CI: '' }, null],
    [{ CI: 'false' }, null],
    [{ CI: '0' }, null],
    [{ CI: '1' }, 'CI'],
    [{ SAIHM_EPHEMERAL_HOME: '1' }, 'SAIHM_EPHEMERAL_HOME'],
    [{ SAIHM_EPHEMERAL_HOME: 'true' }, 'SAIHM_EPHEMERAL_HOME'],
    [{ SAIHM_EPHEMERAL_HOME: 'YES' }, 'SAIHM_EPHEMERAL_HOME'],
    [{ SAIHM_EPHEMERAL_HOME: ' 1' }, 'SAIHM_EPHEMERAL_HOME'],
    [{ SAIHM_EPHEMERAL_HOME: '' }, null],
    [{ SAIHM_EPHEMERAL_HOME: '0', CI: 'true', CLAUDE_CODE_REMOTE: 'true' }, null],
    [{ SAIHM_EPHEMERAL_HOME: 'off', GITHUB_ACTIONS: 'true' }, null],
    [{ SAIHM_EPHEMERAL_HOME: 'False', CI: '1' }, null],
  ];
  for (const [env, want] of cases) assert.equal(withEnv(env, () => ephemeralHomeSignal()), want, JSON.stringify(env));
});

test('with self-join off, the no-identity message still says where the values go and where they never go', () => {
  const { m } = message(() => withEnv({ SAIHM_SELF_JOIN: '0' }, () => resolveIdentityFromEnv()));
  assert.match(m, /in this environment's settings - never in the chat or a repository file/);
  assert.match(m, /SAIHM_MASTER_SECRET_FILE or SAIHM_MASTER_SECRET_HEX/);
  assert.ok(m.length <= 256, `fits the plain-message budget (${m.length})`);
});

test('the no-identity message warns against the chat and says a hosted session must start again', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-imp-e-'));
  try {
    mkdirSync(home, { recursive: true });
    const { m } = message(() => withEnv({ SAIHM_HOME: home }, () => resolveIdentityFromEnv()));
    assert.match(m, /never in this chat/);
    assert.match(m, /start a new session/);
    assert.match(m, /Never ask for either value in the chat/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('blank TIER, payment method or key file beside a token are absent - the shape a ${VAR:-} config produces', () => {
  const secret = randomBytes(32).toString('hex');
  const t = tokenFor(secret, { tier: 'PRO', paymentMethod: 'stripe' });
  withEnv(
    { SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase, SAIHM_TIER: '', SAIHM_PAYMENT_METHOD: '', SAIHM_MASTER_SECRET_FILE: '' },
    () => {
      const r = resolveIdentityFromEnv();
      try {
        assert.deepEqual([r.tier, r.paymentMethod], ['PRO', 'stripe']);
        assert.equal(toHex(deriveIdentity(r.master).agentIdHash), idOf(secret), 'and no "Two identities" for a blank key file');
      } finally {
        r.master.fill(0);
      }
    },
  );
});

test('an env-file empty token ("") is as absent as unset; a passphrase alone still names the key file', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-imp-f-'));
  try {
    for (const blank of ['""', "''", 'SAIHM_IDENTITY='])
      assert.equal(withEnv({ SAIHM_HOME: home, SAIHM_IDENTITY: blank }, () => identityTokenConfigured()), false, blank);
    const file = join(home, 'k.hex');
    writeFileSync(file, randomBytes(32).toString('hex'), { mode: 0o600 });
    assert.equal(
      withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_FILE: file, SAIHM_IDENTITY_PASSPHRASE: generatePassphrase() }, () => identityKeyFile()),
      file,
      'a passphrase without its token is not a token: the key file stays named',
    );
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('host flags that say no are not temporary-home signals', () => {
  assert.equal(withEnv({ CI: 'False' }, () => ephemeralHomeSignal()), null);
  assert.equal(withEnv({ GITHUB_ACTIONS: 'false' }, () => ephemeralHomeSignal()), null);
});

test('a key, passphrase or token in a path setting is never shown: split, cut short or pasted as a line', () => {
  const home = mkdtempSync(join(tmpdir(), 'saihm-imp-sh-'));
  try {
    const h = randomBytes(32).toString('hex');
    const p = generatePassphrase();
    const shapes = [
      `${h.slice(0, 32)} ${h.slice(32)}`,
      `${h.slice(0, 32)}\n${h.slice(32)}`,
      h.slice(0, 63),
      h.slice(0, 48),
      `export SAIHM_IDENTITY_PASSPHRASE=${p}`,
      p.replace(/-/g, ' '),
      `export SAIHM_IDENTITY_PASSPHRASE=${p.replace(/-/g, ' ')}`,
    ];
    for (const v of shapes) {
      assert.equal(displayableKeyPath(v), null, JSON.stringify(v));
      const { m } = message(() => withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_FILE: v }, () => SaihmProClient.bootFromEnv()));
      for (const part of [h.slice(0, 32), h.slice(32), p, p.replace(/-/g, '')]) assert.ok(!m.includes(part), m);
    }
    // Positive control: real paths, including one holding a 40-hex commit id, are still shown.
    for (const v of ['keys/my.key', join(home, 'free-identity.key'), `/srv/${h.slice(0, 40)}/k.key`])
      assert.equal(displayableKeyPath(v), v);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a passphrase that is only quotes is blank: the inline secret boots', () => {
  const hex = randomBytes(32).toString('hex');
  for (const blank of ['""', "''", ' "" '])
    assert.equal(resolvedId({ SAIHM_MASTER_SECRET_HEX: hex, SAIHM_IDENTITY_PASSPHRASE: blank }), idOf(hex));
});

test('an empty SAIHM_ENDPOINT_URL beside an identity says how to fix the URL, and nothing about joining', () => {
  const t = tokenFor(randomBytes(32).toString('hex'));
  const { m } = message(() =>
    withEnv({ SAIHM_ENDPOINT_URL: '', SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase }, () =>
      SaihmProClient.bootFromEnv(),
    ),
  );
  assert.match(m, /^SAIHM_ENDPOINT_URL is set but empty: set it to an endpoint URL, or leave it out for the default\.$/);
});

test('a tier is shown only when it is a plan this package knows', () => {
  for (const t of ['FREE', 'PRO', 'PRO_FAST', 'ENTERPRISE', 'ENTERPRISE_FAST']) assert.equal(displayablePlan(t), t);
  for (const t of ['pro', 'PAYG', randomBytes(16).toString('hex'), generatePassphrase(), ''])
    assert.equal(displayablePlan(t), null, t);
});

test('SAIHM_EPHEMERAL_HOME: each explicit no declares the home kept, even where the host is flagged as hosted', () => {
  for (const no of ['0', 'false', 'no', 'off']) assert.equal(withEnv({ CI: 'true', SAIHM_EPHEMERAL_HOME: no }, () => ephemeralHomeSignal()), null, no);
  assert.notEqual(withEnv({ CI: 'true' }, () => ephemeralHomeSignal()), null, 'positive control: CI alone is a temporary home');
});

test('a SAIHM_HOME or SAIHM_STATE_DIR with the shape of a secret stops boot: named, never shown, nothing created in the working directory', async () => {
  const { readdirSync } = await import('node:fs');
  // A relative home is created in the working directory - in a hosted agent, a repository checkout an agent
  // may commit - by the server's own writers, after boot (security R6 F1). So boot refuses it first.
  const cwd = mkdtempSync(join(tmpdir(), 'saihm-imp-cwd-'));
  const before = process.cwd();
  const savedStateDir = process.env.SAIHM_STATE_DIR;
  try {
    process.chdir(cwd);
    const t = tokenFor(randomBytes(32).toString('hex'));
    const p = generatePassphrase();
    for (const name of ['SAIHM_HOME', 'SAIHM_STATE_DIR'] as const)
      for (const v of [p, `SAIHM_IDENTITY_PASSPHRASE: ${p}`]) {
        if (name === 'SAIHM_STATE_DIR') process.env.SAIHM_STATE_DIR = v;
        else delete process.env.SAIHM_STATE_DIR;
        // Beside SAIHM_STATE_DIR, an ordinary relative home: no boot here - nor under a regression of this
        // refusal - reaches the runner's own ~/.saihm.
        const home = { SAIHM_HOME: name === 'SAIHM_HOME' ? v : 'saihm-state' };
        const { e, m } = message(() =>
          withEnv({ SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase, ...home }, () => SaihmProClient.bootFromEnv()),
        );
        assert.ok(e instanceof SaihmConfigError, m);
        assert.equal(
          m,
          `${name} holds what looks like a key, passphrase or token rather than a directory, so nothing is written there. Fix ${name}, then start a new session.`,
        );
        assert.ok(!m.includes(p) && !m.includes(p.replace(/-/g, '')), m);
        assert.deepEqual(readdirSync(cwd), [], `${name}: nothing is created in the working directory`);
      }
    // Positive control: an ordinary relative SAIHM_HOME boots.
    delete process.env.SAIHM_STATE_DIR;
    const c = withEnv({ SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase, SAIHM_HOME: 'saihm-state' }, () =>
      SaihmProClient.bootFromEnv(),
    );
    assert.ok(c instanceof SaihmProClient);
    // So do folders the display test withholds but the refusal must not stop: four five-letter words, and a
    // timestamp or run id (correctness R7 F1, F3).
    for (const [h, sd] of [['saihm-agent-state-store', undefined], ['saihm-state', '20261002103045123456'], ['run-20261002103045123456', undefined]] as const) {
      if (sd === undefined) delete process.env.SAIHM_STATE_DIR;
      else process.env.SAIHM_STATE_DIR = sd;
      const b = withEnv({ SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase, SAIHM_HOME: h }, () => SaihmProClient.bootFromEnv());
      assert.ok(b instanceof SaihmProClient, `${h} / ${sd ?? '-'}`);
    }
    delete process.env.SAIHM_STATE_DIR;
  } finally {
    process.chdir(before);
    if (savedStateDir === undefined) delete process.env.SAIHM_STATE_DIR;
    else process.env.SAIHM_STATE_DIR = savedStateDir;
    rmSync(cwd, { recursive: true, force: true });
  }
});

test('a key or passphrase in SAIHM_TIER or SAIHM_PAYMENT_METHOD stops boot: the variable is named, the value is never sent or shown', () => {
  // The fields beside the secret ones in an install form. A token boot with its own passphrase pasted into
  // SAIHM_TIER sent it to the endpoint as the tier (security R6 B3).
  const home = mkdtempSync(join(tmpdir(), 'saihm-imp-tp-'));
  try {
    const hex = randomBytes(32).toString('hex');
    const t = tokenFor(randomBytes(32).toString('hex'));
    const identities = [
      { SAIHM_MASTER_SECRET_HEX: hex },
      { SAIHM_IDENTITY: t.token, SAIHM_IDENTITY_PASSPHRASE: t.passphrase },
    ];
    for (const id of identities)
      for (const name of ['SAIHM_TIER', 'SAIHM_PAYMENT_METHOD'] as const)
        // Lower case and dash-less too: the boot check is the display test, not the narrower path refusal (R7 B9).
        for (const v of [t.passphrase, t.passphrase.toLowerCase().replace(/-/g, ''), randomBytes(32).toString('hex')]) {
          const { e, m } = message(() =>
            withEnv({ SAIHM_HOME: home, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe', ...id, [name]: v }, () =>
              SaihmProClient.bootFromEnv(),
            ),
          );
          assert.ok(e instanceof SaihmConfigError, m);
          assert.equal(m, `${name} holds what looks like a key, passphrase or token, so it is not sent. Fix ${name}, then start a new session.`);
          assert.ok(!m.includes(v) && !m.includes(v.replace(/-/g, '')), m);
        }
    // Positive control: a plan and a payment method boot.
    const c = withEnv({ SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: hex, SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' }, () =>
      SaihmProClient.bootFromEnv(),
    );
    assert.ok(c instanceof SaihmProClient);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a key that cannot be created under a SAIHM_HOME withheld from display is reported by its code, never its path', { skip: process.getuid?.() === 0 && 'root ignores directory modes' }, async () => {
  const { chmodSync } = await import('node:fs');
  const { ensureSelfJoinIdentityEnv } = await import('../src/client.js');
  // A folder named in five-letter words is joinable, but withheld wherever a path is shown. Node names the path
  // in its own error, so a failed create relayed it (security R6 F2, docs R6 L3).
  const base = mkdtempSync(join(tmpdir(), 'saihm-imp-ro-'));
  try {
    chmodSync(base, 0o500);
    const { e, m } = message(() => withEnv({ SAIHM_HOME: join(base, 'saihm-agent-state-store') }, () => ensureSelfJoinIdentityEnv()));
    assert.ok(e instanceof SaihmConfigError, m);
    assert.equal(m, 'the key could not be created under SAIHM_HOME (EACCES); its path has the shape of a key, so it is not shown.');
    // Positive control: an ordinary folder under the same read-only parent keeps Node's own error, path and all.
    const ctl = message(() => withEnv({ SAIHM_HOME: join(base, 'state') }, () => ensureSelfJoinIdentityEnv()));
    assert.equal((ctl.e as { code?: unknown }).code, 'EACCES', ctl.m);
    assert.ok(ctl.m.includes(join(base, 'state')), ctl.m);
  } finally {
    chmodSync(base, 0o700);
    rmSync(base, { recursive: true, force: true });
  }
});
