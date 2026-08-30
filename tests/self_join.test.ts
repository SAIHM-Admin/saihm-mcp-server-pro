// Deterministic unit coverage for the DARK self-join client helpers (src/client.ts):
// selfJoinEnabled / defaultIdentityPath / ensureSelfJoinIdentityEnv + the bootFromEnv fallback.
// No network. Proves: the key self-generates + persists mode 600 (never returned), is idempotent,
// yields to a configured env secret, and that bootFromEnv (a) throws the friendly join hint when the
// flag is on with no identity, (b) is UNCHANGED (generic throw) when the flag is off, and (c) loads
// the persisted default-file identity on a bare restart.
// Runner: npx tsx --test tests/self_join.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  existsSync,
  statSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  SaihmProClient,
  selfJoinEnabled,
  defaultIdentityPath,
  ensureSelfJoinIdentityEnv,
  identityKeyFile,
  DEFAULT_ENDPOINT,
  SaihmConfigError,
} from '../src/client.js';
import { failText, MAX_ERROR_MESSAGE_CHARS } from '../src/render_fence.js';
import ts from 'typescript';

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

test('a CONFIGURED but empty secret file is an error, not a silent fall-through to another identity', () => {
  // REPRODUCED before it was fixed. `bootFromEnv` guarded the self-join fallback with `!secretHex`,
  // which conflates "no secret was configured" with "the configured secret is empty". A ZERO-BYTE
  // SAIHM_MASTER_SECRET_FILE therefore fell through to the default identity: the process booted a
  // DIFFERENT key while `identityKeyFile()` - and every backup line built on it - named the file the
  // operator had configured. The operator backs up an empty file and the only key to their memory is
  // never named, which is this release's defect class with the stakes at their highest.
  //
  // The endpoint check twenty lines above already draws the distinction this one missed: "explicitly
  // empty is still a configuration error, not an opt-in to the default".
  const home = mkdtempSync(join(tmpdir(), 'saihm-empty-'));
  try {
    const configured = join(home, 'configured.key');
    writeFileSync(configured, '');
    withEnv(
      {
        SAIHM_HOME: home,
        SAIHM_MASTER_SECRET_FILE: configured,
        SAIHM_MASTER_SECRET_HEX: undefined,
        SAIHM_SELF_JOIN: undefined,
        SAIHM_ENDPOINT_URL: DEFAULT_ENDPOINT,
      },
      () => {
        // A real self-join identity exists and is the thing that used to get booted silently.
        writeFileSync(defaultIdentityPath(), randomBytes(32).toString('hex'));
        assert.equal(identityKeyFile(), configured, 'the configured file is still the one named');
        assert.throws(
          () => SaihmProClient.bootFromEnv(),
          (e: unknown) =>
            e instanceof SaihmConfigError && (e as Error).message.includes(configured),
          'an empty configured secret must be reported as a configuration error naming the FILE, ' +
            'never resolved by booting a different identity the caller was never told about',
        );
      },
    );
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
      // NULL, not a path-shaped sentinel. The old value was the string `(SAIHM_MASTER_SECRET_HEX)`
      // and every render site treated it as a file: `Back up (SAIHM_MASTER_SECRET_HEX)`, `key file:
      // (SAIHM_MASTER_SECRET_HEX)`, and a doubled-parenthesis `key ((SAIHM_MASTER_SECRET_HEX))`. It
      // also kept the inline-secret branch at each of those sites permanently dead, a sentinel being
      // truthy. There is no file here, and that is what the caller must be told.
      assert.equal(r.keyPath, null, 'an inline secret has NO key file, and must not name one');
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
    // The endpoint the operator SET is carried as data, not spliced into the sentence. Interpolated,
    // it shared MAX_ERROR_MESSAGE_CHARS with a 39-character prefix, so a URL over ~217 characters was
    // reported back to them already cut -- naming a value they cannot match against what they typed.
    // Pinned on the THROW here; the render of that value has its own coverage in the fence suite.
    const longBad = 'not-a-url-' + 'q'.repeat(500);
    withEnv({ SAIHM_HOME: home, SAIHM_ENDPOINT_URL: longBad }, () => {
      assert.throws(
        () => SaihmProClient.bootFromEnv(),
        (e: unknown) =>
          e instanceof SaihmConfigError &&
          e.valueKind === 'url' &&
          e.message.includes(longBad),
        'the endpoint must be typed as url-bearing so the render fence widens for it',
      );
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
  // FROM THE PARSER, not from stripped text. The previous cut blanked comments and then matched
  // source, which closed the COMMENT spelling and left the STRING spelling open: replacing the call
  // with `void 'ensureSelfJoinIdentityEnv() is now done lazily'` left the entire suite green while
  // `free-join` on a bare machine threw the join hint instead of joining. Measured. Its own comment
  // said an unstripped match "would pass on prose alone while the code did nothing" - which is
  // exactly what it then did, one quote character over. A CALL is not a spelling.
  const sf = ts.createSourceFile(
    'server.ts',
    readFileSync(new URL('../src/server.ts', import.meta.url), 'utf-8'),
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TS,
  );
  const nodes: ts.Node[] = [];
  const walk = (n: ts.Node): void => {
    nodes.push(n);
    n.forEachChild((c) => {
      walk(c);
    });
  };
  const fn = (() => {
    walk(sf);
    return nodes.find(
      (n): n is ts.FunctionDeclaration =>
        ts.isFunctionDeclaration(n) && n.name?.text === 'runFreeJoin',
    );
  })();
  assert.ok(fn, 'runFreeJoin must exist; renaming it silently voids this sweep');
  const calls: { name: string; pos: number }[] = [];
  const collect = (n: ts.Node): void => {
    if (ts.isCallExpression(n)) {
      const e = n.expression;
      const name = ts.isIdentifier(e)
        ? e.text
        : ts.isPropertyAccessExpression(e)
          ? e.name.text
          : '';
      if (name) calls.push({ name, pos: n.getStart(sf) });
    }
    n.forEachChild((c) => {
      collect(c);
    });
  };
  collect(fn);
  const called = (name: string): number =>
    calls.filter((c) => c.name === name).length;
  assert.ok(called('ensureSelfJoinIdentityEnv') > 0, 'zero-config join requires the CLI to mint an identity');
  // ...and on WHAT CONDITION, which the line above cannot see. It asks only that a call EXISTS
  // somewhere in the body, and the shipped call is already conditional
  // (`if (selfJoinEnabled()) ensureSelfJoinIdentityEnv();`), so any EXTRA conjunct narrows when the
  // identity is minted while this sweep stays green. Measured: adding `&& process.env.X === '1'`
  // left the whole suite passing while the shipped CLI stopped self-joining on a bare machine and
  // told the caller to join first - the exact regression the preamble above says it is closing, and
  // it closed only the deletion half.
  const guardsReaching = (target: string): string[] => {
    const found: string[] = [];
    const visit = (n: ts.Node, guards: string[]): void => {
      if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === target)
        found.push(guards.join(' && ') || '<unconditional>');
      if (ts.isIfStatement(n)) {
        visit(n.expression, guards);
        visit(n.thenStatement, [...guards, n.expression.getText(sf)]);
        if (n.elseStatement) visit(n.elseStatement, [...guards, `!(${n.expression.getText(sf)})`]);
        return;
      }
      if (ts.isConditionalExpression(n)) {
        visit(n.condition, guards);
        visit(n.whenTrue, [...guards, n.condition.getText(sf)]);
        visit(n.whenFalse, [...guards, `!(${n.condition.getText(sf)})`]);
        return;
      }
      if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
        visit(n.left, guards);
        visit(n.right, [...guards, n.left.getText(sf)]);
        return;
      }
      // A NESTED FUNCTION is not a call - it is a call SITE that runs whenever someone invokes it.
      // Hoisting the mint into `const mintIdentity = () => { if (selfJoinEnabled()) ... }` and
      // invoking it AFTER `bootFromEnv` leaves both the guard TEXT and the TEXTUAL order untouched,
      // so this sweep and the `firstOf` check below were both green while `free-join` regressed on a
      // bare machine: boot ran first and threw the "Join SAIHM" hint, with no way for the caller to
      // comply. Recorded as a guard so it shows up in the comparison rather than silently passing;
      // the mint must be a direct statement of this function, where the order below is meaningful.
      if (
        n !== fn &&
        (ts.isFunctionDeclaration(n) ||
          ts.isArrowFunction(n) ||
          ts.isFunctionExpression(n) ||
          ts.isMethodDeclaration(n))
      ) {
        n.forEachChild((c) => {
          visit(c, [...guards, '<nested function: statement order does not decide run order>']);
        });
        return;
      }
      n.forEachChild((c) => {
        visit(c, guards);
      });
    };
    visit(fn as ts.Node, []);
    return found;
  };
  assert.deepEqual(
    guardsReaching('ensureSelfJoinIdentityEnv'),
    ['selfJoinEnabled()'],
    'the CLI mints its identity under a condition other than `selfJoinEnabled()` alone. A caller ' +
      'on a bare machine - no secret, no endpoint, self-join left at its default - must reach the ' +
      'mint, or `free-join` tells them to join first and there is no way to comply',
  );
  assert.ok(called('selfJoinEnabled') > 0, 'SAIHM_SELF_JOIN=0 must still suppress self-join in the CLI');
  assert.ok(called('bootFromEnv') > 0, 'the CLI must boot a client');
  const firstOf = (name: string): number =>
    Math.min(...calls.filter((c) => c.name === name).map((c) => c.pos));
  assert.ok(
    firstOf('ensureSelfJoinIdentityEnv') < firstOf('bootFromEnv'),
    'the identity must be ensured BEFORE boot, or boot throws on the bare machine this promises to serve',
  );
});

test('an unreadable SELF-JOIN IDENTITY names its path in full, not cut to fit the sentence', () => {
  // The third conversion site, and the one my own mutation sweep never covered: reverting it left
  // the entire suite green. Its sibling sites both go red, which is exactly why the gap was silent.
  // Reachable because `existsSync` passes on a DIRECTORY and `readFileSync` then throws EISDIR.
  const root = mkdtempSync(join(tmpdir(), 'saihm-sjid-'));
  // One segment is deliberately NON-ASCII. This test pinned the BUDGET while every fixture in the
  // suite stayed ASCII, so flipping this site's `valueKind` from 'path' to 'url' - which swaps
  // safePathField for safeField - left the WHOLE suite green, restoring the release's headline
  // defect in one token. safeField collapses non-ASCII to '?', so the FENCE is now pinned too.
  const seg = 'h'.repeat(40);
  const home = join(root, seg, seg, 'h\u00e9-\u65e5\u672c-' + 'h'.repeat(28), seg, seg, seg);
  mkdirSync(home, { recursive: true });
  const keyPath = join(home, 'free-identity.key');
  mkdirSync(keyPath); // exists, but reading it throws
  try {
    assert.ok(
      keyPath.length > MAX_ERROR_MESSAGE_CHARS,
      'fixture must exceed the budget the path used to share with the sentence',
    );
    withEnv(
      {
        SAIHM_HOME: home,
        SAIHM_MASTER_SECRET_FILE: undefined,
        SAIHM_MASTER_SECRET_HEX: undefined,
        SAIHM_ENDPOINT_URL: 'https://x.test/mcp',
      },
      () => {
        let caught: unknown;
        try {
          SaihmProClient.bootFromEnv();
        } catch (e) {
          caught = e;
        }
        assert.ok(caught instanceof SaihmConfigError, 'must be typed as carrying a path');
        // Anchored on the clause AFTER the path: cut to fit, the path takes the setup hint with it.
        const m = /identity file could not be read: (.+?)\. To start free/.exec(
          failText(caught),
        );
        assert.ok(m, `path and trailing clause must both survive. got: ${failText(caught)}`);
        assert.equal(m![1], keyPath, 'and the path is whole');
      },
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a FILESYSTEM failure carries the path NODE embedded through the fence whole', () => {
  // The fourth instance of the class, and the one the sweep missed entirely: Node writes its own
  // message and embeds the path in it. Those reach failText's catch-all arm, which is narrow by
  // design, so the operator was told permission was denied on a directory they could not read.
  // A regular FILE standing where a directory must be makes mkdir fail unprivileged and
  // deterministically -- no chmod, no umask assumption.
  const root = mkdtempSync(join(tmpdir(), 'saihm-f3-'));
  const blocker = join(root, 'blocker');
  writeFileSync(blocker, 'not a directory');
  const home = join(blocker, ...Array<string>(6).fill('d'.repeat(40)));
  try {
    assert.ok(home.length > MAX_ERROR_MESSAGE_CHARS, 'fixture must exceed the narrow budget');
    withEnv(
      {
        SAIHM_HOME: home,
        SAIHM_MASTER_SECRET_FILE: undefined,
        SAIHM_MASTER_SECRET_HEX: undefined,
      },
      () => {
        let caught: unknown;
        try {
          ensureSelfJoinIdentityEnv();
        } catch (e) {
          caught = e;
        }
        assert.ok(caught instanceof Error, 'mkdir beneath a FILE must fail');
        const rendered = failText(caught);
        const m = /mkdir '(.+)'$/.exec(rendered);
        assert.ok(m, `Node names the directory it could not make. got: ${rendered}`);
        assert.equal(m![1], dirname(join(home, 'free-identity.key')), 'named in full');
      },
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a corrupt self-join identity names the FILE on the join paths too, not a variable nobody set', () => {
  // `ensureSelfJoinIdentityEnv` writes the minted key path into `SAIHM_MASTER_SECRET_FILE` so the
  // boot path can read it, and that made `secretSource` unable to tell a file the OPERATOR
  // configured from one we configured for them. Measured before the fix: the `free-join` verb and
  // the `saihm_join` tool - the two entry points that mint FIRST, and the two a caller reaches by
  // following the advice the other message's own hint gives them - answered
  // `SAIHM_MASTER_SECRET_FILE <path>`, naming a variable absent from their MCP config, from
  // `server.json` and from the install UI. Same file, same session, two different names.
  //
  // Pinned on the MESSAGE rather than on the branch, because the branch is one refactor away from
  // being spelled differently and the message is what the operator has to act on.
  const home = mkdtempSync(join(tmpdir(), 'saihm-selfjoin-label-'));
  withEnv(
    { SAIHM_HOME: home, SAIHM_MASTER_SECRET_HEX: undefined, SAIHM_MASTER_SECRET_FILE: undefined },
    () => {
      ensureSelfJoinIdentityEnv();
      writeFileSync(join(home, 'free-identity.key'), 'ZZZZ not canonical hex');
      assert.throws(
        () => SaihmProClient.bootFromEnv(),
        (e: Error) => {
          assert.match(
            e.message,
            /^the self-join identity file /,
            `a corrupt self-join identity must name the FILE it read, not a variable the caller ` +
              `never set. Got: ${e.message}`,
          );
          return true;
        },
      );
    },
  );
  rmSync(home, { recursive: true, force: true });
});

const JOINSTATE_TAIL_REFS_PIN = 6;

// A generation check guards WRITES and READS, or it guards nothing. Every background callback in the
// fresh-join flow already wrote under `joinState === s`; the reads after `waitForJoinSignal` did not,
// and that asymmetry was reachable: the already-running branch CLEARS `joinState` on error, which
// reopens the fresh path for a third interleaved call, and this flow then reported the NEWER flow's
// state while its own failure went unreported and rendered as pending.
//
// Scoped to the fresh-flow tail deliberately. The already-running branch ABOVE the declaration reads
// the module global on purpose - it has no `s` in scope and the global is exactly what it means. A
// sweep over the whole handler flags those fifteen correct reads, which is how a guard earns itself a
// blanket exemption from the next author.
test('after the fresh-join flow captures its own state, no read reaches the module global', () => {
  const sf = ts.createSourceFile(
    'server.ts',
    readFileSync(new URL('../src/server.ts', import.meta.url), 'utf-8'),
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TS,
  );
  let decl: ts.VariableStatement | undefined;
  const find = (n: ts.Node): void => {
    if (ts.isVariableStatement(n) && n.getText(sf).startsWith('const s: JoinState')) decl = n;
    n.forEachChild(find);
  };
  find(sf);
  // LOUD on an input this cannot evaluate: a rename that hides the declaration must not read as a
  // clean sweep of zero sites.
  assert.ok(decl, 'could not locate `const s: JoinState` — the fresh-join flow was renamed or moved');

  const after = decl.end;
  const bare: string[] = [];
  let refs = 0;
  const walk = (n: ts.Node): void => {
    if (ts.isIdentifier(n) && n.text === 'joinState' && n.pos >= after) {
      refs++;
      const p = n.parent;
      const isGuard =
        ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken;
      const isWrite =
        ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.EqualsToken && p.left === n;
      if (!isGuard && !isWrite) bare.push(p.getText(sf).replace(/\s+/g, ' ').slice(0, 70));
    }
    n.forEachChild(walk);
  };
  walk(decl.parent);

  assert.deepEqual(
    bare,
    [],
    'the fresh-join flow reads the module global `joinState` instead of its own `s`; a newer ' +
      'interleaved flow makes these reads report the wrong state and swallow this one’s error',
  );
  // A RISE means new references were added and wants review. A FALL is guilty until proven innocent:
  // it reads the same whether a reference was deliberately removed or the walk stopped recognising
  // one, and the second case silently retires every assertion above.
  assert.equal(
    refs,
    JOINSTATE_TAIL_REFS_PIN,
    `expected ${JOINSTATE_TAIL_REFS_PIN} \`joinState\` references after the flow captures \`s\`, ` +
      `found ${refs}. A RISE: confirm each new one is a guard or a write, then raise the pin. A ` +
      `FALL: do NOT lower the pin until you have confirmed the reference was deleted on purpose ` +
      `and the walk still recognises the ones that remain.`,
  );
});
