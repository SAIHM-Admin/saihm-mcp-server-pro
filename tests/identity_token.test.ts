// Unit coverage for the portable identity token (src/identity-token.ts): the seal/open round trip,
// the damage a paste does that it must survive (case, dashes, whitespace reflow, quotes, a whole
// NAME=value line), and every refusal. Each refusal is typed, names the variable to fix, carries none
// of the token, the passphrase or the secret, and fits the plain-error render budget, because these
// messages reach an agent's transcript as tool errors.
// Runner: npx tsx --test tests/identity_token.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { createCipheriv, randomBytes, scryptSync } from 'node:crypto';
import {
  IDENTITY_ENV,
  IDENTITY_LABEL_HEX,
  IDENTITY_TOKEN_PREFIX,
  IdentityTokenError,
  PASSPHRASE_ENV,
  cleanPastedValue,
  generatePassphrase,
  normalizePassphrase,
  openIdentityToken,
  sealIdentityToken,
} from '../src/identity-token.js';
import { MAX_ERROR_MESSAGE_CHARS } from '../src/render_fence.js';

const hex = (n: number): string => randomBytes(n).toString('hex');
const SYMBOL = '[0-9A-HJKMNP-TV-Z]';
const PASSPHRASE_SHAPE = new RegExp(`^${SYMBOL}{5}(-${SYMBOL}{5}){3}$`);

function fixture(contents: { tier?: string; paymentMethod?: string } = { tier: 'PRO', paymentMethod: 'stripe' }) {
  const secretHex = hex(32);
  const agentIdHash = hex(32);
  const passphrase = generatePassphrase();
  const token = sealIdentityToken({ secretHex, ...contents }, agentIdHash, passphrase);
  return { secretHex, agentIdHash, passphrase, token };
}

/** Assert a refusal: typed, names `variable`, leaks nothing in `secrets`, fits the render budget. */
function assertRefusal(fn: () => unknown, variable: string, pattern: RegExp, secrets: string[]): void {
  let caught: unknown;
  try {
    fn();
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof IdentityTokenError, `expected IdentityTokenError, got ${String(caught)}`);
  const m = (caught as Error).message;
  assert.ok(m.includes(variable), `message must name ${variable}: ${m}`);
  assert.match(m, pattern);
  assert.ok(m.length <= MAX_ERROR_MESSAGE_CHARS, `message exceeds the render budget (${m.length})`);
  for (const s of secrets) if (s.length >= 8) assert.ok(!m.includes(s), 'message must not carry a secret value');
}

test('round trip: the secret, tier and payment method come back exactly, under the label', () => {
  const f = fixture();
  const opened = openIdentityToken(f.token, f.passphrase);
  assert.equal(opened.secretHex, f.secretHex);
  assert.equal(opened.tier, 'PRO');
  assert.equal(opened.paymentMethod, 'stripe');
  assert.equal(opened.label, f.agentIdHash.slice(0, IDENTITY_LABEL_HEX));
});

test('round trip: a longer secret and absent hints stay absent (no undefined-valued keys)', () => {
  const secretHex = hex(48);
  const passphrase = generatePassphrase();
  const opened = openIdentityToken(sealIdentityToken({ secretHex }, hex(32), passphrase), passphrase);
  assert.equal(opened.secretHex, secretHex);
  assert.ok(!('tier' in opened) && !('paymentMethod' in opened));
});

test('token shape: one line of URL-safe characters, nothing an env file or a shell would reinterpret', () => {
  const { token } = fixture();
  assert.match(token, new RegExp(`^${IDENTITY_TOKEN_PREFIX.replace('-', '\\-')}\\.[0-9a-f]{16}\\.[A-Za-z0-9_-]+$`));
  assert.ok(token.length < 4096, 'must fit the smallest documented host value limit');
  assert.doesNotMatch(token, /[#$"'\s]/);
});

test('two seals of the same identity differ (fresh salt and nonce each time)', () => {
  const secretHex = hex(32);
  const id = hex(32);
  const p = generatePassphrase();
  assert.notEqual(sealIdentityToken({ secretHex }, id, p), sealIdentityToken({ secretHex }, id, p));
});

test('generated passphrases: four groups of five Crockford symbols, distinct, using the whole alphabet', () => {
  const seen = new Set<string>();
  const symbols = new Set<string>();
  for (let i = 0; i < 200; i++) {
    const p = generatePassphrase();
    assert.match(p, PASSPHRASE_SHAPE);
    seen.add(p);
    for (const ch of p.replace(/-/g, '')) symbols.add(ch);
  }
  assert.equal(seen.size, 200);
  assert.equal(symbols.size, 32, 'every one of the 32 symbols must be reachable');
});

test('passphrase normalization forgives case, dashes, spaces, quotes, the NAME= line and Crockford aliases', () => {
  const canon = normalizePassphrase('0123456789ABCDEFGHJK');
  assert.equal(canon, '0123456789ABCDEFGHJK');
  for (const v of [
    '01234-56789-abcde-fghjk',
    ' 01234 56789\nABCDE\tFGHJK ',
    '"01234-56789-ABCDE-FGHJK"',
    `${PASSPHRASE_ENV}=01234-56789-ABCDE-FGHJK`,
    'O1234-56789-ABCDE-FGHJK', // O reads as 0
  ])
    assert.equal(normalizePassphrase(v), canon, v);
  assert.equal(normalizePassphrase('I0000-L0000-i0000-l0000'), '10000100001000010000');
  for (const bad of ['', 'U0000-00000-00000-00000', '0000-00000-00000-00000', 'hunter2', '00000-00000-00000-000000'])
    assert.equal(normalizePassphrase(bad), null, bad);
});

test('token paste damage: reflow, quotes and the whole NAME=value line all still open', () => {
  const f = fixture();
  const reflowed = f.token.replace(/(.{40})/g, '$1\n  ');
  for (const v of [reflowed, `"${f.token}"`, `'${f.token}'`, `${IDENTITY_ENV}=${f.token}`, `${IDENTITY_ENV}="${f.token}"`])
    assert.equal(openIdentityToken(v, f.passphrase.toLowerCase()).secretHex, f.secretHex);
  assert.equal(cleanPastedValue(` ${IDENTITY_ENV}='x' `, IDENTITY_ENV), 'x');
});

test('refusals are typed, named, bounded and secret-free', () => {
  const f = fixture();
  const secrets = [f.secretHex, f.passphrase, f.passphrase.replace(/-/g, ''), f.token.split('.')[2]!.slice(0, 40)];
  const body = f.token.split('.')[2]!;
  const flip = (s: string, i: number): string => s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1);

  assertRefusal(() => openIdentityToken(f.token, generatePassphrase()), IDENTITY_ENV, /did not open/, secrets);
  assertRefusal(() => openIdentityToken(`${IDENTITY_TOKEN_PREFIX}.${f.token.split('.')[1]}.${flip(body, 30)}`, f.passphrase), IDENTITY_ENV, /did not open/, secrets);
  assertRefusal(() => openIdentityToken(`${IDENTITY_TOKEN_PREFIX}.${'0'.repeat(16)}.${body}`, f.passphrase), IDENTITY_ENV, /did not open/, secrets);
  assertRefusal(() => openIdentityToken(f.token.slice(0, f.token.length - 5), f.passphrase), IDENTITY_ENV, /did not open/, secrets);
  assertRefusal(() => openIdentityToken(f.token.slice(0, 40), f.passphrase), IDENTITY_ENV, /cut short/, secrets);
  assertRefusal(() => openIdentityToken(f.token.replace(IDENTITY_TOKEN_PREFIX, 'saihm-id2'), f.passphrase), IDENTITY_ENV, /newer version/, secrets);
  assertRefusal(() => openIdentityToken('hello', f.passphrase), IDENTITY_ENV, /not a SAIHM identity token/, secrets);
  assertRefusal(() => openIdentityToken(`${IDENTITY_TOKEN_PREFIX}.XYZ.${body}`, f.passphrase), IDENTITY_ENV, /damaged/, secrets);
  assertRefusal(() => openIdentityToken(f.passphrase, f.token), IDENTITY_ENV, /holds a passphrase, not a token/, secrets);
  assertRefusal(() => openIdentityToken(f.token, f.token), PASSPHRASE_ENV, /swapped/, secrets);
  assertRefusal(() => openIdentityToken('${SAIHM_IDENTITY}', f.passphrase), IDENTITY_ENV, /unexpanded reference/, secrets);
  assertRefusal(() => openIdentityToken(f.token, '$SAIHM_IDENTITY_PASSPHRASE'), PASSPHRASE_ENV, /unexpanded reference/, secrets);
  assertRefusal(() => openIdentityToken(f.token, ''), PASSPHRASE_ENV, /is set but SAIHM_IDENTITY_PASSPHRASE is not/, secrets);
  assertRefusal(() => openIdentityToken('  ', f.passphrase), IDENTITY_ENV, /SAIHM_IDENTITY_PASSPHRASE is set but SAIHM_IDENTITY is not/, secrets);
  assertRefusal(() => openIdentityToken(f.token, 'hunter2'), PASSPHRASE_ENV, /not in the form/, secrets);
  assertRefusal(() => openIdentityToken(`${f.token}${'A'.repeat(5000)}`, f.passphrase), IDENTITY_ENV, /far longer/, secrets);
});

/**
 * Build a token the way `sealIdentityToken` does, minus its input checks, so the OPEN side's own
 * validation can be driven with contents no honest export produces. It restates the format on
 * purpose: if the format drifts, this stops opening and the test says so.
 */
function craft(fields: Record<string, unknown>, label: string, passphrase: string): string {
  const pass = normalizePassphrase(passphrase)!;
  const header = `${IDENTITY_TOKEN_PREFIX}.${label}`;
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(pass, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 67108864 });
  const c = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  c.setAAD(Buffer.from(header, 'utf8'));
  const sealed = Buffer.concat([c.update(Buffer.from(JSON.stringify(fields), 'utf8')), c.final(), c.getAuthTag()]);
  return `${header}.${Buffer.concat([salt, iv, sealed]).toString('base64url')}`;
}

test('the crafting helper matches the real format (positive control for the next test)', () => {
  const p = generatePassphrase();
  const k = hex(32);
  assert.equal(openIdentityToken(craft({ k, t: 'PRO' }, hex(8), p), p).secretHex, k);
});

test('a token that opens but carries unusable contents is refused, never booted', () => {
  const p = generatePassphrase();
  for (const fields of [
    { k: 'zz'.repeat(32) },
    { k: 'ab'.repeat(31) },
    { k: 'abc' },
    { k: 7 },
    { k: 'ab'.repeat(32), t: 'PRO; echo' },
    { k: 'ab'.repeat(32), p: 'x'.repeat(33) },
    { k: 'ab'.repeat(32), t: 5 },
  ]) {
    const t = craft(fields, hex(8), p);
    assertRefusal(() => openIdentityToken(t, p), IDENTITY_ENV, /not an identity this version can use/, []);
  }
});

test('seal refuses a tier or payment method no token can carry, naming the variable', () => {
  const p = generatePassphrase();
  for (const [contents, variable] of [
    [{ tier: ' PRO' }, 'SAIHM_TIER'],
    [{ tier: 'PRO FAST' }, 'SAIHM_TIER'],
    [{ tier: 'P'.repeat(33) }, 'SAIHM_TIER'],
    [{ paymentMethod: 'x402:usdc' }, 'SAIHM_PAYMENT_METHOD'],
    [{ paymentMethod: 'Stripe Card' }, 'SAIHM_PAYMENT_METHOD'],
  ] as const)
    assertRefusal(() => sealIdentityToken({ secretHex: hex(32), ...contents }, hex(32), p), variable, /cannot carry/, []);
  for (const tier of ['FREE', 'PRO', 'PRO_FAST', 'ENTERPRISE', 'ENTERPRISE_FAST'])
    for (const paymentMethod of ['stripe', 'stablecoin', 'paypal', 'paystack'])
      assert.equal(openIdentityToken(sealIdentityToken({ secretHex: hex(32), tier, paymentMethod }, hex(32), p), p).tier, tier);
});

test('seal refuses a secret no token could carry back: wrong shape, too short, too long', () => {
  const p = generatePassphrase();
  for (const secretHex of ['AB'.repeat(32), 'abc', 'ab'.repeat(31), 'zz'.repeat(32), 'ab'.repeat(1600)])
    assert.throws(() => sealIdentityToken({ secretHex }, hex(32), p), IdentityTokenError, secretHex.slice(0, 8));
});

test('seal refuses a passphrase this package did not generate, and a non-hex identity hash', () => {
  assert.throws(() => sealIdentityToken({ secretHex: hex(32) }, hex(32), 'correct horse'), IdentityTokenError);
  assert.throws(() => sealIdentityToken({ secretHex: hex(32) }, 'Z'.repeat(64), generatePassphrase()), IdentityTokenError);
});

test('seal refuses a passphrase in a hint field, naming the field and never the value', () => {
  for (const [field, variable] of [['tier', 'SAIHM_TIER'], ['paymentMethod', 'SAIHM_PAYMENT_METHOD']] as const)
    for (const v of [generatePassphrase(), generatePassphrase().replace(/-/g, '').toLowerCase()])
      assertRefusal(
        () => sealIdentityToken({ secretHex: hex(32), [field]: v }, hex(32), generatePassphrase()),
        variable,
        /looks like an identity passphrase, not a plan setting/,
        [v],
      );
  // A plan name that happens to be twenty letters is not refused for its length alone.
  assert.ok(sealIdentityToken({ secretHex: hex(32), tier: 'ENTERPRISE_FAST' }, hex(32), generatePassphrase()));
});

test('a path is refused only for a part that holds a secret shape AND a digit, not for a folder named like one', async () => {
  const { pathHoldsIdentitySecret } = await import('../src/identity-token.js');
  const hex = 'c3'.repeat(32);
  for (const p of [`/x/${hex}/free-identity.key`, '/x/6SV38-T6E9Y-EQ4NY-WVY0T/free-identity.key', `/x/saihm-id1.${'ab'.repeat(8)}.QUJD/k`])
    assert.equal(pathHoldsIdentitySecret(p), true, p);
  for (const p of ['/home/u/saihm-agent-state-store/free-identity.key', '/home/u/.saihm/free-identity.key', '/x/ABCDEFGHJKMNPQRSTVWX/k'])
    assert.equal(pathHoldsIdentitySecret(p), false, p);
});

test('a temporary folder is not refused: a passphrase counts as a whole run, printed in any case or otherwise in capitals', async () => {
  const { pathHoldsIdentitySecret } = await import('../src/identity-token.js');
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  // The shape that failed: twenty symbols once the dashes go, with a digit among mkdtemp's six characters.
  // Dashes placed other than as printed are a folder when the run has lowercase letters, as every temporary
  // folder's has; so is a folder named in five-letter words, and a run that is not twenty symbols at all.
  for (const p of ['/tmp/saihm-sweep-home-9NntOy/k', '/tmp/saihm-sweep-home-1rJT9i/k', '/srv/build-cache-store-daily-2024/k'])
    assert.equal(pathHoldsIdentitySecret(p), false, p);
  // Real temporary folders, made as a test or a host makes them: none is refused.
  for (let i = 0; i < 200; i++) {
    const d = mkdtempSync(join(tmpdir(), 'saihm-sweep-home-'));
    try {
      assert.equal(pathHoldsIdentitySecret(join(d, 'free-identity.key')), false, d);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // A secret that a slip put there is still refused, in each form a paste leaves it.
  const pass = '6SV38-T6E9Y-EQ4NY-WVY0T';
  for (const part of [pass, pass.toLowerCase(), pass.replace(/-/g, ''), `"${pass}"`, ` ${pass} `, `SAIHM_IDENTITY_PASSPHRASE=${pass}`, `PASSPHRASE='${pass}'`, `0x${'c3'.repeat(32)}`])
    assert.equal(pathHoldsIdentitySecret(`/home/u/${part}/free-identity.key`), true, part);
  // REFUSED SINCE BATCH 7, where this test listed it as a folder: it is `pass` with one dash moved, which opens
  // the token as `pass` does, in capitals as a passphrase is printed. A retyped passphrase arrives this way.
  assert.equal(pathHoldsIdentitySecret('/tmp/6SV3-8T6E9Y-EQ4NY-WVY0T/k'), true);
});

test('a passphrase in a path part is refused in every form a paste leaves it; a folder that only looks like one is not', async () => {
  const { pathHoldsIdentitySecret } = await import('../src/identity-token.js');
  const P = '7K2QX-M9PDA-W4RTE-HB3NC';
  // Each form leaves P as a whole run of letters, digits and dashes: the wrapping a copied config line, markdown
  // or a sentence puts around it ends the run, so none of it hides P. Batch 6b let these through, and the export
  // then printed them (security R6 F2, correctness R6 F1, docs R6 L3).
  const wrapped = [
    `SAIHM_IDENTITY_PASSPHRASE: ${P}`, // YAML
    `"SAIHM_IDENTITY_PASSPHRASE": "${P}",`, // a JSON line
    `"${P}",`,
    `\`${P}\``,
    `${P}.`,
    `$env:SAIHM_IDENTITY_PASSPHRASE="${P}"`, // PowerShell
    `-e SAIHM_IDENTITY_PASSPHRASE=${P}`, // docker
    `<${P}>`,
    `passphrase:${P}`,
    `${P},`,
    `${P};`,
    `${P}-`,
    `-${P}`,
    `\u201c${P}\u201d`, // smart quotes
    // A table row or a sentence: removing the whitespace glues the name to P, so the raw reading must see P alone
    // (correctness R7 F3).
    `SAIHM_IDENTITY_PASSPHRASE\t${P}`,
    `Passphrase ${P}`,
  ];
  // Dashes misplaced, missing or replaced: each still opens the token as P, and is in capitals as P is printed.
  const retyped = [
    '7K2QXM9PDA-W4RTE-HB3NC', // one dash dropped
    '7K2QXM9PDA-W4RTEHB3NC', // 10-10
    '7K2Q-XM9PDA-W4RTE-HB3NC', // 4-6-5-5
    '7K2QX M9PDA-W4RTE-HB3NC', // a space for one dash
  ];
  // All letters, as printed: about one generated passphrase in 1,800 has no digit, and it is refused in this form.
  for (const part of [...wrapped, ...retyped, 'ABCDE-FGHJK-MNPQR-STVWX'])
    assert.equal(pathHoldsIdentitySecret(`/home/u/${part}/free-identity.key`), true, part);
  // A Windows path is split on its backslashes (correctness R6 B4).
  assert.equal(pathHoldsIdentitySecret(`C:\\Users\\u\\${P}\\free-identity.key`), true, 'backslash path');
  // Precision: a digit elsewhere in the path does not make a word folder a passphrase (correctness R6 B9), and a
  // temporary folder's run, twenty symbols or not, has lowercase letters.
  for (const p of ['/home/u1/saihm-agent-state-store/free-identity.key', '/tmp/saihm_sweep_home_9NntOy/k', '/tmp/saihm-sweep-home-1rJT9i/k'])
    assert.equal(pathHoldsIdentitySecret(p), false, p);
});

test('a folder named by a timestamp or a run id is not refused: a passphrase run has a letter (correctness R7 F1)', async () => {
  const { pathHoldsIdentitySecret } = await import('../src/identity-token.js');
  // Twenty digits is Python's %Y%m%d%H%M%S%f; about one generated passphrase in 10^10 is all digits.
  for (const p of ['/srv/state/20261002103045123456', '/tmp/run-20261002103045123456/k', '/tmp/2026-10-02-10-30-45-123456/k', '/x/12345-67890-12345-67890/k'])
    assert.equal(pathHoldsIdentitySecret(p), false, p);
  // A letter among the digits is a passphrase again, in capitals or as printed.
  for (const p of ['/x/2026100210304512345A/k', '/x/7K2QX-M9PDA-W4RTE-HB3NC/k'])
    assert.equal(pathHoldsIdentitySecret(p), true, p);
});

test('a key in capitals is withheld as one in lower case is (correctness R7 B3)', async () => {
  const { looksLikeIdentitySecret } = await import('../src/identity-token.js');
  const hex = 'c3'.repeat(32);
  for (const v of [hex, hex.toUpperCase(), `0x${hex.toUpperCase()}`, `/home/u/${hex.toUpperCase()}/k`])
    assert.equal(looksLikeIdentitySecret(v), true, v);
});
