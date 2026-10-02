/**
 * Portable identity token: carry an EXISTING SAIHM identity to another machine, or into a hosted
 * agent environment, as two pasteable values instead of a key file.
 *
 * WHY THIS EXISTS. A hosted agent session (a cloud coding session, a background agent, a CI-hosted
 * agent) usually starts in a fresh machine whose home directory is discarded when the session ends,
 * and whose only way in for configuration is the host's environment-variable or secrets setting.
 * The key file this package keeps under `~/.saihm` cannot be copied there, so the server found no
 * identity, told the agent to relay "Join SAIHM", and the join minted a NEW key inside a home that was
 * about to be thrown away - every session, while the operator's real memory sat on another machine.
 *
 * WHAT IT IS. `export-identity` seals the identity's master secret, plus the tier and payment method
 * it onboards with, under a passphrase this package GENERATES. The result is two values:
 *
 *   SAIHM_IDENTITY             saihm-id1.<label>.<sealed>   ciphertext; useless on its own
 *   SAIHM_IDENTITY_PASSPHRASE  XXXXX-XXXXX-XXXXX-XXXXX      100 bits from the system CSPRNG
 *
 * Set both in any environment that runs this server and it boots that identity in memory - no file,
 * no join, no second identity.
 *
 * WHAT IT IS NOT. The token plus its passphrase IS the identity: whoever holds both can read, change,
 * erase and share every memory of it, exactly as with the raw secret. Sealing buys transport safety
 * (the token alone can sit in a private repository or pass through a chat without exposing the key),
 * typed diagnostics instead of a silent second identity, and a tier that travels with the key. It
 * does not buy revocation; nothing in this protocol revokes a key short of moving to a new identity.
 *
 * THE PASSPHRASE IS NEVER USER-CHOSEN. Its entropy is what protects a token that leaks without it,
 * and a chosen phrase cannot be measured from inside this process. A generated one can be stated:
 * 20 Crockford base32 symbols, 5 bits each. The decoder accepts any case, any dashes or spaces, and
 * the Crockford aliases (O for 0, I and L for 1), because the value is retyped and reflowed by humans
 * and by chat surfaces, and none of that changes which 100 bits it names.
 *
 * KDF COST is chosen for a 100-bit secret, not for a password: scrypt with N = 2^15, r = 8, p = 1.
 * Against a generated passphrase the work factor is defence in depth, and it is paid on every boot of
 * every session, so it is kept where a cold boot does not notice it. The parameters are fixed for
 * the `saihm-id1` format; a different cost is a different format prefix, never a field an attacker
 * could set to make a victim's boot allocate without bound.
 *
 * NOTHING HERE PRINTS A SECRET. Every error below states a CONDITION and names the variable; none
 * interpolates the token, the passphrase or any decrypted field, so an error relayed into a chat
 * transcript carries nothing worth stealing.
 */
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'node:crypto';

/** Format prefix. Bumped, never reinterpreted, when anything below changes. */
export const IDENTITY_TOKEN_PREFIX = 'saihm-id1';

/** The environment variables the token arrives in. Named once so messages and code cannot drift. */
export const IDENTITY_ENV = 'SAIHM_IDENTITY';
export const PASSPHRASE_ENV = 'SAIHM_IDENTITY_PASSPHRASE';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const PASSPHRASE_SYMBOLS = 20;
const PASSPHRASE_GROUP = 5;

/** Hex characters of the agentIdHash carried in clear as the token's label. */
export const IDENTITY_LABEL_HEX = 16;

const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;
// The scrypt cost, one plain number each so every bound reads (and is pinned) on its own line.
// `maxmem` is explicit because Node's default ceiling sits exactly at this cost and rejects it.
const KDF_N = 32768; // 2^15
const KDF_R = 8;
const KDF_P = 1;
const KDF_MAXMEM_BYTES = 67108864; // 64 MiB

/**
 * Upper bound on the cleaned token, checked BEFORE decoding. A real token is a few hundred
 * characters; the bound only has to stop a pasted file or log from being decoded and decrypted.
 */
const MAX_TOKEN_CHARS = 4096;

/** What a token carries. `secretHex` is the master secret; the other two are onboarding hints. */
export interface IdentityTokenContents {
  secretHex: string;
  tier?: string | undefined;
  paymentMethod?: string | undefined;
}

/** An opened token: its contents and the label it was sealed under. */
export interface OpenedIdentityToken extends IdentityTokenContents {
  label: string;
}

/**
 * A token or passphrase that cannot be used. The message is OURS and names a variable and a
 * condition, never a value - see the header.
 */
export class IdentityTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdentityTokenError';
  }
}

/** Generate a passphrase: `XXXXX-XXXXX-XXXXX-XXXXX`, 100 bits, unbiased (32 divides 256). */
export function generatePassphrase(): string {
  const bytes = randomBytes(PASSPHRASE_SYMBOLS);
  let out = '';
  bytes.forEach((b, i) => {
    if (i > 0 && i % PASSPHRASE_GROUP === 0) out += '-';
    out += CROCKFORD.charAt(b & 31);
  });
  bytes.fill(0);
  return out;
}

/**
 * Undo what a paste does to a value on its way into an environment setting: whitespace from
 * reflow anywhere in it, one pair of surrounding quotes, and the whole `NAME=value` line pasted
 * into a field that wanted only the value. None of these characters can occur inside a valid token
 * or passphrase, so removing them never changes which one is meant.
 */
export function cleanPastedValue(raw: string, name: string): string {
  const unquote = (s: string): string =>
    s.length >= 2 && (s[0] === '"' || s[0] === "'") && s[s.length - 1] === s[0] ? s.slice(1, -1) : s;
  let v = unquote(raw.replace(/\s+/g, ''));
  if (v.startsWith(`${name}=`)) v = unquote(v.slice(name.length + 1));
  return v;
}

/** The canonical 20-symbol form of a passphrase, or `null` if it is not one this package made. */
export function normalizePassphrase(raw: string): string | null {
  const v = cleanPastedValue(raw, PASSPHRASE_ENV)
    .replace(/-/g, '')
    .toUpperCase()
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
  if (v.length !== PASSPHRASE_SYMBOLS) return null;
  for (const ch of v) if (!CROCKFORD.includes(ch)) return null;
  return v;
}

/** A hint value as carried in a token: a short identifier, or absent. */
const HINT = /^[A-Za-z0-9_-]{1,32}$/;

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, KEY_BYTES, { N: KDF_N, r: KDF_R, p: KDF_P, maxmem: KDF_MAXMEM_BYTES });
}

/**
 * Seal `contents` for the identity whose agentIdHash is `agentIdHashHex`. The label is bound into
 * the ciphertext as associated data, so a token whose label was edited does not open.
 */
export function sealIdentityToken(
  contents: IdentityTokenContents,
  agentIdHashHex: string,
  passphrase: string,
): string {
  const pass = normalizePassphrase(passphrase);
  if (pass === null) throw new IdentityTokenError('the passphrase is not one this package generated.');
  if (!/^[0-9a-f]{64,}$/.test(agentIdHashHex))
    throw new IdentityTokenError('the identity hash is not lowercase hex.');
  // THE SAME SHAPE `openIdentityToken` requires of the secret, so nothing seals that will not open.
  if (!/^(?:[0-9a-f]{2}){32,}$/.test(contents.secretHex))
    throw new IdentityTokenError('the master secret is not lowercase hex of at least 32 bytes.');
  // THE SAME RULE `openIdentityToken` applies, checked here so a value no token can carry is refused
  // while the operator is still looking at it - not exported as a token that will never open, behind
  // a remedy ("export it again") that reproduces it.
  for (const [name, v] of [
    ['SAIHM_TIER', contents.tier],
    ['SAIHM_PAYMENT_METHOD', contents.paymentMethod],
  ] as const)
    if (v !== undefined && !HINT.test(v))
      throw new IdentityTokenError(
        `${name} holds a value an identity token cannot carry (letters, digits, - and _ only, up to ` +
          '32 characters). Fix it, then export again.',
      );
    // A PASSPHRASE IN A HINT FIELD fits the hint rule, and would travel in the token to wherever the tier
    // is sent or shown. The field beside the passphrase in an install form is where a paste slip lands.
    else if (v !== undefined && normalizePassphrase(v) !== null)
      throw new IdentityTokenError(
        `${name} holds what looks like an identity passphrase, not a plan setting. Fix it, then export again.`,
      );
  const header = `${IDENTITY_TOKEN_PREFIX}.${agentIdHashHex.slice(0, IDENTITY_LABEL_HEX)}`;
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = deriveKey(pass, salt);
  const plaintext = Buffer.from(
    JSON.stringify({ k: contents.secretHex, t: contents.tier, p: contents.paymentMethod }),
    'utf8',
  );
  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(Buffer.from(header, 'utf8'));
    const sealed = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    const token = `${header}.${Buffer.concat([salt, iv, sealed]).toString('base64url')}`;
    // And nothing so long that the import side refuses it unread.
    if (token.length > MAX_TOKEN_CHARS)
      throw new IdentityTokenError('the master secret is too long to carry in an identity token.');
    return token;
  } finally {
    key.fill(0);
    plaintext.fill(0);
  }
}

/**
 * Open a token with its passphrase. Every failure is an {@link IdentityTokenError} naming the
 * variable to fix; none falls back to anything. A token that does not open must never lead to a
 * different identity being booted or minted in its place.
 */
export function openIdentityToken(rawToken: string, rawPassphrase: string): OpenedIdentityToken {
  // AN UNEXPANDED REFERENCE first, for either variable. A host that does not supply a variable named
  // in an MCP config's `env` block may pass the reference through as literal text, so `${NAME}` is
  // what arrives. Neither value can contain `$`, so this is never a token or passphrase that merely
  // looks odd, and naming it as a reference is the only message that leads to the real fix.
  for (const [name, raw] of [
    [IDENTITY_ENV, rawToken],
    [PASSPHRASE_ENV, rawPassphrase],
  ] as const)
    if (raw.includes('$'))
      throw new IdentityTokenError(
        `${name} holds an unexpanded reference ($...): the host did not supply the variable it ` +
          "names. Set that in the host's environment or secrets; a shared MCP config can reference " +
          'it with a :- default so an unset one arrives blank.',
      );
  if (cleanPastedValue(rawToken, IDENTITY_ENV) === '')
    throw new IdentityTokenError(
      `${PASSPHRASE_ENV} is set but ${IDENTITY_ENV} is not. Add the token export-identity wrote ` +
        'beside it, or unset the passphrase.',
    );
  const token = cleanPastedValue(rawToken, IDENTITY_ENV);
  if (normalizePassphrase(token) !== null || token.startsWith(`${PASSPHRASE_ENV}=`))
    throw new IdentityTokenError(
      `${IDENTITY_ENV} holds a passphrase, not a token. Put the token (it starts with ` +
        `${IDENTITY_TOKEN_PREFIX}.) in ${IDENTITY_ENV} and the passphrase in ${PASSPHRASE_ENV}.`,
    );
  if (token.length > MAX_TOKEN_CHARS)
    throw new IdentityTokenError(
      `${IDENTITY_ENV} is far longer than an identity token. Paste only the value export-identity wrote.`,
    );
  const parts = token.split('.');
  const [prefix = '', label = '', body = ''] = parts;
  if (parts.length !== 3 || !prefix.startsWith('saihm-id'))
    throw new IdentityTokenError(
      `${IDENTITY_ENV} is not a SAIHM identity token: it should start with ${IDENTITY_TOKEN_PREFIX}. ` +
        'Paste the whole value export-identity wrote, exactly as written.',
    );
  if (prefix !== IDENTITY_TOKEN_PREFIX)
    throw new IdentityTokenError(
      `${IDENTITY_ENV} was made by a newer version of @saihm/mcp-server-pro. Update this one, or ` +
        'export the identity again with the version installed here.',
    );
  if (!new RegExp(`^[0-9a-f]{${IDENTITY_LABEL_HEX}}$`).test(label) || !/^[A-Za-z0-9_-]+$/.test(body))
    throw new IdentityTokenError(
      `${IDENTITY_ENV} is damaged: characters were changed or lost. Copy it again exactly, or run ` +
        'export-identity again and replace both values.',
    );
  const blob = Buffer.from(body, 'base64url');
  if (blob.length <= SALT_BYTES + IV_BYTES + TAG_BYTES)
    throw new IdentityTokenError(
      `${IDENTITY_ENV} is cut short. Copy it again exactly, or run export-identity again and replace ` +
        'both values.',
    );

  if (rawPassphrase.trim() === '')
    throw new IdentityTokenError(
      `${IDENTITY_ENV} is set but ${PASSPHRASE_ENV} is not. Add the passphrase export-identity wrote ` +
        'beside the token.',
    );
  if (cleanPastedValue(rawPassphrase, PASSPHRASE_ENV).startsWith(`${IDENTITY_TOKEN_PREFIX}.`))
    throw new IdentityTokenError(
      `${PASSPHRASE_ENV} holds the token, not the passphrase. The two values are swapped.`,
    );
  const pass = normalizePassphrase(rawPassphrase);
  if (pass === null)
    throw new IdentityTokenError(
      `${PASSPHRASE_ENV} is not in the form export-identity writes (20 letters and digits, ` +
        'dashes optional). Copy it again, or run export-identity again and replace both values.',
    );

  const salt = blob.subarray(0, SALT_BYTES);
  const iv = blob.subarray(SALT_BYTES, SALT_BYTES + IV_BYTES);
  const tag = blob.subarray(blob.length - TAG_BYTES);
  const sealed = blob.subarray(SALT_BYTES + IV_BYTES, blob.length - TAG_BYTES);
  const key = deriveKey(pass, salt);
  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(Buffer.from(`${IDENTITY_TOKEN_PREFIX}.${label}`, 'utf8'));
    decipher.setAuthTag(tag);
    const part = decipher.update(sealed);
    plaintext = Buffer.concat([part, decipher.final()]);
    part.fill(0);
  } catch {
    // One message for both causes, because authenticated decryption cannot tell them apart and a
    // guess would send the reader to fix the wrong value.
    throw new IdentityTokenError(
      `${IDENTITY_ENV} did not open with ${PASSPHRASE_ENV}: the passphrase is not the one made with ` +
        'this token, or the token was changed. Copy both from one export, or run export-identity again.',
    );
  } finally {
    key.fill(0);
  }

  let fields: unknown;
  try {
    fields = JSON.parse(plaintext.toString('utf8'));
  } catch {
    fields = undefined;
  } finally {
    plaintext.fill(0);
  }
  const f = fields as { k?: unknown; t?: unknown; p?: unknown } | undefined;
  const hintOk = (v: unknown): boolean => v === undefined || (typeof v === 'string' && HINT.test(v));
  if (
    typeof f !== 'object' ||
    f === null ||
    typeof f.k !== 'string' ||
    !/^(?:[0-9a-f]{2}){32,}$/.test(f.k) ||
    !hintOk(f.t) ||
    !hintOk(f.p)
  )
    throw new IdentityTokenError(
      `${IDENTITY_ENV} opened but its contents are not an identity this version can use. Export it ` +
        'again with the version installed here.',
    );
  return {
    label,
    secretHex: f.k,
    ...(f.t !== undefined ? { tier: f.t as string } : {}),
    ...(f.p !== undefined ? { paymentMethod: f.p as string } : {}),
  };
}

/**
 * Whether a value has the shape of an identity secret: 64+ hex characters (a master secret), a
 * passphrase `export-identity` generates, or a token. Used to keep such a value out of a message
 * that would otherwise echo it.
 */
export function looksLikeIdentitySecret(v: string): boolean {
  // ANYWHERE in the value, not as the whole of it: a key pasted as `NAME=…`, quoted, prefixed with
  // `0x` or `export`, or followed by a stray character is still the key. A real path that happens to
  // hold such a run is withheld too - the cost is a path not shown, never a secret shown.
  //
  // And with WHITESPACE REMOVED, as the paste cleaner reads a token: a key reflowed across lines or
  // split by a space is still the key. 48 hex rather than 64, because a key cut short by a few
  // characters is still nearly all of it.
  const s = v.replace(/\s+/g, '');
  // A dash-less passphrase: a run of EXACTLY twenty such symbols, so a long alphanumeric path segment
  // is not mistaken for one. Tried on both forms: removing a space can lengthen a run past twenty.
  const dashless = /(?:^|[^0-9A-Za-z])[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20}(?:[^0-9A-Za-z]|$)/;
  return (
    /[0-9a-fA-F]{48}/.test(s) ||
    s.includes(`${IDENTITY_TOKEN_PREFIX}.`) ||
    /[0-9A-Za-z]{5}-[0-9A-Za-z]{5}-[0-9A-Za-z]{5}-[0-9A-Za-z]{5}/.test(s) ||
    dashless.test(v) ||
    dashless.test(s) ||
    normalizePassphrase(v) !== null
  );
}

/**
 * Whether a PATH holds an identity secret in one of its parts: the test for REFUSING a directory - a join,
 * an export, or starting at all under one - which must be stricter than the one for withholding a value,
 * since a refusal blocks outright. A part counts for a key or a token anywhere in it, or for a passphrase
 * as a whole RUN of letters, digits and dashes: a paste's wrapping - quotes, a `NAME=` or `Name:` prefix,
 * a trailing period, the rest of a config line - ends a run, so it cannot hide one. Within a run, the
 * grouping this package prints counts in any case; any other placement of dashes, or none, counts only in
 * capitals, as the passphrase is printed - `saihm-sweep-home-` and the six characters a temporary folder
 * adds make twenty symbols once the dashes go, and are not capitals. A run must also carry a digit, as
 * every key and token does and a folder named like `saihm-agent-state-store` does not - except the printed
 * grouping in capitals, the form in which the one generated passphrase in about 1,800 that is all letters
 * arrives.
 */
export function pathHoldsIdentitySecret(p: string): boolean {
  return p.split(/[\\/]/).some(partHoldsIdentitySecret);
}

function partHoldsIdentitySecret(part: string): boolean {
  const s = part.replace(/\s+/g, '');
  if (/[0-9a-fA-F]{48}/.test(s) || s.includes(`${IDENTITY_TOKEN_PREFIX}.`)) return true;
  // Both forms: a space can end a run (`Name: value`) or stand where a reflow broke one.
  return [part, s].some((v) => (v.match(/[0-9A-Za-z-]+/g) ?? []).some(runIsPassphrase));
}

const PRINTED_GROUPING = new RegExp(
  `^[^-]{${PASSPHRASE_GROUP}}(?:-[^-]{${PASSPHRASE_GROUP}}){${PASSPHRASE_SYMBOLS / PASSPHRASE_GROUP - 1}}$`,
);

function runIsPassphrase(run: string): boolean {
  // A LETTER as well: a run of digits alone is a timestamp or a run id (Python's %Y%m%d%H%M%S%f is twenty digits),
  // and boot stopped under such a folder. One generated passphrase in about 10^10 is all digits.
  if (normalizePassphrase(run) === null || !/[A-Za-z]/.test(run)) return false;
  const capitals = !/[a-z]/.test(run);
  const digit = /\d/.test(run);
  return PRINTED_GROUPING.test(run) ? digit || capitals : digit && capitals;
}
