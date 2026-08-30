/**
 * SAIHM — production thin-client (`SaihmProClient`), non-custodial.
 *
 * Every cryptographic operation that touches plaintext or the master secret runs HERE, client-side,
 * via `@saihm/client-pro`. The wire carries only opaque ciphertext + wrapped DEKs + ML-KEM share
 * ciphertext; the SAIHM endpoint stores / anchors / bills BLIND and never holds a key able to read
 * the memory.
 *
 * Transport mirrors the standards thin-client (`@saihm/mcp-server` `saihm_runtime_client.ts`)
 * VERBATIM: `POST {method, params}` + `Authorization: Bearer <JWT>` to the bridge `/mcp`. The bridge
 * verifies the JWT and injects tenant = JWT.sub = agentIdHash + tier; this client sends NEITHER
 * tenant NOR tier. The only behavioural difference from the custodial standards client: `params` are
 * SEALED client-side before POST, and recall OPENS client-side after fetch.
 *
 * Read-path trust: a recalled cell is accepted only if its decoded envelope is bound to THIS agent
 * (`agentIdHash`) and to the requested cell id, and decrypts under this identity's KEK. The cell id
 * and sequence are taken from the AEAD-authenticated envelope, never from the server's row label —
 * a blind/compromised endpoint cannot relabel, mis-attribute, or rollback a cell undetected.
 *
 * Configure via env (see {@link SaihmProClient.bootFromEnv}):
 *   SAIHM_ENDPOINT_URL      `https://…/mcp` (or `http://` only for 127.0.0.1 / localhost, dev).
 *   SAIHM_AUTH_HEADER       OPTIONAL Authorization value, e.g. `"Bearer <JWT>"`. When UNSET, the
 *                           client SELF-ONBOARDS: it mints + auto-refreshes its own short-lived JWT
 *                           from the master secret (ML-DSA challenge/response against `/api/onboard`),
 *                           so a subscriber pastes one config ONCE and never re-pastes a token. When
 *                           set, it is used verbatim and no self-onboarding occurs.
 *   SAIHM_PAYMENT_METHOD    required for self-onboarding (e.g. `"stripe"` / `"stablecoin"`); the
 *                           proof-of-entitlement rail the endpoint checks. Ignored when SAIHM_AUTH_HEADER is set.
 *   SAIHM_MASTER_SECRET_HEX >= 64 hex chars (>= 32 bytes) of high-entropy material; CLIENT-HELD,
 *                           never transmitted or logged. Its derived `agentIdHash` MUST equal the
 *                           JWT `sub` (the blind endpoint rejects a write whose signed agentIdHash
 *                           != JWT.sub — BLIND_ATTRIBUTION_MISMATCH).
 *   SAIHM_TIER              the billing tier label baked into sealed cell metadata. REQUIRED for
 *                           self-onboarding (it is part of the onboard request); otherwise optional —
 *                           if unset (static-auth mode) the client resolves it once via `status()`.
 *   SAIHM_DISCOVERY_SOURCE  OPTIONAL attribution tag (e.g. `"glama"`, `"mcp-registry"`) naming the
 *                           channel this install came from; sent as `source` on self-onboard so the
 *                           operator can attribute the paid conversion. Sanitised endpoint-side.
 *   SAIHM_SEQ_STATE_PATH    OVERRIDES where per-cell seq high-water marks are persisted (mode 600),
 *                           so a cell UPDATE survives a process restart without a stale-seq
 *                           rejection. Not the on/off switch it once was: the MCP server's boot path
 *                           opts in and DEFAULTS this to `dirname(defaultIdentityPath())/seq.<id>.json`,
 *                           so unset now means "the default location", not "no persistence". A
 *                           library caller constructing the client directly still gets nothing on
 *                           disk unless it sets this or passes `persistSeqState`.
 *   SAIHM_RECALL_CACHE_PATH optional path (mode 600); when set, `recall` runs in DELTA mode —
 *                           it fetches only cells not already cached, cutting a session-start
 *                           recall from O(all cells) to O(new). Holds plaintext at rest ⇒ opt-in.
 *
 * Concurrency: writes to DISTINCT cells are safe to run concurrently. Concurrent updates to the
 * SAME cell are single-writer by contract — the server's monotonic-seq guard rejects the loser with
 * a typed stale-seq error (no corruption); serialize same-cell updates if you need both to land.
 */

import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join as pathJoin } from 'node:path';
import { homedir } from 'node:os';

import {
  deriveIdentity,
  signChallenge,
  sealCell,
  openCell,
  shareCell,
  decodeShareEnvelope,
  unwrapSharedDek,
  verifyShareSig,
  openCellWithDek,
  verifyEnvelope,
  verifyIdentityRecord,
  encodeEnvelope,
  decodeEnvelope,
  encodeShareEnvelope,
  encodeIdentityRecord,
  decodeIdentityRecord,
  fromHex,
  toHex,
  utf8,
  fromUtf8,
  ctEqual,
  SeqHighWaterMark,
} from '@saihm/client-pro';
import { safePathField, MAX_PATH_FIELD_CHARS } from './render_fence.js';
import type {
  ClientIdentity,
  WireEnvelope,
  WireShareEnvelope,
  WireIdentityRecord,
} from '@saihm/client-pro';

const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
/**
 * Ceiling on the endpoint-chosen `error` string carried on a {@link SaihmEndpointError}. A real code
 * is a short constant (`BLIND_SCOPE_UNSUPPORTED`); this exists so a hostile one cannot be a payload.
 */
export const MAX_ERROR_CODE_CHARS = 64;
const MAX_SEQ = (1n << 64n) - 1n; // wire uint64 ceiling (mirrors client-pro wire U64_MAX)
/**
 * Hard ceiling on share announcements kept from one recall. Announcements are unauthenticated and
 * cost the endpoint nothing to mint, so an uncapped list is a context-flood primitive: the 16MiB body
 * cap divided by a ~62-byte minimal row is ~270k rows, each of which an MCP host would render. The
 * cap is applied to the KEPT set (post-dedup) and truncation is reported, never silent.
 *
 * A ROW cap alone does not close that primitive, and an earlier cut of this comment wrongly implied
 * it did. Row count and byte count are independent axes: 256 rows carrying a 40KB `cellId` each still
 * spends the whole 16MiB budget, and while the SERVER's render cap bounds the text block, nothing
 * bounded `structuredContent`. Measured against this client before the field/total caps below existed:
 * a 16,753,811-byte response produced a 6,827-byte text block and a 16,754,638-byte structuredContent
 * — 2,455x — in a single successful recall. Both axes of THIS channel are now capped: measured after,
 * a 16,777,216-byte body yields at most a 3,595-byte text block and a 51,515-byte structuredContent.
 *
 * Those two figures are worth stating as MEASURED and re-measured, because the pair that stood here
 * before ("3,547" and "51,003") were both wrong, and wrong in ways that matter more than the digits.
 * 3,547 was a stale ceiling: the worst case needs an OFF-CONTRACT scope, which renders the 11-char
 * `(malformed)` marker rather than the 9-char `readwrite` the previous fixture used. 51,003 was a
 * `String.length`, not a byte count — the exact CHARS-for-BYTES confusion the paragraph below warns
 * about, eleven lines above the warning. Both were written from arithmetic rather than from a run.
 *
 * Two limits on the claim, both measured, neither hypothetical:
 *  - It is a claim about the ANNOUNCEMENT channel only. The endpoint's `error` string reaches the same
 *    tool's output through {@link SaihmEndpointError}; until it was truncated at the mint (see
 *    {@link MAX_ERROR_CODE_CHARS}) it carried 33,554,563 bytes — ~609x the 55,078-byte worst case
 *    here. That denominator is a JOINT maximum, not a sum of the per-channel ones (3,595 + 51,515 =
 *    55,110): the two channels are maximised by different epoch representations, so both cannot be
 *    at their own maximum in one response. Earlier cuts divided by 54,216 (619x) and by 55,112 (a
 *    fixture that cannot exist). See the matching note in `render_fence.ts`.
 *  - The budgets below count UTF-16 code units (`String.length`), NOT bytes. For the ASCII an endpoint
 *    has any reason to send the two coincide; for what a hostile one can send they do not. Measured
 *    against the 32,768-unit budget: control characters, which JSON-escape to six bytes per unit,
 *    reach ~215 KB of `structuredContent` — 6.6x, not the "~3.4x" claimed here before. (Astral
 *    characters cannot be the worst case, and the fixture that produced the old figure could not have
 *    existed: one astral character is TWO code units, so 64 of them exceed the 64-unit field cap and
 *    the row is always dropped. The widest admissible astral field is 32 characters.) The text block
 *    is unaffected — the server sanitises to ASCII and caps separately — so the residue is confined
 *    to structured-output hosts and is bounded, not a flood. Named here so the next reader does not
 *    have to re-measure it, and so `CHARS` is not mistaken for `BYTES`.
 */
export const MAX_SHARED_ANNOUNCEMENTS = 256;
/**
 * Per-field character ceiling for an announcement. Every field has a real shape at or below this — a
 * sharer is exactly 64 hex, a scope is one of two words, an epoch is a handful of digits, and a
 * `cellId` accommodates a full sha256 hex id — so this is not a validation rule, it is a bound on how
 * many bytes an unauthenticated row may spend.
 *
 * It is deliberately EQUAL to the server's per-field render budget, and that equality is the whole
 * point: it makes one invariant true end to end — every announcement this client keeps renders its
 * `cellId` at FULL LENGTH in the text block, never truncated. Were this cap the larger of the two,
 * rows in the gap would render a cut `cellId`, which cannot be passed back to resolve the grant: an
 * actionable-looking pointer that is not actionable.
 *
 * "Full length" is the exact claim, and it is narrower than usable. The cap equality closes the
 * TRUNCATION route to an unusable pointer; it does not close the SANITISER route. `cellId` is
 * free-form, so a writer may choose one the scrubbers rewrite: a non-ASCII character, a bracket or a
 * pipe (`safeField`), or an `=` (`labelSafe`, added at the pointer site to stop a `cellId` minting a
 * label). `notes-über` renders as `notes-?ber` and `note=1` as `note?1` — full length, no truncation
 * marker, and just as unusable when fed back. The `=` class is the newest and was NOT in this list
 * when it was added one line away in the render; an enumeration of scrubbed characters that lives in
 * a different file from the scrubbers goes stale by default, so read the two `.replace` chains in
 * `render_fence.ts` as the authority and this sentence as a pointer to them. That is the same outcome this equality
 * exists to prevent, reached through the scrubber instead of the cap, and it is a residual rather
 * than a bug: the alternative is rendering an unescaped free-form field into a text block, which is
 * the hole the fence exists to close. A writer who wants a resolvable pointer picks an ASCII id.
 *
 * `cellId` and no other field, which an earlier cut of this comment overstated into "every pointer an
 * agent is shown is a pointer it can act on". Only `cellId` is free-form and therefore only `cellId`
 * goes through the length-capped sanitiser. The other three have contracts, so the renderer CHECKS
 * them instead — and a kept row whose `sharer`, `scope` or `expiryEpoch` is off-contract but within
 * this cap renders that field as `(malformed)`. An uppercase 64-hex sharer is the clearest case: it
 * is admitted here, and shown as malformed there, because the shipped `fromHex` would throw on it.
 * That is the correct outcome and the coverage says so, but it is not the outcome the old sentence
 * described, and the gap between the two is exactly where an unusable pointer would hide.
 *
 * A row with any field longer is therefore dropped, not truncated. That costs nothing a hostile
 * endpoint does not already have (it can simply omit the row) and matches the skip-never-throw policy
 * these rows already follow. A writer who chooses a cellId longer than this loses only the pointer;
 * the cell itself still resolves through `recallShared` once the id is known out-of-band.
 */
export const MAX_ANNOUNCEMENT_FIELD_CHARS = 64;
/**
 * Total character ceiling across all kept announcements — the byte axis stated directly, rather than
 * left to be inferred from the row and field caps. Those two alone bound a listing at 256 x 4 x 64 =
 * 64KB; this binds earlier, whenever rows average more than ~32 chars per field.
 *
 * That threshold is BELOW a real row, not above it, and an earlier cut of this comment had it exactly
 * backwards — it said ~32 was "already well above every real row", which would make this cap a
 * defence against pathological input only. MEASURED against the row shape the paragraph above
 * defines (a 64-hex sharer, a full sha256 `cellId`): 64+64+`read` = 132 chars = 33.00 per field, 248
 * rows kept; with `readwrite` = 137 = 34.25, 239 rows; plus a 10-digit epoch = 147 = 36.75, 222 rows.
 * Every real-shaped row is above the threshold, so for a LEGITIMATE listing it is this cap and not
 * the 256-row cap that binds — an agent holding MORE THAN 222 grants sees `(LIST TRUNCATED)` from
 * the byte axis. 222 is the last count that FITS (222 x 147 = 32,634 <= 32,768); the flag first
 * fires at 223 (32,781), because `openRecallRows` flags on `announcedChars + rowChars > MAX`. The repo's own coverage already said so (`client_announce.test.ts` trips the budget at
 * row ~239, `server_shared_announce.test.ts` admits 219 of its rows) while this sentence claimed the
 * opposite. Exceeding it reports truncation exactly like the row cap, never silently.
 *
 * The consequence is a real limit on grant listings, not a rounding detail: past ~222 grants the
 * pointer list is partial by design, and the count of what was withheld is what makes that honest.
 */
export const MAX_ANNOUNCEMENT_TOTAL_CHARS = 32 * 1024;

/**
 * The hosted, non-custodial operator. `server.json` already declares this as
 * SAIHM_ENDPOINT_URL's `default`, so registry-driven installs receive it — but a
 * hand-written MCP config (`npx -y @saihm/mcp-server-pro` with no env) did not,
 * and every memory tool then failed with a bare `SAIHM_ENDPOINT_URL env var
 * required` that never mentioned `saihm_join`. Honouring the declared default in
 * code makes the two agree and lets boot reach the join hint below.
 *
 * Defaulting reaches no network on its own: bootFromEnv still requires an
 * identity, so an unconfigured agent gets the join hint *before* any request,
 * and `saihm_join` needs explicit human approval before memory is activated.
 */
export const DEFAULT_ENDPOINT = 'https://saihm.coti.global/mcp';

/**
 * Appended to every remaining bootFromEnv configuration error. A bare env-var
 * name is a dead end for the agent reading it: it cannot tell that a free,
 * zero-config path exists one tool call away.
 *
 * It MUST be computed per call, not frozen into a constant: under
 * SAIHM_SELF_JOIN=0 the server registers eight tools and no `saihm_join`, so
 * naming that tool would send the agent after something that does not exist —
 * a worse dead end than the bare message it replaced.
 */
function setupHint(): string {
  return selfJoinEnabled()
    ? ' To start free with no configuration, ask me to "Join SAIHM" (the saihm_join tool).' +
        ' To use a different operator, set SAIHM_ENDPOINT_URL to its endpoint.'
    : ' Self-join is off (SAIHM_SELF_JOIN=0), so supply a master secret via' +
        ' SAIHM_MASTER_SECRET_FILE or SAIHM_MASTER_SECRET_HEX. Unset SAIHM_SELF_JOIN' +
        ' to start free with no configuration instead.';
}

/** Mirrors the standards client: https only, except 127.0.0.1 / localhost over http (dev). */
function assertEndpointUrl(endpoint: string): void {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new SaihmConfigError(
      `SAIHM_ENDPOINT_URL is not a valid URL: ${endpoint}`,
      'url',
    );
  }
  if (url.protocol === 'https:') return;
  if (
    url.protocol === 'http:' &&
    (url.hostname === '127.0.0.1' || url.hostname === 'localhost')
  )
    return;
  // A plain `Error`, and deliberately NOT a {@link SaihmConfigError}, though it sits beside one and
  // interpolates a caller-supplied value. The embedded value is a URL SCHEME, which is not something
  // the operator has to go and open, so there is no actionable value here to lose.
  //
  // Note what actually gets cut, because the first version of this note had it backwards: the scheme
  // is at the FRONT, so it is not the scheme that truncation removes -- it is the trailing sentence,
  // `Plain http:// is only allowed for 127.0.0.1 or localhost (dev).` MEASURED, because the earlier
  // wording rounded and then reasoned from the rounding: the fixed prose is exactly 110 of the 256
  // characters and the trailing sentence is 63, so a 146-character scheme cuts its FIRST character
  // and only a 208-character one takes the whole sentence. Between those the advice degrades a
  // character at a time rather than vanishing. Still not a finding: `new URL` accepts a scheme only
  // as `[A-Za-z][A-Za-z0-9+.-]*`, so reaching 146 means typing 146 of them before `://`. Recorded
  // so the next sweep neither re-derives it nor files it as a defect.
  throw new Error(
    `SAIHM_ENDPOINT_URL must use https:// (got ${url.protocol}//). ` +
      `Plain http:// is only allowed for 127.0.0.1 or localhost (dev).`,
  );
}

/** Refresh a self-onboard JWT this long before its `exp` (cushions clock skew + in-flight latency). */
const JWT_REFRESH_SKEW_MS = 60_000;
/** Conservative assumed lifetime for an opaque (non-JWT) token whose `exp` we cannot read. */
const OPAQUE_TOKEN_TTL_MS = 5 * 60_000;

/** Default client->bridge poll cadence for the FREE device-flow claim loop when the bridge gives none. */
const FREE_ONBOARD_POLL_MS = 5_000;

/**
 * The monthly-subscription tiers a FREE identity may upgrade to via {@link SaihmProClient.requestUpgradeUrl}.
 * FREE (the origin) and any usage-metered/PAYG label are deliberately excluded: the free->paid door lands on
 * a mandatory monthly subscription (ratified), never a pay-as-you-go plan.
 */
const MONTHLY_PAID_TIERS: ReadonlySet<string> = new Set([
  'PRO',
  'PRO_FAST',
  'ENTERPRISE',
  'ENTERPRISE_FAST',
]);

/** Lifetime-usage fractions (percent) at which the FREE tier surfaces an upgrade nag. 100 = hard cap reached. */
const QUOTA_NAG_THRESHOLDS = [80, 95, 100] as const;
type QuotaNagThreshold = (typeof QUOTA_NAG_THRESHOLDS)[number];

/** Advisory upgrade call-to-action carried on every {@link QuotaNag} (no pricing — set by the operator/site). */
const UPGRADE_HINT =
  'Upgrade to a monthly PRO subscription to keep going — your memories stay on this same key. ' +
  'Run `npx -y @saihm/mcp-server-pro upgrade` for a checkout link.';

/**
 * The ceiling a quota counter is bounded by BEFORE its grammar is checked, so the work is bounded by
 * the ANSWER's size and not by the endpoint's input.
 *
 * `server.ts`'s `MAX_NUMERIC_CHARS` applies this same principle to the display numbers in
 * `saihm_status`; the sweep that produced it did not reach here, though these counters arrive through
 * the same unvalidated cast from the same endpoint-chosen body. Unbounded, this ran its regex and then
 * `BigInt()` over whatever fit inside `MAX_RESPONSE_BYTES`. MEASURED at 16 MiB of digits: the regex
 * costs 27.6 ms and `BigInt()` costs 6,124.8 ms, and `maybeNagFromResult` calls this twice per
 * response on the main thread of a stdio server. Unlike the sibling — whose whole cost was one 212 ms
 * scan, and whose comment says plainly that no end-to-end impact was demonstrated — that is a stall a
 * caller would notice. It is still not a boundary breach: the endpoint pays nothing and reads nothing.
 *
 * The bound also removes the reason the threshold arithmetic could go wrong, which is the half worth
 * keeping. `fraction` is `Number(used) / Number(limit)`, and a bigint past ~1.8e308 converts to
 * `Infinity`, so TWO huge counters gave `NaN` and the `pct >= t` loop then fired nothing — a quota
 * reported as exhausted produced silence rather than the 100% nag. Every value that survives this cap
 * converts to a finite double, so that branch is gone rather than merely unlikely.
 *
 * 32 clears every real counter with room to spare, and nothing is lost above it: a double stops being
 * exact at 16 digits, so a value needing more than 32 is not one this client could act on anyway.
 */
const MAX_COUNTER_CHARS = 32;

/** Parse a non-negative decimal-string bigint (as bridges serialise counters); `null` if not one. */
function parseDecimalBig(v: unknown): bigint | null {
  if (typeof v !== 'string' || v.length > MAX_COUNTER_CHARS) return null;
  if (!/^[0-9]+$/.test(v)) return null;
  try {
    return BigInt(v);
  } catch {
    return null;
  }
}

/** Minimal async sleep used by the FREE device-flow poll loop. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Decode a JWT's `exp` (seconds since epoch) into epoch-ms; `undefined` if it is not parseable. */
function jwtExpMs(jwt: string): number | undefined {
  const parts = jwt.split('.');
  const payloadB64 = parts[1];
  if (parts.length !== 3 || !payloadB64) return undefined;
  try {
    const payload = JSON.parse(
      Buffer.from(payloadB64, 'base64url').toString('utf-8'),
    ) as { exp?: unknown };
    if (typeof payload.exp === 'number' && Number.isFinite(payload.exp)) {
      return payload.exp * 1000;
    }
  } catch {
    /* opaque / non-JWT token — caller falls back to a conservative TTL */
  }
  return undefined;
}

/**
 * A failure surfaced by the SAIHM endpoint or transport. `code` is the endpoint's typed error
 * string when present (e.g. `"BLIND_NO_FREE_TIER"`, `"BLIND_BAD_EXPIRY"`, `"BLIND_STALE_SEQ"`,
 * `"BLIND_SCOPE_UNSUPPORTED"`, `"governance_unavailable"`, `"tenant_erased"`) or a client-side
 * transport code (`"timeout"`, `"network"`, `"response_too_large"`, `"malformed_json"`,
 * `"seq_exhausted"`) or a read-integrity code (`"malformed_envelope"`, `"malformed_response"`,
 * `"foreign_envelope"`, `"cell_mismatch"`, `"stale_cell"`, `"undecryptable"`, `"cell_not_found"`)
 * or a recipient share-read code (`"bad_sharer"`, `"malformed_share"`, `"foreign_share"`,
 * `"share_mismatch"`, `"bad_share_sig"`, `"undecryptable_share"`, `"unverified_envelope"`)
 * or a caller-input code (`"bad_recipient"` — a malformed share recipient record / pinned hash).
 * The message never includes the response body verbatim; branch on `status` / `code`.
 */
export class SaihmEndpointError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | undefined,
    message: string,
  ) {
    super(message);
    this.name = 'SaihmEndpointError';
  }
}

/**
 * A configuration error whose MESSAGE names a value the caller has to go and act on.
 *
 * Use this INSTEAD of `Error` when, and only when, the message embeds a path or URL the operator
 * must open. A config error with nothing actionable in it (`SAIHM_TIER` unset, a hex secret that
 * will not decode) has nothing that truncation can cost the reader and stays a plain `Error`.
 *
 * `valueKind` exists so the RENDERER can widen its fence to fit the embedded value: a path or URL
 * spliced into a sentence is otherwise governed by the sentence's budget. That leaves 59 characters
 * for the path on the branch a first-run operator actually takes -- `selfJoinEnabled()` is
 * `SAIHM_SELF_JOIN !== '0'`, so an operator who never set the variable gets the LONG hint and the
 * 59. The other branch leaves 23 and is reached by opting OUT with `SAIHM_SELF_JOIN=0`. An earlier
 * wording had these two the wrong way round and also blamed the throw SITE for being unguarded:
 * the site is indeed unguarded, but which hint it carries is chosen entirely inside `setupHint()`.
 * That is the same polarity error already recorded as found and fixed twice in this tree. Both
 * numbers are far below a real path. The budget itself is not
 * passed from here — `render_fence.ts` imports this module, so handing it a number would close a
 * cycle. It gets the value's CLASS and keeps the choice of bound where the other bounds live.
 *
 * The value stays IN the message. An earlier cut carried it out to a separate field and dropped it
 * from the message, which regressed a documented library entry point: consumers of `bootFromEnv()`
 * catch these and read `.message`, and `.message` was never the truncated thing — only the render
 * was.
 *
 * `.message` is byte-identical to what these sites threw before at THREE of the four — the invalid
 * `SAIHM_ENDPOINT_URL`, the unreadable `SAIHM_MASTER_SECRET_FILE` and the unreadable self-join
 * identity file. It is NOT at the fourth, and this line used to say it was of all of them.
 * `badSecret` rewrote its own text in the same release, to name the source it actually read instead
 * of blaming `SAIHM_MASTER_SECRET_HEX` for a corrupt file the caller never set — a fix, but a
 * message change, and the two facts were stated as one. The type change and the text change are
 * independent and are disclosed separately in CHANGELOG.md.
 *
 * Not "nothing changes", which was the first wording and is refuted by measurement: `name` goes
 * `Error` -> `SaihmConfigError`, so `String(e)`, the first line of `e.stack`, and `JSON.stringify(e)`
 * all differ. That is the same shape `SaihmEndpointError` already presents on this path, the class is
 * not public API, and nothing in `src/` serialises a caught error — recorded rather than fixed.
 *
 * Extends `Error`, so existing `catch (e) { if (e instanceof Error) … }` code is unaffected.
 * Deliberately NOT re-exported from `index.ts`: it carries no information a consumer cannot already
 * read off `.message`. The reason once given here -- that exporting it "would make this a `feat` and
 * a minor bump" -- is void as of this release, which is a `feat` and a minor bump anyway, on the
 * `e.name` change rather than on any type surface. The decision stands on its own merits: nothing
 * needs the constructor to branch, and `.message` is the contract.
 */
export class SaihmConfigError extends Error {
  constructor(
    message: string,
    /** Class of the actionable value embedded in `message`; selects the render budget. */
    readonly valueKind: 'path' | 'url',
  ) {
    super(message);
    this.name = 'SaihmConfigError';
  }
}

/**
 * Marker for an error whose message NODE wrote and whose text embeds a caller-chosen path.
 *
 * The sweep that produced {@link SaihmConfigError} converted OUR sentences and stopped there. Node
 * writes its own: `EACCES: permission denied, mkdir '<path>'`, and a failed rename carries TWO
 * paths in one message. Those reach the renderer's catch-all arm at the message budget and are cut
 * mid-path — measured on the shipped CLI with a 315-character `SAIHM_HOME`, where the rendered text
 * no longer contained the directory it was naming. The paths are caller-chosen env vars
 * (`SAIHM_HOME`, `SAIHM_SEQ_STATE_PATH`, `SAIHM_RECALL_CACHE_PATH`) — the same ones the
 * sentence-level sites honour.
 *
 * The ORIGINAL error is marked and rethrown rather than replaced by a `SaihmConfigError`. Replacing
 * it would drop `code`, `errno`, `syscall` and `path` off a Node `SystemError`, which is the same
 * shape of consumer regression that splitting the value out of `.message` caused — a caller
 * branching on `e.code === 'EACCES'` would silently stop matching. Nothing observable changes here;
 * only the renderer learns which bound to use.
 *
 * Non-enumerable so it never appears in `JSON.stringify`, a log dump, or a deep-equal in a test.
 */
const PATH_BEARING = Symbol('saihm.pathBearingMessage');

/**
 * Mark `e` and return it UNCHANGED in every other respect. See {@link PATH_BEARING}.
 *
 * `Symbol()` and not `Symbol.for()`: the global registry would let any same-realm code — a
 * compromised dependency — mark an arbitrary error and widen its render. A module-local symbol makes
 * "only errors this package marked" an invariant instead of a convention, at no cost.
 *
 * Never throws - the whole body is guarded, prototype and `in` traps included. `defineProperty`
 * on a frozen, sealed or proxy-denying error would raise a TypeError
 * from inside a `catch`, replacing the failure being reported with one about the reporting — and
 * this function is generic, so a caller can hand it anything. A mark that cannot be applied means
 * the render stays narrow, which is the safe direction.
 */
export function markPathBearing<E>(e: E): E {
  // The WHOLE body is guarded, not only `defineProperty`. `e instanceof Error` runs a
  // `getPrototypeOf` trap and `PATH_BEARING in e` runs a `has` trap, so on a proxy whose traps
  // throw, the throw came from the TEST - outside the old guard - and the "never throws" property
  // documented above was false as written. Nothing marked today is a proxy; these are Node fs
  // errors. But this runs on the failure path, and a fence that can itself throw is not a fence.
  try {
    if (e instanceof Error && !(PATH_BEARING in e)) {
      Object.defineProperty(e, PATH_BEARING, { value: true, enumerable: false });
    }
  } catch {
    /* frozen, sealed, unwritable, or trap-throwing: rendered narrow, never replaced */
  }
  return e;
}

/** True when {@link markPathBearing} tagged this error. Used only to widen the render fence. */
export function isPathBearing(e: unknown): boolean {
  // Same trap exposure. The rationale this comment used to give -- that it matters MORE here,
  // because `failText` exists so a throw cannot take down the server -- was backwards: at its only
  // call site `failText` has already run three UNGUARDED `instanceof` checks against the same
  // object, so a trap-throwing proxy raises there, before this is reached. The guard protects
  // nothing today. It is kept because it is free and correct-direction, and because the reason it
  // is currently redundant lives in another function that may stop being written that way.
  try {
    return e instanceof Error && PATH_BEARING in e;
  } catch {
    return false;
  }
}

/** Read a response body with a hard byte budget — never trusts the content-length header. */
async function readBodyCapped(
  res: Response,
  max: number,
  method: string,
): Promise<string> {
  const tooLarge = (): SaihmEndpointError =>
    new SaihmEndpointError(
      0,
      'response_too_large',
      `SAIHM endpoint ${method} response exceeded ${max}B`,
    );
  const body = res.body;
  if (!body) {
    const t = await res.text();
    if (Buffer.byteLength(t) > max) throw tooLarge();
    return t;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > max) {
        await reader.cancel();
        throw tooLarge();
      }
      chunks.push(value);
    }
  }
  return Buffer.concat(chunks).toString('utf-8');
}

// ── Result shapes (the blind endpoint's JSON; bigint -> decimal string, bytes -> hex) ────────────
/**
 * The receipt for one write. Three of the four fields are LOCAL — {@link SaihmProClient.remember}
 * composes them from the envelope this process sealed, not from the endpoint's response — so the
 * provenance is stated per field below and is not merely a matter of what the endpoint chose to echo.
 */
export interface RememberResult {
  /** OURS: the cell identifier this content was stored under (caller-supplied or client-generated). */
  cellId: string;
  /**
   * THE ENDPOINT'S: opaque storage-shard id (hex). The only field here with no local authority — it
   * names endpoint-side storage — so it is the only one a hostile endpoint can choose. Treat it as
   * display-only and fence it before it reaches an agent's context.
   */
  shardId: string;
  /** OURS: the monotonic per-cell sequence number this write was committed at (decimal string). */
  seq: string;
  /**
   * OURS: sha256(ciphertext) (hex) — the anchorable commitment to the stored bytes, read off the
   * envelope sealed in this process. An endpoint-supplied commitment would commit to nothing.
   */
  commitmentHash: string;
}

export interface RecalledCell {
  cellId: string;
  /** The decrypted plaintext (opened client-side; the endpoint never saw it). */
  plaintext: string;
  /** The committed sequence number of the returned envelope (decimal string). */
  seq: string;
  /**
   * sha256(ciphertext) (hex), RECOMPUTED locally from the opened envelope's ciphertext -- never the
   * endpoint's `publicMeta` echo, which nothing on this path authenticates.
   */
  commitmentHash: string;
}

/**
 * A cell another agent has granted to this one, as ANNOUNCED by the endpoint during a recall.
 *
 * A POINTER, NOT A CELL, and NOT A FACT. The announcement row carries no envelope and no signature —
 * nothing here is authenticated, and a hostile endpoint can fabricate one at will. It is a claim that
 * `sharer` granted `cellId`; only {@link SaihmProClient.recallShared} authenticates that claim, by
 * verifying the share signature against a sharer identity record the caller pinned OUT-OF-BAND. The
 * endpoint holds no identity records and must never vend one, so an announcement can never be resolved
 * from the announcement alone. Never present these as held memories and never auto-resolve them:
 * acting on them unprompted would let the endpoint choose which fetches this client performs.
 */
export interface SharedAnnouncement {
  /** The SHARER's agentIdHash (hex), as claimed by the endpoint. Pin it out-of-band before trusting it. */
  sharer: string;
  /** The shared cell id, as claimed. Collides freely with this agent's own cellIds — they share no namespace. */
  cellId: string;
  /** Grant scope as claimed by the endpoint (e.g. `"read"`). */
  scope: string;
  /**
   * Expiry as CLAIMED by the endpoint: a decimal epoch STRING, or `null` for a grant that never
   * expires — which is the server's DEFAULT, not an edge case. Parse with `BigInt`, never `Number`:
   * the reason is the WIRE TYPE, not magnitude. The endpoint stringifies a bigint, and this field is
   * unauthenticated, so the value is whatever the endpoint sent — `Number` would coerce `null` to 0,
   * `''` to 0 and a non-numeric claim to NaN, each of which reads as a plausible expiry. (An earlier
   * cut of this comment claimed an epoch "overflows exact-integer range". It does not: an MPS epoch
   * is ~5e5 today and gains 1 per hour, some eleven orders of magnitude below MAX_SAFE_INTEGER. The
   * mandate was right, the justification was invented — do not restore it.) Deliberately kept as the
   * raw claimed string and NOT checked to be numeric here — expiry is enforced by the endpoint at
   * resolution time, and rejecting a row on an unauthenticated field would only add a way to hide a
   * live grant. So a conforming endpoint always sends digits, but a hostile one need not: guard the
   * `BigInt` call, or check `/^[0-9]+$/` first. Display hint only; sanitise before rendering.
   */
  expiryEpoch: string | null;
  /** Always `false` — a structural reminder that nothing on this row has been authenticated. */
  verified: false;
}

/**
 * The result of {@link SaihmProClient.recallWithShared}: this agent's own opened cells, plus whatever
 * share announcements the SAME response carried. The two travel together so they can never be
 * cross-attributed between concurrent recalls — see `recallWithShared`.
 */
export interface RecallWithShared {
  /** This agent's own cells, opened and authenticated. Identical to what {@link SaihmProClient.recall} returns. */
  cells: RecalledCell[];
  /** Unauthenticated pointers — read {@link SharedAnnouncement} before surfacing any of these. */
  announcements: SharedAnnouncement[];
  /** `true` when the endpoint announced more than the cap and the list was cut. Surface it: a silently
   *  truncated listing reads as "these are all your grants" when it is not. */
  announcementsTruncated: boolean;
}

export interface ForgetResult {
  cellId: string;
  shardId: string;
  complete: boolean;
  sharesPurged: number;
  steps: ReadonlyArray<{ step: string; success: boolean; detail: string }>;
  epoch: string;
  /**
   * Set by THIS CLIENT, never by the endpoint, when the erasure succeeded but the local plaintext
   * cache could not be purged. `undefined` on every other path. See {@link SaihmProClient.forget}.
   */
  localCacheResidual?: string;
}

export interface StatusSnapshot {
  agentIdHashHex: string;
  tier: string;
  activeShardCount: number;
  activeSharingContracts: number;
  bfsi: number;
  bfsi_R: string;
  bfsi_M: string;
  prsInstrumented: boolean;
  snapshotEpoch: string;
  custody: string;
}

export interface ShareResult {
  cellId: string;
  sharer: string;
  recipient: string;
}

export interface RevokeResult {
  cellId: string;
  recipient: string;
  revoked: boolean;
}

export interface RememberOpts {
  /**
   * Target an EXISTING cell to update it (a new monotonic seq is issued). Omit to create a fresh
   * cell under a random id. When you pass a `cellId` the client has no local high-water mark for
   * (e.g. after a restart with no `SAIHM_SEQ_STATE_PATH`), it first reads the current LIVE envelope
   * to learn the server seq. Note: a cell that was previously `forget`-ten is permanently retired —
   * the endpoint retains its sequence high-water mark for anti-resurrection, so reusing that id
   * surfaces a typed `BLIND_STALE_SEQ` error; choose a fresh id rather than reusing a forgotten one.
   */
  cellId?: string;
}

export interface ShareGrant {
  /** The cell to grant. The client recalls it to obtain the sharer envelope to re-wrap the DEK. */
  cellId: string;
  /** The grantee's identity record (hex), fetched from the directory; verified against the pin. */
  recipientRecord: WireIdentityRecord;
  /** The grantee's agentIdHash (hex), pinned OUT-OF-BAND — defeats directory key substitution. */
  recipientPinnedAgentIdHashHex: string;
  /** Sharing scope; defaults to `"read"`. */
  scope?: 'read' | 'write' | 'readwrite';
  /** Optional expiry as a UNIX-epoch count; omit / null for no time bound. */
  expiryEpoch?: bigint | null;
}

/** Inputs to read a cell that another agent shared TO this agent (see {@link SaihmProClient.recallShared}). */
export interface SharedReadGrant {
  /** The SHARER's agentIdHash (hex), pinned OUT-OF-BAND — the namespace the cell was shared from. */
  sharerPinnedAgentIdHashHex: string;
  /** The SHARER's identity record (hex), from the directory; verified against the pin (anti key-substitution). */
  sharerRecord: WireIdentityRecord;
  /** The shared cell id to read. */
  cellId: string;
}

export interface SaihmProClientOpts {
  /**
   * The caller's billing tier baked into each cell's (signed) public metadata. Best-effort label
   * only — billing is authoritative from the JWT at the endpoint. If omitted, the client resolves
   * the authoritative tier once via `status()` and caches it, so the metadata stays truthful.
   */
  tier?: string;
  /** Path to persist per-cell seq high-water marks (mode 600). Enables cross-restart cell updates. */
  seqStatePath?: string;
  /**
   * Persist sequence marks to a DEFAULT path when `seqStatePath` is not given.
   *
   * Off unless asked for, and that asymmetry is deliberate. `bootFromEnv` turns it on because the
   * MCP server is the surface the rollback guard protects and `~/.saihm` is already its home - the
   * identity key is written there. A caller who constructs this class DIRECTLY gets nothing written
   * anywhere: a library that touches `$HOME` as a side effect of a constructor is intrusive, it
   * makes an embedder's tests order-dependent through a file they never named, and it silently
   * changes what a second client in one process observes. Available to library callers who do want
   * the guard, by asking for it.
   */
  persistSeqState?: boolean;
  /**
   * Path to persist this agent's opened cells (mode 600), keyed by cellId. When set, `recall`
   * switches to DELTA mode: it sends the cached cellIds to the endpoint and fetches only cells it
   * does not already hold, cutting a session-start recall from O(all cells) to O(new cells). Holds
   * plaintext at rest, so it is opt-in (unset = full recall-all every call, the prior behavior).
   * Requires an endpoint that supports delta recall; degrades gracefully to a
   * full recall if the endpoint does not support it.
   */
  recallCachePath?: string;
  /**
   * The proof-of-entitlement rail (`"stripe"`, `"stablecoin"`, …) used when SELF-ONBOARDING (i.e.
   * no static `authHeader`). Sent in the `/api/onboard` request alongside the ML-DSA-signed nonce.
   * Required for self-onboarding; ignored when a static `authHeader` is supplied.
   */
  paymentMethod?: string;
  /**
   * Optional discovery-attribution tag naming the channel this install came from
   * (e.g. `"glama"`, `"mcp-registry"`). Sent as `source` in the `/api/onboard` body so
   * the operator can attribute a paid conversion to its origin (referrer is not
   * available for CLI/registry installs). Free-form; the endpoint sanitises it.
   */
  discoverySource?: string;
  /**
   * Override the base origin used for self-onboarding requests (`/api/onboard/challenge`,
   * `/api/onboard`). Defaults to the origin of `SAIHM_ENDPOINT_URL`. Advanced / testing knob.
   */
  onboardBaseUrl?: string;
  /**
   * Per-request timeout budget in milliseconds (default 30000). A request that exceeds it is aborted
   * and surfaces a typed `SaihmEndpointError(408, "timeout")`. An advanced / testing tuning knob — a
   * non-positive or non-numeric value falls back to the default.
   */
  requestTimeoutMs?: number;
  /**
   * FREE tier only: an advisory callback invoked as lifetime usage approaches (80/95%) or reaches
   * (100%) the FREE quota for a call type, so a host can nudge the user to upgrade BEFORE the hard cap.
   * It NEVER blocks or fails a call (a throwing callback is swallowed) and fires at most once per
   * (callType, threshold). Paid tiers never invoke it. See {@link QuotaNag}.
   */
  onQuotaNag?: (nag: QuotaNag) => void;
}

/** The human-facing device-flow prompt surfaced by {@link SaihmProClient.acquireFreeEntitlement}. */
export interface FreeDevicePrompt {
  /** The short code the human types at `verificationUri` (e.g. `WDJB-MJHT`). */
  userCode: string;
  /** The URL the human opens in a browser to enter `userCode` (e.g. `https://github.com/login/device`). */
  verificationUri: string;
  /** Seconds until the device/user code expires and the flow must be restarted. */
  expiresIn: number;
}

/** Options for {@link SaihmProClient.acquireFreeEntitlement}. */
export interface FreeEntitlementOpts {
  /**
   * OAuth provider slug the operator's bridge is configured for (default `"github"`). The provider's
   * OAuth client_id lives SERVER-SIDE only; the device flow runs on the bridge and this client never
   * sees or holds the provider access token — it stays server-ephemeral (device flow, not token reuse).
   */
  provider?: string;
  /**
   * Invoked ONCE with the device-flow prompt: display `userCode` and have the human open
   * `verificationUri` in a browser and enter it. This is what makes FREE onboarding headless — no
   * redirect URI, no browser automation, works from a CLI / MCP host.
   */
  onPrompt: (prompt: FreeDevicePrompt) => void;
  /** Overall wall-clock budget (ms) to wait for authorization. Defaults to the flow's `expiresIn`. */
  timeoutMs?: number;
  /**
   * Override the client->bridge claim poll cadence (ms). Advanced / testing knob; defaults to the
   * bridge-advertised `interval`, else {@link FREE_ONBOARD_POLL_MS}. Non-positive values are ignored.
   */
  pollIntervalMs?: number;
}

/** Result of a successful {@link SaihmProClient.acquireFreeEntitlement}. */
export interface FreeEntitlementResult {
  /** This client's sovereign agent id (hex) the durable FREE entitlement was bound to. */
  agentIdHash: string;
}

/**
 * Self-join flag. When enabled, the pro server exposes the `saihm_join` bootstrap tool and
 * this client will (a) self-generate + persist an identity on the first join and (b) re-load
 * that persisted identity on a plain restart with no env secret.
 *
 * Default ON. A fresh install otherwise has no in-band way to start the free trial: every
 * other path requires the operator to hand-generate a >= 64 hex-char master secret first,
 * which an autonomous agent cannot do for itself. Set `SAIHM_SELF_JOIN=0` to opt out, which
 * restores the previous behaviour — `saihm_join` is not registered and every self-join path
 * below is inert.
 */
export function selfJoinEnabled(): boolean {
  return process.env.SAIHM_SELF_JOIN !== '0';
}

/** Default on-disk location of a self-generated FREE identity (written mode 600). */
export function defaultIdentityPath(): string {
  const home = process.env.SAIHM_HOME || pathJoin(homedir(), '.saihm');
  return pathJoin(home, 'free-identity.key');
}

/**
 * Where the sequence high-water marks live when the operator has not named a file.
 *
 * Derived from `defaultIdentityPath()` — the FUNCTION, not a copy of the chain it reads — because
 * these two files must move together or not at all. Sequence state is IDENTITY-scoped: it records
 * what one identity has seen. If it relocated while the identity stayed put, the guard would restart
 * from zero, silently, which is the same disarming a torn read causes.
 *
 * Deliberately NOT `SAIHM_STATE_DIR`. That knob exists for state a caller may relocate freely, and
 * `defaultIdentityPath` already refuses it for the stated reason that honouring it would move an
 * EXISTING identity file out from under its owner. The same reasoning binds here.
 *
 * SCOPED BY IDENTITY, because the on-disk shape is a flat `{cellId: …}` map with no identity in it,
 * while `load()` stamps every entry it reads with THIS identity's hash. Two identities sharing one
 * home — reachable today by pointing `SAIHM_MASTER_SECRET_FILE` elsewhere while `SAIHM_HOME` stays
 * default — would inherit each other's marks, and the higher one would refuse the other's legitimate
 * reads as `stale_cell` permanently. Unreachable while nothing was persisted by default; naming this
 * file is what would arm it. The hash is already rendered to the operator's own terminal, so it
 * discloses nothing to anyone who could not already read the key file beside it.
 */
export function defaultSeqStatePath(agentIdHashHex: string): string {
  return pathJoin(dirname(defaultIdentityPath()), `seq.${agentIdHashHex.slice(0, 16)}.json`);
}

/**
 * The key FILE this process would boot from, or `null` when the secret is INLINE and there is no
 * file to name.
 *
 * ONE resolution, because there were two and they disagreed. Every line that tells an operator what
 * to back up has to answer the same question, and `runJoin` answered it by not asking: it printed
 * `Keep SAIHM_MASTER_SECRET_HEX safe` unconditionally, so a caller whose key is in a FILE - every
 * `saihm_join` user with a generated `free-identity.key` who later subscribes - was sent to an env
 * var that does not exist and never told the file that does. `runFreeJoin` had been fixed for
 * exactly that 60 lines away in the same module; the fix landed in one of the two copies.
 *
 * The precedence MIRRORS `bootFromEnv`: an explicit FILE wins, an inline HEX means there is no file,
 * and otherwise the self-join default is used if it is enabled and the file is already there. It
 * does not CREATE anything - naming a key to back up must not mint one as a side effect.
 */
export function identityKeyFile(): string | null {
  if (process.env.SAIHM_MASTER_SECRET_FILE) return process.env.SAIHM_MASTER_SECRET_FILE;
  if (process.env.SAIHM_MASTER_SECRET_HEX) return null;
  if (selfJoinEnabled()) {
    const p = defaultIdentityPath();
    if (existsSync(p)) return p;
  }
  return null;
}

/**
 * Ensure an identity secret is available to {@link SaihmProClient.bootFromEnv} for a self-join,
 * WITHOUT ever returning or printing the secret. If an env secret (HEX or FILE) is already
 * configured it is left untouched. Otherwise the default key file is used — read if present, else
 * freshly generated (32 bytes CSPRNG) and written atomically at mode 600. `SAIHM_MASTER_SECRET_FILE`
 * and (only if unset) `SAIHM_TIER=FREE` are set so the very next bootFromEnv self-onboards this
 * identity FREE. The master secret is the ONLY key to the memory and is never logged — only its path.
 */
export function ensureSelfJoinIdentityEnv(): { created: boolean; keyPath: string | null } {
  if (process.env.SAIHM_MASTER_SECRET_FILE) {
    return { created: false, keyPath: process.env.SAIHM_MASTER_SECRET_FILE };
  }
  if (process.env.SAIHM_MASTER_SECRET_HEX) {
    // NULL, not a sentinel. This returned the STRING `(SAIHM_MASTER_SECRET_HEX)` in a field named
    // and typed as a path, and all three render sites duly rendered it as one: `Back up
    // (SAIHM_MASTER_SECRET_HEX)`, `Using your existing memory key ((SAIHM_MASTER_SECRET_HEX))`, and
    // `key file: (SAIHM_MASTER_SECRET_HEX)`. Reproduced, all three. That is this release's own defect
    // class one level up - a value of one kind rendered in a slot built for another - and each of
    // those sites already carried a correct branch for the inline-secret case which could never run,
    // because a sentinel is truthy. There is no file on this path. The type now says so, and every
    // caller has to answer for it rather than inherit a plausible-looking string.
    return { created: false, keyPath: null };
  }
  const keyPath = defaultIdentityPath();
  let created = false;
  if (!existsSync(keyPath)) {
    try {
      const secretHex = randomBytes(32).toString('hex');
      mkdirSync(dirname(keyPath), { recursive: true, mode: 0o700 });
      const tmp = `${keyPath}.tmp.${process.pid}.${Date.now()}`;
      writeFileSync(tmp, secretHex, { mode: 0o600, flag: 'wx' });
      try {
        renameSync(tmp, keyPath); // atomic; inherits the tmp file's 0600 mode
      } catch (e) {
        // The tmp already holds the full contents. Nothing in this package sweeps stale tmp files, and
        // no later purge reaches one: `forget()` and a delta recall both rewrite `<path>`, which the tmp
        // is not. So a failed rename used to leave THE MASTER SECRET sitting beside the file
        // the operator was told to check, permanently. Unlinked here because `wx` above proves THIS
        // process created it — an exact name, never a glob, so another process's in-flight tmp is never
        // touched. A kill between the write and the rename still leaves one; that is inherent to
        // tmp-then-rename and is not what this closes.
        try {
          unlinkSync(tmp);
        } catch {
          /* never created, or already gone */
        }
        throw e;
      }
      created = true;
    } catch (e) {
      // Node named `keyPath` (or the tmp beside it) in its own message; widen the fence for it.
      throw markPathBearing(e);
    }
  } else {
    // EXISTS BUT HOLDS NOTHING, which `existsSync` alone reads as "already provisioned". The file
    // was then handed to boot as `SAIHM_MASTER_SECRET_FILE` - set on the line below, by this
    // function, not by the caller - and boot failed with `SAIHM_MASTER_SECRET_FILE is set but
    // holds no secret`, naming a variable the operator had never set. Every retry repeated it:
    // `existsSync` stays true, so nothing regenerates, and the one verb that could fix it is the
    // one looping. 0.4.1 looped too, but its text was honest about what it had read.
    //
    // Not regenerated, deliberately. This package writes this file with `wx` and an atomic
    // rename, so it is never left empty by a failed write here - an empty one came from somewhere
    // else, a restore or a `touch`, and minting a fresh identity over it would be the silent
    // switch to a different identity that the configured-but-empty error exists to prevent. So it
    // is an error, named against the file it actually read, and it says what clears it.
    let holdsSecret = false;
    try {
      holdsSecret = readFileSync(keyPath, 'utf-8').trim().length > 0;
    } catch (e) {
      // SYMMETRY with the empty-file arm below, which is the other outcome of THIS SAME read. That
      // one names the file and says what clears it; this one used to re-throw Node's errno, so an
      // unreadable identity surfaced as `EACCES: permission denied, open '<path>'` with no
      // attribution and no remedy - and under `EISDIR`, whose message carries no path at all, not
      // even the file. 0.4.1 had no read here: the failure reached `bootFromEnv`, which wrapped it.
      // Moving the read forward moved it out from behind that wrapper, so the wrapper is restored
      // here. The changelog's stated remedy for this whole class is "match on the VARIABLE NAME",
      // which a bare errno cannot satisfy for any consumer.
      throw new SaihmConfigError(
        `the self-join identity file could not be read: ${keyPath} ` +
          `(${(e as NodeJS.ErrnoException).code ?? 'unknown'}). Fix its permissions, or restore ` +
          'your backup of it - deleting it and running the join again mints a NEW identity, which ' +
          'starts an EMPTY memory.',
        'path',
      );
    }
    if (!holdsSecret)
      throw new SaihmConfigError(
        `the self-join identity file holds no secret: ${keyPath}. Restore your backup of it, or ` +
          'delete it and run the join again to mint a new identity - which starts an EMPTY memory, ' +
          'so restore first if you have a backup.',
        'path',
      );
  }
  process.env.SAIHM_MASTER_SECRET_FILE = keyPath;
  if (!process.env.SAIHM_TIER) process.env.SAIHM_TIER = 'FREE';
  return { created, keyPath };
}

/**
 * An advisory FREE-tier usage nag surfaced via {@link SaihmProClientOpts.onQuotaNag} as lifetime usage
 * approaches (80/95%) or reaches (100%) the FREE quota for a call type. It NEVER blocks a call and is
 * fired at most once per (callType, threshold) for the life of the client. FREE tier only.
 */
export interface QuotaNag {
  /** The metered call type this nag is about: `"remember"`, `"recall"`, `"forget"`, or `"sharing"`. */
  callType: string;
  /** The crossed threshold as a percent of the lifetime quota (80, 95, or 100). */
  threshold: QuotaNagThreshold;
  /** True when the hard cap is reached (threshold 100): the NEXT such call is rejected until upgrade. */
  atHardCap: boolean;
  /** Lifetime usage of `callType` after the triggering call; `null` when the surface carried no counter. */
  used: bigint | null;
  /** The FREE lifetime quota for `callType`; `null` when the surface carried no counter. */
  limit: bigint | null;
  /** `used / limit` in [0,1]; `1` at the hard cap. `null` when the counters were unavailable. */
  fraction: number | null;
  /** A ready-to-show upgrade call-to-action (no pricing). See {@link UPGRADE_HINT}. */
  upgradeHint: string;
}

// ── per-cell seq high-water store (in-memory rule from @saihm/client-pro, optional file mirror) ──
class SeqState {
  private readonly hwm = new SeqHighWaterMark();
  private readonly cellIds = new Set<string>();
  // The commitment hash of the envelope observed AT the current high-water seq, per cellId.
  // Monotonic seq alone cannot close rollback, because a seq can legitimately repeat: `remember`
  // advances the mark only after the endpoint accepts the write, so a write the endpoint COMMITS
  // whose response is lost leaves the mark unadvanced and the next write reuses that seq. Two
  // validly-signed envelopes then exist at one (cellId, seq), and a `<`-only guard admits both --
  // measured: the endpoint served two different plaintexts at the same seq, alternately, with no
  // error. Pinning the commitment makes the pair distinguishable, which the sequence number alone
  // never can be. Tightening the guard to `<=` instead would be wrong: it rejects every legitimate
  // re-read of the cell at its current seq.
  private readonly commitments = new Map<string, string>();

  /**
   * Cells whose LIVE seq this process has actually seen, as opposed to cells we merely hold a mark
   * for. Populated only by `observe`, whose two call sites are both authenticated observations of
   * the endpoint's current state; never by `load`, which reads a file.
   *
   * The distinction did not exist while marks were in-memory only, because then "we hold a mark"
   * and "we observed it live" were the same set. Persisting marks split them, and `remember`'s
   * discovery gate was written against the old equality: `current(cellId) === undefined` meant
   * never-observed. With a mark on disk it means nothing of the kind, and the gate stopped firing
   * on exactly the case it exists for -- a mark that is BEHIND the endpoint. That happens on one
   * machine, with no second writer: `remember` advances the mark only after the endpoint accepts,
   * so a COMMITTED write whose response was lost leaves the mark one short. Before marks persisted,
   * a restart cleared it and the next `remember` re-seeded from the live envelope. Now the stale
   * mark survives the restart, the gate sees it, and the re-seed never happens -- so the client
   * writes at a seq the endpoint has already committed. That is the equivocating pair `stale_cell`
   * exists to detect, manufactured locally.
   */
  private readonly observedLive = new Set<string>();

  /**
   * The file backing these marks, or `undefined` once persistence has been given up on.
   *
   * Not `readonly`: a write that fails DEGRADES this to in-memory rather than propagating. `remember`
   * calls `observe` after the endpoint has already ACCEPTED the write, so throwing here would report
   * a stored cell as a failed one — the exact outcome `RecallCache` refuses in the same words. The
   * reason is kept so the degradation is answerable rather than silent.
   */
  private path: string | undefined;
  /**
   * Why persistence stopped, or `null` while it is working. Surfaced by `saihm_status`.
   *
   * A short TOKEN - `unwritable(EACCES)`, `unparseable` - not a sentence. It is rendered through
   * `safeScalar`, whose budget is `MAX_SCALAR_CHARS`, so a sentence would arrive at the operator cut
   * off mid-clause and look like a bug in the client rather than a report about their filesystem.
   * The prose that explains what to do about it belongs in the README, which has room for it.
   */
  private degradedReason: string | null = null;

  /**
   * Did the READ at construction fail for a reason other than the file being absent? See
   * {@link persisting}, which is the only reader - this is not a second degradation, it is the
   * knowledge that the first write will not survive, available before that write is attempted.
   */
  private loadReadFailed = false;

  /**
   * Did the OPERATOR name this file, or did we choose it?
   *
   * The distinction decides what a failed write means, and the two answers are genuinely different
   * events. A path someone set in their config and cannot be written is a CONFIGURATION ERROR, and
   * swallowing it hides their mistake behind a security guard that quietly stopped working. A path
   * we defaulted to and cannot write is OUR problem, and failing `remember` over it would break a
   * write the endpoint has already accepted - on a read-only or containerised `$HOME` that would
   * be every write, forever, for a file the operator never asked for.
   *
   * Not a split by install age, which is invisible and untestable. A split by whether someone asked.
   */
  private readonly pathIsExplicit: boolean;

  constructor(
    private readonly agentIdHashHex: string,
    explicitPath?: string,
    allowDefault = false,
  ) {
    // An explicit path keeps its meaning exactly. Only the DEFAULT is derived and identity-scoped,
    // and only when the caller asked for a default at all - see `persistSeqState`.
    this.pathIsExplicit = explicitPath !== undefined;
    this.path =
      explicitPath ?? (allowDefault ? defaultSeqStatePath(agentIdHashHex) : undefined);
    if (this.path !== undefined) this.load();
  }

  /** `null` when marks are persisting normally; otherwise why they are not. */
  get degraded(): string | null {
    return this.degradedReason;
  }

  /**
   * Are marks still reaching disk? NOT the negation of `degraded`, and that is the whole point.
   *
   * `unparseable` is a degradation persistence SURVIVES: the file could not be read as JSON, so this
   * run started with no marks, but the very next write rebuilds it. MEASURED: after an unparseable
   * file, the mark reached disk and `degraded` still said `unparseable`. `unreadable` and
   * `unwritable` are the opposite - `path` is given up on and nothing more is written.
   */
  get persisting(): boolean {
    if (this.path === undefined) return false;
    // A READ that failed at load is not a state persistence survives either, even though `path` is
    // still set and no write has been attempted yet. `saihm_status` performs no write, so this is
    // the window an operator actually looks at, and reporting `persisting` in it tells them the
    // safeguard is intact when the very next write is what disproves it.
    //
    // The coupling that makes this sound, named because a future edit could break it silently:
    // every code that reaches here also fails the WRITE. `flushMarks` fails closed on EACCES, EPERM
    // and EIO, so those never reach disk; its benign set is exactly ENOENT, EISDIR and ENOTDIR, and
    // ENOENT does not get here at all while the other two fail later anyway - EISDIR at the rename
    // onto a directory, ENOTDIR at the `mkdirSync`. If a code is ever added to that benign set which
    // a write can survive, this getter stops being true and has to be derived rather than flagged.
    return !this.loadReadFailed;
  }

  /**
   * A persisted mark, or `null` if the entry is not one.
   *
   * ONE function, called from both `load` and `flushMarks`, because those carried copies of this
   * parse and the copies had already drifted from the one at `parseDecimalBig` - same parse, same
   * file, 700 lines apart, and only that one bounded its input before handing it to `BigInt`.
   * Duplicating a guard is how one copy comes to lack it; this release fixed `share` for exactly
   * that, and these two sites are the same shape.
   *
   * Two rejections, and only ONE of them can change an outcome. `MAX_SEQ` is the wire uint64
   * ceiling - 20 digits - and the regex above forbids leading zeros, so every value the
   * `MAX_COUNTER_CHARS` cap rejects is necessarily above the ceiling too. The cap therefore bounds
   * WORK, not results: it stops `BigInt` from converting a megabyte of digits before the ceiling
   * refuses them. Stated because a mutation that deletes the cap SURVIVES, and a surviving mutant
   * with no explanation beside it reads as a hole in the tests rather than as subsumption. It is
   * kept as defence-in-depth behind a guard that IS pinned, and matching `parseDecimalBig`, which
   * bounds the identical parse the same way.
   *
   * The ceiling is not a bound but a definition. A seq above it cannot
   * have come from a valid envelope, because `decodeEnvelope` parses seq as u64 - so it is not a
   * mark that is too big, it is not a mark. Admitting one is worse than dropping it, and silently:
   * `next()` returns MAX_SEQ+1, every subsequent write to that cell is refused as `seq_exhausted`,
   * and nothing anywhere says the cause is a number in a local file. Dropping it costs one re-seed
   * from the live envelope, which is the state a cold client already occupies.
   */
  private static parseMark(v: unknown): bigint | null {
    const t = typeof v === 'string' ? v : (v as { seq?: unknown })?.seq;
    if (typeof t !== 'string' || t.length > MAX_COUNTER_CHARS) return null;
    if (!/^(?:0|[1-9][0-9]*)$/.test(t)) return null;
    const n = BigInt(t);
    return n > MAX_SEQ ? null : n;
  }

  private load(): void {
    let raw: string;
    try {
      raw = readFileSync(this.path!, 'utf-8');
    } catch (e) {
      // ABSENT is normal and silent: a first run, a new venue, or a file the operator deleted to
      // reset this device's view. The client re-seeds from the LIVE envelope on first touch, and
      // that path AEAD-authenticates the seq before trusting it. Anything ELSE — a permission
      // failure, a directory where the file should be — is a read we could not perform, and
      // reporting it as "first run" is how a guard disarms without anyone noticing.
      if ((e as NodeJS.ErrnoException)?.code !== 'ENOENT') {
        this.degradedReason = `unreadable(${(e as NodeJS.ErrnoException)?.code ?? 'unknown'})`;
        this.loadReadFailed = true;
      }
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      // Present but unparseable — a torn write, or another tool's file. Marks start empty, which is
      // recoverable, but it is NOT the same event as a first run and must not be reported as one.
      this.degradedReason = 'unparseable';
      return;
    }
    // VALID JSON IS NOT A MARKS FILE. `null`, `[]`, `7` and `"x"` all parse, and `Object.entries`
    // THROWS on the first of them -- from the CONSTRUCTOR, outside the try above, so it does not
    // degrade: it takes down `getClient()`, and every SAIHM tool then fails with `Cannot convert
    // undefined or null to object`, which names nothing the operator can act on. `RecallCache.load`
    // has carried this exact check since it was written; this sibling did not, and a one-line file
    // containing `null` was the whole distance between the two.
    //
    // Its own token, not `unparseable`. The file WAS readable and WAS valid JSON, so an operator
    // told `unparseable` goes looking for a torn write and finds well-formed content. Handled the
    // same way, reported as the different thing it is - the split this class already makes between
    // absent, unreadable and unparseable, one shape further along.
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      this.degradedReason = 'malformed';
      return;
    }
    const obj = parsed as Record<string, unknown>;
    for (const [cellId, v] of Object.entries(obj)) {
      // NO `__proto__` SKIP HERE, deliberately, and this is the reverse of what it looks like.
      // Every consumer of a cellId on this path is prototype-safe already: `hwm` keys a Map,
      // `commitments` is a Map, `cellIds` is a Set, and `flushMarks` writes onto a NULL-PROTOTYPE
      // object. `JSON.parse` creates `__proto__` with CreateDataProperty, so it arrives here as an
      // own property - data - and reaches none of those as a setter.
      //
      // Skipping it therefore protected nothing and cost the mark: the write side stored such a key
      // faithfully and the read side dropped it, so a cell named `__proto__` reset to seq zero on
      // every restart -- the silent loss the skip claimed to prevent, caused by the skip. `cellId`
      // is caller-supplied through `RememberOpts`, so a client that names one is not exotic.
      //
      // The null prototype in `flushMarks` is what makes this safe, and it is the ONLY thing that
      // does. If that object ever becomes a plain `{}`, this skip has to come back on both sides.
      // Two accepted shapes. A bare decimal string is the LEGACY form, written before commitments
      // were pinned; it loads with no commitment, so the first envelope observed at that seq pins
      // one. Refusing to load it would regress every existing agent's whole sequence state to zero
      // -- a far worse outcome than an unpinned first read, which is the state a cold start is in
      // anyway. `{seq, commitmentHash}` is the current form.
      const seq = SeqState.parseMark(v);
      if (seq === null) continue;
      if (this.hwm.admit(this.agentIdHashHex, cellId, seq)) this.cellIds.add(cellId);
      // A commitment found in the file is READ PAST, deliberately, and this is the whole of the
      // decision recorded at the top of `persist`. A pinned commitment is only sound while one
      // writer owns the mark. Two sessions of the same identity - two Claude Code windows, a
      // laptop and a desktop - can both hold a cell at seq N, both write N+1, and both seal
      // DIFFERENT content there, because a write whose response was lost leaves the mark
      // unadvanced and the next write reuses the seq. Restoring one of those pins from disk would
      // make the other session's honest envelope permanently unreadable. Pins are therefore
      // established only from envelopes THIS process observed, and they expire with it.
    }
  }

  /**
   * Depth-tracked so a nested `withBatch` does not flush the outer one early, and a flag for whether
   * anything asked to persist while it was set.
   */
  private batching = false;
  private pendingFlush = false;

  /**
   * Run `fn` with persistence COALESCED: at most one file write, at the end, however many marks
   * advance inside.
   *
   * `flushMarks` rewrites the WHOLE file - read, parse, merge, stringify, write, rename - and
   * `observe` called it once per ADVANCING mark. A cold recall observes every cell, so a recall of
   * n cells performed n whole-file rewrites of a file that is itself O(n): quadratic, on the first
   * operation this package recommends anyone run. The bound is the claim, and it is read off the
   * code rather than measured: no timing is quoted here, because a timing describes one fixture on
   * one filesystem and rots where the shape does not.
   *
   * Scoped and synchronous rather than debounced. A microtask or timer would move the flush outside
   * the call, where a throw on an operator-named path is an UNCAUGHT exception instead of an error
   * out of the method that caused it - trading a slow write for a dead process. Everything here
   * still happens inside the caller's frame, so the explicit-path policy in `persist` is unchanged.
   *
   * Wrapped around `openRecallRows`, the one place that opens many rows in a loop; every other
   * caller advances a single mark and already costs a single write. Forgetting to wrap a future loop
   * costs the OLD behaviour - slower, never wrong - which is the failure direction to choose when a
   * guard has to be applied by its caller rather than called.
   *
   * SYNCHRONOUS BODIES ONLY, and unenforced because the failure is benign in the same direction. An
   * `async` body returns a promise, the batch closes before the awaited work runs, and the marks
   * that work observes persist one at a time - the pre-batch cost, with nothing lost. Stated so the
   * next author does not read this as `await`-aware and build something on that, not guarded,
   * because a throw would turn a slow path into a broken one.
   */
  withBatch<T>(fn: () => T): T {
    const outer = this.batching;
    this.batching = true;
    let out: T;
    try {
      out = fn();
    } catch (e) {
      // NOT FLUSHED HERE, and the marks are not lost by that. `pendingFlush` stays set, and
      // `flushMarks` writes every cellId this process holds rather than only the newly-advanced one,
      // so the next persisting operation writes them along with its own.
      //
      // The alternative was a best-effort flush in this catch, which is where it started. Two things
      // ruled it out and only one is about style. A marks-file error raised from here would REPLACE
      // the error being reported - a `502 malformed_response` arriving as `EACCES` - so it would have
      // to be swallowed; and a swallowed call plus a marked-rethrow call makes `flushPending` a
      // method the render-fence sweep cannot classify, since that sweep decides per METHOD whether a
      // persist-reaching call is wrapped or swallowed. Bending the instrument to fit this shape would
      // have bought a flush on a path where the endpoint controls whether we ever saw the envelope
      // in the first place - so the marks it would preserve are ones a hostile endpoint could simply
      // have withheld. Worth less than the guard.
      this.batching = outer;
      throw e;
    }
    this.batching = outer;
    // The body SUCCEEDED, so a persist failure is this call's only failure and propagates exactly as
    // it would have from the unbatched write it replaced.
    //
    // MARKED, and this is the half of the batch that is easy to get wrong. Deferring the write moved
    // it OUT of the `markPathBearing` wrappers that sit at the two `observe` call sites, so an
    // operator-named seq path failing during a recall would have reached `failText` unmarked and had
    // the directory Node named cut to fit the narrow budget - the exact defect the `remember` arm has
    // a test for. The render-fence sweep found it; no behavioural test here would have.
    if (!outer) {
      try {
        this.flushPending();
      } catch (e) {
        throw markPathBearing(e);
      }
    }
    return out;
  }

  private flushPending(): void {
    if (!this.pendingFlush) return;
    this.pendingFlush = false;
    this.persist();
  }

  /** Monotonic within the process, so two writes in one millisecond cannot claim one tmp name. */
  private static tmpCounter = 0;

  /**
   * Marks a failure that came from READING the file we were about to merge, not from writing it.
   *
   * `persist` labels the degradation from where its catch sits, and that catch sits on the write. So
   * a file whose own mode is 000, in a perfectly writable directory, reported `unwritable(EACCES)` -
   * measured - and sent the operator to check the wrong thing. Naming the failure from the catch
   * site rather than from the failure is the same defect this release is named for, one level down.
   */
  private static readonly READ_FAILED = Symbol('saihm.seqReadFailed');

  /**
   * SEQ ONLY, never the commitment. See the note in `load`: a persisted commitment is sound only
   * while a single writer owns the mark, and two sessions of one identity legitimately collide at a
   * seq. The high-water mark carries no such hazard - it moves in one direction, so a mark seen
   * anywhere is a floor everywhere and is safe to carry across every venue an identity is used from.
   * That asymmetry is the entire reason only half of this state reaches disk.
   */
  private persist(): void {
    if (this.path === undefined) return;
    // Inside a batch this is a NOTE, not a write. See `withBatch`.
    if (this.batching) {
      this.pendingFlush = true;
      return;
    }
    try {
      this.flushMarks(this.path);
    } catch (e) {
      // AN EXPLICIT PATH STILL THROWS. The operator named this file; that it cannot be written is a
      // fact about their configuration and it is theirs to see, carried up through `markPathBearing`
      // so the directory Node named survives the message budget whole.
      if (this.pathIsExplicit) throw e;
      // A DEFAULTED path never propagates. `observe` runs from `remember` AFTER the endpoint has
      // accepted the write, so throwing would report a stored cell as a failed one - the outcome
      // `RecallCache.upsert` refuses in as many words. Marks stay correct in memory; only their
      // survival across a restart is lost, and a cold client re-seeds from the live envelope anyway.
      // Given up on for the rest of the run rather than retried: a directory unwritable now is
      // unwritable a millisecond later, and a failing syscall per write costs more than the
      // guarantee is worth. A restart re-attempts.
      this.path = undefined;
      // WHAT failed, not where it was caught. A read failure and a write failure send an operator to
      // different files with different fixes, and only one of them is the directory.
      let how = 'unwritable';
      try {
        if (typeof e === 'object' && e !== null && SeqState.READ_FAILED in e) how = 'unreadable';
      } catch {
        /* same proxy reasoning as the tag site; fall back to the write label */
      }
      this.degradedReason = `${how}(${(e as NodeJS.ErrnoException)?.code ?? 'unknown'})`;
    }
  }

  /**
   * Named `flushMarks`, not `write`: the render sweep recognises render surfaces by `.write(` on a
   * stream, and `this.write(...)` landed in its list of writes reaching a stream it cannot identify.
   * That sweep is right to report it, and the cheaper answer is a name rather than an exception
   * carved into a check that exists to catch exactly the thing an exception would hide.
   */
  private flushMarks(path: string): void {
    // NULL PROTOTYPE. `obj[cellId] = …` on a `{}` sends a cellId of `__proto__` to an inherited
    // setter: no own property is created, `JSON.stringify` omits it, and that cell's mark vanishes
    // with no error anywhere. `cellId` is caller-supplied through `RememberOpts` and the schema
    // admitting it is a bare string.
    const obj: Record<string, { seq: string }> = Object.create(null) as Record<string, { seq: string }>;
    // MERGE, do not overwrite. This is a whole-file rewrite with no lock, and one identity can sit
    // behind several processes - two editor windows, a terminal beside them. Each holds only the
    // cells IT has touched, so a plain write drops every mark the other owns and hands back the
    // sequence space this file exists to defend. The per-cell MAXIMUM keeps both views, and a
    // maximum is the correct merge because the mark is monotonic by construction.
    //
    // Read-then-rename is still not atomic: a write landing between them is lost. That is a lost
    // mark, not a corrupt one - the next touch of that cell re-seeds from the live envelope over the
    // AEAD-authenticated path - so the worst case degrades to the state a cold client already
    // occupies. That is the strongest claim available without a lock file, and it is stated rather
    // than dressed up as atomicity.
    //
    // THE READ AND THE PARSE ARE SEPARATE FAILURES and were one. `absent or unreadable - either way
    // this process's own view is the whole of what we know` was false for the second half: absent
    // means there is nothing to merge, UNREADABLE means marks may be sitting there perfectly intact
    // and we cannot see them. Swallowing both wrote this session's cells over a file we never read.
    // MEASURED before this guard: a mode-000 file holding `{old_a:7, old_b:9}` in a WRITABLE
    // directory came back as `{fresh_cell:1}` - two anti-rollback marks destroyed, silently, while
    // `degraded` dutifully reported `unreadable(EACCES)`. Reporting a read failure and then
    // performing the write is a guard reporting its own damage. That is B4's compaction arriving
    // through the one branch the merge does not cover.
    let onDisk: Record<string, unknown> = {};
    let diskRaw: string | undefined;
    try {
      diskRaw = readFileSync(path, 'utf-8');
    } catch (e) {
      // THE BENIGN SET IS "THERE ARE NO MARKS OF OURS HERE TO LOSE", not "the read succeeded".
      // ENOENT - nothing at this path. EISDIR - a directory, which is not a marks file. ENOTDIR - a
      // component is not a directory, so our file cannot exist. None of the three can be hiding
      // marks, so writing over them destroys nothing, which is the entire property this guard
      // defends. EACCES, EPERM and EIO are the opposite case: the file may be sitting there intact
      // and unreadable, and those FAIL CLOSED.
      //
      // BOTH EXCEPTIONS ARE THERE BECAUSE OMITTING THEM BROKE SOMETHING MEASURABLE, and each is
      // pinned by a sibling test rather than by argument.
      //
      // EISDIR: the test proving a failed rename leaves no tmp behind arranges its failure by making
      // the path a DIRECTORY. Without this, the read refused first, no tmp was ever created, and the
      // rename guard was never exercised. Its own positive control caught it - "nothing was created
      // in this directory, so the empty strays below prove nothing" - which is what a control is for.
      // A guard that makes an existing test vacuous has narrowed the code under test, not hardened it.
      //
      // ENOTDIR: this read sits AHEAD of the `mkdirSync` below, so without this exception an
      // unmakeable directory was reported as `ENOTDIR ... open '<dir>/seq.json'` - an `open` naming
      // the FILE - where the operator needs `mkdir` naming the DIRECTORY they have to go and fix.
      // Letting it fall through is what keeps that diagnosis with the syscall that owns it. Pinned
      // by the test that asserts Node names the directory; drop `ENOTDIR` here and that test fails.
      // Reordering the two calls also fixes it, and was tried - but no test can tell the orderings
      // apart once this exception exists, so the exception is the guard and the order is not.
      //
      // Failing closed here means THROWING, handed to `persist`, whose policy already splits an
      // operator-named path (throw - their configuration, their problem to see) from a defaulted one
      // (degrade to memory, never break an accepted write). Deciding it here would duplicate that
      // split, which is the defect `share` was fixed for one commit earlier.
      const code = (e as NodeJS.ErrnoException)?.code;
      if (code !== 'ENOENT' && code !== 'EISDIR' && code !== 'ENOTDIR') {
        // Guarded like `markPathBearing`, and for its stated reason: a fence on the failure path
        // that can itself throw is not a fence. Nothing reaching here today is a proxy - these are
        // Node fs errors - but the tag is best-effort and the original error is rethrown either way.
        try {
          if (typeof e === 'object' && e !== null)
            Object.defineProperty(e, SeqState.READ_FAILED, { value: true, enumerable: false });
        } catch {
          /* frozen, sealed, or a hostile trap - the throw below is what matters */
        }
        throw e;
      }
    }
    if (diskRaw !== undefined) {
      try {
        const parsed: unknown = JSON.parse(diskRaw);
        // Same shape check as `load`, for the same reason and a different reach: here
        // `Object.entries(null)` throws out of `flushMarks` into `persist`, which on an explicit
        // path rethrows -- so a file holding `null` would fail every `remember` instead of failing
        // one constructor. Not merged and not preserved: a non-object holds no marks, so rewriting
        // it loses nothing that could ever have been read back.
        if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed))
          onDisk = parsed as Record<string, unknown>;
      } catch {
        // Present but UNPARSEABLE is genuinely different from unreadable: there are no marks to
        // preserve, so rewriting loses nothing that could ever have been read back. Not merged, not
        // thrown - and distinguished from the read failure above rather than sharing its catch.
      }
    }
    // Read without naming properties, deliberately: this is the shape written by a DIFFERENT
    // process, possibly an older build, so the readable shapes are exactly the two `load` accepts and
    // nothing here may assume a field exists. Nothing read here reaches a renderer - every value is
    // either discarded by the digit test below or becomes a decimal seq string this file wrote.
    for (const [cellId, v] of Object.entries(onDisk)) {
      // No prototype skip - see `load`. `onDisk` came from `JSON.parse` (own properties) and `obj`
      // below has a null prototype, so these keys are data at both ends of this merge.
      const seq = SeqState.parseMark(v);
      // Written back in canonical decimal rather than echoed. Every accepted form already IS
      // canonical (the regex refuses leading zeros), so this normalises nothing today and cannot
      // widen what is written if the accepted set ever grows.
      if (seq !== null) obj[cellId] = { seq: seq.toString(10) };
    }
    for (const cellId of this.cellIds) {
      const c = this.hwm.current(this.agentIdHashHex, cellId);
      if (c === undefined) continue;
      const prior = obj[cellId];
      if (prior === undefined || BigInt(prior.seq) < c) obj[cellId] = { seq: c.toString(10) };
    }
    // The counter is load-bearing, not decoration. `wx` REFUSES an existing path, and pid+ms alone
    // repeats whenever two marks advance inside one millisecond - which `recall` does routinely,
    // observing a row per cell. That collision used to throw out of `remember`; it would now trip
    // the degradation above and quietly stop persisting for the rest of the run, so the failure
    // would have MOVED rather than gone.
    // `mode` applies ONLY when the directory is CREATED - an existing one keeps its own permissions,
    // so this hardens the path we make and never re-permissions a shared one. Pinned rather than
    // left to the umask: under a umask of 0 the default is 0777.
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const tmp = `${path}.tmp.${process.pid}.${Date.now()}.${SeqState.tmpCounter++}`;
    writeFileSync(tmp, JSON.stringify(obj), { mode: 0o600, flag: 'wx' });
    try {
      renameSync(tmp, path); // atomic; inherits the tmp file's 0600 mode
    } catch (e) {
      // The tmp already holds the full contents. Nothing in this package sweeps stale tmp files, and
      // no later purge reaches one: `forget()` and a delta recall both rewrite `<path>`, which the tmp
      // is not. So a failed rename used to leave this agent’s whole sequence state sitting beside the file
      // the operator was told to check, permanently. Unlinked here because `wx` above proves THIS
      // process created it — an exact name, never a glob, so another process's in-flight tmp is never
      // touched. A kill between the write and the rename still leaves one; that is inherent to
      // tmp-then-rename and is not what this closes.
      try {
        unlinkSync(tmp);
      } catch {
        /* never created, or already gone */
      }
      throw e;
    }
  }

  current(cellId: string): bigint | undefined {
    return this.hwm.current(this.agentIdHashHex, cellId);
  }

  /** Has THIS process observed the endpoint's seq for `cellId`? See {@link observedLive}. */
  observedLiveThisRun(cellId: string): boolean {
    return this.observedLive.has(cellId);
  }

  /** The commitment pinned AT the current high-water seq, if one has been observed. */
  currentCommitment(cellId: string): string | undefined {
    return this.commitments.get(cellId);
  }

  /** Seed / advance the high-water mark to a server-observed value (monotonic; persists on change).
   *  `commitmentHash` belongs to the envelope carrying `seq` and is pinned with it. It is recorded
   *  only when the mark actually ADVANCES, so a re-read at the current seq can never overwrite the
   *  pin with a second, equivocating envelope's hash -- which would hand the endpoint the very
   *  substitution this pin exists to detect. */
  observe(cellId: string, seq: bigint, commitmentHash?: string): void {
    // Recorded whether or not the mark ADVANCES, and the two reasons are different. `admit` refuses
    // `seq === held` as well as `seq < held` (`acceptSeq` accepts strictly greater), so "did the mark
    // advance" is the wrong question here: a re-read AT the seq we hold is a real observation of the
    // endpoint's position, which is the whole question the discovery gate asks.
    //
    // BELOW the mark is the case that would NOT be, and it cannot arrive. A response under the floor
    // is what a REPLAYED older envelope looks like, and AEAD cannot tell the difference -- it proves
    // the envelope is genuinely ours at that seq, never that it is the CURRENT one. Recording one
    // would satisfy the gate, the next write would skip the live read and go out at `mark + 1`, and
    // against an endpoint further along that is a second envelope at a seq already committed.
    //
    // THE COUPLING THAT MAKES THIS UNCONDITIONAL RECORD SOUND, named because it lives in another
    // method and a future edit could break it silently: both call sites already guarantee
    // `seq >= held`. `openRow` throws `stale_cell` on `env.seq < knownSeq` BEFORE it reaches here,
    // and `remember` observes only after the endpoint accepted a write at `next()`, which is
    // `current + 1`. Weaken the read-path rollback guard and this line stops being safe -- the test
    // named for a replayed envelope below the mark is the one that says so.
    this.observedLive.add(cellId);
    if (this.hwm.admit(this.agentIdHashHex, cellId, seq)) {
      this.cellIds.add(cellId);
      if (commitmentHash !== undefined) this.commitments.set(cellId, commitmentHash);
      else this.commitments.delete(cellId);
      this.persist();
    }
  }

  /** The next seq to use for `cellId` = current high-water + 1 (1 for a never-seen cell). */
  next(cellId: string): bigint {
    return (this.current(cellId) ?? 0n) + 1n;
  }
}

// ── recall delta cache (dark; active only when a recallCachePath is configured) ──────────────────
// Persists this agent's OPENED cells keyed by cellId so a session start can ask the endpoint for
// only NEW cells (delta) instead of a full recall-all fan-out. Holds plaintext ⇒ written mode 600
// (same posture as the seq store) and opt-in by config, never on by default. A corrupt/absent file
// is treated as a cold start — the next recall repopulates it from a full or delta response.
//
// SELF-WRITE COHERENCE: a delta recall SKIPS cellIds the client already holds, so a client's own
// in-place UPDATE (remember with an existing cellId) or fresh create would be invisible to its next
// recall. remember() and forget() therefore update this cache directly (upsert / remove), keeping a
// client coherent with its OWN writes. A different client/session sharing the same cache path would
// not observe that update until it re-reads the cell — the same single-writer contract the seq store
// already carries; document + serialize same-cell writes across clients if you need both to land.
class RecallCache {
  private cells = new Map<string, RecalledCell>();
  // Bumped by every mutation that actually changed something. A recall snapshots this BEFORE its
  // network call and re-checks it after: a response is only allowed to rewrite the cache if no local
  // write landed while it was in flight. Without that check a response captured before a `forget`
  // resurrects the cell it erased, and one captured before a `remember` deletes the cell it wrote —
  // both silently, both defeating the self-write coherence this class exists to provide. A plain
  // counter is enough because the only question asked of it is "did anything change", never "what".
  private mutations = 0;
  constructor(private readonly path?: string) {
    if (this.path) this.load();
  }

  get configured(): boolean {
    return this.path !== undefined;
  }

  /** Monotonic mutation count — see `mutations`. Snapshot before an await, compare after. */
  get version(): number {
    return this.mutations;
  }

  /** Where the cache lives, for a residual message that tells the operator what to go and check. */
  get cachePath(): string | undefined {
    return this.path;
  }

  private load(): void {
    let raw: string;
    try {
      raw = readFileSync(this.path!, 'utf-8');
    } catch {
      return; // no cache yet — cold start
    }
    let obj: unknown;
    try {
      obj = JSON.parse(raw);
    } catch {
      return; // corrupt/empty — cold start (a full recall will rebuild it)
    }
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return;
    for (const [cellId, v] of Object.entries(obj as Record<string, unknown>)) {
      const c = v as Partial<RecalledCell>;
      if (
        c !== null &&
        typeof c === 'object' &&
        typeof c.plaintext === 'string' &&
        typeof c.seq === 'string' &&
        typeof c.commitmentHash === 'string'
      ) {
        this.cells.set(cellId, { cellId, plaintext: c.plaintext, seq: c.seq, commitmentHash: c.commitmentHash });
      }
    }
  }

  private persist(): void {
    if (this.path === undefined) return;
    const obj: Record<string, RecalledCell> = {};
    for (const [id, c] of this.cells) obj[id] = c;
    // `mode` applies ONLY when the directory is CREATED — an existing one keeps its own
    // permissions, so this hardens the path we make and never re-permissions a shared one.
    // Pinned rather than left to the umask, matching the identity writer above: under a
    // umask of 0 the default is 0777, and this directory holds cell plaintext at rest.
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.tmp.${process.pid}.${Date.now()}`;
    writeFileSync(tmp, JSON.stringify(obj), { mode: 0o600, flag: 'wx' });
    try {
      renameSync(tmp, this.path); // atomic; inherits the tmp file's 0600 mode
    } catch (e) {
      // The tmp already holds the full contents. Nothing in this package sweeps stale tmp files, and
      // no later purge reaches one: `forget()` and a delta recall both rewrite `<path>`, which the tmp
      // is not. So a failed rename used to leave EVERY CACHED CELL’S PLAINTEXT sitting beside the file
      // the operator was told to check, permanently. Unlinked here because `wx` above proves THIS
      // process created it — an exact name, never a glob, so another process's in-flight tmp is never
      // touched. A kill between the write and the rename still leaves one; that is inherent to
      // tmp-then-rename and is not what this closes.
      try {
        unlinkSync(tmp);
      } catch {
        /* never created, or already gone */
      }
      throw e;
    }
  }

  knownCellIds(): string[] {
    return [...this.cells.keys()];
  }

  all(): RecalledCell[] {
    return [...this.cells.values()];
  }

  /** Merge a delta `added` set and prune to the endpoint's authoritative live cellId set. Persists
   *  only when something actually changed, so a no-op delta recall (nothing added, nothing forgotten)
   *  does not rewrite the whole cache file each session start. */
  merge(added: RecalledCell[], liveCellIds: string[]): void {
    const live = new Set(liveCellIds);
    let changed = false;
    for (const id of [...this.cells.keys()])
      if (!live.has(id)) {
        this.cells.delete(id); // prune forgotten
        changed = true;
      }
    for (const c of added) {
      this.cells.set(c.cellId, c);
      changed = true;
    }
    if (changed) {
      this.mutations++;
      this.persist();
    }
  }

  /** Replace the whole cache from a full recall result, then persist. */
  replaceAll(cells: RecalledCell[]): void {
    this.cells = new Map(cells.map((c) => [c.cellId, c]));
    this.mutations++;
    this.persist();
  }

  /** Insert/replace one cell the client itself just wrote (create or update), then persist. No-op
   *  when the cache is disabled. Keeps a self-written update visible to the next delta recall, which
   *  would otherwise skip a cellId the client already holds. */
  upsert(cell: RecalledCell): void {
    if (this.path === undefined) return;
    this.cells.set(cell.cellId, cell);
    this.mutations++;
    this.persist();
  }

  /** Drop one cell the client just forgot, then persist. Prevents the cache from serving a cell the
   *  endpoint has crypto-shredded (delta would not re-list it, so it must be removed here). */
  remove(cellId: string): void {
    if (this.path === undefined) return;
    if (this.cells.delete(cellId)) {
      this.mutations++;
      this.persist();
    }
  }
}

export class SaihmProClient {
  private readonly endpoint: string;
  /** A static Authorization header (e.g. `"Bearer <JWT>"`), or `undefined` in self-onboard mode. */
  private readonly staticAuthHeader: string | undefined;
  /** Self-onboard only: the proof-of-entitlement rail sent to `/api/onboard`. */
  private readonly paymentMethod: string | undefined;
  /** WS-J discovery-attribution tag sent as `source` on self-onboard (optional). */
  private readonly discoverySource: string | undefined;
  /** Base origin for `/api/onboard*` + `/api/stripe/*` calls (defaults to the endpoint origin). */
  private readonly onboardBase: string;
  private readonly identity: ClientIdentity;
  private readonly agentIdHashHex: string;
  private readonly seq: SeqState;
  private readonly recallCache: RecallCache;
  private readonly requestTimeoutMs: number;
  private tier: string | undefined;
  // Self-onboard token cache (single-flight via authInFlight; never written to disk).
  private cachedJwt: string | undefined;
  private cachedJwtRefreshAtMs = 0;
  private authInFlight: Promise<string> | null = null;
  /** FREE-tier upgrade-nag callback (advisory; paid never fires it). */
  private readonly onQuotaNag: ((nag: QuotaNag) => void) | undefined;
  /** `${callType}:${threshold}` keys already nagged, so each nag fires at most once per client. */
  private readonly firedNagKeys = new Set<string>();

  constructor(
    endpoint: string,
    authHeader: string | undefined,
    masterSecret: Uint8Array,
    opts: SaihmProClientOpts = {},
  ) {
    assertEndpointUrl(endpoint);
    this.endpoint = endpoint;
    // deriveIdentity derives the KEK + ML-DSA/ML-KEM keys and does NOT retain `masterSecret`.
    this.identity = deriveIdentity(masterSecret);
    this.agentIdHashHex = toHex(this.identity.agentIdHash);
    this.tier = opts.tier;
    this.onQuotaNag = opts.onQuotaNag;
    this.discoverySource = opts.discoverySource;
    this.seq = new SeqState(
      this.agentIdHashHex,
      opts.seqStatePath,
      opts.persistSeqState === true,
    );
    this.recallCache = new RecallCache(opts.recallCachePath);
    this.requestTimeoutMs =
      typeof opts.requestTimeoutMs === 'number' && opts.requestTimeoutMs > 0
        ? opts.requestTimeoutMs
        : REQUEST_TIMEOUT_MS;

    // Base for /api/onboard* + /api/stripe/* — always available (the `join` flow + self-onboard need it).
    this.onboardBase = (
      opts.onboardBaseUrl ?? new URL(endpoint).origin
    ).replace(/\/+$/, '');

    const trimmedAuth =
      typeof authHeader === 'string' && authHeader.trim()
        ? authHeader
        : undefined;
    if (trimmedAuth) {
      this.staticAuthHeader = trimmedAuth;
    } else {
      // SELF-ONBOARD MODE: mint + auto-refresh the JWT from this identity. Requires the tier (it is
      // part of the onboard request). PAID tiers also require a payment method (the entitlement rail
      // the endpoint checks). The FREE tier carries NO payment: its entitlement is proven ONCE, out of
      // band, via `acquireFreeEntitlement` (bridge-proxied OAuth device flow) and bound to this sovereign
      // key; thereafter /api/onboard mints FREE JWTs with no paymentMethod and the same refresh loop runs.
      if (this.tier !== 'FREE' && !opts.paymentMethod) {
        throw new Error(
          'self-onboarding requires a paymentMethod (set SAIHM_PAYMENT_METHOD) when no auth header is supplied',
        );
      }
      if (this.tier === undefined) {
        throw new Error(
          'self-onboarding requires a tier (set SAIHM_TIER) when no auth header is supplied',
        );
      }
      this.paymentMethod = opts.paymentMethod;
    }
  }

  static bootFromEnv(): SaihmProClient {
    // Unset => the hosted operator declared as this var's default in server.json.
    // Explicitly empty is still a configuration error, not an opt-in to the default.
    const endpoint =
      process.env.SAIHM_ENDPOINT_URL === undefined
        ? DEFAULT_ENDPOINT
        : process.env.SAIHM_ENDPOINT_URL;
    const auth = process.env.SAIHM_AUTH_HEADER;
    if (!endpoint)
      throw new Error('SAIHM_ENDPOINT_URL is set but empty.' + setupHint());
    // Validate here, not only in the constructor: boot can throw on a missing
    // identity long before a client is ever constructed, which silently masked a
    // malformed or plain-http endpoint behind the join hint. The endpoint is
    // never contacted either way, so this is a diagnostic fix — it reports the
    // misconfiguration the operator actually has.
    assertEndpointUrl(endpoint);
    // The master secret may be supplied inline via SAIHM_MASTER_SECRET_HEX, or — preferably for
    // operators / security-conscious users — as the path to a mode-600 file via
    // SAIHM_MASTER_SECRET_FILE so the root seed is never inlined into a synced/shared MCP config.
    // FILE wins when both are set.
    const secretFile = process.env.SAIHM_MASTER_SECRET_FILE;
    // CONFIGURED, not merely non-empty - the distinction `SAIHM_ENDPOINT_URL` above already makes
    // ("explicitly empty is still a configuration error, not an opt-in to the default") and this
    // did not. The self-join fallback was guarded by `!secretHex`, which conflates "no secret was
    // configured" with "the configured secret is empty", so a ZERO-BYTE SAIHM_MASTER_SECRET_FILE
    // fell through to the default identity: the process booted a DIFFERENT key while every backup
    // line - and `identityKeyFile()` with it - named the file the operator had configured.
    // Reproduced end to end: `identityKeyFile()` reported the empty file while `bootFromEnv()`
    // returned the default file's identity, so the only key to that memory was never named.
    //
    // TRUTHINESS, not `!== undefined`. The first cut of this used `!== undefined` and so treated an
    // EMPTY variable as "configured" while the read gate below tests truthiness and never opens it:
    // `SAIHM_MASTER_SECRET_FILE=""` then hard-failed with "holds no secret: " and nothing after the
    // colon, where 0.4.1 self-joined. `server.json` declares that variable optional with
    // `format: filepath` and no default, so a blank field in a registry install UI emits exactly
    // that - a real deployment shape, broken for no security gain. An empty variable is not
    // POINTING at a secret; a variable naming an empty FILE is, and that is the case this guard
    // exists for.
    //
    // Deliberately unlike `SAIHM_ENDPOINT_URL` above, where empty IS an error: that has no safe
    // fallback to fall to, and this does.
    const secretConfigured = Boolean(
      process.env.SAIHM_MASTER_SECRET_FILE || process.env.SAIHM_MASTER_SECRET_HEX,
    );
    let secretHex: string | undefined;
    if (secretFile) {
      // A WHITESPACE-ONLY value is named as one rather than printed. `SAIHM_MASTER_SECRET_FILE=" "`
      // is truthy, so it reached the read and failed with `could not be read:  .` - a diagnostic
      // whose whole subject is invisible in it, and one an operator cannot tell from a bug. It is
      // not quoted to make it visible: wrapping a value in delimiters hands it an escape. The
      // CONDITION is stated instead, which needs no value at all. (This once said the value is
      // "rendered downstream inside a fenced `label=value` line". It is not - it reaches
      // `configErrorText` and lands as standalone text; `safePathField` does not scrub `=` and no
      // site of its own is a labelled line. The reasoning above holds on delimiters alone.)
      if (secretFile.trim().length === 0)
        throw new SaihmConfigError(
          'SAIHM_MASTER_SECRET_FILE is set to a whitespace-only value, which is not a path. Unset ' +
            'it to start free, or point it at your key file.' + setupHint(),
          'path',
        );
      try {
        secretHex = readFileSync(secretFile, 'utf-8');
      } catch {
        throw new SaihmConfigError(
          `SAIHM_MASTER_SECRET_FILE could not be read: ${secretFile}.` +
            setupHint(),
          'path',
        );
      }
      try {
        // Advisory only (never blocks): warn if the secret file is group/world-accessible on POSIX.
        if (
          process.platform !== 'win32' &&
          (statSync(secretFile).mode & 0o077) !== 0
        ) {
          // FENCED, not deleted. An earlier cut dropped the path entirely on the theory that this
          // file cannot import the fence - `render_fence.ts` imports from here, and `safePathField`
          // is an `export const`, so the reverse edge was called a TDZ fault. MEASURED FALSE: an ESM
          // cycle only faults on a binding read during module EVALUATION, and every `client.ts`
          // symbol `render_fence.ts` uses is read inside a function body, so the cycle resolves
          // under both entry orders. Deleting the path also broke this advisory's own contract - its
          // test is named "never leaking the secret", meaning it names the FILE and withholds the
          // KEY - and cost a log consumer information it had. stderr is a human-read surface, the
          // operator's terminal under the CLI paths, so the value is fenced like any other path.
          process.stderr.write(
            `warning: SAIHM_MASTER_SECRET_FILE ${safePathField(secretFile, MAX_PATH_FIELD_CHARS)} ` +
              'is group/world-accessible; chmod 600 it.\n',
          );
        }
      } catch {
        /* stat is advisory only */
      }
    } else {
      secretHex = process.env.SAIHM_MASTER_SECRET_HEX;
    }
    // Self-join fallback (ON by default; `SAIHM_SELF_JOIN=0` opts out): a prior `saihm_join`
    // persists the self-generated identity to the default key file, so a plain restart with no
    // env secret re-loads it. Under `SAIHM_SELF_JOIN=0` this block is inert.
    // This read "SAIHM_SELF_JOIN=1 only ... Off by default => this block is inert and boot
    // behaviour is unchanged" and was false: `selfJoinEnabled()` is `!== '0'` (measured across
    // unset/''/'1'/'anything' => true, '0' => false). The identical sentence was already found
    // and corrected in server.ts:833-835 and never propagated to this second
    // copy — the same fix-one-of-N-sites defect the shardId resolve-twice mutation exposed.
    if (!secretConfigured && selfJoinEnabled()) {
      const p = defaultIdentityPath();
      if (existsSync(p)) {
        try {
          secretHex = readFileSync(p, 'utf-8');
        } catch {
          throw new SaihmConfigError(
            `self-join identity file could not be read: ${p}.` + setupHint(),
            'path',
          );
        }
      }
    }
    if (!secretHex) {
      // A CONFIGURED secret that is empty is a configuration error, and it is named as one. Sending
      // this caller to `saihm_join` would be the wrong direction twice over: they did configure a
      // secret, and joining would mint a SECOND identity while the empty file sat there looking
      // like the key to the first.
      //
      // ONE BRANCH, not two. This carried an `SAIHM_MASTER_SECRET_HEX is set but empty.` arm that
      // cannot run: `secretConfigured` is deliberately TRUTHINESS-based for the reason given
      // above, so an empty `SAIHM_MASTER_SECRET_HEX` is not configured, and a non-empty one makes
      // `!secretHex` false. Proved dead by mutation - nineteen boot cases, zero hits. It also
      // typed itself `valueKind: 'path'` while carrying no path, which would have widened the
      // render to a path budget for a message naming only a variable. (That mistyping is the
      // whole objection - NOT that a path-less message may never be a `SaihmConfigError`. The
      // live whitespace-only-`SAIHM_MASTER_SECRET_FILE` throw ~70 lines above names no path and
      // is deliberately `'path'`-typed, because its remedy does not fit in 256 characters. The
      // reason to delete this branch is that it is DEAD, not that its type is forbidden.) A dead branch is not
      // free: it made the compatibility note about a "configured but EMPTY secret" read as though
      // it covered an empty VARIABLE, which it never did - only a zero-byte FILE.
      if (secretConfigured && secretFile !== undefined)
        throw new SaihmConfigError(
          `SAIHM_MASTER_SECRET_FILE is set but holds no secret: ${secretFile}.` + setupHint(),
          'path',
        );
      // Self-join enabled but no identity yet => guide the agent to the join tool rather than
      // surfacing a raw env-var error (a memory tool was called before `saihm_join`).
      if (selfJoinEnabled())
        throw new Error(
          'No SAIHM memory yet on this device. Ask me to "Join SAIHM" first (the saihm_join tool) to create your free memory, then try again.',
        );
      throw new Error(
        'SAIHM_MASTER_SECRET_HEX (or SAIHM_MASTER_SECRET_FILE) env var required (>= 64 hex chars).' +
          setupHint(),
      );
    }
    // WHERE THE SECRET CAME FROM, because both checks below used to name
    // `SAIHM_MASTER_SECRET_HEX` whatever the source was. Measured: with no env var set at all and a
    // corrupt `free-identity.key`, boot said "SAIHM_MASTER_SECRET_HEX must be canonical lowercase
    // hex" - naming a variable the operator never set, about a file it never named, on the one
    // error whose whole job is to say what to go and fix. That is this release's defect class in a
    // sentence: the value is actionable and it is the wrong one.
    //
    // `secretFile` MAY HAVE BEEN SET BY US. `ensureSelfJoinIdentityEnv` writes the minted key path
    // into `SAIHM_MASTER_SECRET_FILE` so the boot below can read it, and after that this branch
    // could no longer tell a file the operator configured from one we configured for them. It named
    // the variable on precisely the two entry points that mint FIRST - the `free-join` verb and the
    // `saihm_join` tool - which are the paths a caller reaches by following the advice this very
    // message's `setupHint` gives them. Same file, same session, two different variable names, and
    // the one they were shown is absent from their config, from `server.json` and from the install
    // UI. Comparing against `defaultIdentityPath()` rather than tracking a flag: both sides call the
    // same function, so they cannot disagree, and an operator who points the variable AT the
    // self-join file is told the truth either way.
    const selfJoinIdentity = defaultIdentityPath();
    const secretSource: { label: string; kind: 'path' | 'env' } = secretFile
      ? secretFile === selfJoinIdentity
        ? { label: `the self-join identity file ${secretFile}`, kind: 'path' }
        : { label: `SAIHM_MASTER_SECRET_FILE ${secretFile}`, kind: 'path' }
      : process.env.SAIHM_MASTER_SECRET_HEX
        ? { label: 'SAIHM_MASTER_SECRET_HEX', kind: 'env' }
        : { label: `the self-join identity file ${selfJoinIdentity}`, kind: 'path' };
    const badSecret = (why: string): Error =>
      secretSource.kind === 'path'
        ? new SaihmConfigError(`${secretSource.label} ${why}.` + setupHint(), 'path')
        : new Error(`${secretSource.label} ${why}.` + setupHint());
    let master: Uint8Array;
    try {
      master = fromHex(secretHex.trim());
    } catch {
      throw badSecret('must hold canonical lowercase hex');
    }
    if (master.length < 32) {
      master.fill(0);
      throw badSecret('must decode to >= 32 bytes');
    }
    const optTier =
      process.env.SAIHM_TIER ?? (selfJoinEnabled() ? 'FREE' : undefined);
    const optSeqPath = process.env.SAIHM_SEQ_STATE_PATH;
    const optRecallCachePath = process.env.SAIHM_RECALL_CACHE_PATH;
    const optPaymentMethod = process.env.SAIHM_PAYMENT_METHOD;
    const optDiscoverySource = process.env.SAIHM_DISCOVERY_SOURCE;
    const opts: SaihmProClientOpts = {};
    if (optTier) opts.tier = optTier;
    if (optSeqPath) opts.seqStatePath = optSeqPath;
    // THE SERVER OPTS IN. This is the boot path of the MCP server, where the rollback guard is worth
    // having across restarts and where `~/.saihm` already holds this identity's key. Constructing
    // `SaihmProClient` directly does not reach here and writes nothing.
    opts.persistSeqState = true;
    if (optRecallCachePath) opts.recallCachePath = optRecallCachePath;
    if (optPaymentMethod) opts.paymentMethod = optPaymentMethod;
    if (optDiscoverySource) opts.discoverySource = optDiscoverySource;
    // SAIHM_AUTH_HEADER is OPTIONAL. Unset => self-onboard from SAIHM_MASTER_SECRET_HEX +
    // SAIHM_PAYMENT_METHOD + SAIHM_TIER (paste-once). Set => used verbatim, no self-onboarding.
    try {
      return new SaihmProClient(endpoint, auth, master, opts);
    } finally {
      master.fill(0); // scrub the decoded master secret; the identity holds only derived material
    }
  }

  /** This client's public agent identifier (hex) = sha256(ML-DSA pubkey) = the JWT sub. */
  get agentIdHash(): string {
    return this.agentIdHashHex;
  }

  /**
   * `null` while sequence marks are persisting; otherwise a short token saying why they are not.
   *
   * Reported because the alternative is a security control that stops working without saying so.
   * When this is non-null the rollback guard still holds for the life of THIS process and no longer
   * survives a restart, which is a real reduction the operator is entitled to see. It is LOCAL - it
   * describes this machine's filesystem, never anything the endpoint said.
   */
  get seqStateDegraded(): string | null {
    return this.seq.degraded;
  }

  /**
   * True while sequence marks are still reaching disk. Read WITH `seqStateDegraded`, never inferred
   * from it: a degradation is not the same event as persistence stopping, and reporting a run as
   * memory-only while its marks are demonstrably on disk is a false statement in a security line.
   * A warning that is sometimes false is one a reader learns to skip, which costs the cases where it
   * is true - the concern the status renderer states in its own words directly above that line.
   */
  get seqStatePersisting(): boolean {
    return this.seq.persisting;
  }

  /** This client's PUBLIC identity record (hex) to publish so others can share TO this agent. */
  get identityRecord(): WireIdentityRecord {
    return encodeIdentityRecord(this.identity.identityRecord);
  }

  /**
   * Resolve the Authorization header for a request. In static-auth mode this is the configured
   * header. In self-onboard mode it returns a cached JWT, transparently minting/refreshing one
   * (single-flight) when none is cached or it is within 60s of expiry.
   */
  private async currentAuthHeader(): Promise<string> {
    if (this.staticAuthHeader) return this.staticAuthHeader;
    if (this.cachedJwt && Date.now() < this.cachedJwtRefreshAtMs) {
      return 'Bearer ' + this.cachedJwt;
    }
    if (!this.authInFlight) {
      this.authInFlight = this.onboard().finally(() => {
        this.authInFlight = null;
      });
    }
    return 'Bearer ' + (await this.authInFlight);
  }

  /**
   * Mint a fresh subscriber JWT: GET a challenge nonce, sign it with this identity's ML-DSA secret
   * key, and POST {pubkey, nonce, signature, tier, paymentMethod} to `/api/onboard`. The endpoint
   * verifies the signature + an active subscription and returns a short-lived JWT, which is cached
   * with its decoded expiry. The master secret / secret key never leave this process.
   */
  private async onboard(): Promise<string> {
    const base = this.onboardBase;
    const ch = await this.onboardFetch<{ nonce?: unknown }>(
      base + '/api/onboard/challenge',
      { method: 'GET' },
    );
    const nonce = ch.nonce;
    if (typeof nonce !== 'string' || nonce.length === 0) {
      throw new SaihmEndpointError(
        502,
        'onboard_no_nonce',
        'onboard challenge returned no nonce',
      );
    }
    let nonceBytes: Uint8Array;
    try {
      nonceBytes = fromHex(nonce);
    } catch {
      throw new SaihmEndpointError(
        502,
        'onboard_bad_nonce',
        'onboard challenge nonce is not hex',
      );
    }
    const signature = toHex(
      signChallenge(this.identity.mldsaSecretKey, nonceBytes),
    );
    const out = await this.onboardFetch<{ jwt?: unknown }>(
      base + '/api/onboard',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          pubkey: toHex(this.identity.mldsaPubKey),
          nonce,
          signature,
          tier: this.tier,
          paymentMethod: this.paymentMethod,
          ...(this.discoverySource ? { source: this.discoverySource } : {}),
        }),
      },
    );
    if (typeof out.jwt !== 'string' || out.jwt.length === 0) {
      throw new SaihmEndpointError(
        502,
        'onboard_no_jwt',
        'onboard did not return a JWT',
      );
    }
    this.cachedJwt = out.jwt;
    // Schedule proactive refresh BEFORE expiry. Honor the token's own `exp`; for an opaque token assume
    // a short conservative TTL. Clamp the skew to at most half the remaining life so a short-lived token
    // still yields a positive cache window (otherwise we would re-onboard on every single call).
    const now = Date.now();
    const expMs = jwtExpMs(out.jwt) ?? now + OPAQUE_TOKEN_TTL_MS;
    const skew = Math.min(
      JWT_REFRESH_SKEW_MS,
      Math.max(0, Math.floor((expMs - now) / 2)),
    );
    this.cachedJwtRefreshAtMs = expMs - skew;
    return out.jwt;
  }

  /**
   * Self-serve operator join: request a Stripe HOSTED-checkout URL to subscribe THIS identity at the
   * configured tier (`SAIHM_TIER`). Open the URL in a browser to pay; afterwards the client
   * self-onboards on the next run. Only the PUBLIC key is sent; the master secret never leaves here.
   */
  async requestCheckoutUrl(): Promise<string> {
    if (this.tier === undefined) {
      throw new SaihmEndpointError(
        0,
        'no_tier',
        'join requires a tier (set SAIHM_TIER)',
      );
    }
    return this.checkoutUrlForTier(this.tier);
  }

  /**
   * FREE -> monthly-PRO upgrade: request a Stripe HOSTED-checkout URL to subscribe THIS SAME sovereign
   * identity to a paid MONTHLY tier (default `PRO`). The upgrade attaches billing to the SAME ML-DSA key,
   * so `agentIdHash` is unchanged and every existing memory persists — no migration, no re-onboard. After
   * payment, reconfigure `SAIHM_TIER`/`SAIHM_PAYMENT_METHOD` for the paid tier and the ordinary refresh
   * loop mints paid JWTs. This is the FREE->paid door: it requires `SAIHM_TIER=FREE` (an already-paid
   * identity uses {@link requestCheckoutUrl}) and refuses anything but a monthly subscription tier.
   * Only the PUBLIC key is sent; the master secret never leaves here.
   */
  async requestUpgradeUrl(targetTier: string = 'PRO'): Promise<string> {
    if (this.tier !== 'FREE') {
      throw new SaihmEndpointError(
        0,
        'not_free_tier',
        'requestUpgradeUrl is the FREE->paid upgrade path (set SAIHM_TIER=FREE); a paid identity uses requestCheckoutUrl',
      );
    }
    const target = targetTier.trim();
    if (!MONTHLY_PAID_TIERS.has(target)) {
      throw new SaihmEndpointError(
        0,
        'bad_upgrade_tier',
        `upgrade target must be a monthly paid tier (${[...MONTHLY_PAID_TIERS].join(', ')}); got '${targetTier}'`,
      );
    }
    return this.checkoutUrlForTier(target);
  }

  /**
   * Shared checkout-URL request for a given billing `tier`, bound to THIS identity. Proof-of-possession:
   * `/api/stripe/checkout` requires a fresh server nonce signed by THIS identity's ML-DSA secret key (the
   * same gate `/api/onboard` uses), proving we hold the private key for the `mldsaPubKey` we send —
   * without it the route 401s. Underpins both {@link requestCheckoutUrl} and {@link requestUpgradeUrl}.
   */
  private async checkoutUrlForTier(tier: string): Promise<string> {
    const ch = await this.onboardFetch<{ nonce?: unknown }>(
      this.onboardBase + '/api/onboard/challenge',
      { method: 'GET' },
    );
    const nonce = ch.nonce;
    if (typeof nonce !== 'string' || nonce.length === 0) {
      throw new SaihmEndpointError(
        502,
        'checkout_no_nonce',
        'onboard challenge returned no nonce',
      );
    }
    let nonceBytes: Uint8Array;
    try {
      nonceBytes = fromHex(nonce);
    } catch {
      throw new SaihmEndpointError(
        502,
        'checkout_bad_nonce',
        'onboard challenge nonce is not hex',
      );
    }
    const signature = toHex(signChallenge(this.identity.mldsaSecretKey, nonceBytes));
    const out = await this.onboardFetch<{ url?: unknown }>(
      this.onboardBase + '/api/stripe/checkout',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          tier,
          mldsaPubKey: toHex(this.identity.mldsaPubKey),
          nonce,
          signature,
          uiMode: 'hosted',
        }),
      },
    );
    if (typeof out.url !== 'string' || !out.url.startsWith('https://')) {
      throw new SaihmEndpointError(
        502,
        'checkout_no_url',
        'checkout did not return a hosted URL',
      );
    }
    return out.url;
  }

  /** GET a fresh single-use onboard challenge nonce (validated hex). Shared by the FREE poll loop. */
  private async fetchChallengeNonce(base: string): Promise<string> {
    const ch = await this.onboardFetch<{ nonce?: unknown }>(
      base + '/api/onboard/challenge',
      { method: 'GET' },
    );
    const nonce = ch.nonce;
    if (typeof nonce !== 'string' || nonce.length === 0) {
      throw new SaihmEndpointError(
        502,
        'onboard_no_nonce',
        'onboard challenge returned no nonce',
      );
    }
    try {
      fromHex(nonce); // fail HERE on a non-hex nonce, not inside signChallenge
    } catch {
      throw new SaihmEndpointError(
        502,
        'onboard_bad_nonce',
        'onboard challenge nonce is not hex',
      );
    }
    return nonce;
  }

  /**
   * ONE-TIME FREE-tier onboarding via an OAuth-provider DEVICE FLOW (RFC 8628), bridge-proxied.
   *
   * Proves a real, Sybil-resistant human identity and binds it to THIS sovereign ML-DSA key so the
   * operator can write a durable FREE entitlement — WITHOUT this client ever holding the provider's
   * OAuth token (the device flow runs server-side on the bridge; the token is server-ephemeral). One
   * ML-DSA-signed challenge nonce is BOTH the proof-of-key-possession AND the identity-binding nonce:
   * it ties the provider identity to `agentIdHash` in a single, single-use step.
   *
   * Flow: `POST /api/free-onboard/start {pubkey, provider}` -> `{flowId, userCode, verificationUri, …}`;
   * surface the prompt to the human (open the URL, enter the code); then poll
   * `POST /api/free-onboard/claim {flowId, pubkey, nonce, signature}` until the bridge reports
   * `granted` (human authorized + Sybil gate admitted). After this resolves the entitlement is durable
   * (`endEpoch=null`) and the ordinary self-onboard/refresh loop mints FREE JWTs indefinitely — no
   * payment, no re-auth. Call ONCE per identity; a second call on an already-entitled key returns a
   * typed idempotent success (`already_granted`).
   *
   * SECURITY: the only crypto that crosses the wire is this client's own ML-DSA nonce signature; the
   * master secret / secret key never leave this process; the provider access token is never sent to or
   * held by this client. Requires `SAIHM_TIER=FREE`.
   */
  async acquireFreeEntitlement(
    opts: FreeEntitlementOpts,
  ): Promise<FreeEntitlementResult> {
    if (this.tier !== 'FREE') {
      throw new SaihmEndpointError(
        0,
        'not_free_tier',
        'acquireFreeEntitlement requires the FREE tier (set SAIHM_TIER=FREE)',
      );
    }
    const provider = (opts.provider ?? 'github').trim() || 'github';
    const base = this.onboardBase;
    const pubkey = toHex(this.identity.mldsaPubKey);

    // Step 1 — start the SERVER-SIDE device flow. The client receives only a display prompt + an opaque
    // flow handle; it never receives the provider device_code or any provider token.
    const start = await this.onboardFetch<{
      flowId?: unknown;
      userCode?: unknown;
      verificationUri?: unknown;
      expiresIn?: unknown;
      interval?: unknown;
    }>(base + '/api/free-onboard/start', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pubkey, provider }),
    });
    const flowId = start.flowId;
    const userCode = start.userCode;
    const verificationUri = start.verificationUri;
    if (
      typeof flowId !== 'string' ||
      !flowId ||
      typeof userCode !== 'string' ||
      !userCode ||
      typeof verificationUri !== 'string' ||
      !verificationUri
    ) {
      throw new SaihmEndpointError(
        502,
        'free_onboard_bad_start',
        'free-onboard start did not return a device prompt',
      );
    }
    // RFC 8628 device codes are short-lived (~15 min); clamp the bridge-advertised window to a sane
    // range [60s, 1800s] so a hostile/broken bridge cannot make this loop honor an absurd deadline.
    const expiresIn = Math.min(
      1_800,
      Math.max(
        60,
        typeof start.expiresIn === 'number' && start.expiresIn > 0
          ? Math.floor(start.expiresIn)
          : 900,
      ),
    );
    const pollMs =
      typeof opts.pollIntervalMs === 'number' && opts.pollIntervalMs > 0
        ? opts.pollIntervalMs
        : Math.min(
            // Cap the bridge-advertised cadence well under the server challenge-nonce TTL (~30 min) so a
            // freshly-minted nonce cannot expire mid-sleep — this keeps the pollMs << NONCE_TTL invariant
            // the consecutive-401 terminal-surface logic relies on. Symmetric to the `expiresIn` clamp.
            60_000,
            Math.max(
              1_000,
              (typeof start.interval === 'number' && start.interval > 0
                ? start.interval
                : FREE_ONBOARD_POLL_MS / 1_000) * 1_000,
            ),
          );

    // Surface the one-tap prompt to the human (open verificationUri, enter userCode).
    opts.onPrompt({ userCode, verificationUri, expiresIn });

    // Step 2 — sign a fresh challenge nonce; it is BOTH proof-of-possession AND the single-use
    // identity-binding nonce (F6). The signature (not the master secret) is all that crosses the wire.
    let nonce = await this.fetchChallengeNonce(base);
    let signature = toHex(
      signChallenge(this.identity.mldsaSecretKey, fromHex(nonce)),
    );

    // Step 3 — CLAIM-FIRST poll loop. The re-mint decision is robust to BOTH shapes a Phase-7 handler
    // might use for a stale/consumed nonce, so the client is not load-bearing on a single contract:
    //   - a 2xx body `status:'nonce_stale'` (the clean contract: pending polls VERIFY-not-consume, and
    //     the single-use F6 consume happens only AT grant), OR
    //   - a 401 (the naive contract, if the handler reuses `consumeChallenge` per-poll): a nonce this
    //     client JUST signed can only 401 for a server-side nonce-lifecycle reason (expired/consumed/
    //     replayed), NEVER a genuine bad signature — so a claim-path 401 means "re-mint + retry".
    // Response `status` map: granted|already_granted -> done; pending -> wait; nonce_stale -> re-mint;
    // any other status -> terminal typed denial (e.g. sybil_denied). Terminal denials arrive as a 2xx
    // status or a NON-401 error, so they are never swallowed by the 401 re-mint path. Polling BEFORE
    // sleeping guarantees >=1 claim; we only sleep when the next poll still fits inside the deadline.
    const budgetMs =
      typeof opts.timeoutMs === 'number' && opts.timeoutMs > 0
        ? opts.timeoutMs
        : expiresIn * 1_000;
    const deadline = Date.now() + budgetMs;
    // A single 401 on a freshly-signed nonce is optimistically treated as a nonce-lifecycle event and
    // re-minted; but a claim carrying a JUST-re-minted (fresh) nonce that ALSO 401s is a TERMINAL auth
    // denial (bad signature, bad_tier, sybil-expressed-as-401), NOT a nonce issue — so surface it rather
    // than burn the whole poll budget. The counter (cleared by any 2xx) bounds the optimism to one re-mint.
    let consecutive401 = 0;
    for (;;) {
      let refresh = false;
      let terminal: SaihmEndpointError | undefined;
      try {
        const claim = await this.onboardFetch<{
          status?: unknown;
          agentIdHash?: unknown;
          error?: unknown;
        }>(base + '/api/free-onboard/claim', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ flowId, pubkey, nonce, signature }),
        });
        consecutive401 = 0; // any 2xx response clears the 401 streak
        const status = claim.status;
        if (status === 'granted' || status === 'already_granted') {
          // Trust only THIS identity's own agentIdHash, never the server-returned value.
          return { agentIdHash: this.agentIdHashHex };
        }
        if (status === 'nonce_stale') {
          refresh = true;
        } else if (status !== 'pending') {
          terminal = new SaihmEndpointError(
            403,
            // TRUNCATED AT THE MINT. `claim.error` is endpoint-chosen and arrives on an HTTP 200:
            // `onboardFetch` caps the BODY at `MAX_RESPONSE_BYTES` but no field, so before this slice
            // a 16 MiB `error` landed on `.code` unbounded and was retained on `joinState.error`
            // until the next join. Render was never unsafe — `failText` re-fences it — so this was
            // unbounded-at-mint, bounded-at-render.
            //
            // NO COUNT IS STATED HERE ON PURPOSE. The count has been wrong three times, and the
            // third time it was wrong ABOUT THIS CONSTRUCTION: the slice below was added while the
            // `status` interpolated into the MESSAGE argument two lines down was left unbounded, so a
            // comment declaring the category closed sat directly above an open instance of it.
            //
            // SCOPE, STATED EXACTLY, because the repair for that was itself too broad. It claimed
            // "EVERY endpoint-chosen string entering a `SaihmEndpointError` is sliced AT THE MINT —
            // the `code` argument and the `message` argument alike". Only the first half is true. The
            // `code` argument is the one this slice and its two siblings close, and closing it is
            // what `render_fence.ts` relies on when it imports the budget instead of restating it.
            // The MESSAGE argument is NOT closed and is not meant to be: several mints on the read,
            // share and shared-read paths interpolate envelope-derived values — `env.cellId`,
            // `env.seq`, `envelope.cellId`, `envelope.seq`, `cell.cellId` — straight into the message
            // with no slice, to say WHICH cell mismatched or rolled back.
            //
            // That is safe, and the reason is a different layer rather than this one: an error never
            // reaches an agent as `.message`, only through `failText`, which re-fences it at
            // `MAX_ERROR_MESSAGE_CHARS`. So the message half is unbounded-at-mint,
            // bounded-at-render — the same shape as `claim.error` before this slice existed.
            //
            // A cut of that paragraph closed with a second reason: "acceptable here because nothing
            // retains a message across calls the way `joinState` retains a code". The retention half
            // of it is false. `JoinState.error` is typed `unknown` and holds the whole error object,
            // message included, until the next join replaces it — so a message IS retained across
            // calls, and the sentence was resting on the one claim it had backwards.
            //
            // What actually holds is narrower and was never named: on the JOIN path specifically,
            // every endpoint-chosen value is sliced AT THE MINT, so no endpoint-sized message exists
            // to be retained. An unnamed reason is an unpinned one, and this one now has a test
            // rather than a sentence — `FF18` in `client_free_onboard.test.ts` drives the
            // endpoint-chosen mints on the path at two magnitudes, then sweeps the region and
            // requires every mint whose message is not a bare literal to be either one of those
            // driven mints or listed there with the reason its interpolands are client-local.
            //
            // It does NOT pin that the driven mints are the only ones that interpolate, and a cut
            // of this sentence said it did. The sweep's own comment says the opposite in as many
            // words: driving two mints proves those two are fenced, it does not prove they are the
            // only two. Adding ANY interpolating mint turns the sweep red — which is the property
            // worth having, and is not the same claim.
            //
            // NO RENDERED LENGTH IS STATED HERE EITHER, for the reason the paragraph above gives
            // about counts. A cut of this comment did state one — "a 4,000,043-character message
            // renders as 299 characters" — and it was one fixture's output wearing the grammar of a
            // property. `failText` renders a `SaihmEndpointError` as fixed chrome plus the fenced
            // `code`, plus the decimal `status`, plus the message fenced at this budget, so the
            // total moves with the code and the status and says nothing about the message. The
            // bound that IS true of the message is the budget named two lines up, and it is named
            // rather than evaluated.
            //
            // Do not replace this with a count of either half. The sweep is the artefact, not its
            // result: mints are found with `new SaihmEndpointError`, not with a grep for this
            // constant, and the message half is found by looking for `${` inside a mint that has no
            // `.slice(` — which is a command anyone can re-run, unlike a number in prose.
            typeof claim.error === 'string'
              ? claim.error.slice(0, MAX_ERROR_CODE_CHARS)
              : 'free_onboard_denied',
            `free-onboard was not granted (${
              typeof status === 'string' ? status.slice(0, MAX_ERROR_CODE_CHARS) : 'unknown'
            })`,
          );
        }
      } catch (e) {
        // A 401 on a freshly-signed nonce is assumed to be a server-side nonce-lifecycle event and
        // re-minted ONCE. If the very next claim (fresh nonce) 401s again, the 401 is terminal (bad-sig /
        // bad_tier / sybil-as-401) — surface it. Anything non-401 (404, other 4xx/5xx, transport) is
        // terminal and surfaced unchanged.
        if (e instanceof SaihmEndpointError && e.status === 401) {
          consecutive401 += 1;
          if (consecutive401 >= 2) throw e;
          refresh = true;
        } else {
          throw e;
        }
      }
      if (terminal) throw terminal;
      if (refresh) {
        nonce = await this.fetchChallengeNonce(base);
        signature = toHex(
          signChallenge(this.identity.mldsaSecretKey, fromHex(nonce)),
        );
      }
      if (Date.now() + pollMs > deadline) {
        throw new SaihmEndpointError(
          408,
          'free_onboard_timeout',
          'free-onboard timed out waiting for authorization',
        );
      }
      await sleep(pollMs);
    }
  }

  /** Onboard-path HTTP with the same timeout + body-cap + typed-error discipline as `doCall`. */
  private async onboardFetch<T>(url: string, init: RequestInit): Promise<T> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.requestTimeoutMs);
    try {
      const res = await fetch(url, { ...init, signal: ctrl.signal });
      const text = await readBodyCapped(res, MAX_RESPONSE_BYTES, 'onboard');
      if (!res.ok) {
        let code: string | undefined;
        try {
          const j = JSON.parse(text) as Record<string, unknown>;
          // TRUNCATED AT THE MINT, exactly as `doCall` does — see the longer note there. This
          // sentence said "there are TWO mints" and was itself the fourth instance of the failure it
          // was written to warn about: a THIRD mint sat 45 lines above, in the free-onboard claim
          // branch, taking `claim.error` off an HTTP 200 with no slice. Counted by re-running the
          // sweep rather than by recalling it: 55 `new SaihmEndpointError` sites, 52 hard-coded
          // literals, 3 endpoint-chosen — all three now slice. `render_fence.ts` justified importing
          // the budget rather than restating it with "the client truncates `code` at EVERY mint";
          // that claim only became true at this commit. Do not restate the COUNT here — a number in
          // prose goes stale silently. `MAX_ERROR_CODE_CHARS` is the grep handle; the invariant is
          // that no endpoint-chosen string reaches `.code` without passing through it.
          if (typeof j.error === 'string') code = j.error.slice(0, MAX_ERROR_CODE_CHARS);
        } catch {
          /* non-JSON error body — leave code undefined */
        }
        throw new SaihmEndpointError(
          res.status,
          code,
          // `statusText` is an endpoint-chosen reason phrase, sliced at the mint like every other
          // endpoint string reaching an error: short by RFC, unbounded by our transport.
          `SAIHM onboard failed: ${res.status} ${res.statusText.slice(0, MAX_ERROR_CODE_CHARS)}` +
            (code ? ` (${code})` : ''),
        );
      }
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new SaihmEndpointError(
          res.status,
          'malformed_json',
          'SAIHM onboard returned a non-JSON 2xx response',
        );
      }
    } catch (e) {
      if (e instanceof SaihmEndpointError) throw e;
      if (e instanceof Error && e.name === 'AbortError') {
        throw new SaihmEndpointError(
          408,
          'timeout',
          `SAIHM onboard timed out after ${this.requestTimeoutMs}ms`,
        );
      }
      throw new SaihmEndpointError(
        0,
        'network',
        'SAIHM onboard transport error',
      );
    } finally {
      clearTimeout(timer);
    }
  }

  private async call<T>(method: string, params: unknown): Promise<T> {
    const header = await this.currentAuthHeader();
    let result: T;
    try {
      result = await this.doCall<T>(method, params, header);
    } catch (e) {
      // Self-onboard mode: a 401 means the cached JWT expired or was revoked mid-flight. Drop it,
      // re-onboard once, and retry. Static-auth mode surfaces the 401 to the caller unchanged.
      if (
        !this.staticAuthHeader &&
        e instanceof SaihmEndpointError &&
        e.status === 401
      ) {
        this.cachedJwt = undefined;
        const fresh = await this.currentAuthHeader();
        try {
          result = await this.doCall<T>(method, params, fresh);
        } catch (e2) {
          this.maybeNagFromError(method, e2); // advisory; never swallows e2
          throw e2;
        }
        this.maybeNagFromResult(method, result); // advisory; never throws
        return result;
      }
      this.maybeNagFromError(method, e); // advisory; never swallows e
      throw e;
    }
    this.maybeNagFromResult(method, result); // advisory; never throws
    return result;
  }

  /** Map an MCP tool method to the monetization call type its quota is tracked under (nag labelling). */
  private nagCallType(method: string): string {
    switch (method) {
      case 'saihm_remember':
        return 'remember';
      case 'saihm_recall':
        return 'recall';
      case 'saihm_forget':
        return 'forget';
      case 'saihm_share':
      case 'saihm_revoke_share':
        return 'sharing';
      default:
        return 'usage';
    }
  }

  /**
   * Fire the FREE-tier upgrade nag for the highest crossed threshold not yet fired for `callType`, and
   * mark that threshold AND every lower one fired (so a single big jump nags once, not 3×). FREE only;
   * a no-op unless an `onQuotaNag` callback is set. A throwing callback is swallowed — a nag NEVER
   * affects the underlying call's success. On the hard-cap-error path `used`/`limit` are `null` (no
   * counter was carried) but `fraction` is `1` — the 429 is itself definitive proof of 100% usage.
   */
  private fireNag(
    callType: string,
    threshold: QuotaNagThreshold,
    used: bigint | null,
    limit: bigint | null,
    fraction: number | null,
  ): void {
    if (!this.onQuotaNag || this.tier !== 'FREE') return;
    const key = `${callType}:${threshold}`;
    if (this.firedNagKeys.has(key)) return;
    // Suppress this and every lower threshold so a jump straight to 96% nags once (at 95), not at 80+95.
    for (const t of QUOTA_NAG_THRESHOLDS) {
      if (t <= threshold) this.firedNagKeys.add(`${callType}:${t}`);
    }
    try {
      this.onQuotaNag({
        callType,
        threshold,
        atHardCap: threshold === 100,
        used,
        limit,
        fraction,
        upgradeHint: UPGRADE_HINT,
      });
    } catch {
      /* an advisory nag must never break the caller's operation */
    }
  }

  /**
   * FREE tier only: if a 2xx tool response carried optional quota telemetry
   * (`quota: { callType?, used, limit }`, decimal-string counters; `limit` "0" = unlimited), nag at the
   * highest crossed 80/95/100 threshold. Additive + optional: paid responses and telemetry-free bridges
   * carry no `quota` field, so this is a silent no-op there. Note `recall`'s all-memories response is a
   * bare JSON array with nowhere to carry `quota`, so recall surfaces upgrade pressure only via the 429
   * hard-cap path in {@link maybeNagFromError}, not at 80/95%.
   */
  private maybeNagFromResult<T>(method: string, result: T): void {
    if (!this.onQuotaNag || this.tier !== 'FREE') return;
    if (typeof result !== 'object' || result === null) return;
    const q = (result as { quota?: unknown }).quota;
    if (typeof q !== 'object' || q === null) return;
    const used = parseDecimalBig((q as { used?: unknown }).used);
    const limit = parseDecimalBig((q as { limit?: unknown }).limit);
    if (used === null || limit === null || limit <= 0n) return; // unusable / unlimited (0) => no nag
    const rawCt = (q as { callType?: unknown }).callType;
    const callType =
      typeof rawCt === 'string' && rawCt ? rawCt : this.nagCallType(method);
    const fraction = Number(used) / Number(limit);
    const pct = fraction * 100;
    // Highest crossed threshold first; fireNag no-ops if it (or a higher one) already fired.
    for (const t of [100, 95, 80] as const) {
      if (pct >= t) {
        this.fireNag(callType, t, used, limit, Math.min(1, fraction));
        return;
      }
    }
  }

  /**
   * FREE tier only: a `429 quota_hard_cap` is the live bridge telling us the lifetime cap is reached, so
   * nag at 100% (`atHardCap`) BEFORE the error propagates. This rides an EXISTING server behaviour — it
   * needs no new telemetry contract — so it is the one nag that works the moment the FREE tier is live.
   * The error is re-thrown by the caller unchanged; this method only observes.
   */
  private maybeNagFromError(method: string, e: unknown): void {
    if (!this.onQuotaNag || this.tier !== 'FREE') return;
    if (
      e instanceof SaihmEndpointError &&
      e.status === 429 &&
      e.code === 'quota_hard_cap'
    ) {
      this.fireNag(this.nagCallType(method), 100, null, null, 1);
    }
  }

  private async doCall<T>(
    method: string,
    params: unknown,
    authHeader: string,
  ): Promise<T> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.requestTimeoutMs);
    try {
      const res = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: authHeader,
        },
        body: JSON.stringify({ method, params }),
        signal: ctrl.signal,
      });
      const text = await readBodyCapped(res, MAX_RESPONSE_BYTES, method);
      if (!res.ok) {
        let code: string | undefined;
        try {
          const j = JSON.parse(text) as Record<string, unknown>;
          // TRUNCATED AT THE MINT. `error` is endpoint-chosen and was previously unbounded: it lands
          // in `code` AND, below, inside `message`, so a 16MiB error body became a ~32MiB string that
          // every consumer of this error then rendered. Bounding it here fixes it for ALL consumers
          // rather than at one call site — a real code is a short constant, so nothing legitimate is
          // lost. Callers that RENDER this must still sanitise: it is bounded here, not made safe.
          if (typeof j.error === 'string') code = j.error.slice(0, MAX_ERROR_CODE_CHARS);
        } catch {
          /* non-JSON error body — leave code undefined */
        }
        throw new SaihmEndpointError(
          res.status,
          code,
          // `statusText` is endpoint-chosen — sliced at the mint, same invariant as the `code` arm.
          `SAIHM endpoint ${method} failed: ${res.status} ${res.statusText.slice(0, MAX_ERROR_CODE_CHARS)}` +
            (code ? ` (${code})` : ''),
        );
      }
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new SaihmEndpointError(
          res.status,
          'malformed_json',
          `SAIHM endpoint ${method} returned a non-JSON 2xx response`,
        );
      }
    } catch (e) {
      if (e instanceof SaihmEndpointError) throw e;
      if (e instanceof Error && e.name === 'AbortError') {
        throw new SaihmEndpointError(
          408,
          'timeout',
          `SAIHM endpoint ${method} timed out after ${this.requestTimeoutMs}ms`,
        );
      }
      throw new SaihmEndpointError(
        0,
        'network',
        `SAIHM endpoint ${method} transport error`,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Decode + authenticate + open a recalled envelope. The cell id and sequence come from the
   * AEAD-authenticated envelope, NOT the server's row label. Rejects (typed) a malformed envelope,
   * one bound to a different agent, one whose id != the requested id, or one this identity's KEK
   * cannot open — so a blind/compromised endpoint cannot relabel, mis-attribute, or rollback a cell.
   */
  private openRow(
    expectedCellId: string | null,
    wire: WireEnvelope,
  ): RecalledCell {
    let env;
    try {
      env = decodeEnvelope(wire);
    } catch {
      throw new SaihmEndpointError(
        502,
        'malformed_envelope',
        `endpoint returned a malformed envelope${expectedCellId ? ` for cell '${expectedCellId}'` : ''}`,
      );
    }
    if (!ctEqual(env.agentIdHash, this.identity.agentIdHash)) {
      throw new SaihmEndpointError(
        502,
        'foreign_envelope',
        'endpoint returned an envelope bound to a different agent',
      );
    }
    if (expectedCellId !== null && env.cellId !== expectedCellId) {
      throw new SaihmEndpointError(
        502,
        'cell_mismatch',
        `endpoint returned cell '${env.cellId}' for requested '${expectedCellId}'`,
      );
    }
    // Read-path rollback guard: env.seq is authenticated, but a hostile/buggy endpoint could replay
    // an OLDER validly-sealed version. Reject anything below a sequence we have already observed.
    const knownSeq = this.seq.current(env.cellId);
    if (knownSeq !== undefined && env.seq < knownSeq) {
      throw new SaihmEndpointError(
        502,
        'stale_cell',
        `endpoint returned a rolled-back envelope for cell '${env.cellId}' (seq ${env.seq} < ${knownSeq})`,
      );
    }
    let plaintext: string;
    try {
      plaintext = fromUtf8(openCell(env, this.identity.kek));
    } catch {
      throw new SaihmEndpointError(
        502,
        'undecryptable',
        `cell '${env.cellId}' could not be opened with this identity's key`,
      );
    }
    // Rollback WITHIN a sequence number, which the `<` comparison above cannot see. A seq can repeat:
    // `remember` advances the mark only after the endpoint accepts the write, so a committed write
    // whose response was lost leaves the mark unadvanced and the next write reuses that seq. Both
    // envelopes are genuinely signed by this identity, so every other check on this path passes and
    // the endpoint may serve either, alternately, forever. Comparing the pinned commitment is what
    // separates them. Only ever checked at EQUAL seq -- a higher seq is a legitimate new version and
    // pins a new commitment below.
    //
    // The commitment is RECOMPUTED, never read from `publicMeta`. As served, that field is the
    // endpoint's echo: it sits outside both AEAD AADs (`cellAad` and `wrapAad` cover agentIdHash,
    // cellId, seq and schemaVer, nothing else), and the ML-DSA signature that does cover it is not
    // checked here -- `verifyEnvelope` runs on the SHARED read path, where a foreign envelope has no
    // other source of provenance. This path gets provenance from our own KEK instead: nothing but
    // this identity can produce a `wrappedDek` that unwraps. So the signature adds nothing openRow
    // consumes, but the echo would let the endpoint pick both sides of the comparison below.
    //
    // Placed AFTER the decrypt deliberately, and moving it earlier to "fail fast" regresses two
    // things. A tampered ciphertext would then be reported as `stale_cell` rather than
    // `undecryptable`, and only when a pin happens to exist -- a misdiagnosis whose presence depends
    // on unrelated state. Here `env.ciphertext` has been authenticated by the AEAD open, so the hash
    // is taken over bytes this identity has already vouched for.
    const envCommitment = createHash('sha256').update(env.ciphertext).digest('hex');
    const knownCommitment = this.seq.currentCommitment(env.cellId);
    if (knownSeq !== undefined && env.seq === knownSeq && knownCommitment !== undefined && envCommitment !== knownCommitment) {
      throw new SaihmEndpointError(
        502,
        'stale_cell',
        `endpoint returned a different envelope at the same sequence for cell '${env.cellId}' (seq ${env.seq})`,
      );
    }
    // Both authenticated: seq is bound into the AEAD AAD, and the commitment was recomputed above
    // from the ciphertext this identity's KEK has now opened. Neither is the endpoint's echo.
    try {
      this.seq.observe(env.cellId, env.seq, envCommitment);
    } catch (e) {
      throw markPathBearing(e);
    }
    return {
      cellId: env.cellId,
      plaintext,
      seq: env.seq.toString(10),
      commitmentHash: envCommitment,
    };
  }

  /** Authoritative tier from the JWT (via status), cached. Used to label sealed cell metadata. */
  private async resolveTier(): Promise<string> {
    if (this.tier !== undefined) return this.tier;
    const st = await this.status();
    this.tier = st.tier;
    return st.tier;
  }

  /**
   * Seal `content` client-side and store it BLIND. Creates a new cell, or updates `opts.cellId`
   * with a fresh monotonic seq. Returns the storage receipt (no plaintext leaves the process).
   */
  async remember(
    content: string,
    opts: RememberOpts = {},
  ): Promise<RememberResult> {
    const cellId = opts.cellId ?? randomBytes(16).toString('hex');
    // Updating a provided cellId THIS PROCESS has not seen live: learn the LIVE server seq first so
    // the write is not guaranteed-rejected as stale. Route the discovered envelope through openRow so
    // its seq is AEAD-AUTHENTICATED (openCell binds seq into the AAD) BEFORE we seed the high-water
    // mark. A structural decode alone is NOT enough: a hostile/buggy endpoint could forge a high seq
    // on an otherwise-valid-looking envelope and poison our monotonic counter — burning the cell's
    // sequence space and, with a persisted seq file, corrupting it across restarts.
    // The ceiling is exempt, and exempt provably rather than as an optimisation. A mark AT `MAX_SEQ`
    // cannot be raised by anything the endpoint could serve: a seq above the u64 ceiling cannot come
    // from a valid envelope, because `decodeEnvelope` parses it as u64, and `parseMark` refuses one
    // from disk. So `next()` is `MAX_SEQ + 1` whatever the live read returns, and the outcome is
    // `seq_exhausted` either way. The round trip would change no result and would be paid on every
    // attempt against a cell that is permanently unwritable.
    if (
      opts.cellId !== undefined &&
      !this.seq.observedLiveThisRun(cellId) &&
      this.seq.current(cellId) !== MAX_SEQ
    ) {
      const existing = await this.recallRawOne(cellId);
      if (existing.found && existing.wire) {
        this.openRow(cellId, existing.wire); // decode + attribute + openCell(authenticates seq) + observe
      }
    }
    const seq = this.seq.next(cellId);
    if (seq > MAX_SEQ) {
      throw new SaihmEndpointError(
        0,
        'seq_exhausted',
        `cell '${cellId}' has exhausted its uint64 sequence space`,
      );
    }
    const tier = await this.resolveTier();
    const env = sealCell({
      plaintext: utf8(content),
      kek: this.identity.kek,
      mldsaSecretKey: this.identity.mldsaSecretKey,
      mldsaPubKey: this.identity.mldsaPubKey,
      agentIdHash: this.identity.agentIdHash,
      cellId,
      seq,
      tier,
    });
    const wire = encodeEnvelope(env);
    const r = await this.call<RememberResult>('saihm_remember', { wire });
    // Advance only after the endpoint accepted the write, and pin the commitment of the envelope
    // THIS process just sealed -- so a later read of a DIFFERENT envelope at this same seq, which a
    // lost response makes possible, is detectable rather than silently accepted.
    try {
      this.seq.observe(cellId, seq, toHex(env.publicMeta.commitmentHash));
    } catch (e) {
      // THE CELL IS STORED. Reaching here means the endpoint accepted the write and the local marks
      // file could not be updated - and only an OPERATOR-NAMED path throws at all, since a defaulted
      // one degrades to memory rather than break an accepted write. A bare `EACCES ... open '<path>'`
      // arriving out of `remember` reads as a failed write, which is the one thing it is not, and the
      // operator's repair for it -- write it again -- burns a second seq on a cell already holding
      // the content. Prefixed rather than replaced so the path Node named still reaches them.
      if (e instanceof Error) {
        try {
          e.message = `cell stored; local sequence marks could not be updated: ${e.message}`;
        } catch {
          /* frozen or getter-only message: the unprefixed error is still the right one to raise */
        }
      }
      throw markPathBearing(e);
    }
    // Delta-cache coherence: a delta recall SKIPS cellIds we already hold, so an in-place UPDATE (or a
    // fresh create) would otherwise be invisible to this client's next recall. Cache the CANONICAL
    // opened cell by re-opening OUR OWN just-sealed envelope — byte-identical to a future recall, with
    // seq + commitmentHash taken from the authenticated envelope, never the endpoint's echo. The cache
    // is a convenience: a successful write must never be reported as failed because of it, so a
    // (practically impossible) open failure just drops the entry for the next recall to re-fetch.
    if (this.recallCache.configured) {
      try {
        this.recallCache.upsert(this.openRow(cellId, wire));
      } catch {
        // The recovery must not re-enter the operation that just failed, and it used to: `upsert`
        // sets the entry and THEN persists, so an unwritable cache throws with the entry already in
        // the map — and `remove` finds it, deletes it, and persists again, failing identically. That
        // second throw escaped, and the tool reported a FAILED WRITE for a cell the endpoint had
        // accepted and stored. The line three comments up says a successful write must never be
        // reported as failed because of the cache; this is what enforces it rather than intending it.
        // The agent's likely response to a false failure is to write the content again, which is how
        // a duplicate cell gets created for a cell that was already there.
        try {
          this.recallCache.remove(cellId);
        } catch {
          /* cache unwritable; the entry is dropped in memory and the next recall rebuilds it */
        }
      }
    }
    // The receipt is composed from what WE authenticated, not from `r`. Returning the endpoint's echo
    // was the wider mistake: the cache three lines up was already careful to take seq + commitmentHash
    // "from the authenticated envelope, never the endpoint's echo", so the distinction was understood —
    // and then the echo was handed straight to a caller that renders it into the agent's text block as
    // a RECEIPT for a write the agent explicitly asked for. That is a more credible channel than the
    // announcement list these caps were built for. All three values are ours already: `cellId` is
    // caller-supplied or client-generated, `seq` is this client's monotonic counter, and
    // `commitmentHash` is read off the envelope THIS process sealed. Taking them from the response
    // bought nothing and let the endpoint choose them.
    // Resolved ONCE into a local, then type-checked and returned — never read twice. The reason
    // recorded here before was that `r` is `JSON.parse` output and so carries only own data
    // properties, making a second read provably identical. That reason is FALSE, and in the exact
    // case the guard exists for: `r.shardId` is a PROTOTYPE-CHAIN lookup, so when the endpoint's
    // 200 body OMITS `shardId` the read resolves on `Object.prototype`, where an accessor can
    // return a different value on each read. No in-repo pollution vector was found, so this is
    // shape, not an active defect — but resolve-once is cheap and does not depend on that search
    // having been exhaustive, which is why it stays.
    const rawShardId: unknown = r?.shardId;
    const shardId = typeof rawShardId === 'string' ? rawShardId : '';
    return {
      cellId,
      seq: seq.toString(10),
      commitmentHash: toHex(env.publicMeta.commitmentHash),
      // The one field with no local authority — it names endpoint-side storage, so only the endpoint
      // can know it. Brought to the declared type rather than cast into a lie (an omitted field would
      // otherwise be `undefined` typed `string`), and fenced again at every render site.
      //
      // A `typeof` TEST, not `String(v)`, because `String` is not total: it recurses through nested
      // arrays, so a JSON array nested 4,000 deep — an 8 KB response body that `JSON.parse` accepts
      // without complaint — throws `RangeError: Maximum call stack size exceeded` from inside this
      // expression. That escaped the tool handler as a bare stack-overflow string with no SAIHM
      // prefix and no attribution, reading to the agent as a bug in its own client. The render fence
      // guards its own coercion for the same reason; this one is upstream of it and needed its own.
      // A shard id that is not a string is not a shard id, so there is nothing to salvage by
      // stringifying it.
      //
      // RESOLVED ONCE, above, not re-read here. Written inline as
      // `typeof r?.shardId === 'string' ? r.shardId : ''` this reads the property TWICE — once to
      // test it, once to take it — and the two reads are not guaranteed to agree. A getter that
      // returns a short string to the guard and 5,000 characters to the taker defeats it; that was
      // measured, not supposed. Unreachable today because `r` is `JSON.parse`d and so carries only
      // data properties, but the guard is written to be true of its own expression rather than of a
      // fact about a caller three frames away.
      shardId,
    };
  }

  private async recallRawOne(
    cellId: string,
  ): Promise<{ found: boolean; wire?: WireEnvelope }> {
    const r = await this.call<unknown>('saihm_recall', { cellId });
    if (typeof r !== 'object' || r === null || Array.isArray(r)) {
      throw new SaihmEndpointError(
        502,
        'malformed_response',
        'endpoint returned a malformed recall response',
      );
    }
    return r as { found: boolean; wire?: WireEnvelope };
  }

  /**
   * Recall + open ALL of this agent's cells, optionally keyword-filtered (client-side) by `query`.
   * All-or-nothing: a cell that fails read-integrity (malformed / foreign / undecryptable) throws a
   * typed {@link SaihmEndpointError} naming it, rather than being silently dropped (silent drops
   * would hide data loss). `forget` such a cell to exclude it.
   */
  async recall(query?: string): Promise<RecalledCell[]> {
    return (await this.recallWithShared(query)).cells;
  }

  /**
   * {@link recall}, but also returning the share announcements the SAME response carried — pointers to
   * cells OTHER agents have granted to this one.
   *
   * The announcements are bound to the RESPONSE, never to the client: there is no accessor and no
   * instance state to go stale, so concurrent recalls cannot cross-attribute their announcement sets
   * (a hostile endpoint controls interleaving simply by delaying a response) and a FAILED recall
   * cannot leave a previous set readable. A caller that wants only its own memories should keep
   * calling {@link recall}, whose contract is unchanged.
   *
   * `announcements` is `[]` — never absent — when the endpoint announced none, which is also what an
   * endpoint with shared discovery switched off returns and what every endpoint predating the feature
   * returns. UNAUTHENTICATED POINTERS, NOT MEMORIES: read {@link SharedAnnouncement} before surfacing
   * them. To actually read one, obtain the sharer's identity record out-of-band and call
   * {@link recallShared} — that path, and only that path, authenticates the grant.
   */
  async recallWithShared(query?: string): Promise<RecallWithShared> {
    const needle = query?.toLowerCase();
    const filter = (cells: RecalledCell[]): RecalledCell[] =>
      needle === undefined ? cells : cells.filter((c) => c.plaintext.toLowerCase().includes(needle));

    // DELTA PATH (dark; active only when a recall cache is configured). Send the endpoint the
    // cellIds we already hold; it fans out reads over only the NEW ones (server work O(new) not
    // O(all)) and returns `liveCellIds` so we can prune anything since forgotten. We answer the
    // caller from the merged cache. If the endpoint's delta gate is off (or it is an older build),
    // it returns the legacy array instead — we treat that as a full recall and rebuild the cache,
    // so a delta-configured client is always correct against any endpoint.
    if (this.recallCache.configured) {
      // `knownSharedKeys` is deliberately NOT sent, and the response's `liveSharedKeys` is deliberately
      // ignored. That pair is the delta protocol for ANNOUNCEMENTS, and it presupposes a client-side
      // shared cache — which does not exist here by design. Sending it would make the endpoint omit
      // already-echoed announcements from `added`, leaving this client with nothing to serve them from
      // and silently TRUNCATING the listing. Full re-announcement every recall is what makes the list
      // complete and lets it be replaced wholesale; the cost is a few hundred bytes per grant.
      // Snapshotted BEFORE the await. `remember` and `forget` mutate this cache directly so a client
      // stays coherent with its own writes, and both can land while this request is in flight: the SDK
      // does not serialise tool handlers and this client is a process-wide singleton, so the endpoint
      // picks the interleaving simply by choosing when to answer. Everything below rewrites the cache
      // from a snapshot the endpoint took before those writes existed, so applying it unconditionally
      // undoes them — measured, both directions: a `forget` during an in-flight recall had the erased
      // cell's PLAINTEXT written back to disk after the tool reported `complete: true`, and a
      // `remember` during one had the new cell dropped from the cache entirely.
      const cacheVersion = this.recallCache.version;
      const resp = await this.call<unknown>('saihm_recall', {
        knownCellIds: this.recallCache.knownCellIds(),
      });
      // A local write landed while this was in flight, so the response predates it and is not safe to
      // apply. Skipping the cache write is always sound: this is a cache, the next recall rebuilds it,
      // and the caller below is still answered from live state. Overwriting is the only unsound option.
      const cacheIsStale = this.recallCache.version !== cacheVersion;
      // `liveCellIds` is narrowed to `unknown[]`, NOT `string[]`, because `Array.isArray` is all this
      // predicate checks and claiming otherwise would be a type-level lie in exactly the place a
      // reader looks for reassurance. `added` was already honestly typed `unknown[]`, which made the
      // asymmetry read as deliberate rather than as an oversight. The elements are filtered below
      // before they reach the cache; the claim and the check now agree.
      const isDelta = (r: unknown): r is { mode: 'delta'; added: unknown[]; liveCellIds: unknown[] } =>
        typeof r === 'object' &&
        r !== null &&
        !Array.isArray(r) &&
        (r as { mode?: unknown }).mode === 'delta' &&
        Array.isArray((r as { added?: unknown }).added) &&
        Array.isArray((r as { liveCellIds?: unknown }).liveCellIds);
      if (isDelta(resp)) {
        const { cells: added, announcements, announcementsTruncated } = this.openRecallRows(resp.added);
        // Non-strings are dropped rather than coerced. `new Set([...])` on a mixed array would treat
        // every non-string as an id that is NOT live, and `merge` prunes exactly what is missing from
        // that set — so a response of `[null]` would evict the whole cache while looking well-formed.
        // The endpoint can already prune by sending `[]`, so this bounds a type confusion, not a
        // capability; it is here because the cast is what made the confusion invisible.
        // `merge` prunes every cellId missing from the endpoint's live set, so a stale `liveCellIds`
        // deletes a cell this client wrote after the snapshot. The delta branch cannot RESURRECT a
        // forgotten cell — the endpoint omits it from `added` because the client already listed it as
        // known — but it drops a concurrent write exactly as the full branch does, which is why the
        // guard covers both and not just the one that reaches plaintext.
        if (!cacheIsStale)
          try {
            this.recallCache.merge(added, resp.liveCellIds.filter((id): id is string => typeof id === 'string'));
          } catch (e) {
            throw markPathBearing(e);
          }
        return { cells: filter(this.recallCache.all()), announcements, announcementsTruncated };
      }
      if (!Array.isArray(resp)) {
        throw new SaihmEndpointError(
          502,
          'malformed_response',
          'endpoint returned a malformed recall response',
        );
      }
      const { cells, announcements, announcementsTruncated } = this.openRecallRows(resp);
      if (!cacheIsStale)
        try {
          this.recallCache.replaceAll(cells);
        } catch (e) {
          throw markPathBearing(e);
        }
      return { cells: filter(cells), announcements, announcementsTruncated };
    }

    // FULL PATH (default, unchanged): recall-all, open every row, filter client-side.
    const rows = await this.call<unknown>('saihm_recall', {});
    if (!Array.isArray(rows)) {
      throw new SaihmEndpointError(
        502,
        'malformed_response',
        'endpoint returned a malformed recall-all response',
      );
    }
    const { cells, announcements, announcementsTruncated } = this.openRecallRows(rows);
    return { cells: filter(cells), announcements, announcementsTruncated };
  }

  /**
   * `openRecallRowsUnbatched` under ONE marks write instead of one per row - see
   * {@link SeqState.withBatch}. Every caller goes through here; the inner name exists so the batch
   * cannot be bypassed by accident, and the docblock below stays with the logic it describes rather
   * than with this delegation.
   */
  private openRecallRows(rows: unknown[]) {
    return this.seq.withBatch(() => this.openRecallRowsUnbatched(rows));
  }

  /**
   * Open + attribute + de-duplicate a recall row set (full recall-all OR a delta `added` list),
   * splitting it into this agent's OWN opened cells and the endpoint's SHARE ANNOUNCEMENTS.
   *
   * An honest endpoint stores exactly one current envelope per (tenant, cellId), so a set never
   * repeats a cellId. A repeat — even of two individually-authentic envelopes — is the endpoint
   * controlling cardinality: it could re-present a superseded version next to the live one (the
   * per-row rollback guard only rejects a DESCENDING seq) or duplicate a row to skew a caller's
   * aggregate. Reject the whole ambiguous response (all-or-nothing), keyed on the AUTHENTICATED
   * cellId from openRow, never the server's row label. Query-filtering is applied by the caller.
   *
   * That rejection covers OWN cells only. Announcement rows are a separate, unauthenticated channel
   * and are handled under weaker rules — see the comment at the `row.shared` branch. The two streams
   * never share a key: a shared cellId may equal one this agent owns, and both must survive.
   */
  private openRecallRowsUnbatched(rows: unknown[]): {
    cells: RecalledCell[];
    announcements: SharedAnnouncement[];
    announcementsTruncated: boolean;
  } {
    const out: RecalledCell[] = [];
    const announcements: SharedAnnouncement[] = [];
    let announcementsTruncated = false;
    let announcedChars = 0; // running total across KEPT announcements; see MAX_ANNOUNCEMENT_TOTAL_CHARS
    const seen = new Set<string>();
    const seenShared = new Set<string>();
    for (const raw of rows) {
      if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
        throw new SaihmEndpointError(
          502,
          'malformed_response',
          'endpoint returned a malformed recall row',
        );
      }
      const row = raw as {
        cellId: string;
        found?: boolean;
        wire?: WireEnvelope;
        shared?: boolean;
        sharer?: string;
        scope?: string;
        // DECIMAL STRING or null — never a number. The endpoint stringifies the epoch and defaults it
        // to null (a grant with no expiry). Typing this `number` made the whole feature inert.
        expiryEpoch?: string | null;
      };

      // SHARE ANNOUNCEMENT — must be taken BEFORE the found/wire skip below, because an announcement
      // row carries NEITHER field and would otherwise be dropped on `!row.found`. It is metadata only:
      // a claim that `sharer` granted `cellId`, with no envelope and no signature to check it against.
      // It is deliberately NOT opened, NOT cached and NOT counted as a cell — resolving it requires a
      // sharer identity record pinned out-of-band (see `recallShared`), which no announcement supplies.
      //
      // A malformed or repeated announcement is SKIPPED, never thrown on: these rows are unauthenticated
      // by construction, so letting one abort the response would hand a hostile endpoint a way to deny
      // this agent its OWN memories. The all-or-nothing rejection below is reserved for own cells, whose
      // rows ARE authenticated and where ambiguous cardinality is a real integrity signal.
      // ONE EXCEPTION, deliberate: a `shared:true` row that ALSO carries `wire` is not an announcement
      // at all, so it falls through to be handled as an own cell. If it also carries `found`, it is
      // opened — and an own cell that fails to open does throw; if `found` is absent or false it is
      // dropped by the `!row.found` skip below, silently, like any other unusable row. (An earlier
      // cut of this comment stated the throw unconditionally; it holds only on the `found` path.)
      // Either way that grants no new denial capability — the identical row without the flag behaves
      // identically — and it is the price of making the two streams unconflatable.
      if (row.shared === true) {
        // An announcement carries NO envelope. Refusing a row that has one is what keeps the two
        // streams unconflatable: without this, appending `shared:true` to a GENUINE {found, wire} row
        // would divert an authenticated own-cell into the announcement list, making it VANISH — and on
        // the cached full path replaceAll would then delete it from the on-disk cache too, a route from
        // this unauthenticated branch into PERSISTED own-cell state. Fall through instead, so such a
        // row is opened and counted as the own cell it actually is.
        if (row.wire === undefined) {
          // `expiryEpoch` is a DECIMAL STRING or null — the endpoint stringifies it and null is its
          // DEFAULT (no expiry). Absent normalises to null so an older endpoint that omits the field
          // still announces. Never coerced to a number — see `SharedAnnouncement.expiryEpoch`.
          if (
            typeof row.sharer !== 'string' ||
            typeof row.cellId !== 'string' ||
            typeof row.scope !== 'string' ||
            !(typeof row.expiryEpoch === 'string' || row.expiryEpoch == null)
          )
            continue;
          // FIELD CAP. A row with an over-long field is dropped outright and does NOT set
          // `truncated`: it is a malformed row like any other, and flagging it would let the endpoint
          // make every listing claim to be incomplete.
          const epochChars = row.expiryEpoch == null ? 0 : row.expiryEpoch.length;
          if (
            row.sharer.length > MAX_ANNOUNCEMENT_FIELD_CHARS ||
            row.cellId.length > MAX_ANNOUNCEMENT_FIELD_CHARS ||
            row.scope.length > MAX_ANNOUNCEMENT_FIELD_CHARS ||
            epochChars > MAX_ANNOUNCEMENT_FIELD_CHARS
          )
            continue;
          // DEDUP FIRST, ahead of both caps. Injective in (sharer, cellId): a plain
          // `${sharer}:${cellId}` collapses ("a:b","c") onto ("a","b:c"), which an endpoint choosing
          // both fields could use to suppress an announcement. (sharer, cellId) IS the identity of a
          // grant, so two rows differing only in scope or expiry are one pointer, not two — the
          // resolved grant is whatever the endpoint honours at read.
          //
          // Ordering it first is what makes a repeat FREE. A duplicate cannot withhold anything — the
          // grant it names is already in the list — so it must not set `truncated`, and it must not
          // be weighed against a budget it will never be added to. Both caps used to be TESTED
          // against it before dedup was consulted, with one measured consequence and one latent one:
          //
          //  - MEASURED: a repeat arriving on a full budget set `announcementsTruncated` on a listing
          //    from which nothing had been withheld. The server renders that flag as `(LIST
          //    TRUNCATED: the endpoint announced more)` — an assertion to the agent, in the trusted
          //    channel, that grants exist beyond what it can see, raised at the endpoint's choosing.
          //  - LATENT: the budget was never actually CONSUMED by a repeat, because `announcedChars +=`
          //    has always sat after the dedup check. That made the safe behaviour an accident of
          //    statement order rather than a property: moving that one line above this one turns a
          //    repeated announcement into real suppression — spend the whole budget on copies of one
          //    legal row, and every genuine grant arriving later is dropped behind that same banner.
          //
          // The budget is a bound on DISTINCT unauthenticated rows. Enforcing it by ORDER, and
          // pinning both halves in tests, is what stops that from being one refactor away.
          const key = JSON.stringify([row.sharer, row.cellId]); // opaque; never parsed back apart
          if (seenShared.has(key)) continue;
          const rowChars =
            row.sharer.length + row.cellId.length + row.scope.length + epochChars;
          // BYTE AXIS. This said it is checked before the row cap "because a single row can exceed the
          // whole budget", which the field cap above refutes: every one of the four summed fields is
          // already bounded at MAX_ANNOUNCEMENT_FIELD_CHARS, so `rowChars` cannot exceed 256 against a
          // 32,768 budget — unreachable by a factor of 128. The ordering is inert either way (both
          // axes set `announcementsTruncated` and `continue`); only the reason was false. Kept in this
          // order because the byte axis is the cheaper test, and flagged because the two neighbouring
          // orderings in this block ARE argued from measurement, which is what made this one read as
          // if it had been.
          // `continue`, never `break`: the scan must keep running to reach this agent's OWN cells,
          // which arrive interleaved with announcements and whose loss would be silent — and, on the
          // cached path, would then be written through to the on-disk cache by replaceAll.
          if (announcedChars + rowChars > MAX_ANNOUNCEMENT_TOTAL_CHARS) {
            announcementsTruncated = true;
            continue;
          }
          // ROW AXIS. Both caps sit BEFORE the `seenShared` insert, so the key set is bounded by what
          // is KEPT and not by what was announced: inserting first would let a 16MiB body of unique
          // announcements retain ~270k keys to keep 256 of them, which is the very memory flood the
          // cap exists to stop.
          if (announcements.length >= MAX_SHARED_ANNOUNCEMENTS) {
            announcementsTruncated = true;
            continue;
          }
          seenShared.add(key);
          announcedChars += rowChars;
          announcements.push({
            sharer: row.sharer,
            cellId: row.cellId,
            scope: row.scope,
            expiryEpoch: row.expiryEpoch ?? null,
            verified: false,
          });
          continue;
        }
      }

      if (!row.found || !row.wire) continue;
      const cell = this.openRow(null, row.wire); // trusts env.cellId/seq, not the server row label
      // Own cells only. An announcement never reaches this set, which is precisely why a shared cellId
      // may collide with one this agent owns without tripping the duplicate check.
      if (seen.has(cell.cellId)) {
        throw new SaihmEndpointError(
          502,
          'malformed_response',
          `endpoint returned cell '${cell.cellId}' more than once in a recall response`,
        );
      }
      seen.add(cell.cellId);
      out.push(cell);
    }
    return { cells: out, announcements, announcementsTruncated };
  }

  /** Recall + open a single cell. Returns `null` if it does not exist. */
  async recallOne(cellId: string): Promise<RecalledCell | null> {
    const r = await this.recallRawOne(cellId);
    if (!r.found || !r.wire) return null;
    return this.openRow(cellId, r.wire);
  }

  /** Crypto-shred a cell (GDPR Art.17): the endpoint destroys the wrapped DEK + tombstones. */
  async forget(cellId: string): Promise<ForgetResult> {
    const r = await this.call<ForgetResult>('saihm_forget', { id: cellId });
    // PAST THIS LINE THE ERASURE HAS HAPPENED AND IS IRREVERSIBLE. The cache purge below is local
    // bookkeeping, and it used to run unguarded: any I/O failure threw, the server rendered
    // `fail(e)`, and the operator was told the forget FAILED on a cell whose DEK was already
    // destroyed — the worst possible direction to be wrong in on this tool.
    //
    // Swallowing it is NOT the fix and was rejected: that reports plain success while the cell's
    // PLAINTEXT is still sitting in the on-disk cache, which is the opposite lie about the one
    // promise this tool makes. Both halves are reported instead. The in-memory delete has already
    // happened, so the residual is bounded — the next successful persist rewrites the file without
    // this cell — but "it will probably fix itself" is not something to leave unsaid on an erasure.
    let localCacheResidual: string | undefined;
    try {
      this.recallCache.remove(cellId);
    } catch {
      const where = this.recallCache.cachePath ?? 'the configured recall cache';
      localCacheResidual =
        `the DEK is destroyed and this cell is unrecoverable, but the local plaintext cache could ` +
        `not be purged: plaintext may remain in ${where} until the next successful cache write`;
    }
    // The endpoint's claim is DELETED before ours is set, not merely overwritten. `r` is an
    // unvalidated cast of the endpoint's body, so a hostile endpoint can put `localCacheResidual` in
    // its 200 and would otherwise be writing a sentence straight into a rendered erasure receipt —
    // the same channel the announcement caps and `failText`'s fences exist to close, on the one tool
    // where an operator is most likely to act on what it says. `delete` rather than assigning
    // `undefined` because `exactOptionalPropertyTypes` makes absent and present-but-undefined
    // different things, and absent is the one that means "this client had nothing to report".
    const out: ForgetResult = { ...r };
    delete out.localCacheResidual;
    if (localCacheResidual !== undefined) out.localCacheResidual = localCacheResidual;
    return out;
  }

  /** Non-custodial status: operator-observable metadata only (no plaintext). */
  async status(): Promise<StatusSnapshot> {
    return this.call('saihm_status', {});
  }

  /**
   * GRANT a cell to another agent, end-to-end authenticated. The DEK is re-wrapped to the grantee's
   * pinned ML-KEM key client-side; the endpoint blind-stores the share envelope. `shareCell` rejects
   * a directory record that does not match the out-of-band pin (throws `KeySubstitutionError` before
   * any secret is bound). The grantee reads it with {@link SaihmProClient.recallShared}.
   */
  async share(grant: ShareGrant): Promise<ShareResult> {
    const own = await this.recallRawOne(grant.cellId);
    if (!own.found || !own.wire) {
      throw new SaihmEndpointError(
        404,
        'cell_not_found',
        `cannot share unknown cell '${grant.cellId}'`,
      );
    }
    // ONE authority for what a served envelope must satisfy, and it is the read path's. This block
    // used to re-implement a SUBSET of `openRow` inline - structural decode, agentIdHash, cellId,
    // and `seq <` - and the two checks it left out are the two that decide this case: the AEAD open
    // that authenticates the envelope, and the equal-seq commitment comparison.
    //
    // A seq legitimately REPEATS. `remember` advances the mark only after the endpoint accepts the
    // write, so a committed write whose response was lost leaves the mark unadvanced and the next
    // write reuses that seq - measured, and the reason the commitment pin exists at all. Both
    // envelopes at that seq are genuinely signed by this identity, so `seq <` is false for BOTH and
    // the endpoint could hand `share` whichever it preferred. The superseded one was then re-wrapped
    // to the GRANTEE, who has no pin, no history, and no way to know they are reading a version the
    // sharer replaced. The caller saw nothing either: `share` returned success.
    //
    // That is why this is not a duplicate-code cleanup. A guard copied into a second site is a guard
    // that can be missing from one of them; a guard CALLED cannot be. The read path grew the
    // commitment check and this copy did not, and nothing existed to notice.
    //
    // Side effects are intended, not tolerated: `openRow` observes the seq and pins the commitment
    // exactly as a read would, so sharing a cell this session has not read establishes the same pin
    // a read would have. It also tightens two error paths - an undecryptable envelope now surfaces
    // as a typed `undecryptable` here rather than as whatever `shareCell` threw on the unwrap.
    this.openRow(grant.cellId, own.wire);
    // The SAME bytes `openRow` just authenticated. `decodeEnvelope` is a pure function of `own.wire`,
    // so this is that envelope and not a second opinion; it is re-derived only because `openRow`
    // returns the plaintext and `shareCell` needs the envelope.
    const envelope = decodeEnvelope(own.wire);
    // Caller-supplied grant inputs: surface a malformed record / pinned hash as a TYPED error rather
    // than leaking client-pro's raw WireFormatError / hex Error past this client's error contract.
    // (shareCell's KeySubstitutionError below is intentionally distinct — it is a security signal.)
    let recipientRecord;
    let recipientPinnedAgentIdHash;
    try {
      recipientRecord = decodeIdentityRecord(grant.recipientRecord);
      recipientPinnedAgentIdHash = fromHex(grant.recipientPinnedAgentIdHashHex);
    } catch {
      throw new SaihmEndpointError(
        0,
        'bad_recipient',
        'recipient identity record or pinned agentIdHash is malformed',
      );
    }
    const shareEnv = shareCell({
      envelope,
      sharerKek: this.identity.kek,
      sharerMldsaSecretKey: this.identity.mldsaSecretKey,
      sharerAgentIdHash: this.identity.agentIdHash,
      recipientRecord,
      recipientPinnedAgentIdHash,
    });
    const params: {
      shareWire: ReturnType<typeof encodeShareEnvelope>;
      scope: string;
      expiryEpoch?: string;
    } = {
      shareWire: encodeShareEnvelope(shareEnv),
      scope: grant.scope ?? 'read',
    };
    if (grant.expiryEpoch !== undefined && grant.expiryEpoch !== null) {
      params.expiryEpoch = grant.expiryEpoch.toString(10);
    }
    return this.call('saihm_share', params);
  }

  /** Revoke a prior grant to `recipientHex` for `cellId` (deletes the share envelope). */
  async revokeShare(
    cellId: string,
    recipientHex: string,
  ): Promise<RevokeResult> {
    return this.call('saihm_revoke_share', { cellId, recipient: recipientHex });
  }

  /**
   * Recipient READ of a cell shared TO this agent. Fetches the opaque ML-KEM share envelope and the
   * sharer's content ciphertext, authenticates the grant against the OUT-OF-BAND-pinned sharer key,
   * unwraps the content DEK with this agent's ML-KEM secret, and opens the content. Returns `null`
   * when no live grant exists (never shared, revoked, or expired) or the content was forgotten.
   *
   * Trust model (the endpoint is blind + assumed hostile): it never holds the DEK, so it cannot forge
   * content — a tampered ciphertext fails the AEAD open, a substituted cell fails the id/attribution
   * checks, and an unauthenticated share fails `verifyShareSig`. `verifyEnvelope` additionally proves
   * the sharer's ML-DSA signature over the exact content (non-repudiation). The recipient's tier must
   * be sharing-capable; otherwise the endpoint rejects the fetch (`BLIND_SHARE_TIER_REQUIRED`, 402).
   *
   * TWO PROPERTIES ARE ENDPOINT-ENFORCED, NOT CRYPTOGRAPHIC, and the paragraph above used to be read
   * as covering them. It does not, and the distinction is the same one `SharedAnnouncement.expiryEpoch`
   * already draws for its own fields:
   *
   *   - FRESHNESS. An OLDER envelope the sharer genuinely signed for this same cellId passes every
   *     check listed above: the ciphertext is untampered, the cell is not substituted, the share is
   *     authenticated. `recall` and `share` both carry an explicit rollback guard against exactly this
   *     (`stale_cell`, on `this.seq.current(cellId)`); this path has none and cannot cheaply gain one,
   *     because `this.seq` is THIS agent's own write counter and a recipient holds no authenticated
   *     high-water mark for a foreign cell — the first read of one is unprotectable in principle. What
   *     the caller DOES get is `seq` on the returned row, taken off the verified envelope: a caller
   *     that remembers the highest seq it has seen per (sharer, cellId) can enforce monotonicity
   *     itself. Nothing here does that for it.
   *   - REVOCATION. `null` for a revoked grant is the HONEST endpoint declining to serve it. A hostile
   *     one replays the share envelope and content it served before the revocation, and every check
   *     above still passes. Revocation is a server-side authorization decision, so it is exactly as
   *     strong as the party this paragraph assumes hostile — state it that way rather than reading the
   *     `null` return as a cryptographic guarantee.
   */
  async recallShared(grant: SharedReadGrant): Promise<RecalledCell | null> {
    // 1) Pin the sharer's identity (defeats directory key-substitution) → trusted sharer ML-DSA key.
    let sharerRecord;
    let sharerPinned;
    try {
      sharerRecord = decodeIdentityRecord(grant.sharerRecord);
      sharerPinned = fromHex(grant.sharerPinnedAgentIdHashHex);
    } catch {
      throw new SaihmEndpointError(
        0,
        'bad_sharer',
        'sharer identity record or pinned agentIdHash is malformed',
      );
    }
    verifyIdentityRecord(sharerRecord, sharerPinned); // throws KeySubstitutionError on a pin mismatch
    const sharerHex = toHex(sharerPinned);

    // 2) Fetch {share envelope, content ciphertext} for (sharer, cellId), keyed to THIS recipient.
    const r = await this.call<unknown>('saihm_recall', {
      sharer: sharerHex,
      cellId: grant.cellId,
    });
    if (typeof r !== 'object' || r === null || Array.isArray(r)) {
      throw new SaihmEndpointError(
        502,
        'malformed_response',
        'endpoint returned a malformed shared-recall response',
      );
    }
    const res = r as {
      found?: boolean;
      wire?: WireShareEnvelope;
      contentWire?: WireEnvelope;
    };
    if (!res.found || !res.wire || !res.contentWire) return null; // no live grant / content unavailable

    // 3) Authenticate the grant + unwrap the content DEK with this agent's ML-KEM secret.
    let share;
    try {
      share = decodeShareEnvelope(res.wire);
    } catch {
      throw new SaihmEndpointError(
        502,
        'malformed_share',
        `endpoint returned a malformed share envelope for cell '${grant.cellId}'`,
      );
    }
    if (!ctEqual(share.recipientAgentIdHash, this.identity.agentIdHash)) {
      throw new SaihmEndpointError(
        502,
        'foreign_share',
        'endpoint returned a share addressed to a different recipient',
      );
    }
    if (
      !ctEqual(share.sharerAgentIdHash, sharerPinned) ||
      share.cellId !== grant.cellId
    ) {
      throw new SaihmEndpointError(
        502,
        'share_mismatch',
        `endpoint returned a share for the wrong sharer/cell`,
      );
    }
    if (!verifyShareSig(share, sharerRecord.mldsaPubKey)) {
      throw new SaihmEndpointError(
        502,
        'bad_share_sig',
        'share envelope signature does not verify against the pinned sharer key',
      );
    }
    let dek;
    try {
      dek = unwrapSharedDek({
        share,
        recipientAgentIdHash: this.identity.agentIdHash,
        sharerPinnedMldsaPubKey: sharerRecord.mldsaPubKey,
        recipientMlkemSecretKey: this.identity.mlkemSecretKey,
      });
    } catch {
      throw new SaihmEndpointError(
        502,
        'undecryptable_share',
        `share DEK for cell '${grant.cellId}' could not be unwrapped with this identity`,
      );
    }

    // 4) Decode + verify the sharer-signed content envelope, then open with the unwrapped DEK.
    try {
      let env;
      try {
        env = decodeEnvelope(res.contentWire);
      } catch {
        throw new SaihmEndpointError(
          502,
          'malformed_envelope',
          `endpoint returned a malformed content envelope for cell '${grant.cellId}'`,
        );
      }
      if (!ctEqual(env.agentIdHash, sharerPinned)) {
        throw new SaihmEndpointError(
          502,
          'foreign_envelope',
          'shared content envelope is not signed by the pinned sharer',
        );
      }
      if (env.cellId !== grant.cellId) {
        throw new SaihmEndpointError(
          502,
          'cell_mismatch',
          `endpoint returned cell '${env.cellId}' for requested '${grant.cellId}'`,
        );
      }
      if (!verifyEnvelope(env)) {
        throw new SaihmEndpointError(
          502,
          'unverified_envelope',
          `shared content envelope for cell '${grant.cellId}' failed verification`,
        );
      }
      let plaintext;
      try {
        plaintext = fromUtf8(openCellWithDek(env, dek));
      } catch {
        throw new SaihmEndpointError(
          502,
          'undecryptable',
          `shared cell '${grant.cellId}' could not be opened with the unwrapped DEK`,
        );
      }
      return {
        cellId: env.cellId,
        plaintext,
        seq: env.seq.toString(10),
        commitmentHash: toHex(env.publicMeta.commitmentHash),
      };
    } finally {
      dek.fill(0); // scrub the unwrapped DEK regardless of outcome
    }
  }

  /**
   * Governance is served as a clean unavailable at launch (the endpoint returns a 403 stub). These
   * bindings exist for surface parity. The endpoint's 403 makes `call()` throw a typed
   * {@link SaihmEndpointError} (`code === 'governance_unavailable'`); the explicit throw below is an
   * unreachable fallback should a future deployment ever return 2xx for governance.
   */
  async governancePropose(args: {
    scope: 'emission_param' | 'protocol_upgrade';
    paramKey: string | null;
    proposedValue: string | null;
  }): Promise<never> {
    await this.call('saihm_governance_propose', args);
    throw new SaihmEndpointError(
      403,
      'governance_unavailable',
      'governance unavailable',
    );
  }

  async governanceVote(args: {
    proposalId: string;
    approve: boolean;
  }): Promise<never> {
    await this.call('saihm_governance_vote', args);
    throw new SaihmEndpointError(
      403,
      'governance_unavailable',
      'governance unavailable',
    );
  }
}
