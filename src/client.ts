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
 *   SAIHM_SEQ_STATE_PATH    optional path; persists per-cell seq high-water marks (mode 600) so a
 *                           cell UPDATE survives a process restart without a stale-seq rejection.
 *   SAIHM_RECALL_CACHE_PATH optional path (mode 600); when set, `recall` runs in DELTA mode —
 *                           it fetches only cells not already cached, cutting a session-start
 *                           recall from O(all cells) to O(new). Holds plaintext at rest ⇒ opt-in.
 *
 * Concurrency: writes to DISTINCT cells are safe to run concurrently. Concurrent updates to the
 * SAME cell are single-writer by contract — the server's monotonic-seq guard rejects the loser with
 * a typed stale-seq error (no corruption); serialize same-cell updates if you need both to land.
 */

import { randomBytes } from 'node:crypto';
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
    throw new Error(`SAIHM_ENDPOINT_URL is not a valid URL: ${endpoint}`);
  }
  if (url.protocol === 'https:') return;
  if (
    url.protocol === 'http:' &&
    (url.hostname === '127.0.0.1' || url.hostname === 'localhost')
  )
    return;
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
  /** sha256(ciphertext) (hex), taken from the authenticated envelope. */
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
 * Ensure an identity secret is available to {@link SaihmProClient.bootFromEnv} for a self-join,
 * WITHOUT ever returning or printing the secret. If an env secret (HEX or FILE) is already
 * configured it is left untouched. Otherwise the default key file is used — read if present, else
 * freshly generated (32 bytes CSPRNG) and written atomically at mode 600. `SAIHM_MASTER_SECRET_FILE`
 * and (only if unset) `SAIHM_TIER=FREE` are set so the very next bootFromEnv self-onboards this
 * identity FREE. The master secret is the ONLY key to the memory and is never logged — only its path.
 */
export function ensureSelfJoinIdentityEnv(): { created: boolean; keyPath: string } {
  if (process.env.SAIHM_MASTER_SECRET_FILE) {
    return { created: false, keyPath: process.env.SAIHM_MASTER_SECRET_FILE };
  }
  if (process.env.SAIHM_MASTER_SECRET_HEX) {
    return { created: false, keyPath: '(SAIHM_MASTER_SECRET_HEX)' };
  }
  const keyPath = defaultIdentityPath();
  let created = false;
  if (!existsSync(keyPath)) {
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

  constructor(
    private readonly agentIdHashHex: string,
    private readonly path?: string,
  ) {
    if (this.path) this.load();
  }

  private load(): void {
    let raw: string;
    try {
      raw = readFileSync(this.path!, 'utf-8');
    } catch {
      return; // no state yet — first run
    }
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return; // corrupt/empty — treat as no state (admit() is monotonic; nothing regresses)
    }
    for (const [cellId, v] of Object.entries(obj)) {
      if (typeof v !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(v)) continue;
      if (this.hwm.admit(this.agentIdHashHex, cellId, BigInt(v)))
        this.cellIds.add(cellId);
    }
  }

  private persist(): void {
    if (!this.path) return;
    const obj: Record<string, string> = {};
    for (const cellId of this.cellIds) {
      const c = this.hwm.current(this.agentIdHashHex, cellId);
      if (c !== undefined) obj[cellId] = c.toString(10);
    }
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

  /** Seed / advance the high-water mark to a server-observed value (monotonic; persists on change). */
  observe(cellId: string, seq: bigint): void {
    if (this.hwm.admit(this.agentIdHashHex, cellId, seq)) {
      this.cellIds.add(cellId);
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
  constructor(private readonly path?: string) {
    if (this.path) this.load();
  }

  get configured(): boolean {
    return this.path !== undefined;
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
    if (changed) this.persist();
  }

  /** Replace the whole cache from a full recall result, then persist. */
  replaceAll(cells: RecalledCell[]): void {
    this.cells = new Map(cells.map((c) => [c.cellId, c]));
    this.persist();
  }

  /** Insert/replace one cell the client itself just wrote (create or update), then persist. No-op
   *  when the cache is disabled. Keeps a self-written update visible to the next delta recall, which
   *  would otherwise skip a cellId the client already holds. */
  upsert(cell: RecalledCell): void {
    if (this.path === undefined) return;
    this.cells.set(cell.cellId, cell);
    this.persist();
  }

  /** Drop one cell the client just forgot, then persist. Prevents the cache from serving a cell the
   *  endpoint has crypto-shredded (delta would not re-list it, so it must be removed here). */
  remove(cellId: string): void {
    if (this.path === undefined) return;
    if (this.cells.delete(cellId)) this.persist();
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
    this.seq = new SeqState(this.agentIdHashHex, opts.seqStatePath);
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
    let secretHex: string | undefined;
    if (secretFile) {
      try {
        secretHex = readFileSync(secretFile, 'utf-8');
      } catch {
        throw new Error(
          `SAIHM_MASTER_SECRET_FILE could not be read: ${secretFile}.` +
            setupHint(),
        );
      }
      try {
        // Advisory only (never blocks): warn if the secret file is group/world-accessible on POSIX.
        if (
          process.platform !== 'win32' &&
          (statSync(secretFile).mode & 0o077) !== 0
        ) {
          process.stderr.write(
            `warning: SAIHM_MASTER_SECRET_FILE ${secretFile} is group/world-accessible; chmod 600 it.\n`,
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
    if (!secretHex && selfJoinEnabled()) {
      const p = defaultIdentityPath();
      if (existsSync(p)) {
        try {
          secretHex = readFileSync(p, 'utf-8');
        } catch {
          throw new Error(
            `self-join identity file could not be read: ${p}.` + setupHint(),
          );
        }
      }
    }
    if (!secretHex) {
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
    let master: Uint8Array;
    try {
      master = fromHex(secretHex.trim());
    } catch {
      throw new Error(
        'SAIHM_MASTER_SECRET_HEX must be canonical lowercase hex.' + setupHint(),
      );
    }
    if (master.length < 32) {
      master.fill(0);
      throw new Error(
        'SAIHM_MASTER_SECRET_HEX must decode to >= 32 bytes.' + setupHint(),
      );
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
    this.seq.observe(env.cellId, env.seq); // env.seq is authenticated (bound into the AEAD AAD)
    return {
      cellId: env.cellId,
      plaintext,
      seq: env.seq.toString(10),
      commitmentHash: toHex(env.publicMeta.commitmentHash),
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
    // Updating a provided cellId we have no local high-water for: learn the LIVE server seq first so
    // the write is not guaranteed-rejected as stale. Route the discovered envelope through openRow so
    // its seq is AEAD-AUTHENTICATED (openCell binds seq into the AAD) BEFORE we seed the high-water
    // mark. A structural decode alone is NOT enough: a hostile/buggy endpoint could forge a high seq
    // on an otherwise-valid-looking envelope and poison our monotonic counter — burning the cell's
    // sequence space and, with a persisted seq file, corrupting it across restarts.
    if (opts.cellId !== undefined && this.seq.current(cellId) === undefined) {
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
    this.seq.observe(cellId, seq); // advance only after the endpoint accepted the write
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
      const resp = await this.call<unknown>('saihm_recall', {
        knownCellIds: this.recallCache.knownCellIds(),
      });
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
        this.recallCache.merge(added, resp.liveCellIds.filter((id): id is string => typeof id === 'string'));
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
      this.recallCache.replaceAll(cells);
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
  private openRecallRows(rows: unknown[]): {
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
    let envelope;
    try {
      envelope = decodeEnvelope(own.wire);
    } catch {
      throw new SaihmEndpointError(
        502,
        'malformed_envelope',
        `endpoint returned a malformed envelope for cell '${grant.cellId}'`,
      );
    }
    if (!ctEqual(envelope.agentIdHash, this.identity.agentIdHash)) {
      throw new SaihmEndpointError(
        502,
        'foreign_envelope',
        'endpoint returned an envelope bound to a different agent',
      );
    }
    if (envelope.cellId !== grant.cellId) {
      throw new SaihmEndpointError(
        502,
        'cell_mismatch',
        `endpoint returned cell '${envelope.cellId}' for requested '${grant.cellId}'`,
      );
    }
    // Rollback parity with the read path: if we already know a newer seq for this cell, refuse to
    // re-wrap a stale version the endpoint may have replayed (the grantee would otherwise read it).
    const knownSeq = this.seq.current(grant.cellId);
    if (knownSeq !== undefined && envelope.seq < knownSeq) {
      throw new SaihmEndpointError(
        502,
        'stale_cell',
        `endpoint returned a rolled-back envelope for cell '${grant.cellId}' (seq ${envelope.seq} < ${knownSeq})`,
      );
    }
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
