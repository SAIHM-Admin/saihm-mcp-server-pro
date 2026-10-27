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
 *   SAIHM_IDENTITY          an identity token written by `export-identity`: the master secret sealed
 *                           under a generated passphrase, with the tier and payment method it
 *                           onboards with. Needs SAIHM_IDENTITY_PASSPHRASE beside it, and EXCLUDES
 *                           the two master-secret variables (both set is an error, never a pick).
 *                           Non-empty SAIHM_TIER / SAIHM_PAYMENT_METHOD override what it carries.
 *   SAIHM_IDENTITY_PASSPHRASE the passphrase `export-identity` generated for that token.
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
 *   SAIHM_RECALL_CACHE_PATH path (mode 600) of the recall cache; with a cache, `recall` runs in DELTA
 *                           mode — it reads the version listing, then fetches only cells not cached
 *                           at their listed version, cutting a recall from O(all cells) to O(new or
 *                           changed). Holds plaintext at rest. The MCP server's boot
 *                           path turns the cache ON by default at `dirname(defaultIdentityPath())/
 *                           recall.<id>.json` when this identity boots from a key file (the default
 *                           one, or SAIHM_MASTER_SECRET_FILE's; 0.14.3); set this to relocate it or to
 *                           enable it for an identity token or an inline secret.
 *   SAIHM_RECALL_CACHE      `0` turns the recall cache off, default and explicit path alike.
 *
 * Concurrency: writes to DISTINCT cells are safe to run concurrently. Concurrent updates to the
 * SAME cell are single-writer by contract — the server's monotonic-seq guard rejects the loser with
 * a typed stale-seq error (no corruption); serialize same-cell updates if you need both to land.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomBytes } from 'node:crypto';
import { Agent as HttpAgent, request as httpRequest } from 'node:http';
import { Agent as HttpsAgent, request as httpsRequest, type RequestOptions as HttpsRequestOptions } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import { isIP } from 'node:net';
import type { Duplex, Transform } from 'node:stream';
import { Readable } from 'node:stream';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';
import {
  accessSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  renameSync,
  unlinkSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join as pathJoin } from 'node:path';
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
import {
  MAX_ENTRIES as SHARE_MAP_MAX_ENTRIES,
  ShareEventsFeed,
  listingEntryFrom,
  type FeedStore,
  type ListingEntry,
  type ShareEventsTransport,
  type ShareStates,
  type SharesPass,
  type SharesPassEnd,
} from './share-events.js';
import {
  COVERS_THROUGH_PATTERN,
  SNAPSHOT_ID_PATTERN,
  begunUpload,
  begunUploadId,
  committedSnapshot,
  contentDigestOf,
  contentDigestSha256,
  listedSnapshots,
  openSnapshotKey,
  openSnapshotParts,
  partsDigest,
  sealSnapshot,
  warmStartLimits,
  warmStartRoute,
  type ListedSnapshot,
  type WarmStartLimits,
  type WarmStartRoute,
  type WarmStartSnapshot,
} from './warm-start.js';
import { FileFeedStore, feedStatePath } from './feed-state-file.js';
import { SessionTokenFile } from './session-token-file.js';
import { readShareStates, shareStatesPath, writeShareStates } from './share-states-file.js';
import { ChangeFeedWriter, DESTRUCTION_ANCHOR, isoTime } from './change-feed.js';
import { MALFORMED, safePathField, MAX_PATH_FIELD_CHARS } from './render_fence.js';
import {
  openIdentityToken,
  cleanPastedValue,
  looksLikeIdentitySecret,
  normalizePassphrase,
  pathHoldsIdentitySecret,
  IdentityTokenError,
  IDENTITY_ENV,
  PASSPHRASE_ENV,
  type OpenedIdentityToken,
} from './identity-token.js';
import {
  MAX_FEED_CELL_ID_CHARS,
  PREDECESSOR_SUFFIX,
  emitErasureLineReporting,
  ensureTenantDir,
  feedPathFor,
  resolveFeedRoot,
} from './erasure-feed.js';
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
 * — 2,455x — in a single successful recall. Both axes of THIS channel are now capped, and their worst
 * case is not written here: the WORST CASE test in `tests/server_shared_announce.test.ts` floods a
 * recall with maximal rows and holds the text block, the structured content and the two together to
 * bounds it derives from the caps below.
 *
 * Figures written here went wrong, in ways that matter more than the digits: a ceiling taken from a
 * fixture with a legal scope, where the worst case needs an OFF-CONTRACT one (it renders the 11-char
 * `(malformed)` marker rather than the 9-char `readwrite`); a `String.length` taken for a byte count,
 * the exact CHARS-for-BYTES confusion the paragraph below warns about; and a ceiling that moved when
 * a banner grew. Hence the test.
 *
 * Two limits on the claim, neither hypothetical:
 *  - It is a claim about the ANNOUNCEMENT channel only. The endpoint's `error` string reaches the same
 *    tool's output through {@link SaihmEndpointError}; until it was truncated at the mint (see
 *    {@link MAX_ERROR_CODE_CHARS}) it carried 33,554,563 bytes, far past this channel's worst case.
 *    That worst case is a JOINT maximum, not the sum of the per-channel ones: the two channels are
 *    maximised by different epoch representations, so both cannot be at their own maximum in one
 *    response. See the matching note in `render_fence.ts`.
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
export const DEFAULT_ENDPOINT = 'https://saihm.net/mcp';

/**
 * The wait an endpoint asks for in `retry-after`, as words: its whole seconds when it gives them, otherwise a minute.
 * Only a short run of digits is read; a date or anything else is not echoed.
 */
function retryAfterWait(res: { headers: { get(name: string): string | null } }): string {
  const ra = res.headers.get('retry-after')?.trim() ?? '';
  if (!/^[0-9]{1,5}$/.test(ra)) return 'a minute';
  const n = Number(ra);
  if (n === 0) return 'a moment';
  if (n < 60) return n === 1 ? '1 second' : `${n} seconds`;
  // A wait of a minute or more in minutes, rounded up so the wait said is never shorter than the one asked for: "Wait
  // 1800 seconds" made the reader do the sum (0.14.3).
  const m = Math.ceil(n / 60);
  return m === 1 ? '1 minute' : `${m} minutes`;
}

/**
 * How the sign-in's own rate-limit refusal opens: the edge's limit, which sends no body. A user whose identity is
 * active meets it too, at a session start or when the sign-in renews, so it says "sign in", not "onboard" (0.14.3).
 * The server tells a join's limit from a memory call's by it. The mint in `onboardFetch` writes it out; a test holds
 * the two equal.
 */
export const SIGN_IN_LIMITED = 'SAIHM could not sign in: too many sign-ins in a short time';

/**
 * The fix for the two onboard refusals that a CONFIGURATION causes, appended to the error.
 *
 * Selected by EXACT match on the endpoint's typed `reason`, and the sentences are ours: the most an
 * endpoint can do by choosing a reason is pick one of these two, and each only names variables to
 * check. Anything else gets no remedy, rather than a guess presented as a diagnosis. Kept short
 * enough that the whole message, with every endpoint-chosen part at its slice, stays inside the
 * plain-message render budget.
 */
function onboardRemedy(status: number, code: string | undefined, reason: string | undefined): string {
  if (status !== 401 || code !== 'verification_failed') return '';
  // The join comes FIRST (0.14.3, O22): this is what an identity whose free join waits for approval meets, from any
  // process but the one running the join (that one answers with the join's own steps), and the paid-plan variables
  // first read as if a new identity were needed. A join run again reuses the key that is there.
  if (reason === 'no_free_entitlement')
    return ' A free join may still be waiting for approval: open its link and enter its code, or say "Join SAIHM". Paid plan? Set SAIHM_TIER and SAIHM_PAYMENT_METHOD for it.';
  if (reason === 'no_active_subscription')
    return ' Check that SAIHM_TIER names the plan this identity was bought on.';
  return '';
}

/**
 * Appended to the one boot error that is not about an identity: an empty SAIHM_ENDPOINT_URL. A bare
 * env-var name is a dead end for the agent reading it: it cannot tell that a free, zero-config path
 * exists one tool call away.
 *
 * NOT appended to errors about a CONFIGURED identity - a key file that is unreadable, empty or
 * malformed, an inline secret that is not hex, a token that does not open. Every one of those used to
 * end "ask me to Join SAIHM", and following that advice minted a SECOND identity while the
 * operator's real one sat there unread: the remedy for a broken key is to fix the key.
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

/**
 * Whether part of an endpoint setting has the shape of a key, passphrase or token, as a message may not show it: the
 * key-file test, and a passphrase in ANY grouping or case. A path keeps the stricter rule for folders, which have
 * ordinary reasons to look like one; nothing in an endpoint's scheme, host or path does.
 */
function endpointValueHoldsSecret(v: string): boolean {
  // Plain words count too (`saihm-gateway-internal` is twenty symbols once the dashes go) and are withheld: a digit
  // cannot be required, as one generated passphrase in about 1,800 has none.
  return displayableKeyPath(v) === null || (v.match(/[0-9A-Za-z-]+/g) ?? []).some((run) => normalizePassphrase(run) !== null);
}

/**
 * The headers a redirect hop carries: all of them within the request's own origin (scheme, host and port), and none of
 * its credentials across origins - the bearer token and any cookie were meant for the endpoint, as fetch decides it.
 */
export function redirectHopHeaders(from: URL, to: URL, headers: Record<string, string>): Record<string, string> {
  if (to.origin === from.origin) return headers;
  const kept: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() !== 'authorization' && k.toLowerCase() !== 'cookie') kept[k] = v;
  return kept;
}

/** Mirrors the standards client: https only, except 127.0.0.1 / localhost over http (dev). */
function assertEndpointUrl(endpoint: string): void {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new SaihmConfigError(
      // Not echoed when it has the shape of a key, passphrase or token: one pasted into the wrong one of
      // several settings fields would otherwise come back in a reply an agent repeats.
      endpointValueHoldsSecret(endpoint)
        ? 'SAIHM_ENDPOINT_URL is not a valid URL, and what it holds looks like a key, passphrase or token, so it is not shown.'
        : // Nor when it holds an `@`. A URL that does not parse has no userinfo this client can find, so
          // `https://admin:pw@host:99999/mcp` came back whole, password included. Where a user name or password
          // ends is a guess in a string that does not parse (either may hold `/`, `?` or `#`), so none of it is shown.
          endpoint.includes('@')
          ? 'SAIHM_ENDPOINT_URL is not a valid URL, and it holds an @, so it may carry a user name or password and is not shown.'
          : `SAIHM_ENDPOINT_URL is not a valid URL: ${unparseableEndpointShown(endpoint)}`,
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
  // Not echoed when the scheme has the shape of a key, passphrase or token: one pasted before a colon reads as a scheme.
  if (endpointValueHoldsSecret(url.protocol))
    throw new Error(
      'SAIHM_ENDPOINT_URL must use https://, and its scheme looks like a key, passphrase or token, so it is not shown. ' +
        'Plain http:// is only allowed for 127.0.0.1 or localhost (dev).',
    );
  throw new Error(
    `SAIHM_ENDPOINT_URL must use https:// (got ${url.protocol}//). ` +
      `Plain http:// is only allowed for 127.0.0.1 or localhost (dev).`,
  );
}

/**
 * An endpoint that does not parse, as a message may show it: cut before any query or fragment, which may carry a token,
 * as {@link safeEndpoint} drops them from one that does. Only called once the value holds no `@`.
 */
function unparseableEndpointShown(v: string): string {
  const cut = v.search(/[?#]/);
  return cut === -1 ? v : `${v.slice(0, cut)} (its query and fragment are not shown)`;
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
 * numbers are far below a real path. (Those sentences no longer carry the hint at all - an error
 * about a configured key now names its own remedy - but the class still matters for the path.)
 * The budget itself is not
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
/** A Node error's code as a report may carry it - `EACCES` and the like - never its message, which names paths. */
export function nodeErrorCode(e: unknown): string {
  try {
    const code = (e as { code?: unknown } | null)?.code;
    return typeof code === 'string' && /^E[A-Z0-9]{2,15}$/.test(code) ? code : 'a file system error';
  } catch {
    return 'a file system error';
  }
}

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
/*
 * KEEP-ALIVE TRANSPORT.
 *
 * WHY THIS EXISTS. The client previously called global `fetch`, whose connection pool has a
 * ~4 s idle timeout. An agent harness idles longer than that between tool calls almost every
 * time — model inference alone usually exceeds it — so in practice nearly EVERY operation
 * re-paid a full TCP+TLS handshake. Measured from a subscriber vantage at ~325 ms RTT:
 * ~1.5 s cold vs ~0.35 s warm, i.e. roughly 77% of every operation after the first was
 * handshake the subscriber did not need to pay. The same trap sat on the free-onboarding
 * device-flow poll, whose 5 s interval is just past the 4 s cutoff, so the very first thing a
 * subscriber ever does reconnected on every single poll.
 *
 * WHY A SHIM RATHER THAN A FLAG. Node's `fetch` does not accept an agent, and the underlying
 * pool is not configurable without taking on a runtime dependency. A dependency is an
 * install-time failure surface for every subscriber, so the stdlib path was chosen instead.
 *
 * WHAT THIS MUST PRESERVE, because both call sites and `readBodyCapped` depend on it:
 *   - a real `Response`, with a WHATWG `body` stream, so the response cap can still abort
 *     mid-stream rather than after buffering everything;
 *   - `AbortError` BY NAME on signal abort — the callers branch on `e.name`;
 *   - redirect following and content decoding, both of which `fetch` does silently and
 *     `https.request` does not. Omitting either would be a silent behaviour change.
 *
 * NOT AN HTTP/2 CLIENT. Measured: the client negotiates http/1.1 today, while the server
 * prefers h2 when offered. This keeps that unchanged — it is parity, not a downgrade. h2
 * (also stdlib, via node:http2) is a separate and larger win, deliberately not bundled here.
 */
/*
 * TCP keep-alive PROBE interval, not an idle cap. Node's agent does not expire free sockets on
 * its own — reuse ends when the SERVER closes, measured at more than 180 s against the live
 * endpoint (one socket served requests across 30/60/90/120/180 s idle gaps). The probe keeps
 * NAT and firewall paths from silently dropping an idle connection in between.
 */
const KEEPALIVE_PROBE_MS = 30_000;

/* Redirect hops before giving up. `fetch` follows redirects and `request` does not, so this
 * bound is part of restoring that behaviour rather than an addition to it. */
const MAX_REDIRECTS = 5;

/*
 * Status line + headers Node will accept on a response.
 *
 * Node's http client caps this at 16 KiB by default and REJECTS the whole response past it —
 * `fetch` does not, at that boundary. That is not academic: an endpoint that answers with an
 * oversized reason phrase produced a transport error here where `fetch` returned a perfectly
 * readable non-2xx, which turned a typed endpoint failure into an opaque one and lost the
 * status the caller needed. Raised so the transport swap cannot narrow what the client can
 * still read and report. The response BODY is bounded separately and unchanged.
 */
const MAX_RESPONSE_HEADER_BYTES = 96 * 1024;

/**
 * An endpoint URL is safe to quote in an error ONLY after userinfo, query and fragment are
 * dropped. SAIHM_ENDPOINT_URL is operator-supplied and may legitimately carry credentials
 * (https://user:pass@host) or a token in the query string; an error is read by an agent and
 * lands in a transcript, so echoing it raw would publish what this client exists to protect.
 * Scheme, host and path are what identify a mistyped endpoint, and nothing more is needed.
 */
export function safeEndpoint(raw: string): string {
  try {
    const u = new URL(raw);
    // A key, passphrase or token pasted into the URL is withheld like any value of that shape: the host alone is
    // named when only the path has that shape, and the variable when the host has it.
    if (endpointValueHoldsSecret(u.host)) return 'SAIHM_ENDPOINT_URL';
    if (endpointValueHoldsSecret(u.pathname)) return `${u.protocol}//${u.host}`;
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return '(unparseable endpoint URL)';
  }
}

/**
 * The reason a transport attempt failed, as a short code. MEASURED 2026-09-23: a refused
 * connection and a DNS failure both produced the SAME message here — two different causes
 * collapsed into one line that named neither the endpoint nor the reason, so a reader had
 * no signal that more detail existed. Node puts the code on the error or on its `cause`.
 */
export function transportReason(e: unknown): string {
  const err = e as { code?: string; message?: string; cause?: { code?: string; message?: string } };
  return err?.code ?? err?.cause?.code ?? err?.cause?.message ?? err?.message ?? 'no further detail available';
}

const KEEPALIVE_OPTS = { keepAlive: true, keepAliveMsecs: KEEPALIVE_PROBE_MS, maxSockets: 8, maxFreeSockets: 4 };

/*
 * ONE AGENT PER SCHEME. `fetch` handles http: and https: transparently; `request` does not,
 * and an agent belongs to exactly one scheme. Hardcoding https here failed most of the suite
 * on the first run — every test that points the client at a local http://127.0.0.1 server,
 * which is most of them. Caught by baselining the suite BEFORE the change, green, and
 * diffing, rather than by reading the failures and guessing.
 */
const saihmKeepAliveAgentHttps = new HttpsAgent(KEEPALIVE_OPTS);
const saihmKeepAliveAgentHttp = new HttpAgent(KEEPALIVE_OPTS);

/*
 * PROXIES. A hosted agent environment, or a corporate network, may let traffic out only through an
 * HTTP proxy named in HTTPS_PROXY - and this transport, being `node:https` with its own agent,
 * honoured none: there the endpoint was simply unreachable, behind a remedy ("allow the host") that
 * could not help. `https_proxy` (or `HTTPS_PROXY` when that is unset) is honoured now, for https
 * endpoints only. `HTTP_PROXY` names a proxy for http traffic, which npm and curl never use for an
 * https URL either - a machine that sets it for that would see this endpoint rerouted - and an http
 * endpoint is legal on loopback alone, which never goes through a proxy. NO_PROXY excludes hosts the way curl and npm read it: `*`, exact names, and domain suffixes
 * with or without a leading dot or `*`, each optionally with a port.
 *
 * The tunnel is a CONNECT to the proxy and TLS to the endpoint THROUGH it, so the proxy learns the
 * host name and nothing more, and the endpoint's certificate is checked exactly as on a direct
 * connection. A proxy's credentials (user:password in its URL) go to the proxy and nowhere else:
 * every failure here is reported as a fixed code, never with the URL that carried them.
 */
const PROXY_VARIABLES = ['https_proxy', 'HTTPS_PROXY'] as const;

/** A request's abort signal, as the tunnel agent receives it: Node hands an agent every request option but `signal`. */
const TUNNEL_ABORT = Symbol('saihm.tunnelAbort');

/**
 * Each proxied request's own abort signal, by REQUEST. Node builds the socket for a QUEUED request (one
 * waiting behind `maxSockets`) from the options of whichever socket's close freed the slot - another
 * request's, carrying that request's signal - so the options alone cannot name the right one; see
 * `ProxyTunnelAgent.createSocket`. `null` records that a request has none, so it never inherits one.
 */
const TUNNEL_SIGNALS = new WeakMap<object, AbortSignal | null>();

/** An error whose `code` is the whole report: `transportReason` surfaces it, and it carries no value. */
function codedError(code: string): Error {
  const e = new Error(code) as Error & { code: string };
  e.code = code;
  return e;
}

function noProxyMatches(hostname: string, port: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[(.*)\]$/, '$1');
  // 127/8 as an ADDRESS: a host NAME that merely starts with `127.` is someone's domain, not this machine.
  if (host === 'localhost' || host.endsWith('.localhost') || host === '::1' || (isIP(host) === 4 && host.startsWith('127.')))
    return true;
  // Trimmed like the proxy variables, so a blank `no_proxy` does not hide `NO_PROXY`.
  const list = (process.env.no_proxy?.trim() || process.env.NO_PROXY?.trim() || '').toLowerCase();
  for (const item of list.split(/[\s,]+/)) {
    if (item === '') continue;
    if (item === '*') return true;
    let name = item;
    let only = '';
    const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(item);
    if (bracketed) {
      name = bracketed[1] ?? '';
      only = bracketed[2] ?? '';
    } else {
      const at = item.lastIndexOf(':');
      if (at > 0 && item.indexOf(':') === at && /^\d+$/.test(item.slice(at + 1))) {
        name = item.slice(0, at);
        only = item.slice(at + 1);
      }
    }
    if (only !== '' && only !== port) continue;
    name = name.replace(/^\*/, '');
    if (name === '' || name === '.') continue;
    if (name.startsWith('.') ? host.endsWith(name) || host === name.slice(1) : host === name || host.endsWith(`.${name}`))
      return true;
  }
  return false;
}

/** The proxy variable this transport reads: the first one set, lower case first, as curl reads them. */
function proxyVariableInUse(): (typeof PROXY_VARIABLES)[number] | null {
  for (const n of PROXY_VARIABLES) if (process.env[n]?.trim()) return n;
  return null;
}

/**
 * The proxy to reach an https `target` through, or `null` to connect directly. Throws a coded error
 * - naming the variable, never its value - when the configured proxy cannot be used at all, rather
 * than quietly connecting direct where the operator said not to.
 */
export function proxyForTarget(target: URL): URL | null {
  if (target.protocol !== 'https:') return null;
  const name = proxyVariableInUse();
  const raw = name === null ? '' : (process.env[name] ?? '').trim();
  if (raw === '' || noProxyMatches(target.hostname, target.port || '443')) return null;
  // A scheme with ONE slash (`http:/host`) is a typo, not a bare host: prefixed with http:// it read as a proxy at host `http`.
  if (!raw.includes('://') && /^[A-Za-z][A-Za-z0-9+.-]*:[\\/]/.test(raw)) throw codedError(`${name}_NOT_A_URL`);
  let proxy: URL;
  try {
    proxy = new URL(raw.includes('://') ? raw : `http://${raw}`);
  } catch {
    throw codedError(`${name}_NOT_A_URL`);
  }
  if (proxy.protocol !== 'http:' || proxy.hostname === '') throw codedError(`${name}_NOT_AN_HTTP_PROXY`);
  return proxy;
}

/** Whether a request to `url` goes through a proxy - or would have, had the proxy setting been usable. */
function proxyApplies(url: string): boolean {
  let target: URL;
  try {
    target = new URL(url);
  } catch {
    return false;
  }
  try {
    return proxyForTarget(target) !== null;
  } catch {
    return true;
  }
}

/**
 * Whether a transport failure is a certificate this machine does not trust, which is what a network
 * that inspects TLS produces. Expired and wrong-name certificates are not in it: no CA added here
 * fixes either.
 */
export function untrustedCertificate(reason: string): boolean {
  return /SELF_SIGNED|UNABLE_TO_(?:VERIFY|GET_ISSUER)/.test(reason);
}

/** Whether a transport failure is a proxy setting this transport cannot use at all: not an http:// URL. */
export function unusableProxy(reason: string): boolean {
  return /(?:https_proxy|HTTPS_PROXY)_NOT_(?:A_URL|AN_HTTP_PROXY)\b/.test(reason);
}

/** An https agent whose sockets are TLS tunnels through one proxy, pooled and kept alive like the direct one. */
class ProxyTunnelAgent extends HttpsAgent {
  readonly #proxy: URL;

  constructor(proxy: URL) {
    super(KEEPALIVE_OPTS);
    this.#proxy = proxy;
  }

  /**
   * Node's agent makes every socket through here, and is handed the request it is for. For a request
   * that was QUEUED, `options` are those of the socket whose close freed the slot, so their signal was
   * another request's: that request's abort failed this healthy one at once, and this one's own abort
   * could not reach its CONNECT. The request's own entry wins. A request still being constructed - its
   * first, unqueued pass - has no entry yet, and the options it brings are its own.
   */
  createSocket(req: object, options: HttpsRequestOptions, cb: (err: Error | null, socket?: Duplex) => void): void {
    // A request that already FAILED - its own CONNECT refused or reset - is destroyed without its signal
    // aborting, as its caller cleared the timer, and Node keeps it at the head of the queue: the socket
    // made for it would answer to nobody until its deadline. It is read as given up, as an aborted one is.
    const own = (req as { destroyed?: boolean }).destroyed ? AbortSignal.abort() : TUNNEL_SIGNALS.get(req);
    const opts = own === undefined ? options : { ...options, [TUNNEL_ABORT]: own ?? undefined };
    (HttpsAgent.prototype as unknown as { createSocket: (r: object, o: object, c: typeof cb) => void }).createSocket.call(
      this,
      req,
      opts,
      cb,
    );
  }

  override createConnection(
    options: HttpsRequestOptions,
    callback?: (err: Error | null, stream: Duplex) => void,
  ): Duplex | null | undefined {
    const host = String(options.host ?? options.hostname ?? '');
    const port = Number(options.port) || 443;
    const authority = host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
    const headers: Record<string, string> = { host: authority };
    if (this.#proxy.username !== '' || this.#proxy.password !== '') {
      const user = decodeURIComponent(this.#proxy.username);
      const pass = decodeURIComponent(this.#proxy.password);
      headers['proxy-authorization'] = `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
    }
    let settled = false;
    const done = (err: Error | null, stream?: Duplex): void => {
      if (settled) {
        stream?.destroy();
        return;
      }
      settled = true;
      callback?.(err, stream as Duplex);
    };
    // WHOSE ABORT ENDS THIS CONNECT: the request it was opened for, while that one waits; once it gives up,
    // the next request still queued for this host - the one the socket will then serve - and only when none
    // waits is the CONNECT abandoned. Node opens every replacement socket for the head of the queue, and
    // leaves a request there after it gave up, so a CONNECT tied to one request stranded the rest.
    const name = this.getName(options);
    const nextWaiting = (): AbortSignal | null | undefined => {
      const next = (this.requests[name] ?? []).find((r) => !r.destroyed);
      return next === undefined ? undefined : (TUNNEL_SIGNALS.get(next) ?? null);
    };
    const signal = (options as { [TUNNEL_ABORT]?: AbortSignal })[TUNNEL_ABORT];
    if (signal?.aborted && nextWaiting() === undefined) {
      done(codedError('PROXY_CONNECT_ABORTED'));
      return undefined;
    }
    const connect = httpRequest({
      host: this.#proxy.hostname.replace(/^\[(.*)\]$/, '$1'),
      port: Number(this.#proxy.port) || 80,
      method: 'CONNECT',
      path: authority,
      headers,
      agent: false,
    });
    // AN ABSOLUTE DEADLINE, not an idle timer: a proxy that trickles its reply re-arms an idle timer with
    // every byte, and the phase never ends. The caller's abort ends it too. The request waiting on this
    // tunnel has no socket yet, so destroying that request leaves the CONNECT running - holding the
    // process open - until the proxy answers.
    let watched: AbortSignal | undefined;
    const abort = (): void => {
      watched = undefined;
      const next = nextWaiting();
      if (next === undefined) connect.destroy(codedError('PROXY_CONNECT_ABORTED'));
      else if (next !== null && !next.aborted) watch(next);
    };
    const watch = (s: AbortSignal): void => {
      watched = s;
      s.addEventListener('abort', abort, { once: true });
    };
    const deadline = setTimeout(() => connect.destroy(codedError('PROXY_CONNECT_TIMEOUT')), REQUEST_TIMEOUT_MS);
    if (signal?.aborted) abort();
    else if (signal) watch(signal);
    const finished = (): void => {
      clearTimeout(deadline);
      watched?.removeEventListener('abort', abort);
    };
    connect.once('connect', (res, socket, head) => {
      finished();
      if (res.statusCode !== 200) {
        socket.destroy();
        done(codedError(`PROXY_CONNECT_${res.statusCode ?? 0}`));
        return;
      }
      if (head.length > 0) socket.unshift(head);
      // TLS to the ENDPOINT, verified as on a direct connection: the default trust store (plus
      // NODE_EXTRA_CA_CERTS), the endpoint's own name for SNI and the certificate check, and
      // nothing taken from the request options that could loosen either.
      const tls = tlsConnect({ socket, ...(isIP(host) === 0 ? { servername: host } : { host }) });
      done(null, tls);
    });
    connect.on('error', (e) => {
      finished();
      done(e);
    });
    connect.end();
    return undefined;
  }
}

const proxyTunnelAgents = new Map<string, ProxyTunnelAgent>();
function proxyTunnelAgent(proxy: URL): ProxyTunnelAgent {
  let agent = proxyTunnelAgents.get(proxy.href);
  if (agent === undefined) {
    agent = new ProxyTunnelAgent(proxy);
    proxyTunnelAgents.set(proxy.href, agent);
  }
  return agent;
}

/** Transport codes for an answer that ARRIVED but cannot be used: the endpoint was reached, so network advice misleads. */
const UNUSABLE_ANSWER = new Set([
  'REDIRECT_CROSS_ORIGIN',
  'REDIRECT_LOCATION_INVALID',
  'REDIRECT_SCHEME_UNSUPPORTED',
  'STATUS_OUT_OF_RANGE',
  'RESPONSE_INVALID',
]);

function decodeBody(stream: Readable, encoding: string | undefined): Readable {
  let decoder: Transform;
  switch ((encoding ?? '').trim().toLowerCase()) {
    case 'gzip':
    case 'x-gzip':
      decoder = createGunzip();
      break;
    case 'deflate':
      decoder = createInflate();
      break;
    case 'br':
      decoder = createBrotliDecompress();
      break;
    default:
      return stream;
  }
  // pipe() carries data, not an error or an early close: a body cut off mid-way left the decoder, and the call reading
  // it, waiting for ever. Either one now ends the decoder with an error, which the reader sees.
  stream.once('error', (e: Error) => decoder.destroy(e));
  stream.once('close', () => {
    if (!stream.readableEnded) decoder.destroy(new Error('the response ended before its body did'));
  });
  return stream.pipe(decoder);
}

/** An answer's two timing headers, raw and by name (see `keepAliveFetch`); `endpointTiming` decides what they say. */
const answerHeaders = new WeakMap<Response, { readonly serverTiming: string | undefined; readonly admission: string | undefined }>();

/** An answer's `Content-Digest`, raw and by name: a warm-start part's, checked against its bytes before it is used. */
const answerDigests = new WeakMap<Response, string>();

/** Drop-in replacement for `fetch` over a keep-alive agent. Same contract, warm sockets. */
async function keepAliveFetch(
  url: string,
  init: RequestInit = {},
  redirectsLeft = MAX_REDIRECTS,
): Promise<Response> {
  const target = new URL(url);
  const signal = init.signal as AbortSignal | null | undefined;
  const method = (init.method ?? 'GET').toUpperCase();
  // A string, or the raw bytes of a warm-start part. Anything else is not a body this transport sends.
  const body = typeof init.body === 'string' || init.body instanceof Uint8Array ? init.body : undefined;
  const headers: Record<string, string> = { ...(init.headers as Record<string, string> | undefined) };
  if (body !== undefined && headers['content-length'] === undefined) {
    headers['content-length'] = String(Buffer.byteLength(body));
  }
  headers['accept-encoding'] ??= 'gzip, deflate, br';

  return new Promise<Response>((resolve, reject) => {
    const abortError = (): Error => {
      const e = new Error('The operation was aborted');
      e.name = 'AbortError';
      return e;
    };
    if (signal?.aborted) { reject(abortError()); return; }

    const isHttps = target.protocol === 'https:';
    const doRequest = isHttps ? httpsRequest : httpRequest;
    const proxy = proxyForTarget(target);
    const req = doRequest(
      {
        agent: proxy !== null ? proxyTunnelAgent(proxy) : isHttps ? saihmKeepAliveAgentHttps : saihmKeepAliveAgentHttp,
        protocol: target.protocol,
        host: target.hostname,
        port: target.port || (isHttps ? 443 : 80),
        path: target.pathname + target.search,
        method,
        headers,
        maxHeaderSize: MAX_RESPONSE_HEADER_BYTES,
        ...(proxy !== null && signal ? { [TUNNEL_ABORT]: signal } : {}),
      },
      (res) => {
        const status = res.statusCode ?? 0;
        const location = res.headers.location;
        // A status no Response can carry (an endpoint can send 600 to 999) is a transport failure: thrown here, in the
        // response callback, it would end the process.
        if (status < 200 || status > 599) {
          res.resume();
          if (signal) signal.removeEventListener('abort', onAbort);
          reject(codedError('STATUS_OUT_OF_RANGE'));
          return;
        }
        if (status >= 300 && status < 400 && typeof location === 'string' && redirectsLeft > 0) {
          res.resume();
          if (signal) signal.removeEventListener('abort', onAbort);
          // An unusable Location is a transport failure too, for the same reason.
          let next: URL;
          try {
            next = new URL(location, target);
          } catch {
            reject(codedError('REDIRECT_LOCATION_INVALID'));
            return;
          }
          // So is one to a scheme this transport does not speak (ftp:, data:, file:). Followed, Node refused it as
          // ERR_INVALID_PROTOCOL, which read as a network failure and sent the reader to check the network.
          if (next.protocol !== 'https:' && next.protocol !== 'http:') {
            reject(codedError('REDIRECT_SCHEME_UNSUPPORTED'));
            return;
          }
          // 301/302/303 downgrade to GET and drop the body, matching fetch; 307/308 preserve both.
          const keepMethod = status === 307 || status === 308;
          // But never to ANOTHER ORIGIN with a body: fetch would re-send it there, and a body here can be a sign-in proof
          // (onboarding's signed nonce) that whoever receives it could present first.
          if (keepMethod && init.body !== undefined && next.origin !== target.origin) {
            reject(codedError('REDIRECT_CROSS_ORIGIN'));
            return;
          }
          let nextInit: RequestInit = init;
          if (!keepMethod) {
            // Omit `body` entirely rather than setting it undefined — the project builds with
            // exactOptionalPropertyTypes, under which an explicit undefined is not the same as absent.
            const { body: _dropped, ...rest } = init;
            nextInit = { ...rest, method: 'GET' };
          }
          // A redirect to ANOTHER ORIGIN never carries this request's credentials, as fetch drops them: the bearer token
          // and any cookie were meant for the endpoint, not for wherever it points.
          if (nextInit.headers) nextInit = { ...nextInit, headers: redirectHopHeaders(target, next, nextInit.headers as Record<string, string>) };
          keepAliveFetch(next.toString(), nextInit, redirectsLeft - 1).then(resolve, reject);
          return;
        }
        // 204, 205 and 304 carry no body and are never decoded: a decompressor over an empty body errors, and nothing
        // listens to it here, so that error would end the process.
        const nullBody = status === 204 || status === 205 || status === 304;
        const decoded = nullBody ? null : decodeBody(res, res.headers['content-encoding'] as string | undefined);
        if (nullBody) res.resume();
        /*
         * ONE RESPONSE HEADER IS COPIED ONTO THE Response, BY NAME: `retry-after`, and only as a
         * short run of digits. The rest are deliberately not copied.
         *
         * Copying them all would mean an anonymous whole-object read of attacker-influenced
         * header names and values, which is precisely the shape `server_render_fence` refuses
         * to let through unenumerated. `retry-after` has readers: a 429 names the wait it asks
         * for, and the share events feed waits that long when the body names no wait. Without
         * this copy both read nothing, since every header was dropped here. A date, or any value
         * that is not 1 to 5 digits, is dropped as before.
         */
        const retryAfter = res.headers['retry-after'];
        const wait = typeof retryAfter === 'string' && /^\s*[0-9]{1,5}\s*$/.test(retryAfter) ? retryAfter.trim() : null;
        // A Response refuses a body for 204, 205 and 304, so none is passed. Any other answer Node parsed but a Response
        // cannot carry (a status text with a control character) is a transport failure: thrown here, in the response
        // callback, it would end the process.
        let response: Response;
        try {
          response = new Response(decoded === null ? null : (Readable.toWeb(decoded) as unknown as ReadableStream<Uint8Array>), {
            status,
            statusText: res.statusMessage ?? '',
            ...(wait !== null ? { headers: { 'retry-after': wait } } : {}),
          });
        } catch {
          res.resume();
          if (signal) signal.removeEventListener('abort', onAbort);
          reject(codedError('RESPONSE_INVALID'));
          return;
        }
        // TWO MORE HEADERS ARE READ BY NAME, and kept BESIDE the Response rather than copied onto it: the two the
        // latency objective rides (`Server-Timing` and `SAIHM-Admission`). A value a Response refuses would turn a
        // usable answer into RESPONSE_INVALID, so they are held raw here and judged once, in `endpointTiming`.
        const serverTiming = res.headers['server-timing'];
        const admission = res.headers['saihm-admission'];
        // ONE MORE, the same way: `Content-Digest`, which a restore checks each part against (RFC 9530).
        const contentDigest = res.headers['content-digest'];
        if (typeof contentDigest === 'string') answerDigests.set(response, contentDigest);
        if (typeof serverTiming === 'string' || typeof admission === 'string')
          answerHeaders.set(response, {
            serverTiming: typeof serverTiming === 'string' ? serverTiming : undefined,
            admission: typeof admission === 'string' ? admission : undefined,
          });
        resolve(response);
      },
    );

    // SETTLED HERE, not only destroyed: a request still waiting for its socket - a proxy tunnel being
    // opened - reports its error only once the agent hands it one, so the caller's timeout waited on the proxy.
    function onAbort(): void {
      req.destroy(abortError());
      reject(abortError());
    }
    if (proxy !== null) TUNNEL_SIGNALS.set(req, signal ?? null);
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    req.on('error', (e: Error) => { reject(e); });
    // `end(body)` rather than `write(body); end()` — one call, and it keeps this file free of a
    // `.write(` whose receiver is not a render stream. server_render_fence sweeps every such call
    // and requires each to be either a swept render surface or a written-down exception; an HTTP
    // request body is neither, so the better answer is not to create the site.
    if (body === undefined) req.end();
    else req.end(body);
  });
}

/** A body as bytes, refused past `max`: a warm-start part, or an answer read before it is parsed. */
async function readBytesCapped(res: Response, max: number, method: string): Promise<Uint8Array> {
  const tooLarge = (): SaihmEndpointError =>
    new SaihmEndpointError(0, 'response_too_large', `SAIHM endpoint ${method} response exceeded ${max}B`);
  const body = res.body;
  if (!body) return new Uint8Array(0);
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
  return Buffer.concat(chunks);
}

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

/**
 * The timing a tool result passes on: `totalMs` measured by this client, from just before the request
 * is sent to the last byte received; `serverMs` from the answer's `Server-Timing: saihm;dur=<ms>`; `admission` from its
 * `SAIHM-Admission`. A field the answer did not send is null; `totalMs` is always this client's own measurement.
 */
export interface EndpointTiming {
  readonly serverMs: number | null;
  readonly totalMs: number;
  readonly admission: 'reserved' | 'shared' | null;
}

/**
 * What one endpoint answer said about itself beyond its result, as this client read it. `timing` is `'malformed'` when
 * the answer sent timing this client cannot use, and absent when it sent none. The rest are read from a recall answer
 * only, and only from one that is an object: the full recall without a cache is a JSON array and carries none of them.
 */
export interface AnswerNotes {
  readonly timing?: EndpointTiming | 'malformed';
  /** Where the answer was served: "origin" or a region id; {@link MALFORMED} when it said something else. */
  readonly servedBy?: string;
  /** The origin time the answer reflects every change up to, re-serialised; absent when it stated none this client reads. */
  readonly asOf?: string;
  /** The order the answer lists the grants shared with this identity in, when it declares one this client knows. */
  readonly sharedOrder?: 'newest-first' | 'grant-order';
}

/**
 * The answers of ONE tool call, per endpoint method, the last answer of each method kept. Held in the call's async
 * context, so two tool calls in flight at once never read each other's answers, and a write's follow-up calls under
 * another method (the share re-issue after a remember) cannot stand in for the write's own answer.
 */
const answerNotes = new AsyncLocalStorage<Map<string, AnswerNotes>>();

/** Run `fn` and return, beside its value, what each endpoint method's last answer during it said about itself. */
export async function withAnswerNotes<T>(fn: () => Promise<T>): Promise<{ value: T; notes: ReadonlyMap<string, AnswerNotes> }> {
  const notes = new Map<string, AnswerNotes>();
  const value = await answerNotes.run(notes, fn);
  return { value, notes };
}

/** The longest `Server-Timing` value read; a longer one is refused whole, never read in part. */
const MAX_SERVER_TIMING_CHARS = 4_096;
/** A `dur` as this client takes it: plain decimal milliseconds, at most nine integer digits, never an exponent. */
const SERVER_TIMING_DUR = /^[0-9]{1,9}(?:\.[0-9]+)?$/;

/**
 * The `dur` of the `saihm` metric in a `Server-Timing` value (W3C Server Timing: comma-separated metrics, each a name
 * and `;`-separated parameters whose values are tokens or quoted strings). Null when no metric is named `saihm`: other
 * metrics are an intermediary's, and ignored. `'malformed'` when the value cannot be split, when two metrics are named
 * `saihm`, or when the one there has no single `dur` in plain decimal milliseconds: a missing `dur` is never read as 0.
 */
export function saihmServerMs(header: string): number | null | 'malformed' {
  if (header.length > MAX_SERVER_TIMING_CHARS) return 'malformed';
  // Split outside quoted strings: a `desc` may hold a comma or a semicolon.
  const metrics: string[][] = [];
  let fields: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < header.length; i++) {
    const c = header.charAt(i);
    if (quoted) {
      if (c === '\\') {
        field += c + header.charAt(++i);
        continue;
      }
      if (c === '"') quoted = false;
      field += c;
    } else if (c === '"') {
      quoted = true;
      field += c;
    } else if (c === ';' || c === ',') {
      fields.push(field.trim());
      field = '';
      if (c === ',') {
        metrics.push(fields);
        fields = [];
      }
    } else field += c;
  }
  if (quoted) return 'malformed';
  fields.push(field.trim());
  metrics.push(fields);
  let found = false;
  let dur: number | null = null;
  for (const [name, ...params] of metrics) {
    if (name !== 'saihm') continue;
    if (found) return 'malformed';
    found = true;
    const durs = params.filter((p) => /^dur\s*=/i.test(p)).map((p) => p.slice(p.indexOf('=') + 1).trim());
    if (durs.length !== 1) return 'malformed';
    const raw = durs[0] as string;
    const v = raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw;
    if (!SERVER_TIMING_DUR.test(v)) return 'malformed';
    dur = Number(v);
  }
  return found ? dur : null;
}

/**
 * The timing of one answer, or `'malformed'`, or undefined when the answer sent neither timing header: this client
 * never states a timing for a server that states none. Both headers are judged before anything is passed on, and either
 * one unusable withholds the whole, so a malformed header never travels beside a plausible-looking measurement.
 */
export function endpointTiming(
  h: { readonly serverTiming: string | undefined; readonly admission: string | undefined } | undefined,
  totalMs: number,
): EndpointTiming | 'malformed' | undefined {
  const serverMs = h?.serverTiming === undefined ? null : saihmServerMs(h.serverTiming);
  if (serverMs === 'malformed') return 'malformed';
  const said = h?.admission?.trim();
  if (said !== undefined && said !== 'reserved' && said !== 'shared') return 'malformed';
  const admission = said ?? null;
  if (serverMs === null && admission === null) return undefined;
  return { serverMs, totalMs: Math.round(totalMs * 1000) / 1000, admission };
}

/** "origin" or a region id: what a recall answer's `servedBy` may say. */
const SERVED_BY = /^[A-Za-z0-9._:-]{1,64}$/;

/**
 * Record what an answer said about itself, for the tool call it belongs to (nothing outside one). `servedBy` that is
 * present but not a name this client accepts becomes {@link MALFORMED}, never absent: absent reads as a server that
 * predates replicas, which answers from the origin, and a miss at the origin is one a reader may act on. `asOf` that is not
 * a time is left out, as the version listing's always was: absent only leaves the answer's lag unbounded.
 */
function noteAnswer(method: string, res: Response, totalMs: number, body: unknown): void {
  const notes = answerNotes.getStore();
  if (notes === undefined) return;
  const timing = endpointTiming(answerHeaders.get(res), totalMs);
  const o =
    method === 'saihm_recall' && typeof body === 'object' && body !== null && !Array.isArray(body)
      ? (body as { servedBy?: unknown; asOf?: unknown; sharedOrder?: unknown })
      : undefined;
  const servedBy =
    o?.servedBy === undefined ? undefined : typeof o.servedBy === 'string' && SERVED_BY.test(o.servedBy) ? o.servedBy : MALFORMED;
  const asOf = o === undefined ? null : isoTime(o.asOf);
  const sharedOrder = o?.sharedOrder === 'newest-first' || o?.sharedOrder === 'grant-order' ? o.sharedOrder : undefined;
  notes.set(method, {
    ...(timing !== undefined ? { timing } : {}),
    ...(servedBy !== undefined ? { servedBy } : {}),
    ...(asOf !== null ? { asOf } : {}),
    ...(sharedOrder !== undefined ? { sharedOrder } : {}),
  });
}

/** The deepest a status answer's `features` may nest. The four features defined today need five levels. */
const MAX_FEATURES_DEPTH = 16;
/** The most JSON characters a status answer's `features` may take. The four features defined today take about one KiB. */
const MAX_FEATURES_CHARS = 16_384;

/**
 * What THIS identity may use, from a status answer: its `features` object, or null. Absent and null are
 * null: a server that predates the field sends none, and none means no feature. An object passes whole and unread when
 * it is a plain object within both bounds; anything else is null with `malformed` set, so the text can say so.
 *
 * DEPTH IS BOUNDED, not only size, and MEASURED (node 20): `JSON.parse` accepts a million levels of nesting while
 * `JSON.stringify` throws a RangeError near four thousand, inside eight KiB. Passed on, such an object would fail where
 * the tool result is serialised, after this function had already called it acceptable.
 */
export function featuresOf(v: unknown): { readonly features: Record<string, unknown> | null; readonly malformed: boolean } {
  if (v === undefined || v === null) return { features: null, malformed: false };
  if (typeof v !== 'object' || Array.isArray(v) || !boundedJson(v, MAX_FEATURES_DEPTH, MAX_FEATURES_CHARS))
    return { features: null, malformed: true };
  let chars: number;
  try {
    chars = JSON.stringify(v).length;
  } catch {
    return { features: null, malformed: true };
  }
  return chars <= MAX_FEATURES_CHARS ? { features: v as Record<string, unknown>, malformed: false } : { features: null, malformed: true };
}

/**
 * Whether a parsed JSON value nests no deeper than `maxDepth` levels and holds no more than `maxValues` values in all.
 * Iterative, since the value may be far deeper than the stack; and COUNTED, so a value far larger than any it could pass
 * as is refused at once rather than walked whole (and then serialised) first: JSON text of N characters holds fewer
 * than N values, so a count over the character bound already decides it.
 */
function boundedJson(root: object, maxDepth: number, maxValues: number): boolean {
  let values = 0;
  const stack: [unknown, number][] = [[root, 1]];
  for (let top = stack.pop(); top !== undefined; top = stack.pop()) {
    const [v, depth] = top;
    values++;
    if (typeof v !== 'object' || v === null) continue;
    if (depth > maxDepth) return false;
    const children: unknown[] = Array.isArray(v) ? v : Object.values(v);
    // Every value found so far counts - walked, waiting, and these - so one over the bound is refused before the rest.
    if (values + stack.length + children.length > maxValues) return false;
    for (const child of children) stack.push([child, depth + 1]);
  }
  return true;
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
  /**
   * THE ENDPOINT'S: when the origin committed this write (ISO-8601 UTC with milliseconds), or null when the endpoint
   * did not state a time this client can read. Lets a consumer of the change feed match this write's own report.
   */
  at: string | null;
  /**
   * Present when this write left existing grants of the cell on the previous version. Every write seals the cell
   * under a new key and a grant carries the key of one version, so a grant made before this write cannot open it
   * until it is re-issued. See {@link ShareReissueReport}.
   */
  shares?: ShareReissueReport;
}

/**
 * What became of the grants a write left on an older version. Counts are this client's own: a grant counts as
 * re-issued only when this client built a new share for it and the endpoint accepted that share.
 */
export interface ShareReissueReport {
  reissued: number;
  /**
   * Grants that were not re-issued. `recipient` is set only when it was read off a share signed by THIS identity for
   * this cell; it is `null` when the endpoint's entry did not verify, so an endpoint cannot name a recipient here.
   */
  notReissued: Array<{ recipient: string | null; reason: ShareReissueSkip }>;
  /**
   * True when the endpoint listed grants this client did not examine: the walk stopped at its page bound, at a page
   * it could not continue from, or at a failed request. The counts above then cover only the grants examined.
   */
  incomplete: boolean;
}

/**
 * - `unverified`: the share is not this identity's grant of this cell to that recipient, or the recipient record does
 *   not verify against the recipient.
 * - `no_record`: the endpoint holds no recipient record for this grant (grants made before re-issue existed); share
 *   the cell again with `saihm_share`.
 * - `revoked`: this process revoked the grant; it is not re-issued even though the endpoint listed it.
 * - `refused`: the endpoint did not accept the new share.
 * - `unavailable`: the re-issue request failed (an older endpoint, a newer write of the cell, or no connection).
 */
export type ShareReissueSkip = 'unverified' | 'no_record' | 'revoked' | 'refused' | 'unavailable';

/** Grants per re-issue request and per page; the endpoint's page size. */
const REISSUE_PAGE = 16;
/** Pages followed for one write, so one write re-issues at most REISSUE_PAGE × MAX_REISSUE_PAGES grants. */
const MAX_REISSUE_PAGES = 64;

/** The share events feed renews a rejected token at most this often, so a token that keeps failing does not keep the
 *  onboarding route busy. */
const FEED_RENEW_INTERVAL_MS = 900_000;
const HEX64_RE = /^[0-9a-f]{64}$/;

/** An own data property of a JSON value, never a prototype-chain lookup. */
function ownField(o: unknown, k: string): unknown {
  return o !== null && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k)
    ? (o as Record<string, unknown>)[k]
    : undefined;
}

/**
 * The `staleShares` page of an endpoint response, structurally. Nothing in it is trusted; every grant is verified
 * before it is used. `after` is where the next page starts: the endpoint's cursor when it is a recipient id, or, when
 * the page lists more grants than this client handles in one page, the recipient of the last grant it handles, so
 * the grants it dropped are listed again on the next page. `stuck` is set when there is more to read and no usable
 * cursor to read it with.
 */
function staleGrantsPage(r: unknown): { grants: unknown[]; after: string | null; stuck: boolean } | undefined {
  const page = ownField(r, 'staleShares');
  const grants = ownField(page, 'grants');
  if (!Array.isArray(grants)) return undefined;
  const cursor = (v: unknown): string | null => (typeof v === 'string' && HEX64_RE.test(v) ? v : null);
  if (grants.length <= REISSUE_PAGE) return { grants, after: cursor(ownField(page, 'after')), stuck: false };
  const after = cursor(ownField(grants[REISSUE_PAGE - 1], 'recipient'));
  return { grants: grants.slice(0, REISSUE_PAGE), after, stuck: after === null };
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
  /**
   * A shared read only: the grant the endpoint says served the read (hex), when it sends one. Not authenticated: it is
   * for comparing a copy with its `shareStates` entry.
   */
  grant?: string;
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
  /**
   * `true` when an announcement was left out BEFORE any cut: one this client cannot carry (a field that is not the
   * type it must be, or over {@link MAX_ANNOUNCEMENT_FIELD_CHARS}). Such a row is skipped wherever it stands, so the
   * kept list is then not one END of the endpoint's order, and no end may be named for it. A repeat of a pointer
   * already kept is not counted: it withholds nothing.
   */
  announcementsSkipped: boolean;
}

export interface ForgetResult {
  cellId: string;
  shardId: string;
  /**
   * Whether the erasure is ATTESTED: true only when the endpoint states `complete: true` WITH a destruction anchor of
   * the agreed shape (then `destructionAnchor` carries it), false for any other boolean it states — the value the
   * erasure line carries. False means this client cannot point at the destruction, not that none happened.
   */
  complete: boolean;
  /**
   * THE ENDPOINT'S: why `complete` is false — `'not-found'` for an id that never existed or was already erased,
   * `'not-attested'` when the store could not persist the deletion durably (forget the id again later). Present only
   * beside `complete: false`, and only as one of these two; undefined when the endpoint names none (an older server).
   */
  reason?: 'not-found' | 'not-attested';
  /**
   * THE ENDPOINT'S record of the key destruction: present only when it states `complete: true` with an anchor of the
   * agreed shape (1 to 256 of `A-Z a-z 0-9 . _ : -`), copied verbatim — the same anchor the erasure line carries.
   * Store it; compare it only for equality; never interpret it.
   */
  destructionAnchor?: string;
  sharesPurged: number;
  steps: ReadonlyArray<{ step: string; success: boolean; detail: string }>;
  epoch: string;
  /**
   * THE ENDPOINT'S: when it performed the erasure (ISO-8601 UTC with milliseconds), or null when it states none this
   * client can read — same convention as {@link RememberResult.at}.
   */
  at: string | null;
  /**
   * Set by THIS CLIENT, never by the endpoint, when the erasure succeeded but the local plaintext
   * cache could not be purged. `undefined` on every other path. See {@link SaihmProClient.forget}.
   */
  localCacheResidual?: string;
  /**
   * Set by THIS CLIENT, never by the endpoint, when the erasure succeeded but the downstream erasure
   * feed line could not be written — so nothing derived from this cell has been told to purge it.
   *
   * Deliberately NOT folded into `localCacheResidual`: that field states that PLAINTEXT may remain
   * in a local cache, which is a different subsystem and a different remedy. An operator who read a
   * feed failure under that name would go looking for a cache file that is perfectly fine.
   */
  feedResidual?: string;
}

/** One own cell in a version listing, as the endpoint's index states it: metadata only, no content. */
export interface ListedVersion {
  /** THE ENDPOINT'S claim of the cell id. */
  cellId: string;
  /** The version's sequence number (decimal string), or null when the endpoint's index does not state one. */
  seq: string | null;
  /** The commitment to that version's ciphertext (64 hex). Two versions are equal only when seq AND commitment are. */
  commitment: string;
}

/**
 * One page of the version listing of this identity's own cells (`saihm_recall` with `listOnly`). The listing is
 * complete once a page answers `next: null`; only a complete listing may end anything.
 */
export interface VersionListing {
  cells: ListedVersion[];
  /** The `after` for the next page, or null on the last one. */
  next: string | null;
  /** When the origin began the listing, when it says (ISO-8601 UTC with milliseconds). */
  asOf?: string;
}

/** The most entries one page may hold; endpoints send far fewer, and a page above this is refused, never cut. */
export const MAX_LISTING_PAGE = 4_096;
/**
 * The most listing pages a recall with the copy on reads; a listing that runs past it fails the recall. About a million
 * cells at the hosted page size of 1,000, far past what one copy holds.
 */
export const MAX_COPY_LISTING_PAGES = 1_024;
/**
 * How many times a recall with the copy on is run when a write made on this computer, while it was in flight, moved
 * the copy under it. Its answer then predates that write, so it is neither applied nor answered; the recall runs again.
 */
export const COPY_RECALL_ATTEMPTS = 3;
/**
 * The error a recall with the copy on fails with when every one of its {@link COPY_RECALL_ATTEMPTS} was overtaken. No
 * count: each try was overtaken by at least one write, so a number would be a floor read as a total. Trying again
 * helps once the writes stop, which is all the last sentence says.
 */
const RECALL_INTERRUPTED =
  'Recall stopped: your memories on this device kept changing while it was reading them. Nothing was lost. Try ' +
  'again once they stop changing.';
/**
 * How the error opens when the copy could not be checked against the service; the cause's own message follows as the
 * next sentence. It promises no retry: at a hard cap, or with a certificate this machine does not trust, trying again
 * cannot help, and the cause says what does. "Nothing was lost" and not "nothing was changed", which right after
 * "changes made elsewhere" read as "no changes were found".
 */
const COPY_CHECK_FAILED =
  "Recall stopped: this device's copy of your memories could not be checked for changes made elsewhere, so it was " +
  'not used. Nothing was lost.';

/**
 * Marker for an endpoint error whose message is this package's own opening, a space, and then a cause's message. It
 * holds the opening, so the renderer fences the two apart: fenced as one message under one budget, the opening spent
 * the room the cause needed, and a certificate this machine does not trust rendered without the warning never to turn
 * certificate checks off (R14). A module-local symbol, like {@link PATH_BEARING}: only errors this package made carry
 * it, and text an endpoint chose cannot.
 */
const OWN_OPENING = Symbol('saihm.ownOpening');

/**
 * The opening this package put before the cause in `e`'s message, while the message still begins with it; otherwise
 * undefined. Never throws: it runs on the failure path, inside the renderer whose contract is that it never crashes.
 */
export function ownOpeningOf(e: SaihmEndpointError): string | undefined {
  try {
    const opening: unknown = (e as unknown as Record<symbol, unknown>)[OWN_OPENING];
    return typeof opening === 'string' && typeof e.message === 'string' && e.message.startsWith(`${opening} `)
      ? opening
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The message of the cause an error carries after this package's opening (see {@link ownOpeningOf}), or the error's
 * own message when it carries none. For a reader that tells causes apart by how their message begins. A cause whose
 * own opening was folded into this one (see `withOpening`) is read after both: none that reader checks has one.
 */
export function causeMessageOf(e: SaihmEndpointError): string {
  const opening = ownOpeningOf(e);
  return opening === undefined ? e.message : e.message.slice(opening.length + 1);
}

/**
 * An endpoint error with the cause's status and code whose message is `opening`, this package's own text, followed by
 * the cause's message as its own sentence (a lower-case first letter made a capital). Marked (see
 * {@link OWN_OPENING}), so the renderer gives the cause the budget it has alone. The cause must be one that renders at
 * the message budget alone - an endpoint error, or a throw that is not path-bearing or a configuration error - and both
 * callers below hand it only those.
 */
function withOpening(opening: string, cause: unknown, otherwise: string): SaihmEndpointError {
  const e = cause instanceof SaihmEndpointError ? cause : undefined;
  const why = cause instanceof Error ? String(cause.message) : otherwise;
  const sentence = /^[a-z]/.test(why) ? why.charAt(0).toUpperCase() + why.slice(1) : why;
  const err = new SaihmEndpointError(e?.status ?? 0, e?.code, `${opening} ${sentence}`);
  // A cause that opens with this package's own text keeps it ours (0.14.3): the two openings are fenced as one, before
  // the rest of the cause, so the endpoint a transport failure's opening names cannot cut the remedy after it.
  const inner = e === undefined ? undefined : ownOpeningOf(e);
  const own = inner !== undefined && sentence.startsWith(`${inner} `) ? `${opening} ${inner}` : opening;
  Object.defineProperty(err, OWN_OPENING, { value: own, enumerable: false });
  return err;
}

/**
 * A call's transport failure: `opening` names the call and the endpoint, `rest` the reason and the remedy. The opening
 * is marked as this package's own (see {@link OWN_OPENING}), so the renderer fences it apart from the rest: a long
 * SAIHM_ENDPOINT_URL is cut inside the opening and never cuts the remedy, which before 0.14.3 it did (a certificate
 * this machine does not trust lost "Never disable certificate checks" to a long path). Both parts are this package's
 * text and the operator's own setting; nothing in either is the endpoint's.
 */
function transportFailure(opening: string, rest: string): SaihmEndpointError {
  const err = new SaihmEndpointError(0, 'network', `${opening} ${rest}`);
  Object.defineProperty(err, OWN_OPENING, { value: opening, enumerable: false });
  return err;
}

/**
 * The error a recall with the copy on fails with when the copy could not be checked. Nothing more is asked of the
 * endpoint after it, so nothing more is charged. A cause here is the failure of a listing request (which reads and
 * writes no file) or of a listing page. Exported for the render tests.
 */
export function copyCheckFailed(cause: unknown): SaihmEndpointError {
  return withOpening(COPY_CHECK_FAILED, cause, 'the check failed');
}

/**
 * What a write refused as stale says (`BLIND_STALE_SEQ`: the endpoint holds a version numbered at or past this one, so
 * one was written there that this write did not start from). Bare, the refusal read "409 Conflict (BLIND_STALE_SEQ)"
 * with no way forward. Which text is true depends on what is there now, and each is chosen only where it is:
 * - `changed`: a version newer than the one this device last read or saved is there (written by another device or
 *   session, or by this one when an answer was lost). Recalling it shows that version, after which the edit goes through.
 * - `erased`: the memory this device had read or saved is gone: it was erased. The endpoint keeps its sequence number
 *   and refuses a write at or below it, but stores one past it, from a device whose mark is the last version's, as the
 *   memory again; so an edit of a memory this process knows to be erased is refused here before its write, in this
 *   text (see `refuseIfKnownErased`). Only a new memory could keep the text.
 * - `used`: the cellId names no memory this device ever read, and the endpoint has used it: for a memory erased since,
 *   or one saved elsewhere just before this write. Either way only a new memory could keep the text.
 * An erasure is deliberate, and may have been made elsewhere by the user: neither text invites saving the text again
 * without the user's say.
 */
type StaleWrite = 'changed' | 'erased' | 'used';
const STALE_EDIT =
  'This memory has changed since this device last read or saved it, so your edit was not saved. Recall it to see ' +
  'the newer version, then make your edit again.';
const ERASED_EDIT =
  'This memory was erased, so your edit was not saved. Ask the user before saving this text again as a new memory ' +
  'without a cellId.';
const ID_USED =
  'This cellId was already used by a memory saved earlier, which may since have been erased, so this one was not ' +
  'saved under it. Ask the user before saving this text as a new memory without a cellId.';

/** Whether a write's failure is the endpoint's refusal of it as stale. */
function refusedAsStale(cause: unknown): cause is SaihmEndpointError {
  return cause instanceof SaihmEndpointError && cause.code === 'BLIND_STALE_SEQ';
}

/**
 * A write's failure, with the remedy put first when the endpoint refused it as stale; any other failure unchanged.
 * Exported for the render tests.
 */
export function staleWriteRefusal(cause: unknown, why: StaleWrite): unknown {
  return refusedAsStale(cause)
    ? withOpening(why === 'erased' ? ERASED_EDIT : why === 'used' ? ID_USED : STALE_EDIT, cause, '')
    : cause;
}

/**
 * A seq mark a recall read and has not applied. It is applied only together with the content it describes: once
 * that content is in the copy, or is the answer. A mark ahead of what this computer holds and answers lets an edit
 * built on the older text be stored over the newer version, where the endpoint would otherwise refuse it as stale.
 */
interface PendingMark {
  readonly cellId: string;
  readonly seq: bigint;
  readonly commitment: string;
}
/** The longest cell id (and `next`) a listing may carry. */
const MAX_LISTED_CELL_ID_CHARS = 4_096;
const LIST_DIGITS = /^[0-9]{1,20}$/;
const LIST_HEX64 = /^[0-9a-f]{64}$/;

/**
 * A version listing page, checked whole. A page that drops or alters an entry would read, once complete, as an erasure
 * of the cell left out, so any entry this client cannot read refuses the PAGE: nothing is skipped and nothing is cut.
 * The recall-all array an endpoint without the listing answers with is refused by name (`listing_unsupported`); any
 * other answer that is not a listing is malformed.
 */
export function versionListingFrom(r: unknown): VersionListing {
  const malformed = (what: string): never => {
    throw new SaihmEndpointError(502, 'malformed_response', `endpoint returned a malformed version listing (${what})`);
  };
  // Only the recall-all array is what an endpoint without the listing answers with (it ignores `listOnly`). Any other
  // answer that is not a listing is one this client cannot read, and a recall with the copy on fails on it.
  if (Array.isArray(r)) {
    throw new SaihmEndpointError(
      501,
      'listing_unsupported',
      'the endpoint does not offer a version listing: it answered with a recall instead',
    );
  }
  if (typeof r !== 'object' || r === null) return malformed('not an object');
  if ((r as { mode?: unknown }).mode !== 'list') return malformed('not a listing');
  const o = r as { cells?: unknown; next?: unknown; asOf?: unknown };
  const cells = o.cells;
  const next = o.next;
  const asOf = o.asOf;
  if (!Array.isArray(cells)) return malformed('no cells');
  if (cells.length > MAX_LISTING_PAGE) return malformed('page too long');
  if (!(next === null || (typeof next === 'string' && next.length > 0 && next.length <= MAX_LISTED_CELL_ID_CHARS))) {
    return malformed('next');
  }
  const out: ListedVersion[] = [];
  const ids = new Set<string>();
  for (const raw of cells as unknown[]) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return malformed('entry');
    const e = raw as { cellId?: unknown; seq?: unknown; commitment?: unknown };
    const cellId = e.cellId;
    const seq = e.seq;
    const commitment = e.commitment;
    if (typeof cellId !== 'string' || cellId.length === 0 || cellId.length > MAX_LISTED_CELL_ID_CHARS) return malformed('cellId');
    if (!(seq === null || (typeof seq === 'string' && LIST_DIGITS.test(seq)))) return malformed('seq');
    if (typeof commitment !== 'string' || !LIST_HEX64.test(commitment)) return malformed('commitment');
    if (ids.has(cellId)) return malformed('a cell listed twice');
    ids.add(cellId);
    out.push({ cellId, seq, commitment });
  }
  // Optional, and only a helper: a value that is not a time is left out rather than passed on.
  const at = isoTime(asOf);
  return { cells: out, next, ...(at !== null ? { asOf: at } : {}) };
}

// ── the paged share listing ─────────────────────────────────────────────────────────────────────────────────────────

/** The most rows a share-listing page may hold, and what a pass asks for: the endpoint's own ceiling. */
export const SHARES_PAGE_MAX = 1_000;
/**
 * What the recall tool asks for: this many rows of four fields at the field cap ({@link MAX_ANNOUNCEMENT_FIELD_CHARS})
 * fit the announcement budget ({@link MAX_ANNOUNCEMENT_TOTAL_CHARS}) whole, so a tool page is never cut. A test pins the
 * product.
 */
export const SHARES_TOOL_PAGE_MAX = 128;
/** The longest cursor a pass carries: the wire's bound. */
export const MAX_SHARES_CURSOR_CHARS = 65_536;
/** The longest cursor the recall tool carries, as for the version listing: a longer one fails the page instead. */
export const MAX_TOOL_SHARES_CURSOR_CHARS = 4_096;
/** A pass's bounds: no more pages than this... */
export const SHARES_PASS_MAX_PAGES = 64;
/** ...and no page asked for once this has passed, whatever the endpoint sends. (Entries: the share map's own bound.) */
export const SHARES_PASS_DEADLINE_MS = 600_000;
/**
 * How long a status's word that the paged listing is NOT offered is kept: meanwhile no page is asked for and the status
 * is not read again for one; once it has passed, the next page or pass reads the status again, so a listing switched
 * on later is found. A status that could not be read says nothing: it is neither an offer nor an absence.
 */
export const SHARES_PAGED_ABSENT_MS = 600_000;
/** A cursor's characters, by the wire: opaque, printable, and nothing a fence must rewrite. */
const SHARES_CURSOR = /^[A-Za-z0-9._-]+$/;
/** `value` held to [least, most]; one that is not a number (NaN) is `most`, so no bound is lost to it. */
const withinBound = (value: number, least: number, most: number): number => {
  const n = Number(value);
  return Number.isNaN(n) ? most : Math.max(least, Math.min(n, most));
};

/** One share row of a page: the grant's key and terms and, where the endpoint follows shares, its grant, version and staleness. */
export interface SharesPageRow {
  /** THE ENDPOINT'S claims, unauthenticated, as for {@link SharedAnnouncement}. */
  readonly sharer: string;
  readonly cellId: string;
  readonly scope: string;
  /**
   * The expiry as claimed, or null for no expiry: a conforming endpoint sends a decimal epoch, a hostile one need not, so
   * guard any parse as {@link SharedAnnouncement} says.
   */
  readonly expiryEpoch: string | null;
  readonly grant: string | null;
  readonly seq: string | null;
  readonly commitment: string | null;
  readonly stale: boolean | null;
}

/** One page of the share listing (`saihm_recall` with `sharesOnly` and `paged`), in key order: sharer, then cell id. */
export interface SharesPage {
  readonly rows: readonly SharesPageRow[];
  /** The `after` for the next page, or null on the last one. Opaque: pass it back exactly. */
  readonly next: string | null;
  /** When the origin began the page, when it says (ISO-8601 UTC with milliseconds). */
  readonly asOf?: string;
  /** How many shares were live when the page was served, when the endpoint says: advisory, never a sign of completeness. */
  readonly total?: number;
}

/** The endpoint does not page the share listing: the reader falls back to the default recall's capped view. */
const sharesPagingUnsupported = (why: string): SaihmEndpointError =>
  new SaihmEndpointError(501, 'shares_paging_unsupported', `the endpoint does not offer the paged share listing: ${why}`);

/** Whether key `a` comes strictly before key `b`: sharer first, then cell id, both in UTF-16 code units, as the wire orders them. */
const shareKeyBefore = (a: { sharer: string; cellId: string }, b: { sharer: string; cellId: string }): boolean =>
  a.sharer < b.sharer || (a.sharer === b.sharer && a.cellId < b.cellId);

/**
 * A page of the share listing, checked whole. Only an object of mode "shares" that names `next` (null, or a cursor of the
 * wire's characters within `maxNextChars`) is a page; anything else (a list, the one-answer share listing, a full
 * recall) is `shares_paging_unsupported`, and nothing of it is kept. A page holds at most `max` rows, each a share row
 * by the announcement rules (no envelope; a sharer, cell id and scope that are strings; an expiry that is a string or
 * none), in strictly increasing key order, and at least one row when it names a next page. Anything else refuses the
 * PAGE as `malformed_response`: a page read in part would let a pass vouch for keys it never saw.
 */
export function sharesPageFrom(r: unknown, max: number, maxNextChars: number = MAX_SHARES_CURSOR_CHARS): SharesPage {
  if (typeof r !== 'object' || r === null || Array.isArray(r) || (r as { mode?: unknown }).mode !== 'shares' || !Object.hasOwn(r, 'next')) {
    throw sharesPagingUnsupported('it answered with something other than a page');
  }
  const malformed = (what: string): never => {
    throw new SaihmEndpointError(502, 'malformed_response', `endpoint returned a malformed share listing page (${what})`);
  };
  const o = r as { added?: unknown; next?: unknown; asOf?: unknown; total?: unknown };
  const added = o.added;
  const next = o.next;
  if (!(next === null || (typeof next === 'string' && next.length <= maxNextChars && SHARES_CURSOR.test(next)))) return malformed('next');
  if (!Array.isArray(added)) return malformed('no rows');
  if (added.length > max) return malformed('page too long');
  // `next` names the last key returned, so a page that returned none can name no next page.
  if (added.length === 0 && next !== null) return malformed('a next page after no row');
  const rows: SharesPageRow[] = [];
  let prev: SharesPageRow | undefined;
  for (const raw of added as unknown[]) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return malformed('row');
    const x = raw as Record<string, unknown>;
    const sharer = x.sharer;
    const cellId = x.cellId;
    const scope = x.scope;
    const expiryEpoch = x.expiryEpoch ?? null;
    if (
      x.shared !== true ||
      x.wire !== undefined ||
      typeof sharer !== 'string' ||
      typeof cellId !== 'string' ||
      typeof scope !== 'string' ||
      !(expiryEpoch === null || typeof expiryEpoch === 'string')
    ) {
      return malformed('row');
    }
    const row: SharesPageRow = {
      sharer,
      cellId,
      scope,
      expiryEpoch,
      grant: typeof x.grant === 'string' && LIST_HEX64.test(x.grant) ? x.grant : null,
      seq: typeof x.seq === 'string' && LIST_DIGITS.test(x.seq) ? x.seq : null,
      commitment: typeof x.commitment === 'string' && LIST_HEX64.test(x.commitment) ? x.commitment : null,
      stale: typeof x.stale === 'boolean' ? x.stale : null,
    };
    if (prev !== undefined && !shareKeyBefore(prev, row)) return malformed('rows out of key order');
    rows.push(row);
    prev = row;
  }
  // Optional, and helpers only: a value that is not what it should be is left out rather than passed on.
  const at = isoTime(o.asOf);
  const total = typeof o.total === 'number' && Number.isSafeInteger(o.total) && o.total >= 0 ? o.total : undefined;
  return { rows, next, ...(at !== null ? { asOf: at } : {}), ...(total !== undefined ? { total } : {}) };
}

/**
 * The page size the endpoint offers for the paged share listing, from a status answer's features
 * (`sharesPaged: {v: [1], max}`), or null when it offers none this client can use: then no page is ever requested. A
 * `max` left out is the wire's default and ceiling; one that is not a whole number of at least 1 makes the offer unusable.
 */
export function sharesPagedOffer(features: Readonly<Record<string, unknown>> | null): number | null {
  const f = features?.sharesPaged;
  if (typeof f !== 'object' || f === null || Array.isArray(f)) return null;
  const { v, max } = f as { v?: unknown; max?: unknown };
  if (!Array.isArray(v) || !v.includes(1)) return null;
  if (max === undefined) return SHARES_PAGE_MAX;
  return typeof max === 'number' && Number.isSafeInteger(max) && max >= 1 ? Math.min(max, SHARES_PAGE_MAX) : null;
}

/** The bounds of one pass, and the clock it is dated and timed by. */
export interface SharesPassOptions {
  /** The most keys the pass may hold: at most the share map's own bound. */
  readonly maxEntries: number;
  readonly maxPages: number;
  readonly deadlineMs: number;
  readonly now: () => number;
  /** Stops the pass between pages; it then ends incomplete (`stopped`). */
  readonly signal?: AbortSignal;
}

/**
 * A pass over the paged share listing: pages from the first (no `after`) until one names no next page. It is COMPLETE
 * only when every page was read, keys strictly increased across the whole pass (no key twice), no `next` repeated, the
 * last page named none, every row was a key the share map can hold, and the pass kept within its entries, pages and
 * time. A cursor the endpoint refuses (`bad_cursor`) starts the pass over once; a second refusal ends it. Any other
 * failure ends it incomplete, and an answer that is not a page (paging switched off) ends it `unsupported`. The page,
 * time and entry bounds hold for the whole call, a pass started over included.
 *
 * An incomplete pass vouches for nothing missing from it: it ends no share. Its rows are each a live claim when their
 * page was served, as a listing's are.
 */
export async function sharesPass(page: (after: string | undefined) => Promise<SharesPage>, opts: SharesPassOptions): Promise<SharesPass> {
  const maxEntries = withinBound(opts.maxEntries, 0, SHARE_MAP_MAX_ENTRIES);
  const maxPages = withinBound(opts.maxPages, 1, SHARES_PASS_MAX_PAGES);
  const deadline = opts.now() + withinBound(opts.deadlineMs, 0, SHARES_PASS_DEADLINE_MS);
  let pages = 0;
  let restarted = false;
  pass: for (;;) {
    const startedAt = opts.now();
    const entries: ListingEntry[] = [];
    const nexts = new Set<string>();
    let last: { sharer: string; cellId: string } | undefined;
    let unheld = false;
    let after: string | undefined;
    const end = (incomplete: SharesPassEnd): SharesPass => ({ complete: false, entries, pages, startedAt, incomplete });
    for (;;) {
      if (opts.signal?.aborted) return end('stopped');
      if (pages >= maxPages) return end('pages');
      if (opts.now() > deadline) return end('deadline');
      pages++;
      let p: SharesPage;
      try {
        p = await page(after);
      } catch (e) {
        const refusal = e instanceof SaihmEndpointError ? e : undefined;
        if (refusal?.code === 'bad_cursor' && refusal.status === 400 && !restarted) {
          restarted = true;
          continue pass;
        }
        return end(
          refusal?.code === 'shares_paging_unsupported'
            ? 'unsupported'
            : refusal?.code === 'bad_cursor'
              ? 'bad_cursor'
              : refusal?.code === 'malformed_response'
                ? 'malformed'
                : 'refused',
        );
      }
      if (opts.now() > deadline) return end('deadline');
      for (const row of p.rows) {
        if (last !== undefined && !shareKeyBefore(last, row)) return end('order');
        last = row;
        const entry = listingEntryFrom(row);
        // A key the map cannot hold is not refused: the pass just cannot vouch for it, and reads on.
        if (entry === null) {
          unheld = true;
          continue;
        }
        if (entries.length >= maxEntries) return end('entries');
        entries.push(entry);
      }
      if (p.next === null) return unheld ? end('unheld') : { complete: true, entries, pages, startedAt };
      if (nexts.has(p.next)) return end('repeated');
      nexts.add(p.next);
      after = p.next;
    }
  }
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
  /** What this identity may use, as the endpoint sent it: unchecked here, judged by `featuresOf`. */
  features?: unknown;
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
   * to learn the server seq. Note: reusing the id of a cell that was `forget`-ten is refused with a
   * typed `BLIND_STALE_SEQ` error by this client when it knows the cell erased (this device's erasure
   * feed names it, or a read here found it gone) and had read or saved it, and by the endpoint for a
   * device that never saw it (the endpoint keeps the cell's sequence high-water mark). Choose a fresh
   * id rather than reusing a forgotten one.
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
  /** Optional expiry in whole HOURS since the UNIX epoch (not seconds); omit / null for no time bound. */
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
   * Create `<feed root>/tenants/<agentIdHash>/` at construction so a downstream erasure consumer can
   * arm a directory watch on a directory that EXISTS rather than polling for one to appear.
   *
   * Off unless asked for, on the same asymmetry as `persistSeqState` above and for the same measured
   * reason: a directly-constructed client writes nothing anywhere. `bootFromEnv` turns it on. It
   * creates the directory only — never the `erasures.ndjson` file, because an empty feed and a
   * never-written one read identically to a consumer, and the directory alone says "this identity is
   * wired" without asserting an erasure history that does not exist.
   */
  ensureErasureFeedDir?: boolean;
  /**
   * Path to persist this agent's opened cells (mode 600), keyed by cellId. When set, `recall`
   * switches to DELTA mode: it reads the endpoint's version listing of this identity's cells, sends
   * as known the cached cells at their listed version, and fetches only the others (new, or changed
   * elsewhere), cutting a session-start recall from O(all cells) to O(new or changed cells). Holds
   * plaintext at rest, so it is opt-in (unset = full recall-all every call, the prior behavior).
   * Requires an endpoint that supports the listing and delta recall; degrades to a full recall if
   * the endpoint does not support them.
   */
  recallCachePath?: string;
  /**
   * Use {@link defaultRecallCachePath} when `recallCachePath` is not given. Off unless asked for, on
   * the same asymmetry as `persistSeqState`: a directly-constructed client writes nothing. `bootFromEnv`
   * turns it on for an identity booted from a key file (from 0.14.3, any key file), unless `SAIHM_RECALL_CACHE=0`.
   */
  persistRecallCache?: boolean;
  /**
   * Keep this identity's sign-in in {@link defaultSessionTokenPath} (0.14.3), so a later session on this device uses
   * it while it is good instead of signing in again. Off unless asked for, like `persistSeqState`: a directly
   * constructed client writes nothing. `bootFromEnv` turns it on for the default key file, unless
   * `SAIHM_SESSION_CACHE=0`. Ignored with a static `authHeader`, which signs in to nothing.
   */
  persistSessionToken?: boolean;
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
  /**
   * Invoked as each claim poll is SENT, and again as its answer leaves the flow still waiting (pending, or a nonce to
   * re-mint). Lets a caller tell when a poll that began after a given moment has been answered, so a memory call made
   * just after the human approves can wait for the poll that sees the approval. Optional; nothing else depends on it.
   */
  onClaimSent?: () => void;
  /** See {@link FreeEntitlementOpts.onClaimSent}. */
  onClaimAnswered?: () => void;
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

/**
 * Whether a `forget` writes its downstream erasure-feed line. DEFAULT ON; `SAIHM_ERASURE_FEED=0`
 * opts out. Same `!== '0'` shape as {@link selfJoinEnabled} so one rule covers both knobs.
 *
 * On by default because the consumer half of this seam is on by default: a delete that stops at this
 * substrate leaves artifacts derived from the cell alive downstream, which presents to the operator
 * as an erasure that happened. A feed that has to be switched on is a feed nobody switches on, and
 * the failure it prevents is silent. Writing costs one <=1KiB append under the identity's own home,
 * and a write that cannot happen is REPORTED on the receipt rather than thrown.
 */
export function erasureFeedEnabled(): boolean {
  return process.env.SAIHM_ERASURE_FEED !== '0';
}

/**
 * SAIHM_HOME as set, or `undefined` when it is unset or blank. Spaces alone made every path under it relative to the
 * working directory - a repository checkout, in a hosted agent - and a join minted the key there.
 */
export function saihmHomeSetting(): string | undefined {
  const v = process.env.SAIHM_HOME;
  return v !== undefined && v.trim() !== '' ? v : undefined;
}

/** The directory settings whose files this server writes, and so whose relative values it refuses. */
type DirSetting = 'SAIHM_HOME' | 'SAIHM_STATE_DIR';

/**
 * The first of `names` set to a path that is not absolute, or null; blank counts as unset, as everywhere. A relative
 * value, or one that begins with a space, resolves against the working directory - in a hosted agent a repository
 * checkout an agent may commit - and the key, an export, the sequence marks and the plaintext recall cache land there.
 */
export function relativeDirSetting(names: readonly DirSetting[] = ['SAIHM_HOME', 'SAIHM_STATE_DIR']): DirSetting | null {
  for (const name of names) {
    const v = process.env[name];
    if (v !== undefined && v.trim() !== '' && !isAbsolute(v)) return name;
  }
  return null;
}

/**
 * Why nothing is written under a relative directory setting, and what fixes it. Names the variable, never its value. An
 * earlier version wrote under such a value, so the refusal says where those files are: a key among them, for
 * SAIHM_HOME, and pointing it at an empty directory instead would leave a join free to make a new, empty identity.
 */
export function relativeDirRefusal(name: DirSetting, then: string): string {
  return (
    `${name} is not a full path, so nothing is written there: a relative path, or one that begins with a space, ` +
    `lands under the working directory. Set ${name} to the full path of a directory (JSON settings do not expand ~), ` +
    `then ${then}. Any files an earlier version wrote under this setting are in the folder it names inside the working ` +
    `directory of the run that wrote them (a leading ~ there is a folder named ~)` +
    (name === 'SAIHM_HOME' ? ', your key among them' : '') +
    // The path last, outside every delimiter: a path may hold any character a delimiter is made of.
    `: move them into that directory first. This run's working directory: ${safePathField(process.cwd(), MAX_PATH_FIELD_CHARS)}`
  );
}

/** Default on-disk location of a self-generated FREE identity (written mode 600). */
export function defaultIdentityPath(): string {
  const home = saihmHomeSetting() ?? pathJoin(homedir(), '.saihm');
  return pathJoin(home, 'free-identity.key');
}

/**
 * The identity's folder as a message names it: SAIHM_HOME when that is set, otherwise ~/.saihm. A refusal that said
 * "Fix SAIHM_HOME" when only the home folder's path had the shape of a key sent the reader to a variable never set.
 */
export function identityHomeName(): string {
  return saihmHomeSetting() !== undefined ? 'SAIHM_HOME' : '~/.saihm';
}

/** Why nothing is created under the identity's folder when its path has the shape of a key, and what fixes it. */
export function keyShapedHomeRefusal(verb: 'join' | 'export'): string {
  const consequence = verb === 'join' ? ', so no key is created there' : '';
  // An export reads the key this machine boots, which lives under that folder: once SAIHM_HOME moves, only naming the
  // key file as well lets the export find it.
  // Only a key that lives in a file needs naming: one given inline (SAIHM_MASTER_SECRET_HEX) or as a token has none.
  // Nor one already named: telling an operator to set SAIHM_MASTER_SECRET_FILE when it is set sends them to a done step.
  const namesKeyFile =
    verb === 'export' &&
    !process.env['SAIHM_MASTER_SECRET_HEX']?.trim() &&
    !process.env['SAIHM_MASTER_SECRET_FILE']?.trim() &&
    !identityTokenConfigured();
  const keyFile = namesKeyFile ? ', and SAIHM_MASTER_SECRET_FILE to the full path of your key file' : '';
  return saihmHomeSetting() !== undefined
    ? `SAIHM_HOME holds what looks like a key, passphrase or token rather than a directory${consequence}. ` +
        `Fix SAIHM_HOME${namesKeyFile ? ', set SAIHM_MASTER_SECRET_FILE to the full path of your key file' : ''}, then ${verb} again.`
    : `The path of your home folder, where ~/.saihm is, holds what looks like a key, passphrase or token${consequence}. ` +
        `Set SAIHM_HOME to the full path of a directory whose path does not${keyFile}, then ${verb} again.`;
}

/** The self-join key file as a message names it: its path, or its folder when the path has the shape of a key. */
function selfJoinKeyFileShown(p: string): string {
  return (
    displayableKeyPath(p) ??
    `free-identity.key under ${identityHomeName()} (its path has the shape of a key, so it is not shown)`
  );
}

/**
 * Whether an identity token is configured - the token, OR its passphrase alone. TRIMMED truthiness: a
 * blank value is what a `${SAIHM_IDENTITY:-}` reference in a shared MCP config yields on a machine
 * that has no token, and that machine must go on booting its own identity. The passphrase counts on
 * its own so that a host which delivered it and lost the token gets a typed error naming the missing
 * variable, instead of quietly booting whatever other identity this machine happens to hold.
 */
export function identityTokenConfigured(): boolean {
  return (
    identityTokenSet() || cleanPastedValue(process.env.SAIHM_IDENTITY_PASSPHRASE ?? '', PASSPHRASE_ENV) !== ''
  );
}

/**
 * Whether the TOKEN itself is set - not merely its passphrase. Blank as the paste cleaner reads it, so
 * an env file's `SAIHM_IDENTITY=""` (which arrives as two quote characters) is as absent as unset.
 * What names "the token" to a reader asks this; what decides whether to open one or to mint asks
 * {@link identityTokenConfigured}, because a passphrase alone must stop both.
 */
export function identityTokenSet(): boolean {
  return cleanPastedValue(process.env.SAIHM_IDENTITY ?? '', IDENTITY_ENV) !== '';
}

/**
 * A tier as it may be SHOWN: a plan this package knows by name, or `null`. SAIHM_TIER is typed by
 * hand, one field after the identity's passphrase in an install form, so a reply that echoed any
 * value would carry whatever was pasted there by mistake.
 */
export function displayablePlan(tier: string): string | null {
  return tier === 'FREE' || MONTHLY_PAID_TIERS.has(tier) ? tier : null;
}

/**
 * A key-file setting, or a path under the identity's folder, as it may be SHOWN: the value, or `null` when it has
 * the shape of a key, passphrase or token, or holds one in a part of the path - the test that refuses a folder.
 * Every site that names a key-file path to a reader goes through this, so a path a refusal blocks is never one a
 * message prints, and the guard cannot be applied at one site and missed at another. (A forget receipt's residual
 * paths are fenced on their own; they name the recall cache and erasure feed files, never a key file.)
 */
export function displayableKeyPath(v: string): string | null {
  return looksLikeIdentitySecret(v) || pathHoldsIdentitySecret(v) ? null : v;
}

/**
 * Whether {@link ensureSelfJoinIdentityEnv} would CREATE a key if called now. The join gates ask
 * this before calling it, and it reads the same variables in the same order, so the question asked
 * and the act performed cannot come apart.
 */
export function selfJoinWouldMint(): boolean {
  return (
    !identityTokenConfigured() &&
    !process.env.SAIHM_MASTER_SECRET_FILE &&
    !process.env.SAIHM_MASTER_SECRET_HEX &&
    !existsSync(defaultIdentityPath())
  );
}

/**
 * Signals that this process runs where the home directory is DISCARDED when the session ends: a
 * hosted agent session or a CI runner. A key minted there dies with the machine, and minting one
 * spends the once-per-person free activation on it - so the join paths refuse to mint where one of
 * these is set unless told the home does persist.
 *
 * Each entry is a variable the host itself documents and sets. Detection is a convenience on top of
 * the confirmation the join asks for anyway, never the only guard: an unlisted host is treated as
 * persistent, which is the behaviour every release before this one had everywhere.
 * `SAIHM_EPHEMERAL_HOME` overrides it both ways: `1` declares the home temporary, `0` declares it kept.
 */
const EPHEMERAL_HOME_SIGNALS: ReadonlyArray<readonly [string, (v: string) => boolean]> = [
  ['CLAUDE_CODE_REMOTE', (v) => v.trim().toLowerCase() === 'true'],
  ['GITHUB_ACTIONS', (v) => v.trim().toLowerCase() === 'true'],
  ['CI', (v) => v !== '' && v !== '0' && v.toLowerCase() !== 'false'],
];

/** The variable that marks this home as temporary, or `null` when none does. */
export function ephemeralHomeSignal(): string | null {
  // ANY DECLARATION COUNTS, not only `1`. The override is the operator's only way to mark a host this
  // list does not know, and `true` or `yes` meaning "kept" was a refusal that silently did not happen.
  // Only an explicit no (`0`, `false`, `no`, `off`) declares the home kept; blank means undeclared.
  const override = (process.env.SAIHM_EPHEMERAL_HOME ?? '').trim().toLowerCase();
  if (['0', 'false', 'no', 'off'].includes(override)) return null;
  if (override !== '') return 'SAIHM_EPHEMERAL_HOME';
  for (const [name, isSet] of EPHEMERAL_HOME_SIGNALS) {
    const v = process.env[name];
    if (v !== undefined && isSet(v)) return name;
  }
  return null;
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
 * Where the recall cache lives when the MCP server turns it on by default.
 *
 * Beside the default key file and the sequence marks, for the reasons given on
 * {@link defaultSeqStatePath}: the cache is identity-scoped, so it moves with the identity or not at
 * all, and it is named by the identity's hash so two identities sharing a home never read each
 * other's cells. The default applies to an identity that boots from a key file, this default one or
 * the one SAIHM_MASTER_SECRET_FILE names (0.14.3; before, only this one) — see `bootFromEnv`. For a key
 * file kept elsewhere the copy is still here, in SAIHM_HOME, beside the sequence marks this process
 * already keeps here for every identity.
 */
export function defaultRecallCachePath(agentIdHashHex: string): string {
  return pathJoin(dirname(defaultIdentityPath()), `recall.${agentIdHashHex.slice(0, 16)}.json`);
}

/**
 * Where a sign-in is kept between sessions (0.14.3): beside the default key file, the sequence marks and the recall
 * copy, named by the identity's hash like them, so two identities sharing a home never use each other's. Only the
 * default key file's identity keeps one (see `bootFromEnv`): that key mints any number of these tokens, so the file
 * gives nothing that the key beside it does not.
 */
export function defaultSessionTokenPath(agentIdHashHex: string): string {
  return pathJoin(dirname(defaultIdentityPath()), `session.${agentIdHashHex.slice(0, 16)}.json`);
}

/** A file's first line, read no further than the longest line the feed writes (1 KiB, its newline included). */
function firstLineOf(path: string): string {
  const firstLineReader = openSync(path, 'r');
  try {
    const buf = Buffer.alloc(1024);
    const n = readSync(firstLineReader, buf, 0, buf.length, 0);
    const text = buf.subarray(0, n).toString('utf8');
    const nl = text.indexOf('\n');
    return nl < 0 ? text : text.slice(0, nl);
  } finally {
    closeSync(firstLineReader);
  }
}

/**
 * The cellIds this identity's erasure feed records, each with a digest of the newest line naming it (so a second
 * erasure of one id is told from the first), re-read only when a feed file (the current one or its rotated
 * predecessor) changed: the same map is returned until then. Never throws: no feed yet, an unreadable one or a
 * misconfigured root all mean "nothing known to be erased", which leaves the cache exactly as it was before this reader
 * existed.
 */
function erasedCellIdsReader(agentIdHashHex: string): () => ReadonlyMap<string, string> {
  let seen = '';
  let ids: ReadonlyMap<string, string> = new Map<string, string>();
  return () => {
    try {
      const file = feedPathFor(resolveFeedRoot(), agentIdHashHex);
      // The predecessor too: a rotation must not make a session forget an erasure it has to keep off the disk.
      const files = [`${file}${PREDECESSOR_SUFFIX}`, file];
      // What identifies a file's content cheaply. Inode, size and time alone can repeat: an inode is reused once its
      // file is gone, and a coarse clock gives a recreated file of the same size the same time. The first line (at
      // most one line's worth) tells a recreated or rotated file from the one read before.
      const stats = files.map((f) => {
        try {
          const st = statSync(f);
          return `${st.ino}:${st.size}:${st.mtimeMs}:${JSON.stringify(firstLineOf(f))}`;
        } catch {
          return '-';
        }
      });
      if (stats[1] === '-' && stats[0] === '-') throw new Error('no feed');
      const key = stats.join('|');
      if (key !== seen) {
        const next = new Map<string, string>();
        for (const f of files) {
          let text: string;
          try {
            text = readFileSync(f, 'utf-8');
          } catch {
            continue;
          }
          for (const line of text.split('\n')) {
            try {
              const r = JSON.parse(line) as { cellId?: unknown };
              // The predecessor is read first, so the newest line naming an id is the one kept.
              if (typeof r.cellId === 'string') next.set(r.cellId, createHash('sha256').update(line).digest('base64'));
            } catch {
              /* a torn or empty line names no cell */
            }
          }
        }
        ids = next;
        seen = key;
      }
    } catch {
      /* nothing known to be erased */
    }
    return ids;
  };
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
  // A token has no file: the identity lives in the environment, and boot refuses a token configured
  // beside either secret variable, so nothing below can be the key this process uses.
  if (identityTokenSet()) return null;
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
/**
 * Age below which a stale identity temp is LEFT ALONE. A temp younger than this may belong to a
 * live `ensureSelfJoinIdentityEnv` in another process that is between its write and its rename,
 * and deleting that one would break a working mint to clean up after a dead one.
 */
export const STALE_TEMP_MIN_AGE_MS = 60 * 60 * 1000; // 1 hour

/**
 * Sweep orphaned identity temp files left by a HARD KILL between the atomic write and the rename.
 *
 * `ensureSelfJoinIdentityEnv` already unlinks its own temp when the RENAME throws, and `wx` proves
 * that temp was ours. Neither covers SIGKILL: the process simply stops, and what it leaves behind
 * is a mode-600 file containing THE MASTER SECRET, beside the key file, that nothing ever removes.
 * `forget()` and a delta recall both rewrite `<keyPath>`, which the temp is not.
 *
 * Bounded exactly as specified, because this function deletes files:
 *  - EXACT PREFIX `<basename>.tmp.`, matched with startsWith on enumerated directory entries. Not a
 *    glob. The key file itself is `<basename>` with no `.tmp.` suffix, so it can never match.
 *  - REGULAR FILES ONLY, via lstat, so a symlink planted in the directory is skipped rather than
 *    followed — the delete must never act through a link to somewhere else.
 *  - OWN UID only, where the platform reports one.
 *  - OLDER THAN `STALE_TEMP_MIN_AGE_MS`, so a concurrent in-flight mint is never destroyed.
 *  - UNLINKED BY EXACT RESOLVED NAME, one at a time.
 * Best-effort throughout: a failure on one entry must never prevent the join it is running ahead of.
 *
 * DARK BY DEFAULT. Runs only under `SAIHM_SWEEP_STALE_TEMPS=1` until the behaviour has been proven
 * in the field, because the failure mode of a sweep bug is deleting something that mattered.
 *
 * @returns the number of files actually unlinked.
 */
export function sweepStaleIdentityTemps(keyPath: string, now: number = Date.now()): number {
  const dir = dirname(keyPath);
  const prefix = `${basename(keyPath)}.tmp.`;
  let swept = 0;
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return 0; // no directory yet, or unreadable: nothing to sweep, and never a reason to fail a join
  }
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  for (const name of entries) {
    if (!name.startsWith(prefix)) continue;
    const full = pathJoin(dir, name);
    try {
      const st = lstatSync(full); // lstat, NOT stat: a symlink must be skipped, never followed
      if (!st.isFile()) continue;
      if (uid !== null && st.uid !== uid) continue;
      if (now - st.mtimeMs < STALE_TEMP_MIN_AGE_MS) continue;
      unlinkSync(full);
      swept++;
    } catch {
      continue; // vanished under us, or not ours to remove
    }
  }
  return swept;
}

export function ensureSelfJoinIdentityEnv(): { created: boolean; keyPath: string | null } {
  // Clear orphaned temps from a previous hard kill. ABOVE both early returns on purpose: the first
  // successful mint SETS `SAIHM_MASTER_SECRET_FILE`, so every subsequent call returns at the very
  // next line — and the steady state, where the key already exists and nothing is minted, is
  // precisely the run on which an orphan from the kill that preceded it would otherwise sit
  // forever. Wiring this below those returns made it dead code in the only case that matters.
  //
  // Always the DEFAULT path, never `SAIHM_MASTER_SECRET_FILE`: this package writes temps at the
  // default path and nowhere else, so a temp beside an operator-configured key file was not ours
  // and is not ours to delete.
  if (process.env.SAIHM_SWEEP_STALE_TEMPS === '1') {
    try {
      sweepStaleIdentityTemps(defaultIdentityPath());
    } catch {
      /* a sweep must never break a join */
    }
  }
  // A TOKEN IS AN IDENTITY, so there is nothing to mint and no file to name. Boot opens it - or says
  // why it does not open - and never falls back to a key minted here in its place: on a machine whose
  // home is discarded at session end, that fallback is how the join loop started.
  if (identityTokenConfigured()) return { created: false, keyPath: null };
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
    // Never under a SAIHM_HOME with the shape of a key, passphrase or token. The join gates refuse first,
    // in their own words; this keeps any other caller from creating a key whose path is a secret.
    if (pathHoldsIdentitySecret(keyPath))
      throw new SaihmConfigError(keyShapedHomeRefusal('join'), 'path');
    // Nor under a relative one: the key would be created under the working directory.
    if (relativeDirSetting(['SAIHM_HOME']) !== null)
      throw new SaihmConfigError(relativeDirRefusal('SAIHM_HOME', 'join again'), 'path');
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
      // Node named `keyPath` (or the tmp beside it) in its own message: widened only where that path may be
      // shown, and otherwise replaced by Node's code, so a home the refusal let through is not printed here.
      if (displayableKeyPath(keyPath) === null)
        throw new SaihmConfigError(
          `the key could not be created under ${identityHomeName()} (${nodeErrorCode(e)}); its path has the shape of a ` +
            'key, so it is not shown.',
          'path',
        );
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
      const shown = displayableKeyPath(keyPath);
      const code = (e as NodeJS.ErrnoException).code ?? 'unknown';
      throw new SaihmConfigError(
        (shown === null
          ? `the self-join identity file could not be read: free-identity.key under ${identityHomeName()} (${code}; its ` +
            'path has the shape of a key, so it is not shown). '
          : `the self-join identity file could not be read: ${shown} (${code}). `) +
          'Fix its permissions, or restore your backup of it - deleting it and running the join again mints a NEW ' +
          'identity, which starts an EMPTY memory.',
        'path',
      );
    }
    if (!holdsSecret)
      throw new SaihmConfigError(
        `the self-join identity file holds no secret: ${selfJoinKeyFileShown(keyPath)}. Restore your backup of it, or ` +
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
 * Whether files can be written in `dir`: it is a folder this process may write in, or it does not exist yet and the
 * nearest folder above it that does is one (a recursive mkdir would make it). Read at boot, so it is a forecast: a
 * folder made read-only later is met as before, by the write itself.
 */
function dirCanBeWritten(dir: string): boolean {
  for (let d = dir; ; d = dirname(d)) {
    try {
      accessSync(d, fsConstants.W_OK | fsConstants.X_OK);
      return statSync(d).isDirectory();
    } catch (e) {
      if (nodeErrorCode(e) !== 'ENOENT' || dirname(d) === d) return false;
    }
  }
}

/** The identity this process boots, as {@link resolveIdentityFromEnv} found it. */
export interface ResolvedIdentity {
  /** The master secret. The CALLER owns it and must scrub it (`fill(0)`) when done. */
  master: Uint8Array;
  tier: string | undefined;
  /** Where `tier` came from, so an export can say whether it is a choice or a default. */
  tierFrom: 'SAIHM_TIER' | 'SAIHM_IDENTITY' | 'default' | 'none';
  paymentMethod: string | undefined;
  /** Booted from the self-join default key file. */
  defaultKey: boolean;
  /**
   * Booted from a key FILE, the self-join default or the one `SAIHM_MASTER_SECRET_FILE` names: what the recall-cache
   * default keys on from 0.14.3 (it keyed on `defaultKey` before). Not an identity token or an inline secret.
   */
  keyFile: boolean;
  /** Where it came from: a variable name, or a phrase naming the file. */
  source: string;
}

/** Key files already warned about as group/world-accessible in this process. */
const looseKeyFilesWarned = new Set<string>();

/**
 * Resolve the identity this process would boot, WITHOUT constructing a client and without touching
 * the network: an identity token, else `SAIHM_MASTER_SECRET_FILE`, else `SAIHM_MASTER_SECRET_HEX`,
 * else the self-join default key file. Boot and `export-identity` both call this, so the identity a
 * server boots and the identity an export carries are the same one by construction. It never mints:
 * creating a key is {@link ensureSelfJoinIdentityEnv}'s job, and only the join paths call that.
 */
export function resolveIdentityFromEnv(): ResolvedIdentity {
  // AN IDENTITY TOKEN EXCLUDES the two master-secret variables rather than ranking above them. FILE
  // over HEX is a precedence operators built configs around; a token arriving beside either is a
  // SECOND identity, and picking one would open the wrong memory while every backup line named the
  // other. So both set is an error naming both, and a token that does not open is an error too - never
  // a fall-through to the self-join key below, which, on a machine whose home is discarded at session
  // end, is where the join loop came from.
  //
  // ONLY A TOKEN THAT IS REALLY THERE conflicts. A blank token beside its passphrase, or an unexpanded
  // `${...}` reference, is reported as itself by `openIdentityToken` - "Two identities are configured"
  // would name a variable that holds nothing, and its remedy, "unset the other", would point the
  // operator at the one variable that does hold their identity.
  let imported: OpenedIdentityToken | undefined;
  if (identityTokenConfigured()) {
    const token = process.env.SAIHM_IDENTITY ?? '';
    const alsoSet = ['SAIHM_MASTER_SECRET_FILE', 'SAIHM_MASTER_SECRET_HEX'].filter((n) => process.env[n]);
    if (alsoSet.length > 0 && identityTokenSet() && !token.includes('$'))
      throw new Error(
        `Two identities are configured: ${IDENTITY_ENV} and ${alsoSet.join(' and ')}. Keep the one ` +
          'whose memory you mean and unset the other; SAIHM does not guess between identities.',
      );
    imported = openIdentityToken(token, process.env.SAIHM_IDENTITY_PASSPHRASE ?? '');
  }
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
          'it, or point it at your key file.',
        'path',
      );
    try {
      secretHex = readFileSync(secretFile, 'utf-8');
    } catch {
      // A KEY PASTED WHERE A PATH BELONGS is not echoed. This message names the value so a mistyped
      // path can be fixed, and it reaches an agent's transcript as tool text - so a master secret, a
      // passphrase or a token pasted into the path field (the field beside them in an install form)
      // would land there in full. Those three shapes are recognisable, and none is a plausible path.
      if (displayableKeyPath(secretFile) === null)
        throw new Error(
          'SAIHM_MASTER_SECRET_FILE could not be read, and what it holds looks like a key, passphrase or ' +
            'token, so it is not shown. If it is a key, put the path of your key file there instead; if it is a ' +
            'path, check that the file exists and that you can read it.',
        );
      throw new SaihmConfigError(
        `SAIHM_MASTER_SECRET_FILE could not be read: ${secretFile}. Check the path and the file's ` +
          'permissions.',
        'path',
      );
    }
    try {
      // Advisory only (never blocks): warn if the secret file is group/world-accessible on POSIX.
      if (
        process.platform !== 'win32' &&
        !looseKeyFilesWarned.has(secretFile) &&
        (statSync(secretFile).mode & 0o077) !== 0
      ) {
        // ONCE per file per process: the join's tier check and the boot behind it both resolve the identity.
        looseKeyFilesWarned.add(secretFile);
        const shown = displayableKeyPath(secretFile);
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
          shown === null
            ? 'warning: the key file SAIHM_MASTER_SECRET_FILE names is group/world-accessible; chmod 600 it ' +
                '(its path has the shape of a key, so it is not shown).\n'
            : `warning: SAIHM_MASTER_SECRET_FILE ${safePathField(shown, MAX_PATH_FIELD_CHARS)} ` +
                'is group/world-accessible; chmod 600 it.\n',
        );
      }
    } catch {
      /* stat is advisory only */
    }
  } else {
    secretHex = process.env.SAIHM_MASTER_SECRET_HEX;
  }
  if (imported) secretHex = imported.secretHex;
  // Self-join fallback (ON by default; `SAIHM_SELF_JOIN=0` opts out): a prior `saihm_join`
  // persists the self-generated identity to the default key file, so a plain restart with no
  // env secret re-loads it. Under `SAIHM_SELF_JOIN=0` this block is inert.
  // This read "SAIHM_SELF_JOIN=1 only ... Off by default => this block is inert and boot
  // behaviour is unchanged" and was false: `selfJoinEnabled()` is `!== '0'` (measured across
  // unset/''/'1'/'anything' => true, '0' => false). The identical sentence was already found
  // and corrected in server.ts:833-835 and never propagated to this second
  // copy — the same fix-one-of-N-sites defect the shardId resolve-twice mutation exposed.
  if (!secretConfigured && !imported && selfJoinEnabled()) {
    const p = defaultIdentityPath();
    if (existsSync(p)) {
      try {
        secretHex = readFileSync(p, 'utf-8');
      } catch {
        throw new SaihmConfigError(
          `self-join identity file could not be read: ${selfJoinKeyFileShown(p)}. Fix its permissions, or restore your ` +
            'backup of it.',
          'path',
        );
      }
      // PRESENT BUT EMPTY is not "no identity". It fell through to the no-memory message below, which
      // called the file "not there" and steered to a join or an import - for the one case where the
      // real identity is in danger. Same words as the join path, which already refuses it.
      if (secretHex.trim() === '')
        throw new SaihmConfigError(
          `the self-join identity file holds no secret: ${selfJoinKeyFileShown(p)}. Restore your backup of it, or delete ` +
            'it and join again to mint a new identity - which starts an EMPTY memory, so restore ' +
            'first if you have a backup.',
          'path',
        );
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
        `SAIHM_MASTER_SECRET_FILE is set but holds no secret: ${displayableKeyPath(secretFile) ?? 'the file it names (its path has the shape of a key, so it is not shown)'}. Restore the key into ` +
          'it, or point the variable at the file that holds it.',
        'path',
      );
    // Self-join enabled but no identity yet => guide the agent to the join tool rather than
    // surfacing a raw env-var error (a memory tool was called before `saihm_join`).
    //
    // IT SAYS WHAT WAS CHECKED and asks the question the join used to skip. On a hosted agent's fresh
    // machine this is the first thing every session saw, and "Say 'Join SAIHM'" was the only way
    // forward it offered - so an operator whose memory lived on another machine was led, session after
    // session, into minting a new and empty one. The import path comes first because it is the one
    // nobody would find unprompted. A `'path'` config error because the message carries the default
    // key path; its remedy does not fit the plain-message budget.
    if (selfJoinEnabled())
      throw new SaihmConfigError(
        `No SAIHM memory yet on this device. Checked ${IDENTITY_ENV}, SAIHM_MASTER_SECRET_FILE and ` +
          // SAIHM_HOME-derived, so shown only when it has the shape of a path.
          `SAIHM_MASTER_SECRET_HEX (none set) and ${displayableKeyPath(defaultIdentityPath()) ?? 'the default key file'} (not there). Tell the ` +
          'operator: "SAIHM memory is installed but not active yet. Already have a SAIHM identity? ' +
          'Do not join: run npx -y @saihm/mcp-server-pro export-identity where it lives, set ' +
          `${IDENTITY_ENV} and ${PASSPHRASE_ENV} in this environment's settings (environment ` +
          'variables or secrets - never in this chat or a file in the repository; each host\'s steps ' +
          "are in the package README under Hosted agent environments), then start a new session. " +
          'New to SAIHM? Say ' +
          "'Join SAIHM' to start a new, empty memory.\" Run the saihm_join tool only when they ask " +
          'to join, then try again. Never ask for either value in the chat.',
        'path',
      );
    throw new Error(
      `No SAIHM identity is configured and self-join is off (SAIHM_SELF_JOIN=0). Set ${IDENTITY_ENV} and ` +
        `${PASSPHRASE_ENV}, or SAIHM_MASTER_SECRET_FILE or SAIHM_MASTER_SECRET_HEX, in this ` +
        "environment's settings - never in the chat or a repository file.",
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
  // `defaultKey` rides on the same comparison, however this process was pointed at that file. The recall-cache
  // default keys on `kind` (a key file of either kind) from 0.14.3.
  const secretSource: { label: string; kind: 'path' | 'env'; defaultKey: boolean } = imported
    ? { label: IDENTITY_ENV, kind: 'env', defaultKey: false }
    : secretFile
    ? secretFile === selfJoinIdentity
      ? { label: `the self-join identity file ${secretFile}`, kind: 'path', defaultKey: true }
      : { label: `SAIHM_MASTER_SECRET_FILE ${secretFile}`, kind: 'path', defaultKey: false }
    : process.env.SAIHM_MASTER_SECRET_HEX
      ? { label: 'SAIHM_MASTER_SECRET_HEX', kind: 'env', defaultKey: false }
      : { label: `the self-join identity file ${selfJoinIdentity}`, kind: 'path', defaultKey: true };
  // A path label is shown as every message that names a key file shows one: a key-shaped path is named by its folder,
  // or by the setting that holds it, and not printed. `source` keeps the full label; its one reader withholds it too.
  const shownLabel =
    secretSource.kind !== 'path' || displayableKeyPath(secretFile || selfJoinIdentity) !== null
      ? secretSource.label
      : secretSource.defaultKey
        ? `the self-join identity file under ${identityHomeName()}`
        : 'the file SAIHM_MASTER_SECRET_FILE names';
  const badSecret = (why: string): Error =>
    secretSource.kind === 'path'
      ? new SaihmConfigError(`${shownLabel} ${why}.`, 'path')
      : new Error(`${secretSource.label} ${why}.`);
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
  // THE LABEL IS CHECKED, not trusted. It travels in clear so a reader can tell tokens apart, and it
  // is bound into the ciphertext, so a token that opens with a label naming some other identity was
  // built that way by someone holding its passphrase. Refused before anything is written under it.
  if (imported && !toHex(deriveIdentity(master).agentIdHash).startsWith(imported.label)) {
    master.fill(0);
    throw new IdentityTokenError(
      `${IDENTITY_ENV} is labelled for a different identity than the one sealed inside it. Export ` +
        'the identity again on the machine that holds it.',
    );
  }
  // EMPTY MEANS UNSET for the tier, as it already did for the payment method. `??` let a blank
  // SAIHM_TIER through as a tier of '', which the constructor then reported as a missing payment
  // method. A blank is what a `${SAIHM_TIER:-}` reference yields wherever the variable is unset, so it
  // now falls through like an unset one: to the token's tier, then to the self-join default.
  return {
    master,
    tier: process.env.SAIHM_TIER || imported?.tier || (selfJoinEnabled() ? 'FREE' : undefined),
    tierFrom: process.env.SAIHM_TIER
      ? 'SAIHM_TIER'
      : imported?.tier
        ? 'SAIHM_IDENTITY'
        : selfJoinEnabled()
          ? 'default'
          : 'none',
    paymentMethod: process.env.SAIHM_PAYMENT_METHOD || imported?.paymentMethod,
    defaultKey: secretSource.defaultKey,
    keyFile: secretSource.kind === 'path',
    source: secretSource.label,
  };
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

/**
 * A sequence number written as a decimal string, or `null` if `t` is not one: digits without a leading zero, at most
 * the wire ceiling. The rule of a persisted mark (see `SeqState.parseMark`), shared with the recall copy's entries and
 * the version listing so all three are read alike.
 */
function seqFromDecimal(t: unknown): bigint | null {
  if (typeof t !== 'string' || t.length > MAX_COUNTER_CHARS) return null;
  if (!/^(?:0|[1-9][0-9]*)$/.test(t)) return null;
  const n = BigInt(t);
  return n > MAX_SEQ ? null : n;
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
   *
   * A cell shown gone - by a recall, a read or an erasure - STAYS in this set. Leaving it would send
   * the next edit to read the live version and write over whatever is there: a memory written again
   * under that id after its erasure, or one a full recall left out only because its stored copy
   * could not be read (measured: both stored over a version this process never saw, copy on or
   * off). Kept, the edit goes at the next number after the version seen here, so the endpoint
   * refuses it if anything was written since; `whyRefusedAsStale` then says which text is true. One
   * this process knows to be erased is refused before its write instead (see `GoneRecords`).
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
    return seqFromDecimal(typeof v === 'string' ? v : (v as { seq?: unknown })?.seq);
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
    // named for a replayed envelope below the mark is the one that says so. A third source, a cell a
    // recall answers from the copy, is marked only at the number the copy's own authenticated version
    // carries and the listing states (or leaves unstated, for that very version), and never when a mark above it is
    // held (`knownAtListedVersion`).
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

  /** The cells a mark is held for here: every one this device has read or saved, from this process or its marks file. */
  marked(): ReadonlySet<string> {
    return this.cellIds;
  }
}

/**
 * The memories this process knows to be erased, so that an edit of one is refused here, before anything is asked of the
 * endpoint. The endpoint keeps an erased memory's sequence number but stores a write past it, so an edit from a device
 * that had read the last version would save the memory again, without anyone being asked. A memory is known erased
 * when this process erased it, when this device's erasure feed names it in a line written since this process started
 * (a forget in another session here, or one made elsewhere and reported to it), or when an answer showed it
 * gone: a read by id, a share's read, an edit's own read or the read after a refused edit answering "no such cell", or
 * a recall's complete version listing leaving it out. A recall without the listing says nothing: it leaves out a
 * memory whose stored copy could not be read, as if it were gone.
 *
 * A record ends only when an answer shows the memory live and opens it, to a request sent after the record was made: a
 * read by id, a share's read, an edit's own read, an accepted write or a recall. Then the edit is checked against the
 * version seen, as any other. An answer to a request sent before the record was made shows a state that may predate
 * the erasure, so it ends nothing: what is in doubt is treated as erased, and the next read settles it. Records live in
 * this process only; a later session learns again from the feed, or from its edit's own read.
 */
class GoneRecords {
  /** Ordinal of the last request sent or record made in this process. */
  private turn = 0;
  /** cellId -> the turn at which it was last known gone. */
  private readonly at = new Map<string, number>();
  /** The feed's map as last read, and the newest line noted for each id it names. */
  private feedRead: ReadonlyMap<string, string> | undefined;
  private readonly feedLines = new Map<string, string>();

  /**
   * The feed's baseline is taken here, when the process starts, not at its first request: a memory this process saves
   * as new is seen with no request that would read the feed, and an erasure of it in another session before the
   * process's first such request would otherwise be taken for one from before the process (R17).
   */
  constructor(private readonly erasureFeed?: () => ReadonlyMap<string, string>) {
    this.noteFeed();
  }

  /** Taken just before a request whose answer may show a memory live. An erasure on the feed by then is noted first. */
  sent(): number {
    this.noteFeed();
    return ++this.turn;
  }

  /** A memory known gone from now on. */
  found(cellId: string): void {
    this.at.set(cellId, ++this.turn);
  }

  /** An answer to the request sent at `turn` opened a live version: a record made before that request ends. */
  live(cellId: string, turn: number): void {
    const t = this.at.get(cellId);
    if (t !== undefined && t < turn) this.at.delete(cellId);
  }

  /** Whether the memory is known gone here now. */
  has(cellId: string): boolean {
    this.noteFeed();
    return this.at.has(cellId);
  }

  /**
   * Each id the feed names in a line not noted before is known gone from now on. The lines already there when this
   * process starts are only noted: they record erasures from before it, and since then this device may
   * have read the memory saved again elsewhere, and edited it, in a session that has ended. An edit's own read, made
   * before every edit of a memory this process has not seen, tells those apart.
   */
  private noteFeed(): void {
    const named = this.erasureFeed?.();
    if (named === undefined || named === this.feedRead) return;
    const first = this.feedRead === undefined;
    for (const [id, line] of named) {
      if (this.feedLines.get(id) !== line) {
        this.feedLines.set(id, line);
        if (!first) this.found(id);
      }
    }
    this.feedRead = named;
  }
}

// ── recall delta cache (dark; active only when a recallCachePath is configured) ──────────────────
// Persists this agent's OPENED cells keyed by cellId so a session start can ask the endpoint for
// only new or changed cells (delta) instead of a full recall-all fan-out. Holds plaintext ⇒ written mode 600
// (same posture as the seq store) and opt-in by config, never on by default. A corrupt/absent file
// is treated as a cold start — the next recall repopulates it from a full or delta response.
//
// SELF-WRITE COHERENCE: a delta recall SKIPS cellIds it sends as known, so a client's own in-place
// UPDATE (remember with an existing cellId) or fresh create would be invisible to its next recall.
// remember() and forget() therefore update this cache directly (upsert / remove), keeping a client
// coherent with its OWN writes.
//
// OTHER WRITERS' VERSIONS: an update made by another computer, or another session whose copy this
// one never re-reads, keeps the cell's id. So a recall sends as known only the cells the copy holds
// at the version the endpoint's complete version listing states, commitment and sequence number
// (`knownAtListedVersion`), and the delta sends the current version of every other cell. A version written after the listing was
// read is fetched by the next recall. Without a listing the recall is a full one; a listing that
// cannot be used fails the recall.
const RECALL_CACHE_LOCK_WAIT_MS = 5_000;
/** The share map file is rewritten at least this often while the feed runs, so its `asOf` stays near the truth. */
const SHARE_STATES_WRITE_MS = 60_000;
const RECALL_CACHE_LOCK_STALE_MS = 30_000;
const RECALL_CACHE_LOCK_MALFORMED_GRACE_MS = 1_000;
const LOCK_WAIT_CELL = new Int32Array(new SharedArrayBuffer(4));

/** True unless the process is known to be gone (EPERM means it exists under another user). */
function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

class RecallCache {
  private cells = new Map<string, RecalledCell>();
  // Bumped by every mutation that actually changed something. A recall snapshots this BEFORE its
  // network call and re-checks it after: a response is only allowed to rewrite the cache if no local
  // write landed while it was in flight. Without that check a response captured before a `forget`
  // resurrects the cell it erased, and one captured before a `remember` deletes the cell it wrote —
  // both silently, both defeating the self-write coherence this class exists to provide. A plain
  // counter is enough because the only question asked of it is "did anything change", never "what".
  private mutations = 0;
  constructor(
    private readonly path?: string,
    private readonly erasedElsewhere?: () => ReadonlyMap<string, string>,
  ) {
    if (this.path) this.load();
  }

  /**
   * Drop every cell this identity has erased in ANY session. `forget` appends to the identity's erasure
   * feed; a second running session that still holds the cell in memory would otherwise write its
   * plaintext back on its next save — after the endpoint's copy was crypto-shredded, the only plaintext
   * left. Applied after load and before every save. With the feed off (SAIHM_ERASURE_FEED=0) the next
   * recall's live-cell list is what evicts it. A cellId written again after its erasure stays dropped
   * too, for as long as the feed names it: the erasure keeps winning, so nothing erased is ever written
   * back, and the newer cell is never cached. A delta recall answers from this cache, so it does not
   * return that cell at all (stale, not merely slower); only a full recall's answer, the endpoint's list
   * as sent, still carries it. A known limitation until the two are ordered by the endpoint's sequence.
   */
  private dropErased(): boolean {
    const erased = this.erasedElsewhere?.();
    if (!erased) return false;
    let dropped = false;
    for (const [id] of erased) if (this.cells.delete(id)) dropped = true;
    return dropped;
  }

  // The FILE still holds plaintext of a cell dropped at load. Memory no longer knows the cell, so a
  // `forget` of it would find nothing to remove and leave the plaintext on disk without saying so;
  // this flag makes that forget rewrite the file anyway — and report the residual if it cannot.
  private erasedOnDisk = false;

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
    // No write from a constructor: the next save rewrites the file, and a forget of the dropped cell
    // does so even though memory no longer holds it (see `erasedOnDisk`).
    if (this.dropErased()) this.erasedOnDisk = true;
  }

  private persist(): void {
    if (this.path === undefined) return;
    this.withWriteLock(() => this.persistLocked());
  }

  private persistLocked(): void {
    if (this.path === undefined) return;
    this.dropErased();
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
      this.erasedOnDisk = false;
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

  // CROSS-PROCESS WRITE LOCK. Two sessions of one identity can share this file. Measured against 0.7.0 with two real
  // processes: a forget removed the cell and only then appended its erasure line, and a save by the other session that
  // landed between the two had read the feed before the line existed, so it wrote the forgotten cell's plaintext back
  // while the forget reported nothing. Every save now reads the feed and renames under `<path>.lock`, and `forget`
  // appends the line and removes the cell under the same lock, so a save either lands before the erasure (and the
  // forgetting session's own write replaces it) or reads the feed after the line exists (and drops the cell).
  // Re-entrant within one process (a forget holds it across the removal's own save). A lock whose holder process is
  // gone, or that is older than RECALL_CACHE_LOCK_STALE_MS, is taken over; a live holder past RECALL_CACHE_LOCK_WAIT_MS
  // makes the call throw, which every caller already reports as a residual.
  private lockDepth = 0;

  withWriteLock<T>(fn: () => T): T {
    if (this.path === undefined) return fn();
    if (this.lockDepth > 0) {
      this.lockDepth++;
      try {
        return fn();
      } finally {
        this.lockDepth--;
      }
    }
    // Pinned like the directory the cache itself creates (see persistLocked).
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const lock = `${this.path}.lock`;
    const token = `${process.pid} ${Date.now()} ${randomBytes(8).toString('hex')}`;
    const deadline = Date.now() + RECALL_CACHE_LOCK_WAIT_MS;
    for (;;) {
      try {
        writeFileSync(lock, token, { mode: 0o600, flag: 'wx' });
        break;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      }
      let holder: string;
      let age: number;
      try {
        holder = readFileSync(lock, 'utf-8');
        age = Date.now() - statSync(lock).mtimeMs;
      } catch {
        continue; // released between the create and the read
      }
      const pid = Number(holder.split(' ')[0]);
      // An empty or unparseable lock is one being written right now (the create and the write are two steps), so it
      // is only taken over once it is clearly abandoned.
      const wellFormed = Number.isInteger(pid) && pid > 0;
      const abandoned =
        age > RECALL_CACHE_LOCK_STALE_MS || (wellFormed ? !processAlive(pid) : age > RECALL_CACHE_LOCK_MALFORMED_GRACE_MS);
      if (abandoned) {
        try {
          if (readFileSync(lock, 'utf-8') === holder) unlinkSync(lock);
        } catch {
          /* its owner or another waiter got there first */
        }
        continue;
      }
      if (Date.now() > deadline) {
        throw new Error(`the recall cache is locked by process ${wellFormed ? pid : 'unknown'}`);
      }
      Atomics.wait(LOCK_WAIT_CELL, 0, 0, 5);
    }
    this.lockDepth = 1;
    try {
      return fn();
    } finally {
      this.lockDepth = 0;
      try {
        if (readFileSync(lock, 'utf-8') === token) unlinkSync(lock);
      } catch {
        /* already gone */
      }
    }
  }

  /** How many cells the cache holds. */
  get size(): number {
    return this.cells.size;
  }

  /** The commitment of the version the cache holds for `cellId`, or undefined when it holds none. */
  commitmentOf(cellId: string): string | undefined {
    return this.cells.get(cellId)?.commitmentHash;
  }

  all(): RecalledCell[] {
    return [...this.cells.values()];
  }

  /** Merge a delta `added` set and prune to the endpoint's authoritative live cellId set. Persists
   *  only when something actually changed, so a no-op delta recall (nothing added, nothing forgotten)
   *  does not rewrite the whole cache file each session start. With `known`, the ids the request
   *  sent as known, a cached cell that was not among them was asked for: it is replaced by what came
   *  back, and when nothing came back for it (unreadable now, or no key held) it leaves the cache, as
   *  it would be absent from a full recall, rather than being served at a version the endpoint no
   *  longer holds. Without `known` every cached cell counts as known, as before. A file that cannot be
   *  written puts the cache back as it was (see `replaceAll`). */
  merge(added: RecalledCell[], liveCellIds: string[], known?: ReadonlySet<string>): void {
    const live = new Set(liveCellIds);
    const before = new Map(this.cells);
    let changed = false;
    for (const id of [...this.cells.keys()])
      if (!live.has(id) || (known !== undefined && !known.has(id))) {
        this.cells.delete(id); // prune forgotten, and every cell asked for again
        changed = true;
      }
    for (const c of added) {
      this.cells.set(c.cellId, c);
      changed = true;
    }
    if (changed) {
      this.mutations++;
      try {
        this.persist();
      } catch (e) {
        this.cells = before; // see `replaceAll`
        throw e;
      }
    }
  }

  /**
   * Replace the whole cache from a full recall result, then persist. When the file cannot be written the cache is put
   * back as it was and the failure thrown: the recall fails and answers nothing, so nothing it read may stay here
   * ahead of the seq marks, which it does not move either (see PendingMark). The next recall reads it again.
   */
  replaceAll(cells: RecalledCell[]): void {
    const before = this.cells;
    this.cells = new Map(cells.map((c) => [c.cellId, c]));
    this.mutations++;
    try {
      this.persist();
    } catch (e) {
      this.cells = before;
      throw e;
    }
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
    if (this.cells.delete(cellId) || this.erasedOnDisk) {
      this.mutations++;
      this.persist();
    }
  }
}

/** What this identity may use of warm start, as one call takes it (see `SaihmProClient.warmStartOffer`). */
export type WarmStartOffer = WarmStartLimits & WarmStartRoute;

/** One warm-start answer: its status, its body, its `Content-Digest` and the wait it asks for, all read by name. */
interface WarmStartAnswer {
  readonly status: number;
  readonly bytes: Uint8Array;
  readonly digest: string | undefined;
  readonly retryAfterS: number | null;
}

interface WarmStartRequestOpts {
  readonly body?: Uint8Array | string;
  readonly headers?: Readonly<Record<string, string>>;
  /** The most bytes the answer may hold. */
  readonly cap: number;
}

/** The most a warm-start answer other than a part or the listing may hold. */
const WARM_START_ANSWER_BYTES = 65_536;
/** The most a snapshot listing may hold. */
const WARM_START_LIST_BYTES = 1_048_576;
/** Room for a refusal's body where an answer is otherwise held to what a snapshot has left. */
const WARM_START_REFUSAL_BYTES = 4096;
/** How many times a part or a commit is sent before its refusal is the call's answer. */
const WARM_START_ATTEMPTS = 3;
/**
 * How many times an abort is sent: once, and once more only after a busy answer (503) or a connection refused or reset
 * before any answer. Never again after no answer in time.
 */
const WARM_START_ABORT_ATTEMPTS = 2;
/**
 * How long an abort may take in all, its second try included: the put's own failure is thrown no later than this after
 * it fails, whatever the endpoint does.
 */
export const WARM_START_ABORT_MS = 5_000;
/** The pause before an abort's second try, and never past the bound above. */
const WARM_START_ABORT_PAUSE_MS = 1_000;
/**
 * A commit's failures that do not say its snapshot was NOT stored: the upload gone (a commit sent again after an answer
 * that never came back finds it committed), the front unable to reach or relay the operator, or no answer at all.
 */
const COMMIT_FATE_UNKNOWN: ReadonlySet<string> = new Set(['upload_not_found', 'upstream_unavailable', 'bad_gateway', 'network', 'timeout']);

/** An answer's JSON, or undefined when it is not JSON. */
const parsedAnswer = (bytes: Uint8Array): unknown => {
  try {
    return JSON.parse(Buffer.from(bytes).toString('utf-8'));
  } catch {
    return undefined;
  }
};

/** Wait the seconds an answer asks for, between 1 and 30, plus up to a second of jitter. */
const warmStartPause = (seconds: number): Promise<void> =>
  new Promise((r) => setTimeout(r, Math.min(30, Math.max(1, seconds)) * 1000 + Math.floor(Math.random() * 1000)));

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
  /** Grants this process revoked, keyed JSON [cellId, recipientHex]: never re-issued, whatever the endpoint lists. */
  private readonly revokedGrants = new Set<string>();
  /** The share events feed, when started (SAIHM_EVENTS=1). Memory only: a new map and `since` at each start. */
  private shareFeed?: ShareEventsFeed;
  private shareStatesWriter?: { soon: () => void; stop: () => void };
  /** The writer of this identity's own-cell event files, when the feed runs and the erasure feed is on. */
  private ownChanges: ChangeFeedWriter | undefined;
  private lastFeedRenewAt = -Infinity;
  /**
   * The page size of the paged share listing, as the status last offered it; undefined until a status offers it, and
   * again after any answer to a page request that was not a page.
   */
  private sharesPagedMax: number | undefined;
  /** Until when the status's word that the paged listing is not offered is kept ({@link SHARES_PAGED_ABSENT_MS}). */
  private sharesPagedAbsentUntil = -Infinity;
  private readonly recallCache: RecallCache;
  /** The memories this process knows to be erased (see {@link GoneRecords}). */
  private readonly gone: GoneRecords;
  /** The uncached-recall notice is written at most once per process. */
  private saidRecallIsUncached = false;
  private readonly requestTimeoutMs: number;
  private tier: string | undefined;
  // Self-onboard token cache (single-flight via authInFlight). Written to disk only as the kept sign-in below.
  private cachedJwt: string | undefined;
  private cachedJwtRefreshAtMs = 0;
  private authInFlight: Promise<string> | null = null;
  /** The sign-in kept between sessions on this device (0.14.3), when on; see {@link SessionTokenFile}. */
  private sessionTokens: SessionTokenFile | undefined;
  /** After the endpoint refused a token, the next sign-in is a fresh one: no kept sign-in is used until one is made. */
  private keptSignInRefused = false;
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
    const recallCachePath =
      opts.recallCachePath ??
      (opts.persistRecallCache === true ? defaultRecallCachePath(this.agentIdHashHex) : undefined);
    // One reader of this identity's erasure feed, for the copy (which drops what it names) and for the edits it refuses.
    const erasures = erasureFeedEnabled() ? erasedCellIdsReader(this.agentIdHashHex) : undefined;
    this.recallCache = new RecallCache(recallCachePath, recallCachePath !== undefined ? erasures : undefined);
    this.gone = new GoneRecords(erasures);
    // Create this identity's erasure-feed directory NOW, while the identity is being loaded, rather
    // than lazily at the first `forget`. A downstream consumer can arm a directory watch on a
    // directory that exists; a missing one leaves it polling until something appears, so an erasure
    // is applied late for no reason other than when the directory happened to be made. The file is
    // NOT created — an empty `erasures.ndjson` and a never-written one read identically, and the
    // directory alone carries "this identity is wired" without asserting a history that is not there.
    //
    // Never fatal. A client that cannot make a directory under its own home is a client with a
    // problem worth reporting, but refusing to CONSTRUCT over it would take away recall and remember
    // as well — a strictly larger outage than the one being prevented. A `forget` that cannot write
    // its line says so on its own receipt, which is where an operator is actually looking.
    //
    // OPT-IN, exactly like `persistSeqState` and for the identical reason. Doing this in the
    // constructor was measured: `new SaihmProClient(...)` created `tenants/` inside the caller's real
    // `$HOME`, and the suite said so — a library that touches `$HOME` as a side effect of a
    // constructor is intrusive on its own, and it makes an embedder's tests order-dependent through
    // a directory they never named. `bootFromEnv` turns it on because the MCP server is the surface
    // that actually erases and `~/.saihm` is already its home.
    if (opts.ensureErasureFeedDir === true && erasureFeedEnabled()) {
      try {
        ensureTenantDir(this.agentIdHashHex);
      } catch {
        /* reported per-erasure on the receipt via `feedResidual`, not at construction */
      }
    }
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
      // The tier FIRST: with none, a FREE identity (self-join off) was told to set a payment method it does not need.
      if (this.tier === undefined) {
        throw new Error(
          'self-onboarding requires a tier (set SAIHM_TIER) when no auth header is supplied',
        );
      }
      if (this.tier !== 'FREE' && !opts.paymentMethod) {
        throw new Error(
          'self-onboarding requires a paymentMethod (set SAIHM_PAYMENT_METHOD) when no auth header is supplied',
        );
      }
      this.paymentMethod = opts.paymentMethod;
      // Bound to what the token is for: a file kept for another endpoint, identity, plan or payment method is not used.
      if (opts.persistSessionToken === true) {
        this.sessionTokens = new SessionTokenFile(defaultSessionTokenPath(this.agentIdHashHex), () => ({
          endpoint: this.endpoint,
          agentIdHash: this.agentIdHashHex,
          tier: this.tier,
          paymentMethod: this.paymentMethod,
        }));
      }
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
      throw new Error(
        'SAIHM_ENDPOINT_URL is set but empty: set it to an endpoint URL, or leave it out for the default.' +
          // The join hint only where a join would start an identity: one already configured has nothing to join.
          (selfJoinWouldMint() ? setupHint() : ''),
      );
    // Validate here, not only in the constructor: boot can throw on a missing
    // identity long before a client is ever constructed, which silently masked a
    // malformed or plain-http endpoint behind the join hint. The endpoint is
    // never contacted either way, so this is a diagnostic fix — it reports the
    // misconfiguration the operator actually has.
    assertEndpointUrl(endpoint);
    // A STATE DIRECTORY WITH THE SHAPE OF A SECRET is refused before anything is written under it: this
    // server's own writers create it - relative to the working directory when it is relative, which in a
    // hosted agent is a repository checkout an agent may commit. The join and the export refuse it too.
    for (const name of ['SAIHM_HOME', 'SAIHM_STATE_DIR'] as const) {
      const v = process.env[name];
      if (v && pathHoldsIdentitySecret(v))
        throw new SaihmConfigError(
          `${name} holds what looks like a key, passphrase or token rather than a directory, so nothing is ` +
            `written there. Fix ${name}, then start a new session.`,
          'path',
        );
    }
    // A RELATIVE STATE DIRECTORY is refused next, for the reason above: this server's writers would create it under
    // the working directory. After the secret check, so a secret pasted there is refused as one, unshown.
    const relativeDir = relativeDirSetting();
    if (relativeDir !== null)
      throw new SaihmConfigError(relativeDirRefusal(relativeDir, 'start a new session'), 'path');
    // A SECRET IN A PLAN OR PAYMENT FIELD - the fields beside the secret ones in an install form - is
    // refused rather than sent to the endpoint as the tier or the payment method.
    for (const name of ['SAIHM_TIER', 'SAIHM_PAYMENT_METHOD'] as const) {
      const v = process.env[name];
      if (v && looksLikeIdentitySecret(v))
        throw new SaihmConfigError(
          `${name} holds what looks like a key, passphrase or token, so it is not sent. Fix ${name}, then ` +
            'start a new session.',
          'path',
        );
    }
    const id = resolveIdentityFromEnv();
    const optTier = id.tier;
    const optSeqPath = process.env.SAIHM_SEQ_STATE_PATH;
    const optRecallCachePath = process.env.SAIHM_RECALL_CACHE_PATH;
    const optPaymentMethod = id.paymentMethod;
    const optDiscoverySource = process.env.SAIHM_DISCOVERY_SOURCE;
    const opts: SaihmProClientOpts = {};
    if (optTier) opts.tier = optTier;
    if (optSeqPath) opts.seqStatePath = optSeqPath;
    // THE SERVER OPTS IN. This is the boot path of the MCP server, where the rollback guard is worth
    // having across restarts and where `~/.saihm` already holds this identity's key. Constructing
    // `SaihmProClient` directly does not reach here and writes nothing.
    opts.persistSeqState = true;
    // THE SERVER OPTS IN here too, and only here. Same boundary as the line above: this is the
    // process that performs erasures, so this is the process whose consumer has something to watch.
    opts.ensureErasureFeedDir = true;
    // THE SERVER OPTS IN to the recall cache too, by default for an identity booted from a key FILE: the
    // self-join default in SAIHM_HOME, or the one SAIHM_MASTER_SECRET_FILE names (0.14.3, a privacy-default
    // change: before, only the default file). The copy goes in SAIHM_HOME beside the sequence marks, wherever
    // the key file is. An identity token or an inline secret is how hosted and CI environments carry an
    // identity, often with a home that is not kept, so the cache stays off there unless
    // SAIHM_RECALL_CACHE_PATH names a file. SAIHM_RECALL_CACHE=0 turns it off in every case, an explicit
    // path included.
    // ONLY WHERE THAT FOLDER CAN BE WRITTEN: a copy that cannot be written fails the recall it belongs to, and a
    // key file kept elsewhere is how a container mounts a secret beside a home it does not let anyone write. There,
    // 0.14.2 kept no copy and recalled; so does this. Measured: such a recall failed EACCES with the copy on.
    // NOR WHERE THE HOME IS TEMPORARY OR KEPT FOR LATER JOBS (0.14.3 review): a hosted session or a CI runner, as the
    // join reads it (ephemeralHomeSignal). A self-hosted runner keeps its home for the next job, so a default copy there
    // would leave every recalled memory, unencrypted, for jobs that never asked for it. A path set on purpose is kept,
    // and SAIHM_EPHEMERAL_HOME=0 declares the home kept.
    const recallCacheOff = process.env.SAIHM_RECALL_CACHE === '0';
    const temporaryHome = ephemeralHomeSignal() !== null;
    if (!recallCacheOff && optRecallCachePath) opts.recallCachePath = optRecallCachePath;
    else if (!recallCacheOff && id.keyFile && !temporaryHome && dirCanBeWritten(dirname(defaultIdentityPath()))) opts.persistRecallCache = true;
    if (optPaymentMethod) opts.paymentMethod = optPaymentMethod;
    if (optDiscoverySource) opts.discoverySource = optDiscoverySource;
    // THE SERVER OPTS IN to keeping its sign-in between sessions (0.14.3), for the DEFAULT key file only: the token file
    // then sits beside the key that can mint any number of them. A key file elsewhere (a removable or encrypted volume,
    // a mounted secret), an identity token and an inline secret sign in once per session, as before; so does any
    // identity where the home is temporary or kept for later jobs, as for the recall copy above.
    if (process.env.SAIHM_SESSION_CACHE !== '0' && id.defaultKey && !temporaryHome) opts.persistSessionToken = true;
    // SAIHM_AUTH_HEADER is OPTIONAL. Unset => self-onboard from SAIHM_MASTER_SECRET_HEX +
    // SAIHM_PAYMENT_METHOD + SAIHM_TIER (paste-once). Set => used verbatim, no self-onboarding.
    try {
      return new SaihmProClient(endpoint, auth, id.master, opts);
    } finally {
      id.master.fill(0); // scrub the decoded master secret; the identity holds only derived material
    }
  }

  /**
   * Say once, on the first recall, that this client is fetching every memory each time.
   *
   * The cache is deliberately off for an identity whose key did not come from a key file (an identity token, or an
   * inline secret: how hosted and CI environments carry one), and from 0.14.3 where the home is temporary or kept for
   * later jobs — this cache holds plaintext at rest, so it is not switched on for them. What was
   * missing is that nobody was TOLD: the difference is a recall that fetches only what changed against one that
   * fetches everything, and a subscriber had no way to know which one they were paying for.
   *
   * To stderr, never stdout: stdout carries the tool protocol, and a line written there corrupts it.
   *
   * Silent when the cache was turned off deliberately (`SAIHM_RECALL_CACHE=0`): someone who chose that does not
   * need telling, and a notice they cannot act on is noise that teaches them to ignore the next one.
   */
  private noticeIfRecallIsUncached(): void {
    if (this.saidRecallIsUncached || this.recallCache.configured) return;
    this.saidRecallIsUncached = true;
    if (process.env.SAIHM_RECALL_CACHE === '0') return;
    process.stderr.write(
      'saihm: recall fetches every memory on each call here, because this identity keeps no local copy: it comes ' +
      'from an identity token or an inline secret, SAIHM_HOME cannot be written, or the home is temporary or kept ' +
      'for later jobs. To fetch only what has changed since the last recall, point SAIHM_RECALL_CACHE_PATH at a ' +
      'file you own; it holds your memories as plaintext at rest, readable only by you. SAIHM_RECALL_CACHE=0 ' +
      'keeps it off and silences this.\n',
    );
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
      this.authInFlight = this.signIn().finally(() => {
        this.authInFlight = null;
      });
    }
    return 'Bearer ' + (await this.authInFlight);
  }

  /**
   * A token for the next request: the one an earlier session on this device kept, while it is good for more than the
   * refresh margin (0.14.3), else a fresh sign-in, which is then kept for the next session. A kept token is used only
   * as {@link SessionTokenFile} reads one; whether it is still good is read from the token's own expiry.
   */
  private async signIn(): Promise<string> {
    const kept = this.keptSignInRefused ? undefined : this.sessionTokens?.read();
    if (kept !== undefined) {
      const expMs = jwtExpMs(kept);
      if (expMs !== undefined && Date.now() < expMs - JWT_REFRESH_SKEW_MS) {
        this.holdToken(kept, expMs);
        return kept;
      }
    }
    const jwt = await this.onboard();
    this.keptSignInRefused = false;
    // Only a token whose expiry can be read: the next session could not tell whether any other is still good.
    if (jwtExpMs(jwt) !== undefined) this.sessionTokens?.keep(jwt);
    return jwt;
  }

  /**
   * The endpoint refused the token in `header` (a 401): drop it here and from the file that kept it, if it still holds
   * that token, and make the next sign-in a fresh one.
   */
  private tokenRefused(header: string): void {
    this.cachedJwt = undefined;
    if (this.sessionTokens === undefined) return;
    this.keptSignInRefused = true;
    if (header.startsWith('Bearer ')) this.sessionTokens.drop(header.slice('Bearer '.length));
  }

  /**
   * Hold `jwt` in memory until shortly before `expMs`. The skew is clamped to at most half the remaining life, so a
   * short-lived token still yields a positive cache window (otherwise every call would sign in again).
   */
  private holdToken(jwt: string, expMs: number): void {
    this.cachedJwt = jwt;
    const now = Date.now();
    const skew = Math.min(JWT_REFRESH_SKEW_MS, Math.max(0, Math.floor((expMs - now) / 2)));
    this.cachedJwtRefreshAtMs = expMs - skew;
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
    // Schedule proactive refresh BEFORE expiry. Honor the token's own `exp`; for an opaque token assume
    // a short conservative TTL.
    this.holdToken(out.jwt, jwtExpMs(out.jwt) ?? Date.now() + OPAQUE_TOKEN_TTL_MS);
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
        opts.onClaimSent?.();
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
      opts.onClaimAnswered?.();
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
      const res = await keepAliveFetch(url, { ...init, signal: ctrl.signal });
      const text = await readBodyCapped(res, MAX_RESPONSE_BYTES, 'onboard');
      if (!res.ok) {
        let code: string | undefined;
        let reason: string | undefined;
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
          // The REASON rides beside the code and was dropped here, so a paid identity booted at the
          // default FREE tier read `verification_failed` on every call with nothing saying which
          // variable was wrong. Sliced at the mint like the code, and rendered beside it.
          if (typeof j.reason === 'string') reason = j.reason.slice(0, MAX_ERROR_CODE_CHARS);
        } catch {
          /* non-JSON error body — leave code undefined */
        }
        // A LIMIT WITH NO BODY - the edge's own, which sends only `retry-after` - is named for what it is, with the
        // wait. It read as an `[unknown]` error with no way forward. A 429 that carries a code keeps it.
        if (res.status === 429 && code === undefined)
          throw new SaihmEndpointError(
            429,
            'rate_limited',
            // Opens with SIGN_IN_LIMITED, written out so the join path's mint sweep names it by its text.
            `SAIHM could not sign in: too many sign-ins in a short time (429 ${res.statusText.slice(0, MAX_ERROR_CODE_CHARS)}). Wait ${retryAfterWait(res)}, then try again.`,
          );
        throw new SaihmEndpointError(
          res.status,
          code,
          // `statusText` is an endpoint-chosen reason phrase, sliced at the mint like every other
          // endpoint string reaching an error: short by RFC, unbounded by our transport.
          `SAIHM onboard failed: ${res.status} ${res.statusText.slice(0, MAX_ERROR_CODE_CHARS)}` +
            (code ? ` (${code}${reason ? `: ${reason}` : ''})` : '') +
            onboardRemedy(res.status, code, reason),
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
      // A timeout whatever the error is called: see `doCall`, whose body read stalls the same way.
      if ((e instanceof Error && e.name === 'AbortError') || ctrl.signal.aborted) {
        throw new SaihmEndpointError(
          408,
          'timeout',
          `SAIHM onboard timed out after ${this.requestTimeoutMs}ms`,
        );
      }
      // BARE LITERALS, deliberately, and they stay so. FF18 sweeps the join path for every
      // SaihmEndpointError mint whose message is not a bare literal and requires each to be
      // individually accounted for and driven at two magnitudes — the guarantee being that
      // no endpoint-sized text can reach the JoinState the server retains. Naming the dialed
      // endpoint here was tried on 2026-09-23 and the sweep correctly rejected it: the win is
      // small, the invariant is not, and the endpoint-call path already carries the detail.
      //
      // Each is still ONE bare literal after gaining its remedy - a concatenation reads to that sweep
      // as a built message - and which one is CHOSEN by the class of the failure, never built from
      // it: a certificate this machine does not trust (a network that inspects TLS), a proxy setting
      // this transport cannot use, a proxy in the way, or none. A hosted agent environment that
      // blocks the endpoint's host is the common way to arrive at the last two - its egress proxy
      // refuses the tunnel - so the allowlist leads there too. An answer that arrived but cannot be used comes first:
      // the endpoint was reached, and that advice would send the reader to the wrong place.
      if (transportReason(e) === 'REDIRECT_CROSS_ORIGIN')
        throw new SaihmEndpointError(
          0,
          'network',
          'SAIHM onboard transport error: the SAIHM endpoint redirects to another host, which is not followed when signing in. Set SAIHM_ENDPOINT_URL to the address your operator gives.',
        );
      if (UNUSABLE_ANSWER.has(transportReason(e)))
        throw new SaihmEndpointError(
          0,
          'network',
          'SAIHM onboard transport error: the SAIHM endpoint sent an answer this client cannot use. Check SAIHM_ENDPOINT_URL; if it is right, tell the operator.',
        );
      if (untrustedCertificate(transportReason(e)))
        throw new SaihmEndpointError(
          0,
          'network',
          "SAIHM onboard transport error: the SAIHM endpoint's certificate is not trusted here. Never turn certificate checks off: if this network inspects TLS, get its CA certificate from its administrator, set NODE_EXTRA_CA_CERTS to that file and restart.",
        );
      // Named exactly: the lowercase variable is read first, and naming HTTPS_PROXY for a broken
      // https_proxy sent the reader to fix the one that was fine.
      if (unusableProxy(transportReason(e)) && transportReason(e).startsWith('https_proxy'))
        throw new SaihmEndpointError(
          0,
          'network',
          "SAIHM onboard transport error: the proxy in https_proxy (read before HTTPS_PROXY) is not an http URL, and only http proxies are supported. Fix it, or add the endpoint's host to NO_PROXY.",
        );
      if (unusableProxy(transportReason(e)))
        throw new SaihmEndpointError(
          0,
          'network',
          "SAIHM onboard transport error: the proxy in HTTPS_PROXY is not an http URL, and only http proxies are supported. Fix it, or add the endpoint's host to NO_PROXY.",
        );
      // The variable READ is named: with a broken https_proxy, that is the one to fix, whatever HTTPS_PROXY holds.
      if (proxyApplies(url) && proxyVariableInUse() === 'https_proxy')
        throw new SaihmEndpointError(
          0,
          'network',
          "SAIHM onboard transport error: the SAIHM endpoint could not be reached through the proxy in https_proxy. In a hosted agent environment, allow its host (saihm.net by default) in the network settings; else check the proxy and NO_PROXY.",
        );
      if (proxyApplies(url))
        throw new SaihmEndpointError(
          0,
          'network',
          "SAIHM onboard transport error: the SAIHM endpoint could not be reached through the proxy in HTTPS_PROXY. In a hosted agent environment, allow its host (saihm.net by default) in the network settings; else check the proxy and NO_PROXY.",
        );
      throw new SaihmEndpointError(
        0,
        'network',
        "SAIHM onboard transport error: the SAIHM endpoint could not be reached. In a hosted agent environment, allow the endpoint's host (saihm.net by default) in its network settings; if traffic must go through a proxy, set HTTPS_PROXY.",
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
        this.tokenRefused(header);
        const fresh = await this.currentAuthHeader();
        try {
          result = await this.doCall<T>(method, params, fresh);
        } catch (e2) {
          // The fresh token refused too: it is not kept for the next session either.
          if (e2 instanceof SaihmEndpointError && e2.status === 401) this.tokenRefused(fresh);
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
      // From just before the request is sent to the last byte received: the client's half of `timing`.
      const sentAt = performance.now();
      const res = await keepAliveFetch(this.endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: authHeader,
        },
        body: JSON.stringify({ method, params }),
        signal: ctrl.signal,
      });
      const text = await readBodyCapped(res, MAX_RESPONSE_BYTES, method);
      const totalMs = performance.now() - sentAt;
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
        // A limit with no body, as on the onboard path: named, with the wait.
        if (res.status === 429 && code === undefined)
          throw new SaihmEndpointError(
            429,
            'rate_limited',
            `SAIHM endpoint ${method} failed: 429 ${res.statusText.slice(0, MAX_ERROR_CODE_CHARS)}. Wait ${retryAfterWait(res)}, then try again.`,
          );
        throw new SaihmEndpointError(
          res.status,
          code,
          // `statusText` is endpoint-chosen — sliced at the mint, same invariant as the `code` arm.
          `SAIHM endpoint ${method} failed: ${res.status} ${res.statusText.slice(0, MAX_ERROR_CODE_CHARS)}` +
            (code ? ` (${code})` : ''),
        );
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new SaihmEndpointError(
          res.status,
          'malformed_json',
          `SAIHM endpoint ${method} returned a non-JSON 2xx response`,
        );
      }
      noteAnswer(method, res, totalMs, parsed);
      return parsed as T;
    } catch (e) {
      if (e instanceof SaihmEndpointError) throw e;
      // A TIMEOUT whatever the error is called. The limit landing while the body streams destroys the socket, and the
      // body read then fails as ECONNRESET: an endpoint that answered and then stalled read as one never reached.
      if ((e instanceof Error && e.name === 'AbortError') || ctrl.signal.aborted) {
        throw new SaihmEndpointError(
          408,
          'timeout',
          `SAIHM endpoint ${method} timed out after ${this.requestTimeoutMs}ms`,
        );
      }
      const reason = transportReason(e);
      // The endpoint was reached, but its answer cannot be used: no network advice.
      // The endpoint is named in the OPENING (see `transportFailure`), so a long SAIHM_ENDPOINT_URL is cut there and
      // never cuts the reason and the remedy after it. The message is the text it always was.
      if (UNUSABLE_ANSWER.has(reason))
        throw transportFailure(
          `SAIHM endpoint ${method} got an answer it cannot use from ${safeEndpoint(this.endpoint)}`,
          `(${reason}). ` +
            (reason === 'REDIRECT_CROSS_ORIGIN'
              ? 'It redirects to another host: set SAIHM_ENDPOINT_URL to the address your operator gives.'
              : 'Check SAIHM_ENDPOINT_URL; if it is right, tell the operator.'),
        );
      throw transportFailure(
        `SAIHM endpoint ${method} could not reach ${safeEndpoint(this.endpoint)}`,
        `(${reason}). ` +
          (untrustedCertificate(reason)
            ? 'Never disable certificate checks; if TLS is inspected here, set NODE_EXTRA_CA_CERTS to a file ' +
              "of the network admin's CA certificate."
            : unusableProxy(reason)
              ? 'Only an http proxy URL is supported: fix the variable named above, or add this host to NO_PROXY.'
              : proxyApplies(this.endpoint)
                ? proxyVariableInUse() === 'https_proxy'
                  ? 'Via https_proxy: if hosted, allow this host in its network settings; else check the proxy and ' +
                    'NO_PROXY.'
                  : 'Via HTTPS_PROXY: if hosted, allow this host in its network settings; else check the proxy and ' +
                    'NO_PROXY.'
                : 'If hosted, allow that host in its network settings; to use a proxy, set HTTPS_PROXY and check ' +
                  'NO_PROXY.'),
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
    marks?: PendingMark[],
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
    // With `marks`, the mark is handed to the caller instead (see PendingMark): a recall applies it only with the answer.
    if (marks !== undefined) marks.push({ cellId: env.cellId, seq: env.seq, commitment: envCommitment });
    else this.observeMark(env.cellId, env.seq, envCommitment);
    return {
      cellId: env.cellId,
      plaintext,
      seq: env.seq.toString(10),
      commitmentHash: envCommitment,
    };
  }

  /** Advance one seq mark, the path of an operator-named marks file kept whole in its error. */
  private observeMark(cellId: string, seq: bigint, commitment: string): void {
    try {
      this.seq.observe(cellId, seq, commitment);
    } catch (e) {
      throw markPathBearing(e);
    }
  }

  /**
   * Apply the marks a recall read, under one marks write, the recall's first request sent at `turn`. With `held`, only
   * a mark whose version the copy now holds: one the copy dropped (erased in another session) or never took stays where
   * it was. A memory whose mark is applied is one the answer shows live (see {@link GoneRecords}).
   */
  private applyMarks(marks: readonly PendingMark[], held: ((cellId: string) => string | undefined) | undefined, turn: number): void {
    this.seq.withBatch(() => {
      for (const m of marks) {
        if (held !== undefined && held(m.cellId) !== m.commitment) continue;
        this.observeMark(m.cellId, m.seq, m.commitment);
        this.gone.live(m.cellId, turn);
      }
    });
  }

  /**
   * Put a version of an own cell whose mark a single read just advanced into the copy, so the mark and what this
   * computer holds move together (see PendingMark). A version the copy already holds is not written again. The copy
   * is a convenience: if it cannot be written the entry is dropped instead, and the read or write it serves never
   * fails because of it.
   */
  private keepInCopy(cell: RecalledCell): void {
    if (!this.recallCache.configured || this.recallCache.commitmentOf(cell.cellId) === cell.commitmentHash) return;
    try {
      this.recallCache.upsert(cell);
    } catch {
      try {
        this.recallCache.remove(cell.cellId);
      } catch {
        /* cache unwritable; the entry is dropped in memory and the next recall rebuilds it */
      }
    }
  }

  /**
   * Take a memory a read just found gone out of the copy, so its text does not stay on this device after its erasure
   * until the next recall. Only while the copy holds the version it held before that read was sent: one a write of this
   * process put there meanwhile stays. If the copy cannot be written, the entry is dropped in memory and the next save
   * that succeeds drops it from the file. Its read mark and sequence mark stay (see `whyRefusedAsStale`).
   */
  private dropGoneFromCopy(cellId: string, heldBefore: string | undefined): void {
    if (heldBefore === undefined || this.recallCache.commitmentOf(cellId) !== heldBefore) return;
    try {
      this.recallCache.remove(cellId);
    } catch {
      /* unwritable: gone from memory now, and from the file at the next save that succeeds */
    }
  }

  /**
   * Refuse an edit of a memory this process knows to be erased (see {@link GoneRecords}) and this device had read or
   * saved (a mark held here), before anything is asked of the endpoint, with the code it gives a stale write: it stores
   * a write past an erased memory's number, so the edit would save the memory again without the user. Nothing is sent
   * and nothing is charged. A cellId this device never read or saved goes to the endpoint as before.
   */
  private refuseIfKnownErased(cellId: string): void {
    if (this.seq.current(cellId) !== undefined && this.gone.has(cellId)) {
      throw new SaihmEndpointError(409, 'BLIND_STALE_SEQ', ERASED_EDIT);
    }
  }

  /**
   * Which text is true for a write refused as stale (see {@link StaleWrite}). After a read of the live version it is
   * known without another request: what that read found, and for a memory gone, whether this device had read or saved
   * it (a mark held here; a memory gone with one is refused before its write, see `refuseIfKnownErased`). Without one -
   * this process had read or saved the memory, and a version past that was written since - the memory is read once
   * more, to tell whether it is still there. Not charged when it is gone (the endpoint answers "no such cell" before it
   * counts a read); if the read fails, the text says what the refusal itself shows. That read moves no mark and puts
   * nothing in the copy, and a memory found gone keeps its marks here and is known erased from then on (see
   * {@link GoneRecords}), so the next edit is refused here with nothing asked, and one after a memory written again
   * under this id, or one a recall left out because it could not be read, is still checked against the version this
   * process saw: refused, never replaced unseen. (Dropping the read mark instead made that next edit read the live
   * version and store over it, copy on or off: measured.) The sequence mark stays as the endpoint's does, so an older
   * version served again is still refused.
   */
  private async whyRefusedAsStale(cellId: string, preRead: 'found' | 'gone' | 'unread' | undefined): Promise<StaleWrite> {
    if (preRead === 'found') return 'changed';
    if (preRead === 'gone') return this.seq.current(cellId) !== undefined ? 'erased' : 'used';
    if (preRead === 'unread') return 'used';
    const heldBefore = this.recallCache.commitmentOf(cellId);
    try {
      const now = await this.recallRawOne(cellId);
      if (now.found === false) {
        this.dropGoneFromCopy(cellId, heldBefore);
        this.gone.found(cellId);
        return 'erased';
      }
    } catch {
      /* the read failed: the refusal itself shows only that a newer version was written */
    }
    return 'changed';
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
    // What that read of the live version found: `found`, `gone` (the endpoint's own "no such cell") or `unread` (an
    // answer this client cannot read). Undefined when no read ran: this process had read or saved the cell. A refusal
    // as stale is told by it (see `whyRefusedAsStale`).
    let preRead: 'found' | 'gone' | 'unread' | undefined;
    if (opts.cellId !== undefined) this.refuseIfKnownErased(cellId);
    if (
      opts.cellId !== undefined &&
      !this.seq.observedLiveThisRun(cellId) &&
      this.seq.current(cellId) !== MAX_SEQ
    ) {
      const heldBefore = this.recallCache.commitmentOf(cellId);
      const turn = this.gone.sent();
      const existing = await this.recallRawOne(cellId);
      if (existing.found && existing.wire) {
        // decode + attribute + openCell(authenticates seq) + observe, and the copy holds what the mark now names
        this.keepInCopy(this.openRow(cellId, existing.wire));
        this.gone.live(cellId, turn);
        preRead = 'found';
      } else if (existing.found === false) {
        preRead = 'gone';
        this.dropGoneFromCopy(cellId, heldBefore);
        this.gone.found(cellId);
        // A mark held here (an earlier session read or saved it): an edit of an erased memory, refused before its write.
        this.refuseIfKnownErased(cellId);
      } else preRead = 'unread';
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
    // Known erased while this edit waited (a forget, or a read that found it gone, in this process): refused as above.
    if (opts.cellId !== undefined) this.refuseIfKnownErased(cellId);
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
    let r: RememberResult;
    // A new memory's id is drawn here, so nothing is known of it: only an edit's write can end a record.
    const writeTurn = opts.cellId !== undefined ? this.gone.sent() : 0;
    try {
      r = await this.call<RememberResult>('saihm_remember', { wire });
    } catch (e) {
      // A new memory's id was drawn here at random, so a refusal of it as stale is the endpoint's word alone: passed on.
      if (!refusedAsStale(e) || opts.cellId === undefined) throw e;
      throw staleWriteRefusal(e, await this.whyRefusedAsStale(cellId, preRead));
    }
    // Stored: the memory is live at this version, whatever the marks file below says.
    if (opts.cellId !== undefined) this.gone.live(cellId, writeTurn);
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
    // Resolved once, like `shardId`, and only a zoned time is kept: anything else is no time this client can compare.
    const at = isoTime((r as { at?: unknown } | undefined)?.at);
    // After the write, its marks and its cache entry: the grants it left on the previous version. Never throws.
    const shares = await this.reissueStaleShares(cellId, env, r);
    return {
      ...(shares ? { shares } : {}),
      cellId,
      seq: seq.toString(10),
      commitmentHash: toHex(env.publicMeta.commitmentHash),
      at,
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

  /**
   * The request a recall makes while the copy is on, the copy's mutation count it was made against (taken before
   * that request), and the ids it sent as known. The ids are only the cached cells whose version the endpoint's
   * complete listing states (see {@link ownVersionsForCopy}): a cell updated in place elsewhere keeps its id, so
   * sending every cached id would leave its new version out of the delta for good. A copy with nothing in it has
   * nothing to check, so it asks for everything without a listing. A listing that could not be read throws (see
   * {@link copyCheckFailed}); it never ends in a delta over ids whose versions were not checked.
   */
  private async copyRecallRequest(): Promise<{
    resp: unknown;
    snapshot: number;
    known?: ReadonlySet<string>;
    knownMarks?: readonly PendingMark[];
    /** The complete listing the request was built from, and the copy's mutation count from before it was read. */
    listed?: ReadonlyMap<string, ListedVersion>;
    listedFrom?: number;
  }> {
    if (this.recallCache.size === 0) {
      const snapshot = this.recallCache.version;
      return { resp: await this.call<unknown>('saihm_recall', { knownCellIds: [] }), snapshot, known: new Set() };
    }
    const listedFrom = this.recallCache.version;
    const listed = await this.ownVersionsForCopy();
    if (listed.kind === 'recall-all') return { resp: listed.rows, snapshot: listed.snapshot };
    const snapshot = this.recallCache.version;
    const knownMarks = this.knownAtListedVersion(listed.versions);
    const known = new Set(knownMarks.map((m) => m.cellId));
    return {
      resp: await this.call<unknown>('saihm_recall', { knownCellIds: [...known] }),
      snapshot,
      known,
      knownMarks,
      listed: listed.versions,
      listedFrom,
    };
  }

  /**
   * The cached cells a recall may answer from the copy, each with the mark of the version it holds. A cell is known only
   * when the listing states the very version the copy holds - its commitment AND a sequence number equal to the copy's -
   * and nothing this process saw contradicts that: no mark above it, and no other version pinned at it. That mark is
   * what an edit built on the answer is checked against, as a full recall's mark is: without it the edit re-read the
   * live version and was stored over another device's newer one, where with the copy off it is refused (measured).
   * It cannot refuse a valid edit: the listing's number is the one the endpoint's stale check compares (measured in
   * its source), so an edit at the next number is refused only if a write landed after the listing. A cell listed
   * with no number (a version whose number was not yet recorded) is known at the copy's number when its commitment is
   * the copy's: the commitment pins the ciphertext, and the ciphertext's seal binds the number the copy read from it.
   * A cell listed with a number other than the copy's, or one whose mark here is higher (an endpoint rolled back below
   * what this identity has seen), is asked for again: read and marked from its own version, where the read path's
   * rollback check sees it. No pin check is needed: every path that pins
   * a version here also puts that version in the copy (see `keepInCopy`), and the read path refuses a second envelope
   * at a pinned number, so the copy never holds another version at a number pinned here.
   */
  private knownAtListedVersion(listed: ReadonlyMap<string, ListedVersion>): PendingMark[] {
    const out: PendingMark[] = [];
    for (const cell of this.recallCache.all()) {
      const v = listed.get(cell.cellId);
      if (v === undefined || v.commitment !== cell.commitmentHash) continue;
      // A version listed with no number is the copy's own version at the copy's number (0.14.3): the commitment is the
      // hash of its ciphertext, whose seal binds its number, and the copy took that number from the version it opened.
      // It was read at every recall instead, and charged each time, though nothing could be learnt from the read.
      const copySeq = seqFromDecimal(cell.seq);
      const seq = v.seq === null ? copySeq : seqFromDecimal(v.seq);
      if (seq === null || seq !== copySeq) continue;
      const mark = this.seq.current(cell.cellId);
      if (mark !== undefined && mark > seq) continue;
      out.push({ cellId: cell.cellId, seq, commitment: v.commitment });
    }
    return out;
  }

  /**
   * The complete version listing of this identity's own cells for a recall with the copy on, as cellId to its version:
   * every page read until `next` is null. `recall-all` when a page is answered with a recall-all array: an endpoint
   * without the listing, or with it switched off, ignores `listOnly` and answers with every cell, and that answer is
   * the full recall, returned with the copy's mutation count from before it was asked for, so it is used once and never
   * asked twice. Anything else that is not a complete listing THROWS, with nothing more asked or charged: a refusal or
   * failure of any page, a page this client cannot read, a cell listed twice, a `next` that does not move forward, more
   * than {@link MAX_COPY_LISTING_PAGES} pages, or a pass that runs past the share pass's bound in time
   * ({@link SHARES_PASS_DEADLINE_MS}, checked when each page arrives: the time between pages is this client's own).
   * A full recall in its place would charge every memory, and past the answer size limit fail after that.
   */
  private async ownVersionsForCopy(): Promise<
    | { kind: 'complete'; versions: Map<string, ListedVersion> }
    | { kind: 'recall-all'; rows: unknown[]; snapshot: number }
  > {
    const versions = new Map<string, ListedVersion>();
    const deadline = Date.now() + SHARES_PASS_DEADLINE_MS;
    const overdue = (): SaihmEndpointError =>
      copyCheckFailed(
        new SaihmEndpointError(408, 'timeout', `the service's list of your memories took more than ${SHARES_PASS_DEADLINE_MS / 60_000} minutes`),
      );
    let after: string | undefined;
    for (let pages = 0; pages < MAX_COPY_LISTING_PAGES; pages++) {
      const snapshot = this.recallCache.version;
      let r: unknown;
      try {
        r = await this.call<unknown>('saihm_recall', after === undefined ? { listOnly: true } : { listOnly: true, after });
      } catch (e) {
        throw copyCheckFailed(e);
      }
      if (Array.isArray(r)) return { kind: 'recall-all', rows: r, snapshot };
      if (Date.now() > deadline) throw overdue();
      let page: VersionListing;
      try {
        page = versionListingFrom(r);
      } catch (e) {
        throw copyCheckFailed(e);
      }
      for (const c of page.cells) {
        if (versions.has(c.cellId)) {
          throw copyCheckFailed(new SaihmEndpointError(502, 'malformed_response', "the service's list of your memories named one twice"));
        }
        versions.set(c.cellId, c);
      }
      if (page.next === null) return { kind: 'complete', versions };
      if (after !== undefined && page.next <= after) {
        throw copyCheckFailed(
          new SaihmEndpointError(502, 'malformed_response', "the service's list of your memories did not move forward from one page to the next"),
        );
      }
      after = page.next;
    }
    throw copyCheckFailed(
      new SaihmEndpointError(502, 'malformed_response', `the service's list of your memories ran past ${MAX_COPY_LISTING_PAGES} pages`),
    );
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
    this.noticeIfRecallIsUncached();
    const needle = query?.toLowerCase();
    const filter = (cells: RecalledCell[]): RecalledCell[] =>
      needle === undefined ? cells : cells.filter((c) => c.plaintext.toLowerCase().includes(needle));

    // DELTA PATH (dark; active only when a recall cache is configured). Send the endpoint the
    // cellIds we already hold AT THE VERSION THE ENDPOINT HOLDS (see `copyRecallRequest`); it fans
    // out reads over only the others (server work O(changed) not O(all)) and returns `liveCellIds` so
    // we can prune anything since forgotten. We answer the caller from the merged cache. If the
    // endpoint's delta gate is off (or it is an older build), it returns the legacy array instead —
    // we treat that as a full recall and rebuild the cache, so a delta-configured client is always
    // correct against any endpoint.
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
      for (let attempt = 1; ; attempt++) {
        // `snapshot` is that count, taken before the request whose answer is applied below.
        const turn = this.gone.sent();
        const { resp, snapshot, known, knownMarks, listed, listedFrom } = await this.copyRecallRequest();
        // A local write landed while this was in flight, so the answer predates it. Applied, it would undo that write
        // (measured, above). Answered without being applied, it would show the copy as it was before this recall: the
        // OLD version of a cell the listing showed changed, while opening the answer had already moved that cell's mark
        // to the new one, so an edit built on the old text was stored over the other computer's (measured). So it
        // is neither applied nor answered, nothing it carries moves a mark, and the recall runs again.
        if (this.recallCache.version !== snapshot) {
          if (attempt < COPY_RECALL_ATTEMPTS) continue;
          throw new SaihmEndpointError(409, 'recall_interrupted', RECALL_INTERRUPTED);
        }
        // NOTHING BELOW AWAITS. The answer is opened, applied to the copy and its marks advanced in one synchronous run,
        // so no write of this process lands between the check above and the return.
        const marks: PendingMark[] = [];
        const held = (cellId: string): string | undefined => this.recallCache.commitmentOf(cellId);
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
          const { cells: added, announcements, announcementsTruncated, announcementsSkipped } = this.openRecallRows(resp.added, marks);
          // Non-strings are dropped rather than coerced. `new Set([...])` on a mixed array would treat
          // every non-string as an id that is NOT live, and `merge` prunes exactly what is missing from
          // that set — so a response of `[null]` would evict the whole cache while looking well-formed.
          // The endpoint can already prune by sending `[]`, so this bounds a type confusion, not a
          // capability; it is here because the cast is what made the confusion invisible.
          try {
            this.recallCache.merge(added, resp.liveCellIds.filter((id): id is string => typeof id === 'string'), known);
          } catch (e) {
            // The copy was put back as it was, and no mark moves: this recall answers nothing.
            throw markPathBearing(e);
          }
          // The cells answered from the copy are marked at the version the listing stated and the copy holds, with the
          // rest; one the merge dropped (erased meanwhile) or replaced is skipped by `held`.
          if (knownMarks !== undefined) marks.push(...knownMarks);
          this.applyMarks(marks, held, turn);
          // The complete listing names every memory that exists (it is read from the key records, which a storage fault
          // leaves alone), so one marked here that it leaves out, and the delta did not bring back, is gone. Only when
          // nothing of this process changed the copy during the whole recall: a memory this process saved while the
          // listing was read, then left out of the delta because its stored copy could not be read, is not gone.
          if (listed !== undefined && listedFrom === snapshot) {
            for (const id of this.seq.marked()) if (!listed.has(id) && held(id) === undefined) this.gone.found(id);
          }
          return { cells: filter(this.recallCache.all()), announcements, announcementsTruncated, announcementsSkipped };
        }
        if (!Array.isArray(resp)) {
          throw new SaihmEndpointError(
            502,
            'malformed_response',
            'endpoint returned a malformed recall response',
          );
        }
        const { cells, announcements, announcementsTruncated, announcementsSkipped } = this.openRecallRows(resp, marks);
        try {
          this.recallCache.replaceAll(cells);
        } catch (e) {
          // As above: the copy was put back as it was, and no mark moves.
          throw markPathBearing(e);
        }
        this.applyMarks(marks, held, turn);
        return { cells: filter(cells), announcements, announcementsTruncated, announcementsSkipped };
      }
    }

    // FULL PATH (default): recall-all, open every row, filter client-side. The marks move once every row is open, so
    // they name exactly what the answer carries; a response refused part way moves none. A memory it leaves out is not
    // taken for gone (see GoneRecords): the endpoint leaves out one whose stored copy could not be read.
    const turn = this.gone.sent();
    const rows = await this.call<unknown>('saihm_recall', {});
    if (!Array.isArray(rows)) {
      throw new SaihmEndpointError(
        502,
        'malformed_response',
        'endpoint returned a malformed recall-all response',
      );
    }
    const marks: PendingMark[] = [];
    const { cells, announcements, announcementsTruncated, announcementsSkipped } = this.openRecallRows(rows, marks);
    this.applyMarks(marks, undefined, turn);
    return { cells: filter(cells), announcements, announcementsTruncated, announcementsSkipped };
  }

  /**
   * `openRecallRowsUnbatched` under ONE marks write instead of one per row - see
   * {@link SeqState.withBatch}. Every caller goes through here; the inner name exists so the batch
   * cannot be bypassed by accident, and the docblock below stays with the logic it describes rather
   * than with this delegation.
   */
  private openRecallRows(rows: unknown[], marks: PendingMark[]) {
    return this.seq.withBatch(() => this.openRecallRowsUnbatched(rows, marks));
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
  private openRecallRowsUnbatched(rows: unknown[], marks: PendingMark[]): RecallWithShared {
    const out: RecalledCell[] = [];
    const announcements: SharedAnnouncement[] = [];
    let announcementsTruncated = false;
    // A row this client cannot carry is skipped WHEREVER it stands; before the cut, that makes the kept list something
    // other than one end of the endpoint's order (see RecallWithShared.announcementsSkipped). After the cut it is part
    // of the end the cut already dropped.
    let announcementsSkipped = false;
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
          ) {
            announcementsSkipped ||= !announcementsTruncated;
            continue;
          }
          // FIELD CAP. A row with an over-long field is dropped outright and does NOT set
          // `truncated`: it is a malformed row like any other, and flagging it would let the endpoint
          // make every listing claim to be incomplete.
          const epochChars = row.expiryEpoch == null ? 0 : row.expiryEpoch.length;
          if (
            row.sharer.length > MAX_ANNOUNCEMENT_FIELD_CHARS ||
            row.cellId.length > MAX_ANNOUNCEMENT_FIELD_CHARS ||
            row.scope.length > MAX_ANNOUNCEMENT_FIELD_CHARS ||
            epochChars > MAX_ANNOUNCEMENT_FIELD_CHARS
          ) {
            announcementsSkipped ||= !announcementsTruncated;
            continue;
          }
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
          // ONE END, ONCE CUT. After either cap below has cut the list, no later announcement is kept, so what is kept
          // is always the FRONT of the endpoint's order: the end a result can name (`sharedKept`). The byte axis used to
          // go on keeping a later, smaller row after dropping a larger one, which left a gap no end could describe.
          if (announcementsTruncated) continue;
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

      if (!row.found || !row.wire) {
        // A row that said it was shared and is neither a pointer this client keeps nor an own cell it opens is a
        // skipped announcement like any other (see announcementsSkipped).
        if (row.shared !== undefined) announcementsSkipped ||= !announcementsTruncated;
        continue;
      }
      const cell = this.openRow(null, row.wire, marks); // trusts env.cellId/seq, not the server row label
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
    return { cells: out, announcements, announcementsTruncated, announcementsSkipped };
  }

  /**
   * One page of the version listing of this identity's own cells: ids, sequence numbers and commitments from the
   * endpoint's index, no content. Page with `after` (the previous page's `next`) until `next` is null.
   */
  async listVersions(after?: string): Promise<VersionListing> {
    // Alone, as the endpoint requires: a listing request carries nothing but `listOnly` and `after`.
    const r = await this.call<unknown>('saihm_recall', after === undefined ? { listOnly: true } : { listOnly: true, after });
    return versionListingFrom(r);
  }

  /**
   * One page of the share listing, in key order (sharer, then cell id): pass `after` (the previous page's `next`) until
   * `next` is null. Requested only while the identity's status offers the paged listing (`features.sharesPaged`), at
   * most `max` rows and never more than it offers. `shares_paging_unsupported` when it is not offered, or when the answer
   * is not a page (the listing was switched off between the status and the request): fall back to the default recall's
   * listing. A page longer than `max`, a `next` over `maxNextChars` or outside the wire's characters, or a row this
   * client cannot read is `malformed_response`, the whole page refused. UNAUTHENTICATED POINTERS, as announcements are.
   */
  async listSharesPage(after?: string, max: number = SHARES_PAGE_MAX, maxNextChars: number = MAX_SHARES_CURSOR_CHARS): Promise<SharesPage> {
    const offered = await this.sharesPagedOfferRead();
    if (offered === null) throw sharesPagingUnsupported('the status offers no paged share listing');
    const ask = withinBound(Math.floor(max), 1, offered);
    try {
      // Alone, as the endpoint requires: a page request carries nothing but `sharesOnly`, `paged`, `after` and `max`.
      const r = await this.call<unknown>(
        'saihm_recall',
        after === undefined ? { sharesOnly: true, paged: true, max: ask } : { sharesOnly: true, paged: true, after, max: ask },
      );
      return sharesPageFrom(r, ask, maxNextChars);
    } catch (e) {
      // Any answer that is not a page, a refusal included: the offer is read again before the next page is asked for.
      // An answer that is not a page is dropped unread.
      this.sharesPagedMax = undefined;
      throw e;
    }
  }

  /**
   * Every share made to this identity, read page by page (see {@link sharesPass}): the whole list, where a recall shows
   * a capped view. `complete` only when the pass vouches for every live share; an incomplete pass ends no share, and
   * `incomplete` says why: `unsupported` when the endpoint does not page the listing, and `unread` when the status that
   * says whether it does could not be read (read `recallWithShared` instead in both cases).
   * Bounded by the share map's 4,096 entries and 64 pages, and asks for no page once 10 minutes have passed, or less when
   * asked. Never throws.
   */
  async listAllShares(
    opts: { maxEntries?: number; maxPages?: number; deadlineMs?: number; now?: () => number; signal?: AbortSignal } = {},
  ): Promise<SharesPass> {
    // The offer is read before every page (from what is kept, at no cost while kept), so a status that cannot be read is
    // told apart from a page that failed: it ends the pass `unread`, and is never taken for an offer.
    let unread = false;
    const p = await sharesPass(
      async (after) => {
        try {
          await this.sharesPagedOfferRead();
        } catch (e) {
          unread = true;
          throw e;
        }
        return this.listSharesPage(after);
      },
      {
        maxEntries: opts.maxEntries ?? SHARE_MAP_MAX_ENTRIES,
        maxPages: opts.maxPages ?? SHARES_PASS_MAX_PAGES,
        deadlineMs: opts.deadlineMs ?? SHARES_PASS_DEADLINE_MS,
        now: opts.now ?? Date.now,
        ...(opts.signal !== undefined ? { signal: opts.signal } : {}),
      },
    );
    return unread && !p.complete ? { ...p, incomplete: 'unread' } : p;
  }

  /**
   * The page size the paged share listing is offered at, or null when the status says it is not offered. An offer is
   * kept until an answer to a page request is not a page, and a status's word that there is none for
   * {@link SHARES_PAGED_ABSENT_MS}; otherwise the status is read. A status that cannot be read throws its own failure,
   * which is neither an offer nor an absence and is not kept.
   */
  private async sharesPagedOfferRead(): Promise<number | null> {
    if (this.sharesPagedMax !== undefined) return this.sharesPagedMax;
    if (Date.now() < this.sharesPagedAbsentUntil) return null;
    const s = await this.status();
    const read = sharesPagedOffer(featuresOf((s as { features?: unknown } | null | undefined)?.features).features);
    if (read === null) {
      this.sharesPagedAbsentUntil = Date.now() + SHARES_PAGED_ABSENT_MS;
      return null;
    }
    this.sharesPagedAbsentUntil = -Infinity;
    return (this.sharesPagedMax = read);
  }

  /** Recall + open a single cell. Returns `null` if it does not exist. */
  async recallOne(cellId: string): Promise<RecalledCell | null> {
    const heldBefore = this.recallCache.commitmentOf(cellId);
    const turn = this.gone.sent();
    const r = await this.recallRawOne(cellId);
    // `found: false` is the endpoint's own "no such cell". Anything else without an envelope is an answer this client
    // cannot read: calling it "not found" would put a plausible answer where the endpoint gave a malformed one.
    if (r.found === false) {
      this.dropGoneFromCopy(cellId, heldBefore);
      this.gone.found(cellId);
      return null;
    }
    if (r.found !== true || !r.wire) {
      throw new SaihmEndpointError(502, 'malformed_response', 'endpoint returned a malformed read of one of your cells');
    }
    const cell = this.openRow(cellId, r.wire);
    this.keepInCopy(cell); // the answer, its mark and the copy at one version
    this.gone.live(cellId, turn);
    return cell;
  }

  /** Crypto-shred a cell (GDPR Art.17): the endpoint destroys the wrapped DEK + tombstones. */
  async forget(cellId: string): Promise<ForgetResult> {
    const r = await this.call<ForgetResult>('saihm_forget', { id: cellId });
    // Known erased in this process from here on, feed or no feed: an edit of it is refused before its write.
    this.gone.found(cellId);
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
    const purgeCache = (): void => {
      try {
        this.recallCache.remove(cellId);
      } catch {
        const where = this.recallCache.cachePath ?? 'the configured recall cache';
        localCacheResidual =
          `the DEK is destroyed and this cell is unrecoverable, but the local plaintext cache could ` +
          `not be purged: plaintext may remain in ${where} until the next successful cache write`;
      }
    };
    // Tell anything downstream that derived from this cell. The erasure is ALREADY irreversible, so
    // this cannot be allowed to throw: the pre-erase ordering that makes an append failure fatal is
    // only constructible where the erasure is performed, and it is performed remotely. Report both
    // halves instead, exactly as the cache purge above does.
    //
    // `complete` is TRUE only when the receipt says so AND carries a `destructionAnchor` of the agreed shape,
    // which is copied verbatim; otherwise FALSE. False means this client cannot point at the destruction, not
    // that none happened. An endpoint's bare `complete` is a post-condition that also holds for an id that
    // never existed, and a consumer refuses `complete:true` without an anchor: forwarding a bare `true` would
    // produce a line the consumer discards, which purges nothing and looks like a delivered erasure. Both
    // fields are read ONCE, below, from the unvalidated body.
    //
    // GATED ON THE ID'S LENGTH, and the reason is the RENDER rather than the feed. `cellId` is a
    // caller argument and free-form, so it is the only value on this wire a caller chooses. Emitting
    // an over-long one makes `buildFeedLine` refuse, which sets a residual, which renders a SECOND
    // line in a tool result whose structure is pinned at one — handing a caller a lever over the
    // shape of a render, which is exactly what every fence in this package exists to deny. This
    // package's posture for a hostile caller argument is to render it INERTLY, never to change shape
    // around it, so the id is checked here and the emit is skipped rather than allowed to fail.
    //
    // THE RESIDUAL OF THAT CHOICE, WRITTEN DOWN RATHER THAN CLAIMED AWAY: a cell whose id is longer
    // than the pointer ceiling gets no feed line AND no sentence saying so. Such an id is already
    // unusable through every other surface here — it renders cut, it cannot be kept in an
    // announcement, it cannot be fed back to resolve a grant — so the feed is the last place it stops
    // working, not the first. That does not make the silence free, and if a downstream consumer ever
    // needs to hear about this class, the honest fix is a field on the line the receipt ALREADY
    // renders, never a second conditional line.
    //
    // THE RECEIPT IS RESOLVED HERE, ONCE, and the raw claims are REPLACED in the result below, so the erasure line, the
    // change feed's record of this erasure and the tool result (its text and its structured content) state the same
    // thing. `complete` follows the line: a boolean claim is TRUE only with the anchor (an endpoint whose own-cell events
    // are off states the post-condition `complete: true` with no anchor, even for an id that never existed); a claim
    // that is not even a boolean is left for the tool to name as malformed. `reason` says why a `complete: false` is
    // false, so it travels only beside one, and only as one of the two it may be: `not-found` (no such cell: never
    // written, or erased already) or `not-attested` (the destruction could not be made durable: forget the id again
    // later); an older server names none, a hostile one could name anything. The line carries this same `reason`, so a
    // reader can tell "nothing (more) to erase" from an erasure not yet durable; a forget answered `not-found` is still
    // recorded, because for an id erased before, the line lets a reader drop what it still derives from it. `at` is the
    // endpoint's time of the erasure when it states a zoned time, re-serialised, else null — the convention of
    // `remember`'s `at`.
    const claim: { complete?: unknown; destructionAnchor?: unknown; reason?: unknown; at?: unknown } =
      typeof r === 'object' && r !== null ? r : {};
    const anchor =
      claim.complete === true && typeof claim.destructionAnchor === 'string' && DESTRUCTION_ANCHOR.test(claim.destructionAnchor)
        ? claim.destructionAnchor
        : null;
    const reason =
      claim.complete === false && (claim.reason === 'not-found' || claim.reason === 'not-attested') ? claim.reason : undefined;
    const at = isoTime(claim.at);
    let feedResidual: string | undefined;
    const appendFeed = (): void => {
      if (erasureFeedEnabled() && cellId.length > 0 && cellId.length <= MAX_FEED_CELL_ID_CHARS) {
        feedResidual = emitErasureLineReporting({
          cellId,
          agentIdHash: this.agentIdHashHex,
          at: new Date().toISOString(),
          complete: anchor !== null,
          ...(reason !== undefined ? { reason } : {}),
          ...(anchor !== null ? { destructionAnchor: anchor } : {}),
          source: 'mcp-client',
        });
        // Recorded here: the event feed's report of this erasure is then not written a second time.
        if (feedResidual === undefined) this.ownChanges?.noteOwnErasure(cellId, anchor);
      }
    };
    // ORDER AND LOCK: the erasure line first, then the removal, both under the recall cache's cross-process write lock
    // (see RecallCache.withWriteLock for the two-session measurement this closes). If another live session holds the
    // lock past the wait, the erasure line is still written (so every later save, including this session's, drops the
    // cell), the file is not rewritten (that needs the lock), and the receipt says the plaintext may still be on disk.
    let erasedLocally = false;
    try {
      this.recallCache.withWriteLock(() => {
        erasedLocally = true;
        appendFeed();
        purgeCache();
      });
    } catch {
      if (!erasedLocally) {
        appendFeed();
        const where = this.recallCache.cachePath ?? 'the configured recall cache';
        localCacheResidual =
          `the DEK is destroyed and this cell is unrecoverable, but the recall cache lock could not be taken, so ` +
          `the local plaintext cache was not purged: plaintext may remain in ${where} until the next successful cache write`;
      }
    }

    // The endpoint's claim is DELETED before ours is set, not merely overwritten. `r` is an
    // unvalidated cast of the endpoint's body, so a hostile endpoint can put `localCacheResidual` in
    // its 200 and would otherwise be writing a sentence straight into a rendered erasure receipt —
    // the same channel the announcement caps and `failText`'s fences exist to close, on the one tool
    // where an operator is most likely to act on what it says. `delete` rather than assigning
    // `undefined` because `exactOptionalPropertyTypes` makes absent and present-but-undefined
    // different things, and absent is the one that means "this client had nothing to report".
    // `feedResidual` is the same channel and gets the same treatment.
    // `complete`, `reason` and `destructionAnchor` are the endpoint's fields resolved above, and replaced the same way.
    const out: ForgetResult = { ...r, at };
    if (typeof claim.complete === 'boolean') out.complete = anchor !== null;
    delete out.localCacheResidual;
    delete out.feedResidual;
    delete out.reason;
    delete out.destructionAnchor;
    if (localCacheResidual !== undefined) out.localCacheResidual = localCacheResidual;
    if (feedResidual !== undefined) out.feedResidual = feedResidual;
    if (reason !== undefined) out.reason = reason;
    if (anchor !== null) out.destructionAnchor = anchor;
    return out;
  }

  /** Non-custodial status: operator-observable metadata only (no plaintext). */
  async status(): Promise<StatusSnapshot> {
    const s = await this.call<StatusSnapshot>('saihm_status', {});
    // What this identity may use, told to the event feed, which reads the server's offer only at start and daily.
    const events = (s as { features?: { events?: { kinds?: unknown } } } | null | undefined)?.features?.events;
    this.shareFeed?.noteStatusOffer(Array.isArray(events?.kinds) ? (events.kinds as unknown[]) : undefined);
    return s;
  }

  /**
   * GRANT a cell to another agent, end-to-end authenticated. The DEK is re-wrapped to the grantee's
   * pinned ML-KEM key client-side; the endpoint blind-stores the share envelope. `shareCell` rejects
   * a directory record that does not match the out-of-band pin (throws `KeySubstitutionError` before
   * any secret is bound). The grantee reads it with {@link SaihmProClient.recallShared}.
   */
  async share(grant: ShareGrant): Promise<ShareResult> {
    const heldBefore = this.recallCache.commitmentOf(grant.cellId);
    const turn = this.gone.sent();
    const own = await this.recallRawOne(grant.cellId);
    if (!own.found || !own.wire) {
      if (own.found === false) {
        this.dropGoneFromCopy(grant.cellId, heldBefore);
        this.gone.found(grant.cellId);
      }
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
    // And the copy is kept at the version whose mark this read advanced (see PendingMark).
    this.keepInCopy(this.openRow(grant.cellId, own.wire));
    this.gone.live(grant.cellId, turn);
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
    // The record is public (two public keys and a self-signature) and already verified against the pin above. An
    // endpoint that supports re-issuing keeps it, so this grant can be re-issued after a later write of the cell;
    // one that does not ignores the field.
    const result: ShareResult = await this.call('saihm_share', { ...params, recipientRecord: grant.recipientRecord });
    this.revokedGrants.delete(JSON.stringify([grant.cellId, toHex(recipientPinnedAgentIdHash)]));
    return result;
  }

  /** Revoke a prior grant to `recipientHex` for `cellId` (deletes the share envelope). */
  async revokeShare(
    cellId: string,
    recipientHex: string,
  ): Promise<RevokeResult> {
    // Recorded before the call: a revocation whose response was lost must still stop a later re-issue.
    this.revokedGrants.add(JSON.stringify([cellId, recipientHex.toLowerCase()]));
    return this.call('saihm_revoke_share', { cellId, recipient: recipientHex });
  }

  /**
   * Re-issue the grants a write left on the previous version. The endpoint lists them (`staleShares`), and nothing in
   * the list is trusted:
   *  - a grant is re-issued only when its share is signed by THIS identity for this cell and names that recipient, so
   *    an endpoint cannot add a recipient to the list;
   *  - the new share is built by `shareCell`, which refuses a recipient record that does not verify against the
   *    recipient, so an endpoint cannot substitute keys;
   *  - a grant this process revoked is not re-issued.
   * The new shares wrap the key of `env`, the version just written, and name its commitment, so an endpoint that has
   * a newer write refuses them. Never throws: the write is already stored, and what could not be re-issued is reported.
   */
  private async reissueStaleShares(
    cellId: string,
    env: ReturnType<typeof sealCell>,
    written: unknown,
  ): Promise<ShareReissueReport | undefined> {
    const first = staleGrantsPage(written);
    if (!first) return undefined;
    let page: { grants: unknown[]; after: string | null; stuck: boolean } = first;
    const report: ShareReissueReport = { reissued: 0, notReissued: [], incomplete: false };
    const commitment = toHex(env.publicMeta.commitmentHash);
    const handled = new Set<string>();
    for (let n = 0; ; n++) {
      if (n === MAX_REISSUE_PAGES) {
        report.incomplete = true;
        break;
      }
      const wires: unknown[] = [];
      const built: string[] = [];
      for (const g of page.grants) {
        const p = this.prepareReissue(cellId, env, g);
        if (p.recipient !== null) {
          if (handled.has(p.recipient)) continue;
          handled.add(p.recipient);
        }
        if (p.skip !== undefined) report.notReissued.push({ recipient: p.recipient, reason: p.skip });
        else {
          wires.push(p.wire);
          built.push(p.recipient);
        }
      }
      const after: string | null = page.after;
      const more = after !== null || page.stuck;
      // The next page comes back with a re-issue request, so a page with nothing to send ends the walk.
      if (wires.length === 0) {
        report.incomplete = more;
        break;
      }
      let res: unknown;
      try {
        res = await this.call<unknown>('saihm_share', {
          rewrap: true, cellId, commitment, shareWires: wires, ...(after ? { after } : {}),
        });
      } catch {
        for (const recipient of built) report.notReissued.push({ recipient, reason: 'unavailable' });
        report.incomplete = more;
        break;
      }
      const accepted = new Set<string>();
      const results = ownField(res, 'results');
      if (Array.isArray(results)) {
        for (const x of results) {
          const recipient = ownField(x, 'recipient');
          if (ownField(x, 'ok') === true && typeof recipient === 'string') accepted.add(recipient);
        }
      }
      for (const recipient of built) {
        if (accepted.has(recipient)) report.reissued++;
        else report.notReissued.push({ recipient, reason: 'refused' });
      }
      if (!more) break;
      const next: { grants: unknown[]; after: string | null; stuck: boolean } | undefined =
        after === null ? undefined : staleGrantsPage(res);
      // A next page must move forward: an endpoint that repeats a page, moves back or sends none ends the walk.
      if (!next || after === null || (next.after !== null && next.after <= after)) {
        report.incomplete = true;
        break;
      }
      page = next;
    }
    return report;
  }

  /** One listed grant: a new share for the version just written, or the reason there is none. */
  private prepareReissue(
    cellId: string,
    env: ReturnType<typeof sealCell>,
    g: unknown,
  ): { wire: unknown; recipient: string; skip?: undefined } | { wire?: undefined; recipient: string | null; skip: ShareReissueSkip } {
    const listed = ownField(g, 'recipient');
    let share;
    try {
      share = decodeShareEnvelope(ownField(g, 'share') as WireShareEnvelope);
    } catch {
      return { recipient: null, skip: 'unverified' };
    }
    if (
      typeof listed !== 'string' ||
      !HEX64_RE.test(listed) ||
      share.cellId !== cellId ||
      !ctEqual(share.sharerAgentIdHash, this.identity.agentIdHash) ||
      toHex(share.recipientAgentIdHash) !== listed ||
      !verifyShareSig(share, this.identity.mldsaPubKey)
    ) {
      return { recipient: null, skip: 'unverified' };
    }
    // From here the recipient is authenticated: this identity signed a grant of this cell to it.
    const recipient = listed;
    if (this.revokedGrants.has(JSON.stringify([cellId, recipient]))) return { recipient, skip: 'revoked' };
    const record = ownField(g, 'recipientRecord');
    if (record === null || record === undefined) return { recipient, skip: 'no_record' };
    try {
      const next = shareCell({
        envelope: env,
        sharerKek: this.identity.kek,
        sharerMldsaSecretKey: this.identity.mldsaSecretKey,
        sharerAgentIdHash: this.identity.agentIdHash,
        recipientRecord: decodeIdentityRecord(record as WireIdentityRecord),
        recipientPinnedAgentIdHash: share.recipientAgentIdHash,
      });
      return { wire: encodeShareEnvelope(next), recipient };
    } catch {
      return { recipient, skip: 'unverified' };
    }
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
      grant?: unknown;
    };
    const servingGrant = typeof res.grant === 'string' && /^[0-9a-f]{64}$/.test(res.grant) ? res.grant : undefined;
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
      this.shareFeed?.markOpenFailed(grant.sharerPinnedAgentIdHashHex, grant.cellId);
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
        // Typically a key envelope that wraps an earlier version of the cell: the share is stale until it is re-issued.
        this.shareFeed?.markOpenFailed(grant.sharerPinnedAgentIdHashHex, grant.cellId);
        throw new SaihmEndpointError(
          502,
          'undecryptable',
          `shared cell '${grant.cellId}' could not be opened with the unwrapped DEK`,
        );
      }
      // The sharer's signature was checked against the pinned record above: the feed may say so.
      this.shareFeed?.markSenderVerified(grant.sharerPinnedAgentIdHashHex, grant.cellId);
      return {
        cellId: env.cellId,
        plaintext,
        seq: env.seq.toString(10),
        commitmentHash: toHex(env.publicMeta.commitmentHash),
        ...(servingGrant !== undefined ? { grant: servingGrant } : {}),
      };
    } finally {
      dek.fill(0); // scrub the unwrapped DEK regardless of outcome
    }
  }

  // ── warm start ────────────────────────────────────────────────────────────────────────────────────────────────

  /**
   * What this identity may use of warm start now: its offer from `saihm_status` (`features.warmStart`) and the
   * endpoint's route and part size from its info document. Every warm-start call takes one, so none runs without an
   * offer; with none, `warm_start_unavailable`, and the caller starts cold. Limits are read here, never assumed.
   */
  async warmStartOffer(): Promise<WarmStartOffer> {
    const s = await this.status();
    const limits = warmStartLimits(featuresOf((s as { features?: unknown } | null | undefined)?.features).features);
    if (limits === null)
      throw new SaihmEndpointError(0, 'warm_start_unavailable', 'warm start is not offered to this identity now: start cold');
    const route = await this.warmStartRouteFromInfo();
    if (route === null)
      throw new SaihmEndpointError(0, 'warm_start_unavailable', 'the endpoint does not describe warm start now: start cold');
    return { maxBytes: limits.maxBytes, url: route.url, partBytes: route.partBytes };
  }

  /**
   * Seal `payload` here and store it as a snapshot covering `coversThrough`: begin, every part, then commit. A part or
   * the commit is sent again after a limit or a busy endpoint, so an upload once begun is not lost to a moment's load.
   * A commit whose answer never arrives may have been stored: the listing says whether it was. An upload that fails for
   * good is aborted, best-effort and within {@link WARM_START_ABORT_MS}, so it does not hold the identity's room until it
   * expires; the failure thrown is always the upload's own.
   */
  async warmStartPut(offer: WarmStartOffer, payload: Uint8Array, coversThrough: string): Promise<WarmStartSnapshot> {
    if (!COVERS_THROUGH_PATTERN.test(coversThrough))
      throw new SaihmEndpointError(0, 'invalid_input', 'coversThrough is a position of the change feed: 1 to 64 printable characters');
    const sealed = sealSnapshot(payload, offer.partBytes, {
      kek: this.identity.kek,
      agentIdHash: this.identity.agentIdHash,
      coversThrough,
    });
    if (sealed.bytes > offer.maxBytes)
      throw new SaihmEndpointError(0, 'snapshot_too_large', `the sealed snapshot is ${sealed.bytes} bytes; this identity's snapshots hold at most ${offer.maxBytes}`);
    const begin = await this.warmStartRequest('begin', 'POST', offer.url, {
      body: JSON.stringify({
        v: 1,
        bytes: sealed.bytes,
        parts: sealed.parts.length,
        digest: sealed.digest,
        keyEnvelope: sealed.keyEnvelope,
        coversThrough,
        nonce: sealed.nonce,
      }),
      headers: { 'content-type': 'application/json' },
      cap: WARM_START_ANSWER_BYTES,
    });
    if (begin.status !== 201) throw this.warmStartRefusal('begin', begin).error;
    const begun = parsedAnswer(begin.bytes);
    const upload = begunUpload(begun);
    if (upload === null || upload.partBytes !== offer.partBytes) {
      // An upload this client cannot fill is abandoned at once, when its answer names one.
      const abandoned = begunUploadId(begun);
      if (abandoned !== null) await this.warmStartAbort(offer, abandoned);
      throw new SaihmEndpointError(502, 'malformed_response', 'SAIHM warm start began an upload this client cannot fill');
    }
    const at = `${offer.url}/uploads/${upload.uploadId}`;
    let commit: WarmStartAnswer;
    try {
      for (let n = 0; n < sealed.parts.length; n++) {
        const part = sealed.parts[n] as Uint8Array;
        await this.warmStartPersisting('part', 'PUT', `${at}/parts/${n}`, 204, {
          body: part,
          headers: { 'content-type': 'application/octet-stream', 'content-digest': contentDigestOf(part) },
          cap: WARM_START_ANSWER_BYTES,
        });
      }
      // Only once every part has answered: a part still in flight would race the commit.
      try {
        commit = await this.warmStartPersisting('commit', 'POST', `${at}/commit`, 201, { body: '', cap: WARM_START_ANSWER_BYTES });
      } catch (e) {
        // A failure that does not say the snapshot was not stored: the listing decides, BEFORE any abort. Ours is the
        // entry with this digest and nonce (random per snapshot), at this size and position; any other answer keeps the
        // failure.
        if (!(e instanceof SaihmEndpointError) || e.code === undefined || !COMMIT_FATE_UNKNOWN.has(e.code)) throw e;
        const stored = await this.warmStartListing(offer).then(
          (listed) => listed.find((x) => x.digest === sealed.digest && x.nonce === sealed.nonce && x.bytes === sealed.bytes && x.coversThrough === coversThrough),
          () => undefined,
        );
        if (stored === undefined) throw e;
        return { snapshotId: stored.snapshotId, createdAt: stored.createdAt, bytes: stored.bytes, coversThrough: stored.coversThrough };
      }
    } catch (e) {
      // Failed for good, and not shown stored: free the upload now rather than when it expires. An abort never touches a
      // stored snapshot (the endpoint answers 404 for an upload already committed), never throws, and never replaces
      // this failure, which is the call's answer.
      await this.warmStartAbort(offer, upload.uploadId);
      throw e;
    }
    const snapshot = committedSnapshot(parsedAnswer(commit.bytes), { bytes: sealed.bytes, parts: sealed.parts.length, coversThrough });
    if (snapshot === null)
      throw new SaihmEndpointError(502, 'malformed_response', 'SAIHM warm start committed a snapshot other than the one sent');
    return snapshot;
  }

  /**
   * Restore the newest snapshot: the first of the listing, every part fetched and checked against its own digest, all
   * of them against the snapshot's, every part opened, and only then the payload returned. Null when there is no
   * snapshot. Any failure throws and returns nothing of the snapshot: the caller starts cold.
   */
  async warmStartLatest(offer: WarmStartOffer): Promise<{ readonly snapshot: WarmStartSnapshot; readonly payload: Uint8Array } | null> {
    const newest = (await this.warmStartListing(offer))[0];
    if (newest === undefined) return null;
    if (newest.bytes > offer.maxBytes)
      throw new SaihmEndpointError(0, 'snapshot_too_large', `the newest snapshot is ${newest.bytes} bytes; this identity's snapshots hold at most ${offer.maxBytes}`);
    const binding = { kek: this.identity.kek, agentIdHash: this.identity.agentIdHash, coversThrough: newest.coversThrough };
    const key = openSnapshotKey(newest.keyEnvelope, newest.nonce, binding);
    if (key === null) throw new SaihmEndpointError(502, 'undecryptable', "the newest snapshot's key does not open under this identity");
    try {
      const parts: Uint8Array[] = [];
      let total = 0;
      for (let n = 0; n < newest.parts; n++) {
        // At most what the snapshot has left, or room for a refusal's body: the total is checked after the last part.
        const cap = Math.max(newest.bytes - total, WARM_START_REFUSAL_BYTES);
        const a = await this.warmStartRequest('read', 'GET', `${offer.url}/${newest.snapshotId}/parts/${n}`, { cap });
        if (a.status !== 200) throw this.warmStartRefusal('read', a).error;
        const stated = contentDigestSha256(a.digest);
        if (stated === null || !ctEqual(stated, createHash('sha256').update(a.bytes).digest()))
          throw new SaihmEndpointError(502, 'digest_mismatch', `part ${n} of the newest snapshot does not match its Content-Digest`);
        total += a.bytes.length;
        parts.push(a.bytes);
      }
      if (total !== newest.bytes || partsDigest(parts) !== newest.digest)
        throw new SaihmEndpointError(502, 'digest_mismatch', "the newest snapshot's parts do not match its digest");
      const payload = openSnapshotParts(key, parts, newest.nonce, binding);
      if (payload === null) throw new SaihmEndpointError(502, 'undecryptable', 'a part of the newest snapshot does not open under its key');
      return {
        snapshot: { snapshotId: newest.snapshotId, createdAt: newest.createdAt, bytes: newest.bytes, coversThrough: newest.coversThrough },
        payload,
      };
    } finally {
      key.fill(0);
    }
  }

  /** This identity's snapshots, newest first, as the endpoint lists them: metadata only. */
  async warmStartList(offer: WarmStartOffer): Promise<WarmStartSnapshot[]> {
    return (await this.warmStartListing(offer)).map((e) => ({
      snapshotId: e.snapshotId,
      createdAt: e.createdAt,
      bytes: e.bytes,
      coversThrough: e.coversThrough,
    }));
  }

  /** Destroy one snapshot, its key first. One that no longer exists is `snapshot_not_found`. */
  async warmStartDelete(offer: WarmStartOffer, snapshotId: string): Promise<void> {
    if (!SNAPSHOT_ID_PATTERN.test(snapshotId))
      throw new SaihmEndpointError(0, 'invalid_input', 'a snapshot id is 64 lowercase hex characters');
    const a = await this.warmStartRequest('delete', 'DELETE', `${offer.url}/${snapshotId}`, { cap: WARM_START_ANSWER_BYTES });
    if (a.status !== 204) throw this.warmStartRefusal('delete', a).error;
  }

  /**
   * Abort an upload this client began and will not finish: best-effort, and over within {@link WARM_START_ABORT_MS}
   * whatever the endpoint does, so it never holds back the upload's own failure, which is the caller's answer. Its parts
   * go and its room is freed at once, instead of when it expires. 204 (aborted), 404 (unknown, expired, aborted or
   * committed: never a stored snapshot), 409 (an erasure aborted it already), 410 and every other answer are final; a
   * busy answer (503) or a connection refused or reset before any answer is tried once more; no answer in time is never
   * tried again. A 401 is final too: the abort renews no credential. Never throws.
   */
  private async warmStartAbort(offer: WarmStartOffer, uploadId: string): Promise<void> {
    const url = `${offer.url}/uploads/${uploadId}`;
    const deadline = Date.now() + WARM_START_ABORT_MS;
    const tries = async (): Promise<void> => {
      for (let attempt = 1; attempt <= WARM_START_ABORT_ATTEMPTS; attempt++) {
        const left = deadline - Date.now();
        if (left <= 0) return;
        const a = await this.warmStartAbortOnce(url, left);
        if (a !== 503 && a !== 'refused') return;
        const pause = Math.min(WARM_START_ABORT_PAUSE_MS, deadline - Date.now());
        if (attempt >= WARM_START_ABORT_ATTEMPTS || pause <= 0) return;
        await new Promise<void>((r) => setTimeout(r, pause));
      }
    };
    // The bound holds even where a step has no timeout of its own (a credential being renewed): the caller stops waiting
    // at it, and whatever is still in flight ends on its own.
    let bound: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([tries().catch(() => undefined), new Promise<void>((r) => (bound = setTimeout(r, WARM_START_ABORT_MS)))]);
    clearTimeout(bound);
  }

  /**
   * One abort request: the answer's status, `refused` when the connection was refused or reset before any answer, or
   * `failed` for anything else, no answer within `timeoutMs` included. Never throws.
   */
  private async warmStartAbortOnce(url: string, timeoutMs: number): Promise<number | 'refused' | 'failed'> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      let res: Response;
      try {
        res = await keepAliveFetch(url, { method: 'DELETE', headers: { authorization: await this.currentAuthHeader() }, signal: ctrl.signal });
      } catch (e) {
        const code = (e as { code?: unknown } | null)?.code;
        return !ctrl.signal.aborted && (code === 'ECONNREFUSED' || code === 'ECONNRESET') ? 'refused' : 'failed';
      }
      // Read within the cap, so the connection can be used again; the status alone decides.
      await readBytesCapped(res, WARM_START_ANSWER_BYTES, 'warm_start_abort').catch(() => undefined);
      return res.status;
    } catch {
      return 'failed';
    } finally {
      clearTimeout(timer);
    }
  }

  /** The listing, every entry checked; one it cannot read refuses the listing whole. */
  private async warmStartListing(offer: WarmStartOffer): Promise<ListedSnapshot[]> {
    const a = await this.warmStartRequest('list', 'GET', offer.url, { cap: WARM_START_LIST_BYTES });
    if (a.status !== 200) throw this.warmStartRefusal('list', a).error;
    const listed = listedSnapshots(parsedAnswer(a.bytes));
    if (listed === null) throw new SaihmEndpointError(502, 'malformed_response', 'SAIHM warm start listed snapshots this client cannot read');
    return listed;
  }

  /** The info document's `warmStart`, or null when the endpoint describes none now (or answers no info). */
  private async warmStartRouteFromInfo(): Promise<WarmStartRoute | null> {
    const base = this.endpoint.endsWith('/') ? this.endpoint : `${this.endpoint}/`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.requestTimeoutMs);
    try {
      const res = await keepAliveFetch(new URL('info', base).toString(), { method: 'GET', signal: ctrl.signal });
      const bytes = await readBytesCapped(res, WARM_START_ANSWER_BYTES, 'warm_start_info');
      return res.ok ? warmStartRoute(parsedAnswer(bytes), base) : null;
    } catch (e) {
      throw this.warmStartTransportError('info', e, ctrl.signal);
    } finally {
      clearTimeout(timer);
    }
  }

  /** One request with this identity's credential, renewed once on a 401 when this client mints its own. */
  private async warmStartRequest(
    label: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    url: string,
    opts: WarmStartRequestOpts,
  ): Promise<WarmStartAnswer> {
    const send = async (auth: string): Promise<WarmStartAnswer> => {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.requestTimeoutMs);
      try {
        const res = await keepAliveFetch(url, {
          method,
          headers: { ...opts.headers, authorization: auth },
          ...(opts.body !== undefined ? { body: opts.body } : {}),
          signal: ctrl.signal,
        });
        const bytes = await readBytesCapped(res, opts.cap, `warm_start_${label}`);
        const ra = res.headers.get('retry-after');
        return { status: res.status, bytes, digest: answerDigests.get(res), retryAfterS: ra !== null && /^[0-9]{1,5}$/.test(ra) ? Number(ra) : null };
      } catch (e) {
        throw this.warmStartTransportError(label, e, ctrl.signal);
      } finally {
        clearTimeout(timer);
      }
    };
    const header = await this.currentAuthHeader();
    const first = await send(header);
    if (first.status !== 401 || this.staticAuthHeader) return first;
    this.tokenRefused(header);
    return send(await this.currentAuthHeader());
  }

  /**
   * A request an upload cannot afford to lose, sent again, at most WARM_START_ATTEMPTS times in all, after a limit
   * (429), an endpoint busy or failing to write (503 `busy` or `retry`), or a connection that dropped. It waits as the
   * answer asks, with jitter. A part may be sent again: it replaces the earlier copy.
   */
  private async warmStartPersisting(
    label: string,
    method: 'POST' | 'PUT',
    url: string,
    want: number,
    opts: WarmStartRequestOpts,
  ): Promise<WarmStartAnswer> {
    for (let attempt = 1; ; attempt++) {
      let a: WarmStartAnswer;
      try {
        a = await this.warmStartRequest(label, method, url, opts);
      } catch (e) {
        const dropped = e instanceof SaihmEndpointError && (e.code === 'network' || e.code === 'timeout');
        if (!dropped || attempt >= WARM_START_ATTEMPTS) throw e;
        await warmStartPause(1);
        continue;
      }
      if (a.status === want) return a;
      const refusal = this.warmStartRefusal(label, a);
      const again =
        a.status === 429 ||
        (a.status === 503 && refusal.error.code === 'warm_start_unavailable' && (refusal.reason === 'busy' || refusal.reason === 'retry'));
      if (!again || attempt >= WARM_START_ATTEMPTS) throw refusal.error;
      await warmStartPause(a.retryAfterS ?? (a.status === 429 ? 10 : 5));
    }
  }

  /** An answer this client did not ask for, as the typed error it is: the endpoint's code and reason, never its prose. */
  private warmStartRefusal(label: string, a: WarmStartAnswer): { readonly error: SaihmEndpointError; readonly reason: string | undefined } {
    const j = parsedAnswer(a.bytes) as { error?: unknown; reason?: unknown } | null | undefined;
    const code = typeof j?.error === 'string' ? j.error.slice(0, MAX_ERROR_CODE_CHARS) : undefined;
    const reason = typeof j?.reason === 'string' ? j.reason.slice(0, MAX_ERROR_CODE_CHARS) : undefined;
    if (a.status === 429 && code === undefined)
      return {
        error: new SaihmEndpointError(429, 'rate_limited', `SAIHM warm start ${label} failed: 429. Wait ${a.retryAfterS ?? 10} seconds, then try again.`),
        reason,
      };
    return {
      error: new SaihmEndpointError(a.status, code, `SAIHM warm start ${label} failed: ${a.status}` + (code ? ` (${code}${reason ? `, ${reason}` : ''})` : '')),
      reason,
    };
  }

  /** A request that got no usable answer, as the typed error the rest of this client raises for one. */
  private warmStartTransportError(label: string, e: unknown, signal: AbortSignal): SaihmEndpointError {
    if (e instanceof SaihmEndpointError) return e;
    if ((e instanceof Error && e.name === 'AbortError') || signal.aborted)
      return new SaihmEndpointError(408, 'timeout', `SAIHM warm start ${label} timed out after ${this.requestTimeoutMs}ms`);
    return new SaihmEndpointError(0, 'network', `SAIHM warm start ${label} could not reach ${safeEndpoint(this.endpoint)} (${transportReason(e)})`);
  }

  /**
   * Start the share events feed, when the endpoint offers one. Opt-in (SAIHM_EVENTS=1). The feed long-polls the
   * endpoint's events route and reconciles against this client's own shared listing; nothing it learns opens content.
   */
  startShareEvents(): void {
    if (this.shareFeed) return;
    const base = this.endpoint.endsWith('/') ? this.endpoint : `${this.endpoint}/`;
    const origin = new URL(base).origin;
    // A request ends with the feed or after `ms`, whichever is first; `done` releases the timer and the listener.
    const bounded = (feed: AbortSignal, ms: number): { signal: AbortSignal; done: () => void } => {
      const ctrl = new AbortController();
      const abort = (): void => ctrl.abort();
      const timer = setTimeout(abort, ms);
      feed.addEventListener('abort', abort, { once: true });
      return { signal: ctrl.signal, done: () => { clearTimeout(timer); feed.removeEventListener('abort', abort); } };
    };
    const transport: ShareEventsTransport = {
      info: async (feed) => {
        const r = bounded(feed, this.requestTimeoutMs);
        try {
          const res = await keepAliveFetch(new URL('info', base).toString(), { method: 'GET', signal: r.signal });
          const text = await readBodyCapped(res, 65_536, 'events_info');
          // An endpoint without the info route offers no feed. Any other non-success is no answer yet: the feed retries.
          if (res.status === 404) return null;
          if (!res.ok) throw new Error(`events info answered ${res.status}`);
          return (JSON.parse(text) as { events?: unknown }).events ?? null;
        } finally {
          r.done();
        }
      },
      poll: async (path, body, timeoutMs, feed) => {
        // The advertised path is honoured on this endpoint's own origin only: the request carries the credential.
        const url = new URL(path, base);
        if (url.origin !== origin) throw new Error('events path is not on the endpoint origin');
        const r = bounded(feed, timeoutMs);
        try {
          const send = async (auth: string): Promise<Response> => keepAliveFetch(url.toString(), {
            method: 'POST', headers: { 'content-type': 'application/json', authorization: auth }, body: JSON.stringify(body), signal: r.signal,
          });
          const header = await this.currentAuthHeader();
          let res = await send(header);
          if (res.status === 401 && !this.staticAuthHeader && Date.now() - this.lastFeedRenewAt >= FEED_RENEW_INTERVAL_MS) {
            await readBodyCapped(res, 65_536, 'events_poll').catch(() => '');
            this.lastFeedRenewAt = Date.now();
            this.tokenRefused(header);
            res = await send(await this.currentAuthHeader());
          }
          const text = await readBodyCapped(res, 1_048_576, 'events_poll');
          let parsed: unknown = {};
          try { parsed = text ? JSON.parse(text) : {}; } catch { parsed = {}; }
          const ra = res.headers.get('retry-after');
          return { status: res.status, body: parsed, ...(ra && /^[0-9]{1,5}$/.test(ra) ? { retryAfterS: Number(ra) } : {}) };
        } finally {
          r.done();
        }
      },
      // The share listing alone: an endpoint that offers the feed answers without reading any own cell. One that does
      // not answers with the full listing, which the feed reads for shares only and never opens.
      listing: async () => this.call<unknown>('saihm_recall', { sharesOnly: true }),
      // The whole list by pages where the endpoint offers paging, timed and dated by the feed's clock. Where it does not,
      // where a page answer shows it no longer does, or where the status that says so cannot be read, null: the feed then
      // reads the one-answer listing above, as before paging.
      pass: async (feed, bounds) => {
        const p = await this.listAllShares({ maxEntries: bounds.maxEntries, now: bounds.now, signal: feed });
        return p.incomplete === 'unsupported' || p.incomplete === 'unread' ? null : p;
      },
    };
    // The map for other processes: written soon after a change, at least once a minute, and once more when the feed
    // stops. A root that cannot be resolved means no file, which asserts nothing.
    let path: string | undefined;
    try { path = shareStatesPath(this.agentIdHashHex); } catch { path = undefined; }
    let pending: ReturnType<typeof setTimeout> | undefined;
    const write = (): void => {
      pending = undefined;
      // While another process writes this tenant directory's event files, the map file is that process's to write.
      if (path === undefined || !this.shareFeed || !this.shareFeed.mayWriteMap()) return;
      try { writeShareStates(path, this.shareFeed.snapshot()); } catch { /* a lost lock or a full disk: the next change or minute tries again */ }
    };
    const every = setInterval(write, SHARE_STATES_WRITE_MS);
    every.unref();
    this.shareStatesWriter = {
      soon: () => { if (pending === undefined && path !== undefined) { pending = setTimeout(write, 250); pending.unref(); } },
      stop: () => { clearInterval(every); if (pending !== undefined) clearTimeout(pending); write(); },
    };
    // Where the feed's position survives a restart. `off` keeps it in memory, and so does a root that cannot be
    // resolved: a subscriber with nowhere to write is never broken by this and sets nothing. The cost of memory-only
    // is the listing this client fetched at every start before 0.11.0.
    let store: FeedStore | undefined;
    if ((process.env.SAIHM_SHARE_MAP_STORE ?? 'file') !== 'off') {
      try { store = new FileFeedStore(feedStatePath(this.agentIdHashHex)); } catch { store = undefined; }
    }
    // The own-cell event files (changes.ndjson and the feed's erasure lines), written by one process per tenant
    // directory. Only with the erasure feed on: a change file whose erasures went unrecorded would mislead its reader.
    // The feed uses the writer only while the endpoint offers both own-cell kinds; otherwise nothing here is touched.
    let own: ChangeFeedWriter | undefined;
    if (erasureFeedEnabled()) {
      try { own = new ChangeFeedWriter({ agentIdHash: this.agentIdHashHex }); } catch { own = undefined; }
    }
    this.ownChanges = own;
    this.shareFeed = new ShareEventsFeed({
      transport, ...(store ? { store } : {}), ...(own ? { own } : {}), onChange: () => this.shareStatesWriter?.soon(),
    });
    // Outside every tool call's answer record: started from inside one (the first call boots the client), the feed's own
    // recall listings would otherwise land in that call's record as if they were its answer.
    const feed = this.shareFeed;
    answerNotes.exit(() => feed.start());
  }

  /** Stop the share events feed, including a poll in flight, so nothing keeps the process running. */
  async stopShareEvents(): Promise<void> {
    // The last write of the share map happens before the writer's lease is given up.
    if (this.shareFeed) await this.shareFeed.stop(() => this.shareStatesWriter?.stop());
    else this.shareStatesWriter?.stop();
  }

  /**
   * The share map from the events feed, or undefined when the feed is not running. A process waiting for another to
   * write this tenant directory reports that writer's map, from the file it writes.
   */
  shareStates(): ShareStates | undefined {
    const feed = this.shareFeed;
    if (!feed) return undefined;
    if (feed.role === 'waiting') {
      let path: string | undefined;
      try { path = shareStatesPath(this.agentIdHashHex); } catch { path = undefined; }
      const fromFile = path === undefined ? undefined : readShareStates(path);
      if (fromFile) return fromFile;
    }
    return feed.snapshot();
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
