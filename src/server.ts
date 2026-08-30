#!/usr/bin/env node
/**
 * SAIHM MCP Server (Pro) — self-onboarding, client-side-sealing MCP server.
 *
 * Eight MCP tools any MCP-capable AI agent (Claude Code, Claude Desktop, custom
 * agents) can call. Unlike the bare-bones client, every cell is SEALED in this
 * process via @saihm/client-pro before it leaves, and the access token is minted
 * + auto-refreshed here from your master secret — paste one config once, with no
 * token to re-paste. The master secret, KEK, and plaintext never leave this process.
 *
 *   Core (4):       saihm_remember, saihm_recall, saihm_forget, saihm_status
 *   Sharing (2):    saihm_share, saihm_revoke_share
 *   Governance (2): saihm_governance_propose, saihm_governance_vote
 *
 * Run as an MCP server (the usual case):
 *   npx -y @saihm/mcp-server-pro
 * Join SAIHM (one-off, OAuth device flow) — the default entry point. Needs NO configuration:
 * it generates and persists your identity, defaults the tier FREE and the endpoint to the
 * hosted operator, so this is a complete join on a bare machine:
 *   npx -y @saihm/mcp-server-pro free-join
 * Subscribe an identity directly instead, skipping FREE (one-off, prints a Stripe checkout link).
 * Needs a master secret and SAIHM_TIER/SAIHM_PAYMENT_METHOD in env — see README:
 *   npx -y @saihm/mcp-server-pro join
 * Upgrade FREE -> monthly paid, same key/memories (one-off — requires SAIHM_TIER=FREE):
 *   npx -y @saihm/mcp-server-pro upgrade [PRO|PRO_FAST|ENTERPRISE|ENTERPRISE_FAST]
 *
 * Boot from env (self-onboard): SAIHM_ENDPOINT_URL, SAIHM_MASTER_SECRET_HEX,
 *   SAIHM_TIER, SAIHM_PAYMENT_METHOD. Advanced/legacy: SAIHM_AUTH_HEADER (static).
 */
import { mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join as pathJoin } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  MALFORMED,
  MAX_JOIN_FIELD_CHARS,
  MAX_PATH_FIELD_CHARS,
  MAX_PATH_MESSAGE_CHARS,
  MAX_URL_FIELD_CHARS,
  boundedOrMarker,
  safeField,
  safePathField,
  safeScalar,
  shortScalar,
  labelSafe,
  hexOrMarker,
  scopeOrMarker,
  epochOrMarker,
  failText,
} from './render_fence.js';

import { z } from 'zod';
import {
  SaihmProClient,
  selfJoinEnabled,
  ensureSelfJoinIdentityEnv,
  identityKeyFile,
  MAX_ANNOUNCEMENT_FIELD_CHARS,
  type FreeDevicePrompt,
  type FreeEntitlementResult,
} from './client.js';

const PACKAGE_VERSION: string = (
  JSON.parse(
    readFileSync(
      pathJoin(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'),
      'utf-8',
    ),
  ) as { version: string }
).version;

// Distinct from the standards client's `saihm`: two separately published packages must not announce
// the same serverInfo.name, or directories that key on it conflate them.
const server = new McpServer(
  { name: 'saihm-pro', version: PACKAGE_VERSION },
  { capabilities: { tools: {}, prompts: {} } },
);

// Lazily boot so the MCP `initialize` handshake always succeeds; a misconfiguration surfaces as a
// typed tool error on first use rather than crashing the transport.
let client: SaihmProClient | null = null;
function getClient(): SaihmProClient {
  if (!client) client = SaihmProClient.bootFromEnv();
  return client;
}

const ok = (text: string, structuredContent?: Record<string, unknown>) => ({
  content: [{ type: 'text' as const, text }],
  ...(structuredContent ? { structuredContent } : {}),
});

/** Surface any error as a typed MCP tool error (never crash the server). */
function fail(e: unknown) {
  return { content: [{ type: 'text' as const, text: failText(e) }], isError: true as const };
}

/**
 * An endpoint-supplied count or score, resolved to the number it actually is, or to `null`.
 *
 * The declared TypeScript type of these fields is `number`, but they arrive through an unvalidated
 * cast, so the declaration is an expectation and not a guarantee. `Number(v)` alone is not the answer:
 * it turns `undefined` into `NaN`, `null` and `''` into `0`, and `[]` into `0` — inventing plausible
 * counts out of missing data. A numeric STRING is accepted because JSON round-tripping a large integer
 * legitimately produces one; anything else is reported as absent rather than guessed at.
 *
 * The string branch is DECIMAL-ONLY, and was not: `Number()` applies the whole JS numeric grammar, so
 * `"0x7fffffff"` became 2147483647, `"0o777"` became 511 and `"0b1111"` became 15 — measured, and
 * forms JSON round-tripping never produces. That is the same "inventing plausible counts" the
 * paragraph above rejects, arriving through the branch meant to permit one narrow legitimate case.
 * The range check goes with it: a count is a non-negative integer, so a negative or fractional value
 * is absent data too, not a small one.
 */
const DECIMAL = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?$/;

/**
 * Length ceiling applied BEFORE the grammar, so the work is bounded by the ANSWER's size rather than
 * the input's — the same slice-first principle `safeField` was rebuilt around, which this helper did
 * not follow. Without it a string value costs `v.trim()` (a full copy), then `DECIMAL.test` (a full
 * scan), then `Number(v)` (another) — three passes over an endpoint-chosen string, three times per
 * `saihm_status` call, to produce at most ~20 characters of output.
 *
 * MEASURED at 16 MiB of digits: 212.2 ms here against 0.006 ms for the structured bound. Stated
 * honestly, no end-to-end impact was demonstrated — driving same-size bodies through the real server
 * with the bulk in the numeric fields (610 ms, 574 ms) against the bulk in `tier` (582 ms, 732 ms) is
 * within noise, because transport and `JSON.parse` dominate. This is a principle violation fixed
 * cheaply, NOT a working denial of service, and the comment says so rather than borrowing the
 * urgency of one.
 *
 * 32 characters clears every real value with room to spare. This once justified that with "the longest
 * finite double round-trips as `-1.7976931348623157e+308`, at 24", which answered the wrong question:
 * that is the double of greatest MAGNITUDE, not the one with the longest `String()`. The longest is a
 * SMALL one, because `String` switches to exponent form only below 1e-6, so the widest fixed-notation
 * value is a sign, `0.`, five leading zeros and 17 significant digits — MEASURED at 25 over 3e6 random
 * doubles, worst case `-0.0000048340370808296565`. The bound still holds; its margin is 7, not 8. Kept
 * as a note on method rather than corrected silently: reaching for the extreme of the obvious axis is
 * how a length claim gets argued from magnitude, and the two extremes are different numbers.
 */
const MAX_NUMERIC_CHARS = 32;
const numOrNull = (v: unknown): number | null => {
  if (typeof v === 'string' && v.length > MAX_NUMERIC_CHARS) return null;
  const n = typeof v === 'number' ? v : typeof v === 'string' && DECIMAL.test(v.trim()) ? Number(v) : NaN;
  return Number.isFinite(n) ? n : null;
};
/** A count: {@link numOrNull} plus the range a count actually has. */
const countOrNull = (v: unknown): number | null => {
  const n = numOrNull(v);
  return n !== null && n >= 0 && Number.isInteger(n) ? n : null;
};

/**
 * The device-flow code lifetime in whole minutes, for a line a human reads.
 *
 * A GUARD AT THE RENDER SITE, and today an unreachable one — stated plainly, because an earlier cut
 * of this comment claimed the opposite as observed fact. It said a non-numeric `expiresIn` "printed
 * 'expires in about NaN min'"; it could not have. `acquireFreeEntitlement` already clamps the
 * bridge's value into [60, 1800] with a 900 fallback before either caller sees it, and that clamp
 * predates this helper by two commits. `Math.max(1, NaN)` really is `NaN` and the old inline
 * expression really would have rendered it — but nothing could deliver a NaN to it, so the symptom
 * was reasoned, not seen, and writing it as seen is the error this review round exists to catch.
 *
 * Kept anyway, because the clamp lives in the client and this is the render site: whether a rendered
 * value is a number is not a property the renderer should have to take on trust from elsewhere. The
 * 900-second fallback is THIS codebase's convention (client.ts), not a default from RFC 8628 — §3.2
 * makes `expires_in` REQUIRED and gives it no default, and the only §3.2 parameter with an RFC
 * default is `interval`. An earlier cut credited the RFC for a number it does not contain.
 */
const expiryMins = (seconds: unknown): number => {
  const n = numOrNull(seconds);
  return n === null || n <= 0 ? 15 : Math.min(1440, Math.max(1, Math.round(n / 60)));
};

server.registerTool(
  'saihm_remember',
  {
    title: 'Remember',
    description:
      'Store information to SAIHM persistent encrypted memory (sealed client-side). Pass an existing cellId to update it. Use this when an agent or user wants a fact, decision, or context to persist across sessions.',
    inputSchema: {
      content: z.string().describe('Information to remember'),
      cellId: z
        .string()
        .optional()
        .describe('Existing cell id (hex) to update; omit to create a new cell'),
    },
    outputSchema: {
      cellId: z.string(),
      seq: z.string(),
      shardId: z.string(),
      commitmentHash: z.string(),
    },
    annotations: {
      title: 'Remember',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  async ({ content, cellId }) => {
    try {
      const r = await getClient().remember(content, cellId ? { cellId } : {});
      // Resolved ONCE, then rendered into both halves of the response.
      //
      // Bounding each channel separately let them state different things about the same field, which
      // is the defect `saihm_status` was fixed for and this site kept: the text fence caps at 64 and
      // the structured bound at 256, so an endpoint `shardId` of 100 characters rendered as 64
      // characters plus a truncation marker in the text while `structuredContent` carried all 100,
      // and one of 5,000 rendered as 64 plausible characters in the text while the structured half
      // said `(malformed)`. The second is the damaging direction: the channel an agent READS showed a
      // value the endpoint chose the front of, while the channel a program reads called it unusable.
      //
      // Resolving first makes the VERDICT single. If the bound rejects, both halves say
      // `(malformed)`; if it accepts, the text shows a marked truncation of the same accepted value.
      // The two halves can still differ in LENGTH — that is what the marker announces — but they can
      // no longer disagree about whether the value is usable at all.
      const shardId = boundedOrMarker(r.shardId);
      return ok(
        // `cellId`, `seq` and `commitmentHash` are the CLIENT's, though not all from one source:
        // `cellId` is caller-supplied or client-generated, `seq` is this client's monotonic counter,
        // and only `commitmentHash` is read off the envelope this process sealed. All three are
        // local, which is what the security claim rests on — so the fence here is defence in depth
        // rather than the only thing standing between the endpoint and this line. `shardId` is the
        // exception: it names endpoint-side storage, so it is genuinely endpoint-chosen and the fence
        // is load-bearing for it. Fencing all four keeps the renderer's stated property — safe for ANY
        // input — true independently of what the client happens to guarantee today, which is what a
        // later refactor of `remember()` would otherwise silently break. It matters more here than in
        // the announcement list: this line is a RECEIPT for a write the agent explicitly requested,
        // so a memory-shaped line minted inside it arrives with the agent's own intent behind it.
        `REMEMBERED [${labelSafe(safeScalar(r.cellId))}] seq=${labelSafe(safeScalar(r.seq))} ` +
          `shard=${labelSafe(safeScalar(shardId))} commit=${labelSafe(shortScalar(r.commitmentHash))}`,
        {
          cellId: r.cellId,
          seq: String(r.seq),
          // The only endpoint-chosen value in this result, and so the only one that needs a bound.
          // Unsanitised on purpose — structured output is a named field of a declared schema, not a
          // line in a text block — but SIZE is a separate axis from injection, and it was uncapped
          // here while the announcement channel was capped on both. Bound applied above, once.
          shardId,
          commitmentHash: r.commitmentHash,
        },
      );
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'saihm_recall',
  {
    title: 'Recall',
    description:
      'Retrieve and decrypt your memories (opened client-side). Optional keyword filter. Use this at the start of a session or whenever past context is needed. Can ALSO read one specific cell another agent shared TO you — pass sharerPinnedAgentIdHashHex + sharerRecord + cellId (read-only; the sharer must have shared it with you).',
    inputSchema: {
      query: z
        .string()
        .optional()
        .describe('Filter your OWN memories by keyword (empty = all). Ignored when reading a shared cell.'),
      sharerPinnedAgentIdHashHex: z
        .string()
        .optional()
        .describe(
          "Read a cell shared TO you: the SHARER's agentIdHash (hex), pinned out-of-band. When set, sharerRecord and cellId are also required.",
        ),
      sharerRecord: z
        .object({
          mldsaPubKey: z.string(),
          mlkemPubKey: z.string(),
          mlkemPubKeySelfSig: z.string(),
        })
        .optional()
        .describe("The SHARER's published identity record (hex fields). Required with sharerPinnedAgentIdHashHex."),
      cellId: z
        .string()
        .optional()
        .describe('The shared cell id to read. Required when reading a shared cell.'),
    },
    outputSchema: {
      count: z.number(),
      memories: z.array(
        z.object({ cellId: z.string(), seq: z.string(), plaintext: z.string() }),
      ),
      // MUST be declared, and MUST be emitted by every branch — both halves are load-bearing, for
      // different reasons. DECLARED: this SDK's output validation only throws on failure (it discards
      // the parsed value), so an undeclared key is not stripped here — but it is also not contractual,
      // and this SDK publishes the outputSchema with `additionalProperties:false`, so a consumer
      // validating against it rejects the whole response over an undeclared key. EMITTED EVERYWHERE:
      // a declared key is REQUIRED, so a branch that omits it fails validation — and the failure mode
      // is NOT a protocol error the host surfaces. `validateToolOutput` throws an McpError, the tool
      // dispatcher re-throws only `UrlElicitationRequired`, and everything else is converted into a
      // normal tool result with `isError: true` whose text is the validation message. So an omitted
      // key silently degrades a successful recall into an error string handed to the MODEL, inside a
      // 200 response — visible to the agent, invisible to any caller checking for a JSON-RPC error.
      // Always present, `[]` when there are none — so gate-off emits a DECLARED
      // constant rather than drifting.
      shared: z.array(
        z.object({
          sharer: z.string(),
          cellId: z.string(),
          scope: z.string(),
          // Decimal string, or null for a grant with no expiry (the server's default). Never a number.
          expiryEpoch: z.string().nullable(),
          verified: z.literal(false),
        }),
      ),
      /** True when the endpoint announced more grants than the client keeps; the list above is cut. */
      sharedTruncated: z.boolean(),
    },
    annotations: {
      title: 'Recall',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async ({ query, sharerPinnedAgentIdHashHex, sharerRecord, cellId }) => {
    try {
      // Shared-read branch: read a single cell another agent shared TO this agent. Presence of the
      // sharer pin selects this branch; the sharer record + cellId are then mandatory. The endpoint
      // (blind) only returns a cell for which a live grant to THIS recipient exists; the client
      // authenticates the grant + opens it locally. Read-only — no write scope on the tool surface.
      if (sharerPinnedAgentIdHashHex) {
        if (!sharerRecord || !cellId) {
          throw new Error(
            'To read a shared cell, provide sharerPinnedAgentIdHashHex, sharerRecord, and cellId together.',
          );
        }
        const cell = await getClient().recallShared({
          sharerPinnedAgentIdHashHex,
          sharerRecord,
          cellId,
        });
        // `shared`/`sharedTruncated` are declared on the outputSchema, so this branch emits them too —
        // an omitted key is not the same as an empty one, and a consumer must not have to distinguish
        // "no announcements" from "this branch does not report announcements".
        if (!cell) {
          return ok('No shared cell found (no live grant to you, or content unavailable).', {
            count: 0,
            memories: [],
            shared: [],
            sharedTruncated: false,
          });
        }
        const mem = { cellId: cell.cellId, seq: String(cell.seq), plaintext: cell.plaintext };
        // A FOREIGN plaintext, rendered so it cannot be read as one of the agent's OWN memories.
        //
        // This content is authenticated — `recallShared` verifies the envelope's ML-DSA signature
        // against the sharer pinned OUT-OF-BAND and rejects a cellId that is not the one asked for —
        // so the writer here is the SHARER, not the endpoint. That is a real trust boundary and not a
        // reason to skip the fence: pinning an identity to read ONE cell they offered is not a
        // decision to let them mint lines shaped like the agent's own authenticated memory, which the
        // old single-line `[id] seq=n | text` form let any embedded newline do exactly.
        //
        // The fence is a per-line PREFIX, not a sanitiser, and that choice is the point. Scrubbing
        // would be the wrong tool twice over: it is someone's memory, so collapsing non-ASCII would
        // destroy any content not written in English and strip the `|` or `[` from a legitimate note,
        // and unlike an announcement `cellId` there is no adversary-prose budget to defend — the agent
        // asked for this cell by id. Marking every PHYSICAL line closes line-minting completely and
        // losslessly: an embedded newline can only ever produce another marked line, never a top-level
        // one, and no byte of the memory is altered. Own-cell plaintext below stays unmarked and
        // unfenced for the same reason inverted — it is the agent's own data, and `  ! `/`  > ` are
        // exactly the signals that distinguish the two.
        //
        // The split covers the line terminators of CPython's `str.splitlines()`: LF, CR, CRLF, VT,
        // FF, FS, GS, RS, NEL, U+2028 and U+2029. That set is CITED, not asserted — it is a superset
        // of ECMAScript's LineTerminator, and Python is the reference MCP SDK's language, so it is the
        // widest set a host in this ecosystem is known to honour. Anything outside it is a gap this
        // comment does NOT claim to have closed.
        //
        // The wording matters because the universal form of this claim has now been wrong twice. An
        // earlier cut split on CR, LF and CRLF alone and claimed that closed line-minting
        // "completely"; MEASURED, it did not — U+2028, U+2029, NEL, VT and FF each turned one marked
        // line into three rendered lines, two unmarked, one matching the own-memory shape exactly.
        // Its replacement then claimed the split covered "EVERY line terminator a renderer may
        // honour", and measured, FS, GS and RS (U+001C-U+001E) did the same thing again: emitted as
        // ONE marked line here, they became two lines under `str.splitlines()`, the second unmarked
        // and matching `^ {2}\[[^\]\n]*\] seq=`. The sweep behind that word had only ever looked at
        // the JS set. A universal quantifier over a set nobody enumerated is not a stronger claim
        // than a cited one — it is an unfalsifiable one, and it failed the same way twice.
        //
        // The argument for including a bare CR — a host honouring it starts a fresh visual line —
        // applies verbatim to all ten. This site deliberately does not scrub AND marks every line
        // that survives, and it is the only one that does both. "The one render site where
        // terminators survive" would be too broad, and this comment said it: own-cell `plaintext` is
        // interpolated raw in the branch below, so all ten survive there too — a residual the
        // `sharedLines` block states rather than closes. What is unique here is WHOSE content it is.
        // Every site that fences an ENDPOINT-chosen value scrubs the whole below-U+0020 range through
        // `safeField`, which is why the gap existed on these two lines and nowhere else. Normalising
        // a line ending is the one alteration worth making — every other byte of the memory survives
        // verbatim, which is the property scrubbing could not offer.
        //
        // Length is deliberately NOT capped, matching the own-memory branch: truncating a memory the
        // agent explicitly requested would corrupt the answer to its own question. The residual is a
        // sharer who was already pinned choosing to store a very large cell — a cost the recipient
        // opted into, not one the endpoint can impose.
        const sharedBody = cell.plaintext
          .split(/\r\n|[\n\r\u2028\u2029\u0085\u000b\u000c\u001c\u001d\u001e]/)
          .map((l) => `  > ${l}`)
          .join('\n');
        return ok(
          `SHARED-RECALL [${labelSafe(safeScalar(cell.cellId))}] seq=${labelSafe(safeScalar(cell.seq))} — content below is ` +
            `ANOTHER AGENT'S, not your own memory\n${sharedBody}`,
          {
            count: 1,
            memories: [mem],
            shared: [],
            sharedTruncated: false,
          },
        );
      }

      // Partial shared-read args (record/cellId but no sharer pin) => fail loud rather than silently
      // returning the caller's OWN memories, which would surprise an agent that intended a shared read.
      if (sharerRecord || cellId) {
        throw new Error(
          'To read a shared cell, provide sharerPinnedAgentIdHashHex, sharerRecord, and cellId together.',
        );
      }

      // Own-memories branch, plus any share announcements the SAME response carried. Both come from
      // one call: this client is a process-wide singleton and the SDK does not serialise tool handlers,
      // so reading announcements from client state would let two concurrent recalls cross-attribute
      // their sets — an interleaving a hostile endpoint chooses simply by delaying one response.
      const { cells, announcements, announcementsTruncated } =
        await getClient().recallWithShared(query);
      const memories = cells.map((c) => ({
        cellId: c.cellId,
        seq: String(c.seq),
        plaintext: c.plaintext,
      }));
      // Pointers to cells OTHER agents granted to this one. Reported separately from `memories` and
      // never folded into `count`: they are unauthenticated endpoint claims carrying no content, and
      // an agent that mistook one for a held memory would be reporting something it has never read.
      // The keyword filter is deliberately not applied — there is no plaintext here to match on.
      const shared = announcements.map((a) => ({
        sharer: a.sharer,
        cellId: a.cellId,
        scope: a.scope,
        expiryEpoch: a.expiryEpoch,
        verified: false as const,
      }));
      // Every line EXCEPT the banner is prefixed `  ! `, so no field the ENDPOINT chose can read as a
      // memory and a replayed footer cannot appear to close the block early. The banner is
      // server-composed and interpolates no endpoint-chosen text, so it needs no marker of its own.
      //
      // Scope of that guarantee, precisely: it holds against the endpoint, which is the party this
      // block defends against. It is NOT a claim that the `  ! ` shape is unreachable in general —
      // own-cell `plaintext` is interpolated raw below, so a memory whose CONTENT contains a newline
      // followed by `  ! POINTER …` renders a line of this shape. That content is authenticated as
      // this agent's own cell; authenticated means it is the agent's, not that it is trustworthy, so
      // an agent that stored attacker-influenced text can be shown a pointer its own memory minted.
      // The damage is bounded — resolving any pointer still needs a sharer identity record pinned
      // OUT-OF-BAND, which a forged line cannot supply — and the general problem (stored untrusted
      // content re-read as instruction) is neither created nor solved here.
      //
      // Only as many pointers as an agent can actually use are rendered here. The cap on the LIST is
      // the client's (256); this second, tighter cap is on the CHANNEL, because the text block is what
      // lands in the agent's context on the tool the session-bootstrap prompt calls first. It is a
      // budget on ADVERSARY PROSE, not a display preference: `cellId` is genuinely free-form, so it
      // can only be sanitised, never checked. MEASURED worst case at RENDER_LIMIT 16: the free-form
      // `cellId` contributes 16 × 64 = 1,024 characters, but `sharer` and `expiry` are endpoint-chosen
      // too, so the endpoint-supplied total is 16 × (64 + 64 + 20) = 2,368 and the whole text block
      // tops out at 3,595 bytes over a 200-character worst-case pointer line. Reaching either number
      // requires an OFF-CONTRACT scope: `(malformed)` is 11 characters where `readwrite` is 9, so a
      // fixture using a legal scope stops at 3,563 bytes and 198 characters and leaves the ceiling
      // untested. (Two earlier cuts of this comment were wrong in the other direction: one called the
      // cellId figure the per-recall total, at "near 1 KB", counting one of three fields; its
      // replacement said 3,547, which was the legal-scope fixture mistaken for the ceiling.) That
      // still lists more grants than a real agent is likely to hold; the withheld count is always
      // stated, and `structuredContent.shared` stays complete.
      const RENDER_LIMIT = 16;
      const rendered = announcements.slice(0, RENDER_LIMIT);
      const unrendered = announcements.length - rendered.length;
      const sharedLines =
        announcements.length === 0
          ? []
          : [
              `SHARED WITH YOU: ${announcements.length} unverified pointer(s) — no content, nothing below is authenticated${
                announcementsTruncated ? ' (LIST TRUNCATED: the endpoint announced more)' : ''
              }`,
              ...rendered.map(
                (a) =>
                  // cellId is the only free-form field — a writer picks it, so it can be any string and
                  // must go through the sanitiser. The other three have contracts the endpoint cannot
                  // widen, so they are CHECKED rather than sanitised: a conforming value renders whole
                  // (the sharer in particular must render in FULL, since it IS the pin the footer tells
                  // the agent to supply, and a truncated hash is one it cannot use), and a
                  // non-conforming one renders as a fixed marker carrying none of the endpoint's bytes.
                  // The render budget IS the client's per-field cap, imported rather than restated:
                  // every kept announcement then renders WHOLE, so no pointer is ever shown truncated
                  // and therefore unusable. safeField's own truncation stays as a backstop — this
                  // renderer must be safe for any input, not only for what today's client admits.
                  `  ! POINTER cell=${labelSafe(safeField(a.cellId, MAX_ANNOUNCEMENT_FIELD_CHARS))} sharer=${hexOrMarker(a.sharer)} ` +
                  `scope=${scopeOrMarker(a.scope)} expires=${epochOrMarker(a.expiryEpoch)}`,
              ),
              // States the withheld count WITHOUT naming where the rest can be read. `structuredContent`
              // is deliberately unsanitised, so a line in the trusted channel that sends the agent
              // there is a server-composed instruction to go read attacker-chosen bytes — the two
              // halves compose into the very injection the sanitising exists to prevent. The count is
              // the honest part and is kept; the routing is not.
              ...(unrendered > 0 ? [`  ! …and ${unrendered} more withheld from this list.`] : []),
              "  ! To read one, supply that sharer's identity record (obtained out-of-band) as",
              '  ! sharerPinnedAgentIdHashHex + sharerRecord + cellId. Until then these are claims, not memories.',
            ];
      // "No memories stored." is kept verbatim whenever there are no OWN cells, announcements or not:
      // it is the string existing consumers and tests key on, and losing it the moment an endpoint
      // announces a grant would be a live behaviour change triggered by a third party's action.
      const lines =
        cells.length === 0
          ? ['No memories stored.']
          : [
              `RECALL ${cells.length} memories`,
              // cellId and seq land in LABEL position, exactly as in the REMEMBERED and
              // SHARED-RECALL receipts, and are fenced identically here. NOT because the endpoint
              // chose them: `openRow` DISCARDS the server's row label and takes both from the
              // envelope this identity's own key opened, binding seq into the AEAD AAD.
              // `render_fence.ts` records calling these two endpoint-chosen as a prior error made
              // in the other direction. (`server_render_hostile.test.ts` says the same in its
              // reachability note, but SAYS is the right verb: its two assertions are about line
              // and label grammar, so citing it as a pin for ownership would be the mistake this
              // tree keeps making.)
              //
              // CALLER-SUPPLIED IS NOT CALLER-CHOSEN, and that — not housekeeping — is why the
              // fence is here. `cellId` is a free-form argument to `saihm_remember` with no pattern
              // and no length bound, which the tool's own description invites callers to supply. An
              // agent that lifts an id out of a forged pointer line and stores under it signs the
              // payload itself, and the endpoint then replays it authenticated. The endpoint cannot
              // SET this field; it can INDUCE it, and an induced id in LABEL position is exactly
              // what `labelSafe` and the scalar budget are for. A first cut of this comment gave
              // only renderer-consistency as the reason, which understated it into a tidiness
              // argument.
              //
              // The consistency argument is real but secondary: one of three sibling receipts
              // rendering a label by a different rule is how the other two stop being evidence for
              // anything, and the announcement block above keeps its own backstop for the same
              // reason — this renderer must be safe for ANY input, not only for what today's
              // client admits.
              //
              // The structured `memories[]` copy is deliberately left WHOLE, and as of 2026-08-28
              // that is SETTLED rather than open: `render_fence.ts` carries both the reasoning and
              // the premise it rests on. This fence answers a renderer question, and the channel it
              // fences is the one an agent actually reads.
              //
              // Plaintext stays RAW by design — it is the payload, not a label;
              // the residual that creates is documented on the `sharedLines` block earlier in this
              // same handler, not above it.
              ...cells.map(
                (c) =>
                  `  [${labelSafe(safeScalar(c.cellId))}] seq=${labelSafe(safeScalar(c.seq))} | ${c.plaintext}`,
              ),
            ];
      return ok([...lines, ...sharedLines].join('\n'), {
        count: cells.length,
        memories,
        shared,
        sharedTruncated: announcementsTruncated,
      });
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'saihm_forget',
  {
    title: 'Forget (GDPR erasure)',
    description:
      'Cryptographically erase a memory (GDPR Art. 17): destroys the endpoint-side wrapped DEK so the cell can never be decrypted again. Use this only to permanently and irreversibly delete a memory by its cell id.',
    inputSchema: { id: z.string().describe('Memory cell id (hex) to erase') },
    annotations: {
      title: 'Forget (GDPR erasure)',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async ({ id }) => {
    try {
      const r = await getClient().forget(id);
      return ok(
        // The cell NAMED here is the one the agent asked to erase, not the one the endpoint echoed
        // back. The echo is an unvalidated cast, so `forget('cellA')` answered with `cellId:'cellB'`
        // used to print `FORGOTTEN [cellB]` — and this is a DESTRUCTIVE, irreversible tool, so the
        // agent would come away believing it had erased a cell it had not touched and spared one it
        // had just destroyed. Fencing the echo makes it harmless to render; not rendering it makes
        // the line correct. The remaining three fields are outcomes only the endpoint can report,
        // so they stay its own — fenced, because that is exactly what an unvalidated cast needs.
        `FORGOTTEN [${labelSafe(safeScalar(id))}] complete=${labelSafe(safeScalar(r.complete))} ` +
          `sharesPurged=${labelSafe(safeScalar(r.sharesPurged))} epoch=${labelSafe(safeScalar(r.epoch))}` +
          // The erasure succeeded; this line says what did NOT. It is rendered because a residual an
          // operator never sees is the same as no residual at all — and this is the one tool where
          // the thing left behind is the plaintext they asked to destroy. The sentence is ours, but
          // it interpolates the cache path, which comes from operator env and is not statically
          // known here, so it goes through a fence like every other rendered value.
          //
          // MAX_PATH_MESSAGE_CHARS and not MAX_ERROR_MESSAGE_CHARS: the sentence is 166 fixed
          // characters, so the message budget alone left 90 for the path and cut any longer one --
          // naming a file the operator cannot then go and find, on the line that exists to send
          // them to it. Safe to widen HERE specifically because `client.ts` deletes any
          // endpoint-supplied field of this name before setting its own, so nothing hostile reaches
          // this value; the budget is not widened for the endpoint-facing sites that share the
          // narrower constant.
          (r.localCacheResidual
            ? `\n  ! ${safePathField(r.localCacheResidual, MAX_PATH_MESSAGE_CHARS)}`
            : ''),
      );
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'saihm_status',
  {
    title: 'Status',
    description:
      'Show operator-observable session status (no plaintext): tier, shards, sharing, BFSI, custody. Use this to check the identity, custody, storage, and sharing state of the current SAIHM session.',
    inputSchema: {},
    outputSchema: {
      agentIdHash: z.string(),
      tier: z.string(),
      custody: z.string(),
      // NULLABLE, and that is a deliberate widening of a shipped contract. `status()` is an
      // unvalidated cast, so these three arrive as whatever the endpoint sent. Declaring them
      // strictly `z.number()` did not make them numbers — it made ONE non-numeric character enough to
      // fail output validation, and this SDK converts that failure into `isError: true` carrying
      // `MCP error -32602 Output validation error` IN PLACE OF the whole composed result. The fenced
      // text, markers and all, is discarded; the agent sees what reads like a bug in its own client,
      // and the endpoint can hold `saihm_status` in that state indefinitely. That is the exact
      // degradation the note on `saihm_recall`'s outputSchema warns about, and it was reintroduced
      // here. `null` says "the endpoint did not supply a usable number" and says it INSIDE a
      // successful result; a sentinel like `0` or `-1` would be worse than either, since a malformed
      // value must never be normalised into a plausible one. A consumer that was validating strictly
      // was already receiving an error for these inputs, so nothing that worked stops working.
      activeShardCount: z.number().nullable(),
      activeSharingContracts: z.number().nullable(),
      bfsi: z.number().nullable(),
      snapshotEpoch: z.string(),
      // LOCAL, and the only field on this schema that is. Everything above is what the endpoint
      // said; this is what our own filesystem did. Declared rather than merely emitted because the
      // SDK publishes this schema with `additionalProperties: false`, so an undeclared field fails
      // OUTPUT VALIDATION and the SDK replaces the whole composed result with an error - the
      // degradation the note above records. Nullable and always present, so adding it widens the
      // contract without making any consumer's previously-valid response invalid.
      seqStateDegraded: z.string().nullable(),
    },
    annotations: {
      title: 'Status',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async () => {
    try {
      const client = getClient();
      const d = await client.status();
      // The identity is READ LOCALLY, never from the response. `status()` is an unvalidated cast, so
      // `d.agentIdHashHex` is simply what the endpoint chose to say this agent is — and the agent's
      // own identity is the last value that should come from a party it does not trust: reported
      // wrongly, it is the hash the agent then publishes for others to pin. The client derives it from
      // its own key material, so there is a local answer and no reason to ask.
      const agentIdHash = client.agentIdHash;
      // Endpoint-supplied counts, resolved ONCE so the text and the structured output can never
      // disagree about whether a value was usable — the text saying `(malformed)` while
      // `structuredContent` carried a number would be worse than either alone.
      const shards = countOrNull(d.activeShardCount);
      const sharing = countOrNull(d.activeSharingContracts);
      const bfsi = numOrNull(d.bfsi);
      // The three STRINGS resolve once for the same reason the three numbers do. Bounding only the
      // structured copy let the two channels disagree about one field in one response: a 16 MiB
      // `tier` rendered as 64 characters plus the truncation marker in the text — precisely "a
      // plausible-looking value the endpoint chose the front of" — while structuredContent said
      // `(malformed)`. Resolving first and fencing the RESULT means the text can only ever be a
      // display-truncation of the same value the structured channel carries.
      const tier = boundedOrMarker(d.tier);
      const custody = boundedOrMarker(d.custody);
      const snapshotEpoch = boundedOrMarker(d.snapshotEpoch);
      const seqStateDegraded = client.seqStateDegraded;
      return ok(
        // Every remaining interpolated value is endpoint-chosen, and the `\n  ` here is OURS — which
        // is exactly why a raw field carrying its own newline could mint a further line in this block.
        `SAIHM Session\n  agent=${labelSafe(shortScalar(agentIdHash))}  ` +
          `tier=${labelSafe(safeScalar(tier))}  custody=${labelSafe(safeScalar(custody))}\n  ` +
          `shards=${shards ?? MALFORMED}  sharing=${sharing ?? MALFORMED}  ` +
          `bfsi=${bfsi === null ? MALFORMED : bfsi.toFixed(3)}  ` +
          // NOT parenthesised. `R` and `M` are raw endpoint-chosen strings - unlike `tier`,
          // `custody` and `snapshotEpoch` above, they are not resolved through `boundedOrMarker` -
          // and `)` survives every fence in this module: `safeField` scrubs newlines and `[`, `]`,
          // `|`, `labelSafe` scrubs `=`, and neither touches a paren. So an endpoint that answered
          // `0.900)  Renew at evil.example  (ig` CLOSED our parenthetical and spoke the rest in the
          // server's own voice. The fix is the SITE, not a wider scrub: a value cannot escape a
          // delimiter that was never opened, and every other field on this line is already a
          // two-space-separated `key=value` pair, so the wrapper bought nothing.
          `R=${labelSafe(safeScalar(d.bfsi_R))}  M=${labelSafe(safeScalar(d.bfsi_M))}  ` +
          `epoch=${labelSafe(safeScalar(snapshotEpoch))}` +
          // Only when there IS something to say. A line reading `seq=ok` on every healthy call is
          // noise that trains the reader to skip the place the warning will appear.
          // PURE `key=value`, no parenthetical. The lesson recorded on `R`/`M` twenty lines up is
          // that `)` survives every fence in this module, so a wrapper only offers a delimiter to
          // close; a pair that was never opened cannot be closed. Same two-space separator as every
          // other field, on its own line so it reads as a report rather than a suffix on `epoch`.
          (seqStateDegraded === null
            ? ''
            : `\n  seq-state=${labelSafe(safeScalar(seqStateDegraded))}  rollback-guard=memory-only-this-run`),
        {
          agentIdHash,
          tier,
          custody,
          activeShardCount: shards,
          activeSharingContracts: sharing,
          bfsi,
          snapshotEpoch,
          seqStateDegraded,
        },
      );
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'saihm_share',
  {
    title: 'Share',
    description:
      "Share a cell with another agent, end-to-end authenticated. Pin the grantee's agentIdHash out-of-band. Use this to grant another agent access to a specific memory.",
    inputSchema: {
      cellId: z.string().describe('The cell to share'),
      recipientRecord: z
        .object({
          mldsaPubKey: z.string(),
          mlkemPubKey: z.string(),
          mlkemPubKeySelfSig: z.string(),
        })
        .describe("The grantee's published identity record (hex fields)"),
      recipientPinnedAgentIdHashHex: z
        .string()
        .describe("The grantee's agentIdHash (hex), pinned out-of-band"),
      scope: z
        .enum(['read', 'write', 'readwrite'])
        .optional()
        .describe('Access scope (default read)'),
      expiryEpoch: z
        .string()
        .regex(/^[0-9]+$/, 'expiryEpoch must be a decimal UNIX-epoch count')
        .optional()
        .describe('Optional expiry as a UNIX-epoch count (decimal string)'),
    },
    annotations: {
      title: 'Share',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  async ({
    cellId,
    recipientRecord,
    recipientPinnedAgentIdHashHex,
    scope,
    expiryEpoch,
  }) => {
    try {
      const client = getClient();
      await client.share({
        cellId,
        recipientRecord,
        recipientPinnedAgentIdHashHex,
        ...(scope ? { scope } : {}),
        ...(expiryEpoch ? { expiryEpoch: BigInt(expiryEpoch) } : {}),
      });
      // Every value on this line is known locally, so none of it is read back from the response: the
      // cell and the recipient are the agent's own arguments, and the sharer is this client. The
      // endpoint's echo named all three, which let a grant to one recipient be reported as a grant to
      // another — the one confirmation an agent has that it shared with who it meant to. `share()`
      // already throws on any failure, so reaching this line IS the endpoint's acknowledgement; there
      // is nothing its echo could add that is not either already known or not to be trusted.
      return ok(
        `SHARED cell=${labelSafe(safeScalar(cellId))} sharer=${labelSafe(shortScalar(client.agentIdHash))} ` +
          `recipient=${labelSafe(shortScalar(recipientPinnedAgentIdHashHex))}`,
      );
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'saihm_revoke_share',
  {
    title: 'Revoke share',
    description:
      "Revoke a prior share grant to a recipient for a cell. Use this to withdraw a grantee's access.",
    inputSchema: {
      cellId: z.string().describe('The shared cell id'),
      recipientHex: z
        .string()
        .describe("The grantee's agentIdHash (hex) to revoke"),
    },
    annotations: {
      title: 'Revoke share',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async ({ cellId, recipientHex }) => {
    try {
      const r = await getClient().revokeShare(cellId, recipientHex);
      return ok(
        // Cell and recipient are the agent's own arguments, for the reason given on `saihm_share`;
        // `revoked` is the endpoint's report of what it did, which only it can know, so it is the one
        // value here that has to be taken on trust — and therefore the one that has to be fenced.
        `REVOKED cell=${labelSafe(safeScalar(cellId))} recipient=${labelSafe(shortScalar(recipientHex))} ` +
          `revoked=${labelSafe(safeScalar(r.revoked))}`,
      );
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'saihm_governance_propose',
  {
    title: 'Propose (governance)',
    description:
      "Submit a gSAIHM governance proposal. Scope MUST be 'emission_param' or 'protocol_upgrade'. Use this to open a protocol governance vote.",
    inputSchema: {
      scope: z
        .enum(['emission_param', 'protocol_upgrade'])
        .describe('Governable scope'),
      paramKey: z
        .string()
        .optional()
        .describe('Parameter key (when scope=emission_param)'),
      proposedValue: z.string().optional().describe('Proposed value as string'),
    },
    annotations: {
      title: 'Propose (governance)',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  async ({ scope, paramKey, proposedValue }) => {
    try {
      await getClient().governancePropose({
        scope,
        paramKey: paramKey ?? null,
        proposedValue: proposedValue ?? null,
      });
      return ok('PROPOSED'); // governance is a clean-unavailable stub at launch; the call above throws.
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'saihm_governance_vote',
  {
    title: 'Vote (governance)',
    description:
      'Cast a vote on an open gSAIHM governance proposal. Use this to approve or reject an open proposal by its proposalId.',
    inputSchema: {
      proposalId: z.string().describe('Hex proposalId'),
      approve: z.boolean().describe('true = approve, false = reject'),
    },
    annotations: {
      title: 'Vote (governance)',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  async ({ proposalId, approve }) => {
    try {
      await getClient().governanceVote({ proposalId, approve });
      return ok('VOTED');
    } catch (e) {
      return fail(e);
    }
  },
);

// Session-bootstrap prompt (an MCP Prompt, not a tool — the 8-tool surface is unchanged).
// Hosts surface this so an agent loads its persistent memory before other work.
server.registerPrompt(
  'saihm_session_bootstrap',
  {
    title: 'Load SAIHM memory',
    description:
      'Load your SAIHM persistent memory at the start of a session, before other work.',
  },
  () => ({
    messages: [
      {
        role: 'user' as const,
        content: {
          type: 'text' as const,
          text: 'Before anything else, call the saihm_recall tool to load my SAIHM persistent memory for this session, then briefly summarise what you recalled. If you already have a topic in mind, pass it as a keyword — a focused recall is faster than loading everything.',
        },
      },
    ],
  }),
);

// ============================================================================
// saihm_join — self-join bootstrap tool (registered BY DEFAULT; SAIHM_SELF_JOIN=0 opts out).
// This line read "DARK: registered only when SAIHM_SELF_JOIN=1" and was false: selfJoinEnabled()
// is `!== '0'`. The correct statement was already 38 lines below, in the same block.
// Lets an agent activate FREE memory straight from a chat prompt with no prior website
// visit and no pre-provisioned key: it self-generates the sovereign key on this device,
// runs the Sybil-safe device flow (one human approval), and brings the memory tools
// online. The master secret is created locally and NEVER printed. This is a bootstrap
// affordance — like the saihm_session_bootstrap prompt — NOT a 9th protocol tool; the
// canonical 8 protocol tools remain the surface (STATE:#60, amended 2026-07-10).
// ============================================================================
interface JoinState {
  running: boolean;
  prompt?: FreeDevicePrompt;
  result?: FreeEntitlementResult;
  error?: unknown;
  /** The key FILE, or `null` when the secret is inline in `SAIHM_MASTER_SECRET_HEX` and no file exists. */
  keyPath: string | null;
  createdKey: boolean;
}
let joinState: JoinState | null = null;

/** Wait (bounded) until the background flow produces a prompt, a result, or an error. */
async function waitForJoinSignal(ms: number): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (!joinState || joinState.prompt || joinState.result || joinState.error) return;
    await new Promise((r) => setTimeout(r, 200));
  }
}

function joinPendingText(s: JoinState): string {
  const p = s.prompt as FreeDevicePrompt;
  const mins = expiryMins(p.expiresIn);
  // Fenced, though `keyPath` is env-derived rather than endpoint-derived. Two hostile reviews found
  // this independently and one reproduced it: a `SAIHM_HOME` containing a newline renders a forged
  // `RECALL` banner and a line in authenticated-memory shape INSIDE this result, in the tool's own
  // voice. It was twice dismissed on the reasoning that whoever sets your env owns the process. That
  // is weaker than it sounds — `SAIHM_HOME` is set in an MCP client config, which is reviewed for
  // PATHS and not for embedded newlines — and the line below already fences an endpoint value with a
  // twelve-line note on why lines must not be forgeable. At PATH_MAX the fence costs nothing.
  // `null` means the secret is INLINE in SAIHM_MASTER_SECRET_HEX and there is no file to name. It
  // used to arrive as the string `(SAIHM_MASTER_SECRET_HEX)` and render as a path, twice over.
  const keyPath = s.keyPath === null ? null : safePathField(s.keyPath, MAX_PATH_FIELD_CHARS);
  const keyNote =
    keyPath === null
      ? 'Your memory key is the SAIHM_MASTER_SECRET_HEX value you supplied — keep it safe; it is the only key to your memory and cannot be recovered.'
      : s.createdKey
        ? `A new memory key was created and saved to ${keyPath} — keep this file safe; it is the only key to your memory and cannot be recovered.`
        : // UNDELIMITED, and last on the line. This read `... memory key (${keyPath}).` and the
          // fence has no reason to scrub `)` - `Program Files (x86)` is a legal path, and scrubbing
          // the character would corrupt one to protect a sentence. So the sentence gives up the
          // delimiter instead: a value wrapped in anything can close the wrapper early, and the
          // only wrapper that cannot be closed is the one that is not there. The fence already
          // guarantees no LINE break gets out, so ending the line with the value is enough.
          `Using your existing memory key: ${keyPath}`;
  // Both values come from the onboarding bridge, which is the SAME ORIGIN as the memory endpoint —
  // one hostile operator controls both — and the client type-checks them only as non-empty strings.
  // Rendered raw they were the softest target in the server: this block exists to be RELAYED TO A
  // HUMAN as numbered instructions, so a newline inside `verificationUri` appends steps 3 and 4 in
  // the same authoritative voice, and the reader has been told to follow them. `saihm_join` is
  // registered by DEFAULT, so this is reachable before any memory tool has been called once.
  //
  // A URI is fenced, not validated to a scheme, on purpose: the operator legitimately chooses its own
  // verification host, so there is no allowlist to check against, and a mangled-but-visible URI is a
  // failure the user can see and report. What the fence removes is the ability to add LINES.
  return [
    'To activate your free SAIHM memory, in a browser:',
    `  1. open   ${safeField(p.verificationUri, MAX_JOIN_FIELD_CHARS)}`,
    `  2. enter  ${safeScalar(p.userCode)}`,
    `The code expires in about ${mins} min. Approve it, then ask me to "Join SAIHM" again and I will finish.`,
    keyNote,
  ].join('\n');
}

function joinSuccessText(s: JoinState): string {
  return [
    "You're in — your free SAIHM memory is active.",
    // `hexOrMarker`, because this is the ENDPOINT'S copy of the hash: `s.result` is an unvalidated
    // cast of the join response. `saihm_status` refuses this same field on purpose - "the agent's
    // own identity is the last value that should come from a party it does not trust" - and reads
    // the local one, while this line rendered the endpoint's raw, on a line beginning `identity: `.
    // A hash with a newline in it forges whatever lines it likes in a success message. The checker
    // answers the marker for anything that is not 64 lowercase hex, so there is nothing to forge
    // WITH, and it is the same fence `sharer=` already uses for the same kind of value.
    `  identity: ${hexOrMarker((s.result as FreeEntitlementResult).agentIdHash)}`,
    s.keyPath === null
      ? '  key: the SAIHM_MASTER_SECRET_HEX value you supplied (the only key to your memory; keep it safe — it cannot be recovered)'
      : `  key file: ${safePathField(s.keyPath, MAX_PATH_FIELD_CHARS)} (the only key to your memory; keep it safe — it cannot be recovered)`,
    'Your SAIHM memory tools are ready to use now.',
  ].join('\n');
}

if (selfJoinEnabled()) {
  server.registerTool(
    'saihm_join',
    {
      title: 'Join SAIHM (activate free memory)',
      description:
        'Activate free SAIHM persistent memory for this agent. Call this when the user asks to join, sign up for, or set up SAIHM. It self-generates a sovereign memory key on this device and starts a one-time human approval — the tool returns a URL and short code for the user to open and enter. After the user approves, call saihm_join again to finish; the memory tools then work. No payment and no website visit.',
      inputSchema: {},
      annotations: {
        title: 'Join SAIHM (activate free memory)',
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async () => {
      try {
        // Resume an in-flight or finished flow (the human approves between two calls).
        if (joinState) {
          if (joinState.result) return ok(joinSuccessText(joinState));
          if (joinState.error) {
            const e = joinState.error;
            joinState = null; // allow a clean retry
            return fail(e);
          }
          if (joinState.prompt) return ok(joinPendingText(joinState));
          await waitForJoinSignal(15_000); // running but no prompt yet
          if (joinState?.result) return ok(joinSuccessText(joinState));
          if (joinState?.error) {
            const e = joinState.error;
            joinState = null;
            return fail(e);
          }
          if (joinState?.prompt) return ok(joinPendingText(joinState));
          return ok('Still getting your activation ready — ask me to "Join SAIHM" again in a few seconds.');
        }

        // Fresh flow: ensure an identity, boot a FREE client, run the device flow in the background.
        const { created, keyPath } = ensureSelfJoinIdentityEnv();
        const jc = SaihmProClient.bootFromEnv(); // tier FREE (defaulted by ensureSelfJoinIdentityEnv)
        // Capture THIS flow's state object; every background callback guards on `joinState === s` so a
        // late callback from a superseded flow can never mutate a newer one (defence in depth — by
        // construction only one background runs at a time, but this survives future refactors).
        const s: JoinState = { running: true, keyPath, createdKey: created };
        joinState = s;
        void jc
          .acquireFreeEntitlement({
            onPrompt: (p) => {
              if (joinState === s) s.prompt = p;
            },
          })
          .then((res) => {
            if (joinState === s) {
              s.result = res;
              s.running = false;
              client = jc; // memory tools use the joined client for the rest of this session
            }
          })
          .catch((err) => {
            if (joinState === s) {
              s.error = err;
              s.running = false;
            }
          });

        await waitForJoinSignal(15_000);
        // Read THIS flow's state object, not the module global. Every background WRITE above is
        // guarded by `joinState === s`; these reads had no matching guard. A third interleaved call
        // can install a newer flow here — the already-running branch clears `joinState` on error,
        // which reopens the fresh path — and this call then reported the NEWER flow's state while
        // its OWN failure went unreported and rendered as pending. Guarding one side of a generation
        // check and not the other is the one-arm shape this package keeps reproducing.
        if (s.error) {
          const e = s.error;
          if (joinState === s) joinState = null; // clearing unconditionally would kill a NEWER join
          return fail(e);
        }
        if (s.result) return ok(joinSuccessText(s)); // instant already_granted
        if (s.prompt) return ok(joinPendingText(s));
        return ok('Starting your free activation — ask me to "Join SAIHM" again in a few seconds to get your approval code.');
      } catch (e) {
        joinState = null;
        return fail(e);
      }
    },
  );
}

/**
 * Self-serve operator join: derive this identity from the env master secret, ask the operator endpoint
 * for a Stripe hosted-checkout link to subscribe it, and print the link to pay. After payment, run the
 * server normally (no `join`) and it self-onboards. Writes only to stderr/stdout — not the MCP stream.
 */
/**
 * Write a hosted-checkout URL to a file beside the printed copy; return where it went, or '' if it
 * could not be written.
 *
 * A hosted-checkout URL is long and carries a MANDATORY `#fid…` fragment that Stripe Checkout
 * reads in the browser. Chat surfaces, markdown autolinkers and mail clients cut at the `#`, and a
 * cut link is refused with "This link is incomplete" — which, to the payer, is indistinguishable
 * from a broken backend. That misreading is not hypothetical: on 2026-08-27 a truncated relay of
 * this exact URL was reported as a backend defect concatenating a stored fragment, and the proposed
 * remedy — strip the fragment before returning it — would have broken every hosted checkout. A file
 * is the one delivery channel that cannot reflow the URL.
 *
 * Best-effort by design: the printed URL remains the fallback, so a read-only or absent home
 * directory degrades the affordance instead of failing the join.
 */
function persistCheckoutUrl(fenced: string): string {
  try {
    // `SAIHM_HOME` is honoured as a FALLBACK, and it is the only directory knob `server.json`
    // declares - `SAIHM_STATE_DIR` is undeclared, so a registry-installed operator who relocated
    // `SAIHM_HOME` (the containerised or read-only-$HOME install this function is written for) had
    // this file written under `~/.saihm` with nothing declared to redirect it and nothing saying so.
    // `SAIHM_STATE_DIR` still wins where both are set.
    //
    // These are NOT two names for one directory, and an earlier revision of this comment said they
    // were. `defaultIdentityPath` reads `SAIHM_HOME` ALONE and deliberately does not consult
    // `SAIHM_STATE_DIR`: honouring it there would relocate an EXISTING identity file, and a join
    // that cannot find its identity mints a new one, which starts an EMPTY memory. So an operator
    // who sets only `SAIHM_STATE_DIR` keeps their identity under `~/.saihm` while this file moves.
    // That asymmetry is two variables with two jobs, not a split left half-closed.
    const dir =
      process.env.SAIHM_STATE_DIR || process.env.SAIHM_HOME || pathJoin(homedir(), '.saihm');
    // BOTH `mode` options here apply ONLY ON CREATION — an existing directory or file keeps whatever
    // permissions it already had, and neither call reports that it did nothing. Where `~/.saihm`
    // already exists - which is the common case, since the rest of the SAIHM toolchain creates it -
    // the 0o700 below is inert. The mode is still correct to request (it hardens
    // a directory we DO create) and is deliberately not followed by a `chmodSync`: this directory is
    // shared with the rest of the SAIHM toolchain, and silently re-permissioning it would reach well
    // outside this function.
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const to = pathJoin(dir, 'checkout-url.txt');
    // Write-then-rename with O_EXCL, matching every other persister in this codebase — this was the
    // one that wrote DIRECTLY to a fixed, fully predictable path in a group-writable directory.
    // `writeFileSync` follows symlinks, so a same-group local user could plant `checkout-url.txt` as
    // a link to any file this process can write — `master_secret.hex` beside it being the obvious
    // target, which would destroy the identity and with it every cell. Two properties close that, and
    // both are needed: `wx` (O_EXCL) makes the tmp write REFUSE any path that already exists,
    // including a symlink, and `renameSync` replaces the destination entry itself rather than
    // following a link at it. The tmp name carries pid + ms so concurrent CLI runs cannot collide.
    const tmp = `${to}.tmp.${process.pid}.${Date.now()}`;
    writeFileSync(tmp, fenced + '\n', { mode: 0o600, flag: 'wx' });
    try {
      renameSync(tmp, to); // atomic; inherits the tmp file's 0600 mode even if `to` pre-existed at 0644
    } catch (e) {
      // Nothing sweeps stale tmp files, so a failed rename would leave one beside the real path
      // forever. `wx` above proves THIS process created it, so the exact name is safe to unlink —
      // never a glob, which would be reaching for another process's in-flight write.
      try {
        unlinkSync(tmp);
      } catch {
        /* never created, or already gone */
      }
      throw e;
    }
    return to;
  } catch {
    return '';
  }
}

/**
 * The printed URL, delimited so that truncation in transit is VISIBLE rather than silent.
 *
 * `savedTo` is fenced for the same reason the URL is: this block is addressed to a human and is a
 * rendering surface, so anything interpolated into it must be unable to start a line. The path is
 * derived from `SAIHM_STATE_DIR`, else `SAIHM_HOME`, else `~/.saihm` - all caller-chosen rather
 * than endpoint-chosen — a weaker
 * threat, but the fence costs nothing and the distinction is not worth encoding in a place where
 * getting it wrong forges an instruction in the tool's own voice.
 *
 * The BUDGET is {@link MAX_PATH_FIELD_CHARS} and not the join-field one this line used to carry.
 * The whole point of the line is to name a file the caller can open; a path cut at a budget sized
 * for a device-flow URI names one that does not exist, which fails the line at its only job.
 */
function checkoutUrlBlock(fenced: string, savedTo: string): string[] {
  return [
    '  --- BEGIN CHECKOUT URL (one line, open unmodified) ---',
    '  ' + fenced,
    '  --- END CHECKOUT URL ---',
    '',
    ...(savedTo ? ['  Also written to: ' + safePathField(savedTo, MAX_PATH_FIELD_CHARS), ''] : []),
  ];
}

async function runJoin(): Promise<void> {
  const c = SaihmProClient.bootFromEnv();
  const url = await c.requestCheckoutUrl();
  const fenced = safeField(url, MAX_URL_FIELD_CHARS);
  // Resolved ONCE. It was called twice below - as the condition, then again inside the branch with
  // an `as string` cast re-asserting what the condition had just proved. Two reads of process env
  // either side of a branch can disagree with each other, and the cast is what hid that they could.
  const keyFile = identityKeyFile();
  process.stdout.write(
    [
      '',
      'SAIHM — subscribe this identity to activate your memory:',
      '',
      ...checkoutUrlBlock(fenced, persistCheckoutUrl(fenced)),
      `  identity (agentIdHash): ${c.agentIdHash}`,
      '',
      '  Open the link above in a browser and pay. Copy it whole — everything after the "#" is part',
      '  of the link, and a copy that loses it is refused as incomplete.',
      '',
      // The SAME resolution `free-join` uses, from `identityKeyFile()`. This line was
      // unconditionally "Keep SAIHM_MASTER_SECRET_HEX safe", which is the exact defect `free-join`
      // fixed 60 lines below and which nobody propagated here: a caller who reached `join` after
      // `saihm_join` has a generated key FILE and no such variable, and this told them to protect
      // the wrong thing while never naming the file they must actually back up.
      keyFile
        ? `  Back up ${safePathField(keyFile, MAX_PATH_FIELD_CHARS)} — it is`
        : '  Keep SAIHM_MASTER_SECRET_HEX safe — it is',
      '  the only key to your memory and cannot be recovered. After payment, start the server',
      '  normally (drop the "join" argument) and it connects automatically.',
      '',
    ].join('\n'),
  );
}

/**
 * Self-serve FREE activation: derive this identity from the env master secret and onboard it to the
 * FREE tier via the operator bridge's OAuth device flow (RFC 8628). Prints the one-tap prompt (open a
 * URL, enter a code) and waits for authorization; the provider token stays server-ephemeral and this
 * process never holds it. After it succeeds, run the server normally (no `free-join`) and it
 * self-onboards FREE. Writes only to stdout/stderr — not the MCP stream.
 *
 * Takes no configuration: it ensures an identity the same way the `saihm_join` tool does, so
 * `npx -y @saihm/mcp-server-pro free-join` is a complete join on a bare machine — the endpoint
 * falls back to DEFAULT_ENDPOINT and the tier is defaulted FREE. An env secret already set is
 * left untouched, so bring-your-own-key still works. Under SAIHM_SELF_JOIN=0 nothing is
 * generated and bootFromEnv raises its own guided error, which is the point of that switch.
 */
async function runFreeJoin(): Promise<void> {
  // Called for its SIDE EFFECT - it mints the key file and points SAIHM_MASTER_SECRET_FILE at it
  // - and no longer for its return value. What to TELL the operator is resolved once, by
  // `identityKeyFile()`, so this verb and `join` cannot drift apart again.
  if (selfJoinEnabled()) ensureSelfJoinIdentityEnv();
  const c = SaihmProClient.bootFromEnv();
  const r = await c.acquireFreeEntitlement({
    onPrompt: (p) =>
      process.stdout.write(
        [
          '',
          'SAIHM — activate your FREE memory. In a browser:',
          '',
          // Fenced for the same reason as the MCP copy in `joinPendingText`, even though this one
          // goes to a terminal rather than to an agent: the bridge chooses both strings, and a bare
          // CR here lets it overwrite the code it just printed with a different one while the human
          // watches. A terminal is a rendering surface too.
          `  1. open   ${safeField(p.verificationUri, MAX_JOIN_FIELD_CHARS)}`,
          `  2. enter  ${safeScalar(p.userCode)}`,
          '',
          `  (code expires in ~${expiryMins(p.expiresIn)} min) — waiting for authorization…`,
          '',
        ].join('\n'),
      ),
  });
  // Resolved ONCE, as in `join` above.
  const keyFile = identityKeyFile();
  process.stdout.write(
    [
      '',
      'FREE memory activated for this identity:',
      '',
      // `hexOrMarker` for the same reason as `joinSuccessText`: `r` is the endpoint's response to
      // `acquireFreeEntitlement`, so this is the ENDPOINT'S copy of the hash, not ours. Fixing the
      // tool path and leaving the CLI verb was the one-arm pattern once more.
      `  identity (agentIdHash): ${hexOrMarker(r.agentIdHash)}`,
      '',
      // Name the key the caller ACTUALLY has. This line was unconditionally
      // "Keep SAIHM_MASTER_SECRET_HEX safe", which for a self-generated identity points at an env
      // var that does not exist — sending the one caller who most needs to take a backup to look
      // for the wrong thing. safeField: keyPath is env-derived on the bring-your-own-key path,
      // at MAX_PATH_FIELD_CHARS — this names the ONLY key to the caller's memory, so a path
      // truncated to a URI's budget is worse than no line at all: it reads as a backup taken.
      // Not `identity?.keyPath` alone: under SAIHM_SELF_JOIN=0 nothing is ensured, yet a caller
      // who supplied SAIHM_MASTER_SECRET_FILE still has a FILE to back up. Reading env directly
      // covers that case too, so the only caller told to keep the HEX var is one who set it.
      keyFile
        ? `  Back up ${safePathField(keyFile, MAX_PATH_FIELD_CHARS)} — it is the only key to your`
        : '  Keep SAIHM_MASTER_SECRET_HEX safe — it is the only key to your',
      '  memory and cannot be recovered. Start the server normally (drop the "free-join" argument)',
      '  and it connects automatically. Upgrading to a paid plan later attaches to THIS same key —',
      '  your memories persist.',
      '',
    ].join('\n'),
  );
}

/**
 * Self-serve FREE -> paid upgrade: derive this identity from the env master secret and request a Stripe
 * hosted-checkout link to subscribe it to a monthly paid tier (default PRO; override via arg or
 * SAIHM_UPGRADE_TIER). Billing attaches to THIS same key, so every existing memory persists. Requires
 * SAIHM_TIER=FREE. After payment, reconfigure SAIHM_TIER/SAIHM_PAYMENT_METHOD and start the server
 * normally. Writes only to stdout/stderr — not the MCP stream.
 */
async function runUpgrade(): Promise<void> {
  const c = SaihmProClient.bootFromEnv();
  // `|| 'PRO'` AFTER the trim, not `??` alone. `??` falls through only on null/undefined, so
  // `upgrade ""` — and an exported-but-empty SAIHM_UPGRADE_TIER — reached `requestUpgradeUrl('')`.
  //
  // Stated precisely, because the obvious reading of this is wrong: that call does NOT render an
  // empty tier into the line below. `requestUpgradeUrl` THROWS on `''` and is awaited BEFORE
  // anything is written (measured: `upgrade BOGUS` exits 1 having written zero `upgrade this
  // identity to` lines to stdout), so the interpolation is unreachable FROM HERE with an empty
  // target. Two narrower statements, because the wider ones are false. WHICH code is thrown is
  // conditional: the `tier !== 'FREE'` gate fires `not_free_tier` FIRST, so `bad_upgrade_tier`
  // is reached only on a FREE-tier client — naming it unconditionally was wrong. And the empty
  // tier IS interpolated, into `bad_upgrade_tier`'s own message ("...; got ''"), which `failText`
  // renders to stderr; that is unreachable from `runUpgrade` because of the `|| 'PRO'` below, but
  // reachable through the exported client API. The guarantee is about THIS call site, not the
  // function. What the `??` actually cost was the DEFAULT:
  // an empty argument turned a documented fallback to PRO into a hard error naming a tier the user
  // never typed. `client.ts` gets this exact shape right for the provider argument; this site did
  // not. An empty string is absence here, not a choice — which is what `||` says and `??` does not.
  const target =
    (process.argv[3] ?? process.env.SAIHM_UPGRADE_TIER ?? 'PRO').trim() || 'PRO';
  const url = await c.requestUpgradeUrl(target);
  const fenced = safeField(url, MAX_URL_FIELD_CHARS);
  // The tier is the operator's own `argv`/env, so this is not a trust boundary - but it is still a
  // value from outside the program rendered into a line the agent reads, and every other such value
  // on this branch is fenced. A tier carrying a newline should not be able to add a line here.
  const fencedTier = safeField(target, MAX_JOIN_FIELD_CHARS);
  process.stdout.write(
    [
      '',
      `SAIHM — upgrade this identity to ${fencedTier} (monthly). Your memories stay on this same key:`,
      '',
      ...checkoutUrlBlock(fenced, persistCheckoutUrl(fenced)),
      `  identity (agentIdHash): ${c.agentIdHash}`,
      '',
      '  Open the link above in a browser and pay. Copy it whole — everything after the "#" is part',
      '  of the link, and a copy that loses it is refused as incomplete. After payment, set SAIHM_TIER and',
      '  SAIHM_PAYMENT_METHOD for the paid tier and start the server normally (drop the',
      '  "upgrade" argument) — it self-onboards paid and every prior memory is still there.',
      '',
    ].join('\n'),
  );
}

// argv[2] absent means "run as an MCP server" — the package's primary job, and the default that must
// not change. An argv[2] that is PRESENT but unrecognized is a different situation: someone mistyped
// a verb, or reached for `--help`. Matching only the known verbs and letting everything else fall
// through folded those two cases together, so a typo started a stdio server that waited on stdin
// forever and printed nothing. The README sends people to a terminal, which made that silence the
// first thing a mistaken user saw. Discriminate on PRESENCE first, then on match.
// Spelled as `npx -y @saihm/mcp-server-pro`, not as the bare bin name: no documented install path
// puts that name on anyone's PATH, and every invocation in the README is the npx form. Printing the
// bare name would answer a mistyped command with a command that is not found either.
const CLI_USAGE: string = [
  `@saihm/mcp-server-pro ${PACKAGE_VERSION}`,
  '',
  'Usage:',
  '  npx -y @saihm/mcp-server-pro                 run as an MCP server over stdio (default)',
  '  npx -y @saihm/mcp-server-pro free-join       join the free tier — nothing to configure',
  '  npx -y @saihm/mcp-server-pro join            join a paid tier directly',
  '  npx -y @saihm/mcp-server-pro upgrade [TIER]  move a free identity to a monthly paid tier',
  '',
  'Environment:',
  '  free-join  nothing — it generates and stores your key for you',
  '  join       SAIHM_MASTER_SECRET_HEX or SAIHM_MASTER_SECRET_FILE, plus SAIHM_TIER',
  '             and SAIHM_PAYMENT_METHOD',
  '  upgrade    your key, and SAIHM_TIER=FREE. TIER defaults to PRO and can also be',
  '             given as SAIHM_UPGRADE_TIER',
  '',
  'Options:',
  '  -h, --help     show this message',
  '  -v, --version  print the version',
  '',
].join('\n');

async function main(): Promise<void> {
  const verb = process.argv[2];

  if (verb === undefined || verb === '') {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    return;
  }
  if (verb === 'join') {
    await runJoin();
    return;
  }
  if (verb === 'free-join') {
    await runFreeJoin();
    return;
  }
  if (verb === 'upgrade') {
    await runUpgrade();
    return;
  }
  if (verb === '-h' || verb === '--help' || verb === 'help') {
    process.stdout.write(CLI_USAGE);
    return;
  }
  if (verb === '-v' || verb === '--version') {
    process.stdout.write(`${PACKAGE_VERSION}\n`);
    return;
  }
  // The rejected argument gets a line of its own, undelimited, the way every other caller-supplied
  // value in this file is printed. Wrapping it in quotes instead hands it an escape: the fence
  // collapses control characters and the label metacharacters, but not the delimiter, so an argument
  // carrying a quote closes the field early and continues in prose that reads as ours.
  //
  // safeScalar, not safeField: a verb is a short token, and the wider budget is documented as a
  // verification-URI size. Under it a rejected argument echoes back far more attacker-chosen text
  // than any real verb is long.
  //
  // exitCode rather than exit(): stderr is a pipe as often as a terminal, and exit() can drop a
  // write that has not drained. Returning lets the process end on its own once this one has.
  process.stderr.write(
    ['saihm: unrecognized argument', `  ${safeScalar(verb)}`, '', CLI_USAGE].join('\n'),
  );
  process.exitCode = 2;
  return;
}

main().catch((e) => {
  // failText, not String(e.message): this message embeds `res.statusText` and the endpoint's own
  // `error` field, so raw it carried real newlines, intact `[`/`]`/`|` and live ANSI escapes to the
  // operator's terminal — the one endpoint-derived path in this file that bypassed the fence every
  // other error path uses.
  process.stderr.write(failText(e) + '\n');
  process.exit(1);
});
