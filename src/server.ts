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
 * Self-serve join (one-off, prints a Stripe checkout link to subscribe this identity):
 *   npx -y @saihm/mcp-server-pro join
 * Self-serve FREE activation (one-off, OAuth device flow — requires SAIHM_TIER=FREE):
 *   npx -y @saihm/mcp-server-pro free-join
 * Upgrade FREE -> monthly paid, same key/memories (one-off — requires SAIHM_TIER=FREE):
 *   npx -y @saihm/mcp-server-pro upgrade [PRO|PRO_FAST|ENTERPRISE|ENTERPRISE_FAST]
 *
 * Boot from env (self-onboard): SAIHM_ENDPOINT_URL, SAIHM_MASTER_SECRET_HEX,
 *   SAIHM_TIER, SAIHM_PAYMENT_METHOD. Advanced/legacy: SAIHM_AUTH_HEADER (static).
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join as pathJoin } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  MALFORMED,
  safeField,
  safeScalar,
  hexOrMarker,
  scopeOrMarker,
  epochOrMarker,
  failText,
} from './render_fence.js';

import { z } from 'zod';
import {
  SaihmProClient,
  SaihmEndpointError,
  selfJoinEnabled,
  ensureSelfJoinIdentityEnv,
  MAX_ANNOUNCEMENT_FIELD_CHARS,
  MAX_ERROR_CODE_CHARS,
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
      return ok(
        `REMEMBERED [${r.cellId}] seq=${r.seq} shard=${r.shardId} commit=${r.commitmentHash.slice(0, 16)}…`,
        {
          cellId: r.cellId,
          seq: String(r.seq),
          shardId: String(r.shardId),
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
        return ok(`SHARED-RECALL [${cell.cellId}] seq=${cell.seq} | ${cell.plaintext}`, {
          count: 1,
          memories: [mem],
          shared: [],
          sharedTruncated: false,
        });
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
      // tops out at 3,547 bytes. (An earlier cut of this comment claimed the cellId figure WAS the
      // per-recall total and called it "near 1 KB" — it was counting one of the three fields.) That
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
                  `  ! POINTER cell=${safeField(a.cellId, MAX_ANNOUNCEMENT_FIELD_CHARS)} sharer=${hexOrMarker(a.sharer)} ` +
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
              ...cells.map((c) => `  [${c.cellId}] seq=${c.seq} | ${c.plaintext}`),
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
        `FORGOTTEN [${safeScalar(r.cellId)}] complete=${safeScalar(r.complete)} ` +
          `sharesPurged=${safeScalar(r.sharesPurged)} epoch=${safeScalar(r.epoch)}`,
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
      activeShardCount: z.number(),
      activeSharingContracts: z.number(),
      bfsi: z.number(),
      snapshotEpoch: z.string(),
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
      const d = await getClient().status();
      return ok(
        // Every interpolated value is endpoint-chosen (`status()` is an unvalidated cast), and the
        // `\n  ` here is OURS — which is exactly why a raw field carrying its own newline could mint
        // a further line in this block. `bfsi` is checked rather than fenced because `.toFixed` on a
        // non-number throws, and failing closed beats rendering a marker for a number.
        `SAIHM Session\n  agent=${safeScalar(d.agentIdHashHex).slice(0, 16)}…  ` +
          `tier=${safeScalar(d.tier)}  custody=${safeScalar(d.custody)}\n  ` +
          `shards=${safeScalar(d.activeShardCount)}  sharing=${safeScalar(d.activeSharingContracts)}  ` +
          `bfsi=${typeof d.bfsi === 'number' ? d.bfsi.toFixed(3) : MALFORMED} ` +
          `(R=${safeScalar(d.bfsi_R)} M=${safeScalar(d.bfsi_M)})  epoch=${safeScalar(d.snapshotEpoch)}`,
        {
          agentIdHash: d.agentIdHashHex,
          tier: String(d.tier),
          custody: String(d.custody),
          activeShardCount: Number(d.activeShardCount),
          activeSharingContracts: Number(d.activeSharingContracts),
          bfsi: d.bfsi,
          snapshotEpoch: String(d.snapshotEpoch),
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
      const r = await getClient().share({
        cellId,
        recipientRecord,
        recipientPinnedAgentIdHashHex,
        ...(scope ? { scope } : {}),
        ...(expiryEpoch ? { expiryEpoch: BigInt(expiryEpoch) } : {}),
      });
      return ok(
        `SHARED cell=${safeScalar(r.cellId)} sharer=${safeScalar(r.sharer).slice(0, 16)}… ` +
          `recipient=${safeScalar(r.recipient).slice(0, 16)}…`,
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
        `REVOKED cell=${safeScalar(r.cellId)} recipient=${safeScalar(r.recipient).slice(0, 16)}… ` +
          `revoked=${safeScalar(r.revoked)}`,
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
// saihm_join — self-join bootstrap tool (DARK: registered only when SAIHM_SELF_JOIN=1).
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
  keyPath: string;
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
  const mins = Math.max(1, Math.round(p.expiresIn / 60));
  const keyNote = s.createdKey
    ? `A new memory key was created and saved to ${s.keyPath} — keep this file safe; it is the only key to your memory and cannot be recovered.`
    : `Using your existing memory key (${s.keyPath}).`;
  return [
    'To activate your free SAIHM memory, in a browser:',
    `  1. open   ${p.verificationUri}`,
    `  2. enter  ${p.userCode}`,
    `The code expires in about ${mins} min. Approve it, then ask me to "Join SAIHM" again and I will finish.`,
    keyNote,
  ].join('\n');
}

function joinSuccessText(s: JoinState): string {
  return [
    "You're in — your free SAIHM memory is active.",
    `  identity: ${(s.result as FreeEntitlementResult).agentIdHash}`,
    `  key file: ${s.keyPath} (the only key to your memory; keep it safe — it cannot be recovered)`,
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
        if (joinState?.error) {
          const e = joinState.error;
          joinState = null;
          return fail(e);
        }
        if (joinState?.result) return ok(joinSuccessText(joinState)); // instant already_granted
        if (joinState?.prompt) return ok(joinPendingText(joinState));
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
async function runJoin(): Promise<void> {
  const c = SaihmProClient.bootFromEnv();
  const url = await c.requestCheckoutUrl();
  process.stdout.write(
    [
      '',
      'SAIHM — subscribe this identity to activate your memory:',
      '',
      '  ' + url,
      '',
      `  identity (agentIdHash): ${c.agentIdHash}`,
      '',
      '  Open the link above in a browser and pay. Keep SAIHM_MASTER_SECRET_HEX safe — it is',
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
 * self-onboards FREE. Requires SAIHM_TIER=FREE. Writes only to stdout/stderr — not the MCP stream.
 */
async function runFreeJoin(): Promise<void> {
  const c = SaihmProClient.bootFromEnv();
  const r = await c.acquireFreeEntitlement({
    onPrompt: (p) =>
      process.stdout.write(
        [
          '',
          'SAIHM — activate your FREE memory. In a browser:',
          '',
          `  1. open   ${p.verificationUri}`,
          `  2. enter  ${p.userCode}`,
          '',
          `  (code expires in ~${Math.max(1, Math.round(p.expiresIn / 60))} min) — waiting for authorization…`,
          '',
        ].join('\n'),
      ),
  });
  process.stdout.write(
    [
      '',
      'FREE memory activated for this identity:',
      '',
      `  identity (agentIdHash): ${r.agentIdHash}`,
      '',
      '  Keep SAIHM_MASTER_SECRET_HEX safe — it is the only key to your memory and cannot be',
      '  recovered. Start the server normally (drop the "free-join" argument) and it connects',
      '  automatically. Upgrading to a paid plan later attaches to THIS same key — your memories persist.',
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
  const target = (process.argv[3] ?? process.env.SAIHM_UPGRADE_TIER ?? 'PRO').trim();
  const url = await c.requestUpgradeUrl(target);
  process.stdout.write(
    [
      '',
      `SAIHM — upgrade this identity to ${target} (monthly). Your memories stay on this same key:`,
      '',
      '  ' + url,
      '',
      `  identity (agentIdHash): ${c.agentIdHash}`,
      '',
      '  Open the link above in a browser and pay. After payment, set SAIHM_TIER and',
      '  SAIHM_PAYMENT_METHOD for the paid tier and start the server normally (drop the',
      '  "upgrade" argument) — it self-onboards paid and every prior memory is still there.',
      '',
    ].join('\n'),
  );
}

async function main(): Promise<void> {
  if (process.argv[2] === 'join') {
    await runJoin();
    return;
  }
  if (process.argv[2] === 'free-join') {
    await runFreeJoin();
    return;
  }
  if (process.argv[2] === 'upgrade') {
    await runUpgrade();
    return;
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((e) => {
  process.stderr.write(String(e instanceof Error ? e.message : e) + '\n');
  process.exit(1);
});
