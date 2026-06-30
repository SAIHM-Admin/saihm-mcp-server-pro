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
 *
 * Boot from env (self-onboard): SAIHM_ENDPOINT_URL, SAIHM_MASTER_SECRET_HEX,
 *   SAIHM_TIER, SAIHM_PAYMENT_METHOD. Advanced/legacy: SAIHM_AUTH_HEADER (static).
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join as pathJoin } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { SaihmProClient, SaihmEndpointError } from './client.js';

const PACKAGE_VERSION: string = (
  JSON.parse(
    readFileSync(
      pathJoin(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'),
      'utf-8',
    ),
  ) as { version: string }
).version;

const server = new McpServer(
  { name: 'saihm', version: PACKAGE_VERSION },
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
  const text =
    e instanceof SaihmEndpointError
      ? `SAIHM error [${e.code}] (status ${e.status}): ${e.message}`
      : e instanceof Error
        ? e.message
        : String(e);
  return { content: [{ type: 'text' as const, text }], isError: true as const };
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
      'Retrieve and decrypt your memories (opened client-side). Optional keyword filter. Use this at the start of a session or whenever past context is needed.',
    inputSchema: { query: z.string().optional().describe('Filter by keyword (empty = all)') },
    outputSchema: {
      count: z.number(),
      memories: z.array(
        z.object({ cellId: z.string(), seq: z.string(), plaintext: z.string() }),
      ),
    },
    annotations: {
      title: 'Recall',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async ({ query }) => {
    try {
      const cells = await getClient().recall(query);
      const memories = cells.map((c) => ({
        cellId: c.cellId,
        seq: String(c.seq),
        plaintext: c.plaintext,
      }));
      if (cells.length === 0) return ok('No memories stored.', { count: 0, memories });
      const lines = [`RECALL ${cells.length} memories`];
      for (const c of cells)
        lines.push(`  [${c.cellId}] seq=${c.seq} | ${c.plaintext}`);
      return ok(lines.join('\n'), { count: cells.length, memories });
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
        `FORGOTTEN [${r.cellId}] complete=${r.complete} sharesPurged=${r.sharesPurged} epoch=${r.epoch}`,
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
        `SAIHM Session\n  agent=${d.agentIdHashHex.slice(0, 16)}…  tier=${d.tier}  custody=${d.custody}\n  shards=${d.activeShardCount}  sharing=${d.activeSharingContracts}  bfsi=${d.bfsi.toFixed(3)} (R=${d.bfsi_R} M=${d.bfsi_M})  epoch=${d.snapshotEpoch}`,
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
        `SHARED cell=${r.cellId} sharer=${r.sharer.slice(0, 16)}… recipient=${r.recipient.slice(0, 16)}…`,
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
        `REVOKED cell=${r.cellId} recipient=${r.recipient.slice(0, 16)}… revoked=${r.revoked}`,
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
          text: 'Before anything else, call the saihm_recall tool (no query, or a keyword if you have one) to load my SAIHM persistent memory for this session, then briefly summarise what you recalled.',
        },
      },
    ],
  }),
);

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

async function main(): Promise<void> {
  if (process.argv[2] === 'join') {
    await runJoin();
    return;
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((e) => {
  process.stderr.write(String(e instanceof Error ? e.message : e) + '\n');
  process.exit(1);
});
