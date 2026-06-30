# @saihm/mcp-server-pro

[![npm version](https://img.shields.io/npm/v/@saihm/mcp-server-pro.svg)](https://www.npmjs.com/package/@saihm/mcp-server-pro)
[![license](https://img.shields.io/npm/l/@saihm/mcp-server-pro.svg)](./LICENSE)

Production thin-client for **SAIHM non-custodial memory**.

`SaihmProClient` seals every cell **on the client** with [`@saihm/client-pro`](https://www.npmjs.com/package/@saihm/client-pro), then POSTs the resulting ciphertext to the blind SAIHM `/mcp` endpoint. The endpoint stores, anchors, shares, and meters over ciphertext — it never holds your keys and cannot read your memory. Your master secret, key-encryption key, and plaintext never leave this process.

- **Seal before send** — `remember` encrypts client-side; `recall` decrypts client-side.
- **Post-quantum** — ML-DSA-65 identity/signing, ML-KEM-768 authenticated sharing (via `@saihm/client-pro`).
- **Same transport as the standards client** — `POST {method, params}` + `Authorization: Bearer <JWT>`; the endpoint binds your tenant from the JWT. HTTPS-only (loopback `http` permitted for local dev).
- **Crypto-shred erasure** — `forget` destroys the endpoint-side wrapped DEK, rendering the cell undecryptable (GDPR Art. 17).

> **Key loss is unrecoverable by design.** If you lose your master secret you lose your KEK, and no one — including SAIHM — can open your cells. Back it up securely.

## See it run

- **Live cross-model demos** — offline, ~1 min each, no account: <https://citw2.github.io/saihm-demos/>. Ground a memory you own in Claude, GPT, DeepSeek, Qwen, Kimi, or GLM, then prove you can erase it. `demo-claude-code` runs a stdio MCP server exactly like this one for Claude Code and Cursor.
- **Token benchmark** — recalling a bounded set of memory cells instead of re-sending the transcript cut input tokens by **62.8%–85.9%** (up to ~86%) across a realistic multi-session task; open, offline, reproducible: <https://github.com/citw2/saihm-token-benchmark>.

## Tool reference

| Tool | Title | Behavior |
|---|---|---|
| `saihm_remember` | Remember | seals + writes a memory cell (client-side) |
| `saihm_recall` | Recall | read-only; opens cells client-side |
| `saihm_forget` | Forget (GDPR erasure) | **destructive** — irreversible erasure |
| `saihm_status` | Status | read-only |
| `saihm_share` | Share | end-to-end-authenticated grant |
| `saihm_revoke_share` | Revoke share | withdraws a grant |
| `saihm_governance_propose` | Propose (governance) | opens a proposal |
| `saihm_governance_vote` | Vote (governance) | casts a vote |

Each tool carries MCP annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) and a human-readable `title`, so MCP hosts can gate confirmations and agents can select the right tool at reasoning time.

## Install

```sh
npm install @saihm/mcp-server-pro
```

## Run as an MCP server

The package ships a stdio MCP server. Point your MCP host (Claude Desktop,
Claude Code, …) at it — paste this **once**:

```jsonc
{
  "mcpServers": {
    "saihm": {
      "command": "npx",
      "args": ["-y", "@saihm/mcp-server-pro"],
      "env": {
        "SAIHM_ENDPOINT_URL": "https://saihm.coti.global/mcp",
        "SAIHM_MASTER_SECRET_HEX": "<your 64+ hex master secret>",
        "SAIHM_TIER": "PRO",
        "SAIHM_PAYMENT_METHOD": "stripe",
      },
    },
  },
}
```

With no `SAIHM_AUTH_HEADER`, the server **self-onboards**: it mints and
auto-refreshes its own short-lived access token from your master secret, so
there is no token to paste or re-paste. Eight tools are exposed
(`saihm_remember`, `saihm_recall`, `saihm_forget`, `saihm_status`,
`saihm_share`, `saihm_revoke_share`, `saihm_governance_propose`,
`saihm_governance_vote`).

### Self-serve join

To subscribe an identity from the command line instead of the website, run the
one-off `join` command with the same env:

```sh
SAIHM_ENDPOINT_URL=https://saihm.coti.global/mcp \
SAIHM_MASTER_SECRET_HEX=<your 64+ hex master secret> \
SAIHM_TIER=PRO SAIHM_PAYMENT_METHOD=stripe \
  npx -y @saihm/mcp-server-pro join
```

It prints a Stripe checkout link bound to your identity. Pay in a browser, then
start the server normally (drop `join`) — it connects automatically. Keep
`SAIHM_MASTER_SECRET_HEX` safe: it is the only key to your memory and cannot be
recovered.

## Use as a library

```ts
import { SaihmProClient } from '@saihm/mcp-server-pro';

// Boot from env: SAIHM_ENDPOINT_URL, SAIHM_MASTER_SECRET_HEX
//   self-onboard (recommended): + SAIHM_PAYMENT_METHOD + SAIHM_TIER (omit SAIHM_AUTH_HEADER)
//   static token (advanced):    + SAIHM_AUTH_HEADER="Bearer <JWT>"
//   (optional: SAIHM_SEQ_STATE_PATH)
const saihm = SaihmProClient.bootFromEnv();

// Store — encrypted before it leaves the process.
const { cellId } = await saihm.remember('remember this');

// Recall — decrypted after it returns.
const cell = await saihm.recallOne(cellId);
console.log(cell?.plaintext); // 'remember this'

// Recall everything (client-side keyword filter; the endpoint has no plaintext to filter on).
const matches = await saihm.recall('this');

// Update an existing cell (a fresh monotonic sequence is issued automatically).
await saihm.remember('new contents', { cellId });

// Forget — crypto-shred.
await saihm.forget(cellId);

// Share a cell with another agent, end-to-end authenticated. Pin the grantee's agentIdHash
// out-of-band; the library rejects directory key-substitution.
await saihm.share({
  cellId,
  recipientRecord, // the grantee's published identity record (hex)
  recipientPinnedAgentIdHashHex, // pinned out-of-band
});
await saihm.revokeShare(cellId, recipientPinnedAgentIdHashHex);

// Read a cell another agent shared TO you (the recipient side of `share`). Pin the
// sharer's agentIdHash out-of-band; the library verifies the sharer's signature and
// returns null when there is no live grant (e.g. revoked, or the sharer crypto-shredded it).
const shared = await saihm.recallShared({
  sharerPinnedAgentIdHashHex, // the sharer's agentIdHash, pinned out-of-band
  sharerRecord, // the sharer's published identity record (hex)
  cellId,
});
console.log(shared?.plaintext);

// Operator-observable metadata only (no plaintext).
const status = await saihm.status();
```

The derived `saihm.agentIdHash` is the `sub` the endpoint binds your tenant to — when self-onboarding the client proves it via ML-DSA; with a static `SAIHM_AUTH_HEADER` it must equal the JWT `sub`. Publish `saihm.identityRecord` so other agents can share to you.

## Configuration

| Env                        | Required          | Meaning                                                                                                                                                                                                           |
| -------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SAIHM_ENDPOINT_URL`       | yes               | `https://…/mcp` (or `http://` only for `127.0.0.1`/`localhost`).                                                                                                                                                  |
| `SAIHM_AUTH_HEADER`        | no                | `Bearer <JWT>`, used verbatim. **Omit to self-onboard** (recommended): the client mints + auto-refreshes its own short-lived JWT from the master secret, so you paste one config once and never re-paste a token. |
| `SAIHM_PAYMENT_METHOD`     | self-onboard only | Your entitlement rail (e.g. `stripe`). Required when `SAIHM_AUTH_HEADER` is unset; ignored otherwise.                                                                                                             |
| `SAIHM_MASTER_SECRET_HEX`  | yes\*             | ≥ 64 hex chars (≥ 32 bytes), high-entropy, client-held; never sent. \*Provide this **or** `SAIHM_MASTER_SECRET_FILE`.                                                                                             |
| `SAIHM_MASTER_SECRET_FILE` | yes\*             | Path to a **mode-600** file holding the hex master secret. Preferred for operators: keeps the root seed out of a synced/shared MCP config. Takes precedence over `SAIHM_MASTER_SECRET_HEX` when both are set.     |
| `SAIHM_TIER`               | self-onboard only | Tier label baked into sealed metadata. Required when self-onboarding; otherwise optional — resolved via `status()` if unset.                                                                                      |
| `SAIHM_SEQ_STATE_PATH`     | no                | Persists per-cell sequence high-water marks (mode 600) for cross-restart updates.                                                                                                                                 |

> **Self-onboarding (paste once):** with `SAIHM_AUTH_HEADER` unset, the client proves
> control of your identity via the endpoint's ML-DSA challenge/response and mints its own
> token, refreshing transparently on expiry. Cancelling your subscription stops the next
> refresh, so access ends naturally.

## Errors

Non-2xx responses throw `SaihmEndpointError` with `status` and a typed `code` (e.g. `BLIND_BAD_EXPIRY`, `BLIND_STALE_SEQ`, `governance_unavailable`). Branch on those rather than the message.

## Security model

| Property                        | Guarantee                                                                                                                                                                                                               |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Confidentiality vs the endpoint | The endpoint holds ciphertext + wrapped DEKs + public keys only; no key able to decrypt.                                                                                                                                |
| Integrity / authenticity        | Every cell is ML-DSA-65-signed over its contents, including the sequence number.                                                                                                                                        |
| Anti-replay                     | The signed monotonic sequence is rejected by the endpoint if not strictly increasing.                                                                                                                                   |
| Tenant isolation                | Your `agentIdHash` (= the JWT `sub`) namespaces your state; a write whose signed identity differs from the JWT is rejected.                                                                                             |
| Authenticated sharing           | Grantee public keys are pinned out-of-band and verified before any secret is bound to them; on the recipient side, `recallShared` pins the sharer's key and verifies the cell signature before returning any plaintext. |
| Erasure                         | Destroying the endpoint-side wrapped DEK crypto-shreds the cell.                                                                                                                                                        |

## Where sealed cells are stored

This client seals cells and hands the ciphertext to whatever operator endpoint
you point `SAIHM_ENDPOINT_URL` at; **that operator chooses and configures the
durable storage backend** — typically a local IPFS / Kubo node first, then a
Filecoin deep-archive provider (e.g. Pinata, Synapse, or Lighthouse). Storage
is operator-configured **by design**: the protocol never locks anyone to a
single provider. If you run your own endpoint, provisioning that backend is
your responsibility — see your operator deployment guide.

Prefer not to run storage at all? **Join SAIHM** at <https://saihm.coti.global>
and use the hosted **non-custodial** operator, which provides durable storage
for you. Because this client seals every cell locally, the hosted operator
only ever stores **ciphertext** and never holds your keys — managed storage
without giving up custody (a paid hosted service).

## License

Apache-2.0 © SAIHM
