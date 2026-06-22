# @saihm/mcp-server-pro

Production thin-client for **SAIHM non-custodial memory**.

`SaihmProClient` seals every cell **on the client** with [`@saihm/client-pro`](https://www.npmjs.com/package/@saihm/client-pro), then POSTs the resulting ciphertext to the blind SAIHM `/mcp` endpoint. The endpoint stores, anchors, shares, and meters over ciphertext — it never holds your keys and cannot read your memory. Your master secret, key-encryption key, and plaintext never leave this process.

- **Seal before send** — `remember` encrypts client-side; `recall` decrypts client-side.
- **Post-quantum** — ML-DSA-65 identity/signing, ML-KEM-768 authenticated sharing (via `@saihm/client-pro`).
- **Same transport as the open client** — `POST {method, params}` + `Authorization: Bearer <JWT>`; the endpoint binds your tenant from the JWT. HTTPS-only (loopback `http` permitted for local dev).
- **Crypto-shred erasure** — `forget` destroys the endpoint-side wrapped DEK, rendering the cell undecryptable (GDPR Art. 17).

> **▶ Try it across models.** Runnable, copy-paste demos — persistent memory shared across Claude, GPT, DeepSeek, Qwen, Kimi, GLM and more — live at the demo hub: **[github.com/citw2](https://github.com/citw2)**.

> **Key loss is unrecoverable by design.** If you lose your master secret you lose your KEK, and no one — including SAIHM — can open your cells. Back it up securely.

## Install

```sh
npm install @saihm/mcp-server-pro
```

## Usage

```ts
import { SaihmProClient } from '@saihm/mcp-server-pro';

// Boot from env: SAIHM_ENDPOINT_URL, SAIHM_AUTH_HEADER, SAIHM_MASTER_SECRET_HEX
//   (optional: SAIHM_TIER, SAIHM_SEQ_STATE_PATH)
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
  recipientRecord,                       // the grantee's published identity record (hex)
  recipientPinnedAgentIdHashHex,         // pinned out-of-band
});
await saihm.revokeShare(cellId, recipientPinnedAgentIdHashHex);

// Operator-observable metadata only (no plaintext).
const status = await saihm.status();
```

The derived `saihm.agentIdHash` must match the `sub` of the JWT in `SAIHM_AUTH_HEADER`; publish `saihm.identityRecord` so other agents can share to you.

## Configuration

| Env | Required | Meaning |
|---|---|---|
| `SAIHM_ENDPOINT_URL` | yes | `https://…/mcp` (or `http://` only for `127.0.0.1`/`localhost`). |
| `SAIHM_AUTH_HEADER` | yes | `Bearer <JWT>`; the endpoint binds your tenant from the JWT `sub`. |
| `SAIHM_MASTER_SECRET_HEX` | yes | ≥ 64 hex chars (≥ 32 bytes), high-entropy, client-held; never sent. |
| `SAIHM_TIER` | no | Tier label baked into sealed metadata; resolved via `status()` if unset. |
| `SAIHM_SEQ_STATE_PATH` | no | Persists per-cell sequence high-water marks (mode 600) for cross-restart updates. |

## Errors

Non-2xx responses throw `SaihmEndpointError` with `status` and a typed `code` (e.g. `BLIND_NO_FREE_TIER`, `BLIND_BAD_EXPIRY`, `governance_unavailable`). Branch on those rather than the message.

## Security model

| Property | Guarantee |
|---|---|
| Confidentiality vs the endpoint | The endpoint holds ciphertext + wrapped DEKs + public keys only; no key able to decrypt. |
| Integrity / authenticity | Every cell is ML-DSA-65-signed over its contents, including the sequence number. |
| Anti-replay | The signed monotonic sequence is rejected by the endpoint if not strictly increasing. |
| Tenant isolation | Your `agentIdHash` (= the JWT `sub`) namespaces your state; a write whose signed identity differs from the JWT is rejected. |
| Authenticated sharing | Grantee public keys are pinned out-of-band and verified before any secret is bound to them. |
| Erasure | Destroying the endpoint-side wrapped DEK crypto-shreds the cell. |

## Companion packages & demos

- **[`@saihm/client-pro`](https://www.npmjs.com/package/@saihm/client-pro)** — source: [SAIHM-Admin/saihm-client-pro](https://github.com/SAIHM-Admin/saihm-client-pro). The client-side post-quantum crypto library this package seals with.
- **[`@saihm/mcp-server`](https://www.npmjs.com/package/@saihm/mcp-server)** — source: [SAIHM-Admin/saihm-mcp](https://github.com/SAIHM-Admin/saihm-mcp). The open MCP thin-client for the SAIHM transport.
- **Runnable demos** — copy-paste quickstarts that put SAIHM memory behind Claude, GPT, DeepSeek, Qwen, Kimi, GLM and more, at the demo hub: **[github.com/citw2](https://github.com/citw2)**.
- **Join the protocol** — [saihm.coti.global/join](https://saihm.coti.global/join).

## License

Apache-2.0 © SAIHM
