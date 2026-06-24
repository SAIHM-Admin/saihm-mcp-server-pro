# @saihm/mcp-server-pro

Production thin-client for **SAIHM non-custodial memory**.

`SaihmProClient` seals every cell **on the client** with [`@saihm/client-pro`](https://www.npmjs.com/package/@saihm/client-pro), then POSTs the resulting ciphertext to the blind SAIHM `/mcp` endpoint. The endpoint stores, anchors, shares, and meters over ciphertext — it never holds your keys and cannot read your memory. Your master secret, key-encryption key, and plaintext never leave this process.

- **Seal before send** — `remember` encrypts client-side; `recall` decrypts client-side.
- **Post-quantum** — ML-DSA-65 identity/signing, ML-KEM-768 authenticated sharing (via `@saihm/client-pro`).
- **Same transport as the standards client** — `POST {method, params}` + `Authorization: Bearer <JWT>`; the endpoint binds your tenant from the JWT. HTTPS-only (loopback `http` permitted for local dev).
- **Crypto-shred erasure** — `forget` destroys the endpoint-side wrapped DEK, rendering the cell undecryptable (GDPR Art. 17).

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

The derived `saihm.agentIdHash` must match the `sub` of the JWT in `SAIHM_AUTH_HEADER`; publish `saihm.identityRecord` so other agents can share to you.

## Configuration

| Env                       | Required | Meaning                                                                           |
| ------------------------- | -------- | --------------------------------------------------------------------------------- |
| `SAIHM_ENDPOINT_URL`      | yes      | `https://…/mcp` (or `http://` only for `127.0.0.1`/`localhost`).                  |
| `SAIHM_AUTH_HEADER`       | yes      | `Bearer <JWT>`; the endpoint binds your tenant from the JWT `sub`.                |
| `SAIHM_MASTER_SECRET_HEX` | yes      | ≥ 64 hex chars (≥ 32 bytes), high-entropy, client-held; never sent.               |
| `SAIHM_TIER`              | no       | Tier label baked into sealed metadata; resolved via `status()` if unset.          |
| `SAIHM_SEQ_STATE_PATH`    | no       | Persists per-cell sequence high-water marks (mode 600) for cross-restart updates. |

## Errors

Non-2xx responses throw `SaihmEndpointError` with `status` and a typed `code` (e.g. `BLIND_NO_FREE_TIER`, `BLIND_BAD_EXPIRY`, `governance_unavailable`). Branch on those rather than the message.

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
