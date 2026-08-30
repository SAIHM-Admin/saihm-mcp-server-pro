# SAIHM — memory for AI agents

**Portable memory for AI agents.** Your assistant remembers what matters — across
sessions, across models, across vendors. Share a memory with someone else's
agent, take it back, or erase it for good.

[![npm version](https://img.shields.io/npm/v/@saihm/mcp-server-pro.svg)](https://www.npmjs.com/package/@saihm/mcp-server-pro)
[![license](https://img.shields.io/npm/l/@saihm/mcp-server-pro.svg)](./LICENSE)

AI assistants forget everything when the session ends. SAIHM gives yours a memory
that doesn't — one that follows you to a different assistant, a different model,
or a different company's product.

Everything is encrypted on your own machine before it goes anywhere, so nobody
else can read your memories. Not the storage, not SAIHM.

## Start free — one command

```sh
npx -y @saihm/mcp-server-pro free-join
```

That's it. No card, no account to fill in, nothing to invent. It sets up your
identity on this machine and prints a one-time sign-in to confirm you're a real
person. Open the link, enter the short code, approve.

Then point your AI tool at it. This works in Claude Desktop, Claude Code, Cursor,
Cline, and anything else that speaks MCP — add the `"saihm"` entry inside your
existing `mcpServers` section:

```json
{
  "mcpServers": {
    "saihm": {
      "command": "npx",
      "args": ["-y", "@saihm/mcp-server-pro"],
      "env": {
        "SAIHM_ENDPOINT_URL": "https://saihm.coti.global/mcp"
      },
      "timeout": 60
    }
  }
}
```

Restart the connection and say **"Recall my SAIHM memories."** You're running.

Two details in that config are load-bearing:

- **Keep `timeout: 60`.** Some tools allow as little as 1.5 seconds for a server
  to start, which isn't long enough for `npx` to fetch and launch a package. A
  server that misses the deadline is skipped **silently** — the tools simply never
  appear, and nothing in the chat says why.
- **No trailing commas.** These files are strict JSON. A stray comma doesn't just
  break this entry; it invalidates the whole file and every other tool you had
  configured disappears with it.

**Prefer not to touch a terminal?** Add the config above first, then say **"Join
SAIHM"** to your assistant. It does the same setup for you.

## Things to say

You don't call tools by name — you talk to your assistant. Some starters:

> Liberally use SAIHM protocol to maximize token economy.

> Recall my SAIHM memories before you start.

> Remember that I prefer short answers and no preamble.

> Set an invariant to doubly confirm before any SAIHM forget action.

> Share that note with my colleague's agent until 5:00 pm today.

> How much of my SAIHM allowance is left?

> Forget everything I told you about the Henderson account.

| Tool | What it does |
|---|---|
| `saihm_remember` | Encrypts on your machine, then stores it |
| `saihm_recall` | Fetches and decrypts on your machine |
| `saihm_forget` | **Permanently erases.** No undo |
| `saihm_status` | Your usage and settings |
| `saihm_share` | Grants one memory to one agent, optionally with an expiry |
| `saihm_revoke_share` | Withdraws that grant |

Every tool is labelled for your AI tool to read, including which are read-only and
which one destroys data — so hosts that ask "are you sure?" before destructive
actions know when to ask. Two further tools, `saihm_governance_propose` and
`saihm_governance_vote`, are registered for a roadmap feature and are not yet
active.

**"Forget" really means forget.** The key to that specific memory is destroyed, so
the stored copy becomes permanently unreadable — by you, by SAIHM, by anyone
holding a backup of it. This is how SAIHM answers a GDPR Article 17 erasure
request, and it is why there is no undo.

## Your memories follow your key

Your memory belongs to your key, not to a computer — that's what makes it
portable. The key is created on your machine during setup and never sent
anywhere, which is exactly why nobody else can read your memories. **Keep a copy
of the key file somewhere safe.** SAIHM cannot make you another one.

Setup prints the file's location when it runs — that's the line to keep. The same
key carries through if you upgrade to a paid plan: same identity, same memories,
nothing migrated.

**Using a second computer?** Two ways:

- **Same memory, both machines** — put your key file on the second machine, set up
  the config there, and say *"Recall my SAIHM memories."*
- **Work and personal kept apart** — start fresh on the second machine and share
  across instead: *"Share these notes with my work agent until 5:00 pm."* A share
  can be revoked or given an expiry, so the two stay separate.

## See it run

- **Live demos across every major model** — offline, about a minute each, no
  account: <https://citw2.github.io/saihm-demos/>. Store a memory in Claude, GPT,
  DeepSeek, Qwen, Kimi, or GLM, then prove you can erase it.
- **Token benchmark** — recalling a bounded set of memories instead of re-sending
  the whole conversation cut input tokens by **62.8%–85.9%** across a realistic
  multi-session task. Open, offline, reproducible:
  <https://github.com/citw2/saihm-token-benchmark>.

## What it costs

Start free. The free tier is a fixed, one-time allowance of writes, reads, and
shares for trying SAIHM on real infrastructure — it doesn't reset or refill.
**No card, and nothing to cancel.** Your assistant shows what's left and warns you
as it runs low, so nothing fails by surprise.

Paid plans are monthly. Upgrading keeps the same key and every memory you already
have:

```sh
SAIHM_MASTER_SECRET_FILE=$HOME/.saihm/free-identity.key \
SAIHM_TIER=FREE \
  npx -y @saihm/mcp-server-pro upgrade PRO
```

That prints a checkout link tied to your identity. Pay, then add two lines to your
config's `env` block and restart:

```json
"SAIHM_TIER": "PRO",
"SAIHM_PAYMENT_METHOD": "stripe"
```

Both are needed — a paid plan without `SAIHM_PAYMENT_METHOD` refuses to start,
because that setting names which payment rail to check. `stripe` is one option;
`stablecoin` is another, and your assistant can tell you what your operator
accepts.

## If something isn't working

| What you see | Usual cause |
|---|---|
| No SAIHM tools appear, and no error anywhere | `timeout` too low — see the config above |
| Every other tool vanished too | A trailing comma broke the settings file |
| Tools appear but every call fails | `SAIHM_ENDPOINT_URL` unreachable |
| "no identity" | Setup hasn't run on this machine yet |
| A different memory than you expected | This machine has its own key rather than yours |
| `status` mentions `seq-state` | A small local safeguard file couldn't be read or written. Your memories are unaffected — see `SAIHM_SEQ_STATE_PATH` below |

## How it works

**In plain terms.** Everything is encrypted on your machine before it is sent, and
decrypted on your machine after it comes back. What's stored is unreadable
ciphertext and no key that opens it. To erase something, its key is destroyed —
which is why erasure is immediate and final rather than a promise that a copy was
deleted somewhere.

**For the technically inclined.**

- **Encrypt before send** — `remember` encrypts client-side; `recall` decrypts
  client-side. Your plaintext, master secret, and key-encryption key never leave
  this process.
- **Post-quantum** — ML-DSA-65 for identity and signing, ML-KEM-768 for
  authenticated sharing, via
  [`@saihm/client-pro`](https://www.npmjs.com/package/@saihm/client-pro).
- **Crypto-shred erasure** — `forget` destroys the endpoint-side wrapped
  data-encryption key, rendering the cell undecryptable (GDPR Art. 17).
- **Standard transport** — `POST {method, params}` with
  `Authorization: Bearer <JWT>`; the endpoint binds your tenant from the JWT.
  HTTPS only, with loopback `http` permitted for local development.
- **Self-onboarding** — with no `SAIHM_AUTH_HEADER` set, the client proves control
  of your identity and mints its own short-lived token, refreshing transparently.
  You paste one config once and never re-paste a token. Cancelling a subscription
  stops the next refresh, so access ends naturally.

### Security model

| Property | Guarantee |
| --- | --- |
| Confidentiality vs the endpoint | The endpoint holds ciphertext, wrapped DEKs, and public keys only — no key able to decrypt. |
| Integrity / authenticity | Every cell is ML-DSA-65-signed over its contents, including the sequence number. |
| Anti-replay | The signed monotonic sequence is rejected by the endpoint if it does not strictly increase. |
| Tenant isolation | Your `agentIdHash` (the JWT `sub`) namespaces your state; a write whose signed identity differs from the JWT is rejected. |
| Authenticated sharing | Grantee public keys are pinned out-of-band and verified before any secret is bound to them; on the recipient side, `recallShared` pins the sharer's key and verifies the cell signature before returning any plaintext. |
| Erasure | Destroying the endpoint-side wrapped DEK crypto-shreds the cell. |

### Where encrypted cells are stored

This client encrypts cells and hands the ciphertext to whichever operator endpoint
`SAIHM_ENDPOINT_URL` points at; **that operator chooses and configures the durable
storage behind it** — typically a local IPFS / Kubo node first, then a Filecoin
deep-archive provider. Storage is operator-configured **by design**: the protocol
never locks anyone to a single provider. Running your own endpoint means
provisioning that storage yourself.

Prefer not to run storage at all? The hosted operator at
<https://saihm.coti.global> provides durable storage and is **non-custodial** —
because this client encrypts every cell locally, the hosted operator only ever
stores ciphertext and never holds a key.

## Configuration

Most people need none of this: the setup above sets one variable and the rest have
working defaults.

| Env | Required | Meaning |
| --- | --- | --- |
| `SAIHM_ENDPOINT_URL` | no | `https://…/mcp` (or `http://` for `127.0.0.1`/`localhost` only). **Defaults to `https://saihm.coti.global/mcp`** — set it only to reach a different operator. |
| `SAIHM_MASTER_SECRET_FILE` | see note | Path to a **mode-600** file holding the hex master secret. **The preferred way to supply a key**, because it keeps the key out of a config file that may be synced or shared. Takes precedence over `SAIHM_MASTER_SECRET_HEX`. |
| `SAIHM_MASTER_SECRET_HEX` | see note | The master secret inline, ≥ 64 hex characters (≥ 32 bytes), high-entropy, client-held, never sent. Prefer the file form: anything inline lands in the config file itself. |
| `SAIHM_SELF_JOIN` | no | Controls the `saihm_join` onboarding tool — the one that answers *"Join SAIHM"*. **On by default**; set to `0` to remove it and expose only the canonical eight tools. |
| `SAIHM_HOME` | no | Where the identity file lives (`$SAIHM_HOME/free-identity.key`, mode 600) and where per-restart bookkeeping is kept. Defaults to `~/.saihm`. |
| `SAIHM_AUTH_HEADER` | no | `Bearer <JWT>`, used verbatim. **Omit to self-onboard** (recommended) — the client mints and refreshes its own token, so there is nothing to paste or re-paste. |
| `SAIHM_TIER` | self-onboard only | Plan label recorded in encrypted metadata (`FREE`, `PRO`, …). Required when self-onboarding; otherwise resolved via `status()`. |
| `SAIHM_PAYMENT_METHOD` | paid self-onboard | Entitlement rail (`stripe`, `stablecoin`, …) for a paid plan. **Not used by the free tier.** Ignored when `SAIHM_AUTH_HEADER` is set. |
| `SAIHM_SEQ_STATE_PATH` | no | Overrides where the anti-rollback bookkeeping is written. Running as an MCP server this is **on by default** at `$SAIHM_HOME/seq.<id>.json`; set it only to relocate it. The default location is ours to manage: if it can't be written, the tally stays in memory for the session and `status` says so. A location **you** set is yours: if it can't be written, calls fail and name the path, so a safeguard you asked for never goes quiet without telling you. `status` reports this as `seq-state=…` followed by `rollback-guard=persisting` (writes still work, so the next one rewrites the file) or `memory-only-this-run` (it retries at the next restart). Either way, if the file couldn't be READ at startup the safeguard starts from scratch and rebuilds as each memory is next read — so an older copy of a memory would not be caught during that window. |
| `SAIHM_STATE_DIR` | no | Where transient operator state (such as `checkout-url.txt`) is written. Does **not** relocate your identity or its bookkeeping. |

*Note:* a master secret is required, from one source or the other — but setup
creates and configures it for you, which is why the config above has neither.

## For developers

```sh
npm install @saihm/mcp-server-pro
```

```ts
import { SaihmProClient } from '@saihm/mcp-server-pro';

// Boot from env: SAIHM_ENDPOINT_URL, SAIHM_MASTER_SECRET_FILE (or _HEX)
//   self-onboard (recommended): + SAIHM_PAYMENT_METHOD + SAIHM_TIER (omit SAIHM_AUTH_HEADER)
//   static token (advanced):    + SAIHM_AUTH_HEADER="Bearer <JWT>"
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
  expiryEpoch, // optional; omit or null for no time bound
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

The derived `saihm.agentIdHash` is the `sub` the endpoint binds your tenant to —
when self-onboarding the client proves it via ML-DSA; with a static
`SAIHM_AUTH_HEADER` it must equal the JWT `sub`. Publish `saihm.identityRecord` so
other agents can share to you.

Constructing `SaihmProClient` directly writes nothing to your home directory; the
per-restart bookkeeping is opted into by the MCP server's boot path, or by setting
`SAIHM_SEQ_STATE_PATH` explicitly.

**Errors.** Non-2xx responses throw `SaihmEndpointError` carrying `status` and a
typed `code` (e.g. `BLIND_BAD_EXPIRY`, `BLIND_STALE_SEQ`,
`governance_unavailable`). Branch on the code rather than the message.

## License

Apache-2.0 © SAIHM
