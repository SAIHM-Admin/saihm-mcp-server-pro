# SAIHM — memory for AI agents

**Portable memory for AI agents.** Your assistant remembers what matters —
across sessions, across models, and across vendors. Share a memory with someone
else's agent, take it back, or erase it for good. The service that stores it
holds no key and cannot read a word of it.

[![npm version](https://img.shields.io/npm/v/@saihm/mcp-server-pro.svg)](https://www.npmjs.com/package/@saihm/mcp-server-pro)
[![license](https://img.shields.io/npm/l/@saihm/mcp-server-pro.svg)](./LICENSE)

AI assistants forget everything when the session ends. This gives yours a memory
that doesn't — one that follows you to a different assistant, a different model,
or a different company's product, and that only you can open.

`@saihm/mcp-server-pro` is the piece that does the locking, and it runs on your
own machine. Everything is sealed before it leaves, so the service on the other
end only ever holds a locked box it has no key to.

## Set it up

About two minutes. No card, and no secret to invent.

**1. Add this to your AI tool's settings.** It works with Claude Desktop, Claude
Code, Cursor, Cline, and anything else that speaks MCP. If the file already has
an `mcpServers` section, add the `"saihm"` entry inside it rather than replacing
the file:

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

**2. Restart the connection, then say this to your assistant:**

> Join SAIHM.

That is the whole setup. Your assistant creates your key on this machine, hands
you a one-time sign-in link that confirms you are a real person, and your memory
is live. Next session, it is still there.

**3. Back up the key file it tells you about.** More on that just below — it is
the one step worth doing properly.

Two details in that config are load-bearing:

- **Keep `timeout: 60`.** Some tools allow as little as 1.5 seconds for a server
  to start (that is Cline's default), which is not long enough for `npx` to fetch
  and launch a package. A server that misses the deadline is skipped **silently**
  — the tools simply never appear, and nothing in the chat says why.
- **No trailing commas.** These settings files are strict JSON. A stray comma
  doesn't just break this entry; it invalidates the whole file and every other
  tool you had configured disappears with it.

Prefer a terminal? `npx -y @saihm/mcp-server-pro free-join` does the same thing
in one command, then start the server normally.

## Your key is the whole thing

Your memories are locked with a key that is created on your machine and never
sent anywhere. That is what makes the service unable to read them — and it also
means there is nobody to ask for a password reset.

**If you joined the free way, the key is at `~/.saihm/free-identity.key`.** If
you supplied your own, it is whatever file `SAIHM_MASTER_SECRET_FILE` points at.
Either way it is a small text file, and the client prints its path when it sets
your identity up, so you never have to guess which one to keep.

Anyone who has that file can read everything you have ever stored, so treat it
the way you'd treat the master password to a password manager.

**Back it up somewhere you'd trust with that password** — a password manager's
secure note is the simplest option. If you lose it, no one, including SAIHM, can
open your cells. That is the design working as intended, not a gap.

## Using it on more than one computer

Your memory is tied to your key, not to a computer. Any machine holding that key
sees the same memories — home laptop, work desktop, a different assistant, a
different model. That portability is the point, and the key file is how you get
it.

**To use the same memory somewhere else:** copy your key file — the one named
just above — to the second machine before you start the server there, and set up
the config the same way. Then **don't** say "Join SAIHM" on that machine: you
don't need to, and joining again would create a second, unrelated memory with
nothing in it. Just ask your assistant to recall something and it will be there.

Behind the scenes, a machine that has your key but has never been used before
asks the service where your memories currently stand and picks up from there, so
nothing is lost and nothing is overwritten.

Move the file over something you'd trust with a password: paste it into your
password manager and back out again on the other side, or copy it directly
between machines you control.

> **Don't put your key in Dropbox, iCloud, Google Drive, or a shared network
> folder.** Sync services keep copies and version history, and anyone who gets
> into that account gets your key. If your AI tool's config file lives in a
> synced folder — a common setup — keep the key out of it and point at it with
> `SAIHM_MASTER_SECRET_FILE` instead of pasting the key itself into the config.

**Work and personal are often better kept separate.** Rather than putting your
personal key on an employer's machine, join separately there and use `share` to
grant that identity access to the specific memories it needs. You can revoke a
share later; you cannot un-copy a key.

**A note on the small files beside your key.** `~/.saihm` also holds bookkeeping
files named `seq.<something>.json`. They are not secret and they are not your
memories — they are a local tally that keeps an old copy of a memory from
overwriting a newer one after a restart. Each machine keeps its own. You can
copy them along or leave them behind, and if one is ever missing or damaged you
can simply delete it: the client reads the current state back from the service
and carries on.

## What you can ask for

You don't call these by name — you talk to your assistant and it picks the right
one. The plain-language phrasings are what most people actually use.

| Say something like | Tool | What happens |
|---|---|---|
| "Remember that I prefer …" | `saihm_remember` | Locked on your machine, then stored |
| "What do you know about …?" | `saihm_recall` | Fetched and unlocked on your machine |
| "Forget what I told you about …" | `saihm_forget` | **Permanently erased.** No undo |
| "How much memory have I used?" | `saihm_status` | Your usage and settings. Reads nothing else |
| "Share that note with my colleague's agent" | `saihm_share` | Grants one specific memory to one specific agent |
| "Stop sharing that" | `saihm_revoke_share` | Withdraws the grant |
| "Propose a protocol change" / "Vote on it" | `saihm_governance_propose` / `saihm_governance_vote` | Protocol governance |

Every tool is labelled for your AI tool to read, including which ones are
read-only and which one destroys data — so hosts that ask "are you sure?" before
destructive actions know when to ask.

**"Forget" really means forget.** The key that opens that specific memory is
destroyed, so the stored copy becomes permanently unreadable — by you, by the
service, by anyone holding a backup of it. This is how SAIHM answers a GDPR
Article 17 erasure request, and it is why there is no undo.

## See it run

- **Live demos across every major model** — offline, about a minute each, no
  account: <https://citw2.github.io/saihm-demos/>. Store a memory in Claude, GPT,
  DeepSeek, Qwen, Kimi, or GLM, then prove you can erase it.
- **Token benchmark** — recalling a bounded set of memories instead of re-sending
  the whole conversation cut input tokens by **62.8%–85.9%** across a realistic
  multi-session task. Open, offline, and reproducible:
  <https://github.com/citw2/saihm-token-benchmark>.

## What it costs

The free tier is a fixed, one-time allowance of writes, reads, and shares for
trying it on real infrastructure. It does not reset or refill. **No card, and
nothing to cancel** — it is not an auto-renewing subscription. Your assistant
shows the remaining balance and warns you as it runs low, so nothing fails by
surprise.

Paid tiers are monthly. Upgrading keeps the same key and every memory you already
have:

```sh
SAIHM_ENDPOINT_URL=https://saihm.coti.global/mcp \
SAIHM_MASTER_SECRET_FILE=$HOME/.saihm/free-identity.key \
SAIHM_TIER=FREE \
  npx -y @saihm/mcp-server-pro upgrade PRO
```

That prints a checkout link tied to your identity. Pay, then add two lines to
your config's `env` block and restart:

```json
"SAIHM_TIER": "PRO",
"SAIHM_PAYMENT_METHOD": "stripe"
```

Both are needed — a paid tier without `SAIHM_PAYMENT_METHOD` refuses to start,
because that setting is how the client tells the service which subscription to
check. Billing attaches to the same key you already have, so nothing is migrated
and nothing is lost.

<details>
<summary>Subscribing directly, without starting free</summary>

This skips the free tier and goes straight to a paid tier from the command line
instead of the website. Unlike `free-join` it is not zero-config: it needs a
master secret you supply and an explicit tier.

Generate the secret yourself first — it never leaves your machine, and it is the
only key to your memory:

```sh
openssl rand -hex 32 > saihm-master.key && chmod 600 saihm-master.key
```

```sh
SAIHM_ENDPOINT_URL=https://saihm.coti.global/mcp \
SAIHM_MASTER_SECRET_FILE=./saihm-master.key \
SAIHM_TIER=PRO SAIHM_PAYMENT_METHOD=stripe \
  npx -y @saihm/mcp-server-pro join
```

It prints a checkout link bound to your identity. Pay in a browser, then start
the server normally (drop `join`). The same three settings the command above used
— `SAIHM_MASTER_SECRET_FILE`, `SAIHM_TIER` and `SAIHM_PAYMENT_METHOD` — have to be
in the server's own `env` block too, or it will refuse to start on a paid tier.
Back up `saihm-master.key`; it cannot be recovered.

</details>

## If something isn't working

| What you see | Usual cause |
|---|---|
| No SAIHM tools appear, and no error anywhere | `timeout` too low — see the config above |
| Every other tool vanished too | A trailing comma broke the settings file |
| Tools appear but every call fails | `SAIHM_ENDPOINT_URL` unreachable |
| "no identity" | "Join SAIHM" hasn't been run on this machine yet |
| A different memory than you expected | A second key was created; check `~/.saihm` |
| `status` shows a `seq-state=` line | The bookkeeping file can't be written (a read-only or full home directory). Memory still works; the safeguard just falls back to this session only |

## How it works

**In plain terms.** Everything is locked on your machine before it is sent, and
unlocked on your machine after it comes back. The service in the middle stores
sealed boxes and the locks that go with them, but never a key that opens one. To
erase something, the lock is destroyed — which is why erasure is immediate and
final rather than a promise that a copy was deleted somewhere.

**For the technically inclined.**

- **Seal before send** — `remember` encrypts client-side; `recall` decrypts
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
- **Self-onboarding** — with no `SAIHM_AUTH_HEADER` set, the client proves
  control of your identity to the endpoint and mints its own short-lived token,
  refreshing it transparently. You paste one config once and never re-paste a
  token. Cancelling a subscription stops the next refresh, so access ends
  naturally.

### Security model

| Property | Guarantee |
| --- | --- |
| Confidentiality vs the endpoint | The endpoint holds ciphertext, wrapped DEKs, and public keys only — no key able to decrypt. |
| Integrity / authenticity | Every cell is ML-DSA-65-signed over its contents, including the sequence number. |
| Anti-replay | The signed monotonic sequence is rejected by the endpoint if it does not strictly increase. |
| Tenant isolation | Your `agentIdHash` (the JWT `sub`) namespaces your state; a write whose signed identity differs from the JWT is rejected. |
| Authenticated sharing | Grantee public keys are pinned out-of-band and verified before any secret is bound to them; on the recipient side, `recallShared` pins the sharer's key and verifies the cell signature before returning any plaintext. |
| Erasure | Destroying the endpoint-side wrapped DEK crypto-shreds the cell. |

### Where sealed cells are stored

This client seals cells and hands the locked box to whichever operator endpoint
`SAIHM_ENDPOINT_URL` points at; **that operator chooses and configures the
durable storage behind it** — typically a local IPFS / Kubo node first, then a
Filecoin deep-archive provider. Storage is operator-configured **by design**: the
protocol never locks anyone to a single provider. Running your own endpoint means
provisioning that storage yourself.

Prefer not to run storage at all? The hosted operator at
<https://saihm.coti.global> provides durable storage and is **non-custodial** —
because this client seals every cell locally, the hosted service only ever stores
ciphertext and never holds a key (a paid hosted service).

## Configuration

Most people need none of this: the setup at the top of this page sets one
variable and the rest have working defaults.

| Env | Required | Meaning |
| --- | --- | --- |
| `SAIHM_ENDPOINT_URL` | no | `https://…/mcp` (or `http://` for `127.0.0.1`/`localhost` only). **Defaults to `https://saihm.coti.global/mcp`** — set it only to reach a different operator. |
| `SAIHM_MASTER_SECRET_FILE` | see note | Path to a **mode-600** file holding the hex master secret. **The preferred way to supply a key**, because it keeps the key itself out of a config file that may be synced or shared. Takes precedence over `SAIHM_MASTER_SECRET_HEX`. |
| `SAIHM_MASTER_SECRET_HEX` | see note | The master secret inline, ≥ 64 hex characters (≥ 32 bytes), high-entropy, client-held, never sent. Prefer `SAIHM_MASTER_SECRET_FILE`: anything inline lands in the config file, and MCP config files are frequently synced between machines. |
| `SAIHM_SELF_JOIN` | no | Controls the `saihm_join` onboarding tool — the one that answers *"Join SAIHM"*. **On by default**; set to `0` to remove it and expose only the canonical eight tools. |
| `SAIHM_HOME` | no | Where the identity file lives (`$SAIHM_HOME/free-identity.key`, mode 600) and where per-restart bookkeeping is kept. Defaults to `~/.saihm`. |
| `SAIHM_AUTH_HEADER` | no | `Bearer <JWT>`, used verbatim. **Omit to self-onboard** (recommended) — the client mints and refreshes its own token, so there is nothing to paste or re-paste. |
| `SAIHM_TIER` | self-onboard only | Tier label recorded in sealed metadata (`FREE`, `PRO`, …). Required when self-onboarding; otherwise resolved via `status()`. |
| `SAIHM_PAYMENT_METHOD` | paid self-onboard | Entitlement rail (e.g. `stripe`) for a paid tier. **Not used by the free tier.** Ignored when `SAIHM_AUTH_HEADER` is set. |
| `SAIHM_SEQ_STATE_PATH` | no | Overrides where the anti-rollback bookkeeping is written. Running as an MCP server, this is **on by default** at `$SAIHM_HOME/seq.<id>.json`; set this only to relocate it. If the location can't be written the client keeps the tally in memory for the session and says so in `status`. |
| `SAIHM_STATE_DIR` | no | Where transient operator state (such as `checkout-url.txt`) is written. Does **not** relocate your identity or its bookkeeping. |

*Note:* a master secret is required, from one source or the other — but on the
free path `saihm_join` creates and configures it for you, which is why the setup
at the top of this page has neither.

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
`SAIHM_AUTH_HEADER` it must equal the JWT `sub`. Publish
`saihm.identityRecord` so other agents can share to you.

Constructing `SaihmProClient` directly writes nothing to your home directory; the
per-restart bookkeeping is opted into by the MCP server's boot path, or by
setting `SAIHM_SEQ_STATE_PATH` explicitly.

**Errors.** Non-2xx responses throw `SaihmEndpointError` carrying `status` and a
typed `code` (e.g. `BLIND_BAD_EXPIRY`, `BLIND_STALE_SEQ`,
`governance_unavailable`). Branch on the code rather than the message.

## License

Apache-2.0 © SAIHM
