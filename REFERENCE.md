# SAIHM MCP server — technical reference

The [README](./README.md) gets you started in minutes. This reference holds the detail behind it: each
client's fine print, hosted environments, every setting, the security model, and the interfaces for developers
and for SHM.

## Contents

- [Joining in detail](#joining-in-detail)
- [Client setup in detail](#client-setup-in-detail)
- [Tools](#tools)
- [Exporting your identity](#exporting-your-identity)
- [Your identity record, for sharing](#your-identity-record-for-sharing)
- [Hosted agent environments in detail](#hosted-agent-environments-in-detail)
- [Troubleshooting](#troubleshooting)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [For developers](#for-developers)
- [SHM and this client](#shm-and-this-client)

## Joining in detail

No GitHub account? Start at <https://saihm.net/free> instead. It signs you in with
Google or Microsoft, in the browser, and then gives you your key and the steps to connect
your assistant. Keep the key out of project and workspace settings, which can be committed
with a repository. Your key is already active, so there is nothing to join: a join there
makes no new key.

**If a join stops before you approve it.** A join, from the command or from *"Join
SAIHM"*, writes your key when it starts, before you approve. If the join stops while it
waits (the terminal closes, or the session ends), the key stays. Join again on the same
machine and follow its steps: it uses that same key, so it is the same identity, and it
writes no second key. While a join started by your assistant waits for approval, the
memory tools answer with its steps (an identity that was already active keeps working). To stop a join you don't want, stop the command
(Ctrl+C) or end the session, and don't enter the code; it expires after the time the
join shows. Keep the key file all the same: a later join on this machine uses it.

**Your assistant asks first.** When a join would create a new key, the first *"Join SAIHM"*
answers with a question for you: whether you already have a SAIHM identity, on another
machine or from an earlier session, and whether this environment keeps its home directory.
Only a call after that question creates the key, even when the assistant says at once that
you want a new one. A join that would refuse anyway (a temporary home or a CI runner's, a
`SAIHM_HOME` with the shape of a key, a paid `SAIHM_TIER` with no identity here) says so before
asking.

## Client setup in detail

The configurations for Claude Code, Gemini CLI and the OpenAI Agents SDK are presented
as tested (see [which clients are checked](#which-clients-are-checked)); the others are
documented from each vendor's own documentation. Every configuration is subject to change
at the vendor's discretion.

Before you paste:

- **Valid JSON.** In a JSON settings file, a trailing comma, or a non-breaking space
  (U+00A0) copied from an email or a web page, makes the whole file invalid, and every
  server in it disappears.
  Paste through a plain-text editor, or retype the indentation.
- **Start-up time.** The first start downloads the package, which takes longer than
  some clients wait by default. Where a client needs a longer limit, its block in the README sets
  one: keep it. A server that misses the limit can be skipped **silently**: the tools
  never appear, and nothing in the chat says why.
- **Download it once first.** `npx -y @saihm/mcp-server-pro --version` downloads the package, prints its
  version and exits. Run it in a terminal before the first start, or when the tools do
  not appear the first time, then restart the client.

**Default endpoint.** From 0.11.2 the default endpoint is `https://saihm.net/mcp`. Versions 0.11.1 and
earlier default to the previous host, `saihm.coti.global`, which is being retired: upgrade, or set
`SAIHM_ENDPOINT_URL` explicitly. Every client block in the README sets it.

### Claude Code (Anthropic)

For one repository only, leave `--scope` out: the entry then applies to the project you
run it in, for you alone. `--scope project` writes it to the repository's `.mcp.json`
instead, shared with everyone who uses the repository. If the tools are missing after the first start, give the server
longer to start: `MCP_TIMEOUT=60000 claude` (milliseconds).

**Check the setup.** `claude mcp list` shows whether each server connected, and says so
when a config file is not valid JSON. If the broken file is `~/.claude.json`, Claude Code
may replace it with a fresh one, without your servers (`claude mcp list` does; an
interactive session asks first), and keep the original under
`~/.claude/backups/`: fix that copy and put it back. To check a file yourself without printing it, run
`python3 -m json.tool <file> > /dev/null && echo valid` on it (`~/.claude.json` for the
command in the README, or a repository's `.mcp.json`; on Windows, in Command Prompt: `py -m json.tool <file> > NUL && echo valid`, writing `"%USERPROFILE%\.claude.json"` for `~/.claude.json`): it prints `valid`, or the line and column of
the first error. Never print a config file into a chat or an agent's
session: it can hold other servers' keys. A config copied from an email or a web page
can carry non-breaking spaces (U+00A0) in its indentation, and JSON rejects them.

### Claude Desktop (Anthropic)

**Edit Config** opens `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`, Windows:
`%APPDATA%\Claude\`).

This starts the server with the Node.js installed on your machine, so install it first.
If the server does not connect, its log is `mcp-server-saihm.log` in
`~/Library/Logs/Claude` (macOS) or `%APPDATA%\Claude\logs` (Windows).

### Codex CLI (OpenAI)

Codex waits 10 seconds for a server to start unless `startup_timeout_sec` says
otherwise; a server still starting may miss the first message's tools and appear from the
next one. A project's `.codex/config.toml` is read only once you trust the project. It passes the server only a few basic variables (such as `HOME` and `PATH`);
to pass another from your shell, such as `HTTPS_PROXY`, name it in
`env_vars = ["HTTPS_PROXY"]`. Check with `codex mcp list`, or `/mcp` inside Codex.

### OpenAI Agents SDK (Python)

The SDK waits 5 seconds for each server reply by default, too short for the first `npx`
download, hence `client_session_timeout_seconds=60`. The server gets only a few basic
variables (such as `HOME` and `PATH`) plus what you put in `env`, so set any other
`SAIHM_*` setting there, and `HTTPS_PROXY` or `NODE_EXTRA_CA_CERTS` if your network needs
them. Pass a secret from the environment
(`os.environ["SAIHM_IDENTITY_PASSPHRASE"]`), never as a literal in your code.

### Gemini CLI (Google)

No `timeout` is needed: Gemini CLI waits up to 10 minutes by default. If you set one, it
is in milliseconds, so the `"timeout": 60` other clients use would mean 60 ms here. Gemini
CLI also withholds inherited variables that look sensitive: names containing words such
as `SECRET`, `KEY`, `TOKEN`, `AUTH`, `PASSWORD`, `CREDENTIAL`, `CERT` or `PRIVATE`, and
values such as a URL with a user name and password. If the server needs one, set it in
`env`: write a path itself (`SAIHM_MASTER_SECRET_FILE`, `NODE_EXTRA_CA_CERTS`), and give a
value that holds a password, such as a proxy URL with one, as a reference to the name
your shell sets: `"HTTPS_PROXY": "$HTTPS_PROXY"`, or `"$https_proxy"` if it sets only the
lowercase one. Gemini CLI fills a reference from the environment it was
started from, before it withholds anything, and a reference to a variable missing there
comes out empty. If your version leaves a reference empty, write the value only in
`~/.gemini/settings.json`, never in a project's `.gemini/settings.json`, which can be
committed with its repository. Never write a key itself into a settings file. Run Gemini
CLI in a folder you trust: in an untrusted folder it does not start local servers. Check with `gemini mcp list`, or `/mcp` inside Gemini CLI. The first
`gemini mcp list` can show the server disconnected while `npx` is still downloading,
because that check waits only a few seconds; run it again.

Since 2026-06-18, Google no longer serves personal Google accounts in the Gemini CLI:
signing in with one answers "This client is no longer supported for Gemini Code Assist
for individuals". As of October 2026 it still works with a Gemini API key, or with a
Gemini Code Assist Standard or Enterprise licence.

### Antigravity CLI (Google)

Antigravity CLI reads `~/.gemini/config/mcp_config.json` for all projects and a
project's `.agents/mcp_config.json` for one project, with the same `mcpServers` entry
as the README's block. `/mcp` inside the CLI shows whether the server connected and can
reload it.

### Grok Build (xAI)

Grok Build waits 30 seconds for a server to start unless `startup_timeout_sec` says
otherwise. It reads `~/.grok/config.toml` for user-level servers and a project's
`.grok/config.toml` for project-scoped ones, and also loads an existing `saihm` entry from
`~/.claude.json` or a project's `.mcp.json`, merged below `config.toml` in priority. Check
with `grok mcp list`, or `grok mcp doctor saihm`.

### Cline

`timeout` is in seconds in Cline. Without it, the Cline CLI gives a server only a few
seconds to start (the editor extension waits longer).

- **Cline in the editor:** open the Cline panel, select the **MCP Servers** icon, then
  **Configure > Configure MCP Servers**. Cline's documentation says a server that does not
  respond can be restarted from its MCP settings.
- **Cline CLI:** the file is `~/.cline/data/settings/cline_mcp_settings.json`, or the file
  `CLINE_MCP_SETTINGS_PATH` names. `cline mcp install` writes its entry in another shape
  (`"transport": { ... }`), with no `timeout` and no `env`: add `"timeout": 60` beside
  `"transport"`, or use the entry in the README. Start a new CLI session after editing it.
  If `cline` is not found in your shell, run it from the shell where you installed it.

If the tools don't appear the first time, run `npx -y @saihm/mcp-server-pro --version` in a
terminal. It downloads the package, prints its version and exits. Then restart the server.

### Other MCP clients

The README's block for other clients is the generic MCP form. Add the `"saihm"` entry
inside the existing `mcpServers` object rather than replacing it. If your client documents
a start-up time, give it about a minute, in the unit its documentation gives.

### Which clients are checked

Before each release, the server is started from the README's configurations in Claude
Code and Gemini CLI, which must each report it connected, and in the OpenAI Agents SDK,
which must list the SAIHM tools. That check covers start-up only: memory calls through
each client are not part of it. The other clients, Codex CLI and Antigravity CLI included, are
documented only.

## Tools

**The full tool list.** The server registers eight protocol tools: `saihm_remember`,
`saihm_recall`, `saihm_forget`, `saihm_status`, `saihm_share`, `saihm_revoke_share`,
`saihm_governance_propose` and `saihm_governance_vote`. The two governance tools are
present but answer "governance unavailable" for now. It also registers `saihm_join`, the
bootstrap tool that answers *"Join SAIHM"*: on by default, removed by
`SAIHM_SELF_JOIN=0`. So a client lists nine tools by default, and eight with
`SAIHM_SELF_JOIN=0`.

**Sharing.** `saihm_share` takes the `cellId` of one memory and the recipient: either
`recipientRecordFile`, the full path of the file `identity-record` writes, or
`recipientRecord` with `recipientPinnedAgentIdHashHex`. It also takes an optional `scope`
(`read`, `write` or `readwrite`; blank is `read`) and an optional `expiryEpoch` in whole hours
since the UNIX epoch. See [Your identity record, for sharing](#your-identity-record-for-sharing).
To read a memory shared with you, `saihm_recall` takes the sharer's agent ID as
`sharerPinnedAgentIdHashHex` and the memory's `cellId`; no record is needed.

**"Forget" really means forget.** The key to that specific memory is destroyed, so
the stored copy becomes permanently unreadable — by you, by SAIHM, by anyone
holding a backup of it. This is how SAIHM answers a GDPR Article 17 erasure
request, and it is why there is no undo. The answer says `complete=true` once the
endpoint's record of that destruction comes back with it; short of that, it tells
you exactly what it does know (see [Troubleshooting](#troubleshooting)).

## Exporting your identity

`npx -y @saihm/mcp-server-pro export-identity`, run on the machine that has your key, carries your identity
to another machine or a hosted agent (see the [README](./README.md#your-memories-follow-your-key)).

Run it with the same `SAIHM_*` settings your MCP client gives the server there —
on a paid plan at least `SAIHM_TIER` and `SAIHM_PAYMENT_METHOD`, e.g.
`SAIHM_TIER=PRO SAIHM_PAYMENT_METHOD=stripe npx -y @saihm/mcp-server-pro export-identity`
— because it exports the identity and tier this shell would boot, and it prints
the identity and tier so you can check. If your key is inline
(`SAIHM_MASTER_SECRET_HEX`), put it in a mode-600 file and point
`SAIHM_MASTER_SECRET_FILE` at it for the export, rather than typing it into your
shell history. It writes two values to a file only you can read:
`SAIHM_IDENTITY` (your key, sealed) and `SAIHM_IDENTITY_PASSPHRASE` (the passphrase
that opens it). Set both as environment variables or secrets wherever the memory
should follow you — a hosted agent environment's settings, or the environment
your MCP client starts the server from — and the memory tools use that identity
from the next session. Don't say *"Join SAIHM"* there: a join creates a new, empty
memory. Together the two values **are** your identity: never paste them into a
chat or write them into a config file in a repository. Keep a copy in a password
manager, then delete the export file.

## Your identity record, for sharing

`npx -y @saihm/mcp-server-pro identity-record [FILE]` writes this identity's public
identity record: one JSON document with your agent ID (`agentIdHash`) and your
`identityRecord` (`mldsaPubKey`, `mlkemPubKey` and `mlkemPubKeySelfSig`, in hex). With
`FILE` it writes there, never over a file that exists and never into a folder that is not
there; with no `FILE`, or `-`, it writes the document to stdout and what it is to stderr.
It reads the identity a server started from this shell would use, as `export-identity`
does, never creates one, and asks the endpoint nothing.

The record holds no secret: nothing in it can read, change or erase your memory, so it can
be sent to anyone. A colleague's agent uses it to share a memory with you: `saihm_share`
takes the file's full path as `recipientRecordFile` and reads the record and your agent ID
from it, or takes `identityRecord` as `recipientRecord` and `agentIdHash` as
`recipientPinnedAgentIdHashHex`.

To read a memory you shared with them, your colleague's agent needs only your agent ID:
`saihm_recall` takes it as `sharerPinnedAgentIdHashHex`, with the `cellId`. SAIHM checks the
key that comes with the memory against the agent ID before it uses it. A `sharerRecord`
(the record's `identityRecord`) may be given too, and must then hold that same key. Send
your agent ID yourself, or check it with your colleague another way, as for a record.

The agent ID is the pin: it is the hash of the record's signing key, and that key signs
the record's other key, so SAIHM refuses a record that does not belong to its agent ID,
and a record swapped in transit fails unless the agent ID was swapped with it. If the file
travels by a channel someone else could change, check the agent ID with your colleague
another way. The self-signature changes each time the command runs; any one of them
verifies.

With `recipientRecordFile`, the agent names the file and SAIHM reads it on your machine,
so the agent does not copy the record's 13 KB of keys into the call. The file must be a
regular file of at most 64 KB holding exactly the document the command writes, in UTF-8
(a file saved as UTF-16, as a PowerShell redirect writes it, is refused and says so), and its
record must check out against its agent ID before anything is shared. Name it by its full
path: a relative path is read from the server's working directory, which is your project
in some AI clients and not in others, and `~` is not expanded. The agent ID in the file
came with the file, so it is only as sure as the way the file reached you: to check it,
get the agent ID from your colleague another way and pass it as
`recipientPinnedAgentIdHashHex` beside the file. It must then be the agent ID in the file,
or nothing is shared. A refused share says why in a fixed sentence, with its code:
`bad_recipient_record_file` for the file, `bad_recipient` for an agent ID that is not 64
hex characters, `recipient_mismatch` for an agent ID that is not the file's,
`recipient_required` when no recipient is named, and `invalid_input` for a file and an
inline record together. It never shows the file's contents or its path.

## Hosted agent environments in detail

A hosted agent session usually starts on a fresh machine and discards its home
directory when it ends, so a key created there is lost with it. Bring your identity
in with the two `export-identity` values instead, set in the environment's own
settings — never in the chat. A hosted environment reads its variables when a
session starts, so start a new session after setting them. The server needs to run
locally (stdio) and reach `saihm.net` (or your `SAIHM_ENDPOINT_URL` host) — directly,
or through the proxy in `HTTPS_PROXY` if the environment sets one (`NO_PROXY` is
honoured; a network that inspects TLS needs its CA certificate, from the network's
administrator and never copied from the connection, saved to a file whose path is in
`NODE_EXTRA_CA_CERTS`). Configuration differs by host. The steps follow each host's own documentation; none of these hosts
has been tested end to end yet.

### Claude Code on the web

Add both values under the environment's
*Environment variables*. Its documentation warns that anyone who uses the
environment can read these values, and the dialog advises against putting secrets
there, so use a dedicated environment that only you use, for repositories you
trust: every session in it, on any repository, can read them. (Its API-credential
setting does not help here: those are attached to outbound requests and never
reach the server.) Choose *Custom* network access, add `saihm.net`, and check
*Also include default list of common package managers*, so `npx` can still reach npm.
Then pass the values through the repository's `.mcp.json`:

*The `.mcp.json` block for this host is in the [README](./README.md#hosted-agent-environments).*

The `:-` form passes an unset variable as empty, which the server treats as unset
for these five, so the same file still works on your own machine. In that
repository Claude Code uses this entry in place of any `saihm` entry in your user
settings. Carry over only non-secret settings (`SAIHM_TIER`, `SAIHM_PAYMENT_METHOD`,
and `SAIHM_ENDPOINT_URL` written as the URL itself, or left out: an empty endpoint
is refused rather than defaulted) — never `SAIHM_MASTER_SECRET_FILE` or `_HEX`,
which would either commit your key or clash with the token. To keep your own machine's setup
in that repository, add it at local scope (`claude mcp add --scope local …`), which
takes precedence over `.mcp.json`. Project servers load in cloud sessions with a
single repository. A committed `.mcp.json` adds the server for everyone who uses the
repository; your identity stays in your environment's settings. Every command the
session runs can read these variables. If the `saihm` tools do not appear, check the
file as under [Claude Code](#claude-code-anthropic): `claude mcp list` in the session,
`python3 -m json.tool .mcp.json > /dev/null && echo valid` (never print the file), and no
non-breaking spaces (U+00A0) pasted into it.
`MCP_TIMEOUT=60000` in the environment variables gives the server longer to start.

### GitHub Copilot cloud agent

Store the values as Agents secrets (repository
*Settings → Secrets and variables → Agents*) named `COPILOT_MCP_SAIHM_IDENTITY` and
`COPILOT_MCP_SAIHM_IDENTITY_PASSPHRASE`; only Agents secrets with that prefix can be
passed to an MCP server, and GitHub documents them as available to MCP servers only, not
to the agent's own environment. The server still runs in that environment, beside every
command the agent runs: use this only in a repository whose code you trust.
Map them in the repository's MCP configuration (*Settings → Copilot → MCP
servers*):

*The configuration block for this host is in the [README](./README.md#hosted-agent-environments).*

Copilot runs the listed tools without asking, so this list leaves out
`saihm_forget` and the sharing tools; add them only if you want the agent to erase
or share without confirmation. GitHub applies this configuration to Copilot code
review too, and by default lets a review call the read-only tools (`saihm_recall`,
`saihm_status`) on any pull request in the repository, so your memories could
reach review comments. Unless you want that, turn off the repository setting
**Allow Copilot to use MCP tools when reviewing pull requests**; that also stops
reviews calling the default GitHub and Playwright MCP servers.

### Elsewhere, including other clients' cloud agents

This should work on any host
that runs local MCP servers, lets the server read both variables, and lets it reach
`saihm.net` (and `registry.npmjs.org`, for `npx`). Put the two values in the host's
own secrets or environment settings, and add `SAIHM_EPHEMERAL_HOME=1` there if its home
directory does not persist. Use settings scoped to you alone, never ones shared with a
team, in an environment only you use and for repositories you trust: the agent, and
every command it runs, may be able to read them. Not verified on other hosts. Hosts
that only connect to remote MCP servers cannot run this package.

### Temporary home directories

Where the home directory is temporary, or is a CI runner's home that later jobs can reach,
the join refuses to create a key there — where it can tell: in a session a host marks as
hosted or CI (`CLAUDE_CODE_REMOTE`, `GITHUB_ACTIONS`, `CI`, or a CI runner's own marker,
listed under `SAIHM_EPHEMERAL_HOME` in [Configuration](#configuration)), or wherever
`SAIHM_EPHEMERAL_HOME` is set to anything but `0`/`false`/`no`/`off`. A key there would be
lost with the session, or left where later jobs could read it. Join on your own computer
instead, and bring the identity in; a CI job can take its own key file, as a secret file
named by `SAIHM_MASTER_SECRET_FILE`. Nothing an agent passes to `saihm_join` overrides the
refusal; setting `SAIHM_EPHEMERAL_HOME=0` in the environment's settings does, and declares
a home that is kept and that only you use, so set it only there. The `free-join` command
reads it from its own environment, so a command-line setting overrides it there (a person
still has to approve the sign-in). In a temporary home the client's local bookkeeping (the
anti-rollback marks, and the recall cache if one is turned on) also starts empty each
session.

## Troubleshooting

| What you see | Usual cause |
|---|---|
| No SAIHM tools appear, and no error anywhere | The client stopped waiting before `npx` finished its first download: keep the start-up setting in [your client's block](./README.md#add-saihm-to-your-ai-client). Then check the file is valid JSON |
| Every other tool vanished too | The settings file is no longer valid JSON: a trailing comma, or non-breaking spaces (U+00A0) from a copy and paste. Claude Code may replace a broken `~/.claude.json` with a fresh one and keep the original under `~/.claude/backups/`: fix that copy and put it back |
| The memory tools say the join is waiting for approval | Open the link the join gave, sign in, enter the code and approve. The join then finishes by itself, and the next memory call works |
| A memory call says a free join may still be waiting for approval | This identity has no free memory yet: approve the join you started (in a terminal or another session), or say *"Join SAIHM"*, which reuses the key that is there and shows its link and code. A paid identity needs `SAIHM_TIER` and `SAIHM_PAYMENT_METHOD` for its plan |
| "SAIHM could not sign in: too many sign-ins in a short time" | The sign-in that starts a session, or renews it, met the endpoint's limit. Wait the time it names, then try again |
| Tools appear but every call fails | `SAIHM_ENDPOINT_URL` unreachable |
| Every call fails behind a proxy | In a hosted environment, allow the endpoint's host in its network settings; otherwise check `HTTPS_PROXY` (an `http://` URL) and `NO_PROXY`. A network that inspects TLS needs its CA certificate, from its administrator, in a file named by `NODE_EXTRA_CA_CERTS` |
| "No SAIHM identity is configured" | Self-join is off (`SAIHM_SELF_JOIN=0`) and no identity is set here: set one, or remove that setting to join |
| A hosted session keeps asking to join | The environment has no identity of yours — see *Hosted agent environments* |
| A different memory than you expected | This machine has its own key rather than yours |
| `status` mentions `seq-state` | A small local safeguard file couldn't be read or written. Your memories are unaffected — see `SAIHM_SEQ_STATE_PATH` under [Configuration](#configuration) |
| `forget` worked but mentions a feed | The erasure stands — only the notification line couldn't be written. See `SAIHM_ERASURE_FEED` under [Configuration](#configuration) |
| `forget` says `reason=not-attested` | The endpoint could not make the erasure durable yet: forget the same id again later |
| `forget` says `reason=not-found` | No memory has that id: it was never written, or it was already erased |
| `forget` says `complete=false` and that no key destruction is attested | The endpoint reported the erasure without its record of the key's destruction (an endpoint that does not offer events for your own cells never sends one), so this client cannot point at the destruction. That is not to say none happened |
| A warm-start call says `warm_start_unavailable` | The endpoint does not serve warm start to this identity now, or is busy: start cold, and try again later. `features.warmStart` in `saihm_status` shows whether it is offered |
| A warm-start call says `warm_start_file_unsafe` | The warm-start folder or the payload file is not your user's alone (folder 0700, file 0600), is a link, has a second name, is not a folder or a regular file, or cannot be read; or the folder holds a folder, or sits beside another program's files: fix it, then call again |

## How it works

**In plain terms.** Your memories are encrypted on your machine before they are sent,
and decrypted on your machine after they come back. SAIHM stores them encrypted, with
the few routing details they need and each memory's key locked under yours (the
security model below lists what it holds). To erase something, that key is destroyed —
which is why erasing the stored memory is immediate and final rather than a promise that
a copy was deleted somewhere.

**For the technically inclined.**

- **Encrypt before send** — `remember` encrypts client-side; `recall` decrypts
  client-side. The plaintext of your memories, your master secret and your
  key-encryption key are never sent to the endpoint. When the recall cache is on (by
  default with a key file), your memories are also kept unencrypted on your device; see
  Local recall cache below.
- **Post-quantum** — ML-DSA-65 for identity and signing, ML-KEM-768 for
  authenticated sharing, via
  [`@saihm/client-pro`](https://www.npmjs.com/package/@saihm/client-pro).
- **Crypto-shred erasure** — `forget` destroys the endpoint-side wrapped
  data-encryption key, rendering the cell undecryptable (GDPR Art. 17).
- **Erasure that travels** — `forget` also appends one line to a per-identity
  feed, so anything that derived from a cell — an index, a mirror, an extracted
  fact — can be told to drop it too. An erasure that stops at this substrate is
  not an erasure. On by default; `SAIHM_ERASURE_FEED=0` in every AI client and
  app that runs SAIHM with your key on this device turns it off.
- **Standard transport** — `POST {method, params}` with
  `Authorization: Bearer <JWT>`; the endpoint binds your tenant from the JWT.
  HTTPS only, with loopback `http` permitted for local development.
- **Self-onboarding** — with no `SAIHM_AUTH_HEADER` set, the client proves control
  of your identity and mints its own short-lived token, refreshing transparently.
  You paste one config once and never re-paste a token. Cancelling a subscription
  stops the next refresh, so access ends naturally. With the key file in `SAIHM_HOME`,
  the token is kept for the next session on this device until it expires (see
  `SAIHM_SESSION_CACHE`).

### Security model

| Property | Guarantee |
| --- | --- |
| Confidentiality vs the endpoint | The endpoint holds ciphertext, wrapped DEKs, public keys and the routing details each cell needs, such as its id and time — no key able to decrypt. |
| Integrity / authenticity | Every cell is ML-DSA-65-signed over its contents, including the sequence number. |
| Anti-replay | The signed monotonic sequence is rejected by the endpoint if it does not strictly increase. |
| Tenant isolation | Your `agentIdHash` (the JWT `sub`) namespaces your state; a write whose signed identity differs from the JWT is rejected. |
| Authenticated sharing | Grantee public keys are pinned out-of-band and verified before any secret is bound to them; on the recipient side, `recallShared` pins the sharer's agent ID, checks that the sharer's key hashes to it before using that key, and verifies the share and cell signatures before returning any plaintext. |
| Erasure | Destroying the endpoint-side wrapped DEK crypto-shreds the cell. |
| Local recall cache | When the recall cache is on, every memory saved or read on this device and, after the first recall, all of your memories are also kept unencrypted in a mode-600 file in `SAIHM_HOME` (`~/.saihm` by default), one file shared by every process on the device that uses that key with the cache on. `forget` removes the memory from it, and `SAIHM_RECALL_CACHE` below says how to go without one. |
| Kept sign-in | With the key file in `SAIHM_HOME`, the short-lived sign-in token is kept in a mode-600 file beside the key, for the next session on this device. It holds no key, is used only for the endpoint, identity, plan and payment method it was issued for, and expires on its own. `SAIHM_SESSION_CACHE=0` in every AI client and app that runs SAIHM with your key on this device keeps it in memory only. |
| Warm-start snapshots | Encrypted in this process under a fresh key per snapshot, which is wrapped under your key-encryption key and never stored unwrapped. The endpoint holds the ciphertext and the wrapped key. A forget that reaches your snapshots destroys them before it reports the erasure complete. |
| Erasure cascade | Each `forget` appends one line to `$SAIHM_HOME/tenants/<agentIdHash>/erasures.ndjson`. The line carries the cell id, the identity and the time — never cell content — and, beside `complete: false`, the `reason` the forget returns: `not-found` means there was nothing (more) to erase, not a failed erasure. With your own cells followed (`SAIHM_EVENTS=1`), erasures made elsewhere are added as they are reported. |

### Where encrypted cells are stored

This client encrypts cells and hands the ciphertext to whichever operator endpoint
`SAIHM_ENDPOINT_URL` points at; **that operator chooses and configures the durable
storage behind it** — typically a local IPFS / Kubo node first, then a Filecoin
deep-archive provider. Storage is operator-configured **by design**: the protocol
never locks anyone to a single provider. Running your own endpoint means
provisioning that storage yourself.

Prefer not to run storage at all? The hosted operator at
<https://saihm.net> provides durable storage and is **non-custodial** —
because this client encrypts every cell locally, the hosted operator never holds a
key that can open your memories.

## Configuration

Most people need none of this: the client blocks in the README set one variable, and
the rest have working defaults.

| Env | Required | Meaning |
| --- | --- | --- |
| `SAIHM_ENDPOINT_URL` | no | `https://…/mcp` (or `http://` for `127.0.0.1`/`localhost` only). **Defaults to `https://saihm.net/mcp`** — set it only to reach a different operator. Versions 0.11.1 and earlier defaulted to `saihm.coti.global`, which is being retired. |
| `SAIHM_MASTER_SECRET_FILE` | see note | Path to a **mode-600** file holding the hex master secret. **The preferred way to supply a key**, because it keeps the key out of a config file that may be synced or shared. Takes precedence over `SAIHM_MASTER_SECRET_HEX`. Cannot be combined with `SAIHM_IDENTITY`. |
| `SAIHM_IDENTITY` | see note | An identity token written by `export-identity`: your key, sealed. Set it with `SAIHM_IDENTITY_PASSPHRASE` to use that identity without a key file — see *Hosted agent environments*. Cannot be combined with either master-secret variable; blank counts as unset. |
| `SAIHM_IDENTITY_PASSPHRASE` | with `SAIHM_IDENTITY` | The passphrase `export-identity` generated for that token. The two together are your identity: store them as secrets, never in a chat or a committed file. |
| `SAIHM_MASTER_SECRET_HEX` | see note | The master secret inline, ≥ 64 hex characters (≥ 32 bytes), high-entropy, client-held, never sent. Prefer the file form: anything inline lands in the config file itself. |
| `SAIHM_SELF_JOIN` | no | Controls the `saihm_join` onboarding tool — the one that answers *"Join SAIHM"*. **On by default**; set to `0` to remove it and expose only the canonical eight tools. |
| `HTTPS_PROXY` / `NO_PROXY` | no | An HTTP proxy for reaching an `https://` endpoint, and the hosts to reach directly instead — `https_proxy`, or `HTTPS_PROXY` if that is unset (`HTTP_PROXY` is not used for https, as with npm and curl). Only an `http://` proxy URL is supported; any other fails with an error naming the setting rather than connecting directly. A network that inspects TLS presents its own certificate: get its CA certificate (PEM) from the network's administrator (never copy one from the connection itself), save it to a file and set `NODE_EXTRA_CA_CERTS` to that file's path in the server's environment; Node reads it at start. `NO_PROXY` (or `no_proxy`) takes `*`, host names, domain suffixes and ports. Loopback endpoints (`127.0.0.0/8`, `::1`, `localhost` and `*.localhost`) never use a proxy. Proxy credentials in the URL go to the proxy only and are never printed. |
| `SAIHM_EPHEMERAL_HOME` | no | Says whether this environment's home directory is temporary, discarded when a session ends, or a CI runner's home that later jobs can reach. Set it (e.g. `1`) where it is: the join then refuses to create a key there (it would be lost, or left where those jobs could read it), and SAIHM keeps no recall copy and no sign-in there by default. `0` declares a home that is kept and that only you use, and overrides a host's own signal: set it only there, never on a runner whose home later jobs can reach. Unset, SAIHM recognizes it where the host says so: `CLAUDE_CODE_REMOTE`, `GITHUB_ACTIONS` or `CI`, and on the runners that set no `CI`, by their own marker: Jenkins (`JENKINS_URL` with `BUILD_ID`), Azure Pipelines (`TF_BUILD`), TeamCity (`TEAMCITY_VERSION`), AWS CodeBuild (`CODEBUILD_BUILD_ARN`), Google Cloud Build (`BUILDER_OUTPUT`) and Bamboo (`bamboo_planKey`). On any other runner, and wherever the home folder outlives the job, set it to `1`. |
| `SAIHM_HOME` | no | Where the identity file lives (`$SAIHM_HOME/free-identity.key`, mode 600), where per-restart bookkeeping is kept, and where the erasure feed is written unless `SAIHM_ERASURE_FEED_DIR` overrides it. Defaults to `~/.saihm`. Give a full path: a JSON config does not expand `~`, so `~/.saihm` there is a relative path, and a relative path (or one that begins with a space) is refused at start. Versions before 0.13.0 used it, under the server's working directory: a key made there is still there, so move it into the full path you set. |
| `SAIHM_AUTH_HEADER` | no | `Bearer <JWT>`, used verbatim. **Omit to self-onboard** (recommended) — the client mints and refreshes its own token, so there is nothing to paste or re-paste. |
| `SAIHM_SESSION_CACHE` | no | Keeps your sign-in between sessions on this device. **On by default** for the key file in `SAIHM_HOME` (the one a join creates), except where the home is temporary or kept for later jobs (see `SAIHM_EPHEMERAL_HOME`): after a sign-in, the token is kept in `$SAIHM_HOME/session.<first 16 characters of your agent ID>.json`, readable only by your user (mode 600), and a new session on this device uses it until it expires instead of signing in again. That makes one sign-in per device rather than one per session, so a team behind one office address signs in far less often. The file holds the sign-in token, which expires on its own, and the endpoint, agent ID, plan and payment method it was issued for. It holds no key, so it cannot make another sign-in. A session uses it only for that same endpoint, identity, plan and payment method, and only from a file of your user's that no one else can read; a token the service refuses is removed, and anything else is replaced at the next sign-in. `0` keeps the sign-in in memory only, one per session, as before 0.14.3, and deletes the sign-in this identity kept here earlier when it next loads your key: that file only, and only while it holds a SAIHM sign-in for your agent ID. Set it to `0` in every AI client and app that runs SAIHM with your key on this device. An identity token, an inline secret and a key file kept elsewhere sign in once per session either way. |
| `SAIHM_TIER` | paid self-onboard; any self-onboard with `SAIHM_SELF_JOIN=0` | Plan label carried with each memory's routing details (`FREE`, `PRO`, …). Defaults to `FREE` while self-join is on (the default); set it for a paid plan, and with self-join off for every plan, `FREE` included. An `export-identity` token carries its own, which a non-empty value here overrides. With self-join off and a static `SAIHM_AUTH_HEADER`, resolved via `status()`. |
| `SAIHM_PAYMENT_METHOD` | paid self-onboard | Entitlement rail (`stripe`, `stablecoin`, …) for a paid plan: `stripe` for the card checkout that `upgrade` prints, which keeps the key you have and its memories; `stablecoin` for a plan paid on [the join page](https://saihm.net/join). Paying there starts a new identity with its own key, and the memories on a key you already have do not move to it, so upgrade an existing key with the card link. **Not used by the free tier.** Ignored when `SAIHM_AUTH_HEADER` is set. An identity token carries it; a non-empty value here overrides the token's. |
| `SAIHM_SEQ_STATE_PATH` | no | Overrides where the anti-rollback bookkeeping is written. Running as an MCP server this is **on by default** at `$SAIHM_HOME/seq.<id>.json`; set it only to relocate it. The default location is ours to manage: if it can't be written, the tally stays in memory for the session and `status` says so. A location **you** set is yours: if it can't be written, calls fail and name the path, so a safeguard you asked for never goes quiet without telling you. `status` reports this as `seq-state=…` followed by `rollback-guard=persisting` (writes still work, so the next one rewrites the file) or `memory-only-this-run` (it retries at the next restart). Either way, if the file couldn't be READ at startup the safeguard starts from scratch and rebuilds as each memory is next read — so an older copy of a memory would not be caught during that window. At the default location that window is about accidental corruption rather than an attacker: writing to that file takes the same access that reads the identity key sitting beside it. Somewhere you relocate it to, that no longer follows — give it the protection you give `$SAIHM_HOME`. Give a full path: a relative one resolves against the server's working directory. |
| `SAIHM_RECALL_CACHE` | no | Controls the recall cache: a copy of every memory saved or read on this device and, after the first recall, of all your memories, kept so that recall asks the service only for memories that are new or have changed, on this device or another. **On by default** when your key comes from a key file: the self-join identity file in `SAIHM_HOME`, or the file `SAIHM_MASTER_SECRET_FILE` names, wherever it is (from 0.14.3; before, only the first), as long as files can be written in `SAIHM_HOME` (where they cannot, recall fetches every memory, as with the copy off) and the home is not temporary or kept for later jobs (a hosted agent session or a CI runner, as `SAIHM_EPHEMERAL_HOME` describes: there a copy is made only at a `SAIHM_RECALL_CACHE_PATH` you set); `0` stops making one. Every process on this device that uses your key with the cache on writes the same file, so set `0` in every AI client and app that runs SAIHM with your key on this device; the README's [How it works](./README.md#how-it-works) has the steps to turn the copy off everywhere and delete one already written. The copy is kept unencrypted, so recall can use it at once, in a file readable only by your user (mode 600) in `SAIHM_HOME`; `forget` removes a memory from it, and a memory erased from another device leaves it at the next successful recall. A memory erased on this device and then saved again elsewhere may not show in a recall here. |
| `SAIHM_RECALL_CACHE_PATH` | no | Where the recall cache is written. **With a cache, a recall first checks each memory's version with the service and fetches only what is new or has changed since the last one; without a cache it fetches every memory, every time.** The cache is a file, so it survives a restart: only the very first run, which builds it, pays the full fetch. If the service offers no version check, the recall fetches every memory; if the check fails, the recall reports the error. It never answers from the cache unchecked. The cache defaults ON for an identity that boots from a key file: the one in `$SAIHM_HOME`, or one `SAIHM_MASTER_SECRET_FILE` names anywhere (from 0.14.3; before, only the first), except where the home is temporary or kept for later jobs (see `SAIHM_EPHEMERAL_HOME`), where only a path set here makes one. It is then written in `$SAIHM_HOME`, beside the sequence marks. For an identity token or an inline secret, which usually run where the home folder is not kept, it is OFF unless you set this, and the client says so once on its first recall. The copy is kept unencrypted, in a file only your user can read, so a recall can use it at once. `SAIHM_RECALL_CACHE=0` turns it off in every case, an explicit path included, and silences the notice. To keep no copy, set it in every AI client and app that runs SAIHM with your key on this device. Give a full path: a relative one resolves against the server's working directory. |
| `SAIHM_STATE_DIR` | no | Where transient operator state (such as `checkout-url.txt`) is written. Does **not** relocate your identity or its bookkeeping. Give a full path: a relative one is refused at start. |
| `SAIHM_ERASURE_FEED` | no | Controls the erasure feed — one line appended per `forget`, so a consumer can drop whatever it derived from that cell. **On by default**; set it to `0` in every AI client and app that runs SAIHM with your key on this device to write nothing. Writing the line can never fail an erasure: the erasure is what you asked for and the line is a notification about it, so a feed that can't be written is reported beside the result and the erasure still stands. With `SAIHM_EVENTS=1`, `0` also means the own-cell kinds are never asked for, and while the endpoint offers them this process writes no `share-states.json` (the file would vouch for change files it does not write). |
| `SAIHM_EVENTS` | no | Set to `1` to follow share events: from the moment the server starts, it long-polls the endpoint for shares made to you (new, updated, stale, ended, erased), and for changes to your own cells when the endpoint offers them (one process per identity and directory then writes `changes.ndjson`, rotating it and `erasures.ndjson`: see *Changes to your own cells* below). `saihm_recall` then returns a summary as `shareStates` when it lists memories, beside `shared`, with every entry when the call passes `shareEntries: true`, and the map is written to `share-states.json` beside the erasure feed for other processes to read (see *Following shares* below). **Off by default.** The map and the position in the feed survive a restart (see `SAIHM_SHARE_MAP_STORE`); a sender is marked verified only after a shared memory is read and its signature checked. Endpoints that do not offer events are left alone. |
| `SAIHM_SHARE_MAP_STORE` | no | Where the share feed keeps its position between runs: `file` (the default) writes `feed-state.json` beside the erasure feed, so a restart asks the endpoint only for what it missed; `off` keeps everything in memory, and the client fetches the whole share listing at every start. A root that cannot be written falls back to memory on its own, so this needs no setting where there is nowhere to write. Only read when the feed is on. |
| `SAIHM_ERASURE_FEED_DIR` | no | Overrides the feed's root. Defaults to `SAIHM_HOME`, then `~/.saihm`; the feed itself is at `<root>/tenants/<agentIdHash>/erasures.ndjson`, and the directory is created the first time a tool runs. Must be an **absolute** path — a relative one resolves against the working directory, so one identity would write to a different file depending on where the process started while a consumer reported the feed missing. Deliberately **not** `SAIHM_STATE_DIR`: a feed is identity-scoped, so it has to move with the identity or not at all, and a consumer refuses a line from an identity it is not watching. |

*Note:* a master secret is required, from one source or the other — but setup
creates and configures it for you, which is why the client blocks in the README have neither.

## For developers

The [README](./README.md#for-developers) shows the client library in action; this section covers the rest.

The derived `saihm.agentIdHash` is the `sub` the endpoint binds your tenant to —
when self-onboarding the client proves it via ML-DSA; with a static
`SAIHM_AUTH_HEADER` it must equal the JWT `sub`. Publish `saihm.identityRecord` so
other agents can share to you, or have the `identity-record` command write it, with the
agent ID, to a file (see [Your identity record, for sharing](#your-identity-record-for-sharing)).

Constructing `SaihmProClient` directly writes nothing to your home directory; the
per-restart bookkeeping is opted into by the MCP server's boot path, or by setting
`SAIHM_SEQ_STATE_PATH` explicitly.

### Following shares (optional)

Set `SAIHM_EVENTS=1` (or call `saihm.startShareEvents()` in your own process; `saihm.stopShareEvents()` stops it), and
the client keeps a live map of the memories other agents have shared with you. Read it with `saihm.shareStates()`, or
from `shareStates` in a `saihm_recall` result that lists memories.

| Summary field | Meaning |
|---|---|
| `complete` | `true` once the map holds every share made to you |
| `since` | When the map was first complete. It is kept across restarts, so it can be earlier than `startedAt` |
| `asOf` | When the endpoint last brought the map up to date; `null` until then |
| `startedAt` | When this process started following |
| `stopped` | Why following stopped: `unsupported` (the endpoint offers no feed), `tier` (the plan has none) or `erased` (the identity was erased); `complete` is then false |
| `counts` | How many entries are `live`, `stale`, `ended` and `erased` |

Pass `shareEntries: true` to get the entries too; without it they are absent, which is not the same as empty. Each
entry gives the sharer, the cell, its `status`, the grant, the sharer's latest `seq` and `commitment` when known, and
`senderVerified`, true once a read has checked the sharer's signature. Times are ISO-8601 UTC with milliseconds.

Read the map safely:

- Treat a cached copy of a shared memory as erased when its entry is `erased`, or when the copy was made before the
  entry's `copiesInvalidBefore` plus 5 minutes (for clock skew). An entry whose `endedBy` is `reconciliation` may have
  been erased rather than revoked: treat its copies as possibly erased.
- Conclude anything from a missing entry only when `since` is set and `complete` is true. Only a complete map is a
  baseline for comparing later maps.
- The map is only as fresh as `asOf`, which stops moving while the network is down. After a restart the map is not
  complete until the endpoint has answered.

**Other programs** can read the same map from `share-states.json` in `<root>/tenants/<agentIdHash>/`, where `<root>` is
`SAIHM_ERASURE_FEED_DIR`, else `SAIHM_HOME`, else `~/.saihm`. The file is owner-only and rewritten after each change and at least
once a minute; its `asOf` shows its age. When several processes of one identity write it, the newest map wins. While your own
cells are followed (next section), only the one writer described there writes it. No file means no feed has run there.

**Restarts.** The feed position is saved in `feed-state.json` beside it, so a new process asks only for what it missed.
Nothing in that file is trusted: a state that is unusable or older than the endpoint keeps events for is ignored, and
the client starts fresh. `SAIHM_SHARE_MAP_STORE=off` keeps the position in memory only, and so does a root
that cannot be written.

**Shared reads** (`saihm_recall` with the sharer and the cell) return the `commitment` of the version opened and, when
the endpoint sends it, the `grant` that served it, so a copy matches its entry exactly. The row also carries `sharer`, the
agent ID the read was pinned to, and `owner: "another-agent"`, and the text names that agent ID beside its label, so the
memory is marked as another agent's in both parts of the result.

**Every share, page by page.** Where `saihm_status` offers `features.sharesPaged`, `saihm_recall` with
`sharesOnly: true` (and only `after`) lists every memory shared with you, by sharer and then by cell, without reading
any of them: pass `next` back as `after` until it is null, and conclude nothing from a missing share before the last
page. A page carries `shared`, `next`, `sharedSkipped` (pointers left out because a field is longer than the client
carries, the same ones on every pass) and `total` (the endpoint's count, never a sign that a pass is complete), and
never `sharedTruncated`. Without the offer it answers `shares_paging_unsupported`: recall without it. Where it is
offered, the map reconciles page by page too, and `saihm.listAllShares()` reads every page for a program, with
`complete: true` only when it read them all in order.

### Changes to your own cells (optional)

When the endpoint also offers events for your own cells (its `events` capability lists both `cell-written` and
`cell-erased`), `SAIHM_EVENTS=1` follows them too. Programs running beside the client then learn of every write and
erasure, by any process or device of your identity, without polling. They arrive in two files, `changes.ndjson` and
`erasures.ndjson`. With the erasure feed off (`SAIHM_ERASURE_FEED=0`) none of this runs, and while the endpoint offers
these events that process writes no `share-states.json`.

- **One writer.** Only the process holding `feed.lock` in `<root>/tenants/<agentIdHash>/` writes these files; it
  refreshes the lock every 10 seconds. If the lock goes 30 seconds without a refresh, or 20 when its process on this
  machine has gone, another process takes over from the saved position. The other processes still record their own
  erasures in `erasures.ndjson` and report the writer's map.
- **`changes.ndjson`.** Each line has `v`, `kind`, `agentIdHash` and `at`, and is one of three kinds:
  - `cell-written` (`cellId`, `seq`, `commitment`, `source`): a new version of one of your cells, your own writes
    included. Compare `seq` and `commitment` with what you hold to skip your own.
  - `position` (`cursor`): everything up to here is covered.
  - `gap` (`cursor`, `reason`): events before here may be missing. Whatever the reason, reconcile with the version
    listing, taken after you read the gap.
- **`erasures.ndjson`.** Besides each `forget`'s own line, a line with `source: "server-event"` arrives for every
  erasure made elsewhere (a repeat of one made here is harmless), with `at` for the erasure and `receivedAt` for its
  arrival. `complete: true` always comes with its `destructionAnchor`. With `complete: false`, `reason` is `not-found`
  (nothing more to erase, which is not a failure) or `not-attested` (not durable yet), or is left out when the event
  gives neither.
- **Reading order.** A `position` covers every line above it in `changes.ndjson` and every line already in
  `erasures.ndjson`, so read `erasures.ndjson` to its end before acting on it. After a restart, lines may repeat but
  are never lost, and every line is safe to apply twice.
- **Liveness.** `share-states.json` is rewritten after every answer, so an `asOf` older than the endpoint's longest wait
  plus a round trip means the files say nothing about what has not changed. A map that is `complete` while `asOf` is
  still `null` (after a restart or takeover) is not live yet.
- **Rotation.** Past a few megabytes, a file moves to `.1` (replacing the previous one) and a `rotation` gap appears in
  `changes.ndjson`. If you resume by byte offset, compare the file's first line too: when it differs, or the fresh file
  is not there yet, finish the `.1` file first, then read the new one from its start. This applies to both files.
- **Lines are hints.** If a cell named by a `cell-written` line cannot be read, treat it as erased only when an erasure
  line names it.

**Through the tools.** `saihm_recall` with `cellId` alone reads one of your cells. With `listOnly: true` it lists your
cells' versions (`cellId`, `seq`, `commitment`) a page at a time: pass `next` back as `after` until it is null, and
conclude nothing from a missing cell before the last page. Two versions are equal only when `seq` and `commitment` both
match. Recalled memories carry their `commitment`; a `saihm_remember` result carries `commitment` (also as the
deprecated `commitmentHash`) and, when the endpoint gives it, its commit time `at`.

### Warm start (optional)

When the endpoint offers it, a program beside the client (SHM, for one) can keep an encrypted snapshot of its own
state and restore it in a new session or on another device, then catch up from the change feed instead of starting
over. `saihm_status` shows the offer as `features.warmStart`, with its limits: read them there. While this client
serves that offer, it adds `"token": "required"` to it. Without an offer, a warm-start call reaches none of the
endpoint's warm-start routes: it answers `warm_start_unavailable`, or an earlier refusal of its input or folder
(below). Everything else works as before.

Payloads pass through files in `<root>/tenants/<agentIdHash>/warm-start/`, the folder beside the event files above,
private to your user (0700). Each call names its file by a `token` you choose at random for that call: 16 to 32
characters from `a-z` and `0-9`. Two processes of one identity therefore never read each other's payload.

| Call | What it does | Result |
|---|---|---|
| `saihm_remember` with `warmStart: "put"`, `coversThrough` and `token` | Encrypts `put-<token>.bin` here, stores it as a snapshot covering that position of the change feed, and removes the file, whether or not the upload succeeds | `snapshotId`, `createdAt`, `bytes`, `coversThrough` |
| `saihm_recall` with `warmStart: "latest"` and `token` | Restores the newest snapshot into `latest-<token>.bin`: read it, then remove it | `snapshot`: those four fields, or `null` when there is none |
| `saihm_recall` with `warmStart: "list"` and `token` | Lists your snapshots, newest first | `snapshots` |
| `saihm_forget` with `warmStart: "delete"`, `snapshotId` and `token` | Destroys one snapshot, its key first | `deleted: true` |

- **One mode per call.** `warmStart` takes only the fields shown. Any other field, or a missing or malformed
  `token`, is refused (`invalid_input`, or the tool's input check) before any file is touched.
- **The files.** Write `put-<token>.bin` as a temporary file in the folder, then rename it. A payload file must be a
  regular file of your user's alone (0600) with one name and no link; anything else is refused with
  `warm_start_file_unsafe`. Every warm-start call first removes the files in the folder older than five minutes,
  temporary files included, so a crash never leaves a payload behind for long. A put takes its own `put-<token>.bin`
  whatever its age. Keep nothing else there.
- **`coversThrough`** is the `cursor` of a `position` marker in `changes.ndjson` whose lines you have applied, or of a
  `gap` marker once you have reconciled after it. A put whose position precedes an erasure that reached you answers
  `snapshot_superseded`: apply what follows, then take a new snapshot.
- **Restoring is all or nothing.** Every part is checked against its digest and opened before the payload file is
  written. Any failure writes nothing and answers an error: start cold, as with no snapshot.
- **Encryption.** Each snapshot has its own key, wrapped under your key-encryption key. Each part is sealed on its own
  and bound to your identity, the position, the snapshot and its place in it, so a part that is moved, dropped or
  taken from another snapshot fails the restore. The endpoint stores ciphertext it cannot read.
- **Errors** name `invalid_input`, `warm_start_unavailable`, `warm_start_file_missing`, `warm_start_file_unsafe`,
  `snapshot_too_large`, `snapshot_superseded`, `snapshot_not_found`, `tier_required` and the endpoint's other codes,
  as `error` on the result (below).

From a program that holds the payload in memory, call `saihm.warmStartOffer()` and pass the offer to
`saihm.warmStartPut(offer, payload, coversThrough)`, `saihm.warmStartLatest(offer)`, `saihm.warmStartList(offer)` or
`saihm.warmStartDelete(offer, snapshotId)`; no file is involved.

### What the tools return

`saihm_remember`, `saihm_recall`, `saihm_status` and `saihm_forget` also return structured content, for programs that
read fields rather than text. No field is required, so a failed call, which carries only `error`, still matches its
schema. A field is absent, or null where it is always present, when the endpoint did not give it.

| Field | Returned by | Meaning |
|---|---|---|
| `error` | any failed call of the eight protocol tools | `{code, status}`, as in the text's `SAIHM error [code]`; status `0` when no answer arrived; `{code: "unknown", status: 0}` when the failure is not the endpoint's |
| `timing` | all four | `serverMs` (the endpoint's time), `totalMs` (this client's time, from request to last byte) and `admission` (`reserved` or `shared`); present when the endpoint sends timing |
| `features` | `saihm_status` | What this identity may use, passed on unread (check each shape yourself); `null` when the endpoint gives none. `features.warmStart.token` is this client's own: `"required"` while it serves that offer |
| `snapshotId`, `createdAt`, `bytes`, `coversThrough` | `saihm_remember` with `warmStart: "put"` | The snapshot stored (see *Warm start*) |
| `snapshot`, `snapshots` | `saihm_recall` with `warmStart` | The snapshot restored, or `null`; the snapshots listed |
| `deleted` | `saihm_forget` with `warmStart: "delete"` | `true` once the snapshot is destroyed |
| `servedBy`, `asOf` | `saihm_recall` | Where the answer was served (`origin` or a region id) and the origin time it reflects |
| `count`, `memories` | `saihm_recall` | The memories read, each with `cellId`, `seq`, `plaintext` and `commitment`. A shared read's row also carries `grant` (when the endpoint sends it), `sharer` (the agent ID the read was pinned to) and `owner: "another-agent"`; your own memories carry neither `sharer` nor `owner` |
| `shared`, `sharedTruncated`, `sharedKept` | a `saihm_recall` that lists memories | Pointers to memories shared with you (the endpoint's unverified claims, without content); whether the list was cut; which end was kept, `newest` or `oldest` |
| `shared`, `next`, `sharedSkipped`, `total` | `saihm_recall` with `sharesOnly` | One page of those pointers; the `after` for the next page, or null on the last; how many were left out for a field too long to carry; the endpoint's count (see *Following shares*) |
| `found` | `saihm_recall` with `cellId` alone | `true` when the cell was read; `false` when no cell has that id (never written, or erased), which is not an error; absent on other recalls |
| `complete`, `destructionAnchor`, `reason`, `sharesPurged`, `epoch`, `at` | `saihm_forget` | See *Forget* below |

Details:

- **Text-only failures.** A call the MCP library rejects before the tool runs (such as an argument of the wrong type)
  and a failure of `saihm_join` report in the text only.
- **Malformed values.** Timing the client cannot read is left out, and the text says `timing=(malformed)`. Unusable
  `features` arrive as `null`, with `features=(malformed)` in the text. An unusable `servedBy` reads `(malformed)`,
  never absent: absent means the endpoint does not say, and answers from the origin.
- **Timing.** When the endpoint sends only one of `serverMs` and `admission`, the other is null. A tool that calls the
  endpoint more than once reports its last call of its own kind: a `saihm_remember` that re-issues shares reports the
  write.
- **Recall.** On a version listing, `asOf` is when the origin began the listing. A full recall without the recall cache
  is a plain list and carries neither `servedBy` nor `asOf`. A shared read opens a pointer's memory and checks it.
- **Cut share lists.** A cut keeps one end of the list: once it leaves a pointer out, it keeps none after it. With
  `sharedKept: "newest"`, the kept pointers are the newest and everything left out comes after them. `sharedKept` is
  absent when the list was not cut, when no order was declared, and when a pointer the client could not carry was
  skipped before the cut. The text of a cut list names `sharesOnly`, which lists every pointer where it is offered.
- **Forget.** `complete` is true only when the answer carries the endpoint's record of the key's destruction,
  `destructionAnchor`: store it as sent, and compare it only for equality. With `complete: false`, `reason` says why
  when the endpoint names it: `not-found` (nothing more to erase, which is not a failed erasure) or `not-attested`
  (forget the id again later); the erasure line carries the same `reason`. `sharesPurged` and `epoch` match the text,
  and `at` is the endpoint's time of the erasure, or null. `complete: false` means the client cannot point at the
  destruction, not that none happened.

### Errors

Non-2xx responses throw `SaihmEndpointError` carrying `status` and a
typed `code` (e.g. `BLIND_BAD_EXPIRY`, `BLIND_STALE_SEQ`,
`governance_unavailable`). Branch on the code rather than the message.

## SHM and this client

With this server, [SHM](./README.md#shm--super-human-memory) works through your MCP
client: it runs the SAIHM tools and reads each result's structured content (see [What the tools return](#what-the-tools-return)).

- Before a session opens, SHM asks for your account status with `saihm_status`.
- It recalls by query with `saihm_recall`, reads the memories shared with you from the
  `shared` pointers, and writes the knowledge it derives back to SAIHM with
  `saihm_remember`.
- It checks what it holds against the version listing (`saihm_recall` with
  `listOnly: true`), and reads a list of shared pointers cut at the oldest end
  (`sharedKept: "newest"`) as incomplete rather than refusing it.
- It follows the files this client writes: the change feed (`changes.ndjson`), the erasure
  feed (`erasures.ndjson`) and the share states (`share-states.json`).
- When the endpoint offers warm start and this client states `token` in the offer, SHM restores
  its state at the start of a session (`saihm_recall` with `warmStart: "latest"`) and stores
  a new snapshot whenever its deployment calls for one (see [Warm start](#warm-start-optional)).
- Use this client at 0.13.0 or later with SHM: the version listing and `sharedKept` are
  new in 0.13.0.
