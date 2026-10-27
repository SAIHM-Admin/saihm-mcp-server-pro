# SAIHM — memory for AI agents

**Portable memory for AI agents.** Your assistant remembers what matters — across
sessions, across models, across vendors. Share a memory with someone else's
agent, take it back, or erase it for good.

[![npm version](https://img.shields.io/npm/v/@saihm/mcp-server-pro.svg)](https://www.npmjs.com/package/@saihm/mcp-server-pro)
[![license](https://img.shields.io/npm/l/@saihm/mcp-server-pro.svg)](./LICENSE)
[![Star on GitHub](https://img.shields.io/badge/GitHub-Star-181717?logo=github&logoColor=white)](https://github.com/SAIHM-Admin/saihm-mcp-server-pro)
[![Sponsor SAIHM](https://img.shields.io/badge/Sponsor-SAIHM-ea4aaa?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/SAIHM-Admin)
[![Subscribe on YouTube](https://img.shields.io/badge/YouTube-Subscribe-FF0000?logo=youtube&logoColor=white)](https://www.youtube.com/@SAIHM-Memory?sub_confirmation=1)
[![Follow on X](https://img.shields.io/badge/X-Follow-000000?logo=x&logoColor=white)](https://x.com/SAIHMemory)

<table>
  <tr>
    <td width="50%"><a href="https://www.youtube.com/watch?v=yCWfsGnp0rE"><img src="https://img.youtube.com/vi/yCWfsGnp0rE/maxresdefault.jpg" alt="Watch on YouTube: SAIHM Short Overview, 6 minutes" width="100%"></a></td>
    <td width="50%"><a href="https://www.youtube.com/watch?v=t3rXudDKank"><img src="https://img.youtube.com/vi/t3rXudDKank/maxresdefault.jpg" alt="Watch on YouTube: SAIHM Detailed Overview, 30 minutes" width="100%"></a></td>
  </tr>
  <tr>
    <td align="center"><b>▶ SAIHM Short Overview</b><br>6 minutes</td>
    <td align="center"><b>▶ SAIHM Detailed Overview</b><br>30 minutes</td>
  </tr>
</table>

**Enjoyed them?** Like the videos, [subscribe to the SAIHM channel](https://www.youtube.com/@SAIHM-Memory?sub_confirmation=1),
and turn on notifications with the bell 🔔 to hear about new videos and updates.

**Prefer to read?** [The SAIHM manual](https://saihm.net/manual) (PDF) is a
decision-maker's guide to SAIHM and [SHM](#shm--super-human-memory).

AI assistants forget everything when the session ends. SAIHM gives yours a memory
that doesn't — one that follows you to a different assistant, a different model,
or a different company's product.

**Encrypted before it leaves your machine.** Nobody else can read your memories — not
the storage, not SAIHM. There is nothing to switch on. With your key in a file, as in the
standard setup, SAIHM also keeps an unencrypted copy of your memories on your own device
for fast recall. Only your account can read it, and [one setting](#how-it-works) turns it
off.

## Start free — one command

```sh
npx -y @saihm/mcp-server-pro free-join
```

No card and no wallet. You need a browser and a GitHub account once, for a quick
sign-in that confirms you're a real person:

1. The command creates your key on this machine and shows a link and a short code. Its
   first run downloads the package, which can take a minute before anything appears.
2. Open the link, sign in to GitHub, enter the code and approve.
3. The command finishes by itself and shows where your key is saved.

**No GitHub account?** Start at <https://saihm.net/free> instead: you sign in with
Google or Microsoft, and the page gives you your new key as a file to download. Save it
as `~/.saihm/free-identity.key` (or in your `SAIHM_HOME`), where SAIHM finds it with no
setting, and keep it safe: it is the only key to your memory. On macOS or Linux,
`chmod 600 ~/.saihm/free-identity.key` makes it readable only by you. The settings the
page shows hold only `SAIHM_ENDPOINT_URL` and `SAIHM_TIER` set to `FREE`. Your key is
ready, so skip *"Join SAIHM"*: a join would make a second, different key.

Then [add SAIHM to your AI client](#add-saihm-to-your-ai-client), restart it, and say
**"Recall my SAIHM memories."** You're running.

**Prefer not to touch a terminal?** Install SAIHM in your AI client first: for Claude
Code that is the one command under [Claude Code](#claude-code-anthropic), and the other
clients are [below](#add-saihm-to-your-ai-client). Restart the client, then say **"Join
SAIHM"** to your assistant. It asks whether you already have a SAIHM identity, then runs
the same setup and gives you the same link and code to approve.

**If a join is interrupted**, join again on the same machine: it reuses the key it
already created, so you keep the same identity. To cancel a join, stop it and don't
enter the code; the code expires on its own. Keep the key file either way.
[Joining in detail](./REFERENCE.md#joining-in-detail).

## Add SAIHM to your AI client

The configurations below for Claude Code, Gemini CLI and the OpenAI Agents SDK are
presented as tested ([which clients are checked](./REFERENCE.md#which-clients-are-checked));
the others are documented from each vendor's own documentation. Every configuration is
subject to change at the vendor's discretion.

SAIHM runs on your machine as a local MCP server that your AI client starts with
`npx`, so you need Node.js 20.19 or later. The package is
[`@saihm/mcp-server-pro`](https://www.npmjs.com/package/@saihm/mcp-server-pro) on npm,
and the official [MCP Registry](https://registry.modelcontextprotocol.io) lists it as
`io.github.SAIHM-Admin/saihm-mcp-server-pro`.

Find your client below, add its block, and restart the client. Three tips:

- **Keep the file valid.** A trailing comma, or a non-breaking space copied from an
  email or a web page, makes a JSON settings file invalid. Paste through a plain-text
  editor.
- **Keep the start-up setting.** The first start downloads the package. Where a block
  sets a longer start-up time, keep it, so the tools appear on the first try.
- **Download it once first.** Run `npx -y @saihm/mcp-server-pro --version` in a
  terminal. It downloads the package, prints its version and exits, so the client's
  first start is quick.

Each block follows that client's own documentation. Before every release, the server
is started from these blocks in Claude Code, Gemini CLI and the OpenAI Agents SDK to
confirm it connects. Each client's fine print is in the
[reference](./REFERENCE.md#client-setup-in-detail).

**Adding another AI client on this computer?** It uses the key already in `~/.saihm` by
itself, so don't join again there: add its block, restart it and say *"Recall my SAIHM
memories."* If your key file is somewhere else, set the same `SAIHM_MASTER_SECRET_FILE` in
its block, and on a paid plan add `SAIHM_TIER` and `SAIHM_PAYMENT_METHOD` too.

### Claude Code (Anthropic)

One command adds SAIHM for all your projects:

```sh
claude mcp add --env SAIHM_ENDPOINT_URL=https://saihm.net/mcp --transport stdio --scope user saihm -- npx -y @saihm/mcp-server-pro
```

If the tools don't appear after the first start, give the server more time:
`MCP_TIMEOUT=60000 claude`, or run `npx -y @saihm/mcp-server-pro --version` once in a terminal and
start Claude Code again. `claude mcp list` shows whether it connected. For Claude
Code on the web, see [Hosted agent environments](#hosted-agent-environments).

### Claude Desktop (Anthropic)

Open **Settings > Developer > Edit Config**, add the `"saihm"` entry inside
`mcpServers`, then quit and reopen Claude Desktop:

```json
{
  "mcpServers": {
    "saihm": {
      "command": "npx",
      "args": ["-y", "@saihm/mcp-server-pro"],
      "env": { "SAIHM_ENDPOINT_URL": "https://saihm.net/mcp" }
    }
  }
}
```

Claude Desktop starts the server with the Node.js installed on your machine, so
install Node.js first. If the tools don't appear the first time, run
`npx -y @saihm/mcp-server-pro --version` in a terminal, then quit and reopen Claude Desktop.

### Codex CLI (OpenAI)

Add this to `~/.codex/config.toml`, or to a project's `.codex/config.toml`:

```toml
[mcp_servers.saihm]
command = "npx"
args = ["-y", "@saihm/mcp-server-pro"]
env = { SAIHM_ENDPOINT_URL = "https://saihm.net/mcp" }
startup_timeout_sec = 60
```

Check it with `codex mcp list`, or `/mcp` inside Codex.

### OpenAI Agents SDK (Python)

```python
import asyncio
from agents import Agent, Runner
from agents.mcp import MCPServerStdio

async def main():
    async with MCPServerStdio(
        name="saihm",
        params={
            "command": "npx",
            "args": ["-y", "@saihm/mcp-server-pro"],
            "env": {"SAIHM_ENDPOINT_URL": "https://saihm.net/mcp"},
        },
        client_session_timeout_seconds=60,
    ) as saihm:
        agent = Agent(name="Assistant", mcp_servers=[saihm])
        result = await Runner.run(agent, "Recall my SAIHM memories.")
        print(result.final_output)

asyncio.run(main())
```

The 60-second timeout gives the first `npx` download time to finish. Pass secrets
from the environment, never as literals in your code.

### Gemini CLI (Google)

Add this to `~/.gemini/settings.json` (all projects) or `.gemini/settings.json` (one
project):

```json
{
  "mcpServers": {
    "saihm": {
      "command": "npx",
      "args": ["-y", "@saihm/mcp-server-pro"],
      "env": { "SAIHM_ENDPOINT_URL": "https://saihm.net/mcp" }
    }
  }
}
```

Or install the Gemini CLI extension, which carries the same entry:
`gemini extensions install https://github.com/SAIHM-Admin/saihm-mcp-server-pro`.

Run Gemini CLI in a folder you trust, since it starts local servers only there. Check
with `gemini mcp list`, or `/mcp` inside Gemini CLI.

Since 2026-06-18, Google no longer serves personal Google accounts in the Gemini CLI:
signing in with one answers "This client is no longer supported for Gemini Code Assist
for individuals". As of October 2026 the Gemini CLI still works with a Gemini API key,
or with a Gemini Code Assist Standard or Enterprise licence.

### Antigravity CLI (Google)

Add this to `~/.gemini/config/mcp_config.json` (all projects) or `.agents/mcp_config.json`
in a project:

```json
{
  "mcpServers": {
    "saihm": {
      "command": "npx",
      "args": ["-y", "@saihm/mcp-server-pro"],
      "env": { "SAIHM_ENDPOINT_URL": "https://saihm.net/mcp" }
    }
  }
}
```

Type `/mcp` inside Antigravity CLI to see whether it connected. If the tools don't appear
the first time, run `npx -y @saihm/mcp-server-pro --version` in a terminal, then reload the server there.

### Grok Build (xAI)

Add this to `~/.grok/config.toml`, or to a project's `.grok/config.toml`:

```toml
[mcp_servers.saihm]
command = "npx"
args = ["-y", "@saihm/mcp-server-pro"]
env = { SAIHM_ENDPOINT_URL = "https://saihm.net/mcp" }
startup_timeout_sec = 60
```

Grok Build also picks up an existing `saihm` entry from `~/.claude.json` or a
project's `.mcp.json`, so if you already added it for another client you may not need
this step. Check it with `grok mcp list`, or `grok mcp doctor saihm`.

### GitHub Copilot in VS Code (Microsoft)

Add this to `.vscode/mcp.json` in a workspace, or to your user `mcp.json` (run **MCP:
Open User Configuration**). VS Code uses `servers` here, not `mcpServers`:

```json
{
  "servers": {
    "saihm": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@saihm/mcp-server-pro"],
      "env": { "SAIHM_ENDPOINT_URL": "https://saihm.net/mcp" }
    }
  }
}
```

Or add it to your user profile from a terminal (bash, zsh or Command Prompt):

```sh
code --add-mcp "{\"name\":\"saihm\",\"command\":\"npx\",\"args\":[\"-y\",\"@saihm/mcp-server-pro\"],\"env\":{\"SAIHM_ENDPOINT_URL\":\"https://saihm.net/mcp\"}}"
```

**MCP: List Servers** shows the server, and its **Show Output** action shows the log.
If the tools don't appear the first time, run `npx -y @saihm/mcp-server-pro --version` in a terminal,
then restart the server from **MCP: List Servers**.
For the GitHub Copilot cloud agent, see
[Hosted agent environments](#hosted-agent-environments).

### GitHub Copilot for enterprises (Microsoft)

If your company decides which MCP servers GitHub Copilot may run, an enterprise owner can
allow SAIHM:

1. If your company keeps an MCP allowlist, add SAIHM in the same form as the entries
   already on it, because in a list with command entries, Copilot can require every
   local server to match one.

   - In a list with command entries, add one with the command in this README's setup
     blocks:

     ```json
     { "serverCommand": ["npx", "-y", "@saihm/mcp-server-pro"] }
     ```

     VS Code's MCP server gallery installs SAIHM pinned to the current version and
     without `-y`, for example `["npx", "@saihm/mcp-server-pro@0.14.3"]`. Copilot matches
     the command and each argument exactly, so list each form your users run.
   - In a list without command entries, add `{ "serverName": "saihm" }`, and have your
     users add SAIHM with this README's setup blocks, which give it that name. A copy
     installed from VS Code's gallery carries a different name, so it doesn't match this
     entry.
2. Make sure the **MCP servers in Copilot** policy is on for your enterprise, or for the
   organizations that should use SAIHM.

If your company limits MCP servers to a registry, SAIHM's ID in the official MCP Registry
is `io.github.SAIHM-Admin/saihm-mcp-server-pro`. GitHub's
[guide to enterprise MCP allowlists](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/administer-copilot/manage-mcp-usage/configure-enterprise-allowlist)
covers the rest, including how entries are matched and how changes reach your users.

With a key file, as in the standard setup, SAIHM keeps an unencrypted copy of each user's
memories on their device for fast recall, readable only by their account. Users who prefer
not to keep one can turn it off, as [How it works](#how-it-works) describes; the allowlist
can't do this for them.

### Cline

Add the `"saihm"` entry inside the existing `mcpServers` object of Cline's MCP settings.
In the editor, open the Cline panel, select the **MCP Servers** icon, then **Configure >
Configure MCP Servers**. The Cline CLI reads `~/.cline/data/settings/cline_mcp_settings.json`,
or the file `CLINE_MCP_SETTINGS_PATH` names.

```json
{
  "mcpServers": {
    "saihm": {
      "command": "npx",
      "args": ["-y", "@saihm/mcp-server-pro"],
      "env": { "SAIHM_ENDPOINT_URL": "https://saihm.net/mcp" },
      "timeout": 60
    }
  }
}
```

`timeout` is in seconds in Cline: keep it, so the first `npx` download has time to finish.
After saving, restart the server from Cline's MCP settings if its tools don't appear, and
start a new session of the Cline CLI, which reads the file when it starts. If the tools
still don't appear, run `npx -y @saihm/mcp-server-pro --version` in a terminal once: it
downloads the package, prints its version and exits. Then restart the server again.

### Other MCP clients

For other clients that run local MCP servers from an `mcpServers` block, such as Cursor
or Windsurf, add the same `"saihm"` entry inside the existing `mcpServers` object. Keep a
start-up time of about a minute where your client has one, in the unit its documentation
gives. If the tools don't appear the first time, run `npx -y @saihm/mcp-server-pro --version`
in a terminal, then restart the client.

## Agent frameworks

Building agents in Python? The same encrypted memory plugs into the major frameworks. Each
adapter needs Node.js 20.19 or later, like this server, and encrypts inside your process,
so Python never holds a key.

| Framework | What you get | Install |
|---|---|---|
| LangGraph | A long-term memory store for your graph | `pip install saihm-langgraph` ([repository](https://github.com/SAIHM-Admin/saihm-langgraph)) |
| CrewAI | One memory your whole crew shares | `pip install saihm-crewai` ([repository](https://github.com/SAIHM-Admin/saihm-crewai)) |
| LangChain | Chat history you own | `pip install "saihm-adapters[langchain]"` |
| LlamaIndex | Chat memory, and a retriever for RAG | `pip install "saihm-adapters[llamaindex]"` and `[rag]` |
| AutoGen | A memory your agent owns | `pip install "saihm-adapters[autogen]"` |

[saihm-adapters](https://github.com/SAIHM-Admin/saihm-adapters) brings them all together, with live
demos.

## Things to say

You talk to your assistant in plain language and name SAIHM, and it picks the tools.
Name SAIHM each time: some assistants, Claude Code among them, keep notes of their own,
and a request that does not name SAIHM may go there. Some starters for a team:

> Liberally use SAIHM to maximize token economy. Recall by topic instead of re-reading files, and save each decision as we make it.

> Recall only my SAIHM memories about the billing service, then give me its open decisions and next steps in five bullets before we write any code.

> Remember in SAIHM as a decision record: webhook retries use idempotency keys, decided 2026-10-20 by Dana; revisit if duplicate charges exceed 0.1%.

> Set a SAIHM invariant: ask me twice before any SAIHM erase, and never store passwords, keys or customer personal data in SAIHM.

> Before we finish, save a SAIHM memory of what we changed, why, and what is still open, so any agent with my key can pick it up tomorrow.

> Share my SAIHM memory about the release runbook with the agent in ./identities/qa-agent.json, read-only, until Friday 17:00 UTC.

> A customer asked us to delete their data. Find every SAIHM memory that mentions Acme Corp, show me each one, and erase them one at a time after I confirm.

> In this CI job, recall the team's SAIHM memory "release rules" and fail the job if the changelog breaks any of them.

The sharing starter needs your colleague's identity record, which one command makes (see
[Share with a colleague](#share-with-a-colleague)). The CI starter needs the job's own
identity, set as in [Hosted agent environments](#hosted-agent-environments).

More prompts, and a case study of three agent roles doing the work of about twenty agents,
are in the [SAIHM manual](https://saihm.net/manual) and in [CASE-STUDY.md](./CASE-STUDY.md).

| Tool | What it does |
|---|---|
| `saihm_remember` | Encrypts on your machine, then stores it |
| `saihm_recall` | Fetches and decrypts on your machine |
| `saihm_forget` | **Permanently erases.** No undo |
| `saihm_status` | Your identity, plan and memory counts |
| `saihm_share` | Grants one memory to one agent, optionally with an expiry |
| `saihm_revoke_share` | Withdraws that grant |

Every tool is labelled for your AI tool to read, including which are read-only and
which one destroys data — so hosts that ask "are you sure?" before destructive
actions know when to ask. The reference has [the full tool list](./REFERENCE.md#tools).

**"Forget" really means forget.** The key to that memory is destroyed, so the stored
copy becomes permanently unreadable — by you, by SAIHM, by anyone holding a backup of
it. This is how SAIHM answers a GDPR Article 17 erasure request, and it is why there
is no undo. The answer confirms the erasure once the service's record of the key's
destruction comes back with it.

## Your memories follow your key

Your memory belongs to your key, not to a computer — that's what makes it portable.
The key is created on your machine and never sent anywhere, which is exactly why
nobody else can read your memories. **Keep a copy of the key file somewhere safe:**
SAIHM cannot make you another one. Setup shows where the file is, and upgrading to a
paid plan keeps the same key and every memory.

**Using a second computer, or a hosted agent?** Three ways:

- **Same memory, anywhere** — on the machine that has your key, run:

  ```bash
  npx -y @saihm/mcp-server-pro export-identity
  ```

  It saves two values to a file only you can read: `SAIHM_IDENTITY` (your key,
  sealed) and `SAIHM_IDENTITY_PASSPHRASE` (the passphrase that opens it). Set both as
  environment variables or secrets wherever the memory should follow you, then start
  a new session. Don't say *"Join SAIHM"* there: a join starts a new, empty memory.
  Together the two values **are** your identity: keep them in a password manager,
  never in a chat or a repository, and delete the export file. On a paid plan, see
  [exporting your identity](./REFERENCE.md#exporting-your-identity) first.
- **Copy the key file** — put it at `~/.saihm/free-identity.key` on the other machine
  (or point `SAIHM_MASTER_SECRET_FILE` at it) before the server starts, use the same
  settings as the first machine (on a paid plan, `SAIHM_TIER` and
  `SAIHM_PAYMENT_METHOD` too), and say *"Recall my SAIHM memories."*
- **Keep work and personal apart** — start fresh on the second machine and share
  across instead: *"Share these notes with my work agent until 5:00 pm."* A share can
  be revoked or given an expiry, so the two stay separate. Each side needs the other's
  identity record, made as below.

### Share with a colleague

To share a memory with a colleague's agent, ask them for their identity record. They make
it with one command, on the machine that has their key:

```sh
npx -y @saihm/mcp-server-pro identity-record qa-agent.json
```

It holds only their public keys and agent ID, so it is safe to send by email or chat:
nothing in it can read, change or erase their memory. Put the file in your project and
name it when you share, for example *"Share my SAIHM memory about the release runbook with
the agent in ./identities/qa-agent.json, read-only, until Friday 17:00 UTC."* To read what
you share, their agent needs your identity record too, made the same way. If the file
reaches you by a channel someone else could change, check the agent ID with your colleague
another way. The record is not the `export-identity` file: never send that one to anyone.

## Hosted agent environments

A hosted agent session usually starts on a fresh machine and discards its home
directory when it ends, so a key created there would be lost with it. Bring your
identity in instead: set the two `export-identity` values in the environment's own
settings — never in the chat — and start a new session, because the environment reads
its variables when a session starts. The server runs locally in the session and needs
to reach `saihm.net`, and npm for `npx`. The steps below follow each host's own
documentation; the [reference](./REFERENCE.md#hosted-agent-environments-in-detail)
covers proxies and the finer points.

- **Claude Code on the web** — add both values under the environment's *Environment
  variables*. Anyone who uses that environment can read them, so use a dedicated
  environment that only you use, for repositories you trust. Choose *Custom* network
  access, add `saihm.net`, and check *Also include default list of common package
  managers*, so `npx` can still reach npm. Then pass the values through the
  repository's `.mcp.json`:

  ```json
  {
    "mcpServers": {
      "saihm": {
        "command": "npx",
        "args": ["-y", "@saihm/mcp-server-pro"],
        "env": {
          "SAIHM_ENDPOINT_URL": "https://saihm.net/mcp",
          "SAIHM_IDENTITY": "${SAIHM_IDENTITY:-}",
          "SAIHM_IDENTITY_PASSPHRASE": "${SAIHM_IDENTITY_PASSPHRASE:-}",
          "SAIHM_TIER": "${SAIHM_TIER:-}",
          "SAIHM_PAYMENT_METHOD": "${SAIHM_PAYMENT_METHOD:-}",
          "CLAUDE_CODE_REMOTE": "${CLAUDE_CODE_REMOTE:-}"
        }
      }
    }
  }
  ```

  The same file still works on your own machine. Never add `SAIHM_MASTER_SECRET_FILE`
  or `SAIHM_MASTER_SECRET_HEX` to it: either would commit your key or clash with the
  identity. If the tools don't appear, run `claude mcp list` in the session, and set
  `MCP_TIMEOUT=60000` in the environment variables to give the server longer to start.
- **GitHub Copilot cloud agent** — store the values as Agents secrets (repository
  *Settings → Secrets and variables → Agents*) named `COPILOT_MCP_SAIHM_IDENTITY` and
  `COPILOT_MCP_SAIHM_IDENTITY_PASSPHRASE`. The server runs beside every command the
  agent runs, so use this only in a repository whose code you trust. Map the secrets
  in the repository's MCP configuration (*Settings → Copilot → MCP servers*):

  ```json
  {
    "mcpServers": {
      "saihm": {
        "type": "local",
        "command": "npx",
        "args": ["-y", "@saihm/mcp-server-pro"],
        "tools": ["saihm_recall", "saihm_remember", "saihm_status"],
        "env": {
          "SAIHM_ENDPOINT_URL": "https://saihm.net/mcp",
          "SAIHM_IDENTITY": "$COPILOT_MCP_SAIHM_IDENTITY",
          "SAIHM_IDENTITY_PASSPHRASE": "$COPILOT_MCP_SAIHM_IDENTITY_PASSPHRASE",
          "SAIHM_EPHEMERAL_HOME": "1"
        }
      }
    }
  }
  ```

  Copilot runs the listed tools without asking, so this list leaves out
  `saihm_forget` and the sharing tools. By default, Copilot code review can call the
  read-only tools on any pull request, so your memories could reach review comments:
  unless you want that, turn off **Allow Copilot to use MCP tools when reviewing pull
  requests**.
- **Elsewhere** — this should work on any host that runs local MCP servers, lets the
  server read both values, and lets it reach `saihm.net` and `registry.npmjs.org`. Put
  the values in the host's own secrets or environment settings, scoped to you alone, in
  an environment only you use: the agent, and every command it runs, may be able to
  read them. Add `SAIHM_EPHEMERAL_HOME=1` there if its home directory does not
  persist. Hosts that only connect to remote MCP servers cannot run this package.

Where it can tell that the home directory is temporary, a join refuses to create a key
that would be lost with it.

## See it run

- **Live demos across every major model** — offline, about a minute each, no
  account: <https://saihm-admin.github.io/saihm-demos/>. Store a memory in Claude, GPT,
  DeepSeek, Qwen, Kimi, or GLM, then prove you can erase it.
- **Token benchmark** — recalling a bounded set of memories instead of re-sending
  the whole conversation cut input tokens by **62.8%–85.9%** across a realistic
  multi-session task. Open, offline, reproducible:
  <https://github.com/SAIHM-Admin/saihm-token-benchmark>.

## What it costs

Start free. The free tier is a fixed, one-time allowance of writes, reads, and shares
for trying SAIHM on real infrastructure — it doesn't reset or refill. **No card, and
nothing to cancel.** Once it is used up you can still list your memories and erase them,
and upgrading keeps every one.

Paid plans are monthly; prices are on the [pricing page](https://saihm.net/pricing).
Upgrading keeps the same key and every memory you already have:

```sh
SAIHM_MASTER_SECRET_FILE=$HOME/.saihm/free-identity.key \
SAIHM_TIER=FREE \
  npx -y @saihm/mcp-server-pro upgrade PRO
```

That prints a checkout link tied to your identity, to open in a browser, and the two
lines to add to your client's `env` block once you have paid. Add both and restart the
client:

```json
"SAIHM_TIER": "PRO",
"SAIHM_PAYMENT_METHOD": "stripe"
```

A paid plan needs both lines: without `SAIHM_PAYMENT_METHOD`, which names the payment
rail to check, the server won't start. Then say *"Show my SAIHM status"* to see the plan.

| How you pay | Where | Your key and memories | `SAIHM_PAYMENT_METHOD` |
|---|---|---|---|
| Card, for the key you have | the `upgrade` command's link | kept | `stripe` |
| Card or another method on the website | the [join page](https://saihm.net/join) | a new identity with its own key | the one in the configuration the page gives you |
| Stablecoin | the [join page](https://saihm.net/join) | a new identity with its own key | `stablecoin` |

The memories on a key you already have stay on that key and do not move to a new one, so
to upgrade the key you have, use the card link.

## If something isn't working

| What you see | What to do |
|---|---|
| No SAIHM tools appear, and no error anywhere | The client stopped waiting before `npx` finished its first download. Keep the start-up setting in [your client's block](#add-saihm-to-your-ai-client), and check that the file is valid JSON |
| Every other tool vanished too | The settings file is no longer valid JSON: look for a trailing comma, or non-breaking spaces from a copy and paste |
| The memory tools say the join is waiting for approval | Open the link the join gave, sign in, enter the code and approve. The join then finishes by itself, and the next memory call works |
| A memory call says a free join may still be waiting for approval | Approve the join you started. Or say *"Join SAIHM"*: it reuses the key that is there and shows its link and code |
| SAIHM could not sign in: too many sign-ins in a short time | Wait the time it names, then try again |
| Tools appear but every call fails | The machine cannot reach the endpoint (`saihm.net`, unless you set another). In a hosted environment, allow it in the network settings |
| A hosted session keeps asking to join | The environment has no identity of yours: see [Hosted agent environments](#hosted-agent-environments) |
| A different memory than you expected | This machine has its own key rather than yours |

Proxies, erasure answers and everything else are in the
[full troubleshooting table](./REFERENCE.md#troubleshooting).

## How it works

Your memories are encrypted on your machine before they are sent, and decrypted on your
machine after they come back. SAIHM stores them encrypted, with the few routing details
they need and each memory's key locked under yours. To erase something, that key is
destroyed — which is why erasing the stored memory is immediate and final rather than a
promise that a copy was deleted somewhere.

- **Post-quantum by design.** ML-DSA-65 signs every memory, and ML-KEM-768 protects
  sharing.
- **Non-custodial.** The hosted service at <https://saihm.net> provides the durable
  storage, yet never holds a key that can open your memories.
- **Erasure that travels.** Each `forget` also writes a notice, so anything built from
  that memory — an index, a mirror, an extracted fact — can drop it too.
- **Fast recall on your device.** With your key in a file (the standard setup, or the
  file `SAIHM_MASTER_SECRET_FILE` names, wherever it is), SAIHM keeps a local copy of every
  memory you save or read on this device and, after the first recall, of all your
  memories. A recall then fetches only what is new or has changed, on this device or
  another, so it is faster and uses fewer reads. The copy is kept unencrypted on your
  device, in `~/.saihm` (or your `SAIHM_HOME`), so recall can use it at once, and only
  your user account can read it. `forget` removes a memory from it too, and your other
  devices drop it at their next successful recall. A memory erased on this device and
  then saved again elsewhere may not show in a recall here. Backups of your device keep
  the copy as it was when they were made. From 0.14.3, a key file kept anywhere has the
  copy, not only the standard one.
- **Everything encrypted at rest, if you prefer.** Set `SAIHM_RECALL_CACHE` to `0` in
  every AI client and app that runs SAIHM with your key on this device, in the same place
  as its `SAIHM_ENDPOINT_URL` setting and written the same way. Then quit all of them,
  every open session and window included, delete the files in `~/.saihm` (or your
  `SAIHM_HOME`) whose names start with `recall.`, and start them again. From then on SAIHM
  keeps no local copy, so every memory it holds at rest is ciphertext, and each recall
  fetches all your memories again. That is slower and, on a plan that limits recalls, such
  as the free tier, uses up its allowance faster. Add the setting to any client or app you
  set up later, too. If a `recall.` file ever comes back there, a client or app still has
  the copy on.

The [technical reference](./REFERENCE.md#how-it-works) has the security model, where
the encrypted memories are stored, and every setting.

## Configuration

Most people need none: the blocks above set the one setting that matters, and the
rest have working defaults. Every setting is listed in the
[reference](./REFERENCE.md#configuration).

## For developers

Use SAIHM from your own Node.js code. The
[developer reference](./REFERENCE.md#for-developers) covers identity records,
following shares, changes to your own cells, warm start, structured tool
results and errors.

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

// Update an existing cell (a fresh monotonic sequence is issued automatically). When the endpoint reports
// shares of the cell left on the previous version, `shares` in the result reports their re-issue.
await saihm.remember('new contents', { cellId });

// Forget — crypto-shred.
await saihm.forget(cellId);

// Share a cell with another agent, end-to-end authenticated. Pin the grantee's agentIdHash
// out-of-band; the library rejects directory key-substitution.
await saihm.share({
  cellId,
  recipientRecord, // the grantee's published identity record (hex fields), as `identity-record` writes it
  recipientPinnedAgentIdHashHex, // pinned out-of-band
  expiryEpoch, // optional whole HOURS since the UNIX epoch (498192n = 2026-11-01 00:00 UTC); omit or null for no time bound
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

## SHM — Super-Human Memory

SAIHM keeps memory safe. SHM, Super-Human Memory, makes it work efficiently: it is the
layer on top of SAIHM that organises memory and brings the right part of it forward, by
meaning, before the agent asks. It keeps tasks apart and the context
window clean, so one agent can take on work that today needs several, and a correction
saved once is recalled every time after.

SHM runs on your side, next to your agent, over the memories your agent can read, so none
of this requires your plaintext to leave home. It ranks them with hybrid retrieval and an
optional local reranker, brings forward only what the current task needs, within a budget
you set, and keeps what it stores encrypted under a key you hold. When a memory is erased
in SAIHM, SHM removes it from its index, its caches and everything it derived from it.

```sh
npm install @saihm/shm
```

SHM needs Node.js 20.20 or later.

**How SHM and this client fit together.** SHM works through this MCP server, version
0.13.0 or later, which keeps SHM in step with your SAIHM memory:

- The change feed tells SHM which of your memories were written, so SHM reads them
  again.
- The erasure feed tells SHM which memories were erased, so SHM removes them and
  everything it derived from them.
- Share states tell SHM which memories other agents have shared with you, and which of
  those shares have ended.
- Structured tool results give SHM each answer in a form it checks before acting on it.
- Warm start lets SHM save an encrypted snapshot of its state and pick up where it
  left off in a new session or on another device.

The [reference](./REFERENCE.md#shm-and-this-client) lists the tools and files SHM uses.

The [SAIHM manual](https://saihm.net/manual) covers both: chapter 4 for what SHM adds,
chapter 5 for its levers and recipes, and chapter 9 for why to choose SAIHM and SHM
together.

## Questions

Message SAIHM on WhatsApp at `@saihm.inc`, ask in the
[SAIHM community group on WhatsApp](https://chat.whatsapp.com/LYYL1MgKe3IE2hcR8qfErf), or write through
[saihm.net/contact](https://saihm.net/contact). SAIHM personnel never ask for your key
file; never send it to anyone.

## Support SAIHM

If SAIHM is useful to you, here is how to help it reach more people:

- **Star it on [GitHub](https://github.com/SAIHM-Admin/saihm-mcp-server-pro).** Stars help other developers find
  SAIHM.
- **Share it** with a colleague, your team, or anyone whose assistant keeps forgetting.
- **Follow [@SAIHMemory on X](https://x.com/SAIHMemory)** for news and updates.
- **Sponsor it** through [GitHub Sponsors](https://github.com/sponsors/SAIHM-Admin), monthly or one-time.
- **Follow along on YouTube:** like the videos,
  [subscribe to the channel](https://www.youtube.com/@SAIHM-Memory?sub_confirmation=1), and turn on notifications
  with the bell 🔔 for new videos and updates.

## Discount codes

Upgrading? Run the upgrade command in [What it costs](#what-it-costs), then enter one of these
codes in the promotion-code box at checkout:

| Code | Offer |
|---|---|
| `SAIHM-90-OFF` | 90% off your first payment, for new customers |
| `SAIHM-75-OFF` | 75% off your first payment |
| `SAIHM-50-OFF` | 50% off for four months |
| `SAIHM-25-OFF` | 25% off for six months |

One code per checkout, while the offers last.

## License

Apache-2.0 © SAIHM
