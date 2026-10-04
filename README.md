# SAIHM — memory for AI agents

**Portable memory for AI agents.** Your assistant remembers what matters — across
sessions, across models, across vendors. Share a memory with someone else's
agent, take it back, or erase it for good.

[![npm version](https://img.shields.io/npm/v/@saihm/mcp-server-pro.svg)](https://www.npmjs.com/package/@saihm/mcp-server-pro)
[![license](https://img.shields.io/npm/l/@saihm/mcp-server-pro.svg)](./LICENSE)

<a href="https://saihm.net/overview"><img src="https://saihm.net/media/saihm-short-overview-play.jpg" alt="Watch: SAIHM in 6 minutes" width="480"></a>

**New to SAIHM?** [Watch the 6-minute overview](https://saihm.net/overview) (captions and transcript), or [read the SAIHM manual](https://saihm.net/manual).

AI assistants forget everything when the session ends. SAIHM gives yours a memory
that doesn't — one that follows you to a different assistant, a different model,
or a different company's product.

Everything is encrypted on your own machine before it goes anywhere, so nobody
else can read your memories. Not the storage, not SAIHM.

## Start free — one command

```sh
npx -y @saihm/mcp-server-pro free-join
```

No card and no wallet. It does need you once, with a browser and a GitHub account, for
a one-time sign-in that confirms you're a real person:

1. The command creates your key on this machine and prints a link and a short code.
2. Open the link in a browser, sign in to GitHub, enter the code and approve.
3. The command then finishes by itself and prints where your key is saved.

No GitHub account? Start at <https://saihm.net/free> instead. It signs you in with
Google, in the browser, and then shows a configuration that holds your new key. Save
the key to a file only you can read and set `SAIHM_MASTER_SECRET_FILE` to that file's
path in your client's block below. Never put the key itself in a settings file, least of
all one in a project or workspace, which can be committed with a repository. Do not ask
your assistant to join: that makes a different key, and its approval needs GitHub.

Then [add SAIHM to your AI client](#add-saihm-to-your-ai-client), restart it, and say
**"Recall my SAIHM memories."** You're running.

**Prefer not to touch a terminal?** Add SAIHM to your client first, then say **"Join
SAIHM"** to your assistant. It runs the same setup and gives you the same link and code
to approve.

**If a join stops before you approve it.** A join, from the command or from *"Join
SAIHM"*, writes your key when it starts, before you approve. If the join stops while it
waits (the terminal closes, or the session ends), the key stays. Join again on the same
machine and follow its steps: it uses that same key, so it is the same identity, and it
writes no second key. While a join started by your assistant waits for approval, the
memory tools answer with its steps (an identity that was already active keeps working). To stop a join you don't want, stop the command
(Ctrl+C) or end the session, and don't enter the code; it expires after the time the
join shows. Keep the key file all the same: a later join on this machine uses it.

## Add SAIHM to your AI client

SAIHM runs as a local (stdio) MCP server that your client starts with `npx`, so the
machine needs Node.js 20 or later. The package is on npm as
[`@saihm/mcp-server-pro`](https://www.npmjs.com/package/@saihm/mcp-server-pro), and in
the official [MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.SAIHM-Admin/saihm-mcp-server-pro`.

Each client below is marked *documented*: its steps follow that provider's own
documentation as of October 2026, and SAIHM has not tested them end to end. See
[Which clients are checked](#which-clients-are-checked).

Before you paste:

- **Valid JSON.** In a JSON settings file, a trailing comma, or a non-breaking space
  (U+00A0) copied from an email or a web page, makes the whole file invalid, and every
  server in it disappears.
  Paste through a plain-text editor, or retype the indentation.
- **Start-up time.** The first start downloads the package, which takes longer than
  some clients wait by default. Where a client needs a longer limit, its block below sets
  one: keep it. A server that misses the limit can be skipped **silently**: the tools
  never appear, and nothing in the chat says why.

> **Host note (2026-09-23).** From 0.11.2 the default endpoint is `https://saihm.net/mcp`. Versions 0.11.1 and earlier default to the previous host, `saihm.coti.global`, which serves the identical service until 2026-12-31 and is then discontinued: upgrade, or set `SAIHM_ENDPOINT_URL` explicitly. Every client block below sets it.

### Claude Code (Anthropic)

*Documented.* One command adds SAIHM for all your projects:

```sh
claude mcp add --env SAIHM_ENDPOINT_URL=https://saihm.net/mcp --transport stdio --scope user saihm -- npx -y @saihm/mcp-server-pro
```

For one repository only, leave `--scope` out: the entry then applies to the project you
run it in, for you alone. `--scope project` writes it to the repository's `.mcp.json`
instead, shared with everyone who uses the repository. If the tools are missing after the first start, give the server
longer to start: `MCP_TIMEOUT=60000 claude` (milliseconds).

**Check the setup.** `claude mcp list` shows whether each server connected, and says so
when a config file is not valid JSON. If the broken file is `~/.claude.json`, Claude Code
may replace it with a fresh one, without your servers (`claude mcp list` does; an
interactive session asks first), and keep the original under
`~/.claude/backups/`: fix that copy and put it back. To check a file yourself without printing it, run
`python3 -m json.tool <file> > /dev/null && echo valid` on it (on Windows, in Command Prompt: `py -m json.tool <file> > NUL && echo valid`, writing `"%USERPROFILE%\.claude.json"` for `~/.claude.json`; `~/.claude.json` for the
command above, or a repository's `.mcp.json`): it prints `valid`, or the line and column of
the first error. Never print a config file into a chat or an agent's
session: it can hold other servers' keys. A config copied from an email or a web page
can carry non-breaking spaces (U+00A0) in its indentation, and JSON rejects them.

Claude Code on the web (cloud sessions): see
[Hosted agent environments](#hosted-agent-environments).

### Claude Desktop (Anthropic)

*Documented.* In Claude Desktop, open **Settings > Developer > Edit Config**. It opens
`claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`, Windows:
`%APPDATA%\Claude\`). Add the `"saihm"` entry inside `mcpServers`, then quit and reopen
Claude Desktop:

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

This starts the server with the Node.js installed on your machine, so install it first.
If the server does not connect, its log is `mcp-server-saihm.log` in
`~/Library/Logs/Claude` (macOS) or `%APPDATA%\Claude\logs` (Windows).

### Codex CLI (OpenAI)

*Documented.* Add this to `~/.codex/config.toml`, or to a project's `.codex/config.toml`:

```toml
[mcp_servers.saihm]
command = "npx"
args = ["-y", "@saihm/mcp-server-pro"]
env = { SAIHM_ENDPOINT_URL = "https://saihm.net/mcp" }
startup_timeout_sec = 60
```

Codex waits 10 seconds for a server to start unless `startup_timeout_sec` says
otherwise; a server still starting may miss the first message's tools and appear from the
next one. A project's `.codex/config.toml` is read only once you trust the project. It passes the server only a few basic variables (such as `HOME` and `PATH`);
to pass another from your shell, such as `HTTPS_PROXY`, name it in
`env_vars = ["HTTPS_PROXY"]`. Check with `codex mcp list`, or `/mcp` inside Codex.

### OpenAI Agents SDK (Python)

*Documented.*

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

The SDK waits 5 seconds for each server reply by default, too short for the first `npx`
download, hence `client_session_timeout_seconds=60`. The server gets only a few basic
variables (such as `HOME` and `PATH`) plus what you put in `env`, so set any other
`SAIHM_*` setting there, and `HTTPS_PROXY` or `NODE_EXTRA_CA_CERTS` if your network needs
them. Pass a secret from the environment
(`os.environ["SAIHM_IDENTITY_PASSPHRASE"]`), never as a literal in your code.

### Gemini CLI (Google)

*Documented.* Add this to `~/.gemini/settings.json` (all projects) or
`.gemini/settings.json` (one project):

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

### GitHub Copilot in VS Code (Microsoft)

*Documented.* Add this to `.vscode/mcp.json` in a workspace, or to your user `mcp.json`
(run **MCP: Open User Configuration**). VS Code's own format uses `servers`, not
`mcpServers`:

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

**MCP: List Servers** shows the server, and its **Show Output** action shows the
server's log. For the GitHub Copilot cloud agent, see
[Hosted agent environments](#hosted-agent-environments).

### Other MCP clients

*Documented for Cline; for other clients this is the generic MCP form.* For third-party
clients such as Cline, Cursor or Windsurf: where the client runs local MCP servers from an
`mcpServers` block in its settings file, add the `"saihm"` entry inside the existing
`mcpServers` object rather than replacing it:

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

`timeout` is in seconds in Cline. Without it, the Cline CLI gives a server only a few
seconds to start (the editor extension waits longer). If your client documents another unit for `timeout`, or none, follow its
documentation.

- **Cline in the editor:** open the Cline panel, select the **MCP Servers** icon, then
  **Configure > Configure MCP Servers**.
- **Cline CLI:** the file is `~/.cline/data/settings/cline_mcp_settings.json`.
  `cline mcp install` writes its entry in another shape (`"transport": { ... }`), with no
  `timeout` and no `env`: add `"timeout": 60` beside `"transport"`, or use the entry
  above.

### Which clients are checked

Before each release, the server is started from the configurations above in Claude
Code and Gemini CLI, which must each report it connected, and in the OpenAI Agents SDK,
which must list the SAIHM tools. That check covers start-up only: memory calls through
each client are not part of it. The other clients, Codex CLI included, are documented
only.

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
actions know when to ask.

**The full tool list.** The server registers eight protocol tools: `saihm_remember`,
`saihm_recall`, `saihm_forget`, `saihm_status`, `saihm_share`, `saihm_revoke_share`,
`saihm_governance_propose` and `saihm_governance_vote`. The two governance tools are
present but answer "governance unavailable" for now. It also registers `saihm_join`, the
bootstrap tool that answers *"Join SAIHM"*: on by default, removed by
`SAIHM_SELF_JOIN=0`. So a client lists nine tools by default, and eight with
`SAIHM_SELF_JOIN=0`.

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

**Using a second computer, or a hosted agent?** Three ways:

- **Same memory, on another machine or hosted agent** — on the machine that has your key, run:

  ```bash
  npx -y @saihm/mcp-server-pro export-identity
  ```

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
- **Copy the key file** — on a machine you can copy files to, put the key file at
  `~/.saihm/free-identity.key` (or point `SAIHM_MASTER_SECRET_FILE` at it) before
  the server starts, with the same config as the first machine (for a paid key,
  `SAIHM_TIER` and `SAIHM_PAYMENT_METHOD` too), and say *"Recall my SAIHM memories."*
- **Work and personal kept apart** — start fresh on the second machine and share
  across instead: *"Share these notes with my work agent until 5:00 pm."* A share
  can be revoked or given an expiry, so the two stay separate.

## Hosted agent environments

A hosted agent session usually starts on a fresh machine and discards its home
directory when it ends, so a key created there is lost with it. Bring your identity
in with the two `export-identity` values instead, set in the environment's own
settings — never in the chat. A hosted environment reads its variables when a
session starts, so start a new session after setting them. The server needs to run
locally (stdio) and reach `saihm.net` (or your `SAIHM_ENDPOINT_URL` host) — directly,
or through the proxy in `HTTPS_PROXY` if the environment sets one (`NO_PROXY` is
honoured; a network that inspects TLS needs its CA certificate, from the network's
administrator and never copied from the connection, saved to a file whose path is in
`NODE_EXTRA_CA_CERTS`). Configuration differs by host; per each host's documentation as of
October 2026 — none of these hosts has been tested end to end yet:

- **Claude Code on the web** — add both values under the environment's
  *Environment variables*. Its documentation warns that anyone who uses the
  environment can read these values, and the dialog advises against putting secrets
  there, so use a dedicated environment that only you use, for repositories you
  trust: every session in it, on any repository, can read them. (Its API-credential
  setting does not help here: those are attached to outbound requests and never
  reach the server.) Choose *Custom* network access, add `saihm.net`, and check
  *Also include default list of common package managers*, so `npx` can still reach npm.
  Then pass the values through the repository's `.mcp.json`:

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
- **GitHub Copilot cloud agent** — store the values as Agents secrets (repository
  *Settings → Secrets and variables → Agents*) named `COPILOT_MCP_SAIHM_IDENTITY` and
  `COPILOT_MCP_SAIHM_IDENTITY_PASSPHRASE`; only Agents secrets with that prefix can be
  passed to an MCP server, and GitHub documents them as available to MCP servers only, not
  to the agent's own environment. The server still runs in that environment, beside every
  command the agent runs: use this only in a repository whose code you trust.
  Map them in the repository's MCP configuration (*Settings → Copilot → MCP
  servers*):

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
  `saihm_forget` and the sharing tools; add them only if you want the agent to erase
  or share without confirmation. GitHub applies this configuration to Copilot code
  review too, and by default lets a review call the read-only tools (`saihm_recall`,
  `saihm_status`) on any pull request in the repository, so your memories could
  reach review comments. Unless you want that, turn off the repository setting
  **Allow Copilot to use MCP tools when reviewing pull requests**; that also stops
  reviews calling the default GitHub and Playwright MCP servers.
- **Elsewhere, including other clients' cloud agents** — this should work on any host
  that runs local MCP servers, lets the server read both variables, and lets it reach
  `saihm.net` (and `registry.npmjs.org`, for `npx`). Put the two values in the host's
  own secrets or environment settings, and add `SAIHM_EPHEMERAL_HOME=1` there if its home
  directory does not persist. Use settings scoped to you alone, never ones shared with a
  team, in an environment only you use and for repositories you trust: the agent, and
  every command it runs, may be able to read them. Not verified on other hosts. Hosts
  that only connect to remote MCP servers cannot run this package.

Where the home directory is temporary, the join refuses to create a key — where it
can tell: in a session a host marks as hosted or CI (`CLAUDE_CODE_REMOTE`,
`GITHUB_ACTIONS`, `CI`), or
wherever `SAIHM_EPHEMERAL_HOME` is set to anything but `0`/`false`/`no`/`off`. Nothing
an agent passes to `saihm_join` overrides that; setting `SAIHM_EPHEMERAL_HOME=0` in
the environment's settings does, and the `free-join` command reads it from its own
environment, so a command-line setting overrides it there (a person still has to
approve the sign-in). In a temporary home the client's local bookkeeping (the
anti-rollback marks, and the recall cache if one is turned on) also starts empty each
session.

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
| No SAIHM tools appear, and no error anywhere | The client stopped waiting before `npx` finished its first download: keep the start-up setting in [your client's block](#add-saihm-to-your-ai-client). Then check the file is valid JSON |
| Every other tool vanished too | The settings file is no longer valid JSON: a trailing comma, or non-breaking spaces (U+00A0) from a copy and paste. Claude Code may replace a broken `~/.claude.json` with a fresh one and keep the original under `~/.claude/backups/`: fix that copy and put it back |
| The memory tools say the join is waiting for approval | Open the link the join gave, sign in, enter the code and approve; then say *"Join SAIHM"* again |
| Tools appear but every call fails | `SAIHM_ENDPOINT_URL` unreachable |
| Every call fails behind a proxy | In a hosted environment, allow the endpoint's host in its network settings; otherwise check `HTTPS_PROXY` (an `http://` URL) and `NO_PROXY`. A network that inspects TLS needs its CA certificate, from its administrator, in a file named by `NODE_EXTRA_CA_CERTS` |
| "No SAIHM identity is configured" | Self-join is off (`SAIHM_SELF_JOIN=0`) and no identity is set here: set one, or remove that setting to join |
| A hosted session keeps asking to join | The environment has no identity of yours — see *Hosted agent environments* |
| A different memory than you expected | This machine has its own key rather than yours |
| `status` mentions `seq-state` | A small local safeguard file couldn't be read or written. Your memories are unaffected — see `SAIHM_SEQ_STATE_PATH` below |
| `forget` worked but mentions a feed | The erasure stands — only the notification line couldn't be written. See `SAIHM_ERASURE_FEED` below |

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
- **Erasure that travels** — `forget` also appends one line to a per-identity
  feed, so anything that derived from a cell — an index, a mirror, an extracted
  fact — can be told to drop it too. An erasure that stops at this substrate is
  not an erasure. On by default; `SAIHM_ERASURE_FEED=0` turns it off.
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
| Local recall cache | When the recall cache is on, memories this device has opened are also kept unencrypted in a mode-600 file beside your key. `forget` removes the memory from it; `SAIHM_RECALL_CACHE=0` keeps no local copy. |
| Erasure cascade | Each `forget` appends one line to `$SAIHM_HOME/tenants/<agentIdHash>/erasures.ndjson`. The line carries the cell id, the identity and the time — never cell content. |

### Where encrypted cells are stored

This client encrypts cells and hands the ciphertext to whichever operator endpoint
`SAIHM_ENDPOINT_URL` points at; **that operator chooses and configures the durable
storage behind it** — typically a local IPFS / Kubo node first, then a Filecoin
deep-archive provider. Storage is operator-configured **by design**: the protocol
never locks anyone to a single provider. Running your own endpoint means
provisioning that storage yourself.

Prefer not to run storage at all? The hosted operator at
<https://saihm.net> provides durable storage and is **non-custodial** —
because this client encrypts every cell locally, the hosted operator only ever
stores ciphertext and never holds a key.

## Configuration

Most people need none of this: the setup above sets one variable and the rest have
working defaults.

| Env | Required | Meaning |
| --- | --- | --- |
| `SAIHM_ENDPOINT_URL` | no | `https://…/mcp` (or `http://` for `127.0.0.1`/`localhost` only). **Defaults to `https://saihm.net/mcp`** — set it only to reach a different operator. Versions 0.11.1 and earlier defaulted to `saihm.coti.global`, which serves the identical service until 2026-12-31 and is then discontinued. |
| `SAIHM_MASTER_SECRET_FILE` | see note | Path to a **mode-600** file holding the hex master secret. **The preferred way to supply a key**, because it keeps the key out of a config file that may be synced or shared. Takes precedence over `SAIHM_MASTER_SECRET_HEX`. Cannot be combined with `SAIHM_IDENTITY`. |
| `SAIHM_IDENTITY` | see note | An identity token written by `export-identity`: your key, sealed. Set it with `SAIHM_IDENTITY_PASSPHRASE` to use that identity without a key file — see *Hosted agent environments*. Cannot be combined with either master-secret variable; blank counts as unset. |
| `SAIHM_IDENTITY_PASSPHRASE` | with `SAIHM_IDENTITY` | The passphrase `export-identity` generated for that token. The two together are your identity: store them as secrets, never in a chat or a committed file. |
| `SAIHM_MASTER_SECRET_HEX` | see note | The master secret inline, ≥ 64 hex characters (≥ 32 bytes), high-entropy, client-held, never sent. Prefer the file form: anything inline lands in the config file itself. |
| `SAIHM_SELF_JOIN` | no | Controls the `saihm_join` onboarding tool — the one that answers *"Join SAIHM"*. **On by default**; set to `0` to remove it and expose only the canonical eight tools. |
| `HTTPS_PROXY` / `NO_PROXY` | no | An HTTP proxy for reaching an `https://` endpoint, and the hosts to reach directly instead — `https_proxy`, or `HTTPS_PROXY` if that is unset (`HTTP_PROXY` is not used for https, as with npm and curl). Only an `http://` proxy URL is supported; any other fails with an error naming the setting rather than connecting directly. A network that inspects TLS presents its own certificate: get its CA certificate (PEM) from the network's administrator (never copy one from the connection itself), save it to a file and set `NODE_EXTRA_CA_CERTS` to that file's path in the server's environment; Node reads it at start. `NO_PROXY` (or `no_proxy`) takes `*`, host names, domain suffixes and ports. Loopback endpoints (`127.0.0.0/8`, `::1`, `localhost` and `*.localhost`) never use a proxy. Proxy credentials in the URL go to the proxy only and are never printed. |
| `SAIHM_EPHEMERAL_HOME` | no | Says whether this environment discards its home directory when a session ends. Set it (e.g. `1`) where it does: the join then refuses to create a key that would be lost. `0` declares the home kept and overrides a host's own signal. Unset: detected where the host says so. |
| `SAIHM_HOME` | no | Where the identity file lives (`$SAIHM_HOME/free-identity.key`, mode 600), where per-restart bookkeeping is kept, and where the erasure feed is written unless `SAIHM_ERASURE_FEED_DIR` overrides it. Defaults to `~/.saihm`. Give a full path: a JSON config does not expand `~`, so `~/.saihm` there names a folder called `~` in the server's working directory. |
| `SAIHM_AUTH_HEADER` | no | `Bearer <JWT>`, used verbatim. **Omit to self-onboard** (recommended) — the client mints and refreshes its own token, so there is nothing to paste or re-paste. |
| `SAIHM_TIER` | paid self-onboard; any self-onboard with `SAIHM_SELF_JOIN=0` | Plan label recorded in encrypted metadata (`FREE`, `PRO`, …). Defaults to `FREE` while self-join is on (the default); set it for a paid plan, and with self-join off for every plan, `FREE` included. An `export-identity` token carries its own, which a non-empty value here overrides. With self-join off and a static `SAIHM_AUTH_HEADER`, resolved via `status()`. |
| `SAIHM_PAYMENT_METHOD` | paid self-onboard | Entitlement rail (`stripe`, `stablecoin`, …) for a paid plan. **Not used by the free tier.** Ignored when `SAIHM_AUTH_HEADER` is set. An identity token carries it; a non-empty value here overrides the token's. |
| `SAIHM_SEQ_STATE_PATH` | no | Overrides where the anti-rollback bookkeeping is written. Running as an MCP server this is **on by default** at `$SAIHM_HOME/seq.<id>.json`; set it only to relocate it. The default location is ours to manage: if it can't be written, the tally stays in memory for the session and `status` says so. A location **you** set is yours: if it can't be written, calls fail and name the path, so a safeguard you asked for never goes quiet without telling you. `status` reports this as `seq-state=…` followed by `rollback-guard=persisting` (writes still work, so the next one rewrites the file) or `memory-only-this-run` (it retries at the next restart). Either way, if the file couldn't be READ at startup the safeguard starts from scratch and rebuilds as each memory is next read — so an older copy of a memory would not be caught during that window. At the default location that window is about accidental corruption rather than an attacker: writing to that file takes the same access that reads the identity key sitting beside it. Somewhere you relocate it to, that no longer follows — give it the protection you give `$SAIHM_HOME`. |
| `SAIHM_RECALL_CACHE` | no | Controls the recall cache: the memories this device has already opened, kept so that recall asks the service only for new ones. **On by default** when your key is the self-join identity file in `SAIHM_HOME`; set to `0` to keep no local copy. The copy is **unencrypted** in a file readable only by your user (mode 600), beside the key; `forget` removes a memory from it, and a memory erased from another device leaves it at the next recall. |
| `SAIHM_RECALL_CACHE_PATH` | no | Where the recall cache is written. **With a cache, a recall fetches only what has changed since the last one; without a cache it fetches every memory, every time** — measured on 2026-09-17 against ~208 memories on the hosted endpoint: a warm recall took 24 ms with a cache and 818 ms without, and because the cache is a file it survives a restart — the FIRST recall of a new process took 114-115 ms with a populated cache against 1,022-1,094 ms without. Only the very first run, which builds the cache, pays the full fetch. The cache defaults ON only for an identity that boots from the key file in `$SAIHM_HOME` (that installation already keeps its key and sequence marks there). For any other key source — including `SAIHM_MASTER_SECRET_FILE` pointing elsewhere, or an inline secret — it is OFF unless you set this, and the client says so once on its first recall. **The file holds your memories as plaintext at rest**, which is why it is not simply on for everyone: it is your decision. `SAIHM_RECALL_CACHE=0` turns it off in every case, an explicit path included, and silences the notice. |
| `SAIHM_STATE_DIR` | no | Where transient operator state (such as `checkout-url.txt`) is written. Does **not** relocate your identity or its bookkeeping. |
| `SAIHM_ERASURE_FEED` | no | Controls the erasure feed — one line appended per `forget`, so a consumer can drop whatever it derived from that cell. **On by default**; set to `0` to write nothing. Writing the line can never fail an erasure: the erasure is what you asked for and the line is a notification about it, so a feed that can't be written is reported beside the result and the erasure still stands. |
| `SAIHM_EVENTS` | no | Set to `1` to follow share events: from the moment the server starts, it long-polls the endpoint for shares made to you (new, updated, stale, ended, erased). `saihm_recall` then returns a summary as `shareStates` when it lists memories, beside `shared`, with every entry when the call passes `shareEntries: true`, and the map is written to `share-states.json` beside the erasure feed for other processes to read (see *Following shares* below). **Off by default.** The map and the position in the feed survive a restart (see `SAIHM_SHARE_MAP_STORE`); a sender is marked verified only after a shared memory is read and its signature checked. Endpoints that do not offer events are left alone. |
| `SAIHM_SHARE_MAP_STORE` | no | Where the share feed keeps its position between runs: `file` (the default) writes `feed-state.json` beside the erasure feed, so a restart asks the endpoint only for what it missed; `off` keeps everything in memory, and the client fetches the whole share listing at every start. A root that cannot be written falls back to memory on its own, so this needs no setting where there is nowhere to write. Only read when the feed is on. |
| `SAIHM_ERASURE_FEED_DIR` | no | Overrides the feed's root. Defaults to `SAIHM_HOME`, then `~/.saihm`; the feed itself is at `<root>/tenants/<agentIdHash>/erasures.ndjson`, and the directory is created the first time a tool runs. Must be an **absolute** path — a relative one resolves against the working directory, so one identity would write to a different file depending on where the process started while a consumer reported the feed missing. Deliberately **not** `SAIHM_STATE_DIR`: a feed is identity-scoped, so it has to move with the identity or not at all, and a consumer refuses a line from an identity it is not watching. |

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

// Update an existing cell (a fresh monotonic sequence is issued automatically). When the endpoint reports
// shares of the cell left on the previous version, `shares` in the result reports their re-issue.
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

**Following shares (optional).** With `SAIHM_EVENTS=1`, or `saihm.startShareEvents()` in your own process, the client
long-polls the endpoint and keeps a map of the shares made to you: `saihm.shareStates()`, and `shareStates` in the
`saihm_recall` result. The summary is on every recall that lists memories: `since`, `complete`, `asOf`, `stopped`,
`startedAt` and `counts` (`live`, `stale`, `ended`, `erased`). The entries are added only when the call passes
`shareEntries: true`; without it they are absent, which is not the same as empty. Each entry names the sharer and cell,
a `status` (`live`, `stale`, `ended` or `erased`), the grant, the sharer's latest `seq` and `commitment` when known, and
`senderVerified`, which is true only after a read checked the sharer's signature. Every time is ISO-8601 UTC with
milliseconds (`YYYY-MM-DDTHH:MM:SS.sssZ`). To read it safely:

- Treat a cached copy of a shared memory as erased when its entry is `erased`, or when the copy was made before the
  entry's `copiesInvalidBefore` (count a copy made up to 5 minutes after that time as made before it, for clock skew).
- An entry whose `endedBy` is `reconciliation` may have been erased rather than revoked: treat its copies as possibly
  erased.
- Conclude anything from a missing entry only when `since` is set and `complete` is true. Until then the map may still
  be catching up, and a `live` entry may be out of date. A map with `since` null or `complete` false is no baseline to
  compare a later map against: only a complete map replaces one.
- The map is as of `asOf`, the time of the latest answer from the endpoint or completed catch-up; it is null until the
  first. While the network is down `asOf` stops advancing and `complete` stays as it was, so compare `asOf` with your
  clock when you need a current map.
- `stopped` says why the client stopped following: `unsupported` (the endpoint offers no feed), `tier` (the plan has
  none) or `erased` (the identity was erased). `complete` is then false until a later catch-up completes. `startedAt` is
  when this process started following, so a null `asOf` reads as starting or as stopped.
- The map and the position in the feed survive a restart, so `since` carries over and a new process asks the endpoint
  for what it missed rather than for the whole listing. `since` may therefore be EARLIER than `startedAt`: it is when
  the map this process resumed was first complete, not when this process began. Before 0.11.0 `since` always followed
  `startedAt`; do not use the two together to tell one run from another. A restored map is NOT complete until this process has had an
  answer: `complete` is false and `asOf` null until then, which is exactly the state above in which nothing may be
  concluded from a missing entry. `saihm.stopShareEvents()` ends the polling.

For other processes, the client writes the summary and every entry to `<root>/tenants/<agentIdHash>/share-states.json`,
beside the erasure feed and under the same root (`SAIHM_ERASURE_FEED_DIR`, then `SAIHM_HOME`, then `~/.saihm`). It is
owner-only (file 0600, directory 0700), replaced whole, written soon after the map, `since`, `complete` or `stopped`
changes and at least once a minute, and left in place when the process ends; its `asOf` shows its age. The client never
reads it back. Several processes of one identity each keep their own map and may each write the file: it is replaced
under a lock and only by a map whose `asOf` is not older, and its `since` is the writer's. Until a new process has its
first answer, the file may still be an earlier process's. No file means no feed has run for that identity under that
root; it asserts nothing.

The position itself is kept in `<root>/tenants/<agentIdHash>/feed-state.json`, in the same directory and with the same
owner-only modes, and this file the client does read back. Nothing in it is trusted: a state that is missing,
unreadable, malformed, too large or older than the endpoint keeps events for is ignored, and the client starts cold as
it always did. Set `SAIHM_SHARE_MAP_STORE=off` to keep the position in memory only; a root that cannot be written does
the same without being asked. Several processes of one identity may each write the file, and each write holds a
position and the map that goes with it together, so whichever was written last is a pair a later process can resume
from.

A shared read (`saihm_recall` with the sharer and cell) returns the `commitment` of the version it opened and, when the
endpoint sends it, the `grant` that served the read, named as in the entries, so a copy compares with its entry exactly.

**Errors.** Non-2xx responses throw `SaihmEndpointError` carrying `status` and a
typed `code` (e.g. `BLIND_BAD_EXPIRY`, `BLIND_STALE_SEQ`,
`governance_unavailable`). Branch on the code rather than the message.

## License

Apache-2.0 © SAIHM
