# Installing @saihm/mcp-server-pro

This file is for the AI agent doing the install. Follow it end to end. You can do
the install without the user, except for restarting the client where step 2 says so.
Activating the free memory needs the user once:
a browser and a GitHub account for a one-time sign-in (step 4).

## What this server is

Sovereign, client-side-sealed persistent memory. Cells are sealed **in the
client process** before they leave the machine, so the operator stores
ciphertext it cannot open.

The server registers eight protocol tools: `saihm_remember`, `saihm_recall`,
`saihm_forget`, `saihm_status`, `saihm_share`, `saihm_revoke_share`,
`saihm_governance_propose` and `saihm_governance_vote`. The two governance tools are
present but answer "governance unavailable" for now. It also registers `saihm_join`,
the bootstrap tool that answers "Join SAIHM": on by default, removed by
`SAIHM_SELF_JOIN=0`. So a client lists nine tools by default, and eight with
`SAIHM_SELF_JOIN=0`.

## Step 1 — write the MCP config

The server is local (stdio), starts with `npx`, and needs Node.js 20 or later.
Write the entry in the host's own format, and merge it into what is there rather
than overwriting it. Per host (from each provider's documentation, October 2026;
`README.md` has a ready block for each):

- **Claude Code:** `claude mcp add --env SAIHM_ENDPOINT_URL=https://saihm.net/mcp --transport stdio --scope user saihm -- npx -y @saihm/mcp-server-pro`.
  If the first start times out, set `MCP_TIMEOUT=60000` in the environment Claude
  Code starts from.
- **Claude Desktop:** `claude_desktop_config.json` (Settings > Developer > Edit
  Config), the entry below without `timeout`.
- **Codex CLI:** `~/.codex/config.toml`, a `[mcp_servers.saihm]` table with
  `command`, `args`, `env` and `startup_timeout_sec = 60` (the default is 10).
- **OpenAI Agents SDK:** `MCPServerStdio(name="saihm", params={"command": "npx",
  "args": ["-y", "@saihm/mcp-server-pro"], "env": {...}},
  client_session_timeout_seconds=60)` (the default is 5).
- **Gemini CLI:** `~/.gemini/settings.json`, the entry below without `timeout`:
  Gemini reads `timeout` in milliseconds, and its default is 10 minutes. Its
  `gemini mcp list` check waits only a few seconds, so on the first start, while
  `npx` downloads, it can show the server disconnected; check again.
- **VS Code (GitHub Copilot):** `.vscode/mcp.json` or the user `mcp.json`; the
  top-level key is `servers`, and the entry adds `"type": "stdio"`, without `timeout`.
- **Cline:** the entry below, with `"timeout": 60` (seconds). In the editor: Cline
  panel > MCP Servers > Configure > Configure MCP Servers. The CLI reads
  `~/.cline/data/settings/cline_mcp_settings.json`; `cline mcp install` writes a
  nested `transport` object with no `timeout` and no `env`, so add `"timeout": 60`
  beside `transport`.
- **Other hosts that take `mcpServers` JSON:** the entry below. Keep `timeout` only
  where the host documents it in seconds.

```json
{
  "mcpServers": {
    "saihm": {
      "command": "npx",
      "args": ["-y", "@saihm/mcp-server-pro"],
      "env": {
        "SAIHM_ENDPOINT_URL": "https://saihm.net/mcp"
      },
      "timeout": 60
    }
  }
}
```

Host note (2026-09-23): From 0.11.2 the default endpoint is `https://saihm.net/mcp`. Versions 0.11.1 and earlier default to the previous host, `saihm.coti.global`, which serves the identical service until 2026-12-31 and is then discontinued: upgrade, or set `SAIHM_ENDPOINT_URL` explicitly.

**The start-up setting is required, not decorative.** The first start downloads
the package with `npx`, which takes longer than some hosts wait by default: the Cline
CLI, without `timeout`, waits only a few seconds. A server that misses the deadline is
skipped **silently** — the tools simply never appear, with no error surfaced in the
chat. If this server seems absent after install, check the start-up setting first,
then that the file is valid JSON: a trailing comma, or a non-breaking space
(U+00A0) pasted from an email or web page, invalidates the whole file. In Claude
Code, `claude mcp list` shows whether the server connected and says so when a
config file is not valid JSON (a broken `~/.claude.json` may then be replaced by a fresh one
without the servers, and the original kept under `~/.claude/backups/`: fix that copy and
put it back); `python3 -m json.tool <file> > /dev/null && echo valid` checks a file
without printing it (on Windows, in Command Prompt: `py -m json.tool <file> > NUL && echo valid`, writing
`"%USERPROFILE%\.claude.json"` for `~/.claude.json`). Never print a config file: it can hold other
servers' credentials, and your transcript keeps what you print.

Do **not** ask the user for an API key, token, or master secret at this step.
The free path needs none, and the master secret in particular must never be
pasted into a third-party config store — see *Paid tiers* below.

## Step 2 — verify

Restart the MCP connection and confirm the host lists tools under the `saihm`
server. Nine should appear by default (eight with `SAIHM_SELF_JOIN=0`). If zero
appear, revisit the start-up setting first, then confirm `npx` is on `PATH`.

Do not call `saihm_join` as a smoke test — see below. To verify liveness
without side effects, `saihm_status` is read-only.

## Step 3 — tell the user (always)

Once the tools appear, tell the user that memory is installed but not yet
activated. If they already have a SAIHM identity, they bring it rather than
joining (see point 3 below); if they are new, saying **"Join SAIHM"** activates
it. Do this whether or not they asked: they cannot ask for something they do
not know exists. Say it once, in your own words, and do not call `saihm_join`
yourself.

## Step 4 — activation (only when the user says "Join SAIHM")

When they do, confirm they have no identity to bring, then call `saihm_join`
with `newIdentity: true` (without it, a tool call that would create a key asks
that question instead). It
generates a 32-byte master secret locally at `~/.saihm/free-identity.key`
(mode 600) and returns a one-time device sign-in link plus a short code. The
user does the next part, in a browser: they open the link, sign in to GitHub,
enter the code, and approve. That step confirms a unique person. The secret never
leaves the machine. A user without a GitHub account can start from
<https://saihm.net/free> instead, which signs in with Google. That page gives the user a
configuration holding their new key: have them save the key to a file only they can
read (never by pasting it into the chat) and set `SAIHM_MASTER_SECRET_FILE` to its path,
and do not call `saihm_join` for them.

If the join is interrupted: the key file is written when the join starts, before
approval, and it stays if the join stops while it waits. Calling `saihm_join` again
on the same machine uses that same key, so it is the same identity, and no second
key is written. While a join waits for approval, the memory tools answer with its
steps (an identity that was already active keeps working). To stop a join the user does not want, they stop the command or end the
session, and do not enter the code; it expires after the time the join shows. Leave
the key file in place: a later join on this machine uses it.

Three things to tell the user, in your own words:

1. **`saihm_join` is one-time.** It claims a lifetime free grant for this
   device identity. Do not call it speculatively, in a loop, or to test that
   the install worked. Ask first whether they already have a SAIHM identity:
   a join creates a NEW, EMPTY memory, so pass `newIdentity: true` only once
   they confirm they want one. In a hosted or cloud session that starts fresh
   each time, do not join there either: they join on a machine they keep, then
   bring that identity in (point 3). Where it can tell that the home directory is
   discarded when the session ends (the host marks a hosted or CI session, or
   `SAIHM_EPHEMERAL_HOME` is set), it refuses to create a key; only the
   environment's owner can override that.
2. **`~/.saihm/free-identity.key` is the only copy of their key.** Advise
   backing it up. If it is lost, no one — including SAIHM — can open their
   cells. That is the point of the design, and it is not recoverable.

3. **A second computer, or a hosted agent.** Offer sharing first: a separate
   identity on the second machine plus `saihm_share` (which takes an optional
   `expiryEpoch`) keeps work and personal apart, and a share can be revoked where
   a copied key cannot. If they want the SAME memory there, have them run
   `npx -y @saihm/mcp-server-pro export-identity` on the machine that holds the
   key, with the same `SAIHM_*` settings their MCP client uses there (on a paid
   plan, `SAIHM_TIER` and `SAIHM_PAYMENT_METHOD`), and set the two values it
   writes, `SAIHM_IDENTITY` and `SAIHM_IDENTITY_PASSPHRASE`, in the other
   environment's own variables or secrets settings, then start a new session (a
   key file placed before the server starts also works where files can be
   copied). Never run `saihm_join` there: it mints an unrelated identity with an
   empty memory. Never ask them to paste either value into the chat, never
   write either into a file, and never open or print the export file.

Set `SAIHM_SELF_JOIN=0` to suppress `saihm_join` and expose only the canonical
eight tools.

## Paid tiers

If the user already has a master secret, have them save it to a file readable
only by them (never by pasting it into the chat) and point at it with
`SAIHM_MASTER_SECRET_FILE`, alongside
`SAIHM_TIER` and `SAIHM_PAYMENT_METHOD`. Prefer the file over
`SAIHM_MASTER_SECRET_HEX` for the reason given in step 1: an inline secret lands
in the config store itself, which is frequently synced between machines. Have
the user write the value; do not ask them to read it out to you. Full option
table: see `README.md`.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| No tools appear, no error | Start-up setting missing or too low, or the config file is not valid JSON — see step 1 |
| Tools appear, calls fail | `SAIHM_ENDPOINT_URL` unreachable |
| Memory tools say the join is waiting for approval | The user has not approved yet: they open the link, sign in, enter the code and approve; then call `saihm_join` again |
| Tool calls report no identity | New user: `saihm_join` not yet run. Second machine or hosted session: `SAIHM_IDENTITY` and its passphrase not set there (point 3) |
