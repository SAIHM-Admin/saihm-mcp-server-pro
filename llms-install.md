# Installing @saihm/mcp-server-pro

This file is for the AI agent doing the install. Follow it end to end; it needs
no input from the user for the free path.

## What this server is

Sovereign, client-side-sealed persistent memory. Cells are sealed **in the
client process** before they leave the machine, so the operator stores
ciphertext it cannot open. Nine tools are exposed: the eight canonical protocol
tools (`saihm_remember`, `saihm_recall`, `saihm_forget`, `saihm_status`,
`saihm_share`, `saihm_revoke_share`, `saihm_governance_propose`,
`saihm_governance_vote`) plus `saihm_join`, a one-time onboarding affordance.

## Step 1 — write the MCP config

Add this entry to the host's MCP settings file. For Cline that is
`cline_mcp_settings.json`; merge into the existing `mcpServers` object rather
than overwriting it.

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

**`timeout` is required, not decorative.** Cline's default MCP start-up budget
is 1.5 seconds. `npx` cannot resolve and launch a package that fast, and a
server that misses the deadline is skipped **silently** — the tools simply never
appear, with no error surfaced in the chat. If this server seems absent after
install, check the setting before anything else.

Do **not** ask the user for an API key, token, or master secret at this step.
The free path needs none, and the master secret in particular must never be
pasted into a third-party config store — see step 3.

## Step 2 — verify

Restart the MCP connection and confirm the host lists tools under the `saihm`
server. Nine should appear. If zero appear, revisit `timeout` first, then
confirm `npx` is on `PATH`.

Do not call `saihm_join` as a smoke test — see below. To verify liveness
without side effects, `saihm_status` is read-only.

## Step 3 — activation (only when the user asks)

Tell the user that memory is installed but not yet activated, and that saying
**"Join SAIHM"** activates it. When they do, call `saihm_join`. It generates a
32-byte master secret locally at `~/.saihm/free-identity.key` (mode 600) and
returns a one-time device sign-in link plus a short code; the user opens the
link, enters the code, and approves. That step confirms a unique person. The
secret never leaves the machine.

Three things to tell the user, in your own words:

1. **`saihm_join` is one-time.** It claims a lifetime free grant for this
   device identity. Do not call it speculatively, in a loop, or to test that
   the install worked.
2. **`~/.saihm/free-identity.key` is the only copy of their key.** Advise
   backing it up. If it is lost, no one — including SAIHM — can open their
   cells. That is the point of the design, and it is not recoverable.

3. **A second computer.** Offer sharing first: a separate identity on the second
   machine plus `saihm_share` (which takes an optional `expiryEpoch`) keeps work
   and personal apart, and a share can be revoked where a copied key cannot. If
   they want the SAME memory on both, the key file has to be on both — placed
   before the server starts, and without running `saihm_join` there, since that
   mints an unrelated identity with an empty memory.

Set `SAIHM_SELF_JOIN=0` to suppress `saihm_join` and expose only the canonical
eight tools.

## Paid tiers

If the user already has a master secret, have them save it to a file readable
only by them and point at it with `SAIHM_MASTER_SECRET_FILE`, alongside
`SAIHM_TIER` and `SAIHM_PAYMENT_METHOD`. Prefer the file over
`SAIHM_MASTER_SECRET_HEX` for the reason given in step 1: an inline secret lands
in the config store itself, which is frequently synced between machines. Have
the user write the value; do not ask them to read it out to you. Full option
table: see `README.md`.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| No tools appear, no error | `timeout` too low — see step 1 |
| Tools appear, calls fail | `SAIHM_ENDPOINT_URL` unreachable |
| Tool calls report no identity | `saihm_join` not yet run |
