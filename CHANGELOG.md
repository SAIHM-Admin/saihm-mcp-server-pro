# Changelog

All notable changes to `@saihm/mcp-server-pro` are documented here. This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **`serverInfo.name` is now `saihm-pro`, was `saihm`.** The standards client
  `@saihm/mcp-server` also reports `saihm`, so two separately published packages
  were announcing one server name. Any directory, registry, or host that keys on
  `serverInfo.name` rather than on the package identifier could conflate them.
  No protocol, wire-format, or tool-surface change: the canonical eight tools
  plus the `saihm_join` bootstrap affordance are unchanged, and clients key their
  configuration on the `mcpServers` entry name, not on this field. Visible where
  a host displays the server's self-reported name. A handshake assertion now
  guards the value so the divergence cannot silently regress.

## [0.2.1] — 2026-07-28

First-run fix. No protocol, wire-format, or tool-surface change; the canonical
eight tools plus the `saihm_join` bootstrap affordance are unchanged.

### Fixed

- **A fresh install dead-ended on its very first tool call.** With no
  `SAIHM_ENDPOINT_URL` set — the state of every hand-written MCP config, e.g. a
  bare `npx -y @saihm/mcp-server-pro` — `saihm_recall`, `saihm_status`, and
  `saihm_remember` all failed with `SAIHM_ENDPOINT_URL env var required`, which
  never mentions `saihm_join`. The shipped `saihm_session_bootstrap` prompt
  makes this the first thing an agent hits, since it instructs a `saihm_recall`
  before anything else. 0.2.0 already carried the actionable _"Ask me to Join
  SAIHM first"_ message, but the endpoint check threw before execution could
  reach it.

  An unset `SAIHM_ENDPOINT_URL` now resolves to `https://saihm.coti.global/mcp`
  — the value `server.json` already declared as this variable's `default`, so
  code and manifest now agree and registry-driven and hand-written configs
  behave identically. Defaulting reaches no network by itself: boot still
  requires an identity, so an unconfigured agent gets the join hint *before* any
  request is made, and `saihm_join` still needs explicit human approval. Setting
  the variable to an explicit empty string remains a configuration error rather
  than a silent opt-in to the default.

- **Every remaining boot error was a bare env-var name.** All of them now carry
  a setup hint naming `saihm_join` for the free zero-config path and
  `SAIHM_ENDPOINT_URL` for a different operator: unreadable
  `SAIHM_MASTER_SECRET_FILE`, unreadable self-join identity file, missing master
  secret, non-canonical hex, and under-length secret. No secret material is
  interpolated into any message.

### Changed

- `server.json`: `SAIHM_ENDPOINT_URL` is now `isRequired: false`, matching the
  code, so registry clients stop prompting for a value that has a working
  default.
- README: the configuration table listed `SAIHM_ENDPOINT_URL` as required. It is
  now documented as optional with its default.
- `DEFAULT_ENDPOINT` is exported from the package root so an embedding consumer
  can reference the same constant.

### Notes

- Regression cover added for the genuinely-unset state. Every pre-existing
  self-join test pinned `SAIHM_ENDPOINT_URL`, so the suite was green while the
  real first-run path was broken; three new cases assert the unset, defaulted,
  and explicitly-empty behaviours, and pin `SAIHM_HOME` to a temp dir so a
  developer's own `~/.saihm` identity cannot mask a failure.

## [0.2.0] — 2026-07-28

Onboarding release. No protocol or wire-format change; the canonical eight
tools are unchanged.

### Changed

- **`saihm_join` is now registered by default (`SAIHM_SELF_JOIN` defaults on).**
  Previously it was opt-in via `SAIHM_SELF_JOIN=1`, which left a fresh install
  with no in-band way to start: every other path first requires a hand-generated
  64+ hex-char master secret, which an autonomous agent cannot produce for
  itself. Self-join generates and persists that identity on-device instead, so
  _"Join SAIHM"_ works out of the box. Set `SAIHM_SELF_JOIN=0` to restore the
  previous behaviour — the tool is not registered and every self-join path is
  inert. `saihm_join` remains a one-time onboarding bootstrap affordance, not a
  ninth protocol tool.
- Boot with no master secret and no persisted identity now returns the
  actionable _"Ask me to Join SAIHM first"_ hint rather than the bare
  `SAIHM_MASTER_SECRET_HEX ... required` error. Opting out restores the
  original message.
- The free allowance is described consistently as a **free trial** for testing
  on real infrastructure — a fixed, one-time allowance, no card and nothing to
  cancel — matching `@saihm/mcp-server`.

### Added

- `server.json` manifest and an MCP registry publish step, so this package is
  discoverable in the MCP registry. Previously only the crypto-free
  `@saihm/mcp-server` was listed, and that package cannot activate an account.
- npm discovery keywords: `memory`, `sovereign-memory`, `free-tier`,
  `claude-code`, `claude-desktop`, `cursor`.

### Fixed

- The documented `free-join` command now uses `SAIHM_MASTER_SECRET_FILE` with a
  shown `openssl rand -hex 32` step, instead of an unexplained
  `<your 64+ hex master secret>` placeholder.

## [0.1.11] — 2026-07-19

### Added

- Opt-in delta recall cache (`SAIHM_RECALL_CACHE_PATH`) for faster session-start
  recall.

## [0.1.10] — 2026-07-10

### Added

- **`saihm_join` — self-serve activation from inside the agent.** Prompt your agent to _"Join SAIHM"_ and it activates a free, non-custodial memory allowance with no manual key handling: the agent generates its own identity seed on-device, persists it mode-600 under `~/.saihm/` (or `SAIHM_HOME`), and completes a one-time device sign-in that confirms a unique person. Off by default; opt in with `SAIHM_SELF_JOIN=1`. The master secret is generated locally and never leaves the process. This is an onboarding bootstrap affordance, not a protocol tool — the eight SAIHM tools remain the surface.
- **`saihm_recall` reads memories shared _to_ you.** The recall tool now accepts an optional sharer identity (`sharerPinnedAgentIdHashHex` plus the sharer's published identity record) and a `cellId`, routing to the recipient-side `recallShared` read (present in the library since 0.1.3) so tool-only agents — not just library callers — can open a cell another agent shared with them. It pins the sharer out-of-band, verifies the sharer and content signatures, and fails closed when there is no live grant. Own-memory recall is unchanged, and the tool count stays eight.

## [0.1.9] — 2026-07-06

### Added

- **Free tier — self-serve, non-custodial activation.** `npx -y @saihm/mcp-server-pro free-join` (with `SAIHM_TIER=FREE`) activates a free, one-time lifetime memory allowance bound to your own key. A one-time GitHub device sign-in confirms a unique person; the provider token stays server-ephemeral and the client never holds it. `acquireFreeEntitlement()` exposes the same headless device flow to library callers, with an `onPrompt` callback for the user-code display.
- **`upgrade` subcommand.** `npx -y @saihm/mcp-server-pro upgrade [PRO|PRO_FAST|ENTERPRISE|ENTERPRISE_FAST]` prints a monthly checkout link bound to your identity; billing attaches to the same key, so every existing memory persists. `requestUpgradeUrl(tier)` for library callers.
- **Advisory free-tier usage nags** via the `onQuotaNag` client option — a non-blocking heads-up as lifetime usage approaches its limit (fired at most once per call type and threshold). It never blocks a call.

## [0.1.8] — 2026-06-30

### Added

- **Structured tool output.** `saihm_remember`, `saihm_recall`, and `saihm_status` now advertise an `outputSchema` and return matching `structuredContent`, so MCP hosts and agents get typed results instead of parsing prose.
- **`saihm_session_bootstrap` prompt.** A new MCP prompt (the `prompts` capability is now advertised) that tells an agent to load its SAIHM memory via `saihm_recall` at the start of a session.
- **`SAIHM_DISCOVERY_SOURCE`** (also `discoverySource` on `SaihmProClientOpts`) — an optional attribution tag (e.g. `"glama"`, `"mcp-registry"`) sent as `source` on self-onboard, so an operator can attribute a paid conversion to the install channel. Free-form; sanitised endpoint-side.
- npm `keywords`, README badges, and a `SECURITY.md` coordinated-disclosure policy (source tree only; not part of the published tarball) for discovery.

### Changed

- Depends on `@saihm/client-pro` >= 0.1.5 (was >= 0.1.2).

## [0.1.7] — 2026-06-28

### Changed

- **`join` now completes the endpoint's proof-of-possession challenge before requesting a checkout link.** It fetches a server challenge and signs it with the in-process ML-DSA-65 secret key — the same challenge/response the self-onboarding path already performs — so the hosted checkout is cryptographically bound to the caller's own identity. Required by the current `/api/stripe/checkout` contract.

## [0.1.6] — 2026-06-25

### Changed

- Reproducible publish: regenerated lockfile and removed a stray formatter config. No API changes.

## [0.1.5] — 2026-06-25

### Added

- **Runnable stdio MCP server.** The package now ships a `saihm-mcp-server-pro` bin (run via `npx -y @saihm/mcp-server-pro`) that exposes the eight SAIHM tools (`saihm_remember`, `saihm_recall`, `saihm_forget`, `saihm_status`, `saihm_share`, `saihm_revoke_share`, `saihm_governance_propose`, `saihm_governance_vote`) over `SaihmProClient`. Point any MCP host (Claude Desktop, Claude Code, …) at it.
- **Self-onboarding (paste once, never re-paste a token).** With `SAIHM_AUTH_HEADER` unset, the server proves control of your identity via the endpoint's ML-DSA challenge/response and mints + auto-refreshes its own short-lived access token from the master secret. A static `SAIHM_AUTH_HEADER` is still honored verbatim.
- **`join` subcommand.** `npx -y @saihm/mcp-server-pro join` prints a checkout link bound to your identity, for self-serve subscription from the command line.
- **`SAIHM_MASTER_SECRET_FILE`** — read the hex master secret from a mode-600 file instead of `SAIHM_MASTER_SECRET_HEX` (keeps the root seed out of a synced MCP config); takes precedence when both are set.

### Changed

- Depends on `@saihm/client-pro` >= 0.1.2 (adds `signChallenge`) and adds `@modelcontextprotocol/sdk` + `zod`.

## [0.1.3] — 2026-06-24

### Added

- `recallShared(grant)` — read a cell another agent shared **to** you (the recipient side of `share`). Pins the sharer's `agentIdHash` out-of-band, verifies the sharer's signature and the cell's content signature, and fails closed (returns `null`) when there is no live grant — e.g. after the sharer revokes the grant or crypto-shreds the cell. `KeySubstitutionError` is re-exported so callers can `instanceof`-handle a sharer key-substitution.
- `repository` metadata linking the package to its source.

## [0.1.0] — 2026-06-22

Initial public release.

- `SaihmProClient` — production thin-client for SAIHM non-custodial memory. Seals every cell client-side via [`@saihm/client-pro`](https://www.npmjs.com/package/@saihm/client-pro) (ML-DSA-65 identity, per-cell AES-256-GCM DEK wrapped under a client KEK, ML-KEM-768 authenticated sharing) and POSTs opaque ciphertext to the blind SAIHM `/mcp` endpoint. The master secret, KEK, and plaintext never leave the process.
- API: `remember`, `recall`, `recallOne`, `forget`, `status`, `share`, `revokeShare`; `bootFromEnv()`; getters `agentIdHash`, `identityRecord`.
- Endpoint hardening (HTTPS-only; loopback `http` permitted for local dev), signed monotonic anti-replay sequencing with optional mode-600 persistence, and a fully typed `SaihmEndpointError` surface.

[0.1.10]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.10
[0.1.9]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.9
[0.1.8]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.8
[0.1.7]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.7
[0.1.6]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.6
[0.1.5]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.5
[0.1.3]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.3
[0.1.0]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.0
