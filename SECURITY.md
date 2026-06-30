# Security policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in
`@saihm/mcp-server-pro` (the SAIHM production sealing thin-client), please
report it privately so that we can investigate and remediate before public
disclosure.

**Private channel:** architect@saihm.coti.global

Please include, where possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce, or a proof-of-concept
- Affected version(s) of `@saihm/mcp-server-pro`
- Whether the issue is in the MCP tool surface, client-side sealing, the
  self-onboarding / token handling, the way it talks to the SAIHM operator
  endpoint, or in a dependency
- Your name or handle if you wish to be credited in the fix

We acknowledge reports within **14 days**. We aim to provide an initial
assessment and a fix or mitigation plan within **30 days** for confirmed
vulnerabilities, depending on severity and complexity.

## Scope

In scope:

- The published npm package `@saihm/mcp-server-pro` and its source in this
  repository
- Client-side sealing (via `@saihm/client-pro`), master-secret handling, JWT
  minting/refresh, and the way this package talks to a SAIHM operator endpoint
  (configuration, authentication, tool input/output forwarding)

Out of scope (please report to the relevant project instead):

- Vulnerabilities in third-party MCP clients (Claude Code, Claude Desktop,
  Cursor, etc.) — report to the client vendor
- Vulnerabilities in the underlying Model Context Protocol — report to
  https://github.com/modelcontextprotocol
- Vulnerabilities in the COTI V2 blockchain network — report to COTI Group
- Vulnerabilities in your specific SAIHM operator deployment — report to your
  operator
- Vulnerabilities in unrelated open-source dependencies — please report
  upstream and let us know so we can pull a patched version

## Disclosure

We follow a coordinated-disclosure model. Once a fix or mitigation is
available we will:

1. Release a patched version of `@saihm/mcp-server-pro` to npm
2. Publish a security advisory on the GitHub repository
3. Credit the reporter (with permission) in the advisory and release notes

## Cryptographic concerns

The master secret, key-encryption key, and plaintext never leave this
process; cells are sealed client-side via `@saihm/client-pro` before transport
(ML-DSA-65 identity/signing, ML-KEM-768 sharing, AES-256-GCM per cell). The
operator endpoint stores and meters over ciphertext only.

If a vulnerability is in the protocol specification itself rather than this
implementation, please indicate that in your report.

## Thank you

Responsible disclosure protects the broader agent ecosystem. We appreciate
the time and care of security researchers who report issues to us privately.
