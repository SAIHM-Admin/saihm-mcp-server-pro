# Changelog

All notable changes to `@saihm/mcp-server-pro` are documented here. This project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.3] — 2026-06-24

### Added

- `recallShared(grant)` — read a cell another agent shared **to** you (the recipient side of `share`). Pins the sharer's `agentIdHash` out-of-band, verifies the sharer's signature and the cell's content signature, and fails closed (returns `null`) when there is no live grant — e.g. after the sharer revokes the grant or crypto-shreds the cell. `KeySubstitutionError` is re-exported so callers can `instanceof`-handle a sharer key-substitution.
- `repository` metadata linking the package to its source.

## [0.1.0] — 2026-06-22

Initial public release.

- `SaihmProClient` — production thin-client for SAIHM non-custodial memory. Seals every cell client-side via [`@saihm/client-pro`](https://www.npmjs.com/package/@saihm/client-pro) (ML-DSA-65 identity, per-cell AES-256-GCM DEK wrapped under a client KEK, ML-KEM-768 authenticated sharing) and POSTs opaque ciphertext to the blind SAIHM `/mcp` endpoint. The master secret, KEK, and plaintext never leave the process.
- API: `remember`, `recall`, `recallOne`, `forget`, `status`, `share`, `revokeShare`; `bootFromEnv()`; getters `agentIdHash`, `identityRecord`.
- Endpoint hardening (HTTPS-only; loopback `http` permitted for local dev), signed monotonic anti-replay sequencing with optional mode-600 persistence, and a fully typed `SaihmEndpointError` surface.

[0.1.3]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.3
[0.1.0]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.0
