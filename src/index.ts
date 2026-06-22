// @saihm production thin-client — public surface. Seals client-side via @saihm/client-pro, then
// POSTs opaque ciphertext to the blind SAIHM endpoint. Holds no plaintext or key material on the wire.

export { SaihmProClient, SaihmEndpointError } from './client.js';
export type {
  RememberResult,
  RecalledCell,
  ForgetResult,
  StatusSnapshot,
  ShareResult,
  RevokeResult,
  RememberOpts,
  ShareGrant,
  SaihmProClientOpts,
} from './client.js';
