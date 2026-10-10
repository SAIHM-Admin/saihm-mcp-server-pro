// @saihm production thin-client — public surface. Seals client-side via @saihm/client-pro, then
// POSTs opaque ciphertext to the blind SAIHM endpoint. Holds no plaintext or key material on the wire.

export { SaihmProClient, SaihmEndpointError, DEFAULT_ENDPOINT } from './client.js';
// Re-exported so consumers can `instanceof`-catch the error `recallShared` throws on a sharer
// key-substitution without taking a direct dependency on @saihm/client-pro.
export { KeySubstitutionError } from '@saihm/client-pro';
export type {
  RememberResult,
  RecalledCell,
  ForgetResult,
  StatusSnapshot,
  ShareResult,
  RevokeResult,
  RememberOpts,
  ShareGrant,
  SharedReadGrant,
  SharedAnnouncement,
  RecallWithShared,
  SaihmProClientOpts,
  ShareReissueReport,
  ShareReissueSkip,
  VersionListing,
  ListedVersion,
  WarmStartOffer,
  SharesPage,
  SharesPageRow,
} from './client.js';
export type { WarmStartSnapshot } from './warm-start.js';
// The paged share listing's whole pass (`listAllShares`): its result, why one is incomplete, and its entries.
export type { SharesPass, SharesPassEnd, ListingEntry } from './share-events.js';
