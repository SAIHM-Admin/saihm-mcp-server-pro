/**
 * SAIHM — production thin-client (`SaihmProClient`), non-custodial.
 *
 * Every cryptographic operation that touches plaintext or the master secret runs HERE, client-side,
 * via `@saihm/client-pro`. The wire carries only opaque ciphertext + wrapped DEKs + ML-KEM share
 * ciphertext; the SAIHM endpoint stores / anchors / bills BLIND and never holds a key able to read
 * the memory.
 *
 * Transport mirrors the standards thin-client (`@saihm/mcp-server` `saihm_runtime_client.ts`)
 * VERBATIM: `POST {method, params}` + `Authorization: Bearer <JWT>` to the bridge `/mcp`. The bridge
 * verifies the JWT and injects tenant = JWT.sub = agentIdHash + tier; this client sends NEITHER
 * tenant NOR tier. The only behavioural difference from the custodial standards client: `params` are
 * SEALED client-side before POST, and recall OPENS client-side after fetch.
 *
 * Read-path trust: a recalled cell is accepted only if its decoded envelope is bound to THIS agent
 * (`agentIdHash`) and to the requested cell id, and decrypts under this identity's KEK. The cell id
 * and sequence are taken from the AEAD-authenticated envelope, never from the server's row label —
 * a blind/compromised endpoint cannot relabel, mis-attribute, or rollback a cell undetected.
 *
 * Configure via env (see {@link SaihmProClient.bootFromEnv}):
 *   SAIHM_ENDPOINT_URL      `https://…/mcp` (or `http://` only for 127.0.0.1 / localhost, dev).
 *   SAIHM_AUTH_HEADER       OPTIONAL Authorization value, e.g. `"Bearer <JWT>"`. When UNSET, the
 *                           client SELF-ONBOARDS: it mints + auto-refreshes its own short-lived JWT
 *                           from the master secret (ML-DSA challenge/response against `/api/onboard`),
 *                           so a subscriber pastes one config ONCE and never re-pastes a token. When
 *                           set, it is used verbatim and no self-onboarding occurs.
 *   SAIHM_PAYMENT_METHOD    required for self-onboarding (e.g. `"stripe"` / `"stablecoin"`); the
 *                           proof-of-entitlement rail the endpoint checks. Ignored when SAIHM_AUTH_HEADER is set.
 *   SAIHM_MASTER_SECRET_HEX >= 64 hex chars (>= 32 bytes) of high-entropy material; CLIENT-HELD,
 *                           never transmitted or logged. Its derived `agentIdHash` MUST equal the
 *                           JWT `sub` (the blind endpoint rejects a write whose signed agentIdHash
 *                           != JWT.sub — BLIND_ATTRIBUTION_MISMATCH).
 *   SAIHM_TIER              the billing tier label baked into sealed cell metadata. REQUIRED for
 *                           self-onboarding (it is part of the onboard request); otherwise optional —
 *                           if unset (static-auth mode) the client resolves it once via `status()`.
 *   SAIHM_DISCOVERY_SOURCE  OPTIONAL attribution tag (e.g. `"glama"`, `"mcp-registry"`) naming the
 *                           channel this install came from; sent as `source` on self-onboard so the
 *                           operator can attribute the paid conversion. Sanitised endpoint-side.
 *   SAIHM_SEQ_STATE_PATH    optional path; persists per-cell seq high-water marks (mode 600) so a
 *                           cell UPDATE survives a process restart without a stale-seq rejection.
 *
 * Concurrency: writes to DISTINCT cells are safe to run concurrently. Concurrent updates to the
 * SAME cell are single-writer by contract — the server's monotonic-seq guard rejects the loser with
 * a typed stale-seq error (no corruption); serialize same-cell updates if you need both to land.
 */

import { randomBytes } from 'node:crypto';
import {
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname } from 'node:path';

import {
  deriveIdentity,
  signChallenge,
  sealCell,
  openCell,
  shareCell,
  decodeShareEnvelope,
  unwrapSharedDek,
  verifyShareSig,
  openCellWithDek,
  verifyEnvelope,
  verifyIdentityRecord,
  encodeEnvelope,
  decodeEnvelope,
  encodeShareEnvelope,
  encodeIdentityRecord,
  decodeIdentityRecord,
  fromHex,
  toHex,
  utf8,
  fromUtf8,
  ctEqual,
  SeqHighWaterMark,
} from '@saihm/client-pro';
import type {
  ClientIdentity,
  WireEnvelope,
  WireShareEnvelope,
  WireIdentityRecord,
} from '@saihm/client-pro';

const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_SEQ = (1n << 64n) - 1n; // wire uint64 ceiling (mirrors client-pro wire U64_MAX)

/** Mirrors the standards client: https only, except 127.0.0.1 / localhost over http (dev). */
function assertEndpointUrl(endpoint: string): void {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new Error(`SAIHM_ENDPOINT_URL is not a valid URL: ${endpoint}`);
  }
  if (url.protocol === 'https:') return;
  if (
    url.protocol === 'http:' &&
    (url.hostname === '127.0.0.1' || url.hostname === 'localhost')
  )
    return;
  throw new Error(
    `SAIHM_ENDPOINT_URL must use https:// (got ${url.protocol}//). ` +
      `Plain http:// is only allowed for 127.0.0.1 or localhost (dev).`,
  );
}

/** Refresh a self-onboard JWT this long before its `exp` (cushions clock skew + in-flight latency). */
const JWT_REFRESH_SKEW_MS = 60_000;
/** Conservative assumed lifetime for an opaque (non-JWT) token whose `exp` we cannot read. */
const OPAQUE_TOKEN_TTL_MS = 5 * 60_000;

/** Decode a JWT's `exp` (seconds since epoch) into epoch-ms; `undefined` if it is not parseable. */
function jwtExpMs(jwt: string): number | undefined {
  const parts = jwt.split('.');
  const payloadB64 = parts[1];
  if (parts.length !== 3 || !payloadB64) return undefined;
  try {
    const payload = JSON.parse(
      Buffer.from(payloadB64, 'base64url').toString('utf-8'),
    ) as { exp?: unknown };
    if (typeof payload.exp === 'number' && Number.isFinite(payload.exp)) {
      return payload.exp * 1000;
    }
  } catch {
    /* opaque / non-JWT token — caller falls back to a conservative TTL */
  }
  return undefined;
}

/**
 * A failure surfaced by the SAIHM endpoint or transport. `code` is the endpoint's typed error
 * string when present (e.g. `"BLIND_NO_FREE_TIER"`, `"BLIND_BAD_EXPIRY"`, `"BLIND_STALE_SEQ"`,
 * `"BLIND_SCOPE_UNSUPPORTED"`, `"governance_unavailable"`, `"tenant_erased"`) or a client-side
 * transport code (`"timeout"`, `"network"`, `"response_too_large"`, `"malformed_json"`,
 * `"seq_exhausted"`) or a read-integrity code (`"malformed_envelope"`, `"malformed_response"`,
 * `"foreign_envelope"`, `"cell_mismatch"`, `"stale_cell"`, `"undecryptable"`, `"cell_not_found"`)
 * or a recipient share-read code (`"bad_sharer"`, `"malformed_share"`, `"foreign_share"`,
 * `"share_mismatch"`, `"bad_share_sig"`, `"undecryptable_share"`, `"unverified_envelope"`)
 * or a caller-input code (`"bad_recipient"` — a malformed share recipient record / pinned hash).
 * The message never includes the response body verbatim; branch on `status` / `code`.
 */
export class SaihmEndpointError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | undefined,
    message: string,
  ) {
    super(message);
    this.name = 'SaihmEndpointError';
  }
}

/** Read a response body with a hard byte budget — never trusts the content-length header. */
async function readBodyCapped(
  res: Response,
  max: number,
  method: string,
): Promise<string> {
  const tooLarge = (): SaihmEndpointError =>
    new SaihmEndpointError(
      0,
      'response_too_large',
      `SAIHM endpoint ${method} response exceeded ${max}B`,
    );
  const body = res.body;
  if (!body) {
    const t = await res.text();
    if (Buffer.byteLength(t) > max) throw tooLarge();
    return t;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > max) {
        await reader.cancel();
        throw tooLarge();
      }
      chunks.push(value);
    }
  }
  return Buffer.concat(chunks).toString('utf-8');
}

// ── Result shapes (the blind endpoint's JSON; bigint -> decimal string, bytes -> hex) ────────────
export interface RememberResult {
  /** The cell identifier this content was stored under (caller-supplied or client-generated). */
  cellId: string;
  /** Opaque storage-shard id (hex). */
  shardId: string;
  /** The monotonic per-cell sequence number this write was committed at (decimal string). */
  seq: string;
  /** sha256(ciphertext) (hex) — the anchorable commitment to the stored bytes. */
  commitmentHash: string;
}

export interface RecalledCell {
  cellId: string;
  /** The decrypted plaintext (opened client-side; the endpoint never saw it). */
  plaintext: string;
  /** The committed sequence number of the returned envelope (decimal string). */
  seq: string;
  /** sha256(ciphertext) (hex), taken from the authenticated envelope. */
  commitmentHash: string;
}

export interface ForgetResult {
  cellId: string;
  shardId: string;
  complete: boolean;
  sharesPurged: number;
  steps: ReadonlyArray<{ step: string; success: boolean; detail: string }>;
  epoch: string;
}

export interface StatusSnapshot {
  agentIdHashHex: string;
  tier: string;
  activeShardCount: number;
  activeSharingContracts: number;
  bfsi: number;
  bfsi_R: string;
  bfsi_M: string;
  prsInstrumented: boolean;
  snapshotEpoch: string;
  custody: string;
}

export interface ShareResult {
  cellId: string;
  sharer: string;
  recipient: string;
}

export interface RevokeResult {
  cellId: string;
  recipient: string;
  revoked: boolean;
}

export interface RememberOpts {
  /**
   * Target an EXISTING cell to update it (a new monotonic seq is issued). Omit to create a fresh
   * cell under a random id. When you pass a `cellId` the client has no local high-water mark for
   * (e.g. after a restart with no `SAIHM_SEQ_STATE_PATH`), it first reads the current LIVE envelope
   * to learn the server seq. Note: a cell that was previously `forget`-ten is permanently retired —
   * the endpoint retains its sequence high-water mark for anti-resurrection, so reusing that id
   * surfaces a typed `BLIND_STALE_SEQ` error; choose a fresh id rather than reusing a forgotten one.
   */
  cellId?: string;
}

export interface ShareGrant {
  /** The cell to grant. The client recalls it to obtain the sharer envelope to re-wrap the DEK. */
  cellId: string;
  /** The grantee's identity record (hex), fetched from the directory; verified against the pin. */
  recipientRecord: WireIdentityRecord;
  /** The grantee's agentIdHash (hex), pinned OUT-OF-BAND — defeats directory key substitution. */
  recipientPinnedAgentIdHashHex: string;
  /** Sharing scope; defaults to `"read"`. */
  scope?: 'read' | 'write' | 'readwrite';
  /** Optional expiry as a UNIX-epoch count; omit / null for no time bound. */
  expiryEpoch?: bigint | null;
}

/** Inputs to read a cell that another agent shared TO this agent (see {@link SaihmProClient.recallShared}). */
export interface SharedReadGrant {
  /** The SHARER's agentIdHash (hex), pinned OUT-OF-BAND — the namespace the cell was shared from. */
  sharerPinnedAgentIdHashHex: string;
  /** The SHARER's identity record (hex), from the directory; verified against the pin (anti key-substitution). */
  sharerRecord: WireIdentityRecord;
  /** The shared cell id to read. */
  cellId: string;
}

export interface SaihmProClientOpts {
  /**
   * The caller's billing tier baked into each cell's (signed) public metadata. Best-effort label
   * only — billing is authoritative from the JWT at the endpoint. If omitted, the client resolves
   * the authoritative tier once via `status()` and caches it, so the metadata stays truthful.
   */
  tier?: string;
  /** Path to persist per-cell seq high-water marks (mode 600). Enables cross-restart cell updates. */
  seqStatePath?: string;
  /**
   * The proof-of-entitlement rail (`"stripe"`, `"stablecoin"`, …) used when SELF-ONBOARDING (i.e.
   * no static `authHeader`). Sent in the `/api/onboard` request alongside the ML-DSA-signed nonce.
   * Required for self-onboarding; ignored when a static `authHeader` is supplied.
   */
  paymentMethod?: string;
  /**
   * Optional discovery-attribution tag naming the channel this install came from
   * (e.g. `"glama"`, `"mcp-registry"`). Sent as `source` in the `/api/onboard` body so
   * the operator can attribute a paid conversion to its origin (referrer is not
   * available for CLI/registry installs). Free-form; the endpoint sanitises it.
   */
  discoverySource?: string;
  /**
   * Override the base origin used for self-onboarding requests (`/api/onboard/challenge`,
   * `/api/onboard`). Defaults to the origin of `SAIHM_ENDPOINT_URL`. Advanced / testing knob.
   */
  onboardBaseUrl?: string;
  /**
   * Per-request timeout budget in milliseconds (default 30000). A request that exceeds it is aborted
   * and surfaces a typed `SaihmEndpointError(408, "timeout")`. An advanced / testing tuning knob — a
   * non-positive or non-numeric value falls back to the default.
   */
  requestTimeoutMs?: number;
}

// ── per-cell seq high-water store (in-memory rule from @saihm/client-pro, optional file mirror) ──
class SeqState {
  private readonly hwm = new SeqHighWaterMark();
  private readonly cellIds = new Set<string>();

  constructor(
    private readonly agentIdHashHex: string,
    private readonly path?: string,
  ) {
    if (this.path) this.load();
  }

  private load(): void {
    let raw: string;
    try {
      raw = readFileSync(this.path!, 'utf-8');
    } catch {
      return; // no state yet — first run
    }
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return; // corrupt/empty — treat as no state (admit() is monotonic; nothing regresses)
    }
    for (const [cellId, v] of Object.entries(obj)) {
      if (typeof v !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(v)) continue;
      if (this.hwm.admit(this.agentIdHashHex, cellId, BigInt(v)))
        this.cellIds.add(cellId);
    }
  }

  private persist(): void {
    if (!this.path) return;
    const obj: Record<string, string> = {};
    for (const cellId of this.cellIds) {
      const c = this.hwm.current(this.agentIdHashHex, cellId);
      if (c !== undefined) obj[cellId] = c.toString(10);
    }
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp.${process.pid}.${Date.now()}`;
    writeFileSync(tmp, JSON.stringify(obj), { mode: 0o600 });
    renameSync(tmp, this.path); // atomic; inherits the tmp file's 0600 mode
  }

  current(cellId: string): bigint | undefined {
    return this.hwm.current(this.agentIdHashHex, cellId);
  }

  /** Seed / advance the high-water mark to a server-observed value (monotonic; persists on change). */
  observe(cellId: string, seq: bigint): void {
    if (this.hwm.admit(this.agentIdHashHex, cellId, seq)) {
      this.cellIds.add(cellId);
      this.persist();
    }
  }

  /** The next seq to use for `cellId` = current high-water + 1 (1 for a never-seen cell). */
  next(cellId: string): bigint {
    return (this.current(cellId) ?? 0n) + 1n;
  }
}

export class SaihmProClient {
  private readonly endpoint: string;
  /** A static Authorization header (e.g. `"Bearer <JWT>"`), or `undefined` in self-onboard mode. */
  private readonly staticAuthHeader: string | undefined;
  /** Self-onboard only: the proof-of-entitlement rail sent to `/api/onboard`. */
  private readonly paymentMethod: string | undefined;
  /** WS-J discovery-attribution tag sent as `source` on self-onboard (optional). */
  private readonly discoverySource: string | undefined;
  /** Base origin for `/api/onboard*` + `/api/stripe/*` calls (defaults to the endpoint origin). */
  private readonly onboardBase: string;
  private readonly identity: ClientIdentity;
  private readonly agentIdHashHex: string;
  private readonly seq: SeqState;
  private readonly requestTimeoutMs: number;
  private tier: string | undefined;
  // Self-onboard token cache (single-flight via authInFlight; never written to disk).
  private cachedJwt: string | undefined;
  private cachedJwtRefreshAtMs = 0;
  private authInFlight: Promise<string> | null = null;

  constructor(
    endpoint: string,
    authHeader: string | undefined,
    masterSecret: Uint8Array,
    opts: SaihmProClientOpts = {},
  ) {
    assertEndpointUrl(endpoint);
    this.endpoint = endpoint;
    // deriveIdentity derives the KEK + ML-DSA/ML-KEM keys and does NOT retain `masterSecret`.
    this.identity = deriveIdentity(masterSecret);
    this.agentIdHashHex = toHex(this.identity.agentIdHash);
    this.tier = opts.tier;
    this.discoverySource = opts.discoverySource;
    this.seq = new SeqState(this.agentIdHashHex, opts.seqStatePath);
    this.requestTimeoutMs =
      typeof opts.requestTimeoutMs === 'number' && opts.requestTimeoutMs > 0
        ? opts.requestTimeoutMs
        : REQUEST_TIMEOUT_MS;

    // Base for /api/onboard* + /api/stripe/* — always available (the `join` flow + self-onboard need it).
    this.onboardBase = (
      opts.onboardBaseUrl ?? new URL(endpoint).origin
    ).replace(/\/+$/, '');

    const trimmedAuth =
      typeof authHeader === 'string' && authHeader.trim()
        ? authHeader
        : undefined;
    if (trimmedAuth) {
      this.staticAuthHeader = trimmedAuth;
    } else {
      // SELF-ONBOARD MODE: mint + auto-refresh the JWT from this identity. Requires the tier (it is
      // part of the onboard request) and the payment method (the entitlement rail the endpoint checks).
      if (!opts.paymentMethod) {
        throw new Error(
          'self-onboarding requires a paymentMethod (set SAIHM_PAYMENT_METHOD) when no auth header is supplied',
        );
      }
      if (this.tier === undefined) {
        throw new Error(
          'self-onboarding requires a tier (set SAIHM_TIER) when no auth header is supplied',
        );
      }
      this.paymentMethod = opts.paymentMethod;
    }
  }

  static bootFromEnv(): SaihmProClient {
    const endpoint = process.env.SAIHM_ENDPOINT_URL;
    const auth = process.env.SAIHM_AUTH_HEADER;
    if (!endpoint) throw new Error('SAIHM_ENDPOINT_URL env var required');
    // The master secret may be supplied inline via SAIHM_MASTER_SECRET_HEX, or — preferably for
    // operators / security-conscious users — as the path to a mode-600 file via
    // SAIHM_MASTER_SECRET_FILE so the root seed is never inlined into a synced/shared MCP config.
    // FILE wins when both are set.
    const secretFile = process.env.SAIHM_MASTER_SECRET_FILE;
    let secretHex: string | undefined;
    if (secretFile) {
      try {
        secretHex = readFileSync(secretFile, 'utf-8');
      } catch {
        throw new Error(
          `SAIHM_MASTER_SECRET_FILE could not be read: ${secretFile}`,
        );
      }
      try {
        // Advisory only (never blocks): warn if the secret file is group/world-accessible on POSIX.
        if (
          process.platform !== 'win32' &&
          (statSync(secretFile).mode & 0o077) !== 0
        ) {
          process.stderr.write(
            `warning: SAIHM_MASTER_SECRET_FILE ${secretFile} is group/world-accessible; chmod 600 it.\n`,
          );
        }
      } catch {
        /* stat is advisory only */
      }
    } else {
      secretHex = process.env.SAIHM_MASTER_SECRET_HEX;
    }
    if (!secretHex)
      throw new Error(
        'SAIHM_MASTER_SECRET_HEX (or SAIHM_MASTER_SECRET_FILE) env var required (>= 64 hex chars)',
      );
    let master: Uint8Array;
    try {
      master = fromHex(secretHex.trim());
    } catch {
      throw new Error(
        'SAIHM_MASTER_SECRET_HEX must be canonical lowercase hex',
      );
    }
    if (master.length < 32) {
      master.fill(0);
      throw new Error('SAIHM_MASTER_SECRET_HEX must decode to >= 32 bytes');
    }
    const optTier = process.env.SAIHM_TIER;
    const optSeqPath = process.env.SAIHM_SEQ_STATE_PATH;
    const optPaymentMethod = process.env.SAIHM_PAYMENT_METHOD;
    const optDiscoverySource = process.env.SAIHM_DISCOVERY_SOURCE;
    const opts: SaihmProClientOpts = {};
    if (optTier) opts.tier = optTier;
    if (optSeqPath) opts.seqStatePath = optSeqPath;
    if (optPaymentMethod) opts.paymentMethod = optPaymentMethod;
    if (optDiscoverySource) opts.discoverySource = optDiscoverySource;
    // SAIHM_AUTH_HEADER is OPTIONAL. Unset => self-onboard from SAIHM_MASTER_SECRET_HEX +
    // SAIHM_PAYMENT_METHOD + SAIHM_TIER (paste-once). Set => used verbatim, no self-onboarding.
    try {
      return new SaihmProClient(endpoint, auth, master, opts);
    } finally {
      master.fill(0); // scrub the decoded master secret; the identity holds only derived material
    }
  }

  /** This client's public agent identifier (hex) = sha256(ML-DSA pubkey) = the JWT sub. */
  get agentIdHash(): string {
    return this.agentIdHashHex;
  }

  /** This client's PUBLIC identity record (hex) to publish so others can share TO this agent. */
  get identityRecord(): WireIdentityRecord {
    return encodeIdentityRecord(this.identity.identityRecord);
  }

  /**
   * Resolve the Authorization header for a request. In static-auth mode this is the configured
   * header. In self-onboard mode it returns a cached JWT, transparently minting/refreshing one
   * (single-flight) when none is cached or it is within 60s of expiry.
   */
  private async currentAuthHeader(): Promise<string> {
    if (this.staticAuthHeader) return this.staticAuthHeader;
    if (this.cachedJwt && Date.now() < this.cachedJwtRefreshAtMs) {
      return 'Bearer ' + this.cachedJwt;
    }
    if (!this.authInFlight) {
      this.authInFlight = this.onboard().finally(() => {
        this.authInFlight = null;
      });
    }
    return 'Bearer ' + (await this.authInFlight);
  }

  /**
   * Mint a fresh subscriber JWT: GET a challenge nonce, sign it with this identity's ML-DSA secret
   * key, and POST {pubkey, nonce, signature, tier, paymentMethod} to `/api/onboard`. The endpoint
   * verifies the signature + an active subscription and returns a short-lived JWT, which is cached
   * with its decoded expiry. The master secret / secret key never leave this process.
   */
  private async onboard(): Promise<string> {
    const base = this.onboardBase;
    const ch = await this.onboardFetch<{ nonce?: unknown }>(
      base + '/api/onboard/challenge',
      { method: 'GET' },
    );
    const nonce = ch.nonce;
    if (typeof nonce !== 'string' || nonce.length === 0) {
      throw new SaihmEndpointError(
        502,
        'onboard_no_nonce',
        'onboard challenge returned no nonce',
      );
    }
    let nonceBytes: Uint8Array;
    try {
      nonceBytes = fromHex(nonce);
    } catch {
      throw new SaihmEndpointError(
        502,
        'onboard_bad_nonce',
        'onboard challenge nonce is not hex',
      );
    }
    const signature = toHex(
      signChallenge(this.identity.mldsaSecretKey, nonceBytes),
    );
    const out = await this.onboardFetch<{ jwt?: unknown }>(
      base + '/api/onboard',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          pubkey: toHex(this.identity.mldsaPubKey),
          nonce,
          signature,
          tier: this.tier,
          paymentMethod: this.paymentMethod,
          ...(this.discoverySource ? { source: this.discoverySource } : {}),
        }),
      },
    );
    if (typeof out.jwt !== 'string' || out.jwt.length === 0) {
      throw new SaihmEndpointError(
        502,
        'onboard_no_jwt',
        'onboard did not return a JWT',
      );
    }
    this.cachedJwt = out.jwt;
    // Schedule proactive refresh BEFORE expiry. Honor the token's own `exp`; for an opaque token assume
    // a short conservative TTL. Clamp the skew to at most half the remaining life so a short-lived token
    // still yields a positive cache window (otherwise we would re-onboard on every single call).
    const now = Date.now();
    const expMs = jwtExpMs(out.jwt) ?? now + OPAQUE_TOKEN_TTL_MS;
    const skew = Math.min(
      JWT_REFRESH_SKEW_MS,
      Math.max(0, Math.floor((expMs - now) / 2)),
    );
    this.cachedJwtRefreshAtMs = expMs - skew;
    return out.jwt;
  }

  /**
   * Self-serve operator join: request a Stripe HOSTED-checkout URL to subscribe THIS identity at the
   * configured tier (`SAIHM_TIER`). Open the URL in a browser to pay; afterwards the client
   * self-onboards on the next run. Only the PUBLIC key is sent; the master secret never leaves here.
   */
  async requestCheckoutUrl(): Promise<string> {
    if (this.tier === undefined) {
      throw new SaihmEndpointError(
        0,
        'no_tier',
        'join requires a tier (set SAIHM_TIER)',
      );
    }
    // Proof-of-possession: /api/stripe/checkout requires a fresh server nonce signed
    // by THIS identity's ML-DSA secret key (the same gate /api/onboard uses), proving
    // we hold the private key for the mldsaPubKey we send. Without it the route 401s.
    const ch = await this.onboardFetch<{ nonce?: unknown }>(
      this.onboardBase + '/api/onboard/challenge',
      { method: 'GET' },
    );
    const nonce = ch.nonce;
    if (typeof nonce !== 'string' || nonce.length === 0) {
      throw new SaihmEndpointError(
        502,
        'checkout_no_nonce',
        'onboard challenge returned no nonce',
      );
    }
    let nonceBytes: Uint8Array;
    try {
      nonceBytes = fromHex(nonce);
    } catch {
      throw new SaihmEndpointError(
        502,
        'checkout_bad_nonce',
        'onboard challenge nonce is not hex',
      );
    }
    const signature = toHex(signChallenge(this.identity.mldsaSecretKey, nonceBytes));
    const out = await this.onboardFetch<{ url?: unknown }>(
      this.onboardBase + '/api/stripe/checkout',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          tier: this.tier,
          mldsaPubKey: toHex(this.identity.mldsaPubKey),
          nonce,
          signature,
          uiMode: 'hosted',
        }),
      },
    );
    if (typeof out.url !== 'string' || !out.url.startsWith('https://')) {
      throw new SaihmEndpointError(
        502,
        'checkout_no_url',
        'checkout did not return a hosted URL',
      );
    }
    return out.url;
  }

  /** Onboard-path HTTP with the same timeout + body-cap + typed-error discipline as `doCall`. */
  private async onboardFetch<T>(url: string, init: RequestInit): Promise<T> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.requestTimeoutMs);
    try {
      const res = await fetch(url, { ...init, signal: ctrl.signal });
      const text = await readBodyCapped(res, MAX_RESPONSE_BYTES, 'onboard');
      if (!res.ok) {
        let code: string | undefined;
        try {
          const j = JSON.parse(text) as Record<string, unknown>;
          if (typeof j.error === 'string') code = j.error;
        } catch {
          /* non-JSON error body */
        }
        throw new SaihmEndpointError(
          res.status,
          code,
          `SAIHM onboard failed: ${res.status} ${res.statusText}` +
            (code ? ` (${code})` : ''),
        );
      }
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new SaihmEndpointError(
          res.status,
          'malformed_json',
          'SAIHM onboard returned a non-JSON 2xx response',
        );
      }
    } catch (e) {
      if (e instanceof SaihmEndpointError) throw e;
      if (e instanceof Error && e.name === 'AbortError') {
        throw new SaihmEndpointError(
          408,
          'timeout',
          `SAIHM onboard timed out after ${this.requestTimeoutMs}ms`,
        );
      }
      throw new SaihmEndpointError(
        0,
        'network',
        'SAIHM onboard transport error',
      );
    } finally {
      clearTimeout(timer);
    }
  }

  private async call<T>(method: string, params: unknown): Promise<T> {
    const header = await this.currentAuthHeader();
    try {
      return await this.doCall<T>(method, params, header);
    } catch (e) {
      // Self-onboard mode: a 401 means the cached JWT expired or was revoked mid-flight. Drop it,
      // re-onboard once, and retry. Static-auth mode surfaces the 401 to the caller unchanged.
      if (
        !this.staticAuthHeader &&
        e instanceof SaihmEndpointError &&
        e.status === 401
      ) {
        this.cachedJwt = undefined;
        const fresh = await this.currentAuthHeader();
        return await this.doCall<T>(method, params, fresh);
      }
      throw e;
    }
  }

  private async doCall<T>(
    method: string,
    params: unknown,
    authHeader: string,
  ): Promise<T> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.requestTimeoutMs);
    try {
      const res = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: authHeader,
        },
        body: JSON.stringify({ method, params }),
        signal: ctrl.signal,
      });
      const text = await readBodyCapped(res, MAX_RESPONSE_BYTES, method);
      if (!res.ok) {
        let code: string | undefined;
        try {
          const j = JSON.parse(text) as Record<string, unknown>;
          if (typeof j.error === 'string') code = j.error;
        } catch {
          /* non-JSON error body — leave code undefined */
        }
        throw new SaihmEndpointError(
          res.status,
          code,
          `SAIHM endpoint ${method} failed: ${res.status} ${res.statusText}` +
            (code ? ` (${code})` : ''),
        );
      }
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new SaihmEndpointError(
          res.status,
          'malformed_json',
          `SAIHM endpoint ${method} returned a non-JSON 2xx response`,
        );
      }
    } catch (e) {
      if (e instanceof SaihmEndpointError) throw e;
      if (e instanceof Error && e.name === 'AbortError') {
        throw new SaihmEndpointError(
          408,
          'timeout',
          `SAIHM endpoint ${method} timed out after ${this.requestTimeoutMs}ms`,
        );
      }
      throw new SaihmEndpointError(
        0,
        'network',
        `SAIHM endpoint ${method} transport error`,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Decode + authenticate + open a recalled envelope. The cell id and sequence come from the
   * AEAD-authenticated envelope, NOT the server's row label. Rejects (typed) a malformed envelope,
   * one bound to a different agent, one whose id != the requested id, or one this identity's KEK
   * cannot open — so a blind/compromised endpoint cannot relabel, mis-attribute, or rollback a cell.
   */
  private openRow(
    expectedCellId: string | null,
    wire: WireEnvelope,
  ): RecalledCell {
    let env;
    try {
      env = decodeEnvelope(wire);
    } catch {
      throw new SaihmEndpointError(
        502,
        'malformed_envelope',
        `endpoint returned a malformed envelope${expectedCellId ? ` for cell '${expectedCellId}'` : ''}`,
      );
    }
    if (!ctEqual(env.agentIdHash, this.identity.agentIdHash)) {
      throw new SaihmEndpointError(
        502,
        'foreign_envelope',
        'endpoint returned an envelope bound to a different agent',
      );
    }
    if (expectedCellId !== null && env.cellId !== expectedCellId) {
      throw new SaihmEndpointError(
        502,
        'cell_mismatch',
        `endpoint returned cell '${env.cellId}' for requested '${expectedCellId}'`,
      );
    }
    // Read-path rollback guard: env.seq is authenticated, but a hostile/buggy endpoint could replay
    // an OLDER validly-sealed version. Reject anything below a sequence we have already observed.
    const knownSeq = this.seq.current(env.cellId);
    if (knownSeq !== undefined && env.seq < knownSeq) {
      throw new SaihmEndpointError(
        502,
        'stale_cell',
        `endpoint returned a rolled-back envelope for cell '${env.cellId}' (seq ${env.seq} < ${knownSeq})`,
      );
    }
    let plaintext: string;
    try {
      plaintext = fromUtf8(openCell(env, this.identity.kek));
    } catch {
      throw new SaihmEndpointError(
        502,
        'undecryptable',
        `cell '${env.cellId}' could not be opened with this identity's key`,
      );
    }
    this.seq.observe(env.cellId, env.seq); // env.seq is authenticated (bound into the AEAD AAD)
    return {
      cellId: env.cellId,
      plaintext,
      seq: env.seq.toString(10),
      commitmentHash: toHex(env.publicMeta.commitmentHash),
    };
  }

  /** Authoritative tier from the JWT (via status), cached. Used to label sealed cell metadata. */
  private async resolveTier(): Promise<string> {
    if (this.tier !== undefined) return this.tier;
    const st = await this.status();
    this.tier = st.tier;
    return st.tier;
  }

  /**
   * Seal `content` client-side and store it BLIND. Creates a new cell, or updates `opts.cellId`
   * with a fresh monotonic seq. Returns the storage receipt (no plaintext leaves the process).
   */
  async remember(
    content: string,
    opts: RememberOpts = {},
  ): Promise<RememberResult> {
    const cellId = opts.cellId ?? randomBytes(16).toString('hex');
    // Updating a provided cellId we have no local high-water for: learn the LIVE server seq first so
    // the write is not guaranteed-rejected as stale. Route the discovered envelope through openRow so
    // its seq is AEAD-AUTHENTICATED (openCell binds seq into the AAD) BEFORE we seed the high-water
    // mark. A structural decode alone is NOT enough: a hostile/buggy endpoint could forge a high seq
    // on an otherwise-valid-looking envelope and poison our monotonic counter — burning the cell's
    // sequence space and, with a persisted seq file, corrupting it across restarts.
    if (opts.cellId !== undefined && this.seq.current(cellId) === undefined) {
      const existing = await this.recallRawOne(cellId);
      if (existing.found && existing.wire) {
        this.openRow(cellId, existing.wire); // decode + attribute + openCell(authenticates seq) + observe
      }
    }
    const seq = this.seq.next(cellId);
    if (seq > MAX_SEQ) {
      throw new SaihmEndpointError(
        0,
        'seq_exhausted',
        `cell '${cellId}' has exhausted its uint64 sequence space`,
      );
    }
    const tier = await this.resolveTier();
    const env = sealCell({
      plaintext: utf8(content),
      kek: this.identity.kek,
      mldsaSecretKey: this.identity.mldsaSecretKey,
      mldsaPubKey: this.identity.mldsaPubKey,
      agentIdHash: this.identity.agentIdHash,
      cellId,
      seq,
      tier,
    });
    const r = await this.call<RememberResult>('saihm_remember', {
      wire: encodeEnvelope(env),
    });
    this.seq.observe(cellId, seq); // advance only after the endpoint accepted the write
    return r;
  }

  private async recallRawOne(
    cellId: string,
  ): Promise<{ found: boolean; wire?: WireEnvelope }> {
    const r = await this.call<unknown>('saihm_recall', { cellId });
    if (typeof r !== 'object' || r === null || Array.isArray(r)) {
      throw new SaihmEndpointError(
        502,
        'malformed_response',
        'endpoint returned a malformed recall response',
      );
    }
    return r as { found: boolean; wire?: WireEnvelope };
  }

  /**
   * Recall + open ALL of this agent's cells, optionally keyword-filtered (client-side) by `query`.
   * All-or-nothing: a cell that fails read-integrity (malformed / foreign / undecryptable) throws a
   * typed {@link SaihmEndpointError} naming it, rather than being silently dropped (silent drops
   * would hide data loss). `forget` such a cell to exclude it.
   */
  async recall(query?: string): Promise<RecalledCell[]> {
    const rows = await this.call<unknown>('saihm_recall', {});
    if (!Array.isArray(rows)) {
      throw new SaihmEndpointError(
        502,
        'malformed_response',
        'endpoint returned a malformed recall-all response',
      );
    }
    const needle = query?.toLowerCase();
    const out: RecalledCell[] = [];
    // An honest endpoint stores exactly one current envelope per (tenant, cellId), so a recall-all set
    // never repeats a cellId. A repeat — even of two individually-authentic envelopes — is the endpoint
    // controlling cardinality: it could re-present a superseded version next to the live one (the
    // per-row rollback guard only rejects a DESCENDING seq) or duplicate a row to skew a caller's
    // aggregate. Reject the whole ambiguous response (all-or-nothing), keyed on the AUTHENTICATED
    // cellId from openRow, never the server's row label.
    const seen = new Set<string>();
    for (const raw of rows) {
      if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
        throw new SaihmEndpointError(
          502,
          'malformed_response',
          'endpoint returned a malformed recall-all row',
        );
      }
      const row = raw as {
        cellId: string;
        found: boolean;
        wire?: WireEnvelope;
      };
      if (!row.found || !row.wire) continue;
      const cell = this.openRow(null, row.wire); // trusts env.cellId/seq, not the server row label
      if (seen.has(cell.cellId)) {
        throw new SaihmEndpointError(
          502,
          'malformed_response',
          `endpoint returned cell '${cell.cellId}' more than once in a recall-all response`,
        );
      }
      seen.add(cell.cellId);
      if (
        needle !== undefined &&
        !cell.plaintext.toLowerCase().includes(needle)
      )
        continue;
      out.push(cell);
    }
    return out;
  }

  /** Recall + open a single cell. Returns `null` if it does not exist. */
  async recallOne(cellId: string): Promise<RecalledCell | null> {
    const r = await this.recallRawOne(cellId);
    if (!r.found || !r.wire) return null;
    return this.openRow(cellId, r.wire);
  }

  /** Crypto-shred a cell (GDPR Art.17): the endpoint destroys the wrapped DEK + tombstones. */
  async forget(cellId: string): Promise<ForgetResult> {
    return this.call('saihm_forget', { id: cellId });
  }

  /** Non-custodial status: operator-observable metadata only (no plaintext). */
  async status(): Promise<StatusSnapshot> {
    return this.call('saihm_status', {});
  }

  /**
   * GRANT a cell to another agent, end-to-end authenticated. The DEK is re-wrapped to the grantee's
   * pinned ML-KEM key client-side; the endpoint blind-stores the share envelope. `shareCell` rejects
   * a directory record that does not match the out-of-band pin (throws `KeySubstitutionError` before
   * any secret is bound). The grantee reads it with {@link SaihmProClient.recallShared}.
   */
  async share(grant: ShareGrant): Promise<ShareResult> {
    const own = await this.recallRawOne(grant.cellId);
    if (!own.found || !own.wire) {
      throw new SaihmEndpointError(
        404,
        'cell_not_found',
        `cannot share unknown cell '${grant.cellId}'`,
      );
    }
    let envelope;
    try {
      envelope = decodeEnvelope(own.wire);
    } catch {
      throw new SaihmEndpointError(
        502,
        'malformed_envelope',
        `endpoint returned a malformed envelope for cell '${grant.cellId}'`,
      );
    }
    if (!ctEqual(envelope.agentIdHash, this.identity.agentIdHash)) {
      throw new SaihmEndpointError(
        502,
        'foreign_envelope',
        'endpoint returned an envelope bound to a different agent',
      );
    }
    if (envelope.cellId !== grant.cellId) {
      throw new SaihmEndpointError(
        502,
        'cell_mismatch',
        `endpoint returned cell '${envelope.cellId}' for requested '${grant.cellId}'`,
      );
    }
    // Rollback parity with the read path: if we already know a newer seq for this cell, refuse to
    // re-wrap a stale version the endpoint may have replayed (the grantee would otherwise read it).
    const knownSeq = this.seq.current(grant.cellId);
    if (knownSeq !== undefined && envelope.seq < knownSeq) {
      throw new SaihmEndpointError(
        502,
        'stale_cell',
        `endpoint returned a rolled-back envelope for cell '${grant.cellId}' (seq ${envelope.seq} < ${knownSeq})`,
      );
    }
    // Caller-supplied grant inputs: surface a malformed record / pinned hash as a TYPED error rather
    // than leaking client-pro's raw WireFormatError / hex Error past this client's error contract.
    // (shareCell's KeySubstitutionError below is intentionally distinct — it is a security signal.)
    let recipientRecord;
    let recipientPinnedAgentIdHash;
    try {
      recipientRecord = decodeIdentityRecord(grant.recipientRecord);
      recipientPinnedAgentIdHash = fromHex(grant.recipientPinnedAgentIdHashHex);
    } catch {
      throw new SaihmEndpointError(
        0,
        'bad_recipient',
        'recipient identity record or pinned agentIdHash is malformed',
      );
    }
    const shareEnv = shareCell({
      envelope,
      sharerKek: this.identity.kek,
      sharerMldsaSecretKey: this.identity.mldsaSecretKey,
      sharerAgentIdHash: this.identity.agentIdHash,
      recipientRecord,
      recipientPinnedAgentIdHash,
    });
    const params: {
      shareWire: ReturnType<typeof encodeShareEnvelope>;
      scope: string;
      expiryEpoch?: string;
    } = {
      shareWire: encodeShareEnvelope(shareEnv),
      scope: grant.scope ?? 'read',
    };
    if (grant.expiryEpoch !== undefined && grant.expiryEpoch !== null) {
      params.expiryEpoch = grant.expiryEpoch.toString(10);
    }
    return this.call('saihm_share', params);
  }

  /** Revoke a prior grant to `recipientHex` for `cellId` (deletes the share envelope). */
  async revokeShare(
    cellId: string,
    recipientHex: string,
  ): Promise<RevokeResult> {
    return this.call('saihm_revoke_share', { cellId, recipient: recipientHex });
  }

  /**
   * Recipient READ of a cell shared TO this agent. Fetches the opaque ML-KEM share envelope and the
   * sharer's content ciphertext, authenticates the grant against the OUT-OF-BAND-pinned sharer key,
   * unwraps the content DEK with this agent's ML-KEM secret, and opens the content. Returns `null`
   * when no live grant exists (never shared, revoked, or expired) or the content was forgotten.
   *
   * Trust model (the endpoint is blind + assumed hostile): it never holds the DEK, so it cannot forge
   * content — a tampered ciphertext fails the AEAD open, a substituted cell fails the id/attribution
   * checks, and an unauthenticated share fails `verifyShareSig`. `verifyEnvelope` additionally proves
   * the sharer's ML-DSA signature over the exact content (non-repudiation). The recipient's tier must
   * be sharing-capable; otherwise the endpoint rejects the fetch (`BLIND_SHARE_TIER_REQUIRED`, 402).
   */
  async recallShared(grant: SharedReadGrant): Promise<RecalledCell | null> {
    // 1) Pin the sharer's identity (defeats directory key-substitution) → trusted sharer ML-DSA key.
    let sharerRecord;
    let sharerPinned;
    try {
      sharerRecord = decodeIdentityRecord(grant.sharerRecord);
      sharerPinned = fromHex(grant.sharerPinnedAgentIdHashHex);
    } catch {
      throw new SaihmEndpointError(
        0,
        'bad_sharer',
        'sharer identity record or pinned agentIdHash is malformed',
      );
    }
    verifyIdentityRecord(sharerRecord, sharerPinned); // throws KeySubstitutionError on a pin mismatch
    const sharerHex = toHex(sharerPinned);

    // 2) Fetch {share envelope, content ciphertext} for (sharer, cellId), keyed to THIS recipient.
    const r = await this.call<unknown>('saihm_recall', {
      sharer: sharerHex,
      cellId: grant.cellId,
    });
    if (typeof r !== 'object' || r === null || Array.isArray(r)) {
      throw new SaihmEndpointError(
        502,
        'malformed_response',
        'endpoint returned a malformed shared-recall response',
      );
    }
    const res = r as {
      found?: boolean;
      wire?: WireShareEnvelope;
      contentWire?: WireEnvelope;
    };
    if (!res.found || !res.wire || !res.contentWire) return null; // no live grant / content unavailable

    // 3) Authenticate the grant + unwrap the content DEK with this agent's ML-KEM secret.
    let share;
    try {
      share = decodeShareEnvelope(res.wire);
    } catch {
      throw new SaihmEndpointError(
        502,
        'malformed_share',
        `endpoint returned a malformed share envelope for cell '${grant.cellId}'`,
      );
    }
    if (!ctEqual(share.recipientAgentIdHash, this.identity.agentIdHash)) {
      throw new SaihmEndpointError(
        502,
        'foreign_share',
        'endpoint returned a share addressed to a different recipient',
      );
    }
    if (
      !ctEqual(share.sharerAgentIdHash, sharerPinned) ||
      share.cellId !== grant.cellId
    ) {
      throw new SaihmEndpointError(
        502,
        'share_mismatch',
        `endpoint returned a share for the wrong sharer/cell`,
      );
    }
    if (!verifyShareSig(share, sharerRecord.mldsaPubKey)) {
      throw new SaihmEndpointError(
        502,
        'bad_share_sig',
        'share envelope signature does not verify against the pinned sharer key',
      );
    }
    let dek;
    try {
      dek = unwrapSharedDek({
        share,
        recipientAgentIdHash: this.identity.agentIdHash,
        sharerPinnedMldsaPubKey: sharerRecord.mldsaPubKey,
        recipientMlkemSecretKey: this.identity.mlkemSecretKey,
      });
    } catch {
      throw new SaihmEndpointError(
        502,
        'undecryptable_share',
        `share DEK for cell '${grant.cellId}' could not be unwrapped with this identity`,
      );
    }

    // 4) Decode + verify the sharer-signed content envelope, then open with the unwrapped DEK.
    try {
      let env;
      try {
        env = decodeEnvelope(res.contentWire);
      } catch {
        throw new SaihmEndpointError(
          502,
          'malformed_envelope',
          `endpoint returned a malformed content envelope for cell '${grant.cellId}'`,
        );
      }
      if (!ctEqual(env.agentIdHash, sharerPinned)) {
        throw new SaihmEndpointError(
          502,
          'foreign_envelope',
          'shared content envelope is not signed by the pinned sharer',
        );
      }
      if (env.cellId !== grant.cellId) {
        throw new SaihmEndpointError(
          502,
          'cell_mismatch',
          `endpoint returned cell '${env.cellId}' for requested '${grant.cellId}'`,
        );
      }
      if (!verifyEnvelope(env)) {
        throw new SaihmEndpointError(
          502,
          'unverified_envelope',
          `shared content envelope for cell '${grant.cellId}' failed verification`,
        );
      }
      let plaintext;
      try {
        plaintext = fromUtf8(openCellWithDek(env, dek));
      } catch {
        throw new SaihmEndpointError(
          502,
          'undecryptable',
          `shared cell '${grant.cellId}' could not be opened with the unwrapped DEK`,
        );
      }
      return {
        cellId: env.cellId,
        plaintext,
        seq: env.seq.toString(10),
        commitmentHash: toHex(env.publicMeta.commitmentHash),
      };
    } finally {
      dek.fill(0); // scrub the unwrapped DEK regardless of outcome
    }
  }

  /**
   * Governance is served as a clean unavailable at launch (the endpoint returns a 403 stub). These
   * bindings exist for surface parity. The endpoint's 403 makes `call()` throw a typed
   * {@link SaihmEndpointError} (`code === 'governance_unavailable'`); the explicit throw below is an
   * unreachable fallback should a future deployment ever return 2xx for governance.
   */
  async governancePropose(args: {
    scope: 'emission_param' | 'protocol_upgrade';
    paramKey: string | null;
    proposedValue: string | null;
  }): Promise<never> {
    await this.call('saihm_governance_propose', args);
    throw new SaihmEndpointError(
      403,
      'governance_unavailable',
      'governance unavailable',
    );
  }

  async governanceVote(args: {
    proposalId: string;
    approve: boolean;
  }): Promise<never> {
    await this.call('saihm_governance_vote', args);
    throw new SaihmEndpointError(
      403,
      'governance_unavailable',
      'governance unavailable',
    );
  }
}
