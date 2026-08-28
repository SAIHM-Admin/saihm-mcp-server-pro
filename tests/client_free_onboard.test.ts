/**
 * Phase-5 e2e suite — SaihmProClient FREE-tier device-flow onboarding (`acquireFreeEntitlement`).
 * Runner: npx tsx --test tests/client_free_onboard.test.ts
 *
 * Topology: a self-contained mock BRIDGE stands in for the Phase-7 operator endpoints
 *   GET  /api/onboard/challenge      (existing)      -> { nonce }
 *   POST /api/free-onboard/start     (Phase-7 fwd)   -> { flowId, userCode, verificationUri, … }
 *   POST /api/free-onboard/claim     (Phase-7 fwd)   -> { status: pending|granted|denied, agentIdHash }
 *   POST /api/onboard                (existing FREE) -> { jwt }   (no paymentMethod for FREE)
 *   POST /mcp                        (existing)      -> status snapshot
 *
 * The mock CRYPTOGRAPHICALLY verifies the client's ML-DSA signature over the challenge nonce
 * (ml_dsa65.verify) — a grant is impossible without a genuine signature from THIS identity's secret
 * key, so these are true bindings, not found-flags. The mock NEVER returns a provider token and the
 * client NEVER sends one (proven by exact-key assertions on every request body): the provider access
 * token stays server-ephemeral by construction.
 */

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { fromHex } from '@saihm/client-pro';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { SaihmProClient, SaihmEndpointError, MAX_ERROR_CODE_CHARS } from '../src/client.js';

const masterOf = (n: number): Uint8Array => new Uint8Array(32).fill(n & 0xff);
const sha256Hex = (hex: string): string =>
  createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const b64url = (o: unknown): string =>
  Buffer.from(JSON.stringify(o)).toString('base64url');

interface FreeMockOpts {
  /** claim polls that report `pending` before the grant (default 1). */
  pendingBeforeGrant?: number;
  /** report `nonce_stale` on the FIRST claim, forcing a re-challenge + re-sign (default false). */
  expireNonceOnce?: boolean;
  /** always report `pending` (never grant) — exercises the client timeout (default false). */
  alwaysPending?: boolean;
  /** report a terminal Sybil denial instead of granting (default false). */
  deny?: boolean;
  /** grant idempotently on the FIRST claim via `already_granted` (default false). */
  grantAlready?: boolean;
  /** omit exactly this required field from the start response, exercising the bad-start guard. */
  malformedStart?: 'flowId' | 'userCode' | 'verificationUri';
  /** on grant, return a BOGUS agentIdHash in the body (the client must ignore it). */
  bogusGrantAgentId?: boolean;
  /** 401 (verification_failed) on the FIRST claim — the naive per-poll-consume shape (re-mint path). */
  claim401Once?: boolean;
  /** 401 on EVERY claim — a terminal auth denial expressed as 401 (must surface, not loop to timeout). */
  claimAlways401?: boolean;
  /**
   * Scripted per-claim outcomes, e.g. ['p401','pending','p401','grant'] — models a NAIVE per-poll-consume
   * server across a slow human wait (each 401 is a distinct nonce-lifecycle event separated by a 2xx).
   * Exercises the reset-on-2xx that keeps `consecutive401` from spuriously tripping. Overrun -> grant.
   */
  claimSequence?: ReadonlyArray<'p401' | 'pending' | 'nonce_stale' | 'grant'>;
  /** return this NON-401 HTTP status on every claim (e.g. 404 flow-not-found) — must be TERMINAL. */
  claimHttpError?: number;
  /** malform the challenge response: 'no_nonce' (empty body) or 'bad_hex' (non-hex nonce). */
  challengeMode?: 'no_nonce' | 'bad_hex';
  /** the `interval` (seconds) the bridge advertises in the start response (default 5). */
  advertisedInterval?: number;
  /** `expiresIn` the bridge advertises on /start, before the client's [60s,1800s] clamp. */
  advertisedExpiresIn?: unknown;
  /**
   * /claim answers HTTP 200 with a TERMINAL verdict whose `status` and `error` are each this many
   * chars — the endpoint spending the body cap on two fields the client turns into an error.
   */
  hostileClaimChars?: number;
  /**
   * /start answers 4xx with a reason phrase AND a body `error` of this many chars — the same axis
   * one layer up, where the reason phrase rides the status line rather than the body.
   */
  hostileStartChars?: number;
}

const BOGUS_AGENT_ID = 'de'.repeat(32);

interface FreeMock {
  base: string;
  startCount: () => number;
  onboardCount: () => number;
  challengeCount: () => number;
  claimBodies: () => ReadonlyArray<Record<string, unknown>>;
  startBodies: () => ReadonlyArray<Record<string, unknown>>;
  onboardBodies: () => ReadonlyArray<Record<string, unknown>>;
  grantedAgentId: () => string | null;
  issuedFlowId: () => string;
}

async function withFreeMock(
  run: (m: FreeMock) => Promise<void>,
  opts: FreeMockOpts = {},
): Promise<void> {
  const issuedNonces = new Set<string>();
  const valid = new Set<string>();
  const claimBodies: Record<string, unknown>[] = [];
  const startBodies: Record<string, unknown>[] = [];
  const onboardBodies: Record<string, unknown>[] = [];
  let challenges = 0;
  let starts = 0;
  let onboards = 0;
  let pendingRemaining = opts.pendingBeforeGrant ?? 1;
  let nonceExpiredUsed = false;
  let claim401Used = false;
  let claimSeqIdx = 0;
  let issuedFlowId = ''; // the device-flow handle /start issued; claim must echo it back exactly
  let grantedAgentId: string | null = null;

  const server: Server = createServer((req, res) => {
    const url = (req.url ?? '').split('?')[0];
    const send = (status: number, body: unknown, statusText?: string): void => {
      // A reason phrase is only ever passed by the hostile arms; Node derives the standard one
      // otherwise. The branch is for READERS, not for Node: measured, `writeHead(s, undefined, h)`
      // and `writeHead(s, h)` produce the same status line, so a cut of this comment claiming they
      // differ was asserting a distinction that is not there.
      if (statusText === undefined) res.writeHead(status, { 'content-type': 'application/json' });
      else res.writeHead(status, statusText, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    const readBody = (cb: (o: Record<string, unknown>) => void): void => {
      let buf = '';
      req.on('data', (c) => (buf += c));
      req.on('end', () => {
        try {
          cb(JSON.parse(buf || '{}') as Record<string, unknown>);
        } catch {
          send(400, { error: 'bad_json' });
        }
      });
    };
    const verifySig = (b: Record<string, unknown>): boolean => {
      const nonce = String(b.nonce ?? '');
      if (!issuedNonces.has(nonce)) return false;
      try {
        return ml_dsa65.verify(
          fromHex(String(b.signature ?? '')),
          fromHex(nonce),
          fromHex(String(b.pubkey ?? '')),
        );
      } catch {
        return false;
      }
    };

    if (req.method === 'GET' && url === '/api/onboard/challenge') {
      challenges += 1;
      if (opts.challengeMode === 'no_nonce') return send(200, {});
      if (opts.challengeMode === 'bad_hex') return send(200, { nonce: 'zzzz' });
      const nonce = randomBytes(32).toString('hex');
      issuedNonces.add(nonce);
      return send(200, { nonce });
    }

    if (req.method === 'POST' && url === '/api/free-onboard/start') {
      return readBody((b) => {
        starts += 1;
        startBodies.push(b);
        if (opts.hostileStartChars) {
          const n = opts.hostileStartChars;
          return send(400, { error: 'E'.repeat(n) }, 'S'.repeat(n));
        }
        const full: Record<string, unknown> = {
          flowId: 'flow-' + starts,
          userCode: 'WDJB-MJHT',
          verificationUri: 'https://github.com/login/device',
          expiresIn: 'advertisedExpiresIn' in opts ? opts.advertisedExpiresIn : 900,
          interval: opts.advertisedInterval ?? 5,
        };
        if (opts.malformedStart) delete full[opts.malformedStart]; // drop one required field
        issuedFlowId = typeof full.flowId === 'string' ? full.flowId : '';
        return send(200, full);
      });
    }

    if (req.method === 'POST' && url === '/api/free-onboard/claim') {
      return readBody((b) => {
        claimBodies.push(b);
        // Correlate the poll to the issued device-flow handle, exactly as the real bridge must: a claim
        // carrying the wrong flowId cannot resolve a pending authorization -> flow_not_found (404).
        if (issuedFlowId && b.flowId !== issuedFlowId) {
          return send(404, { error: 'flow_not_found' });
        }
        if (opts.hostileClaimChars) {
          const n = opts.hostileClaimChars;
          return send(200, { status: 'D'.repeat(n), error: 'E'.repeat(n) });
        }
        if (opts.claimHttpError) {
          // A NON-401 terminal error (e.g. 404 flow-not-found) — the client must surface it, not re-mint.
          return send(opts.claimHttpError, { error: 'flow_not_found' });
        }
        if (opts.expireNonceOnce && !nonceExpiredUsed) {
          // The challenge nonce went stale; the client must re-mint + re-sign (verify-not-consumed).
          nonceExpiredUsed = true;
          return send(200, { status: 'nonce_stale' });
        }
        if (opts.claim401Once && !claim401Used) {
          // Naive per-poll-consume server: a replayed/consumed nonce surfaces as a generic 401. The
          // client keys off the 401 STATUS (not the error string) and must re-mint + retry.
          claim401Used = true;
          return send(401, { error: 'verification_failed', reason: 'nonce_replay' });
        }
        if (opts.claimAlways401) {
          // A terminal denial (bad-sig / bad_tier / sybil) expressed as 401 — even a fresh nonce 401s.
          return send(401, { error: 'verification_failed', reason: 'account_too_new' });
        }
        if (opts.claimSequence) {
          const step = opts.claimSequence[claimSeqIdx++] ?? 'grant';
          if (step === 'p401') {
            return send(401, { error: 'verification_failed', reason: 'nonce_replay' });
          }
          if (step === 'pending') return send(200, { status: 'pending' });
          if (step === 'nonce_stale') return send(200, { status: 'nonce_stale' });
          // 'grant' — crypto-gate the fresh nonce, then record the real binding and grant.
          if (!verifySig(b)) return send(401, { error: 'bad_signature' });
          issuedNonces.delete(String(b.nonce));
          grantedAgentId = sha256Hex(String(b.pubkey));
          return send(200, { status: 'granted', agentIdHash: grantedAgentId });
        }
        // Cryptographic gate: no grant without a valid ML-DSA signature over an issued nonce.
        if (!verifySig(b)) return send(401, { error: 'bad_signature' });
        if (opts.deny) return send(200, { status: 'denied', error: 'sybil_denied' });
        if (opts.alwaysPending) return send(200, { status: 'pending' });
        // The response body's agentIdHash may be BOGUS — the client must ignore it and return its own.
        const bodyAgentId = opts.bogusGrantAgentId ? BOGUS_AGENT_ID : sha256Hex(String(b.pubkey));
        if (opts.grantAlready) {
          issuedNonces.delete(String(b.nonce));
          grantedAgentId = sha256Hex(String(b.pubkey));
          return send(200, { status: 'already_granted', agentIdHash: bodyAgentId });
        }
        if (pendingRemaining > 0) {
          pendingRemaining -= 1;
          return send(200, { status: 'pending' });
        }
        issuedNonces.delete(String(b.nonce)); // single-use at the terminal grant (F6)
        grantedAgentId = sha256Hex(String(b.pubkey));
        return send(200, { status: 'granted', agentIdHash: bodyAgentId });
      });
    }

    if (req.method === 'POST' && url === '/api/onboard') {
      return readBody((b) => {
        onboardBodies.push(b);
        if (b.tier !== 'FREE') return send(400, { error: 'bad_tier' });
        if (!verifySig(b)) return send(401, { error: 'bad_signature' });
        onboards += 1;
        const sub = sha256Hex(String(b.pubkey));
        const jwt = `${b64url({ alg: 'EdDSA' })}.${b64url({
          sub,
          tier: 'FREE',
          exp: Math.floor(Date.now() / 1000) + 3600,
        })}.sig${onboards}`;
        valid.add(jwt);
        return send(201, { jwt });
      });
    }

    if (req.method === 'POST' && url === '/mcp') {
      const auth = req.headers['authorization'] ?? '';
      const tok = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      if (!valid.has(tok)) return send(401, { error: 'unauthorized' });
      return readBody(() =>
        send(200, {
          agentIdHashHex: 'x',
          tier: 'FREE',
          activeShardCount: 0,
          custody: 'COTI',
        }),
      );
    }
    return send(404, { error: 'not_found' });
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    await run({
      base,
      startCount: () => starts,
      onboardCount: () => onboards,
      challengeCount: () => challenges,
      claimBodies: () => claimBodies,
      startBodies: () => startBodies,
      onboardBodies: () => onboardBodies,
      grantedAgentId: () => grantedAgentId,
      issuedFlowId: () => issuedFlowId,
    });
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

describe('FF1: acquireFreeEntitlement drives the device flow to a bound grant', () => {
  it('surfaces the prompt once, polls to grant, and binds githubSub<->agentIdHash', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(10), {
          tier: 'FREE',
        });
        let prompts = 0;
        let seenUri = '';
        let seenCode = '';
        const r = await c.acquireFreeEntitlement({
          pollIntervalMs: 5,
          onPrompt: (p) => {
            prompts += 1;
            seenUri = p.verificationUri;
            seenCode = p.userCode;
          },
        });
        assert.equal(prompts, 1, 'the human prompt is surfaced exactly once');
        assert.equal(seenUri, 'https://github.com/login/device');
        assert.equal(seenCode, 'WDJB-MJHT');
        // The entitlement is bound to THIS sovereign identity, cryptographically proven server-side.
        assert.equal(r.agentIdHash, c.agentIdHash);
        assert.equal(m.grantedAgentId(), c.agentIdHash);
        assert.equal(m.startCount(), 1);
        assert.ok(m.claimBodies().length >= 2, 'polled at least once past the initial pending');
        assert.equal(m.challengeCount(), 1, 'a pending poll does NOT re-mint the nonce');
        assert.equal(
          m.claimBodies()[0].flowId,
          m.issuedFlowId(),
          'claim echoes the exact flowId /start issued (the device-flow session handle)',
        );
        // The START pubkey is THIS identity's ML-DSA key — pins its value absolutely (not just its key),
        // closing the last opaque-value gap: a mutation corrupting only the start pubkey fails here.
        assert.equal(
          sha256Hex(String(m.startBodies()[0].pubkey)),
          c.agentIdHash,
          'start carries this identity pubkey (one consistent sovereign key across start + claim)',
        );
      },
      { pendingBeforeGrant: 1 },
    );
  });

  it('never sends a provider token: request bodies carry only the expected keys', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(11), {
          tier: 'FREE',
        });
        await c.acquireFreeEntitlement({ pollIntervalMs: 5, onPrompt: () => {} });
        // Guard against vacuous truth: the flow must actually have issued the requests we inspect.
        assert.ok(m.startBodies().length > 0, 'start was actually called');
        assert.ok(m.claimBodies().length > 0, 'claim was actually called');
        assert.equal(
          m.startBodies()[0].provider,
          'github',
          'the default provider slug is github (not some other OAuth provider)',
        );
        for (const b of m.startBodies()) {
          assert.deepEqual(Object.keys(b).sort(), ['provider', 'pubkey']);
        }
        for (const b of m.claimBodies()) {
          assert.deepEqual(
            Object.keys(b).sort(),
            ['flowId', 'nonce', 'pubkey', 'signature'],
          );
        }
      },
      { pendingBeforeGrant: 0 },
    );
  });
});

describe('FF2: FREE self-onboard needs no paymentMethod and mints a FREE JWT', () => {
  it('the tier-agnostic refresh loop onboards FREE (no paymentMethod) and authorizes /mcp', async () => {
    await withFreeMock(async (m) => {
      // A FREE self-onboard client needs NO paymentMethod (constructor relaxation).
      const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(12), {
        tier: 'FREE',
      });
      const st = await c.status();
      assert.equal(st.tier, 'FREE');
      assert.equal(m.onboardCount(), 1, 'one onboard mints the first FREE token');
      const body = m.onboardBodies()[0];
      assert.equal(body.tier, 'FREE');
      assert.equal(
        body.paymentMethod,
        undefined,
        'FREE onboard carries no paymentMethod',
      );
    });
  });
});

describe('FF3: an expired challenge nonce mid-flow is recovered (re-challenge + re-sign)', () => {
  it('re-mints a fresh nonce and still reaches a grant', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(13), {
          tier: 'FREE',
        });
        const r = await c.acquireFreeEntitlement({
          pollIntervalMs: 5,
          onPrompt: () => {},
        });
        assert.equal(r.agentIdHash, c.agentIdHash);
        assert.ok(
          m.challengeCount() >= 2,
          'a second challenge was fetched after nonce_expired',
        );
      },
      { expireNonceOnce: true, pendingBeforeGrant: 0 },
    );
  });
});

describe('FF4: a Sybil denial is a terminal typed error (no infinite poll)', () => {
  it('throws SaihmEndpointError(sybil_denied)', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(14), {
          tier: 'FREE',
        });
        await assert.rejects(
          () =>
            c.acquireFreeEntitlement({
              pollIntervalMs: 5,
              timeoutMs: 3000, // fast-fail: a terminal-status mishandling mutation must not hang to 900s
              onPrompt: () => {},
            }),
          (e: unknown) =>
            e instanceof SaihmEndpointError && e.code === 'sybil_denied',
        );
      },
      { deny: true },
    );
  });
});

describe('FF5: acquireFreeEntitlement requires the FREE tier', () => {
  it('a non-FREE client rejects with not_free_tier before any network call', async () => {
    await withFreeMock(async (m) => {
      const c = new SaihmProClient(m.base + '/mcp', 'Bearer static', masterOf(15), {
        tier: 'PRO',
      });
      await assert.rejects(
        () => c.acquireFreeEntitlement({ pollIntervalMs: 5, onPrompt: () => {} }),
        (e: unknown) =>
          e instanceof SaihmEndpointError && e.code === 'not_free_tier',
      );
      assert.equal(m.startCount(), 0, 'no device flow was started');
    });
  });
});

describe('FF6: never-authorized flow times out (bounded, not an infinite loop)', () => {
  it('throws free_onboard_timeout after the budget', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(16), {
          tier: 'FREE',
        });
        await assert.rejects(
          () =>
            c.acquireFreeEntitlement({
              pollIntervalMs: 5,
              timeoutMs: 40,
              onPrompt: () => {},
            }),
          (e: unknown) =>
            e instanceof SaihmEndpointError && e.code === 'free_onboard_timeout',
        );
        assert.ok(m.claimBodies().length >= 1, 'it polled before timing out');
      },
      { alwaysPending: true },
    );
  });
});

describe('FF7: the poll-cadence fallback TRACKS the bridge-advertised interval (no pollIntervalMs)', () => {
  // Two data points pin the plumbing: a busy-loop (0ms) fails the lower bound, the 5s default fails the
  // upper bound, and a hardcoded constant (e.g. 1500ms) fails one of the two interval-specific bands.
  // NON-OVERLAPPING bands (gap 2200..2600): no single constant poll value fits both, so a mutation that
  // ignores `start.interval` and hardcodes any constant is killed by at least one case. The interval=1
  // upper bound (2200) keeps ~1200ms of CI headroom over the nominal 1000ms sleep.
  for (const [interval, lo, hi] of [
    [1, 800, 2200],
    [3, 2600, 4500],
  ] as const) {
    it(`interval=${interval}s -> ~${interval}s sleep (not busy-loop, not 5s default, tracks interval)`, async () => {
      await withFreeMock(
        async (m) => {
          const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(17), {
            tier: 'FREE',
          });
          const t0 = Date.now();
          const r = await c.acquireFreeEntitlement({ onPrompt: () => {} }); // NO pollIntervalMs
          const elapsed = Date.now() - t0;
          assert.equal(r.agentIdHash, c.agentIdHash);
          assert.equal(m.grantedAgentId(), c.agentIdHash); // server-side crypto binding, not tautology
          assert.ok(elapsed >= lo, `interval=${interval}: expected >=${lo}ms, got ${elapsed}ms`);
          assert.ok(elapsed <= hi, `interval=${interval}: expected <=${hi}ms, got ${elapsed}ms`);
        },
        { pendingBeforeGrant: 1, advertisedInterval: interval },
      );
    });
  }
});

describe('FF8: an already-entitled key is an idempotent success (already_granted)', () => {
  it('resolves with this identity agentIdHash, no error', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(18), {
          tier: 'FREE',
        });
        const r = await c.acquireFreeEntitlement({
          pollIntervalMs: 5,
          onPrompt: () => {},
        });
        assert.equal(r.agentIdHash, c.agentIdHash);
        assert.equal(m.grantedAgentId(), c.agentIdHash);
      },
      { grantAlready: true },
    );
  });
});

describe('FF9: any missing required start field is a typed free_onboard_bad_start (no polling/prompt)', () => {
  for (const field of ['flowId', 'userCode', 'verificationUri'] as const) {
    it(`start missing ${field} -> free_onboard_bad_start before any claim or prompt`, async () => {
      await withFreeMock(
        async (m) => {
          const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(19), {
            tier: 'FREE',
          });
          let prompts = 0;
          await assert.rejects(
            () =>
              c.acquireFreeEntitlement({
                pollIntervalMs: 5,
                onPrompt: () => {
                  prompts += 1;
                },
              }),
            (e: unknown) =>
              e instanceof SaihmEndpointError &&
              e.code === 'free_onboard_bad_start',
          );
          assert.equal(m.claimBodies().length, 0, 'never polled claim');
          assert.equal(prompts, 0, 'never surfaced a prompt on a bad start');
        },
        { malformedStart: field },
      );
    });
  }
});

describe('FF10: a claim-path 401 (naive per-poll-consume server) re-mints, not a terminal failure', () => {
  it('re-mints a fresh nonce on the 401 and still reaches a bound grant', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(20), {
          tier: 'FREE',
        });
        const r = await c.acquireFreeEntitlement({
          pollIntervalMs: 5,
          timeoutMs: 3000, // fail fast (not the 900s default) if a re-sign regression loops
          onPrompt: () => {},
        });
        assert.equal(r.agentIdHash, c.agentIdHash);
        assert.equal(m.grantedAgentId(), c.agentIdHash);
        assert.ok(m.challengeCount() >= 2, 're-minted a fresh nonce after the 401');
      },
      { claim401Once: true, pendingBeforeGrant: 0 },
    );
  });
});

describe('FF11: a server-returned agentIdHash is never trusted (client returns its own)', () => {
  it('ignores a BOGUS grant agentIdHash', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(21), {
          tier: 'FREE',
        });
        const r = await c.acquireFreeEntitlement({
          pollIntervalMs: 5,
          onPrompt: () => {},
        });
        assert.equal(r.agentIdHash, c.agentIdHash);
        assert.equal(m.grantedAgentId(), c.agentIdHash); // the grant really happened (self-contained)
        assert.notEqual(r.agentIdHash, BOGUS_AGENT_ID);
      },
      { bogusGrantAgentId: true, pendingBeforeGrant: 0 },
    );
  });
});

describe('FF13: a naive per-poll-consume server (401->pending->401->grant) still reaches a bound grant', () => {
  it('resets the 401 streak on each 2xx so alternating nonce-lifecycle 401s never falsely surface', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(23), {
          tier: 'FREE',
        });
        const r = await c.acquireFreeEntitlement({
          pollIntervalMs: 5,
          timeoutMs: 5000, // ample budget: the point is it GRANTS, not that it times out
          onPrompt: () => {},
        });
        assert.equal(r.agentIdHash, c.agentIdHash);
        assert.equal(m.grantedAgentId(), c.agentIdHash);
        // two 401s each forced a re-mint (challengeCount: initial + 2), and neither tripped the terminal
        // guard because the interleaved `pending` reset the streak. Deleting `consecutive401=0` throws
        // terminal at the second 401 instead of granting -> this rejects.
        assert.equal(m.challengeCount(), 3, 'exactly two re-mints (one per 401), NONE on the pending');
        assert.equal(m.claimBodies().length, 4, 'polled the full alternating sequence, no extra');
      },
      { claimSequence: ['p401', 'pending', 'p401', 'grant'] },
    );
  });
});

describe('FF14: the 401 streak resets on ANY 2xx (a nonce_stale between two 401s never trips terminal)', () => {
  it('grants across p401 -> nonce_stale -> p401 -> grant (reset is broad, not pending-only)', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(24), {
          tier: 'FREE',
        });
        let prompts = 0;
        const r = await c.acquireFreeEntitlement({
          pollIntervalMs: 5,
          timeoutMs: 5000,
          onPrompt: () => {
            prompts += 1;
          },
        });
        assert.equal(r.agentIdHash, c.agentIdHash);
        assert.equal(m.grantedAgentId(), c.agentIdHash);
        // Step 1 (start + prompt) runs EXACTLY ONCE despite 3 nonce re-mints — the documented onPrompt
        // "invoked once" contract. A mutation moving start/onPrompt into the re-mint path re-prompts here.
        assert.equal(prompts, 1, 'the human is prompted exactly once across all re-mints');
        assert.equal(m.startCount(), 1, 'the device flow is started exactly once; re-mint refreshes only the nonce');
        // Each of the two 401s AND the nonce_stale re-mints (initial + 3); the nonce_stale's 2xx reset
        // is what keeps the trailing 401 at consec=1. Narrowing the reset to pending-only throws terminal
        // at the second 401 -> this rejects.
        assert.equal(m.challengeCount(), 4, 'one re-mint per 401 AND per nonce_stale');
        assert.equal(m.claimBodies().length, 4, 'full scripted sequence, no extra');
      },
      { claimSequence: ['p401', 'nonce_stale', 'p401', 'grant'] },
    );
  });
});

describe('FF12: a PERSISTENT claim 401 surfaces the terminal error fast (not a full-budget timeout)', () => {
  it('re-mints once, then surfaces the 401 on the fresh nonce (bad-sig / sybil-as-401)', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(22), {
          tier: 'FREE',
        });
        await assert.rejects(
          () =>
            c.acquireFreeEntitlement({
              pollIntervalMs: 5,
              timeoutMs: 5000, // generous budget: proves it surfaces WITHOUT burning it
              onPrompt: () => {},
            }),
          (e: unknown) =>
            e instanceof SaihmEndpointError &&
            e.status === 401 &&
            e.code === 'verification_failed' && // the caught 401 propagates unchanged
            e.code !== 'free_onboard_timeout',
        );
        assert.equal(
          m.claimBodies().length,
          2,
          'surfaced after exactly one re-mint — no budget burn',
        );
      },
      { claimAlways401: true },
    );
  });
});

describe('FF15: a non-401 claim error (404 flow-not-found) is TERMINAL, not re-minted', () => {
  it('surfaces the 404 on the first claim — no re-mint, no timeout', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(25), {
          tier: 'FREE',
        });
        await assert.rejects(
          () =>
            c.acquireFreeEntitlement({
              pollIntervalMs: 5,
              timeoutMs: 5000,
              onPrompt: () => {},
            }),
          (e: unknown) =>
            e instanceof SaihmEndpointError &&
            e.status === 404 &&
            e.code !== 'free_onboard_timeout',
        );
        assert.equal(m.challengeCount(), 1, 'no re-mint on a non-401 terminal error');
        assert.equal(m.claimBodies().length, 1, 'surfaced on the first claim, no retry');
      },
      { claimHttpError: 404 },
    );
  });
});

describe('FF16: a challenge response with no nonce is a typed onboard_no_nonce (before any claim)', () => {
  it('throws onboard_no_nonce', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(26), {
          tier: 'FREE',
        });
        await assert.rejects(
          () => c.acquireFreeEntitlement({ pollIntervalMs: 5, onPrompt: () => {} }),
          (e: unknown) =>
            e instanceof SaihmEndpointError && e.code === 'onboard_no_nonce',
        );
        assert.equal(m.claimBodies().length, 0, 'never polled claim');
      },
      { challengeMode: 'no_nonce' },
    );
  });
});

describe('FF17: a non-hex challenge nonce is a typed onboard_bad_nonce (fails before signing)', () => {
  it('throws onboard_bad_nonce', async () => {
    await withFreeMock(
      async (m) => {
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(27), {
          tier: 'FREE',
        });
        await assert.rejects(
          () => c.acquireFreeEntitlement({ pollIntervalMs: 5, onPrompt: () => {} }),
          (e: unknown) =>
            e instanceof SaihmEndpointError && e.code === 'onboard_bad_nonce',
        );
        assert.equal(m.claimBodies().length, 0, 'never polled claim');
      },
      { challengeMode: 'bad_hex' },
    );
  });
});

describe('FF10: the bridge-advertised expiry is CLAMPED to [60s, 1800s] before it becomes a deadline', () => {
  // The clamp's output is `expiresIn` on the prompt, and it becomes `budgetMs` — the deadline the
  // device-code poll loop runs against. Asserted HERE, on the value, because the rendered receipt
  // cannot see it: minutes are `Math.max(1, Math.round(n / 60))`, so a floor of 60 and a floor of 59
  // both render "about 1 min". A test written against that text surface had no kill power at all.
  //
  // A hostile or broken bridge that advertises `expiresIn: 1` gives the poll loop one second, so the
  // join dies with `free_onboard_timeout` before a human could finish the device flow — the bridge
  // suppressing its own onboarding through a NUMBER rather than a refusal, with nothing to point at.
  // The ceiling is the mirror case: "good for a decade" means a dead code is never re-requested.
  //
  // The mock previously hardcoded `expiresIn: 900`, which sits inside the clamp, so neither arm was
  // ever exercised and BOTH bounds were free to move. That is why the lower bound was reported as an
  // equivalent mutant: test-equivalent is not behaviour-equivalent.
  for (const [label, advertised, want] of [
    ['below the floor is RAISED', 1, 60],
    ['one second under the floor is raised to exactly the floor', 59, 60],
    ['at the floor is untouched', 60, 60],
    ['above the ceiling is CUT', 86_400 * 365 * 10, 1800],
    ['at the ceiling is untouched', 1800, 1800],
    ['a legitimate window passes through', 600, 600],
    ['zero is not a window — falls back to the default', 0, 900],
    ['negative falls back to the default', -3600, 900],
    ['non-numeric falls back to the default', 'soon', 900],
  ] as const) {
    it(`${label}: bridge says ${JSON.stringify(advertised)} -> ${want}s`, async () => {
      await withFreeMock(
        async (m) => {
          const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(29), {
            tier: 'FREE',
          });
          let seen: unknown;
          const r = await c.acquireFreeEntitlement({
            pollIntervalMs: 5,
            onPrompt: (pr) => {
              seen = pr.expiresIn;
            },
          });
          assert.equal(r.agentIdHash, c.agentIdHash);
          assert.equal(
            seen,
            want,
            `bridge advertised ${JSON.stringify(advertised)}: expected a clamped ${want}s deadline, got ${String(seen)}`,
          );
        },
        { pendingBeforeGrant: 1, advertisedExpiresIn: advertised },
      );
    });
  }
});

describe('FF18: no endpoint-chosen value reaches a message the JOIN STATE will retain', () => {
  // `client.ts` states that the message half of a `SaihmEndpointError` is unbounded-at-mint and
  // bounded-at-render, and gives as the reason that "nothing retains a message across calls the way
  // `joinState` retains a code". The retention half of that sentence is not true: the server's
  // `JoinState.error` is typed `unknown` and holds the whole error object — message included — until
  // the next join replaces it. What makes the conclusion safe is a different fact that the sentence
  // never names: on THIS path, every endpoint-chosen value is sliced at the mint, so there is no
  // endpoint-sized message to retain in the first place.
  //
  // An unnamed fact is an unpinned one, so it is pinned here rather than described anywhere. Both
  // endpoint-chosen mints on the join path are driven, because a control narrower than the claim it
  // certifies is the failure this module keeps repeating — the budget enumeration scoped by name
  // prefix, `noUnusedLocals` adopted for one directory, the `safeScalar` sweep named for one file.
  //
  // Each mint is driven at TWO magnitudes 64x apart. Equal message lengths across the pair is the
  // property — independence from what the endpoint sent — and it holds without anyone writing down
  // what the length is, which a measured number in a comment could not do.
  //
  // The magnitudes differ per axis because the two endpoint-chosen values travel differently. A body
  // field is bounded only by `MAX_RESPONSE_BYTES`, so the endpoint can make it enormous. A reason
  // phrase rides the STATUS LINE, and past a point the HTTP transport stops delivering it whole — a
  // hostile phrase large enough arrives SHORTER, not longer, which would exercise the transport's
  // behaviour instead of this client's fence. So the status-line axis is driven with headroom below
  // that point. No figure is written down for it: the `includes` assertion below fails loudly if the
  // transport ever starts cutting beneath the fence, which is the drift this would otherwise hide.

  // Bounds the fallback name for a mint whose message has no literal in it at all, so a failure
  // message can never itself become the unbounded string this suite exists to keep out of one.
  const ABBREV = 48;

  // `text` is the marker the endpoint puts where the MESSAGE will read from; `code` is the marker it
  // puts where `.code` will read from. Distinct letters so an assertion cannot pass on the wrong one.
  const SCENARIOS = [
    {
      label: 'a terminal claim verdict off an HTTP 200 (`free-onboard was not granted (`)',
      opt: (n: number): FreeMockOpts => ({ hostileClaimChars: n }),
      text: 'D',
      code: 'E',
      status: 403,
      magnitudes: [1_024, 65_536],
    },
    {
      label: 'a non-2xx from the device-flow start (`SAIHM onboard failed: `)',
      opt: (n: number): FreeMockOpts => ({ hostileStartChars: n }),
      text: 'S',
      code: 'E',
      status: 400,
      magnitudes: [256, 16_384],
    },
  ] as const;

  for (const sc of SCENARIOS) {
    it(`bounds both halves of ${sc.label}`, async () => {
      const seen: { message: number; code: number; status: number }[] = [];
      for (const n of sc.magnitudes) {
        let err: unknown;
        await withFreeMock(
          async (m) => {
            const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(31), {
              tier: 'FREE',
            });
            await assert.rejects(
              () => c.acquireFreeEntitlement({ pollIntervalMs: 5, onPrompt: () => {} }),
              (e: unknown) => {
                err = e;
                return e instanceof SaihmEndpointError;
              },
            );
          },
          sc.opt(n),
        );
        const e = err as SaihmEndpointError;
        seen.push({ message: e.message.length, code: (e.code ?? '').length, status: e.status });

        // NON-VACUITY, both directions. The hostile value must actually have REACHED the message —
        // a fence that bounds a value the client never read would pass this test while proving
        // nothing — and it must have been cut at exactly the named budget, not merely somewhere.
        assert.ok(
          e.message.includes(sc.text.repeat(MAX_ERROR_CODE_CHARS)),
          `the endpoint's ${n}-char value never reached the message, so this fence was not exercised: ${e.message}`,
        );
        assert.ok(
          !e.message.includes(sc.text.repeat(MAX_ERROR_CODE_CHARS + 1)),
          'an endpoint-chosen value passed the message fence by at least one char',
        );
        assert.equal(
          (e.code ?? '').includes(sc.code.repeat(MAX_ERROR_CODE_CHARS)),
          true,
          'the endpoint-chosen code never reached `.code`, so its slice was not exercised either',
        );
        assert.ok(
          !(e.code ?? '').includes(sc.code.repeat(MAX_ERROR_CODE_CHARS + 1)),
          'an endpoint-chosen value passed the code fence by at least one char',
        );
        assert.equal(e.status, sc.status);
      }

      // THE PROPERTY: a change in what the endpoint sent moves neither half by one character. Read
      // across EVERY magnitude rather than a pair of indices. A cut of this compared `seen[1]` to
      // `seen[0]` while the magnitudes were a list, so a third entry would have been driven and
      // never looked at — the same silent narrowing the sweep below now fails closed against.
      assert.ok(sc.magnitudes.length >= 2, 'one magnitude proves nothing about independence');
      assert.equal(seen.length, sc.magnitudes.length, 'a magnitude was driven but not recorded');
      for (const s of seen) {
        assert.deepEqual(
          s,
          seen[0],
          `the retained error grew with the endpoint's payload — ${JSON.stringify(seen)}`,
        );

        // And it is small in terms of the constant that makes it small, rather than in terms of a
        // number someone measured once. The message is fixed chrome plus a fenced reason plus a
        // fenced code; two budgets and change cannot reach four.
        assert.ok(
          s.message < 4 * MAX_ERROR_CODE_CHARS,
          `the retained message is not bounded by its own budgets: ${s.message} chars`,
        );
      }
    });
  }

  it('EVERY join-path mint whose message is not a bare literal is accounted for — the sweep, not a promise', () => {
    // Driving two mints proves those two are fenced. It does not prove they are the only two, and
    // that is exactly the gap this module keeps shipping: a true conclusion carried by a control
    // that cannot reach all of it. So the region is swept. A third interpolating mint added to the
    // join path turns this red and sends its author here to say why it is safe, which is the whole
    // difference between a declared exception and an undiscovered one.
    const src = readFileSync(
      fileURLToPath(new URL('../src/client.ts', import.meta.url)),
      'utf-8',
    );

    // STATED LIMIT, MEASURED EMPTY. The stripper below treats `//` as a comment start even inside a
    // STRING LITERAL, and this is the file that has them — a scheme prefix in a URL, and both halves
    // of the endpoint-scheme error. Blanking one takes the rest of its line with it, so a mint placed
    // after one would vanish and this sweep would report a clean, complete-looking result over source
    // it never read. That is the exact failure the paragraphs below indict, committed by the
    // instrument instead of by the code, and a disclosure of it would be the blank cheque this test
    // already refuses to accept from anyone else. So the ARRANGEMENT is checked rather than lexed:
    // it cannot tell a comment from a string and does not try, and fails closed either way.
    src.split('\n').forEach((line, i) => {
      const tok = line.search(/new SaihmEndpointError\(/);
      const slashes = line.indexOf('//');
      assert.ok(
        tok < 0 || slashes < 0 || slashes > tok,
        `client.ts:${i + 1} places a mint after a \`//\` on one line. If that \`//\` is inside a ` +
          'string literal the stripper blanks the mint with it and this sweep goes quiet — put the ' +
          'mint on its own line, or replace the stripper with something that lexes string literals',
      );
    });

    // Comments are stripped first, newline structure preserved, because this region's own doc blocks
    // quote the mint shape while discussing it. The `[^\n]` replacement is deliberate: a stripper
    // that collapsed each block to a single space once made a sibling sweep report a call site 77
    // lines above itself.
    const stripped = src
      .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
      .replace(/\/\/[^\n]*/g, (m) => ' '.repeat(m.length));

    // The join path is DERIVED, not delimited. A cut of this sliced the file positionally, from
    // `acquireFreeEntitlement` to where the authenticated call path begins — and `fetchChallengeNonce`
    // is declared ABOVE that start while the join path calls it twice, so a third of the path sat
    // outside the sweep. MEASURED against a mint interpolating an endpoint value: placed inside the
    // slice it went red; placed in `fetchChallengeNonce`, the identical mint left the suite green.
    // Same detector, same shape, only the location differed. That is the seventh time this module has
    // certified a conclusion with a control that could not reach all of it, and the second time inside
    // this very test — the first was the detector below, this was the input it ran on.
    //
    // So the path is walked instead of guessed: start at the entry point, follow every call it makes
    // transitively, and sweep every body reached. A helper added anywhere in the file is covered the
    // moment the path calls it, wherever its declaration happens to sit and whatever kind it is.
    //
    // A cut of this walk followed `this.<method>(` ONLY, and disclosed that as a stated limit — but
    // the disclosure was paired with a fact: "every mint in this file is currently a class method, so
    // nothing is uncovered today". That fact was false, and it is the reason the limit read as empty.
    // `readBodyCapped` is a module-scope `async function` holding a mint, and `onboardFetch` — in the
    // closure — calls it. MEASURED: an endpoint-interpolating mint placed inside `readBodyCapped` left
    // the suite green at 33/33; the identical mint inside `onboardFetch` turned it red naming its own
    // chrome. Only the location differed. That was the eighth time this module certified a conclusion
    // with a control that could not reach all of it, and the third consecutive time inside the guard
    // against that shape. A disclosed limit is not a bounded one: unless the disclosure is MEASURED
    // to be empty it is a blank cheque, and the measurement is the thing that was missing.
    //
    // So the walk follows BOTH shapes: `this.<method>(` and a bare `name(` that resolves to a
    // declaration in this file. Free functions and class methods are declarations alike here and
    // share one ordered list.
    //
    // A method's body is the span from its own declaration to the NEXT declaration. That needs no
    // brace matching, so an object return type — `): {` — cannot be mistaken for the body's opening
    // brace. If the pattern ever MISSES a declaration the two bodies merge, which over-reports rather
    // than under-reports: a mint from a method that is not on the path shows up below as an undeclared
    // entry, loudly, instead of a join-path mint disappearing quietly.
    const DECL = /\n {2}(?:private |public |protected )?(?:static )?(?:async )?([A-Za-z_$][\w$]*)\s*(?:<[^>()]*>)?\s*\(/g;
    // Module-scope functions, in both shapes this file uses. Sliced by the same next-declaration rule
    // as methods, so the two kinds go into ONE ordered list rather than two walks that could disagree.
    const FREE =
      /\n(?:export )?(?:async )?function ([A-Za-z_$][\w$]*)\s*(?:<[^>()]*>)?\s*\(|\n(?:export )?const ([A-Za-z_$][\w$]*)\s*=\s*(?:async )?\(/g;
    // `\n  for (` and `\n  if (` satisfy the declaration pattern, which never mattered while only class
    // members were walked — inside a class those sit at four spaces or deeper. A module-scope function
    // body sits at two, so once free functions are in the list they land in `decls` as well.
    //
    // MEASURED, because the obvious reason to filter them is the wrong one: dropping `for` alone does
    // NOT lose coverage of the loop it splits, since `for (` reads as a call too and the walk simply
    // follows it back in. What breaks is RESOLUTION — an unfiltered `if` resolves to many
    // declarations at once, `bodyOf` refuses to guess between them, and the whole sweep dies with
    // `\`if\` is declared more than once`. So the filter is here to stop a spurious hard failure,
    // not to restore reach.
    const KEYWORD = new Set(['if', 'for', 'while', 'switch', 'catch', 'do', 'else', 'return', 'with']);
    const allDecls = [
      ...[...stripped.matchAll(DECL)].map((m) => ({ name: m[1] as string, at: m.index })),
      ...[...stripped.matchAll(FREE)].map((m) => ({ name: (m[1] ?? m[2]) as string, at: m.index })),
    ].sort((a, b) => a.at - b.at);
    const decls = allDecls.filter((d) => !KEYWORD.has(d.name));
    assert.ok(decls.length > 0, 'no declarations were found — this sweep is blind');

    // THAT CLAIM, RUN RATHER THAN DESCRIBED. A cut of the paragraph above closed by saying "the
    // control that pins it removes `if` and reads that message" — and no such control existed
    // anywhere, asserted in the present tense, in the test whose entire subject is a conclusion
    // outrunning what checks it. It also stated the collision count as a number, which decays in
    // silence the day someone adds or removes a two-space-indent `if`. Both are replaced by this:
    // the collision is recomputed here, and no figure is written down.
    assert.ok(
      allDecls.filter((d) => d.name === 'if').length > 1,
      '`if` no longer collides, so KEYWORD is preventing nothing here — either the filter is now ' +
        'obsolete, or the declaration pattern has stopped matching control flow and the walk has ' +
        'gone blind in a way this sweep can no longer see',
    );

    const bodyOf = (name: string): string | undefined => {
      const hits = decls.filter((d) => d.name === name);
      // A name that resolves to two declarations resolves to neither. This class file holds several
      // classes, so a collision is possible in principle; refusing to guess is the only safe answer.
      assert.ok(hits.length <= 1, `\`${name}\` is declared more than once — this walk cannot resolve it`);
      const i = hits.length ? decls.indexOf(hits[0]!) : -1;
      return i < 0 ? undefined : stripped.slice(decls[i]!.at, decls[i + 1]?.at ?? stripped.length);
    };

    const CALL = /this\.([A-Za-z_$][\w$]*)\s*(?:<[^;=]*?>)?\s*\(/g;
    // A bare `name(` is followed only when it RESOLVES to a declaration here. The two call shapes are
    // treated differently on purpose: a `this.` call that does not resolve is a HOLE and is reported,
    // whereas an unresolved bare name is ordinary — `Buffer.concat(`, `String(` and every import land
    // in this matcher too — so it is skipped. A bare call that collides with a method name is followed
    // and over-reports one body, which surfaces as a loud undeclared entry rather than a quiet miss.
    const FREE_CALL = /(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(/g;
    const declared = new Set(decls.map((d) => d.name));
    const closure = new Map<string, string>();
    const unresolved: string[] = [];
    const queue = ['acquireFreeEntitlement'];
    while (queue.length) {
      const name = queue.pop() as string;
      if (closure.has(name)) continue;
      const body = bodyOf(name);
      if (body === undefined) {
        unresolved.push(name);
        continue;
      }
      closure.set(name, body);
      for (const c of body.matchAll(CALL)) queue.push(c[1] as string);
      for (const c of body.matchAll(FREE_CALL)) {
        const n = c[1] as string;
        if (declared.has(n)) queue.push(n);
      }
    }

    // Both halves of the walk are pinned, because a resolver that silently returns nothing would make
    // every assertion below vacuous. It must have REACHED the callees the path is known to have, and
    // it must have left NOTHING unresolved — a name it could not find is a hole, not a detail.
    // `readBodyCapped` is in this list because it is the free function that was missing when the walk
    // followed methods alone; it is what makes the widening non-vacuous rather than merely present.
    assert.deepEqual(unresolved, [], `the walk could not resolve a method the join path calls`);
    for (const required of [
      'acquireFreeEntitlement',
      'fetchChallengeNonce',
      'onboardFetch',
      'readBodyCapped',
    ]) {
      assert.ok(
        closure.has(required),
        `the join-path closure never reached \`${required}\`; it saw ${[...closure.keys()].sort().join(', ')}`,
      );
    }

    // Reaching a declaration is not the same as reading its body. Bodies are sliced to the NEXT
    // declaration, so a pattern that treats something inside a function as a declaration truncates it
    // and the sweep goes quiet over the tail — which is exactly what a control-flow keyword did here
    // before `KEYWORD` existed. Pin that the one body known to mint below its own first statement
    // still contains a mint after slicing.
    assert.match(
      closure.get('readBodyCapped') as string,
      /new SaihmEndpointError\(/,
      'the `readBodyCapped` body was sliced short of the mint it holds — the walk reaches it but does not read it',
    );

    // Splits a call's arguments on TOP-LEVEL commas only, so a comma inside a nested call, an object
    // or a string does not end an argument early. A quote scanner runs alongside the paren counter
    // for the same reason.
    const argsOf = (t: string, open: number): string[] => {
      const out: string[] = [];
      let depth = 0;
      let quote = '';
      let start = open + 1;
      for (let i = open; i < t.length; i++) {
        const c = t[i];
        if (quote) {
          if (c === '\\') i++;
          else if (c === quote) quote = '';
          continue;
        }
        if (c === "'" || c === '"' || c === '`') quote = c;
        else if (c === '(' || c === '[' || c === '{') depth++;
        else if (c === ')' || c === ']' || c === '}') {
          if (c === ')' && depth === 1) {
            out.push(t.slice(start, i));
            return out;
          }
          depth--;
        } else if (c === ',' && depth === 1) {
          out.push(t.slice(start, i));
          start = i + 1;
        }
      }
      throw new Error('unbalanced parentheses while scanning a join-path mint');
    };

    // A message is SAFE only in one shape: a single string literal with nothing evaluated inside it.
    // Everything else is declared below, whatever syntax it uses.
    //
    // A cut of this sweep asked the opposite question — it looked for a message that BEGINS with a
    // template literal containing `${`. That enumerates dangerous shapes, and an enumeration of
    // dangerous shapes is only ever as complete as the imagination behind it: a message built by
    // concatenation, `'prefix ' + value`, walked straight past it and the sweep stayed green. So the
    // test written to stop a control from being narrower than its conclusion was narrower than its
    // conclusion, which is the sixth time this module has shipped that shape and the first time it
    // shipped inside the guard against it.
    //
    // Asking for the one SAFE shape instead is complete by construction. Concatenation, a template
    // in any position, a ternary, a function call, and whatever syntax gets invented next all fail
    // closed, because none of them is a bare literal.
    const BARE_LITERAL = [
      /^'(?:[^'\\]|\\.)*'$/, // 'plain'
      /^"(?:[^"\\]|\\.)*"$/, // "plain"
      /^`(?:[^`\\$]|\\.|\$(?!\{))*`$/, // `plain`, but NOT one containing ${
    ];

    // A mint is named by the literal chrome its message opens with — never by a line number, which
    // is the citation this module's rules exist to keep out of failure messages. Chrome is read from
    // the FIRST literal in the argument, so a concatenation is named by its leading text exactly as a
    // template is; a message with no literal at all falls back to its own bounded text.
    const chromeOf = (t: string): string => {
      const q = t.search(/['"`]/);
      if (q < 0) return t.replace(/\s+/g, ' ').slice(0, ABBREV);
      const open = t[q] as string;
      const rest = t.slice(q + 1);
      const stops = [rest.indexOf(open), open === '`' ? rest.indexOf('${') : -1].filter((i) => i >= 0);
      return stops.length ? rest.slice(0, Math.min(...stops)) : rest.slice(0, ABBREV);
    };

    const MINT = 'new SaihmEndpointError(';
    const notBare: string[] = [];
    let mints = 0;
    for (const body of closure.values()) {
      for (const m of body.matchAll(/new SaihmEndpointError\(/g)) {
        mints++;
        const args = argsOf(body, m.index + MINT.length - 1);
        const message = (args[2] ?? '').trim();
        if (BARE_LITERAL.some((re) => re.test(message))) continue;
        notBare.push(chromeOf(message));
      }
    }
    assert.ok(mints > 0, 'the sweep found no mints in the join path at all — the matcher is broken');

    assert.deepEqual(
      notBare.sort(),
      [
        // Endpoint-chosen, both fenced at `MAX_ERROR_CODE_CHARS` and both driven by the two tests
        // above at two magnitudes.
        'SAIHM onboard failed: ',
        'free-onboard was not granted (',
        // Interpolates `this.requestTimeoutMs` — the client's OWN configured timeout. Nothing the
        // endpoint chose reaches it, so there is nothing here for a fence to cut.
        'SAIHM onboard timed out after ',
        // `readBodyCapped`'s over-budget throw, and the entry this list gained when the walk stopped
        // following methods alone. It interpolates its `method` argument and its `max` argument. On
        // the join path the only caller is `onboardFetch`, which passes a string LITERAL for the
        // first and `MAX_RESPONSE_BYTES` for the second, so both are the client's own and neither is
        // a value the endpoint returned. Note what it does NOT interpolate: the body it just refused
        // to read. That is the whole point of the mint — it fires because the payload was too large,
        // and putting any of that payload in the message would defeat the budget it enforces.
        'SAIHM endpoint ',
      ].sort(),
      'a join-path mint builds its message from something other than a plain string literal, and ' +
        'no test above drives it. If what it evaluates is endpoint-chosen it must be sliced at the ' +
        'mint and driven here; if it is local, say so in this list.',
    );
  });
});
