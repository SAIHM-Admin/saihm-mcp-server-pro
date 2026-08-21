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
import { SaihmProClient, SaihmEndpointError } from '../src/client.js';

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
    const send = (status: number, body: unknown): void => {
      res.writeHead(status, { 'content-type': 'application/json' });
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
