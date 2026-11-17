/**
 * Phase-6 e2e suite — SaihmProClient FREE->paid UPGRADE (`requestUpgradeUrl`) + lifetime-quota NAG
 * (`onQuotaNag`). Runner: npx tsx --test tests/client_upgrade_nag.test.ts
 *
 * Topology: a self-contained mock BRIDGE stands in for the operator endpoints:
 *   GET  /api/onboard/challenge   (existing)     -> { nonce }
 *   POST /api/stripe/checkout     (existing)     -> { url }        (upgrade + join share this route)
 *   POST /api/onboard             (existing)     -> { jwt }        (self-onboard, echoes tier)
 *   POST /mcp                     (existing)     -> tool result, OPTIONALLY carrying quota telemetry
 *                                                   { quota: { callType?, used, limit } } on 2xx, or a
 *                                                   429 { error: "quota_hard_cap" } at the lifetime cap.
 *
 * The checkout route CRYPTOGRAPHICALLY verifies the client's ML-DSA signature over the challenge nonce
 * (ml_dsa65.verify) — a URL is impossible without a genuine signature from THIS identity's secret key,
 * so proof-of-possession is a true binding, not a found-flag. The quota-telemetry field is the Phase-7
 * forward contract: `used`/`limit` are decimal-string counters and `limit` "0" means unlimited.
 */

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join as pathJoin } from 'node:path';

/**
 * A throwaway `SAIHM_HOME` for every server this harness spawns.
 *
 * The sequence-state default derives from the IDENTITY's directory - `SAIHM_HOME` - and deliberately
 * not from `SAIHM_STATE_DIR`, because relocating identity-scoped state while the identity stays put
 * restarts the rollback guard from zero. The consequence for a TEST harness is that isolating only
 * the state dir is not isolation at all: marks land in the developer's real `~/.saihm`, beside their
 * actual master secret. Measured at 60 stray files from a single afternoon of runs.
 */
const SEQ_ISOLATED_HOME = mkdtempSync(pathJoin(tmpdir(), 'saihm-home-'));
process.on('exit', () => rmSync(SEQ_ISOLATED_HOME, { recursive: true, force: true }));


import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { fromHex } from '@saihm/client-pro';
import { SaihmProClient, SaihmEndpointError, type QuotaNag } from '../src/client.js';
import { PlanFile, PAID_PLAN_TIERS } from '../src/plan-file.js';
import { failText, MAX_ERROR_MESSAGE_CHARS } from '../src/render_fence.js';

// The erasure feed's root derives from the IDENTITY's directory - `SAIHM_ERASURE_FEED_DIR`, then
// `SAIHM_HOME`, then `~/.saihm` - so a `forget()` in an unpinned test appends a REAL erasure line to
// whoever runs this suite. Pin the FEED alone rather than `SAIHM_HOME`: nothing else in this file
// reads this variable, so what is under test is unchanged and the sequence-state default is left
// exactly where each harness already put it.
process.env.SAIHM_ERASURE_FEED_DIR = mkdtempSync(pathJoin(tmpdir(), 'saihm-feed-'));

const masterOf = (n: number): Uint8Array => new Uint8Array(32).fill(n & 0xff);
const sha256Hex = (hex: string): string =>
  createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const b64url = (o: unknown): string =>
  Buffer.from(JSON.stringify(o)).toString('base64url');

// ─ CLI subprocess harness (UN20). The pro server runs main() on import ([[HG-#110]] pattern), so its
// subcommands must be exercised as a SPAWNED process, never imported. Async execFile keeps the test
// process's event loop free to serve the in-process mock bridge while the child runs — execFileSync would
// block the loop and deadlock the mock (which lives in this same process).
const pexec = promisify(execFile);
const serverPath = fileURLToPath(new URL('../src/server.ts', import.meta.url));
const tsxBin = fileURLToPath(new URL('../node_modules/.bin/tsx', import.meta.url));
const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const MASTER70_HEX = Buffer.from(masterOf(70)).toString('hex');
// The `upgrade` CLI persists its checkout URL under SAIHM_STATE_DIR, and `cliEnv` strips every
// ambient SAIHM_* — so without a value of its own the child falls back to ~/.saihm and every run of
// this file writes into the operator's real home. Give it a throwaway directory, and remove it when
// the process exits. (The sibling fix in server.test.ts covered only that file; this is the other
// spawn site, found by checking that the home file had actually stopped appearing.)
const CLI_STATE_DIR = mkdtempSync(pathJoin(tmpdir(), 'saihm-upgrade-nag-'));
process.on('exit', () => rmSync(CLI_STATE_DIR, { recursive: true, force: true }));

/** Child env with every ambient SAIHM_* stripped, then the explicit vars applied (no host bleed-through). */
const cliEnv = (extra: Record<string, string>): NodeJS.ProcessEnv => ({
  ...Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !k.startsWith('SAIHM_')),
  ),
  SAIHM_STATE_DIR: CLI_STATE_DIR,
  ...extra,
});

/** Optional quota telemetry the bridge attaches to a 2xx tool result (Phase-7 forward contract). */
interface QuotaTelem {
  callType?: string;
  used: string;
  limit: string;
}

interface MockOpts {
  /** GET /api/onboard/challenge malformation: 'no_nonce' (empty) or 'bad_hex' (non-hex nonce). */
  challengeMode?: 'no_nonce' | 'bad_hex';
  /** The checkout URL to return; default a valid https link. Set to a non-https value to test the guard. */
  checkoutUrl?: string;
  /** Omit the `url` field from the checkout response entirely (exercises the no-url guard). */
  checkoutNoUrl?: boolean;
  /** Quota telemetry to attach to the Nth saihm_remember 2xx result (index by remember call count). */
  rememberQuota?: ReadonlyArray<QuotaTelem | null>;
  /** Tool methods that should 429 with `quota_hard_cap` instead of succeeding. */
  hardCap?: ReadonlyArray<string>;
  /** Override the error `code` returned with a hardCap 429 (default 'quota_hard_cap'). */
  hardCapCode?: string;
  /** Mint the FIRST onboard's JWT as stale (never accepted), forcing one 401->re-onboard->retry. */
  staleFirstOnboard?: boolean;
  /** Quota telemetry to attach to a saihm_forget 2xx (drives the result-path callType fallback for a NON-remember method). */
  forgetQuota?: QuotaTelem;
  /** Force the minted JWT's `tier` claim to diverge from the tier the client sent (client-opt vs JWT-tier test). */
  onboardTierOverride?: string;
  /** Sent as `paid` on every FREE onboard answer, success or refusal (0.15.0: the key's paid plan). */
  onboardPaid?: unknown;
  /** A FREE onboard is refused as the endpoint refuses a key with no free plan (401 no_free_entitlement). */
  onboardNoFreePlan?: boolean;
  /** Every onboard fails with this HTTP status (a transient failure). */
  onboardFailStatus?: number;
  /** Every onboard's connection is cut before any answer (a network failure). */
  onboardDrop?: boolean;
  /** Every onboard meets the edge's own limit: a 429 with no body, only `retry-after` (0.15.0 review). */
  onboardLimitNoBody?: boolean;
  /** The checkout answers 409 with this body: a server that refuses a second checkout itself (0.15.0 review 2). */
  checkoutConflict?: unknown;
}

interface Mock {
  base: string;
  challengeCount: () => number;
  checkoutCount: () => number;
  /** Every POST /api/onboard that arrived, whatever its answer. */
  onboardAttempts: () => number;
  /** The tier each POST /api/onboard sent, in order. */
  onboardTiers: () => ReadonlyArray<string>;
  checkoutBodies: () => ReadonlyArray<Record<string, unknown>>;
  rememberCount: () => number;
  requestCount: () => number;
}

async function withMock(
  run: (m: Mock) => Promise<void>,
  opts: MockOpts = {},
): Promise<void> {
  const issuedNonces = new Set<string>();
  const valid = new Set<string>();
  const checkoutBodies: Record<string, unknown>[] = [];
  let challenges = 0;
  let checkouts = 0;
  let remembers = 0;
  let onboards = 0;
  let onboardAttempts = 0;
  const onboardTiers: string[] = [];
  let requests = 0;
  const hardCap = new Set(opts.hardCap ?? []);

  const server: Server = createServer((req, res) => {
    requests += 1;
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
    // ML-DSA proof-of-possession over an ISSUED nonce, keyed to the sender's pubkey field.
    const verifySig = (b: Record<string, unknown>, pubField: string): boolean => {
      const nonce = String(b.nonce ?? '');
      if (!issuedNonces.has(nonce)) return false;
      try {
        return ml_dsa65.verify(
          fromHex(String(b.signature ?? '')),
          fromHex(nonce),
          fromHex(String(b[pubField] ?? '')),
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

    if (req.method === 'POST' && url === '/api/stripe/checkout') {
      return readBody((b) => {
        checkouts += 1;
        checkoutBodies.push(b);
        // No URL without a valid PoP signature — the client must actually hold the private key.
        if (!verifySig(b, 'mldsaPubKey')) return send(401, { error: 'bad_signature' });
        issuedNonces.delete(String(b.nonce)); // single-use
        if (opts.checkoutNoUrl) return send(200, {});
        if (opts.checkoutConflict !== undefined) return send(409, opts.checkoutConflict);
        return send(200, {
          url: opts.checkoutUrl ?? `https://checkout.stripe.test/session/${b.tier}`,
        });
      });
    }

    if (req.method === 'POST' && url === '/api/onboard') {
      onboardAttempts += 1;
      if (opts.onboardDrop) {
        req.socket.destroy();
        return;
      }
      return readBody((b) => {
        onboardTiers.push(String(b.tier));
        if (!verifySig(b, 'pubkey')) return send(401, { error: 'bad_signature' });
        if (opts.onboardFailStatus !== undefined) return send(opts.onboardFailStatus, { error: 'busy' });
        if (opts.onboardLimitNoBody) {
          res.writeHead(429, { 'retry-after': '30' });
          res.end();
          return;
        }
        const paid = b.tier === 'FREE' && opts.onboardPaid !== undefined ? { paid: opts.onboardPaid } : {};
        if (b.tier === 'FREE' && opts.onboardNoFreePlan) {
          return send(401, { error: 'verification_failed', reason: 'no_free_entitlement', ...paid });
        }
        onboards += 1;
        const sub = sha256Hex(String(b.pubkey));
        const jwt = `${b64url({ alg: 'EdDSA' })}.${b64url({
          sub,
          tier: opts.onboardTierOverride ?? String(b.tier),
          exp: Math.floor(Date.now() / 1000) + 3600,
        })}.sig${onboards}`;
        // staleFirstOnboard: the first minted JWT is intentionally NOT accepted, forcing exactly one
        // 401 -> drop cached JWT -> re-onboard -> retry cycle in the client.
        if (!(opts.staleFirstOnboard && onboards === 1)) valid.add(jwt);
        return send(201, { jwt, ...paid });
      });
    }

    if (req.method === 'POST' && url === '/mcp') {
      const auth = req.headers['authorization'] ?? '';
      const tok = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      if (!valid.has(tok)) return send(401, { error: 'unauthorized' });
      return readBody((body) => {
        const method = String(body.method ?? '');
        if (hardCap.has(method)) {
          return send(429, {
            error: opts.hardCapCode ?? 'quota_hard_cap',
            reason: `${method} lifetime cap`,
          });
        }
        if (method === 'saihm_remember') {
          const q = (opts.rememberQuota ?? [])[remembers] ?? null;
          remembers += 1;
          const r: Record<string, unknown> = {
            cellId: 'cell' + remembers,
            shardId: 'shard' + remembers,
            seq: String(remembers),
            commitmentHash: 'ab'.repeat(32),
          };
          if (q) r.quota = q;
          return send(200, r);
        }
        if (method === 'saihm_recall') return send(200, []); // recall-all: bare array
        if (method === 'saihm_forget') {
          const r: Record<string, unknown> = {
            cellId: 'x',
            shardId: 'y',
            complete: true,
            sharesPurged: 0,
            steps: [],
            epoch: '1',
          };
          if (opts.forgetQuota) r.quota = opts.forgetQuota;
          return send(200, r);
        }
        return send(200, {});
      });
    }
    return send(404, { error: 'not_found' });
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    await run({
      base,
      challengeCount: () => challenges,
      checkoutCount: () => checkouts,
      onboardAttempts: () => onboardAttempts,
      onboardTiers: () => onboardTiers,
      checkoutBodies: () => checkoutBodies,
      rememberCount: () => remembers,
      requestCount: () => requests,
    });
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

// A FREE client (self-onboard; no paymentMethod — constructor relaxation).
const freeClient = (base: string, n: number, onQuotaNag?: (q: QuotaNag) => void) =>
  new SaihmProClient(base + '/mcp', undefined, masterOf(n), {
    tier: 'FREE',
    ...(onQuotaNag ? { onQuotaNag } : {}),
  });

// ─────────────────────────── UPGRADE (requestUpgradeUrl) ───────────────────────────

describe('UN1: FREE->PRO upgrade returns a checkout URL bound to THIS same key', () => {
  it('signs a nonce, sends tier=PRO + this pubkey, returns the hosted URL', async () => {
    await withMock(async (m) => {
      const c = freeClient(m.base, 20);
      const url = await c.requestUpgradeUrl('PRO');
      assert.ok(url.startsWith('https://'), 'a hosted https URL is returned');
      assert.equal(m.checkoutCount(), 1);
      const body = m.checkoutBodies()[0];
      // Exact request shape — no extra fields leak, target tier + THIS sovereign key are carried.
      assert.deepEqual(
        Object.keys(body).sort(),
        ['mldsaPubKey', 'nonce', 'signature', 'tier', 'uiMode'],
      );
      assert.equal(body.tier, 'PRO', 'the TARGET tier (not FREE) drives checkout');
      assert.equal(body.uiMode, 'hosted');
      assert.equal(
        sha256Hex(String(body.mldsaPubKey)),
        c.agentIdHash,
        'billing attaches to the SAME key -> agentIdHash unchanged -> memories persist',
      );
    });
  });
});

describe('UN2: requestUpgradeUrl defaults the target to monthly PRO', () => {
  it('no argument => tier PRO', async () => {
    await withMock(async (m) => {
      const c = freeClient(m.base, 21);
      await c.requestUpgradeUrl();
      assert.equal(m.checkoutBodies()[0].tier, 'PRO');
    });
  });
});

describe('UN3: a paid identity cannot use the FREE->paid door', () => {
  it('tier!=FREE => not_free_tier, ZERO network', async () => {
    await withMock(async (m) => {
      const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(22), {
        tier: 'PRO',
        paymentMethod: 'stripe',
      });
      await assert.rejects(
        () => c.requestUpgradeUrl('PRO_FAST'),
        (e: unknown) =>
          e instanceof SaihmEndpointError && e.code === 'not_free_tier',
      );
      assert.equal(m.challengeCount(), 0, 'refused before any network');
      assert.equal(m.checkoutCount(), 0);
    });
  });
});

describe('UN26: purchase safety: a key that already pays is not sent to checkout again (0.15.0)', () => {
  const refusal = (tier: string): string =>
    `This key already has ${tier}, so no checkout was created. To change or cancel your plan, email ops@saihm.net.`;
  const refused = (tier: string) => (e: unknown): boolean =>
    e instanceof SaihmEndpointError && e.code === 'already_subscribed' && e.status === 409 && e.message === refusal(tier);

  it('a FREE answer that names a paid plan: refused, ONE onboard, and no checkout', async () => {
    await withMock(
      async (m) => {
        const c = freeClient(m.base, 26);
        await assert.rejects(() => c.requestUpgradeUrl('PRO_FAST'), refused('PRO'));
        assert.equal(m.checkoutCount(), 0, 'no checkout was requested');
        assert.equal(m.onboardAttempts(), 1, 'one probe');
        assert.deepEqual(m.onboardTiers(), ['FREE'], 'the probe is a FREE onboard');
        assert.equal(m.challengeCount(), 1, "the probe's challenge only");
      },
      { onboardPaid: { tier: 'PRO', paymentMethod: 'stripe' } },
    );
  });

  it('a FREE refusal (no free plan) that names a paid plan: refused the same way', async () => {
    await withMock(
      async (m) => {
        const c = freeClient(m.base, 27);
        await assert.rejects(() => c.requestUpgradeUrl('PRO'), refused('PRO_FAST'));
        assert.equal(m.checkoutCount(), 0);
        assert.equal(m.onboardAttempts(), 1);
      },
      { onboardPaid: { tier: 'PRO_FAST', paymentMethod: 'paystack' }, onboardNoFreePlan: true },
    );
  });

  it('fails open: a probe that fails, or names no plan, leads to the checkout as before, with no second probe', async () => {
    const cases: Array<[string, MockOpts]> = [
      ['an HTTP failure', { onboardFailStatus: 503 }],
      ['a cut connection', { onboardDrop: true }],
      ['a refusal that names no plan', { onboardNoFreePlan: true }],
      ['a FREE answer that names no plan', {}],
      ['a `paid` that is not a plan', { onboardPaid: { tier: 'PRO', paymentMethod: 'stablecoin' } }],
    ];
    for (const [what, opts] of cases) {
      await withMock(async (m) => {
        const c = freeClient(m.base, 28);
        const url = await c.requestUpgradeUrl('PRO');
        assert.equal(url, 'https://checkout.stripe.test/session/PRO', `${what}: the checkout link`);
        assert.equal(m.checkoutCount(), 1, `${what}: one checkout`);
        assert.equal(m.onboardAttempts(), 1, `${what}: one probe, never repeated`);
      }, opts);
    }
  });

  it('a probe stopped by the sign-in limit (429) stops the upgrade: no checkout, the limit said, no second probe', async () => {
    // 0.15.0 review: failing open here sent runs made close together, the case the check is for, to a second checkout.
    for (const [what, opts] of [
      ['a limit with a code', { onboardFailStatus: 429 }],
      ['the edge limit, no body', { onboardLimitNoBody: true }],
    ] as Array<[string, MockOpts]>) {
      await withMock(async (m) => {
        const c = freeClient(m.base, 29);
        await assert.rejects(() => c.requestUpgradeUrl('PRO'), (e: unknown) => e instanceof SaihmEndpointError && e.status === 429, what);
        assert.equal(m.checkoutCount(), 0, `${what}: no checkout`);
        assert.equal(m.onboardAttempts(), 1, `${what}: one probe, never repeated`);
      }, opts);
    }
  });

  it('the `upgrade` command: refused on stderr, exit 1, no link printed, nothing marked pending', async () => {
    await withMock(
      async (m) => {
        const home = mkdtempSync(pathJoin(tmpdir(), 'saihm-un-paid-'));
        try {
          const env = cliEnv({ SAIHM_ENDPOINT_URL: m.base + '/mcp', SAIHM_MASTER_SECRET_HEX: MASTER70_HEX, SAIHM_HOME: home, SAIHM_TIER: 'FREE' });
          const run = await pexec(tsxBin, [serverPath, 'upgrade', 'PRO'], { cwd: projectRoot, env, timeout: 30_000 }).then(
            () => ({ code: 0, stdout: '', stderr: '' }),
            (e: { code?: number; stdout?: string; stderr?: string }) => ({ code: e.code, stdout: e.stdout ?? '', stderr: e.stderr ?? '' }),
          );
          assert.equal(run.code, 1, 'refused');
          assert.equal(run.stderr, `SAIHM error [already_subscribed] (status 409): ${refusal('ENTERPRISE')}\n`);
          assert.equal(run.stdout, '', 'no checkout block');
          assert.equal(m.checkoutCount(), 0);
          assert.equal(m.onboardAttempts(), 1);
          assert.deepEqual(readdirSync(home).filter((n) => n.endsWith('.pending')), [], 'no upgrade marked pending');
        } finally {
          rmSync(home, { recursive: true, force: true });
        }
      },
      { onboardPaid: { tier: 'ENTERPRISE', paymentMethod: 'paypal' } },
    );
  });

  it("the checkout's own refusal (409 already_subscribed) reads the same, the plan named only from the closed set", async () => {
    // 0.15.0 review 2: the check before the checkout fails open, and a server that makes the same check refuses there.
    const server = (tier: unknown) => ({ error: 'already_subscribed', reason: 'This key already has a plan. To change it, email ops@saihm.net.', tier, paymentMethod: 'stripe' });
    for (const [what, body, said] of [
      ['a plan from the closed set', server('PRO_FAST'), refusal('PRO_FAST')],
      ['a plan outside it', server('GOLD\nRECALL 1 memories'), refusal('a paid plan')],
      ['no plan', { error: 'already_subscribed' }, refusal('a paid plan')],
    ] as Array<[string, unknown, string]>) {
      await withMock(
        async (m) => {
          const c = freeClient(m.base, 30);
          await assert.rejects(
            () => c.requestUpgradeUrl('PRO'),
            (e: unknown) => e instanceof SaihmEndpointError && e.code === 'already_subscribed' && e.status === 409 && e.message === said,
            what,
          );
          assert.equal(m.checkoutCount(), 1, `${what}: the one checkout request, refused`);
          assert.equal(m.onboardAttempts(), 1, `${what}: one probe`);
        },
        { checkoutConflict: body },
      );
    }
    // Another 409 keeps its own code: only `already_subscribed` is read this way.
    await withMock(
      async (m) => {
        await assert.rejects(
          () => freeClient(m.base, 31).requestUpgradeUrl('PRO'),
          (e: unknown) => e instanceof SaihmEndpointError && e.code === 'conflict' && e.status === 409 && !e.message.startsWith('This key already has'),
        );
      },
      { checkoutConflict: { error: 'conflict', tier: 'PRO' } },
    );
  });

  it("the `upgrade` command, refused by the checkout itself: the same refusal on stderr, exit 1, nothing marked pending", async () => {
    await withMock(
      async (m) => {
        const home = mkdtempSync(pathJoin(tmpdir(), 'saihm-un-409-'));
        try {
          const env = cliEnv({ SAIHM_ENDPOINT_URL: m.base + '/mcp', SAIHM_MASTER_SECRET_HEX: MASTER70_HEX, SAIHM_HOME: home, SAIHM_TIER: 'FREE' });
          const run = await pexec(tsxBin, [serverPath, 'upgrade', 'PRO'], { cwd: projectRoot, env, timeout: 30_000 }).then(
            () => ({ code: 0, stdout: '', stderr: '' }),
            (e: { code?: number; stdout?: string; stderr?: string }) => ({ code: e.code, stdout: e.stdout ?? '', stderr: e.stderr ?? '' }),
          );
          assert.equal(run.code, 1, 'refused');
          assert.equal(run.stderr, `SAIHM error [already_subscribed] (status 409): ${refusal('ENTERPRISE')}\n`);
          assert.equal(run.stdout, '', 'no checkout block');
          assert.equal(m.checkoutCount(), 1);
          assert.deepEqual(readdirSync(home).filter((n) => n.endsWith('.pending')), [], 'no upgrade marked pending');
        } finally {
          rmSync(home, { recursive: true, force: true });
        }
      },
      { checkoutConflict: { error: 'already_subscribed', reason: 'This key already has a plan.', tier: 'ENTERPRISE', paymentMethod: 'paystack' } },
    );
  });

  it('the refusal renders whole through the error fence, for the longest plan name', () => {
    const longest = [...PAID_PLAN_TIERS].sort((a, b) => b.length - a.length)[0];
    const e = new SaihmEndpointError(409, 'already_subscribed', refusal(longest));
    assert.equal(failText(e), `SAIHM error [already_subscribed] (status 409): ${refusal(longest)}`);
    assert.ok(refusal(longest).length <= MAX_ERROR_MESSAGE_CHARS, `${refusal(longest).length} chars`);
  });
});

describe('UN4: upgrade target must be a monthly PAID tier', () => {
  for (const bad of ['FREE', 'PAYG', 'BOGUS', 'pro', '']) {
    it(`refuses '${bad}' => bad_upgrade_tier, ZERO network`, async () => {
      await withMock(async (m) => {
        const c = freeClient(m.base, 23);
        await assert.rejects(
          () => c.requestUpgradeUrl(bad),
          (e: unknown) =>
            e instanceof SaihmEndpointError && e.code === 'bad_upgrade_tier',
        );
        assert.equal(m.challengeCount(), 0, 'validated before any network');
        assert.equal(m.checkoutCount(), 0);
      });
    });
  }
});

describe('UN5: every monthly paid tier is a valid upgrade target', () => {
  for (const t of ['PRO', 'PRO_FAST', 'ENTERPRISE', 'ENTERPRISE_FAST']) {
    it(`accepts ${t} and carries it to checkout`, async () => {
      await withMock(async (m) => {
        const c = freeClient(m.base, 24);
        const url = await c.requestUpgradeUrl(t);
        assert.ok(url.startsWith('https://'));
        assert.equal(m.checkoutBodies()[0].tier, t);
      });
    });
  }
  it('tolerates surrounding whitespace on the target', async () => {
    await withMock(async (m) => {
      const c = freeClient(m.base, 25);
      await c.requestUpgradeUrl('  PRO  ');
      assert.equal(m.checkoutBodies()[0].tier, 'PRO');
    });
  });
});

describe('UN6: the checkoutUrlForTier extraction did NOT change requestCheckoutUrl', () => {
  it('paid join still sends tier=this.tier (byte-identical checkout wire)', async () => {
    await withMock(async (m) => {
      const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(26), {
        tier: 'PRO',
        paymentMethod: 'stripe',
      });
      await c.requestCheckoutUrl();
      const body = m.checkoutBodies()[0];
      assert.deepEqual(
        Object.keys(body).sort(),
        ['mldsaPubKey', 'nonce', 'signature', 'tier', 'uiMode'],
      );
      assert.equal(body.tier, 'PRO');
      assert.equal(body.uiMode, 'hosted');
    });
  });
  it('requestCheckoutUrl with no tier still throws no_tier', async () => {
    await withMock(async (m) => {
      const c = new SaihmProClient(m.base + '/mcp', `Bearer static`, masterOf(27));
      await assert.rejects(
        () => c.requestCheckoutUrl(),
        (e: unknown) => e instanceof SaihmEndpointError && e.code === 'no_tier',
      );
    });
  });
});

describe('UN7: shared checkout helper surfaces the same typed errors on both paths', () => {
  it('non-https url => checkout_no_url', async () => {
    await withMock(
      async (m) => {
        const c = freeClient(m.base, 28);
        await assert.rejects(
          () => c.requestUpgradeUrl('PRO'),
          (e: unknown) =>
            e instanceof SaihmEndpointError && e.code === 'checkout_no_url',
        );
      },
      { checkoutUrl: 'http://not-https.test/x' },
    );
  });
  it('missing url => checkout_no_url', async () => {
    await withMock(
      async (m) => {
        const c = freeClient(m.base, 29);
        await assert.rejects(
          () => c.requestUpgradeUrl('PRO'),
          (e: unknown) =>
            e instanceof SaihmEndpointError && e.code === 'checkout_no_url',
        );
      },
      { checkoutNoUrl: true },
    );
  });
  it('empty challenge => checkout_no_nonce', async () => {
    await withMock(
      async (m) => {
        const c = freeClient(m.base, 30);
        await assert.rejects(
          () => c.requestUpgradeUrl('PRO'),
          (e: unknown) =>
            e instanceof SaihmEndpointError && e.code === 'checkout_no_nonce',
        );
      },
      { challengeMode: 'no_nonce' },
    );
  });
  it('non-hex challenge => checkout_bad_nonce', async () => {
    await withMock(
      async (m) => {
        const c = freeClient(m.base, 31);
        await assert.rejects(
          () => c.requestUpgradeUrl('PRO'),
          (e: unknown) =>
            e instanceof SaihmEndpointError && e.code === 'checkout_bad_nonce',
        );
      },
      { challengeMode: 'bad_hex' },
    );
  });
});

// ─────────────────────────── NAG (onQuotaNag) ───────────────────────────

describe('UN8: FREE lifetime-usage nag fires at the 80% threshold', () => {
  it('used/limit crossing 80% surfaces one nag with correct fields', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 40, (n) => nags.push(n));
        await c.remember('hello');
        assert.equal(m.rememberCount(), 1, 'the write actually happened');
        assert.equal(nags.length, 1, 'exactly one nag');
        const n = nags[0];
        assert.equal(n.threshold, 80);
        assert.equal(n.atHardCap, false);
        assert.equal(n.callType, 'remember');
        assert.equal(n.used, 200n);
        assert.equal(n.limit, 250n);
        assert.ok(n.fraction !== null && Math.abs(n.fraction - 0.8) < 1e-9);
        assert.ok(n.upgradeHint.length > 0, 'a ready-to-show CTA is included');
        // Pin the load-bearing CTA content: the MANDATORY monthly-subscription framing and the exact
        // runnable command (the user copy-pastes it). Incidental wording may still vary freely.
        assert.match(n.upgradeHint, /monthly PRO/, 'CTA must state the monthly PRO subscription');
        assert.match(
          n.upgradeHint,
          /npx -y @saihm\/mcp-server-pro upgrade/,
          'CTA must carry the exact upgrade command',
        );
      },
      { rememberQuota: [{ callType: 'remember', used: '200', limit: '250' }] },
    );
  });
});

describe('UN9: rising usage nags each threshold once; a big jump nags only the highest crossed', () => {
  it('79->81->96->100 fires [80,95,100]; 0->96 would fire only 95', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 41, (n) => nags.push(n));
        await c.remember('a'); // 79.6% -> no nag
        assert.equal(nags.length, 0);
        await c.remember('b'); // 80.4% -> 80
        await c.remember('c'); // 96%   -> 95 (highest crossed; 80 already fired)
        await c.remember('d'); // 100%  -> 100
        assert.deepEqual(nags.map((n) => n.threshold), [80, 95, 100]);
        assert.equal(nags[2].atHardCap, true);
        // telemetry carried no `callType` -> label must fall back to nagCallType(method).
        assert.equal(nags[0].callType, 'remember', 'result-path fallback labels via nagCallType');
      },
      {
        rememberQuota: [
          { used: '199', limit: '250' },
          { used: '201', limit: '250' },
          { used: '240', limit: '250' },
          { used: '250', limit: '250' },
        ],
      },
    );
  });
  it('a single jump straight to 96% fires ONLY the 95 nag (not 80 too)', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 42, (n) => nags.push(n));
        await c.remember('x'); // 96%
        assert.deepEqual(nags.map((n) => n.threshold), [95]);
      },
      { rememberQuota: [{ used: '240', limit: '250' }] },
    );
  });
});

describe('UN10: hard cap (429 quota_hard_cap) nags at 100 AND still throws', () => {
  it('the nag fires with atHardCap and the 429 propagates unchanged', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 43, (n) => nags.push(n));
        await assert.rejects(
          () => c.remember('over'),
          (e: unknown) =>
            e instanceof SaihmEndpointError &&
            e.status === 429 &&
            e.code === 'quota_hard_cap',
        );
        assert.equal(nags.length, 1);
        assert.equal(nags[0].threshold, 100);
        assert.equal(nags[0].atHardCap, true);
        assert.equal(nags[0].callType, 'remember');
        assert.equal(nags[0].used, null, 'no counter carried on the error path');
        assert.equal(nags[0].limit, null);
        assert.equal(nags[0].fraction, 1, 'hard cap is definitively 100% even without counters');
      },
      { hardCap: ['saihm_remember'] },
    );
  });
});

describe('UN10b: a 429 that is NOT quota_hard_cap does NOT nag (code discriminator)', () => {
  it('a generic rate-limit 429 throws but fires no upgrade nag', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 59, (n) => nags.push(n));
        await assert.rejects(
          () => c.remember('rl'),
          (e: unknown) =>
            e instanceof SaihmEndpointError &&
            e.status === 429 &&
            e.code === 'rate_limited',
        );
        assert.equal(nags.length, 0, 'only quota_hard_cap nags; a generic 429 must not upsell');
      },
      { hardCap: ['saihm_remember'], hardCapCode: 'rate_limited' },
    );
  });
});

describe('UN10c: the 429 nag fires on the post-reauth RETRY branch (client.ts:1106)', () => {
  it('a stale JWT forces one 401->re-onboard->retry, then the retry 429 still nags at 100', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 60, (n) => nags.push(n));
        await assert.rejects(
          () => c.remember('retry-cap'),
          (e: unknown) =>
            e instanceof SaihmEndpointError &&
            e.status === 429 &&
            e.code === 'quota_hard_cap',
        );
        assert.deepEqual(nags.map((n) => n.threshold), [100]);
        assert.equal(nags[0].atHardCap, true);
      },
      { staleFirstOnboard: true, hardCap: ['saihm_remember'] },
    );
  });
});

describe('UN9c: the result nag fires on the post-reauth RETRY branch (client.ts:1109)', () => {
  it('a stale JWT forces one 401->re-onboard->retry, then the retry 2xx telemetry nags', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 61, (n) => nags.push(n));
        await c.remember('retry-ok'); // 401 -> re-onboard -> retry 2xx @ 96%
        assert.deepEqual(nags.map((n) => n.threshold), [95]);
        assert.equal(nags[0].callType, 'remember');
      },
      {
        staleFirstOnboard: true,
        rememberQuota: [{ used: '240', limit: '250' }], // 96%
      },
    );
  });
});

describe('UN9d: an over-cap 2xx result clamps fraction to 1 (Math.min guard)', () => {
  it('used>limit on a 2xx nags at 100 with fraction exactly 1, never >1', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 62, (n) => nags.push(n));
        await c.remember('over'); // 300/250 = 120% -> clamp to 1
        assert.deepEqual(nags.map((n) => n.threshold), [100]);
        assert.equal(nags[0].fraction, 1, 'fraction clamped to 1, never >1');
        assert.equal(nags[0].used, 300n);
        assert.equal(nags[0].limit, 250n);
        assert.equal(nags[0].atHardCap, true);
      },
      { rememberQuota: [{ used: '300', limit: '250' }] },
    );
  });
});

describe('UN9e: the 95 threshold fires at EXACTLY 95.0% and is NOT the hard cap', () => {
  it('used/limit = 190/200 (exactly 95%) fires the 95 nag with atHardCap=false', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 66, (n) => nags.push(n));
        await c.remember('exact95'); // 190/200 = 95.0% exactly -> pins `pct >= 95`, not `>`
        assert.deepEqual(nags.map((n) => n.threshold), [95]);
        assert.equal(nags[0].atHardCap, false, '95% is advisory, not the hard cap');
      },
      { rememberQuota: [{ used: '190', limit: '200' }] },
    );
  });
});

describe('UN11: each (callType, threshold) nag fires at most once', () => {
  it('repeated writes in the 80% band nag exactly once', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 44, (n) => nags.push(n));
        await c.remember('1');
        await c.remember('2');
        await c.remember('3');
        assert.equal(nags.length, 1, 'deduped across calls');
        assert.equal(nags[0].threshold, 80);
      },
      {
        rememberQuota: [
          { used: '205', limit: '250' },
          { used: '210', limit: '250' },
          { used: '215', limit: '250' },
        ],
      },
    );
  });
  it('after 95 fires, a later call reporting a LOWER (80%) band does NOT re-nag', async () => {
    // Kills the equivalent mutant where fireNag marks only the exact threshold: once 95 has fired it
    // must also mark 80, so a subsequent call whose fraction dips back into the 80% band stays silent.
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 58, (n) => nags.push(n));
        await c.remember('hi'); // 96% -> fires 95 (marks 80 + 95)
        assert.deepEqual(nags.map((n) => n.threshold), [95]);
        await c.remember('lo'); // 82% -> 80 already marked; must NOT fire
        assert.deepEqual(
          nags.map((n) => n.threshold),
          [95],
          '80 stays suppressed after 95 fired',
        );
      },
      {
        rememberQuota: [
          { used: '240', limit: '250' }, // 96%
          { used: '205', limit: '250' }, // 82%
        ],
      },
    );
  });
});

describe('UN11c: dedupe key is per (callType, threshold), not per threshold alone', () => {
  it('after remember hits 100%, a distinct sharing-labeled 80% nag still fires', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 67, (n) => nags.push(n));
        await c.remember('a'); // callType 'remember' @ 100% -> marks remember:{80,95,100}
        await c.remember('b'); // callType 'sharing'  @ 80%  -> distinct key, must still nag
        assert.deepEqual(
          nags.map((n) => [n.callType, n.threshold]),
          [
            ['remember', 100],
            ['sharing', 80],
          ],
          'a global-per-threshold dedupe would wrongly swallow the sharing nag',
        );
      },
      {
        rememberQuota: [
          { callType: 'remember', used: '250', limit: '250' },
          { callType: 'sharing', used: '20', limit: '25' },
        ],
      },
    );
  });
});

describe('UN12: paid tiers NEVER nag (FREE-only gate)', () => {
  it('a PRO client hitting 429 quota_hard_cap gets NO nag; the error still throws', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(45), {
          tier: 'PRO',
          paymentMethod: 'stripe',
          onQuotaNag: (n) => nags.push(n),
        });
        await assert.rejects(
          () => c.remember('paid'),
          (e: unknown) =>
            e instanceof SaihmEndpointError && e.status === 429,
        );
        assert.equal(nags.length, 0, 'paid never nags — the FREE->PRO CTA would be wrong');
      },
      { hardCap: ['saihm_remember'] },
    );
  });
  it('a PRO client with quota telemetry present also does not nag', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(46), {
          tier: 'PRO',
          paymentMethod: 'stripe',
          onQuotaNag: (n) => nags.push(n),
        });
        await c.remember('paid');
        assert.equal(nags.length, 0);
      },
      { rememberQuota: [{ used: '999', limit: '250' }] },
    );
  });
});

describe('UN13: with no onQuotaNag callback, telemetry + 429 are harmless', () => {
  it('remember returns normally when telemetry present but no callback', async () => {
    await withMock(
      async (m) => {
        const c = freeClient(m.base, 47); // no callback
        const r = await c.remember('ok');
        // The receipt is the CLIENT's, not the endpoint's echo of `cell1`: a write's cellId, seq and
        // commitment all have a local, authenticated source, so only `shardId` is the endpoint's.
        // What this test is about is that quota telemetry does not disturb the receipt at all.
        assert.match(r.cellId, /^[0-9a-f]{32}$/);
        assert.equal(r.seq, '1');
      },
      { rememberQuota: [{ used: '250', limit: '250' }] },
    );
  });
  it('a 429 still throws (unchanged) with no callback', async () => {
    await withMock(
      async (m) => {
        const c = freeClient(m.base, 48);
        await assert.rejects(
          () => c.remember('x'),
          (e: unknown) => e instanceof SaihmEndpointError && e.status === 429,
        );
      },
      { hardCap: ['saihm_remember'] },
    );
  });
});

describe('UN14: unusable telemetry never nags', () => {
  it('limit "0" (unlimited) => no nag', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 49, (n) => nags.push(n));
        await c.remember('u');
        assert.equal(nags.length, 0);
      },
      { rememberQuota: [{ used: '9999', limit: '0' }] },
    );
  });
  it('non-numeric counters => no nag, no throw', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 50, (n) => nags.push(n));
        const r = await c.remember('u');
        assert.match(r.cellId, /^[0-9a-f]{32}$/); // the client's own id, never the endpoint's echo
        assert.equal(nags.length, 0);
      },
      { rememberQuota: [{ used: 'lots', limit: 'many' } as unknown as QuotaTelem] },
    );
  });
  it('usage below 80% => no nag', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 51, (n) => nags.push(n));
        await c.remember('u');
        assert.equal(nags.length, 0);
      },
      { rememberQuota: [{ used: '197', limit: '250' }] }, // 78.8%
    );
  });
});

describe('UN15: a throwing nag callback cannot break the operation', () => {
  it('remember still returns its result when the callback throws', async () => {
    await withMock(
      async (m) => {
        const c = freeClient(m.base, 52, () => {
          throw new Error('callback blew up');
        });
        const r = await c.remember('resilient');
        assert.match(r.cellId, /^[0-9a-f]{32}$/, 'the write result is returned despite the throw');
      },
      { rememberQuota: [{ used: '250', limit: '250' }] },
    );
  });
  it('the ORIGINAL 429 (not the callback throw) propagates on the hard-cap path', async () => {
    await withMock(
      async (m) => {
        const c = freeClient(m.base, 53, () => {
          throw new Error('callback blew up');
        });
        await assert.rejects(
          () => c.remember('over'),
          (e: unknown) =>
            e instanceof SaihmEndpointError && e.code === 'quota_hard_cap',
        );
      },
      { hardCap: ['saihm_remember'] },
    );
  });
});

describe('UN16: nag callType labelling', () => {
  it('telemetry callType overrides the method mapping', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 54, (n) => nags.push(n));
        await c.remember('x');
        assert.equal(nags[0].callType, 'sharing', 'server-declared callType wins');
      },
      { rememberQuota: [{ callType: 'sharing', used: '20', limit: '25' }] }, // 80%
    );
  });
  it('a 429 on recall labels the nag callType "recall"', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 55, (n) => nags.push(n));
        await assert.rejects(() => c.recall(), (e: unknown) => e instanceof SaihmEndpointError);
        assert.equal(nags.length, 1);
        assert.equal(nags[0].callType, 'recall');
        assert.equal(nags[0].threshold, 100);
      },
      { hardCap: ['saihm_recall'] },
    );
  });
  it('a 429 on forget labels the nag callType "forget"', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 56, (n) => nags.push(n));
        await assert.rejects(
          () => c.forget('deadbeef'),
          (e: unknown) => e instanceof SaihmEndpointError,
        );
        assert.equal(nags[0].callType, 'forget');
      },
      { hardCap: ['saihm_forget'] },
    );
  });
  it('a 429 on revokeShare labels the nag callType "sharing"', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 63, (n) => nags.push(n));
        await assert.rejects(
          () => c.revokeShare('cellX', 'aa'.repeat(32)),
          (e: unknown) =>
            e instanceof SaihmEndpointError &&
            e.status === 429 &&
            e.code === 'quota_hard_cap',
        );
        assert.equal(nags.length, 1);
        assert.equal(nags[0].callType, 'sharing', 'share/revoke_share map to the sharing quota');
        assert.equal(nags[0].threshold, 100);
      },
      { hardCap: ['saihm_revoke_share'] },
    );
  });
  it('a 429 on an unmapped method (status) falls back to callType "usage"', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 64, (n) => nags.push(n));
        await assert.rejects(
          () => c.status(),
          (e: unknown) =>
            e instanceof SaihmEndpointError &&
            e.status === 429 &&
            e.code === 'quota_hard_cap',
        );
        assert.equal(nags.length, 1);
        assert.equal(nags[0].callType, 'usage', 'unmapped methods label the nag "usage"');
      },
      { hardCap: ['saihm_status'] },
    );
  });
});

describe('UN16d: result-path callType falls back to nagCallType for a NON-remember method', () => {
  it('forget 2xx telemetry with no callType labels the nag "forget" (not a hardcoded remember)', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 68, (n) => nags.push(n));
        await c.forget('deadbeef'); // 2xx quota @ 80%, telemetry carries NO callType
        assert.equal(nags.length, 1);
        assert.equal(
          nags[0].callType,
          'forget',
          'result-path fallback must use nagCallType(method), not a literal "remember"',
        );
        assert.equal(nags[0].threshold, 80);
      },
      { forgetQuota: { used: '20', limit: '25' } }, // 80%, no callType
    );
  });
});

describe('UN16e: an empty-string telemetry callType falls back to the method mapping', () => {
  it('callType:"" is treated as absent -> nag labeled by nagCallType, not ""', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 69, (n) => nags.push(n));
        await c.remember('x'); // telemetry callType '' (empty) -> must fall back to 'remember'
        assert.equal(nags.length, 1);
        assert.equal(
          nags[0].callType,
          'remember',
          'an empty callType is falsy-guarded, never used as the label',
        );
      },
      { rememberQuota: [{ callType: '', used: '200', limit: '250' }] }, // 80%, empty callType
    );
  });
});

describe('UN17: recall-all (a bare array) carries no telemetry field and never falsely nags', () => {
  it('a successful recall-all does not nag', async () => {
    await withMock(async (m) => {
      const nags: QuotaNag[] = [];
      const c = freeClient(m.base, 57, (n) => nags.push(n));
      const rows = await c.recall();
      assert.deepEqual(rows, []);
      assert.equal(nags.length, 0);
    });
  });
});

describe('UN18: (callType, threshold) nag dedupe holds under concurrent in-flight calls', () => {
  it('six concurrent writes all in the 80% band nag exactly once', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 71, (n) => nags.push(n));
        // The six calls share ONE single-flighted onboard, then fire concurrently. fireNag's
        // check-then-mark is synchronous (no await between the `has` guard and the marking loop), so
        // the first crossing wins and the other five are no-ops. A regression that yielded the loop
        // between guard and mark would let several race past and double-fire.
        await Promise.all([
          c.remember('a'),
          c.remember('b'),
          c.remember('c'),
          c.remember('d'),
          c.remember('e'),
          c.remember('f'),
        ]);
        assert.equal(m.rememberCount(), 6, 'all six writes landed');
        assert.equal(m.challengeCount(), 1, 'the six first-calls shared one single-flighted onboard');
        assert.equal(nags.length, 1, 'concurrent crossings dedupe to a single nag');
        assert.equal(nags[0].threshold, 80);
      },
      {
        rememberQuota: [
          { used: '205', limit: '250' },
          { used: '206', limit: '250' },
          { used: '207', limit: '250' },
          { used: '208', limit: '250' },
          { used: '209', limit: '250' },
          { used: '210', limit: '250' },
        ],
      },
    );
  });
});

describe('UN19: the nag gate keys on the CONSTRUCTOR tier, not the JWT tier claim', () => {
  it('a FREE client still nags even when the minted JWT claims PRO', async () => {
    // A regression that overwrote this.tier from the JWT would make this.tier="PRO" post-onboard and
    // silence the nag — this pins that the client trusts its own construction tier.
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 72, (n) => nags.push(n));
        await c.remember('x'); // 2xx @ 80%; JWT tier says PRO but this.tier is FREE
        assert.equal(nags.length, 1, 'gate follows this.tier=FREE, not the JWT tier');
        assert.equal(nags[0].threshold, 80);
      },
      { rememberQuota: [{ used: '200', limit: '250' }], onboardTierOverride: 'PRO' },
    );
  });
  it('a PRO client never nags even when the minted JWT claims FREE', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = new SaihmProClient(m.base + '/mcp', undefined, masterOf(73), {
          tier: 'PRO',
          paymentMethod: 'stripe',
          onQuotaNag: (n) => nags.push(n),
        });
        await c.remember('x'); // 2xx @ 80%; JWT tier says FREE but this.tier is PRO
        assert.equal(
          nags.length,
          0,
          'a FREE-claiming JWT must not turn on the FREE->PRO upsell for a paid client',
        );
      },
      { rememberQuota: [{ used: '200', limit: '250' }], onboardTierOverride: 'FREE' },
    );
  });
});

describe('UN20: the `upgrade`/`free-join` CLI subcommands execute end-to-end (spawned; main() runs on import)', () => {
  it('`upgrade PRO` prints the hosted checkout URL bound to this identity', async () => {
    await withMock(async (m) => {
      const env = cliEnv({
        SAIHM_ENDPOINT_URL: m.base + '/mcp',
        SAIHM_MASTER_SECRET_HEX: MASTER70_HEX,
        // Isolated because the sequence-state default derives from SAIHM_HOME, not SAIHM_STATE_DIR.
        SAIHM_HOME: SEQ_ISOLATED_HOME,
        SAIHM_TIER: 'FREE',
      });
      const { stdout } = await pexec(tsxBin, [serverPath, 'upgrade', 'PRO'], {
        cwd: projectRoot,
        env,
        timeout: 30_000,
      });
      assert.match(stdout, /https:\/\/checkout\.stripe\.test\/session\/PRO/);
      // 0.15.0: nothing to configure after paying. Each client finds the plan at its next sign-in, so the env and TOML
      // steps 0.14.3 printed are gone, and nothing waits for the payment.
      for (const step of ['"SAIHM_TIER":', '"SAIHM_PAYMENT_METHOD"', 'env = {', 'SAIHM_TIER = ', 'A paid plan needs both'])
        assert.ok(!stdout.includes(step), `no settings step: ${step}\n${stdout}`);
      assert.match(stdout, /After you pay, there is nothing to change: every AI client that uses this key switches to\n  PRO on its own within the hour, once it runs SAIHM 0\.15\.0 or later\. To switch one on\n  this computer now, restart it, then say "Show my SAIHM status"\./);
      assert.match(stdout, /A client whose settings name a paid SAIHM_TIER keeps those settings: remove SAIHM_TIER\n  and SAIHM_PAYMENT_METHOD there to let SAIHM pick the plan\./);
      const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
      const tomlLine = readme.split('\n').find((l) => l.startsWith('env = { SAIHM_ENDPOINT_URL'))!;
      assert.equal(tomlLine, 'env = { SAIHM_ENDPOINT_URL = "https://saihm.net/mcp" }', "the README's env line holds only the endpoint");
      // The printed identity is the one derived from the SAME master secret the child booted from.
      const ref = new SaihmProClient(m.base + '/mcp', undefined, masterOf(70), { tier: 'FREE' });
      assert.ok(stdout.includes(ref.agentIdHash), 'CLI prints the derived agentIdHash');
      assert.equal(m.checkoutCount(), 1);
      assert.ok(m.requestCount() >= 1, 'the request counter sees the checkout');
      assert.equal(m.checkoutBodies()[0].tier, 'PRO', 'the CLI target tier reaches checkout');
    });
  });

  it('`upgrade` reads the FREE plan from the settings, whatever plan was saved from the server (0.15.0)', async () => {
    await withMock(async (m) => {
      const home = mkdtempSync(pathJoin(tmpdir(), 'saihm-un-plan-'));
      try {
        const ref = new SaihmProClient(m.base + '/mcp', undefined, masterOf(70), { tier: 'FREE' });
        assert.equal(new PlanFile(pathJoin(home, `plan.${ref.agentIdHash.slice(0, 16)}.json`), ref.agentIdHash).keep({ tier: 'PRO', paymentMethod: 'stripe' }), true);
        const env = cliEnv({ SAIHM_ENDPOINT_URL: m.base + '/mcp', SAIHM_MASTER_SECRET_HEX: MASTER70_HEX, SAIHM_HOME: home, SAIHM_TIER: 'FREE' });
        const { stdout } = await pexec(tsxBin, [serverPath, 'upgrade', 'PRO_FAST'], { cwd: projectRoot, env, timeout: 30_000 });
        assert.match(stdout, /https:\/\/checkout\.stripe\.test\/session\/PRO_FAST/, 'not refused as a paid identity');
        assert.equal(m.checkoutCount(), 1);
      } finally {
        rmSync(home, { recursive: true, force: true });
      }
    });
  });

  it('`upgrade` refuses a SAIHM_HOME with the shape of a key: never printed, and nothing written under it', async () => {
    await withMock(async (m) => {
      const base = mkdtempSync(pathJoin(tmpdir(), 'saihm-un-kh-'));
      const shaped = randomBytes(32).toString('hex');
      mkdirSync(pathJoin(base, shaped), { recursive: true, mode: 0o700 });
      try {
        const env = cliEnv({
          SAIHM_ENDPOINT_URL: m.base + '/mcp',
          SAIHM_MASTER_SECRET_HEX: MASTER70_HEX,
          SAIHM_HOME: pathJoin(base, shaped),
          // Unset, as on a machine that never set it: the checkout file then lands under SAIHM_HOME.
          SAIHM_STATE_DIR: '',
          SAIHM_TIER: 'FREE',
        });
        // Since batch 7 boot refuses such a home before anything is written under it (security R6 F1): the checkout
        // file landed in it, its location withheld. The intent stands - the home is never printed - and now
        // nothing is written there either.
        await assert.rejects(
          () => pexec(tsxBin, [serverPath, 'upgrade', 'PRO'], { cwd: projectRoot, env, timeout: 30_000 }),
          (e: unknown) => {
            const err = e as { code?: number; stdout?: string; stderr?: string };
            assert.equal(err.code, 1);
            assert.match(err.stderr ?? '', /SAIHM_HOME holds what looks like a key, passphrase or token rather than a directory, so nothing is written there/);
            assert.ok(!`${err.stdout}${err.stderr}`.includes(shaped), 'the key-shaped SAIHM_HOME is not printed');
            return true;
          },
        );
        const { readdirSync } = await import('node:fs');
        assert.deepEqual(readdirSync(pathJoin(base, shaped)), [], 'no checkout file is written under it');
        assert.equal(m.requestCount(), 0, 'refused before any network');
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
    });
  });

  it('`upgrade` with no tier arg defaults to monthly PRO', async () => {
    await withMock(async (m) => {
      const env = cliEnv({
        SAIHM_ENDPOINT_URL: m.base + '/mcp',
        SAIHM_MASTER_SECRET_HEX: MASTER70_HEX,
        // Isolated because the sequence-state default derives from SAIHM_HOME, not SAIHM_STATE_DIR.
        SAIHM_HOME: SEQ_ISOLATED_HOME,
        SAIHM_TIER: 'FREE',
      });
      const { stdout } = await pexec(tsxBin, [serverPath, 'upgrade'], {
        cwd: projectRoot,
        env,
        timeout: 30_000,
      });
      assert.match(stdout, /https:\/\/checkout\.stripe\.test\/session\/PRO/);
      assert.equal(m.checkoutBodies()[0].tier, 'PRO');
      assert.ok(stdout.includes('switches to\n  PRO on its own within the hour'), 'the line names the default tier too');
    });
  });

  it('`upgrade BOGUS` exits non-zero (bad_upgrade_tier) and makes ZERO network calls', async () => {
    await withMock(async (m) => {
      const env = cliEnv({
        SAIHM_ENDPOINT_URL: m.base + '/mcp',
        SAIHM_MASTER_SECRET_HEX: MASTER70_HEX,
        // Isolated because the sequence-state default derives from SAIHM_HOME, not SAIHM_STATE_DIR.
        SAIHM_HOME: SEQ_ISOLATED_HOME,
        SAIHM_TIER: 'FREE',
      });
      await assert.rejects(
        () =>
          pexec(tsxBin, [serverPath, 'upgrade', 'BOGUS'], {
            cwd: projectRoot,
            env,
            timeout: 30_000,
          }),
        (e: unknown) => {
          const err = e as { code?: number; stderr?: string };
          assert.equal(err.code, 1, 'non-zero exit on a bad target');
          assert.match(err.stderr ?? '', /monthly paid tier/, 'the typed error reaches stderr');
          return true;
        },
      );
      assert.equal(m.challengeCount(), 0, 'a bad target is refused before any network');
      assert.equal(m.checkoutCount(), 0);
    });
  });

  it('`free-join` on an identity already on a paid plan exits 0, saying there is nothing to join, before any network', async () => {
    await withMock(async (m) => {
      const env = cliEnv({
        SAIHM_ENDPOINT_URL: m.base + '/mcp',
        SAIHM_MASTER_SECRET_HEX: MASTER70_HEX,
        // Isolated because the sequence-state default derives from SAIHM_HOME, not SAIHM_STATE_DIR.
        SAIHM_HOME: SEQ_ISOLATED_HOME,
        SAIHM_TIER: 'PRO',
        SAIHM_PAYMENT_METHOD: 'stripe',
      });
      const { stdout } = await pexec(tsxBin, [serverPath, 'free-join'], {
        cwd: projectRoot,
        env,
        timeout: 30_000,
      });
      // "configured for the PRO plan" since batch 7: the plan set here, which the join does not check with the endpoint.
      assert.match(stdout, /has a SAIHM identity, configured for the PRO plan\./, 'free-join names the paid plan');
      assert.match(stdout, /nothing to join/, 'and says there is nothing to do');
      assert.equal(m.requestCount(), 0, 'answered before any network');
    });
  });
});

describe('UN25: a quota counter is bounded before it is parsed', () => {
  // The cap is pinned from BOTH sides at its exact value, so it cannot drift silently: 32 digits must
  // still nag, 33 must not. Only this pair is a real regression test. The other half of the defect —
  // two counters past ~1.8e308 converting to `Infinity`, giving `fraction = NaN` and firing NOTHING —
  // is NOT testable through behaviour, because "fires nothing" is also what the fix produces. Writing
  // a case for it would assert something true before and after and read as coverage it is not.
  it('a 33-digit used is unusable data => no nag (the write still succeeds)', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 41, (n) => nags.push(n));
        await c.remember('hello');
        assert.equal(m.rememberCount(), 1, 'the write is unaffected by unusable telemetry');
        // Unbounded, this parsed to a bigint and `Number()` divided it by 250 into a huge fraction,
        // firing a 100% nag off a value no counter can hold. `null` (=> silence) is what the function
        // already documents for unusable data; the cap is what makes this value reach that branch.
        assert.equal(nags.length, 0, 'an over-long counter nags not at all, rather than at 100%');
      },
      {
        rememberQuota: [
          { callType: 'remember', used: '1'.repeat(33), limit: '250' },
        ],
      },
    );
  });

  it('a 32-digit used is still parsed and still nags', async () => {
    await withMock(
      async (m) => {
        const nags: QuotaNag[] = [];
        const c = freeClient(m.base, 42, (n) => nags.push(n));
        await c.remember('hello');
        assert.equal(m.rememberCount(), 1);
        assert.equal(nags.length, 1, 'a value AT the ceiling is not rejected by it');
        assert.equal(nags[0].threshold, 100);
        assert.equal(nags[0].used, BigInt('1'.repeat(32)));
        assert.equal(nags[0].limit, 250n);
        // The clamp, not the raw ratio: `Math.min(1, fraction)` holds even at 1e30x over.
        assert.equal(nags[0].fraction, 1);
      },
      {
        rememberQuota: [
          { callType: 'remember', used: '1'.repeat(32), limit: '250' },
        ],
      },
    );
  });
});

// The 0.15.0 round-1 reviewer's kill tests: `join` and `free-join` read the plan from the settings, never the saved one
// (bootFromEnv({ savedPlan: false })): each pins a guard a mutant removed with the suite still green.
describe('K8K9: join and free-join ignore a saved plan (0.15.0)', () => {
  const seeded = (base: string): string => {
    const home = mkdtempSync(pathJoin(tmpdir(), 'saihm-k89-'));
    const ref = new SaihmProClient(base + '/mcp', undefined, masterOf(70), { tier: 'FREE' });
    assert.equal(new PlanFile(pathJoin(home, `plan.${ref.agentIdHash.slice(0, 16)}.json`), ref.agentIdHash).keep({ tier: 'PRO', paymentMethod: 'stripe' }), true);
    return home;
  };
  const run = (args: string[], env: NodeJS.ProcessEnv) =>
    pexec(tsxBin, [serverPath, ...args], { cwd: projectRoot, env, timeout: 30_000 }).then(
      (r) => ({ code: 0, stdout: r.stdout, stderr: r.stderr }),
      (e: { code?: number; stdout?: string; stderr?: string }) => ({ code: e.code, stdout: e.stdout ?? '', stderr: e.stderr ?? '' }),
    );
  it('K8 `join` with SAIHM_TIER=FREE and a saved PRO plan asks for no PRO checkout', async () => {
    await withMock(async (m) => {
      const home = seeded(m.base);
      try {
        await run(['join'], cliEnv({ SAIHM_ENDPOINT_URL: m.base + '/mcp', SAIHM_MASTER_SECRET_HEX: MASTER70_HEX, SAIHM_HOME: home, SAIHM_TIER: 'FREE' }));
        assert.deepEqual(m.checkoutBodies().map((b) => b.tier), ['FREE'], 'the checkout names the settings plan, never the saved one');
      } finally {
        rmSync(home, { recursive: true, force: true });
      }
    });
  });
  it('K9 `free-join` with SAIHM_TIER=FREE and a saved PRO plan starts the free join, not refused as paid', async () => {
    await withMock(async (m) => {
      const home = seeded(m.base);
      try {
        const r = await run(['free-join'], cliEnv({ SAIHM_ENDPOINT_URL: m.base + '/mcp', SAIHM_MASTER_SECRET_HEX: MASTER70_HEX, SAIHM_HOME: home, SAIHM_TIER: 'FREE' }));
        assert.match(r.stdout, /starting your free join/);
        assert.doesNotMatch(r.stderr, /not_free_tier|requires the FREE tier/, r.stderr);
      } finally {
        rmSync(home, { recursive: true, force: true });
      }
    });
  });
});
