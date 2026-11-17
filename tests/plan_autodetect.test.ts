// The plan found from the server (0.15.0). A FREE sign-in's answer, or its refusal for want of a free plan, names the
// paid plan this key holds (`paid`); the client switches to it, saves it, and signs in on it at once. A paid SAIHM_TIER
// or an identity's paid plan never switches. A found plan the endpoint refuses (lapsed, or changed in the billing
// portal) goes back to FREE, which may name the new plan. Every test counts the onboards: nothing polls, a switch from
// FREE costs one more onboard, and a plan change two at most (one FREE, one on the new plan). Against a local mock bridge
// only.
// Runner: npx tsx --test tests/plan_autodetect.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SaihmProClient, SaihmEndpointError } from '../src/client.js';
import { PlanFile, paidPlanOf } from '../src/plan-file.js';
import { failText, labelSafe, safeField, MAX_ERROR_MESSAGE_CHARS, MAX_JOIN_FIELD_CHARS } from '../src/render_fence.js';

const POSIX = process.platform !== 'win32';
const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
const HEX = (b: string): string => b.repeat(32);

interface Bridge {
  server: Server;
  base: string;
  /** The tier each POST /api/onboard sent, in order. */
  onboards: string[];
  /** The tier in the token each memory call carried, in order. */
  used: string[];
  /** The subscription this key holds, or null. */
  sub: { tier: string; method: string } | null;
  /** Whether a FREE onboard succeeds. */
  freeEntitled: boolean;
  /** Sent as `paid` on FREE answers instead of the subscription, when set (undefined = from `sub`). */
  paidOverride?: unknown;
  /** The paid check refuses whatever the subscription (an endpoint that names a plan it then refuses). */
  refusePaid: boolean;
  /** A paid onboard fails with this status (a transient failure), when set. */
  failPaid?: number;
  /** Token lifetime in seconds; negative = already expired, so every call signs in again. */
  ttlS: number;
  /** The next memory call is refused (401), so the client signs in again and retries, as for a revoked token. */
  refuseNextCall: boolean;
}

async function bridge(init: Partial<Bridge> = {}): Promise<Bridge> {
  const b = { onboards: [], used: [], sub: null, freeEntitled: true, refusePaid: false, ttlS: 3600, refuseNextCall: false, ...init } as unknown as Bridge;
  b.server = createServer((req, res) => {
    const send = (s: number, body: unknown): void => {
      res.writeHead(s, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      const url = req.url ?? '';
      if (req.method === 'GET' && url === '/api/onboard/challenge') return send(200, { nonce: randomBytes(32).toString('hex') });
      let j: Record<string, any> = {};
      try {
        j = JSON.parse(raw);
      } catch {
        /* not JSON */
      }
      const token = (tier: string): string =>
        `${b64url({ alg: 'EdDSA' })}.${b64url({ tier, exp: Math.floor(Date.now() / 1000) + b.ttlS, jti: randomBytes(6).toString('hex') })}.${randomBytes(16).toString('base64url')}`;
      if (req.method === 'POST' && url === '/api/onboard') {
        const tier = String(j.tier);
        b.onboards.push(tier);
        if (tier === 'FREE') {
          const paid = 'paidOverride' in b ? b.paidOverride : b.sub ? { tier: b.sub.tier, paymentMethod: b.sub.method } : undefined;
          const extra = paid === undefined ? {} : { paid };
          if (b.freeEntitled) return send(201, { jwt: token('FREE'), expiresAt: 0, agentIdHash: 'x', ...extra });
          return send(401, { error: 'verification_failed', reason: 'no_free_entitlement', ...extra });
        }
        if (b.failPaid !== undefined) return send(b.failPaid, { error: 'busy' });
        // A paid answer never carries `paid`; this one does, to show the client ignores it there.
        if (!b.refusePaid && b.sub?.tier === tier) return send(201, { jwt: token(tier), paid: { tier: 'ENTERPRISE', paymentMethod: 'stripe' } });
        return send(401, { error: 'verification_failed', reason: 'no_active_subscription' });
      }
      if (req.method === 'POST' && url === '/mcp') {
        const auth = String(req.headers.authorization ?? '');
        let tier = '?';
        try {
          tier = JSON.parse(Buffer.from(auth.slice(7).split('.')[1] ?? '', 'base64url').toString()).tier;
        } catch {
          /* not ours */
        }
        if (b.refuseNextCall) {
          b.refuseNextCall = false;
          return send(401, { error: 'invalid_token' });
        }
        b.used.push(tier);
        return send(200, { agentIdHashHex: 'x', tier, activeShardCount: 0, activeSharingContracts: 0, bfsi: 0.5, snapshotEpoch: '1', custody: 'SAIHM' });
      }
      return send(404, { error: 'not_found' });
    });
  });
  await new Promise<void>((r) => b.server.listen(0, '127.0.0.1', () => r()));
  b.base = `http://127.0.0.1:${(b.server.address() as AddressInfo).port}`;
  return b;
}

const ENV_KEYS = ['SAIHM_ENDPOINT_URL', 'SAIHM_HOME', 'HOME', 'SAIHM_MASTER_SECRET_HEX', 'SAIHM_MASTER_SECRET_FILE', 'SAIHM_TIER', 'SAIHM_PAYMENT_METHOD', 'SAIHM_SELF_JOIN', 'SAIHM_EPHEMERAL_HOME', 'SAIHM_IDENTITY', 'SAIHM_IDENTITY_PASSPHRASE', 'SAIHM_AUTH_HEADER', 'SAIHM_STATE_DIR'] as const;

/** Run `fn` with a fresh home and these SAIHM_* settings, then restore the environment and close the bridge. */
async function withEnv(b: Bridge, env: Record<string, string>, fn: (home: string) => Promise<void>): Promise<void> {
  const saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  const home = mkdtempSync(join(tmpdir(), 'saihm-plan-'));
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, { HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: b.base + '/mcp', SAIHM_EPHEMERAL_HOME: '0', ...env });
  try {
    await fn(home);
  } finally {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    rmSync(home, { recursive: true, force: true });
    await new Promise<void>((r) => b.server.close(() => r()));
  }
}

const planPath = (home: string, c: SaihmProClient): string => join(home, `plan.${c.agentIdHash.slice(0, 16)}.json`);
const savedPlan = (home: string, c: SaihmProClient): unknown => JSON.parse(readFileSync(planPath(home, c), 'utf8'));
const quietly = async <T>(fn: () => Promise<T>): Promise<T> => {
  const write = process.stderr.write.bind(process.stderr);
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    return await fn();
  } finally {
    process.stderr.write = write;
  }
};

test('a FREE success that names a paid plan switches at once: one more onboard, the plan saved 0600, the call on it', async () => {
  const b = await bridge({ sub: { tier: 'PRO', method: 'stripe' } });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('a1') }, async (home) => {
    const c = SaihmProClient.bootFromEnv();
    assert.deepEqual(c.plan, { tier: 'FREE', source: 'default', note: undefined });
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO'], 'one FREE onboard, then one paid');
    assert.deepEqual(b.used, ['PRO'], 'the call went out on the paid plan');
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'server', note: undefined });
    const doc = savedPlan(home, c) as Record<string, unknown>;
    assert.deepEqual(Object.keys(doc).sort(), ['agentIdHash', 'kind', 'paymentMethod', 'savedAt', 'source', 'tier', 'version']);
    assert.equal(doc.tier, 'PRO');
    assert.equal(doc.paymentMethod, 'stripe');
    assert.equal(doc.source, 'server');
    assert.equal(doc.agentIdHash, c.agentIdHash);
    if (POSIX) assert.equal(statSync(planPath(home, c)).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(home).filter((f) => f.endsWith('.tmp')), [], 'no temporary file left behind');
    await c.status();
    assert.deepEqual(b.onboards, ['FREE', 'PRO'], 'no further onboard while the token is good');
  });
});

test('a FREE refusal (no free plan) that names a paid plan switches too', async () => {
  const b = await bridge({ sub: { tier: 'PRO_FAST', method: 'paystack' }, freeEntitled: false });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('a2') }, async () => {
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO_FAST']);
    assert.deepEqual(b.used, ['PRO_FAST']);
    assert.equal(c.plan?.tier, 'PRO_FAST');
  });
});

test('SAIHM_TIER=FREE set explicitly switches; a paid SAIHM_TIER, or an identity carrying a paid plan, never does', async () => {
  const free = await bridge({ sub: { tier: 'PRO', method: 'stripe' } });
  await withEnv(free, { SAIHM_MASTER_SECRET_HEX: HEX('a3'), SAIHM_TIER: 'FREE' }, async () => {
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(free.onboards, ['FREE', 'PRO']);
    assert.equal(c.plan?.source, 'server');
  });
  const paid = await bridge({ sub: { tier: 'PRO', method: 'stripe' } });
  await withEnv(paid, { SAIHM_MASTER_SECRET_HEX: HEX('a4'), SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' }, async (home) => {
    const c = SaihmProClient.bootFromEnv();
    await c.status();
    assert.deepEqual(paid.onboards, ['PRO'], 'no FREE onboard');
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'settings', note: undefined }, 'and the paid answer\'s own `paid` is not read');
    assert.equal(existsSync(planPath(home, c)), false);
  });
  const token = await bridge({ sub: { tier: 'PRO', method: 'stripe' } });
  await withEnv(token, {}, async (home) => {
    const c = new SaihmProClient(token.base + '/mcp', undefined, new Uint8Array(32).fill(7), {
      tier: 'PRO',
      paymentMethod: 'stripe',
      tierSource: 'identity',
      detectPlan: true,
      persistPlan: true,
    });
    await c.status();
    assert.deepEqual(token.onboards, ['PRO']);
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'identity', note: undefined });
    assert.equal(existsSync(planPath(home, c)), false);
  });
});

test('a `paid` that is not a plan and a rail from the closed sets is ignored', async () => {
  for (const paidOverride of [
    { tier: 'GOLD', paymentMethod: 'stripe' },
    { tier: 'PRO', paymentMethod: 'stablecoin' },
    { tier: 'pro', paymentMethod: 'stripe' },
    { tier: 'FREE', paymentMethod: 'stripe' },
    { tier: 'PRO' },
    'PRO',
    null,
    ['PRO', 'stripe'],
  ]) {
    const b = await bridge({ paidOverride });
    await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('a5') }, async (home) => {
      const c = SaihmProClient.bootFromEnv();
      await c.status();
      assert.deepEqual(b.onboards, ['FREE'], JSON.stringify(paidOverride));
      assert.equal(c.plan?.tier, 'FREE');
      assert.equal(existsSync(planPath(home, c)), false);
    });
  }
  assert.deepEqual(paidPlanOf({ tier: 'ENTERPRISE_FAST', paymentMethod: 'paypal', extra: 1 }), { tier: 'ENTERPRISE_FAST', paymentMethod: 'paypal' });
});

test('the paid re-onboard refused (no active subscription): back to FREE on the token it had, plan removed, not retried during the hold', async () => {
  const b = await bridge({ sub: { tier: 'PRO', method: 'stripe' }, refusePaid: true });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('a6') }, async (home) => {
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO']);
    assert.deepEqual(b.used, ['FREE'], 'the call went out on the FREE sign-in it already held');
    assert.equal(c.plan?.tier, 'FREE');
    assert.equal(c.plan?.note, 'SAIHM reports the PRO plan on this key, but signing in on it was refused, so this client stays on the free plan for now and checks again within the hour.');
    assert.equal(existsSync(planPath(home, c)), false, 'the saved plan is removed');
    b.refuseNextCall = true; // the token is refused, so this signs in again: FREE only, the refused plan not taken again
    await c.status();
    assert.deepEqual(b.onboards, ['FREE', 'PRO', 'FREE']);
    assert.deepEqual(b.used, ['FREE', 'FREE']);
  });
});

test('the paid re-onboard fails otherwise: FREE for now, plan kept, and the next sign-in tries once more', async () => {
  const b = await bridge({ sub: { tier: 'PRO', method: 'stripe' }, failPaid: 503 });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('a7') }, async (home) => {
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO'], 'one extra onboard for the switch, no more');
    assert.deepEqual(b.used, ['FREE']);
    assert.equal(c.plan?.tier, 'FREE');
    assert.match(c.plan?.note ?? '', /could not switch to it just now\. It tries again within the hour\./);
    assert.equal((savedPlan(home, c) as { tier: string }).tier, 'PRO', 'the saved plan is kept');
    delete b.failPaid;
    b.refuseNextCall = true; // the next sign-in, as at the hourly refresh
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO', 'FREE', 'PRO'], 'the next sign-in switches');
    assert.deepEqual(b.used, ['FREE', 'PRO']);
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'server', note: undefined });
  });
  // With no FREE sign-in to keep (the free plan was refused), the plan stays: the next sign-in is one onboard, not two.
  const r = await bridge({ sub: { tier: 'PRO', method: 'stripe' }, freeEntitled: false, failPaid: 503 });
  await withEnv(r, { SAIHM_MASTER_SECRET_HEX: HEX('a8') }, async () => {
    const c = SaihmProClient.bootFromEnv();
    await assert.rejects(() => quietly(() => c.status()), (e: unknown) => e instanceof SaihmEndpointError && e.status === 503);
    assert.deepEqual(r.onboards, ['FREE', 'PRO']);
    delete r.failPaid;
    await c.status();
    assert.deepEqual(r.onboards, ['FREE', 'PRO', 'PRO']);
  });
});

test('boot precedence: a paid SAIHM_TIER, then the saved plan, then FREE; savedPlan: false starts FREE', async () => {
  const seed = (home: string, hex: string): void => {
    const id = new SaihmProClient('https://saihm.net/mcp', undefined, Buffer.from(hex, 'hex'), { tier: 'FREE' }).agentIdHash;
    assert.equal(new PlanFile(join(home, `plan.${id.slice(0, 16)}.json`), id).keep({ tier: 'PRO', paymentMethod: 'stripe' }), true);
  };
  const saved = await bridge({ sub: { tier: 'PRO', method: 'stripe' } });
  await withEnv(saved, { SAIHM_MASTER_SECRET_HEX: HEX('b1') }, async (home) => {
    seed(home, HEX('b1'));
    const c = SaihmProClient.bootFromEnv();
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'server', note: undefined });
    await c.status();
    assert.deepEqual(saved.onboards, ['PRO'], 'one sign-in, on the saved plan');
  });
  const explicit = await bridge({ sub: { tier: 'PRO_FAST', method: 'stripe' } });
  await withEnv(explicit, { SAIHM_MASTER_SECRET_HEX: HEX('b2'), SAIHM_TIER: 'PRO_FAST', SAIHM_PAYMENT_METHOD: 'stripe' }, async (home) => {
    seed(home, HEX('b2'));
    const c = SaihmProClient.bootFromEnv();
    assert.deepEqual(c.plan, { tier: 'PRO_FAST', source: 'settings', note: undefined });
  });
  const freeDoor = await bridge();
  await withEnv(freeDoor, { SAIHM_MASTER_SECRET_HEX: HEX('b3') }, async (home) => {
    seed(home, HEX('b3'));
    assert.deepEqual(SaihmProClient.bootFromEnv({ savedPlan: false }).plan, { tier: 'FREE', source: 'default', note: undefined });
  });
});

test('the plan file is used only when it is exactly what this package writes, for this agent ID, private to this user', () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-planfile-'));
  try {
    const p = join(dir, 'plan.x.json');
    const f = new PlanFile(p, 'a'.repeat(64));
    assert.equal(f.read(), undefined);
    assert.equal(f.keep({ tier: 'NOPE', paymentMethod: 'stripe' }), false, 'never writes a plan outside the closed set');
    assert.equal(f.keep({ tier: 'ENTERPRISE', paymentMethod: 'paypal' }), true);
    assert.deepEqual(f.read(), { tier: 'ENTERPRISE', paymentMethod: 'paypal' });
    if (POSIX) assert.equal(statSync(p).mode & 0o777, 0o600);
    assert.equal(new PlanFile(p, 'b'.repeat(64)).read(), undefined, 'another agent ID');
    const doc = JSON.parse(readFileSync(p, 'utf8'));
    const write = (d: unknown, mode = 0o600): void => {
      rmSync(p, { force: true });
      writeFileSync(p, JSON.stringify(d), { mode });
      chmodSync(p, mode);
    };
    write({ ...doc, extra: 1 });
    assert.equal(f.read(), undefined, 'an extra field');
    write({ ...doc, source: 'settings' });
    assert.equal(f.read(), undefined, 'not saved from the server');
    write({ ...doc, tier: 'GOLD' });
    assert.equal(f.read(), undefined, 'a plan outside the closed set');
    if (POSIX) {
      write(doc, 0o644);
      assert.equal(f.read(), undefined, 'readable by others');
    }
    write(doc);
    assert.deepEqual(f.read(), { tier: 'ENTERPRISE', paymentMethod: 'paypal' });
    assert.equal(new PlanFile(p, 'b'.repeat(64)).discard(), false, "another agent ID's discard leaves it");
    assert.equal(f.discard(), true);
    assert.equal(existsSync(p), false);
    assert.deepEqual(readdirSync(dir).filter((n) => n.endsWith('.tmp')), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a saved plan that lapsed goes back to FREE once; a plan changed in the billing portal is followed', async () => {
  const seed = (home: string, c: SaihmProClient): void => void new PlanFile(planPath(home, c), c.agentIdHash).keep({ tier: 'PRO', paymentMethod: 'stripe' });
  const lapsed = await bridge({ sub: null });
  await withEnv(lapsed, { SAIHM_MASTER_SECRET_HEX: HEX('c1') }, async (home) => {
    seed(home, SaihmProClient.bootFromEnv());
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(lapsed.onboards, ['PRO', 'FREE'], 'the refused plan, then FREE once');
    assert.deepEqual(lapsed.used, ['FREE']);
    assert.equal(c.plan?.tier, 'FREE');
    assert.equal(c.plan?.note, "SAIHM found no active subscription for this key's PRO plan at sign-in, so this client now signs in on the free plan. Once a plan is active, this client switches to it within the hour. To renew, email ops@saihm.net.");
    assert.equal(existsSync(planPath(home, c)), false);
  });
  const changed = await bridge({ sub: { tier: 'PRO_FAST', method: 'stripe' } });
  await withEnv(changed, { SAIHM_MASTER_SECRET_HEX: HEX('c2') }, async (home) => {
    seed(home, SaihmProClient.bootFromEnv());
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(changed.onboards, ['PRO', 'FREE', 'PRO_FAST'], 'one FREE probe and one paid onboard per refusal');
    assert.deepEqual(c.plan, { tier: 'PRO_FAST', source: 'server', note: undefined });
    assert.equal((savedPlan(home, c) as { tier: string }).tier, 'PRO_FAST');
  });
  // A FREE answer that names the plan just refused is not switched back to within the hour.
  const loop = await bridge({ sub: { tier: 'PRO', method: 'stripe' }, refusePaid: true });
  await withEnv(loop, { SAIHM_MASTER_SECRET_HEX: HEX('c3') }, async (home) => {
    seed(home, SaihmProClient.bootFromEnv());
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(loop.onboards, ['PRO', 'FREE']);
    assert.equal(c.plan?.tier, 'FREE');
  });
  // With no free plan to fall back to, the error says it is the lapse, not a free join waiting for approval.
  const none = await bridge({ sub: null, freeEntitled: false });
  await withEnv(none, { SAIHM_MASTER_SECRET_HEX: HEX('c4') }, async (home) => {
    seed(home, SaihmProClient.bootFromEnv());
    const c = SaihmProClient.bootFromEnv();
    await assert.rejects(
      () => quietly(() => c.status()),
      (e: unknown) =>
        e instanceof SaihmEndpointError &&
        e.code === 'plan_inactive' &&
        e.message === "SAIHM could not sign in: it found no active subscription for this key's PRO plan, and no free plan. Once a plan is active, this client switches to it within the hour, or at the first sign-in after a restart. To renew, email ops@saihm.net.",
    );
    assert.deepEqual(none.onboards, ['PRO', 'FREE']);
  });
});

test('settings that name a refused plan are kept: one FREE probe an hour names the plan the key has', async () => {
  const b = await bridge({ sub: { tier: 'PRO_FAST', method: 'stripe' } });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('d1'), SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' }, async () => {
    const c = SaihmProClient.bootFromEnv();
    const said = /This key's plan is PRO_FAST, but your settings say PRO\. Remove SAIHM_TIER and SAIHM_PAYMENT_METHOD to let SAIHM pick the plan, or set SAIHM_TIER to PRO_FAST\./;
    await assert.rejects(() => c.status(), (e: unknown) => e instanceof SaihmEndpointError && said.test(e.message));
    assert.deepEqual(b.onboards, ['PRO', 'FREE'], 'the paid onboard, then one FREE probe');
    assert.deepEqual(c.plan?.tier, 'PRO', 'the settings are never overridden');
    assert.match(c.plan?.note ?? '', said);
    assert.deepEqual(b.used, [], 'the probe\'s FREE sign-in is not used');
    await assert.rejects(() => c.status(), (e: unknown) => e instanceof SaihmEndpointError && /no_active_subscription/.test(e.message));
    assert.deepEqual(b.onboards, ['PRO', 'FREE', 'PRO'], 'no second probe within the hour');
  });
  // The key has no other plan: today's message, after one probe.
  const same = await bridge({ sub: null });
  await withEnv(same, { SAIHM_MASTER_SECRET_HEX: HEX('d2'), SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' }, async () => {
    const c = SaihmProClient.bootFromEnv();
    await assert.rejects(() => c.status(), (e: unknown) => e instanceof SaihmEndpointError && /Check that SAIHM_TIER names the plan this identity was bought on/.test(e.message));
    assert.deepEqual(same.onboards, ['PRO', 'FREE']);
  });
});

test('after `upgrade` prints a link, no FREE sign-in is kept on this device, so a restarted session finds the plan at once', async () => {
  const b = await bridge();
  await withEnv(b, {}, async (home) => {
    writeFileSync(join(home, 'free-identity.key'), HEX('e1') + '\n', { mode: 0o600 });
    const first = SaihmProClient.bootFromEnv();
    await first.status();
    assert.deepEqual(b.onboards, ['FREE']);
    const kept = (): boolean => readdirSync(home).some((n) => n.startsWith('session.'));
    assert.ok(kept(), 'the sign-in is kept for the next session (0.14.3)');
    first.markUpgradePending(); // what `upgrade` does after printing the link
    assert.equal(kept(), false, 'the kept FREE sign-in is removed');
    const before = SaihmProClient.bootFromEnv(); // a session that starts before the payment
    await before.status();
    assert.deepEqual(b.onboards, ['FREE', 'FREE']);
    assert.equal(kept(), false, 'a FREE sign-in is not kept while the upgrade waits');
    b.sub = { tier: 'PRO', method: 'stripe' }; // paid
    const next = SaihmProClient.bootFromEnv(); // restarted
    await quietly(() => next.status());
    assert.deepEqual(b.onboards, ['FREE', 'FREE', 'FREE', 'PRO'], 'its first sign-in finds the plan and switches');
    assert.deepEqual(next.plan, { tier: 'PRO', source: 'server', note: undefined });
    assert.ok(kept(), 'the paid sign-in is kept');
    assert.equal(readdirSync(home).some((n) => n.endsWith('.pending')), false, 'the plan is found: nothing pending');
    const later = SaihmProClient.bootFromEnv();
    await later.status();
    assert.deepEqual(b.onboards, ['FREE', 'FREE', 'FREE', 'PRO'], 'the next session starts on the saved plan and the kept sign-in');
  });
});

test('the long plan messages render whole through the error fence and the status line, for the longest plan names', async () => {
  // What a reader is shown: an error through `failText` (each message's budget is MAX_ERROR_MESSAGE_CHARS), a note through
  // the status line's own fence (see saihm_status in src/server.ts). Driven at the longest names a real answer can carry.
  const statusNote = (note: string): string => labelSafe(safeField(note, MAX_JOIN_FIELD_CHARS));
  const whole = (e: SaihmEndpointError, what: string): void => {
    assert.ok(e.message.length <= MAX_ERROR_MESSAGE_CHARS, `${what}: ${e.message.length} chars`);
    assert.equal(failText(e), `SAIHM error [${e.code}] (status ${e.status}): ${e.message}`, `${what}: nothing cut or changed`);
  };
  const mismatch = await bridge({ sub: { tier: 'ENTERPRISE_FAST', method: 'paystack' } });
  await withEnv(mismatch, { SAIHM_MASTER_SECRET_HEX: HEX('f1'), SAIHM_TIER: 'ENTERPRISE', SAIHM_PAYMENT_METHOD: 'stripe' }, async () => {
    const c = SaihmProClient.bootFromEnv();
    let err: unknown;
    await c.status().catch((e: unknown) => (err = e));
    assert.ok(err instanceof SaihmEndpointError, String(err));
    assert.match(err.message, /, or set SAIHM_TIER to ENTERPRISE_FAST\.$/);
    whole(err, 'settings mismatch');
    const note = c.plan?.note ?? '';
    assert.match(note, /^This key's plan is ENTERPRISE_FAST, but your settings say ENTERPRISE\./);
    assert.equal(statusNote(note), note);
  });
  const lapsed = await bridge({ sub: null, freeEntitled: false });
  await withEnv(lapsed, { SAIHM_MASTER_SECRET_HEX: HEX('f2') }, async (home) => {
    const first = SaihmProClient.bootFromEnv();
    new PlanFile(planPath(home, first), first.agentIdHash).keep({ tier: 'ENTERPRISE_FAST', paymentMethod: 'stripe' });
    const c = SaihmProClient.bootFromEnv();
    let err: unknown;
    await quietly(() => c.status()).catch((e: unknown) => (err = e));
    assert.ok(err instanceof SaihmEndpointError && err.code === 'plan_inactive', String(err));
    assert.match(err.message, /To renew, email ops@saihm\.net\.$/);
    whole(err, 'plan_inactive');
    const note = c.plan?.note ?? '';
    assert.match(note, /^SAIHM found no active subscription for this key's ENTERPRISE_FAST plan, and no free plan\./);
    assert.equal(statusNote(note), note);
  });
});

test('a note that the key has another plan is cleared once the plan the settings name signs in again', async () => {
  const b = await bridge({ sub: { tier: 'PRO_FAST', method: 'stripe' } });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('f3'), SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' }, async () => {
    const c = SaihmProClient.bootFromEnv();
    await assert.rejects(() => c.status());
    assert.match(c.plan?.note ?? '', /This key's plan is PRO_FAST, but your settings say PRO\./);
    b.sub = { tier: 'PRO', method: 'stripe' }; // the plan changed back in the billing portal
    await c.status();
    assert.deepEqual(b.onboards, ['PRO', 'FREE', 'PRO']);
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'settings', note: undefined }, 'no out-of-date note');
  });
});
