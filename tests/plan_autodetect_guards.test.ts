// The plan found from the server (0.15.0), its guards and its refusals, from the 0.15.0 round-1 review: the hold on a
// refused plan is by plan AND payment method and shorter than the free sign-in's first refresh; a key with no free plan
// hears `plan_inactive` on every sign-in until one succeeds, never the free join's words; settings with the right plan
// and the wrong payment method are told the method; an identity token's paid plan gets no "leave them unset" hint; the
// upgrade marker is never written through a link planted at its name. From round 2: a hold ends at the free sign-in's
// first refresh even when this clock runs ahead of the server's. From round 3: that hold lasts until that refresh, and
// llms-install's rule for SAIHM_SELF_JOIN=0 holds. With the reviewers' kill tests (K1-K12, KX1-KX4, KR2), each of which
// pins a guard a mutant removed with the suite still green. Every test counts the onboards. A local mock bridge
// only; the clock is moved forward in this process (Date.now), never waited on.
// Runner: npx tsx --test tests/plan_autodetect_guards.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SaihmProClient, SaihmEndpointError } from '../src/client.js';
import { PlanFile } from '../src/plan-file.js';
import { generatePassphrase, sealIdentityToken } from '../src/identity-token.js';
import { deriveIdentity, toHex, fromHex } from '@saihm/client-pro';
import { failText, labelSafe, safeField, MAX_ERROR_MESSAGE_CHARS, MAX_JOIN_FIELD_CHARS } from '../src/render_fence.js';

const POSIX = process.platform !== 'win32';
// The clock, moved forward by the tests that need the hour to pass. Tokens are minted and read on this same clock.
const realNow = Date.now.bind(Date);
let offsetMs = 0;
Date.now = () => realNow() + offsetMs;
const advance = (min: number): void => {
  offsetMs += min * 60_000;
};
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
  /** The reason a refused FREE onboard gives (default no_free_entitlement). */
  freeReason?: string;
  /** The paid check refuses whatever the subscription (an endpoint that names a plan it then refuses). */
  refusePaid: boolean;
  /** The paid check also requires the payment method the subscription is on, as the live store does. */
  railStrict: boolean;
  /** Token lifetime in seconds. */
  ttlS: number;
  /** The next memory call is refused (401), so the client signs in again and retries, as for a revoked token. */
  refuseNextCall: boolean;
  /** Every onboard meets the edge's own sign-in limit: a 429 with no body, only `retry-after`. */
  limited: boolean;
  /** How far the server's clock runs behind this process's, in seconds: it sets each token's expiry. */
  serverBehindS: number;
  /** Tokens are opaque: no expiry to read, so the client assumes a short life on its own clock. */
  opaque: boolean;
}

async function bridge(init: Partial<Bridge> = {}): Promise<Bridge> {
  const b = { onboards: [], used: [], sub: null, freeEntitled: true, refusePaid: false, railStrict: false, ttlS: 3600, refuseNextCall: false, limited: false, serverBehindS: 0, opaque: false, ...init } as unknown as Bridge;
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
        b.opaque
          ? randomBytes(24).toString('base64url')
          : `${b64url({ alg: 'EdDSA' })}.${b64url({ tier, exp: Math.floor(Date.now() / 1000) - b.serverBehindS + b.ttlS, jti: randomBytes(6).toString('hex') })}.${randomBytes(16).toString('base64url')}`;
      if (req.method === 'POST' && url === '/api/onboard') {
        if (b.limited) {
          res.writeHead(429, { 'retry-after': '600' });
          return res.end();
        }
        const tier = String(j.tier);
        b.onboards.push(tier);
        if (tier === 'FREE') {
          const extra = b.sub ? { paid: { tier: b.sub.tier, paymentMethod: b.sub.method } } : {};
          if (b.freeEntitled) return send(201, { jwt: token('FREE'), expiresAt: 0, agentIdHash: 'x', ...extra });
          return send(401, { error: 'verification_failed', reason: b.freeReason ?? 'no_free_entitlement', ...extra });
        }
        if (!b.refusePaid && b.sub?.tier === tier && (!b.railStrict || b.sub.method === j.paymentMethod)) return send(201, { jwt: token(tier) });
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

const ENV_KEYS = ['SAIHM_ENDPOINT_URL', 'SAIHM_HOME', 'HOME', 'SAIHM_MASTER_SECRET_HEX', 'SAIHM_MASTER_SECRET_FILE', 'SAIHM_TIER', 'SAIHM_PAYMENT_METHOD', 'SAIHM_SELF_JOIN', 'SAIHM_EPHEMERAL_HOME', 'SAIHM_IDENTITY', 'SAIHM_IDENTITY_PASSPHRASE', 'SAIHM_AUTH_HEADER', 'SAIHM_STATE_DIR', 'SAIHM_SESSION_CACHE'] as const;

/** Run `fn` with a fresh home, the clock reset, and these SAIHM_* settings; then restore the environment, close the bridge. */
async function withEnv(b: Bridge, env: Record<string, string>, fn: (home: string) => Promise<void>): Promise<void> {
  const saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  const home = mkdtempSync(join(tmpdir(), 'saihm-plan-guard-'));
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, { HOME: home, SAIHM_HOME: home, SAIHM_ENDPOINT_URL: b.base + '/mcp', SAIHM_EPHEMERAL_HOME: '0', ...env });
  offsetMs = 0;
  try {
    await fn(home);
  } finally {
    offsetMs = 0;
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    rmSync(home, { recursive: true, force: true });
    await new Promise<void>((r) => b.server.close(() => r()));
  }
}

const planPath = (home: string, c: SaihmProClient): string => join(home, `plan.${c.agentIdHash.slice(0, 16)}.json`);
const savedPlan = (home: string, c: SaihmProClient): { tier: string; paymentMethod: string } =>
  JSON.parse(readFileSync(planPath(home, c), 'utf8')) as { tier: string; paymentMethod: string };
/** Save `tier` on `paymentMethod` as the plan found from the server, as an earlier session would have. */
const seedPlan = (home: string, tier: string, paymentMethod: string): void => {
  const first = SaihmProClient.bootFromEnv();
  assert.equal(new PlanFile(planPath(home, first), first.agentIdHash).keep({ tier, paymentMethod }), true);
};
/** A default key file in `home`: the identity whose sign-in is kept between sessions (0.14.3). */
const defaultKey = (home: string, hex: string): void => writeFileSync(join(home, 'free-identity.key'), hex + '\n', { mode: 0o600 });
const sessionKept = (home: string): boolean => readdirSync(home).some((n) => n.startsWith('session.'));
const quietly = async <T>(fn: () => Promise<T>): Promise<T> => {
  const write = process.stderr.write.bind(process.stderr);
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    return await fn();
  } finally {
    process.stderr.write = write;
  }
};
/** The error `fn` rejects with (a test failure when it resolves). */
const refusal = async (fn: () => Promise<unknown>): Promise<SaihmEndpointError> => {
  try {
    await quietly(fn);
  } catch (e) {
    assert.ok(e instanceof SaihmEndpointError, String(e));
    return e;
  }
  assert.fail('expected a refusal');
};

const lapseNote = (plan: string): string =>
  `SAIHM found no active subscription for this key's ${plan} plan at sign-in, so this client now signs in on the free plan. Once a plan is active, this client switches to it within the hour. To renew, email ops@saihm.net.`;
const inactiveSaid = (plan: string): string =>
  `found no active subscription for this key's ${plan} plan, and no free plan. Once a plan is active, this client switches to it within the hour, or at the first sign-in after a restart. To renew, email ops@saihm.net.`;
const FREE_JOIN_WORDS = /free join may still be waiting/;

// ---- F1: the hold is by plan and payment method, and shorter than the free sign-in's first refresh ----

test('F1 the same plan moved to another payment provider is taken at once: one refused onboard, one FREE, one paid', async () => {
  const b = await bridge({ sub: { tier: 'PRO', method: 'paystack' }, railStrict: true });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('91') }, async (home) => {
    seedPlan(home, 'PRO', 'stripe');
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['PRO', 'FREE', 'PRO'], 'the saved rail refused, FREE names the new rail, which signs in');
    assert.deepEqual(b.used, ['PRO']);
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'server', note: undefined });
    const saved = savedPlan(home, c);
    assert.equal(saved.tier, 'PRO');
    assert.equal(saved.paymentMethod, 'paystack', 'saved on the payment method that signed in');
  });
  // With no free plan to fall back to, the same: not locked out for the hold.
  const n = await bridge({ sub: { tier: 'PRO', method: 'paystack' }, railStrict: true, freeEntitled: false });
  await withEnv(n, { SAIHM_MASTER_SECRET_HEX: HEX('92') }, async (home) => {
    seedPlan(home, 'PRO', 'stripe');
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(n.onboards, ['PRO', 'FREE', 'PRO']);
    assert.deepEqual(n.used, ['PRO']);
  });
});

test('F1 a renewal gap: the plan refused once is taken back at the free sign-in\'s first refresh, not one refresh later', async () => {
  const b = await bridge({ sub: null });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('93') }, async (home) => {
    seedPlan(home, 'PRO', 'stripe');
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['PRO', 'FREE']);
    assert.deepEqual(c.plan, { tier: 'FREE', source: 'default', note: lapseNote('PRO') });
    b.sub = { tier: 'PRO', method: 'stripe' }; // the store catches up: the plan is active again
    advance(59.5); // past the FREE token's refresh (an hour, less a minute), which the hold must not outlast
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['PRO', 'FREE', 'FREE', 'PRO'], 'the refresh finds the plan and switches back');
    assert.deepEqual(b.used, ['FREE', 'PRO']);
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'server', note: undefined });
  });
});

test('F1 the loop guard still holds: a FREE answer naming the plan just refused, on the same method, waits out the hold', async () => {
  const b = await bridge({ sub: { tier: 'PRO', method: 'stripe' }, refusePaid: true });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('94') }, async (home) => {
    seedPlan(home, 'PRO', 'stripe');
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['PRO', 'FREE'], 'the FREE answer names PRO/stripe again: not taken');
    advance(49);
    b.refuseNextCall = true; // a fresh sign-in inside the hold
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['PRO', 'FREE', 'FREE'], 'still held at 49 minutes: no paid onboard');
    b.refusePaid = false;
    advance(2);
    b.refuseNextCall = true; // a fresh sign-in past the hold
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['PRO', 'FREE', 'FREE', 'FREE', 'PRO'], 'taken once the hold is over');
    assert.equal(c.plan?.tier, 'PRO');
  });
});

// ---- F1/F2/F5/F6: a key with no free plan ----

test('F2 no free plan: every sign-in until one succeeds is `plan_inactive`, a restart takes the plan back at once', async () => {
  const b = await bridge({ sub: null, freeEntitled: false });
  await withEnv(b, {}, async (home) => {
    defaultKey(home, HEX('95')); // the kept sign-in is on: none can be kept for a key with no free plan
    seedPlan(home, 'PRO', 'stripe');
    const c = SaihmProClient.bootFromEnv();
    const first = await refusal(() => c.status());
    assert.equal(first.code, 'plan_inactive');
    assert.equal(first.message, `SAIHM could not sign in: it ${inactiveSaid('PRO')}`);
    assert.deepEqual(c.plan, { tier: 'FREE', source: 'default', note: `SAIHM ${inactiveSaid('PRO')}` });
    assert.deepEqual(b.onboards, ['PRO', 'FREE']);
    b.sub = { tier: 'PRO', method: 'stripe' }; // renewed
    advance(1);
    const later = await refusal(() => c.status());
    assert.equal(later.code, 'plan_inactive', 'not the free join\'s refusal');
    assert.equal(later.message, first.message);
    assert.doesNotMatch(later.message, FREE_JOIN_WORDS);
    assert.deepEqual(b.onboards, ['PRO', 'FREE', 'FREE'], 'one FREE onboard per call during the hold, no paid one');
    assert.equal(sessionKept(home), false);
    const restarted = SaihmProClient.bootFromEnv();
    await quietly(() => restarted.status());
    assert.deepEqual(b.onboards, ['PRO', 'FREE', 'FREE', 'FREE', 'PRO'], 'a restart signs in afresh and switches');
    assert.deepEqual(restarted.plan, { tier: 'PRO', source: 'server', note: undefined });
    advance(50); // the first client, past the hold
    await quietly(() => c.status());
    assert.deepEqual(b.onboards.slice(5), ['FREE', 'PRO'], 'the first client switches by itself after the hold');
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'server', note: undefined });
  });
});

test('F5 a named plan refused on a key with no free plan: `plan_inactive`, not "stays on the free plan" or the free join\'s words', async () => {
  const b = await bridge({ sub: { tier: 'PRO', method: 'stripe' }, freeEntitled: false, refusePaid: true });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('96') }, async () => {
    const c = SaihmProClient.bootFromEnv();
    const e = await refusal(() => c.status());
    assert.equal(e.code, 'plan_inactive');
    assert.equal(e.message, `SAIHM could not sign in: it ${inactiveSaid('PRO')}`);
    assert.doesNotMatch(c.plan?.note ?? '', /stays on the free plan/);
    assert.deepEqual(b.onboards, ['FREE', 'PRO']);
    const again = await refusal(() => c.status());
    assert.equal(again.code, 'plan_inactive');
    assert.deepEqual(b.onboards, ['FREE', 'PRO', 'FREE'], 'held: no second paid onboard');
  });
  // With a FREE sign-in held, the note says the client stays on it, and when it looks again.
  const f = await bridge({ sub: { tier: 'ENTERPRISE', method: 'stripe' }, refusePaid: true });
  await withEnv(f, { SAIHM_MASTER_SECRET_HEX: HEX('97') }, async () => {
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.equal(c.plan?.note, 'SAIHM reports the ENTERPRISE plan on this key, but signing in on it was refused, so this client stays on the free plan for now and checks again within the hour.');
  });
});

test('F2 a free plan granted after `plan_inactive`: the next sign-in is FREE, and the note says so', async () => {
  const b = await bridge({ sub: null, freeEntitled: false });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('98') }, async (home) => {
    seedPlan(home, 'PRO_FAST', 'paystack');
    const c = SaihmProClient.bootFromEnv();
    assert.equal((await refusal(() => c.status())).code, 'plan_inactive');
    b.freeEntitled = true; // a free join approved since
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['PRO_FAST', 'FREE', 'FREE']);
    assert.deepEqual(c.plan, { tier: 'FREE', source: 'default', note: lapseNote('PRO_FAST') });
  });
});

// ---- F3: the right plan on the wrong payment method ----

test('F3 (K1 adapted) settings name the plan the key has on another payment method: the method is named, not the plan', async () => {
  const b = await bridge({ sub: { tier: 'PRO', method: 'paystack' }, railStrict: true });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('b7'), SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' }, async () => {
    const c = SaihmProClient.bootFromEnv();
    const said = "This key's PRO plan is paid through paystack: set SAIHM_PAYMENT_METHOD to paystack, or remove SAIHM_TIER and SAIHM_PAYMENT_METHOD to let SAIHM pick the plan.";
    const e = await refusal(() => c.status());
    assert.equal(e.message, `SAIHM could not sign in (verification_failed: no_active_subscription). ${said}`);
    assert.doesNotMatch(e.message, /your settings say|Check that SAIHM_TIER/);
    assert.deepEqual(b.onboards, ['PRO', 'FREE']);
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'settings', note: said }, 'the settings are kept');
  });
  // The probe names exactly the plan and method the settings name (a renewal gap, say): the refusal as it came.
  const same = await bridge({ sub: { tier: 'PRO', method: 'stripe' }, refusePaid: true });
  await withEnv(same, { SAIHM_MASTER_SECRET_HEX: HEX('b8'), SAIHM_TIER: 'PRO', SAIHM_PAYMENT_METHOD: 'stripe' }, async () => {
    const c = SaihmProClient.bootFromEnv();
    const e = await refusal(() => c.status());
    assert.match(e.message, /\(verification_failed: no_active_subscription\) Check that SAIHM_TIER names the plan this identity was bought on/);
    assert.doesNotMatch(e.message, /your settings say|paid through/);
    assert.deepEqual(same.onboards, ['PRO', 'FREE']);
    assert.equal(c.plan?.note, undefined);
  });
});

// ---- F4: an identity token's paid plan ----

test('F4 an identity token carrying a paid plan, refused: the hint never says to leave settings unset (they are)', async () => {
  const b = await bridge({ sub: { tier: 'PRO_FAST', method: 'stripe' } });
  await withEnv(b, {}, async () => {
    const c = new SaihmProClient(b.base + '/mcp', undefined, new Uint8Array(32).fill(4), { tier: 'PRO', paymentMethod: 'stripe', tierSource: 'identity', detectPlan: true, persistPlan: true });
    const e = await refusal(() => c.status());
    assert.match(e.message, /\(verification_failed: no_active_subscription\) Check that SAIHM_TIER names the plan this identity was bought on\.$/);
    assert.deepEqual(b.onboards, ['PRO']);
  });
  // A token carrying FREE follows the plan: its refusals read as a following client's.
  const free = await bridge({ freeEntitled: false });
  await withEnv(free, {}, async () => {
    const c = new SaihmProClient(free.base + '/mcp', undefined, new Uint8Array(32).fill(5), { tier: 'FREE', tierSource: 'identity', detectPlan: true, persistPlan: true });
    const e = await refusal(() => c.status());
    assert.match(e.message, /Stablecoin plan\? Set SAIHM_TIER and SAIHM_PAYMENT_METHOD\.$/);
  });
});

// ---- the new messages, whole at the longest names ----

test('the new plan messages render whole through the error fence and the status line, for the longest names', async () => {
  const statusNote = (note: string): string => labelSafe(safeField(note, MAX_JOIN_FIELD_CHARS));
  const whole = (e: SaihmEndpointError, what: string): void => {
    assert.ok(e.message.length <= MAX_ERROR_MESSAGE_CHARS, `${what}: ${e.message.length} chars`);
    assert.equal(failText(e), `SAIHM error [${e.code}] (status ${e.status}): ${e.message}`, `${what}: nothing cut or changed`);
  };
  const method = await bridge({ sub: { tier: 'ENTERPRISE_FAST', method: 'paystack' }, railStrict: true });
  await withEnv(method, { SAIHM_MASTER_SECRET_HEX: HEX('c1'), SAIHM_TIER: 'ENTERPRISE_FAST', SAIHM_PAYMENT_METHOD: 'stripe' }, async () => {
    const c = SaihmProClient.bootFromEnv();
    const e = await refusal(() => c.status());
    assert.match(e.message, /set SAIHM_PAYMENT_METHOD to paystack, or remove SAIHM_TIER and SAIHM_PAYMENT_METHOD to let SAIHM pick the plan\.$/);
    whole(e, 'payment method mismatch');
    assert.equal(statusNote(c.plan?.note ?? ''), c.plan?.note);
  });
  const lapsed = await bridge({ sub: null });
  await withEnv(lapsed, { SAIHM_MASTER_SECRET_HEX: HEX('c2') }, async (home) => {
    seedPlan(home, 'ENTERPRISE_FAST', 'paystack');
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.equal(c.plan?.note, lapseNote('ENTERPRISE_FAST'));
    assert.equal(statusNote(lapseNote('ENTERPRISE_FAST')), lapseNote('ENTERPRISE_FAST'));
  });
  const refused = await bridge({ sub: { tier: 'ENTERPRISE_FAST', method: 'paypal' }, refusePaid: true });
  await withEnv(refused, { SAIHM_MASTER_SECRET_HEX: HEX('c3') }, async () => {
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    const note = c.plan?.note ?? '';
    assert.match(note, /^SAIHM reports the ENTERPRISE_FAST plan on this key/);
    assert.equal(statusNote(note), note);
  });
});

// ---- F8: the upgrade marker ----

test('F8 the upgrade marker replaces a link planted at its name: the key file it pointed at survives, and so does the identity', { skip: !POSIX }, async () => {
  const b = await bridge();
  await withEnv(b, {}, async (home) => {
    const key = join(home, 'free-identity.key');
    defaultKey(home, HEX('ad'));
    const before = readFileSync(key);
    const c = SaihmProClient.bootFromEnv();
    const marker = join(home, `upgrade.${c.agentIdHash.slice(0, 16)}.pending`);
    symlinkSync(key, marker); // planted by another user of the group, before `upgrade` runs
    c.markUpgradePending();
    assert.deepEqual(readFileSync(key), before, 'the key file is unchanged');
    const st = lstatSync(marker);
    assert.ok(st.isFile() && !st.isSymbolicLink(), 'the marker is a file of its own now');
    assert.equal(st.mode & 0o777, 0o600);
    assert.equal(st.size, 0);
    assert.deepEqual(readdirSync(home).filter((n) => n.endsWith('.tmp')), [], 'no temporary file left behind');
    const next = SaihmProClient.bootFromEnv();
    assert.equal(next.agentIdHash, c.agentIdHash, 'the identity still loads');
    await next.status();
    assert.equal(sessionKept(home), false, 'and the marker it wrote is honored');
  });
});

test('F8 a link at the marker name is not a marker: it never holds a FREE sign-in back', { skip: !POSIX }, async () => {
  const b = await bridge();
  await withEnv(b, {}, async (home) => {
    defaultKey(home, HEX('ae'));
    const c = SaihmProClient.bootFromEnv();
    const target = join(home, 'elsewhere');
    writeFileSync(target, '', { mode: 0o600 });
    symlinkSync(target, join(home, `upgrade.${c.agentIdHash.slice(0, 16)}.pending`));
    await c.status();
    assert.ok(sessionKept(home), 'the FREE sign-in is kept');
  });
});

// ---- the round-1 reviewer's kill tests (PRO-0150-R1-CODE-A), ported ----

test('K2 an identity token whose paid plan is refused: one onboard, plan kept as the token gives it, nothing saved', async () => {
  const b = await bridge({ sub: null });
  await withEnv(b, {}, async (home) => {
    const c = new SaihmProClient(b.base + '/mcp', undefined, new Uint8Array(32).fill(9), {
      tier: 'PRO', paymentMethod: 'stripe', tierSource: 'identity', detectPlan: true, persistPlan: true,
    });
    const e = await refusal(() => c.status());
    assert.ok(e.code === 'verification_failed' && /no_active_subscription/.test(e.message), e.message);
    assert.deepEqual(b.onboards, ['PRO'], 'no FREE onboard, no lapse');
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'identity', note: undefined });
    assert.equal(existsSync(planPath(home, c)), false);
  });
});

test('K3 an upgrade pending on this device does not stop a PAID sign-in from being kept', async () => {
  const b = await bridge({ sub: { tier: 'PRO', method: 'stripe' } });
  await withEnv(b, {}, async (home) => {
    defaultKey(home, HEX('c7'));
    const first = SaihmProClient.bootFromEnv();
    new PlanFile(planPath(home, first), first.agentIdHash).keep({ tier: 'PRO', paymentMethod: 'stripe' });
    writeFileSync(join(home, `upgrade.${first.agentIdHash.slice(0, 16)}.pending`), '', { mode: 0o600 });
    const c = SaihmProClient.bootFromEnv();
    await c.status();
    assert.deepEqual(b.onboards, ['PRO']);
    assert.ok(sessionKept(home), 'the paid sign-in is kept');
    const next = SaihmProClient.bootFromEnv();
    await next.status();
    assert.deepEqual(b.onboards, ['PRO'], 'the next session reuses it');
  });
});

test('K4 an upgrade marker older than a day no longer stops a FREE sign-in from being kept', async () => {
  const b = await bridge();
  await withEnv(b, {}, async (home) => {
    defaultKey(home, HEX('d7'));
    const first = SaihmProClient.bootFromEnv();
    const marker = join(home, `upgrade.${first.agentIdHash.slice(0, 16)}.pending`);
    writeFileSync(marker, '', { mode: 0o600 });
    const old = (Date.now() - 25 * 3600_000) / 1000;
    utimesSync(marker, old, old);
    await first.status();
    assert.deepEqual(b.onboards, ['FREE']);
    assert.ok(sessionKept(home), 'kept: the marker is stale');
    const fresh = Date.now() / 1000;
    utimesSync(marker, fresh, fresh);
    rmSync(join(home, readdirSync(home).find((n) => n.startsWith('session.'))!));
    const c = SaihmProClient.bootFromEnv();
    await c.status();
    assert.equal(sessionKept(home), false, 'a fresh marker: not kept (positive control)');
  });
});

test('K5 the plan file guards: kind, version, savedAt, one name, size, owner, a link', () => {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-planfile-k5-'));
  try {
    const p = join(dir, 'plan.x.json');
    const f = new PlanFile(p, 'a'.repeat(64));
    assert.equal(f.keep({ tier: 'PRO', paymentMethod: 'stripe' }), true);
    const doc = JSON.parse(readFileSync(p, 'utf8'));
    const write = (text: string): void => {
      rmSync(p, { force: true });
      writeFileSync(p, text, { mode: 0o600 });
      chmodSync(p, 0o600);
    };
    write(JSON.stringify(doc));
    assert.deepEqual(f.read(), { tier: 'PRO', paymentMethod: 'stripe' }, 'positive control');
    write(JSON.stringify({ ...doc, kind: 'saihm-session' }));
    assert.equal(f.read(), undefined, 'kind');
    write(JSON.stringify({ ...doc, version: 2 }));
    assert.equal(f.read(), undefined, 'version');
    write(JSON.stringify({ ...doc, savedAt: 'not a date' }));
    assert.equal(f.read(), undefined, 'savedAt');
    write(JSON.stringify(doc) + ' '.repeat(5000));
    assert.equal(f.read(), undefined, 'size');
    write(JSON.stringify(doc));
    if (POSIX) {
      const alias = join(dir, 'alias.json');
      linkSync(p, alias);
      assert.equal(f.read(), undefined, 'a second name');
      rmSync(alias);
      assert.deepEqual(f.read(), { tier: 'PRO', paymentMethod: 'stripe' });
      assert.equal(new PlanFile(p, 'a'.repeat(64), (process.getuid?.() ?? 0) + 1).read(), undefined, "another user's file");
      const target = join(dir, 'target.json');
      writeFileSync(target, JSON.stringify(doc), { mode: 0o600 });
      rmSync(p);
      symlinkSync(target, p);
      assert.equal(f.read(), undefined, 'a link');
      rmSync(p);
    }
    write(JSON.stringify({ ...doc, kind: 'saihm-session' }));
    assert.equal(f.discard(), false, 'discard leaves a file of another kind');
    assert.equal(existsSync(p), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('K7 a FREE refusal for another reason that carries a plan is not followed', async () => {
  const b = await bridge({ sub: { tier: 'PRO', method: 'stripe' }, freeEntitled: false, freeReason: 'bad_signature' });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('e7') }, async () => {
    const c = SaihmProClient.bootFromEnv();
    const e = await refusal(() => c.status());
    assert.match(e.message, /bad_signature/);
    assert.deepEqual(b.onboards, ['FREE']);
    assert.equal(c.plan?.tier, 'FREE');
  });
});

test('K11 a directly constructed client (no plan following) refused on a paid plan: one onboard, no probe, the old hint', async () => {
  const b = await bridge({ sub: { tier: 'PRO_FAST', method: 'stripe' } });
  await withEnv(b, {}, async () => {
    const c = new SaihmProClient(b.base + '/mcp', undefined, new Uint8Array(32).fill(11), { tier: 'PRO', paymentMethod: 'stripe' });
    const e = await refusal(() => c.status());
    assert.match(e.message, /Check that SAIHM_TIER names the plan this identity was bought on\.$/);
    assert.deepEqual(b.onboards, ['PRO'], 'no FREE probe without plan following');
  });
});

test('K12 an identity token carrying a paid plan, booted from the environment: source identity, no probe on refusal', async () => {
  const b = await bridge({ sub: { tier: 'PRO_FAST', method: 'stripe' } });
  const secretHex = HEX('f9');
  const passphrase = generatePassphrase();
  const token = sealIdentityToken({ secretHex, tier: 'PRO', paymentMethod: 'stripe' }, toHex(deriveIdentity(fromHex(secretHex)).agentIdHash), passphrase);
  await withEnv(b, { SAIHM_IDENTITY: token, SAIHM_IDENTITY_PASSPHRASE: passphrase }, async () => {
    const c = SaihmProClient.bootFromEnv();
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'identity', note: undefined });
    const e = await refusal(() => c.status());
    assert.match(e.message, /no_active_subscription/);
    assert.doesNotMatch(e.message, /your settings say|unset so SAIHM finds the plan/);
    assert.deepEqual(b.onboards, ['PRO'], 'an identity plan is never probed or switched');
  });
});

// ---- round 2 (PRO-0150-R2-CODE-A): a clock that runs ahead of the server's, and the reviewer's kill tests KX1-KX4 ----

test("N2 a client clock ahead of the server's: the plan refused once is still taken back at the free sign-in's first refresh", async () => {
  // The token's expiry comes from the server's clock, 10 minutes behind this one, so the FREE sign-in's refresh comes 49
  // minutes after the lapse on this clock: inside a 50-minute hold counted here, which kept PRO away a second hour.
  const b = await bridge({ sub: null, serverBehindS: 600 });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('e1') }, async (home) => {
    seedPlan(home, 'PRO', 'stripe');
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['PRO', 'FREE']);
    b.sub = { tier: 'PRO', method: 'stripe' }; // renewed
    advance(49.5); // past the FREE token's refresh on this clock, before the 50 minutes
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['PRO', 'FREE', 'FREE', 'PRO'], 'the first refresh takes the plan back');
    assert.deepEqual(b.used, ['FREE', 'PRO']);
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'server', note: undefined });
  });
});

test('N2 a refresh time already past ends no hold early: a server naming a plan it then refuses costs no paid onboard per call', async () => {
  // A clock two hours ahead of the server's reads every token as expired on arrival, so every call signs in again.
  const b = await bridge({ sub: { tier: 'PRO', method: 'stripe' }, refusePaid: true, serverBehindS: 7200 });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('e2') }, async () => {
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO']);
    advance(1);
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO', 'FREE'], 'held: one FREE onboard, no second paid one');
  });
});

test('N2 a token with no expiry ends no hold early: its refresh, on this clock, finds the plan still held', async () => {
  // Such a token is refreshed after a short life assumed here; a hold ended there would cost a paid onboard each time.
  const b = await bridge({ sub: { tier: 'PRO', method: 'stripe' }, refusePaid: true, opaque: true });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('e8') }, async () => {
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO']);
    advance(6); // past the assumed life
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO', 'FREE'], 'held: one FREE onboard, no second paid one');
  });
});

// ---- round 3 (PRO-0150-R3-CODE-A, R3-CODE-B): the kill test KR2, and the llms-install rule for SAIHM_SELF_JOIN=0 ----

test("KR2 a clock ahead of the server's: a sign-in inside the hold is FREE only, and the hold ends at the first FREE refresh, not at once", async () => {
  // The token's expiry comes from the server's clock, 10 minutes behind this one, so the first FREE sign-in refreshes 49
  // minutes after the refusal on this clock, and the hold ends there. A fresh sign-in at 5 minutes falls inside it, and
  // the FREE sign-in it makes (refreshed at 54 minutes) does not move the hold's end.
  const b = await bridge({ sub: { tier: 'PRO', method: 'stripe' }, refusePaid: true, serverBehindS: 600 });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('ea') }, async () => {
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO']);
    advance(5);
    b.refuseNextCall = true; // a fresh sign-in inside the hold
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO', 'FREE'], 'held at 5 minutes: no paid onboard');
    advance(43.5);
    b.refuseNextCall = true; // a fresh sign-in at 48.5 minutes: still before the first FREE refresh
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO', 'FREE', 'FREE'], 'held at 48.5 minutes: the hold lasts until the refresh');
    advance(1);
    b.refuseNextCall = true; // a fresh sign-in at 49.5 minutes: past the first FREE refresh, before the 50 minutes
    await quietly(() => c.status());
    assert.deepEqual(b.onboards, ['FREE', 'PRO', 'FREE', 'FREE', 'FREE', 'PRO'], 'the hold ended at the first FREE refresh (49 minutes)');
  });
});

test('llms-install: with SAIHM_SELF_JOIN=0 every plan sets SAIHM_TIER, FREE for a plan paid by card, which the client then finds', async () => {
  const doc = readFileSync(new URL('../llms-install.md', import.meta.url), 'utf8').replace(/\s+/g, ' ');
  assert.ok(
    doc.includes(
      'With `SAIHM_SELF_JOIN=0`, set `SAIHM_TIER` for every plan: `FREE` for a plan paid by card, which the client then finds at sign-in.',
    ),
    'llms-install states the rule',
  );
  // True as stated: with self-join off and no SAIHM_TIER the client has no plan to sign in on, and says to set it ...
  const unset = await bridge({ sub: { tier: 'PRO', method: 'stripe' } });
  await withEnv(unset, { SAIHM_MASTER_SECRET_HEX: HEX('eb'), SAIHM_SELF_JOIN: '0' }, async () => {
    assert.throws(() => SaihmProClient.bootFromEnv(), /set SAIHM_TIER/);
    assert.deepEqual(unset.onboards, []);
  });
  // ... and with SAIHM_TIER=FREE, a plan paid by card is found at sign-in, with its payment method (railStrict: a paid
  // sign-in that drops or changes the method is refused, as live refuses it).
  const free = await bridge({ sub: { tier: 'PRO', method: 'stripe' }, railStrict: true });
  await withEnv(free, { SAIHM_MASTER_SECRET_HEX: HEX('ec'), SAIHM_SELF_JOIN: '0', SAIHM_TIER: 'FREE' }, async () => {
    const c = SaihmProClient.bootFromEnv();
    await quietly(() => c.status());
    assert.deepEqual(free.onboards, ['FREE', 'PRO']);
    assert.deepEqual(free.used, ['PRO']);
    assert.deepEqual(c.plan, { tier: 'PRO', source: 'server', note: undefined });
  });
});

test("KX1 an upgrade marker owned by another user never holds a FREE sign-in back: the owner is compared", { skip: !POSIX }, async () => {
  const realGetuid = process.getuid!.bind(process);
  const proc = process as { getuid?: () => number };
  const b = await bridge();
  await withEnv(b, {}, async (home) => {
    defaultKey(home, HEX('e3'));
    const c = SaihmProClient.bootFromEnv();
    writeFileSync(join(home, `upgrade.${c.agentIdHash.slice(0, 16)}.pending`), '', { mode: 0o600 });
    proc.getuid = () => realGetuid() + 1; // this process stands for another user: the marker is not its own
    try {
      await c.status();
    } finally {
      proc.getuid = realGetuid;
    }
    assert.equal(sessionKept(home), true, "kept: another user's marker is ignored");
    rmSync(join(home, readdirSync(home).find((n) => n.startsWith('session.'))!));
    await SaihmProClient.bootFromEnv().status();
    assert.equal(sessionKept(home), false, 'the same marker, its own user\'s, holds the sign-in back (positive control)');
  });
});

test('N5 a second name for a file of this user\'s, at the marker name, is not a marker: it never holds a FREE sign-in back', { skip: !POSIX }, async () => {
  const b = await bridge();
  await withEnv(b, {}, async (home) => {
    defaultKey(home, HEX('e7'));
    const c = SaihmProClient.bootFromEnv();
    const other = join(home, 'elsewhere');
    writeFileSync(other, '', { mode: 0o600 });
    linkSync(other, join(home, `upgrade.${c.agentIdHash.slice(0, 16)}.pending`));
    await c.status();
    assert.ok(sessionKept(home), 'the FREE sign-in is kept');
  });
});

test('KX2 a marker whose rename is refused leaves no temporary file behind', { skip: !POSIX }, async () => {
  const b = await bridge();
  await withEnv(b, {}, async (home) => {
    defaultKey(home, HEX('e4'));
    const c = SaihmProClient.bootFromEnv();
    mkdirSync(join(home, `upgrade.${c.agentIdHash.slice(0, 16)}.pending`)); // a folder at the name refuses the rename
    c.markUpgradePending();
    assert.deepEqual(readdirSync(home).filter((n) => n.endsWith('.tmp')), []);
  });
});

test('KX3 while plan_inactive holds, the sign-in limit is said as itself (rate_limited), not as plan_inactive', async () => {
  const b = await bridge({ sub: null, freeEntitled: false });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('e5') }, async (home) => {
    seedPlan(home, 'PRO', 'stripe');
    const c = SaihmProClient.bootFromEnv();
    assert.equal((await refusal(() => c.status())).code, 'plan_inactive');
    b.limited = true;
    const limited = await refusal(() => c.status());
    assert.equal(limited.code, 'rate_limited');
    assert.match(limited.message, /^SAIHM could not sign in: too many sign-ins in a short time/);
  });
});

test('KX4 the sign-in that succeeds clears plan_inactive: a later lapse names the plan refused last', async () => {
  const b = await bridge({ sub: null, freeEntitled: false });
  await withEnv(b, { SAIHM_MASTER_SECRET_HEX: HEX('e6') }, async (home) => {
    seedPlan(home, 'PRO', 'stripe');
    const c = SaihmProClient.bootFromEnv();
    assert.equal((await refusal(() => c.status())).code, 'plan_inactive'); // PRO lapsed, and the key has no free plan
    b.sub = { tier: 'PRO_FAST', method: 'stripe' }; // another plan bought
    await quietly(() => c.status());
    assert.equal(c.plan?.tier, 'PRO_FAST');
    b.sub = null; // canceled, and a free join approved since
    b.freeEntitled = true;
    b.refuseNextCall = true;
    await quietly(() => c.status());
    assert.deepEqual(c.plan, { tier: 'FREE', source: 'default', note: lapseNote('PRO_FAST') });
  });
});
