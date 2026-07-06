/**
 * Phase-7 client<->bridge END-TO-END suite (E1-E4) — the REAL @saihm/mcp-server-pro client
 * (`acquireFreeEntitlement`) driven against the REAL edge bridge request `handler`
 * (edge/mcp-bridge/server.ts) over loopback HTTP, with ONLY the external GitHub device-flow mocked.
 *
 *   Runner: npx tsx --test tests/client_bridge_e2e.test.ts   (run from mcp-server-pro/)
 *
 * Unlike tests/client_free_onboard.test.ts (real client vs a HAND-ROLLED mock bridge) and
 * edge/mcp-bridge/free_onboard.test.ts (bridge state machine, no client, no HTTP), this suite closes
 * the last untested seam: the REAL client's REAL ML-DSA proof-of-possession verified by the REAL
 * bridge `verifyPoP`/`verifyMlDsaSig`, the REAL device-flow state machine, and the REAL Sybil-gated
 * FileGateStore grant — a true integration, not two mocks agreeing with each other.
 *
 * Topology (one process):
 *   test process        : real SaihmProClient  --HTTP-->  createServer(handler) --GitHub-->  fetch stub
 * The globalThis.fetch stub intercepts ONLY github.com (device-code / token / user); every other URL
 * (the client's own loopback calls to the bridge) passes through to the real fetch, so the bridge and
 * the client exchange genuine HTTP. FREE is LIVE in ALLOWED_TIERS (Phase-7 flip 2026-07-06): E4 proves
 * FREE now clears the tier gate and is gated by signature/entitlement, not bad_tier. The suite drives
 * an isolated in-process bridge handler (isMain=false, no operator upstream), so it has zero live-money
 * blast radius regardless.
 */

// ── Env MUST be set before the bridge modules are (dynamically) imported: the Sybil salt + OAuth
//    client-id are read by the identity layer, and the gate-store path is read lazily at first grant.
process.env.OAUTH_GITHUB_CLIENT_ID = "test-client";
process.env.IDENTITY_GATE_SALT_HEX = "00112233445566778899aabbccddeeff";

import { describe, it, after } from "node:test";
import { strict as assert } from "node:assert";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SaihmProClient, SaihmEndpointError } from "../src/client.js";

// ── selective GitHub device-flow stub ─────────────────────────────────────────
// Capture the REAL fetch first; the client's loopback calls to the bridge pass through to it. Only
// github.com is served in-memory (no network) so the bridge's server-side device flow resolves. The
// `githubId` is mutable so a test can model a second sovereign key reusing ONE identity (Sybil,
// vector 5) vs a FRESH identity opening a fresh lane.
const realFetch = globalThis.fetch;
let githubId = 9001;
function gh200(body: unknown): unknown {
  return { ok: true, status: 200, json: async () => body };
}
(globalThis as { fetch: unknown }).fetch = (async (input: unknown, init?: unknown) => {
  const u = String(typeof input === "string" ? input : (input as { url?: string })?.url ?? input);
  if (u.includes("github.com")) {
    if (u.includes("/login/device/code")) {
      return gh200({
        device_code: "DC-" + githubId,
        user_code: "WDJB-MJHT",
        verification_uri: "https://github.com/login/device",
        expires_in: 900,
        interval: 0,
      });
    }
    if (u.includes("/login/oauth/access_token")) return gh200({ access_token: "AT-" + githubId });
    if (u.includes("api.github.com/user")) {
      return gh200({
        id: githubId,
        login: "octo" + githubId,
        created_at: "2019-01-01T00:00:00Z",
        public_repos: 7,
        followers: 4,
      });
    }
    return gh200({});
  }
  return realFetch(input as Parameters<typeof fetch>[0], init as Parameters<typeof fetch>[1]);
}) as typeof fetch;

// The bridge is imported AFTER the fetch override + env are in place. Importing server.ts does NOT
// boot it (isMain=false when it is not process.argv[1]); we drive its exported `handler` directly.
const { handler } = await import("../../edge/mcp-bridge/server.ts");
const { getGateStore, __resetFreeOnboardForTest: resetFreeOnboard } = await import(
  "../../edge/mcp-bridge/free_onboard.ts"
);

const masterOf = (n: number): Uint8Array => new Uint8Array(32).fill(n & 0xff);

/** Fresh per-test NDJSON gate store + cleared in-memory flow map → tests never cross-contaminate. */
function freshStore(): void {
  process.env.IDENTITY_GATE_STORE_FILE = join(mkdtempSync(join(tmpdir(), "saihm-e2e-")), "grants.ndjson");
  resetFreeOnboard();
}

/** Stand the REAL bridge handler up on an ephemeral loopback port for the duration of `run`. */
async function withBridge(run: (base: string) => Promise<void>): Promise<void> {
  freshStore();
  const server = createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    await run(base);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

// Restore the real fetch once the suite finishes so a co-run suite in the same process is unaffected.
after(() => {
  (globalThis as { fetch: unknown }).fetch = realFetch;
});

describe("Phase-7 client<->bridge e2e (real client, real bridge, mock GitHub)", () => {
  it("E1 device flow → crypto-bound FREE grant: real PoP verified by the real bridge → entitledFree", async () => {
    await withBridge(async (base) => {
      githubId = 7001;
      const c = new SaihmProClient(base + "/mcp", undefined, masterOf(1), { tier: "FREE" });
      let prompts = 0;
      const r = await c.acquireFreeEntitlement({
        pollIntervalMs: 25,
        onPrompt: (p) => {
          prompts += 1;
          assert.equal(p.verificationUri, "https://github.com/login/device");
          assert.equal(p.userCode, "WDJB-MJHT");
        },
      });
      assert.equal(prompts, 1, "the human prompt is surfaced exactly once");
      // The client trusts only ITS OWN agentIdHash; a grant is impossible unless the real bridge
      // verifyMlDsaSig accepted this identity's real ML-DSA signature over the real challenge nonce.
      assert.equal(r.agentIdHash, c.agentIdHash);
      // The REAL Sybil-gated FileGateStore now holds a durable FREE entitlement for THIS key.
      assert.equal(await getGateStore().entitledFree(c.agentIdHash), true);
    });
  });

  it("E2 idempotent: a second acquire on an already-entitled key succeeds (already_granted; no double-issue)", async () => {
    await withBridge(async (base) => {
      githubId = 7101;
      const c = new SaihmProClient(base + "/mcp", undefined, masterOf(2), { tier: "FREE" });
      const r1 = await c.acquireFreeEntitlement({ pollIntervalMs: 25, onPrompt: () => {} });
      assert.equal(r1.agentIdHash, c.agentIdHash);
      assert.equal(await getGateStore().entitledFree(c.agentIdHash), true);
      // Re-run the WHOLE flow (new device session, same github id + same sovereign key). The bridge
      // grant is idempotent (Phase-3 entitledFree short-circuit → already_granted), so the client
      // resolves cleanly and the identity stays entitled — no throw, no second lane consumed.
      const r2 = await c.acquireFreeEntitlement({ pollIntervalMs: 25, onPrompt: () => {} });
      assert.equal(r2.agentIdHash, c.agentIdHash);
      assert.equal(await getGateStore().entitledFree(c.agentIdHash), true);
    });
  });

  it("E3 Sybil (vector 5) over real HTTP: a 2nd key reusing ONE github id is denied; a fresh id opens a fresh lane", async () => {
    await withBridge(async (base) => {
      // Key A grants on github id 8001.
      githubId = 8001;
      const cA = new SaihmProClient(base + "/mcp", undefined, masterOf(3), { tier: "FREE" });
      await cA.acquireFreeEntitlement({ pollIntervalMs: 25, onPrompt: () => {} });
      assert.equal(await getGateStore().entitledFree(cA.agentIdHash), true);

      // Key B (DIFFERENT sovereign key) reusing the SAME github id 8001 → duplicate OAuth identity.
      // The real gate denies at commitGrant; the bridge returns status:denied → the client raises a
      // terminal typed error (never loops to timeout).
      const cB = new SaihmProClient(base + "/mcp", undefined, masterOf(4), { tier: "FREE" });
      await assert.rejects(
        () => cB.acquireFreeEntitlement({ pollIntervalMs: 25, timeoutMs: 5_000, onPrompt: () => {} }),
        (e: unknown) => e instanceof SaihmEndpointError,
      );
      assert.equal(await getGateStore().entitledFree(cB.agentIdHash), false, "denied key is not entitled");

      // Fresh github id 8002 + fresh key C → granted (a distinct identity opens a fresh lane).
      githubId = 8002;
      const cC = new SaihmProClient(base + "/mcp", undefined, masterOf(5), { tier: "FREE" });
      await cC.acquireFreeEntitlement({ pollIntervalMs: 25, onPrompt: () => {} });
      assert.equal(await getGateStore().entitledFree(cC.agentIdHash), true);
    });
  });

  it("E4 POST-FLIP: FREE now PASSES ALLOWED_TIERS — a bogus-signature FREE onboard reaches ML-DSA verification (bad_signature), no longer short-circuited as bad_tier", async () => {
    await withBridge(async (base) => {
      // Phase-7 flip (2026-07-06): FREE is now in ALLOWED_TIERS, so this well-formed-except-the-signature
      // onboard is NO LONGER rejected at the tier gate (server.ts L420). It passes the tier gate and
      // reaches consumeChallenge/verifyMlDsaSig, where the bogus signature fails → `bad_signature`.
      // This is the exact inversion of the pre-flip invariant: `bad_signature` (not `bad_tier`) is now
      // the tell that the tier gate no longer fires first — i.e. the flip line is OPEN. The full valid
      // granted-FREE mint path is covered end-to-end by E1 (real PoP → entitledFree).
      const ch = (await (await realFetch(base + "/api/onboard/challenge")).json()) as { nonce: string };
      const res = await realFetch(base + "/api/onboard", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          tier: "FREE",
          pubkey: "ab".repeat(48),
          nonce: ch.nonce,
          signature: "cd".repeat(64),
        }),
      });
      assert.equal(res.status, 401);
      const body = (await res.json()) as { reason?: string };
      assert.equal(body.reason, "bad_signature", "post-flip: FREE clears ALLOWED_TIERS and fails at signature verification, not bad_tier");
    });
  });

  it("E5 grant-time store fault → claim fails closed with a 503 (local try/catch), bridge keeps serving", async () => {
    await withBridge(async (base) => {
      // Point the gate store at a DIRECTORY (not a file) so grantForFlow's store read/append throws
      // (EISDIR) at grant time — the same class of fault as an unset IDENTITY_GATE_SALT_HEX or a disk
      // IO error. This sentinels change #1 ONLY: server.ts's claim-path `try -> 503` catch. Under the
      // fix the client observes a 503 `free_onboard_unavailable`; if that local catch were removed the
      // handler would write NO response and the client would instead hit the 408 poll timeout — so the
      // status assertion below, not a bare `rejects`, is what pins the fail-closed behavior.
      //   (The PROCESS-level guards — change #2, unhandledRejection stay-alive / uncaughtException
      //   exit(1) — live inside `if (isMain)` and are NOT registered on module import, so this suite
      //   cannot exercise them; they are sentineled by edge/mcp-bridge/server_fault_guards.test.ts.)
      process.env.IDENTITY_GATE_STORE_FILE = mkdtempSync(join(tmpdir(), "saihm-e2e-dirstore-"));
      resetFreeOnboard();
      githubId = 7777;
      const c = new SaihmProClient(base + "/mcp", undefined, masterOf(9), { tier: "FREE" });
      await assert.rejects(
        () => c.acquireFreeEntitlement({ pollIntervalMs: 25, timeoutMs: 5_000, onPrompt: () => {} }),
        (e: unknown) =>
          e instanceof SaihmEndpointError &&
          e.status === 503 &&
          /free_onboard_unavailable/.test(e.code ?? ""),
        "grant-time store fault must surface as a 503 free_onboard_unavailable, not a 408 timeout",
      );
      // The bridge survived the handler fault — a subsequent request still gets a real HTTP response.
      const ping = await realFetch(base + "/api/psp/availability");
      assert.ok(ping.status >= 200 && ping.status < 600, "bridge still responding after the failed grant");
    });
  });
});
