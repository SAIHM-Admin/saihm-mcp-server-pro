/**
 * Public smoke suite for @saihm/mcp-server-pro.
 *
 * Exercises the SaihmProClient surface with NO dependency on a live SAIHM
 * endpoint: identity derivation, endpoint-URL hardening, env-boot validation,
 * and the full typed-error transport contract (against throwaway local stub
 * servers). Clone, `npm install`, `npm test` -> all green, fully offline.
 *
 * Runner: npx tsx --test tests/smoke.test.ts   (or `npm test`)
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { createServer } from "node:http";
import type { AddressInfo, Socket } from "node:net";

import { deriveIdentity, toHex, fromHex } from "@saihm/client-pro";
import { SaihmProClient, SaihmEndpointError } from "../src/client.js";

const masterOf = (b: number): Uint8Array => new Uint8Array(32).fill(b);

describe("SC1: identity derivation", () => {
  it("agentIdHash is deterministic = the published record's hash; record shape is correct", () => {
    const master = masterOf(11);
    const c = new SaihmProClient("https://saihm.coti.global/mcp", "Bearer x", master, { tier: "PRO" });
    assert.equal(c.agentIdHash, toHex(deriveIdentity(master).agentIdHash));
    assert.equal(c.identityRecord.mldsaPubKey.length, 1952 * 2); // hex of the 1952-byte ML-DSA-65 public key
  });
});

describe("SC2: endpoint URL hardening", () => {
  it("rejects non-loopback http; accepts https and loopback http", () => {
    const master = masterOf(21);
    assert.throws(() => new SaihmProClient("http://example.com/mcp", "Bearer x", master));
    assert.doesNotThrow(() => new SaihmProClient("https://saihm.coti.global/mcp", "Bearer x", master));
    assert.doesNotThrow(() => new SaihmProClient("http://127.0.0.1:3001/mcp", "Bearer x", master));
  });
});

describe("SC3: bootFromEnv validation", () => {
  it("rejects missing / short / non-hex master; accepts a valid env", () => {
    const save = { ...process.env };
    try {
      for (const k of ["SAIHM_ENDPOINT_URL", "SAIHM_AUTH_HEADER", "SAIHM_MASTER_SECRET_HEX", "SAIHM_TIER", "SAIHM_SEQ_STATE_PATH"]) delete process.env[k];
      assert.throws(() => SaihmProClient.bootFromEnv(), /SAIHM_ENDPOINT_URL/);
      process.env.SAIHM_ENDPOINT_URL = "https://saihm.coti.global/mcp";
      process.env.SAIHM_AUTH_HEADER = "Bearer test";
      process.env.SAIHM_MASTER_SECRET_HEX = "00"; // 1 byte
      assert.throws(() => SaihmProClient.bootFromEnv(), /decode to >= 32 bytes/);
      process.env.SAIHM_MASTER_SECRET_HEX = "zz".repeat(32); // non-hex
      assert.throws(() => SaihmProClient.bootFromEnv(), /lowercase hex/);
      process.env.SAIHM_MASTER_SECRET_HEX = "ab".repeat(32); // valid 32 bytes
      const c = SaihmProClient.bootFromEnv();
      assert.equal(c.agentIdHash, toHex(deriveIdentity(fromHex("ab".repeat(32))).agentIdHash));
    } finally {
      for (const k of Object.keys(process.env)) if (!(k in save)) delete process.env[k];
      Object.assign(process.env, save);
    }
  });
});

describe("SC4: transport-layer failures are typed SaihmEndpointError", () => {
  it("non-JSON 2xx -> malformed_json; oversize body -> response_too_large; dead port -> network", async () => {
    const master = masterOf(36);
    // a) malformed_json: a 200 with a non-JSON body
    const s1 = createServer((_req, res) => { res.writeHead(200, { "content-type": "application/json" }).end("not json at all"); });
    await new Promise<void>((r) => s1.listen(0, "127.0.0.1", () => r()));
    try {
      const c = new SaihmProClient(`http://127.0.0.1:${(s1.address() as AddressInfo).port}/mcp`, "Bearer x", master, { tier: "PRO" });
      await assert.rejects(() => c.status(), (e: unknown) => e instanceof SaihmEndpointError && e.code === "malformed_json");
    } finally { await new Promise<void>((r) => s1.close(() => r())); }
    // b) response_too_large: a 200 body over MAX_RESPONSE_BYTES (16 MiB)
    const big = "a".repeat(17 * 1024 * 1024);
    const s2 = createServer((_req, res) => { res.writeHead(200, { "content-type": "application/json" }).end(big); });
    await new Promise<void>((r) => s2.listen(0, "127.0.0.1", () => r()));
    try {
      const c = new SaihmProClient(`http://127.0.0.1:${(s2.address() as AddressInfo).port}/mcp`, "Bearer x", master, { tier: "PRO" });
      await assert.rejects(() => c.status(), (e: unknown) => e instanceof SaihmEndpointError && e.code === "response_too_large");
    } finally { await new Promise<void>((r) => s2.close(() => r())); }
    // c) network: connect to a port that was listening then closed
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, "127.0.0.1", () => r()));
    const deadPort = (probe.address() as AddressInfo).port;
    await new Promise<void>((r) => probe.close(() => r()));
    const c3 = new SaihmProClient(`http://127.0.0.1:${deadPort}/mcp`, "Bearer x", master, { tier: "PRO" });
    await assert.rejects(() => c3.status(), (e: unknown) => e instanceof SaihmEndpointError && e.code === "network");
  });
});

describe("SC5: a request exceeding the timeout budget is a typed timeout (408)", () => {
  it("a never-responding endpoint aborts with SaihmEndpointError(408, timeout)", async () => {
    const master = masterOf(53);
    const sockets = new Set<Socket>();
    const s = createServer((req) => { void req; /* accept the request, never respond */ });
    s.on("connection", (sock) => { sockets.add(sock); sock.on("close", () => sockets.delete(sock)); });
    await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
    try {
      const c = new SaihmProClient(`http://127.0.0.1:${(s.address() as AddressInfo).port}/mcp`, "Bearer x", master, { tier: "PRO", requestTimeoutMs: 50 });
      await assert.rejects(
        () => c.status(),
        (e: unknown) => e instanceof SaihmEndpointError && e.status === 408 && e.code === "timeout",
      );
    } finally {
      for (const sock of sockets) sock.destroy();
      await new Promise<void>((r) => s.close(() => r()));
    }
  });
});

describe("SC6: a non-2xx error body maps status + the JSON .error code", () => {
  it("plain-text 500 -> code undefined; JSON {error} 401 -> that code; status preserved both", async () => {
    const master = masterOf(54);
    // a) 500 with a non-JSON body -> code stays undefined, status preserved
    const s1 = createServer((_req, res) => { res.writeHead(500, { "content-type": "text/plain" }).end("internal boom"); });
    await new Promise<void>((r) => s1.listen(0, "127.0.0.1", () => r()));
    try {
      const c = new SaihmProClient(`http://127.0.0.1:${(s1.address() as AddressInfo).port}/mcp`, "Bearer x", master, { tier: "PRO" });
      await assert.rejects(
        () => c.status(),
        (e: unknown) => e instanceof SaihmEndpointError && e.status === 500 && e.code === undefined,
      );
    } finally { await new Promise<void>((r) => s1.close(() => r())); }
    // b) 401 with a JSON {error} body -> code surfaced, status preserved
    const s2 = createServer((_req, res) => { const b = JSON.stringify({ error: "unauthorized" }); res.writeHead(401, { "content-type": "application/json" }).end(b); });
    await new Promise<void>((r) => s2.listen(0, "127.0.0.1", () => r()));
    try {
      const c = new SaihmProClient(`http://127.0.0.1:${(s2.address() as AddressInfo).port}/mcp`, "Bearer x", master, { tier: "PRO" });
      await assert.rejects(
        () => c.status(),
        (e: unknown) => e instanceof SaihmEndpointError && e.status === 401 && e.code === "unauthorized",
      );
    } finally { await new Promise<void>((r) => s2.close(() => r())); }
  });
});

describe("SC7: governance surfaces a clean typed unavailable", () => {
  it("propose and vote both throw SaihmEndpointError(403, governance_unavailable)", async () => {
    const master = masterOf(49);
    const s = createServer((_req, res) => { res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ ok: true })); });
    await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
    try {
      const c = new SaihmProClient(`http://127.0.0.1:${(s.address() as AddressInfo).port}/mcp`, "Bearer x", master, { tier: "PRO" });
      await assert.rejects(
        () => c.governancePropose({ scope: "emission_param", paramKey: "k", proposedValue: "1" }),
        (e: unknown) => e instanceof SaihmEndpointError && e.status === 403 && e.code === "governance_unavailable",
      );
      await assert.rejects(
        () => c.governanceVote({ proposalId: "p", approve: true }),
        (e: unknown) => e instanceof SaihmEndpointError && e.status === 403 && e.code === "governance_unavailable",
      );
    } finally { await new Promise<void>((r) => s.close(() => r())); }
  });
});
