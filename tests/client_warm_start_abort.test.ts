// The upload abort against a commit still in flight at the endpoint when the abort arrives. The commit's answer never
// comes back and the listing that would say whether it was stored fails too, so the client cannot know the commit's
// fate: it aborts anyway, because an abort only ever finds an OPEN upload. Both orders at the endpoint: the commit
// holds the identity's lock when the abort arrives (the commit is stored, the abort finds nothing open), or the abort
// takes the lock first (the upload is gone, the commit then finds nothing to store). Either way nothing stored is
// removed, nothing is left open, and the error the put throws is the commit's own.
//
// And the abort never holds that error back: it is over within WARM_START_ABORT_MS whatever the endpoint does. No answer
// in time is never tried again; a busy answer (503) or a connection refused or reset before any answer is tried once more.
//
// Runner: npx tsx --test tests/client_warm_start_abort.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const HOME = mkdtempSync(join(tmpdir(), 'saihm-home-'));
process.env.SAIHM_HOME = HOME;
process.on('exit', () => rmSync(HOME, { recursive: true, force: true }));

const { SaihmProClient, SaihmEndpointError, WARM_START_ABORT_MS } = await import('../src/client.js');

const AT = 'AbCdEf0123456789-_AbCdEf0123456789-_AbCdEf0123';
const PART_BYTES = 1024;
/**
 * The client's request timeout: ample for every answer the endpoint does not hold (a begin, a part) on a loaded host,
 * and still a held commit's answer is lost to it, since the endpoint holds every commit until the abort arrives.
 */
const TIMEOUT_MS = 1_500;

type Order = 'commit-holds-the-lock' | 'abort-takes-the-lock';

/**
 * An endpoint that serialises one identity's commit and abort on one lock, as the operator does, and holds every
 * commit until the abort has arrived. The listing fails (the front cannot reach the operator).
 */
async function endpoint(order: Order) {
  const uploads = new Map<string, { parts: number; got: Set<number> }>();
  const stored: string[] = [];
  const requests: string[] = [];
  const commitAnswers: number[] = [];
  const abortAnswers: number[] = [];
  let lock: Promise<unknown> = Promise.resolve();
  const locked = <T>(fn: () => T | Promise<T>): Promise<T> => {
    const r = lock.then(fn);
    lock = r.catch(() => undefined);
    return r;
  };
  let openGate!: () => void;
  const gate = new Promise<void>((r) => (openGate = r));
  let commitsArrived = 0;
  let firstCommitArrived!: () => void;
  const firstCommit = new Promise<void>((r) => (firstCommitArrived = r));
  const send = (res: ServerResponse, status: number, body?: unknown): void => {
    if (res.destroyed || res.writableEnded) return;
    res.writeHead(status, body === undefined ? {} : { 'content-type': 'application/json' });
    res.end(body === undefined ? '' : JSON.stringify(body));
  };
  const commit = (id: string): number => {
    const up = uploads.get(id);
    if (!up) return 404;
    if (up.got.size !== up.parts) return 400;
    uploads.delete(id);
    stored.push(id);
    return 201;
  };
  const route = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const path = (req.url ?? '').split('?')[0] as string;
    requests.push(`${req.method} ${path.replace(/[0-9a-f]{32}/g, '<up>')}`);
    let g: RegExpExecArray | null;
    if (req.method === 'POST' && path === '/mcp/warm-start') {
      const id = randomBytes(16).toString('hex');
      const b = JSON.parse(Buffer.concat(chunksOf.get(req) ?? []).toString('utf8')) as { parts: number };
      uploads.set(id, { parts: b.parts, got: new Set() });
      return send(res, 201, { v: 1, uploadId: id, partBytes: PART_BYTES, expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
    }
    if (req.method === 'PUT' && (g = /^\/mcp\/warm-start\/uploads\/([0-9a-f]{32})\/parts\/(\d+)$/.exec(path))) {
      const up = uploads.get(g[1] as string);
      if (!up) return send(res, 404, { error: 'upload_not_found' });
      up.got.add(Number(g[2]));
      return send(res, 204);
    }
    if (req.method === 'POST' && (g = /^\/mcp\/warm-start\/uploads\/([0-9a-f]{32})\/commit$/.exec(path))) {
      const id = g[1] as string;
      commitsArrived++;
      firstCommitArrived();
      // In flight: the commit's answer is held past the client's timeout, so its fate is unknown to the client.
      const status =
        order === 'commit-holds-the-lock'
          ? await locked(async () => { await gate; return commit(id); })
          : await gate.then(() => locked(() => commit(id)));
      commitAnswers.push(status);
      return send(res, status, status === 201 ? { v: 1 } : { error: status === 404 ? 'upload_not_found' : 'bad_request' });
    }
    if (req.method === 'GET' && path === '/mcp/warm-start') return send(res, 503, { error: 'upstream_unavailable' });
    if (req.method === 'DELETE' && (g = /^\/mcp\/warm-start\/uploads\/([0-9a-f]{32})$/.exec(path))) {
      const id = g[1] as string;
      // The abort arrives while every commit is still held; then the endpoint lets them go on.
      const answer = locked(() => (uploads.delete(id) ? 204 : 404));
      openGate();
      const status = await answer;
      abortAnswers.push(status);
      return send(res, status, status === 204 ? undefined : { error: 'upload_not_found' });
    }
    return send(res, 404, { error: 'not_found' });
  };
  const chunksOf = new WeakMap<IncomingMessage, Buffer[]>();
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    chunksOf.set(req, chunks);
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => void route(req, res));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    url, uploads, stored, requests, commitAnswers, abortAnswers, firstCommit,
    commits: () => commitsArrived,
    /** Lets every held commit go on (for a client that never aborts), and waits until each has answered. */
    settle: async () => { openGate(); await lock; while (commitAnswers.length < commitsArrived) await new Promise((r) => setTimeout(r, 10)); },
    close: async () => { server.closeAllConnections(); await new Promise<void>((r) => server.close(() => r())); },
  };
}

for (const order of ['commit-holds-the-lock', 'abort-takes-the-lock'] as const) {
  test(`a commit in flight when the abort arrives (${order}), its fate unknown and the listing failing: aborted anyway, nothing stored is removed, nothing left open`, async () => {
    const ep = await endpoint(order);
    try {
      const c = new SaihmProClient(`${ep.url}/mcp`, 'Bearer t', new Uint8Array(32).fill(9), { tier: 'PRO', requestTimeoutMs: TIMEOUT_MS });
      const offer = { maxBytes: 65_536, url: `${ep.url}/mcp/warm-start`, partBytes: PART_BYTES };
      const thrown = await c.warmStartPut(offer, new Uint8Array(3_000).fill(5), AT).then(
        () => assert.fail('the put must fail: its commit never answered and the listing could not say it was stored'),
        (e: unknown) => e,
      );
      await ep.settle();
      // The put's own failure, never the abort's: the commit timed out (each try), and the listing could not tell.
      assert.ok(thrown instanceof SaihmEndpointError && thrown.code === 'timeout', String(thrown));
      const tail = ep.requests.filter((x) => !x.startsWith('PUT'));
      assert.deepEqual(tail.slice(-2), ['GET /mcp/warm-start', 'DELETE /mcp/warm-start/uploads/<up>'], 'the listing first, then the abort');
      assert.equal(tail.filter((x) => x.startsWith('DELETE')).length, 1, 'one abort');
      assert.ok(ep.commits() >= 1);
      if (order === 'commit-holds-the-lock') {
        // The commit held the lock: it stored the snapshot, and the abort found no open upload. Stored stays stored.
        assert.deepEqual([ep.stored.length, ep.abortAnswers], [1, [404]]);
        assert.equal(ep.commitAnswers[0], 201);
      } else {
        // The abort took the lock: the upload went, and every commit then found nothing open to store.
        assert.deepEqual([ep.stored.length, ep.abortAnswers], [0, [204]]);
        assert.ok(ep.commitAnswers.every((s) => s === 404), String(ep.commitAnswers));
      }
      assert.equal(ep.uploads.size, 0, 'nothing left open');
    } finally {
      await ep.close();
    }
  });
}

// ── the abort's own bound ─────────────────────────────────────────────────────────────────────────────────────────────

/** Scheduling slack on a loaded host, beyond the abort's own bound. */
const SLACK_MS = 1_500;

/**
 * An endpoint whose first part is refused for good (409), and whose abort answers by `aborts`, one entry a request:
 * `hold` (never answers), `reset` (closes the connection before any answer), `refuse` (stops listening, so the next
 * connection is refused, and listens again before the client's second try), or an HTTP status.
 */
async function abortEndpoint(aborts: Array<'hold' | 'reset' | 'refuse' | number>) {
  const uploads = new Set<string>();
  const deletes: string[] = [];
  let failedAt = 0;
  let port = 0;
  let reopen: ReturnType<typeof setTimeout> | undefined;
  const held: ServerResponse[] = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const path = (req.url ?? '').split('?')[0] as string;
      const send = (status: number, body?: unknown, headers: Record<string, string> = {}): void => {
        res.writeHead(status, { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers });
        res.end(body === undefined ? '' : JSON.stringify(body));
      };
      if (req.method === 'POST' && path === '/mcp/warm-start') {
        const id = randomBytes(16).toString('hex');
        uploads.add(id);
        return send(201, { v: 1, uploadId: id, partBytes: PART_BYTES, expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
      }
      if (req.method === 'PUT') {
        const next = aborts[0];
        // The part fails for good; before an abort that must find nothing listening, this connection is not kept.
        res.on('finish', () => {
          failedAt = Date.now();
          if (next === 'refuse') {
            // The refused try never reaches this endpoint, so it is taken off the list here.
            aborts.shift();
            server.close();
            server.closeAllConnections();
            reopen = setTimeout(() => server.listen(port, '127.0.0.1'), 300);
          }
        });
        return send(409, { error: 'snapshot_superseded' }, next === 'refuse' ? { connection: 'close' } : {});
      }
      const g = /^\/mcp\/warm-start\/uploads\/([0-9a-f]{32})$/.exec(path);
      if (req.method === 'DELETE' && g) {
        deletes.push(g[1] as string);
        const how = aborts.shift() ?? 404;
        if (how === 'hold') return void held.push(res);
        if (how === 'reset') return void req.socket.destroy();
        if (how === 204) {
          const open = uploads.delete(g[1] as string);
          return send(open ? 204 : 404, open ? undefined : { error: 'upload_not_found' });
        }
        return send(how, { error: how === 503 ? 'warm_start_unavailable' : 'upload_not_found' });
      }
      return send(404, { error: 'not_found' });
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
  const url = `http://127.0.0.1:${port}`;
  return {
    url, uploads, deletes,
    failedAt: () => failedAt,
    // Whatever the test saw: a listener not yet opened again is never opened, so nothing outlives the test.
    close: async () => {
      clearTimeout(reopen);
      for (const r of held) r.destroy();
      server.closeAllConnections();
      if (server.listening) await new Promise<void>((r) => server.close(() => r()));
    },
  };
}

/** A put that fails for good at its first part, timed from that failure to the error it throws. */
async function failedPut(ep: Awaited<ReturnType<typeof abortEndpoint>>): Promise<{ error: unknown; afterFailureMs: number }> {
  // The client's own request timeout stays the default: the abort must be bounded by its own.
  const c = new SaihmProClient(`${ep.url}/mcp`, 'Bearer t', new Uint8Array(32).fill(11), { tier: 'PRO' });
  const offer = { maxBytes: 65_536, url: `${ep.url}/mcp/warm-start`, partBytes: PART_BYTES };
  const error = await c.warmStartPut(offer, new Uint8Array(3_000).fill(6), AT).then(() => assert.fail('the put must fail'), (e: unknown) => e);
  return { error, afterFailureMs: Date.now() - ep.failedAt() };
}

const partRefused = (e: unknown): boolean => e instanceof SaihmEndpointError && e.code === 'snapshot_superseded' && e.status === 409;

test('an abort that gets no answer is not tried again, and the put throws its own failure within the abort bound', async () => {
  const ep = await abortEndpoint(['hold', 204]);
  try {
    const { error, afterFailureMs } = await failedPut(ep);
    assert.ok(partRefused(error), String(error));
    assert.equal(ep.deletes.length, 1, 'no second try after no answer');
    assert.ok(afterFailureMs <= WARM_START_ABORT_MS + SLACK_MS, `thrown ${afterFailureMs} ms after the failure`);
  } finally {
    await ep.close();
  }
});

test('a busy abort is tried once more and the whole abort stays within its bound, the second try held included', async () => {
  const ep = await abortEndpoint([503, 'hold']);
  try {
    const { error, afterFailureMs } = await failedPut(ep);
    assert.ok(partRefused(error), String(error));
    assert.equal(ep.deletes.length, 2);
    assert.ok(afterFailureMs <= WARM_START_ABORT_MS + SLACK_MS, `thrown ${afterFailureMs} ms after the failure`);
  } finally {
    await ep.close();
  }
});

test('a connection refused or reset before any answer is tried once more, and the second try aborts the upload', async () => {
  for (const first of ['refuse', 'reset'] as const) {
    const ep = await abortEndpoint([first, 204]);
    try {
      const { error, afterFailureMs } = await failedPut(ep);
      assert.ok(partRefused(error), `${first}: ${String(error)}`);
      // A refused connection never reaches the endpoint: only the second try is seen there.
      assert.equal(ep.deletes.length, first === 'refuse' ? 1 : 2, first);
      assert.equal(ep.uploads.size, 0, `${first}: the upload was aborted by the second try`);
      assert.ok(afterFailureMs <= WARM_START_ABORT_MS + SLACK_MS, `${first}: thrown ${afterFailureMs} ms after the failure`);
    } finally {
      await ep.close();
    }
  }
});
