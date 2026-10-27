// recallShared by the sharer's agent ID alone (0.14.3), against a hostile endpoint. The sharer's identity record is
// optional: without it, the sharer's signing key is the one the cell's own signed envelope carries, and it is used only
// after it hashes to the pinned agent ID. Every case here is built from the shipped crypto, and the forgeries are
// complete: each is consistent in every part except the one binding the check under test defends, which positive
// controls in the test prove, so a refusal can only come from that check.
//
// Runner: npx tsx --test tests/client_recall_shared_pin.test.ts
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createCipheriv, createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const HOME = mkdtempSync(join(tmpdir(), 'saihm-home-'));
process.env.SAIHM_HOME = HOME;
process.env.SAIHM_ERASURE_FEED_DIR = mkdtempSync(join(tmpdir(), 'saihm-feed-'));
process.on('exit', () => {
  rmSync(HOME, { recursive: true, force: true });
  rmSync(process.env.SAIHM_ERASURE_FEED_DIR!, { recursive: true, force: true });
});

const { SaihmProClient, SaihmEndpointError } = await import('../src/client.js');
const {
  deriveIdentity,
  sealCell,
  shareCell,
  encodeEnvelope,
  encodeShareEnvelope,
  encodeIdentityRecord,
  serializeForSigning,
  cellAad,
  unwrapDek,
  openCellWithDek,
  verifyEnvelope,
  verifyShareSig,
  KeySubstitutionError,
  toHex,
  utf8,
  fromUtf8,
} = await import('@saihm/client-pro');
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

type Identity = ReturnType<typeof deriveIdentity>;
type Envelope = ReturnType<typeof sealCell>;
type Share = ReturnType<typeof shareCell>;

const sha256 = (b: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(b).digest());
const RECIPIENT_SEED = new Uint8Array(32).fill(0xb3);
const B = deriveIdentity(RECIPIENT_SEED); // the client under test reads as B
const A = deriveIdentity(new Uint8Array(32).fill(0xa1)); // the sharer B pins
const M = deriveIdentity(new Uint8Array(32).fill(0x4d)); // another agent, or the endpoint's own key
const PIN_A = toHex(A.agentIdHash);
const RECORD_A = encodeIdentityRecord(A.identityRecord);

function seal(I: Identity, cellId: string, text: string, seq = 1n): Envelope {
  return sealCell({ plaintext: utf8(text), kek: I.kek, mldsaSecretKey: I.mldsaSecretKey, mldsaPubKey: I.mldsaPubKey, agentIdHash: I.agentIdHash, cellId, seq, tier: 'PRO' });
}
/** A share of `env` to B, naming `sharerHash` as the sharer and signed by `signer`, the DEK unwrapped with `kekOwner`'s KEK. */
function grant(kekOwner: Identity, env: Envelope, signer: Identity = kekOwner, sharerHash: Uint8Array = kekOwner.agentIdHash): Share {
  return shareCell({ envelope: env, sharerKek: kekOwner.kek, sharerMldsaSecretKey: signer.mldsaSecretKey, sharerAgentIdHash: sharerHash, recipientRecord: B.identityRecord, recipientPinnedAgentIdHash: B.agentIdHash });
}
const reply = (share: Share, env: Envelope): Record<string, unknown> => ({ found: true, wire: encodeShareEnvelope(share), contentWire: encodeEnvelope(env) });

/**
 * The strongest forgery of A's cell an endpoint (or M) can make without A's secret key: M seals a cell as itself, then
 * rewrites the envelope to claim A's agent ID, re-encrypted under A's associated data, recommitted and re-signed by M,
 * and grants it to B in a share naming A as the sharer, signed by M. Everything in it is consistent except that M's key
 * does not hash to A's agent ID: a reader that took the key from the envelope without that check would open it as A's.
 */
function forgeAsA(cellId: string, text: string): { envelope: Envelope; share: Share; dek: Uint8Array } {
  const own = seal(M, cellId, text);
  const dek = unwrapDek(own, M.kek);
  const c = createCipheriv('aes-256-gcm', dek, own.nonce);
  c.setAAD(cellAad({ agentIdHash: A.agentIdHash, cellId, seq: own.seq, schemaVer: own.schemaVer }));
  const ciphertext = new Uint8Array(Buffer.concat([c.update(utf8(text)), c.final(), c.getAuthTag()]));
  const unsigned = {
    schemaVer: own.schemaVer,
    agentIdHash: A.agentIdHash,
    cellId,
    seq: own.seq,
    ciphertext,
    nonce: own.nonce,
    wrappedDek: own.wrappedDek,
    mldsaPubKey: M.mldsaPubKey,
    publicMeta: { tier: own.publicMeta.tier, createdAt: own.publicMeta.createdAt, commitmentHash: sha256(ciphertext) },
  };
  const envelope = { ...unsigned, mldsaSig: ml_dsa65.sign(serializeForSigning(unsigned), M.mldsaSecretKey) } as Envelope;
  return { envelope, share: grant(M, own, M, A.agentIdHash), dek };
}

interface Endpoint {
  url: string;
  requests: () => number;
  recalls: () => Record<string, unknown>[];
  close: () => Promise<void>;
}
/** A blind endpoint that answers every shared read with `answer`, counting every request it receives. */
async function endpoint(answer: unknown): Promise<Endpoint> {
  let requests = 0;
  const recalls: Record<string, unknown>[] = [];
  const server: Server = createServer((req, res) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => {
      requests++;
      const send = (status: number, body: unknown): void => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      if (req.method !== 'POST' || req.url !== '/mcp') return send(404, { error: 'not_found' });
      const m = JSON.parse(buf) as { method?: string; params?: Record<string, unknown> };
      if (m.method === 'saihm_recall' && m.params?.sharer !== undefined) {
        recalls.push(m.params);
        return send(200, answer);
      }
      return send(404, { error: 'unknown_method' });
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`,
    requests: () => requests,
    recalls: () => recalls,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}
const clientFor = (e: Endpoint) => new SaihmProClient(e.url, 'Bearer t', RECIPIENT_SEED, { tier: 'PRO' });
type Read = { sharerPinnedAgentIdHashHex: string; cellId: string; sharerRecord?: typeof RECORD_A };
const byId = (cellId: string, pin = PIN_A): Read => ({ sharerPinnedAgentIdHashHex: pin, cellId });
const withRecord = (cellId: string, pin = PIN_A, record = RECORD_A): Read => ({ sharerPinnedAgentIdHashHex: pin, cellId, sharerRecord: record });

/** A refusal with this code, whose sentence shows no key, record or agent ID (no run of 64 hex characters). */
async function refused(p: Promise<unknown>, code: string, label: string): Promise<void> {
  await assert.rejects(p, (e: unknown) => {
    assert.ok(e instanceof SaihmEndpointError, `${label}: ${String(e)}`);
    assert.equal(e.code, code, `${label}: ${e.message}`);
    assert.doesNotMatch(e.message, /[0-9a-f]{64}/i, `${label}: the sentence shows a key, a record or an agent ID`);
    return true;
  });
}

test('by agent ID alone: a real grant opens, the same cell as with the record, in the same requests', async () => {
  const env = seal(A, 'doc', 'shared note');
  const e = await endpoint(reply(grant(A, env), env));
  try {
    const client = clientFor(e);
    const plain = await client.recallShared(byId('doc'));
    const afterPlain = e.requests();
    const recorded = await client.recallShared(withRecord('doc'));
    const afterRecorded = e.requests();
    // A JavaScript caller's null is no record, as absent is.
    const nulled = await client.recallShared({ ...byId('doc'), sharerRecord: null } as unknown as Read);
    assert.equal(plain?.plaintext, 'shared note');
    assert.equal(plain?.seq, '1');
    assert.equal(plain?.commitmentHash, toHex(env.publicMeta.commitmentHash));
    // Whose memory it is travels with it (0.14.3 review 3): the pin its signing key was checked against.
    assert.equal(plain?.sharer, PIN_A);
    assert.deepEqual(plain, recorded, 'the same cell either way');
    assert.deepEqual(nulled, plain);
    // No new request: one shared read each, asking the endpoint the same thing.
    assert.equal(afterPlain, 1);
    assert.equal(afterRecorded - afterPlain, afterPlain);
    assert.equal(e.requests() - afterRecorded, afterPlain);
    assert.deepEqual(e.recalls(), [{ sharer: PIN_A, cellId: 'doc' }, { sharer: PIN_A, cellId: 'doc' }, { sharer: PIN_A, cellId: 'doc' }]);
  } finally {
    await e.close();
  }
});

test('a pin that is not 64 lowercase hex is refused before any request, with or without a record', async () => {
  const env = seal(A, 'doc', 'x');
  const e = await endpoint(reply(grant(A, env), env));
  try {
    const client = clientFor(e);
    const pins: unknown[] = ['', 'ab', PIN_A.slice(0, 62), PIN_A.slice(0, 63), PIN_A + '00', PIN_A.toUpperCase(), ` ${PIN_A.slice(1)}`, `0x${PIN_A.slice(2)}`, `${PIN_A}\n`, 7, null];
    for (const pin of pins) {
      for (const read of [{ sharerPinnedAgentIdHashHex: pin, cellId: 'doc' }, { sharerPinnedAgentIdHashHex: pin, cellId: 'doc', sharerRecord: RECORD_A }]) {
        await refused(client.recallShared(read as Read), 'bad_sharer', JSON.stringify(read).slice(0, 120));
      }
    }
    assert.equal(e.requests(), 0, 'no malformed pin reaches the endpoint');
    // Control: the same reads with the pin well formed go out.
    assert.equal((await client.recallShared(byId('doc')))?.plaintext, 'x');
    assert.equal(e.requests(), 1);
  } finally {
    await e.close();
  }
});

test("a key that does not hash to the pin is refused, before the share is read or anything decapsulated", async () => {
  const { envelope, share, dek } = forgeAsA('doc', 'forged as A');
  // Positive controls: the forgery is complete. Its signature, commitment and encryption are all consistent, and its
  // share verifies under the key it carries; only the binding of that key to A's agent ID fails.
  assert.ok(ml_dsa65.verify(envelope.mldsaSig, serializeForSigning(envelope), M.mldsaPubKey), 'control: M signed it');
  assert.deepEqual(sha256(envelope.ciphertext), envelope.publicMeta.commitmentHash, 'control: commitment holds');
  assert.equal(fromUtf8(openCellWithDek(envelope, dek)), 'forged as A', 'control: it opens under A\'s associated data');
  assert.ok(verifyShareSig(share, M.mldsaPubKey), 'control: the share verifies under the key the envelope carries');
  assert.notDeepEqual(sha256(M.mldsaPubKey), A.agentIdHash, 'control: that key is not A\'s');
  assert.equal(verifyEnvelope(envelope), false);
  const answers: [string, unknown][] = [
    ['the forged share', reply(share, envelope)],
    // The envelope is checked FIRST: a share that is malformed, or addressed to someone else, is never reached.
    ['a malformed share', { ...reply(share, envelope), wire: { schemaVer: 'x' } }],
    ['a share to another agent', reply(shareCell({ envelope: seal(M, 'doc', 'y'), sharerKek: M.kek, sharerMldsaSecretKey: M.mldsaSecretKey, sharerAgentIdHash: A.agentIdHash, recipientRecord: M.identityRecord, recipientPinnedAgentIdHash: M.agentIdHash }), envelope)],
  ];
  for (const [label, answer] of answers) {
    const e = await endpoint(answer);
    try {
      await refused(clientFor(e).recallShared(byId('doc')), 'sharer_key_mismatch', label);
      assert.equal(e.requests(), 1, label);
    } finally {
      await e.close();
    }
  }
  // With A's record the path is the one 0.14.2 had: the share is checked first, with the record's key, and M's
  // signature on it does not verify.
  const e = await endpoint(reply(share, envelope));
  try {
    await refused(clientFor(e).recallShared(withRecord('doc')), 'bad_share_sig', 'with the record');
  } finally {
    await e.close();
  }
});

test('a record and an envelope with different signing keys are refused, with or without the record', async () => {
  // A genuine share from A to B, served beside the forged envelope that claims A's agent ID but carries M's key.
  const genuine = seal(A, 'doc', 'the real note');
  const { envelope } = forgeAsA('doc', 'forged as A');
  const e = await endpoint(reply(grant(A, genuine), envelope));
  try {
    const client = clientFor(e);
    // With the record: the share passes under A's key, then the envelope's key is not the record's.
    await refused(client.recallShared(withRecord('doc')), 'sharer_key_mismatch', 'with the record');
    // Without it: the envelope's key does not hash to the pin.
    await refused(client.recallShared(byId('doc')), 'sharer_key_mismatch', 'by agent ID');
  } finally {
    await e.close();
  }
});

test('an envelope from another agent, or a wrong pin, is refused as foreign', async () => {
  // M's genuine cell and genuine share to B, answered to a read pinned to A: an endpoint substituting another sharer.
  const envM = seal(M, 'doc', "M's note");
  const e = await endpoint(reply(grant(M, envM), envM));
  try {
    const client = clientFor(e);
    await refused(client.recallShared(byId('doc')), 'foreign_envelope', 'by agent ID');
    // With A's record the share is checked first, as before, and names the wrong sharer.
    await refused(client.recallShared(withRecord('doc')), 'share_mismatch', 'with the record');
  } finally {
    await e.close();
  }
  // The agent pins the wrong agent ID (M's) for A's genuine cell: the envelope is not M's.
  const envA = seal(A, 'doc', "A's note");
  const e2 = await endpoint(reply(grant(A, envA), envA));
  try {
    await refused(clientFor(e2).recallShared(byId('doc', toHex(M.agentIdHash))), 'foreign_envelope', 'wrong pin');
  } finally {
    await e2.close();
  }
});

test('a share signed by another key is refused, with or without the record', async () => {
  // A's genuine envelope; the share names A as the sharer but M signed it.
  const env = seal(A, 'doc', "A's note");
  const e = await endpoint(reply(grant(A, env, M), env));
  try {
    const client = clientFor(e);
    await refused(client.recallShared(byId('doc')), 'bad_share_sig', 'by agent ID');
    await refused(client.recallShared(withRecord('doc')), 'bad_share_sig', 'with the record');
  } finally {
    await e.close();
  }
});

test('a tampered or substituted envelope is refused before its key is used', async () => {
  const env = seal(A, 'doc', "A's note");
  const share = grant(A, env);
  const tampered = { ...env, ciphertext: env.ciphertext.map((b, i) => (i === 0 ? b ^ 1 : b)) };
  const other = seal(A, 'other', "A's other note");
  const cases: [string, unknown, string][] = [
    ['a ciphertext changed', reply(share, tampered), 'unverified_envelope'],
    // Checked before the share: a malformed share beside it is never reached.
    ['a ciphertext changed, beside a malformed share', { ...reply(share, tampered), wire: { schemaVer: 'x' } }, 'unverified_envelope'],
    ["another of A's cells", reply(share, other), 'cell_mismatch'],
    ['an envelope that does not decode', { ...reply(share, env), contentWire: { schemaVer: 'x' } }, 'malformed_envelope'],
  ];
  for (const [label, answer, code] of cases) {
    const e = await endpoint(answer);
    try {
      await refused(clientFor(e).recallShared(byId('doc')), code, label);
    } finally {
      await e.close();
    }
  }
});

test('no content, or no live grant, is no shared cell, with or without the record', async () => {
  const env = seal(A, 'doc', 'never delivered');
  for (const answer of [{ found: true, wire: encodeShareEnvelope(grant(A, env)) }, { found: false }, { ...reply(grant(A, env), env), found: false }]) {
    const e = await endpoint(answer);
    try {
      const client = clientFor(e);
      assert.equal(await client.recallShared(byId('doc')), null, JSON.stringify(Object.keys(answer)));
      assert.equal(await client.recallShared(withRecord('doc')), null, JSON.stringify(Object.keys(answer)));
    } finally {
      await e.close();
    }
  }
});

test('a stale version: a share of an earlier version does not open the newer cell; a replayed old one opens as itself', async () => {
  const v1 = seal(A, 'doc', 'one', 1n);
  const v2 = seal(A, 'doc', 'two', 2n);
  const shareV1 = grant(A, v1);
  const e = await endpoint(reply(shareV1, v2));
  try {
    await refused(clientFor(e).recallShared(byId('doc')), 'undecryptable', 'by agent ID');
    await refused(clientFor(e).recallShared(withRecord('doc')), 'undecryptable', 'with the record');
  } finally {
    await e.close();
  }
  // Freshness is the endpoint's, as the method says: the old version and its share open, and seq says which it is.
  const e2 = await endpoint(reply(shareV1, v1));
  try {
    const cell = await clientFor(e2).recallShared(byId('doc'));
    assert.deepEqual([cell?.plaintext, cell?.seq], ['one', '1']);
  } finally {
    await e2.close();
  }
});

test("a record that is not the pinned agent's is refused before any request, as before", async () => {
  const env = seal(A, 'doc', 'x');
  const e = await endpoint(reply(grant(A, env), env));
  try {
    await assert.rejects(clientFor(e).recallShared(withRecord('doc', PIN_A, encodeIdentityRecord(M.identityRecord))), (err: unknown) => err instanceof KeySubstitutionError);
    // A record that does not decode is malformed.
    await refused(clientFor(e).recallShared(withRecord('doc', PIN_A, { ...RECORD_A, mldsaPubKey: 'zz' })), 'bad_sharer', 'record');
    assert.equal(e.requests(), 0);
  } finally {
    await e.close();
  }
});
