// recipientRecordFile (0.14.3): the identity record file saihm_share reads, so an agent never copies a record's ~13 KB
// of hex into a call. What these tests hold it to: only the exact document `identity-record` writes is accepted, from a
// regular file of at most 64 KB (a relative path read from the working directory, and a refusal of one saying so), whose
// record verifies against its own agent ID; a folder, a
// pipe, a device or a link to one is refused from its metadata, without blocking; the bound holds on what is read, not
// on the size a file reports; every refusal is a fixed sentence that names neither the path nor anything in the file.
// Runner: npx tsx --test tests/record_file.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import { accessSync, chmodSync, constants as fsConstants, existsSync, mkdirSync, mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { randomBytes } from 'node:crypto';
import { deriveIdentity, encodeIdentityRecord, toHex } from '@saihm/client-pro';
import { SaihmEndpointError } from '../src/client.js';
import { MAX_RECORD_FILE_BYTES, RECORD_FILE_REFUSED, readRecordFile } from '../src/record-file.js';

const POSIX = process.platform !== 'win32';

interface Doc {
  kind: unknown;
  version: unknown;
  agentIdHash: unknown;
  identityRecord: Record<string, unknown>;
  [k: string]: unknown;
}

/** A record document exactly as `identity-record` builds it, for a fresh identity. */
function recordDoc(): Doc {
  const id = deriveIdentity(randomBytes(32));
  const r = encodeIdentityRecord(id.identityRecord);
  return {
    kind: 'saihm-identity-record',
    version: 1,
    agentIdHash: toHex(id.agentIdHash),
    identityRecord: { mldsaPubKey: r.mldsaPubKey, mlkemPubKey: r.mlkemPubKey, mlkemPubKeySelfSig: r.mlkemPubKeySelfSig },
  };
}

/** As `identity-record` writes it: two-space JSON and a newline. */
const asWritten = (doc: unknown): string => JSON.stringify(doc, null, 2) + '\n';

/** A value with the shape of a secret, distinct per test, so a search for it cannot match anything else. */
const secretLike = (): string => randomBytes(32).toString('hex');

function refusal(path: string): SaihmEndpointError {
  try {
    readRecordFile(path);
  } catch (e) {
    if (e instanceof SaihmEndpointError) return e;
    throw e;
  }
  assert.fail('the file was accepted');
}

/** A refusal of the file, with its fixed reason, naming neither the path nor any of the strings given. */
function assertRefused(path: string, reason: RegExp, mustNotShow: string[] = []): void {
  const e = refusal(path);
  assert.equal(e.status, 0);
  assert.equal(e.code, RECORD_FILE_REFUSED);
  assert.match(e.message, /^Nothing was shared: recipientRecordFile /);
  assert.match(e.message, reason);
  for (const s of [path, ...mustNotShow]) assert.ok(!e.message.includes(s), 'the refusal shows nothing of the path or the file');
}

function scratch(): string {
  return mkdtempSync(join(tmpdir(), 'saihm-recfile-'));
}

const NOT_A_RECORD = /is not a SAIHM identity record \(the JSON file the identity-record command writes\)\.$/;
const NOT_REGULAR = /is not a regular file\.$/;
const TOO_LARGE = /is larger than an identity record can be \(64 KB\)\.$/;

test('a record file as identity-record writes it is read whole: the agent ID and the three public fields', () => {
  const dir = scratch();
  try {
    const doc = recordDoc();
    const p = join(dir, 'qa-agent.json');
    writeFileSync(p, asWritten(doc));
    assert.deepEqual(readRecordFile(p), { agentIdHash: doc.agentIdHash, identityRecord: doc.identityRecord });
    // Compact JSON is the same document.
    writeFileSync(join(dir, 'compact.json'), JSON.stringify(doc));
    assert.deepEqual(readRecordFile(join(dir, 'compact.json')).agentIdHash, doc.agentIdHash);
    // A byte-order mark is the decoder's, not the document's.
    writeFileSync(join(dir, 'bom.json'), String.fromCodePoint(0xfeff) + asWritten(doc));
    assert.equal(readRecordFile(join(dir, 'bom.json')).agentIdHash, doc.agentIdHash);
    if (POSIX) {
      // A link to a regular file is that file.
      symlinkSync(p, join(dir, 'link.json'));
      assert.equal(readRecordFile(join(dir, 'link.json')).agentIdHash, doc.agentIdHash);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the bound is 64 KB: a record padded to exactly that is read, one byte more is refused unread', () => {
  const dir = scratch();
  try {
    const doc = recordDoc();
    const text = asWritten(doc);
    const at = join(dir, 'at-bound.json');
    writeFileSync(at, text + ' '.repeat(MAX_RECORD_FILE_BYTES - Buffer.byteLength(text)));
    assert.equal(statSync(at).size, MAX_RECORD_FILE_BYTES);
    assert.equal(readRecordFile(at).agentIdHash, doc.agentIdHash);
    const over = join(dir, 'over.json');
    const secret = secretLike();
    writeFileSync(over, text + ' '.repeat(MAX_RECORD_FILE_BYTES - Buffer.byteLength(text)) + secret);
    assertRefused(over, TOO_LARGE, [secret]);
    writeFileSync(join(dir, 'big.json'), 'x'.repeat(10 * MAX_RECORD_FILE_BYTES));
    assertRefused(join(dir, 'big.json'), TOO_LARGE);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** /proc/kallsyms where this user may read it: a regular file that reports a size of 0 and holds megabytes. */
function kallsymsReadable(): boolean {
  try {
    if (!existsSync('/proc/kallsyms') || statSync('/proc/kallsyms').size !== 0) return false;
    accessSync('/proc/kallsyms', fsConstants.R_OK);
    return true;
  } catch {
    return false;
  }
}

test('the bound holds on what is read: a file that reports no size is cut one byte past it and refused', { skip: !kallsymsReadable() }, () => {
  // /proc files report a size of 0 whatever they hold; this one holds megabytes of kernel symbol names.
  assertRefused('/proc/kallsyms', TOO_LARGE);
  // Positive control: the same file is a regular file, so the size check alone would have let it through.
  assert.ok(statSync('/proc/kallsyms').isFile());
});

test('a folder, a pipe, a device, and a link to any of them is refused from its metadata, without blocking', { skip: !POSIX }, () => {
  const dir = scratch();
  try {
    const folder = join(dir, 'folder.json');
    mkdirSync(folder);
    assertRefused(folder, NOT_REGULAR);
    const fifo = join(dir, 'pipe.json');
    execFileSync('mkfifo', ['-m', '600', fifo]);
    const t0 = Date.now();
    assertRefused(fifo, NOT_REGULAR);
    assert.ok(Date.now() - t0 < 2000, 'a pipe with no writer does not block the read');
    assertRefused('/dev/null', NOT_REGULAR);
    for (const [name, target] of [
      ['to-pipe.json', fifo],
      ['to-folder.json', folder],
      ['to-zero.json', '/dev/zero'],
      ['to-null.json', '/dev/null'],
    ] as const) {
      symlinkSync(target, join(dir, name));
      const t = Date.now();
      assertRefused(join(dir, name), NOT_REGULAR);
      assert.ok(Date.now() - t < 2000, `${name} does not block`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a missing file, a dangling link and an unreadable file are refused with the system code only', () => {
  const dir = scratch();
  try {
    assertRefused(join(dir, 'missing.json'), /could not be read \(ENOENT\)\.$/);
    if (POSIX) {
      symlinkSync(join(dir, 'nowhere.json'), join(dir, 'dangling.json'));
      assertRefused(join(dir, 'dangling.json'), /could not be read \(ENOENT\)\.$/);
      if (process.getuid?.() !== 0) {
        const locked = join(dir, 'locked.json');
        writeFileSync(locked, asWritten(recordDoc()));
        chmodSync(locked, 0o000);
        assertRefused(locked, /could not be read \(EACCES\)\.$/);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a relative path is read from the working directory; a refusal of one says so, and one of a full path does not', () => {
  const dir = scratch();
  try {
    const doc = recordDoc();
    const p = join(dir, 'qa-agent.json');
    writeFileSync(p, asWritten(doc));
    const rel = relative(process.cwd(), p);
    for (const q of [rel, './' + rel]) assert.equal(readRecordFile(q).agentIdHash, doc.agentIdHash, q);
    const relativeHint = /; a relative path is read from the server's working directory, so give the full path\.$/;
    // `~` is not expanded, and a name that is not in the working directory is not looked for elsewhere.
    for (const q of ['~/qa-agent.json', 'qa-agent-nowhere.json']) assertRefused(q, relativeHint);
    assertRefused('~/qa-agent.json', /could not be read \(ENOENT\); a relative path/);
    const folder = join(dir, 'records');
    mkdirSync(folder);
    assertRefused(relative(process.cwd(), folder), /is not a regular file; a relative path/);
    writeFileSync(join(dir, 'not-a-record.json'), '{}');
    assertRefused(relative(process.cwd(), join(dir, 'not-a-record.json')), /is not a SAIHM identity record .*; a relative path/);
    // A full path's refusal carries no such hint.
    const e = refusal(join(dir, 'qa-agent-nowhere.json'));
    assert.doesNotMatch(e.message, /relative path/);
    assert.match(e.message, /could not be read \(ENOENT\)\.$/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a file that is not JSON is refused with a fixed reason: a secret in it never appears, nor the parser\'s quote of it', () => {
  const dir = scratch();
  try {
    const secret = secretLike();
    const cases: [string, string | Buffer][] = [
      ['env', `SAIHM_MASTER_SECRET_HEX=${secret}\n`],
      ['bare-hex', secret],
      ['digits', '1234567890'.repeat(8)],
      ['truncated', asWritten(recordDoc()).slice(0, 200) + secret],
      ['empty', ''],
      ['not-utf8', Buffer.concat([Buffer.from('{"kind":"'), Buffer.from([0xff, 0xfe, 0xc0]), Buffer.from(`${secret}"}`)])],
    ];
    for (const [name, body] of cases) {
      const p = join(dir, `${name}.json`);
      writeFileSync(p, body);
      assertRefused(p, NOT_A_RECORD, [secret, secret.slice(0, 10), 'SAIHM_MASTER', 'Unexpected', 'JSON at position']);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a record written as UTF-16 (a PowerShell redirect) is refused with a sentence that says so; UTF-8 with a mark is read', () => {
  const dir = scratch();
  try {
    const doc = recordDoc();
    const text = asWritten(doc);
    const le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]);
    const be = Buffer.from(le);
    be.swap16();
    const UTF16 = /is UTF-16 text, as a PowerShell redirect writes it: have it written with identity-record FILE, or save it as UTF-8\.$/;
    for (const [name, body] of [['le', le], ['be', be]] as const) {
      const p = join(dir, `utf16${name}.json`);
      writeFileSync(p, body);
      assertRefused(p, UTF16, [doc.agentIdHash, doc.agentIdHash.slice(0, 10)]);
    }
    // A relative path keeps its hint.
    const rel = relative(process.cwd(), join(dir, 'utf16le.json'));
    assertRefused(rel, /is UTF-16 text, .*; a relative path is read from the server's working directory, so give the full path\.$/);
    // Controls: the same record as UTF-8, with and without its mark, is read.
    writeFileSync(join(dir, 'utf8.json'), text);
    writeFileSync(join(dir, 'utf8bom.json'), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text, 'utf8')]));
    assert.equal(readRecordFile(join(dir, 'utf8.json')).agentIdHash, doc.agentIdHash);
    assert.equal(readRecordFile(join(dir, 'utf8bom.json')).agentIdHash, doc.agentIdHash);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a document that is not exactly the record is refused, and nothing in it is shown', () => {
  const dir = scratch();
  try {
    const secret = secretLike();
    const base = recordDoc();
    const rec = base.identityRecord;
    const variants: [string, unknown][] = [
      ['extra top-level field', { ...base, note: secret }],
      ['extra record field', { ...base, identityRecord: { ...rec, mlkemSecretKey: secret } }],
      ['no kind', { version: 1, agentIdHash: base.agentIdHash, identityRecord: rec }],
      ['another kind', { ...base, kind: secret }],
      ['version 2', { ...base, version: 2 }],
      ['version as text', { ...base, version: '1' }],
      ['agent ID in capitals', { ...base, agentIdHash: String(base.agentIdHash).toUpperCase() }],
      ['short agent ID', { ...base, agentIdHash: secret.slice(0, 62) }],
      ['agent ID not hex', { ...base, agentIdHash: 'z' + secret.slice(1) }],
      ['a key cut short', { ...base, identityRecord: { ...rec, mldsaPubKey: String(rec.mldsaPubKey).slice(0, 100) } }],
      ['a key not hex', { ...base, identityRecord: { ...rec, mlkemPubKey: secret + 'g'.repeat(2368 - 64) } }],
      ['a field missing', { ...base, identityRecord: { mldsaPubKey: rec.mldsaPubKey, mlkemPubKey: rec.mlkemPubKey } }],
      ['a field a number', { ...base, identityRecord: { ...rec, mlkemPubKeySelfSig: 7 } }],
      ['record as a list', { ...base, identityRecord: [rec.mldsaPubKey, rec.mlkemPubKey, rec.mlkemPubKeySelfSig] }],
      ['the record alone', rec],
      ['a list', [base]],
      ['null', null],
      ['a string', secret],
    ];
    for (const [name, doc] of variants) {
      const p = join(dir, name.replace(/ /g, '-') + '.json');
      writeFileSync(p, asWritten(doc));
      assertRefused(p, NOT_A_RECORD, [secret, secret.slice(0, 10)]);
    }
    // An own __proto__ key, which JSON.parse makes a property like any other: one field too many.
    const proto = join(dir, 'proto.json');
    writeFileSync(proto, asWritten(base).replace('{\n', `{\n  "__proto__": {"x": "${secret}"},\n`));
    assertRefused(proto, NOT_A_RECORD, [secret]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a record that does not verify against its own agent ID is refused before anything is bound to it', () => {
  const dir = scratch();
  try {
    const secret = secretLike();
    const doc = recordDoc();
    const forged = join(dir, 'forged.json');
    writeFileSync(forged, asWritten({ ...doc, agentIdHash: secret }));
    const notVerified = /holds a record that does not verify \(its agent ID, keys and signature do not match\): ask your colleague for a new one\.$/;
    assertRefused(forged, notVerified, [secret, secret.slice(0, 10)]);
    // Another identity's KEM key with this identity's signing key: the self-signature does not cover it.
    const other = recordDoc();
    const swapped = join(dir, 'swapped.json');
    writeFileSync(swapped, asWritten({ ...doc, identityRecord: { ...doc.identityRecord, mlkemPubKey: other.identityRecord.mlkemPubKey } }));
    assertRefused(swapped, notVerified);
    // One signature byte changed.
    const sig = String(doc.identityRecord.mlkemPubKeySelfSig);
    const flipped = join(dir, 'flipped.json');
    const at = 200;
    writeFileSync(
      flipped,
      asWritten({ ...doc, identityRecord: { ...doc.identityRecord, mlkemPubKeySelfSig: sig.slice(0, at) + (sig[at] === '0' ? '1' : '0') + sig.slice(at + 1) } }),
    );
    assertRefused(flipped, notVerified);
    // Positive control: the unaltered document verifies.
    const good = join(dir, 'good.json');
    writeFileSync(good, asWritten(doc));
    assert.equal(readRecordFile(good).agentIdHash, doc.agentIdHash);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
