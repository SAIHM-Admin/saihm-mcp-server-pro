// Coverage for src/erasure-feed.ts — the GDPR Art.17 cascade feed, one NDJSON line per erasure.
//
// The REFUSALS carry the weight here, not the happy path. Every bound in this module exists because
// the failure it prevents is SILENT: a relative root scatters the feed while a consumer reports it
// absent, a foreign identity line is discarded as a wiring fault, a `complete:true` with no anchor is
// discarded as malformed, and a truncated line corrupts its successor as well as itself. None of
// those throw on their own, and none of them are visible in the artifact afterwards — which is
// exactly why a test that only proves a line gets written has not tested this module.
//
// Every refusal below is paired with a POSITIVE CONTROL in the same test: the identical call with
// the one bad input corrected, asserted to SUCCEED. Without that pair a refusal test passes equally
// well when the function is broken for some unrelated reason, which is the failure mode this suite
// is meant to catch rather than reproduce.
// Runner: npx tsx --test tests/erasure_feed.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ErasureFeedError,
  FEED_VERSION,
  MAX_FEED_CELL_ID_CHARS,
  MAX_FEED_LINE_BYTES,
  appendFeedLine,
  assertTenantDirUnshared,
  buildFeedLine,
  emitErasureLine,
  emitErasureLineReporting,
  ensureTenantDir,
  feedPathFor,
  resolveFeedRoot,
} from '../src/erasure-feed.js';
import type { ErasureFeedRecord } from '../src/erasure-feed.js';

const ID = 'a'.repeat(64);
const AT = '2026-09-11T00:00:00.000Z';

const rec = (over: Partial<ErasureFeedRecord> = {}): ErasureFeedRecord => ({
  cellId: 'cell-1',
  agentIdHash: ID,
  at: AT,
  complete: false,
  source: 'mcp-client',
  ...over,
});

/** A fresh directory, removed by the caller's `finally`. */
const tmp = (): string => mkdtempSync(join(tmpdir(), 'saihm-feed-'));

/** Assert `fn` throws ErasureFeedError, and return the message so a test can assert what it NAMES. */
const refused = (fn: () => unknown, label: string): string => {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof ErasureFeedError, `${label}: threw ${String(e)}, not an ErasureFeedError`);
    return (e as Error).message;
  }
  assert.fail(`${label}: did not refuse`);
};

test('the root follows the IDENTITY chain, and SAIHM_STATE_DIR is not on it', () => {
  const explicit = tmp();
  const home = tmp();
  const state = tmp();
  try {
    // Precedence, each step proved against the one below it rather than in isolation.
    assert.equal(
      resolveFeedRoot({ SAIHM_ERASURE_FEED_DIR: explicit, SAIHM_HOME: home, SAIHM_STATE_DIR: state }),
      explicit,
    );
    assert.equal(resolveFeedRoot({ SAIHM_HOME: home, SAIHM_STATE_DIR: state }), home);
    // THE DELIBERATE OMISSION, as a test rather than as a comment. `SAIHM_STATE_DIR` is set here and
    // set to a real directory, so a reader that honoured it would resolve to it and this would fail.
    // With neither identity variable set the root falls back to `~/.saihm`, which is what the
    // `startsWith` below asserts WITHOUT writing anything to a real home.
    const fallback = resolveFeedRoot({ SAIHM_STATE_DIR: state });
    assert.ok(
      !fallback.startsWith(state),
      'SAIHM_STATE_DIR reached the feed root. It governs one relocatable artifact, not an identity; ' +
        'honouring it splits one identity feed across two roots the first time an operator sets it',
    );
    assert.ok(fallback.endsWith('.saihm'), `fallback root is ${fallback}, not a ~/.saihm`);
  } finally {
    for (const d of [explicit, home, state]) rmSync(d, { recursive: true, force: true });
  }
});

test('a RELATIVE root is refused, and the refusal names the variable that was wrong', () => {
  const abs = tmp();
  try {
    // POSITIVE CONTROL first: the same call with an absolute value returns it, so the refusals below
    // are about the relative-ness and not about the function being broken for every input.
    assert.equal(resolveFeedRoot({ SAIHM_ERASURE_FEED_DIR: abs }), abs);

    const a = refused(() => resolveFeedRoot({ SAIHM_ERASURE_FEED_DIR: './feed' }), 'relative explicit');
    assert.match(a, /SAIHM_ERASURE_FEED_DIR/);
    assert.doesNotMatch(a, /SAIHM_HOME/, 'the refusal named the variable the caller did not set');

    // The SAME wrong value under the OTHER variable must name the OTHER variable. A message that
    // names whichever variable the code checked first sends an operator to edit the wrong line.
    const h = refused(() => resolveFeedRoot({ SAIHM_HOME: './feed' }), 'relative home');
    assert.match(h, /SAIHM_HOME/);
    assert.doesNotMatch(h, /SAIHM_ERASURE_FEED_DIR/);

    // An EMPTY explicit value is not an absent one. `??` only falls through on undefined, so an
    // operator who exports the variable with nothing in it gets a refusal, not a silent fallback to
    // `SAIHM_HOME` — which would write this identity's feed somewhere they did not name.
    assert.match(
      refused(() => resolveFeedRoot({ SAIHM_ERASURE_FEED_DIR: '', SAIHM_HOME: abs }), 'empty explicit'),
      /SAIHM_ERASURE_FEED_DIR/,
    );
  } finally {
    rmSync(abs, { recursive: true, force: true });
  }
});

test('the path is partitioned by identity, and a malformed identity is refused', () => {
  // POSITIVE CONTROL: the well-formed case produces the documented shape.
  assert.equal(feedPathFor('/r', ID), join('/r', 'tenants', ID, 'erasures.ndjson'));
  // Case is normalised rather than refused: the same identity spelled two ways must not open two
  // feeds, because a consumer keyed on the directory name would read them as two tenants.
  assert.equal(feedPathFor('/r', ID.toUpperCase()), feedPathFor('/r', ID));

  for (const [label, bad] of [
    ['too short', 'a'.repeat(63)],
    ['too long', 'a'.repeat(65)],
    ['non-hex', 'g'.repeat(64)],
    ['empty', ''],
    // TRAVERSAL, which is the reason this is a refusal and not a warning: the identity is a PATH
    // SEGMENT, so a value carrying separators or dots escapes the tenant partition entirely and
    // writes one identity's erasures into another's directory, or out of the root altogether.
    ['traversal', '../'.repeat(21) + 'a'],
    ['separator', 'a'.repeat(31) + '/' + 'a'.repeat(32)],
  ] as const)
    assert.match(
      refused(() => feedPathFor('/r', bad), `identity ${label}`),
      /64 lowercase hex/,
      `identity ${label} was not refused with the identity reason`,
    );
});

test('a line is byte-stable, carries no `epoch`, and states its version', () => {
  const line = buildFeedLine(rec());
  assert.ok(line.endsWith('\n'), 'a feed line must terminate its own NDJSON record');
  assert.equal(line, buildFeedLine(rec()), 'the same record serialised to two different lines');
  const o = JSON.parse(line) as Record<string, unknown>;
  // The KEY SET, asserted whole rather than field by field. An extra key is how a value reaches a
  // consumer without anyone deciding it should, and asserting presence alone never catches one.
  assert.deepEqual(Object.keys(o), ['v', 'cellId', 'agentIdHash', 'at', 'complete', 'source']);
  assert.equal(o['v'], FEED_VERSION);
  // `epoch` by NAME, because both `ForgetResult` types carry one and the consumer's `epoch` is HOURS
  // since 1970. A seconds- or millisecond-valued copy is a well-formed number that is wrong by orders
  // of magnitude and therefore never errors anywhere — it is omitted so there is nothing to convert
  // wrongly, and this line is what stops it being added back as an obvious convenience.
  assert.ok(!('epoch' in o), 'an `epoch` reached the wire; the consumer derives time from `at`');
  // The identity is lower-cased ON THE WIRE too, not only in the path. A consumer that compares the
  // line's `agentIdHash` against the directory it found the line in must see one spelling.
  assert.equal(buildFeedLine(rec({ agentIdHash: ID.toUpperCase() })), line);
});

test('`complete:true` without a verbatim anchor is REFUSED, not downgraded', () => {
  // POSITIVE CONTROL: with an anchor the same record builds, and the anchor reaches the wire.
  const ok = JSON.parse(buildFeedLine(rec({ complete: true, destructionAnchor: 'anchor-1' }))) as Record<string, unknown>;
  assert.equal(ok['complete'], true);
  assert.equal(ok['destructionAnchor'], 'anchor-1');
  assert.deepEqual(Object.keys(ok), ['v', 'cellId', 'agentIdHash', 'at', 'complete', 'destructionAnchor', 'source']);

  // REFUSED rather than silently rewritten to `complete:false`. A downgrade would be a line the
  // consumer accepts and applies, describing an erasure regime that is not the one that ran — and the
  // site that emitted it would never learn it had claimed something it could not evidence.
  for (const [label, anchor] of [['absent', undefined], ['empty', '']] as const)
    assert.match(
      refused(() => buildFeedLine(rec({ complete: true, ...(anchor === undefined ? {} : { destructionAnchor: anchor }) })), `anchor ${label}`),
      /destructionAnchor/,
      `complete:true with an ${label} anchor was not refused`,
    );

  // An anchor WITHOUT `complete` is carried, not stripped. A site that can evidence destruction but
  // does not claim completeness is describing a real state, and the consumer reads both fields.
  assert.equal(
    (JSON.parse(buildFeedLine(rec({ destructionAnchor: 'a' }))) as Record<string, unknown>)['destructionAnchor'],
    'a',
  );
});

test('the caller-chosen cellId is bounded, and the bound is a REFUSAL', () => {
  // POSITIVE CONTROL at the exact ceiling, so the refusal below is about crossing it and not about
  // the check being off by one in the direction that rejects everything.
  assert.ok(buildFeedLine(rec({ cellId: 'c'.repeat(MAX_FEED_CELL_ID_CHARS) })).length > 0);
  for (const [label, id] of [
    ['empty', ''],
    ['one over', 'c'.repeat(MAX_FEED_CELL_ID_CHARS + 1)],
    ['hostile', 'c'.repeat(5000)],
  ] as const)
    assert.match(refused(() => buildFeedLine(rec({ cellId: id })), `cellId ${label}`), /cellId is/);

  // NEVER TRUNCATED, and this is the assertion that says so rather than a comment claiming it. A
  // truncated cellId is not a shorter pointer, it is a DIFFERENT one, and a consumer that matches it
  // purges an artifact derived from some other cell.
  const long = 'c'.repeat(MAX_FEED_CELL_ID_CHARS + 1);
  const m = refused(() => buildFeedLine(rec({ cellId: long })), 'cellId truncation');
  assert.ok(!m.includes(long.slice(0, MAX_FEED_CELL_ID_CHARS)), 'the refusal echoed a cut cellId back');
});

test('an OVERSIZE line is refused whole, and leaves the file it would have corrupted alone', () => {
  const root = tmp();
  try {
    const path = feedPathFor(root, ID);
    // A first, good line, so the assertion below is about PRESERVING a file rather than about one
    // that was never written.
    appendFeedLine(path, buildFeedLine(rec({ cellId: 'first' })));
    const before = readFileSync(path);

    // The only field that can still blow the budget once `cellId` is bounded is the anchor, which
    // comes from an erasure receipt rather than from a caller. It is the blind-endpoint site's input,
    // so this is the shape that site has to survive.
    const huge = rec({ complete: true, destructionAnchor: 'z'.repeat(MAX_FEED_LINE_BYTES) });
    const msg = refused(() => buildFeedLine(huge), 'oversize line');
    assert.match(msg, new RegExp(String(MAX_FEED_LINE_BYTES)));
    assert.match(msg, /REFUSED, not/);
    // Nothing was written, and — the part that matters — the PREVIOUS line is untouched. A truncating
    // writer corrupts the record it cuts and the one after it, and neither is visible in a byte count.
    assert.deepEqual(readFileSync(path), before, 'the refused line still reached the file');

    // And the file remains parseable as NDJSON afterwards, which is the property the refusal buys.
    const lines = readFileSync(path, 'utf8').split('\n').filter((l) => l !== '');
    assert.equal(lines.length, 1);
    assert.equal((JSON.parse(lines[0] as string) as Record<string, unknown>)['cellId'], 'first');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('appends are APPEND-ONLY, private, and never rewrite what is already there', () => {
  const root = tmp();
  try {
    const path = feedPathFor(root, ID);
    const first = buildFeedLine(rec({ cellId: 'one' }));
    appendFeedLine(path, first);
    appendFeedLine(path, buildFeedLine(rec({ cellId: 'two' })));
    const text = readFileSync(path, 'utf8');
    assert.ok(text.startsWith(first), 'the second append rewrote the first line');
    assert.deepEqual(
      text.split('\n').filter((l) => l !== '').map((l) => (JSON.parse(l) as Record<string, unknown>)['cellId']),
      ['one', 'two'],
    );
    // MODES. The feed names an identity and the cells it erased, which is exactly the metadata an
    // erasure is supposed to remove the need for. 0600/0700 or it is a disclosure.
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(statSync(join(root, 'tenants', ID)).mode & 0o777, 0o700);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('ensureTenantDir creates the DIRECTORY and deliberately not the file', () => {
  const root = tmp();
  try {
    const path = ensureTenantDir(ID, { SAIHM_ERASURE_FEED_DIR: root });
    assert.equal(path, feedPathFor(root, ID));
    assert.ok(statSync(join(root, 'tenants', ID)).isDirectory(), 'the tenant directory was not created');
    // NOT the file. An empty `erasures.ndjson` and a never-written one are indistinguishable to a
    // reader, so creating one asserts an erasure history that does not exist; the directory alone
    // carries "this identity is wired", which is all a consumer needs to arm a watch.
    assert.ok(!existsSync(path), 'ensureTenantDir created the feed file');
    // IDEMPOTENT, because it runs on every boot of a process that may have run before.
    assert.equal(ensureTenantDir(ID, { SAIHM_ERASURE_FEED_DIR: root }), path);
    // It refuses the same inputs the path builder refuses, rather than making a directory first and
    // discovering the identity was malformed at the first erasure.
    refused(() => ensureTenantDir('nope', { SAIHM_ERASURE_FEED_DIR: root }), 'ensureTenantDir bad identity');
    refused(() => ensureTenantDir(ID, { SAIHM_ERASURE_FEED_DIR: 'relative' }), 'ensureTenantDir relative root');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('the two emit entry points differ in ONE way: which of them throws', () => {
  const root = tmp();
  try {
    const env = { SAIHM_ERASURE_FEED_DIR: root };
    // SUCCESS is identical on both, including the file each one produced — so the difference asserted
    // below is genuinely about failure handling and not about them being two different writers.
    assert.equal(emitErasureLine(rec({ cellId: 'thrower' }), env), feedPathFor(root, ID));
    assert.equal(emitErasureLineReporting(rec({ cellId: 'reporter' }), env), undefined);
    assert.deepEqual(
      readFileSync(feedPathFor(root, ID), 'utf8').split('\n').filter((l) => l !== '')
        .map((l) => (JSON.parse(l) as Record<string, unknown>)['cellId']),
      ['thrower', 'reporter'],
    );

    // THE PRE-ERASE SITE throws, because there the failure must fail the forget: an erasure nothing
    // downstream was told about is a false "erased", and it is only preventable before the erase.
    refused(() => emitErasureLine(rec({ cellId: '' }), env), 'emitErasureLine on a bad record');

    // THE POST-ERASE SITE never throws, because there the erasure is already irreversible and an
    // exception would report a FAILED forget on a cell that is gone — the worst direction to be wrong
    // in on this tool. It reports instead of either throwing or going quiet.
    const why = emitErasureLineReporting(rec({ cellId: '' }), env);
    assert.equal(typeof why, 'string');
    assert.match(why as string, /complete and irreversible/);
    assert.match(why as string, /cellId is/, 'the report dropped the reason it was reporting');

    // ...and on an UNWRITABLE path too, which is the failure an operator can actually cause. A file
    // where the tenant directory should be makes mkdir fail with something Node wrote, not something
    // this module composed, so it proves the catch is not keyed on ErasureFeedError alone.
    const blocked = tmp();
    try {
      writeFileSync(join(blocked, 'tenants'), 'not a directory');
      const io = emitErasureLineReporting(rec(), { SAIHM_ERASURE_FEED_DIR: blocked });
      assert.equal(typeof io, 'string', 'an I/O failure escaped the reporting variant');
      assert.match(io as string, /complete and irreversible/);
    } finally {
      rmSync(blocked, { recursive: true, force: true });
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});


// A test that calls `forget()` without pinning the feed writes a REAL erasure line into the home of
// whoever runs this suite: the root falls through to `$HOME/.saihm`, and `-pro`'s standing invariant
// is that nothing here touches a developer's home. This is DERIVED, not a list - it re-reads the
// test directory on every run, so a file added tomorrow is held to the same rule without anyone
// remembering to come back here. The needle is assembled rather than written so this file does not
// match itself.
test('every test that forgets pins the feed root away from $HOME', () => {
  const dir = new URL('.', import.meta.url).pathname;
  const files = readdirSync(dir).filter((f) => f.endsWith('.test.ts'));
  assert.ok(
    files.length >= 10,
    `the enumeration found ${files.length} test files; it is mis-scoped and would pass vacuously`,
  );

  const needle = '.' + 'forget(';
  const read = (f: string): string => readFileSync(join(dir, f), 'utf8');
  const forgets = files.filter((f) => read(f).includes(needle));
  assert.ok(
    forgets.length > 0,
    'no test file calls forget() - this guard has nothing to range over and proves nothing',
  );

  const unpinned = forgets.filter((f) => !/process\.env\.SAIHM_ERASURE_FEED(_DIR)?\s*=/.test(read(f)));
  assert.deepEqual(
    unpinned,
    [],
    `these tests call forget() with the feed root unpinned, so running the suite appends erasure ` +
      `lines to the runner's own ~/.saihm/tenants: ${unpinned.join(', ')}`,
  );
});


// Sankofa asked for this refusal on the WRITER side (ERASURE-FEED-0911c): her consumer hard-codes
// `tenants/<identity>/erasures.ndjson` and will not rename, so the writer is the half that can
// notice it is about to append into a directory some other store already owns. Every refusal arm
// here is paired with the permissive arm next to it - a guard that refuses everything would pass
// the refusal assertions alone and would silently stop every erasure from being recorded.
test('a tenant directory that belongs to another store is refused, an empty or our own one is not', () => {
  const root = tmp();
  try {
    const dirOf = (id: string): string => join(root, 'tenants', id);

    // ARM 1 - no directory at all: this feed is the one about to create it.
    assertTenantDirUnshared(root, ID);

    // ARM 2 - the directory exists and is EMPTY. `ensureTenantDir` creates exactly this, so a
    // refusal here would refuse the feed's own boot path on the second call.
    mkdirSync(dirOf(ID), { recursive: true });
    assertTenantDirUnshared(root, ID);
    assert.equal(ensureTenantDir(ID, { SAIHM_ERASURE_FEED_DIR: root }), feedPathFor(root, ID));

    // ARM 3 - the REFUSAL: state present, no feed. This is the collision shape.
    const other = 'b'.repeat(64);
    mkdirSync(dirOf(other), { recursive: true });
    writeFileSync(join(dirOf(other), 'store1.json'), '{}');
    const why = refused(() => assertTenantDirUnshared(root, other), 'foreign tenant dir');
    assert.match(why, /belongs to some other store/);
    assert.ok(why.includes(dirOf(other)), 'the refusal did not name the directory it refused');

    // ...and it refuses at BOTH entry points, not only the one the test happened to call.
    refused(() => ensureTenantDir(other, { SAIHM_ERASURE_FEED_DIR: root }), 'ensureTenantDir');
    refused(
      () => emitErasureLine(rec({ agentIdHash: other }), { SAIHM_ERASURE_FEED_DIR: root }),
      'emitErasureLine',
    );
    // The refusal must leave the other store untouched - no feed file, nothing added.
    assert.deepEqual(readdirSync(dirOf(other)), ['store1.json']);

    // ARM 4 - the SAME directory once the feed is in it: ours, so a neighbour no longer blocks an
    // erasure. Without this arm the guard would break rotation and backups, refusing real lines.
    writeFileSync(join(dirOf(other), 'erasures.ndjson'), '');
    assertTenantDirUnshared(root, other);
    emitErasureLine(rec({ agentIdHash: other }), { SAIHM_ERASURE_FEED_DIR: root });
    assert.equal(readFileSync(join(dirOf(other), 'erasures.ndjson'), 'utf8').trim().length > 0, true);

    // ARM 5 - the reporting variant carries the refusal as a sentence instead of throwing, which is
    // what the client's non-fatal emit relies on.
    const foreign = 'c'.repeat(64);
    mkdirSync(dirOf(foreign), { recursive: true });
    writeFileSync(join(dirOf(foreign), 'store1.json'), '{}');
    const said = emitErasureLineReporting(rec({ agentIdHash: foreign }), {
      SAIHM_ERASURE_FEED_DIR: root,
    });
    assert.equal(typeof said, 'string', 'the reporting variant threw instead of reporting');
    assert.match(said as string, /belongs to some other store/);
    assert.equal(existsSync(join(dirOf(foreign), 'erasures.ndjson')), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// A feed line is written through a loop now, because `writeSync` is allowed to write fewer bytes
// than it was handed and this file's whole argument is that a half-record never reaches the disk.
// A loop over a Buffer is offset arithmetic, and offset arithmetic is where a multi-byte character
// gets sliced in half — so the shape this pins is the one the change could plausibly break: several
// appends, non-ASCII among them and one close to the ceiling, compared as BYTES rather than as
// parsed objects. Parsing first would hide the failure, because a corrupted tail still parses if the
// corruption lands past the last brace.
test('appended lines are byte-exact across multi-byte content and repeated appends', () => {
  const root = tmp();
  try {
    const path = feedPathFor(root, ID);
    const bodies = [
      '{"n":1}',
      '{"n":"é中文🔒"}',
      '{"n":"' + 'z'.repeat(MAX_FEED_LINE_BYTES - 20) + '"}',
      '{"n":"é"}',
    ];
    const lines = bodies.map((b) => b + '\n');
    for (const l of lines) appendFeedLine(path, l);

    assert.deepEqual(
      readFileSync(path),
      Buffer.from(lines.join(''), 'utf8'),
      'the file is not the exact concatenation of what was appended',
    );
    const back = readFileSync(path, 'utf8').split('\n').filter((l) => l !== '');
    assert.equal(back.length, lines.length, 'a line was lost or split');
    assert.equal(
      (JSON.parse(back[1] as string) as Record<string, unknown>)['n'],
      'é中文🔒',
      'a multi-byte character did not survive the write loop intact',
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
