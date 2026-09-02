// Coverage for sweepStaleIdentityTemps (src/client.ts) — the bounded sweep that closes the ONE
// partial-state hole tmp-then-rename leaves open: a SIGKILL between the atomic write and the
// rename strands a mode-600 file containing the master secret, which nothing else ever removes.
//
// This function DELETES FILES, so the negative cases carry the weight. Each bound in its contract
// is tested by constructing the thing it must refuse to delete: a fresh temp (a concurrent mint),
// the real key file, an unrelated neighbour, a symlink, and another user's file where that can be
// simulated. A sweep that passes only its happy path has not been tested.
// Runner: npx tsx --test tests/client_stale_temp_sweep.test.ts
import { test } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, symlinkSync, utimesSync, lutimesSync, rmSync, readFileSync, lstatSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sweepStaleIdentityTemps, STALE_TEMP_MIN_AGE_MS, ensureSelfJoinIdentityEnv } from '../src/client.js';

const NOW = Date.now();
const OLD = NOW - STALE_TEMP_MIN_AGE_MS - 60_000; // comfortably past the threshold
const FRESH = NOW - 1_000;

function agedFile(path: string, contents: string, whenMs: number): void {
  writeFileSync(path, contents, { mode: 0o600 });
  const s = whenMs / 1000;
  utimesSync(path, s, s);
}

function fixture(): { dir: string; keyPath: string } {
  const dir = mkdtempSync(join(tmpdir(), 'saihm-sweep-'));
  return { dir, keyPath: join(dir, 'identity.key') };
}

test('sweeps a stale orphan left by a hard kill', () => {
  const { dir, keyPath } = fixture();
  const orphan = `${keyPath}.tmp.4242.${OLD}`;
  agedFile(orphan, 'deadbeef'.repeat(8), OLD);
  assert.equal(sweepStaleIdentityTemps(keyPath, NOW), 1);
  assert.equal(existsSync(orphan), false);
  rmSync(dir, { recursive: true, force: true });
});

test('NEGATIVE: leaves a FRESH temp alone — it may be a live mint mid-rename', () => {
  const { dir, keyPath } = fixture();
  const live = `${keyPath}.tmp.9999.${FRESH}`;
  agedFile(live, 'in-flight', FRESH);
  assert.equal(sweepStaleIdentityTemps(keyPath, NOW), 0);
  assert.equal(existsSync(live), true);
  rmSync(dir, { recursive: true, force: true });
});

test('NEGATIVE: never touches the real key file, however old', () => {
  const { dir, keyPath } = fixture();
  agedFile(keyPath, 'the-actual-master-secret', OLD);
  assert.equal(sweepStaleIdentityTemps(keyPath, NOW), 0);
  assert.equal(existsSync(keyPath), true);
  assert.equal(readFileSync(keyPath, 'utf8'), 'the-actual-master-secret');
  rmSync(dir, { recursive: true, force: true });
});

test('NEGATIVE: never touches unrelated neighbours, including near-miss names', () => {
  const { dir, keyPath } = fixture();
  const others = [
    join(dir, 'identity.key.bak'),        // no .tmp. segment
    join(dir, 'identity.keytmp.1.2'),     // missing the dot before tmp
    join(dir, 'other.key.tmp.1.2'),       // different basename entirely
    join(dir, 'seqstate.json'),
  ];
  for (const o of others) agedFile(o, 'keep-me', OLD);
  assert.equal(sweepStaleIdentityTemps(keyPath, NOW), 0);
  for (const o of others) assert.equal(existsSync(o), true, `${o} must survive`);
  rmSync(dir, { recursive: true, force: true });
});

test('NEGATIVE: skips a symlink rather than following it — the target must survive', () => {
  const { dir, keyPath } = fixture();
  const victim = join(dir, 'somebody-elses-file');
  agedFile(victim, 'must-not-be-deleted', OLD);
  const link = `${keyPath}.tmp.1.${OLD}`;
  symlinkSync(victim, link);
  assert.equal(sweepStaleIdentityTemps(keyPath, NOW), 0);
  assert.equal(existsSync(victim), true);
  assert.equal(readFileSync(victim, 'utf8'), 'must-not-be-deleted');
  rmSync(dir, { recursive: true, force: true });
});

test('NEGATIVE: skips an AGED symlink — here isFile is the ONLY guard standing', () => {
  // The previous symlink case is really carried by the AGE guard: a link created during the test
  // has a fresh mtime, so the sweep skips it before isFile is ever consulted, and dropping isFile
  // survived the suite. Ageing the LINK ITSELF (lutimes, not utimes — utimes would age the target)
  // pushes it past the threshold, so the only thing left refusing to unlink it is the regular-file
  // check. Same lesson as the pad-tag: a guard is untested until it is the sole thing in the way.
  const { dir, keyPath } = fixture();
  const victim = join(dir, 'target-file');
  agedFile(victim, 'target', OLD);
  const link = `${keyPath}.tmp.7.${OLD}`;
  symlinkSync(victim, link);
  const s = OLD / 1000;
  lutimesSync(link, s, s);
  assert.ok(lstatSync(link).mtimeMs < NOW - STALE_TEMP_MIN_AGE_MS, 'link must be past the age threshold');
  assert.equal(sweepStaleIdentityTemps(keyPath, NOW), 0);
  assert.equal(lstatSync(link).isSymbolicLink(), true, 'aged symlink must survive');
  assert.equal(existsSync(victim), true);
  rmSync(dir, { recursive: true, force: true });
});

test('sweeps several stale orphans and returns the count, mixed with things it must keep', () => {
  const { dir, keyPath } = fixture();
  for (const p of [1, 2, 3]) agedFile(`${keyPath}.tmp.${p}.${OLD}`, 'x', OLD);
  agedFile(`${keyPath}.tmp.4.${FRESH}`, 'live', FRESH);
  agedFile(keyPath, 'real', OLD);
  assert.equal(sweepStaleIdentityTemps(keyPath, NOW), 3);
  assert.equal(existsSync(`${keyPath}.tmp.4.${FRESH}`), true);
  assert.equal(existsSync(keyPath), true);
  rmSync(dir, { recursive: true, force: true });
});

test('missing directory returns 0 and never throws', () => {
  assert.equal(sweepStaleIdentityTemps(join(tmpdir(), 'saihm-sweep-does-not-exist', 'identity.key'), NOW), 0);
});

test('GATE: ensureSelfJoinIdentityEnv sweeps only when SAIHM_SWEEP_STALE_TEMPS=1', () => {
  const saved = { ...process.env };
  try {
    const home = mkdtempSync(join(tmpdir(), 'saihm-sweep-home-'));
    process.env.HOME = home;
    delete process.env.SAIHM_MASTER_SECRET_FILE;
    delete process.env.SAIHM_MASTER_SECRET_HEX;
    delete process.env.SAIHM_SWEEP_STALE_TEMPS;

    // Gate OFF: mint once to learn the real key path, then strand an aged orphan beside it.
    const { keyPath } = ensureSelfJoinIdentityEnv();
    assert.ok(keyPath, 'expected a key path');
    const orphan = `${keyPath}.tmp.1234.${OLD}`;
    mkdirSync(join(keyPath!, '..'), { recursive: true });
    agedFile(orphan, 'stranded-secret', OLD);

    ensureSelfJoinIdentityEnv();
    assert.equal(existsSync(orphan), true, 'gate off must not sweep');

    process.env.SAIHM_SWEEP_STALE_TEMPS = '1';
    ensureSelfJoinIdentityEnv();
    assert.equal(existsSync(orphan), false, 'gate on must sweep');

    rmSync(home, { recursive: true, force: true });
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
});
