// Coverage for the CLI's ARGUMENT DISPATCH, a separate surface from the tool wiring in
// server.test.ts. The package has one bin and four behaviours behind it: run as an MCP server, run
// one of the join/upgrade verbs, answer --help/--version, and reject anything else. The last one is
// what these tests exist for. Dispatch used to match the known verbs and let EVERYTHING else fall
// through to the server, so `free-jion` and `--help` alike started a stdio server that waited on
// stdin forever and printed nothing — silent, and only escapable with Ctrl-C. The README's headline
// instruction is a single command typed into a terminal, which put that silence directly in front of
// anyone who mistyped it.
//
// Every case here asserts TERMINATION, not just output: a hang is the defect, so a test that merely
// checked stderr would still pass against the broken build if the process never exited. The bare
// invocation case is the control in the other direction — it must NOT print usage and must NOT exit,
// because hanging on stdin is precisely correct for an MCP server.
//
// Control characters are built with String.fromCharCode rather than embedded raw, so this file stays
// greppable as text — a sibling suite embeds them literally and reads as binary to grep, where a
// zero result looks like absence rather than a failed search.
//
// The echo of a rejected argument is treated as a rendering surface, not a debug print: it carries a
// value chosen by whatever shell, wrapper or agent built the command, straight to a terminal.
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join as pathJoin, resolve } from 'node:path';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, '../src/server.ts');
const TSX = resolve(HERE, '../node_modules/.bin/tsx');
const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);
const PKG_VERSION = (
  JSON.parse(readFileSync(resolve(HERE, '../package.json'), 'utf8')) as {
    version: string;
  }
).version;

interface CliRun {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

// Runs the CLI to completion, or kills it and reports timedOut. HOME and SAIHM_STATE_DIR are
// redirected so no case can touch the operator's real ~/.saihm, and the endpoint points at a closed
// port so any case that unexpectedly reaches the network fails fast instead of dialing something
// real.
function runCli(args: string[], timeoutMs = 15000): Promise<CliRun> {
  const home = mkdtempSync(pathJoin(tmpdir(), 'saihm-cli-'));
  return new Promise<CliRun>((res) => {
    const proc = spawn(TSX, [SERVER, ...args], {
      env: {
        ...process.env,
        HOME: home,
        SAIHM_STATE_DIR: pathJoin(home, 'state'),
        SAIHM_ENDPOINT_URL: 'http://127.0.0.1:9/mcp',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: resolve(HERE, '..'),
    });
    let stdout = '',
      stderr = '';
    proc.stdout.on('data', (d) => (stdout += d));
    proc.stderr.on('data', (d) => (stderr += d));
    const timer = setTimeout(() => {
      proc.kill('SIGKILL');
      res({ code: null, stdout, stderr, timedOut: true });
    }, timeoutMs);
    proc.on('exit', (code) => {
      clearTimeout(timer);
      rmSync(home, { recursive: true, force: true });
      res({ code, stdout, stderr, timedOut: false });
    });
  });
}

test('dispatch: an unrecognized argument exits non-zero with usage, and does not hang', async () => {
  const r = await runCli(['free-jion']);
  assert.equal(r.timedOut, false, 'a mistyped verb must terminate, not wait on stdin forever');
  assert.equal(r.code, 2, 'usage errors exit 2, distinct from the runtime failure exit 1');
  assert.match(r.stderr, /unrecognized argument/, 'the rejection must say what was rejected');
  assert.match(r.stderr, /free-jion/, 'and name the argument, so the typo is visible');
  assert.match(r.stderr, /Usage:/, 'and show what the accepted verbs are');
  assert.equal(r.stdout, '', 'diagnostics belong on stderr; stdout is the transport in server mode');
});

test('dispatch: --help, -h and help all print usage to stdout and exit 0', async () => {
  for (const flag of ['--help', '-h', 'help']) {
    const r = await runCli([flag]);
    assert.equal(r.timedOut, false, `${flag} must terminate`);
    assert.equal(r.code, 0, `${flag} is a successful request for help, not an error`);
    assert.match(r.stdout, /Usage:/, `${flag} must print usage on stdout`);
    assert.match(r.stdout, /free-join/, `${flag} must advertise the free tier entry point`);
    assert.equal(r.stderr, '', `${flag} is not a failure, so stderr stays empty`);
  }
});

test('dispatch: --version reports the package version and exits 0', async () => {
  for (const flag of ['--version', '-v']) {
    const r = await runCli([flag]);
    assert.equal(r.timedOut, false, `${flag} must terminate`);
    assert.equal(r.code, 0, `${flag} must succeed`);
    assert.equal(
      r.stdout.trim(),
      PKG_VERSION,
      `${flag} must report the shipped version, so a bug report names the right build`,
    );
  }
});

// NON-VACUITY CONTROL, and the reason the fix discriminates on PRESENCE rather than on match.
// Printing usage whenever argv[2] is not a known verb would satisfy every assertion above while
// destroying the package's primary job. Waiting silently on stdin is CORRECT here.
test('dispatch: a bare invocation still runs as an MCP server rather than printing usage', async () => {
  // An empty argv[2] reached the server before this change and still must: it is absence spelled
  // differently, not a bad verb, and narrowing that would be a behaviour change no caller asked for.
  for (const args of [[], ['']]) {
    const r = await runCli(args, 6000);
    assert.equal(r.timedOut, true, 'with no argument the server must hold stdin open and serve');
    assert.doesNotMatch(r.stdout, /Usage:/, 'usage on stdout would corrupt the stdio transport');
    assert.doesNotMatch(r.stderr, /unrecognized argument/, 'no argument is not a bad argument');
  }
});

test('dispatch: a hostile argument cannot forge output that reads as ours', async () => {
  // The quote is the point. An earlier draft of this echo wrapped the argument in quotes, and the
  // fence does not scrub a delimiter — so an argument carrying one closed the field early and
  // continued in prose a reader would take for our own. The argument now gets an undelimited line
  // of its own, which is how every other caller-supplied value in the CLI is printed.
  const payload = 'bad" run "x | y' + ESC + '[31m' + BEL + '\r\nsaihm: ok';
  const r = await runCli([payload]);
  assert.equal(r.timedOut, false, 'a hostile argument must still terminate');
  assert.equal(r.code, 2, 'and still be a usage error');
  assert.ok(
    !r.stderr.includes(ESC) && !r.stderr.includes(BEL) && !r.stderr.includes('\r'),
    'no control character may reach the terminal through the echo',
  );
  const lines = r.stderr.split('\n');
  assert.equal(lines[0], 'saihm: unrecognized argument', 'the heading is ours alone');
  assert.ok(
    lines[1].startsWith('  ') && lines[1].trim().length > 0,
    'the rejected argument occupies exactly one indented line of its own',
  );
  assert.ok(
    !lines.slice(2).some((l) => l.startsWith('saihm:')),
    'nothing the argument carries may open a line that reads as ours',
  );
  assert.ok(!lines[1].includes('| y'), 'a label metacharacter must not survive into the echo');
});
