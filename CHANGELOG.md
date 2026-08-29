# Changelog

All notable changes to `@saihm/mcp-server-pro` are documented here. This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Closes a defect class rather than its instances: a caller-actionable value — a
filesystem path, or a URL the operator has to go and open — rendered under a fence
built for a different value class, so the text looks actionable and is not.

The class has two halves, BUDGET and CHARACTER SET, and both are closed here.

**A minor rather than a patch**, on two independent legs, either of which is
sufficient. The first is the rule this project set at 0.3.0: an announced
identifier that changes value is not a patch. Three configuration errors change
`e.name`, and the compatibility note below asks consumers to adjust code that
matches on it — one of the three is thrown from the public `SaihmProClient`
constructor as well as from `bootFromEnv()`. The second leg is the output
regression disclosed below: three previously raw lines no longer round-trip a path
containing `[`, `]`, `|`, a non-space whitespace character, or more than
`MAX_PATH_FIELD_CHARS` characters. Naming both matters, because on the first leg
alone a future revert of `e.name` would grade a release that still contains that
regression as a patch. The 0.3.0 entry applied that rule to `serverInfo.name`;
applying the opposite rule to the same shape here would leave the next author
unable to tell which one governs.

The new `.d.ts` exports are NOT part of that argument, though an earlier draft of
this entry leaned on them. `exports` contains only `"."`, so `dist/render_fence.d.ts`
and `dist/client.d.ts` are unreachable on every supported resolver and
`dist/index.d.ts` is byte-identical; this package already argues, in
`SaihmConfigError`'s own docblock, that a symbol absent from the barrel is not
public surface. On that leg alone this would be a PATCH. It is `e.name` that
carries the bump.

### Budget

- `MAX_PATH_FIELD_CHARS` (PATH_MAX) for the lines that fence a path directly:
  "Also written to" and the free-join "Back up `<keyPath>`". Both had been wearing
  `MAX_JOIN_FIELD_CHARS`, which is sized and documented for a device-flow URI.
- `MAX_CHECKOUT_URL_CHARS` renamed `MAX_URL_FIELD_CHARS`. Value unchanged at 2048.
  A constant named more narrowly than its value class is how a value ends up
  wearing a bound meant for something else.
- Four sites that EMBED the value in a sentence, where no swap of the value's own
  budget could reach it, now size to what the message carries: the `saihm_forget`
  cache residual (90 characters were left for the path), an unreadable
  `SAIHM_MASTER_SECRET_FILE` (59 on the branch a first-run operator actually
  takes, since `selfJoinEnabled()` is `SAIHM_SELF_JOIN !== '0'`; 23 on the
  opted-OUT branch reached by setting `SAIHM_SELF_JOIN=0`), an unreadable
  self-join identity (60), and an invalid `SAIHM_ENDPOINT_URL` (217, against a
  2304 composite).
- `MAX_PATH_MESSAGE_CHARS` budgets for TWO paths, not one, because a failed
  `rename` carries a source and a destination in a single message — the argument is
  recorded on `PATH_BEARING` in `client.ts`, not on the constant itself. At one
  path's width the destination began losing characters at 2152 and was gone
  entirely at 4303.
- Filesystem failures where NODE writes the message and embeds the path in it —
  `SAIHM_HOME`, `SAIHM_SEQ_STATE_PATH`, `SAIHM_RECALL_CACHE_PATH` — are marked so
  the renderer widens for them too. The original error is marked and rethrown, not
  replaced, so `code`/`errno` survive for anyone branching on them.

### Character set

`safeField` maps every non-ASCII code unit to `?`. That is correct for endpoint
prose and wrong for a path: under a non-ASCII home directory it names a file that
does not exist, on the line telling the operator to back that file up. The new
`safePathField` renders all nine path-class CALL SITES — a count pinned per file
by the call-site sweep, not asserted in prose. (The "four sites" above counts
MESSAGES that embed a value in a sentence, which is a different unit, and one of
those four is a URL rendered by `safeField`.) A path keeps every printable
character a filesystem can hold, while removing the invisible and blank characters it
can NAME — which is not the same as all of them, and the difference is the blank-symbol
list below, hand-read and already grown from three to six in three rounds: line terminators, C0/C1 controls, the union of Unicode `Cf` and
`Default_Ignorable_Code_Point`, every whitespace character except the ordinary
space, six blank symbols in no ignorable class (`U+2800`, `U+2D7F`, `U+16FE4`,
`U+1D159` and `U+13441`/`U+13442` EGYPTIAN HIEROGLYPH FULL and HALF BLANK),
`[`/`]`/`|`, `U+2026` and unpaired surrogates. What it does NOT remove, and cannot,
is set out under "The residual" below.

What that changes, precisely:

- **Three lines have mangled a non-ASCII path since 0.4.0** and are fixed: the
  `saihm_forget` erasure residual — a GDPR Art.17 receipt naming the file that may
  still hold the plaintext just erased — plus "Also written to" and the free-join
  "Back up `<keyPath>`".
- **Two `saihm_join` key-file lines were previously unfenced.** They rendered a
  non-ASCII path correctly, but a `SAIHM_HOME` carrying a newline rendered a forged
  memory-recall banner inside a tool result, in the tool's own voice. Now fenced,
  and still correct for non-ASCII.
- **Two sites did not exist before this release** — the config-error path arm and
  the marked-filesystem arm, both in `render_fence.ts`. An earlier draft counted the
  group/world-readable advisory on `SAIHM_MASTER_SECRET_FILE` as a third; it existed
  and rendered the path to stderr RAW. A raw render does not mangle non-ASCII, so it
  belongs with the previously-unfenced lines above, not here — making the accounting
  3 shipped-wrong + 3 raw + 2 that did not exist + 1 added by the `join` fix = 9.
- **One site is new in the fix for `join`** described under Compatibility: that verb
  now names the key file instead of an env var the caller may never have set.

The scrubbed classes are derived from Unicode rather than listed by hand — with one
disclosed exception, the blank symbols, which were found by reading. Hand-listing is
what missed U+061C ARABIC LETTER MARK in the first place — and the limit is not
theoretical: the list shipped as three with a note that a fourth would have to be
found the same way, the next review found two more, and the round after that found a
sixth, `U+16FE4 KHITAN SMALL SCRIPT FILLER`. That list is not a closed class, and this
release stops implying it is. Two arguments were offered for it and neither survives:
that `U+2D7F` joins nothing a reader can see — its own UCD annotation says it marks a
bi-consonant cluster, and `U+17D2 KHMER SIGN COENG` and `U+10A3F KHAROSHTHI VIRAMA`
carry the same "shape shown is arbitrary and is not visibly rendered" annotation and
SURVIVE this fence — and that `U+16FE4` has the measured profile of `U+2D7F` exactly,
which is equally the profile of all 1794 combining marks that must never be scrubbed.
The six stay scrubbed because each draws nothing in a plain-text line; the cost to a
path written in those scripts is real and is now stated on the function rather than
argued away. `Indic_Syllabic_Category` and the NamesList annotations are both
greppable, so "there is no property to derive them from" was stronger than what was
measured. `U+13443 LOST SIGN` is the control and is correctly KEPT, being
a hatched box rather than a blank. The scope then widened again, and
the reason is worth stating: `Bidi_Control` is 12 code points, `Cf` is 170, and the
158 left behind included the 96 code points of the TAG block, U+E0020–U+E007F, 95
of which map onto printable ASCII (U+E007F offsets to DEL). Driven through a real
path, an instruction encoded that way survived and decoded intact, addressed to the
reading agent, while the visible text said something else. The capacity is the
figure that matters and is reproducible: 2048 smuggled bytes at
`MAX_PATH_FIELD_CHARS`. Narrowing to `Bidi_Control` would therefore have been a REGRESSION against
0.4.1, whose ASCII collapse caught the whole block. `Cf` alone was still a
regression: the VARIATION SELECTORS (U+FE00–FE0F and U+E0100–E01EF, 256 code
points, category `Mn`) are a strictly larger channel and `Cf` does not reach them —
measured at that cut, 2048 smuggled bytes survived at `MAX_PATH_FIELD_CHARS`. The
scrub is now the union of `Cf` and `Default_Ignorable_Code_Point`, which is the
property meaning "renders as nothing": 170 and 4174 code points, overlapping in
138, neither a subset of the other, so scrubbing either alone leaves a channel
open.

That union was still not the whole class, and the reason is the same one a third
time: both properties mean "invisible FORMATTING", while what this fence defends is
narrower and more literal. Sixteen non-ASCII WHITESPACE code points sat outside
both, together with U+2800 BRAILLE PATTERN BLANK and U+2D7F TIFINAGH CONSONANT
JOINER, which belong to no ignorable class at all — an 18-symbol alphabet at 4 bits
per unit, 2048 smuggled bytes at `MAX_PATH_FIELD_CHARS`. That is the same capacity
as the variation-selector channel the union had just been widened to close, and
0.4.1's ASCII collapse had given it none. All eighteen are scrubbed. Measured after:
exactly ONE whitespace code point survives, `U+0020`, kept because a path may
legitimately contain a space — disclosed on the function rather than defended, since
runs of spaces remain a low-rate channel.

### The residual

Five cuts each read as closure and none of them was. The sixth review measured why
none of them could be, and that is now written on the function instead of a sixth
claim: **`safePathField` narrows the channel and makes tampering visible as `?`; it
does not eliminate the channel.**

What cannot be removed, and why it is structural rather than an oversight:

- **Combining marks.** 1,794 nonspacing marks survive, and must: `café` in NFD, a
  Devanagari conjunct and a Thai stack are all mark sequences, and a path that loses
  them is precisely the defect this release exists to fix. The capacity is per UTF-16
  UNIT, because that is what the budget slices: 1,069 of those marks are BMP and 725
  are astral at two units each, giving 10.06 bits per unit — **5,152 bytes at
  `MAX_PATH_FIELD_CHARS`**. Measured on that same basis, the three channels this fence
  CLOSES are 1,681 bytes (TAG block), 2,390 (variation selectors) and 867 (the blank
  symbols): 4,938 together, so the residual is larger than **all three put together**.
  Two earlier drafts ranked it against "2,048 each" and disagreed with each other —
  first claiming "larger than all three", then "larger than any two and smaller than
  all three". Both were wrong the same way: 2,048 is a figure one naive encoder
  ACHIEVED and 5,152 is a capacity, and numbers on two bases do not compare. The test
  meant to police these figures had encoded the same error, and now derives every one
  of them from the shipped fence.
- **Homoglyphs**, for the same reason one level up: preserving the characters is what
  makes a path openable, and preserving them admits look-alikes.
- **`U+0020`.** Paths legitimately contain spaces, so runs of them remain a low-rate
  channel.

So the defensible statement is: *no invisible channel that costs a legitimate path
nothing to close.* Anything stronger — "no encoding channel survives", "nothing
invisible gets out" — is false, was claimed here four times, and is what let each cut
read as closure. A caller who needs elimination needs a different value, not a better
fence. Both disclosed figures are re-derived from the shipped fence by a test that
reads `src/render_fence.ts` and fails if the sentence there disagrees, so the DOCBLOCK
cannot drift from the code. This changelog is not covered by that test and is kept in
step by hand.

`U+2026` is scrubbed too, so the truncation marker cannot be forged by the
value. Homoglyphs still survive by design — the character is genuinely in the path, and
scrubbing it would break the copy-paste this fence exists to make possible — but the
zero-width and invisible formatting characters (U+00AD, U+180E, U+200B, U+2060,
U+FEFF) no longer do, because every one of them is `Cf`. A path containing one is
rendered with a `?` in its place and will not round-trip; that is the deliberate
trade against a path that reads as one thing and is another.

URL sites deliberately keep `safeField`: an invalid URL is echoed back to be
recognised, and collapsing an invisible character to `?` makes the cause visible
rather than hiding it. That argument covers the diagnostic arm and NOT the two live
URLs a human is told to open — the hosted checkout link and the device-flow
`verificationUri` — where an IDN authority is mangled to `?` and becomes a link that
looks actionable and opens nothing, which is the same defect class this release
closes for paths. Measured. Not fixed here: it needs a URL-class fence rather than the
path one, and percent-encoded URLs (the common case) are pure ASCII and unaffected.
Tracked separately.

### Guards

- The call-site sweep pins which FENCE a budget is paired with, not the budget
  alone, so a path budget can only be rendered through the path fence.
- The persist sweep proves CONTAINMENT — the call inside a try whose catch carries
  the wrapper — where it previously matched a 400-character window, in which an
  unwrapped call could borrow a neighbour's wrapper.
- A new sweep ENUMERATES every occurrence of a caller-chosen value outside a fence and
  pins the count per file. STATED LIMIT: it is a named-value guard, not taint analysis
  — it knows five identifiers (`keyPath`, `secretFile`, `savedTo`,
  `localCacheResidual`, `SAIHM_HOME`), so a sixth env-derived name still ships green. Both other sweeps key on fence CALL SITES, so an unfenced value
  was invisible to them — which is how three of these sites shipped with no fence at
  all. Two earlier cuts
  of it were evaded in review: matching `${…}` could not see `'literal' + value`,
  and matching any line carrying a string literal missed a line break moved inside
  one expression — measured at the time, that gate discarded 26 of roughly 40
  occurrences then in `src/` before any fence reasoning ran. The exact denominator is
  no longer derivable — the gate is deleted and `src/` has moved on — and the two
  surviving records disagree (39 against 40), so neither is quoted as exact. Counting occurrences asks nothing about how a render looks,
  which is the only property the author of a render does not choose.
- The control and bidi classes are DERIVED from Unicode rather than listed, and the
  budget matcher, the fence order and the truncation boundary are each pinned by a
  mutation that goes red. A non-ASCII path is now driven through a REAL call site:
  every previous path fixture was ASCII, so a one-token change of a value's class
  restored the headline defect with the whole suite green.
- **The sweeps read the TypeScript AST rather than a hand-written lexer.** Four
  consecutive hostile-review rounds found the same defect in them and never the same
  spelling of it: a `//` comment containing `/*` blanked 55 lines of `client.ts`;
  `safeField (x, y)` with one space hid a call site; a generic's comma hid a budget
  from a scan that could not cross it; `async prune()` hid a persist-reaching method
  from a pattern written for a two-space indent; and a regex literal after a keyword
  reopened the phantom block that the regex-literal handling had been added to close.
  TypeScript is not a regular language, so every regex approximation of it has an
  unbounded supply of near-miss spellings, and closing the measured one leaves the
  class open. The compiler's own parser now decides what is a comment, a string, a
  regex literal, a declaration and a call. The comment stripper, the guard that
  policed it and the two tests that policed that guard are all deleted — there is
  nothing left for them to police.
- **The sweeps match on SYMBOLS, not names.** The AST rewrite killed the lexical
  evasions and left a simpler one: every sweep still recognised its subject by the
  name at the call site. Measured, all four — `import { safeField as fence }` and
  `const fence = safeField` each hid a caller-actionable path behind the
  ASCII-collapsing fence at a path budget with the whole suite green; a receiver alias
  hid an unwrapped persist-reaching call; and `s['keyPath']` was not an occurrence at
  all to the one sweep whose whole job is catching a value rendered with no fence. A
  name is a spelling too. The sweeps now build a `ts.Program` and ask the type checker
  which DECLARATION a call reaches, so an alias resolves to the thing it aliases.
- The structured-field sweep's subject is `structuredContent` itself rather than the
  `ok` helper that usually writes it, because a handler returning the object directly
  emitted a whole family of endpoint-chosen keys with nothing going red.
- Containment is read from the tree too, in both sweeps that need it: the enclosing
  `try` whose TRY BLOCK holds a persist-reaching call, and the `registerTool` a
  structured field is emitted INSIDE. Both were positional before — "the nearest
  wrapper" and "the last registration above this line" — and both attributed
  correctly only because nothing had yet been written that they would attribute
  wrongly.
- The sweeps derive their file set from `src/` rather than naming files, and now
  RECURSIVELY: a module in a new subdirectory used to sit outside "every call site"
  with nothing going red. The budget matcher classifies a declaration structurally,
  by which identifiers reach its value, so the ten name and syntax
  heuristics it used to carry are gone; the shapes those made it fail loudly on now
  simply resolve.

### Compatibility

No error's `message` changes, and neither does the tool LIST nor the public API of
`index.js`. Nine narrower things do change. ONE is a regression for some inputs and is
marked as such below; two more are breaking without being regressions (the
`SaihmConfigError` class change and the generated types); the rest are fixes:

- **CLI and server stderr output changes where it was wrong.** `join` ("Also written to") and
  `free-join` ("Back up") now render a non-ASCII path correctly instead of
  replacing each non-ASCII character with `?`. The group/world-readable warning
  on `SAIHM_MASTER_SECRET_FILE`, which wrote the path to stderr with no fence at all,
  now renders it through the same one. That advisory is written from `bootFromEnv()`,
  which the server calls lazily on the first memory tool call, so it fires in the MCP
  server process too and not only under a CLI verb — an MCP-only deployment saw the raw
  path as well: a path carrying a newline can no longer
  forge a second line of warning text, and one carrying a control or format
  character shows `?` in its place.
- **Three lines that were rendered RAW at 0.4.1 are now fenced, and for some paths
  that is a regression.** Two are `saihm_join` TOOL-RESULT text — the pending-join
  note and "key file:" in the success text — and the third is the CLI stderr
  advisory on a group/world-readable `SAIHM_MASTER_SECRET_FILE`. All three now
  carry this package's standing scrubs for the first time: `[`, `]` and `|` become
  `?` although all three are legal POSIX filename characters; whitespace other than
  the ordinary space, and every format or default-ignorable character, become `?`;
  and a path over `MAX_PATH_FIELD_CHARS` is truncated with a marker where it
  previously rendered whole. On those three lines 0.4.1 round-tripped such a path
  and this release does not. The trade is deliberate — two of the three were the lines a
  newline in `SAIHM_HOME` used to forge a counterfeit memory-recall banner through,
  and the third wrote an unfenced path to a terminal — but it is a trade, not a
  pure fix.
- **`saihm_join` and `free-join` no longer name a key FILE when there is none.**
  With the master secret supplied inline in `SAIHM_MASTER_SECRET_HEX`,
  `ensureSelfJoinIdentityEnv()` returned the string `(SAIHM_MASTER_SECRET_HEX)` in a
  field typed as a path, and three lines duly rendered it as one: `Back up
  (SAIHM_MASTER_SECRET_HEX)`, `key file: (SAIHM_MASTER_SECRET_HEX)`, and a
  doubled-parenthesis `key ((SAIHM_MASTER_SECRET_HEX))`. Each of those sites already
  carried the defect differently, and an earlier draft of this entry got that wrong:
  the free-join line DID carry a correct inline-secret branch that a truthy sentinel
  made unreachable, while `key file:` was unconditional and the pending-join line
  branched only on whether the key had just been created. Two of the three gain a
  branch here; one gets a reachable one. The return type is now `keyPath: string | null`, and those
  lines name the variable instead of pointing at a file that does not exist. Anyone
  destructuring `keyPath` from that function has to handle `null`.
- **A configured but EMPTY secret is now an error instead of a silent switch to a
  different identity.** `bootFromEnv` guarded its self-join fallback on whether a
  secret VALUE was present rather than on whether one had been CONFIGURED, so a
  zero-byte `SAIHM_MASTER_SECRET_FILE` fell through to the default self-join identity:
  the process booted a different key while every backup line, and `identityKeyFile()`
  with it, named the file the operator had configured. Reproduced end to end — the
  operator backs up an empty file and the only key to their memory is never named. It
  now raises `SaihmConfigError` naming the file. Anyone relying on an empty secret file
  as an opt-in to self-join must unset the variable instead.
- **`join` names the KEY FILE instead of an env var the caller may never have set.**
  The line was unconditionally `Keep SAIHM_MASTER_SECRET_HEX safe`, so the caller who
  reaches `join` to subscribe after `saihm_join` — key in a generated
  `free-identity.key`, no such variable set anywhere — was told to protect something
  that does not exist and never told the file that does. This is the same defect
  `free-join` fixed sixty lines away in the same module, in the copy nobody
  propagated to. Both verbs now resolve the key through one exported
  `identityKeyFile()`, whose precedence mirrors `bootFromEnv`.
- **`saihm_forget` tool-result text changes.** The erasure residual naming the local
  cache path moves from `safeField` at 256 to `safePathField` at
  `MAX_PATH_MESSAGE_CHARS`: a non-ASCII cache path renders correctly instead of as
  `?`, and the bound widens 33×. `forget` is a tool, not a CLI verb, so this is not
  covered by the CLI bullet.
- **Every tool's failure text changes for marked filesystem errors.** A failure
  naming `SAIHM_HOME`, `SAIHM_SEQ_STATE_PATH` or `SAIHM_RECALL_CACHE_PATH` is
  rendered through the widened path bound rather than cut at 256, so these messages
  get longer and stop mangling non-ASCII. Measured with a 400-character home, one
  such message goes from 257 to 437 characters — measured on `ENAMETOOLONG` from
  `mkdir` under a 400-character `SAIHM_HOME`, which is the shape the figure names.
- **Three configuration errors that name a path or URL now throw
  `SaihmConfigError` rather than `Error`.** The message is byte-identical, but
  `e.name`, `String(e)`, the first line of `e.stack`, `JSON.stringify(e)` and
  `Object.keys(e)` differ — the last two because `SaihmConfigError` carries TWO new
  enumerable own properties: `valueKind` (`'path'` or `'url'`), which is how the
  renderer knows which budget to widen to, and `name`, which a plain `Error` carries
  on its prototype instead. Measured: `Object.keys(e)` is `["valueKind","name"]`
  against `[]` for a plain `Error`. Code matching `/^Error: SAIHM_/` against one of them
  should match the message or use `instanceof` instead. Other configuration errors
  still throw plain `Error`. `SaihmEndpointError` has always presented this shape.
- **Generated types for deep paths change:** `dist/render_fence.d.ts` loses
  `MAX_CHECKOUT_URL_CHARS` and gains `safePathField` plus four constants;
  `dist/client.d.ts` gains `SaihmConfigError`, `markPathBearing`, `isPathBearing` and
  `identityKeyFile`, and narrows `keyPath` from `string` to `string | null`;
  `dist/render_fence.d.ts` also gains `BLANK_SYMBOLS`. Those paths are not in `exports`, so importing them at runtime
  fails on every supported resolver; only a legacy `node10` typecheck or a bundler
  that ignores `exports` could have been reading them. `dist/index.d.ts` is
  byte-identical.

## [0.4.1] — 2026-08-28

- CLI: reject unrecognized arguments instead of starting a silent server.

## [0.4.0] — 2026-08-28

A minor for the new no-configuration join path and the render fence, which is the
larger theme of this release; the rest is correctness.

- `free-join` is a complete join needing no configuration.
- Every endpoint-chosen string is fenced before it reaches the agent, the
  remaining render sites are covered, and the agent's own arguments are named.
- The fence bounds the WORK, not only the output.
- CI now gates this package on push and pull request, not only at release.
- `forget` reports both halves when a local cache purge fails after erasure.
- A failed persist no longer leaves plaintext behind, nor fails a stored write.
- Persist refuses a planted path, and the file modes are pinned rather than left
  to the umask.
- The envelope commitment is pinned so two versions at one `seq` are
  distinguishable, and an in-flight recall can no longer undo a concurrent local
  write.

## [0.3.0] — 2026-08-02

Install correctness. The documented configuration now works as pasted, and the
server no longer announces the same `serverInfo.name` as the standards client.
No protocol, wire-format, or tool-surface change; the canonical eight tools plus
the `saihm_join` bootstrap affordance are unchanged. A minor rather than a patch
because `serverInfo.name` is a publicly announced identifier — anything keying on
it sees a different value.

### Fixed

- **Pasting the documented config into Cline silently installed nothing.** Cline
  allows an MCP server 1.5 seconds to complete `initialize`; `npx` cannot resolve
  and launch a package that fast, so the server missed the deadline on every
  attempt and Cline skipped it — logging to its own file but surfacing no error
  in the chat, so the tools simply never appeared. Measured against Cline CLI
  3.0.48: the documented block failed 4 of 4 runs, including one with a warm
  `npx` cache, and passed once `"timeout": 60` was present. The server itself was
  never at fault — spawned directly with a cold `HOME` it completes the handshake
  and enumerates all nine tools. Both `mcpServers` examples in `README.md` now
  carry `timeout`, with a note on why removing it breaks Cline specifically.
  Hosts that do not recognise the field ignore it.

### Added

- **`llms-install.md`**, agent-oriented install instructions covering the
  `timeout` requirement, verification without side effects, and the two facts a
  user must be told before `saihm_join` runs: it claims a one-time lifetime free
  grant, and `~/.saihm/free-identity.key` is the only copy of their key. Now part
  of the published tarball.

### Changed

- **`serverInfo.name` is now `saihm-pro`, was `saihm`.** The standards client
  `@saihm/mcp-server` also reports `saihm`, so two separately published packages
  were announcing one server name. Any directory, registry, or host that keys on
  `serverInfo.name` rather than on the package identifier could conflate them.
  No protocol, wire-format, or tool-surface change: the canonical eight tools
  plus the `saihm_join` bootstrap affordance are unchanged, and clients key their
  configuration on the `mcpServers` entry name, not on this field. Visible where
  a host displays the server's self-reported name. A handshake assertion now
  guards the value so the divergence cannot silently regress.

## [0.2.1] — 2026-07-28

First-run fix. No protocol, wire-format, or tool-surface change; the canonical
eight tools plus the `saihm_join` bootstrap affordance are unchanged.

### Fixed

- **A fresh install dead-ended on its very first tool call.** With no
  `SAIHM_ENDPOINT_URL` set — the state of every hand-written MCP config, e.g. a
  bare `npx -y @saihm/mcp-server-pro` — `saihm_recall`, `saihm_status`, and
  `saihm_remember` all failed with `SAIHM_ENDPOINT_URL env var required`, which
  never mentions `saihm_join`. The shipped `saihm_session_bootstrap` prompt
  makes this the first thing an agent hits, since it instructs a `saihm_recall`
  before anything else. 0.2.0 already carried the actionable _"Ask me to Join
  SAIHM first"_ message, but the endpoint check threw before execution could
  reach it.

  An unset `SAIHM_ENDPOINT_URL` now resolves to `https://saihm.coti.global/mcp`
  — the value `server.json` already declared as this variable's `default`, so
  code and manifest now agree and registry-driven and hand-written configs
  behave identically. Defaulting reaches no network by itself: boot still
  requires an identity, so an unconfigured agent gets the join hint *before* any
  request is made, and `saihm_join` still needs explicit human approval. Setting
  the variable to an explicit empty string remains a configuration error rather
  than a silent opt-in to the default.

- **Every remaining boot error was a bare env-var name.** All of them now carry
  a setup hint naming `saihm_join` for the free zero-config path and
  `SAIHM_ENDPOINT_URL` for a different operator: unreadable
  `SAIHM_MASTER_SECRET_FILE`, unreadable self-join identity file, missing master
  secret, non-canonical hex, and under-length secret. No secret material is
  interpolated into any message.

### Changed

- `server.json`: `SAIHM_ENDPOINT_URL` is now `isRequired: false`, matching the
  code, so registry clients stop prompting for a value that has a working
  default.
- README: the configuration table listed `SAIHM_ENDPOINT_URL` as required. It is
  now documented as optional with its default.
- `DEFAULT_ENDPOINT` is exported from the package root so an embedding consumer
  can reference the same constant.

### Notes

- Regression cover added for the genuinely-unset state. Every pre-existing
  self-join test pinned `SAIHM_ENDPOINT_URL`, so the suite was green while the
  real first-run path was broken; three new cases assert the unset, defaulted,
  and explicitly-empty behaviours, and pin `SAIHM_HOME` to a temp dir so a
  developer's own `~/.saihm` identity cannot mask a failure.

## [0.2.0] — 2026-07-28

Onboarding release. No protocol or wire-format change; the canonical eight
tools are unchanged.

### Changed

- **`saihm_join` is now registered by default (`SAIHM_SELF_JOIN` defaults on).**
  Previously it was opt-in via `SAIHM_SELF_JOIN=1`, which left a fresh install
  with no in-band way to start: every other path first requires a hand-generated
  64+ hex-char master secret, which an autonomous agent cannot produce for
  itself. Self-join generates and persists that identity on-device instead, so
  _"Join SAIHM"_ works out of the box. Set `SAIHM_SELF_JOIN=0` to restore the
  previous behaviour — the tool is not registered and every self-join path is
  inert. `saihm_join` remains a one-time onboarding bootstrap affordance, not a
  ninth protocol tool.
- Boot with no master secret and no persisted identity now returns the
  actionable _"Ask me to Join SAIHM first"_ hint rather than the bare
  `SAIHM_MASTER_SECRET_HEX ... required` error. Opting out restores the
  original message.
- The free allowance is described consistently as a **free trial** for testing
  on real infrastructure — a fixed, one-time allowance, no card and nothing to
  cancel — matching `@saihm/mcp-server`.

### Added

- `server.json` manifest and an MCP registry publish step, so this package is
  discoverable in the MCP registry. Previously only the crypto-free
  `@saihm/mcp-server` was listed, and that package cannot activate an account.
- npm discovery keywords: `memory`, `sovereign-memory`, `free-tier`,
  `claude-code`, `claude-desktop`, `cursor`.

### Fixed

- The documented `free-join` command now uses `SAIHM_MASTER_SECRET_FILE` with a
  shown `openssl rand -hex 32` step, instead of an unexplained
  `<your 64+ hex master secret>` placeholder.

## [0.1.11] — 2026-07-19

### Added

- Opt-in delta recall cache (`SAIHM_RECALL_CACHE_PATH`) for faster session-start
  recall.

## [0.1.10] — 2026-07-10

### Added

- **`saihm_join` — self-serve activation from inside the agent.** Prompt your agent to _"Join SAIHM"_ and it activates a free, non-custodial memory allowance with no manual key handling: the agent generates its own identity seed on-device, persists it mode-600 under `~/.saihm/` (or `SAIHM_HOME`), and completes a one-time device sign-in that confirms a unique person. Off by default; opt in with `SAIHM_SELF_JOIN=1`. The master secret is generated locally and never leaves the process. This is an onboarding bootstrap affordance, not a protocol tool — the eight SAIHM tools remain the surface.
- **`saihm_recall` reads memories shared _to_ you.** The recall tool now accepts an optional sharer identity (`sharerPinnedAgentIdHashHex` plus the sharer's published identity record) and a `cellId`, routing to the recipient-side `recallShared` read (present in the library since 0.1.3) so tool-only agents — not just library callers — can open a cell another agent shared with them. It pins the sharer out-of-band, verifies the sharer and content signatures, and fails closed when there is no live grant. Own-memory recall is unchanged, and the tool count stays eight.

## [0.1.9] — 2026-07-06

### Added

- **Free tier — self-serve, non-custodial activation.** `npx -y @saihm/mcp-server-pro free-join` (with `SAIHM_TIER=FREE`) activates a free, one-time lifetime memory allowance bound to your own key. A one-time GitHub device sign-in confirms a unique person; the provider token stays server-ephemeral and the client never holds it. `acquireFreeEntitlement()` exposes the same headless device flow to library callers, with an `onPrompt` callback for the user-code display.
- **`upgrade` subcommand.** `npx -y @saihm/mcp-server-pro upgrade [PRO|PRO_FAST|ENTERPRISE|ENTERPRISE_FAST]` prints a monthly checkout link bound to your identity; billing attaches to the same key, so every existing memory persists. `requestUpgradeUrl(tier)` for library callers.
- **Advisory free-tier usage nags** via the `onQuotaNag` client option — a non-blocking heads-up as lifetime usage approaches its limit (fired at most once per call type and threshold). It never blocks a call.

## [0.1.8] — 2026-06-30

### Added

- **Structured tool output.** `saihm_remember`, `saihm_recall`, and `saihm_status` now advertise an `outputSchema` and return matching `structuredContent`, so MCP hosts and agents get typed results instead of parsing prose.
- **`saihm_session_bootstrap` prompt.** A new MCP prompt (the `prompts` capability is now advertised) that tells an agent to load its SAIHM memory via `saihm_recall` at the start of a session.
- **`SAIHM_DISCOVERY_SOURCE`** (also `discoverySource` on `SaihmProClientOpts`) — an optional attribution tag (e.g. `"glama"`, `"mcp-registry"`) sent as `source` on self-onboard, so an operator can attribute a paid conversion to the install channel. Free-form; sanitised endpoint-side.
- npm `keywords`, README badges, and a `SECURITY.md` coordinated-disclosure policy (source tree only; not part of the published tarball) for discovery.

### Changed

- Depends on `@saihm/client-pro` >= 0.1.5 (was >= 0.1.2).

## [0.1.7] — 2026-06-28

### Changed

- **`join` now completes the endpoint's proof-of-possession challenge before requesting a checkout link.** It fetches a server challenge and signs it with the in-process ML-DSA-65 secret key — the same challenge/response the self-onboarding path already performs — so the hosted checkout is cryptographically bound to the caller's own identity. Required by the current `/api/stripe/checkout` contract.

## [0.1.6] — 2026-06-25

### Changed

- Reproducible publish: regenerated lockfile and removed a stray formatter config. No API changes.

## [0.1.5] — 2026-06-25

### Added

- **Runnable stdio MCP server.** The package now ships a `saihm-mcp-server-pro` bin (run via `npx -y @saihm/mcp-server-pro`) that exposes the eight SAIHM tools (`saihm_remember`, `saihm_recall`, `saihm_forget`, `saihm_status`, `saihm_share`, `saihm_revoke_share`, `saihm_governance_propose`, `saihm_governance_vote`) over `SaihmProClient`. Point any MCP host (Claude Desktop, Claude Code, …) at it.
- **Self-onboarding (paste once, never re-paste a token).** With `SAIHM_AUTH_HEADER` unset, the server proves control of your identity via the endpoint's ML-DSA challenge/response and mints + auto-refreshes its own short-lived access token from the master secret. A static `SAIHM_AUTH_HEADER` is still honored verbatim.
- **`join` subcommand.** `npx -y @saihm/mcp-server-pro join` prints a checkout link bound to your identity, for self-serve subscription from the command line.
- **`SAIHM_MASTER_SECRET_FILE`** — read the hex master secret from a mode-600 file instead of `SAIHM_MASTER_SECRET_HEX` (keeps the root seed out of a synced MCP config); takes precedence when both are set.

### Changed

- Depends on `@saihm/client-pro` >= 0.1.2 (adds `signChallenge`) and adds `@modelcontextprotocol/sdk` + `zod`.

## [0.1.3] — 2026-06-24

### Added

- `recallShared(grant)` — read a cell another agent shared **to** you (the recipient side of `share`). Pins the sharer's `agentIdHash` out-of-band, verifies the sharer's signature and the cell's content signature, and fails closed (returns `null`) when there is no live grant — e.g. after the sharer revokes the grant or crypto-shreds the cell. `KeySubstitutionError` is re-exported so callers can `instanceof`-handle a sharer key-substitution.
- `repository` metadata linking the package to its source.

## [0.1.0] — 2026-06-22

Initial public release.

- `SaihmProClient` — production thin-client for SAIHM non-custodial memory. Seals every cell client-side via [`@saihm/client-pro`](https://www.npmjs.com/package/@saihm/client-pro) (ML-DSA-65 identity, per-cell AES-256-GCM DEK wrapped under a client KEK, ML-KEM-768 authenticated sharing) and POSTs opaque ciphertext to the blind SAIHM `/mcp` endpoint. The master secret, KEK, and plaintext never leave the process.
- API: `remember`, `recall`, `recallOne`, `forget`, `status`, `share`, `revokeShare`; `bootFromEnv()`; getters `agentIdHash`, `identityRecord`.
- Endpoint hardening (HTTPS-only; loopback `http` permitted for local dev), signed monotonic anti-replay sequencing with optional mode-600 persistence, and a fully typed `SaihmEndpointError` surface.

[0.1.10]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.10
[0.1.9]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.9
[0.1.8]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.8
[0.1.7]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.7
[0.1.6]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.6
[0.1.5]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.5
[0.1.3]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.3
[0.1.0]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.0
