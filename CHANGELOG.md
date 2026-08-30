# Changelog

All notable changes to `@saihm/mcp-server-pro` are documented here. This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Closes a defect class rather than its instances: a caller-actionable value — a
filesystem path, or a URL the operator has to go and open — rendered under a fence
built for a different value class, so the text looks actionable and is not.

The class has two halves, BUDGET and CHARACTER SET, and both are closed here.

**A minor rather than a patch**, on two independent legs, either of which is
sufficient. The first is the rule this project set at 0.3.0: an announced
identifier that changes value is not a patch. Four configuration errors change
`e.name`, and the compatibility note below asks consumers to adjust code that
matches on it — one of the four is thrown from the public `SaihmProClient`
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
`safePathField` renders all TEN round-trip CALL SITES — a count pinned per file
by the call-site sweep, not asserted in prose. (The "four sites" above counts
MESSAGES that embed a value in a sentence, which is a different unit. An earlier
draft noted that one of those four was a URL still rendered by `safeField`; that
was the last instance of this defect class in the tree, and it is closed below.) A path keeps every printable
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
- **Three sites did not exist before this release** — the config-error PATH arm, the
  config-error URL arm and the marked-filesystem arm, all three in `render_fence.ts`
  and all three inside functions (`configErrorText`, `failText`) that 0.4.1 did not
  have at all. An earlier draft counted the group/world-readable advisory on
  `SAIHM_MASTER_SECRET_FILE` among them; it existed and rendered the path to stderr
  RAW. A raw render does not mangle non-ASCII, so it belongs with the
  previously-unfenced lines above, not here — making the accounting
  3 shipped-wrong + 3 raw + 3 that did not exist + 1 added by the `join` fix = 10.
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
reading agent, while the visible text said something else. What one astral-only encoder ACHIEVED
through it is reproducible: 2048 bytes at `MAX_PATH_FIELD_CHARS`. That is an encoder
measurement, not the channel's capacity, which depends on which TAG alphabet is
counted — 95 printable, 96 with CANCEL TAG, or the 128 code points this fence removes
— giving 1681, 1685 or 1792 bytes. Narrowing to `Bidi_Control` would therefore have been a REGRESSION against
0.4.1, whose ASCII collapse caught the whole block. `Cf` alone was still a
regression: the VARIATION SELECTORS (U+FE00–FE0F and U+E0100–E01EF, 256 code
points, category `Mn`) are a strictly larger channel and `Cf` does not reach them —
measured at that cut, the same astral-only encoder got 2048 bytes through at
`MAX_PATH_FIELD_CHARS`, against a channel optimum of 2390. The
scrub is now the union of `Cf` and `Default_Ignorable_Code_Point`, which is the
property meaning "renders as nothing": 170 and 4174 code points, overlapping in
138, neither a subset of the other, so scrubbing either alone leaves a channel
open.

That union was still not the whole class, and the reason is the same one a third
time: both properties mean "invisible FORMATTING", while what this fence defends is
narrower and more literal. Sixteen non-ASCII WHITESPACE code points sat outside
both, together with U+2800 BRAILLE PATTERN BLANK and U+2D7F TIFINAGH CONSONANT
JOINER, which belong to no ignorable class at all — an 18-symbol alphabet at 4.17 bits
per unit, so 2135 bytes at `MAX_PATH_FIELD_CHARS` — a capacity of the same ORDER as
the variation-selector channel's 2390, not the same figure. (An earlier draft said
"4 bits per unit, 2048 bytes … the same capacity": a floor and an encoder measurement
presented as a channel optimum, which is the two-bases error this entry withdraws
further down and was still making here.) 0.4.1's ASCII collapse had given it none. All eighteen are scrubbed. Measured after:
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
  `MAX_PATH_FIELD_CHARS`**. Compared on that same basis — one alphabet, one
  budget — everything this fence REMOVES is 6,347 code points: 169 BMP, 4,130 astral
  and 2,048 lone surrogates. That alphabet does not compose freely — a high surrogate
  followed by a low one is a PAIR, already counted among the astral entries — so the
  capacity is counted over an automaton that forbids that one juxtaposition, giving
  10.59 bits per unit and **5,420 bytes**: slightly MORE than the 5,152 that survives.
  Four earlier drafts each compared on a different basis and each was wrong. The first
  ranked 5,152 against "2,048 each", a figure a naive encoder ACHIEVED rather than a
  capacity. The second ADDED three channel capacities — 1,681 (TAG) + 2,390 (variation
  selectors) + 867 (blank symbols) = 4,938 — which is not a quantity any input can
  carry: three alphabets used together are one alphabet at one budget. The third swept
  every code point but SKIPPED the surrogate range, and reported 4,299 removed and
  3,878 bytes — under which the residual came out larger; the test written to police
  that figure carried the same skip, so it confirmed the sentence instead of catching
  it. A per-channel figure has no settled
  alphabet to be computed on either — the TAG channel is 95 printable, 96 with CANCEL
  TAG, or the 128 code points this fence actually removes. 5,152 is itself a LOWER
  bound: marks, homoglyphs and runs of `U+0020` are independent channels an encoder may
  use together. The test
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

### The rollback guard now survives a restart

The guard that refuses an out-of-date copy of a memory kept its high-water marks
in memory only, and `SAIHM_SEQ_STATE_PATH` — the one way to persist them — is not
among the four variables `server.json` declares. A registry-installed operator
therefore could not turn it on by any means, so in every stock install the guard
protected exactly one process and no restart, and the commitment fix that shipped
one commit earlier was armed for nobody across a restart.

- **Persisted by default under the MCP server**, at
  `dirname(defaultIdentityPath())/seq.<identity>.json`, mode 600. Derived from the
  IDENTITY's directory rather than the state directory, and scoped by identity:
  `SAIHM_STATE_DIR` deliberately does not relocate an existing identity file, and
  a mark file that moved while the identity stayed put would silently restart the
  count at zero — the same silent reset this change exists to close.
- **`SAIHM_SEQ_STATE_PATH` is now an override, not a switch.** Unset means "the
  default location", not "no persistence". Constructing `SaihmProClient` directly
  still writes nothing: the opt-in lives on the server's boot path, so a library
  embedding this client does not acquire a file in the caller's `$HOME`.
- **An unwritable DEFAULT path degrades to memory for the session** and says so in
  `saihm_status` (`seq-state=…  rollback-guard=memory-only-this-run`). An
  unwritable EXPLICIT path still throws — that one the operator named, so it is a
  configuration error. Failing `remember` over a file nobody asked for would
  report a cell the endpoint has already accepted as a failed write.
- **Concurrent processes on one home merge rather than clobber.** The file is
  rewritten whole with no lock, and one identity routinely sits behind several
  processes; a plain write dropped every mark the other process owned and handed
  back the sequence space the file exists to defend.
- **A file that cannot be READ is never overwritten.** The merge reads the file back
  before rewriting it, and that read shared a catch with the JSON parse. Absent and
  unreadable are not the same event: absent means there is nothing to merge, while
  unreadable means marks may be sitting there intact and unseen. Measured, a
  mode-600-turned-000 file holding two marks — in a writable directory — came back
  holding one, this session's. The read now fails closed, so an operator-named path
  raises the error and a defaulted one degrades to memory, and in neither case is the
  file touched. Absent, a directory, or a path whose parent is not a directory stay
  benign: none of them can be hiding marks. A present-but-unparseable file also stays
  benign, since there is nothing in it to preserve.
- **The degradation names what failed, not where it was caught.** A file that could
  not be read reported `unwritable`, sending an operator to check directory
  permissions for a file whose own mode was the problem.
- **A damaged or hand-edited file no longer resets the count to zero silently** —
  unreadable and unparseable states are distinguished from "not there yet", and
  `__proto__`, `constructor` and `prototype` keys are skipped.

**Only the sequence number is persisted. The commitment pin is not**, and that is
a deliberate limit rather than an oversight. Two sessions of the same identity can
legitimately seal different content at the same sequence number after a lost
response — that is measured, not hypothetical — so a persisted pin would leave one
of them with a permanent mismatch on a healthy cell until a human deleted a file.
**The claim this release makes is that rollback is closed across restarts, not that
equivocation is.** Detecting an equivocating endpoint across restarts needs a
design that survives concurrent venues, and a flag would have implied it was
solved.

Deleting a `seq.<identity>.json` file remains a supported recovery, and a machine
that holds the key but has no mark file — a second computer, or one whose file was
deleted — re-seeds from the live envelope over an AEAD-authenticated read rather
than restarting the count. Both are asserted against a real sealed envelope, since
against a mock that serves no envelope and enforces no monotonicity the write
succeeds either way and the assertion proves nothing.

### `share` now applies the same guard the read path does

`share` re-wraps the data-encryption key of whatever envelope the endpoint returns
and grants it to someone else. It validated that envelope with a local copy of
part of the read path — a structural decode, the agent binding, the cell id, and
`seq <` — and that copy never grew the commitment check the read path grew. So the
whole equivocation guard was absent from the one path whose output goes to a third
party.

The gap is reachable by an ordinary sequence, not a contrived one. A sequence
number legitimately repeats: a write the endpoint commits but whose response is
lost leaves the high-water mark unadvanced, and the next write reuses that number.
Both envelopes at that number are genuinely signed by the same identity, so
`seq <` is false for both and the endpoint could hand `share` whichever it
preferred. The superseded version was then re-wrapped to the grantee — who holds no
pin, no history, and no way to tell — while the sharer was told the share
succeeded.

`share` now routes the returned envelope through the same `openRow` the read path
uses, rather than through a partial reimplementation of it. The change is
subtractive: a duplicated guard is deleted and the canonical one is called. A guard
copied into a second site can be missing from one of them; a guard called cannot
be.

What the endpoint could do here was always bounded, and is stated so the fix is not
read as larger than it is: it could not forge an envelope, because the re-wrap
unwraps with the sharer's own key-encryption key and a forged wrapping does not
open. The exposure was replay of the sharer's own superseded versions.

Three error paths tighten as a consequence. An envelope this identity cannot open
now raises `undecryptable` from `share` rather than whatever the re-wrap threw; an
envelope that differs from the pinned commitment at an already-observed sequence
raises `stale_cell` where `share` previously succeeded; and because `share` now
observes, a session that only shares can surface a sequence-state write failure
that previously only `remember` and `recall` could reach. `share` also pins exactly
as a read does, so sharing a cell this session has not read establishes the same pin
a read would have.

### What persisting the marks broke, and what it did not

Making the rollback guard survive a restart changed the meaning of a test the rest
of the client was written against. `remember` decided whether to re-read a cell's
live sequence by asking whether it held a mark for it, and while marks lived only
in memory, "we hold a mark" and "we have seen this cell live in this run" were the
same set. Persisting them split those sets, and the following five items are what
fell into the gap. Four are fixed here; the fifth is a documentation correction in
`README.md`.

- **A mark that is BEHIND the endpoint is no longer trusted.** `remember` now
  re-reads a cell's live sequence on the first touch of that cell in a process,
  keyed on what this process has OBSERVED rather than on what is on disk. It does
  not take a second machine to get a mark that is behind: `remember` advances the
  mark only after the endpoint ACCEPTS, so a write the endpoint commits whose
  response is lost leaves the mark one short, and before marks persisted a restart
  cleared it. Writing at that sequence puts a second envelope where the endpoint
  already holds one — the equivocation `stale_cell` and the `share` guard exist to
  detect, produced locally, out of a defence. The persisted mark keeps its whole
  security value: it is a FLOOR, and a replayed older envelope still cannot drag a
  client backwards. What it no longer does is stand in for the live read. **Cost:
  one extra recall per updated cell per process** — the behaviour before marks
  persisted. A cell already at the uint64 ceiling is exempt, because nothing the
  endpoint can serve could raise it and the outcome is `seq_exhausted` either way.
- **A marks failure after an accepted write now says the cell was stored.** It
  reached the operator as a bare filesystem error out of `saihm_remember`, which
  reads as a failed write — and the repair for a failed write is to send it again,
  spending a second sequence number on a cell that already holds the text.
- **A marks file that is valid JSON but not an object no longer takes every tool
  down.** `null`, `[]`, `7` and `"x"` all parse; the first threw from the
  constructor, so every SAIHM tool failed with `Cannot convert undefined or null to
  object`, naming nothing actionable. Now reported in `saihm_status` as
  `seq-state=malformed` — its own token, because the file is readable and
  well-formed and `unparseable` would send someone looking for a torn write.
- **A cell whose id is `__proto__`, `constructor` or `prototype` keeps its mark.**
  Those keys were written faithfully and skipped on load, so the mark round-tripped
  to nothing and the cell reset to sequence zero on every restart — the exact loss
  the skip was there to prevent. Nothing on that path is prototype-exposed, so the
  skip cost the mark and bought nothing.
- **A recall writes the marks file ONCE, not once per cell.** `observe` persisted
  per advancing mark and the write rewrites the whole file, so a recall of n cells
  performed n whole-file rewrites of a file that is itself O(n) — quadratic, on the
  first operation this package recommends anyone run.

- **An unreadable marks file no longer reports the guard as still persisting.**
  `saihm_status` performs no write, so checking it straight after a restart is how
  someone confirms the safeguard is intact — and in that window a file the next
  write cannot get past was reported as `rollback-guard=persisting`. `persisting`
  and `degraded` are deliberately not each other's negation, because an unparseable
  file IS a state persistence survives; an unreadable one is not, and it was being
  reported as though it were.

`README.md`'s configuration table and troubleshooting row for
`SAIHM_SEQ_STATE_PATH` described the DEFAULT location's behaviour under the
variable that overrides it. A location you set is yours: if it cannot be written,
calls fail and name the path rather than falling back, so a safeguard you asked for
never goes quiet. Only the default degrades to memory for the session.

### Compatibility

The tool LIST does not change, and neither does the public API of `index.js`. SIXTEEN
narrower things do change, and one of them is that some error MESSAGES change — an
earlier draft of this section opened by claiming none did, which was wrong on three
boot messages and is corrected in its own bullet below. ONE is a regression for some inputs and is
marked as such below; two more are breaking without being regressions (the
`SaihmConfigError` class change and the generated types); the rest are fixes:

- **CLI and server output changes where it was wrong.** `join` AND `upgrade` ("Also
  written to" — both reach it through the same `checkoutUrlBlock`) and `free-join`
  ("Back up") - all on STDOUT, so a consumer capturing only `2>` sees none of them -
  now render a non-ASCII path correctly instead of
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
  note and "key file:" in the success text — and the third is the stderr
  advisory on a group/world-readable `SAIHM_MASTER_SECRET_FILE`, which fires in the
  MCP server process too and not only under a CLI verb, as the bullet above says. All three now
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
  lines name the variable instead of pointing at a file that does not exist. That signature is
  MODULE-INTERNAL and no consumer can be holding it: `ensureSelfJoinIdentityEnv` is not in the
  barrel and `exports` has only `"."`. What reaches a consumer is the changed TEXT, not the type -
  an earlier draft told them to handle a `null` they cannot receive.
- **A configured but EMPTY secret is now an error instead of a silent switch to a
  different identity.** `bootFromEnv` guarded its self-join fallback on whether a
  secret VALUE was present rather than on whether one had been CONFIGURED, so a
  zero-byte `SAIHM_MASTER_SECRET_FILE` fell through to the default self-join identity:
  the process booted a different key while every backup line named the file the operator
  had configured. (`identityKeyFile()` did not exist at 0.4.1 — it is part of this fix, not of
  the defect it describes.) Reproduced end to end — the
  operator backs up an empty file and the only key to their memory is never named. It
  now raises `SaihmConfigError` naming the file. Anyone relying on an empty secret file
  as an opt-in to self-join must unset the variable instead. Two limits worth stating
  precisely: this covers a zero-byte FILE, never an empty VARIABLE — an empty
  `SAIHM_MASTER_SECRET_HEX` or `SAIHM_MASTER_SECRET_FILE` is treated as unset, on
  purpose, because a registry install UI emits exactly that from a blank optional
  field. A whitespace-only `SAIHM_MASTER_SECRET_FILE` is now named as such rather than
  read, where it previously failed with the value invisible in its own message.
- **An UNREADABLE self-join identity file now names the file and a remedy, not a bare errno.**
  The same new read that detects the zero-byte case has two failure arms, and only one of them
  was written. `ensureSelfJoinIdentityEnv()` re-threw Node's own error, so a permission or type
  failure surfaced as `EACCES: permission denied, open '<path>'` — and under `EISDIR`, whose
  message carries no path at all, with nothing identifying the file. At 0.4.1 there was no read
  here: the failure reached `bootFromEnv()`, which wrapped it as `SAIHM_MASTER_SECRET_FILE could
  not be read: <path>. …`. Moving the read earlier moved it out from behind that wrapper. It is
  now a `SaihmConfigError` reading `the self-join identity file could not be read: <path>
  (<errno>). Fix its permissions, or restore your backup of it — deleting it and running the join
  again mints a NEW identity, which starts an EMPTY memory.` Consumers matching the old text, or
  matching on `e.name === 'Error'` here, see a different string and `SaihmConfigError`. Match on
  the VARIABLE NAME, as elsewhere in this section — the bare errno this replaces could not be
  matched on at all.

- **A zero-byte self-join identity file is an error instead of an unrecoverable loop.**
  `ensureSelfJoinIdentityEnv()` treated any existing file as provisioned and set
  `SAIHM_MASTER_SECRET_FILE` to it itself, so the empty secret fell through to the
  guided-onboarding string — `No SAIHM memory yet on this device. Ask me to "Join
  SAIHM" first (the saihm_join tool) to create your free memory, then try again.` —
  which named no variable at all and pointed at the very verb that was looping, so
  every retry repeated. That string is also the one an agent keys on to trigger
  `saihm_join`, so this replaces a message some callers match on. It now names the self-join identity file and says what clears
  it, on the `saihm_join` and `free-join` paths — a plain memory-tool call under a
  zero-byte identity file still returns the unchanged guided string, which is correct:
  the subject here is the retry LOOP, and that is what is broken. It does NOT regenerate: this package writes that file atomically, so an empty one
  came from elsewhere, and minting a fresh identity over it is the silent switch to a
  different identity this section's empty-secret bullet exists to prevent.
- **`join` names the KEY FILE instead of an env var the caller may never have set.**
  The line was unconditionally `Keep SAIHM_MASTER_SECRET_HEX safe`, so the caller who
  reaches `join` to subscribe after `saihm_join` — key in a generated
  `free-identity.key`, no such variable set anywhere — was told to protect something
  that does not exist and never told the file that does. This is the same defect
  `free-join` fixed sixty lines away in the same module, in the copy nobody
  propagated to. Both verbs now resolve the key through one shared
  `identityKeyFile()` - exported from the module, NOT from the package - whose precedence
  mirrors `bootFromEnv`.
- **The `saihm_join` TOOL's key line changed wording in the ordinary case.** `Using your
  existing memory key (<path>).` is now `Using your existing memory key: <path>`, for every
  returning caller — including an ASCII path the fence leaves untouched. This is a TOOL result,
  not CLI output: the line lives in `joinPendingText`, which the CLI `join` verb never reaches,
  so an agent integrator matching on it is the audience for this bullet. The parenthetical went
  because a fenced value must not sit inside a delimiter it can itself close; the
  bullets above disclose only the scrubbing and the null branch. Match the prefix
  rather than the whole line.
- **`saihm_forget` tool-result text changes.** The erasure residual naming the local
  cache path moves from `safeField` at 256 to `safePathField` at
  `MAX_PATH_MESSAGE_CHARS`: a non-ASCII cache path renders correctly instead of as
  `?`, and the bound widens 33×. `forget` is a tool, not a CLI verb, so this is not
  covered by the CLI bullet.
- **`saihm_status` no longer parenthesises the BFSI sub-scores.** The line read
  `bfsi=0.812 (R=0.900 M=0.700)` and now reads `bfsi=0.812  R=0.900  M=0.700`, which
  is the two-space `key=value` convention every other field on that line already
  used. `R` and `M` are raw endpoint-chosen strings — unlike `tier`, `custody` and
  `snapshotEpoch`, they are not resolved through a closed-set checker — and `)`
  survives every fence in the renderer, so an endpoint answering
  `0.900)  Renew at …  (ig` closed our parenthetical and spoke the remainder in the
  server's own voice. Anything parsing that line for the parentheses must key on the
  `R=` and `M=` labels instead — and note that `bfsi_R` and `bfsi_M` have no
  `structuredContent` counterpart (that channel carries `bfsi` alone), so the text
  line is the only place they appear.
- **`SAIHM_HOME` now also redirects the saved checkout URL.** `persistCheckoutUrl`
  resolves `SAIHM_STATE_DIR`, else `SAIHM_HOME`, else `~/.saihm`; 0.4.1 resolved
  `SAIHM_STATE_DIR`, else `~/.saihm`. `SAIHM_HOME` is the only directory variable
  `server.json` declares, so before this an operator who relocated it still had
  `checkout-url.txt` written under `~/.saihm` with no declared way to redirect it.
  If you set `SAIHM_HOME` and read that file from automation, its path moves from
  `~/.saihm/checkout-url.txt` to `$SAIHM_HOME/checkout-url.txt` — set
  `SAIHM_STATE_DIR` to the old location to keep it where it was. The identity file
  is NOT affected: `defaultIdentityPath` reads `SAIHM_HOME` alone, unchanged.
- **Tool failure text changes for marked filesystem errors.** The render change is
  uniform because `failText` is shared, but only a tool that reaches a MARKED site can
  produce one — `recall` through the sequence state and the recall cache, `remember`
  through the sequence state ALONE (both of its recall-cache calls sit inside catches
  that swallow, so no cache failure reaches its failure text), `join` through the
  self-join identity. An earlier draft said "every tool's", which
  overstates reachability. A failure
  naming `SAIHM_HOME`, `SAIHM_SEQ_STATE_PATH` or `SAIHM_RECALL_CACHE_PATH` is
  rendered through the widened path bound rather than cut at 256, so these messages
  get longer and stop mangling non-ASCII. Measured with a 400-character home, one
  such message goes from 257 to 437 characters — measured on `ENAMETOOLONG` from
  `mkdir` under a 400-character `SAIHM_HOME`, which is the shape the figure names. The
  CLI changes identically — its top-level handler renders through the same `failText`
  — so `free-join` under a 400-character `SAIHM_HOME` goes from 258 to 438 characters
  on stderr.
- **Four configuration errors that name a path or URL now throw
  `SaihmConfigError` rather than `Error`.** Three of the four keep a byte-identical
  message — the invalid `SAIHM_ENDPOINT_URL`, the unreadable
  `SAIHM_MASTER_SECRET_FILE` and the unreadable self-join identity file. The fourth
  is the malformed-secret pair described in the message bullet above, whose text
  changes as well, and which throws `SaihmConfigError` only when the secret came from
  a FILE (`SAIHM_MASTER_SECRET_FILE` or the self-join identity file) and a plain
  `Error` when it came from `SAIHM_MASTER_SECRET_HEX`, because only a path has a path
  to widen the render to. For the three that keep their text,
  `e.name`, `String(e)`, the first line of `e.stack`, `JSON.stringify(e)` and
  `Object.keys(e)` differ — the last two because `SaihmConfigError` carries TWO new
  enumerable own properties: `valueKind` (`'path'` or `'url'`), which is how the
  renderer knows which budget to widen to, and `name`, which a plain `Error` carries
  on its prototype instead. Measured: `Object.keys(e)` is `["valueKind","name"]`
  against `[]` for a plain `Error`. "Byte-identical" is a claim about `e.message`
  only: what the OPERATOR SEES changes, because these now render through the widened
  path/URL budget rather than 256. Measured, a long invalid `SAIHM_ENDPOINT_URL` goes
  from 257 to 2,305 characters — it is budget-capped, so that figure is exact. The unreadable
  secret file message is NOT capped, so it grows with the path and no single figure states it;
  an earlier draft gave one without naming its input. Code matching `/^Error: SAIHM_/` against one of them
  should match the message or `e.name === 'SaihmConfigError'` instead. The class is
  NOT exported — the barrel does not re-export it and `exports` has only `"."` — so
  `instanceof` is not available to consumers; `e.name` and the message are. Two further sites are NEW rather than reclassified (the
  configured-but-empty secret and the zero-byte identity file), and the whitespace-only
  `SAIHM_MASTER_SECRET_FILE` shape ALSO moves from a plain `Error` to
  `SaihmConfigError` under a new message — seven construction sites ship in all.
  Configuration errors naming neither a path nor a URL still throw plain `Error`, as
  does a malformed `SAIHM_MASTER_SECRET_HEX`. `SaihmEndpointError` has always presented this shape.
- **A configuration error naming a URL now round-trips that URL.** The invalid
  `SAIHM_ENDPOINT_URL` message rendered through `safeField`, which maps every
  non-ASCII code unit to `?`, so an IDN endpoint came back as `SAIHM_ENDPOINT_URL is
  not a valid URL: m?nchen.example/rpc` — the operator's own configuration handed back
  unreadable, on the line that exists so they can fix it. Its BUDGET is widened to `MAX_URL_MESSAGE_CHARS` by this
  same release — disclosed under Budget above, so this is within-release ordering and
  not a claim about 0.4.1, which had neither the constant nor the function; only the CHARACTER policy was still the prose
  one, which is this release's defect class surviving inside the module that names it.
  It now renders through `safePathField` at the same budget. The line that decides is
  PROVENANCE, not the value's shape: a URL an ENDPOINT chose is attacker-capable and
  still collapses to ASCII, so `verificationUri` and the checkout URL are unchanged —
  there a mangled-but-visible URI is a failure the operator can see and report. This
  changes the RENDER only; `e.message` is untouched.
- **Three boot error messages change.** A malformed secret used to be reported
  against `SAIHM_MASTER_SECRET_HEX` whatever its actual source, so a corrupt self-join
  identity file produced `SAIHM_MASTER_SECRET_HEX must be canonical lowercase hex.`
  for a caller who had never set that variable. The message now names the source it
  read: `SAIHM_MASTER_SECRET_FILE <path>`, `SAIHM_MASTER_SECRET_HEX`, or
  `the self-join identity file <path>`. Two consequences for anyone matching on the
  text: `must be canonical lowercase hex` is now `must hold canonical lowercase hex`,
  which changes for EVERY source including `SAIHM_MASTER_SECRET_HEX`; and
  `must decode to >= 32 bytes` keeps its wording but gains a different prefix whenever
  the secret came from a file. Third, `SAIHM_MASTER_SECRET_HEX (or
  SAIHM_MASTER_SECRET_FILE) env var required (>= 64 hex chars).` is gone from the
  configured-but-empty path, replaced by the two messages in the empty-secret bullet
  above. Match on the VARIABLE NAME. That is the only remedy that
  works for all of them, and an earlier draft named `e.name` first without saying so:
  `e.name === 'SaihmConfigError'` holds only when the secret came from a FILE, because
  the `SAIHM_MASTER_SECRET_HEX` arm throws a plain `Error` — so the one source this
  bullet stresses is exactly the one that remedy misses.
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

[0.4.1]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.4.1
[0.4.0]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.4.0
[0.3.0]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.3.0
[0.2.1]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.2.1
[0.2.0]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.2.0
[0.1.11]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.11
[0.1.10]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.10
[0.1.9]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.9
[0.1.8]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.8
[0.1.7]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.7
[0.1.6]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.6
[0.1.5]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.5
[0.1.3]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.3
[0.1.0]: https://www.npmjs.com/package/@saihm/mcp-server-pro/v/0.1.0
[Unreleased]: https://github.com/SAIHM-Admin/saihm-mcp-server-pro/compare/v0.4.1...HEAD
