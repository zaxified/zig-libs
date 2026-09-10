# uci — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Typed model, one arena: `parse`/`parseDiag` build a `Package{ name?, sections:[]Section }`
(`Section{ type, name?, anonymous, options:[]Option }`, `Option{ key, kind:.single|.list, values }`)
in an internal arena — one `Package.deinit(gpa)` frees everything; `serialize` writes it back as
canonical text. Reentrant, no shared state. Documented quoting, exactly: single quotes take no
escapes (everything between them, `\t`/`\n`/`\r` included, is literal); double quotes take `\" \' \\`
as TRUE escapes, and a backslash before any OTHER character (including `n`/`t`/`r`) just drops the
backslash and yields that character verbatim — UCI text has no backslash escape that PRODUCES a
control byte, but `\t`/`\n`/`\r` can still appear literally, unescaped, inside either kind of quote
(audit A1 U6, `uci_validate_text`, util.c:96 — the only three sub-0x20 bytes real `uci` allows in a
value, written back raw, not via an escape); bare words end at whitespace; adjacent segments of one
token concatenate (`'a'"b"c` → `abc`). Audit A1 U5: a quote (either kind) MAY span physical lines —
real `uci` (`parse_single_quote`/`parse_double_quote`, file.c:157,187) keeps reading via `uci_getln`
until the matching quote closes, and the value keeps the real `\n` byte at each line break crossed;
only running out of input with a quote still open is `error.UnterminatedQuote` (previously: any quote
left open at the end of the line it started on, which rejected the ENTIRE file for a legitimate
multi-line value — a certificate, an SSH key, a LuCI banner). Outside a quote the grammar is still
exactly one physical line: a bare word, `#`, and the statement keyword never cross a `\n`. `#` starts
a comment at the start of a token, OR anywhere inside a bare (unquoted) run — either way it truncates
the token AND discards the rest of the line, matching real `uci` (audit A1 U4, measured against the
real binary: `a#b` unquoted is `a`, not `a#b` — this SPEC previously claimed the opposite as "the
format", which the real binary disproved); `#` inside quotes stays literal. CRLF accepted (outside a
quote only — the CRLF tolerance is a statement-grammar convenience, not part of a quoted value's
content). Repeated-key semantics: a repeated `option` under one key overwrites
(last wins, matching `uci set`); `list` entries accumulate in order; mixing `option` and `list` under
one key → `error.MixedOptionList`, and an `option`/`list` line with no value → `error.MissingArgument`
— **both are this module's OWN additional strictness, not real UCI semantics** (audit A1 U11/U12):
real `uci` merges a mixed option/list under one key (whichever kind appears LAST for that key wins,
discarding the earlier kind) and loads a valueless `option` by simply dropping it, rather than
rejecting the whole file either way. Section/option names real `uci` never accepts are rejected too
(audit A1 U7, `error.InvalidName`; not enforced on an option KEY when *writing* — see
`SerializeError.InvalidName` in `root.zig`): section/option names must be alphanumeric or `_` (not
even `-`); section types are looser (alphanumeric/`_` or any other printable, non-space ASCII byte).
A zero-length name/type/key is exempt from that check (see U7's fix commit) — `config ''`/`option ''
v` producing a literal empty type/key stays accepted, per the deviation noted below. Two `config`
blocks sharing a name are rejected outright as `error.DuplicateSection` (audit A1 U1) rather than
silently building two `Section`s and answering every accessor from the FIRST one's values: real `uci`
either merges same-type duplicates (last option value wins) or rejects a same-name/different-type
collision, and this module's `[]Section` model cannot represent the merge, so it rejects both shapes
rather than silently disagreeing with the device about which value is live.
Never-panic, line-numbered errors: malformed input yields a typed `ParseError` (`UnterminatedQuote`,
`BadKeyword`, `MissingArgument`, `TooManyArguments`, `OptionOutsideSection`, `MixedOptionList`,
`DuplicateSection`, `InvalidName`, `MemoryLimitExceeded`, …); `parseDiag` fills a 1-based
`Diagnostics.line` (0 = not line-tied, e.g. `InputTooLarge`/`MemoryLimitExceeded`). Serialization of
a value with a control byte other than `\t`/`\n`/`\r` (audit A1 U6: those three ARE representable,
written literally) → `error.UnserializableValue`; a section type/name with a character `parse` would
also have rejected → `error.InvalidName`.
Bounded: input over 16 MiB → `error.InputTooLarge`; a line over 16 KiB → `error.LineTooLong`; the
built model over 300000 total items (sections + options + values, combined) →
`error.MemoryLimitExceeded` (audit A1 U3 — the 16 MiB text cap did not bound the MODEL built from
it: a legal, `max_input_len`-sized input measured 22x-41.5x live-byte amplification, up to 371 MB RSS
from a 16.6 MB file; a flat item-count cap bounds that regardless of input shape, independent of
input size — see `max_total_items`'s doc comment in `root.zig` for why a size-relative ratio does
not work here). Canonical output: optional `package
'<name>'` header, blank line between section blocks, tab-indented options, values single-quoted
(double-quoted with escapes only when they contain `'` or a control char). Accessors: `section(type,
name)`, `get`/`getList`, `iterate(type)`, deep `eql`. Two more resolve the addressing forms a UCI key
path uses: `sectionByName(name)` resolves `pkg.<name>.<opt>` (UCI indexes section names in one
namespace per package, not one per type); `nth(type, index)` resolves `@type[N]` positional
addressing including the negative-index-from-the-end form (a negative index adds the
matching-section count to itself; out of range either direction — including a still-negative
result — is "not found", returned here as `null` rather than an error; anonymous and named
sections of `type` both count).

**Both of those are MEASURED against the real `uci` binary.** The transcript is frozen in `root.zig`'s "addressing probe" capture and replayed by a test; it was
taken 2026-09-08 in the same OpenWRT 25.12.4 guest the rest of the capture comes from, with a
config carrying a NAMED, an ANONYMOUS and a second NAMED section of one type — the case the older
`testcfg` capture could not answer, because both of its `rule` sections are anonymous. Real `uci`
labels the anonymous section `@t[1]` in its own `uci show` output, so the ordering is corroborated
from a second direction. Clean-room from the documented OpenWRT UCI file format, with the real
binary used purely as a black-box oracle (root `NOTICE` §0).

## Threat model / out of scope
Not security-sensitive; the hardening is denial-of-service and crash resistance on hostile config
text — the input/line-length/item-count caps and the never-panic typed-error contract bound memory
and rule out OOB/hang on garbage or bit-flipped input. Deviations to note: an empty quoted section
name (`config rule ''`) is treated as anonymous; an empty quoted section type or option key
(`config ''`, `option '' v`) is accepted literally (audit A1 U18's regression test relies on this;
it is the one shape the U7 name/type/key validator deliberately does not cover, since real uci's own
handling of a zero-length argument is a different failure mode — "insufficient arguments" at the
CLI-argument layer — not a character-class violation); values with control chars other than
`\n \t \r` cannot be represented in UCI text and fail serialization. Out of scope: the UCI CLI
layer — `uci set/commit`, `/etc/config` discovery, the transactional delta/state files under
`/var/state`, and typed value coercion. This is the file codec only.

**The concrete trap in "this is the file codec only": a file-only reader loses staged-but-uncommitted
state.** `uci set` without a following `commit` never touches `/etc/config/<pkg>` — it appends a
delta line to `/tmp/.uci/<pkg>`, and `uci get`/`uci show` return that staged value while the on-disk
config file still holds the old one. This is exactly LuCI's "Save" without
"Apply" (routers commonly sit in this state — a webUI change staged but not yet applied), and it is
the concrete trap for anyone replacing a shelled-out `uci get` with `parse(gpa,
readFile("/etc/config/<pkg>"))`: the read is silently stale for any package with a pending delta,
with no error to catch it.

**Measured on the real binary** (OpenWRT 25.12.4 guest, 2026-09-08), not assumed. A config holding
`option v A`, then `uci set probe.alpha.v=Z` with no commit:

```
uci get probe.alpha.v   -> Z          <- the staged value
/etc/config/probe       -> option v A <- the file still holds the old one
/tmp/.uci/probe         -> probe.alpha.v='Z'
```

`uci revert` empties the delta file rather than deleting it — the same run, after
`uci revert probe`:

```
ls -l /tmp/.uci/probe   -> -rw-r--r-- 1 root root 0 ... /tmp/.uci/probe
wc -c  /tmp/.uci/probe  -> 0          <- present, and empty
uci get probe.alpha.v   -> A          <- back to the on-disk value
```

So a caller that checks for the delta file's EXISTENCE as a "has staged changes" fallback latches
that fallback permanently true the first time anything is staged and reverted, even with zero
changes actually pending — check the file's contents/size, not merely whether it exists.

## Verification
Golden tests: parse a realistic `network` config into the model and assert its structure; round-trip
stability (`parse∘serialize` equal, second pass byte-identical) and the exact canonical serialization
bytes. Quoting: double-quote escapes, single-quote literalness, bare words, mid-word `#` (truncates
the token AND discards the rest of the line — audit A1 U4), token concatenation of quoted segments,
comments/blank lines, empty quoted value. Semantics: anonymous sections, list accumulation,
duplicate-option last-wins, mixed option/list rejected, duplicate SECTION name rejected regardless of
type (audit A1 U1), invalid section/option names rejected (audit A1 U7), the model-size cap (audit A1
U3, exact 2N+1-item boundary pinned). Errors (with asserted line numbers): unterminated single/double
quote, option before any section, bad keyword, missing/too-many arguments, line-too-long,
input-too-large. Plus accessor lookups (incl.
`sectionByName`/`nth` against the real-`uci`-capture fixture below — name-across-types resolution,
`@type[N]` positive/negative/out-of-range/no-match), CRLF input,
`package` header serialization, and quoted-type round-tripping (a type needing quotes but still
valid per real uci's name rule — no equivalent case exists for a key, see U7 below). Run: `zig build
test-uci`.

**Fuzz corpus (audit A1 U15).** `fuzzParse`/`fuzzRoundTrip` run a fixed, pinned corpus
(`parse_seeds`/`roundtrip_scripts` in `root.zig`) on every `zig build test-uci` — no `--fuzz`
needed for that baseline coverage; each seed's shape is asserted by a `corpus: …` test next to it.
For continuous generative fuzzing beyond the pinned corpus: `zig build test-uci
-Doptimize=ReleaseSafe --fuzz` (measured working 2026-09-05). `--fuzz` does not currently compile
in Debug on this toolchain (`lib/compiler/test_runner.zig:566`, a toolchain limitation, not a
module bug) — no CI/build-gate step in this repo runs `--fuzz` continuously for any module yet;
wiring one in is a repo-wide `build.zig`/gate change, out of this module's scope.

**Real `uci` capture (OpenWRT 25.12.4 VM lane).** Two hand-written configs were pushed into
`/etc/config/` inside the `scripts/vm/` OpenWRT VM and run through the real `uci` binary; the raw
config bytes plus the real `uci export`/`uci show` stdout are frozen in `root.zig`'s "real uci
capture" section — exercising the real binary purely as a black-box test oracle (root `NOTICE`
policy §0). One config concentrates on quoting/escaping (one option per escape sequence); the other
covers anonymous sections + their `@type[N]` generated addressing, list options, and mixed
quoting/bare-word styles.

**Two real, reproducible bugs were found this way and fixed (not papered over in a golden):**
1. Real `uci`'s double-quote escapes are only `\\`, `\"`, `\'` — a backslash before any OTHER
   character (n/t/r included) drops the backslash and keeps that character literally; UCI text has
   **no escape that produces an actual control byte**. This module previously converted `\n`/`\t`/
   `\r` to real control bytes — invisible to every existing test because they only ever round-tripped
   through this module's own encoder/decoder pair (a self-consistent "blind oracle"; even the fuzz
   round-trip harness can't see a symmetric bug). Confirmed with 8 independent escape probes
   (`\\`,`\"`,`\'`,`\n`,`\t`,`\r`,`\y`, plus single-quote-takes-no-escapes) against the real binary.
   Fixed in the parser and serializer. ⚠ **Correction (audit A1 U6, after this SPEC entry was
   written):** the serializer fix above over-corrected — it rejected `\n`/`\t`/`\r` outright as
   `error.UnserializableValue`, on the reasoning that "no escape produces them" implied "they can't be
   represented". That conflates two different claims: real `uci_validate_text` (util.c:96) DOES allow
   those three sub-0x20 bytes in a value, it just never needs a backslash escape for them — they're
   written back literally, raw, inside the quotes. The serializer now does the same. `\n` in
   particular is representable end to end only because a quote may now span physical lines (U5,
   below) — a value containing a real newline round-trips as a multi-line quoted literal, the shape
   `uci export` itself produces (e.g. `option multi 'line1<LF>line2'`).
3. **Audit A1 U5 (found in the follow-up fix campaign, not the original audit pass):** the parser
   used to be line-oriented — one statement, one physical line, full stop — so a quoted value that
   didn't close before the line ended was `error.UnterminatedQuote`, rejecting the WHOLE file. Real
   `uci` (`parse_single_quote`/`parse_double_quote`, file.c:157,187) instead keeps reading further
   lines via `uci_getln` until the quote closes; the value keeps the real `\n` byte at each line break.
   A value with an embedded newline is not exotic here — a certificate, an SSH key, a LuCI banner —
   and the old behavior failed on the entire package for one such value, not just that option. Fixed
   by rewriting the tokenizer from line-oriented to byte-oriented: outside a quote, the statement
   grammar is still exactly one physical line (unaffected); inside a quote, `\n` is ordinary content
   and only genuine end-of-file with a quote still open is an error. Verified both directions: the
   audit's own multi-line capture (`option multi 'line1<LF>line2'`) now parses AND round-trips, and
   the full existing corpus (golden captures, real OpenWRT configs, the mutation suite, all
   diagnostic-line-number tests) is unchanged — see `root.zig`'s "audit A1 U5" test and the fix
   commit for the RED→GREEN numbers.
2. Real `uci export` prints a bare, unquoted `package <name>` header when the name is
   identifier-safe (`package testcfg`, not `package 'testcfg'`). Fixed (`serialize` now treats the
   package name like a section-type word).

**One style-only difference found and deliberately NOT changed:** a value containing a literal `'`
is double-quoted by this module (`"a'b"`); real `uci` instead splices single-quoted segments the
POSIX-shell way (`'a'\''b'`). Both encode the identical value; changing this module's simpler,
single-segment choice to replicate real `uci`'s multi-segment splicing was judged not worth it for a
cosmetic difference with no behavioral impact. Also not replicated: real `uci export` emits one
extra trailing blank line after the very last section (this module's blank line is only ever
*between* blocks) — a CLI-output-only convention, not a canonical-serialization invariant, and
changing it would touch every other hand test asserting no trailing blank line.

**Audit A1, second fix pass (2026-09-10, fixwt/c).** This module has zero consumers in this repo
(verified against `example-apps/` too), so per the campaign's P1 rule, input-hardening decisions —
including new error values and rejecting input that previously parsed — are the fixer's call, not a
question for the user. Four findings closed this way:
1. **U1 — duplicate section name.** Two `config` blocks sharing a name used to silently build TWO
   `Section`s, with every accessor answering from the FIRST one's (stale) values — the device uses
   the LAST. The model can't represent real uci's merge, so both a same-type collision (which real
   uci merges) and a same-name/different-type collision (which real uci's strict mode already
   rejects) now fail closed as `error.DuplicateSection`, rather than one implementation of "the
   config" silently disagreeing with the other about which value is live.
2. **U3 — the 16 MiB input cap didn't bound the built MODEL.** Measured 22x-41.5x live-byte
   amplification on a legal, `max_input_len`-sized input (up to 371 MB RSS from 16.6 MB of text). A
   ratio-of-input-size cap was tried and rejected: the worst measured shape amplifies close enough to
   this module's OWN legitimate N=64000-distinct-keys perf test (U2's regression guard) that no ratio
   can admit one and reject the other. `max_total_items` (a flat cap on sections+options+values
   combined, independent of input size) does — `error.MemoryLimitExceeded`.
3. **U4 — mid-word `#`.** This SPEC claimed, as fact about the format, that `#` only starts a comment
   at the start of a token. The real binary disproves it: `#` anywhere in a bare (unquoted) run
   truncates the token AND discards the rest of the line. Fixed in `nextToken`; the SPEC line above is
   corrected, not just the code.
4. **U7 — no name/type/key validation.** Real uci's own validator (`uci_validate_str`) never accepted
   most of the 15 hand-written probes this module did (hyphens/dots/spaces/non-ASCII in a name or
   type, hyphens/dots in a key) — dangerous on the WRITE path especially, since `serialize` could
   produce a file real uci refuses to load back, breaking the whole package, not just one section.
   Both `parse` and `serialize` now enforce it (`error.InvalidName`) for section type/name; `parse`
   also enforces it for option keys, but `serialize` deliberately does not (see U14 below). Zero-length
   names/keys are exempt — see the Threat model section's note on U18.

Two more findings closed WITHOUT a code change, by correcting this SPEC instead (P2, "documentation is
the spec, fix the code" — but here the code and doc already agreed with each other, they were just
both wrong about what real uci does, so the fix corrects the CLAIM, not the code):
- **U11/U12 — `MixedOptionList`/valueless-`option` rejection presented as "UCI semantics".** They
  aren't: real uci is more lenient on both (merges a mixed option/list, whichever kind is LAST for a
  key wins; loads a file with a valueless `option` and simply drops it). This module's stricter,
  reject-the-whole-file behavior is intentional and unchanged, but the "Repeated-key semantics" line
  above now says so explicitly instead of implying it is inherited from the format.

**One tension this surfaced, for whoever revisits U5/U6/U8/U9/U10/U19 next:** U7's validation
deliberately carves out a zero-length name/type/key (a real, load-bearing shape — U18's regression
test) and deliberately does NOT reject an option key containing `'` at `serialize` time (U14's
already-closed guarantee that such a key, however it got into a hand-built `Package`, is written
quoted rather than bare/injectable). Both carve-outs are narrow and load-bearing on an *earlier* fix;
widening U7 later without re-reading U14/U18 first will silently re-break one of them.

## Backlog / deferred
None beyond the documented UCI-CLI-layer/typed-coercion out-of-scope list above, and the two
deliberate style differences from real `uci export` noted above (literal-value quoting-segment style;
one trailing blank line).

## Status
`gap · any · codec · reentrant` + deps: none (std only) — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/root.zig:1110+ asserts against verbatim `uci export` / `uci show` stdout captured from a real uci binary, which is what surfaced two symmetric escape bugs a round trip could not see; the rest of the parse/serialise surface is hand-authored

**How it got there.** The anchoring work landed. DONE 463e443: real uci; TWO symmetric escape bugs a round trip could never see
