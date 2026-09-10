# uci — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Typed model, one arena: `parse`/`parseDiag` build a `Package{ name?, sections:[]Section }`
(`Section{ type, name?, anonymous, options:[]Option }`, `Option{ key, kind:.single|.list, values }`)
in an internal arena — one `Package.deinit(gpa)` frees everything; `serialize` writes it back as
canonical text. Reentrant, no shared state. Documented quoting, exactly: single quotes take no
escapes; double quotes take `\" \' \\ \n \t \r` (a backslash before any other char yields that char);
bare words end at whitespace; adjacent segments of one token concatenate (`'a'"b"c` → `abc`); quotes
may not span lines; `#` starts a comment only at the start of a token; CRLF accepted. Repeated-key
semantics: a repeated `option` under one key overwrites (last wins, matching `uci set`); `list`
entries accumulate in order; mixing `option` and `list` under one key → `error.MixedOptionList`.
Never-panic, line-numbered errors: malformed input yields a typed `ParseError` (`UnterminatedQuote`,
`BadKeyword`, `MissingArgument`, `TooManyArguments`, `OptionOutsideSection`, `MixedOptionList`, …);
`parseDiag` fills a 1-based `Diagnostics.line` (0 = not line-tied). Serialization of a value with a
control char that has no UCI escape → `error.UnserializableValue`. Bounded: input over 16 MiB →
`error.InputTooLarge`; a line over 16 KiB → `error.LineTooLong`. Canonical output: optional `package
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
text — the input/line-length caps and the never-panic typed-error contract bound memory and rule out
OOB/hang on garbage or bit-flipped input. Deviations to note: an empty quoted section name (`config
rule ''`) is treated as anonymous; values with control chars other than `\n \t \r` cannot be
represented in UCI text and fail serialization. Out of scope: the UCI CLI layer — `uci set/commit`,
`/etc/config` discovery, the transactional delta/state files under `/var/state`, and typed value
coercion. This is the file codec only.

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
bytes. Quoting: double-quote escapes, single-quote literalness, bare words, mid-word `#`, token
concatenation of quoted segments, comments/blank lines, empty quoted value. Semantics: anonymous
sections, list accumulation, duplicate-option last-wins, mixed option/list rejected. Errors (with
asserted line numbers): unterminated single/double quote, option before any section, bad keyword,
missing/too-many arguments, line-too-long, input-too-large. Plus accessor lookups (incl.
`sectionByName`/`nth` against the real-`uci`-capture fixture below — name-across-types resolution,
`@type[N]` positive/negative/out-of-range/no-match), CRLF input,
`package` header serialization, and quoted keys/types round-tripping. Run: `zig build
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
   Fixed in the parser and serializer (the latter now rejects ALL sub-0x20 bytes, not just
   "other" ones, since none of them have a working escape).
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
