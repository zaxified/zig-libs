# uci — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-04** — test against the real `uci` binary (`UCI_BIN`): it replays `save`'s few `^` records to the same section order, also after a delete and a new section; card records the delta audit.

- **2026-11-04** — **NO CONSUMER-VISIBLE CHANGE:** docs for `save` (SPEC threat paragraph, temp-debris row, README, store.zig header) and the test-only `SessionLabel.save_moved` fuzz reach label; the call-order test now expects the revert fsync.

- **2026-11-04** — **BREAKING (delta audit fixes; new `StoreError.LockFailed`, new `Step.fsync_delta`):** `save` can no longer write a delta that does not load again. `diffRecords` now emits `^` records only for the sections outside the longest run that keeps its order (one `reorder` among 6000 sections is one record, was 6000); `saveEditor` replays its own output on the base editor and refuses with `WouldNotReload` (old delta left in place) when it would not give the editor's state or would cost more than `max_delta_work` to replay. `diffRecords` returns `error.WorkLimitExceeded` for such a reshuffle and `error.InvalidName` for a package name that `diff.deltaNameOk` refuses; `saveEditor` returns `InvalidPackageName` for a name no delta record can carry (leading `-`/`+`/`@`/`^`/`|`/`~`, or `.`, `=`, space, `'`; the real binary writes `-x.lan.x='1'` too and then loses the change itself: measured). `reapTemps` handles names up to 255 bytes; a temp name over the file system's limit is `InvalidPackageName`, not `WriteFailed`. `merge` also catches one name twice with two types in one Package (`parse` cannot produce it) before changing anything. `revert` fsyncs the truncation. A `flock` refused by the kernel is `LockFailed`, not `ReadFailed`.
- **2026-11-04** — **Tests only (delta audit of the file layer, 183 mutants):** a wrapped `std.Io` (`CallProbe` in `store_test.zig`) now sees the real calls of a commit -- fsync of the temp, `rename`, fsync of the directory in that order, failure of each told apart, the temp's mode before `chmod`, `chmod` and truncate failures, an exclusive temp-name collision retried, the exact number of lock attempts for `lock_timeout_ms` 0 and 20, the stamp taken before the read (a commit by another process right after the read is `ChangedOnDisk`, at `editor` and after `Session.commit`), a file that shrinks or grows while read, a file swapped for a directory between `lstat` and `open`. Plus `Stamp.eql` per field, `eqlOnDisk` per difference, exact `diffRecords` output per filter, `save` mode/temps/size/`-p`, argument shapes of `batch` commands, `merge` atomicity on a clash, session item cap over several packages, `FileTooLarge` over `max_input_len`, `OutOfMemory` staying `OutOfMemory`, reaper decoys. No production code changed.

- **2026-11-04** — **BREAKING (last review round):** `Store.commitEditor` takes a fourth argument, `expect: ?Stamp` (`Store.stamp(name)` taken BEFORE the load): under the lock the file's inode, size and mtime are compared and a mismatch is the new `StoreError.ChangedOnDisk`, nothing written (a lost update by another process's commit). `Session` keeps the stamp per package and re-takes it after a commit; `Store.commit` of a bare model and `Store.replace` overwrite (documented). `CommitError` no longer contains `SimulatedCrash` (a test-build-only member that made an exhaustive `switch` differ between test and normal builds); the test seam reports a crash as `WriteFailed` plus `crash_hook.tripped`. Also: the lock is re-checked against the path's inode after it is won (a rename in between retries); the lock wait saturates instead of wrapping; a new package (no file, no lock) no longer reaps temps; a control byte in a package name is refused even with `allow_paths`; `StagedNotCleared` takes precedence over `CommittedNotDurable` (documented on both); `Session.commit` documents the stale, dirty editor after those two errors. Card text corrected (not faster than libuci on quoted values).

- **2026-11-04** — **Fix, found by the session fuzz harness (`saved_replayed` label):** `diffRecords` (and so `save` and `revert pkg.sec`) matched a NAMED section to an ANONYMOUS one with the same id (a section named `cfg0392bd` against the generated id `cfg0392bd`) and replayed a type change onto the wrong one. Matching now needs the same namedness, and a state holding two sections with one id has no delta: `error.DuplicateSection`.

- **2026-11-04** — **BEHAVIOURAL + NEW API (fix round after an independent review; additive except the new `StoreError` members `CommittedNotDurable`, `LockTimeout`, `NoSaveDirectory`, which widen the error set — BREAKING for an exhaustive `switch` over `StoreError`):** `commit` now takes the package's exclusive `flock` (what `strace -f` of `uci commit` shows) and waits at most `StoreOptions.lock_timeout_ms` (default 5000). A failing directory `fsync` after the rename is `CommittedNotDurable` and a delta that cannot be emptied `StagedNotCleared`: in both the new file is visible and `commitStaged` must not be retried (it would replay the delta); crash points now sit between the rename and the delta, and after the directory sync. Temp names are random (`.<pkg>.uci-tmp-<16 hex>`, no pid, so no `std.os.linux` dependency) and stale ones of the package are reaped on commit (exact pattern, regular files). `revert` opens without following links and never creates. A symlink config file pointing at a plain name in the same directory is followed and stays a link, like the binary (chains and links out of the directory stay `NotRegularFile`). New: `Session.save`/`Store.saveEditor` (the staged state as delta records, `diffRecords`), `revert pkg.sec[.opt]` in `Session`, `Store.override` (`-C`), `Store.extra_save` (`-p`), `Store.loadView`/`baseEditor`/`applyDeltas`, `Session.resetBudget`; the editor work budget is per `Session` (was per run) and open packages share `max_session_items`; `merge` checks the whole text before it changes anything. `Session` editors are now built from the committed file plus deltas so anonymous ids match the delta records, and are re-read after a commit. `meta.platform` is `.any` again. Tests: recorded step order with two mutants that turn it red, byte comparison at every crash point, a short write (ENOSPC) with the original intact and the temp removed, link/FIFO/directory cases captured from the binary, the lock with a bounded wait. Bench: roles match the card (go-uci reference, libuci fastest), a quoted-values row and a multi-line row (go-uci cannot read those).

- **2026-11-04** — **Survey + benchmark + one finding (additive API: `Store.readFile`, `store.eqlOnDisk`):** the grade-2 survey (SPEC `## Compared with`: every libuci/`uci` feature with a verdict; libuci's source never read, go-uci MIT read), `tools/bench.zig` with `c_bench.c` (libuci built from a source copy) and `go_bench/` (digineo/go-uci): ours is 0.28–0.90× libuci and 0.30–0.39× go-uci on parse/export rows (SPEC Performance line). The `UCI_FUZZ` session harness found that `Store.commit` of an `Editor` whose last `del_list` entry was removed returned `WouldNotReload`: libuci keeps such an option in its model with no value (measured, `uci show` prints `net.lan.dns=`) but no text can say it; the reload check now ignores option-less options, and a capture case pins the binary's behaviour. `Store.readFile` is `uci -f`. No change to what axp uses: a `parseDiag`/`sectionByName`/`nth` probe is byte-identical in size before and after (ReleaseSmall, mips32 soft-float 39652 B, arm 17284 B, x86_64 15688 B).

- **2026-11-04** — **NEW API (additive):** the file layer. `Store` (`load`, `loadStaged`, `staged`, `hasStaged`, `revert`, `commit`, `commitEditor`, `commitStaged`, `importText`, `replace`): a commit writes a temp file in the config directory, `fsync`s it, `rename(2)`s it over the old file and `fsync`s the directory, keeps the old file's mode (new files `0600`) and empties the delta; text `parse` could not read back is never written (`WouldNotReload`). Package names are one plain file name by default (`StoreOptions.allow_paths` opts out); a FIFO, directory, device or symlink is `NotRegularFile`, absence is `PackageNotFound` and nothing else is, a read error is `ReadFailed`/`AccessDenied`. `Session` (`uci batch`: `set add add_list del_list delete rename reorder revert commit`; stops at the first failing command, `RunOptions.keep_going` goes on like the binary; bounded by the editor work cap), `merge` (`uci import -m`), `parseScript`, `ShowOptions.delimiter` (`uci -d`). Replayed against the real binary (`tools/capture-store.py`, 14 cases) and fuzzed (`UCI_FUZZ` harness `uci-session`).

- **2026-10-31** — **Tests:** delta mutation audit of the § GY no-panic sweep (schemata over the sweep diff; new `(sweep audit GY-…)` tests). No code change.

- **2026-10-31** — **BEHAVIOURAL, small API addition:** no-panic sweep + blind review (§ GY). Editor mutators refuse growth past `max_total_items` (`EditError.MemoryLimitExceeded`, was only refused by `toPackage`). Section-id and option-key lookups are hashed. `applyDelta` charges scans, moves and compared bytes to a work counter and stops at `pub const max_delta_work` (2^26) with the new `DeltaError.WorkLimitExceeded`. `delList` and `show` with `@type[N]` are linear (were O(n²)). `show` refuses output past `pub const max_show_len` (64 MiB) with the new `error.OutputTooLarge` (`ShowError`) and never truncates. `Editor.applyDelta` is documented as not atomic. `serialize` can write lines `parse` would refuse (documented, Backlog).

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-09** — tests: deterministic fuzz driver `UCI_FUZZ` over the existing harnesses.
- **2026-10-06** — **FIX (behaviour change): `serialize` refuses an empty section type, section name or
  option key with `error.InvalidName`.** It used to write `config ''` / `option '' 'v'`, which the real
  libuci refuses as a whole file ("insufficient arguments") — one empty word made the config unloadable on
  OpenWRT — and `config t ''`, which libuci reads as an anonymous section. `parse` still accepts the empty
  words (U18, fail-open on read). Found by the new libuci oracle (`tools/interop.zig` + `tools/libuci_corpus.py`
  → `src/libuci_oracle_test.zig`, 465 inputs): every other input agrees with libuci on the model (0 value
  divergences) and on reading back what `serialize` writes.

- **2026-10-04** — ADDED (all four survey 2026-09-30 gaps), no breaking change: `applyDelta` /
  `Editor.applyDelta` replay a staged-delta file (`/tmp/.uci/<pkg>`) so a file reader sees what
  `uci get` sees; `Editor` (`set`, `setSection`, `add`, `delete`, `deleteOption`,
  `deleteListItem`, `addList`, `delList`, `rename`, `renameOption`, `reorder`, `toPackage`) with
  libuci's semantics; `show` / `Editor.show` (`uci show`, `-X`); `Section.getBool` / `getInt`;
  `Package.resolveSection` (name, `@type[N]`, anonymous id); `anonymousName` (libuci's
  `cfg%02x%04x` ids: section counter + DJB2 of the type, measured); `validNameChars` /
  `validTypeChars` are now public. All formats measured on the real `uci` through its command
  line (`tools/capture-delta.sh` → `src/testdata/delta_capture.txt`, replayed byte for byte).
  Refused where `uci` accepts: renames onto a name/key in use (would produce a package `parse`
  rejects). axp can drop its `uci get` fallback for packages with a pending delta.
  Mutation 2026-10-04: 36 mutants, 35 killed, 1 equivalent; it also found that an index delete
  on a SINGLE option deletes it in `uci` (fixed before landing, test added).

- **2026-09-17** — **BEHAVIOURAL (accepts more; `SerializeError` grows):** audit A1 U25, user
  decision (behave as real `uci`). A `config` block reusing the name of an earlier section of the
  same type now continues that section instead of failing with `DuplicateSection`: a repeated
  option replaces, a list goes on, the section keeps its first position, so `sections.len` can be
  smaller than the number of `config` lines. The same name with another type is still
  `DuplicateSection` (real `uci`'s default strict mode). `serialize` returns the new
  `SerializeError.DuplicateSection` for two sections sharing a name — an exhaustive `switch` over
  `SerializeError` must handle it. Measured on the real binary; `tools/capture-grammar.sh` gained
  eight probes.

- **2026-09-17** — **NO CONSUMER-VISIBLE CHANGE:** test only (audit U23, U24). The round-trip
  harness draws types, names and keys from the validators' alphabets and keeps values printable,
  so its corpus now reaches the comparison (5 of 6 scripts, was 0 of 5 non-empty); the corpus
  guard pins that count.

- **2026-09-13** — **BEHAVIOURAL:** audit A1 U8, U9, U10, U19 (round-2 decision: read the file as
  the real `uci` binary does, established by RUNNING it, never by reading libuci) and U17
  (provenance). Every rule below is replayed from `src/testdata/grammar_capture.txt`, 130 probe
  files captured with the new `tools/capture-grammar.sh`.
  U8: a backslash outside quotes takes the next byte literally (`a\ b` was `TooManyArguments`, is now
  `a b`) or, before a line break, continues the word; inside double quotes a backslash before a line
  break now adds nothing (`"a\<LF>b"` is `ab`, was `a<LF>b` — the old test asserted the unmeasured
  guess).
  U9: `;` separates statements on a line. After a word with a quote or escape it is a separator;
  inside a plain word it drops the rest of the line, as real `uci` does. Keywords also accept
  `c`/`o`/`l`/`p`; a quoted keyword is `BadKeyword`.
  U10: `option k ''` and a valueless `option k` set nothing (was: an option with value `""`, and
  `MissingArgument` — U12's rejection is superseded); `list k` adds an empty element. `serialize`
  refuses an empty single value with `UnserializableValue`.
  U19: a `package` line is validated and ignored; `parse` no longer sets `Package.name`, which is now
  the caller's header for `serialize`, and `serialize` refuses an invalid one (`InvalidName`).
  U17: comments citing libuci source lines (earlier entries below keep theirs as history) were
  replaced by measurements after a separate reviewer found no ported logic.
  `scripts/modtest uci`: 53/53 (was 52), Debug and ReleaseFast.

- **2026-09-11** — Audit A1 U5/U6 (HIGH): the tokenizer was rewritten from line-oriented to
  byte-oriented. Real `uci` (`parse_single_quote`/`parse_double_quote`, file.c:157,187) lets a quote
  span physical lines via `uci_getln`; this module used to reject the WHOLE FILE
  (`error.UnterminatedQuote`) for a quote that didn't close before its line ended — availability
  impact on the main parse path for any value with an embedded newline (a certificate, an SSH key, a
  multi-line LuCI form field). Outside a quote, the grammar is still exactly one physical line
  (unaffected). Downstream of that fix, U6: the serializer previously rejected ALL sub-0x20 bytes in
  a value, including `\t`/`\n`/`\r` — the ONLY three real `uci_validate_text` (util.c:96) actually
  allows, written back literally, not via an escape (the earlier "no escape produces a control byte"
  fix had over-corrected into "no control byte can be represented" for those three). Both parser and
  serializer now match real `uci`; the full existing corpus (golden captures, real OpenWRT configs,
  the mutation suite, every diagnostic-line-number test) is unchanged. See SPEC.md for the RED→GREEN
  measurement and `root.zig`'s "audit A1 U5"/"audit A1 U6" tests.

- **2026-09-10** — Audit A1 second fix pass (P1: this module has zero consumers in the repo, so
  input-hardening decisions, including new error values, are the fixer's call). Three new
  `ParseError` values, one new `SerializeError` value, and one behavior correction:
  - `error.DuplicateSection` (U1): two `config` blocks sharing a name used to silently build two
    `Section`s, with every accessor answering from the FIRST one's stale values; now rejected
    outright, matching or exceeding real `uci`'s own same-name handling.
  - `error.MemoryLimitExceeded` (U3): the 16 MiB input cap did not bound the model built from it
    (measured 22x-41.5x live-byte amplification, up to 371 MB RSS from a legal 16.6 MB file). A new
    `max_total_items` cap (sections + options + values combined, independent of input size — see
    SPEC.md for why a size-relative ratio does not work here) closes that gap.
  - `error.InvalidName` in both `ParseError` and `SerializeError` (U7): section/option names and
    section types real `uci`'s own validator would refuse are now rejected on `parse`, and
    section type/name (not option key — see SPEC.md) are rejected on `serialize` too, closing a
    write-path gap where this module could produce a file real `uci` refuses to load back.
  - `#` inside a bare (unquoted) word now truncates the token AND discards the rest of the line
    (U4) — this module previously kept it literal there, which SPEC.md documented as "the format",
    a claim the real binary disproves.
  - SPEC.md/README.md corrected (no code change): `MixedOptionList`/valueless-`option` rejection
    was presented as "UCI semantics"; it is this module's own additional strictness (U11/U12) —
    real `uci` is more lenient on both.

- **2026-09-08** — The addressing semantics are pinned to a measurement of the real `uci`
  binary. `sectionByName` and `nth` previously rested on prose; every fact they state was
  re-taken by RUNNING that binary in the `scripts/vm/` OpenWRT 25.12.4 guest, frozen as the
  new "addressing probe" capture and replayed by a test. It answers one case the older
  `testcfg` capture could not, because both of its `rule` sections are anonymous: a config
  with a NAMED, an ANONYMOUS and a second NAMED section of one type shows `@t[0]`→named,
  `@t[1]`→anonymous, `@t[2]`→named, and real `uci show` labels the anonymous one `@t[1]`
  itself. Also measured: name lookup crosses types, `-1`/`-3` count from the end, `@t[3]` and
  `@t[-4]` are both "Entry not found" (rc=1), and `-0` behaves as `0`. The module agreed with
  the binary on every one — no behaviour changed, only what the claim rests on.

- **2026-09-07** — Fuzz reach: both harnesses ran one empty input. `fuzzParse` opened
  `smith.bytes(&buf)` then drew the length with `smith.valueRangeAtMost`, which returns
  the range MINIMUM once `bytes` has eaten the input, so the target was `parse("")`.
  `fuzzRoundTrip` opened `smith.value(bool)`, so every choice after it was a minimum too:
  no package name, `n_sections` = 0 — an EMPTY `Package` serialized to an empty string
  and re-parsed, which round-trips perfectly and proves nothing. The serializer's
  bare-vs-quoted decision and its quote-escaping path, named in the harness's own comment
  as the whole reason the second target exists, were never entered. Measured 2026-09-07:
  1 round each, 0 sections, 0 options, 0 values. `fuzzParse` now draws byte-first with
  one `smith.slice` over 15 written config seeds (random bytes reject at the first
  keyword check essentially always, so a corpus is the only way this parser is reached at
  all). `fuzzRoundTrip` draws a SHAPE rather than a byte string, so it now reads every
  choice out of one byte-first `smith.slice` through `testkit.fuzz.Cursor` — the draw is
  honest and a seed is a readable script — with six scripts including the empty one,
  which reproduces the collapsed harness exactly. ⚠ The round-trip guard pins values
  built, not successful round trips: the empty package round-trips successfully, which is
  what the collapsed harness was doing. Pinned: 10 accepted / 48 sections / 47 values for
  `parse`, and 13 sections / 25 values for the generator.

- **2026-08-18** — New: `Package.sectionByName(name)` (resolves `pkg.<name>.<opt>` key-path
  addressing by name alone, across section types) and `Package.nth(type, index)` (resolves
  `@type[N]` positional addressing, including the negative-index-from-the-end form; the
  semantics are pinned to a capture of the real `uci` binary, see SPEC.md).
  Both were previously hand-rolled by consumers over `iterate`, the negative-index case
  needing a counting pass first. Purely additive; no existing behavior changed. Also:
  SPEC.md's out-of-scope section now says explicitly that a file-only reader loses
  staged-but-uncommitted state (`uci set` without `commit`) and that `uci revert` truncates
  its delta file rather than deleting it — both previously implied only by "state files".
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on the
  documented OpenWRT UCI file format.
- **2026-07-07** — New module: OpenWRT UCI config parser + serializer + typed model
  (stable round-trip).
