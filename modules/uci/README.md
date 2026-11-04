# uci

Parser + serializer + typed model for the **OpenWRT UCI** (Unified
Configuration Interface) file format — `config` / `option` / `list`.

- No maintained pure-Zig UCI codec exists; this retires
  shelling out to the `uci` binary for callers that manage OpenWRT-style
  device config.
- **Model after:** OpenWRT UCI file format.
- **Why:** OpenWRT-style device config is commonly read/written by shelling
  out to `uci`; doing it natively removes an exec dependency and gives typed
  access + errors.
- **Platform:** the codec (`parse`, `serialize`, `Editor`, `applyDelta`, `show`, `parseScript`, `diffRecords`) is I/O-free and portable; the file layer (`Store`, `Session`) needs a POSIX file system (`rename`, `flock`, `fsync`) and is Linux-targeted.
  **Role:** codec. **Concurrency:** reentrant (no shared state).
  **Allocation:** model memory lives in an internal arena — one
  `Package.deinit(gpa)` frees everything.

Provenance: original work of the zig-libs authors (MIT); clean-room from the
documented OpenWRT UCI (Unified Configuration Interface) file format (OpenWRT
wiki/docs) — the file format is the documented interface. Every behavioural
claim is settled by RUNNING the real `uci` binary: `root.zig`'s "real uci
capture" and "addressing
probe" sections freeze raw config bytes together with that binary's own
`export`/`show`/`get` stdout, taken inside the `scripts/vm/` OpenWRT VM and
replayed by tests — a black-box oracle, which root `NOTICE` §0 records as owing
no attribution. See SPEC.md for the findings.

## API

```zig
const uci = @import("uci");

// Parse (typed errors, never panics; parseDiag adds a 1-based line number)
var pkg = try uci.parse(gpa, bytes);            // ParseError!Package
defer pkg.deinit(gpa);
var diag: uci.Diagnostics = .{};
_ = uci.parseDiag(gpa, bytes, &diag) catch |e| {
    // e.g. error.UnterminatedQuote at diag.line
};

// Model
// Package{ name: ?[]const u8, sections: []Section }
// Section{ type, name: ?[]const u8, anonymous: bool, options: []Option }
// Option{ key, kind: .single | .list, values: [][]const u8 }

// Accessors
const lan = pkg.section("interface", "lan").?;  // named lookup (type + name)
_ = lan.get("proto");                           // ?[]const u8 (first value)
_ = lan.getList("ports");                       // all values, &.{} if absent
var it = pkg.iterate("interface");              // sections by type, file order
while (it.next()) |sec| { ... }

// Resolve a `pkg.<name>.<opt>` key path when you only have the name, not
// the type (unlike `section`, which needs both).
_ = pkg.sectionByName("lan");                   // ?*const Section

// Resolve `@type[N]` positional addressing, incl. the negative-index-
// from-the-end form (`-1` = last matching section of that type). Anonymous
// and named sections of `type` both count, in file order. Out-of-range
// (either direction) returns null — the real binary's own "not found".
_ = pkg.nth("rule", 0);                         // ?*const Section, first
_ = pkg.nth("rule", -1);                        // ?*const Section, last

// Serialize to canonical UCI text (round-trip stable)
const text = try uci.serialize(gpa, &pkg);      // SerializeError![]u8
defer gpa.free(text);

// Deep equality (used by the round-trip tests)
_ = pkg.eql(&other);

// Typed values (OpenWrt's boolean words; base-10 integers)
_ = lan.getBool("enabled");                     // ?bool: 1 yes on true enabled / 0 no off false disabled
_ = lan.getInt("mtu");                          // ?i64

// Any reference `uci` accepts: name, @type[N], anonymous id (cfg0389a1)
_ = pkg.resolveSection("@rule[-1]");

// Staged-but-uncommitted changes (`/tmp/.uci/<pkg>`): what `uci get` reports
var live = try uci.applyDelta(gpa, &pkg, "network", delta_bytes, &diag); // DeltaError!Package
defer live.deinit(gpa);

// Editing with libuci's operations, then back to a Package
var ed = try uci.Editor.init(gpa, &pkg);
defer ed.deinit();
try ed.set("lan", "proto", "dhcp");
const id = try ed.add("rule");                  // "cfg0589a1"-style id
try ed.addList(id, "proto", "tcp");
try ed.reorder(id, 0);
var edited = try ed.toPackage(gpa);
defer edited.deinit(gpa);
const shown = try ed.show(gpa, "network", .{}); // `uci show` text
```

**Staged deltas, ids and `show` are measured, not read:** `tools/capture-delta.sh`
drives the real `uci` (built from OpenWrt's tree, used only through its command
line) through every operation and records the delta file it writes and what
`uci show` / `uci -X show` then print; the tests replay those deltas and must
print the same text byte for byte. Two cases real `uci` accepts are refused:
a rename onto a section name or option key already in use (`uci` then holds
two of one name, which `parse` refuses and `serialize` cannot write) —
`error.DuplicateSection` / `error.DuplicateOption`.

## Files, commit, batch, import (since 2026-11-04; POSIX)

```zig
// The caller opens the directories (the module never discovers /etc/config)
var conf = try std.Io.Dir.cwd().openDir(io, "/etc/config", .{});
var save = try std.Io.Dir.cwd().openDir(io, "/tmp/.uci", .{}); // staged deltas
const store: uci.Store = .{ .io = io, .conf = conf, .save = save };

var live = try store.loadStaged(gpa, "network", &diag); // what `uci get` reports
var sess = uci.Session.init(gpa, store);                 // `uci batch`
defer sess.deinit();
try sess.run("set network.lan.proto=dhcp\nadd_list network.lan.dns=9.9.9.9\n", .{}, null, null);
try sess.commit("network");   // temp file, fsync, rename, directory fsync; delta emptied
try store.importText(gpa, "firewall", text, null);       // `uci import`: replaces at once
try uci.merge(try sess.editor("network"), &parsed);      // `uci import -m`
try store.revert("network");                             // `uci revert network`
```

- A package name is one plain file name (`A-Za-z0-9_-`); `/`, `..`, `.`, a
  leading dot and the empty name are `error.InvalidPackageName` unless
  `StoreOptions.allow_paths` is set. A directory, FIFO, device or symlink is
  `error.NotRegularFile` and is never opened for reading; only a missing file
  is `error.PackageNotFound` — EACCES is `AccessDenied`, EMFILE/EIO `ReadFailed`.
- `commit` keeps the old file's mode (a new file is `0600`, as `uci import`
  creates it), refuses text `parse` would not read back (`WouldNotReload`,
  `FileTooLarge`) and leaves the old or the new file after a crash. It takes the
  package's exclusive `flock` first, as the binary does (measured with `strace`),
  and waits at most `StoreOptions.lock_timeout_ms` (`LockTimeout`). Order:
  write temp, chmod, fsync, rename, fsync of the directory; stale temps of the
  package (`.<pkg>.uci-tmp-` + 16 hex digits) are reaped on the next commit.
  `CommittedNotDurable` and `StagedNotCleared` mean the new file IS visible:
  never retry `commitStaged` on them (it would replay the delta).
- A symlink as a config file is followed (and stays a link) when its target is
  a plain name in the same directory; the binary also follows chains and
  `../outside`, we do not (`NotRegularFile`; `allow_paths` allows relative
  targets). `Store.override` (`-C`) and `Store.extra_save` (`-p`) are supported;
  `Session.save` writes the staged state as a delta file (few `^` records; it replays its own output first and refuses with `WouldNotReload` if the delta would not load again; a package name no delta record can carry -- leading `-`, or `.`, `=`, space, `'` -- is `InvalidPackageName`); `revert pkg.sec[.opt]`
  restores a section or option to the committed one.
- `Session` stops at the first failing command (`error.NoSuchSection`, ...);
  `RunOptions.keep_going` runs on like `uci batch` and counts failures in
  `RunReport`. Edits live in memory until `commit`; `discard` drops them.
- Not done (see SPEC.md): a rename onto a name already in use (the binary holds
  two; not built, budget), ucimap, hooks.

Provenance of the data and tools added with this layer: `src/testdata/store_capture.txt`
is the output of `tools/capture-store.py` (the real `uci` run as a black box on
14 scripted cases plus 6 file-kind cases (link, chain, escape, dangling, FIFO, directory); no source read); `tools/go_bench/go.mod` and `go.sum` come from
`go get github.com/digineo/go-uci@latest` on 2026-11-04 (MIT, pinned to
`v0.0.0-20210918132103-37c7b10c14fa`, `go-uci`'s own `go.sum` entries for its test
dependencies are not needed); `tools/c_bench.c` is ours and links a libuci the bench
builds from a source copy (`LIBUCI_SRC`), whose source is never kept here.

## Format coverage / semantics

- Named and anonymous sections. A `package <name>` line is checked (one valid
  name) and ignored, as real `uci` does when loading a file (audit A1 U19):
  `parse` never sets `Package.name`; set it yourself to get a header from
  `serialize`.
- Statements, measured against the real `uci` binary and replayed from
  `src/testdata/grammar_capture.txt` (audit A1 U8/U9): keywords `config`/
  `option`/`list`/`package` or `c`/`o`/`l`/`p`; outside quotes a backslash
  takes the next byte literally, or continues the line before a line break;
  `;` separates statements on one line — except inside a word of plain bytes,
  where it ends the word and drops the rest of the line like `#` does
  (`option a 1;option b 2` sets only `a`, `option a '1';option b 2` sets
  both). Details in SPEC.md.
- Single quotes: no escapes — everything between them, `\t`/`\n`/`\r`
  included, is literal. Double quotes: `\" \' \\` are true escapes; a
  backslash before ANY OTHER character (including `n`/`t`/`r`) drops the
  backslash and keeps that character literally — there is no BACKSLASH
  escape that produces an actual control byte (real `uci` binary confirms
  `\n`/`\t`/`\r` are not special-cased; see SPEC.md). That does not mean
  those three bytes can't appear at all: `\t`/`\n`/`\r` are legal LITERAL
  bytes inside either kind of quote (audit A1 U6 — the only three sub-0x20
  bytes real `uci`'s own validator allows in a value) and this module writes
  them back raw, unescaped, same as real `uci export`. Bare words; adjacent
  quoted/bare segments of one token concatenate (`'a'"b"c` → `abc`).
- **A quote (either kind) may span physical lines** (audit A1 U5): a value
  containing a real newline — a certificate, an SSH key, a multi-line LuCI
  form field — is accepted and round-trips as a multi-line quoted literal,
  e.g. `option multi 'line1` + newline + `line2'`, matching real `uci`
  (measured). Only running out of input with a quote still open is
  `error.UnterminatedQuote`. Outside a quote only a backslash continues a
  statement onto the next line.
- Comments: `#` to end of line at the start of a token, OR anywhere inside a
  bare (unquoted) run — either way it truncates the token and discards the
  rest of the *line*, matching real `uci` (audit A1 U4: `a#b` unquoted is
  `a`, not `a#b`). Literal inside quotes. CRLF accepted (statement grammar
  only; not part of a quoted value's own content).
- Repeated `option` under one key: last wins. `list` accumulates in order.
  Mixing `option`/`list` under one key is rejected here as
  `error.MixedOptionList` — this module's OWN additional strictness, not
  real UCI semantics (audit A1 U11): real `uci` merges a mixed option/list
  (last kind for that key wins) rather than rejecting the whole file. An
  empty or missing value does what real `uci` does (audit A1 U10): `option
  k ''` / `option k` set nothing and keep an earlier value, `list k ''` /
  `list k` add an empty element.
- Section/option names must be alphanumeric or `_` (not even `-`); section
  types allow any other printable, non-space ASCII byte too. Real `uci`'s own
  validator draws the same line, on both the read AND write path — a name it
  would refuse to load is rejected here too (audit A1 U7, `error.InvalidName`;
  not enforced on an option key when *writing*, see the source for why). A
  zero-length name/type/key is the one exception (see below).
- A `config` block reusing the name of an earlier section of the same type
  continues that section, as real `uci` does (audit A1 U1/U25, measured): a
  repeated option replaces, a list goes on, options only the first block had
  stay, and the section keeps its first position. The same name with a
  different type is `error.DuplicateSection`, as in real `uci`'s default
  strict mode. `serialize` refuses a `Package` with two sections sharing a
  name (`error.DuplicateSection`), since the text would read back as one.
- Canonical output: optional `package <name>` header (bare when
  identifier-safe, quoted otherwise — matches real `uci export`'s own
  rendering), blank line between section blocks, tab-indented options, values
  single-quoted (double-quoted with escapes when they contain `'` or control
  characters).
- Bounded: inputs over 16 MiB → `error.InputTooLarge`; lines over 16 KiB →
  `error.LineTooLong`; the built model over 300000 total items (sections +
  options + values, combined) → `error.MemoryLimitExceeded` (audit A1 U3 —
  the text cap alone let a legal 16 MiB input cost 371+ MB of RSS).

## Notes / deviations

- An empty quoted section name (`config rule ''`) is treated as anonymous;
  an empty quoted section type or option key (`config ''`, `option '' v`) is
  accepted literally — the one case the name/type/key validation above does
  not cover, since real `uci` treats a zero-length argument as "insufficient
  arguments" (a different failure mode) rather than an invalid character.
- Values containing ANY control character below 0x20 — `\n` `\t` `\r`
  included, since none of them has a working escape (see above) — cannot be
  represented in UCI text and serialize to `error.UnserializableValue`.
- Staged-but-uncommitted state (`uci set` without `commit` — LuCI's "Save"
  without "Apply") is NOT in `/etc/config/<pkg>`: read the delta file
  (`/tmp/.uci/<pkg>`; the reading stays the caller's I/O) and pass it to
  `applyDelta`. An empty delta file means nothing is staged (`uci revert`
  truncates rather than deletes it). Still out of scope: `commit` itself
  (writing `/etc/config` — keep that on the binary, which also runs the
  hooks), `/etc/config` discovery, `/var/state`, `uci import`.
