// SPDX-License-Identifier: MIT

//! uci — parser + serializer + typed model for the OpenWRT UCI
//! (Unified Configuration Interface) file format.
//!
//! A UCI config file is a *package* (implicit — the file itself, optionally
//! restated by a `package` line) containing sections:
//!
//! ```
//! config <type> ['<name>']       # named or anonymous section
//!     option <key> '<value>'     # single value
//!     list   <key> '<value>'     # repeated -> list
//! ```
//!
//! `parse` builds a typed `Package` model (arena-backed — one `deinit` frees
//! everything); `serialize` writes it back as canonical UCI text. Round-trips
//! are stable: `parse(serialize(m))` equals `m`, and the second serialization
//! is byte-identical to the first.
//!
//! Quoting follows the documented format: single quotes take no escapes;
//! double quotes take `\"`, `\'`, `\\` (a backslash before any other
//! character — including `n`/`t`/`r` — drops the backslash and yields that
//! character verbatim; UCI text has no escape that produces an actual
//! control byte, confirmed against a real `uci` binary — see SPEC.md);
//! bare words end at whitespace.
//! Adjacent segments of one token concatenate (`'a'"b"c` -> `abc`). Audit A1
//! U5: a quote (either kind) MAY span physical lines -- real `uci`
//! (`parse_single_quote`/`parse_double_quote`, file.c:157,187) keeps reading
//! following lines via `uci_getln` until the matching quote closes, and the
//! value keeps the real `\n` byte at each line break it crossed; only
//! end-of-file inside an open quote is `error.UnterminatedQuote`. Everything
//! OUTSIDE a quote is still exactly one physical line: a bare word, `#`, and
//! the statement keyword never cross a `\n`. `#` starts a comment at the
//! start of a token, OR anywhere inside a bare (unquoted) run -- either way
//! it truncates the current token and discards the rest of the *line* (audit
//! A1 U4, measured against the real `uci` binary: `a#b` unquoted is `a`, not
//! `a#b`). Inside quotes `#` is always literal.
//!
//! Malformed input yields a typed `ParseError` (never a panic); pass a
//! `Diagnostics` to `parseDiag` to learn the 1-based line number.
//!
//! Semantics on repeated keys within one section: a repeated `option` under
//! the same key overwrites (last wins, matching UCI CLI set semantics);
//! `list` entries under one key accumulate in order; mixing `option` and
//! `list` under the same key is rejected as `error.MixedOptionList`.
//!
//! Provenance: clean-room from the documented OpenWRT UCI file format, with
//! the real `uci` binary used purely as a black-box oracle (root `NOTICE`
//! §0). Every behavioural claim about addressing is MEASURED against that
//! binary and replayed from a frozen transcript.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "OpenWRT UCI config parser + serializer + typed model, with stable round-trip.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .linux32 },
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "OpenWRT UCI file format",
    .deps = .{}, // std only
};

// ── limits ──────────────────────────────────────────────────────────────────

/// Largest accepted input, in bytes. Larger inputs fail with
/// `error.InputTooLarge` (diagnostic line 0).
pub const max_input_len: usize = 1 << 24; // 16 MiB

/// Longest accepted single line, in bytes (excluding the newline).
pub const max_line_len: usize = 1 << 14; // 16 KiB

/// Audit A1 U3: `max_input_len` bounds the TEXT, not the MODEL it builds --
/// measured amplification of a syntactically legal, `max_input_len`-sized
/// input ranged 22x-41.5x live-byte overhead (depending on shape: one option
/// per section vs. many options in one section), i.e. a 16 MiB file could
/// legally cost 371+ MB of RSS on a device with typically 64-256 MB of RAM.
///
/// A bound expressed as "N times the input size" was tried first and
/// rejected: the worst measured shape ("one option per section") already
/// amplifies close to 42x, which is the SAME order of magnitude as the
/// perfectly legitimate "many distinct options in one section" shape this
/// module's own U2 regression test exercises at N=64000 -- so any ratio
/// loose enough to admit that legitimate test back-derives to nearly the
/// same 16 MiB-input ceiling the audit already showed doesn't bound memory
/// (a ratio has to be looser than the worst offender it's meant to catch, or
/// it catches good data too). A flat cap on total model ITEMS (sections +
/// options + values, combined) avoids that: it is independent of input
/// size, so it does not get looser as a file grows, and it directly bounds
/// the allocation count that drives the amplification regardless of shape.
/// `max_total_items` sits comfortably above the U2 test's 128001 items
/// (roughly 2.3x) while still cutting the audit's "one option per section"
/// shape off well before it reaches even a tenth of `max_input_len` --
/// converting unbounded RSS growth into an early, controlled rejection.
pub const max_total_items: usize = 300_000;

// ── errors / diagnostics ────────────────────────────────────────────────────

pub const ParseError = error{
    /// Input exceeds `max_input_len`.
    InputTooLarge,
    /// A line exceeds `max_line_len`.
    LineTooLong,
    /// A single or double quote was not closed before end of INPUT (audit
    /// A1 U5: a quote may span physical lines, so this is no longer raised
    /// at the end of the line it opened on -- only at true end of file).
    UnterminatedQuote,
    /// Line starts with a token other than `config`/`option`/`list`/`package`.
    BadKeyword,
    /// A keyword is missing a required argument (e.g. bare `config`,
    /// `option key` with no value).
    MissingArgument,
    /// Extra tokens after a complete statement.
    TooManyArguments,
    /// `option`/`list` before any `config` section.
    OptionOutsideSection,
    /// `option` and `list` mixed under the same key in one section.
    MixedOptionList,
    /// Audit A1 U1: two `config` sections share a name. Real `uci` either
    /// merges same-type duplicates (last option value wins, `sections.len`
    /// unaffected) or rejects a same-name/different-type collision outright
    /// under `UCI_FLAG_STRICT` -- this module's `[]Section` model cannot
    /// represent the merge (it always allocates a new `Section`, so
    /// `sections.len` would silently disagree with real `uci`'s count and
    /// the first-written values, not the winning ones, would answer every
    /// accessor query). Rather than accept a file whose two implementations
    /// of "the config" disagree about which value is live, this module
    /// rejects ALL duplicate-name collisions (same type or not) rather than
    /// silently returning the wrong side.
    DuplicateSection,
    /// Audit A1 U7: a section name, section type, or option key uses a
    /// character real `uci`'s own validator (`uci_validate_str`, util.c)
    /// never allows there -- anything other than alphanumeric/`_` for a
    /// name/key, or non-printable/space for a type. Zero-length names/keys
    /// are NOT covered by this check (see the comment on `validNameChars`):
    /// `config ''`/`option '' v` stay accepted, a deliberately-tested shape
    /// (audit A1 U18).
    InvalidName,
    /// Audit A1 U3: this input is syntactically legal (under
    /// `max_input_len`) but the in-memory model it would build is
    /// disproportionate to it -- see `checkMemoryLimit`.
    MemoryLimitExceeded,
    OutOfMemory,
};

pub const SerializeError = error{
    /// A value contains a control character below 0x20 that is neither
    /// `\t`, `\n`, nor `\r` -- those three are the ONLY sub-0x20 bytes real
    /// `uci`'s own validator (`uci_validate_text`, util.c:96) allows in a
    /// value, and it writes them back literally (unescaped, inside quotes),
    /// not via a backslash escape -- there is no backslash escape that
    /// produces a control byte at all (audit A1 U6; see the parser's
    /// double-quote comment). Any OTHER control byte genuinely cannot be
    /// represented in UCI text and is rejected here.
    UnserializableValue,
    /// Audit A1 U7 (write side): a section name or section type uses a
    /// character real `uci` would refuse to load — see `ParseError.InvalidName`.
    /// Deliberately NOT enforced on an option *key* here: `writeWord`
    /// already guarantees any key round-trips safely, quoted or not (audit
    /// A1 U14), and a directly-constructed `Package` (bypassing `parse`,
    /// which does enforce this for keys) is allowed to carry one.
    InvalidName,
    OutOfMemory,
};

/// Filled in by `parseDiag` on failure. `line` is 1-based; 0 means the
/// failure was not tied to a line (`error.InputTooLarge`).
pub const Diagnostics = struct {
    line: usize = 0,
};

// ── model ───────────────────────────────────────────────────────────────────

pub const Option = struct {
    key: []const u8,
    kind: Kind,
    /// `.single` -> exactly one entry; `.list` -> one entry per `list` line.
    values: []const []const u8,

    pub const Kind = enum { single, list };

    pub fn eql(a: *const Option, b: *const Option) bool {
        if (!std.mem.eql(u8, a.key, b.key)) return false;
        if (a.kind != b.kind) return false;
        if (a.values.len != b.values.len) return false;
        for (a.values, b.values) |av, bv| {
            if (!std.mem.eql(u8, av, bv)) return false;
        }
        return true;
    }
};

pub const Section = struct {
    type: []const u8,
    /// Null for anonymous sections (`config rule` with no name).
    name: ?[]const u8,
    anonymous: bool,
    options: []const Option,

    /// Find an option (single or list) by key.
    pub fn option(self: *const Section, key: []const u8) ?*const Option {
        for (self.options) |*o| {
            if (std.mem.eql(u8, o.key, key)) return o;
        }
        return null;
    }

    /// First value under `key` (works for both single options and lists).
    pub fn get(self: *const Section, key: []const u8) ?[]const u8 {
        const o = self.option(key) orelse return null;
        if (o.values.len == 0) return null;
        return o.values[0];
    }

    /// All values under `key`; empty slice if the key is absent. A single
    /// option yields a one-element slice.
    pub fn getList(self: *const Section, key: []const u8) []const []const u8 {
        const o = self.option(key) orelse return &.{};
        return o.values;
    }

    pub fn eql(a: *const Section, b: *const Section) bool {
        if (!std.mem.eql(u8, a.type, b.type)) return false;
        if (!optStrEql(a.name, b.name)) return false;
        if (a.anonymous != b.anonymous) return false;
        if (a.options.len != b.options.len) return false;
        for (a.options, b.options) |*ao, *bo| {
            if (!ao.eql(bo)) return false;
        }
        return true;
    }
};

pub const Package = struct {
    /// From an optional `package <name>` line; null when absent (the usual
    /// case — the package is implicitly the file).
    name: ?[]const u8 = null,
    sections: []const Section = &.{},
    arena_state: std.heap.ArenaAllocator.State = .{},

    /// Frees the whole model. `gpa` must be the allocator given to `parse`.
    pub fn deinit(self: *Package, gpa: Allocator) void {
        self.arena_state.promote(gpa).deinit();
        self.* = undefined;
    }

    /// Find a *named* section by type + name. Anonymous sections are never
    /// matched; use `iterate` for those.
    pub fn section(self: *const Package, section_type: []const u8, name: []const u8) ?*const Section {
        for (self.sections) |*s| {
            const n = s.name orelse continue;
            if (std.mem.eql(u8, s.type, section_type) and std.mem.eql(u8, n, name)) return s;
        }
        return null;
    }

    /// Iterate all sections of a given type, in file order.
    pub fn iterate(self: *const Package, section_type: []const u8) TypeIterator {
        return .{ .remaining = self.sections, .section_type = section_type };
    }

    /// Resolve `pkg.<name>.<opt>` addressing: a section by name alone,
    /// across every type — UCI section names share one namespace per
    /// package, not one per type (measured against the real `uci` binary:
    /// see the "addressing probe" capture below, where `alpha`, `gamma` and
    /// `delta` all answer by name although `delta` is a different type).
    /// Unlike `section`, the caller does not
    /// need to already know the section's type. Anonymous sections have no
    /// name and are never matched here — use `nth` for `@type[N]`
    /// addressing.
    pub fn sectionByName(self: *const Package, name: []const u8) ?*const Section {
        for (self.sections) |*s| {
            const n = s.name orelse continue;
            if (std.mem.eql(u8, n, name)) return s;
        }
        return null;
    }

    /// Resolve `@type[N]` positional addressing, matching the real `uci`
    /// binary exactly (measured, not read: see the "addressing probe"
    /// capture below, which pins every case named here):
    /// `index` counts sections of `section_type` in file order — anonymous
    /// *and* named sections of that type both count, the same set `iterate`
    /// walks, not anonymous-only. A negative index counts from the end
    /// (`-1` = last matching section), which is equivalent to adding the
    /// match count to it; `nth` does exactly that. Both an out-of-range
    /// positive index and a negative index whose magnitude exceeds the match
    /// count return `null`: the real binary answers "Entry not found" with a
    /// non-zero status for both (measured: `@t[3]` and `@t[-4]`), which is a
    /// miss rather than a distinct error, so `nth` mirrors it with `null`
    /// rather than an error union. `-0` behaves exactly like `0` (measured:
    /// `@t[-0]` returns the first matching section) — and there is no way to
    /// construct a distinct "negative zero" `i64` either, so that case isn't
    /// separately representable here.
    pub fn nth(self: *const Package, section_type: []const u8, index: i64) ?*const Section {
        var count: i64 = 0;
        for (self.sections) |*s| {
            if (std.mem.eql(u8, s.type, section_type)) count += 1;
        }
        var idx = index;
        if (idx < 0) idx += count;
        if (idx < 0 or idx >= count) return null;
        var c: i64 = 0;
        for (self.sections) |*s| {
            if (!std.mem.eql(u8, s.type, section_type)) continue;
            if (c == idx) return s;
            c += 1;
        }
        return null; // unreachable given the bounds check above
    }

    pub fn eql(a: *const Package, b: *const Package) bool {
        if (!optStrEql(a.name, b.name)) return false;
        if (a.sections.len != b.sections.len) return false;
        for (a.sections, b.sections) |*as, *bs| {
            if (!as.eql(bs)) return false;
        }
        return true;
    }
};

pub const TypeIterator = struct {
    remaining: []const Section,
    section_type: []const u8,

    pub fn next(it: *TypeIterator) ?*const Section {
        while (it.remaining.len > 0) {
            const s = &it.remaining[0];
            it.remaining = it.remaining[1..];
            if (std.mem.eql(u8, s.type, it.section_type)) return s;
        }
        return null;
    }
};

fn optStrEql(a: ?[]const u8, b: ?[]const u8) bool {
    const av = a orelse return b == null;
    const bv = b orelse return false;
    return std.mem.eql(u8, av, bv);
}

// ── name validation (audit A1 U7) ───────────────────────────────────────────
//
// Real `uci`'s `uci_validate_str` (util.c:71) is called on three fields, with
// two different character classes, and is the reason 15/15 hand-written
// probes with an unusual section name/type/key were `MODULE-ACCEPTS-
// LIBUCI-REJECTS` before this fix -- both on the READ path (this module
// called a file "fine" that a real device's `uci_load` rejects outright) and,
// worse, on the WRITE path (`serialize` could write a name/type real `uci`
// will not load back, silently producing a config file that breaks the whole
// package on the device, not just the one section).
//
// Deliberately NOT covered: a zero-length name/type/key. Real `uci`'s CLI
// argument layer treats an empty quoted argument as "insufficient arguments"
// (a different failure mode than a character-class violation), and this
// module has its own, already-decided and already-tested contract for zero-
// length names: `config ''` is anonymous (see "empty section name is
// anonymous" below), and `config ''`/`option '' v` producing a literal empty
// type/key is a deliberately supported round-trip shape pinned by the U18
// regression test ("writeWord's empty-word path..."). Rejecting length-0
// here would silently re-break that already-closed finding, so both
// functions below only ever look at content, never length.

/// Section names and option keys: real `uci` allows only alphanumeric or
/// `_` there (NOT even `-`).
fn validNameChars(s: []const u8) bool {
    for (s) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '_')) return false;
    }
    return true;
}

/// Section types: real `uci` is looser here -- alphanumeric/`_`, or any
/// other printable, non-space ASCII byte (33-126).
fn validTypeChars(s: []const u8) bool {
    for (s) |c| {
        if (c < 33 or c > 126) return false;
    }
    return true;
}

// ── parser ──────────────────────────────────────────────────────────────────

/// Parse UCI text into a `Package`. All model memory comes from an internal
/// arena seeded from `gpa`; free it with `Package.deinit(gpa)`.
pub fn parse(gpa: Allocator, bytes: []const u8) ParseError!Package {
    return parseDiag(gpa, bytes, null);
}

/// Like `parse`, but on error fills `diag.line` with the offending 1-based
/// line number (0 when the error is not line-specific).
pub fn parseDiag(gpa: Allocator, bytes: []const u8, diag: ?*Diagnostics) ParseError!Package {
    if (bytes.len > max_input_len) {
        if (diag) |d| d.line = 0;
        return error.InputTooLarge;
    }

    var arena_impl = std.heap.ArenaAllocator.init(gpa);
    errdefer arena_impl.deinit();

    var p: Parser = .{ .arena = arena_impl.allocator() };
    p.run(bytes) catch |err| {
        if (diag) |d| d.line = p.line_no;
        return err;
    };

    return .{
        .name = p.pkg_name,
        .sections = p.finished,
        .arena_state = arena_impl.state,
    };
}

const OptBuild = struct {
    key: []const u8,
    kind: Option.Kind,
    values: std.ArrayList([]const u8),
};

const SecBuild = struct {
    section_type: []const u8,
    name: ?[]const u8,
    options: std.ArrayList(OptBuild),
    /// key -> index into `options.items`. Without this, `addOption` did a
    /// linear scan of every option seen so far in the section, making a
    /// section with N distinct keys cost O(N^2) — measured at 5 minutes on a
    /// 4.3 MB config with 256000 distinct keys in one section (see the perf
    /// probe in the fix commit). The model built is unchanged: this only
    /// accelerates the "does this key already exist" check `addOption` was
    /// already doing.
    index: std.StringHashMapUnmanaged(usize),
};

const Parser = struct {
    arena: Allocator,
    bytes: []const u8 = &.{},
    /// Byte offset of the parser's cursor into `bytes`.
    pos: usize = 0,
    /// 1-based; the physical line the cursor is currently scanning.
    /// Audit A1 U5: since a quote can now span physical lines, `line_no` is
    /// bumped by `bump`/`quoteByte` whenever a `\n` is consumed AND more
    /// input follows it -- a `\n` that is the LAST byte of the whole input
    /// does not start a phantom next line. That keeps a diagnostic pointing
    /// at the last line that actually had content (typically the statement
    /// that is wrong), not at an empty line past end of file.
    line_no: usize = 1,
    pkg_name: ?[]const u8 = null,
    sections: std.ArrayList(Section) = .empty,
    current: ?SecBuild = null,
    finished: []Section = &.{},
    /// Audit A1 U3: sections + options + values built so far, combined. See
    /// `max_total_items` and `checkMemoryLimit`.
    total_items: usize = 0,

    fn run(p: *Parser, bytes: []const u8) ParseError!void {
        p.bytes = bytes;
        p.pos = 0;
        p.line_no = 1;
        if (bytes.len > 0) try p.checkLineLenAt(0);
        while (p.pos < bytes.len) {
            try p.parseLine();
            try p.consumeLineEnd();
        }
        try p.flushSection();
        p.finished = try p.sections.toOwnedSlice(p.arena);
    }

    /// Audit A1 U3: abort once the model has grown past `max_total_items`
    /// items. O(1) -- this does not reintroduce the U2 quadratic.
    fn checkMemoryLimit(p: *Parser) ParseError!void {
        if (p.total_items > max_total_items) return error.MemoryLimitExceeded;
    }

    /// True at end of input, at a bare `\n`, or at a `\r` that is itself
    /// immediately followed by `\n` (or is the last byte of the input) --
    /// i.e. at the boundary of the CURRENT physical line, the way the old
    /// per-line-sliced tokenizer saw it (it pre-stripped a line's trailing
    /// `\r` before ever tokenizing). Used OUTSIDE quotes only: a bare word,
    /// `#`, and the statement dispatch in `parseLine` never cross this.
    fn atLineEnd(p: *const Parser) bool {
        if (p.pos >= p.bytes.len) return true;
        const c = p.bytes[p.pos];
        if (c == '\n') return true;
        if (c == '\r' and (p.pos + 1 >= p.bytes.len or p.bytes[p.pos + 1] == '\n')) return true;
        return false;
    }

    /// Advance past whatever `atLineEnd` is currently looking at (a CRLF or
    /// bare LF pair, or nothing at end of input), the way `run`'s loop moves
    /// from one statement to the next.
    fn consumeLineEnd(p: *Parser) ParseError!void {
        if (p.pos >= p.bytes.len) return;
        if (p.bytes[p.pos] == '\n' or p.bytes[p.pos] == '\r') _ = try p.bump();
    }

    /// Bound the physical line starting at `start` to `max_line_len` bytes
    /// (a trailing `\r` of a CRLF line does not count, matching the old
    /// per-line stripping). Audit A1 U5: this still guards every individual
    /// physical line even when a quoted value spans several of them --
    /// U5/U6 lift the "one statement = one line" restriction, not the
    /// per-line size cap.
    fn checkLineLenAt(p: *Parser, start: usize) ParseError!void {
        var end = start;
        while (end < p.bytes.len and p.bytes[end] != '\n') end += 1;
        if (end > start and p.bytes[end - 1] == '\r') end -= 1;
        if (end - start > max_line_len) return error.LineTooLong;
    }

    /// Consume one byte OUTSIDE a quote, folding a CRLF pair into a single
    /// logical `\n` (matching the old per-line `\r`-stripping). Bumps
    /// `line_no` (and checks the next physical line's length) whenever the
    /// logical byte consumed is `\n` and more input follows.
    fn bump(p: *Parser) ParseError!u8 {
        var c = p.bytes[p.pos];
        p.pos += 1;
        if (c == '\r' and p.pos < p.bytes.len and p.bytes[p.pos] == '\n') {
            c = p.bytes[p.pos];
            p.pos += 1;
        }
        if (c == '\n' and p.pos < p.bytes.len) {
            p.line_no += 1;
            try p.checkLineLenAt(p.pos);
        }
        return c;
    }

    /// Consume one raw byte of QUOTED content. Audit A1 U5/U6: unlike
    /// `bump`, this does NOT fold a `\r\n` pair -- every byte the file
    /// actually has, `\r` included, becomes part of the value verbatim,
    /// matching `uci_getln` (file.c:41), which just keeps reading raw bytes
    /// rather than translating line endings the way the *statement* grammar
    /// does. Still bumps `line_no` (and checks the next line's length) on a
    /// `\n` that has more input after it.
    fn quoteByte(p: *Parser) ParseError!u8 {
        const c = p.bytes[p.pos];
        p.pos += 1;
        if (c == '\n' and p.pos < p.bytes.len) {
            p.line_no += 1;
            try p.checkLineLenAt(p.pos);
        }
        return c;
    }

    fn skipToEndOfLine(p: *Parser) void {
        while (!p.atLineEnd()) p.pos += 1;
    }

    fn parseLine(p: *Parser) ParseError!void {
        const kw = (try p.nextToken()) orelse return; // blank or comment line

        if (std.mem.eql(u8, kw, "config")) {
            const sec_type = (try p.nextToken()) orelse return error.MissingArgument;
            // Audit A1 U7: section type must match real uci's (looser) name
            // rule. Zero-length is never produced here (nextToken returns
            // null, not "", at end of line -- MissingArgument already
            // covers that), so no empty-string carve-out is needed for the
            // type specifically; `config ''` below is the name case.
            if (!validTypeChars(sec_type)) return error.InvalidName;
            const name_tok = try p.nextToken();
            if (try p.nextToken() != null) return error.TooManyArguments;
            try p.flushSection();
            // An empty quoted name ('') is treated as anonymous.
            const name: ?[]const u8 = if (name_tok) |n| (if (n.len > 0) n else null) else null;
            // Audit A1 U7: a non-empty name must match real uci's name rule.
            if (name) |n| {
                if (!validNameChars(n)) return error.InvalidName;
            }
            // Audit A1 U1: real uci indexes section names in one namespace
            // per package and either merges (same type) or rejects (mixed
            // type) a second `config` block reusing an already-seen name.
            // This module's `[]Section` model can't represent the merge (it
            // always builds a new `Section`), so rather than silently
            // answering every accessor from the FIRST block's values (what
            // the device does not do -- it uses the LAST) it rejects any
            // name collision, same type or not.
            if (name) |n| {
                for (p.sections.items) |*s| {
                    if (s.name) |sn| {
                        if (std.mem.eql(u8, sn, n)) return error.DuplicateSection;
                    }
                }
            }
            p.current = .{ .section_type = sec_type, .name = name, .options = .empty, .index = .empty };
        } else if (std.mem.eql(u8, kw, "option") or std.mem.eql(u8, kw, "list")) {
            if (p.current == null) return error.OptionOutsideSection;
            const key = (try p.nextToken()) orelse return error.MissingArgument;
            // Audit A1 U7: option key must match real uci's name rule.
            // Zero-length keys (`option '' v`) are exempted -- see
            // `validNameChars`'s doc comment (audit A1 U18).
            if (!validNameChars(key)) return error.InvalidName;
            const value = (try p.nextToken()) orelse return error.MissingArgument;
            if (try p.nextToken() != null) return error.TooManyArguments;
            const kind: Option.Kind = if (kw[0] == 'o') .single else .list;
            try p.addOption(key, value, kind);
        } else if (std.mem.eql(u8, kw, "package")) {
            const name = (try p.nextToken()) orelse return error.MissingArgument;
            if (try p.nextToken() != null) return error.TooManyArguments;
            p.pkg_name = name; // last one wins
        } else {
            return error.BadKeyword;
        }
    }

    /// Read one whitespace-delimited token starting at the parser's cursor,
    /// resolving quotes and escapes. Returns null at end of line, at a
    /// comment, or at end of input.
    fn nextToken(p: *Parser) ParseError!?[]const u8 {
        while (p.pos < p.bytes.len and (p.bytes[p.pos] == ' ' or p.bytes[p.pos] == '\t')) p.pos += 1;
        if (p.atLineEnd()) return null;
        if (p.bytes[p.pos] == '#') {
            p.skipToEndOfLine();
            return null;
        }

        var buf: std.ArrayList(u8) = .empty;
        outer: while (!p.atLineEnd()) {
            const c = p.bytes[p.pos];
            if (c == ' ' or c == '\t') break;
            switch (c) {
                '\'' => {
                    // Single quotes: no escapes, everything literal. Audit
                    // A1 U5: the closing `'` may be on a later physical
                    // line; only running out of input unclosed is an error.
                    p.pos += 1;
                    while (true) {
                        if (p.pos >= p.bytes.len) return error.UnterminatedQuote;
                        const d = try p.quoteByte();
                        if (d == '\'') break;
                        try buf.append(p.arena, d);
                    }
                },
                '"' => {
                    p.pos += 1;
                    var closed = false;
                    while (p.pos < p.bytes.len) {
                        const d = try p.quoteByte();
                        if (d == '"') {
                            closed = true;
                            break;
                        }
                        if (d == '\\') {
                            if (p.pos >= p.bytes.len) return error.UnterminatedQuote;
                            // A backslash always just escapes-and-drops: the
                            // following character is kept verbatim, whatever
                            // it is -- including a real `\n` where a quote
                            // continues onto the next physical line (audit
                            // A1 U5). Verified against the real `uci` binary
                            // (see SPEC.md's "real uci capture" section):
                            // `\n`/`\t`/`\r` are NOT special-cased to
                            // control bytes there either — `"a\nb"` round-
                            // trips through real `uci export` as the
                            // literal text `anb`, backslash dropped, 'n'
                            // kept as-is, same as any other `\<char>`. UCI
                            // text has no escape that produces an actual
                            // control byte.
                            const e = try p.quoteByte();
                            try buf.append(p.arena, e);
                        } else {
                            try buf.append(p.arena, d);
                        }
                    }
                    if (!closed) return error.UnterminatedQuote;
                },
                '#' => {
                    p.skipToEndOfLine();
                    break :outer;
                },
                else => {
                    // Bare run: up to whitespace, a quote (concatenation),
                    // '#', or end of line -- a bare word never spans lines.
                    // Audit A1 U4: real `uci` (`parse_str`, file.c:206)
                    // treats '#' ANYWHERE in a bare run as comment-start, not
                    // just at the start of a token -- it truncates the
                    // current token there and discards the rest of the
                    // *line* (not just the token) as a comment. '#' inside a
                    // quoted segment is unaffected -- real uci's quote
                    // scanners never reach this branch at all.
                    const start = p.pos;
                    while (!p.atLineEnd()) {
                        const d = p.bytes[p.pos];
                        if (d == ' ' or d == '\t' or d == '\'' or d == '"' or d == '#') break;
                        p.pos += 1;
                    }
                    try buf.appendSlice(p.arena, p.bytes[start..p.pos]);
                    if (!p.atLineEnd() and p.bytes[p.pos] == '#') {
                        p.skipToEndOfLine(); // discard the rest of the line too
                        break :outer;
                    }
                },
            }
        }
        return try buf.toOwnedSlice(p.arena);
    }

    fn addOption(p: *Parser, key: []const u8, value: []const u8, kind: Option.Kind) ParseError!void {
        const cur = &p.current.?;
        if (cur.index.get(key)) |idx| {
            const ob = &cur.options.items[idx];
            if (ob.kind != kind) return error.MixedOptionList;
            switch (kind) {
                .single => {
                    // Repeated `option` under one key: last one wins -- a
                    // REPLACED value, not a new item, so `total_items` is
                    // unaffected.
                    ob.values.clearRetainingCapacity();
                    try ob.values.append(p.arena, value);
                },
                .list => {
                    try ob.values.append(p.arena, value);
                    p.total_items += 1; // one new value
                    try p.checkMemoryLimit();
                },
            }
            return;
        }
        var values: std.ArrayList([]const u8) = .empty;
        try values.append(p.arena, value);
        const idx = cur.options.items.len;
        try cur.options.append(p.arena, .{ .key = key, .kind = kind, .values = values });
        try cur.index.put(p.arena, key, idx);
        p.total_items += 2; // one new option, one new value
        try p.checkMemoryLimit();
    }

    fn flushSection(p: *Parser) ParseError!void {
        const sec = p.current orelse return;
        const options = try p.arena.alloc(Option, sec.options.items.len);
        for (sec.options.items, options) |*ob, *o| {
            o.* = .{
                .key = ob.key,
                .kind = ob.kind,
                .values = try ob.values.toOwnedSlice(p.arena),
            };
        }
        try p.sections.append(p.arena, .{
            .type = sec.section_type,
            .name = sec.name,
            .anonymous = sec.name == null,
            .options = options,
        });
        p.current = null;
        p.total_items += 1; // one new section
        try p.checkMemoryLimit();
    }
};

// ── serializer ──────────────────────────────────────────────────────────────

/// Serialize a `Package` to canonical UCI text (caller frees with `gpa`):
/// optional `package <name>` header (bare when identifier-safe, matching
/// real `uci export`'s own rendering), blank line between blocks, options
/// tab-indented, values quoted (single quotes by default, double quotes with
/// escapes when the value contains `'` or a control character).
pub fn serialize(gpa: Allocator, pkg: *const Package) SerializeError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    if (pkg.name) |n| {
        try out.appendSlice(gpa, "package ");
        // Bare when identifier-safe, matching real `uci export`'s own
        // rendering (verified: it prints `package testcfg`, not
        // `package 'testcfg'`) — same rule as a section type name.
        try writeWord(gpa, &out, n);
        try out.append(gpa, '\n');
    }
    for (pkg.sections, 0..) |*sec, i| {
        // Audit A1 U7 (write side): a section type/name real `uci` could
        // never have parsed must not be written -- see `ParseError.InvalidName`'s
        // doc comment for why the option key is deliberately NOT checked here
        // (audit A1 U14 already guarantees it round-trips safely either way).
        if (!validTypeChars(sec.type)) return error.InvalidName;
        if (sec.name) |n| {
            if (!validNameChars(n)) return error.InvalidName;
        }
        if (i != 0 or pkg.name != null) try out.append(gpa, '\n');
        try out.appendSlice(gpa, "config ");
        try writeWord(gpa, &out, sec.type);
        if (sec.name) |n| {
            try out.append(gpa, ' ');
            try writeValue(gpa, &out, n);
        }
        try out.append(gpa, '\n');
        for (sec.options) |*opt| {
            const kw: []const u8 = switch (opt.kind) {
                .single => "option",
                .list => "list",
            };
            for (opt.values) |v| {
                try out.append(gpa, '\t');
                try out.appendSlice(gpa, kw);
                try out.append(gpa, ' ');
                try writeWord(gpa, &out, opt.key);
                try out.append(gpa, ' ');
                try writeValue(gpa, &out, v);
                try out.append(gpa, '\n');
            }
        }
    }
    return out.toOwnedSlice(gpa);
}

fn isBareSafe(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-';
}

/// Section types and option keys: bare when identifier-like, quoted otherwise.
fn writeWord(gpa: Allocator, out: *std.ArrayList(u8), word: []const u8) SerializeError!void {
    if (word.len > 0) {
        for (word) |c| {
            if (!isBareSafe(c)) return writeValue(gpa, out, word);
        }
        return out.appendSlice(gpa, word);
    }
    return writeValue(gpa, out, word);
}

/// Audit A1 U6: `\t`/`\n`/`\r` are the ONLY sub-0x20 bytes real `uci`
/// permits in a value (`uci_validate_text`, util.c:96) and it writes them
/// back LITERALLY, not via a backslash escape -- there is no backslash
/// escape that produces a control byte at all (see the parser's
/// double-quote comment). This module previously treated ALL sub-0x20 bytes
/// alike and rejected them, which rejected three bytes real `uci` accepts
/// and re-emits. `\n` in particular is now representable end to end because
/// a quote may span physical lines (audit A1 U5): a value containing a real
/// newline round-trips as a multi-line single- or double-quoted literal,
/// the same shape `uci export` itself produces.
fn isEscapelessControl(c: u8) bool {
    return c < 0x20 and c != '\t' and c != '\n' and c != '\r';
}

fn writeValue(gpa: Allocator, out: *std.ArrayList(u8), value: []const u8) SerializeError!void {
    var needs_double = false;
    for (value) |c| {
        if (c == '\'' or isEscapelessControl(c)) {
            needs_double = true;
            break;
        }
    }
    if (!needs_double) {
        try out.append(gpa, '\'');
        try out.appendSlice(gpa, value);
        try out.append(gpa, '\'');
        return;
    }
    // Double-quote mode only round-trips `\\` and `\"` (the parser's
    // backslash rule drops the backslash and keeps ANY other character
    // literally — including n/t/r, verified against the real `uci` binary,
    // see the parser comment above); `\t`/`\n`/`\r` need no escape at all
    // and are written raw below. Any OTHER control byte still has no
    // representable escape and must be rejected, not silently mis-escaped.
    for (value) |c| {
        if (isEscapelessControl(c)) return error.UnserializableValue;
    }
    try out.append(gpa, '"');
    for (value) |c| switch (c) {
        '\\' => try out.appendSlice(gpa, "\\\\"),
        '"' => try out.appendSlice(gpa, "\\\""),
        else => try out.append(gpa, c),
    };
    try out.append(gpa, '"');
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectRoundTrip(input: []const u8) !void {
    const gpa = testing.allocator;
    var p1 = try parse(gpa, input);
    defer p1.deinit(gpa);
    const s1 = try serialize(gpa, &p1);
    defer gpa.free(s1);
    var p2 = try parse(gpa, s1);
    defer p2.deinit(gpa);
    try testing.expect(p1.eql(&p2));
    const s2 = try serialize(gpa, &p2);
    defer gpa.free(s2);
    try testing.expectEqualStrings(s1, s2);
}

const golden_network =
    \\# /etc/config/network — golden KAT
    \\package 'network'
    \\
    \\config interface 'lan'
    \\    option proto 'static'
    \\    option ipaddr "192.168.1.1"   # trailing comment
    \\    option netmask 255.255.255.0
    \\    list ports 'lan1'
    \\    list ports 'lan2'
    \\    list ports "lan3"
    \\
    \\# anonymous rule
    \\config rule
    \\    option name 'Allow-DHCP # not a comment'
    \\    option enabled '1'
    \\
    \\config interface 'wan'
    \\    option proto 'dhcp'
    \\
;

test "golden: parse network config model" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, golden_network);
    defer pkg.deinit(gpa);

    try testing.expectEqualStrings("network", pkg.name.?);
    try testing.expectEqual(@as(usize, 3), pkg.sections.len);

    const lan = &pkg.sections[0];
    try testing.expectEqualStrings("interface", lan.type);
    try testing.expectEqualStrings("lan", lan.name.?);
    try testing.expect(!lan.anonymous);
    try testing.expectEqual(@as(usize, 4), lan.options.len);
    try testing.expectEqual(Option.Kind.single, lan.option("proto").?.kind);
    try testing.expectEqualStrings("static", lan.get("proto").?);
    try testing.expectEqualStrings("192.168.1.1", lan.get("ipaddr").?);
    try testing.expectEqualStrings("255.255.255.0", lan.get("netmask").?);
    const ports = lan.getList("ports");
    try testing.expectEqual(Option.Kind.list, lan.option("ports").?.kind);
    try testing.expectEqual(@as(usize, 3), ports.len);
    try testing.expectEqualStrings("lan1", ports[0]);
    try testing.expectEqualStrings("lan2", ports[1]);
    try testing.expectEqualStrings("lan3", ports[2]);

    const rule = &pkg.sections[1];
    try testing.expectEqualStrings("rule", rule.type);
    try testing.expect(rule.anonymous);
    try testing.expect(rule.name == null);
    try testing.expectEqualStrings("Allow-DHCP # not a comment", rule.get("name").?);
    try testing.expectEqualStrings("1", rule.get("enabled").?);

    const wan = &pkg.sections[2];
    try testing.expectEqualStrings("wan", wan.name.?);
    try testing.expectEqualStrings("dhcp", wan.get("proto").?);
}

test "golden: round-trip stable" {
    try expectRoundTrip(golden_network);
}

test "canonical serialization bytes" {
    const gpa = testing.allocator;
    const input = "# c\nconfig system\n option hostname  router1   # trailing\n list dns 8.8.8.8\n list dns '1.1.1.1'\n";
    var pkg = try parse(gpa, input);
    defer pkg.deinit(gpa);
    const text = try serialize(gpa, &pkg);
    defer gpa.free(text);
    try testing.expectEqualStrings(
        "config system\n" ++
            "\toption hostname 'router1'\n" ++
            "\tlist dns '8.8.8.8'\n" ++
            "\tlist dns '1.1.1.1'\n",
        text,
    );
}

test "double-quote escapes" {
    // Only \\, \" and \' are true escapes; a backslash before any other
    // character (n/t/r included) just drops the backslash and keeps that
    // character literally — verified against a real `uci` binary (see
    // SPEC.md's "real uci capture"): `\n`/`\t`/`\r` do NOT become control
    // bytes here.
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\toption v \"a\\'b\\\"c\\\\d\\ne\\tf\\rg\"\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("a'b\"c\\dnetfrg", pkg.sections[0].get("v").?);
}

test "single quotes take no escapes" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\toption v 'a\\nb\"c\\\\d'\n");
    defer pkg.deinit(gpa);
    // Backslashes and double quotes are literal inside single quotes.
    try testing.expectEqualStrings("a\\nb\"c\\\\d", pkg.sections[0].get("v").?);
}

test "bare words and mid-word hash" {
    // Audit A1 U4: real `uci` truncates a bare word AND discards the rest of
    // the line at a mid-word '#' (measured against the real binary; see the
    // comment in `nextToken`'s bare-word branch). `option b a#b` therefore
    // yields the *option* `b` with a value of `a`, not `a#b` -- and the `c`
    // that would otherwise follow on the same line never becomes its own
    // option because everything past `#` is gone.
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\toption a abc-def\n\toption b a#b\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("abc-def", pkg.sections[0].get("a").?);
    try testing.expectEqualStrings("a", pkg.sections[0].get("b").?);
    try expectRoundTrip("config t\n\toption a abc-def\n\toption b 'a'\n");

    // '#' immediately after a closing quote still truncates (concatenated
    // bare continuation of a quoted segment) -- matches the real binary's
    // `option v 'a'#b` -> `a`.
    var pkg2 = try parse(gpa, "config t\n\toption v 'a'#b\n");
    defer pkg2.deinit(gpa);
    try testing.expectEqualStrings("a", pkg2.sections[0].get("v").?);

    // A mid-word '#' inside a KEY truncates the key too and discards the
    // rest of the line -- so the value token that would follow is gone,
    // which is `error.MissingArgument`, not a key literally named "a#b".
    var diag: Diagnostics = .{};
    try testing.expectError(
        error.MissingArgument,
        parseDiag(gpa, "config t\n\toption a#b v\n", &diag),
    );
}

test "token concatenation of quoted segments" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\toption v 'a'\"b\"c\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("abc", pkg.sections[0].get("v").?);
}

test "comments and blank lines" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa,
        \\# full-line comment
        \\
        \\   # indented comment
        \\config t 'n'
        \\    # comment between options
        \\    option a '1'   # after a value
        \\
    );
    defer pkg.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), pkg.sections.len);
    try testing.expectEqual(@as(usize, 1), pkg.sections[0].options.len);
    try testing.expectEqualStrings("1", pkg.sections[0].get("a").?);
}

test "anonymous sections" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config rule\n\toption x '1'\nconfig rule\n\toption x '2'\n");
    defer pkg.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), pkg.sections.len);
    try testing.expect(pkg.sections[0].anonymous);
    try testing.expect(pkg.sections[1].anonymous);
    // Named lookup never matches anonymous sections.
    try testing.expect(pkg.section("rule", "x") == null);
    try expectRoundTrip("config rule\n\toption x '1'\nconfig rule\n\toption x '2'\n");
}

test "empty section name is anonymous" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config rule ''\n");
    defer pkg.deinit(gpa);
    try testing.expect(pkg.sections[0].anonymous);
    try testing.expect(pkg.sections[0].name == null);
}

test "list accumulation" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\tlist l 'a'\n\toption o 'x'\n\tlist l 'b'\n\tlist l 'c'\n");
    defer pkg.deinit(gpa);
    const l = pkg.sections[0].getList("l");
    try testing.expectEqual(@as(usize, 3), l.len);
    try testing.expectEqualStrings("a", l[0]);
    try testing.expectEqualStrings("b", l[1]);
    try testing.expectEqualStrings("c", l[2]);
    // Only two Option entries: the list and the single.
    try testing.expectEqual(@as(usize, 2), pkg.sections[0].options.len);
    // get() on a list returns the first value; getList() on a single wraps it.
    try testing.expectEqualStrings("a", pkg.sections[0].get("l").?);
    try testing.expectEqual(@as(usize, 1), pkg.sections[0].getList("o").len);
}

test "duplicate option: last wins" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\toption k 'old'\n\toption k 'new'\n");
    defer pkg.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), pkg.sections[0].options.len);
    try testing.expectEqualStrings("new", pkg.sections[0].get("k").?);
}

test "mixed option/list rejected" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(
        error.MixedOptionList,
        parseDiag(gpa, "config t\n\toption k 'v'\n\tlist k 'w'\n", &diag),
    );
    try testing.expectEqual(@as(usize, 3), diag.line);
    try testing.expectError(
        error.MixedOptionList,
        parseDiag(gpa, "config t\n\tlist k 'v'\n\toption k 'w'\n", &diag),
    );
    try testing.expectEqual(@as(usize, 3), diag.line);
}

test "empty file and comment-only file" {
    const gpa = testing.allocator;
    var empty = try parse(gpa, "");
    defer empty.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), empty.sections.len);
    try testing.expect(empty.name == null);
    const text = try serialize(gpa, &empty);
    defer gpa.free(text);
    try testing.expectEqualStrings("", text);

    var comments = try parse(gpa, "\n\n# only comments\n   \n");
    defer comments.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), comments.sections.len);
}

test "empty quoted value" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config t\n\toption empty ''\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("", pkg.sections[0].get("empty").?);
    try expectRoundTrip("config t\n\toption empty ''\n");
}

test "serializer quoting choices" {
    const gpa = testing.allocator;
    var pkg = try parse(
        gpa,
        "config t\n" ++
            "\toption spaces 'hello world'\n" ++
            "\toption squote \"it's\"\n" ++
            "\toption bslash 'a\\b'\n" ++
            // `\n`/`\t` are NOT control-byte escapes (see "double-quote
            // escapes" above) — this parses to the literal text "anbtc",
            // which needs no quoting beyond a plain single-quoted word.
            "\toption not_ctrl \"a\\nb\\tc\"\n" ++
            "\toption both \"a'\\\\b\"\n",
    );
    defer pkg.deinit(gpa);
    const text = try serialize(gpa, &pkg);
    defer gpa.free(text);
    try testing.expectEqualStrings(
        "config t\n" ++
            "\toption spaces 'hello world'\n" ++
            "\toption squote \"it's\"\n" ++
            "\toption bslash 'a\\b'\n" ++
            "\toption not_ctrl 'anbtc'\n" ++
            "\toption both \"a'\\\\b\"\n",
        text,
    );
    try expectRoundTrip(text);
}

test "serializer rejects unescapable control chars" {
    const gpa = testing.allocator;
    const opts = [_]Option{.{ .key = "k", .kind = .single, .values = &.{"a\x01b"} }};
    const secs = [_]Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opts }};
    const pkg: Package = .{ .sections = &secs };
    try testing.expectError(error.UnserializableValue, serialize(gpa, &pkg));
}

test "serializer WRITES \\n \\t \\r literally, unescaped -- audit A1 U6, supersedes the old rejection" {
    // Audit A1 U6: real `uci_validate_text` (util.c:96) explicitly allows
    // `\t`/`\n`/`\r` in a value -- the ONLY three sub-0x20 bytes it allows
    // -- and real `uci export` writes them back raw, inside quotes, no
    // escape at all. The module previously rejected all three as
    // `error.UnserializableValue`, having conflated "no BACKSLASH escape
    // produces a control byte" (true) with "no control byte can be
    // represented" (false for these three: they're written literally, not
    // escaped). `\n` round-trips as a real multi-line quoted value (audit
    // A1 U5 lifted the one-statement-one-line restriction that used to make
    // that impossible).
    const gpa = testing.allocator;
    for ([_][]const u8{ "a\nb", "a\tb", "a\rb" }) |v| {
        const opts = [_]Option{.{ .key = "k", .kind = .single, .values = &.{v} }};
        const secs = [_]Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opts }};
        const pkg: Package = .{ .sections = &secs };
        const text = try serialize(gpa, &pkg);
        defer gpa.free(text);
        var reparsed = try parse(gpa, text);
        defer reparsed.deinit(gpa);
        try testing.expectEqualStrings(v, reparsed.sections[0].get("k").?);
    }
}

test "error: unterminated single quote with line number" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(error.UnterminatedQuote, parseDiag(gpa, "config foo 'bar\n", &diag));
    try testing.expectEqual(@as(usize, 1), diag.line);
    try testing.expectError(
        error.UnterminatedQuote,
        parseDiag(gpa, "# c\nconfig s\n\toption a 'b\n", &diag),
    );
    try testing.expectEqual(@as(usize, 3), diag.line);
}

test "error: unterminated double quote with line number" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(
        error.UnterminatedQuote,
        parseDiag(gpa, "config s\n\toption a \"b\\\"\n", &diag),
    );
    try testing.expectEqual(@as(usize, 2), diag.line);
    // Trailing backslash inside a double quote is also unterminated.
    try testing.expectError(
        error.UnterminatedQuote,
        parseDiag(gpa, "config s\n\toption a \"b\\\n", &diag),
    );
    try testing.expectEqual(@as(usize, 2), diag.line);
}

test "audit A1 U5: a quoted value may span physical lines, matching real uci" {
    // Real `uci` (`parse_single_quote`/`parse_double_quote`, file.c:157,187)
    // keeps reading via `uci_getln` when a quote hits end of line without
    // closing -- it does not error until end of FILE. The value keeps the
    // real `\n` byte at every line break it crossed (file.c:41). This is
    // the audit's own end-to-end example (single- and double-quoted).
    const gpa = testing.allocator;
    var pkg = try parse(
        gpa,
        "config t\n\toption tabbed 'a\tb'\n\toption multi 'line1\nline2'\n",
    );
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("a\tb", pkg.sections[0].get("tabbed").?);
    try testing.expectEqualStrings("line1\nline2", pkg.sections[0].get("multi").?);

    // Double-quoted values span lines too, including through an escape that
    // straddles the line break.
    var pkg2 = try parse(
        gpa,
        "config t\n\toption v \"line1\\\nline2\"\n\toption w \"a\nb\"\n",
    );
    defer pkg2.deinit(gpa);
    try testing.expectEqualStrings("line1\nline2", pkg2.sections[0].get("v").?);
    try testing.expectEqualStrings("a\nb", pkg2.sections[0].get("w").?);

    // A statement AFTER a multi-line quote is still parsed correctly --
    // line_no tracking must have caught up, not gotten stuck. The quote
    // itself spans physical lines 2-3 ("'a" / "b'"), so "bogus" is on
    // physical line 4.
    var diag: Diagnostics = .{};
    try testing.expectError(
        error.BadKeyword,
        parseDiag(gpa, "config t\n\toption v 'a\nb'\nbogus\n", &diag),
    );
    try testing.expectEqual(@as(usize, 4), diag.line);

    // Still unterminated if the closing quote never comes at all, even
    // across several physical lines -- this is genuine end of FILE, not
    // end of the first line.
    try testing.expectError(
        error.UnterminatedQuote,
        parse(gpa, "config t\n\toption v 'a\nb\nc\n"),
    );

    // Round-trips: serialize(parse(x)) reparses to the same model, and a
    // value with an embedded real newline survives the round trip too.
    try expectRoundTrip("config t\n\toption multi 'line1\nline2'\n");
}

test "error: option before any section" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(
        error.OptionOutsideSection,
        parseDiag(gpa, "option a 'b'\n", &diag),
    );
    try testing.expectEqual(@as(usize, 1), diag.line);
    try testing.expectError(
        error.OptionOutsideSection,
        parseDiag(gpa, "# c\nlist a 'b'\n", &diag),
    );
    try testing.expectEqual(@as(usize, 2), diag.line);
}

test "error: bad keyword" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(error.BadKeyword, parseDiag(gpa, "config s\nfoo bar\n", &diag));
    try testing.expectEqual(@as(usize, 2), diag.line);
}

test "error: missing argument" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(error.MissingArgument, parseDiag(gpa, "config\n", &diag));
    try testing.expectEqual(@as(usize, 1), diag.line);
    try testing.expectError(error.MissingArgument, parseDiag(gpa, "config s\n\toption k\n", &diag));
    try testing.expectEqual(@as(usize, 2), diag.line);
    try testing.expectError(error.MissingArgument, parseDiag(gpa, "package\n", &diag));
}

test "error: too many arguments" {
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};
    try testing.expectError(error.TooManyArguments, parseDiag(gpa, "config a b c\n", &diag));
    try testing.expectEqual(@as(usize, 1), diag.line);
    try testing.expectError(
        error.TooManyArguments,
        parseDiag(gpa, "config s\n\toption k v extra\n", &diag),
    );
    try testing.expectEqual(@as(usize, 2), diag.line);
}

test "error: line too long" {
    const gpa = testing.allocator;
    const line = try gpa.alloc(u8, max_line_len + 10);
    defer gpa.free(line);
    @memset(line, 'a');
    @memcpy(line[0..7], "config ");
    var diag: Diagnostics = .{};
    try testing.expectError(error.LineTooLong, parseDiag(gpa, line, &diag));
    try testing.expectEqual(@as(usize, 1), diag.line);
}

test "line exactly at max_line_len is accepted; one byte more is LineTooLong" {
    // The existing "line too long" test only exercises `max_line_len + 10`,
    // well past the boundary — never the boundary itself. Pin both sides of
    // `line.len > max_line_len`.
    const gpa = testing.allocator;

    var at_limit: [max_line_len]u8 = undefined;
    @memset(&at_limit, 'a');
    @memcpy(at_limit[0..7], "config ");
    var pkg = try parse(gpa, &at_limit);
    defer pkg.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), pkg.sections.len);

    var diag: Diagnostics = .{};
    var over_limit: [max_line_len + 1]u8 = undefined;
    @memset(&over_limit, 'a');
    @memcpy(over_limit[0..7], "config ");
    try testing.expectError(error.LineTooLong, parseDiag(gpa, &over_limit, &diag));
    try testing.expectEqual(@as(usize, 1), diag.line);
}

test "error: input too large" {
    const gpa = testing.allocator;
    const bytes = try gpa.alloc(u8, max_input_len + 1);
    defer gpa.free(bytes);
    @memset(bytes, '\n');
    var diag: Diagnostics = .{ .line = 99 };
    try testing.expectError(error.InputTooLarge, parseDiag(gpa, bytes, &diag));
    try testing.expectEqual(@as(usize, 0), diag.line);
}

test "accessors: section lookup and type iteration" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, golden_network);
    defer pkg.deinit(gpa);

    const lan = pkg.section("interface", "lan").?;
    try testing.expectEqualStrings("static", lan.get("proto").?);
    try testing.expect(pkg.section("interface", "nope") == null);
    try testing.expect(pkg.section("nope", "lan") == null);
    try testing.expect(lan.get("nope") == null);
    try testing.expectEqual(@as(usize, 0), lan.getList("nope").len);

    var it = pkg.iterate("interface");
    try testing.expectEqualStrings("lan", it.next().?.name.?);
    try testing.expectEqualStrings("wan", it.next().?.name.?);
    try testing.expect(it.next() == null);

    var none = pkg.iterate("nope");
    try testing.expect(none.next() == null);
}

test "crlf input" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config s 'n'\r\n\toption a 'b'\r\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("n", pkg.sections[0].name.?);
    try testing.expectEqualStrings("b", pkg.sections[0].get("a").?);
}

test "package keyword and header serialization" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "package dhcp\n\nconfig dnsmasq\n\toption domain 'lan'\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("dhcp", pkg.name.?);
    const text = try serialize(gpa, &pkg);
    defer gpa.free(text);
    // Bare, unquoted — matches real `uci export`'s own rendering (see the
    // "real uci capture" section below: `package testcfg`, not
    // `package 'testcfg'`).
    try testing.expectEqualStrings(
        "package dhcp\n\nconfig dnsmasq\n\toption domain 'lan'\n",
        text,
    );
    try expectRoundTrip(text);
}

test "package name needing quotes still gets them (not identifier-safe)" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "package 'weird name'\n\nconfig t\n\toption a 'b'\n");
    defer pkg.deinit(gpa);
    const text = try serialize(gpa, &pkg);
    defer gpa.free(text);
    try testing.expectEqualStrings(
        "package 'weird name'\n\nconfig t\n\toption a 'b'\n",
        text,
    );
    try expectRoundTrip(text);
}

test "quoted type round-trips when it needs quoting but is still a valid name" {
    // Was "quoted keys and types round-trip", using a section type/option
    // key containing a SPACE ("weird type"/"weird key") -- both now rejected
    // by audit A1 U7's validation (a space is not alnum/`_`, and real uci's
    // TYPE rule excludes it too). Kept as a *valid*-but-quoting-required
    // case instead: '.' is valid per real uci's (looser) TYPE rule --
    // printable ASCII 33-126 -- but is not `isBareSafe`, so it still needs
    // the quoting path exercised. There is no equivalent "valid but needs
    // quoting" KEY case: real uci's KEY rule (alnum/`_` only) is a strict
    // subset of `isBareSafe`, so no valid key ever needs quotes.
    try expectRoundTrip("config 'a.b' 'n'\n\toption k 'v'\n");
}

test "invalid section type, name, and option key are rejected" {
    // Regression for audit A1 U7: real `uci`'s own validator
    // (`uci_validate_str`, util.c) restricts section/option NAMEs to
    // alphanumeric + `_`, and section TYPEs to printable ASCII (33-126,
    // still excluding space). Before this fix all 15/15 hand-written probes
    // with such a name/type/key were `MODULE-ACCEPTS-LIBUCI-REJECTS`; this
    // pins a representative sample of each field/violation.
    const gpa = testing.allocator;

    // Section NAME: hyphen, dot -- both invalid for a name.
    try testing.expectError(error.InvalidName, parse(gpa, "config t 'my-lan'\n"));
    try testing.expectError(error.InvalidName, parse(gpa, "config t 'my.lan'\n"));

    // Section TYPE: embedded space, non-ASCII byte -- both invalid for a
    // type too (space and anything outside 33-126).
    try testing.expectError(error.InvalidName, parse(gpa, "config 'a b' 'n'\n"));
    try testing.expectError(error.InvalidName, parse(gpa, "config t\xc3\xa9\n")); // "té"

    // Option KEY: hyphen, dot -- both invalid for a name (same rule as
    // section name).
    try testing.expectError(error.InvalidName, parse(gpa, "config t\n\toption dest-port '1'\n"));
    try testing.expectError(error.InvalidName, parse(gpa, "config t\n\toption a.b '1'\n"));

    // Positive control: this class of check must not reject ordinary
    // alnum/`_` identifiers.
    var pkg = try parse(gpa, "config my_type 'my_name'\n\toption my_key '1'\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("my_type", pkg.sections[0].type);
}

test "meta is well-formed" {
    try testing.expect(meta.role == .codec);
}

/// `std.time.Timer` is unavailable in this toolchain's std, and this module
/// is std-only / no libc (`.deps = .{}` in `meta`, no `-lc`). Read the
/// monotonic clock via the raw Linux syscall wrapper instead, which needs
/// neither.
fn monotonicNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

test "accessors distinguish prefix-related names, not just a shared prefix" {
    // Regression for audit A1 U13: a mutation campaign found four name
    // comparisons in the accessor layer (`Section.option`, `Parser.addOption`,
    // `TypeIterator.next`, `Package.sectionByName`) could each be weakened
    // from `std.mem.eql` to `std.mem.startsWith` and the existing suite
    // stayed green -- because no fixture anywhere paired a name with
    // something it is a prefix of. These pairs are common in real OpenWRT
    // configs: `key`/`keyfile`, `port`/`ports`, `lan`/`lan_guest`,
    // `interface`/`interface6`. Each case below puts the LONGER name first,
    // the shape that most exposes a `startsWith` bug (it matches on the
    // first scanned entry sharing the prefix, not the one that's actually
    // equal).
    const gpa = testing.allocator;

    // Parser.addOption / Section.option.
    var pkg = try parse(gpa, "config t\n\toption keyfile '/etc/keys/pub'\n\toption key 'SECRET'\n");
    defer pkg.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), pkg.sections[0].options.len);
    try testing.expectEqualStrings("SECRET", pkg.sections[0].get("key").?);
    try testing.expectEqualStrings("/etc/keys/pub", pkg.sections[0].get("keyfile").?);

    // Package.sectionByName.
    var pkg2 = try parse(gpa, "config t 'lan_guest'\n\toption v 'guest'\nconfig t 'lan'\n\toption v 'trusted'\n");
    defer pkg2.deinit(gpa);
    try testing.expectEqualStrings("trusted", pkg2.sectionByName("lan").?.get("v").?);
    try testing.expectEqualStrings("guest", pkg2.sectionByName("lan_guest").?.get("v").?);

    // TypeIterator.next.
    var pkg3 = try parse(gpa, "config interface6 'a'\nconfig interface 'b'\n");
    defer pkg3.deinit(gpa);
    var it = pkg3.iterate("interface");
    const only = it.next().?;
    try testing.expectEqualStrings("b", only.name.?);
    try testing.expectEqualStrings("interface", only.type);
    try testing.expect(it.next() == null);
}

test "isBareSafe boundary: a key containing a quote character must not be written bare" {
    // Regression for audit A1 U14: `isBareSafe` accepts alnum/`_`/`-`. A
    // one-character widening (`or c == '\''`) survives the whole existing
    // suite green, yet 200000-model stress produced 2142 failed reloads and
    // 176 SILENT model drifts (`parse(serialize(m))` != `m`, undetected) --
    // because nothing in the suite exercises a key/type containing the one
    // character the bare-word tokenizer treats as a quote boundary (see
    // `nextToken`'s bare-word branch, which stops at `'`/`"`). This pins the
    // boundary directly: a key containing `'` must come out QUOTED, never
    // bare -- `serialize` deliberately does not validate option-key
    // characters (see `SerializeError.InvalidName`'s doc comment), so a
    // hand-built `Package` bypassing `parse` still gets this safety net.
    //
    // Audit A1 U7 (added after this test, and after U14 was already closed):
    // real `uci` never accepts `'` in a key at all, so `parse`-side
    // validation now refuses to read this safely-quoted text back in -- a
    // stricter, but still safe, outcome: the key was never written bare
    // (U14's actual guarantee, checked directly below), it just can no
    // longer round-trip through TEXT, only survive as an in-memory model.
    // `pkg.eql(&reparsed)` is gone from this test for that reason, not
    // because the quoting regressed.
    const gpa = testing.allocator;
    const opts = [_]Option{.{ .key = "a'b", .kind = .single, .values = &.{"v"} }};
    const secs = [_]Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opts }};
    const pkg: Package = .{ .sections = &secs };
    const text = try serialize(gpa, &pkg);
    defer gpa.free(text);
    // Written quoted (`"a'b"`), never as a bare `a'b` token.
    try testing.expect(std.mem.indexOf(u8, text, "\"a'b\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\ta'b ") == null);
    try testing.expectError(error.InvalidName, parse(gpa, text));
}

test "writeWord's empty-word path round-trips an empty type and an empty key" {
    // Regression for audit A1 U18: `writeWord`'s empty-input branch (falls
    // through to `writeValue`, producing `''`) had no test; a mutation that
    // replaced it with "write nothing" passed the whole suite green, even
    // though `parse` itself can produce both shapes: `config ''` -> an empty
    // section type, `option '' v` -> an empty key.
    const gpa = testing.allocator;
    var pkg = try parse(gpa, "config ''\n\toption '' v\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("", pkg.sections[0].type);
    try testing.expectEqualStrings("", pkg.sections[0].options[0].key);

    const text = try serialize(gpa, &pkg);
    defer gpa.free(text);
    try testing.expectEqualStrings("config ''\n\toption '' 'v'\n", text);

    var reparsed = try parse(gpa, text);
    defer reparsed.deinit(gpa);
    try testing.expect(pkg.eql(&reparsed));
}

test "addOption is not quadratic in distinct keys per section" {
    // Regression guard for a fixed HIGH->MED finding (audit A1 U2):
    // `addOption` used to do a linear scan of every option already seen in
    // the section, so a section with N distinct keys cost O(N^2) -- measured
    // pre-fix at 11.05s for N=64000 (ReleaseFast), and a clean quadratic
    // pattern across 16000/32000/64000/128000/256000. `SecBuild.index`
    // (a key -> options-index hashmap, see `addOption`) makes the per-key
    // lookup amortized O(1). This regression test uses N=16000/64000 (a 4x
    // jump): a still-quadratic implementation would take ~16x longer for the
    // 4x-larger input; a linear one takes ~4x longer. The bound below (8x)
    // sits generously between the two so ordinary machine noise on a shared,
    // loaded box cannot flip it, while a reintroduced O(N^2) scan still trips
    // it by a wide margin.
    const gpa = testing.allocator;
    const sizes = [_]usize{ 16000, 64000 };
    var times_ns: [sizes.len]u64 = undefined;
    for (sizes, 0..) |n, i| {
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(gpa);
        try input.appendSlice(gpa, "config t\n");
        var buf: [32]u8 = undefined;
        for (0..n) |k| {
            const key = try std.fmt.bufPrint(&buf, "k{d}", .{k});
            try input.appendSlice(gpa, "\toption ");
            try input.appendSlice(gpa, key);
            try input.appendSlice(gpa, " v\n");
        }
        const t0 = monotonicNs();
        var pkg = try parse(gpa, input.items);
        times_ns[i] = monotonicNs() - t0;
        try testing.expectEqual(@as(usize, n), pkg.sections[0].options.len);
        pkg.deinit(gpa);
    }
    const ratio = @as(f64, @floatFromInt(times_ns[1])) / @as(f64, @floatFromInt(@max(times_ns[0], 1)));
    std.debug.print(
        "uci U2 perf regression: N=16000 took {d}ns, N=64000 took {d}ns, ratio={d:.2} (quadratic would be ~16x, linear ~4x; gate is <8x)\n",
        .{ times_ns[0], times_ns[1], ratio },
    );
    try testing.expect(ratio < 8.0);
}

test "duplicate named section is rejected" {
    // Regression for audit A1 U1: real `uci` merges a same-type duplicate
    // section name (last option value wins; `sections.len` unaffected) and
    // rejects a same-name/different-type collision outright. This module's
    // `[]Section` model cannot represent the merge (see
    // `ParseError.DuplicateSection`'s doc comment), so instead of silently
    // building two `Section`s and answering every accessor from the FIRST
    // one's (stale) values -- what this module did before this fix, and the
    // exact shape of the audit's reproduction -- it now rejects any name
    // collision, same type or not.
    const gpa = testing.allocator;
    var diag: Diagnostics = .{};

    // Same type, same name: real uci merges (last wins, `proto=none`); this
    // module rejects rather than silently keeping the FIRST value
    // (`proto=static`), which is what the pre-fix audit reproduction showed.
    try testing.expectError(
        error.DuplicateSection,
        parseDiag(
            gpa,
            "config interface 'lan'\n\toption proto 'static'\n\nconfig interface 'lan'\n\toption proto 'none'\n",
            &diag,
        ),
    );
    try testing.expectEqual(@as(usize, 4), diag.line);

    // Different type, same name: real uci's own strict mode rejects this
    // too ("section of different type overwrites prior section with same
    // name") -- this module accepted it before this fix.
    try testing.expectError(
        error.DuplicateSection,
        parseDiag(gpa, "config interface 'lan'\n\nconfig rule 'lan'\n", &diag),
    );

    // Positive control: distinct names in the same file are unaffected.
    var pkg = try parse(gpa, "config interface 'lan'\n\nconfig interface 'wan'\n");
    defer pkg.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), pkg.sections.len);
}

test "total item cap: boundary is exact, one section many options" {
    // Regression for audit A1 U3: `max_input_len` bounded the TEXT but not
    // the MODEL it builds -- a legal 16 MiB input measured 22x-41.5x
    // live-byte amplification against input size (up to 371 MB RSS on a
    // 16.6 MB file). `max_total_items` bounds the model directly and
    // independent of input size (see its doc comment for why a
    // byte-size-relative ratio does not work here: the worst measured shape
    // amplifies close enough to the perfectly legitimate N=64000 case in
    // the test just above that no ratio can admit one and reject the
    // other). This pins the exact boundary: N options in one section builds
    // 2N+1 items (N options + N values + 1 section).
    const gpa = testing.allocator;
    var buf: [32]u8 = undefined;

    const n_below = (max_total_items - 1) / 2; // 2*n_below + 1 <= max_total_items
    var below: std.ArrayList(u8) = .empty;
    defer below.deinit(gpa);
    try below.appendSlice(gpa, "config t\n");
    for (0..n_below) |k| {
        const key = try std.fmt.bufPrint(&buf, "k{d}", .{k});
        try below.appendSlice(gpa, "\toption ");
        try below.appendSlice(gpa, key);
        try below.appendSlice(gpa, " v\n");
    }
    var pkg = try parse(gpa, below.items);
    pkg.deinit(gpa);

    const n_over = n_below + 1; // 2*n_over + 1 > max_total_items
    var over: std.ArrayList(u8) = .empty;
    defer over.deinit(gpa);
    try over.appendSlice(gpa, "config t\n");
    for (0..n_over) |k| {
        const key = try std.fmt.bufPrint(&buf, "k{d}", .{k});
        try over.appendSlice(gpa, "\toption ");
        try over.appendSlice(gpa, key);
        try over.appendSlice(gpa, " v\n");
    }
    try testing.expectError(error.MemoryLimitExceeded, parse(gpa, over.items));
}

// ── fuzz: parse never panics; parse -> serialize -> parse is stable ───────
//
// `parse` is a config-FILE parser, but the file is not always a trusted
// local artifact: `uci import`-style flows, config pulled from a management
// backend, or a device restoring a peer-supplied backup all hand this module
// bytes it did not write. Two harnesses:
//
//  1. Raw arbitrary bytes into `parse` — the "never panic/OOB/hang" bar
//     every parser here must clear. Mostly rejects at the first keyword
//     check, which is fine — it is the cheap, mandatory half.
//  2. A `Package` built directly in memory (bypassing the text grammar
//     entirely, so every generated instance is well-formed by construction)
//     is `serialize`d, `parse`d back, and the two models compared with
//     `Package.eql`, then serialized again and compared byte-for-byte — the
//     round-trip-stability invariant the module doc comment promises. This
//     is the half that actually reaches the serializer's bare-vs-quoted
//     decision and the quote-escaping path, which pure random bytes almost
//     never do (a `config`/`option` keyword match is already astronomically
//     unlikely from raw noise).

// ⚠ Both targets below opened with a collapsing draw and neither carried a
// corpus, so outside `--fuzz` each ran exactly one input, and it was empty.
// `fuzzParse` did `smith.bytes(&buf)` and then drew the length with
// `smith.valueRangeAtMost` — `bytes` eats the input and a ranged draw returns
// the range MINIMUM when fewer than eight octets remain, so the length was 0
// and `parse("")` was the whole target. `fuzzRoundTrip` opened
// `smith.value(bool)`, so every choice in it was a minimum too: no package
// name, `n_sections` = 0, and therefore an EMPTY `Package` serialized to an
// empty string and re-parsed. Measured 2026-09-07: 1 round each, 0 sections
// built, 0 options, 0 values — the serializer's bare-vs-quoted decision and
// its quote-escaping path, which the comment above names as the whole reason
// harness 2 exists, were never entered.

/// `testkit.fuzz.seed`, aliased so the corpora read as the config text and
/// scripts they are. A corpus entry is not the text: `Smith.slice` reads a
/// little-endian `u32` length first.
const seed = @import("testkit").fuzz.seed;

/// UCI config text, in the format the length draw reads. Random bytes reject
/// at the first keyword check essentially always (a `config`/`option` match
/// out of noise is astronomically unlikely), so a corpus is the only way this
/// parser is reached at all outside `--fuzz`.
const parse_seeds = [_][]const u8{
    seed("config rule\n"), // an anonymous section and nothing else
    seed("package net\n\nconfig interface 'lan'\n\toption proto 'static'\n"), // a package name, a named section, one option
    seed("config interface 'lan'\n\tlist ports 'eth0'\n\tlist ports 'eth1'\n"), // the repeated-key → list path
    seed("config x\n\toption v \"a'b\\\\c\\\"d\"\n"), // every double-quote escape the format defines
    seed("config x\n\toption v 'a\"b'\n"), // a single-quoted value that takes no escapes
    seed("config x\n\toption bare value\n"), // an unquoted value
    seed("config x\n\toption v ''\n"), // an empty quoted value
    seed("config x\n\toption v 'unterminated\n"), // a quote the line never closes
    seed("config\n"), // the keyword with no type after it
    seed("option v 'x'\n"), // an option before any section
    seed("config x\n\toption k 'a'\n\tlist k 'b'\n"), // mixed option/list under one key → MixedOptionList
    seed("# a comment\nconfig x\n"), // a comment line
    seed("config x\n\toption k 'v'\n" ** 40), // ~800 octets, inside the 1024 buffer
    seed("\x00\x01\x02\xff"), // control and high bytes: the "rejects at the keyword check" half
    seed(""), // zero length: the ONLY input this target ever ran
};

test "fuzz: parse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParse, .{ .corpus = &parse_seeds });
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    // ⚠ One byte-first draw. Never `bytes` then a ranged length.
    var buf: [1024]u8 = undefined;
    const len: usize = smith.slice(&buf);
    var pkg = parse(testing.allocator, buf[0..len]) catch return;
    pkg.deinit(testing.allocator);
}

test "corpus: every config seed reaches parse, and the model built is pinned" {
    // ⭐ The measurement, executable. `values` is the second number and it is
    // the load-bearing one: `parse("")` SUCCEEDS here — an empty config is a
    // valid package with no sections — so an "accepted > 0" guard would have
    // read 100% while the harness walked nothing at all. An option value
    // cannot be produced by an empty input.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var sections: usize = 0;
    var values: usize = 0;
    for (parse_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [1024]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var pkg = parse(testing.allocator, buf[0..len]) catch continue;
        defer pkg.deinit(testing.allocator);
        accepted += 1;
        sections += pkg.sections.len;
        for (pkg.sections) |s| for (s.options) |o| {
            values += o.values.len;
        };
    }
    // Measured 2026-09-07. Before: 1 round, `parse("")`, 0 sections, 0 values.
    try testing.expectEqual(parse_seeds.len - 1, nonempty); // the deliberate empty seed
    try testing.expectEqual(@as(usize, 10), accepted);
    try testing.expectEqual(@as(usize, 48), sections);
    try testing.expectEqual(@as(usize, 47), values);
}

/// Fill `buf` from the script and return the slice — including bytes below
/// 0x20, which `serialize` legitimately rejects with
/// `error.UnserializableValue` (UCI text has no escape producing a control
/// byte, `\n`/`\t`/`\r` included — see the parser's double-quote comment);
/// the caller is expected to propagate that as an early, no-bug return.
fn fuzzToken(c: *testkitFuzz.Cursor, buf: []u8, min_len: usize) []const u8 {
    const len: usize = @max(min_len, c.ranged(0, @intCast(buf.len)));
    for (buf[0..len]) |*b| b.* = c.byte();
    return buf[0..len];
}

const testkitFuzz = @import("testkit").fuzz;

/// Scripts for the round-trip generator. This harness draws a SHAPE, not a
/// byte string, so there is no frame to be faithful to — the fix is
/// `testkit.fuzz.Cursor`, which reads every choice out of ONE byte-first
/// `smith.slice`. That makes the draw honest (the gate's half) and makes a
/// seed a readable script instead of a sequence of `u64` words (the corpus
/// half), and under `--fuzz` the fuzzer still drives every choice because it
/// drives the slice. A short script CYCLES rather than running out.
const roundtrip_scripts = [_][]const u8{
    seed(""), // the empty script reproduces the collapsed harness EXACTLY: every read is 0, so the package is empty
    seed("\x01wan\x01\x02lan\x01\x03proto\x00\x01static"), // a named package, one named section, one single option
    seed("\x02\x03if\x00\x02a\x01\x01\x02xy\x02b\x00\x01\x01z"), // two sections, one anonymous
    seed("\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03"), // saturate every count: 3 sections x 3 options x 3 values
    seed("\x01p\x01\x02t\x01\x01n\x01\x01k\x01\x03'\"\\"), // a value made of the three characters the quoting rules turn on
    seed("\x01p\x01\x02t\x01\x01n\x01\x01k\x01\x02\x00\x0a"), // a NUL and a newline: the documented UnserializableValue refusal
};

test "fuzz: parse(serialize(pkg)) round-trips to an equal Package (and reserializes byte-identical)" {
    try testing.fuzz({}, fuzzRoundTrip, .{ .corpus = &roundtrip_scripts });
}

test "corpus: every round-trip script builds a package, and the sections built are pinned" {
    // `values` is the second number and it is the load-bearing one: the empty
    // script builds an EMPTY package, which serializes to "" and re-parses to
    // an equal empty package — a completely successful round trip that proves
    // nothing. That is exactly the state the collapsed harness was in on every
    // run, so a guard counting successful round trips would have read 1 of 1.
    var built: usize = 0;
    var sections: usize = 0;
    var values: usize = 0;
    for (roundtrip_scripts) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [64]u8 = undefined;
        const n: usize = smith.slice(&script);
        var c = testkitFuzz.Cursor{ .bytes = script[0..n] };
        var b: RoundTripBuild = undefined;
        const pkg = b.make(&c);
        built += 1;
        sections += pkg.sections.len;
        for (pkg.sections) |s| for (s.options) |o| {
            values += o.values.len;
        };
    }
    // Measured 2026-09-07. Before: 1 round, 0 sections, 0 options, 0 values.
    try testing.expectEqual(roundtrip_scripts.len, built);
    try testing.expectEqual(@as(usize, 13), sections);
    try testing.expectEqual(@as(usize, 25), values);
}

/// The generator's scratch, lifted out of the harness body so the corpus
/// guard above can build the SAME package the harness builds. A guard
/// measuring a different generator from the one the harness runs is not a
/// guard.
const RoundTripBuild = struct {
    pkg_name_buf: [16]u8 = undefined,
    type_bufs: [3][8]u8 = undefined,
    name_bufs: [3][16]u8 = undefined,
    key_bufs: [3][3][8]u8 = undefined,
    val_bufs: [3][3][3][16]u8 = undefined,
    value_slices: [3][3][3][]const u8 = undefined,
    options: [3][3]Option = undefined,
    sections: [3]Section = undefined,

    fn make(self: *RoundTripBuild, c: *testkitFuzz.Cursor) Package {
        const pkg_name: ?[]const u8 = if (c.byte() & 1 == 1) fuzzToken(c, &self.pkg_name_buf, 1) else null;

        const n_sections = c.ranged(0, 3);
        for (0..n_sections) |si| {
            const sec_type = fuzzToken(c, &self.type_bufs[si], 1);
            const has_name = c.byte() & 1 == 1;
            // min_len 1, not 0: the parser collapses an explicit empty-quoted
            // section name to anonymous (`name = null`, see `parseLine`'s
            // "config" branch) — a hand-built `Section{ .name = "" }` is a
            // shape `parse` can never itself produce, so it is deliberately
            // excluded here rather than hitting a spurious round-trip
            // mismatch.
            const sec_name: ?[]const u8 = if (has_name) fuzzToken(c, &self.name_bufs[si], 1) else null;

            const n_opts = c.ranged(0, 3);
            for (0..n_opts) |oi| {
                const key = fuzzToken(c, &self.key_bufs[si][oi], 1);
                // Force distinct keys within one section: a real parse can
                // never produce two Option entries sharing a key (repeated
                // `option` overwrites; `list`/`option` mixed under one key is
                // itself a parse error, `MixedOptionList`) — an accidental
                // collision here would build a Package shape the parser
                // structurally cannot reproduce, and would misreport as a
                // round-trip bug instead of a harness artifact.
                self.key_bufs[si][oi][0] = 'A' + @as(u8, @intCast(oi));
                const kind: Option.Kind = if (c.byte() & 1 == 1) .single else .list;
                const n_values: usize = if (kind == .single) 1 else c.ranged(1, 3);
                for (0..n_values) |vi| {
                    self.value_slices[si][oi][vi] = fuzzToken(c, &self.val_bufs[si][oi][vi], 0);
                }
                self.options[si][oi] = .{ .key = key, .kind = kind, .values = self.value_slices[si][oi][0..n_values] };
            }
            self.sections[si] = .{
                .type = sec_type,
                .name = sec_name,
                .anonymous = sec_name == null,
                .options = self.options[si][0..n_opts],
            };
        }
        return .{ .name = pkg_name, .sections = self.sections[0..n_sections] };
    }
};

fn fuzzRoundTrip(_: void, smith: *std.testing.Smith) !void {
    // ⚠ ONE byte-first draw, then a `Cursor` over it. What stood here opened
    // `smith.value(bool)` and drew every subsequent choice from `smith`
    // directly, so on the single empty input this target ever ran, every
    // choice was a minimum and the "package" was empty.
    var script: [64]u8 = undefined;
    const n: usize = smith.slice(&script);
    var c = testkitFuzz.Cursor{ .bytes = script[0..n] };
    var b: RoundTripBuild = undefined;
    const pkg = b.make(&c);

    const gpa = testing.allocator;
    const s1 = serialize(gpa, &pkg) catch |err| switch (err) {
        // A generated value containing an unescapable control byte, or a
        // generated type/name using a character real uci's own name
        // validator (audit A1 U7) rejects — both documented rejections, not
        // round-trip questions. `fuzzToken` draws raw random bytes for
        // every field including type/name/key, so this is common, not rare.
        error.UnserializableValue, error.InvalidName, error.OutOfMemory => return,
    };
    defer gpa.free(s1);

    var reparsed = parse(gpa, s1) catch |err| {
        std.debug.print("uci fuzz: serialize()'d text failed to re-parse: {s}\nerror: {t}\n", .{ s1, err });
        return err;
    };
    defer reparsed.deinit(gpa);

    if (!pkg.eql(&reparsed)) {
        std.debug.print("uci fuzz: round-trip mismatch\ninput text:\n{s}\n", .{s1});
        return error.RoundTripMismatch;
    }

    const s2 = try serialize(gpa, &reparsed);
    defer gpa.free(s2);
    try testing.expectEqualStrings(s1, s2);
}

// ── real uci capture (OpenWRT 25.12.4 VM lane) ──────────────────────────────
//
// Everything below is frozen from real runs of the real `uci` binary inside
// the OpenWRT image in `scripts/vm/images/` (see scripts/vm/README.md): a
// hand-written config was pushed into the guest's `/etc/config/`, then the
// real `uci export`/`uci show` stdout was captured verbatim — nothing here
// is derived from this module's own parser/serializer (per the project's
// governing rule: never derive a golden from your own output).
//
// Two real, reproducible disagreements were found this way and FIXED above
// (not papered over in a golden):
//  1. Real `uci`'s double-quote escapes are ONLY `\\`, `\"`, `\'` — a
//     backslash before any other character (n/t/r included) drops the
//     backslash and keeps that character literally; there is no UCI escape
//     that produces an actual control byte. This module previously
//     converted `\n`/`\t`/`\r` to real control bytes, which no test caught
//     because the (self-consistent) hand goldens only ever round-tripped
//     through this module's own encoder/decoder pair — a real second
//     implementation was needed to expose it. Fixed in the parser and
//     serializer above; see "double-quote escapes" and the two
//     "serializer rejects" tests.
//  2. Real `uci export` prints an unquoted `package <name>` header (a bare
//     word, not `package '<name>'`) when the name is identifier-safe.
//     Fixed above (`serialize` now uses `writeWord` for the package name);
//     see "package keyword and header serialization".
//
// One STYLE-ONLY difference was found and deliberately NOT changed: when a
// value contains a literal `'`, this module double-quotes it (`"a'b"`); the
// real `uci` binary instead splices single-quoted segments the POSIX-shell
// way (`'a'\''b'`). Both are valid UCI encodings of the identical value —
// this module's simpler single-segment choice is an explicit, documented
// design decision (SPEC.md), not a bug, so the golden below asserts VALUE
// equality for that field rather than raw text equality with real `uci`'s
// own splice-quoting.

const captured_testcfg_raw = "\n" ++
    "config interface 'lan'\n" ++
    "\toption proto 'static'\n" ++
    "\toption ipaddr '192.168.1.1'\n" ++
    "\toption netmask '255.255.255.0'\n" ++
    "\tlist dns '8.8.8.8'\n" ++
    "\tlist dns '1.1.1.1'\n" ++
    "\n" ++
    "config rule\n" ++
    "\toption name 'weird \"quote\" and back\\slash'\n" ++
    "\toption enabled '1'\n" ++
    "\toption note \"line1\\nline2\\ttabbed\"\n" ++
    "\n" ++
    "config rule\n" ++
    "\toption name 'second anon rule, with a comma and # not-a-comment'\n" ++
    "\n" ++
    "config switch 'globals'\n" ++
    "\toption bare_word_value_here 1\n" ++
    "\tlist ports '1'\n" ++
    "\tlist ports '2'\n" ++
    "\tlist ports '6t'\n";

// Real `uci export testcfg` stdout for the config above (the real binary
// always synthesizes a bare `package <name>` header from the requested
// config name — a CLI-layer convention this module's own parser doesn't
// need to replicate for raw-file parsing, but which `serialize` matches
// byte-for-byte once `pkg.name` is set the same way, as the test below
// shows).
const captured_testcfg_export = "package testcfg\n" ++
    "\n" ++
    "config interface 'lan'\n" ++
    "\toption proto 'static'\n" ++
    "\toption ipaddr '192.168.1.1'\n" ++
    "\toption netmask '255.255.255.0'\n" ++
    "\tlist dns '8.8.8.8'\n" ++
    "\tlist dns '1.1.1.1'\n" ++
    "\n" ++
    "config rule\n" ++
    "\toption name 'weird \"quote\" and back\\slash'\n" ++
    "\toption enabled '1'\n" ++
    "\toption note 'line1nline2ttabbed'\n" ++
    "\n" ++
    "config rule\n" ++
    "\toption name 'second anon rule, with a comma and # not-a-comment'\n" ++
    "\n" ++
    "config switch 'globals'\n" ++
    "\toption bare_word_value_here '1'\n" ++
    "\tlist ports '1'\n" ++
    "\tlist ports '2'\n" ++
    "\tlist ports '6t'\n" ++
    "\n";

// Real `uci show testcfg` stdout for the SAME config — dotted notation,
// revealing the generated anonymous-section addressing (`@rule[0]`,
// `@rule[1]`: a per-type, 0-based, file-order index — NOT a random/hashed
// name). The test below checks that same file-order/per-type semantics
// through `Package.iterate`, and a further test below checks it through
// `Package.nth`, which does expose `@type[N]` addressing directly (matching
// the real `uci` binary — see the "addressing probe" capture).
const captured_testcfg_show = "testcfg.lan=interface\n" ++
    "testcfg.lan.proto='static'\n" ++
    "testcfg.lan.ipaddr='192.168.1.1'\n" ++
    "testcfg.lan.netmask='255.255.255.0'\n" ++
    "testcfg.lan.dns='8.8.8.8' '1.1.1.1'\n" ++
    "testcfg.@rule[0]=rule\n" ++
    "testcfg.@rule[0].name='weird \"quote\" and back\\slash'\n" ++
    "testcfg.@rule[0].enabled='1'\n" ++
    "testcfg.@rule[0].note='line1nline2ttabbed'\n" ++
    "testcfg.@rule[1]=rule\n" ++
    "testcfg.@rule[1].name='second anon rule, with a comma and # not-a-comment'\n" ++
    "testcfg.globals=switch\n" ++
    "testcfg.globals.bare_word_value_here='1'\n" ++
    "testcfg.globals.ports='1' '2' '6t'\n";

test "real uci capture: parse(raw file) matches the real `uci show` structure — sections, list accumulation, two distinct anonymous `rule` sections in file order" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, captured_testcfg_raw);
    defer pkg.deinit(gpa);

    try testing.expectEqual(@as(usize, 4), pkg.sections.len);

    const lan = &pkg.sections[0];
    try testing.expectEqualStrings("interface", lan.type);
    try testing.expectEqualStrings("lan", lan.name.?);
    try testing.expectEqualStrings("static", lan.get("proto").?);
    try testing.expectEqualStrings("192.168.1.1", lan.get("ipaddr").?);
    const dns = lan.getList("dns");
    try testing.expectEqual(@as(usize, 2), dns.len);
    try testing.expectEqualStrings("8.8.8.8", dns[0]);
    try testing.expectEqualStrings("1.1.1.1", dns[1]);

    // The two anonymous `rule` sections — real uci addresses these as
    // @rule[0]/@rule[1] in exactly this file order; this module's
    // `iterate` gives the same order without needing that addressing.
    var it = pkg.iterate("rule");
    const r0 = it.next().?;
    try testing.expect(r0.anonymous);
    try testing.expectEqualStrings("weird \"quote\" and back\\slash", r0.get("name").?);
    try testing.expectEqualStrings("1", r0.get("enabled").?);
    // Confirms the real-bug fix: \n/\t are literal, not control bytes.
    try testing.expectEqualStrings("line1nline2ttabbed", r0.get("note").?);
    const r1 = it.next().?;
    try testing.expect(r1.anonymous);
    try testing.expectEqualStrings("second anon rule, with a comma and # not-a-comment", r1.get("name").?);
    try testing.expect(it.next() == null);

    const globals = &pkg.sections[3];
    try testing.expectEqualStrings("switch", globals.type);
    try testing.expectEqualStrings("globals", globals.name.?);
    try testing.expectEqualStrings("1", globals.get("bare_word_value_here").?);
    const ports = globals.getList("ports");
    try testing.expectEqual(@as(usize, 3), ports.len);
    try testing.expectEqualStrings("6t", ports[2]);

    // Confirm the real `@type[N]` addressing convention this capture
    // demonstrates is exactly the file-order-per-type index `iterate`
    // reflects (0 then 1, for the two `rule` sections above).
    try testing.expect(std.mem.indexOf(u8, captured_testcfg_show, "testcfg.@rule[0]=rule\n") != null);
    try testing.expect(std.mem.indexOf(u8, captured_testcfg_show, "testcfg.@rule[1]=rule\n") != null);
}

test "Package.sectionByName: pkg.<name> addressing by name alone, across types (real uci capture)" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, captured_testcfg_raw);
    defer pkg.deinit(gpa);

    // "lan" is type `interface`; sectionByName finds it without being told
    // the type, and agrees with the type-qualified lookup.
    const lan = pkg.sectionByName("lan").?;
    try testing.expectEqual(pkg.section("interface", "lan").?, lan);
    try testing.expectEqualStrings("static", lan.get("proto").?);

    // "globals" is type `switch` — a different type from "lan", still found
    // by name alone.
    const globals = pkg.sectionByName("globals").?;
    try testing.expectEqualStrings("switch", globals.type);
    try testing.expectEqualStrings("1", globals.get("bare_word_value_here").?);

    // A name that doesn't exist, and the anonymous `rule` sections (which
    // have no name to match), both miss.
    try testing.expect(pkg.sectionByName("nope") == null);
    try testing.expect(pkg.sectionByName("rule") == null);
}

test "Package.nth: @type[N] addressing, negative-index and out-of-range semantics (real uci capture)" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, captured_testcfg_raw);
    defer pkg.deinit(gpa);

    // Two `rule` sections in file order (both anonymous, per the capture
    // above) — @rule[0] and @rule[1] in real `uci show` output.
    const r0 = pkg.nth("rule", 0).?;
    try testing.expectEqualStrings("weird \"quote\" and back\\slash", r0.get("name").?);
    const r1 = pkg.nth("rule", 1).?;
    try testing.expectEqualStrings("second anon rule, with a comma and # not-a-comment", r1.get("name").?);

    // Negative index counts from the end: the match count (2) is added to
    // the index (-1 + 2 = 1, -2 + 2 = 0), so -1 is the last and -2 the first,
    // the same sections as above.
    try testing.expectEqual(r1, pkg.nth("rule", -1).?);
    try testing.expectEqual(r0, pkg.nth("rule", -2).?);

    // Out of range, both directions: a positive index at or past the match
    // count, and a negative index whose magnitude exceeds it (-3 + 2 = -1,
    // still negative after the adjustment). The real binary answers "Entry
    // not found" with a non-zero status for both (measured in the addressing
    // probe below), so this returns null rather than an error.
    try testing.expect(pkg.nth("rule", 2) == null);
    try testing.expect(pkg.nth("rule", 100) == null);
    try testing.expect(pkg.nth("rule", -3) == null);
    try testing.expect(pkg.nth("rule", -100) == null);

    // A type with exactly one match: index 0 and -1 both resolve to it.
    const globals = pkg.nth("switch", 0).?;
    try testing.expectEqualStrings("globals", globals.name.?);
    try testing.expectEqual(globals, pkg.nth("switch", -1).?);
    try testing.expect(pkg.nth("switch", 1) == null);
    try testing.expect(pkg.nth("switch", -2) == null);

    // A type with no matches at all: every index misses, index 0 included.
    try testing.expect(pkg.nth("nonexistent", 0) == null);
    try testing.expect(pkg.nth("nonexistent", -1) == null);

    // `nth(type, 0)` addresses the same section `@type[N]` does at N=0,
    // which `-0` also does — there's no separate `i64`
    // value for "-0" to test differently (see the doc-comment; `-0` isn't
    // even writable as a distinct i64 literal, which is the same point).
    const negative_zero: i64 = -@as(i64, 0);
    try testing.expectEqual(r0, pkg.nth("rule", negative_zero).?);
}

test "real uci capture: our serialize() reproduces real `uci export`'s canonical bytes exactly (package header, quoting, blank lines)" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, captured_testcfg_raw);
    defer pkg.deinit(gpa);
    pkg.name = "testcfg"; // `uci export <name>` synthesizes this; see header comment
    const text = try serialize(gpa, &pkg);
    defer gpa.free(text);
    // One further, deliberately-NOT-replicated difference: the real `uci
    // export` ends its output with an extra trailing blank line (verified
    // in the raw capture — a real blank line, not a terminal artifact) even
    // after the LAST block, where this module's `serialize` only inserts a
    // blank line BETWEEN blocks. Trimming that one trailing byte makes the
    // rest byte-identical; changing `serialize`'s general blank-line rule
    // for this one CLI-only trailing newline was judged not worth the
    // blast radius on every other hand test that asserts no trailing
    // blank line.
    try testing.expectEqualStrings(captured_testcfg_export[0 .. captured_testcfg_export.len - 1], text);

    // And it round-trips through this module's own parser back to an
    // equal model (the governing invariant `serialize` promises).
    var reparsed = try parse(gpa, text);
    defer reparsed.deinit(gpa);
    try testing.expect(pkg.eql(&reparsed));
}

// Second capture: one option per escape sequence, isolating exactly which
// backslash sequences are true escapes in real double-quoted UCI text.
const captured_esctest_raw = "config t\n" ++
    "\toption bslash \"a\\\\b\"\n" ++
    "\toption dquote \"a\\\"b\"\n" ++
    "\toption squote \"a\\'b\"\n" ++
    "\toption newline \"a\\nb\"\n" ++
    "\toption tab \"a\\tb\"\n" ++
    "\toption cr \"a\\rb\"\n" ++
    "\toption arbitrary \"a\\yb\"\n" ++
    "\toption single_no_escape 'a\\nb\\tc\\\\d'\n";

// ── addressing probe: named and anonymous sections of the SAME type ─────────
//
// Captured 2026-09-08 from the same OpenWRT 25.12.4 guest. This config exists
// because the `testcfg` capture above cannot answer one question: its two
// `rule` sections are BOTH anonymous, so it never shows whether a NAMED
// section occupies a position in `@type[N]`. That is exactly the semantics
// `sectionByName`/`nth` implement, and until this capture nothing in the tree
// measured it.
//
// What real `uci` said, verbatim (`uci show probe`, then `uci get` per key):
//
//   probe.alpha=t          probe.alpha.v='A'
//   probe.@t[1]=t          probe.@t[1].v='B'      <- the ANONYMOUS one is [1]
//   probe.gamma=t          probe.gamma.v='C'
//   probe.delta=other      probe.delta.v='D'
//
//   alpha      => A  rc=0        @t[0]  => A  rc=0
//   gamma      => C  rc=0        @t[1]  => B  rc=0
//   delta      => D  rc=0        @t[2]  => C  rc=0
//                                @t[3]  => uci: Entry not found  rc=1
//   @t[-1]     => C  rc=0        @t[-4] => uci: Entry not found  rc=1
//   @t[-3]     => A  rc=0        @t[-0] => A  rc=0
//   @other[0]  => D  rc=0
//
// Four facts, each now measured rather than read:
//  1. `pkg.<name>` resolves by NAME ALONE and across types — `delta` is type
//     `other`, `alpha`/`gamma` are type `t`, and all three answer.
//  2. `@type[N]` counts NAMED and ANONYMOUS sections of that type alike, in
//     file order: [0] is the named `alpha`, [1] the anonymous one, [2] the
//     named `gamma`. Real `uci show` labels the anonymous section `@t[1]`
//     itself, which corroborates it from a second direction.
//  3. A negative index counts from the end (-1 = last, -3 = first of three).
//  4. Out of range in EITHER direction is "not found" (rc=1), not an error of
//     a different kind — and `-0` behaves as `0`.
const captured_probe_raw = "config t 'alpha'\n" ++
    "\toption v A\n" ++
    "\n" ++
    "config t\n" ++
    "\toption v B\n" ++
    "\n" ++
    "config t 'gamma'\n" ++
    "\toption v C\n" ++
    "\n" ++
    "config other 'delta'\n" ++
    "\toption v D\n";

test "real uci capture: @type[N] counts NAMED and anonymous sections alike, and name lookup crosses types" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, captured_probe_raw);
    defer pkg.deinit(gpa);

    // 1. name alone, across types.
    try testing.expectEqualStrings("A", pkg.sectionByName("alpha").?.get("v").?);
    try testing.expectEqualStrings("C", pkg.sectionByName("gamma").?.get("v").?);
    try testing.expectEqualStrings("D", pkg.sectionByName("delta").?.get("v").?);

    // 2. the position of a NAMED section in @type[N] — the fact the older
    //    capture could not show, because both its `rule` sections were
    //    anonymous.
    try testing.expectEqualStrings("A", pkg.nth("t", 0).?.get("v").?);
    try testing.expectEqualStrings("B", pkg.nth("t", 1).?.get("v").?);
    try testing.expectEqualStrings("C", pkg.nth("t", 2).?.get("v").?);
    try testing.expect(pkg.nth("t", 3) == null);

    // 3. negative index from the end.
    try testing.expectEqualStrings("C", pkg.nth("t", -1).?.get("v").?);
    try testing.expectEqualStrings("A", pkg.nth("t", -3).?.get("v").?);
    try testing.expect(pkg.nth("t", -4) == null);

    // 4. `-0` is `0`, and each type counts separately.
    try testing.expectEqualStrings("A", pkg.nth("t", -@as(i64, 0)).?.get("v").?);
    try testing.expectEqualStrings("D", pkg.nth("other", 0).?.get("v").?);
}

test "real uci capture: escape-table probe — only \\\\ \\\" \\' are true escapes; \\n \\t \\r \\y all drop the backslash and keep the literal char" {
    const gpa = testing.allocator;
    var pkg = try parse(gpa, captured_esctest_raw);
    defer pkg.deinit(gpa);
    const sec = &pkg.sections[0];

    // Real `uci export`/`uci show` for this file (frozen, for reference):
    //   option bslash 'a\b'      option dquote 'a"b'
    //   option squote 'a'\''b'   option newline 'anb'
    //   option tab 'atb'         option cr 'arb'
    //   option arbitrary 'ayb'   option single_no_escape 'a\nb\tc\\d'
    try testing.expectEqualStrings("a\\b", sec.get("bslash").?);
    try testing.expectEqualStrings("a\"b", sec.get("dquote").?);
    try testing.expectEqualStrings("a'b", sec.get("squote").?); // value equal; see header re: splice-quoting style
    try testing.expectEqualStrings("anb", sec.get("newline").?);
    try testing.expectEqualStrings("atb", sec.get("tab").?);
    try testing.expectEqualStrings("arb", sec.get("cr").?);
    try testing.expectEqualStrings("ayb", sec.get("arbitrary").?);
    // Single quotes take NO escapes at all — backslashes stay literal.
    try testing.expectEqualStrings("a\\nb\\tc\\\\d", sec.get("single_no_escape").?);
}

test "real uci count canary: frozen raw configs + real capture, byte lengths unchanged" {
    try testing.expectEqual(@as(usize, 445), captured_testcfg_raw.len);
    try testing.expectEqual(@as(usize, 462), captured_testcfg_export.len);
    try testing.expectEqual(@as(usize, 198), captured_esctest_raw.len);
}
