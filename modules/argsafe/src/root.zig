// SPDX-License-Identifier: MIT
//! argsafe — allowlist validators + safe argv construction: neutralize
//! argument/flag injection when building an exec argv from untrusted input.
//!
//! Provenance: original work of the zig-libs authors (MIT). Distills the
//! recurring "validate one argv token" pattern — a hand-rolled
//! character-class + length check guarding each
//! `std.process.run(.{ .argv = ... })` call site — into ONE composable
//! primitive (`CharClass`), a set of convenience predicates built on it,
//! and a typed `Argv` builder that makes it impossible to place an
//! unvalidated byte into an argv element.
//!
//! Security model: POSIX argv semantics. The values validated here only ever
//! go into ARRAY elements of an argv passed to `std.process.run` /
//! `std.process.Child` — never into a shell command string. There is therefore
//! no shell to quote against; the threats we actually neutralize are:
//!   * flag injection — a value read as an option (`-rf`, `--foo`) instead of a
//!     positional. Every predicate rejects a leading `-` by default.
//!   * argv-boundary smuggling — a raw NUL (truncates the C string execve sees)
//!     or a `\n`/control byte. NUL is rejected unconditionally; other control
//!     bytes by default.
//!   * path traversal — a `..` where the class shouldn't allow it (default on).
//!
//! Windows note: this module is POSIX-argv only. On Windows the CRT re-parses a
//! single command line via `CommandLineToArgvW`, whose backslash/quote rules are
//! a different (and much sharper) hazard — quoting there is NOT covered here.
//! See README "Boundaries".

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Allowlist validators + a typed argv builder — neutralizes argument/flag injection into an exec `argv`.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure byte checks; argv semantics are POSIX (see README)
    .role = .util,
    .concurrency = .reentrant, // no shared state; every fn is pure over its args
    .model_after = "allowlist validators (shlex.quote-adjacent) + typed argv builder",
    .deps = .{}, // std only
};

// ---------------------------------------------------------------------------
// CharClass — the one composable predicate the 14 seed validators collapse to.
// ---------------------------------------------------------------------------

/// A byte-class + length + structural predicate over a single argv token.
///
/// The default configuration is the *safe* one: a leading `-`/`--` is
/// rejected (flag injection), a raw NUL is rejected unconditionally,
/// control bytes are rejected, and `..` is rejected. Opt out consciously
/// per field.
///
/// A few example configurations:
///   * name with `_-.*`  → `.{ .extra = "_-.*", .first_char = .alnum }`
///   * strict name       → `.{ .extra = "_", .max_len = 64, .first_char = .not_digit }`
///   * dotted key        → `.{ .extra = "._-", .first_char = .alnum }`
///   * service name      → `.{ .extra = "_-", .max_len = 64, .first_char = .alnum }`
pub const CharClass = struct {
    /// Allow `[A-Za-z0-9]`.
    allow_alnum: bool = true,
    /// Extra single-byte characters to allow beyond alnum (e.g. `"_-."`).
    extra: []const u8 = "",
    min_len: usize = 1,
    max_len: usize = 128,
    /// Constraint on the first byte only (applied on top of the per-byte class).
    first_char: FirstChar = .any,
    /// Byte sequences that must not appear anywhere. Default bars path traversal.
    reject_substrings: []const []const u8 = &.{".."},
    /// Reject a leading `-` (flag injection). On by default — override only for
    /// a value you pass *after* a `--` end-of-options marker.
    reject_leading_dash: bool = true,
    /// Reject bytes `< 0x20` and `0x7f` (control + DEL). On by default. NUL is
    /// rejected regardless of this flag (an argv element can never contain one).
    reject_control: bool = true,

    pub const FirstChar = enum {
        /// No extra constraint on the first byte.
        any,
        /// First byte must be `[A-Za-z0-9]`.
        alnum,
        /// First byte must not be a digit (e.g. an identifier that may start
        /// with `_` but not `0`).
        not_digit,
        /// First byte must not be `-` (subsumed by `reject_leading_dash`, kept
        /// for explicit intent).
        not_dash,
    };

    /// True iff `s` satisfies every constraint. Never allocates, never panics.
    /// Delegates to `explain` — the two can never disagree because this IS
    /// `explain(s) == null`, not a second hand-written copy of the same rules.
    pub fn check(self: CharClass, s: []const u8) bool {
        return self.explain(s) == null;
    }

    /// Why `explain` rejected `s`, for a caller (a UI, a config-validation
    /// error message) that wants to say something more specific than "no"
    /// without re-implementing `check`'s rules. Tests the exact same
    /// conditions `check` does, in the exact same order, and returns the
    /// first one `s` fails — so `explain(s) == null` iff `check(s)` is `true`.
    /// Added for the `Template` argv-filler below, whose `fill` reports a
    /// refusal as `{ hole, why: Reason }` rather than a bare "rejected".
    pub const Reason = enum {
        /// `s.len < min_len` — in practice almost always literally `s` being
        /// empty, since `min_len` defaults to 1.
        too_short,
        /// `s.len > max_len`.
        too_long,
        /// Contains a raw NUL byte. Rejected unconditionally — not
        /// overridable by any field, because an argv element can never carry
        /// one (execve would see a truncated C string).
        nul_byte,
        /// Starts with `-` and `reject_leading_dash` is on (flag-injection
        /// guard; handles both `-x` and `--x`).
        leading_dash,
        /// Contains one of `reject_substrings` (default: `".."`).
        forbidden_substring,
        /// The first byte fails the `first_char` constraint.
        bad_first_char,
        /// Contains a control byte (`< 0x20` or `0x7f`) and `reject_control`
        /// is on.
        control_byte,
        /// A byte outside `allow_alnum`'s range and not in `extra`.
        bad_byte,
    };

    /// See `Reason` and `check`.
    pub fn explain(self: CharClass, s: []const u8) ?Reason {
        if (s.len < self.min_len) return .too_short;
        if (s.len > self.max_len) return .too_long;

        // Hard invariant: an argv element cannot carry a NUL — execve would see
        // a truncated C string. Reject regardless of `reject_control`.
        if (std.mem.indexOfScalar(u8, s, 0) != null) return .nul_byte;

        // Flag-injection guard (handles both `-x` and `--x`).
        if (self.reject_leading_dash and s.len > 0 and s[0] == '-') return .leading_dash;

        for (self.reject_substrings) |sub| {
            if (sub.len != 0 and std.mem.indexOf(u8, s, sub) != null) return .forbidden_substring;
        }

        if (s.len > 0) {
            const f = s[0];
            switch (self.first_char) {
                .any => {},
                .alnum => if (!isAlnum(f)) return .bad_first_char,
                .not_digit => if (isDigit(f)) return .bad_first_char,
                .not_dash => if (f == '-') return .bad_first_char,
            }
        }

        for (s) |c| {
            if (self.reject_control and (c < 0x20 or c == 0x7f)) return .control_byte;
            const allowed = (self.allow_alnum and isAlnum(c)) or
                std.mem.indexOfScalar(u8, self.extra, c) != null;
            if (!allowed) return .bad_byte;
        }
        return null;
    }

    /// Adapt this class to a plain `fn([]const u8) bool` for `Argv.pushIf` or
    /// any predicate-taking API. The class is captured at comptime.
    pub fn predicate(comptime self: CharClass) fn ([]const u8) bool {
        return struct {
            fn f(s: []const u8) bool {
                return self.check(s);
            }
        }.f;
    }
};

inline fn isAlnum(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9');
}
inline fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}
inline fn isHexDigit(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

// ---------------------------------------------------------------------------
// Convenience predicates (built on CharClass or the same discipline).
// Every one rejects a leading `-`, a raw NUL and a `\n` on its accept path.
// ---------------------------------------------------------------------------

/// A conservative shell/exec-safe identifier: `[A-Za-z0-9_-]`, first byte
/// alnum, 1..128 bytes. Covers the common service/name-token shape (for
/// names that also allow `.`/`*`, use `CharClass` directly).
pub fn isSafeIdentifier(s: []const u8) bool {
    const class: CharClass = .{ .extra = "_-", .max_len = 128, .first_char = .alnum };
    return class.check(s);
}

/// An absolute filesystem path safe to pass as one argv element: non-empty,
/// `≤ 4096` bytes, starts with `/`, no `..` traversal, no control bytes / NUL.
/// Rejects `..` traversal explicitly, unlike a naive absolute-path check.
pub fn isSafePath(s: []const u8) bool {
    if (s.len == 0 or s.len > 4096) return false;
    if (s[0] != '/') return false; // absolute only (also rules out a leading '-')
    if (std.mem.indexOf(u8, s, "..") != null) return false; // gap fix: no traversal
    for (s) |c| if (c < 0x20 or c == 0x7f) return false; // control + NUL (0x00 < 0x20)
    return true;
}

/// An `http(s)://` URL safe to pass as one argv element: 8..1024 bytes, an
/// `http://` or `https://` scheme, no control/space bytes, and none of the
/// quoting metacharacters `" ' \` `` ` `` (defense-in-depth even though argv is
/// not shell-parsed). The scheme guarantees no leading `-`; note that argv
/// semantics make `?`, `#`, `&`, `=` harmless, so —
/// unlike a shell-quoting validator — those are intentionally allowed.
pub fn isSafeUrl(s: []const u8) bool {
    if (s.len < 8 or s.len > 1024) return false;
    if (!std.mem.startsWith(u8, s, "http://") and !std.mem.startsWith(u8, s, "https://")) return false;
    for (s) |c| {
        if (c <= ' ' or c == 0x7f) return false; // control / space (incl. NUL)
        switch (c) {
            '"', '\'', '`', '\\' => return false,
            else => {},
        }
    }
    return true;
}

/// A base64 token (`[A-Za-z0-9+/=]`). If `exact_len` is given the length must
/// match exactly (`isSafeBase64(k, 44)` is the WireGuard-key shape: 44 accepted,
/// 43/45 rejected); otherwise 1..512 bytes. The charset excludes `-` and NUL, so
/// flag-injection and NUL-smuggling are covered by construction.
pub fn isSafeBase64(s: []const u8, exact_len: ?usize) bool {
    if (exact_len) |n| {
        if (s.len != n) return false;
    } else {
        if (s.len == 0 or s.len > 512) return false;
    }
    for (s) |c| {
        const ok = isAlnum(c) or c == '+' or c == '/' or c == '=';
        if (!ok) return false;
    }
    return true;
}

/// A `sep`-separated CIDR list: hex digits plus `. : /` and the separator only
/// (IPv4/IPv6 CIDRs), 1..256 bytes. The separator is a parameter (e.g. `,`).
/// The charset excludes `-` and NUL.
pub fn isSafeCidrList(s: []const u8, sep: u8) bool {
    if (s.len == 0 or s.len > 256) return false;
    // Explicit flag-injection guard, independent of `sep`: the charset below
    // excludes '-' only incidentally (when the caller's `sep` isn't '-'). A
    // caller passing `sep = '-'` would otherwise put '-' in the allowed set
    // and reopen leading-dash flag injection (e.g. "-4", "--help").
    if (s[0] == '-') return false;
    for (s) |c| {
        const ok = isHexDigit(c) or c == '.' or c == ':' or c == '/' or c == sep;
        if (!ok) return false;
    }
    return true;
}

/// A key=value option *value* passed as one argv token, 1..128 bytes, leading
/// `-` rejected (flag-injection guard). Two shapes:
///   * `printable_ascii = true`  → any printable ASCII `0x20..0x7e` (space
///     included).
///   * `printable_ascii = false` → the token set `[A-Za-z0-9._:/-]` (no spaces
///     / metachars).
pub fn isSafeKvValue(s: []const u8, printable_ascii: bool) bool {
    if (s.len == 0 or s.len > 128) return false;
    if (s[0] == '-') return false; // flag-injection guard
    if (printable_ascii) {
        for (s) |c| if (c < 0x20 or c > 0x7e) return false;
    } else {
        for (s) |c| {
            const ok = isAlnum(c) or c == '.' or c == '_' or c == '-' or c == ':' or c == '/';
            if (!ok) return false;
        }
    }
    return true;
}

/// Exact membership in a compile-time allowlist — for fixed enumerations of
/// accepted tokens (e.g. log levels, firewall keys). O(n)
/// over `allowed`, unrolled at comptime.
pub fn isInAllowlist(s: []const u8, comptime allowed: []const []const u8) bool {
    inline for (allowed) |a| {
        if (std.mem.eql(u8, s, a)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Argv — a typed builder that cannot hold an unvalidated argv element.
// ---------------------------------------------------------------------------

pub const Error = error{
    /// A `pushChecked` / `pushIf` argument failed its predicate.
    Rejected,
};

/// Assembles a `std.process.Child` / `std.process.run`-ready `[]const []const u8`
/// where every element is either a compile-time-known literal (a program name or
/// a fixed subcommand/flag that YOU control) or a run-time value that passed a
/// validator. There is no public method to append a raw run-time byte slice —
/// that is the security property: a caller cannot construct an argv element that
/// was not validated.
///
/// Once any `pushChecked`/`pushIf` is rejected the builder is *poisoned*:
/// `slice()` returns `error.Rejected` even if the caller swallowed the earlier
/// error, so a validation failure can never silently ship a short argv.
///
/// ```zig
/// var argv: argsafe.Argv = .empty;
/// defer argv.deinit(gpa);
/// try argv.push(gpa, "wg");                          // trusted literal
/// try argv.push(gpa, "set");
/// try argv.pushChecked(gpa, iface, .{ .extra = "_-.*", .first_char = .alnum });
/// try argv.push(gpa, "peer");
/// try argv.pushIf(gpa, pubkey, wgKey);               // wgKey: fn([]const u8) bool
/// const res = try std.process.run(gpa, io, .{ .argv = try argv.slice() });
/// ```
pub const Argv = struct {
    items: std.ArrayList([]const u8),
    ok: bool,

    pub const empty: Argv = .{ .items = .empty, .ok = true };

    pub fn deinit(self: *Argv, gpa: std.mem.Allocator) void {
        self.items.deinit(gpa);
    }

    /// Append a trusted, compile-time-known token: the program name, a fixed
    /// subcommand, or an option flag you control. Because `tok` is `comptime`
    /// it can never be an untrusted run-time value.
    pub fn push(self: *Argv, gpa: std.mem.Allocator, comptime tok: []const u8) std.mem.Allocator.Error!void {
        try self.items.append(gpa, tok);
    }

    /// Append a run-time value only if `class.check` passes; otherwise poison
    /// the builder and return `error.Rejected`.
    pub fn pushChecked(self: *Argv, gpa: std.mem.Allocator, s: []const u8, class: CharClass) (std.mem.Allocator.Error || Error)!void {
        if (!class.check(s)) {
            self.ok = false;
            return Error.Rejected;
        }
        try self.items.append(gpa, s);
    }

    /// Append a run-time value only if `pred(s)` is true; otherwise poison the
    /// builder and return `error.Rejected`. Use with the convenience predicates
    /// (`isSafePath`, `isSafeUrl`, …) or a `CharClass.predicate()`.
    pub fn pushIf(self: *Argv, gpa: std.mem.Allocator, s: []const u8, comptime pred: fn ([]const u8) bool) (std.mem.Allocator.Error || Error)!void {
        if (!pred(s)) {
            self.ok = false;
            return Error.Rejected;
        }
        try self.items.append(gpa, s);
    }

    /// The argv slice for `std.process.run` / `std.process.Child.init`, or
    /// `error.Rejected` if any push was rejected. Borrows the builder's storage
    /// — valid until `deinit`.
    pub fn slice(self: *const Argv) Error![]const []const u8 {
        if (!self.ok) return Error.Rejected;
        return self.items.items;
    }
};

// ---------------------------------------------------------------------------
// Template — an argv shape from a TRUSTED config, with typed holes filled by
// UNTRUSTED (per-hole-validated) run-time values.
// ---------------------------------------------------------------------------

/// One `{name}` placeholder a `Template`'s tokens may reference, and the
/// `CharClass` every value substituted for it must pass — exactly the same
/// `class.check`/`explain` a `pushChecked` call would run, so a templated
/// value is held to the identical rules as a hand-built `Argv`.
pub const Hole = struct {
    name: []const u8,
    class: CharClass,
};

pub const ParseError = error{
    /// `tokens` is empty — there is no program to run at all.
    EmptyTemplate,
    /// Two entries of `holes` share the same `name`. Ambiguous: which
    /// `CharClass` would govern a value substituted for that name?
    DuplicateHoleName,
    /// `tokens[0]` (the program) contains a `{...}` placeholder, valid or
    /// not. The program that runs must be fixed by the template alone —
    /// never influenced by a filled-in value — so a hole is refused in
    /// argv[0] regardless of whether its name would otherwise resolve.
    HoleInArgv0,
    /// A `{` has no matching `}`, or a `}` closes nothing, after accounting
    /// for the `{{`/`}}` literal-brace escapes (see `Template`'s doc comment).
    UnbalancedBrace,
    /// A `{name}` names a hole that isn't in `holes`. A config error (the
    /// template author misspelled a hole, or forgot to declare it) — never a
    /// per-value `fill` refusal, which is why it surfaces from `parse`.
    UnknownHole,
};

/// An argv shape from a **trusted config** (e.g. an admin-written action
/// definition: `["systemctl", "restart", "{unit}"]`), with named `{name}`
/// holes that `fill` substitutes with **untrusted** run-time values — each
/// checked against its own `Hole.class` before anything is built, exactly
/// the way `Argv.pushChecked` checks a run-time value against a `CharClass`.
///
/// `tokens` and `holes` are BORROWED, not copied — `parse` allocates nothing.
/// This mirrors `Argv.push`'s "trusted = comptime/caller-owned" story: a
/// config-loaded action definition already outlives every `fill` call made
/// against it (ttydesk keeps its parsed `Action`s in an arena for the
/// process lifetime), so there is nothing to own here beyond what `fill`
/// produces.
///
/// ## Hole syntax
///
/// `{name}` anywhere in a token after `argv[0]` names a hole; `name` must be
/// declared in `holes` (`parse` fails closed on typos — `error.UnknownHole`
/// — rather than silently treating a misspelled hole as literal text). A
/// hole may sit **inside** a token (`"--unit={unit}"`) or be the whole token
/// (`"{unit}"`); it may also be reused — the same name may appear more than
/// once, in one token or across several, and every occurrence substitutes
/// the identical value. `argv[0]` may never contain a hole, valid or not
/// (`error.HoleInArgv0`): the program that runs is the one thing a template
/// must never let a value choose.
///
/// A literal `{` or `}` that is NOT part of a hole is written doubled —
/// `{{` → literal `{`, `}}` → literal `}` — the same convention as
/// `std.fmt`/Python's `str.format`. To write a literal `{` immediately
/// followed by a real hole, double the first brace: `"{{{unit}"` is literal
/// `{` + hole `{unit}`. Any other unmatched `{` or stray `}` is
/// `error.UnbalancedBrace` — a template must parse unambiguously, not fall
/// back to "probably meant literally".
///
/// ## Value checking (flag injection, empty values, control bytes, NUL, …)
///
/// `fill` runs `hole.class.explain(value)` on the RAW value — the same
/// check `Argv.pushChecked` would run, regardless of where the hole sits
/// inside its token. This is a deliberate simplification, not an oversight:
/// tracking "is this occurrence at byte offset 0 of its token" per
/// occurrence would let a value starting with `-` through whenever the hole
/// happens to be embedded (`"--unit={unit}"`), on the reasoning that the
/// resulting token can't start with `-` there — technically true, but it
/// would mean the SAME hole is safe in one token and dangerous in another
/// depending on where the template author put the braces, which is exactly
/// the kind of position-dependent reasoning this module's "one predicate,
/// same rules everywhere" design (see SPEC.md) exists to avoid. So: with the
/// default `reject_leading_dash = true`, a value starting with `-` is always
/// refused, whether the hole is the whole token (where a leading `-` really
/// would be flag injection) or embedded (where this is stricter than
/// strictly necessary). A template author who KNOWS a given hole is never
/// used as a whole token can opt out per-hole via `.{ .reject_leading_dash =
/// false }` on that hole's `CharClass` — the exact same escape hatch
/// `CharClass`'s own doc comment already documents for "a value you pass
/// *after* a `--` end-of-options marker". Empty values, NUL and control
/// bytes need no special handling here either: they are already `min_len`/
/// NUL-always-rejected/`reject_control` in `CharClass`, so a hole with the
/// default class refuses them the same way `isSafeIdentifier` or any other
/// convenience predicate already does.
pub const Template = struct {
    tokens: []const []const u8,
    holes: []const Hole,

    /// Validate `tokens`/`holes` and build a `Template`. Allocates nothing —
    /// `tokens` and `holes` must outlive the returned `Template` (and every
    /// `fill` call made against it).
    pub fn parse(tokens: []const []const u8, holes: []const Hole) ParseError!Template {
        if (tokens.len == 0) return error.EmptyTemplate;
        for (holes, 0..) |h, i| {
            for (holes[i + 1 ..]) |h2| {
                if (std.mem.eql(u8, h.name, h2.name)) return error.DuplicateHoleName;
            }
        }
        try scanToken(tokens[0], holes, true);
        for (tokens[1..]) |tok| try scanToken(tok, holes, false);
        return .{ .tokens = tokens, .holes = holes };
    }

    /// Check every value against its hole's `CharClass` (positional: `values[i]`
    /// is `holes[i]`'s value — same convention as `Argv`'s "you name the
    /// order" style), and if all pass, build the argv: literal tokens copied
    /// verbatim, holed tokens with each `{name}` replaced by `values[i]` and
    /// `{{`/`}}` un-escaped to a literal brace.
    ///
    /// Ownership: the returned `Filled.argv` (on success) lives in
    /// `Filled`'s own arena — call `Filled.deinit` to free it. On a refusal
    /// nothing is allocated.
    pub fn fill(self: *const Template, gpa: std.mem.Allocator, values: []const []const u8) FillError!FillOutcome {
        // A returned error, not an assert: compiled out in ReleaseFast, a
        // count mismatch would read `values` out of bounds below.
        if (values.len != self.holes.len) return error.ValueCountMismatch;
        for (self.holes, values) |h, v| {
            if (h.class.explain(v)) |why| return .{ .refused = .{ .hole = h.name, .why = why } };
        }

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        errdefer arena_state.deinit();
        const arena = arena_state.allocator();

        var argv: std.ArrayList([]const u8) = .empty;
        for (self.tokens) |tok| {
            try argv.append(arena, try renderToken(arena, tok, self.holes, values));
        }
        return .{ .ok = .{ .arena_state = arena_state, .argv = argv.items } };
    }
};

/// `Template.fill`'s errors. A refused value is not one of them — that is
/// `FillOutcome.refused`.
pub const FillError = std.mem.Allocator.Error || error{
    /// `values` does not have exactly one entry per declared hole.
    ValueCountMismatch,
};

/// One hole-fill refusal: which hole, and why its value failed.
pub const Refusal = struct {
    hole: []const u8,
    why: CharClass.Reason,
};

/// The successfully filled argv, owning its own memory — `deinit` frees it
/// in one shot (one arena backs every token's rendered bytes and the argv
/// slice itself).
pub const Filled = struct {
    arena_state: std.heap.ArenaAllocator,
    argv: []const []const u8,

    pub fn deinit(self: *Filled) void {
        self.arena_state.deinit();
    }
};

pub const FillOutcome = union(enum) {
    ok: Filled,
    refused: Refusal,
};

fn holeIndex(holes: []const Hole, name: []const u8) ?usize {
    for (holes, 0..) |h, i| {
        if (std.mem.eql(u8, h.name, name)) return i;
    }
    return null;
}

/// Walk `tok`'s `{{`/`}}`/`{name}` grammar without producing output — used by
/// `Template.parse` to fail closed on a config error before any `fill` ever
/// runs. `forbid_holes` is set for `tokens[0]` only (see `ParseError.HoleInArgv0`).
fn scanToken(tok: []const u8, holes: []const Hole, forbid_holes: bool) ParseError!void {
    var i: usize = 0;
    while (i < tok.len) {
        const c = tok[i];
        if (c == '{') {
            if (i + 1 < tok.len and tok[i + 1] == '{') {
                i += 2;
                continue;
            }
            const close = std.mem.indexOfScalarPos(u8, tok, i, '}') orelse return error.UnbalancedBrace;
            if (forbid_holes) return error.HoleInArgv0;
            const name = tok[i + 1 .. close];
            if (holeIndex(holes, name) == null) return error.UnknownHole;
            i = close + 1;
        } else if (c == '}') {
            if (i + 1 < tok.len and tok[i + 1] == '}') {
                i += 2;
                continue;
            }
            return error.UnbalancedBrace; // stray close, no opener
        } else {
            i += 1;
        }
    }
}

/// Render one token: `{{`/`}}` un-escaped, `{name}` replaced by its value.
/// Called only after `Template.parse` has already validated this exact
/// grammar, so every `{`/`}`/`{name}` here is well-formed by construction —
/// the `.?` unwraps below can never actually fail.
fn renderToken(arena: std.mem.Allocator, tok: []const u8, holes: []const Hole, values: []const []const u8) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < tok.len) {
        const c = tok[i];
        if (c == '{') {
            if (i + 1 < tok.len and tok[i + 1] == '{') {
                try out.append(arena, '{');
                i += 2;
                continue;
            }
            const close = std.mem.indexOfScalarPos(u8, tok, i, '}').?;
            const idx = holeIndex(holes, tok[i + 1 .. close]).?;
            try out.appendSlice(arena, values[idx]);
            i = close + 1;
        } else if (c == '}') {
            // parse() guarantees an unescaped '}' here can only be "}}".
            try out.append(arena, '}');
            i += 2;
        } else {
            try out.append(arena, c);
            i += 1;
        }
    }
    return out.items;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

// --- CharClass: golden allow/reject over representative validators ------

test "documented edges of every predicate (mutation 2026-10-04)" {
    // Each line is a documented boundary the suite did not touch; a flip of
    // each one survived the mutation run of 2026-10-04.
    // `Reason.control_byte`: "< 0x20 or 0x7f" -- DEL is a control byte, and
    // it is reported as one even when `extra` would otherwise allow it.
    const del_ok: CharClass = .{ .extra = "\x7f" };
    try testing.expectEqual(@as(?CharClass.Reason, .control_byte), del_ok.explain("a\x7f"));
    // `allow_alnum = false` really takes the alphanumerics away.
    const no_alnum: CharClass = .{ .allow_alnum = false, .extra = "_" };
    try testing.expect(no_alnum.check("__"));
    try testing.expectEqual(@as(?CharClass.Reason, .bad_byte), no_alnum.explain("_a"));
    // isSafeIdentifier: `[A-Za-z0-9_-]` -- no `.`.
    try testing.expect(!isSafeIdentifier("a.b"));
    // isSafePath: "≤ 4096 bytes", "no control bytes" (DEL included).
    const p4096 = "/" ++ "a" ** 4095;
    try testing.expect(isSafePath(p4096));
    try testing.expect(!isSafePath(p4096 ++ "a"));
    try testing.expect(!isSafePath("/a\x7f"));
    // isSafeBase64 without exact_len: "1..512 bytes".
    try testing.expect(isSafeBase64("A" ** 512, null));
    try testing.expect(!isSafeBase64("A" ** 513, null));
    // isSafeCidrList: hex digits only -- `G`..`Z` are not.
    try testing.expect(isSafeCidrList("fe80::/10,10.0.0.0/8", ','));
    try testing.expect(!isSafeCidrList("Z", ','));
    // isSafeKvValue(printable): "0x20..0x7e" -- DEL is outside.
    try testing.expect(!isSafeKvValue("a\x7f", true));
}

test "CharClass reconstructs ubusNameSafe" {
    // ubus: alnum + `_-.*`, first alnum, ≤128, `..` allowed (a ubus glob).
    const c: CharClass = .{ .extra = "_-.*", .first_char = .alnum, .reject_substrings = &.{} };
    try testing.expect(c.check("network.interface"));
    try testing.expect(c.check("system"));
    try testing.expect(c.check("net*")); // glob passed literally to ubus
    try testing.expect(!c.check("")); // empty
    try testing.expect(!c.check("_leading")); // first not alnum
    try testing.expect(!c.check("-flag")); // flag injection
    try testing.expect(!c.check("a b")); // space
    try testing.expect(!c.check("a;b")); // metachar
}

test "CharClass reconstructs uciNameSafe (first not digit)" {
    const c: CharClass = .{ .extra = "_", .max_len = 64, .first_char = .not_digit };
    try testing.expect(c.check("_anon"));
    try testing.expect(c.check("lan"));
    try testing.expect(c.check("wan6"));
    try testing.expect(!c.check("0bad")); // leading digit
    try testing.expect(!c.check("a-b")); // '-' not in class
    try testing.expect(!c.check("a.b")); // '.' not in class
}

test "CharClass reconstructs sysctlKeySafe (rejects ..)" {
    const c: CharClass = .{ .extra = "._-", .first_char = .alnum };
    try testing.expect(c.check("net.ipv4.ip_forward"));
    try testing.expect(c.check("kernel.hostname"));
    try testing.expect(!c.check("net..ipv4")); // traversal
    try testing.expect(!c.check(".hidden")); // first not alnum
    try testing.expect(!c.check("net/ipv4")); // '/' not allowed
}

test "CharClass length bounds" {
    const c: CharClass = .{ .max_len = 4 };
    try testing.expect(c.check("abcd"));
    try testing.expect(!c.check("abcde"));
    try testing.expect(!c.check("")); // below default min_len 1
    const zero_ok: CharClass = .{ .min_len = 0, .max_len = 4 };
    try testing.expect(zero_ok.check("")); // explicit empty allowed
}

test "CharClass first_char == .not_dash rejects a leading dash directly" {
    // Mutation audit: `.not_dash` was never exercised by any test — a class
    // with `reject_leading_dash = false` so `.not_dash` is the ONLY guard
    // against a leading '-', isolating it the same way the reject_leading_dash
    // isolation test does below.
    const c: CharClass = .{ .extra = "-", .first_char = .not_dash, .reject_leading_dash = false };
    try testing.expect(!c.check("-x"));
    try testing.expect(c.check("x-y")); // '-' elsewhere is fine
}

test "CharClass.predicate adapts to a plain fn" {
    const p = (CharClass{ .extra = "_-", .first_char = .alnum }).predicate();
    try testing.expect(p("eth0"));
    try testing.expect(!p("-x"));
}

// --- Convenience predicates -------------------------------------------------

test "isSafeIdentifier" {
    try testing.expect(isSafeIdentifier("dropbear"));
    try testing.expect(isSafeIdentifier("wg-mesh"));
    try testing.expect(!isSafeIdentifier("_leading")); // first not alnum
    try testing.expect(!isSafeIdentifier("--help")); // flag injection
    try testing.expect(!isSafeIdentifier("a b"));
}

test "isSafePath: absolute, no traversal, no control (fixes seed gap)" {
    try testing.expect(isSafePath("/etc/config/network"));
    try testing.expect(isSafePath("/proc/sys/net/ipv4/ip_forward"));
    try testing.expect(!isSafePath("etc/passwd")); // relative
    try testing.expect(!isSafePath("/etc/../etc/shadow")); // traversal — seed accepted this
    try testing.expect(!isSafePath("/etc/\x00/x")); // NUL
    try testing.expect(!isSafePath("/etc/\nx")); // newline
    try testing.expect(!isSafePath("")); // empty
}

test "isSafeUrl: scheme + no quoting metachars" {
    try testing.expect(isSafeUrl("http://vault.local/v1/backup"));
    try testing.expect(isSafeUrl("https://10.0.0.1:8443/x?a=1&b=2#frag")); // ?&#= are argv-safe
    try testing.expect(!isSafeUrl("ftp://host/x")); // scheme
    try testing.expect(!isSafeUrl("http://a b/x")); // space
    try testing.expect(!isSafeUrl("http://a`id`b/x")); // backtick
    try testing.expect(!isSafeUrl("http://a\"b/x")); // quote
    try testing.expect(!isSafeUrl("http://a'b/x")); // single quote
    try testing.expect(!isSafeUrl("http://")); // too short (7 < 8)
}

test "isSafeBase64: WireGuard key shape (exactly 44)" {
    const key44 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO12="; // 44 chars
    try testing.expectEqual(@as(usize, 44), key44.len);
    try testing.expect(isSafeBase64(key44, 44));
    try testing.expect(!isSafeBase64(key44[0..43], 44)); // 43 rejected
    try testing.expect(!isSafeBase64("x" ++ key44, 44)); // 45 rejected
    try testing.expect(!isSafeBase64("has-dash-not-b64---------------------------==", 44));
    // Unbounded shape still works within 1..512.
    try testing.expect(isSafeBase64("AAAA", null));
    try testing.expect(!isSafeBase64("", null));
    try testing.expect(!isSafeBase64("A-A", null)); // '-' not base64
}

test "isSafeCidrList" {
    try testing.expect(isSafeCidrList("10.0.0.0/24", ','));
    try testing.expect(isSafeCidrList("10.0.0.0/24,fd00::/8", ','));
    try testing.expect(isSafeCidrList("10.0.0.0/24 fd00::/8", ' ')); // custom sep
    try testing.expect(!isSafeCidrList("10.0.0.0/24;rm", ',')); // metachar
    try testing.expect(!isSafeCidrList("", ','));
    try testing.expect(!isSafeCidrList("-10.0.0.0/8", ',')); // '-' not in class
    try testing.expect(!isSafeCidrList("10.0.0.g/24", ',')); // non-hex letter rejected
    try testing.expect(!isSafeCidrList("wg0.0.0.0/24", ',')); // non-hex alnum prefix rejected
}

test "isSafeCidrList: leading dash rejected even when sep collides with '-'" {
    // If a caller passes sep = '-', '-' joins the allowed charset; without an
    // explicit leading-dash guard (independent of sep) this would reopen flag
    // injection via a leading "-4" / "--help".
    try testing.expect(!isSafeCidrList("-4", '-'));
    try testing.expect(!isSafeCidrList("--help", '-'));
    try testing.expect(isSafeCidrList("1.2.3.0/24", '-'));
    try testing.expect(isSafeCidrList("1.2.3.0/24-fd00::/8", '-')); // '-' still works as separator
}

test "isSafeKvValue: token vs printable-ascii" {
    // token mode (fwValueSafe)
    try testing.expect(isSafeKvValue("tcp", false));
    try testing.expect(isSafeKvValue("192.168.1.0/24", false));
    try testing.expect(!isSafeKvValue("has space", false));
    try testing.expect(!isSafeKvValue("-tcp", false)); // flag injection (seed lacked this)
    // printable-ascii mode (sysctlValueSafe): spaces ok, control not
    try testing.expect(isSafeKvValue("1 262144 128", true));
    try testing.expect(!isSafeKvValue("a\tb", true)); // tab is control
    try testing.expect(!isSafeKvValue("a\x00b", true)); // NUL
}

test "isInAllowlist" {
    const levels = &.{ "err", "warn", "info", "debug" };
    try testing.expect(isInAllowlist("info", levels));
    try testing.expect(!isInAllowlist("trace", levels));
    try testing.expect(!isInAllowlist("", levels));
    try testing.expect(!isInAllowlist("INFO", levels)); // case-sensitive
}

// --- Property-style adversarial sweep ---------------------------------------
// Every argv-token predicate must reject these bytes on its accept path.

test "adversarial bytes are never accepted (CharClass family)" {
    const classes = [_]CharClass{
        .{ .extra = "_-", .first_char = .alnum }, // identifier-ish
        .{ .extra = "_-.*", .first_char = .alnum }, // ubus-ish
        .{ .extra = "_", .max_len = 64, .first_char = .not_digit }, // uci-ish
        .{ .extra = "._-", .first_char = .alnum }, // sysctl-key-ish
    };
    const adversarial = [_][]const u8{
        "\x00", // raw NUL
        "a\x00b", // embedded NUL
        "\n", // newline
        "a\nb", // embedded newline
        "-x", // leading dash (flag)
        "--x", // leading double dash
        "a..b", // path traversal
        "\x7f", // DEL
        "\x1b[0m", // ESC control seq
        "", // empty (below min_len)
    };
    for (classes) |c| {
        for (adversarial) |bad| {
            try testing.expect(!c.check(bad));
        }
    }
}

test "adversarial bytes are never accepted (convenience predicates)" {
    // NUL and newline must be rejected everywhere.
    try testing.expect(!isSafeIdentifier("a\x00b"));
    try testing.expect(!isSafeIdentifier("a\nb"));
    try testing.expect(!isSafePath("/a\x00b"));
    try testing.expect(!isSafePath("/a\nb"));
    try testing.expect(!isSafeUrl("http://a\x00b/"));
    try testing.expect(!isSafeUrl("http://a\nb/"));
    try testing.expect(!isSafeBase64("a\x00b", null));
    try testing.expect(!isSafeCidrList("a\x00b", ','));
    try testing.expect(!isSafeKvValue("a\x00b", true));
    try testing.expect(!isSafeKvValue("a\x00b", false));
    // Leading dash rejected where a positional is expected.
    try testing.expect(!isSafeIdentifier("-rf"));
    try testing.expect(!isSafeKvValue("-rf", false));
    try testing.expect(!isSafeKvValue("-rf", true));
}

// --- Argv builder -----------------------------------------------------------

test "Argv builds a validated argv" {
    const gpa = testing.allocator;
    var argv: Argv = .empty;
    defer argv.deinit(gpa);

    try argv.push(gpa, "wg");
    try argv.push(gpa, "set");
    try argv.pushChecked(gpa, "wg0", .{ .extra = "_-.*", .first_char = .alnum });
    try argv.push(gpa, "peer");
    const key44 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO12=";
    try argv.pushIf(gpa, key44, struct {
        fn f(s: []const u8) bool {
            return isSafeBase64(s, 44);
        }
    }.f);

    const got = try argv.slice();
    const want = [_][]const u8{ "wg", "set", "wg0", "peer", key44 };
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| try testing.expectEqualStrings(w, g);
}

test "Argv rejects an unvalidated piece and stays poisoned" {
    const gpa = testing.allocator;
    var argv: Argv = .empty;
    defer argv.deinit(gpa);

    try argv.push(gpa, "date");
    try argv.push(gpa, "-s");
    // Attacker-controlled spec with a metachar → rejected.
    try testing.expectError(Error.Rejected, argv.pushChecked(gpa, "2020;reboot", .{ .extra = ": -.@+TZ", .first_char = .alnum }));
    // The rejected element is NOT in the argv...
    try testing.expectEqual(@as(usize, 2), argv.items.items.len);
    // ...and the builder is poisoned even if the caller swallowed the error.
    try testing.expectError(Error.Rejected, argv.slice());
}

test "Argv pushIf rejection poisons too" {
    const gpa = testing.allocator;
    var argv: Argv = .empty;
    defer argv.deinit(gpa);
    try argv.push(gpa, "cat");
    try testing.expectError(Error.Rejected, argv.pushIf(gpa, "../../etc/shadow", isSafePath));
    try testing.expectError(Error.Rejected, argv.slice());
}

test "CharClass.check: reject_leading_dash is load-bearing in isolation (audit MED)" {
    // Batch-10 audit MED: the flag-injection guard had no ISOLATING positive
    // control — every adversarial sweep also tripped first_char/charset, so a
    // regression neutralizing reject_leading_dash would pass unnoticed. Build a
    // class where '-' is an allowed charset byte and there is no first_char
    // constraint, so reject_leading_dash is the ONLY guard that can reject a
    // flag-shaped arg.
    const guarded: CharClass = .{ .extra = "-", .first_char = .any, .reject_leading_dash = true };
    try testing.expect(!guarded.check("-rf"));
    try testing.expect(!guarded.check("--help"));
    try testing.expect(guarded.check("rf")); // non-flag still passes
    // Same class with the guard off accepts them — proving nothing else rejects,
    // so the assertions above bite iff the guard is intact.
    const unguarded: CharClass = .{ .extra = "-", .first_char = .any, .reject_leading_dash = false };
    try testing.expect(unguarded.check("-rf"));
    try testing.expect(unguarded.check("--help"));
}

// --- CharClass.explain: agrees with check() -------------------------------

test "CharClass.explain(s) == null iff check(s), over a representative sweep" {
    const classes = [_]CharClass{
        .{}, // default
        .{ .extra = "_-", .first_char = .alnum }, // identifier-ish
        .{ .extra = "_-.*", .first_char = .alnum }, // ubus-ish
        .{ .extra = "_", .max_len = 64, .first_char = .not_digit }, // uci-ish
        .{ .extra = "._-", .first_char = .alnum }, // sysctl-key-ish
        .{ .extra = "-", .first_char = .any, .reject_leading_dash = false }, // dash allowed
        .{ .min_len = 0, .max_len = 4 }, // explicit empty allowed
    };
    const inputs = [_][]const u8{
        "",     "a",      "abc",     "abcd",                "abcde",
        "\x00", "a\x00b", "\n",      "a\nb",                "-x",
        "--x",  "a..b",   "\x7f",    "\x1b[0m",             "_leading",
        "0bad", "eth0",   "wg-mesh", "net.ipv4.ip_forward",
    };
    for (classes) |c| {
        for (inputs) |s| {
            try testing.expectEqual(c.explain(s) == null, c.check(s));
        }
    }
}

test "CharClass.explain: each Reason is reachable and matches its condition" {
    const default: CharClass = .{};
    try testing.expectEqual(CharClass.Reason.too_short, default.explain("").?);
    try testing.expectEqual(CharClass.Reason.too_long, default.explain("a" ** 129).?);
    try testing.expectEqual(CharClass.Reason.nul_byte, default.explain("a\x00b").?);
    try testing.expectEqual(CharClass.Reason.leading_dash, default.explain("-x").?);
    try testing.expectEqual(CharClass.Reason.forbidden_substring, default.explain("a..b").?);
    const alnum_first: CharClass = .{ .extra = "_", .first_char = .alnum };
    try testing.expectEqual(CharClass.Reason.bad_first_char, alnum_first.explain("_x").?);
    try testing.expectEqual(CharClass.Reason.control_byte, default.explain("a\nb").?);
    try testing.expectEqual(CharClass.Reason.bad_byte, default.explain("a;b").?);
    try testing.expectEqual(@as(?CharClass.Reason, null), default.explain("abc"));
}

// --- Template ----------------------------------------------------------

test "Template.parse: unknown hole name in a token is a parse error" {
    const holes = [_]Hole{.{ .name = "known", .class = .{} }};
    try testing.expectError(error.UnknownHole, Template.parse(&.{ "prog", "{bogus}" }, &holes));
}

test "Template.parse: a hole in argv[0] is a parse error" {
    const holes = [_]Hole{.{ .name = "prog", .class = .{} }};
    try testing.expectError(error.HoleInArgv0, Template.parse(&.{ "{prog}", "arg" }, &holes));
    // Even an UNKNOWN name in argv[0] is reported as HoleInArgv0, not
    // UnknownHole -- argv[0] never gets a hole, full stop.
    try testing.expectError(error.HoleInArgv0, Template.parse(&.{ "{bogus}", "arg" }, &holes));
}

test "Template.parse: unbalanced braces are a parse error" {
    const holes = [_]Hole{.{ .name = "x", .class = .{} }};
    try testing.expectError(error.UnbalancedBrace, Template.parse(&.{ "prog", "--opt={x" }, &holes)); // unclosed
    try testing.expectError(error.UnbalancedBrace, Template.parse(&.{ "prog", "a}b" }, &.{})); // stray close
}

test "Template.parse: duplicate hole names and an empty template are parse errors" {
    const dup = [_]Hole{ .{ .name = "x", .class = .{} }, .{ .name = "x", .class = .{} } };
    try testing.expectError(error.DuplicateHoleName, Template.parse(&.{"prog"}, &dup));
    try testing.expectError(error.EmptyTemplate, Template.parse(&.{}, &.{}));
}

test "Template.fill: success, including a hole embedded inside a token" {
    const gpa = testing.allocator;
    const holes = [_]Hole{.{ .name = "unit", .class = .{ .extra = "_-.@", .first_char = .alnum } }};
    const t = try Template.parse(&.{ "systemctl", "restart", "{unit}" }, &holes);

    var out = try t.fill(gpa, &.{"nginx.service"});
    switch (out) {
        .ok => |*filled| {
            defer filled.deinit();
            try testing.expectEqual(@as(usize, 3), filled.argv.len);
            try testing.expectEqualStrings("systemctl", filled.argv[0]);
            try testing.expectEqualStrings("restart", filled.argv[1]);
            try testing.expectEqualStrings("nginx.service", filled.argv[2]);
        },
        .refused => return error.TestUnexpectedResult,
    }

    // A hole embedded mid-token, not the whole token.
    const holes2 = [_]Hole{.{ .name = "unit", .class = .{ .extra = "_-.@", .first_char = .alnum } }};
    const t2 = try Template.parse(&.{ "systemctl", "--user", "restart={unit}" }, &holes2);
    out = try t2.fill(gpa, &.{"nginx"});
    switch (out) {
        .ok => |*filled| {
            defer filled.deinit();
            try testing.expectEqualStrings("restart=nginx", filled.argv[2]);
        },
        .refused => return error.TestUnexpectedResult,
    }
}

test "Template.fill: a hole reused twice (same token and across tokens) substitutes consistently" {
    const gpa = testing.allocator;
    const holes = [_]Hole{.{ .name = "name", .class = .{ .extra = "_-", .first_char = .alnum } }};
    const t = try Template.parse(&.{ "cp", "/data/{name}", "/backup/{name}-{name}.bak" }, &holes);
    var out = try t.fill(gpa, &.{"report"});
    switch (out) {
        .ok => |*filled| {
            defer filled.deinit();
            try testing.expectEqualStrings("/data/report", filled.argv[1]);
            try testing.expectEqualStrings("/backup/report-report.bak", filled.argv[2]);
        },
        .refused => return error.TestUnexpectedResult,
    }
}

test "Template.fill: literal brace escaping ({{ and }})" {
    const gpa = testing.allocator;
    const holes = [_]Hole{.{ .name = "x", .class = .{} }};
    // "{{{x}}}" == literal '{' + hole {x} + literal '}'
    const t = try Template.parse(&.{ "prog", "{{{x}}}" }, &holes);
    var out = try t.fill(gpa, &.{"v"});
    switch (out) {
        .ok => |*filled| {
            defer filled.deinit();
            try testing.expectEqualStrings("{v}", filled.argv[1]);
        },
        .refused => return error.TestUnexpectedResult,
    }
}

test "Template.fill: each refusal reason surfaces with the offending hole's name" {
    const gpa = testing.allocator;
    const holes = [_]Hole{
        .{ .name = "a", .class = .{ .max_len = 4 } },
        .{ .name = "b", .class = .{} },
    };
    const t = try Template.parse(&.{ "prog", "{a}", "{b}" }, &holes);

    // Too long.
    var out = try t.fill(gpa, &.{ "toolong", "ok" });
    try testing.expectEqualStrings("a", out.refused.hole);
    try testing.expectEqual(CharClass.Reason.too_long, out.refused.why);

    // Empty value.
    out = try t.fill(gpa, &.{ "", "ok" });
    try testing.expectEqualStrings("a", out.refused.hole);
    try testing.expectEqual(CharClass.Reason.too_short, out.refused.why);

    // NUL / control bytes.
    out = try t.fill(gpa, &.{ "ok", "a\x00b" });
    try testing.expectEqualStrings("b", out.refused.hole);
    try testing.expectEqual(CharClass.Reason.nul_byte, out.refused.why);
    out = try t.fill(gpa, &.{ "ok", "a\nb" });
    try testing.expectEqualStrings("b", out.refused.hole);
    try testing.expectEqual(CharClass.Reason.control_byte, out.refused.why);
}

test "Template.fill: flag-injection attempt (value starting with '-') is refused by default" {
    const gpa = testing.allocator;
    const holes = [_]Hole{.{ .name = "unit", .class = .{ .extra = "_-.", .first_char = .any } }};
    const t = try Template.parse(&.{ "systemctl", "restart", "{unit}" }, &holes);
    const out = try t.fill(gpa, &.{"--now"});
    try testing.expectEqualStrings("unit", out.refused.hole);
    try testing.expectEqual(CharClass.Reason.leading_dash, out.refused.why);
}

test "Template.fill: an explicit reject_leading_dash = false opt-out allows a leading '-' value" {
    // Documents the escape hatch named in `Template`'s doc comment: a
    // template author who knows a hole is safe with a leading '-' (e.g.
    // always embedded after `=`, or always placed after a `--` marker) can
    // turn the guard off per-hole, same as `CharClass` already allows.
    const gpa = testing.allocator;
    const holes = [_]Hole{.{ .name = "n", .class = .{ .extra = "-", .first_char = .any, .reject_leading_dash = false } }};
    const t = try Template.parse(&.{ "prog", "{n}" }, &holes);
    var out = try t.fill(gpa, &.{"-5"});
    switch (out) {
        .ok => |*filled| {
            defer filled.deinit();
            try testing.expectEqualStrings("-5", filled.argv[1]);
        },
        .refused => return error.TestUnexpectedResult,
    }
}

test "Template.fill: a wrong number of values is an error, not an out-of-bounds read" {
    const t = try Template.parse(&.{ "systemctl", "restart", "{unit}" }, &.{.{ .name = "unit", .class = .{} }});
    try testing.expectError(error.ValueCountMismatch, t.fill(testing.allocator, &.{}));
    try testing.expectError(error.ValueCountMismatch, t.fill(testing.allocator, &.{ "a", "b" }));
}
