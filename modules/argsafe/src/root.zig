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
    pub fn check(self: CharClass, s: []const u8) bool {
        if (s.len < self.min_len or s.len > self.max_len) return false;

        // Hard invariant: an argv element cannot carry a NUL — execve would see
        // a truncated C string. Reject regardless of `reject_control`.
        if (std.mem.indexOfScalar(u8, s, 0) != null) return false;

        // Flag-injection guard (handles both `-x` and `--x`).
        if (self.reject_leading_dash and s.len > 0 and s[0] == '-') return false;

        for (self.reject_substrings) |sub| {
            if (sub.len != 0 and std.mem.indexOf(u8, s, sub) != null) return false;
        }

        if (s.len > 0) {
            const f = s[0];
            switch (self.first_char) {
                .any => {},
                .alnum => if (!isAlnum(f)) return false,
                .not_digit => if (isDigit(f)) return false,
                .not_dash => if (f == '-') return false,
            }
        }

        for (s) |c| {
            if (self.reject_control and (c < 0x20 or c == 0x7f)) return false;
            const allowed = (self.allow_alnum and isAlnum(c)) or
                std.mem.indexOfScalar(u8, self.extra, c) != null;
            if (!allowed) return false;
        }
        return true;
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

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

// --- CharClass: golden allow/reject over representative validators ------

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
