// SPDX-License-Identifier: MIT
//! testkit — the harness pieces every module's tests were re-deriving.
//!
//! This is a **test-only** module: `build.zig` wires it into each consumer's
//! TEST binary, never into the module a downstream user imports (see
//! `Module.test_deps`). Importing `frost` does not drag this in.
//!
//! What lives here is only what was measurably duplicated, not everything a
//! test might want:
//!
//!   - `verboseSkip` / `skip` — 42 byte-identical copies across 26 modules.
//!   - `hex.bytes` — 18 byte-identical copies across 8 modules.
//!   - `expectHex` — the golden comparison, which every `goldens.zig` spelled
//!     differently and which is the one piece here that is *better* than what
//!     it replaces (see its doc comment).
//!
//! Deliberately NOT here: netns setup and privileged-capability probing. Those
//! read genuinely differently per module (`tc` wants a fresh netns with `lo`
//! at ifindex 1; `ebpf` wants CAP_BPF in the *initial* user namespace, where
//! `unshare -r` actively lies to you), and a shared abstraction over them
//! would hide exactly the distinctions that make the skips correct. The VOPR
//! side is already a module: `netsim`.

const std = @import("std");
const builtin = @import("builtin");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "std.testing, extended with the helpers this repo's own tests kept re-deriving",
    .deps = .{},
};

test {
    _ = hex;
    _ = @import("golden.zig");
}

pub const hex = @import("hex.zig");

pub const expectHex = @import("golden.zig").expectHex;
pub const expectBytes = @import("golden.zig").expectBytes;

// ── skips ────────────────────────────────────────────────────────────────

/// Portable env-var read for tests.
///
/// (`std.posix.getenv` does not exist in Zig 0.16; `std.testing.environ` +
/// `Environ.getPosix` is this repo's env-read pattern in tests.) That idiom
/// does not compile for `x86_64-windows-gnu`: `Environ.Block` resolves to
/// `GlobalBlock` there, which has no `.view()` method (`WindowsBlock`, which
/// does, is not the type `native_os == .windows` selects) — so `getPosix`'s
/// own body fails to compile for that target, regardless of how the result is
/// used. Measured 2026-08-18: this was one defect copy-pasted into 42
/// call sites across 26 modules (`if (std.testing.environ.getPosix("X_BENCH")
/// == null) return error.SkipZigTest;` and this module's own `verboseSkip`),
/// blocking the Windows cross-compile of every one of them.
///
/// The `if` below is a comptime-known branch — `builtin.target.os.tag` is
/// fixed at compile time — so Sema never analyses the `getPosix` call for a
/// Windows target and the compile error above never triggers. Returning
/// `null` is the honest answer for what this repo uses env reads for in
/// tests: bench opt-ins and skip-reason toggles, neither of which has a
/// Windows-side story to tell (`Environ.getWindows` exists but returns
/// WTF-16 and needs an allocator to become UTF-8 — real plumbing this call
/// is not worth for a bench gate). A caller that truly needs the Windows
/// value should call `std.process.Environ.getWindows` directly and own that
/// conversion; this helper is deliberately not it.
pub fn getEnv(name: []const u8) ?[]const u8 {
    if (builtin.target.os.tag == .windows) return null;
    return std.process.Environ.getPosix(std.testing.environ, name);
}

/// Whether a skipping test may explain itself on stderr.
///
/// Off by default, and that default is load-bearing: `zig build test` prints a
/// `failed command:` line whenever a step writes to stderr, **even when the
/// step succeeded**, so a chatty skip makes a green run look broken. The skip
/// COUNT still reaches the summary either way. Set `ZIG_LIBS_VERBOSE_SKIP` to
/// any non-empty value when you want the reasons.
///
/// ⚠ The NAME is not pinned by any test here, and cannot be: a test that reads
/// the same literal it is checking is circular, and a test binary cannot set a
/// variable for itself. A typo'd name would silently mean "never verbose"
/// forever — a mutation to `ZIG_LIBS_VERBOSE_SKIPS` passes the whole suite.
/// What IS pinned is the decision logic, via `verboseEnabled` below. The name
/// is held only by `scripts/test.sh` and this repo's docs using the same
/// spelling, so grep before you rename it.
pub const verbose_skip_env = "ZIG_LIBS_VERBOSE_SKIP";

pub fn verboseSkip() bool {
    return verboseEnabled(getEnv(verbose_skip_env));
}

/// The decision, split out from the environment read so it can be tested.
/// Unset and set-but-empty both mean off — `FOO= zig build test` is a common
/// way to *clear* a variable and must not turn diagnostics on.
pub fn verboseEnabled(raw: ?[]const u8) bool {
    const v = raw orelse return false;
    return v.len > 0;
}

/// Skip the calling test, explaining why when `ZIG_LIBS_VERBOSE_SKIP` is set.
///
/// Always returns `error.SkipZigTest`, so the call site reads
/// `return testkit.skip("needs CAP_BPF (uid {d})", .{uid});` — one statement
/// that cannot accidentally fall through to the assertions it was meant to
/// skip. That fall-through is not hypothetical: the pattern this replaces was
/// `if (verboseSkip()) print(...); return;`, a bare `return` that silently
/// PASSES rather than skipping, so the module's skip count under-reported.
pub fn skip(comptime fmt: []const u8, args: anytype) error{SkipZigTest} {
    if (verboseSkip()) {
        std.debug.print("\nSKIPPED: " ++ fmt ++ "\n", args);
    }
    return error.SkipZigTest;
}

test "skip always returns SkipZigTest" {
    // It returns the error VALUE, not an error union -- which is what makes
    // `return testkit.skip(...)` a statement the compiler checks, rather than
    // something a caller can ignore.
    try std.testing.expectEqual(error.SkipZigTest, skip("because {s}", .{"reasons"}));
}

test "verbose diagnostics are off unless the variable is set to something non-empty" {
    try std.testing.expect(!verboseEnabled(null));
    try std.testing.expect(!verboseEnabled("")); // `FOO= cmd` clears, not enables
    try std.testing.expect(verboseEnabled("1"));
    try std.testing.expect(verboseEnabled("0")); // any non-empty value, including "0"
}

test "verboseSkip agrees with the logic for the ambient environment" {
    // Weak by construction -- it reads the same constant the function does, so
    // it cannot catch a wrong NAME (see verbose_skip_env's warning). It does
    // catch the read being wired to the wrong predicate.
    const raw = getEnv(verbose_skip_env);
    try std.testing.expectEqual(verboseEnabled(raw), verboseSkip());
}

test "getEnv returns null on windows without touching Environ.getPosix" {
    // The reason this helper exists at all: on windows, calling
    // Environ.getPosix would fail to *compile*, not just return null. This
    // test only runs on windows when someone actually executes a windows
    // test binary (CI here never does — cross-compiled only), but it pins
    // the honest-null behavior for the platform this file cannot otherwise
    // demonstrate a build failure for.
    if (builtin.target.os.tag != .windows) return;
    try std.testing.expectEqual(@as(?[]const u8, null), getEnv("ANYTHING"));
}
