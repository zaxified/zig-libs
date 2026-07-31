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

pub const meta = .{
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

/// Whether a skipping test may explain itself on stderr.
///
/// Off by default, and that default is load-bearing: `zig build test` prints a
/// `failed command:` line whenever a step writes to stderr, **even when the
/// step succeeded**, so a chatty skip makes a green run look broken. The skip
/// COUNT still reaches the summary either way. Set `ZIG_LIBS_VERBOSE_SKIP` to
/// any non-empty value when you want the reasons.
///
/// (`std.posix.getenv` does not exist in Zig 0.16; `std.testing.environ` +
/// `Environ.getPosix` is this repo's env-read pattern in tests.)
/// ⚠ The NAME is not pinned by any test here, and cannot be: a test that reads
/// the same literal it is checking is circular, and a test binary cannot set a
/// variable for itself. A typo'd name would silently mean "never verbose"
/// forever — a mutation to `ZIG_LIBS_VERBOSE_SKIPS` passes the whole suite.
/// What IS pinned is the decision logic, via `verboseEnabled` below. The name
/// is held only by `scripts/test.sh` and this repo's docs using the same
/// spelling, so grep before you rename it.
pub const verbose_skip_env = "ZIG_LIBS_VERBOSE_SKIP";

pub fn verboseSkip() bool {
    return verboseEnabled(std.process.Environ.getPosix(std.testing.environ, verbose_skip_env));
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
    const raw = std.process.Environ.getPosix(std.testing.environ, verbose_skip_env);
    try std.testing.expectEqual(verboseEnabled(raw), verboseSkip());
}
