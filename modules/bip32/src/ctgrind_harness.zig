// SPDX-License-Identifier: MIT

//! ctgrind_harness — `bip32`'s entry in the constant-time gate (A1 `bip32.md`
//! M6). Run it through `../../../scripts/ctgrind.sh bip32`.
//!
//! NOT wired into `zig build test-bip32` — memcheck's context count is
//! valgrind's output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## Targets — each taints ONE secret and nothing that is public
//!
//! * `master`   — the BIP-32 seed through `masterFromSeed` (HMAC-SHA512, the
//!   `IL >= n` / `IL == 0` validity checks).
//! * `derive`   — the master PRIVATE SCALAR through `derivePath`
//!   (`m/44'/0'/0'/0/0`: three hardened and two normal `ckdPriv` steps). The
//!   chain code is NOT tainted: it is half of the `xpub`, i.e. public in the
//!   deployment this module targets.
//! * `seed`     — the mnemonic through `mnemonic.mnemonicToSeed`
//!   (PBKDF2-HMAC-SHA512, 2048 rounds).
//! * `mnemonic` — the mnemonic through `mnemonic.mnemonicToEntropy` (word
//!   split, wordlist lookup, checksum). SPEC.md already names this path as
//!   NOT constant-time (`wordIndex` is a binary search over the wordlist); the
//!   row records how much, so a change in either direction is visible.
//!
//! ## Verdicts are declassified, payloads are not
//!
//! Every target returns an error union whose TAG is a function of the secret
//! (the ~2^-127 invalid-key cases, a checksum mismatch). Branching on that tag
//! in the harness would be a context the harness made up. `settle` reads the
//! payload without a branch, checks the tag on a DECLASSIFIED copy (accept or
//! reject is what any caller learns anyway), and returns the still-tainted
//! payload, which is then printed as the propagation witness.
//!
//! ## The traps
//!
//! 1. Without `-fvalgrind` every row reads 0 regardless — the driver prints
//!    that as its own row.
//! 2. `reloadVolatile` forces a real load from freshly tainted memory, so a
//!    constant-folded copy of the fixed test inputs cannot be used instead.
//! 3. ReleaseFast only.

const std = @import("std");
const builtin = @import("builtin");
const bip32 = @import("root.zig");
const memcheck = std.valgrind.memcheck;

const Target = enum { master, derive, seed, mnemonic };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    inline for (@typeInfo(Target).@"enum".fields) |f| {
        if (std.mem.eql(u8, s, f.name)) return @field(Target, f.name);
    }
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn reloadVolatile(comptime T: type, s: *const T) T {
    const v: *const volatile T = s;
    return v.*;
}

/// Marks `buf` undefined (when tainting) and returns it re-read byte by byte
/// through a volatile pointer, into `out`.
fn taintBytes(buf: []u8, out: []u8, taint: Taint) void {
    if (taint == .yes) memcheck.makeMemUndefined(buf);
    for (out, buf) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
}

/// The payload of `r`, without a branch on its tag; the tag itself is checked
/// on a declassified copy. See the module doc comment.
fn settle(r: anytype) !@typeInfo(@TypeOf(r)).error_union.payload {
    const payload = r catch undefined;
    var copy = r;
    memcheck.makeMemDefined(std.mem.asBytes(&copy));
    _ = try reloadVolatile(@TypeOf(r), &copy);
    return payload;
}

fn fixedSeed() [64]u8 {
    var s: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash("ctgrind-bip32-harness-seed-v1", &s, .{});
    return s;
}

/// BIP-39 English test vector (entropy `7f` * 16). Varied word lengths, so a
/// split that depended on them has something to depend on.
const mnemonic_text = "legal winner thank year wave sausage worth useful legal winner thank yellow";

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const taint = try parseTaint(it.next() orelse return error.MissingTaint);

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    switch (target) {
        .master => {
            var raw = fixedSeed();
            var seed: [64]u8 = undefined;
            taintBytes(&raw, &seed, taint);
            const m = try settle(bip32.masterFromSeed(&seed));
            std.debug.print("privkey={x}\nchain_code={x}\n", .{ m.privkey, m.chain_code });
        },
        .derive => {
            var master = try bip32.masterFromSeed(&fixedSeed()); // untainted setup
            var raw = master.privkey;
            taintBytes(&raw, &master.privkey, taint);
            const h = bip32.hardened_offset;
            const path = [_]u32{ 44 + h, 0 + h, 0 + h, 0, 0 };
            const child = try settle(bip32.derivePath(master, &path));
            std.debug.print("privkey={x}\nchain_code={x}\n", .{ child.privkey, child.chain_code });
        },
        .seed => {
            var raw: [mnemonic_text.len]u8 = mnemonic_text.*;
            var words: [mnemonic_text.len]u8 = undefined;
            taintBytes(&raw, &words, taint);
            var out: [64]u8 = undefined;
            try bip32.mnemonic.mnemonicToSeed(&words, "TREZOR", &out);
            std.debug.print("seed={x}\n", .{out});
        },
        .mnemonic => {
            var raw: [mnemonic_text.len]u8 = mnemonic_text.*;
            var words: [mnemonic_text.len]u8 = undefined;
            taintBytes(&raw, &words, taint);
            var ent: [bip32.mnemonic.max_entropy_bytes]u8 = undefined;
            // Printed as the fixed 16 bytes a 12-word phrase decodes to, not
            // as the returned slice: its LENGTH is also secret-derived, and a
            // formatter looping over it would witness that, not the bytes.
            _ = try settle(bip32.mnemonic.mnemonicToEntropy(&words, &ent));
            std.debug.print("entropy={x}\n", .{ent[0..16].*});
        },
    }
}
