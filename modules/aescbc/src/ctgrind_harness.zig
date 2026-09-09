// SPDX-License-Identifier: MIT

//! ctgrind_harness — measures the two padding strippers, which are the only
//! places this module does its own arithmetic over a secret. Run it through
//! `../../../scripts/ctgrind.sh aescbc`.
//!
//! ## Why this module has a harness at all
//!
//! The 2026-09-09 ctgrind coverage pass filed `aescbc` as a "thin wrapper over
//! std" — hand the key to `std.crypto.core.aes`, measure nothing of our own —
//! and that was wrong. `unpadPkcs7` and `unpadXmlEnc` strip padding from a
//! JUST-DECRYPTED buffer, so the length byte `N` they read is secret-derived,
//! and the module states a constant-time property about them in its own words:
//!
//!   "accumulating every check into a single flag with no secret-dependent
//!    early exit (no distinct control-flow signal for 'bad length' vs.
//!    'bad pad byte')"                                    — `root.zig:152-155`
//!
//! That is a claim about this module's own code, it is the classic padding
//! oracle shape, and nothing in the repository measured it. It is also written
//! in exactly the idiom that did NOT survive the compiler elsewhere: `u1` flags
//! from `@intFromBool`, OR-accumulated. `fss`'s `xorMasked` (`dpf.zig:326`) was
//! written that way, stayed branch-free at two call sites, and became
//! `test $0x1,%r9b` / `je` at a third — in the same binary. Reading the source
//! settles nothing here.
//!
//! ## What is tainted, and what the honest expectation is
//!
//! A real message is padded with the module's own `padPkcs7`, and then the
//! WHOLE padded buffer is marked undefined before the call — which is what a
//! decryption result is: attacker-influenced ciphertext, secret key, so every
//! byte including the trailing length byte `N` is secret-derived. Nothing is
//! narrowed to "just the padding": that would measure a kinder input than the
//! function actually gets.
//!
//! ⚠ **A zero here would be the WRONG answer, and a reader should not want
//! one.** Both functions end in `if (invalid != 0) return error.InvalidPadding`
//! and return `buf.len - pad_len`. Both of those ARE derived from the secret,
//! and both are disclosed to the caller by the API's own contract: the caller
//! learns accept/reject from the error, and the plaintext length from the
//! return value. A branch on a value the function is about to return is not a
//! leak. What the claim above actually forbids is a *distinct* signal per
//! failure reason, or an early exit that ends the scan when the first pad byte
//! mismatches — that is what makes the difference between "the padding was
//! wrong" and "the padding was wrong THIS way", and it is what these rows are
//! for. So read the in-file count as "the accept/reject decision and the
//! length, and nothing else", not as "zero".
//!
//! ## The traps
//!
//! 1. Without `-fvalgrind` every row reads 0 regardless; the driver builds both
//!    ways and prints the no-`-fvalgrind` row as a trap beside the claim.
//! 2. `reloadVolatile` forces a real load from freshly-tainted memory, so the
//!    strippers cannot be handed a defined register copy of `N`.
//! 3. ReleaseFast only. `ReleaseSafe` adds overflow checks over secret-derived
//!    data that bury the signal — measured on `hqc`, whose `decaps` goes from
//!    14 contexts to 92 for exactly that reason.
//!
//! ## The propagation witness
//!
//! The unpadded slice is printed as `ctgrind_result`. Its LENGTH is
//! `buf.len - pad_len`, i.e. secret-derived, so the formatting loop's trip
//! count carries the taint and `Writer.zig` flags it. A non-zero witness beside
//! the in-file count is what makes the count mean "this is what the function
//! does" rather than "the taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const block_len = root.block_len;

/// 30 bytes, so PKCS#7 pads to 32 with `N = 2`: two blocks, a pad shorter than
/// a block, and a scan that has real in-pad and out-of-pad positions to tell
/// apart. A pad of exactly `block_len` would make `in_pad` constant.
fn secretPlaintext() [30]u8 {
    var out: [30]u8 = undefined;
    var st = std.crypto.hash.sha2.Sha256.init(.{});
    st.update("ctgrind-aescbc-harness-plaintext-v1");
    var wide: [32]u8 = undefined;
    st.final(&wide);
    @memcpy(&out, wide[0..30]);
    return out;
}

fn reloadVolatile(comptime n: usize, src: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Target = enum { pkcs7, xmlenc };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "pkcs7")) return .pkcs7;
    if (std.mem.eql(u8, s, "xmlenc")) return .xmlenc;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    // Built with the module's OWN padder, and BEFORE any taint: `padPkcs7`'s
    // only error is `BufferTooSmall`, a buffer-sizing fact of this harness and
    // not a secret, so handling it here branches on nothing under test.
    const msg = secretPlaintext();
    var padded: [2 * block_len]u8 = undefined;
    const padded_len = try root.padPkcs7(&msg, &padded);

    if (tainted) std.valgrind.memcheck.makeMemUndefined(padded[0..padded_len]);
    const buf = reloadVolatile(2 * block_len, &padded);

    // ⚠ The `catch` is a branch on a secret-derived error tag, and it is
    // DELIBERATELY here rather than avoided: it is the accept/reject signal the
    // API hands its caller by contract, so a real consumer writes exactly this.
    // Hiding it in the harness would measure a caller nobody writes. It lands
    // wherever the inliner puts it; see this module's rows in
    // `scripts/ctgrind-expected.tsv` for what was measured.
    const n = switch (target) {
        .pkcs7 => root.unpadPkcs7(buf[0..padded_len]),
        .xmlenc => root.unpadXmlEnc(buf[0..padded_len]),
    } catch |err| {
        std.debug.print("rejected: {t}\n", .{err});
        return;
    };

    std.debug.print("ctgrind_result={x}\n", .{buf[0..n]});
}
