// SPDX-License-Identifier: MIT

//! ctgrind_harness — measures the four SECRET-KEY text codecs, which are the
//! only place this module touches a secret with code of its own choosing.
//! Run it through `../../../scripts/checks/ctgrind.sh sealedbox`.
//!
//! ## Why this module has a harness at all
//!
//! The 2026-09-09 ctgrind coverage pass filed `sealedbox` as a "thin wrapper
//! over std" — hand everything to `std.crypto.nacl.SealedBox`, measure nothing
//! of our own. For `seal`/`open` that is exactly right and they are NOT
//! targets here. But the module's own audit record (A1 `sealedbox.md`, M1)
//! said the opposite about a different part of the surface, and the two were
//! never reconciled:
//!
//!   "sealedbox is not in the ctgrind gate, and when the probe is built, the
//!    SECRET KEY CODECS light up immediately (43/47/8/6 contexts with a frame
//!    in root.zig)"
//!
//! Both can be true, because they are about different functions — and that is
//! the same misfiling `aescbc` turned out to have in the very same pass. The
//! subject here is real: `encodeSecretKeyBase64`, `parseSecretKeyBase64`,
//! `encodeSecretKeyHex` and `parseSecretKeyHex` all handle 32 bytes that grant
//! full decryption capability, and they hand them to `std.base64` and
//! `std.fmt` — neither of which claims to be constant-time.
//!
//! ⚠ Reading the source settles nothing, in EITHER direction. That is the
//! campaign's main result: `std.mem.allEqual`'s naive early-exit loop compiled
//! to a single data-independent `vptest` (twice, `sphinx` and `ctap2pin`),
//! while `bfv`'s correctly-written branch-free `csub` became a real `cmp`/`jb`
//! at one call site out of ninety-nine. These rows exist so the answer comes
//! from the binary.
//!
//! ## What is tainted
//!
//! The 32-byte secret scalar, in full, before every call. For the two parsers
//! the tainted thing is the ENCODED TEXT — which is what a parser actually
//! gets, and it is secret-derived byte for byte, so tainting the raw key and
//! encoding it afterwards would measure a kinder input than the function sees.
//!
//! Public-key codecs are deliberately absent: identical code, public input,
//! nothing to claim.
//!
//! ## What these rows measured, and what they measure now
//!
//! ⛔⛔ **The first run found the leak these rows were built to look for.**
//! 8 / 7 / 43 / 47 in-file contexts, 95 of them reported on a LOAD rather than
//! a conditional jump — and the disassembly showed
//! `movzbl 0x…(%rax),%eax` over a secret character (std's 256-byte
//! `char_to_index`) and `shr/and/movzbl 0x…(%r8)` over a secret 6-bit group
//! (std's 64-byte alphabet). Secret-indexed table lookups, the cache-timing
//! class of T-table AES.
//!
//! ✅ Fixed the same day: the module carries its own table-free codecs for
//! secret material (`root.zig`, `ctB64Char`/`ctB64Index`/`ctHexChar`/
//! `ctHexNibble`). **Encoders are now exact 0; parsers are exact 1.**
//!
//! ⚠ **That 1 is the right answer and a 0 would be wrong.** It is
//! `if (invalid != 0)` — the accept/reject the parser returns to its caller by
//! contract, the same shape `aescbc`'s rows carry. What the constant-time claim
//! forbids is an early exit that reveals WHICH character was bad; the decode
//! loops contribute 0, so there is none. Read the KIND of context, not only the
//! number: there is no LOAD-kind context in-file any more.
//!
//! ⭐⭐ The `out_sha` column did not move by a bit across the fix — the branch
//! changed, the result did not.
//!
//! ## The traps
//!
//! 1. Without `-fvalgrind` every row reads 0 regardless; the driver builds both
//!    ways and prints the no-`-fvalgrind` row as a trap beside the claim.
//! 2. `reloadVolatile` forces a real load from freshly-tainted memory, so a
//!    codec cannot be handed a defined register copy of the key.
//! 3. ReleaseFast only. `ReleaseSafe` adds overflow checks over secret-derived
//!    data that bury the signal — measured on `hqc`, whose `decaps` goes from
//!    14 contexts to 92 for exactly that reason.
//!
//! ## The propagation witness
//!
//! Every target prints its result as `ctgrind_result`, always as `{x}` over the
//! RESULT BYTES. The formatter walks secret-derived bytes, so `Writer.zig`
//! flags it and a non-zero witness beside the in-file count is what makes the
//! count mean "this is what the function does" rather than "the taint never
//! arrived" (`ct25519` C1).
//!
//! ⛔ Two traps found by pinning these rows, both worth keeping:
//!  * `{s}` on the base64 text is NOT pinnable — `out_digest` reads
//!    `name=<8+ hex>`, and base64 is not hex, so the row silently pinned
//!    `NO-OUTPUT`. Hex out, always.
//!  * `hexenc`, `hexdec` and `b64dec` would otherwise share ONE digest, because
//!    printing the key as `{x}` and printing `encodeSecretKeyHex(key)` produce
//!    the SAME 64 characters. Printing the encoders' own output bytes keeps the
//!    four rows distinguishable — a pin three rows share cannot tell them
//!    apart, and would pass for the wrong one.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const secret_length = root.secret_length;

/// A fixed 32-byte stand-in for a secret X25519 scalar. Derived by hashing so
/// it is not a comptime-foldable constant: tainting needs real runtime memory.
fn secretKeyBytes() [secret_length]u8 {
    var out: [secret_length]u8 = undefined;
    var st = std.crypto.hash.sha2.Sha256.init(.{});
    st.update("ctgrind-sealedbox-harness-secret-v1");
    st.final(&out);
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

const Target = enum { hexenc, hexdec, b64enc, b64dec };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "hexenc")) return .hexenc;
    if (std.mem.eql(u8, s, "hexdec")) return .hexdec;
    if (std.mem.eql(u8, s, "b64enc")) return .b64enc;
    if (std.mem.eql(u8, s, "b64dec")) return .b64dec;
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

    switch (target) {
        .hexenc => {
            var sk = secretKeyBytes();
            if (tainted) std.valgrind.memcheck.makeMemUndefined(&sk);
            const key = reloadVolatile(secret_length, &sk);
            const text = root.encodeSecretKeyHex(key);
            std.debug.print("ctgrind_result={x}\n", .{text});
        },
        .b64enc => {
            var sk = secretKeyBytes();
            if (tainted) std.valgrind.memcheck.makeMemUndefined(&sk);
            const key = reloadVolatile(secret_length, &sk);
            var text: [root.base64_sk_len]u8 = undefined;
            root.encodeSecretKeyBase64(&text, &key);
            std.debug.print("ctgrind_result={x}\n", .{text});
        },
        // ⚠ For the two parsers the encode runs BEFORE the taint: the subject
        // is the parse, and an encode inside the tainted region would fold its
        // own contexts into this row's count.
        .hexdec => {
            var text = root.encodeSecretKeyHex(secretKeyBytes());
            if (tainted) std.valgrind.memcheck.makeMemUndefined(&text);
            const input = reloadVolatile(root.hex_sk_len, &text);
            var key: [secret_length]u8 = undefined;
            try root.parseSecretKeyHex(&key, &input);
            std.debug.print("ctgrind_result={x}\n", .{key});
        },
        .b64dec => {
            var text: [root.base64_sk_len]u8 = undefined;
            root.encodeSecretKeyBase64(&text, &secretKeyBytes());
            if (tainted) std.valgrind.memcheck.makeMemUndefined(&text);
            const input = reloadVolatile(root.base64_sk_len, &text);
            var key: [secret_length]u8 = undefined;
            try root.parseSecretKeyBase64(&key, &input);
            std.debug.print("ctgrind_result={x}\n", .{key});
        },
    }
}
