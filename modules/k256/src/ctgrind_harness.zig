// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Constant-time
//! contract" section and for the per-function claims in `field.zig` /
//! `group.zig` / `fast_core.zig`, as an actual committed program. Run it
//! through `../../../scripts/ctgrind.sh k256`.
//!
//! Until this file existed, every constant-time statement in this module was
//! backed by disassembly read once by hand ("Disasm confirms: zero indirect
//! jumps", "both reproduced by disassembly") with nothing in the repo that
//! could re-take the reading. `scripts/ctgrind-expected.tsv` had no row for
//! `k256` and `scripts/ctgrind.sh` had no target for it. That is what this
//! closes.
//!
//! NOT wired into `zig build test-k256` — memcheck's context count is
//! valgrind's output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## The four targets, and which claim each one pins
//!
//! * `field` — `Fe.cMov`, `Fe.add`, `Fe.sub`, `Fe.mul`, `Fe.sq`, `Fe.invert`,
//!   driven from a tainted element AND (for `cMov`) a tainted select bit. This
//!   is the target for `field.zig:71` ("Constant-time: no branch on the
//!   value"), `:195` ("Constant-time conditional move"), `:212`/`:223`
//!   (`add`/`sub`), `:274`/`:290` (`powConst`/`invert` constant-time in the
//!   SECRET element) and, because `field_asm_active` is true on amd64, for
//!   `fast_core.zig`'s "zero branches" asm contract as well: `mul`/`sq`
//!   dispatch straight into `fieldMul`/`fieldSq`. The tainted `cMov` bit is
//!   the part that matters most — it is the exact value whose laundering
//!   through `blackBox` the doc comment says the "constant-time" scalar-mul
//!   paths depend on.
//! * `mul` — `Secp256k1.mul`, the CONSTANT-TIME variable-base fixed
//!   256-iteration double-and-add (`group.zig:262`), with the scalar tainted.
//! * `comb` — `Secp256k1.combMulBase`, the fixed-base comb that the signing
//!   path actually calls (`group.zig:281`), with the scalar tainted. Its
//!   masked linear-scan table gather is the powMont-gather leak class this
//!   repo tracks as montint `b199192`; a secret-indexed load would show up
//!   here as memcheck's "Use of uninitialised value of size 8" on the address.
//! * `sign` — `sign.bip340Sign` end to end from a tainted 32-byte secret key:
//!   the SHIPPED secret path, two `combMulBase` calls plus the scalar
//!   arithmetic and the two affine conversions around them.
//!
//! ## What the counts mean
//!
//! `mul`, `comb` and `sign` are all EXPECTED to report a small non-zero
//! in-file count, and the point of the measurement is *which* lines. Every one
//! of them is a `rejectIdentity()` on a value derived from the secret scalar:
//!
//!   * `group.zig:75` — `rejectIdentity`'s own `if (is_identity != 0)`, reached
//!     from `mul`'s trailing `try q.rejectIdentity()` and from
//!     `combMulBaseWithTable`'s. The branch is on "did the whole scalar
//!     multiplication land on the neutral element", which for `mul` means
//!     `s ≡ 0 (mod n)` for a fixed public base and for `combMulBase` means
//!     exactly `s ≡ 0 (mod n)`. It is the same one-bit validation
//!     `std.crypto.ecc.Secp256k1.mul` performs (k256's API is a drop-in for
//!     it), and it is what makes `error.IdentityElement` a reachable outcome
//!     at all. It is NOT a per-bit or per-window branch: it happens once,
//!     after the ladder, and the count does not scale with the scalar.
//!
//! `sign` additionally reaches std's scalar-field canonicality check on the
//! caller-supplied secret key (`Scalar.fromBytes(secret_key)`, which
//! `scalar.zig` re-exports from std verbatim); `--pattern` is how that
//! attribution gets re-checked instead of believed.
//!
//! `field`'s zero is the strong claim, and it is only readable next to the
//! others: `mul`/`comb`/`sign` being non-zero proves the taint propagates
//! through this module's arithmetic at all, so `field`'s zero means "no branch
//! found", not "the harness is blind". Within `field`, `Fe.invert` runs
//! `powConst`, whose `while (ee != 0)` / `if (ee & 1 == 1)` branch is on the
//! PUBLIC constant exponent `p − 2` — untainted, and therefore invisible here,
//! which is precisely the claim `field.zig:274` makes.
//!
//! ## What this harness does NOT pin (deliberately)
//!
//! * `mulPublic` / `mulPublicGlv` / `mulDoubleBasePublic` / `mulPublicDoubleAdd`
//!   and everything under them (`wnafDigits`, `splitScalar`, `oddMultiples`)
//!   are documented VARIABLE-TIME for PUBLIC scalars. Tainting a scalar into
//!   them would light up memcheck by design, which measures nothing about a
//!   claim. There is no constant-time claim there to pin.
//! * `Fe.sqrt`'s `if (x.sq().equivalent(a))` and `Fe.fromBytes`'s
//!   `if (v >= field_order)` are validations that branch on their input by
//!   contract (they return an error set). They are exercised from `sign` on
//!   PUBLIC values only.
//!
//! ## The traps
//!
//! 1. Without `-fvalgrind`, `std.valgrind.doClientRequest` returns early
//!    (`builtin.valgrind_support` is off outside Debug) and every row reads 0
//!    regardless. The driver builds both ways and prints it as a row.
//! 2. `reloadVolatile` forces a real load from freshly-tainted memory so the
//!    optimizer cannot feed the code under test a defined register copy.
//!    Defensive, not demonstrated.
//! 3. ReleaseFast only. `Debug`/`ReleaseSafe` add integer-overflow checks
//!    inside the `u256`/`u512` limb arithmetic of `field.zig`, which are
//!    branches on tainted values and bury the signal — the same reason every
//!    module here except `chachapoly` states its claim at ReleaseFast.
//!
//! ## The propagation witness
//!
//! Results are formatted with `std.debug.print`, which is not constant-time, so
//! a tainted byte reaching the formatter always produces contexts of its own.
//! A non-zero total next to a small, itemised in-file count is what makes the
//! itemisation mean something.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const Fe = root.Fe;
const Secp256k1 = root.Secp256k1;
const sign = root.sign;

/// Deterministic secret material. Computed at runtime (not folded at comptime)
/// so tainting it marks memory the code under test actually reads.
fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

/// A scalar comfortably inside `[1, n)`: clearing the top byte keeps the value
/// below the group order, so `mul`/`combMulBase` get a realistic input rather
/// than one that happens to exercise the reduction edge.
fn secretScalar(comptime domain: []const u8) [32]u8 {
    var s = secretBytes(32, domain);
    s[0] = 0;
    if (s[31] == 0) s[31] = 1;
    return s;
}

const Target = enum { field, mul, comb, sign };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "field")) return .field;
    if (std.mem.eql(u8, s, "mul")) return .mul;
    if (std.mem.eql(u8, s, "comb")) return .comb;
    if (std.mem.eql(u8, s, "sign")) return .sign;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taintIf(cond: bool, bytes: []u8) void {
    if (cond) std.valgrind.memcheck.makeMemUndefined(bytes);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={} field_asm_active={}\n", .{
        builtin.valgrind_support,
        root.field_asm_active,
    });

    switch (target) {
        .field => {
            // A tainted field element, loaded through `Fe.fromBytes`'s sibling
            // path: `fromBytes` itself validates `v < p` (a branch on its
            // input by contract), so the element is built from limbs instead
            // and only the ARITHMETIC is measured. The top limb is masked to
            // keep the value canonical without inspecting it.
            var raw = secretBytes(32, "ctgrind-k256-harness-field-element-v1");
            raw[31] = 0; // top little-endian byte: value < 2^248 < p, no comparison needed
            taintIf(tainted, &raw);
            const r = reloadVolatile(32, &raw);
            const a = Fe{ .limbs = .{
                std.mem.readInt(u64, r[0..8], .little),
                std.mem.readInt(u64, r[8..16], .little),
                std.mem.readInt(u64, r[16..24], .little),
                std.mem.readInt(u64, r[24..32], .little),
            } };

            // A tainted SELECT BIT for `cMov` — the value `field.zig:195` says
            // must not become a `Jcc`. Derived from a tainted byte so memcheck
            // tracks it as undefined all the way into the mask.
            var bitbuf = secretBytes(1, "ctgrind-k256-harness-cmov-bit-v1");
            taintIf(tainted, &bitbuf);
            const bitr = reloadVolatile(1, &bitbuf);
            const bit: u1 = @truncate(bitr[0]);

            var m = Fe.one;
            m.cMov(a, bit);

            const s = a.add(m).sub(Fe.one).mul(a).sq();
            const inv = s.invert();

            std.debug.print("cmov={x}\n", .{m.toBytes(.big)});
            std.debug.print("chain={x}\n", .{s.toBytes(.big)});
            std.debug.print("inv={x}\n", .{inv.toBytes(.big)});
        },
        .mul => {
            var k = secretScalar("ctgrind-k256-harness-ladder-scalar-v1");
            taintIf(tainted, &k);
            const s = reloadVolatile(32, &k);

            const q = try Secp256k1.mul(Secp256k1.basePoint, s, .big);

            // Raw projective coordinates through `Fe.toBytes` (a branch-free
            // write of the limbs), NOT `affineCoordinates`: that runs
            // `Fe.invert`, which the `field` target measures on its own.
            std.debug.print("x={x}\n", .{q.x.toBytes(.big)});
            std.debug.print("y={x}\n", .{q.y.toBytes(.big)});
            std.debug.print("z={x}\n", .{q.z.toBytes(.big)});
        },
        .comb => {
            var k = secretScalar("ctgrind-k256-harness-comb-scalar-v1");
            taintIf(tainted, &k);
            const s = reloadVolatile(32, &k);

            const q = try Secp256k1.combMulBase(s, .big);

            std.debug.print("x={x}\n", .{q.x.toBytes(.big)});
            std.debug.print("y={x}\n", .{q.y.toBytes(.big)});
            std.debug.print("z={x}\n", .{q.z.toBytes(.big)});
        },
        .sign => {
            var sk = secretScalar("ctgrind-k256-harness-bip340-secret-key-v1");
            taintIf(tainted, &sk);
            const secret_key = reloadVolatile(32, &sk);

            // Message and auxiliary randomness are PUBLIC by BIP340 (the aux
            // is hashed into the nonce but is not a secret the scheme
            // protects), so they are never tainted and a branch on them
            // cannot be mistaken for a secret-dependent one.
            const msg = "ctgrind harness message";
            const aux_rand = secretBytes(32, "ctgrind-k256-harness-aux-rand-v1");

            const sig = try sign.bip340Sign(secret_key, msg, aux_rand);
            std.debug.print("sig={x}\n", .{sig});
        },
    }
}
