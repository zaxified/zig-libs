// SPDX-License-Identifier: MIT

//! ctgrind harness for `mlkem` (added 2026-11-01). Run it through
//! `scripts/checks/ctgrind.sh mlkem`, which builds every mode / `-fvalgrind`
//! switch / taint combination and prints the control table; not wired into
//! `zig build test` (memcheck's context count is valgrind's own output).
//!
//! Usage: ctgrind-mlkem <target> <yes|no>
//!   targets: keygen{512,768,1024} | encaps{512,768,1024} | decaps{512,768,1024} |
//!             fromBytes{512,768,1024}
//!
//! ## What is tainted (marked undefined), per target
//!
//!   keygenN   the whole 64-byte seed d ‖ z. Everything derived from d (rho,
//!             sigma, s, e, t) and z is secret; the public ek is a function of
//!             them and is printed as the propagation witness.
//!   encapsN   the 32-byte message m. The ciphertext and the shared secret are
//!             functions of it (the ciphertext is public on the wire, but only
//!             after the KEM: a branch on m must not exist).
//!   decapsN   the secret polynomial vector `sk.sk` and the implicit-rejection
//!             value `z` of the decapsulation key, AND the ciphertext. The
//!             ciphertext is attacker-chosen, so a timing difference that
//!             depends on it would be an oracle; tainting it also drives the
//!             re-encryption comparison (the Fujisaki-Okamoto select) as a
//!             secret-dependent value. `pk` and `H(pk)` stay clean: they are
//!             public.
//!   fromBytesN  `SecretKey.fromBytes` of a valid dk: the secret part only (the
//!             encoded s vector, the first 384 * k bytes, and z) is tainted. The
//!             embedded ek and H(ek) are public, so the §7.3 modulus check and
//!             the hash compare on them are not counted. `fromNttBytes`'s
//!             range check over the secret s must stay branch-free.
//!
//! ## Why the three traps do not bite
//!
//! 1. `-fvalgrind`: `ctgrind.sh` builds the no-`-fvalgrind` control row.
//! 2. A defined copy kept in a register: the tainted bytes are reloaded through
//!    a `volatile` pointer immediately before the call under test.
//! 3. A zero is only evidence if the taint arrived: every target prints its
//!    result (hex formatting is not constant-time), so the propagation witness
//!    is non-zero by construction.

const std = @import("std");
const builtin = @import("builtin");
const mlkem = @import("root.zig");

const Target = enum {
    keygen512,
    keygen768,
    keygen1024,
    encaps512,
    encaps768,
    encaps1024,
    decaps512,
    decaps768,
    decaps1024,
    fromBytes512,
    fromBytes768,
    fromBytes1024,
};
const Taint = enum { yes, no };

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taintBytes(taint: bool, bytes: []u8) void {
    if (taint) std.valgrind.memcheck.makeMemUndefined(bytes);
}

/// `volatile` reload of a whole value: forces one real load from the memory
/// that was just marked, so the optimizer cannot keep a defined copy.
fn reload(comptime T: type, s: *const T) T {
    var out: T = undefined;
    for (std.mem.asBytes(&out), std.mem.asBytes(s)) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

/// Public, deterministic bytes: a counter-mode SHAKE128 stream under `label`.
fn publicBytes(comptime n: usize, label: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var x = std.crypto.hash.sha3.Shake128.init(.{});
    x.update(label);
    x.squeeze(&out);
    return out;
}

fn keygen(comptime K: type, taint: bool, label: []const u8) void {
    var seed = publicBytes(K.seed_length, label);
    taintBytes(taint, &seed);
    const s = reload([K.seed_length]u8, &seed);
    const kp = K.KeyPair.generateDeterministic(s);
    // Propagation witness: hex formatting is not constant-time.
    const ek = kp.public_key.toBytes();
    std.debug.print("ek={x}\n", .{ek[0..32]});
}

fn encaps(comptime K: type, taint: bool, label: []const u8) void {
    const kp = K.KeyPair.generateDeterministic(publicBytes(K.seed_length, label));
    var m = publicBytes(32, label);
    taintBytes(taint, &m);
    const mm = reload([32]u8, &m);
    const e = kp.public_key.encapsDeterministic(&mm);
    std.debug.print("ct={x}\nss={x}\n", .{ e.ciphertext[0..32], e.shared_secret });
}

fn decaps(comptime K: type, taint: bool, label: []const u8) void {
    const kp = K.KeyPair.generateDeterministic(publicBytes(K.seed_length, label));
    const e = kp.public_key.encapsDeterministic(&publicBytes(32, label));
    var sk = kp.secret_key;
    var ct = e.ciphertext;
    taintBytes(taint, std.mem.asBytes(&sk.sk));
    taintBytes(taint, &sk.z);
    taintBytes(taint, &ct);
    const skr = reload(K.SecretKey, &sk);
    const ctr = reload([K.ciphertext_length]u8, &ct);
    const ss = skr.decaps(&ctr);
    std.debug.print("ss={x}\n", .{ss});
}

fn fromBytes(comptime K: type, taint: bool, label: []const u8) void {
    const kp = K.KeyPair.generateDeterministic(publicBytes(K.seed_length, label));
    var dk = kp.secret_key.toBytes();
    // s (384 bytes per vector element) leads the encoding; z is the last 32.
    const s_len = dk.len - K.PublicKey.encoded_length - 64;
    taintBytes(taint, dk[0..s_len]);
    taintBytes(taint, dk[dk.len - 32 ..]);
    const dr = reload([K.SecretKey.encoded_length]u8, &dk);
    const sk = K.SecretKey.fromBytes(&dr) catch {
        std.debug.print("fromBytes failed\n", .{});
        return;
    };
    // Propagation witness: the imported secret's z and a decaps result.
    std.debug.print("z={x}\n", .{sk.z});
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse return error.UnknownTarget;
    const taint = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    switch (target) {
        .keygen512 => keygen(mlkem.MLKem512, taint, "ctgrind-mlkem-512"),
        .keygen768 => keygen(mlkem.MLKem768, taint, "ctgrind-mlkem-768"),
        .keygen1024 => keygen(mlkem.MLKem1024, taint, "ctgrind-mlkem-1024"),
        .encaps512 => encaps(mlkem.MLKem512, taint, "ctgrind-mlkem-512"),
        .encaps768 => encaps(mlkem.MLKem768, taint, "ctgrind-mlkem-768"),
        .encaps1024 => encaps(mlkem.MLKem1024, taint, "ctgrind-mlkem-1024"),
        .decaps512 => decaps(mlkem.MLKem512, taint, "ctgrind-mlkem-512"),
        .decaps768 => decaps(mlkem.MLKem768, taint, "ctgrind-mlkem-768"),
        .decaps1024 => decaps(mlkem.MLKem1024, taint, "ctgrind-mlkem-1024"),
        .fromBytes512 => fromBytes(mlkem.MLKem512, taint, "ctgrind-mlkem-512"),
        .fromBytes768 => fromBytes(mlkem.MLKem768, taint, "ctgrind-mlkem-768"),
        .fromBytes1024 => fromBytes(mlkem.MLKem1024, taint, "ctgrind-mlkem-1024"),
    }
}
