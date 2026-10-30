// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GP). Each test names the finding it kills.

const std = @import("std");
const ms = @import("root.zig");

fn scryptRaw(ops: u64, mem: u64) ms.RawSecretKey {
    return .{
        .sig_alg = ms.sig_alg_legacy,
        .kdf_alg = ms.kdf_alg_scrypt,
        .chk_alg = ms.chk_alg_blake2b,
        .salt = @splat(0),
        .ops_limit = ops,
        .mem_limit = mem,
        .key_number = @splat(0),
        .secret_key = @splat(0),
        .checksum = @splat(0),
    };
}

var sink: ms.KeyPair = undefined;

test "openSecretKey: ops_limit / mem_limit above the caps are errors before any KDF work (sweep MS-1)" {
    const gpa = std.testing.allocator;
    const lim: ms.SecretKeyLimits = .{};
    try std.testing.expectEqual(ms.ops_limit_sensitive, lim.max_ops_limit);
    try std.testing.expectEqual(@as(u64, ms.mem_limit_sensitive), lim.max_mem_limit);

    // Hostile values: would be hours of CPU / an enormous allocation.
    var raw = scryptRaw(std.math.maxInt(u64), ms.mem_limit_sensitive);
    try std.testing.expectError(error.OpsLimitTooLarge, ms.openSecretKey(gpa, &sink, &raw, "pw"));
    raw = scryptRaw(ms.ops_limit_sensitive + 1, ms.mem_limit_sensitive);
    try std.testing.expectError(error.OpsLimitTooLarge, ms.openSecretKey(gpa, &sink, &raw, "pw"));
    raw = scryptRaw(ms.ops_limit_sensitive, std.math.maxInt(u64));
    try std.testing.expectError(error.MemLimitTooLarge, ms.openSecretKey(gpa, &sink, &raw, "pw"));
    raw = scryptRaw(ms.ops_limit_sensitive, ms.mem_limit_sensitive + 1);
    try std.testing.expectError(error.MemLimitTooLarge, ms.openSecretKey(gpa, &sink, &raw, "pw"));
    // The gate comes before the password check.
    try std.testing.expectError(error.MemLimitTooLarge, ms.openSecretKey(gpa, &sink, &raw, null));

    // Exactly at the caps the file passes the gate: with no password it
    // stops at PasswordRequired, without running scrypt.
    raw = scryptRaw(ms.ops_limit_sensitive, ms.mem_limit_sensitive);
    try std.testing.expectError(error.PasswordRequired, ms.openSecretKey(gpa, &sink, &raw, null));

    // Caps are adjustable.
    raw = scryptRaw(ms.ops_limit_sensitive + 1, ms.mem_limit_sensitive);
    try std.testing.expectError(error.PasswordRequired, ms.openSecretKeyLimited(gpa, &sink, &raw, null, .{ .max_ops_limit = ms.ops_limit_sensitive + 1 }));
}

test "sealSecretKey: mem_limit below the scrypt floor is WeakParameters, not a panic (sweep MS-2)" {
    const gpa = std.testing.allocator;
    var kp: ms.KeyPair = undefined;
    ms.KeyPair.generate(&kp, std.testing.io);
    defer kp.wipe();
    var out: ms.RawSecretKey = undefined;
    const salt: [ms.salt_length]u8 = @splat(7);
    for ([_]usize{ 0, 1, 1023 }) |mem| {
        try std.testing.expectError(error.WeakParameters, ms.sealSecretKey(gpa, &out, &kp, "pw", salt, 32768, mem));
    }
}

test "sealSecretKey refuses costs openSecretKey would refuse (sweep REV-MS-2)" {
    const gpa = std.testing.allocator;
    var kp: ms.KeyPair = undefined;
    ms.KeyPair.generate(&kp, std.testing.io);
    defer kp.wipe();
    var out: ms.RawSecretKey = undefined;
    const salt: [ms.salt_length]u8 = @splat(7);
    try std.testing.expectError(error.OpsLimitTooLarge, ms.sealSecretKey(gpa, &out, &kp, "pw", salt, ms.ops_limit_sensitive + 1, 1 << 16));
    try std.testing.expectError(error.OpsLimitTooLarge, ms.sealSecretKey(gpa, &out, &kp, "pw", salt, 1 << 40, 1 << 16));
    try std.testing.expectError(error.MemLimitTooLarge, ms.sealSecretKey(gpa, &out, &kp, "pw", salt, 32768, ms.mem_limit_sensitive + 1));
    try std.testing.expectError(error.MemLimitTooLarge, ms.sealSecretKey(gpa, &out, &kp, "pw", salt, 32768, std.math.maxInt(usize)));
}

test "openSecretKey: a public half that is not the seed's is NonCanonical for a plain key (sweep REV-MS-1)" {
    const gpa = std.testing.allocator;
    var kp: ms.KeyPair = undefined;
    ms.KeyPair.generate(&kp, std.testing.io);
    defer kp.wipe();
    var raw: ms.RawSecretKey = undefined;
    kp.toRawSecretKeyPlain(&raw);
    var opened: ms.KeyPair = undefined;
    try ms.openSecretKey(gpa, &opened, &raw, null);
    opened.wipe();
    for ([_]usize{ 32, 40, 63 }) |i| {
        var bad = raw;
        bad.secret_key[i] ^= 0x01;
        try std.testing.expectError(error.NonCanonical, ms.openSecretKey(gpa, &opened, &bad, null));
    }
}

test "sealSecretKey: costs exactly at the caps pass the gate, the smallest working mem_limit round-trips (sweep audit GP-MS-1)" {
    var kp: ms.KeyPair = undefined;
    ms.KeyPair.generate(&kp, std.testing.io);
    defer kp.wipe();
    var out: ms.RawSecretKey = undefined;
    const salt: [ms.salt_length]u8 = @splat(7);
    // At the cap the call must get past the gate and reach scrypt's first
    // allocation, which this allocator refuses (no gigabyte of memory is touched).
    var fa: std.testing.FailingAllocator = .init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, ms.sealSecretKey(fa.allocator(), &out, &kp, "pw", salt, ms.ops_limit_sensitive, 1 << 16));
    var fb: std.testing.FailingAllocator = .init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, ms.sealSecretKey(fb.allocator(), &out, &kp, "pw", salt, 32768, ms.mem_limit_sensitive));
    // mem_limit 1024..2047 reaches scrypt with ln = 0, which std refuses as WeakParameters
    // (the same error the floor check gives); 2048 is the smallest cost that works, and
    // the key opens again.
    try std.testing.expectError(error.WeakParameters, ms.sealSecretKey(std.testing.allocator, &out, &kp, "pw", salt, 32768, 1024));
    try ms.sealSecretKey(std.testing.allocator, &out, &kp, "pw", salt, 32768, 2048);
    var opened: ms.KeyPair = undefined;
    try ms.openSecretKey(std.testing.allocator, &opened, &out, "pw");
    defer opened.wipe();
    try std.testing.expectEqualSlices(u8, &kp.ed25519.public_key.bytes, &opened.ed25519.public_key.bytes);
}
