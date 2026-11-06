// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the two burned entry points,
//! `parsePrivateKeyPem` and `writePrivateKeyPem` (SPEC § Open; the burn
//! mutants of the 2026-11-06 mutation run are visible only here). Every key
//! shape the burns must cover: the smallest (P-256 SEC1), the deepest DER
//! walk (ML-DSA-87 `both`, the longest PEM), RSA PKCS#1 and PKCS#8.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip).

const std = @import("std");
const kc = @import("root.zig");
const vectors = @import("vectors.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{});

var der_buf: [kc.max_private_der_len]u8 = undefined;
var der_copy: [kc.max_private_der_len]u8 = undefined;
var pem_out: [kc.max_private_pem_len]u8 = undefined;

const probed = [_][]const u8{ "ec_p256-sec1", "ec_p521-pkcs8", "rsa-pkcs1", "rsa-pkcs8", "ml_dsa_87-both" };

fn caseNamed(name: []const u8) ?vectors.Case {
    for (vectors.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    return null;
}

test "STACKPROBE: no key residue after parsePrivateKeyPem / writePrivateKeyPem" {
    try sp.skipUnlessOptimized();
    var seen: usize = 0;
    for (probed) |name| {
        const c = caseNamed(name) orelse continue;
        seen += 1;
        // The key's DER, outside the probe: the needle the dead stack must
        // not hold.
        const block = (try kc.pem.find(c.pem, (std.meta.stringToEnum(kc.Encoding, c.encoding).?).pemLabel())).?;
        const der = try block.decode(&der_copy);
        const secrets = &[_][]const u8{der};

        _ = try P.run("parsePrivateKeyPem", kc.parsePrivateKeyPem, .{ c.pem, &der_buf }, secrets, .{});
        const k = try kc.parsePrivateKeyPem(c.pem, &der_buf);
        _ = try P.run("writePrivateKeyPem", kc.writePrivateKeyPem, .{ &pem_out, k }, secrets, .{});
    }
    try std.testing.expectEqual(probed.len, seen);
}
