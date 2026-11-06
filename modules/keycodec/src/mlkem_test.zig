// SPDX-License-Identifier: MIT

//! keycodec's ML-KEM encodings against the zig-libs `mlkem` module, which
//! has no ASN.1 of its own (its SPEC defers the encodings here): every
//! OpenSSL 3.5.5 ML-KEM key in `vectors.zig` loads into `mlkem` in each of
//! its three forms, gives OpenSSL's public key, and an `mlkem` key written
//! through keycodec is OpenSSL's bytes.

const std = @import("std");
const kc = @import("root.zig");
const vectors = @import("vectors.zig");
const mlkem = @import("mlkem");
const t = std.testing;

fn KemOf(comptime a: kc.Algorithm) type {
    return switch (a) {
        .ml_kem_512 => mlkem.MLKem512,
        .ml_kem_768 => mlkem.MLKem768,
        .ml_kem_1024 => mlkem.MLKem1024,
        else => @compileError("not ML-KEM"),
    };
}

fn checkCase(comptime a: kc.Algorithm, c: anytype) !void {
    const K = KemOf(a);
    var buf: [kc.max_private_der_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    const k = try kc.parsePrivateKeyPem(c.pem, &buf);
    var pub_buf: [kc.max_public_der_len]u8 = undefined;
    const pk = try kc.parsePublicKeyPem(c.spki_pem, &pub_buf);
    try t.expectEqual(a, k.algorithm);
    try t.expectEqual(a, pk.algorithm);
    var out: [kc.max_private_pem_len]u8 = undefined;
    switch (k.pq_form.?) {
        .seed, .both => {
            const kp = K.KeyPair.generateDeterministic(k.secret[0..K.seed_length].*);
            try t.expectEqualSlices(u8, pk.key, &kp.public_key.toBytes());
            if (k.pq_form.? == .both) try t.expectEqualSlices(u8, k.expanded, &kp.secret_key.toBytes());
            // mlkem's own seed, written back through keycodec in the same
            // form, is OpenSSL's text.
            const seed = kp.secret_key.seedBytes().?;
            const expanded = kp.secret_key.toBytes();
            const back: kc.PrivateKey = .{
                .algorithm = a,
                .encoding = .pkcs8,
                .secret = &seed,
                .expanded = if (k.pq_form.? == .both) &expanded else &.{},
                .pq_form = k.pq_form,
            };
            try t.expectEqualStrings(c.pem, try kc.writePrivateKeyPem(&out, back));
            const pub_bytes = kp.public_key.toBytes();
            try t.expectEqualStrings(c.spki_pem, try kc.writePublicKeyPem(&out, .{ .algorithm = a, .key = &pub_bytes }));
        },
        .expanded => {
            // FIPS 203 §7.3 checks on import; the embedded ek is OpenSSL's.
            const sk = try K.SecretKey.fromBytes(k.secret[0..K.SecretKey.encoded_length]);
            try t.expect(sk.seedBytes() == null);
            const bytes = sk.toBytes();
            try t.expectEqualSlices(u8, k.secret, &bytes);
            const ek_at = K.SecretKey.encoded_length - K.PublicKey.encoded_length - 64;
            try t.expectEqualSlices(u8, pk.key, bytes[ek_at..][0..K.PublicKey.encoded_length]);
        },
    }
}

test "every OpenSSL ML-KEM key loads into mlkem and writes back as OpenSSL's bytes" {
    var seen: usize = 0;
    for (vectors.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.name});
        inline for (.{ kc.Algorithm.ml_kem_512, .ml_kem_768, .ml_kem_1024 }) |a| {
            if (std.mem.eql(u8, c.algorithm, @tagName(a))) {
                try checkCase(a, c);
                seen += 1;
            }
        }
    }
    try t.expect(seen >= 3);
}
