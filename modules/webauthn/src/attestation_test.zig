// SPDX-License-Identifier: MIT
//! attestation_test — `verifyAttestation` against the real W3C §16 vectors
//! (external, byte-exact anchor covering `none`, `packed` self-attestation,
//! `packed` x5c/basic attestation for all three mandated algorithms, and
//! `fido-u2f`), plus adversarial reject-teeth and the `tpm`/`android-key`
//! DEFER-as-unsupported structural check.

const std = @import("std");
const testing = std.testing;
const webauthn = @import("root.zig");
const cbor = @import("cbor");
const vectors = @import("vectors.zig");

fn clientDataHash(client_data_json: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(client_data_json, &h, .{});
    return h;
}

/// Generic extraction of the raw `authData` bytes out of a real
/// `attestationObject` (for hand-building a synthetic attestationObject
/// with a bogus `fmt`/`attStmt` around a REAL authData, for the reject
/// tests below) -- decodes via `cbor.decode` rather than guessing a byte
/// offset, so it stays correct regardless of a given vector's credential
/// ID length / key size.
fn extractAuthDataRaw(a: std.mem.Allocator, attestation_object: []const u8) ![]const u8 {
    const decoded = try cbor.decode(a, attestation_object, .{});
    const entries = decoded.map;
    for (entries) |e| {
        switch (e.key) {
            .text => |t| if (std.mem.eql(u8, t, "authData")) return e.value.bytes,
            else => {},
        }
    }
    return error.MissingField;
}

// ── real-vector positive anchors ────────────────────────────────────────────

test "verifyAttestation: real W3C §16.2 vector (fmt=none)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const hash = clientDataHash(&v.registration_client_data_json);

    const result = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.none, result.attestation_type);
    try testing.expectEqualStrings("none", result.format);
    try testing.expectEqualSlices(u8, &v.credential_id, result.credential_id);
}

test "verifyAttestation: real W3C §16.3 vector (fmt=packed, self attestation)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_self_es256;
    const hash = clientDataHash(&v.registration_client_data_json);

    const result = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.self_attestation, result.attestation_type);
    try testing.expectEqualSlices(u8, &v.credential_id, result.credential_id);
}

test "verifyAttestation: real W3C §16.7 vector (fmt=packed, x5c/basic, ES256)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_es256_full;
    const hash = clientDataHash(&v.registration_client_data_json);
    const result = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.basic, result.attestation_type);
    try testing.expectEqualSlices(u8, &v.credential_id, result.credential_id);
    try testing.expect(result.credential_public_key == .ec2);
}

test "verifyAttestation: real W3C §16.10 vector (fmt=packed, x5c/basic, RS256 credential)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_rs256;
    const hash = clientDataHash(&v.registration_client_data_json);

    const result = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.basic, result.attestation_type);
    try testing.expectEqualSlices(u8, &v.credential_id, result.credential_id);
    // The attestation statement itself is signed by the CA's EC key (per
    // the spec preamble, all examples share one attestation CA), but the
    // extracted CREDENTIAL key must be the RSA key from authData.
    try testing.expect(result.credential_public_key == .rsa);
}

test "verifyAttestation: real W3C §16.11 vector (fmt=packed, x5c/basic, EdDSA credential)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_eddsa;
    const hash = clientDataHash(&v.registration_client_data_json);

    const result = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.basic, result.attestation_type);
    try testing.expect(result.credential_public_key == .okp);
}

test "verifyAttestation: real W3C §16.16 vector (fmt=fido-u2f)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.fido_u2f_es256;
    const hash = clientDataHash(&v.registration_client_data_json);

    const result = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.basic, result.attestation_type);
    try testing.expectEqualSlices(u8, &v.credential_id, result.credential_id);
    try testing.expect(result.credential_public_key == .ec2);
}

// ── deferred formats: structurally recognized and rejected ─────────────────

test "verifyAttestation: fmt=tpm -> error.UnsupportedFormat (deferred, not half-verified)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // clientDataHash content is irrelevant here -- fmt dispatch happens
    // before any signature is touched.
    const hash: [32]u8 = @splat(0);
    try testing.expectError(error.UnsupportedFormat, webauthn.verifyAttestation(a, &vectors.tpm_es256_attestation_object, hash));
}

test "verifyAttestation: fmt=android-key -> error.UnsupportedFormat (deferred, not half-verified)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const hash: [32]u8 = @splat(0);
    try testing.expectError(error.UnsupportedFormat, webauthn.verifyAttestation(a, &vectors.android_key_es256_attestation_object, hash));
}

// ── adversarial reject-teeth ────────────────────────────────────────────────

test "reject: wrong clientDataHash (packed x5c) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_es256_full;
    const wrong_hash: [32]u8 = @splat(0xAA);

    try testing.expectError(error.BadSignature, webauthn.verifyAttestation(a, &v.attestation_object, wrong_hash));
}

test "reject: wrong clientDataHash (fido-u2f) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.fido_u2f_es256;
    const wrong_hash: [32]u8 = @splat(0xAA);

    try testing.expectError(error.BadSignature, webauthn.verifyAttestation(a, &v.attestation_object, wrong_hash));
}

test "reject: wrong clientDataHash (packed x5c, RS256 credential) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_rs256;
    const wrong_hash: [32]u8 = @splat(0xAA);

    try testing.expectError(error.BadSignature, webauthn.verifyAttestation(a, &v.attestation_object, wrong_hash));
}

test "reject: tampered attStmt.sig byte (packed x5c) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_es256_full;
    const hash = clientDataHash(&v.registration_client_data_json);

    var tampered = v.attestation_object;
    // The DER ECDSA signature bytes start right after the CBOR "sig" key +
    // length header, well before the x5c certificate -- flip a byte deep
    // inside that region (byte 40, comfortably inside attStmt.sig).
    tampered[40] ^= 0xff;
    const err = webauthn.verifyAttestation(a, &tampered, hash);
    try testing.expect(err == error.BadSignature or err == error.InvalidSignature);
}

test "reject: tampered attStmt.sig byte (fido-u2f) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.fido_u2f_es256;
    const hash = clientDataHash(&v.registration_client_data_json);

    var tampered = v.attestation_object;
    tampered[40] ^= 0xff;
    const err = webauthn.verifyAttestation(a, &tampered, hash);
    try testing.expect(err == error.BadSignature or err == error.InvalidSignature);
}

test "reject: tampered authData byte inside attestationObject (packed) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_es256_full;
    const hash = clientDataHash(&v.registration_client_data_json);

    var tampered = v.attestation_object;
    // Flip the last byte of the whole attestationObject -- for this vector
    // that lands inside the credential public key's trailing coordinate
    // byte, which is part of authData and therefore part of the signed
    // `authData || clientDataHash` message.
    tampered[tampered.len - 1] ^= 0xff;
    try testing.expectError(error.BadSignature, webauthn.verifyAttestation(a, &tampered, hash));
}

test "reject: fmt=none with non-empty attStmt -> InvalidAttestationStatement" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Hand-build {fmt:"none", attStmt:{"x":1}, authData:<real authData>} --
    // a "none" attestation is REQUIRED to carry an empty attStmt map
    // (WebAuthn §8.7); a non-empty one must be rejected, not silently
    // accepted as if it were legitimately empty.
    const v = vectors.none_es256;
    const auth_data_bytes = try extractAuthDataRaw(a, &v.attestation_object);
    const bogus_entries = [_]cbor.MapEntry{.{ .key = .{ .text = "x" }, .value = .{ .uint = 1 } }};
    const entries = [_]cbor.MapEntry{
        .{ .key = .{ .text = "fmt" }, .value = .{ .text = "none" } },
        .{ .key = .{ .text = "attStmt" }, .value = .{ .map = &bogus_entries } },
        .{ .key = .{ .text = "authData" }, .value = .{ .bytes = auth_data_bytes } },
    };
    const built = try cbor.encode(a, .{ .map = &entries }, .{});

    const hash = clientDataHash(&v.registration_client_data_json);
    try testing.expectError(error.InvalidAttestationStatement, webauthn.verifyAttestation(a, built, hash));
}

test "reject: unknown fmt string -> UnsupportedFormat" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const v = vectors.none_es256;
    const auth_data_bytes = try extractAuthDataRaw(a, &v.attestation_object);
    const empty = [_]cbor.MapEntry{};
    const entries = [_]cbor.MapEntry{
        .{ .key = .{ .text = "fmt" }, .value = .{ .text = "totally-made-up-format" } },
        .{ .key = .{ .text = "attStmt" }, .value = .{ .map = &empty } },
        .{ .key = .{ .text = "authData" }, .value = .{ .bytes = auth_data_bytes } },
    };
    const built = try cbor.encode(a, .{ .map = &entries }, .{});

    const hash = clientDataHash(&v.registration_client_data_json);
    try testing.expectError(error.UnsupportedFormat, webauthn.verifyAttestation(a, built, hash));
}

// ════════════════════════════════════════════════════════════════════════════
// The `x5c` / attestation-object surface: hostile-input regression + fuzz
// ════════════════════════════════════════════════════════════════════════════
//
// `verifyAttestation` is the registration-ceremony entry point, and every byte
// it sees comes off the wire from an arbitrary client: the CBOR framing, the
// `fmt` string, the `attStmt` map, the declared COSE `alg`, the signature, and
// — the sharpest edge — `attStmt.x5c[0]`, a raw DER certificate that ends up in
// `std.crypto.Certificate.parse`. std's DER reader is not total on such input
// (see `x509/src/safe.zig`), which is why `verifyLeafCertSignature` only
// reaches it through `x509.safe.safeCertificate`.
//
// The two tests below are one pair: the first pins the exact reproducer, the
// second is the harness whose absence let that reproducer live undetected
// through a repo-wide fuzz sweep (the pre-existing harnesses sit on
// `parseClientData`/`parseAuthenticatorData`, which the x5c path never reaches).

/// The pieces of an `attestationObject` a hostile client fully controls.
const AttShape = struct {
    fmt: []const u8,
    /// The COSE algorithm `attStmt.alg` declares.
    alg: i64,
    /// `attStmt.x5c[0]`. `null` omits the `x5c` key entirely (the
    /// self-attestation shape); a present-but-empty slice still produces a
    /// one-element array holding an empty byte string.
    x5c: ?[]const u8,
    sig: []const u8,
    auth_data: []const u8,
};

/// CBOR-encode `{fmt, attStmt:{alg, sig[, x5c]}, authData}` — the real
/// attestationObject shape, so the bytes under test are the structured
/// fields rather than entropy a CBOR decoder rejects at byte one.
fn buildAttestationObject(a: std.mem.Allocator, s: AttShape) ![]u8 {
    var att: std.ArrayList(cbor.MapEntry) = .empty;
    const alg_value: cbor.Value = if (s.alg < 0)
        .{ .negint = @intCast(-1 - s.alg) }
    else
        .{ .uint = @intCast(s.alg) };
    try att.append(a, .{ .key = .{ .text = "alg" }, .value = alg_value });
    try att.append(a, .{ .key = .{ .text = "sig" }, .value = .{ .bytes = s.sig } });
    if (s.x5c) |leaf| {
        const arr = try a.alloc(cbor.Value, 1);
        arr[0] = .{ .bytes = leaf };
        try att.append(a, .{ .key = .{ .text = "x5c" }, .value = .{ .array = arr } });
    }
    const entries = [_]cbor.MapEntry{
        .{ .key = .{ .text = "fmt" }, .value = .{ .text = s.fmt } },
        .{ .key = .{ .text = "attStmt" }, .value = .{ .map = att.items } },
        .{ .key = .{ .text = "authData" }, .value = .{ .bytes = s.auth_data } },
    };
    return cbor.encode(a, .{ .map = &entries }, .{});
}

/// The `x5c[0]` bytes out of a real W3C §16 packed-x5c vector — a genuine
/// attestation certificate, so a mutation of it walks deep into the DER
/// parser instead of dying at the outer tag.
fn realX5c(a: std.mem.Allocator, attestation_object: []const u8) ![]const u8 {
    const decoded = try cbor.decode(a, attestation_object, .{});
    for (decoded.map) |e| switch (e.key) {
        .text => |t| if (std.mem.eql(u8, t, "attStmt")) {
            for (e.value.map) |ae| switch (ae.key) {
                .text => |at| if (std.mem.eql(u8, at, "x5c")) return ae.value.array[0].bytes,
                else => {},
            };
        },
        else => {},
    };
    return error.MissingField;
}

test "regression: a 4-byte x5c[0] is a typed error, not a panic (std DER hazard)" {
    // `30 02 30 00` is `SEQUENCE { SEQUENCE {} }`: well-formed DER, and a
    // certificate with an empty tbsCertificate. Handed to
    // `std.crypto.Certificate.parse` RAW it walks off the end of the buffer —
    // `index out of bounds: index 4, len 4` in Debug (the relying-party
    // process aborts), a silent out-of-bounds read under ReleaseFast. It is
    // the exact reproducer `modules/x509/src/safe.zig` was written for, and
    // an attacker puts it in `attStmt.x5c[0]` for free.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const v = vectors.none_es256;
    const auth_data_bytes = try extractAuthDataRaw(a, &v.attestation_object);
    const hostile: []const u8 = &.{ 0x30, 0x02, 0x30, 0x00 };

    // Both formats that consume x5c must reject it as a typed error.
    inline for (.{ "packed", "fido-u2f" }) |fmt| {
        const built = try buildAttestationObject(a, .{
            .fmt = fmt,
            .alg = -7, // ES256
            .x5c = hostile,
            .sig = &.{0x00},
            .auth_data = auth_data_bytes,
        });
        try testing.expectError(
            error.InvalidCertificate,
            webauthn.verifyAttestation(a, built, @splat(0)),
        );
    }

    // Every prefix of a real attestation certificate, likewise: truncation is
    // the general shape the 4-byte case is one instance of.
    const real = try realX5c(a, &vectors.packed_es256_full.attestation_object);
    var cut: usize = 0;
    while (cut < real.len) : (cut += 1) {
        const built = try buildAttestationObject(a, .{
            .fmt = "packed",
            .alg = -7,
            .x5c = real[0..cut],
            .sig = &.{0x00},
            .auth_data = auth_data_bytes,
        });
        // A strict prefix can never verify; the load-bearing property is that
        // the verdict is a typed error and not an abort.
        if (webauthn.verifyAttestation(a, built, @splat(0))) |_| {
            try testing.expect(false);
        } else |_| {}
    }
    // Not vacuous: the untruncated certificate really does reach the signature
    // check (and fails it, since the clientDataHash here is all zeroes).
    const whole = try buildAttestationObject(a, .{
        .fmt = "packed",
        .alg = -7,
        .x5c = real,
        .sig = &.{0x00},
        .auth_data = auth_data_bytes,
    });
    try testing.expectError(
        error.InvalidSignature,
        webauthn.verifyAttestation(a, whole, @splat(0)),
    );
}

// ── fuzz: the attestation / x5c / CBOR surface ─────────────────────────────

/// How the harness derives `x5c[0]` from the fuzzer's bytes. Raw entropy is
/// rejected by the DER reader almost immediately, so most of the modes wrap
/// the fuzzed bytes in structure the parser will actually descend into.
const X5cMode = enum {
    /// No `x5c` key at all — the `packed` self-attestation shape.
    absent,
    /// Raw fuzzer bytes.
    raw,
    /// Fuzzer bytes inside a `SEQUENCE` header, i.e. certificate-shaped.
    der_framed,
    /// A real attestation certificate, truncated at a fuzzer-chosen offset.
    real_truncated,
    /// A real attestation certificate with a fuzzer-chosen byte overwritten.
    real_mutated,
};

const fuzz_formats = [_][]const u8{ "packed", "fido-u2f", "none", "tpm", "android-key", "" };
const fuzz_algs = [_]i64{ -7, -8, -257, -65535, 0, 1 };

/// One hostile attestationObject, assembled from the fuzzer's bytes and run
/// through `verifyAttestation`. The contract is "never panics": any typed
/// error is a fine outcome, an abort is not.
fn fuzzVerifyAttestation(_: void, smith: *std.testing.Smith) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const real_cert = try realX5c(a, &vectors.packed_es256_full.attestation_object);
    const real_auth_data = try extractAuthDataRaw(a, &vectors.none_es256.attestation_object);

    const fmt = fuzz_formats[smith.index(fuzz_formats.len)];
    const alg = fuzz_algs[smith.index(fuzz_algs.len)];
    const mode: X5cMode = @enumFromInt(smith.valueRangeAtMost(u8, 0, @typeInfo(X5cMode).@"enum".fields.len - 1));

    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const raw_len: usize = smith.valueRangeAtMost(u16, 0, raw.len);

    const x5c: ?[]const u8 = switch (mode) {
        .absent => null,
        .raw => raw[0..raw_len],
        .der_framed => blk: {
            // `30 82 <len:be16> <fuzzed bytes>` — a SEQUENCE whose declared
            // length is the fuzzed content's, so the DER reader descends.
            const body = raw[0..raw_len];
            const framed = try a.alloc(u8, body.len + 4);
            framed[0] = 0x30;
            framed[1] = 0x82;
            std.mem.writeInt(u16, framed[2..4], @intCast(body.len), .big);
            @memcpy(framed[4..], body);
            break :blk framed;
        },
        .real_truncated => real_cert[0..smith.valueRangeAtMost(u16, 0, @intCast(real_cert.len))],
        .real_mutated => blk: {
            const mutant = try a.dupe(u8, real_cert);
            mutant[smith.index(mutant.len)] = raw[0];
            break :blk mutant;
        },
    };

    var sig_buf: [128]u8 = undefined;
    smith.bytes(&sig_buf);
    const sig_len: usize = smith.valueRangeAtMost(u8, 0, sig_buf.len);

    // authData: the real §16 blob (so the attested-credential-data parse
    // succeeds and the run gets as far as the attestation statement), or the
    // real blob with one fuzzed byte, or pure entropy.
    const auth_data: []const u8 = switch (smith.valueRangeAtMost(u8, 0, 2)) {
        0 => real_auth_data,
        1 => blk: {
            const mutant = try a.dupe(u8, real_auth_data);
            mutant[smith.index(mutant.len)] = raw[raw.len - 1];
            break :blk mutant;
        },
        else => raw[0..raw_len],
    };

    const built = try buildAttestationObject(a, .{
        .fmt = fmt,
        .alg = alg,
        .x5c = x5c,
        .sig = sig_buf[0..sig_len],
        .auth_data = auth_data,
    });

    var hash: [32]u8 = undefined;
    smith.bytes(&hash);

    // Two entry points: the assembled object, and — so the CBOR framing itself
    // is fuzzed and not only its fields — the fuzzer's raw bytes.
    _ = webauthn.verifyAttestation(a, built, hash) catch {};
    _ = webauthn.verifyAttestation(a, raw[0..raw_len], hash) catch {};
}

test "fuzz: verifyAttestation never panics on a hostile attestationObject" {
    try std.testing.fuzz({}, fuzzVerifyAttestation, .{});
}

test "the attestation fuzz harness reaches the certificate parser (reachability)" {
    // A harness that cannot reach the code it claims to cover is the defect
    // class this test exists to rule out: drive `fuzzVerifyAttestation`'s own
    // body deterministically (a `Smith` with `in` set consumes fixed bytes
    // instead of the fuzzer's) and, separately, assert that each x5c mode the
    // harness can pick really does land inside `verifyLeafCertSignature`.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const real_cert = try realX5c(a, &vectors.packed_es256_full.attestation_object);
    const real_auth_data = try extractAuthDataRaw(a, &vectors.none_es256.attestation_object);

    // `InvalidCertificate` / `InvalidSignature` / `BadSignature` /
    // `UnsupportedAlgorithm` are only reachable *inside*
    // `verifyLeafCertSignature`; any of them proves the x5c path ran.
    var reached: usize = 0;
    for ([_][]const u8{
        &.{ 0x30, 0x02, 0x30, 0x00 }, // the std hazard shape
        real_cert, // the genuine article
        real_cert[0 .. real_cert.len / 2], // truncated
        &.{ 0x30, 0x82, 0x00, 0x02, 0xff, 0xff }, // der_framed shape over junk
    }) |leaf| {
        const built = try buildAttestationObject(a, .{
            .fmt = "packed",
            .alg = -7,
            .x5c = leaf,
            .sig = &.{ 0x30, 0x00 },
            .auth_data = real_auth_data,
        });
        const err = webauthn.verifyAttestation(a, built, @splat(0));
        if (err) |_| {} else |e| switch (e) {
            error.InvalidCertificate,
            error.InvalidSignature,
            error.BadSignature,
            error.UnsupportedAlgorithm,
            => reached += 1,
            else => {},
        }
    }
    try testing.expectEqual(@as(usize, 4), reached);

    // And the harness body itself runs to completion on fixed input — it does
    // not, for instance, bail out before it has built anything.
    var smith: std.testing.Smith = .{ .in = &([_]u8{0x01} ** 64 ++ [_]u8{0x00} ** 1024) };
    try fuzzVerifyAttestation({}, &smith);
}

// ════════════════════════════════════════════════════════════════════════════
// The registration ceremony itself (§7.1): type, challenge, origin, rpIdHash
// ════════════════════════════════════════════════════════════════════════════
//
// `verifyAttestation` proves the attestation statement is internally
// consistent with *some* clientDataHash. It cannot prove the response answers
// the ceremony this relying party started, because it never sees the
// clientDataJSON — and with `fmt == "none"` there is no statement signature to
// prove anything at all. Every input below is a genuine, unmodified W3C §16
// artefact; what is wrong with it is only which ceremony it belongs to. That
// is the shape a malformed-input test cannot reach.

const RegOpts = webauthn.RegistrationOptions;

test "verifyRegistration: every real W3C §16 registration verifies against its own ceremony" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    inline for (.{
        .{ vectors.none_es256, webauthn.AttestationType.none },
        .{ vectors.packed_self_es256, webauthn.AttestationType.self_attestation },
        .{ vectors.packed_es256_full, webauthn.AttestationType.basic },
        .{ vectors.packed_rs256, webauthn.AttestationType.basic },
        .{ vectors.packed_eddsa, webauthn.AttestationType.basic },
        .{ vectors.fido_u2f_es256, webauthn.AttestationType.basic },
    }) |case| {
        const v = case[0];
        const result = try webauthn.verifyRegistration(
            a,
            &v.attestation_object,
            &v.registration_client_data_json,
            .{
                .rp_id = vectors.rp_id,
                .expected_challenge = &v.registration_challenge,
                .expected_origin = vectors.origin,
            },
        );
        try testing.expectEqual(case[1], result.attestation_type);
        try testing.expectEqualSlices(u8, &v.credential_id, result.credential_id);
        // The rpIdHash the ceremony check compared against is the vector's own.
        var expected_rp_id_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(vectors.rp_id, &expected_rp_id_hash, .{});
        try testing.expectEqualSlices(u8, &expected_rp_id_hash, &result.rp_id_hash);
        try testing.expect(result.flags.user_present);
    }
}

test "reject: an assertion's clientDataJSON replayed as a registration -> TypeMismatch" {
    // §16.2's own assertion clientDataJSON: a real, valid, correctly-signed
    // artefact of the *authentication* ceremony, same authenticator, same
    // origin. Paired with §16.2's `fmt == "none"` attestationObject — which
    // carries no signature over the clientDataHash — nothing but the `type`
    // string distinguishes it from the registration response.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;

    try testing.expectError(error.TypeMismatch, webauthn.verifyRegistration(
        a,
        &v.attestation_object,
        &v.assertion_client_data_json,
        .{
            .rp_id = vectors.rp_id,
            .expected_challenge = &v.assertion_challenge,
            .expected_origin = vectors.origin,
        },
    ));

    // And this is exactly what the statement-only entry point cannot see: the
    // same swap through `verifyAttestation` succeeds, because there is no
    // signature and no clientData in its argument list. Documented behaviour,
    // pinned here so it stays a deliberate split and not an accident.
    const hash = clientDataHash(&v.assertion_client_data_json);
    const anyway = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.none, anyway.attestation_type);
}

test "reject: a valid registration response replayed into another ceremony -> ChallengeMismatch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // `fmt == "none"`: the whole response is unauthenticated, so the challenge
    // is the only thing tying it to a ceremony.
    const none = vectors.none_es256;
    try testing.expectError(error.ChallengeMismatch, webauthn.verifyRegistration(
        a,
        &none.attestation_object,
        &none.registration_client_data_json,
        .{
            .rp_id = vectors.rp_id,
            // The challenge the RP issued for a *different* registration.
            .expected_challenge = &vectors.packed_self_es256.registration_challenge,
            .expected_origin = vectors.origin,
        },
    ));

    // `fmt == "packed"` with a real x5c chain: the attestation signature
    // verifies — it is a genuine statement over this exact authData and this
    // exact clientDataHash — and it still says nothing about which challenge
    // the relying party issued. A signature check alone never catches this.
    const full = vectors.packed_es256_full;
    const opts: RegOpts = .{
        .rp_id = vectors.rp_id,
        .expected_challenge = &vectors.packed_eddsa.registration_challenge,
        .expected_origin = vectors.origin,
    };
    try testing.expectError(error.ChallengeMismatch, webauthn.verifyRegistration(
        a,
        &full.attestation_object,
        &full.registration_client_data_json,
        opts,
    ));
    // Not vacuous: with the right challenge the very same bytes verify.
    var right = opts;
    right.expected_challenge = &full.registration_challenge;
    _ = try webauthn.verifyRegistration(a, &full.attestation_object, &full.registration_client_data_json, right);
}

test "reject: registration from another site or another RP ID" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_es256_full;
    const base: RegOpts = .{
        .rp_id = vectors.rp_id,
        .expected_challenge = &v.registration_challenge,
        .expected_origin = vectors.origin,
    };

    // The origin the browser asserted is not this relying party's.
    var wrong_origin = base;
    wrong_origin.expected_origin = "https://evil.example";
    try testing.expectError(error.OriginMismatch, webauthn.verifyRegistration(
        a,
        &v.attestation_object,
        &v.registration_client_data_json,
        wrong_origin,
    ));

    // The authenticator scoped the credential to a different RP ID, so its
    // rpIdHash cannot be ours.
    var wrong_rp = base;
    wrong_rp.rp_id = "example.com";
    try testing.expectError(error.RpIdMismatch, webauthn.verifyRegistration(
        a,
        &v.attestation_object,
        &v.registration_client_data_json,
        wrong_rp,
    ));
}

test "verifyRegistration: user verification is opt-in and load-bearing when opted in" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // §16.2's authData has UP set and UV clear (flags 0x59).
    const v = vectors.none_es256;
    const base: RegOpts = .{
        .rp_id = vectors.rp_id,
        .expected_challenge = &v.registration_challenge,
        .expected_origin = vectors.origin,
    };
    const ok = try webauthn.verifyRegistration(a, &v.attestation_object, &v.registration_client_data_json, base);
    try testing.expect(!ok.flags.user_verified);

    var uv = base;
    uv.require_user_verification = true;
    try testing.expectError(error.UserNotVerified, webauthn.verifyRegistration(
        a,
        &v.attestation_object,
        &v.registration_client_data_json,
        uv,
    ));

    // §16.3's has UV set (flags 0x5D), so the same requirement passes there.
    const w = vectors.packed_self_es256;
    _ = try webauthn.verifyRegistration(a, &w.attestation_object, &w.registration_client_data_json, .{
        .rp_id = vectors.rp_id,
        .expected_challenge = &w.registration_challenge,
        .expected_origin = vectors.origin,
        .require_user_verification = true,
    });
}

test "verifyRegistration: fmt=none is accepted by default and refusable on request" {
    // The deliberate decision, pinned: `none` stays acceptable (§7.1 step 20
    // lists it as a conforming outcome and it is what most platform
    // authenticators send), but the caller is told — `attestation_type ==
    // .none` — and can refuse it outright.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const base: RegOpts = .{
        .rp_id = vectors.rp_id,
        .expected_challenge = &v.registration_challenge,
        .expected_origin = vectors.origin,
    };

    const permissive = try webauthn.verifyRegistration(a, &v.attestation_object, &v.registration_client_data_json, base);
    try testing.expectEqual(webauthn.AttestationType.none, permissive.attestation_type);

    var strict = base;
    strict.require_attestation = true;
    try testing.expectError(error.AttestationNotProvided, webauthn.verifyRegistration(
        a,
        &v.attestation_object,
        &v.registration_client_data_json,
        strict,
    ));

    // A real attestation statement satisfies the same setting.
    const w = vectors.packed_es256_full;
    const attested = try webauthn.verifyRegistration(a, &w.attestation_object, &w.registration_client_data_json, .{
        .rp_id = vectors.rp_id,
        .expected_challenge = &w.registration_challenge,
        .expected_origin = vectors.origin,
        .require_attestation = true,
    });
    try testing.expectEqual(webauthn.AttestationType.basic, attested.attestation_type);
}

// ── fuzz: a registration that VERIFIES must be bound to this ceremony ───────
//
// The defect this section guards is not crash-shaped: a mis-bound registration
// response verifies, it does not abort, so a "never panics" harness cannot see
// it however long it runs. What makes a harness bite here is an **oracle on
// success** rather than on survival — every accepted registration is re-read
// and its clientData compared against the options it was verified under. A
// binding that is dropped, weakened or made conditional turns some accepted
// input into a violation of that invariant.

const AllVectors = struct {
    fn attestationObject(i: usize) []const u8 {
        return switch (i) {
            0 => &vectors.none_es256.attestation_object,
            1 => &vectors.packed_self_es256.attestation_object,
            2 => &vectors.packed_es256_full.attestation_object,
            3 => &vectors.packed_rs256.attestation_object,
            4 => &vectors.packed_eddsa.attestation_object,
            else => &vectors.fido_u2f_es256.attestation_object,
        };
    }
    fn registrationClientData(i: usize) []const u8 {
        return switch (i) {
            0 => &vectors.none_es256.registration_client_data_json,
            1 => &vectors.packed_self_es256.registration_client_data_json,
            2 => &vectors.packed_es256_full.registration_client_data_json,
            3 => &vectors.packed_rs256.registration_client_data_json,
            4 => &vectors.packed_eddsa.registration_client_data_json,
            else => &vectors.fido_u2f_es256.registration_client_data_json,
        };
    }
    fn assertionClientData(i: usize) []const u8 {
        return switch (i) {
            0 => &vectors.none_es256.assertion_client_data_json,
            1 => &vectors.packed_self_es256.assertion_client_data_json,
            2 => &vectors.packed_es256_full.assertion_client_data_json,
            3 => &vectors.packed_rs256.assertion_client_data_json,
            4 => &vectors.packed_eddsa.assertion_client_data_json,
            else => &vectors.fido_u2f_es256.assertion_client_data_json,
        };
    }
    fn challenge(i: usize) []const u8 {
        return switch (i) {
            0 => &vectors.none_es256.registration_challenge,
            1 => &vectors.packed_self_es256.registration_challenge,
            2 => &vectors.packed_es256_full.registration_challenge,
            3 => &vectors.packed_rs256.registration_challenge,
            4 => &vectors.packed_eddsa.registration_challenge,
            else => &vectors.fido_u2f_es256.registration_challenge,
        };
    }
    const count: usize = 6;
};

const fuzz_types = [_][]const u8{ "webauthn.create", "webauthn.get", "webauthn.CREATE", "" };
const fuzz_origins = [_][]const u8{ "https://example.org", "https://example.org.evil.test", "http://example.org", "" };

/// Every accepted registration must satisfy §7.1's binding, whatever the
/// fuzzer built. Any run that returns a result and fails one of these
/// comparisons is a mis-binding — the class of defect that verifies rather
/// than crashes.
fn fuzzRegistrationBinding(_: void, smith: *std.testing.Smith) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const vi = smith.index(AllVectors.count);

    // clientDataJSON: the ceremony's own, another ceremony's, the *assertion*
    // ceremony's, or one assembled field by field from the fuzzer's choices.
    const client_data_json: []const u8 = switch (smith.valueRangeAtMost(u8, 0, 3)) {
        0 => AllVectors.registrationClientData(vi),
        1 => AllVectors.registrationClientData(smith.index(AllVectors.count)),
        2 => AllVectors.assertionClientData(vi),
        else => blk: {
            var chal_raw: [32]u8 = undefined;
            smith.bytes(&chal_raw);
            const chal_len: usize = smith.valueRangeAtMost(u8, 0, chal_raw.len);
            const enc = std.base64.url_safe_no_pad.Encoder;
            const chal_b64 = try a.alloc(u8, enc.calcSize(chal_len));
            _ = enc.encode(chal_b64, chal_raw[0..chal_len]);
            break :blk try std.fmt.allocPrint(
                a,
                "{{\"type\":\"{s}\",\"challenge\":\"{s}\",\"origin\":\"{s}\",\"crossOrigin\":false}}",
                .{
                    fuzz_types[smith.index(fuzz_types.len)],
                    chal_b64,
                    fuzz_origins[smith.index(fuzz_origins.len)],
                },
            );
        },
    };

    var expected_challenge_raw: [32]u8 = undefined;
    smith.bytes(&expected_challenge_raw);
    const options: webauthn.RegistrationOptions = .{
        .rp_id = if (smith.value(bool)) vectors.rp_id else "example.com",
        .expected_challenge = if (smith.value(bool))
            AllVectors.challenge(smith.index(AllVectors.count))
        else
            expected_challenge_raw[0..smith.valueRangeAtMost(u8, 0, 32)],
        .expected_origin = fuzz_origins[smith.index(fuzz_origins.len)],
        .require_user_verification = smith.value(bool),
        .require_attestation = smith.value(bool),
    };

    const result = webauthn.verifyRegistration(
        a,
        AllVectors.attestationObject(vi),
        client_data_json,
        options,
    ) catch return;

    // It verified. Then all of this must hold.
    const cd = try webauthn.parseClientData(a, client_data_json);
    try testing.expectEqualStrings("webauthn.create", cd.type);
    try testing.expectEqualSlices(u8, options.expected_challenge, cd.challenge);
    try testing.expectEqualStrings(options.expected_origin, cd.origin);

    var expected_rp_id_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(options.rp_id, &expected_rp_id_hash, .{});
    try testing.expectEqualSlices(u8, &expected_rp_id_hash, &result.rp_id_hash);
    try testing.expect(result.flags.user_present);
    if (options.require_user_verification) try testing.expect(result.flags.user_verified);
    if (options.require_attestation) try testing.expect(result.attestation_type != .none);
}

test "fuzz: an accepted registration is bound to the ceremony it was verified against" {
    try std.testing.fuzz({}, fuzzRegistrationBinding, .{});
}

test "the registration fuzz harness reaches an accepted registration (reachability)" {
    // An oracle-on-success harness proves nothing if it never succeeds. Drive
    // the same code path deterministically over every vector and assert the
    // accept branch is exercised — otherwise the harness above would stay
    // green while checking nothing at all.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var accepted: usize = 0;
    for (0..AllVectors.count) |i| {
        _ = webauthn.verifyRegistration(
            a,
            AllVectors.attestationObject(i),
            AllVectors.registrationClientData(i),
            .{
                .rp_id = vectors.rp_id,
                .expected_challenge = AllVectors.challenge(i),
                .expected_origin = vectors.origin,
            },
        ) catch continue;
        accepted += 1;
    }
    try testing.expectEqual(AllVectors.count, accepted);

    // And the harness body itself runs to completion on fixed input.
    inline for (.{ 0x00, 0x01, 0x02, 0x55, 0x7f, 0xff }) |filler| {
        var smith: std.testing.Smith = .{ .in = &([_]u8{filler} ** 64 ++ [_]u8{0} ** 512) };
        try fuzzRegistrationBinding({}, &smith);
    }
}
