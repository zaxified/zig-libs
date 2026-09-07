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
    // Regression (audit W2 `webauthn` F6): no certificate for `fmt == "none"`.
    try testing.expect(result.leaf_cert_der == null);
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
    // Regression (audit W2 `webauthn` F6): self-attestation carries no x5c.
    try testing.expect(result.leaf_cert_der == null);
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
    // Regression (audit W2 `webauthn` F6): `.basic` exposes the leaf DER it
    // actually verified against, so a caller can chain it (`x509.verifyChain`
    // against an MDS-derived trust store) instead of trusting the enum name
    // alone — byte-exact against the same x5c[0] independently re-extracted
    // from the raw CBOR, not merely "non-null".
    const expected_leaf = try realX5c(a, &v.attestation_object);
    try testing.expectEqualSlices(u8, expected_leaf, result.leaf_cert_der.?);
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
    // Regression (audit W2 `webauthn` F6): fido-u2f's `.basic` also exposes
    // the leaf it verified against, same contract as `packed`/x5c.
    const expected_leaf = try realX5c(a, &v.attestation_object);
    try testing.expectEqualSlices(u8, expected_leaf, result.leaf_cert_der.?);
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

/// `testkit.fuzz.Cursor` over one corpus seed: the script that drives both
/// harnesses in this file.
///
/// ⚠ It is here because both of them took every choice from a ranged `Smith`
/// draw and their FIRST draw was one, which `check-fuzz-reach` classifies R1. A
/// scalar draw reads eight octets as a little-endian `u64` and returns the range
/// MINIMUM unless the whole word falls inside the range, and after the first
/// short read `Smith` discards the rest of the input -- so outside `--fuzz`
/// EVERY choice collapsed to its minimum. Measured on `fuzzVerifyAttestation`:
/// `fmt` was always "packed", `alg` always -7, the x5c mode always `.absent`,
/// `raw_len` always 0, `sig_len` always 0 and the authData mode always 0. One
/// attestation object, built once, for the life of the harness -- and the
/// `.der_framed`, `.real_truncated` and `.real_mutated` certificate paths,
/// which are the only reason the neighbouring reachability test exists, had
/// never been taken by the harness itself.
///
/// Neither target was exempted. A harness that assembles a structure from a
/// list of choices has an obvious byte-first form: one `smith.slice`, then the
/// octets say what gets built. It also makes a seed reviewable, which a
/// sequence of `u64` words is not. Under `--fuzz` the fuzzer still drives every
/// choice, because it drives the slice.
const Script = @import("testkit").fuzz.Cursor;
const seed = @import("testkit").fuzz.seedHex;

/// What one attestation script produced, so the guard can measure the corpus
/// rather than assert it merely ran.
const AttestationOutcome = struct {
    /// Distinct `fmt` strings the script selected.
    fmt_index: usize = 0,
    /// Which `X5cMode` it selected.
    mode: X5cMode = .absent,
    /// Octets of `x5c` handed to `verifyAttestation` (0 when absent).
    x5c_octets: usize = 0,
    /// Octets of attestation signature.
    sig_octets: usize = 0,
    /// Octets of authData.
    auth_data_octets: usize = 0,
};

/// The body of `fuzzVerifyAttestation`, factored out so the harness and the
/// corpus guard drive the SAME assembly from the same octets. A guard measuring
/// a different sequence from the one the harness runs is not a guard.
///
/// The layout the cursor reads is
/// `fmt, alg, x5cMode, rawLen(2), sigLen, authDataMode, certOffset(2)`,
/// followed by the octets that fill `raw`, the signature and the client-data
/// hash. A short script cycles rather than running out.
fn runAttestationScript(a: std.mem.Allocator, bytes: []const u8) !AttestationOutcome {
    var s = Script{ .bytes = bytes };
    var out: AttestationOutcome = .{};

    const real_cert = try realX5c(a, &vectors.packed_es256_full.attestation_object);
    const real_auth_data = try extractAuthDataRaw(a, &vectors.none_es256.attestation_object);

    out.fmt_index = s.byte() % fuzz_formats.len;
    const fmt = fuzz_formats[out.fmt_index];
    const alg = fuzz_algs[s.byte() % fuzz_algs.len];
    out.mode = @enumFromInt(s.byte() % @typeInfo(X5cMode).@"enum".fields.len);

    var raw: [512]u8 = undefined;
    const raw_len: usize = s.word() % (raw.len + 1);
    const sig_len: usize = s.byte() % 129;
    const auth_mode: u8 = s.byte() % 3;
    const cert_offset: usize = s.word() % (real_cert.len + 1);
    const mutate_at: usize = s.word();
    for (&raw) |*b| b.* = s.byte();

    const x5c: ?[]const u8 = switch (out.mode) {
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
        .real_truncated => real_cert[0..cert_offset],
        .real_mutated => blk: {
            const mutant = try a.dupe(u8, real_cert);
            mutant[mutate_at % mutant.len] = raw[0];
            break :blk mutant;
        },
    };
    out.x5c_octets = if (x5c) |c| c.len else 0;

    var sig_buf: [128]u8 = undefined;
    for (&sig_buf) |*b| b.* = s.byte();
    out.sig_octets = sig_len;

    // authData: the real §16 blob (so the attested-credential-data parse
    // succeeds and the run gets as far as the attestation statement), or the
    // real blob with one fuzzed byte, or pure entropy.
    const auth_data: []const u8 = switch (auth_mode) {
        0 => real_auth_data,
        1 => blk: {
            const mutant = try a.dupe(u8, real_auth_data);
            mutant[mutate_at % mutant.len] = raw[raw.len - 1];
            break :blk mutant;
        },
        else => raw[0..raw_len],
    };
    out.auth_data_octets = auth_data.len;

    const built = try buildAttestationObject(a, .{
        .fmt = fmt,
        .alg = alg,
        .x5c = x5c,
        .sig = sig_buf[0..sig_len],
        .auth_data = auth_data,
    });

    var hash: [32]u8 = undefined;
    for (&hash) |*b| b.* = s.byte();

    // Two entry points: the assembled object, and — so the CBOR framing itself
    // is fuzzed and not only its fields — the raw script bytes.
    _ = webauthn.verifyAttestation(a, built, hash) catch {};
    _ = webauthn.verifyAttestation(a, raw[0..raw_len], hash) catch {};
    return out;
}

/// Attestation scripts. The layout is
/// `fmt, alg, x5cMode, rawLen(2), sigLen, authDataMode, certOffset(2),
/// mutateAt(2)`, then filler. `fmt` indexes `fuzz_formats`
/// (0 packed · 1 fido-u2f · 2 none · 3 tpm · 4 android-key · 5 empty), `alg`
/// indexes `fuzz_algs` (0 ES256 · 1 EdDSA · 2 RS256 · 3 bogus · 4 zero ·
/// 5 one) and `x5cMode` indexes `X5cMode`
/// (0 absent · 1 raw · 2 der_framed · 3 real_truncated · 4 real_mutated).
const attestation_seeds = [_][]const u8{
    seed("0200" ++ "00" ++ "0000" ++ "00" ++ "00" ++ "0000" ++ "0000"), // fmt none, no x5c, no sig, the real authData: the shape that VERIFIES
    seed("0000" ++ "00" ++ "0000" ++ "40" ++ "00" ++ "0000" ++ "0000"), // fmt packed, self-attestation shape, a 64-octet signature
    seed("0000" ++ "04" ++ "0000" ++ "40" ++ "00" ++ "0000" ++ "0000"), // ⭐ packed with a REAL certificate, one byte mutated: `.real_mutated`
    seed("0000" ++ "03" ++ "0000" ++ "40" ++ "00" ++ "0190" ++ "0000"), // ⭐ packed with the real certificate truncated at 400: `.real_truncated`
    seed("0000" ++ "02" ++ "0040" ++ "40" ++ "00" ++ "0000" ++ "0000"), // ⭐ packed with 64 script octets inside a DER SEQUENCE header: `.der_framed`
    seed("0000" ++ "01" ++ "0100" ++ "40" ++ "00" ++ "0000" ++ "0000"), // packed with 256 raw script octets where a certificate belongs
    seed("0100" ++ "04" ++ "0000" ++ "40" ++ "00" ++ "0000" ++ "0000"), // fido-u2f with a real mutated certificate
    seed("0300" ++ "00" ++ "0000" ++ "00" ++ "00" ++ "0000" ++ "0000"), // fmt tpm: the DEFER-as-unsupported path
    seed("0400" ++ "00" ++ "0000" ++ "00" ++ "00" ++ "0000" ++ "0000"), // fmt android-key: the same
    seed("0500" ++ "00" ++ "0000" ++ "00" ++ "00" ++ "0000" ++ "0000"), // an EMPTY fmt string
    seed("0003" ++ "04" ++ "0000" ++ "40" ++ "00" ++ "0000" ++ "0000"), // an unregistered COSE algorithm with a real certificate
    seed("0004" ++ "00" ++ "0000" ++ "00" ++ "01" ++ "0000" ++ "0000"), // alg 0, and the real authData with one octet mutated
    seed("0002" ++ "00" ++ "0000" ++ "00" ++ "02" ++ "0000" ++ "0000"), // RS256, and authData that is pure script entropy
    seed("0000" ++ "01" ++ "0200" ++ "80" ++ "02" ++ "0000" ++ "0000"), // the maxima: 512 raw octets, a 128-octet signature, entropy authData
    seed("00"), // one octet, cycled: the degenerate script
    seed(""), // the empty script: exactly what the collapsed harness ran
};

test "fuzz: verifyAttestation never panics on a hostile attestationObject" {
    try std.testing.fuzz({}, fuzzVerifyAttestation, .{ .corpus = &attestation_seeds });
}

fn fuzzVerifyAttestation(_: void, smith: *std.testing.Smith) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var script: [1024]u8 = undefined;
    const n: usize = smith.slice(&script);
    _ = try runAttestationScript(arena.allocator(), script[0..n]);
}

test "corpus: every attestation script builds a distinct object, and what it built is pinned" {
    // ⭐ Not "accepted", and not a total: the numbers are how many DISTINCT
    // fmt strings and x5c modes the corpus reached, because that is exactly
    // what collapsed. The old harness reached 1 and 1 — "packed" and
    // `.absent`, for ever — while the reachability test beside it separately
    // proved the certificate paths were reachable IF something drove them.
    // Nothing did.
    //
    // ⚠ There is deliberately no "verified" column. `buildAttestationObject`
    // always writes an `attStmt` carrying `alg` and `sig`, and WebAuthn §8.7
    // requires `none` to carry an EMPTY one — so nothing this harness assembles
    // can ever verify, whatever the script says. That is a property of the
    // builder, not a gap in the corpus, and pinning a 0 for it would read like
    // a measurement when it is a tautology. The octet columns are the reach:
    // `x5c_octets` can only be non-zero when a script drives one of the four
    // certificate modes, and `auth_data_octets` only when authData is assembled
    // rather than left at its collapsed default.
    var nonempty: usize = 0;
    var fmts_seen = [_]bool{false} ** fuzz_formats.len;
    var modes_seen = [_]bool{false} ** @typeInfo(X5cMode).@"enum".fields.len;
    var x5c_octets: usize = 0;
    var auth_data_octets: usize = 0;
    for (attestation_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [1024]u8 = undefined;
        const n: usize = smith.slice(&script);
        if (n != 0) nonempty += 1;
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const out = try runAttestationScript(arena.allocator(), script[0..n]);
        fmts_seen[out.fmt_index] = true;
        modes_seen[@intFromEnum(out.mode)] = true;
        x5c_octets += out.x5c_octets;
        auth_data_octets += out.auth_data_octets;
    }
    var fmts: usize = 0;
    for (fmts_seen) |b| {
        if (b) fmts += 1;
    }
    var modes: usize = 0;
    for (modes_seen) |b| {
        if (b) modes += 1;
    }
    // One seed is deliberately the empty script.
    try testing.expectEqual(attestation_seeds.len - 1, nonempty);
    // Measured 2026-09-07: 1 fmt, 1 mode and 0 x5c octets before the draws
    // were restructured — every seed produced the same object.
    try testing.expectEqual(fuzz_formats.len, fmts);
    try testing.expectEqual(@typeInfo(X5cMode).@"enum".fields.len, modes);
    try testing.expectEqual(@as(usize, 2883), x5c_octets);
    try testing.expectEqual(@as(usize, 2808), auth_data_octets);
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
/// The body of `fuzzRegistrationBinding`, factored out so the harness and the
/// corpus guard drive the SAME ceremony from the same octets.
///
/// ⚠ Every choice here used to be a ranged `Smith` draw and the FIRST one
/// was `smith.index(AllVectors.count)`, which `check-fuzz-reach` classifies R1.
/// Outside `--fuzz` all of them collapsed to their minimum: vector 0, client
/// data mode 0, `rp_id` = `"example.com"`, the expected challenge a
/// ZERO-LENGTH slice, origin index 0, and both `require_*` flags false.
///
/// ⛔ And that combination does not verify. `verifyRegistration` refused it,
/// the `catch return` fired, and every assertion after it — the §7.1 binding
/// this harness exists to prove — had never executed. An oracle-on-success
/// harness that never succeeds is green for ever. The measurement is pinned in
/// "the collapsed registration harness never reached its own oracle" below.
///
/// The layout the cursor reads is `vector, clientDataMode, chalLen, type,
/// origin, rpId, expectedChallengeMode, expectedChallengeVector,
/// expectedOrigin, requireUV, requireAttestation`, then filler for the
/// challenge bytes. A short script cycles rather than running out.
fn runRegistrationScript(a: std.mem.Allocator, bytes: []const u8) !RegistrationOutcome {
    var s = Script{ .bytes = bytes };
    var out: RegistrationOutcome = .{};

    const vi = s.byte() % AllVectors.count;
    out.vector = vi;
    out.client_data_mode = s.byte() % 4;

    // clientDataJSON: the ceremony's own, another ceremony's, the *assertion*
    // ceremony's, or one assembled field by field from the script's choices.
    const client_data_json: []const u8 = switch (out.client_data_mode) {
        0 => AllVectors.registrationClientData(vi),
        1 => AllVectors.registrationClientData(s.byte() % AllVectors.count),
        2 => AllVectors.assertionClientData(vi),
        else => blk: {
            var chal_raw: [32]u8 = undefined;
            const chal_len: usize = s.byte() % (chal_raw.len + 1);
            for (&chal_raw) |*b| b.* = s.byte();
            const enc = std.base64.url_safe_no_pad.Encoder;
            const chal_b64 = try a.alloc(u8, enc.calcSize(chal_len));
            _ = enc.encode(chal_b64, chal_raw[0..chal_len]);
            break :blk try std.fmt.allocPrint(
                a,
                "{{\"type\":\"{s}\",\"challenge\":\"{s}\",\"origin\":\"{s}\",\"crossOrigin\":false}}",
                .{
                    fuzz_types[s.byte() % fuzz_types.len],
                    chal_b64,
                    fuzz_origins[s.byte() % fuzz_origins.len],
                },
            );
        },
    };

    out.right_rp_id = s.byte() % 2 == 0;
    const use_real_challenge = s.byte() % 2 == 0;
    const challenge_vector = s.byte() % AllVectors.count;
    const raw_challenge_len = s.byte() % 33;
    var expected_challenge_raw: [32]u8 = undefined;
    for (&expected_challenge_raw) |*b| b.* = s.byte();
    out.origin_index = s.byte() % fuzz_origins.len;

    const options: webauthn.RegistrationOptions = .{
        .rp_id = if (out.right_rp_id) vectors.rp_id else "example.com",
        .expected_challenge = if (use_real_challenge)
            AllVectors.challenge(challenge_vector)
        else
            expected_challenge_raw[0..raw_challenge_len],
        .expected_origin = fuzz_origins[out.origin_index],
        .require_user_verification = s.byte() % 2 == 0,
        .require_attestation = s.byte() % 2 == 0,
    };
    out.require_uv = options.require_user_verification;
    out.require_attestation = options.require_attestation;

    const result = webauthn.verifyRegistration(
        a,
        AllVectors.attestationObject(vi),
        client_data_json,
        options,
    ) catch return out;
    out.accepted = true;

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
    return out;
}

/// What one registration script chose and what came of it.
const RegistrationOutcome = struct {
    vector: usize = 0,
    client_data_mode: u8 = 0,
    origin_index: usize = 0,
    right_rp_id: bool = false,
    require_uv: bool = false,
    require_attestation: bool = false,
    accepted: bool = false,
};

/// Registration scripts. The layout is `vector, clientDataMode, [chalLen, type,
/// origin]*, rpId, challengeMode, challengeVector, rawChalLen, chal(32),
/// expectedOrigin, requireUV, requireAttestation`. `clientDataMode` is
/// 0 own · 1 another ceremony's · 2 the ASSERTION ceremony's · 3 assembled;
/// even octets mean "the right one" for the boolean knobs.
const registration_seeds = [_][]const u8{
    // The six accepting ceremonies: vector i, its own clientDataJSON, the real
    // rp_id, its own challenge, origin 0, neither `require_*` set.
    seed("0000" ++ "00" ++ "00" ++ "00" ++ "00" ++ ("00" ** 32) ++ "00" ++ "01" ++ "01"),
    seed("0100" ++ "00" ++ "00" ++ "01" ++ "00" ++ ("00" ** 32) ++ "00" ++ "01" ++ "01"),
    seed("0200" ++ "00" ++ "00" ++ "02" ++ "00" ++ ("00" ** 32) ++ "00" ++ "01" ++ "01"),
    seed("0300" ++ "00" ++ "00" ++ "03" ++ "00" ++ ("00" ** 32) ++ "00" ++ "01" ++ "01"),
    seed("0400" ++ "00" ++ "00" ++ "04" ++ "00" ++ ("00" ** 32) ++ "00" ++ "01" ++ "01"),
    seed("0500" ++ "00" ++ "00" ++ "05" ++ "00" ++ ("00" ** 32) ++ "00" ++ "01" ++ "01"),
    // ⭐ vector 2 with ANOTHER ceremony's clientDataJSON: the cross-ceremony
    // replay the §7.1 binding exists to refuse.
    seed("0201" ++ "05" ++ "00" ++ "00" ++ "02" ++ "00" ++ ("00" ** 32) ++ "00" ++ "01" ++ "01"),
    // ⭐ vector 2 with its own ASSERTION clientDataJSON: type is webauthn.get.
    seed("0202" ++ "00" ++ "00" ++ "02" ++ "00" ++ ("00" ** 32) ++ "00" ++ "01" ++ "01"),
    // A hand-assembled clientDataJSON: type index 0, origin index 0, 32 octets
    // of challenge.
    seed("0003" ++ "20" ++ ("00" ** 32) ++ "00" ++ "00" ++ "00" ++ "00" ++ "00" ++ "00" ++ ("00" ** 32) ++ "00" ++ "01" ++ "01"),
    // ⭐ the WRONG rp_id: "example.com" against a zone signed for example.org.
    seed("0000" ++ "01" ++ "00" ++ "00" ++ "00" ++ ("00" ** 32) ++ "00" ++ "01" ++ "01"),
    // ⭐ the WRONG expected origin: the confusable "https://example.org.evil.test".
    seed("0000" ++ "00" ++ "00" ++ "00" ++ "00" ++ ("00" ** 32) ++ "01" ++ "01" ++ "01"),
    // ⭐ an expected challenge belonging to a DIFFERENT vector.
    seed("0000" ++ "00" ++ "00" ++ "03" ++ "00" ++ ("00" ** 32) ++ "00" ++ "01" ++ "01"),
    // ⭐ a raw expected challenge of 32 zero octets: right length, wrong value.
    seed("0000" ++ "00" ++ "01" ++ "00" ++ "20" ++ ("00" ** 32) ++ "00" ++ "01" ++ "01"),
    // ⭐ `require_user_verification` set, on a vector whose UV bit is what it is.
    seed("0000" ++ "00" ++ "00" ++ "00" ++ "00" ++ ("00" ** 32) ++ "00" ++ "00" ++ "01"),
    // ⭐ `require_attestation` set: `none` attestation must then be refused.
    seed("0000" ++ "00" ++ "00" ++ "00" ++ "00" ++ ("00" ** 32) ++ "00" ++ "01" ++ "00"),
    // Both flags set, on the x5c vector that can satisfy attestation.
    seed("0200" ++ "00" ++ "00" ++ "02" ++ "00" ++ ("00" ** 32) ++ "00" ++ "00" ++ "00"),
    seed("00"), // one octet, cycled: the degenerate script
    seed(""), // the empty script: exactly what the collapsed harness ran
};

test "fuzz: an accepted registration is bound to the ceremony it was verified against" {
    try std.testing.fuzz({}, fuzzRegistrationBinding, .{ .corpus = &registration_seeds });
}

fn fuzzRegistrationBinding(_: void, smith: *std.testing.Smith) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var script: [256]u8 = undefined;
    const n: usize = smith.slice(&script);
    _ = try runRegistrationScript(arena.allocator(), script[0..n]);
}

test "the collapsed registration harness never reached its own oracle (regression)" {
    // ⭐ The measurement behind the comment on `runRegistrationScript`,
    // executable so it cannot quietly stop being true, and kept because it is
    // the whole reason that harness was restructured rather than left alone.
    //
    // The old body opened `smith.index(AllVectors.count)` and then took every
    // other choice from a ranged draw. Two of those choices decided whether
    // `verifyRegistration` could possibly succeed:
    //
    //     .rp_id = if (smith.value(bool)) vectors.rp_id else "example.com",
    //     .expected_challenge = if (smith.value(bool)) ... else <raw, len 0>,
    //
    // `value(bool)` is `rangeAtMost(u1, 0, 1)`, which reads EIGHT octets as a
    // little-endian u64 and returns the range minimum unless the whole word
    // lands in [0,1]. So for the fixed inputs the reachability test below
    // drives -- and for the one empty input the corpus-less lane replayed --
    // it was FALSE: the RP id was "example.com" against vectors signed for
    // example.org, and the expected challenge was a zero-length slice.
    // `verifyRegistration` refused, the `catch return` fired, and every
    // assertion after it -- the §7.1 binding this harness exists to prove --
    // had never executed. An oracle-on-success harness that never succeeds is
    // green for ever.
    //
    // The reachability test below did not catch it: it counts accepted
    // registrations in a loop of its OWN, calling `verifyRegistration`
    // directly, and only asks of the harness that its body "runs to
    // completion".
    inline for (.{ 0x00, 0x01, 0x02, 0x55, 0x7f, 0xff }) |filler| {
        var smith: std.testing.Smith = .{ .in = &([_]u8{filler} ** 64 ++ [_]u8{0} ** 512) };
        _ = smith.index(AllVectors.count); // the R1 first draw
        _ = smith.valueRangeAtMost(u8, 0, 3); // the clientData mode
        var chal: [32]u8 = undefined;
        smith.bytes(&chal);
        try testing.expect(!smith.value(bool)); // -> rp_id "example.com": WRONG
        try testing.expect(!smith.value(bool)); // -> a zero-length expected challenge
    }

    // And the consequence, end to end: the exact options the collapsed harness
    // built are refused, so the oracle block was unreachable. The zero-length
    // challenge is caught first, before the RP id even gets compared — two
    // independent reasons the one input this harness ever ran could not pass.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.ChallengeMismatch, webauthn.verifyRegistration(
        arena.allocator(),
        AllVectors.attestationObject(0),
        AllVectors.registrationClientData(0),
        .{
            .rp_id = "example.com",
            .expected_challenge = "",
            .expected_origin = fuzz_origins[0],
        },
    ));
}

test "corpus: the registration scripts reach both verdicts, and the spread is pinned" {
    // ⭐ An oracle-on-success harness has TWO failure modes and only one of them
    // is "never succeeds". The reachability test below rules that one out. This
    // guard rules out the other: a corpus that only ever succeeds re-proves the
    // same passing ceremony and never puts the §7.1 binding under load. So the
    // pinned numbers are the spread — how many vectors, how many clientData
    // modes and how many origins the corpus reached, and how the accept/refuse
    // split falls.
    //
    // The collapsed harness scored 1 vector, 1 mode, 1 origin and accepted
    // every time.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var refused: usize = 0;
    var vectors_seen = [_]bool{false} ** AllVectors.count;
    var modes_seen = [_]bool{false} ** 4;
    var origins_seen = [_]bool{false} ** fuzz_origins.len;
    for (registration_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [256]u8 = undefined;
        const n: usize = smith.slice(&script);
        if (n != 0) nonempty += 1;
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const out = try runRegistrationScript(arena.allocator(), script[0..n]);
        vectors_seen[out.vector] = true;
        modes_seen[out.client_data_mode] = true;
        origins_seen[out.origin_index] = true;
        if (out.accepted) accepted += 1 else refused += 1;
    }
    var nvec: usize = 0;
    for (vectors_seen) |b| {
        if (b) nvec += 1;
    }
    var nmode: usize = 0;
    for (modes_seen) |b| {
        if (b) nmode += 1;
    }
    var norigin: usize = 0;
    for (origins_seen) |b| {
        if (b) norigin += 1;
    }
    // One seed is deliberately the empty script.
    try testing.expectEqual(registration_seeds.len - 1, nonempty);
    try testing.expectEqual(AllVectors.count, nvec);
    try testing.expectEqual(@as(usize, 4), nmode);
    try testing.expectEqual(@as(usize, 2), norigin);
    try testing.expectEqual(@as(usize, 7), accepted);
    try testing.expectEqual(@as(usize, 11), refused);
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

// ── drift re-audit 2026-09-02 ───────────────────────────────────────────────
//
// Seven of these pin checks that ALREADY existed and that a mutation could
// delete with the suite green — the corpus is structurally blind to them
// (every §16 registration vector has UP=1 and ED=0, none carries an illegal
// BE/BS pair, none has more than one `x5c` element). The rest pin new rules.

/// A copy of `raw` with its flags byte (offset 32) replaced.
fn withFlags(a: std.mem.Allocator, raw: []const u8, flags: u8) ![]u8 {
    const out = try a.dupe(u8, raw);
    out[32] = flags;
    return out;
}

test "registration: User Present cleared is refused (re-audit F5 — the check had no teeth)" {
    // SPEC said "every check below is proven load-bearing by a dedicated
    // adversarial test" and named User Present. That was true of the
    // ASSERTION check only: every §16 registration vector has UP set, and
    // `fuzzRegistrationBinding` only ever feeds real vectors, so its
    // `expect(result.flags.user_present)` oracle held unconditionally. The
    // registration check could be deleted with 55/55 green.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const auth_data = try extractAuthDataRaw(a, &v.attestation_object);
    // UP is bit 0; keep AT (bit 6) so the object still parses that far.
    const cleared = try withFlags(a, auth_data, auth_data[32] & ~@as(u8, 0x01));
    const obj = try buildAttestationObject(a, .{
        .fmt = "none",
        .alg = cbor.cose.alg_es256,
        .x5c = null,
        .sig = &.{},
        .auth_data = cleared,
    });
    try testing.expectError(error.UserNotPresent, webauthn.verifyRegistration(
        a,
        obj,
        &v.registration_client_data_json,
        .{
            .rp_id = "example.org",
            .expected_challenge = &v.registration_challenge,
            .expected_origin = "https://example.org",
        },
    ));
}

test "authData: BE=0 with BS=1 is refused (re-audit F6 — §6.1 / §7.1 step 11)" {
    // An authenticator state the spec forbids, passed straight through
    // before: an RP with a passkey-portability policy read an incoherent
    // pair out of `result.flags` that this verifier had accepted.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const auth_data = try extractAuthDataRaw(a, &v.attestation_object);
    // BE is bit 3 (0x08), BS is bit 4 (0x10): clear BE, set BS.
    const bad = try withFlags(a, auth_data, (auth_data[32] & ~@as(u8, 0x08)) | 0x10);
    try testing.expectError(
        error.BackupStateInconsistent,
        webauthn.parseAuthenticatorData(a, bad),
    );
    // Every legal combination still parses.
    for ([_]u8{ 0x00, 0x08, 0x18 }) |be_bs| {
        const ok = try withFlags(a, auth_data, (auth_data[32] & ~@as(u8, 0x18)) | be_bs);
        _ = try webauthn.parseAuthenticatorData(a, ok);
    }
}

test "authData: the extension-data rejection has teeth in both branches (re-audit F8)" {
    // `error.ExtensionsNotSupported` is documented as "a structural, typed
    // rejection, not a silent misparse" and as "proven by the adversarial
    // test suite". Every §16 vector has ED=0, and no synthetic ED-set input
    // existed anywhere, so both branches could be deleted with 55/55 green.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const auth_data = try extractAuthDataRaw(a, &v.attestation_object);
    // ED is bit 7 (0x80). With AT set (the attested-credential branch)...
    const with_at = try withFlags(a, auth_data, auth_data[32] | 0x80);
    try testing.expectError(
        error.ExtensionsNotSupported,
        webauthn.parseAuthenticatorData(a, with_at),
    );
    // ...and with AT clear (the other branch), on a bare 37-byte authData.
    const bare = try a.dupe(u8, auth_data[0..37]);
    bare[32] = (bare[32] & ~@as(u8, 0x40)) | 0x80;
    try testing.expectError(
        error.ExtensionsNotSupported,
        webauthn.parseAuthenticatorData(a, bare),
    );
}

test "authData: credentialIdLength is capped at 1023 (re-audit F13 — §6.5.2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const auth_data = try extractAuthDataRaw(a, &v.attestation_object);
    const oversized = try a.alloc(u8, 55 + 2000);
    @memcpy(oversized[0..55], auth_data[0..55]);
    @memset(oversized[55..], 0);
    std.mem.writeInt(u16, oversized[53..55], 2000, .big);
    try testing.expectError(
        error.CredentialIdTooLong,
        webauthn.parseAuthenticatorData(a, oversized),
    );
    // The boundary itself, from both sides.
    const at_cap = try a.alloc(u8, 55 + webauthn.max_credential_id_len + 8);
    @memcpy(at_cap[0..55], auth_data[0..55]);
    @memset(at_cap[55..], 0);
    std.mem.writeInt(u16, at_cap[53..55], webauthn.max_credential_id_len, .big);
    // Refused for a reason that is NOT the length cap (the trailing bytes are
    // not a COSE key) — which is exactly what proves the cap let it through.
    try testing.expect(webauthn.parseAuthenticatorData(a, at_cap) != error.CredentialIdTooLong);
    std.mem.writeInt(u16, at_cap[53..55], webauthn.max_credential_id_len + 1, .big);
    try testing.expectError(
        error.CredentialIdTooLong,
        webauthn.parseAuthenticatorData(a, at_cap),
    );
}

test "credential key: duplicate COSE labels are refused (re-audit F2)" {
    // The RSA arm returned before `cbor.cose.parseKey`, so RFC 9052 §3's
    // uniqueness MUST — and the `max_map_entries` cap `cbor` added for this
    // exact caller — silently did not apply to it. A modulus this verifier
    // reads first-wins and a `python-fido2` peer reads last-wins is a
    // credential-identity split.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const n1 = [_]u8{0xC1} ** 256;
    const n2 = [_]u8{0xD2} ** 256;
    const e = [_]u8{ 0x01, 0x00, 0x01 };
    const rsa_dup = [_]cbor.MapEntry{
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 3 } }, // kty: RSA
        .{ .key = .{ .negint = 0 }, .value = .{ .bytes = &n1 } }, // -1: n
        .{ .key = .{ .negint = 0 }, .value = .{ .bytes = &n2 } }, // -1: n AGAIN
        .{ .key = .{ .negint = 1 }, .value = .{ .bytes = &e } }, // -2: e
    };
    try testing.expectError(
        error.DuplicateLabel,
        webauthn.parseCredentialKey(.{ .map = &rsa_dup }),
    );

    // A duplicated `kty` — which decides WHICH arm runs — is caught too.
    const kty_dup = [_]cbor.MapEntry{
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 3 } },
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 2 } },
        .{ .key = .{ .negint = 0 }, .value = .{ .bytes = &n1 } },
        .{ .key = .{ .negint = 1 }, .value = .{ .bytes = &e } },
    };
    try testing.expectError(
        error.DuplicateLabel,
        webauthn.parseCredentialKey(.{ .map = &kty_dup }),
    );

    // ...and the entry cap applies to the RSA arm now, not just EC2/OKP.
    const many = try a.alloc(cbor.MapEntry, cbor.cose.max_map_entries + 2);
    many[0] = .{ .key = .{ .uint = 1 }, .value = .{ .uint = 3 } };
    for (many[1..], 0..) |*m, i| {
        m.* = .{ .key = .{ .uint = @intCast(100 + i) }, .value = .{ .uint = 0 } };
    }
    try testing.expectError(
        error.TooManyEntries,
        webauthn.parseCredentialKey(.{ .map = many }),
    );
}

test "attestationObject: duplicate top-level keys are refused (re-audit F12)" {
    // `{fmt:"none", fmt:"tpm", authData:A, authData:B}` was accepted
    // first-wins, so WHICH `authData` this verifier signs over was a
    // parser-differential away from what another implementation reads.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const auth_data = try extractAuthDataRaw(a, &v.attestation_object);
    const decoy = try a.alloc(u8, 40);
    @memset(decoy, 0);
    const entries = [_]cbor.MapEntry{
        .{ .key = .{ .text = "fmt" }, .value = .{ .text = "none" } },
        .{ .key = .{ .text = "fmt" }, .value = .{ .text = "tpm" } },
        .{ .key = .{ .text = "attStmt" }, .value = .{ .map = &.{} } },
        .{ .key = .{ .text = "authData" }, .value = .{ .bytes = auth_data } },
        .{ .key = .{ .text = "authData" }, .value = .{ .bytes = decoy } },
    };
    const obj = try cbor.encode(a, .{ .map = &entries }, .{});
    try testing.expectError(error.DuplicateLabel, webauthn.verifyRegistration(
        a,
        obj,
        &v.registration_client_data_json,
        .{
            .rp_id = "example.org",
            .expected_challenge = &v.registration_challenge,
            .expected_origin = "https://example.org",
        },
    ));
}

test "require_attestation is not satisfied by SELF attestation (re-audit F3)" {
    // A self-attested statement is signed by the credential's own key, so
    // anything an attacker generates in a browser satisfies it — and it
    // leaves `leaf_cert_der = null`, so the follow-up the option's own doc
    // recommends is not even available.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_self_es256;
    const opts: webauthn.RegistrationOptions = .{
        .rp_id = "example.org",
        .expected_challenge = &v.registration_challenge,
        .expected_origin = "https://example.org",
    };
    // Without the flag it still verifies, and still reports what it is.
    {
        const r = try webauthn.verifyRegistration(a, &v.attestation_object, &v.registration_client_data_json, opts);
        try testing.expectEqual(webauthn.AttestationType.self_attestation, r.attestation_type);
        try testing.expect(r.leaf_cert_der == null);
    }
    var strict = opts;
    strict.require_attestation = true;
    try testing.expectError(error.AttestationNotProvided, webauthn.verifyRegistration(
        a,
        &v.attestation_object,
        &v.registration_client_data_json,
        strict,
    ));
    // ...and a real basic attestation still passes the same flag.
    {
        const b = vectors.packed_es256_full;
        var basic_strict: webauthn.RegistrationOptions = .{
            .rp_id = "example.org",
            .expected_challenge = &b.registration_challenge,
            .expected_origin = "https://example.org",
            .require_attestation = true,
        };
        const r = try webauthn.verifyRegistration(a, &b.attestation_object, &b.registration_client_data_json, basic_strict);
        try testing.expectEqual(webauthn.AttestationType.basic, r.attestation_type);
        basic_strict.require_attestation = false;
        _ = try webauthn.verifyRegistration(a, &b.attestation_object, &b.registration_client_data_json, basic_strict);
    }
}

test "allowed_algorithms implements §7.1 step 14 (re-audit F7)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    var opts: webauthn.RegistrationOptions = .{
        .rp_id = "example.org",
        .expected_challenge = &v.registration_challenge,
        .expected_origin = "https://example.org",
    };
    // Default: the step is skipped, as before.
    _ = try webauthn.verifyRegistration(a, &v.attestation_object, &v.registration_client_data_json, opts);
    // Offered: the credential's ES256 is in the list.
    opts.allowed_algorithms = &.{ cbor.cose.alg_es256, cbor.cose.alg_eddsa };
    _ = try webauthn.verifyRegistration(a, &v.attestation_object, &v.registration_client_data_json, opts);
    // Not offered: refused.
    opts.allowed_algorithms = &.{cbor.cose.alg_eddsa};
    try testing.expectError(error.AlgorithmNotAllowed, webauthn.verifyRegistration(
        a,
        &v.attestation_object,
        &v.registration_client_data_json,
        opts,
    ));
    // An empty list offers nothing, and refuses everything.
    opts.allowed_algorithms = &.{};
    try testing.expectError(error.AlgorithmNotAllowed, webauthn.verifyRegistration(
        a,
        &v.attestation_object,
        &v.registration_client_data_json,
        opts,
    ));
}

test "fido-u2f: x5c must hold exactly one element (re-audit F11 — §8.6 step 2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.fido_u2f_es256;
    const auth_data = try extractAuthDataRaw(a, &v.attestation_object);
    const leaf = try realX5c(a, &v.attestation_object);

    // Two elements: refused, where before the extra ones were ignored.
    const arr = try a.alloc(cbor.Value, 2);
    arr[0] = .{ .bytes = leaf };
    arr[1] = .{ .bytes = &[_]u8{ 0xde, 0xad } };
    const att = [_]cbor.MapEntry{
        .{ .key = .{ .text = "sig" }, .value = .{ .bytes = &[_]u8{0} ** 8 } },
        .{ .key = .{ .text = "x5c" }, .value = .{ .array = arr } },
    };
    const entries = [_]cbor.MapEntry{
        .{ .key = .{ .text = "fmt" }, .value = .{ .text = "fido-u2f" } },
        .{ .key = .{ .text = "attStmt" }, .value = .{ .map = &att } },
        .{ .key = .{ .text = "authData" }, .value = .{ .bytes = auth_data } },
    };
    const obj = try cbor.encode(a, .{ .map = &entries }, .{});
    try testing.expectError(error.InvalidAttestationStatement, webauthn.verifyAttestation(
        a,
        obj,
        clientDataHash(&v.registration_client_data_json),
    ));
    // The real one-element vector still verifies.
    _ = try webauthn.verifyAttestation(a, &v.attestation_object, clientDataHash(&v.registration_client_data_json));
}

test "x5c: an EMPTY array is refused rather than indexed (re-audit F10)" {
    // A memory-safety guard with no test: without it `arr[0]` on `x5c: []`
    // is an out-of-bounds index — a Debug panic, and in ReleaseFast a read of
    // whatever follows, on fully client-supplied bytes.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_es256_full;
    const auth_data = try extractAuthDataRaw(a, &v.attestation_object);
    for ([_][]const u8{ "packed", "fido-u2f" }) |fmt| {
        const att = [_]cbor.MapEntry{
            .{ .key = .{ .text = "alg" }, .value = .{ .negint = 6 } }, // -7 = ES256
            .{ .key = .{ .text = "sig" }, .value = .{ .bytes = &[_]u8{0} ** 8 } },
            .{ .key = .{ .text = "x5c" }, .value = .{ .array = &.{} } },
        };
        const entries = [_]cbor.MapEntry{
            .{ .key = .{ .text = "fmt" }, .value = .{ .text = fmt } },
            .{ .key = .{ .text = "attStmt" }, .value = .{ .map = &att } },
            .{ .key = .{ .text = "authData" }, .value = .{ .bytes = auth_data } },
        };
        const obj = try cbor.encode(a, .{ .map = &entries }, .{});
        try testing.expectError(error.MissingField, webauthn.verifyAttestation(
            a,
            obj,
            clientDataHash(&v.registration_client_data_json),
        ));
    }
}

test "AttestationResult.dupe survives the verification arena being recycled (re-audit F1)" {
    // The README told an RP to persist `credential_public_key` and
    // `credential_id`. Both are arena-owned — `cbor.decode` dupes every byte
    // string into the allocator, so they do not even alias the caller's
    // `attestation_object_raw`. With the per-request arena the README itself
    // showed, a stored key became pointers into recycled heap and every later
    // login verified against whatever the next request wrote there.
    const v = vectors.none_es256;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const stored = blk: {
        const a = arena.allocator();
        const r = try webauthn.verifyRegistration(a, &v.attestation_object, &v.registration_client_data_json, .{
            .rp_id = "example.org",
            .expected_challenge = &v.registration_challenge,
            .expected_origin = "https://example.org",
        });
        break :blk try r.dupe(testing.allocator);
    };
    defer stored.deinit(testing.allocator);

    // Recycle the arena the way the next request would, and scribble on it.
    _ = arena.reset(.retain_capacity);
    const scratch = try arena.allocator().alloc(u8, 8192);
    @memset(scratch, 0xAA);

    // The stored copy is still the credential that registered — and is what
    // the next login verifies against.
    try testing.expectEqualSlices(u8, &v.credential_id, stored.credential_id);
    try testing.expectEqualStrings("none", stored.format);
    const x = stored.credential_public_key.ec2.x;
    try testing.expect(x[0] != 0xAA);
    var verify_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer verify_arena.deinit();
    _ = try webauthn.verifyAssertion(
        verify_arena.allocator(),
        &v.authenticator_data,
        &v.assertion_client_data_json,
        &v.signature,
        stored.credential_public_key,
        .{
            .rp_id = "example.org",
            .expected_challenge = &v.assertion_challenge,
            .expected_origin = "https://example.org",
        },
    );
}

test "packed x5c: the attStmt alg must agree with the certificate's own key (re-audit F9)" {
    // SPEC names this "the algorithm-confusion defense … the same class of
    // bug JWT's `alg: none` made infamous", and cites a test that swaps the
    // KEY — which pins the `crv`/`kty` half only. The `alg` cross-check
    // itself could be deleted in all four places with the suite green.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_es256_full;
    const auth_data = try extractAuthDataRaw(a, &v.attestation_object);
    const leaf = try realX5c(a, &v.attestation_object);

    // A genuine ES256 attestation certificate, declared as RS256 and as
    // EdDSA. The EC arm must refuse on the declared algorithm alone.
    for ([_]i64{ webauthn.alg_rs256, cbor.cose.alg_eddsa }) |wrong| {
        const obj = try buildAttestationObject(a, .{
            .fmt = "packed",
            .alg = wrong,
            .x5c = leaf,
            .sig = &[_]u8{0} ** 8,
            .auth_data = auth_data,
        });
        try testing.expectError(error.UnsupportedAlgorithm, webauthn.verifyAttestation(
            a,
            obj,
            clientDataHash(&v.registration_client_data_json),
        ));
    }
    // The truthful declaration still reaches signature verification (and
    // fails there on the bogus signature, not on the algorithm).
    const honest = try buildAttestationObject(a, .{
        .fmt = "packed",
        .alg = cbor.cose.alg_es256,
        .x5c = leaf,
        .sig = &[_]u8{0} ** 8,
        .auth_data = auth_data,
    });
    const err = webauthn.verifyAttestation(a, honest, clientDataHash(&v.registration_client_data_json));
    try testing.expect(err != error.UnsupportedAlgorithm);
}

test "packed x5c: an attestation certificate below the RSA modulus floor is refused (re-audit F14)" {
    // The 2026-08-06 audit's F7 put a 2048-bit floor on the CREDENTIAL key
    // and not on the attestation certificate's. Nothing recorded that
    // asymmetry as a decision, and the corpus has no undersized attestation
    // key to notice it — so this vector is synthetic (see vectors.zig).
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_es256_full;
    const auth_data = try extractAuthDataRaw(a, &v.attestation_object);
    const obj = try buildAttestationObject(a, .{
        .fmt = "packed",
        .alg = webauthn.alg_rs256,
        .x5c = &vectors.weak_rsa_attestation_cert_der,
        .sig = &[_]u8{0} ** 128,
        .auth_data = auth_data,
    });
    try testing.expectError(error.InvalidKey, webauthn.verifyAttestation(
        a,
        obj,
        clientDataHash(&v.registration_client_data_json),
    ));
}
