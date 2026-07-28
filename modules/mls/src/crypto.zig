// SPDX-License-Identifier: MIT
//! mls.crypto — the labeled-crypto primitives RFC 9420 §5 builds every
//! higher-level MLS derivation on: `RefHash`/`MakeKeyPackageRef`/
//! `MakeProposalRef` (§5.2), `ExpandWithLabel`/`DeriveSecret` (§8),
//! `DeriveTreeSecret` (§9.1), `SignWithLabel`/`VerifyWithLabel` (§5.1.2),
//! and `EncryptWithLabel`/`DecryptWithLabel` (§5.1.3). Every later MLS
//! part (key schedule, TreeKEM, framing) is built ENTIRELY out of these
//! seven functions plus `treemath.zig` — nothing here is provisional.
//!
//! Two of MLS's own label-framing structs (`KDFLabel`, `SignContent`,
//! `EncryptContext` — RFC 9420 §8/§5.1.2/§5.1.3) look superficially like
//! `hpke.suite`'s `LabeledExtract`/`LabeledExpand` but are a SEPARATE wire
//! encoding, not a call into HPKE's own labeling: HPKE's construction
//! prepends `"HPKE-v1" || suite_id`; MLS's prepends nothing but writes its
//! own `KDFLabel`/`SignContent`/`EncryptContext` struct (via
//! `codec.Writer`) and calls `KDF.Expand`/the signature scheme DIRECTLY.
//! The one place this file DOES hand off to `hpke` wholesale is
//! `EncryptWithLabel`/`DecryptWithLabel` (RFC 9420 §5.1.3: "The functions
//! SealBase and OpenBase are defined in Section 6.1 of [RFC9180]") — MLS's
//! own label framing there becomes HPKE's `info` parameter, and HPKE then
//! applies ITS OWN "HPKE-v1"+suite_id labeling around that on top; the two
//! layers compose, they don't collide.
//!
//! Scratch-buffer note: `ExpandWithLabel`/`SignWithLabel`/`VerifyWithLabel`/
//! `EncryptWithLabel`/`DecryptWithLabel` each assemble ONE contiguous
//! label-framing buffer on the stack (`label_scratch_len` bytes) before
//! calling into the KDF/signature/HPKE primitive — the same fixed-buffer-
//! plus-typed-error shape `hpke.suite.labeledExpand` uses for its own
//! "HPKE-v1"+suite_id+label+info assembly, for the identical reason
//! (`Hkdf.expand`/`Ed25519.sign`/HPKE's `info` all need ONE contiguous
//! slice, not a streamed multi-call). `label_scratch_len` (512 bytes,
//! matching `hpke`'s own constant) comfortably covers every label this
//! Part or the KAT vectors use; a LATER part deriving a secret from a
//! multi-kilobyte `GroupContext` (extensions included) may need a larger
//! bound or a caller-supplied scratch slice — tracked in `SPEC.md`'s
//! backlog, not a Part 1 gap for anything exercised here.
//!
//! Model: RFC 9420 §5.1.2 (`SignWithLabel`/`VerifyWithLabel`), §5.1.3
//! (`EncryptWithLabel`/`DecryptWithLabel`), §5.2 (`RefHash`/
//! `MakeKeyPackageRef`/`MakeProposalRef`), §8 (`ExpandWithLabel`/
//! `DeriveSecret`), §9.1 (`DeriveTreeSecret`).

const std = @import("std");
const hpke = @import("hpke");
const codec = @import("codec.zig");
const suite = @import("suite.zig");

/// The `"MLS 1.0 "` prefix RFC 9420 prepends to every `Label` argument of
/// `ExpandWithLabel`/`SignWithLabel`/`EncryptWithLabel` (NOT `RefHash` —
/// see that function's doc comment). Note the trailing space — it's part
/// of the literal per RFC 9420 §5.1.2/§5.1.3/§8 ("label = 'MLS 1.0 ' +
/// Label").
pub const mls10_label_prefix = "MLS 1.0 ";

/// See this file's module doc comment's "Scratch-buffer note".
const label_scratch_len: usize = 512;

pub const Error = error{
    /// The assembled label-framing buffer (`KDFLabel`/`SignContent`/
    /// `EncryptContext`) didn't fit `label_scratch_len` bytes — see the
    /// module doc comment's scratch-buffer note.
    LabelTooLong,
    /// `RefHash`'s `label`/`value` byte length exceeds
    /// `codec.varint.max_value` (2^30 - 1) and cannot be varint-length-
    /// prefixed at all.
    ValueTooLarge,
} || codec.Error;

// ── §5.2: RefHash / MakeKeyPackageRef / MakeProposalRef ──────────────────

/// RFC 9420 §5.2 `RefHash(label, value) = Hash(RefHashInput)` where
/// `RefHashInput { opaque label<V>; opaque value<V>; }`. Unlike
/// `ExpandWithLabel`/`SignWithLabel`/`EncryptWithLabel`, `label` here is
/// used EXACTLY as passed — NO `"MLS 1.0 "` prefix is added by this
/// function itself (the concrete callers below, `make_keypackage_ref`/
/// `make_proposal_ref`, pass the full `"MLS 1.0 ... Reference"` string
/// literal, matching RFC 9420 §5.2's own `MakeKeyPackageRef`/
/// `MakeProposalRef` definitions verbatim).
///
/// Streams both fields through the hash incrementally (varint length
/// prefix, then the bytes, per field) rather than assembling a
/// contiguous buffer first — `value` is an entire encoded `KeyPackage`/
/// `AuthenticatedContent` in real use and has no fixed upper bound the
/// way `ExpandWithLabel`'s label/context do, so (unlike this file's other
/// label-framing functions) `RefHash` needs no `label_scratch_len` bound
/// at all.
pub fn RefHash(comptime S: type, label: []const u8, value: []const u8) Error![S.Hash.digest_length]u8 {
    var h = S.Hash.init(.{});
    try hashOpaqueVector(S.Hash, &h, label);
    try hashOpaqueVector(S.Hash, &h, value);
    var out: [S.Hash.digest_length]u8 = undefined;
    h.final(&out);
    return out;
}

fn hashOpaqueVector(comptime Hash: type, h: *Hash, bytes: []const u8) Error!void {
    var len_buf: [4]u8 = undefined;
    const len_enc = codec.varint.encode(bytes.len, &len_buf) catch return error.ValueTooLarge;
    h.update(len_enc);
    h.update(bytes);
}

/// RFC 9420 §5.2 `MakeKeyPackageRef(value) = RefHash("MLS 1.0 KeyPackage
/// Reference", value)`. `encoded_key_package` is a fully wire-encoded
/// `KeyPackage` (a later part's `codec`-serialized form) — opaque bytes to
/// this function.
pub fn make_keypackage_ref(comptime S: type, encoded_key_package: []const u8) Error![S.Hash.digest_length]u8 {
    return RefHash(S, "MLS 1.0 KeyPackage Reference", encoded_key_package);
}

/// RFC 9420 §5.2 `MakeProposalRef(value) = RefHash("MLS 1.0 Proposal
/// Reference", value)`. `encoded_authenticated_content` is a fully
/// wire-encoded `AuthenticatedContent` carrying a `Proposal` (a later
/// part's concern) — opaque bytes to this function.
pub fn make_proposal_ref(comptime S: type, encoded_authenticated_content: []const u8) Error![S.Hash.digest_length]u8 {
    return RefHash(S, "MLS 1.0 Proposal Reference", encoded_authenticated_content);
}

// ── §8: ExpandWithLabel / DeriveSecret ────────────────────────────────────

/// Assembles `KDFLabel { uint16 length; opaque label<V>; opaque
/// context<V>; }` (RFC 9420 §8) into `buf`: `length = Length`, `label =
/// "MLS 1.0 " ++ Label`, `context = Context`. Shared by `ExpandWithLabel`
/// (the only caller) — pulled out so the wire-encoding recipe has exactly
/// one implementation.
fn encodeKdfLabel(buf: []u8, length: u16, label: []const u8, context: []const u8) codec.Error![]const u8 {
    var w = codec.Writer.init(buf);
    try w.writeU16(length);
    try w.writeVectorConcat(&.{ mls10_label_prefix, label });
    try w.writeVector(context);
    return w.finish();
}

/// The exact number of bytes `encodeKdfLabel` will write for this
/// (`label`, `context`) pair — i.e. the smallest scratch buffer
/// `ExpandWithLabelScratch` can succeed with. Exposed because the KEY
/// SCHEDULE (RFC 9420 §8) derives `joiner_secret`/`epoch_secret` with a
/// serialized `GroupContext` as `Context`, and a `GroupContext` carrying
/// group extensions has NO fixed upper bound — exactly the case this
/// file's module doc comment flagged as needing more than
/// `label_scratch_len`. Returns `error.VarintTooLarge` if either field is
/// too long to be varint-length-prefixed at all.
pub fn kdfLabelLen(label: []const u8, context: []const u8) Error!usize {
    const full_label_len = mls10_label_prefix.len + label.len;
    return 2 // uint16 length
    + try codec.varint.encodedLen(full_label_len) + full_label_len +
        try codec.varint.encodedLen(context.len) + context.len;
}

/// `ExpandWithLabel` over a CALLER-SUPPLIED scratch buffer, for contexts
/// with no compile-time size bound (a serialized `GroupContext`). Size
/// `scratch` with `kdfLabelLen(label, context)`; anything smaller yields
/// `error.LabelTooLong`.
pub fn ExpandWithLabelScratch(
    comptime S: type,
    secret: [S.Nh]u8,
    label: []const u8,
    context: []const u8,
    out: []u8,
    scratch: []u8,
) Error!void {
    const length = std.math.cast(u16, out.len) orelse return error.LabelTooLong;
    const info = encodeKdfLabel(scratch, length, label, context) catch return error.LabelTooLong;
    S.Hkdf.expand(out, info, secret);
}

/// RFC 9420 §8 `ExpandWithLabel(Secret, Label, Context, Length) =
/// KDF.Expand(Secret, KDFLabel, Length)`. Writes exactly `out.len` bytes
/// (`Length = out.len`). Uses this file's fixed `label_scratch_len` stack
/// buffer — see `ExpandWithLabelScratch` when `context` can be arbitrarily
/// large.
pub fn ExpandWithLabel(comptime S: type, secret: [S.Nh]u8, label: []const u8, context: []const u8, out: []u8) Error!void {
    var buf: [label_scratch_len]u8 = undefined;
    return ExpandWithLabelScratch(S, secret, label, context, out, &buf);
}

/// RFC 9420 §8 `DeriveSecret(Secret, Label) = ExpandWithLabel(Secret,
/// Label, "", KDF.Nh)`.
pub fn DeriveSecret(comptime S: type, secret: [S.Nh]u8, label: []const u8) Error![S.Nh]u8 {
    var out: [S.Nh]u8 = undefined;
    try ExpandWithLabel(S, secret, label, "", &out);
    return out;
}

// ── §9.1: DeriveTreeSecret ────────────────────────────────────────────────

/// RFC 9420 §9.1 `DeriveTreeSecret(Secret, Label, Generation, Length) =
/// ExpandWithLabel(Secret, Label, Generation, Length)`, where `Generation`
/// is encoded as a big-endian `uint32` (this function's `Context`
/// argument to `ExpandWithLabel`). Used by the (later-part) Secret Tree to
/// derive ratchet keys/nonces/next-generation secrets — defined here per
/// the task brief, ahead of the Secret Tree part itself, since it's pure
/// composition of `ExpandWithLabel` plus one `uint32` encode.
pub fn DeriveTreeSecret(comptime S: type, secret: [S.Nh]u8, label: []const u8, generation: u32, out: []u8) Error!void {
    var ctx: [4]u8 = undefined;
    std.mem.writeInt(u32, &ctx, generation, .big);
    try ExpandWithLabel(S, secret, label, &ctx, out);
}

// ── §5.1.2: SignWithLabel / VerifyWithLabel ───────────────────────────────

/// Assembles `SignContent { opaque label<V>; opaque content<V>; }` (RFC
/// 9420 §5.1.2) into `buf`: `label = "MLS 1.0 " ++ Label`, `content =
/// Content`. Shared by `SignWithLabel`/`VerifyWithLabel`.
fn encodeSignContent(buf: []u8, label: []const u8, content: []const u8) codec.Error![]const u8 {
    var w = codec.Writer.init(buf);
    try w.writeVectorConcat(&.{ mls10_label_prefix, label });
    try w.writeVector(content);
    return w.finish();
}

/// RFC 9420 §5.1.2 `SignWithLabel(SignatureKey, Label, Content) =
/// Signature.Sign(SignatureKey, SignContent)`. Ed25519 signing is
/// DETERMINISTIC (RFC 8032 — no `noise`/hedging is passed to
/// `std.crypto.sign.Ed25519.KeyPair.sign`), so `SignWithLabel` on the same
/// `(key_pair, label, content)` always reproduces the SAME signature
/// bytes — the KAT (`kat_test.zig`) checks this byte-exact against the
/// official vector's `signature` field, not merely a verify-round-trip
/// (which is all a randomized scheme like ECDSA could offer).
/// Error set is INFERRED (like `hpke.sealBase`/`openBase`) — folds in this
/// file's own `Error` (`LabelTooLong`/`ValueTooLarge`/`codec.Error`) plus
/// whatever `S.Sig.KeyPair.sign` itself can fail with (Ed25519:
/// `IdentityElementError`/`NonCanonicalError`/`KeyMismatchError`/
/// `WeakPublicKeyError`) without this file needing to name that set by
/// hand for every possible `S.Sig`.
pub fn SignWithLabel(comptime S: type, key_pair: S.Sig.KeyPair, label: []const u8, content: []const u8) !S.Sig.Signature {
    var buf: [label_scratch_len]u8 = undefined;
    const sign_content = encodeSignContent(&buf, label, content) catch return error.LabelTooLong;
    return key_pair.sign(sign_content, null);
}

/// RFC 9420 §5.1.2 `VerifyWithLabel(VerificationKey, Label, Content,
/// SignatureValue) = Signature.Verify(VerificationKey, SignContent,
/// SignatureValue)`. Error set inferred, see `SignWithLabel`'s doc comment.
pub fn VerifyWithLabel(comptime S: type, public_key: S.Sig.PublicKey, label: []const u8, content: []const u8, signature: S.Sig.Signature) !void {
    var buf: [label_scratch_len]u8 = undefined;
    const sign_content = encodeSignContent(&buf, label, content) catch return error.LabelTooLong;
    try signature.verify(sign_content, public_key);
}

// ── §5.1.3: EncryptWithLabel / DecryptWithLabel ───────────────────────────

/// Assembles `EncryptContext { opaque label<V>; opaque context<V>; }` (RFC
/// 9420 §5.1.3) into `buf`: `label = "MLS 1.0 " ++ Label`, `context =
/// Context`. This becomes HPKE's OWN `info` parameter to `SealBase`/
/// `OpenBase` — HPKE then applies its own "HPKE-v1"+suite_id labeling
/// around it (see the module doc comment).
fn encodeEncryptContext(buf: []u8, label: []const u8, context: []const u8) codec.Error![]const u8 {
    var w = codec.Writer.init(buf);
    try w.writeVectorConcat(&.{ mls10_label_prefix, label });
    try w.writeVector(context);
    return w.finish();
}

/// RFC 9420 §5.1.3 `EncryptWithLabel(PublicKey, Label, Context,
/// Plaintext) = SealBase(PublicKey, EncryptContext, "", Plaintext)` — HPKE
/// base-mode seal (`hpke.sealBase`) with `aad = ""` and `info =
/// EncryptContext`. Writes `out.len == plaintext.len + S.Aead.tag_length`
/// bytes to `ciphertext_out`, matching `hpke.sealBase`'s own contract, and
/// returns the `enc` (ephemeral KEM public key) the caller must transmit
/// alongside the ciphertext.
pub fn EncryptWithLabel(
    comptime S: type,
    pkR: S.Kem.PublicKey,
    io: std.Io,
    label: []const u8,
    context: []const u8,
    plaintext: []const u8,
    ciphertext_out: []u8,
) !S.Kem.EncappedKey {
    var buf: [label_scratch_len]u8 = undefined;
    const info = encodeEncryptContext(&buf, label, context) catch return error.LabelTooLong;
    const sealed = try hpke.sealBase(S.Kem, S.Aead, S.Nh, pkR, io, info, "", plaintext, ciphertext_out);
    return sealed.enc;
}

/// RFC 9420 §5.1.3 `DecryptWithLabel(PrivateKey, Label, Context,
/// KEMOutput, Ciphertext) = OpenBase(KEMOutput, PrivateKey, EncryptContext,
/// "", Ciphertext)` — the receiver mirror of `EncryptWithLabel`.
pub fn DecryptWithLabel(
    comptime S: type,
    enc: S.Kem.EncappedKey,
    skR: S.Kem.KeyPair,
    label: []const u8,
    context: []const u8,
    ciphertext: []const u8,
    plaintext_out: []u8,
) !void {
    var buf: [label_scratch_len]u8 = undefined;
    const info = encodeEncryptContext(&buf, label, context) catch return error.LabelTooLong;
    try hpke.openBase(S.Kem, S.Aead, S.Nh, enc, skR, info, "", ciphertext, plaintext_out);
}

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;
const TestSuite = suite.default;

test "RefHash: empty label/value hashes RefHashInput = 0x00 0x00 (two zero-length varints)" {
    const got = try RefHash(TestSuite, "", "");
    const want = TestSuite.hash(&[_]u8{ 0x00, 0x00 });
    try testing.expectEqualSlices(u8, &want, &got);
}

test "make_keypackage_ref / make_proposal_ref: distinct labels produce distinct refs for the same value" {
    const value = "an encoded object";
    const kp_ref = try make_keypackage_ref(TestSuite, value);
    const prop_ref = try make_proposal_ref(TestSuite, value);
    try testing.expect(!std.mem.eql(u8, &kp_ref, &prop_ref));
    // Deterministic: same (label, value) always the same ref.
    const kp_ref2 = try make_keypackage_ref(TestSuite, value);
    try testing.expectEqualSlices(u8, &kp_ref, &kp_ref2);
}

test "DeriveSecret: equals ExpandWithLabel(secret, label, \"\", Nh)" {
    const secret = [_]u8{0x11} ** TestSuite.Nh;
    const got = try DeriveSecret(TestSuite, secret, "test label");
    var want: [TestSuite.Nh]u8 = undefined;
    try ExpandWithLabel(TestSuite, secret, "test label", "", &want);
    try testing.expectEqualSlices(u8, &want, &got);
}

test "kdfLabelLen: matches what encodeKdfLabel actually writes, and sizes ExpandWithLabelScratch exactly" {
    const secret = [_]u8{0x33} ** TestSuite.Nh;
    // A context far larger than `label_scratch_len` — the GroupContext-with-
    // extensions case `ExpandWithLabel`'s fixed buffer cannot serve.
    const big_context = [_]u8{0xab} ** 4096;
    const label = "epoch";

    const need = try kdfLabelLen(label, &big_context);
    var buf: [4200]u8 = undefined;
    const encoded = try encodeKdfLabel(buf[0..need], 32, label, &big_context);
    try testing.expectEqual(need, encoded.len);

    // The fixed-buffer entry point must REFUSE rather than truncate.
    var out_fixed: [TestSuite.Nh]u8 = undefined;
    try testing.expectError(error.LabelTooLong, ExpandWithLabel(TestSuite, secret, label, &big_context, &out_fixed));

    // The scratch entry point succeeds at exactly `need` bytes, and fails
    // one byte short.
    var out: [TestSuite.Nh]u8 = undefined;
    try ExpandWithLabelScratch(TestSuite, secret, label, &big_context, &out, buf[0..need]);
    try testing.expectError(error.LabelTooLong, ExpandWithLabelScratch(TestSuite, secret, label, &big_context, &out, buf[0 .. need - 1]));
}

test "DeriveTreeSecret: context is the big-endian uint32 generation" {
    const secret = [_]u8{0x22} ** TestSuite.Nh;
    var got: [16]u8 = undefined;
    try DeriveTreeSecret(TestSuite, secret, "key", 0x01020304, &got);
    var want: [16]u8 = undefined;
    try ExpandWithLabel(TestSuite, secret, "key", &[_]u8{ 0x01, 0x02, 0x03, 0x04 }, &want);
    try testing.expectEqualSlices(u8, &want, &got);
}

test "SignWithLabel/VerifyWithLabel: round trip, and a tampered content is rejected" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const kp = TestSuite.Sig.KeyPair.generate(io);

    const sig = try SignWithLabel(TestSuite, kp, "test", "hello, mls");
    try VerifyWithLabel(TestSuite, kp.public_key, "test", "hello, mls", sig);
    try testing.expectError(error.SignatureVerificationFailed, VerifyWithLabel(TestSuite, kp.public_key, "test", "TAMPERED", sig));
    try testing.expectError(error.SignatureVerificationFailed, VerifyWithLabel(TestSuite, kp.public_key, "different label", "hello, mls", sig));
}

test "EncryptWithLabel/DecryptWithLabel: round trip, and a mismatched label fails to decrypt" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const kp = TestSuite.Kem.generateKeyPair(io);

    const pt = "mls encrypt-with-label round trip";
    var ct: [pt.len + TestSuite.Aead.tag_length]u8 = undefined;
    const enc = try EncryptWithLabel(TestSuite, kp.public_key, io, "test", "some context", pt, &ct);

    var out: [pt.len]u8 = undefined;
    try DecryptWithLabel(TestSuite, enc, kp, "test", "some context", &ct, &out);
    try testing.expectEqualSlices(u8, pt, &out);

    try testing.expectError(error.DecryptionFailed, DecryptWithLabel(TestSuite, enc, kp, "WRONG label", "some context", &ct, &out));
}
