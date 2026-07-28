// SPDX-License-Identifier: MIT
//! mls.keypackage — RFC 9420 §10's `KeyPackage`/`KeyPackageTBS` WIRE FORMAT.
//!
//! **Why this file exists in Part 5 (framing) rather than Part 3.** §10 is
//! Part 3's subject, and Part 3 is not what this batch built. But framing
//! cannot decode a `Proposal` without it: §12.1.1's `Add` is literally
//! `struct { KeyPackage key_package; }`, so a `Proposal` decoder that
//! cannot parse a `KeyPackage` cannot parse the single most common
//! proposal type — and every `public_message_proposal` in the official
//! `messages.json` interop vector carries exactly that. So Part 5 builds
//! §10's STRUCTURE (encode/decode/`KeyPackageTBS` signature) because
//! framing carries it, and deliberately builds NONE of §10.1's
//! VALIDATION rules (lifetime freshness, capability/extension consistency,
//! `leaf_node_source == key_package`, init-key/encryption-key
//! distinctness, KeyPackage uniqueness within a Commit). Those are
//! semantic admission checks over a decoded KeyPackage, they need Part 3's
//! credential/Authentication-Service context, and this file asserts
//! nothing about them. `verifySignature` below is the one §10 check that
//! IS here, because it is a pure function of the bytes with no policy
//! content — and because leaving a struct that carries a signature field
//! with no way to check it would invite callers to skip it.
//!
//! Everything the struct is made of already existed: `tree.LeafNode`,
//! `tree.Extension` (Part 2), `crypto.SignWithLabel`/`VerifyWithLabel`
//! (Part 1). This file is the ~60 lines of wire shape between them.
//!
//! Model: RFC 9420 §10 (Key Packages) — the `KeyPackage`/`KeyPackageTBS`
//! structs and §10's `SignWithLabel(., "KeyPackageTBS", KeyPackageTBS)`
//! signature rule; §5.2's `MakeKeyPackageRef` lives in `crypto.zig`
//! already. Anchored by `kat_messages_test.zig`, which drives every
//! `add_proposal` and `mls_key_package` field of the official
//! `messages.json` interop vector through decode→re-encode byte-exact.

const std = @import("std");
const codec = @import("codec.zig");
const crypto = @import("crypto.zig");
const suite = @import("suite.zig");
const tree = @import("tree.zig");
const wire = @import("wire_lists.zig");
const keyschedule = @import("keyschedule.zig");

const varintLen = wire.varintLen;

pub const Error = tree.Error;

/// The label RFC 9420 §10 signs a `KeyPackageTBS` under. Named rather than
/// inlined so the signer and the verifier below read it from one place.
pub const label_tbs = "KeyPackageTBS";

/// RFC 9420 §10's `KeyPackage`. Every byte field ALIASES caller memory;
/// only `decode` allocates, and only for the nested lists (`leaf_node`'s
/// credential/capabilities/extensions and this struct's own `extensions`)
/// — the same no-copy convention `tree.LeafNode` follows.
///
/// `KeyPackageTBS` is not a separate Zig type: it is exactly this struct
/// minus `signature`, so it is expressed as `tbsEncodedLen`/`tbsEncode`
/// here the way `tree.LeafNode` expresses `LeafNodeTBS`. Keeping one
/// struct means the signed bytes cannot drift from the transmitted bytes
/// through a field added to one and not the other.
pub const KeyPackage = struct {
    version: keyschedule.ProtocolVersion = .mls10,
    cipher_suite: suite.CipherSuiteId,
    /// An HPKE public key (`opaque<V>` on the wire) — the key a `Welcome`
    /// is encrypted to. Distinct from `leaf_node.encryption_key`.
    init_key: []const u8,
    leaf_node: tree.LeafNode,
    extensions: []const tree.Extension = &.{},
    signature: []const u8,

    fn tbsBodyLen(self: KeyPackage) usize {
        return 2 // ProtocolVersion
        + 2 // CipherSuite
        + varintLen(self.init_key.len) + self.init_key.len +
            self.leaf_node.encodedLen() +
            wire.varVecLen(tree.Extension, self.extensions);
    }

    pub fn encodedLen(self: KeyPackage) usize {
        return self.tbsBodyLen() + varintLen(self.signature.len) + self.signature.len;
    }

    /// RFC 9420 §10's `KeyPackageTBS` — every field except `signature`.
    pub fn tbsEncodedLen(self: KeyPackage) usize {
        return self.tbsBodyLen();
    }

    pub fn tbsEncode(self: KeyPackage, w: *codec.Writer) Error!void {
        try w.writeEnum(keyschedule.ProtocolVersion, self.version);
        try w.writeEnum(suite.CipherSuiteId, self.cipher_suite);
        try w.writeVector(self.init_key);
        try self.leaf_node.encode(w);
        try wire.encodeVarVec(tree.Extension, w, self.extensions);
    }

    pub fn encode(self: KeyPackage, w: *codec.Writer) Error!void {
        try self.tbsEncode(w);
        try w.writeVector(self.signature);
    }

    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !KeyPackage {
        const version = try r.readEnum(keyschedule.ProtocolVersion);
        const cs = try r.readEnum(suite.CipherSuiteId);
        const init_key = try r.readVector();
        const leaf_node = try tree.LeafNode.decode(allocator, r);
        errdefer leaf_node.deinit(allocator);
        const extensions = try tree.decodeExtensionList(allocator, r);
        errdefer allocator.free(extensions);
        const signature = try r.readVector();
        return .{
            .version = version,
            .cipher_suite = cs,
            .init_key = init_key,
            .leaf_node = leaf_node,
            .extensions = extensions,
            .signature = signature,
        };
    }

    pub fn deinit(self: KeyPackage, allocator: std.mem.Allocator) void {
        self.leaf_node.deinit(allocator);
        allocator.free(self.extensions);
    }

    /// Serializes into a freshly allocated slice (caller frees) — what
    /// `crypto.make_keypackage_ref` (§5.2) needs as input.
    pub fn encodeAlloc(self: KeyPackage, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, self.encodedLen());
        errdefer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.encode(&w);
        std.debug.assert(w.finish().len == buf.len);
        return buf;
    }

    /// RFC 9420 §10: `VerifyWithLabel(leaf_node.signature_key,
    /// "KeyPackageTBS", KeyPackageTBS, signature)`. The verification key is
    /// the LEAF NODE's `signature_key` (§10: "The whole structure is signed
    /// using the client's signature key") — not a separate KeyPackage key,
    /// which is why a KeyPackage is self-verifying but says nothing about
    /// whether that key is one the Authentication Service vouches for
    /// (§10.1/Part 3's job).
    ///
    /// Only suite `0x0001` (Ed25519) is wired, so a `signature_key`/
    /// `signature` of any other length is `error.WrongKeyLength` — mirrors
    /// `tree.LeafNode.verifySignature`'s handling exactly.
    pub fn verifySignature(self: KeyPackage, comptime S: type, allocator: std.mem.Allocator) !void {
        if (self.leaf_node.signature_key.len != 32) return error.WrongKeyLength;
        if (self.signature.len != 64) return error.WrongKeyLength;
        const buf = try allocator.alloc(u8, self.tbsEncodedLen());
        defer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.tbsEncode(&w);

        var pk_bytes: [32]u8 = undefined;
        @memcpy(&pk_bytes, self.leaf_node.signature_key);
        const pk = try S.Sig.PublicKey.fromBytes(pk_bytes);
        var sig_bytes: [64]u8 = undefined;
        @memcpy(&sig_bytes, self.signature);
        try crypto.VerifyWithLabel(S, pk, label_tbs, w.finish(), S.Sig.Signature.fromBytes(sig_bytes));
    }

    /// The signing counterpart of `verifySignature`: produces the
    /// `signature` field for an otherwise-complete `KeyPackage`. The
    /// caller stores the returned bytes and sets `signature` to them —
    /// this function does not mutate `self`, because `signature` aliases
    /// caller memory and this file owns no allocation policy for it.
    pub fn sign(self: KeyPackage, comptime S: type, allocator: std.mem.Allocator, key_pair: S.Sig.KeyPair) !S.Sig.Signature {
        const buf = try allocator.alloc(u8, self.tbsEncodedLen());
        defer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.tbsEncode(&w);
        return crypto.SignWithLabel(S, key_pair, label_tbs, w.finish());
    }
};

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;
const TestSuite = suite.default;

fn sampleLeaf() tree.LeafNode {
    return .{
        .encryption_key = &[_]u8{0xaa} ** 32,
        .signature_key = &[_]u8{0xbb} ** 32,
        .credential = .{ .basic = "alice" },
        .capabilities = .{
            .versions = &[_]u16{1},
            .cipher_suites = &[_]u16{1},
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &[_]u16{1},
        },
        .leaf_node_source = .key_package,
        .lifetime = .{ .not_before = 0, .not_after = 1 },
        .extensions = &.{},
        .signature = &[_]u8{0xcc} ** 64,
    };
}

test "KeyPackage: encodedLen matches what encode actually writes, and decode round-trips" {
    const kp: KeyPackage = .{
        .cipher_suite = TestSuite.id,
        .init_key = &[_]u8{0xdd} ** 32,
        .leaf_node = sampleLeaf(),
        .extensions = &.{},
        .signature = &[_]u8{0xee} ** 64,
    };
    const bytes = try kp.encodeAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    try testing.expectEqual(kp.encodedLen(), bytes.len);

    var r = codec.Reader.init(bytes);
    const back = try KeyPackage.decode(testing.allocator, &r);
    defer back.deinit(testing.allocator);
    try testing.expect(r.atEnd());
    try testing.expectEqual(kp.version, back.version);
    try testing.expectEqual(kp.cipher_suite, back.cipher_suite);
    try testing.expectEqualSlices(u8, kp.init_key, back.init_key);
    try testing.expectEqualSlices(u8, kp.signature, back.signature);
    try testing.expectEqualSlices(u8, kp.leaf_node.encryption_key, back.leaf_node.encryption_key);

    const re = try back.encodeAlloc(testing.allocator);
    defer testing.allocator.free(re);
    try testing.expectEqualSlices(u8, bytes, re);
}

test "KeyPackage: sign then verify, and a flipped TBS byte is rejected" {
    var seed: [32]u8 = @splat(7);
    const kpair = try TestSuite.Sig.KeyPair.generateDeterministic(seed);
    seed = @splat(0);

    var leaf = sampleLeaf();
    const pk_bytes = kpair.public_key.toBytes();
    leaf.signature_key = &pk_bytes;

    var kp: KeyPackage = .{
        .cipher_suite = TestSuite.id,
        .init_key = &[_]u8{0xdd} ** 32,
        .leaf_node = leaf,
        .signature = &.{},
    };
    const sig = try kp.sign(TestSuite, testing.allocator, kpair);
    const sig_bytes = sig.toBytes();
    kp.signature = &sig_bytes;
    try kp.verifySignature(TestSuite, testing.allocator);

    // Perturbing a field COVERED by KeyPackageTBS must break the signature.
    var kp2 = kp;
    kp2.init_key = &[_]u8{0xdc} ** 32;
    try testing.expectError(error.SignatureVerificationFailed, kp2.verifySignature(TestSuite, testing.allocator));
}

test "KeyPackage.verifySignature: a non-Ed25519-sized key/signature is WrongKeyLength, not a crash" {
    var leaf = sampleLeaf();
    leaf.signature_key = &[_]u8{0xbb} ** 31; // one byte short
    const kp: KeyPackage = .{
        .cipher_suite = TestSuite.id,
        .init_key = &[_]u8{0xdd} ** 32,
        .leaf_node = leaf,
        .signature = &[_]u8{0xee} ** 64,
    };
    try testing.expectError(error.WrongKeyLength, kp.verifySignature(TestSuite, testing.allocator));
}
