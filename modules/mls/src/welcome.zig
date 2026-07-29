// SPDX-License-Identifier: MIT
//! mls.welcome — RFC 9420 §12.4.3 (`GroupInfo`/`GroupInfoTBS`), §12.4.3.1
//! (`PathSecret`/`GroupSecrets`/`EncryptedGroupSecrets`/`Welcome` and the
//! joiner's whole procedure) and §12.4.3.3 (the `ratchet_tree` extension).
//! This is the path by which a client that is not yet a member of a group
//! ends up holding the same epoch secrets as everyone already in it.
//!
//! **Where the RFC actually puts this.** There is no top-level "Welcome"
//! section: `GroupInfo` and `GroupInfoTBS` are defined in §12.4.3 ("Adding
//! Members to the Group") directly, and everything else — `PathSecret`,
//! `GroupSecrets`, `EncryptedGroupSecrets`, `Welcome`, and the twelve-step
//! receiving procedure — is §12.4.3.1 ("Joining via Welcome Message").
//! §12.4.3.2 is external commits (see "What is NOT here" below) and
//! §12.4.3.3 is the `ratchet_tree` extension, which is how a `GroupInfo`
//! carries the tree itself rather than just its hash.
//!
//! **The shape of the construction, and why it is that shape.** A Welcome
//! must be readable by several new members at once, but the bulk of it —
//! the `GroupInfo`, which is kilobytes once it carries a ratchet tree — is
//! identical for all of them. So §12.4.3.1 splits it in two:
//!
//!   1. the `GroupInfo` is encrypted ONCE under a symmetric key derived
//!      from the new epoch's `welcome_secret` (`welcomeKeyNonce` below);
//!   2. the `joiner_secret` that key ultimately comes from is encrypted
//!      per-member under HPKE to each new member's `KeyPackage.init_key`.
//!
//! The binding between the two halves is the detail worth stating
//! explicitly, because it is easy to drop and nothing round-trips
//! differently if you do: the per-member HPKE encryption takes the ENTIRE
//! `encrypted_group_info` blob as its `EncryptWithLabel` *context*. A
//! delivery service that swaps in a different `encrypted_group_info` (say,
//! one from a different Welcome for a different group) therefore cannot
//! get any recipient to decrypt its `GroupSecrets` at all — the AEAD in
//! HPKE fails. That is the whole reason `encryptGroupSecrets`/
//! `decryptGroupSecrets` below take `encrypted_group_info` rather than
//! anything smaller like its hash.
//!
//! **What a joiner has to take on trust, and what redeems it.** The joiner
//! receives `joiner_secret` from the committer and cannot recompute it: it
//! has neither the previous epoch's `init_secret` nor the Commit's
//! `commit_secret` (that is exactly why §8's chain is entered one step
//! lower — see `keyschedule.deriveEpochFromJoiner`). What makes this sound
//! is the ORDER of the remaining checks: the joiner derives the epoch from
//! that `joiner_secret` and the `GroupContext` in the signed `GroupInfo`,
//! and then verifies the `GroupInfo`'s `confirmation_tag` with the
//! `confirmation_key` it just derived. A committer who sent a
//! `joiner_secret` that does not match the group's real epoch produces a
//! `confirmation_key` that does not verify the tag it also signed. `join`
//! below runs the steps in that order and fails closed.
//!
//! **What is NOT here.**
//!
//! * **External commits (§12.4.3.2) and §8.3's external initialization.**
//!   `ExternalPub` (the `GroupInfo` extension that enables them) IS here,
//!   because it is a wire structure and a joiner has to be able to read a
//!   `GroupInfo` that carries one. Everything that USES it is not: an
//!   external joiner derives `init_secret` via HPKE's `SetupBaseS`/
//!   `SetupBaseR` plus one `Context.export` (§8.3). **These are scoped out,
//!   NOT blocked.** The batch that built this file was scoped on the
//!   understanding that the sibling `hpke` module exported only the
//!   single-shot `sealBase`/`openBase` wrappers; it exports the whole RFC
//!   9180 §5.1 setup layer (`hpke.setupBaseS`/`setupBaseR`/
//!   `Context.exportSecret`), so the dependency is satisfied. §8.3 itself
//!   is now two small functions in `keyschedule.zig`; §12.4.3.2 on top of
//!   it additionally needs the commit-processing machinery this module
//!   does not have. Note that neither has an upstream interop vector, so
//!   both would land round-trip-anchored only.
//! * **Applying a Commit.** Joining is a one-shot state construction;
//!   FOLLOWING the group afterwards needs §12.2's proposal-list validity,
//!   §12.3's application order and §12.4.2's commit processing, none of
//!   which exist in this module.
//! * **§12.4.3.1's tree-integrity checks beyond the tree hash.** The
//!   parent-hash chain and the per-leaf validation the RFC lists there are
//!   `treekem.validateParentHashes` (already present) and §7.3 LeafNode
//!   validation (Part 3, absent). `verifyTreeHash` below is the one check
//!   this file owns, because it is the check that binds the tree to the
//!   SIGNED `GroupContext` and so is the precondition for the other two
//!   meaning anything.
//! * **Setting the joiner's private keys into the tree.** §12.4.3.1's last
//!   construction step derives node private keys up from `path_secret`.
//!   The `path_secret` is decoded and handed back by `join`; installing it
//!   requires a mutable group-state object this module deliberately does
//!   not have (`framing.zig`'s module doc comment makes the same call).
//!
//! Model: RFC 9420 §12.4.3, §12.4.3.1, §12.4.3.3, plus §17.3's extension
//! registry for `ratchet_tree`/`external_pub`. Anchored byte-exact against
//! the official `mlswg/mls-implementations` `welcome.json` (the whole
//! decrypt/verify path with real keys, plus reproduction of the vector's
//! own `encrypted_group_info` in the SEND direction) and `messages.json`
//! (wire round-trips for `Welcome`, `GroupInfo`, `GroupSecrets` and the
//! `ratchet_tree` extension) — see `kat_welcome_test.zig`,
//! `kat_messages_test.zig` and `NOTICE`.

const std = @import("std");
const codec = @import("codec.zig");
const crypto = @import("crypto.zig");
const suite = @import("suite.zig");
const tree = @import("tree.zig");
const treehash = @import("treehash.zig");
const treekem = @import("treekem.zig");
const keyschedule = @import("keyschedule.zig");
const secrettree = @import("secrettree.zig");
const transcript = @import("transcript.zig");
const wire = @import("wire_lists.zig");

const varintLen = wire.varintLen;

pub const Error = error{
    /// No entry in `Welcome.secrets` had a `new_member` equal to the
    /// caller's `KeyPackageRef` (RFC 9420 §12.4.3.1's first receiving step:
    /// "If no such field exists ... return an error").
    NoMatchingKeyPackage,
    /// `Welcome.cipher_suite` or `GroupInfo.group_context.cipher_suite`
    /// named a suite other than the one this call was instantiated for
    /// (§12.4.3.1: "if the cipher suite indicated in the KeyPackage does
    /// not match the one in the Welcome message, return an error", and the
    /// same check again against the decrypted `GroupInfo`).
    CipherSuiteMismatch,
    /// The decrypted `GroupSecrets.joiner_secret` was not `KDF.Nh` bytes,
    /// so it cannot be an epoch chain input at all.
    WrongSecretLength,
    /// The `PreSharedKeyID` list the caller resolved keys for is not the
    /// list the `GroupSecrets` actually names (different count, or a
    /// different identifier at some position). Deriving the epoch anyway
    /// would silently produce a `psk_secret` nobody else in the group has
    /// — §12.4.3.1: "If a PreSharedKeyID is part of the GroupSecrets and
    /// the client is not in possession of the corresponding PSK, return an
    /// error."
    PskMismatch,
    /// A `GroupInfo` extension of type `ratchet_tree`/`external_pub` was
    /// requested and is not present.
    ExtensionNotFound,
    /// `verifyTreeHash`: the ratchet tree's root hash is not the
    /// `tree_hash` in the signed `GroupContext` (§12.4.3.3's closing MUST).
    TreeHashMismatch,
    /// An AEAD open failed — the `encrypted_group_info` under the welcome
    /// key, or the HPKE-sealed `GroupSecrets`. One error for both, matching
    /// `framing.zig`'s reasoning: which one failed is not information a
    /// caller should be able to branch on.
    DecryptionFailed,
    /// An `encrypted_group_info` shorter than the AEAD tag.
    CiphertextTooShort,
} || tree.Error || keyschedule.Error || crypto.Error;

// ── §17.3: the two GroupInfo extension types this file understands ────────

/// RFC 9420 §17.3 Table 9 / §12.4.3.3 — the extension carrying the whole
/// public ratchet tree inside a `GroupInfo`.
pub const extension_type_ratchet_tree: u16 = 0x0002;

/// RFC 9420 §17.3 Table 9 / §12.4.3.2 — the extension carrying
/// `ExternalPub { HPKEPublicKey external_pub; }`, without which a
/// `GroupInfo` cannot be used for an external join.
pub const extension_type_external_pub: u16 = 0x0004;

// ── §12.4.3 / §12.4.3.1: the labels ───────────────────────────────────────

/// The label RFC 9420 §12.4.3 signs a `GroupInfoTBS` under.
pub const label_group_info_tbs = "GroupInfoTBS";

/// The `EncryptWithLabel` label §12.4.3.1 seals `GroupSecrets` under.
pub const label_welcome = "Welcome";

/// The two `ExpandWithLabel` labels §12.4.3.1 derives the group-info AEAD
/// key and nonce under. Same spellings as §9.1's ratchet labels, different
/// secret — named here rather than shared with `secrettree.zig` because a
/// future RFC changing one must not silently change the other.
pub const label_key = "key";
pub const label_nonce = "nonce";

// ── §12.4.3: GroupInfo / GroupInfoTBS ─────────────────────────────────────

/// RFC 9420 §12.4.3's `GroupInfo` — everything a new member needs to
/// bootstrap local group state, signed by an existing member.
///
/// Every byte field ALIASES caller memory; only `decode` allocates, and
/// only for the two extension LISTS (this struct's own and the nested
/// `GroupContext`'s) — the same no-copy convention `keyschedule
/// .GroupContext` and `tree.LeafNode` follow.
///
/// `GroupInfoTBS` is not a separate Zig type: §12.4.3 defines it as exactly
/// this struct minus `signature`, so it is expressed as `tbsEncodedLen`/
/// `tbsEncode` here, the way `keypackage.KeyPackage` expresses
/// `KeyPackageTBS`. One struct means the signed bytes cannot drift from the
/// transmitted bytes through a field added to one and not the other.
pub const GroupInfo = struct {
    group_context: keyschedule.GroupContext,
    extensions: []const tree.Extension = &.{},
    /// `MAC confirmation_tag` — §12.4.3: the tag from the Commit that
    /// started this epoch (equivalently `MAC(confirmation_key,
    /// confirmed_transcript_hash)`).
    confirmation_tag: []const u8,
    /// The leaf index of the member who signed this `GroupInfo`. §12.4.3:
    /// the verification key is that leaf's `signature_key`, so resolving
    /// this index needs the ratchet tree — see `verifySignature`.
    signer: u32,
    signature: []const u8,

    /// The exact wire bytes two later steps must not re-derive, set ONLY by
    /// `decode` and `null` for a `GroupInfo` a caller built in memory.
    ///
    /// **Why this exists.** Both the signature check and the key schedule
    /// consume a SERIALIZATION of fields this struct also holds decoded. A
    /// re-encode that differs from the received bytes by even one varint
    /// would make a valid signature look invalid, or (much worse) derive an
    /// epoch nobody else in the group derived, while every unit test that
    /// only round-trips this module's own encoder still passes.
    /// `keyschedule.GroupContext`'s own doc comment already calls this out
    /// as the reason `joinerSecret`/`epochSecret` take `[]const u8`; this
    /// field is how a decoded `GroupInfo` supplies them.
    raw: ?Raw = null,

    pub const Raw = struct {
        /// The encoded `GroupContext` — `deriveEpochFromJoiner`'s input.
        group_context: []const u8,
        /// The encoded `GroupInfoTBS` — every field above `signature`.
        tbs: []const u8,
    };

    fn tbsBodyLen(self: GroupInfo) usize {
        return self.group_context.encodedLen() +
            wire.varVecLen(tree.Extension, self.extensions) +
            varintLen(self.confirmation_tag.len) + self.confirmation_tag.len +
            4; // uint32 signer
    }

    /// RFC 9420 §12.4.3's `GroupInfoTBS` — every field except `signature`.
    pub fn tbsEncodedLen(self: GroupInfo) usize {
        return self.tbsBodyLen();
    }

    pub fn tbsEncode(self: GroupInfo, w: *codec.Writer) Error!void {
        try self.group_context.encode(w);
        try wire.encodeVarVec(tree.Extension, w, self.extensions);
        try w.writeVector(self.confirmation_tag);
        try w.writeU32(self.signer);
    }

    pub fn encodedLen(self: GroupInfo) usize {
        return self.tbsBodyLen() + varintLen(self.signature.len) + self.signature.len;
    }

    pub fn encode(self: GroupInfo, w: *codec.Writer) Error!void {
        try self.tbsEncode(w);
        try w.writeVector(self.signature);
    }

    /// Decodes, recording the raw `GroupContext` and `GroupInfoTBS` byte
    /// ranges as it goes (see `raw`). The ranges are derived from the
    /// reader's own consumption, never from a re-encode.
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !GroupInfo {
        const from_start = r.remaining();

        const group_context = try keyschedule.GroupContext.decode(allocator, r);
        errdefer group_context.deinit(allocator);
        const after_gc = r.remaining();
        const gc_raw = from_start[0 .. from_start.len - after_gc.len];

        const extensions = try tree.decodeExtensionList(allocator, r);
        errdefer allocator.free(extensions);
        const confirmation_tag = try r.readVector();
        const signer = try r.readU32();
        const after_tbs = r.remaining();
        const tbs_raw = from_start[0 .. from_start.len - after_tbs.len];

        const signature = try r.readVector();
        return .{
            .group_context = group_context,
            .extensions = extensions,
            .confirmation_tag = confirmation_tag,
            .signer = signer,
            .signature = signature,
            .raw = .{ .group_context = gc_raw, .tbs = tbs_raw },
        };
    }

    pub fn deinit(self: GroupInfo, allocator: std.mem.Allocator) void {
        self.group_context.deinit(allocator);
        allocator.free(self.extensions);
    }

    pub fn encodeAlloc(self: GroupInfo, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, self.encodedLen());
        errdefer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.encode(&w);
        std.debug.assert(w.finish().len == buf.len);
        return buf;
    }

    /// The encoded `GroupContext` — the received bytes when this
    /// `GroupInfo` came off the wire, a fresh re-encode otherwise. The
    /// returned slice is owned by the caller ONLY in the second case, which
    /// is why this returns both parts.
    pub fn groupContextBytes(self: GroupInfo, allocator: std.mem.Allocator) !struct { bytes: []const u8, owned: bool } {
        if (self.raw) |raw| return .{ .bytes = raw.group_context, .owned = false };
        return .{ .bytes = try self.group_context.encodeAlloc(allocator), .owned = true };
    }

    /// RFC 9420 §12.4.3: `VerifyWithLabel(signature_key, "GroupInfoTBS",
    /// GroupInfoTBS, signature)`.
    ///
    /// `signature_key` is NOT in the `GroupInfo`: §12.4.3 says it is the
    /// `signature_key` of the ratchet tree's leaf at index `signer`, and
    /// resolving that needs the tree, which this file does not own (a
    /// `GroupInfo` may or may not carry one — see `ratchetTree`). The
    /// caller passes the key it resolved, exactly as `framing.zig` hands
    /// back a `leaf_index` for the caller to resolve. `signer` naming a
    /// BLANK leaf is likewise the caller's rejection to make (§12.4.3.1:
    /// "If the node is blank ... return an error").
    ///
    /// Only suite `0x0001` (Ed25519) is wired, so a `signature` of any
    /// other length is `error.WrongKeyLength` — mirrors
    /// `keypackage.KeyPackage.verifySignature` exactly.
    pub fn verifySignature(
        self: GroupInfo,
        comptime S: type,
        allocator: std.mem.Allocator,
        signature_key: S.Sig.PublicKey,
    ) !void {
        if (self.signature.len != S.Nx) return error.WrongKeyLength;
        var sig_bytes: [S.Nx]u8 = undefined;
        @memcpy(&sig_bytes, self.signature);

        if (self.raw) |raw| {
            return crypto.VerifyWithLabelAlloc(S, allocator, signature_key, label_group_info_tbs, raw.tbs, S.Sig.Signature.fromBytes(sig_bytes));
        }
        const buf = try allocator.alloc(u8, self.tbsEncodedLen());
        defer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.tbsEncode(&w);
        return crypto.VerifyWithLabelAlloc(S, allocator, signature_key, label_group_info_tbs, w.finish(), S.Sig.Signature.fromBytes(sig_bytes));
    }

    /// The signing counterpart of `verifySignature`: produces the
    /// `signature` field for an otherwise-complete `GroupInfo`. Does not
    /// mutate `self` — `signature` aliases caller memory and this file owns
    /// no allocation policy for it, the same contract
    /// `keypackage.KeyPackage.sign` has.
    pub fn sign(
        self: GroupInfo,
        comptime S: type,
        allocator: std.mem.Allocator,
        key_pair: S.Sig.KeyPair,
    ) !S.Sig.Signature {
        const buf = try allocator.alloc(u8, self.tbsEncodedLen());
        defer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.tbsEncode(&w);
        return crypto.SignWithLabelAlloc(S, allocator, key_pair, label_group_info_tbs, w.finish());
    }

    /// The `extension_data` of the first extension of `extension_type`, or
    /// `null`. RFC 9420 §13 requires unknown extensions to be IGNORED, so
    /// absence is not an error here — the two typed accessors below decide
    /// whether their own absence is one.
    pub fn extension(self: GroupInfo, extension_type: u16) ?[]const u8 {
        for (self.extensions) |ext| {
            if (ext.extension_type == extension_type) return ext.extension_data;
        }
        return null;
    }

    /// RFC 9420 §12.4.3.3: decodes the `ratchet_tree` extension into a
    /// `tree.RatchetTree` (trailing blanks re-extended, per that section's
    /// receiver MUST — `tree.RatchetTree.decode` does it). Returns
    /// `error.ExtensionNotFound` when the `GroupInfo` does not carry one,
    /// which is legal: §12.4.3.3 explicitly allows the tree to be fetched
    /// out of band, and `verifyTreeHash` is what makes that safe.
    ///
    /// The returned tree owns its allocations — `deinit` it.
    pub fn ratchetTree(self: GroupInfo, allocator: std.mem.Allocator) !tree.RatchetTree {
        const data = self.extension(extension_type_ratchet_tree) orelse return error.ExtensionNotFound;
        var r = codec.Reader.init(data);
        var t = try tree.RatchetTree.decode(allocator, &r);
        errdefer t.deinit();
        if (!r.atEnd()) return error.Malformed;
        return t;
    }

    /// RFC 9420 §12.4.3.2's `ExternalPub { HPKEPublicKey external_pub; }` —
    /// one `opaque<V>` field, so the extension body is length-prefixed, not
    /// a bare key. Returned as bytes aliasing the extension: this module
    /// has nothing to DO with it yet (external commits need §8.3, which
    /// needs HPKE context setup the sibling `hpke` module does not export),
    /// but a joiner must be able to read a `GroupInfo` that carries one
    /// without tripping over the extra length prefix.
    pub fn externalPub(self: GroupInfo) !?[]const u8 {
        const data = self.extension(extension_type_external_pub) orelse return null;
        var r = codec.Reader.init(data);
        const key = try r.readVector();
        if (!r.atEnd()) return error.Malformed;
        return key;
    }
};

/// RFC 9420 §12.4.3.3's closing MUST, and §12.4.3.1's first tree-integrity
/// bullet: "the client MUST verify that the root hash of the ratchet tree
/// matches the tree_hash of the GroupContext before using the tree".
///
/// This is the check that makes an out-of-band tree safe to use at all, so
/// it is stated as its own function rather than folded into `join` (where
/// the tree may legitimately not be present yet).
pub fn verifyTreeHash(
    comptime S: type,
    allocator: std.mem.Allocator,
    t: *const tree.RatchetTree,
    group_context: keyschedule.GroupContext,
) !void {
    const root = try treehash.rootHash(S, allocator, t);
    if (group_context.tree_hash.len != root.len) return error.TreeHashMismatch;
    if (!std.mem.eql(u8, group_context.tree_hash, &root)) return error.TreeHashMismatch;
}

// ── §12.4.3.1: PathSecret / GroupSecrets ──────────────────────────────────

/// RFC 9420 §12.4.3.1's `GroupSecrets` — the per-member half of a Welcome.
///
/// `path_secret` is `optional<PathSecret>` where `PathSecret` is itself a
/// struct wrapping one `opaque<V>`; on the wire that is a presence byte
/// followed by a length-prefixed vector, and this struct flattens it to a
/// `?[]const u8` because the wrapper carries no other field. It is present
/// exactly when the committer's Commit reset nodes on the new member's
/// direct path (§12.4.3.1: "the path secret for the lowest node contained
/// in the direct paths of both the committer and the new member").
///
/// Every byte field ALIASES caller memory; only `decode` allocates, and
/// only for the `psks` list.
pub const GroupSecrets = struct {
    joiner_secret: []const u8,
    path_secret: ?[]const u8 = null,
    psks: []const keyschedule.PreSharedKeyId = &.{},

    pub fn encodedLen(self: GroupSecrets) usize {
        const path: usize = if (self.path_secret) |ps| 1 + varintLen(ps.len) + ps.len else 1;
        return varintLen(self.joiner_secret.len) + self.joiner_secret.len +
            path +
            wire.varVecLen(keyschedule.PreSharedKeyId, self.psks);
    }

    pub fn encode(self: GroupSecrets, w: *codec.Writer) Error!void {
        try w.writeVector(self.joiner_secret);
        try w.writePresence(self.path_secret != null);
        if (self.path_secret) |ps| try w.writeVector(ps);
        try wire.encodeVarVec(keyschedule.PreSharedKeyId, w, self.psks);
    }

    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !GroupSecrets {
        const joiner_secret = try r.readVector();
        const path_secret: ?[]const u8 = if (try r.readPresence()) try r.readVector() else null;
        const psks = try wire.decodeVarVec(keyschedule.PreSharedKeyId, false, allocator, r, keyschedule.PreSharedKeyId.decode);
        return .{ .joiner_secret = joiner_secret, .path_secret = path_secret, .psks = psks };
    }

    pub fn deinit(self: GroupSecrets, allocator: std.mem.Allocator) void {
        allocator.free(self.psks);
    }

    pub fn encodeAlloc(self: GroupSecrets, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, self.encodedLen());
        errdefer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.encode(&w);
        std.debug.assert(w.finish().len == buf.len);
        return buf;
    }
};

// ── §12.4.3.1: EncryptedGroupSecrets / Welcome ────────────────────────────

/// RFC 9420 §12.4.3.1's `EncryptedGroupSecrets` — one recipient's slot in a
/// Welcome. `new_member` is a `KeyPackageRef` (§5.2's `HashReference`, an
/// `opaque<V>`), i.e. `crypto.make_keypackage_ref` of the recipient's
/// encoded `KeyPackage`.
pub const EncryptedGroupSecrets = struct {
    new_member: []const u8,
    encrypted_group_secrets: treekem.HPKECiphertext,

    pub fn encodedLen(self: EncryptedGroupSecrets) usize {
        return varintLen(self.new_member.len) + self.new_member.len +
            self.encrypted_group_secrets.encodedLen();
    }

    pub fn encode(self: EncryptedGroupSecrets, w: *codec.Writer) codec.Error!void {
        try w.writeVector(self.new_member);
        try self.encrypted_group_secrets.encode(w);
    }

    pub fn decode(r: *codec.Reader) codec.Error!EncryptedGroupSecrets {
        return .{
            .new_member = try r.readVector(),
            .encrypted_group_secrets = try treekem.HPKECiphertext.decode(r),
        };
    }
};

/// RFC 9420 §12.4.3.1's `Welcome`. Note that the cipher suite is carried
/// HERE and not (as everywhere else in MLS) inside a `GroupContext` — a
/// recipient has to know the suite before it can decrypt anything, so this
/// is the one place the suite travels in the clear.
///
/// Every byte field ALIASES caller memory; only `decode` allocates, and
/// only for the `secrets` list.
pub const Welcome = struct {
    cipher_suite: suite.CipherSuiteId,
    secrets: []const EncryptedGroupSecrets = &.{},
    encrypted_group_info: []const u8,

    pub fn encodedLen(self: Welcome) usize {
        return 2 // CipherSuite
        + wire.varVecLen(EncryptedGroupSecrets, self.secrets) +
            varintLen(self.encrypted_group_info.len) + self.encrypted_group_info.len;
    }

    pub fn encode(self: Welcome, w: *codec.Writer) Error!void {
        try w.writeEnum(suite.CipherSuiteId, self.cipher_suite);
        try wire.encodeVarVec(EncryptedGroupSecrets, w, self.secrets);
        try w.writeVector(self.encrypted_group_info);
    }

    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !Welcome {
        const cs = try r.readEnum(suite.CipherSuiteId);
        const secrets = try wire.decodeVarVec(EncryptedGroupSecrets, false, allocator, r, EncryptedGroupSecrets.decode);
        errdefer allocator.free(secrets);
        return .{
            .cipher_suite = cs,
            .secrets = secrets,
            .encrypted_group_info = try r.readVector(),
        };
    }

    pub fn deinit(self: Welcome, allocator: std.mem.Allocator) void {
        allocator.free(self.secrets);
    }

    pub fn encodeAlloc(self: Welcome, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, self.encodedLen());
        errdefer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.encode(&w);
        std.debug.assert(w.finish().len == buf.len);
        return buf;
    }

    /// RFC 9420 §12.4.3.1's first receiving step: "Identify an entry in the
    /// secrets array where the new_member value corresponds to one of this
    /// client's KeyPackages". A plain byte comparison is right here — a
    /// `KeyPackageRef` is a public hash of a public `KeyPackage`, not a
    /// secret, so there is nothing for a timing side channel to leak.
    pub fn findSecret(self: Welcome, key_package_ref: []const u8) ?EncryptedGroupSecrets {
        for (self.secrets) |s| {
            if (std.mem.eql(u8, s.new_member, key_package_ref)) return s;
        }
        return null;
    }
};

// ── §12.4.3.1: the two encryption layers ──────────────────────────────────

/// RFC 9420 §12.4.3.1:
///
/// ```text
/// welcome_nonce = ExpandWithLabel(welcome_secret, "nonce", "", AEAD.Nn)
/// welcome_key   = ExpandWithLabel(welcome_secret, "key",   "", AEAD.Nk)
/// ```
///
/// Reuses `secrettree.KeyNonce(S)` as the carrier type: it is the same
/// (key, nonce) pair shape §9.1 produces, and giving this one its own
/// near-identical struct would only invite the two to be passed to each
/// other's functions.
///
/// Note there is NO generation and NO reuse guard here, unlike §9.1/§6.3.1:
/// a `welcome_secret` encrypts exactly one `GroupInfo`, so the nonce is
/// used once by construction.
pub fn welcomeKeyNonce(comptime S: type, welcome_secret: [S.Nh]u8) crypto.Error!secrettree.KeyNonce(S) {
    var out: secrettree.KeyNonce(S) = undefined;
    try crypto.ExpandWithLabel(S, welcome_secret, label_nonce, "", &out.nonce);
    try crypto.ExpandWithLabel(S, welcome_secret, label_key, "", &out.key);
    return out;
}

/// Seals an encoded `GroupInfo` under the welcome key/nonce, producing the
/// `Welcome.encrypted_group_info` field. AAD is empty — §12.4.3.1 names a
/// key and a nonce and no associated data, and the binding to the rest of
/// the Welcome runs the other way (the ciphertext produced here is the
/// CONTEXT of every per-member HPKE encryption; see `encryptGroupSecrets`).
///
/// Deterministic given the `welcome_secret` and the plaintext: AES-GCM with
/// a fixed key and nonce is a function, not a sampling. That is what lets
/// `kat_welcome_test.zig` reproduce the official vector's own
/// `encrypted_group_info` byte-for-byte rather than merely round-trip it.
pub fn encryptGroupInfo(
    comptime S: type,
    allocator: std.mem.Allocator,
    welcome_secret: [S.Nh]u8,
    group_info: []const u8,
) ![]u8 {
    var kn = try welcomeKeyNonce(S, welcome_secret);
    defer kn.wipe();

    const out = try allocator.alloc(u8, group_info.len + S.Aead.tag_length);
    errdefer allocator.free(out);
    S.Aead.encrypt(out[0..group_info.len], out[group_info.len..][0..S.Aead.tag_length], group_info, "", kn.nonce, kn.key);
    return out;
}

/// The receiver mirror of `encryptGroupInfo`. Returns the encoded
/// `GroupInfo` (caller frees) — `GroupInfo.decode` then reads it, and the
/// resulting `GroupInfo.raw` slices ALIAS this buffer, so it must outlive
/// the decoded struct.
pub fn decryptGroupInfo(
    comptime S: type,
    allocator: std.mem.Allocator,
    welcome_secret: [S.Nh]u8,
    encrypted_group_info: []const u8,
) ![]u8 {
    const tag_len = S.Aead.tag_length;
    if (encrypted_group_info.len < tag_len) return error.CiphertextTooShort;
    const pt_len = encrypted_group_info.len - tag_len;

    var kn = try welcomeKeyNonce(S, welcome_secret);
    defer kn.wipe();

    const pt = try allocator.alloc(u8, pt_len);
    errdefer allocator.free(pt);
    var tag: [tag_len]u8 = undefined;
    @memcpy(&tag, encrypted_group_info[pt_len..]);
    S.Aead.decrypt(pt, encrypted_group_info[0..pt_len], tag, "", kn.nonce, kn.key) catch
        return error.DecryptionFailed;
    return pt;
}

/// RFC 9420 §12.4.3.1:
///
/// ```text
/// encrypted_group_secrets =
///   EncryptWithLabel(init_key, "Welcome", encrypted_group_info,
///                    group_secrets)
/// ```
///
/// `init_key` is the recipient's `KeyPackage.init_key`, NOT its
/// `leaf_node.encryption_key` — §10 keeps them distinct precisely so that
/// joining and the ratchet tree use different keys.
///
/// The `encrypted_group_info` argument is the `EncryptWithLabel` CONTEXT,
/// which is what binds this per-member ciphertext to that one group-info
/// blob (see this file's module doc comment). Passing anything else
/// produces something that decrypts for nobody.
///
/// Returns a `treekem.HPKECiphertext` whose `kem_output` and `ciphertext`
/// are freshly allocated (caller frees both). `io` supplies the ephemeral
/// KEM keypair HPKE draws per encryption — which is exactly why the SEND
/// direction of this layer cannot be reproduced byte-for-byte from a test
/// vector, while `encryptGroupInfo`'s can.
pub fn encryptGroupSecrets(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    init_key: S.Kem.PublicKey,
    encrypted_group_info: []const u8,
    group_secrets: []const u8,
) !treekem.HPKECiphertext {
    const ct = try allocator.alloc(u8, group_secrets.len + S.Aead.tag_length);
    errdefer allocator.free(ct);
    // The `EncryptContext` here embeds the WHOLE `encrypted_group_info`,
    // which grows with the group (it carries the ratchet tree), so it does
    // not fit `crypto.EncryptWithLabel`'s fixed stack scratch for any group
    // of realistic size — see `crypto.encryptContextLen`. An exactly-sized
    // heap scratch also makes `error.LabelTooLong` unreachable below, which
    // matters: `decryptGroupSecrets` used to map it to
    // `error.DecryptionFailed` and so reported a buffer-size bug as a
    // wrong-key one.
    const scratch = try allocator.alloc(u8, try crypto.encryptContextLen(label_welcome, encrypted_group_info));
    defer allocator.free(scratch);
    const enc = try crypto.EncryptWithLabelScratch(S, init_key, io, label_welcome, encrypted_group_info, group_secrets, ct, scratch);

    const kem_output = try allocator.alloc(u8, enc.len);
    errdefer allocator.free(kem_output);
    @memcpy(kem_output, &enc);
    return .{ .kem_output = kem_output, .ciphertext = ct };
}

/// The receiver mirror of `encryptGroupSecrets`. Returns the encoded
/// `GroupSecrets` (caller frees) — `GroupSecrets.decode`'s output ALIASES
/// this buffer.
pub fn decryptGroupSecrets(
    comptime S: type,
    allocator: std.mem.Allocator,
    init_key_pair: S.Kem.KeyPair,
    encrypted_group_info: []const u8,
    ct: treekem.HPKECiphertext,
) ![]u8 {
    const tag_len = S.Aead.tag_length;
    if (ct.ciphertext.len < tag_len) return error.CiphertextTooShort;
    if (ct.kem_output.len != S.Kem.Npk) return error.WrongKeyLength;
    var enc: S.Kem.EncappedKey = undefined;
    @memcpy(&enc, ct.kem_output);

    const pt = try allocator.alloc(u8, ct.ciphertext.len - tag_len);
    errdefer allocator.free(pt);
    // Exactly-sized scratch — see `encryptGroupSecrets` for why the fixed
    // buffer is not enough here, and why sizing it exactly is what keeps
    // the `catch` below honest (it can now only mean a real AEAD/decap
    // failure).
    const scratch = try allocator.alloc(u8, try crypto.encryptContextLen(label_welcome, encrypted_group_info));
    defer allocator.free(scratch);
    crypto.DecryptWithLabelScratch(S, enc, init_key_pair, label_welcome, encrypted_group_info, ct.ciphertext, pt, scratch) catch
        return error.DecryptionFailed;
    return pt;
}

// ── §12.4.3.1: the joiner's procedure ─────────────────────────────────────

/// What a successful `join` produces: the group state a new member starts
/// its first epoch with. Owns the two decrypted plaintext buffers, because
/// every slice in `group_info`/`group_secrets` aliases one of them.
pub fn Joined(comptime S: type) type {
    return struct {
        const Self = @This();

        /// The decrypted, encoded `GroupInfo` — `group_info`'s slices and
        /// `group_info.raw` alias this.
        group_info_bytes: []u8,
        /// The decrypted, encoded `GroupSecrets` — `group_secrets`' slices
        /// alias this.
        group_secrets_bytes: []u8,

        group_info: GroupInfo,
        group_secrets: GroupSecrets,

        /// Every RFC 9420 §8 secret for the epoch the joiner has landed in,
        /// derived from `group_secrets.joiner_secret` (see
        /// `keyschedule.deriveEpochFromJoiner`).
        secrets: keyschedule.EpochSecrets(S),

        /// §8.2's `interim_transcript_hash` for this epoch, computed from
        /// the `GroupInfo`'s `confirmed_transcript_hash` and its
        /// `confirmation_tag` — §12.4.3.1's "Use the confirmed transcript
        /// hash and confirmation tag to compute the interim transcript hash
        /// in the new state". The joiner cannot compute it the normal way:
        /// it never saw the Commit.
        interim_transcript_hash: [S.Hash.digest_length]u8,

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.group_info.deinit(allocator);
            self.group_secrets.deinit(allocator);
            allocator.free(self.group_info_bytes);
            allocator.free(self.group_secrets_bytes);
            self.* = undefined;
        }
    };
}

/// Everything `join` needs that is not in the `Welcome` itself.
pub fn JoinParams(comptime S: type) type {
    return struct {
        welcome: Welcome,
        /// `crypto.make_keypackage_ref` of the caller's own encoded
        /// `KeyPackage` — what identifies its slot in `welcome.secrets`.
        key_package_ref: []const u8,
        /// The private half of that `KeyPackage`'s `init_key`.
        init_key_pair: S.Kem.KeyPair,
        /// The signature public key of the leaf named by
        /// `GroupInfo.signer`. Resolving it needs the ratchet tree; see
        /// `GroupInfo.verifySignature` for why that is the caller's step.
        signer_key: S.Sig.PublicKey,
        /// The PSKs named by `GroupSecrets.psks`, resolved by the caller,
        /// IN THE SAME ORDER — `join` checks that the identifiers match and
        /// refuses (`error.PskMismatch`) otherwise, because §8.4's
        /// `psk_secret` chain is position-dependent and a silently
        /// mismatched list derives an epoch nobody else has.
        psks: []const keyschedule.PreSharedKey(S) = &.{},
    };
}

/// RFC 9420 §12.4.3.1's receiving procedure, in the order the RFC states
/// its steps, stopping where this module's scope stops.
///
/// Runs: suite check → find this client's slot → HPKE-decrypt
/// `GroupSecrets` → check the PSK list is the one the caller resolved →
/// derive `welcome_secret` → AEAD-decrypt and decode the `GroupInfo` →
/// verify its signature → check the suite AGAIN against the signed
/// `GroupContext` → derive the epoch from `joiner_secret` → verify the
/// `confirmation_tag` with the `confirmation_key` just derived → compute
/// the interim transcript hash.
///
/// **Deliberately NOT run** (each needs state this module does not own, and
/// each is the CALLER's to run against the returned value):
/// group-id uniqueness across the caller's other groups; the tree-integrity
/// block (`verifyTreeHash` plus `treekem.validateParentHashes` plus §7.3
/// leaf validation); finding the leaf whose `LeafNode` equals the caller's
/// `KeyPackage`'s; installing private keys from `group_secrets.path_secret`;
/// and §12.4.3.1's closing reinit/branch-resumption-PSK rules.
pub fn join(comptime S: type, allocator: std.mem.Allocator, params: JoinParams(S)) !Joined(S) {
    if (params.welcome.cipher_suite != S.id) return error.CipherSuiteMismatch;

    const slot = params.welcome.findSecret(params.key_package_ref) orelse return error.NoMatchingKeyPackage;

    const gs_bytes = try decryptGroupSecrets(
        S,
        allocator,
        params.init_key_pair,
        params.welcome.encrypted_group_info,
        slot.encrypted_group_secrets,
    );
    errdefer allocator.free(gs_bytes);

    var gs_reader = codec.Reader.init(gs_bytes);
    const group_secrets = try GroupSecrets.decode(allocator, &gs_reader);
    errdefer group_secrets.deinit(allocator);
    if (!gs_reader.atEnd()) return error.Malformed;
    if (group_secrets.joiner_secret.len != S.Nh) return error.WrongSecretLength;

    try checkPskList(S, allocator, group_secrets.psks, params.psks);
    const psk_secret = try keyschedule.pskSecret(S, allocator, params.psks);

    var joiner: [S.Nh]u8 = undefined;
    @memcpy(&joiner, group_secrets.joiner_secret);
    const welcome_secret = try keyschedule.welcomeSecret(S, joiner, psk_secret);

    const gi_bytes = try decryptGroupInfo(S, allocator, welcome_secret, params.welcome.encrypted_group_info);
    errdefer allocator.free(gi_bytes);

    var gi_reader = codec.Reader.init(gi_bytes);
    const group_info = try GroupInfo.decode(allocator, &gi_reader);
    errdefer group_info.deinit(allocator);
    if (!gi_reader.atEnd()) return error.Malformed;

    try group_info.verifySignature(S, allocator, params.signer_key);
    if (group_info.group_context.cipher_suite != S.id) return error.CipherSuiteMismatch;

    // `raw.group_context` is always set here: this `GroupInfo` came from
    // `decode`. Using it rather than a re-encode is the point — see
    // `GroupInfo.raw`.
    const gc_bytes = group_info.raw.?.group_context;
    const secrets = try keyschedule.deriveEpochFromJoiner(S, allocator, joiner, psk_secret, gc_bytes);

    try keyschedule.verifyConfirmationTag(
        S,
        secrets.confirmation_key,
        group_info.group_context.confirmed_transcript_hash,
        group_info.confirmation_tag,
    );

    const interim = try transcript.interimTranscriptHash(
        S,
        group_info.group_context.confirmed_transcript_hash,
        group_info.confirmation_tag,
    );

    return .{
        .group_info_bytes = gi_bytes,
        .group_secrets_bytes = gs_bytes,
        .group_info = group_info,
        .group_secrets = group_secrets,
        .secrets = secrets,
        .interim_transcript_hash = interim,
    };
}

/// The `PreSharedKeyID` list in the `GroupSecrets` must be exactly the list
/// the caller resolved keys for, position by position. Compared by ENCODED
/// bytes rather than field-by-field so that a future `PreSharedKeyID` arm
/// cannot be added and silently skipped by this check.
fn checkPskList(
    comptime S: type,
    allocator: std.mem.Allocator,
    named: []const keyschedule.PreSharedKeyId,
    resolved: []const keyschedule.PreSharedKey(S),
) !void {
    if (named.len != resolved.len) return error.PskMismatch;
    for (named, resolved) |want, got| {
        if (want.encodedLen() != got.id.encodedLen()) return error.PskMismatch;
        const a = try allocator.alloc(u8, want.encodedLen());
        defer allocator.free(a);
        const b = try allocator.alloc(u8, got.id.encodedLen());
        defer allocator.free(b);
        var wa = codec.Writer.init(a);
        var wb = codec.Writer.init(b);
        try want.encode(&wa);
        try got.id.encode(&wb);
        if (!std.mem.eql(u8, wa.finish(), wb.finish())) return error.PskMismatch;
    }
}

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;
const TestSuite = suite.default;

fn sampleGroupContext() keyschedule.GroupContext {
    return .{
        .cipher_suite = TestSuite.id,
        .group_id = "welcome-test",
        .epoch = 3,
        .tree_hash = &[_]u8{0x11} ** 32,
        .confirmed_transcript_hash = &[_]u8{0x22} ** 32,
        .extensions = &.{},
    };
}

test "GroupInfo: encodedLen matches what encode writes, and decode round-trips byte-exact" {
    const gi: GroupInfo = .{
        .group_context = sampleGroupContext(),
        .extensions = &.{},
        .confirmation_tag = &[_]u8{0x33} ** 32,
        .signer = 2,
        .signature = &[_]u8{0x44} ** 64,
    };
    const bytes = try gi.encodeAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    try testing.expectEqual(gi.encodedLen(), bytes.len);

    var r = codec.Reader.init(bytes);
    const back = try GroupInfo.decode(testing.allocator, &r);
    defer back.deinit(testing.allocator);
    try testing.expect(r.atEnd());
    try testing.expectEqual(gi.signer, back.signer);
    try testing.expectEqualSlices(u8, gi.confirmation_tag, back.confirmation_tag);

    const re = try back.encodeAlloc(testing.allocator);
    defer testing.allocator.free(re);
    try testing.expectEqualSlices(u8, bytes, re);

    // `decode` records the two raw ranges, and they are PREFIXES of the
    // encoding in the RFC's own field order.
    try testing.expect(std.mem.startsWith(u8, bytes, back.raw.?.group_context));
    try testing.expect(std.mem.startsWith(u8, bytes, back.raw.?.tbs));
    try testing.expectEqual(gi.tbsEncodedLen(), back.raw.?.tbs.len);
    try testing.expectEqual(gi.group_context.encodedLen(), back.raw.?.group_context.len);
}

test "GroupInfo: sign then verify, and a flipped TBS byte is rejected" {
    var seed: [32]u8 = @splat(11);
    const kp = try TestSuite.Sig.KeyPair.generateDeterministic(seed);
    seed = @splat(0);

    var gi: GroupInfo = .{
        .group_context = sampleGroupContext(),
        .confirmation_tag = &[_]u8{0x33} ** 32,
        .signer = 1,
        .signature = &.{},
    };
    const sig = try gi.sign(TestSuite, testing.allocator, kp);
    const sig_bytes = sig.toBytes();
    gi.signature = &sig_bytes;
    try gi.verifySignature(TestSuite, testing.allocator, kp.public_key);

    // `signer` is inside GroupInfoTBS, so moving it must break the check —
    // otherwise a relay could redirect the signature to another leaf.
    var moved = gi;
    moved.signer = 2;
    try testing.expectError(error.SignatureVerificationFailed, moved.verifySignature(TestSuite, testing.allocator, kp.public_key));

    // And the raw-bytes path must agree with the re-encode path: sign a
    // constructed struct, verify the DECODED one (which uses `raw.tbs`).
    const bytes = try gi.encodeAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    var r = codec.Reader.init(bytes);
    const back = try GroupInfo.decode(testing.allocator, &r);
    defer back.deinit(testing.allocator);
    try testing.expect(back.raw != null);
    try back.verifySignature(TestSuite, testing.allocator, kp.public_key);
}

test "GroupSecrets: both optional<PathSecret> arms round-trip, with and without PSKs" {
    const psks = [_]keyschedule.PreSharedKeyId{
        .{ .id = .{ .external = "psk-id" }, .psk_nonce = &[_]u8{0x55} ** 32 },
    };
    const cases = [_]GroupSecrets{
        .{ .joiner_secret = &[_]u8{0x66} ** 32 },
        .{ .joiner_secret = &[_]u8{0x66} ** 32, .path_secret = &[_]u8{0x77} ** 32 },
        .{ .joiner_secret = &[_]u8{0x66} ** 32, .path_secret = &[_]u8{0x77} ** 32, .psks = &psks },
    };
    for (cases) |gs| {
        const bytes = try gs.encodeAlloc(testing.allocator);
        defer testing.allocator.free(bytes);
        try testing.expectEqual(gs.encodedLen(), bytes.len);

        var r = codec.Reader.init(bytes);
        const back = try GroupSecrets.decode(testing.allocator, &r);
        defer back.deinit(testing.allocator);
        try testing.expect(r.atEnd());
        try testing.expectEqual(gs.path_secret == null, back.path_secret == null);
        try testing.expectEqual(gs.psks.len, back.psks.len);

        const re = try back.encodeAlloc(testing.allocator);
        defer testing.allocator.free(re);
        try testing.expectEqualSlices(u8, bytes, re);
    }
}

test "Welcome: round-trips, and findSecret matches on the KeyPackageRef only" {
    const secrets = [_]EncryptedGroupSecrets{
        .{ .new_member = &[_]u8{0xa1} ** 32, .encrypted_group_secrets = .{ .kem_output = &[_]u8{0xb1} ** 32, .ciphertext = &[_]u8{0xc1} ** 48 } },
        .{ .new_member = &[_]u8{0xa2} ** 32, .encrypted_group_secrets = .{ .kem_output = &[_]u8{0xb2} ** 32, .ciphertext = &[_]u8{0xc2} ** 48 } },
    };
    const w: Welcome = .{
        .cipher_suite = TestSuite.id,
        .secrets = &secrets,
        .encrypted_group_info = &[_]u8{0xd0} ** 64,
    };
    const bytes = try w.encodeAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    try testing.expectEqual(w.encodedLen(), bytes.len);

    var r = codec.Reader.init(bytes);
    const back = try Welcome.decode(testing.allocator, &r);
    defer back.deinit(testing.allocator);
    try testing.expect(r.atEnd());
    try testing.expectEqual(@as(usize, 2), back.secrets.len);

    const re = try back.encodeAlloc(testing.allocator);
    defer testing.allocator.free(re);
    try testing.expectEqualSlices(u8, bytes, re);

    try testing.expect(back.findSecret(&[_]u8{0xa2} ** 32) != null);
    try testing.expect(back.findSecret(&[_]u8{0xa3} ** 32) == null);
}

test "welcomeKeyNonce: key and nonce are independent derivations of the same secret" {
    const ws: [TestSuite.Nh]u8 = @splat(0x5a);
    const kn = try welcomeKeyNonce(TestSuite, ws);
    // Different labels must give different bytes — a copy-paste of one
    // ExpandWithLabel call into the other would pass a round-trip test.
    try testing.expect(!std.mem.eql(u8, kn.key[0..@min(TestSuite.Nk, TestSuite.Nn)], kn.nonce[0..@min(TestSuite.Nk, TestSuite.Nn)]));

    const again = try welcomeKeyNonce(TestSuite, ws);
    try testing.expectEqualSlices(u8, &kn.key, &again.key);
    try testing.expectEqualSlices(u8, &kn.nonce, &again.nonce);
}

test "encryptGroupInfo/decryptGroupInfo: round trip, and a wrong welcome_secret fails" {
    const ws: [TestSuite.Nh]u8 = @splat(0x21);
    const pt = "an encoded GroupInfo would go here";

    const ct = try encryptGroupInfo(TestSuite, testing.allocator, ws, pt);
    defer testing.allocator.free(ct);
    try testing.expectEqual(pt.len + TestSuite.Aead.tag_length, ct.len);

    const back = try decryptGroupInfo(TestSuite, testing.allocator, ws, ct);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, pt, back);

    var wrong = ws;
    wrong[0] ^= 1;
    try testing.expectError(error.DecryptionFailed, decryptGroupInfo(TestSuite, testing.allocator, wrong, ct));
    try testing.expectError(error.CiphertextTooShort, decryptGroupInfo(TestSuite, testing.allocator, ws, ct[0..4]));
}

test "encryptGroupSecrets/decryptGroupSecrets: round trip, and the encrypted_group_info context is binding" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var seed: [32]u8 = @splat(3);
    const kp = try TestSuite.Kem.KeyPair.generateDeterministic(seed);
    seed = @splat(0);

    const egi = [_]u8{0x9e} ** 96;
    const gs: GroupSecrets = .{ .joiner_secret = &[_]u8{0x42} ** 32, .path_secret = &[_]u8{0x43} ** 32 };
    const gs_bytes = try gs.encodeAlloc(testing.allocator);
    defer testing.allocator.free(gs_bytes);

    const ct = try encryptGroupSecrets(TestSuite, testing.allocator, io, kp.public_key, &egi, gs_bytes);
    defer testing.allocator.free(ct.kem_output);
    defer testing.allocator.free(ct.ciphertext);

    const back = try decryptGroupSecrets(TestSuite, testing.allocator, kp, &egi, ct);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, gs_bytes, back);

    // The whole point of the context: a different `encrypted_group_info`
    // must make this ciphertext undecryptable, not merely unbound.
    var other = egi;
    other[0] ^= 1;
    try testing.expectError(error.DecryptionFailed, decryptGroupSecrets(TestSuite, testing.allocator, kp, &other, ct));
}

test "join: end-to-end against a Welcome this file also produced" {
    // A self-consistency check only — the AUTHORITATIVE anchor is
    // `kat_welcome_test.zig`, which drives the official interop vector.
    // What this adds is the SEND half of the HPKE layer, which no vector
    // can pin (the ephemeral KEM keypair is drawn per encryption).
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const alloc = testing.allocator;

    var seed: [32]u8 = @splat(9);
    const init_kp = try TestSuite.Kem.KeyPair.generateDeterministic(seed);
    seed = @splat(13);
    const sig_kp = try TestSuite.Sig.KeyPair.generateDeterministic(seed);
    seed = @splat(0);

    const joiner_secret = [_]u8{0x31} ** TestSuite.Nh;
    const psk_secret = keyschedule.zeroSecret(TestSuite);
    const welcome_secret = try keyschedule.welcomeSecret(TestSuite, joiner_secret, psk_secret);

    const gc = sampleGroupContext();
    const gc_bytes = try gc.encodeAlloc(alloc);
    defer alloc.free(gc_bytes);
    const secrets = try keyschedule.deriveEpochFromJoiner(TestSuite, alloc, joiner_secret, psk_secret, gc_bytes);
    const tag = keyschedule.confirmationTag(TestSuite, secrets.confirmation_key, gc.confirmed_transcript_hash);

    var gi: GroupInfo = .{
        .group_context = gc,
        .confirmation_tag = &tag,
        .signer = 0,
        .signature = &.{},
    };
    const sig = try gi.sign(TestSuite, alloc, sig_kp);
    const sig_bytes = sig.toBytes();
    gi.signature = &sig_bytes;

    const gi_bytes = try gi.encodeAlloc(alloc);
    defer alloc.free(gi_bytes);
    const egi = try encryptGroupInfo(TestSuite, alloc, welcome_secret, gi_bytes);
    defer alloc.free(egi);

    const gs: GroupSecrets = .{ .joiner_secret = &joiner_secret };
    const gs_bytes = try gs.encodeAlloc(alloc);
    defer alloc.free(gs_bytes);
    const hpke_ct = try encryptGroupSecrets(TestSuite, alloc, io, init_kp.public_key, egi, gs_bytes);
    defer alloc.free(hpke_ct.kem_output);
    defer alloc.free(hpke_ct.ciphertext);

    const kp_ref = [_]u8{0x77} ** 32;
    const slots = [_]EncryptedGroupSecrets{.{ .new_member = &kp_ref, .encrypted_group_secrets = hpke_ct }};
    const w: Welcome = .{ .cipher_suite = TestSuite.id, .secrets = &slots, .encrypted_group_info = egi };

    var joined = try join(TestSuite, alloc, .{
        .welcome = w,
        .key_package_ref = &kp_ref,
        .init_key_pair = init_kp,
        .signer_key = sig_kp.public_key,
    });
    defer joined.deinit(alloc);

    try testing.expectEqualSlices(u8, &secrets.epoch_secret, &joined.secrets.epoch_secret);
    try testing.expectEqualSlices(u8, &secrets.epoch_authenticator, &joined.secrets.epoch_authenticator);
    try testing.expectEqual(gc.epoch, joined.group_info.group_context.epoch);
    try testing.expect(joined.group_secrets.path_secret == null);

    // An unknown KeyPackageRef is a named refusal, not a decrypt attempt.
    try testing.expectError(error.NoMatchingKeyPackage, join(TestSuite, alloc, .{
        .welcome = w,
        .key_package_ref = &[_]u8{0x78} ** 32,
        .init_key_pair = init_kp,
        .signer_key = sig_kp.public_key,
    }));

    // A Welcome naming a suite this call is not instantiated for is refused
    // BEFORE any decryption is attempted.
    var wrong_suite = w;
    wrong_suite.cipher_suite = .mls_128_dhkemp256_aes128gcm_sha256_p256;
    try testing.expectError(error.CipherSuiteMismatch, join(TestSuite, alloc, .{
        .welcome = wrong_suite,
        .key_package_ref = &kp_ref,
        .init_key_pair = init_kp,
        .signer_key = sig_kp.public_key,
    }));

    // A caller that resolved no PSKs cannot join a Welcome that names one.
    const psk_ids = [_]keyschedule.PreSharedKeyId{
        .{ .id = .{ .external = "some-psk" }, .psk_nonce = &[_]u8{0x11} ** 32 },
    };
    const gs_psk: GroupSecrets = .{ .joiner_secret = &joiner_secret, .psks = &psk_ids };
    const gs_psk_bytes = try gs_psk.encodeAlloc(alloc);
    defer alloc.free(gs_psk_bytes);
    const hpke_ct2 = try encryptGroupSecrets(TestSuite, alloc, io, init_kp.public_key, egi, gs_psk_bytes);
    defer alloc.free(hpke_ct2.kem_output);
    defer alloc.free(hpke_ct2.ciphertext);
    const slots2 = [_]EncryptedGroupSecrets{.{ .new_member = &kp_ref, .encrypted_group_secrets = hpke_ct2 }};
    try testing.expectError(error.PskMismatch, join(TestSuite, alloc, .{
        .welcome = .{ .cipher_suite = TestSuite.id, .secrets = &slots2, .encrypted_group_info = egi },
        .key_package_ref = &kp_ref,
        .init_key_pair = init_kp,
        .signer_key = sig_kp.public_key,
    }));
}

test "join: a confirmation_tag that does not match the derived confirmation_key is rejected" {
    // The check that makes taking `joiner_secret` on trust sound. Build a
    // Welcome whose GroupInfo is correctly signed but whose confirmation
    // tag belongs to a DIFFERENT epoch, and confirm `join` fails closed
    // even though every signature in it verifies.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const alloc = testing.allocator;

    var seed: [32]u8 = @splat(9);
    const init_kp = try TestSuite.Kem.KeyPair.generateDeterministic(seed);
    seed = @splat(13);
    const sig_kp = try TestSuite.Sig.KeyPair.generateDeterministic(seed);
    seed = @splat(0);

    const joiner_secret = [_]u8{0x31} ** TestSuite.Nh;
    const welcome_secret = try keyschedule.welcomeSecret(TestSuite, joiner_secret, keyschedule.zeroSecret(TestSuite));

    const gc = sampleGroupContext();
    const bad_tag = [_]u8{0xee} ** TestSuite.Nm;
    var gi: GroupInfo = .{ .group_context = gc, .confirmation_tag = &bad_tag, .signer = 0, .signature = &.{} };
    const sig = try gi.sign(TestSuite, alloc, sig_kp);
    const sig_bytes = sig.toBytes();
    gi.signature = &sig_bytes;

    const gi_bytes = try gi.encodeAlloc(alloc);
    defer alloc.free(gi_bytes);
    const egi = try encryptGroupInfo(TestSuite, alloc, welcome_secret, gi_bytes);
    defer alloc.free(egi);

    const gs: GroupSecrets = .{ .joiner_secret = &joiner_secret };
    const gs_bytes = try gs.encodeAlloc(alloc);
    defer alloc.free(gs_bytes);
    const hpke_ct = try encryptGroupSecrets(TestSuite, alloc, io, init_kp.public_key, egi, gs_bytes);
    defer alloc.free(hpke_ct.kem_output);
    defer alloc.free(hpke_ct.ciphertext);

    const kp_ref = [_]u8{0x77} ** 32;
    const slots = [_]EncryptedGroupSecrets{.{ .new_member = &kp_ref, .encrypted_group_secrets = hpke_ct }};

    try testing.expectError(error.MacMismatch, join(TestSuite, alloc, .{
        .welcome = .{ .cipher_suite = TestSuite.id, .secrets = &slots, .encrypted_group_info = egi },
        .key_package_ref = &kp_ref,
        .init_key_pair = init_kp,
        .signer_key = sig_kp.public_key,
    }));
}

test "verifyTreeHash / ratchetTree / externalPub: the three GroupInfo-extension paths" {
    const alloc = testing.allocator;

    // A one-leaf tree is enough to exercise the hash binding: what is under
    // test is the COMPARISON against the signed GroupContext, and
    // `treehash.zig` is already vector-pinned for the hash itself.
    const leaf: tree.LeafNode = .{
        .encryption_key = &[_]u8{0xaa} ** 32,
        .signature_key = &[_]u8{0xbb} ** 32,
        .credential = .{ .basic = "solo" },
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
    var nodes = [_]?tree.Node{.{ .leaf = leaf }};
    const t: tree.RatchetTree = .{ .allocator = alloc, .nodes = &nodes };
    const encoded = try t.encode(alloc);
    defer alloc.free(encoded);
    const root = try treehash.rootHash(TestSuite, alloc, &t);

    const ext_pub_body = [_]u8{0x20} ++ [_]u8{0x5e} ** 32; // opaque<V> of 32 bytes
    const exts = [_]tree.Extension{
        .{ .extension_type = extension_type_ratchet_tree, .extension_data = encoded },
        .{ .extension_type = extension_type_external_pub, .extension_data = &ext_pub_body },
    };
    var gc = sampleGroupContext();
    gc.tree_hash = &root;
    const gi: GroupInfo = .{
        .group_context = gc,
        .extensions = &exts,
        .confirmation_tag = &[_]u8{0x33} ** 32,
        .signer = 0,
        .signature = &[_]u8{0x44} ** 64,
    };

    var decoded_tree = try gi.ratchetTree(alloc);
    defer decoded_tree.deinit();
    try testing.expectEqual(@as(usize, 1), decoded_tree.nodes.len);
    try verifyTreeHash(TestSuite, alloc, &decoded_tree, gi.group_context);

    // A GroupContext claiming a different tree hash must be refused — this
    // is the only thing standing between a joiner and an out-of-band tree
    // supplied by whoever felt like it.
    var bad_gc = gc;
    const wrong_hash = [_]u8{0x00} ** 32;
    bad_gc.tree_hash = &wrong_hash;
    try testing.expectError(error.TreeHashMismatch, verifyTreeHash(TestSuite, alloc, &decoded_tree, bad_gc));

    try testing.expectEqualSlices(u8, &[_]u8{0x5e} ** 32, (try gi.externalPub()).?);

    const no_ext: GroupInfo = .{
        .group_context = gc,
        .confirmation_tag = &[_]u8{0x33} ** 32,
        .signer = 0,
        .signature = &[_]u8{0x44} ** 64,
    };
    try testing.expectError(error.ExtensionNotFound, no_ext.ratchetTree(alloc));
    try testing.expectEqual(@as(?[]const u8, null), try no_ext.externalPub());
}
