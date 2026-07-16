// SPDX-License-Identifier: MIT
//! mls.tree — **Part 2** of this module's arc (see `SPEC.md`'s "Arc
//! breakdown"): the ratchet tree's DATA — `LeafNode`/`ParentNode`/`Node`
//! (RFC 9420 §7.1/§7.2), their wire encoding, `LeafNode` signature
//! verification, and `RatchetTree` (the array-based container Appendix C's
//! `treemath.zig`, Part 1, already indexes into) — plus the mechanical
//! (non-Fable) tree-EDITING operations §7.7/§12.1.1-§12.1.3 describe
//! (`addLeaf`/`updateLeaf`/`removeLeaf`). The genuinely hard TreeKEM
//! algorithms — `resolution`, `parentHash`+chain validation, and the
//! path-secret-derivation/`UpdatePath` machinery — are `treekem.zig`'s
//! `@panic` stubs, deliberately NOT here (see that file's module doc
//! comment and `gate.zig`).
//!
//! **Allocator-owned, unlike Part 1.** `codec.zig`'s `Writer`/`Reader` are
//! zero-allocation by design (Part 1's primitives are all fixed-size or
//! caller-bounded). A `RatchetTree` is inherently a DYNAMIC collection —
//! member count varies at runtime, `Capabilities`/`extensions` lists vary
//! per `LeafNode` — so this file (like the sibling `ssh` module's
//! `messages.readString`/`readNameList(gpa, r)`) takes an allocator for
//! every `decode`, and every decoded value OWNS the sub-slices it
//! allocated (`deinit(allocator)` frees them; slices that merely ALIAS the
//! input buffer — a `readVector()` result with no further parsing, e.g.
//! `LeafNode.encryption_key`/`signature`/`ParentNode.parent_hash` — are
//! NOT owned and must outlive the tree, matching `codec.Reader`'s own
//! no-copy convention one level down).
//!
//! **Wire encoding is byte-exact against the RFC's own struct order** —
//! every `encode`/`decode`/`encodedLen` triple below is a direct
//! transcription of RFC 9420 §7.1 (`ParentNode`)/§7.2 (`Capabilities`/
//! `Lifetime`/`Extension`/`LeafNode`/`LeafNodeTBS`)/§5.3 (`Credential`)/
//! §12.4.3.3 (`Node`, `optional<Node> ratchet_tree<V>` — the padded/
//! trimmed array-of-nodes wire shape `RatchetTree.decode`/`encode` use).
//! `encodedLen` exists ONLY so `encode` (and `RatchetTree.encode`, which
//! needs the TOTAL tree's byte length up front to size one allocation) can
//! size a destination without a scratch buffer or a growable writer — pure
//! arithmetic over already-in-memory fields, see `wire_lists.zig`'s module
//! doc comment.
//!
//! Model: RFC 9420 §4.1.1 (node/resolution concepts), §5.3 (`Credential`),
//! §7.1/§7.2 (`ParentNode`/`LeafNode`/`LeafNodeTBS`), §7.7 (add/remove leaf
//! tree-shape edits), §12.1.1-§12.1.3 (Add/Update/Remove proposal
//! APPLICATION semantics — not the proposal MESSAGE framing itself, which
//! is Part 5's job per `SPEC.md`), §12.4.3.3 (`Node`/`ratchet_tree<V>` wire
//! shape and its padding/trimming rule).

const std = @import("std");
const codec = @import("codec.zig");
const crypto = @import("crypto.zig");
const treemath = @import("treemath.zig");
const wire = @import("wire_lists.zig");

const varintLen = wire.varintLen;

pub const Error = error{
    /// A structurally-invalid but bounds-safe decode: a list byte length
    /// isn't a multiple of its fixed element width, an enum tag that
    /// should never appear on the wire in context did (e.g. a `Node` whose
    /// `node_type` decoded to `reserved`/an unrecognized tag), or a
    /// `select`-guarded field (`Lifetime`/`parent_hash`) is missing for
    /// the `leaf_node_source` that requires it.
    Malformed,
    /// `LeafNode.signature`/`signature_key` had the wrong length for the
    /// suite's signature scheme (this module currently only wires suite
    /// `0x0001`/Ed25519 — 64-byte signature, 32-byte public key, `suite
    /// .zig`'s `Nx`/§5.1.1).
    WrongKeyLength,
    /// `RatchetTree.addLeaf`/`updateLeaf`/`removeLeaf`: the leaf index
    /// named doesn't exist in the tree at all (`>= n_leaves`).
    InvalidLeafIndex,
} || codec.Error || crypto.Error || std.mem.Allocator.Error;

// ── §12.4.3.3: NodeType (also reused by treehash.zig's TreeHashInput) ────

pub const NodeType = enum(u8) { reserved = 0, leaf = 1, parent = 2, _ };

// ── §7.2: LeafNodeSource ──────────────────────────────────────────────────

pub const LeafNodeSource = enum(u8) { reserved = 0, key_package = 1, update = 2, commit = 3, _ };

// ── §5.3: CredentialType / Credential ────────────────────────────────────

pub const CredentialType = enum(u16) { reserved = 0, basic = 1, x509 = 2, _ };

/// RFC 9420 §5.3 `Credential`. `basic` is a bare opaque identity (the
/// application defines its encoding); `x509` is an ordered DER certificate
/// chain, `x509_certs[0]` the end-entity cert (`certificates[0]` in the
/// RFC's `Certificate certificates<V>`, each entry itself a `Certificate
/// { opaque cert_data<V>; }` — flattened here to `[][]const u8` of raw
/// `cert_data` since `Certificate` has no other field).
pub const Credential = union(enum) {
    basic: []const u8,
    x509: [][]const u8,

    pub fn credentialType(self: Credential) CredentialType {
        return switch (self) {
            .basic => .basic,
            .x509 => .x509,
        };
    }

    pub fn encodedLen(self: Credential) usize {
        return 2 + switch (self) {
            .basic => |id| varintLen(id.len) + id.len,
            .x509 => |certs| blk: {
                var body: usize = 0;
                for (certs) |c| body += varintLen(c.len) + c.len;
                break :blk varintLen(body) + body;
            },
        };
    }

    pub fn encode(self: Credential, w: *codec.Writer) codec.Error!void {
        try w.writeEnum(CredentialType, self.credentialType());
        switch (self) {
            .basic => |id| try w.writeVector(id),
            .x509 => |certs| {
                var body: usize = 0;
                for (certs) |c| body += varintLen(c.len) + c.len;
                try w.writeVarint(body);
                for (certs) |c| try w.writeVector(c);
            },
        }
    }

    /// Allocator-owning: `x509`'s `[][]const u8` slice is a fresh
    /// allocation (its individual `cert_data` entries alias the input
    /// buffer); `basic`'s payload aliases the input buffer directly.
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !Credential {
        const t = try r.readEnum(CredentialType);
        return switch (t) {
            .basic => .{ .basic = try r.readVector() },
            .x509 => blk: {
                const bytes = try r.readVector();
                var sub = codec.Reader.init(bytes);
                var list: std.ArrayList([]const u8) = .empty;
                errdefer list.deinit(allocator);
                while (!sub.atEnd()) try list.append(allocator, try sub.readVector());
                break :blk .{ .x509 = try list.toOwnedSlice(allocator) };
            },
            else => error.Malformed,
        };
    }

    pub fn deinit(self: Credential, allocator: std.mem.Allocator) void {
        switch (self) {
            .basic => {},
            .x509 => |certs| allocator.free(certs),
        }
    }
};

// ── §7.2: Lifetime / Extension / Capabilities ────────────────────────────

pub const Lifetime = struct {
    not_before: u64,
    not_after: u64,

    pub fn encodedLen(_: Lifetime) usize {
        return 16;
    }
    pub fn encode(self: Lifetime, w: *codec.Writer) codec.Error!void {
        try w.writeU64(self.not_before);
        try w.writeU64(self.not_after);
    }
    pub fn decode(r: *codec.Reader) codec.Error!Lifetime {
        return .{ .not_before = try r.readU64(), .not_after = try r.readU64() };
    }
};

pub const Extension = struct {
    extension_type: u16,
    extension_data: []const u8,

    pub fn encodedLen(self: Extension) usize {
        return 2 + varintLen(self.extension_data.len) + self.extension_data.len;
    }
    pub fn encode(self: Extension, w: *codec.Writer) codec.Error!void {
        try w.writeU16(self.extension_type);
        try w.writeVector(self.extension_data);
    }
    /// Aliases the input buffer — no allocation (matches `codec.Reader`'s
    /// own no-copy convention; only the LIST of `Extension` needs an
    /// allocation, see `decodeExtensionList`).
    pub fn decode(r: *codec.Reader) codec.Error!Extension {
        const t = try r.readU16();
        const data = try r.readVector();
        return .{ .extension_type = t, .extension_data = data };
    }
};

fn extensionListLen(list: []const Extension) usize {
    return wire.varVecLen(Extension, list);
}
fn encodeExtensionList(w: *codec.Writer, list: []const Extension) codec.Error!void {
    try wire.encodeVarVec(Extension, w, list);
}
/// Test/decode-only helper made `pub` so `kat_treekem_test.zig`'s
/// test-local `KeyPackage` parser (needed only to drive `tree-
/// operations.json`'s Add proposals — full `KeyPackage` is Part 3's public
/// API, see `SPEC.md`) can decode `KeyPackage.extensions<V>`, which is the
/// identical wire shape as `LeafNode.extensions<V>`.
pub fn decodeExtensionList(allocator: std.mem.Allocator, r: *codec.Reader) ![]Extension {
    return wire.decodeVarVec(Extension, false, allocator, r, Extension.decode);
}

/// RFC 9420 §7.2. The five lists are all `uint16 foo<V>` vectors —
/// `ProtocolVersion`/`CipherSuite`/`ExtensionType`/`ProposalType`/
/// `CredentialType` are all `uint16`-tagged (`suite.CipherSuiteId`,
/// `NodeType`... etc. — none of those enum TYPES are reused directly here,
/// this struct stores the raw `u16` tag values, matching how a
/// capabilities list legitimately contains GREASE/unknown values a typed
/// enum would reject, RFC 9420 §13).
pub const Capabilities = struct {
    versions: []const u16,
    cipher_suites: []const u16,
    extensions: []const u16,
    proposals: []const u16,
    credentials: []const u16,

    pub fn encodedLen(self: Capabilities) usize {
        return wire.fixedVecLen(self.versions.len, 2) +
            wire.fixedVecLen(self.cipher_suites.len, 2) +
            wire.fixedVecLen(self.extensions.len, 2) +
            wire.fixedVecLen(self.proposals.len, 2) +
            wire.fixedVecLen(self.credentials.len, 2);
    }
    pub fn encode(self: Capabilities, w: *codec.Writer) codec.Error!void {
        try wire.encodeU16Vec(w, self.versions);
        try wire.encodeU16Vec(w, self.cipher_suites);
        try wire.encodeU16Vec(w, self.extensions);
        try wire.encodeU16Vec(w, self.proposals);
        try wire.encodeU16Vec(w, self.credentials);
    }
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !Capabilities {
        const versions = try wire.decodeU16Vec(allocator, r);
        errdefer allocator.free(versions);
        const cipher_suites = try wire.decodeU16Vec(allocator, r);
        errdefer allocator.free(cipher_suites);
        const extensions = try wire.decodeU16Vec(allocator, r);
        errdefer allocator.free(extensions);
        const proposals = try wire.decodeU16Vec(allocator, r);
        errdefer allocator.free(proposals);
        const credentials = try wire.decodeU16Vec(allocator, r);
        return .{
            .versions = versions,
            .cipher_suites = cipher_suites,
            .extensions = extensions,
            .proposals = proposals,
            .credentials = credentials,
        };
    }
    pub fn deinit(self: Capabilities, allocator: std.mem.Allocator) void {
        allocator.free(self.versions);
        allocator.free(self.cipher_suites);
        allocator.free(self.extensions);
        allocator.free(self.proposals);
        allocator.free(self.credentials);
    }
};

// ── §7.2: LeafNode / LeafNodeTBS ──────────────────────────────────────────

/// RFC 9420 §7.2's `LeafNode`. The `select (LeafNode.leaf_node_source)`
/// field is `lifetime` (source `key_package`), absent (source `update`),
/// or `parent_hash` (source `commit`) — modeled as two `?`-optional Zig
/// fields rather than a tagged union so `leaf_node_source` (the RFC's own
/// discriminant) stays the single source of truth for which is active;
/// `encode`/`decode`/`verifySignature` all switch on it, never on
/// `lifetime != null`/`parent_hash != null` alone.
pub const LeafNode = struct {
    encryption_key: []const u8,
    signature_key: []const u8,
    credential: Credential,
    capabilities: Capabilities,
    leaf_node_source: LeafNodeSource,
    lifetime: ?Lifetime = null,
    parent_hash: ?[]const u8 = null,
    extensions: []const Extension,
    signature: []const u8,

    fn selectFieldLen(self: LeafNode) usize {
        return switch (self.leaf_node_source) {
            .key_package => 16, // Lifetime
            .update => 0,
            .commit => blk: {
                const ph = self.parent_hash orelse break :blk 0; // malformed; encode() will surface it
                break :blk varintLen(ph.len) + ph.len;
            },
            else => 0,
        };
    }
    fn encodeSelectField(self: LeafNode, w: *codec.Writer) Error!void {
        switch (self.leaf_node_source) {
            .key_package => try (self.lifetime orelse return error.Malformed).encode(w),
            .update => {},
            .commit => try w.writeVector(self.parent_hash orelse return error.Malformed),
            else => {},
        }
    }

    pub fn encodedLen(self: LeafNode) usize {
        return varintLen(self.encryption_key.len) + self.encryption_key.len +
            varintLen(self.signature_key.len) + self.signature_key.len +
            self.credential.encodedLen() +
            self.capabilities.encodedLen() +
            1 + // leaf_node_source
            self.selectFieldLen() +
            extensionListLen(self.extensions) +
            varintLen(self.signature.len) + self.signature.len;
    }

    pub fn encode(self: LeafNode, w: *codec.Writer) Error!void {
        try w.writeVector(self.encryption_key);
        try w.writeVector(self.signature_key);
        try self.credential.encode(w);
        try self.capabilities.encode(w);
        try w.writeEnum(LeafNodeSource, self.leaf_node_source);
        try self.encodeSelectField(w);
        try encodeExtensionList(w, self.extensions);
        try w.writeVector(self.signature);
    }

    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !LeafNode {
        const encryption_key = try r.readVector();
        const signature_key = try r.readVector();
        const credential = try Credential.decode(allocator, r);
        errdefer credential.deinit(allocator);
        const capabilities = try Capabilities.decode(allocator, r);
        errdefer capabilities.deinit(allocator);
        const source = try r.readEnum(LeafNodeSource);
        var lifetime: ?Lifetime = null;
        var parent_hash: ?[]const u8 = null;
        switch (source) {
            .key_package => lifetime = try Lifetime.decode(r),
            .update => {},
            .commit => parent_hash = try r.readVector(),
            else => return error.Malformed,
        }
        const extensions = try decodeExtensionList(allocator, r);
        errdefer allocator.free(extensions);
        const signature = try r.readVector();
        return .{
            .encryption_key = encryption_key,
            .signature_key = signature_key,
            .credential = credential,
            .capabilities = capabilities,
            .leaf_node_source = source,
            .lifetime = lifetime,
            .parent_hash = parent_hash,
            .extensions = extensions,
            .signature = signature,
        };
    }

    pub fn deinit(self: LeafNode, allocator: std.mem.Allocator) void {
        self.credential.deinit(allocator);
        self.capabilities.deinit(allocator);
        allocator.free(self.extensions);
    }

    /// RFC 9420 §7.2's `LeafNodeTBS` — `LeafNode` minus `signature`, PLUS
    /// (only when `leaf_node_source` is `update`/`commit`) a trailing
    /// `opaque group_id<V>; uint32 leaf_index;` — the group binds the
    /// signature once the leaf is actually IN a group; a `key_package`
    /// LeafNode (not yet in any group) signs neither.
    pub fn tbsEncodedLen(self: LeafNode, group_id_len: usize) usize {
        var total = varintLen(self.encryption_key.len) + self.encryption_key.len +
            varintLen(self.signature_key.len) + self.signature_key.len +
            self.credential.encodedLen() +
            self.capabilities.encodedLen() +
            1 +
            self.selectFieldLen() +
            extensionListLen(self.extensions);
        switch (self.leaf_node_source) {
            .key_package => {},
            .update, .commit => total += varintLen(group_id_len) + group_id_len + 4,
            else => {},
        }
        return total;
    }
    pub fn tbsEncode(self: LeafNode, w: *codec.Writer, group_id: []const u8, leaf_index: u32) Error!void {
        try w.writeVector(self.encryption_key);
        try w.writeVector(self.signature_key);
        try self.credential.encode(w);
        try self.capabilities.encode(w);
        try w.writeEnum(LeafNodeSource, self.leaf_node_source);
        try self.encodeSelectField(w);
        try encodeExtensionList(w, self.extensions);
        switch (self.leaf_node_source) {
            .key_package => {},
            .update, .commit => {
                try w.writeVector(group_id);
                try w.writeU32(leaf_index);
            },
            else => {},
        }
    }

    /// RFC 9420 §7.2/§5.1.2: `VerifyWithLabel(signature_key, "LeafNodeTBS",
    /// LeafNodeTBS, signature)`. `group_id`/`leaf_index` are ignored (and
    /// may be anything, e.g. `""`/`0`) when `leaf_node_source ==
    /// .key_package` — see `tbsEncode`. Only suite `0x0001` (Ed25519,
    /// 32-byte public key / 64-byte signature, this module's only wired
    /// suite so far — `suite.zig`) is supported; a `signature_key`/
    /// `signature` of any other length is `error.WrongKeyLength`, not a
    /// crash.
    pub fn verifySignature(self: LeafNode, comptime S: type, allocator: std.mem.Allocator, group_id: []const u8, leaf_index: u32) !void {
        if (self.signature_key.len != 32) return error.WrongKeyLength;
        if (self.signature.len != 64) return error.WrongKeyLength;
        const len = self.tbsEncodedLen(group_id.len);
        const buf = try allocator.alloc(u8, len);
        defer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.tbsEncode(&w, group_id, leaf_index);
        const content = w.finish();

        var pk_bytes: [32]u8 = undefined;
        @memcpy(&pk_bytes, self.signature_key);
        const pk = try S.Sig.PublicKey.fromBytes(pk_bytes);
        var sig_bytes: [64]u8 = undefined;
        @memcpy(&sig_bytes, self.signature);
        const sig = S.Sig.Signature.fromBytes(sig_bytes);
        try crypto.VerifyWithLabel(S, pk, "LeafNodeTBS", content, sig);
    }
};

// ── §7.1: ParentNode ──────────────────────────────────────────────────────

pub const ParentNode = struct {
    encryption_key: []const u8,
    parent_hash: []const u8,
    /// MUST be sorted increasing (RFC 9420 §7.1) — not enforced by this
    /// struct (a decode-time policy check, not a wire-shape concern; the
    /// KAT harness's tree-validation tests may add an explicit check if a
    /// vector exercises it).
    unmerged_leaves: []const u32,

    pub fn encodedLen(self: ParentNode) usize {
        return varintLen(self.encryption_key.len) + self.encryption_key.len +
            varintLen(self.parent_hash.len) + self.parent_hash.len +
            wire.fixedVecLen(self.unmerged_leaves.len, 4);
    }
    pub fn encode(self: ParentNode, w: *codec.Writer) codec.Error!void {
        try w.writeVector(self.encryption_key);
        try w.writeVector(self.parent_hash);
        try wire.encodeU32Vec(w, self.unmerged_leaves);
    }
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !ParentNode {
        const encryption_key = try r.readVector();
        const parent_hash = try r.readVector();
        const unmerged_leaves = try wire.decodeU32Vec(allocator, r);
        return .{ .encryption_key = encryption_key, .parent_hash = parent_hash, .unmerged_leaves = unmerged_leaves };
    }
    pub fn deinit(self: ParentNode, allocator: std.mem.Allocator) void {
        allocator.free(self.unmerged_leaves);
    }

    /// Returns a copy of `self` with `unmerged_leaves` replaced by a fresh
    /// allocation containing the old list plus `leaf_index` appended
    /// (caller frees the OLD `unmerged_leaves` — this does not, since the
    /// caller may still hold other references to it, e.g. mid-iteration).
    pub fn withAppendedUnmerged(self: ParentNode, allocator: std.mem.Allocator, leaf_index: u32) !ParentNode {
        var new_list = try allocator.alloc(u32, self.unmerged_leaves.len + 1);
        @memcpy(new_list[0..self.unmerged_leaves.len], self.unmerged_leaves);
        new_list[self.unmerged_leaves.len] = leaf_index;
        return .{ .encryption_key = self.encryption_key, .parent_hash = self.parent_hash, .unmerged_leaves = new_list };
    }
};

// ── §12.4.3.3: Node ────────────────────────────────────────────────────────

pub const Node = union(enum) {
    leaf: LeafNode,
    parent: ParentNode,

    pub fn nodeType(self: Node) NodeType {
        return switch (self) {
            .leaf => .leaf,
            .parent => .parent,
        };
    }
    pub fn encodedLen(self: Node) usize {
        return 1 + switch (self) {
            .leaf => |l| l.encodedLen(),
            .parent => |p| p.encodedLen(),
        };
    }
    pub fn encode(self: Node, w: *codec.Writer) Error!void {
        try w.writeEnum(NodeType, self.nodeType());
        switch (self) {
            .leaf => |l| try l.encode(w),
            .parent => |p| try p.encode(w),
        }
    }
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !Node {
        const t = try r.readEnum(NodeType);
        return switch (t) {
            .leaf => .{ .leaf = try LeafNode.decode(allocator, r) },
            .parent => .{ .parent = try ParentNode.decode(allocator, r) },
            else => error.Malformed,
        };
    }
    pub fn deinit(self: Node, allocator: std.mem.Allocator) void {
        switch (self) {
            .leaf => |l| l.deinit(allocator),
            .parent => |p| p.deinit(allocator),
        }
    }
};

// ── RatchetTree: the array-based container (Appendix C / `treemath.zig`) ──

/// The next value of the form `2^(d+1) - 1` that is `>= n` (RFC 9420
/// §12.4.3.3's padding rule: a `ratchet_tree<V>` vector with its trailing
/// blanks trimmed MUST be extended back to this width on decode). `0` maps
/// to `0` (the empty tree — never actually produced by any KAT here, but a
/// well-defined identity rather than an infinite loop).
fn paddedWidth(n: usize) usize {
    if (n == 0) return 0;
    var width: usize = 1;
    while (width < n) width = width * 2 + 1;
    return width;
}

/// The array-based ratchet tree (RFC 9420 Appendix C / `treemath.zig`):
/// `nodes[i]` is `null` for a blank node, `Node.leaf`/`Node.parent`
/// otherwise. Owns every non-aliased sub-allocation reachable from
/// `nodes` — `deinit` frees the whole tree.
pub const RatchetTree = struct {
    allocator: std.mem.Allocator,
    nodes: []?Node,

    pub fn nLeaves(self: RatchetTree) usize {
        return (self.nodes.len + 1) / 2;
    }

    pub fn deinit(self: *RatchetTree) void {
        for (self.nodes) |maybe_node| if (maybe_node) |n| n.deinit(self.allocator);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    /// RFC 9420 §12.4.3.3: reads the varint-length-prefixed `optional<Node>
    /// ratchet_tree<V>` vector (INCLUDING that outer length prefix — `r`
    /// must be positioned right before it), then pads the result back out
    /// to `paddedWidth` with blanks (the sender trims trailing blanks; the
    /// receiver MUST re-extend).
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !RatchetTree {
        const bytes = try r.readVector();
        var sub = codec.Reader.init(bytes);
        var list: std.ArrayList(?Node) = .empty;
        errdefer {
            for (list.items) |m| if (m) |n| n.deinit(allocator);
            list.deinit(allocator);
        }
        while (!sub.atEnd()) {
            if (try sub.readPresence()) {
                try list.append(allocator, try Node.decode(allocator, &sub));
            } else {
                try list.append(allocator, null);
            }
        }
        const target = paddedWidth(list.items.len);
        while (list.items.len < target) try list.append(allocator, null);
        return .{ .allocator = allocator, .nodes = try list.toOwnedSlice(allocator) };
    }

    /// The mirror of `decode`: trims trailing blanks (RFC 9420 §12.4.3.3:
    /// "the sender MUST NOT include blank nodes after the last non-blank
    /// node"), then emits the varint-length-prefixed vector. Returns a
    /// freshly allocated buffer the caller owns.
    pub fn encode(self: RatchetTree, allocator: std.mem.Allocator) ![]u8 {
        var count: usize = 0;
        var i: usize = self.nodes.len;
        while (i > 0) {
            i -= 1;
            if (self.nodes[i] != null) {
                count = i + 1;
                break;
            }
        }
        var body: usize = 0;
        for (self.nodes[0..count]) |m| {
            body += 1;
            if (m) |n| body += n.encodedLen();
        }
        const total = varintLen(body) + body;
        const out = try allocator.alloc(u8, total);
        errdefer allocator.free(out);
        var w = codec.Writer.init(out);
        try w.writeVarint(body);
        for (self.nodes[0..count]) |m| {
            try w.writePresence(m != null);
            if (m) |n| try n.encode(&w);
        }
        return w.finish();
    }

    fn blank(self: *RatchetTree, index: usize) void {
        if (self.nodes[index]) |old| old.deinit(self.allocator);
        self.nodes[index] = null;
    }

    /// RFC 9420 §12.1.1 Add proposal application (tree-shape half only —
    /// NOT the "add L's leaf index to unmerged_leaves" bookkeeping's
    /// interaction with `resolution`, which doesn't apply here: this is
    /// mechanical index bookkeeping, not the Fable-flagged resolution
    /// ALGORITHM itself). Finds the leftmost blank leaf (extending the
    /// tree by one level if none exists), places `leaf` there, and adds
    /// the new leaf's index to `unmerged_leaves` on every non-blank
    /// ancestor. Takes ownership of `leaf`'s allocator-owned sub-slices.
    /// Returns the new member's leaf index.
    pub fn addLeaf(self: *RatchetTree, leaf: LeafNode) !usize {
        var n_leaves = self.nLeaves();
        var leaf_index: ?usize = null;
        var i: usize = 0;
        while (i < n_leaves) : (i += 1) {
            if (self.nodes[i * 2] == null) {
                leaf_index = i;
                break;
            }
        }
        if (leaf_index == null) {
            const old_width = self.nodes.len;
            const new_width = if (old_width == 0) 1 else old_width * 2 + 1;
            const new_nodes = try self.allocator.realloc(self.nodes, new_width);
            for (new_nodes[old_width..]) |*slot| slot.* = null;
            self.nodes = new_nodes;
            leaf_index = n_leaves;
            n_leaves = self.nLeaves();
        }
        const li = leaf_index.?;
        self.nodes[li * 2] = .{ .leaf = leaf };

        var path_buf: [treemath.max_path_len]usize = undefined;
        const path = try treemath.direct_path(li * 2, n_leaves, &path_buf);
        for (path) |idx| {
            if (self.nodes[idx]) |node| switch (node) {
                .parent => |p| {
                    const updated = try p.withAppendedUnmerged(self.allocator, @intCast(li));
                    self.allocator.free(p.unmerged_leaves);
                    self.nodes[idx] = .{ .parent = updated };
                },
                .leaf => {}, // an internal direct-path node is always a parent slot; defensive no-op otherwise
            };
        }
        return li;
    }

    /// RFC 9420 §12.1.2 Update proposal application: replace the sender's
    /// `LeafNode`, blank the direct path. Takes ownership of `new_leaf`.
    pub fn updateLeaf(self: *RatchetTree, sender_index: usize, new_leaf: LeafNode) !void {
        const li = sender_index * 2;
        if (li >= self.nodes.len) return error.InvalidLeafIndex;
        self.blank(li);
        self.nodes[li] = .{ .leaf = new_leaf };
        const n_leaves = self.nLeaves();
        var path_buf: [treemath.max_path_len]usize = undefined;
        const path = try treemath.direct_path(li, n_leaves, &path_buf);
        for (path) |idx| self.blank(idx);
    }

    fn hasNonBlankLeaf(nodes: []const ?Node) bool {
        var i: usize = 0;
        while (i < nodes.len) : (i += 2) if (nodes[i] != null) return true;
        return false;
    }

    /// RFC 9420 §12.1.3 Remove proposal application + §7.7's truncation:
    /// blank the removed leaf and its direct path, then repeatedly drop
    /// the tree's right subtree while it holds no non-blank leaf.
    pub fn removeLeaf(self: *RatchetTree, removed_index: usize) !void {
        const li = removed_index * 2;
        if (li >= self.nodes.len) return error.InvalidLeafIndex;
        self.blank(li);
        var n_leaves = self.nLeaves();
        var path_buf: [treemath.max_path_len]usize = undefined;
        const path = try treemath.direct_path(li, n_leaves, &path_buf);
        for (path) |idx| self.blank(idx);

        while (n_leaves > 1) {
            const root_idx = treemath.root(n_leaves);
            const left_idx = treemath.left(root_idx) orelse break;
            // The left subtree occupies indices `[0, 2*left_idx+1)` — NOT
            // `[0, left_idx]`: `left_idx` is the ARRAY INDEX of the left
            // subtree's own ROOT node (the middle of that span), not its
            // boundary. For a perfect tree the left subtree of an
            // `n_leaves`-leaf tree always has exactly `n_leaves/2` leaves,
            // so its width is `2*left_idx + 1` (`node_width(n_leaves/2)`,
            // which for power-of-two `n_leaves` equals `2*left_idx+1`
            // algebraically: `left_idx = n_leaves/2 - 1`). `right_subtree`
            // starts one slot after the ROOT (`root_idx`, at index
            // `2*left_idx+1`), i.e. at `2*left_idx+2`.
            const right_subtree = self.nodes[2 * left_idx + 2 ..];
            if (hasNonBlankLeaf(right_subtree)) break;
            for (right_subtree) |m| if (m) |n| n.deinit(self.allocator);
            self.nodes = try self.allocator.realloc(self.nodes, 2 * left_idx + 1);
            n_leaves = self.nLeaves();
        }
    }
};
