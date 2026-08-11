// SPDX-License-Identifier: MIT
//! mls.framing — RFC 9420 §6 (Message Framing): the layer that turns a
//! Proposal/Commit/application payload into something that can safely cross
//! an untrusted network, and back.
//!
//! §6's own structure, which this file follows exactly:
//!
//! * **§6 itself** — `ProtocolVersion`/`ContentType`/`SenderType`/`Sender`/
//!   `WireFormat`, `FramedContent` (the payload plus who sent it, in which
//!   group, at which epoch), `MLSMessage` (the outermost envelope), and
//!   `AuthenticatedContent` (`wire_format` + content + auth — the form
//!   "most of the protocol" handles messages in, per §6's opening).
//! * **§6.1 Content Authentication** — `FramedContentTBS` (what gets
//!   signed) and `FramedContentAuthData` (the signature, plus a
//!   `confirmation_tag` iff the content is a Commit).
//! * **§6.2 Encoding and Decoding a Public Message** — `PublicMessage`,
//!   `AuthenticatedContentTBM`, and the `membership_tag` that proves the
//!   sender is in the group.
//! * **§6.3 Encoding and Decoding a Private Message** — `PrivateMessage`,
//!   with §6.3.1's `PrivateMessageContent`/`PrivateContentAAD`/reuse-guard
//!   and §6.3.2's `SenderData`/`SenderDataAAD`/`ciphertext_sample`.
//!
//! **Three things here are easy to get subtly wrong and are therefore
//! spelled out rather than inferred.**
//!
//! 1. *The signature covers the wire format.* `FramedContentTBS` starts
//!    `version || wire_format`, so the same `FramedContent` signed for a
//!    `PublicMessage` and for a `PrivateMessage` produces DIFFERENT
//!    signatures. That is deliberate (§6.1: the signature "covers the
//!    message content and the wire format that will be used for this
//!    message") — it stops a handshake message from being lifted out of
//!    its encrypted envelope and replayed in the clear. `protectPublic`/
//!    `protectPrivate` therefore each pass their own `WireFormat` into the
//!    TBS; there is no "sign once, encode either way" path, and there
//!    must not be.
//! 2. *The GroupContext is in the TBS for `member`/`new_member_commit`
//!    senders only.* §6.1's `select` gives `external`/
//!    `new_member_proposal` an empty struct. A verifier that always
//!    appended the context (or never did) would accept a signature from
//!    the wrong epoch or reject a legitimate external proposal.
//! 3. *The reuse guard is XORed into the nonce, not appended to it.*
//!    §6.3.1: the sender XORs a fresh random four-byte value into the
//!    FIRST four bytes of the key-schedule nonce and ships it in
//!    `SenderData.reuse_guard`. It is a defence against key-schedule state
//!    loss (a replayed generation would otherwise reuse an exact
//!    key/nonce pair), not a source of entropy for the AEAD — the receiver
//!    must apply the identical XOR before decrypting.
//!
//! **Padding is a receiver-enforced invariant, not a formatting nicety.**
//! §6.3.1 requires the padding octets to be all-zero and requires the
//! receiver to REJECT the message otherwise; `parsePrivateContent` returns
//! `error.NonZeroPadding`. Without that check the padding region is a
//! covert channel out of the encrypted envelope, which is exactly the
//! reason the RFC makes it a MUST.
//!
//! **What this file deliberately does not do.** No key lookup: choosing
//! which leaf's ratchet and which generation a message decrypts under is
//! the caller's (a `secrettree.Window` per leaf, keyed by the `SenderData`
//! this file hands back). No membership/tree validation: whether
//! `SenderData.leaf_index` names a non-blank leaf (§6.3.2's closing MUST)
//! needs a `RatchetTree` this file has no reference to — `decryptSenderData`
//! returns the index for the caller to check. There is deliberately no
//! single `unprotectPrivate` either: §6.3.2's sender data names the key
//! §6.3.1's content needs, and resolving that key is the step this file
//! cannot do, so the three stages are separate. No proposal/commit
//! SEMANTICS: see `content.zig`.
//!
//! Model: RFC 9420 §6/§6.1/§6.2/§6.3/§6.3.1/§6.3.2, plus §17.2's MLS Wire
//! Formats registry for `WireFormat` values. Anchored byte-exact against
//! the official `mlswg/mls-implementations` `message-protection.json`
//! (full protect/unprotect with real keys: `PrivateMessage` for all three
//! content types, `PublicMessage` for the two handshake types, and the
//! refusal of the third) and `messages.json` (wire round-trips) — see
//! `kat_framing_test.zig`/`kat_messages_test.zig` and `NOTICE`.

const std = @import("std");
const codec = @import("codec.zig");
const crypto = @import("crypto.zig");
const suite = @import("suite.zig");
const tree = @import("tree.zig");
const content_mod = @import("content.zig");
const keypackage = @import("keypackage.zig");
const keyschedule = @import("keyschedule.zig");
const secrettree = @import("secrettree.zig");
const wire = @import("wire_lists.zig");
// `welcome.zig` imports `transcript.zig`, which imports this file back —
// a legal import cycle in Zig (files are analyzed lazily) and NOT a type
// cycle: no struct here contains one whose size depends on this one.
// `MLSMessage` carries `welcome.Welcome`/`welcome.GroupInfo` by value, and
// neither of those reaches back into `framing`.
const welcome_mod = @import("welcome.zig");

const varintLen = wire.varintLen;

pub const Error = error{
    /// A `FramedContentAuthData` for a Commit had no `confirmation_tag`,
    /// or a caller asked to protect a Commit without supplying one (RFC
    /// 9420 §6.1: the `select` makes it mandatory for `commit`).
    MissingConfirmationTag,
    /// A `PublicMessage` from a `member` sender had no `membership_tag`
    /// (RFC 9420 §6.2 makes it mandatory for that sender type).
    MissingMembershipTag,
    /// A signature/verification over a `member`/`new_member_commit`
    /// sender's content was attempted without the encoded `GroupContext`
    /// that RFC 9420 §6.1's `select` puts in the TBS.
    MissingGroupContext,
    /// RFC 9420 §6: "Applications MUST use PrivateMessage to encrypt
    /// application messages." `protectPublic` refuses application content
    /// rather than producing a message that is legal TLS-presentation
    /// syntax and illegal MLS.
    ApplicationContentMustBeEncrypted,
    /// A `PrivateMessageContent`'s padding region contained a non-zero
    /// octet (RFC 9420 §6.3.1: "A receiver MUST verify that there are no
    /// non-zero bytes in the padding field, and if this check fails, the
    /// enclosing PrivateMessage MUST be rejected as malformed").
    NonZeroPadding,
    /// A `SenderData` was requested for a sender whose `sender_type` is
    /// not `member` (RFC 9420 §6.3.2: "the sender MUST verify
    /// Sender.sender_type is member").
    SenderNotMember,
    /// An AEAD open failed — a wrong key/nonce/AAD, or a tampered
    /// ciphertext. Deliberately one error for all three: distinguishing
    /// them would leak which part of the header an attacker got right.
    DecryptionFailed,
    /// A `PrivateMessage`'s `ciphertext`/`encrypted_sender_data` was
    /// shorter than the AEAD tag, so it cannot be a valid sealed message
    /// at all.
    CiphertextTooShort,
} || tree.Error || keyschedule.Error || secrettree.Error;

// ── §6 / §17.2: the enums ─────────────────────────────────────────────────

/// RFC 9420 §17.2's "MLS Wire Formats" registry (Table 8). Non-exhaustive:
/// an unknown wire format is a thing a conformant deployment may legally
/// put on the wire once the registry grows, so it must decode to a value
/// that compares and prints, not be reinterpreted.
pub const WireFormat = enum(u16) {
    reserved = 0,
    mls_public_message = 1,
    mls_private_message = 2,
    mls_welcome = 3,
    mls_group_info = 4,
    mls_key_package = 5,
    _,
};

pub const ContentType = enum(u8) { reserved = 0, application = 1, proposal = 2, commit = 3, _ };

pub const SenderType = enum(u8) {
    reserved = 0,
    member = 1,
    external = 2,
    new_member_proposal = 3,
    new_member_commit = 4,
    _,
};

/// RFC 9420 §6's `Sender`. The two index-carrying arms are different
/// indices into different things — `member`'s is a leaf index in the
/// ratchet tree, `external`'s is an index into the `external_senders`
/// group-context extension (§12.1.8.1) — so they are separate arms rather
/// than one `index` field with a type tag beside it.
pub const Sender = union(enum) {
    member: u32,
    external: u32,
    new_member_proposal,
    new_member_commit,

    pub fn senderType(self: Sender) SenderType {
        return switch (self) {
            .member => .member,
            .external => .external,
            .new_member_proposal => .new_member_proposal,
            .new_member_commit => .new_member_commit,
        };
    }

    /// RFC 9420 §6.1's `select (FramedContentTBS.content.sender
    /// .sender_type)`: `member` and `new_member_commit` put the
    /// `GroupContext` in the signed content; `external` and
    /// `new_member_proposal` put nothing.
    pub fn tbsIncludesGroupContext(self: Sender) bool {
        return switch (self) {
            .member, .new_member_commit => true,
            .external, .new_member_proposal => false,
        };
    }

    pub fn encodedLen(self: Sender) usize {
        return 1 + switch (self) {
            .member, .external => @as(usize, 4),
            .new_member_proposal, .new_member_commit => 0,
        };
    }
    pub fn encode(self: Sender, w: *codec.Writer) codec.Error!void {
        try w.writeEnum(SenderType, self.senderType());
        switch (self) {
            .member, .external => |idx| try w.writeU32(idx),
            .new_member_proposal, .new_member_commit => {},
        }
    }
    pub fn decode(r: *codec.Reader) codec.Error!Sender {
        return switch (try r.readEnum(SenderType)) {
            .member => .{ .member = try r.readU32() },
            .external => .{ .external = try r.readU32() },
            .new_member_proposal => .new_member_proposal,
            .new_member_commit => .new_member_commit,
            else => error.Malformed,
        };
    }
};

// ── §6: FramedContent ─────────────────────────────────────────────────────

/// The `select (FramedContent.content_type)` body. `application`'s payload
/// aliases caller memory; `proposal`/`commit` own whatever their own
/// `deinit` frees.
pub const FramedContentBody = union(enum) {
    application: []const u8,
    proposal: content_mod.Proposal,
    commit: content_mod.Commit,

    pub fn contentType(self: FramedContentBody) ContentType {
        return switch (self) {
            .application => .application,
            .proposal => .proposal,
            .commit => .commit,
        };
    }

    /// Which of a leaf's two §9.1 ratchets encrypts this body (RFC 9420
    /// §6.3.1: "the sender ... chooses an unused generation from either the
    /// handshake ratchet or the application ratchet, depending on the
    /// content type of the message").
    pub fn ratchetKind(self: FramedContentBody) secrettree.RatchetKind {
        return switch (self) {
            .application => .application,
            .proposal, .commit => .handshake,
        };
    }

    pub fn encodedLen(self: FramedContentBody) usize {
        return switch (self) {
            .application => |d| varintLen(d.len) + d.len,
            .proposal => |p| p.encodedLen(),
            .commit => |c| c.encodedLen(),
        };
    }
    pub fn encode(self: FramedContentBody, w: *codec.Writer) Error!void {
        switch (self) {
            .application => |d| try w.writeVector(d),
            .proposal => |p| try p.encode(w),
            .commit => |c| try c.encode(w),
        }
    }
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader, ct: ContentType) !FramedContentBody {
        return switch (ct) {
            .application => .{ .application = try r.readVector() },
            .proposal => .{ .proposal = try content_mod.Proposal.decode(allocator, r) },
            .commit => .{ .commit = try content_mod.Commit.decode(allocator, r) },
            else => error.Malformed,
        };
    }
    pub fn deinit(self: FramedContentBody, allocator: std.mem.Allocator) void {
        switch (self) {
            .application => {},
            .proposal => |p| p.deinit(allocator),
            .commit => |c| c.deinit(allocator),
        }
    }
};

/// RFC 9420 §6's `FramedContent`. Note the field ORDER: `content_type` sits
/// AFTER `authenticated_data`, immediately before the body it selects — not
/// beside `sender` where a reader skimming the struct might expect it. The
/// same order is reused (minus `sender`) by `PrivateMessage` and its two
/// AAD structures, which is what lets a receiver read the AAD fields
/// straight off a `PrivateMessage` header without parsing the encrypted
/// part first.
pub const FramedContent = struct {
    group_id: []const u8,
    epoch: u64,
    sender: Sender,
    /// Data the sender wants authenticated but not encrypted — it is in
    /// the AEAD's AAD, in the clear on the wire (§6.3.1: "It is up to the
    /// application to decide what authenticated_data to provide").
    authenticated_data: []const u8 = &.{},
    body: FramedContentBody,

    pub fn contentType(self: FramedContent) ContentType {
        return self.body.contentType();
    }

    pub fn encodedLen(self: FramedContent) usize {
        return varintLen(self.group_id.len) + self.group_id.len + 8 +
            self.sender.encodedLen() +
            varintLen(self.authenticated_data.len) + self.authenticated_data.len +
            1 + self.body.encodedLen();
    }

    pub fn encode(self: FramedContent, w: *codec.Writer) Error!void {
        try w.writeVector(self.group_id);
        try w.writeU64(self.epoch);
        try self.sender.encode(w);
        try w.writeVector(self.authenticated_data);
        try w.writeEnum(ContentType, self.contentType());
        try self.body.encode(w);
    }

    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !FramedContent {
        const group_id = try r.readVector();
        const epoch = try r.readU64();
        const sender = try Sender.decode(r);
        const ad = try r.readVector();
        const ct = try r.readEnum(ContentType);
        const body = try FramedContentBody.decode(allocator, r, ct);
        return .{
            .group_id = group_id,
            .epoch = epoch,
            .sender = sender,
            .authenticated_data = ad,
            .body = body,
        };
    }

    pub fn deinit(self: FramedContent, allocator: std.mem.Allocator) void {
        self.body.deinit(allocator);
    }
};

// ── §6.1: FramedContentAuthData / FramedContentTBS ────────────────────────

/// RFC 9420 §6.1. `confirmation_tag` is present iff the content is a
/// Commit; it is `?[]const u8` rather than a fixed `[S.Nm]u8` because this
/// struct is a WIRE shape (`opaque MAC<V>`) that must round-trip a tag of
/// whatever length arrived, including a wrong one — verifying its length
/// is `keyschedule.verifyConfirmationTag`'s job, not the decoder's.
pub const FramedContentAuthData = struct {
    signature: []const u8,
    confirmation_tag: ?[]const u8 = null,

    /// NOTE: this struct deliberately has NO bare `encodedLen()`, unlike
    /// every other wire type in this module. Its encoded length depends on
    /// the enclosing `FramedContent`'s type, which it does not carry — a
    /// no-argument version could only guess from `confirmation_tag !=
    /// null`, and would then disagree with `encode` for the one case that
    /// matters (a non-Commit that happens to carry a tag). `encodedLenFor`
    /// takes the discriminant instead.
    /// `ct` is the enclosing content's type — the RFC's `select` discriminant
    /// lives in `FramedContent`, not in this struct, so it must be passed
    /// in. Encoding a Commit's auth data without a tag is
    /// `error.MissingConfirmationTag`, never a silently shorter message.
    pub fn encode(self: FramedContentAuthData, w: *codec.Writer, ct: ContentType) Error!void {
        try w.writeVector(self.signature);
        if (ct == .commit) try w.writeVector(self.confirmation_tag orelse return error.MissingConfirmationTag);
    }

    pub fn decode(r: *codec.Reader, ct: ContentType) Error!FramedContentAuthData {
        const sig = try r.readVector();
        const tag: ?[]const u8 = if (ct == .commit) try r.readVector() else null;
        return .{ .signature = sig, .confirmation_tag = tag };
    }

    /// `encodedLen` for the `ct` a caller is about to encode under —
    /// differs from `encodedLen()` only if the struct's tag and the content
    /// type disagree, which `encode` then rejects.
    pub fn encodedLenFor(self: FramedContentAuthData, ct: ContentType) usize {
        var n = varintLen(self.signature.len) + self.signature.len;
        if (ct == .commit) {
            const t = self.confirmation_tag orelse return n; // encode() will error
            n += varintLen(t.len) + t.len;
        }
        return n;
    }
};

/// RFC 9420 §6.1's `FramedContentTBS` — the exact bytes `SignWithLabel(.,
/// "FramedContentTBS", .)` is applied to.
///
/// `group_context` is the ALREADY-ENCODED `GroupContext` (§8.1), matching
/// `keyschedule`'s convention of taking encoded bytes: a caller who already
/// holds the wire form (off a `GroupInfo`, say) must not have to
/// round-trip through the struct and risk a re-encode that differs by a
/// byte. It is required exactly when `sender.tbsIncludesGroupContext()`.
pub const label_framed_content_tbs = "FramedContentTBS";

/// The `WireFormat` is not a parameter here even though `framedContentTbsEncode`
/// takes one: it is a fixed-width `uint16` whose two bytes are already in the
/// constant below, so its VALUE cannot change the length.
pub fn framedContentTbsLen(fc: FramedContent, group_context: ?[]const u8) Error!usize {
    var n: usize = 2 + 2 + fc.encodedLen(); // ProtocolVersion + WireFormat
    if (fc.sender.tbsIncludesGroupContext()) n += (group_context orelse return error.MissingGroupContext).len;
    return n;
}

pub fn framedContentTbsEncode(w: *codec.Writer, wf: WireFormat, fc: FramedContent, group_context: ?[]const u8) Error!void {
    try w.writeEnum(keyschedule.ProtocolVersion, .mls10);
    try w.writeEnum(WireFormat, wf);
    try fc.encode(w);
    if (fc.sender.tbsIncludesGroupContext()) {
        try w.writeBytes(group_context orelse return error.MissingGroupContext);
    }
}

/// Serializes a `FramedContentTBS` into a fresh allocation (caller frees).
pub fn framedContentTbsAlloc(allocator: std.mem.Allocator, wf: WireFormat, fc: FramedContent, group_context: ?[]const u8) ![]u8 {
    const buf = try allocator.alloc(u8, try framedContentTbsLen(fc, group_context));
    errdefer allocator.free(buf);
    var w = codec.Writer.init(buf);
    try framedContentTbsEncode(&w, wf, fc, group_context);
    std.debug.assert(w.finish().len == buf.len);
    return buf;
}

/// RFC 9420 §6.1: `SignWithLabel(., "FramedContentTBS", FramedContentTBS)`.
/// The signing key is chosen by sender type (§6.1's four bullets: the leaf's
/// key for `member`, the `external_senders` key for `external`, the Commit
/// path's leaf for `new_member_commit`, the Add's KeyPackage leaf for
/// `new_member_proposal`) — this function signs with whatever key pair it
/// is handed and does not enforce that choice, which needs a tree.
pub fn signFramedContent(
    comptime S: type,
    allocator: std.mem.Allocator,
    key_pair: S.Sig.KeyPair,
    wf: WireFormat,
    fc: FramedContent,
    group_context: ?[]const u8,
) !S.Sig.Signature {
    const tbs = try framedContentTbsAlloc(allocator, wf, fc, group_context);
    defer allocator.free(tbs);
    return crypto.SignWithLabelAlloc(S, allocator, key_pair, label_framed_content_tbs, tbs);
}

/// The verification counterpart. Only suite `0x0001` (Ed25519) is wired, so
/// a `signature`/`public_key` of another length is `error.WrongKeyLength`
/// — same handling as `tree.LeafNode.verifySignature`.
pub fn verifyFramedContent(
    comptime S: type,
    allocator: std.mem.Allocator,
    public_key: S.Sig.PublicKey,
    ac: AuthenticatedContent,
    group_context: ?[]const u8,
) !void {
    if (ac.auth.signature.len != S.Nx) return error.WrongKeyLength;
    const tbs = try framedContentTbsAlloc(allocator, ac.wire_format, ac.content, group_context);
    defer allocator.free(tbs);
    var sig_bytes: [S.Nx]u8 = undefined;
    @memcpy(&sig_bytes, ac.auth.signature);
    try crypto.VerifyWithLabelAlloc(S, allocator, public_key, label_framed_content_tbs, tbs, S.Sig.Signature.fromBytes(sig_bytes));
}

// ── §6: AuthenticatedContent ──────────────────────────────────────────────

/// RFC 9420 §6's `AuthenticatedContent` — "In most of the protocol,
/// messages are handled in the form of AuthenticatedContent objects."
/// It is also the value §5.2's `MakeProposalRef` hashes and the value
/// §8.2's transcript hashes are computed from (see `transcript.zig`), which
/// is why its ENCODING matters even though it never appears on the wire as
/// a message in its own right.
pub const AuthenticatedContent = struct {
    wire_format: WireFormat,
    content: FramedContent,
    auth: FramedContentAuthData,

    pub fn encodedLen(self: AuthenticatedContent) usize {
        return 2 + self.content.encodedLen() + self.auth.encodedLenFor(self.content.contentType());
    }
    pub fn encode(self: AuthenticatedContent, w: *codec.Writer) Error!void {
        try w.writeEnum(WireFormat, self.wire_format);
        try self.content.encode(w);
        try self.auth.encode(w, self.content.contentType());
    }
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !AuthenticatedContent {
        const wf = try r.readEnum(WireFormat);
        const fc = try FramedContent.decode(allocator, r);
        errdefer fc.deinit(allocator);
        const auth = try FramedContentAuthData.decode(r, fc.contentType());
        return .{ .wire_format = wf, .content = fc, .auth = auth };
    }
    pub fn deinit(self: AuthenticatedContent, allocator: std.mem.Allocator) void {
        self.content.deinit(allocator);
    }
    pub fn encodeAlloc(self: AuthenticatedContent, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, self.encodedLen());
        errdefer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.encode(&w);
        std.debug.assert(w.finish().len == buf.len);
        return buf;
    }
};

/// RFC 9420 §5.2's `MakeProposalRef` applied to the `AuthenticatedContent`
/// a Proposal was sent in — the value a later `Commit` puts in a
/// by-reference `ProposalOrRef` (`content.ProposalOrRef.reference`). Lives
/// here rather than in `content.zig` because it needs this file's encoding;
/// see `content.zig`'s doc comment.
pub fn proposalRef(comptime S: type, allocator: std.mem.Allocator, ac: AuthenticatedContent) ![S.Hash.digest_length]u8 {
    const bytes = try ac.encodeAlloc(allocator);
    defer allocator.free(bytes);
    return crypto.make_proposal_ref(S, bytes);
}

// ── §6.2: PublicMessage ───────────────────────────────────────────────────

/// RFC 9420 §6.2. `membership_tag` is present iff the sender is a `member`.
pub const PublicMessage = struct {
    content: FramedContent,
    auth: FramedContentAuthData,
    membership_tag: ?[]const u8 = null,

    pub fn encodedLen(self: PublicMessage) usize {
        return self.content.encodedLen() +
            self.auth.encodedLenFor(self.content.contentType()) +
            (if (self.membership_tag) |t| varintLen(t.len) + t.len else 0);
    }

    pub fn encode(self: PublicMessage, w: *codec.Writer) Error!void {
        try self.content.encode(w);
        try self.auth.encode(w, self.content.contentType());
        if (self.content.sender == .member) {
            try w.writeVector(self.membership_tag orelse return error.MissingMembershipTag);
        }
    }

    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !PublicMessage {
        const fc = try FramedContent.decode(allocator, r);
        errdefer fc.deinit(allocator);
        const auth = try FramedContentAuthData.decode(r, fc.contentType());
        const tag: ?[]const u8 = if (fc.sender == .member) try r.readVector() else null;
        return .{ .content = fc, .auth = auth, .membership_tag = tag };
    }

    pub fn deinit(self: PublicMessage, allocator: std.mem.Allocator) void {
        self.content.deinit(allocator);
    }

    /// The `AuthenticatedContent` this message decodes to (§6: "these
    /// protections are enforced ... when decoding a PublicMessage or
    /// PrivateMessage into an AuthenticatedContent object"). The
    /// `wire_format` is `mls_public_message` by construction — it is what
    /// the signature covers, so it cannot be read off the message body.
    pub fn authenticatedContent(self: PublicMessage) AuthenticatedContent {
        return .{ .wire_format = .mls_public_message, .content = self.content, .auth = self.auth };
    }

    pub fn encodeAlloc(self: PublicMessage, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, self.encodedLen());
        errdefer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.encode(&w);
        std.debug.assert(w.finish().len == buf.len);
        return buf;
    }
};

/// RFC 9420 §6.2's `AuthenticatedContentTBM` = `FramedContentTBS` followed
/// by `FramedContentAuthData`. Serialized into a fresh allocation (caller
/// frees) — this is the input to `MAC(membership_key, ·)`.
pub fn authenticatedContentTbmAlloc(
    allocator: std.mem.Allocator,
    fc: FramedContent,
    auth: FramedContentAuthData,
    group_context: ?[]const u8,
) ![]u8 {
    const ct = fc.contentType();
    const total = (try framedContentTbsLen(fc, group_context)) + auth.encodedLenFor(ct);
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);
    var w = codec.Writer.init(buf);
    try framedContentTbsEncode(&w, .mls_public_message, fc, group_context);
    try auth.encode(&w, ct);
    std.debug.assert(w.finish().len == buf.len);
    return buf;
}

/// RFC 9420 §6.2: `membership_tag = MAC(membership_key,
/// AuthenticatedContentTBM)`. The MAC itself is
/// `keyschedule.membershipTag`; this function is the missing half it
/// documented as "a Part 5 framing structure".
pub fn membershipTag(
    comptime S: type,
    allocator: std.mem.Allocator,
    membership_key: [S.Nh]u8,
    fc: FramedContent,
    auth: FramedContentAuthData,
    group_context: ?[]const u8,
) ![S.Nm]u8 {
    const tbm = try authenticatedContentTbmAlloc(allocator, fc, auth, group_context);
    defer allocator.free(tbm);
    return keyschedule.membershipTag(S, membership_key, tbm);
}

/// Constant-time verification of a received `PublicMessage`'s
/// `membership_tag`. A message from a non-`member` sender has no tag to
/// check and returns successfully — §6.2's `select` gives those sender
/// types an empty struct, and their authenticity rests on the signature
/// alone (§12.1.8: an external proposal's signer is named by the
/// `external_senders` extension).
pub fn verifyMembershipTag(
    comptime S: type,
    allocator: std.mem.Allocator,
    membership_key: [S.Nh]u8,
    pm: PublicMessage,
    group_context: ?[]const u8,
) !void {
    if (pm.content.sender != .member) return;
    const tag = pm.membership_tag orelse return error.MissingMembershipTag;
    const tbm = try authenticatedContentTbmAlloc(allocator, pm.content, pm.auth, group_context);
    defer allocator.free(tbm);
    try keyschedule.verifyMembershipTag(S, membership_key, tbm, tag);
}

/// Everything a sender needs to turn a `FramedContent` into a
/// `PublicMessage` (RFC 9420 §12.4.1's "If encoding as PublicMessage,
/// compute the membership_tag value" step, generalized to all content
/// types).
pub fn ProtectPublicParams(comptime S: type) type {
    return struct {
        signature_key_pair: S.Sig.KeyPair,
        membership_key: [S.Nh]u8,
        /// The encoded `GroupContext` (§8.1). Required for `member`/
        /// `new_member_commit` senders; ignored otherwise.
        group_context: ?[]const u8 = null,
        content: FramedContent,
        /// Required iff `content` is a Commit. Computed by
        /// `keyschedule.confirmationTag` over the NEW epoch's
        /// `confirmed_transcript_hash` — see `transcript.zig`.
        confirmation_tag: ?[]const u8 = null,
    };
}

/// RFC 9420 §6.2's encode path: sign, MAC, and serialize. Returns freshly
/// allocated `PublicMessage` wire bytes (caller frees) — bytes rather than
/// a struct because the struct's `signature`/`membership_tag` fields alias
/// memory that would have to be owned somewhere, and the thing a sender
/// actually wants is the bytes.
///
/// Refuses application content: RFC 9420 §6 requires application messages
/// to be encrypted (`error.ApplicationContentMustBeEncrypted`). The
/// official `message-protection.json` vector's procedure checks exactly
/// this ("For the application message, instead verify that protecting as a
/// PublicMessage fails").
pub fn protectPublic(comptime S: type, allocator: std.mem.Allocator, params: ProtectPublicParams(S)) ![]u8 {
    if (params.content.contentType() == .application) return error.ApplicationContentMustBeEncrypted;
    if (params.content.contentType() == .commit and params.confirmation_tag == null) {
        return error.MissingConfirmationTag;
    }

    const sig = try signFramedContent(
        S,
        allocator,
        params.signature_key_pair,
        .mls_public_message,
        params.content,
        params.group_context,
    );
    const sig_bytes = sig.toBytes();
    const auth: FramedContentAuthData = .{
        .signature = &sig_bytes,
        .confirmation_tag = params.confirmation_tag,
    };

    var pm: PublicMessage = .{ .content = params.content, .auth = auth };
    var tag: [S.Nm]u8 = undefined;
    if (params.content.sender == .member) {
        tag = try membershipTag(S, allocator, params.membership_key, params.content, auth, params.group_context);
        pm.membership_tag = &tag;
    }
    return pm.encodeAlloc(allocator);
}

/// RFC 9420 §6.2's decode path: "the application MUST check membership_tag
/// and MUST check that the FramedContentAuthData is valid". Both are done
/// here; the returned `PublicMessage` aliases `bytes` and owns the
/// allocations its `deinit` frees.
///
/// The signature public key is the caller's to supply, because finding it
/// means walking a ratchet tree (`member`) or a group-context extension
/// (`external`) — see `signFramedContent`'s doc comment.
pub fn unprotectPublic(
    comptime S: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    signature_public_key: S.Sig.PublicKey,
    membership_key: [S.Nh]u8,
    group_context: ?[]const u8,
) !PublicMessage {
    var r = codec.Reader.init(bytes);
    const pm = try PublicMessage.decode(allocator, &r);
    errdefer pm.deinit(allocator);
    try verifyMembershipTag(S, allocator, membership_key, pm, group_context);
    try verifyFramedContent(S, allocator, signature_public_key, pm.authenticatedContent(), group_context);
    return pm;
}

// ── §6.3.2: SenderData ────────────────────────────────────────────────────

/// RFC 9420 §6.3.2's `SenderData` — fixed width (4 + 4 + 4), so no varints
/// and no allocation.
pub const SenderData = struct {
    leaf_index: u32,
    generation: u32,
    reuse_guard: [4]u8,

    pub const encoded_len: usize = 12;

    pub fn encode(self: SenderData, w: *codec.Writer) codec.Error!void {
        try w.writeU32(self.leaf_index);
        try w.writeU32(self.generation);
        try w.writeBytes(&self.reuse_guard);
    }
    pub fn decode(r: *codec.Reader) codec.Error!SenderData {
        const leaf_index = try r.readU32();
        const generation = try r.readU32();
        var guard: [4]u8 = undefined;
        @memcpy(&guard, try r.readBytes(4));
        return .{ .leaf_index = leaf_index, .generation = generation, .reuse_guard = guard };
    }
};

/// RFC 9420 §6.3.1's reuse guard, applied: the first four bytes of the
/// key-schedule nonce XORed with `reuse_guard`, the rest untouched.
/// Involutive — the same function is used to protect and to unprotect.
pub fn applyReuseGuard(comptime S: type, nonce: [S.Nn]u8, reuse_guard: [4]u8) [S.Nn]u8 {
    var out = nonce;
    for (reuse_guard, 0..) |g, i| out[i] ^= g;
    return out;
}

// ── §6.3: PrivateMessage ──────────────────────────────────────────────────

/// RFC 9420 §6.3. Every field aliases caller memory; nothing here is
/// allocated, because a `PrivateMessage` is entirely opaque bytes until its
/// two AEADs are opened.
pub const PrivateMessage = struct {
    group_id: []const u8,
    epoch: u64,
    content_type: ContentType,
    authenticated_data: []const u8 = &.{},
    encrypted_sender_data: []const u8,
    ciphertext: []const u8,

    pub fn encodedLen(self: PrivateMessage) usize {
        return varintLen(self.group_id.len) + self.group_id.len + 8 + 1 +
            varintLen(self.authenticated_data.len) + self.authenticated_data.len +
            varintLen(self.encrypted_sender_data.len) + self.encrypted_sender_data.len +
            varintLen(self.ciphertext.len) + self.ciphertext.len;
    }
    pub fn encode(self: PrivateMessage, w: *codec.Writer) codec.Error!void {
        try w.writeVector(self.group_id);
        try w.writeU64(self.epoch);
        try w.writeEnum(ContentType, self.content_type);
        try w.writeVector(self.authenticated_data);
        try w.writeVector(self.encrypted_sender_data);
        try w.writeVector(self.ciphertext);
    }
    pub fn decode(r: *codec.Reader) codec.Error!PrivateMessage {
        return .{
            .group_id = try r.readVector(),
            .epoch = try r.readU64(),
            .content_type = try r.readEnum(ContentType),
            .authenticated_data = try r.readVector(),
            .encrypted_sender_data = try r.readVector(),
            .ciphertext = try r.readVector(),
        };
    }
    pub fn encodeAlloc(self: PrivateMessage, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, self.encodedLen());
        errdefer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.encode(&w);
        std.debug.assert(w.finish().len == buf.len);
        return buf;
    }

    /// RFC 9420 §6.3.2's `SenderDataAAD` — the first three fields of this
    /// struct, re-encoded. Written into `out`, which must be at least
    /// `senderDataAadLen()` bytes.
    pub fn senderDataAadLen(self: PrivateMessage) usize {
        return varintLen(self.group_id.len) + self.group_id.len + 8 + 1;
    }
    pub fn senderDataAad(self: PrivateMessage, out: []u8) codec.Error![]u8 {
        var w = codec.Writer.init(out);
        try w.writeVector(self.group_id);
        try w.writeU64(self.epoch);
        try w.writeEnum(ContentType, self.content_type);
        return w.finish();
    }

    /// RFC 9420 §6.3.1's `PrivateContentAAD` — `SenderDataAAD` plus
    /// `authenticated_data`. The two AADs are deliberately different: the
    /// sender-data AEAD is opened BEFORE `authenticated_data` has been
    /// authenticated by anything, so binding it there would be circular.
    pub fn contentAadLen(self: PrivateMessage) usize {
        return self.senderDataAadLen() + varintLen(self.authenticated_data.len) + self.authenticated_data.len;
    }
    pub fn contentAad(self: PrivateMessage, out: []u8) codec.Error![]u8 {
        var w = codec.Writer.init(out);
        try w.writeVector(self.group_id);
        try w.writeU64(self.epoch);
        try w.writeEnum(ContentType, self.content_type);
        try w.writeVector(self.authenticated_data);
        return w.finish();
    }
};

/// RFC 9420 §6.3.2: decrypt `encrypted_sender_data` and parse it. The key
/// and nonce come from `secrettree.senderDataKeys`, which samples the
/// message's own `ciphertext` — so this cannot be done before the message
/// is in hand, and a sender-data blob cannot be lifted onto a different
/// ciphertext.
pub fn decryptSenderData(
    comptime S: type,
    allocator: std.mem.Allocator,
    pm: PrivateMessage,
    sender_data_secret: [S.Nh]u8,
) !SenderData {
    const tag_len = S.Aead.tag_length;
    if (pm.encrypted_sender_data.len < tag_len) return error.CiphertextTooShort;
    const pt_len = pm.encrypted_sender_data.len - tag_len;

    const keys = try secrettree.senderDataKeys(S, sender_data_secret, pm.ciphertext);
    const aad = try allocator.alloc(u8, pm.senderDataAadLen());
    defer allocator.free(aad);
    const aad_bytes = try pm.senderDataAad(aad);

    const pt = try allocator.alloc(u8, pt_len);
    defer allocator.free(pt);
    var tag: [tag_len]u8 = undefined;
    @memcpy(&tag, pm.encrypted_sender_data[pt_len..]);
    S.Aead.decrypt(pt, pm.encrypted_sender_data[0..pt_len], tag, aad_bytes, keys.nonce, keys.key) catch
        return error.DecryptionFailed;

    var r = codec.Reader.init(pt);
    return SenderData.decode(&r);
}

/// The AEAD-opened plaintext of a `PrivateMessage.ciphertext` — i.e. an
/// encoded `PrivateMessageContent` (§6.3.1), still to be parsed by
/// `parsePrivateContent`. Freshly allocated; caller frees.
///
/// `key_nonce` is the generation named by the message's own `SenderData`,
/// drawn from the sending leaf's handshake or application ratchet per
/// `FramedContentBody.ratchetKind`. The nonce has the reuse guard applied
/// here, so callers pass the ratchet's nonce unmodified.
pub fn decryptContent(
    comptime S: type,
    allocator: std.mem.Allocator,
    pm: PrivateMessage,
    key_nonce: secrettree.KeyNonce(S),
    reuse_guard: [4]u8,
) ![]u8 {
    const tag_len = S.Aead.tag_length;
    if (pm.ciphertext.len < tag_len) return error.CiphertextTooShort;
    const pt_len = pm.ciphertext.len - tag_len;

    const aad = try allocator.alloc(u8, pm.contentAadLen());
    defer allocator.free(aad);
    const aad_bytes = try pm.contentAad(aad);

    const pt = try allocator.alloc(u8, pt_len);
    errdefer allocator.free(pt);
    var tag: [tag_len]u8 = undefined;
    @memcpy(&tag, pm.ciphertext[pt_len..]);
    S.Aead.decrypt(
        pt,
        pm.ciphertext[0..pt_len],
        tag,
        aad_bytes,
        applyReuseGuard(S, key_nonce.nonce, reuse_guard),
        key_nonce.key,
    ) catch return error.DecryptionFailed;
    return pt;
}

/// Parses a decrypted `PrivateMessageContent` (§6.3.1) and REBUILDS the
/// `AuthenticatedContent` it came from: the body and auth come from the
/// plaintext, and `group_id`/`epoch`/`content_type`/`authenticated_data`
/// come from the enclosing `PrivateMessage`'s header — which is sound
/// precisely because those four fields are the content AEAD's AAD, so the
/// tag that just verified covers them.
///
/// `sender` is not in either place: §6.3 replaces it with the encrypted
/// `SenderData`, so the caller passes the `leaf_index` it decrypted (RFC
/// 9420 §6.3.2: "the sender MUST verify Sender.sender_type is member and
/// use Sender.leaf_index").
///
/// Enforces §6.3.1's all-zero padding MUST.
pub fn parsePrivateContent(
    allocator: std.mem.Allocator,
    pm: PrivateMessage,
    plaintext: []const u8,
    leaf_index: u32,
) !AuthenticatedContent {
    var r = codec.Reader.init(plaintext);
    const body = try FramedContentBody.decode(allocator, &r, pm.content_type);
    errdefer body.deinit(allocator);
    const auth = try FramedContentAuthData.decode(&r, pm.content_type);
    for (r.remaining()) |b| if (b != 0) return error.NonZeroPadding;

    return .{
        .wire_format = .mls_private_message,
        .content = .{
            .group_id = pm.group_id,
            .epoch = pm.epoch,
            .sender = .{ .member = leaf_index },
            .authenticated_data = pm.authenticated_data,
            .body = body,
        },
        .auth = auth,
    };
}

/// Everything a sender needs to turn a `FramedContent` into a
/// `PrivateMessage`.
pub fn ProtectPrivateParams(comptime S: type) type {
    return struct {
        signature_key_pair: S.Sig.KeyPair,
        /// The encoded `GroupContext` (§8.1) — a `PrivateMessage` always
        /// comes from a `member`, so this is always required.
        group_context: []const u8,
        content: FramedContent,
        confirmation_tag: ?[]const u8 = null,
        /// The key/nonce for `generation` of the sending leaf's ratchet
        /// (`FramedContentBody.ratchetKind` picks which one).
        key_nonce: secrettree.KeyNonce(S),
        generation: u32,
        /// RFC 9420 §6.3.1: MUST be freshly random per message. This
        /// module does not generate it — the application owns randomness
        /// policy, exactly as `keyschedule.PreSharedKeyId.psk_nonce`.
        reuse_guard: [4]u8,
        sender_data_secret: [S.Nh]u8,
        /// Zero octets appended inside the encrypted envelope to blur the
        /// message's true length (§6.3.1: "It is up to the application to
        /// decide ... how much padding to add").
        padding_len: usize = 0,
    };
}

/// RFC 9420 §6.3's encode path: sign, frame, pad, encrypt the content,
/// then encrypt the sender data under a key sampled from that ciphertext.
/// Returns freshly allocated `PrivateMessage` wire bytes (caller frees).
pub fn protectPrivate(comptime S: type, allocator: std.mem.Allocator, params: ProtectPrivateParams(S)) ![]u8 {
    const ct = params.content.contentType();
    if (ct == .commit and params.confirmation_tag == null) return error.MissingConfirmationTag;
    const leaf_index = switch (params.content.sender) {
        .member => |i| i,
        else => return error.SenderNotMember, // §6.3.2's MUST
    };

    const sig = try signFramedContent(
        S,
        allocator,
        params.signature_key_pair,
        .mls_private_message,
        params.content,
        params.group_context,
    );
    const sig_bytes = sig.toBytes();
    const auth: FramedContentAuthData = .{
        .signature = &sig_bytes,
        .confirmation_tag = params.confirmation_tag,
    };

    // §6.3.1's PrivateMessageContent: body || auth || zero padding.
    const pt_len = params.content.body.encodedLen() + auth.encodedLenFor(ct) + params.padding_len;
    const pt = try allocator.alloc(u8, pt_len);
    defer allocator.free(pt);
    @memset(pt, 0);
    {
        var w = codec.Writer.init(pt);
        try params.content.body.encode(&w);
        try auth.encode(&w, ct);
        std.debug.assert(w.finish().len + params.padding_len == pt_len);
    }

    const tag_len = S.Aead.tag_length;
    const ciphertext = try allocator.alloc(u8, pt_len + tag_len);
    defer allocator.free(ciphertext);

    // The header fields are fixed before either AEAD runs, because both
    // AADs are computed from them.
    var header: PrivateMessage = .{
        .group_id = params.content.group_id,
        .epoch = params.content.epoch,
        .content_type = ct,
        .authenticated_data = params.content.authenticated_data,
        .encrypted_sender_data = &.{},
        .ciphertext = &.{},
    };

    {
        const aad = try allocator.alloc(u8, header.contentAadLen());
        defer allocator.free(aad);
        const aad_bytes = try header.contentAad(aad);
        S.Aead.encrypt(
            ciphertext[0..pt_len],
            ciphertext[pt_len..][0..tag_len],
            pt,
            aad_bytes,
            applyReuseGuard(S, params.key_nonce.nonce, params.reuse_guard),
            params.key_nonce.key,
        );
    }
    header.ciphertext = ciphertext;

    // §6.3.2: the sender-data key is sampled from the ciphertext above, so
    // this step strictly follows it.
    var sd_pt: [SenderData.encoded_len]u8 = undefined;
    {
        var w = codec.Writer.init(&sd_pt);
        try (SenderData{
            .leaf_index = leaf_index,
            .generation = params.generation,
            .reuse_guard = params.reuse_guard,
        }).encode(&w);
    }
    const sd_ct = try allocator.alloc(u8, sd_pt.len + tag_len);
    defer allocator.free(sd_ct);
    {
        const keys = try secrettree.senderDataKeys(S, params.sender_data_secret, ciphertext);
        const aad = try allocator.alloc(u8, header.senderDataAadLen());
        defer allocator.free(aad);
        const aad_bytes = try header.senderDataAad(aad);
        S.Aead.encrypt(sd_ct[0..sd_pt.len], sd_ct[sd_pt.len..][0..tag_len], &sd_pt, aad_bytes, keys.nonce, keys.key);
    }
    header.encrypted_sender_data = sd_ct;

    return header.encodeAlloc(allocator);
}

// ── §6: MLSMessage ────────────────────────────────────────────────────────

/// RFC 9420 §6's outermost envelope, covering every §17.2 wire format the
/// registry defines: `mls_public_message`, `mls_private_message` and
/// `mls_key_package` (see `keypackage.zig` for why §10's struct is here),
/// plus `mls_welcome` and `mls_group_info`, whose bodies live in
/// `welcome.zig` (RFC 9420 §12.4.3/§12.4.3.1). An unregistered wire-format
/// value is `error.Malformed` — there is nothing to decode past it.
///
/// Note the asymmetry `mls_welcome` introduces: a `Welcome` is the ONE arm
/// whose cipher suite is carried in the message itself rather than in a
/// `GroupContext`, because its recipient is by definition not yet a member
/// and has no group state to look it up in.
pub const MLSMessage = union(enum) {
    public_message: PublicMessage,
    private_message: PrivateMessage,
    key_package: keypackage.KeyPackage,
    welcome: welcome_mod.Welcome,
    group_info: welcome_mod.GroupInfo,

    pub fn wireFormat(self: MLSMessage) WireFormat {
        return switch (self) {
            .public_message => .mls_public_message,
            .private_message => .mls_private_message,
            .key_package => .mls_key_package,
            .welcome => .mls_welcome,
            .group_info => .mls_group_info,
        };
    }

    pub fn encodedLen(self: MLSMessage) usize {
        return 4 + switch (self) {
            .public_message => |m| m.encodedLen(),
            .private_message => |m| m.encodedLen(),
            .key_package => |m| m.encodedLen(),
            .welcome => |m| m.encodedLen(),
            .group_info => |m| m.encodedLen(),
        };
    }

    pub fn encode(self: MLSMessage, w: *codec.Writer) !void {
        try w.writeEnum(keyschedule.ProtocolVersion, .mls10);
        try w.writeEnum(WireFormat, self.wireFormat());
        switch (self) {
            .public_message => |m| try m.encode(w),
            .private_message => |m| try m.encode(w),
            .key_package => |m| try m.encode(w),
            .welcome => |m| try m.encode(w),
            .group_info => |m| try m.encode(w),
        }
    }

    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !MLSMessage {
        _ = try r.readEnum(keyschedule.ProtocolVersion);
        return switch (try r.readEnum(WireFormat)) {
            .mls_public_message => .{ .public_message = try PublicMessage.decode(allocator, r) },
            .mls_private_message => .{ .private_message = try PrivateMessage.decode(r) },
            .mls_key_package => .{ .key_package = try keypackage.KeyPackage.decode(allocator, r) },
            .mls_welcome => .{ .welcome = try welcome_mod.Welcome.decode(allocator, r) },
            .mls_group_info => .{ .group_info = try welcome_mod.GroupInfo.decode(allocator, r) },
            else => error.Malformed,
        };
    }

    pub fn deinit(self: MLSMessage, allocator: std.mem.Allocator) void {
        switch (self) {
            .public_message => |m| m.deinit(allocator),
            .private_message => {},
            .key_package => |m| m.deinit(allocator),
            .welcome => |m| m.deinit(allocator),
            .group_info => |m| m.deinit(allocator),
        }
    }

    pub fn encodeAlloc(self: MLSMessage, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, self.encodedLen());
        errdefer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.encode(&w);
        std.debug.assert(w.finish().len == buf.len);
        return buf;
    }
};

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;
const TestSuite = suite.default;

fn testGroupContext(allocator: std.mem.Allocator) ![]u8 {
    const gc: keyschedule.GroupContext = .{
        .cipher_suite = TestSuite.id,
        .group_id = "group",
        .epoch = 7,
        .tree_hash = &[_]u8{0x11} ** 32,
        .confirmed_transcript_hash = &[_]u8{0x22} ** 32,
    };
    return gc.encodeAlloc(allocator);
}

test "Sender: every arm round-trips, and §6.1's GroupContext select is per sender type" {
    const cases = [_]Sender{ .{ .member = 3 }, .{ .external = 9 }, .new_member_proposal, .new_member_commit };
    for (cases) |s| {
        var buf: [8]u8 = undefined;
        var w = codec.Writer.init(&buf);
        try s.encode(&w);
        try testing.expectEqual(s.encodedLen(), w.finish().len);
        var r = codec.Reader.init(w.finish());
        const back = try Sender.decode(&r);
        try testing.expect(r.atEnd());
        try testing.expectEqual(s.senderType(), back.senderType());
    }
    try testing.expect((Sender{ .member = 0 }).tbsIncludesGroupContext());
    try testing.expect(@as(Sender, .new_member_commit).tbsIncludesGroupContext());
    try testing.expect(!(Sender{ .external = 0 }).tbsIncludesGroupContext());
    try testing.expect(!@as(Sender, .new_member_proposal).tbsIncludesGroupContext());
}

test "FramedContentAuthData: a Commit without a confirmation_tag cannot be encoded" {
    var buf: [128]u8 = undefined;
    var w = codec.Writer.init(&buf);
    const auth: FramedContentAuthData = .{ .signature = &[_]u8{0xaa} ** 64 };
    try testing.expectError(error.MissingConfirmationTag, auth.encode(&w, .commit));
    // The same auth data is perfectly valid for a proposal.
    var w2 = codec.Writer.init(&buf);
    try auth.encode(&w2, .proposal);
}

test "framedContentTbs: the same content signed for public vs private differs in the wire_format field" {
    const gc = try testGroupContext(testing.allocator);
    defer testing.allocator.free(gc);
    const fc: FramedContent = .{
        .group_id = "group",
        .epoch = 7,
        .sender = .{ .member = 1 },
        .body = .{ .proposal = .{ .remove = 2 } },
    };
    const a = try framedContentTbsAlloc(testing.allocator, .mls_public_message, fc, gc);
    defer testing.allocator.free(a);
    const b = try framedContentTbsAlloc(testing.allocator, .mls_private_message, fc, gc);
    defer testing.allocator.free(b);
    try testing.expectEqual(a.len, b.len);
    try testing.expect(!std.mem.eql(u8, a, b));
    // ...and they differ in exactly the two wire_format bytes.
    try testing.expectEqualSlices(u8, a[0..2], b[0..2]); // version
    try testing.expectEqualSlices(u8, a[4..], b[4..]);
}

test "framedContentTbs: an external sender's TBS omits the GroupContext (and needs none)" {
    const gc = try testGroupContext(testing.allocator);
    defer testing.allocator.free(gc);
    const fc: FramedContent = .{
        .group_id = "group",
        .epoch = 7,
        .sender = .{ .external = 0 },
        .body = .{ .proposal = .{ .remove = 2 } },
    };
    const tbs = try framedContentTbsAlloc(testing.allocator, .mls_public_message, fc, null);
    defer testing.allocator.free(tbs);
    try testing.expectEqual(@as(usize, 4 + fc.encodedLen()), tbs.len);

    // A member sender with no context is a hard error, not a shorter TBS.
    var member = fc;
    member.sender = .{ .member = 0 };
    try testing.expectError(error.MissingGroupContext, framedContentTbsAlloc(testing.allocator, .mls_public_message, member, null));
}

test "protectPublic/unprotectPublic: a proposal round-trips and the tags are checked" {
    const gc = try testGroupContext(testing.allocator);
    defer testing.allocator.free(gc);
    var seed: [32]u8 = @splat(3);
    const kp = try TestSuite.Sig.KeyPair.generateDeterministic(seed);
    seed = @splat(0);
    const membership_key: [TestSuite.Nh]u8 = @splat(0x5c);

    const fc: FramedContent = .{
        .group_id = "group",
        .epoch = 7,
        .sender = .{ .member = 1 },
        .body = .{ .proposal = .{ .remove = 2 } },
    };
    const bytes = try protectPublic(TestSuite, testing.allocator, .{
        .signature_key_pair = kp,
        .membership_key = membership_key,
        .group_context = gc,
        .content = fc,
    });
    defer testing.allocator.free(bytes);

    const pm = try unprotectPublic(TestSuite, testing.allocator, bytes, kp.public_key, membership_key, gc);
    defer pm.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 2), pm.content.body.proposal.remove);
    try testing.expectEqual(@as(u32, 1), pm.content.sender.member);

    // A wrong membership key must fail before the signature is even reached.
    const wrong: [TestSuite.Nh]u8 = @splat(0x5d);
    try testing.expectError(
        error.MacMismatch,
        unprotectPublic(TestSuite, testing.allocator, bytes, kp.public_key, wrong, gc),
    );
}

test "protectPublic: application content is refused (RFC 9420 §6's MUST)" {
    const gc = try testGroupContext(testing.allocator);
    defer testing.allocator.free(gc);
    var seed: [32]u8 = @splat(4);
    const kp = try TestSuite.Sig.KeyPair.generateDeterministic(seed);
    seed = @splat(0);
    try testing.expectError(error.ApplicationContentMustBeEncrypted, protectPublic(TestSuite, testing.allocator, .{
        .signature_key_pair = kp,
        .membership_key = @splat(0),
        .group_context = gc,
        .content = .{
            .group_id = "group",
            .epoch = 7,
            .sender = .{ .member = 1 },
            .body = .{ .application = "hello" },
        },
    }));
}

test "protectPrivate/unprotect: application data round-trips through both AEADs" {
    const gc = try testGroupContext(testing.allocator);
    defer testing.allocator.free(gc);
    var seed: [32]u8 = @splat(5);
    const kp = try TestSuite.Sig.KeyPair.generateDeterministic(seed);
    seed = @splat(0);

    const encryption_secret: [TestSuite.Nh]u8 = @splat(0x77);
    const sender_data_secret: [TestSuite.Nh]u8 = @splat(0x88);
    const base = try secrettree.ratchetBaseSecret(TestSuite, encryption_secret, 2, 1, .application);
    var ratchet = secrettree.Ratchet(TestSuite).init(base);
    const kn = try ratchet.current();

    const fc: FramedContent = .{
        .group_id = "group",
        .epoch = 7,
        .sender = .{ .member = 1 },
        .authenticated_data = "aad",
        .body = .{ .application = "hello, group" },
    };
    const bytes = try protectPrivate(TestSuite, testing.allocator, .{
        .signature_key_pair = kp,
        .group_context = gc,
        .content = fc,
        .key_nonce = kn,
        .generation = 0,
        .reuse_guard = .{ 1, 2, 3, 4 },
        .sender_data_secret = sender_data_secret,
        .padding_len = 5,
    });
    defer testing.allocator.free(bytes);

    // `protectPrivate` produces a bare `PrivateMessage`; wrapping it in an
    // `MLSMessage` is a separate, explicit step (see `MLSMessage.encode`).
    var r = codec.Reader.init(bytes);
    const pmsg = try PrivateMessage.decode(&r);
    try testing.expect(r.atEnd());

    const sd = try decryptSenderData(TestSuite, testing.allocator, pmsg, sender_data_secret);
    try testing.expectEqual(@as(u32, 1), sd.leaf_index);
    try testing.expectEqual(@as(u32, 0), sd.generation);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, &sd.reuse_guard);

    const pt = try decryptContent(TestSuite, testing.allocator, pmsg, kn, sd.reuse_guard);
    defer testing.allocator.free(pt);
    const ac = try parsePrivateContent(testing.allocator, pmsg, pt, sd.leaf_index);
    defer ac.deinit(testing.allocator);
    try testing.expectEqualStrings("hello, group", ac.content.body.application);
    try testing.expectEqualStrings("aad", ac.content.authenticated_data);
    try verifyFramedContent(TestSuite, testing.allocator, kp.public_key, ac, gc);
}

test "decryptContent: the reuse guard is load-bearing — a wrong guard fails the AEAD" {
    const gc = try testGroupContext(testing.allocator);
    defer testing.allocator.free(gc);
    var seed: [32]u8 = @splat(6);
    const kp = try TestSuite.Sig.KeyPair.generateDeterministic(seed);
    seed = @splat(0);
    const base = try secrettree.ratchetBaseSecret(TestSuite, @splat(0x77), 2, 1, .handshake);
    var ratchet = secrettree.Ratchet(TestSuite).init(base);
    const kn = try ratchet.current();

    const bytes = try protectPrivate(TestSuite, testing.allocator, .{
        .signature_key_pair = kp,
        .group_context = gc,
        .content = .{
            .group_id = "group",
            .epoch = 7,
            .sender = .{ .member = 1 },
            .body = .{ .proposal = .{ .remove = 2 } },
        },
        .key_nonce = kn,
        .generation = 0,
        .reuse_guard = .{ 0xde, 0xad, 0xbe, 0xef },
        .sender_data_secret = @splat(0x88),
    });
    defer testing.allocator.free(bytes);

    var r = codec.Reader.init(bytes);
    const pmsg = try PrivateMessage.decode(&r);
    try testing.expectError(
        error.DecryptionFailed,
        decryptContent(TestSuite, testing.allocator, pmsg, kn, .{ 0xde, 0xad, 0xbe, 0xee }),
    );
}

test "parsePrivateContent: a non-zero padding octet is rejected (§6.3.1's MUST)" {
    const pm: PrivateMessage = .{
        .group_id = "g",
        .epoch = 1,
        .content_type = .proposal,
        .encrypted_sender_data = &.{},
        .ciphertext = &.{},
    };
    // Proposal(remove 2) || signature<V> (empty) || one non-zero pad byte.
    const plaintext = [_]u8{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01 };
    try testing.expectError(
        error.NonZeroPadding,
        parsePrivateContent(testing.allocator, pm, &plaintext, 0),
    );
    // The same bytes with a zero pad octet parse fine.
    const ok = [_]u8{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00 };
    const ac = try parsePrivateContent(testing.allocator, pm, &ok, 0);
    defer ac.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 2), ac.content.body.proposal.remove);
}

test "applyReuseGuard: involutive, and touches only the first four bytes" {
    const nonce: [TestSuite.Nn]u8 = @splat(0xa5);
    const guard = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const once = applyReuseGuard(TestSuite, nonce, guard);
    try testing.expectEqualSlices(u8, nonce[4..], once[4..]);
    try testing.expectEqualSlices(u8, &nonce, &applyReuseGuard(TestSuite, once, guard));
}

test "MLSMessage: every §17.2 wire format decodes; an unregistered value is Malformed" {
    // A truncated `mls_welcome` header now reaches the Welcome DECODER (it
    // runs out of input) rather than being refused at the wire-format
    // switch — the check that this arm is really wired, not still stubbed.
    var welcome = [_]u8{ 0x00, 0x01, 0x00, 0x03 };
    var r = codec.Reader.init(&welcome);
    try testing.expectError(error.BufferTooShort, MLSMessage.decode(testing.allocator, &r));

    var group_info = [_]u8{ 0x00, 0x01, 0x00, 0x04 };
    var rg = codec.Reader.init(&group_info);
    try testing.expectError(error.BufferTooShort, MLSMessage.decode(testing.allocator, &rg));

    var unknown = [_]u8{ 0x00, 0x01, 0xff, 0xff };
    var r2 = codec.Reader.init(&unknown);
    try testing.expectError(error.Malformed, MLSMessage.decode(testing.allocator, &r2));

    // §17.2's Table 8 values.
    try testing.expectEqual(@as(u16, 1), @intFromEnum(WireFormat.mls_public_message));
    try testing.expectEqual(@as(u16, 2), @intFromEnum(WireFormat.mls_private_message));
    try testing.expectEqual(@as(u16, 3), @intFromEnum(WireFormat.mls_welcome));
    try testing.expectEqual(@as(u16, 4), @intFromEnum(WireFormat.mls_group_info));
    try testing.expectEqual(@as(u16, 5), @intFromEnum(WireFormat.mls_key_package));
}

// ── fuzz: the outermost untrusted-wire decoder never panics/OOB ───────────

test "fuzz: MLSMessage.decode never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzMlsMessageDecode, .{});
}

fn fuzzMlsMessageDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [2048]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var r = codec.Reader.init(buf[0..len]);
    const msg = MLSMessage.decode(std.testing.allocator, &r) catch return;
    msg.deinit(std.testing.allocator);
}
