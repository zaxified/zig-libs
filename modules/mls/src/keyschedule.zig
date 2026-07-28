// SPDX-License-Identifier: MIT
//! mls.keyschedule — RFC 9420 §8, the per-epoch key schedule: the single
//! chain that turns "the group changed" into every symmetric key the group
//! uses for that epoch. Everything above this file (framing, proposals,
//! commits, welcome) consumes its outputs; nothing above it can be checked
//! for interop until this chain is byte-exact.
//!
//! **Why the ORDER matters more than the arithmetic.** Every step here is
//! one `KDF.Extract` or one `ExpandWithLabel` — individually trivial, all
//! of them already built in `crypto.zig`. What RFC 9420 §8's Figure 22
//! actually pins down is the *shape* of the graph: which value is the
//! Extract SALT and which is the IKM (the figure states this explicitly —
//! salt comes in from the top, IKM from the left, a convention that is easy
//! to invert and impossible to detect without a vector), where the
//! `GroupContext` is mixed in (twice: into `joiner_secret` and again into
//! `epoch_secret`, so a client that agrees on the tree but disagrees on the
//! group's metadata derives different keys), and that `welcome_secret`
//! branches off the *member* secret rather than off `epoch_secret`. Get any
//! of that wrong and every derived secret is still a perfectly
//! well-distributed 32 bytes — just not the same 32 bytes anyone else
//! computed. That is why this file is driven end-to-end by the official
//! `key-schedule.json` interop vectors rather than by round-trip tests.
//!
//! ```text
//!                  init_secret_[n-1]                    (salt)
//!                        |
//!   commit_secret --> KDF.Extract                       (IKM from left)
//!                        |
//!                ExpandWithLabel(., "joiner", GroupContext_[n], Nh)
//!                        |
//!                   joiner_secret
//!                        |
//!   psk_secret (or 0) -> KDF.Extract  = member secret
//!                        |
//!                        +--> DeriveSecret(., "welcome") = welcome_secret
//!                        |
//!                ExpandWithLabel(., "epoch", GroupContext_[n], Nh)
//!                        |
//!                    epoch_secret --> DeriveSecret(., <label>) x 9
//! ```
//!
//! **The `GroupContext` is unbounded, so this file does not use
//! `crypto.ExpandWithLabel`'s fixed 512-byte scratch** for the two
//! context-carrying derivations. `crypto.zig`'s module doc comment
//! predicted exactly this ("a LATER part deriving a secret from a
//! multi-kilobyte `GroupContext` (extensions included) may need a larger
//! bound or a caller-supplied scratch slice"); the answer is
//! `crypto.kdfLabelLen` + `crypto.ExpandWithLabelScratch`, which is why
//! `joinerSecret`/`epochSecret`/`deriveEpoch` take an allocator and the
//! nine `epoch_secret` fan-out derivations (context `""`) do not.
//!
//! **What is here and what is deliberately NOT.** Here: §8's epoch chain,
//! §8.1's `GroupContext` wire format, §8.4's `PreSharedKeyID`/`psk_secret`
//! chain, §8.5's `MLS-Exporter`, §8's `external_pub` derivation, and §6.1's
//! `confirmation_tag`/`membership_tag` MAC computations (they live here
//! because they consume `confirmation_key`/`membership_key` and nothing
//! else in this Part; their INPUTS are framing structs Part 5 builds —
//! `framing.membershipTag` assembles the `AuthenticatedContentTBM` that
//! `membershipTag` below MACs).
//! **§8.2's transcript hashes are now in `transcript.zig`** (Part 5): they
//! hash an encoded `AuthenticatedContent`, which did not exist until the
//! framing layer did, and they live in their own file rather than here
//! because `framing.zig` imports THIS file — folding §8.2 back in would
//! close the loop into an import cycle.
//! Still NOT here and still not anywhere: §8.3's external initialization,
//! which needs an HPKE `SetupBaseS`/`SetupBaseR` context for the
//! external-commit join flow (Part 6). It is not exercised by
//! `key-schedule.json`, and stubbing it here would mean shipping
//! untestable code.
//!
//! Model: RFC 9420 §8 (Key Schedule) + §8.1 (Group Context) + §8.4
//! (Pre-Shared Keys) + §8.5 (Exporters) + §6.1 (Content Authentication's
//! two MACs). Verified byte-exact against the official
//! `mlswg/mls-implementations` `key-schedule.json` and `psk_secret.json`
//! vectors — see `kat_keyschedule_test.zig` and `NOTICE`.

const std = @import("std");
const codec = @import("codec.zig");
const suite = @import("suite.zig");
const crypto = @import("crypto.zig");
const tree = @import("tree.zig");
const wire = @import("wire_lists.zig");

pub const Error = error{
    /// `pskSecret` was handed more than 65535 PSKs — `PSKLabel.count` is a
    /// `uint16` (RFC 9420 §8.4), so a longer list cannot be encoded at all.
    TooManyPsks,
    /// A `confirmation_tag`/`membership_tag` did not match the recomputed
    /// MAC.
    MacMismatch,
} || crypto.Error || std.mem.Allocator.Error;

// ── §8.1: GroupContext ────────────────────────────────────────────────────

/// RFC 9420 §7.1's `ProtocolVersion`. `mls10` (1) is the only version RFC
/// 9420 defines; the enum is non-exhaustive so a version read off the wire
/// compares/prints without being rejected by the decoder itself (that's a
/// validation decision, not a codec one — the same convention
/// `suite.CipherSuiteId` follows).
pub const ProtocolVersion = enum(u16) { reserved = 0, mls10 = 1, _ };

/// RFC 9420 §8.1's `GroupContext` — the summary of group state every member
/// maintains, and (crucially) the value mixed into `joiner_secret` and
/// `epoch_secret` so that two members who disagree about the group's
/// identity, epoch, tree or transcript derive different keys.
///
/// All four byte fields ALIAS caller memory; only `decode` allocates (the
/// `extensions` LIST, matching `tree.decodeExtensionList`'s convention —
/// the extension bodies themselves still alias the reader's buffer).
pub const GroupContext = struct {
    version: ProtocolVersion = .mls10,
    cipher_suite: suite.CipherSuiteId,
    group_id: []const u8,
    epoch: u64,
    tree_hash: []const u8,
    confirmed_transcript_hash: []const u8,
    extensions: []const tree.Extension = &.{},

    pub fn encodedLen(self: GroupContext) usize {
        return 2 // ProtocolVersion
        + 2 // CipherSuite
        + wire.varintLen(self.group_id.len) + self.group_id.len + 8 // uint64 epoch
        + wire.varintLen(self.tree_hash.len) + self.tree_hash.len +
            wire.varintLen(self.confirmed_transcript_hash.len) + self.confirmed_transcript_hash.len +
            wire.varVecLen(tree.Extension, self.extensions);
    }

    pub fn encode(self: GroupContext, w: *codec.Writer) codec.Error!void {
        try w.writeEnum(ProtocolVersion, self.version);
        try w.writeEnum(suite.CipherSuiteId, self.cipher_suite);
        try w.writeVector(self.group_id);
        try w.writeU64(self.epoch);
        try w.writeVector(self.tree_hash);
        try w.writeVector(self.confirmed_transcript_hash);
        try wire.encodeVarVec(tree.Extension, w, self.extensions);
    }

    /// Serializes into a freshly allocated slice (caller frees). The key
    /// schedule needs the encoded form, not the struct — `joinerSecret`/
    /// `epochSecret` take `[]const u8` precisely so a caller who already
    /// holds the wire bytes (a `GroupInfo` off the network, say) never has
    /// to round-trip through this struct and risk a re-encode that differs.
    pub fn encodeAlloc(self: GroupContext, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, self.encodedLen());
        errdefer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.encode(&w);
        std.debug.assert(w.finish().len == buf.len);
        return buf;
    }

    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !GroupContext {
        const version = try r.readEnum(ProtocolVersion);
        const cs = try r.readEnum(suite.CipherSuiteId);
        const group_id = try r.readVector();
        const epoch = try r.readU64();
        const tree_hash = try r.readVector();
        const cth = try r.readVector();
        const extensions = try tree.decodeExtensionList(allocator, r);
        return .{
            .version = version,
            .cipher_suite = cs,
            .group_id = group_id,
            .epoch = epoch,
            .tree_hash = tree_hash,
            .confirmed_transcript_hash = cth,
            .extensions = extensions,
        };
    }

    /// Frees only what `decode` allocated (the extension list).
    pub fn deinit(self: GroupContext, allocator: std.mem.Allocator) void {
        allocator.free(self.extensions);
    }
};

// ── §8: the epoch chain ───────────────────────────────────────────────────

/// RFC 9420 §8 Table 4's label column, in the RFC's own row order. Kept as
/// named constants rather than inline literals so the KAT and the
/// derivation read from the same source (a typo in one would otherwise
/// silently become a typo in both).
pub const label_joiner = "joiner";
pub const label_welcome = "welcome";
pub const label_epoch = "epoch";
pub const label_sender_data = "sender data";
pub const label_encryption = "encryption";
pub const label_exporter = "exporter";
pub const label_external = "external";
pub const label_confirm = "confirm";
pub const label_membership = "membership";
pub const label_resumption = "resumption";
pub const label_authentication = "authentication";
pub const label_init = "init";

/// Every secret RFC 9420 §8 defines for one epoch: the three chain values
/// plus Table 4's eight fan-out secrets plus the next epoch's
/// `init_secret`. Field names match the RFC's own names exactly.
pub fn EpochSecrets(comptime S: type) type {
    return struct {
        const Self = @This();

        /// Chain values (Figure 22's vertical spine).
        joiner_secret: [S.Nh]u8,
        welcome_secret: [S.Nh]u8,
        epoch_secret: [S.Nh]u8,

        /// Table 4's fan-out from `epoch_secret`.
        sender_data_secret: [S.Nh]u8,
        encryption_secret: [S.Nh]u8,
        exporter_secret: [S.Nh]u8,
        external_secret: [S.Nh]u8,
        confirmation_key: [S.Nh]u8,
        membership_key: [S.Nh]u8,
        resumption_psk: [S.Nh]u8,
        epoch_authenticator: [S.Nh]u8,

        /// The NEXT epoch's `init_secret` — this epoch's contribution to
        /// the chain (`init_secret_[n]`).
        init_secret: [S.Nh]u8,

        /// RFC 9420 §9.2's deletion schedule applied to a whole epoch:
        /// overwrite every secret once the epoch is done. Not a substitute
        /// for the per-value deletion §9.2 actually requires (that
        /// granularity lives in `secrettree.zig`'s ratchets) — this is the
        /// coarse "the epoch has ended" sweep.
        pub fn wipe(self: *Self) void {
            inline for (@typeInfo(Self).@"struct".fields) |f| {
                std.crypto.secureZero(u8, &@field(self, f.name));
            }
        }
    };
}

/// Figure 22's FIRST Extract: salt = the previous epoch's `init_secret`
/// (the arrow from the top), IKM = this epoch's `commit_secret` (the arrow
/// from the left). Named and exposed separately from `joinerSecret` because
/// this argument order is the single easiest thing in §8 to get backwards
/// and the hardest to notice.
pub fn extractInitCommit(comptime S: type, init_secret_prev: [S.Nh]u8, commit_secret: [S.Nh]u8) [S.Nh]u8 {
    return S.Hkdf.extract(&init_secret_prev, &commit_secret);
}

/// RFC 9420 §8 `joiner_secret = ExpandWithLabel(KDF.Extract(
/// init_secret_[n-1], commit_secret), "joiner", GroupContext_[n], KDF.Nh)`.
/// `group_context` is the ENCODED `GroupContext` (see
/// `GroupContext.encodeAlloc`); the allocator sizes the KDFLabel scratch,
/// which a `GroupContext` with extensions can push past
/// `crypto.ExpandWithLabel`'s fixed buffer.
pub fn joinerSecret(
    comptime S: type,
    allocator: std.mem.Allocator,
    init_secret_prev: [S.Nh]u8,
    commit_secret: [S.Nh]u8,
    group_context: []const u8,
) Error![S.Nh]u8 {
    const pre_joiner = extractInitCommit(S, init_secret_prev, commit_secret);
    var out: [S.Nh]u8 = undefined;
    try expandWithContext(S, allocator, pre_joiner, label_joiner, group_context, &out);
    return out;
}

/// Figure 22's SECOND Extract: salt = `joiner_secret` (from the top), IKM =
/// `psk_secret` (from the left). The RFC gives this value no name; it is
/// the branch point from which BOTH `welcome_secret` and `epoch_secret`
/// derive, which is the structural detail worth naming — deriving
/// `welcome_secret` from `epoch_secret` instead would type-check, run, and
/// be wrong.
pub fn memberSecret(comptime S: type, joiner_secret: [S.Nh]u8, psk_secret: [S.Nh]u8) [S.Nh]u8 {
    return S.Hkdf.extract(&joiner_secret, &psk_secret);
}

/// RFC 9420 §8 `welcome_secret = DeriveSecret(member_secret, "welcome")`.
/// Pass `psk_secret = zeroSecret(S)` when the Commit injects no PSKs (§8.4:
/// "if there are no PreSharedKey proposals ... the resulting psk_secret is
/// psk_secret_[0], the all-zero vector").
pub fn welcomeSecret(comptime S: type, joiner_secret: [S.Nh]u8, psk_secret: [S.Nh]u8) Error![S.Nh]u8 {
    return crypto.DeriveSecret(S, memberSecret(S, joiner_secret, psk_secret), label_welcome);
}

/// RFC 9420 §8 `epoch_secret = ExpandWithLabel(member_secret, "epoch",
/// GroupContext_[n], KDF.Nh)`.
pub fn epochSecret(
    comptime S: type,
    allocator: std.mem.Allocator,
    joiner_secret: [S.Nh]u8,
    psk_secret: [S.Nh]u8,
    group_context: []const u8,
) Error![S.Nh]u8 {
    var out: [S.Nh]u8 = undefined;
    try expandWithContext(S, allocator, memberSecret(S, joiner_secret, psk_secret), label_epoch, group_context, &out);
    return out;
}

/// The whole of RFC 9420 §8 Figure 22 in one call: previous epoch's
/// `init_secret` + this epoch's `commit_secret` + `psk_secret` +
/// encoded `GroupContext_[n]` in, every epoch secret out.
pub fn deriveEpoch(
    comptime S: type,
    allocator: std.mem.Allocator,
    init_secret_prev: [S.Nh]u8,
    commit_secret: [S.Nh]u8,
    psk_secret: [S.Nh]u8,
    group_context: []const u8,
) Error!EpochSecrets(S) {
    const joiner = try joinerSecret(S, allocator, init_secret_prev, commit_secret, group_context);
    return deriveEpochFromJoiner(S, allocator, joiner, psk_secret, group_context);
}

/// Figure 22 entered ONE STEP LOWER — from `joiner_secret` rather than from
/// `init_secret_[n-1] + commit_secret`. This is the entry point a NEW MEMBER
/// uses: RFC 9420 §12.4.3.1 hands a joiner the `joiner_secret` itself inside
/// `GroupSecrets`, precisely because it has neither the previous epoch's
/// `init_secret` nor the Commit's `commit_secret` and could not run
/// `deriveEpoch` at all. Everything from `member_secret` down is identical,
/// so `deriveEpoch` is now literally `joinerSecret` followed by this — the
/// two paths cannot drift apart.
///
/// Note that `joiner_secret` is where an existing member's and a joiner's
/// views of the epoch MUST meet: the joiner takes it on trust from the
/// committer, and what proves the committer was honest is the
/// `confirmation_tag` check the joiner runs afterwards with the
/// `confirmation_key` this function derives.
pub fn deriveEpochFromJoiner(
    comptime S: type,
    allocator: std.mem.Allocator,
    joiner: [S.Nh]u8,
    psk_secret: [S.Nh]u8,
    group_context: []const u8,
) Error!EpochSecrets(S) {
    const member = memberSecret(S, joiner, psk_secret);

    var out: [S.Nh]u8 = undefined;
    try expandWithContext(S, allocator, member, label_epoch, group_context, &out);
    const epoch = out;

    return .{
        .joiner_secret = joiner,
        .welcome_secret = try crypto.DeriveSecret(S, member, label_welcome),
        .epoch_secret = epoch,
        .sender_data_secret = try crypto.DeriveSecret(S, epoch, label_sender_data),
        .encryption_secret = try crypto.DeriveSecret(S, epoch, label_encryption),
        .exporter_secret = try crypto.DeriveSecret(S, epoch, label_exporter),
        .external_secret = try crypto.DeriveSecret(S, epoch, label_external),
        .confirmation_key = try crypto.DeriveSecret(S, epoch, label_confirm),
        .membership_key = try crypto.DeriveSecret(S, epoch, label_membership),
        .resumption_psk = try crypto.DeriveSecret(S, epoch, label_resumption),
        .epoch_authenticator = try crypto.DeriveSecret(S, epoch, label_authentication),
        .init_secret = try crypto.DeriveSecret(S, epoch, label_init),
    };
}

/// The all-zero `KDF.Nh`-byte string RFC 9420 §8 writes as `0` — the
/// `psk_secret` for an epoch with no PSKs, and `psk_secret_[0]` in §8.4's
/// chain.
pub fn zeroSecret(comptime S: type) [S.Nh]u8 {
    return [_]u8{0} ** S.Nh;
}

/// `ExpandWithLabel` with an EXACTLY-sized heap scratch — the two
/// `GroupContext`-carrying derivations, see this file's module doc comment.
fn expandWithContext(
    comptime S: type,
    allocator: std.mem.Allocator,
    secret: [S.Nh]u8,
    label: []const u8,
    context: []const u8,
    out: []u8,
) Error!void {
    const scratch = try allocator.alloc(u8, try crypto.kdfLabelLen(label, context));
    defer allocator.free(scratch);
    try crypto.ExpandWithLabelScratch(S, secret, label, context, out, scratch);
}

// ── §8: external_pub ──────────────────────────────────────────────────────

/// RFC 9420 §8, below Table 4: `external_priv, external_pub =
/// KEM.DeriveKeyPair(external_secret)`. The resulting public key is
/// published in `GroupInfo` so a non-member can join by external Commit;
/// the private key is held by the whole group.
pub fn externalKeyPair(comptime S: type, external_secret: [S.Nh]u8) S.Kem.KeyPair {
    return S.Kem.deriveKeyPair(&external_secret);
}

// ── §8.5: MLS-Exporter ────────────────────────────────────────────────────

/// RFC 9420 §8.5 `MLS-Exporter(Label, Context, Length) =
/// ExpandWithLabel(DeriveSecret(exporter_secret, Label), "exported",
/// Hash(Context), Length)`.
///
/// Note the asymmetry that makes this allocation-free while the key
/// schedule proper is not: the application's `Context` is HASHED before it
/// becomes the `ExpandWithLabel` context, so the KDFLabel is bounded by
/// `Hash.digest_length` no matter how large the application's context is.
/// Only an absurdly long `Label` can overflow the fixed scratch, and that
/// surfaces as `error.LabelTooLong` rather than a truncated derivation.
pub fn mlsExporter(
    comptime S: type,
    exporter_secret: [S.Nh]u8,
    label: []const u8,
    context: []const u8,
    out: []u8,
) crypto.Error!void {
    const derived = try crypto.DeriveSecret(S, exporter_secret, label);
    const context_hash = S.hash(context);
    try crypto.ExpandWithLabel(S, derived, "exported", &context_hash, out);
}

// ── §6.1: confirmation_tag / membership_tag ───────────────────────────────

/// RFC 9420 §6.1: `confirmation_tag = MAC(confirmation_key,
/// GroupContext.confirmed_transcript_hash)`. The MAC is HMAC with the
/// suite's hash (§17.1's text under Table 7) — see `suite.CipherSuite.Mac`.
pub fn confirmationTag(
    comptime S: type,
    confirmation_key: [S.Nh]u8,
    confirmed_transcript_hash: []const u8,
) [S.Nm]u8 {
    var out: [S.Nm]u8 = undefined;
    S.Mac.create(&out, confirmed_transcript_hash, &confirmation_key);
    return out;
}

/// Recomputes and CONSTANT-TIME compares a received `confirmation_tag`.
/// Use this rather than comparing `confirmationTag`'s output with
/// `std.mem.eql` — a `confirmation_tag` is attacker-supplied.
pub fn verifyConfirmationTag(
    comptime S: type,
    confirmation_key: [S.Nh]u8,
    confirmed_transcript_hash: []const u8,
    tag: []const u8,
) Error!void {
    const want = confirmationTag(S, confirmation_key, confirmed_transcript_hash);
    if (tag.len != want.len) return error.MacMismatch;
    if (!std.crypto.timing_safe.eql([S.Nm]u8, want, tag[0..S.Nm].*)) return error.MacMismatch;
}

/// RFC 9420 §6.1: `membership_tag = MAC(membership_key,
/// AuthenticatedContentTBM)`. `authenticated_content_tbm` is the ENCODED
/// `AuthenticatedContentTBM` struct (`FramedContentTBS` followed by
/// `FramedContentAuthData`) — a Part 5 framing structure, so this function
/// takes the already-serialized bytes rather than pretending to own a
/// struct this Part cannot build.
pub fn membershipTag(
    comptime S: type,
    membership_key: [S.Nh]u8,
    authenticated_content_tbm: []const u8,
) [S.Nm]u8 {
    var out: [S.Nm]u8 = undefined;
    S.Mac.create(&out, authenticated_content_tbm, &membership_key);
    return out;
}

/// Constant-time verification of a received `membership_tag`, mirroring
/// `verifyConfirmationTag`.
pub fn verifyMembershipTag(
    comptime S: type,
    membership_key: [S.Nh]u8,
    authenticated_content_tbm: []const u8,
    tag: []const u8,
) Error!void {
    const want = membershipTag(S, membership_key, authenticated_content_tbm);
    if (tag.len != want.len) return error.MacMismatch;
    if (!std.crypto.timing_safe.eql([S.Nm]u8, want, tag[0..S.Nm].*)) return error.MacMismatch;
}

// ── §8.4: Pre-Shared Keys ─────────────────────────────────────────────────

/// RFC 9420 §8.4's `PSKType`.
pub const PskType = enum(u8) { reserved = 0, external = 1, resumption = 2, _ };

/// RFC 9420 §8.4's `ResumptionPSKUsage`.
pub const ResumptionPskUsage = enum(u8) { reserved = 0, application = 1, reinit = 2, branch = 3, _ };

/// RFC 9420 §8.4's `PreSharedKeyID` — the IDENTIFIER of an injected PSK,
/// not the key itself. Every byte field aliases caller memory.
///
/// `psk_nonce` MUST be a fresh random value of `KDF.Nh` bytes each time a
/// PSK is injected (§8.4) — that is what stops a re-used PSK from producing
/// the same key-schedule input twice. This type does not generate it (the
/// application owns randomness policy) but `pskSecret` mixes it in, so a
/// caller that reuses a nonce silently reuses a `psk_input` too.
pub const PreSharedKeyId = struct {
    id: Id,
    psk_nonce: []const u8,

    pub const Id = union(enum) {
        external: []const u8, // psk_id<V>
        resumption: Resumption,
    };

    pub const Resumption = struct {
        usage: ResumptionPskUsage,
        psk_group_id: []const u8,
        psk_epoch: u64,
    };

    pub fn pskType(self: PreSharedKeyId) PskType {
        return switch (self.id) {
            .external => .external,
            .resumption => .resumption,
        };
    }

    pub fn encodedLen(self: PreSharedKeyId) usize {
        const body: usize = switch (self.id) {
            .external => |psk_id| wire.varintLen(psk_id.len) + psk_id.len,
            .resumption => |r| 1 + wire.varintLen(r.psk_group_id.len) + r.psk_group_id.len + 8,
        };
        return 1 + body + wire.varintLen(self.psk_nonce.len) + self.psk_nonce.len;
    }

    pub fn encode(self: PreSharedKeyId, w: *codec.Writer) codec.Error!void {
        try w.writeEnum(PskType, self.pskType());
        switch (self.id) {
            .external => |psk_id| try w.writeVector(psk_id),
            .resumption => |r| {
                try w.writeEnum(ResumptionPskUsage, r.usage);
                try w.writeVector(r.psk_group_id);
                try w.writeU64(r.psk_epoch);
            },
        }
        try w.writeVector(self.psk_nonce);
    }

    /// Aliases the reader's buffer — no allocation. Rejects a `psktype`
    /// the `select` in §8.4 has no arm for (`reserved`, or any future
    /// value): unlike the codec's non-exhaustive enums elsewhere, an
    /// unknown `psktype` here means the rest of the struct cannot be
    /// parsed at all, so this is a decode failure, not a validation one.
    pub fn decode(r: *codec.Reader) codec.Error!PreSharedKeyId {
        const t = try r.readEnum(PskType);
        const id: Id = switch (t) {
            .external => .{ .external = try r.readVector() },
            .resumption => .{ .resumption = .{
                .usage = try r.readEnum(ResumptionPskUsage),
                .psk_group_id = try r.readVector(),
                .psk_epoch = try r.readU64(),
            } },
            else => return error.Malformed,
        };
        return .{ .id = id, .psk_nonce = try r.readVector() };
    }
};

/// One PSK as `pskSecret` consumes it: its `PreSharedKeyID` (which goes
/// into the `PSKLabel`) plus the key material itself. For a RESUMPTION PSK
/// the `secret` is the `resumption_psk` of the group/epoch named in
/// `id` — resolving that is the caller's job (this file has no access to
/// other epochs' state).
pub fn PreSharedKey(comptime S: type) type {
    return struct {
        id: PreSharedKeyId,
        secret: [S.Nh]u8,
    };
}

/// RFC 9420 §8.4's `PSKLabel { PreSharedKeyID id; uint16 index; uint16
/// count; }` — the per-PSK domain separator that binds each PSK's
/// contribution to its POSITION in the list, so that reordering the same
/// set of PSKs yields a different `psk_secret`.
pub const PskLabel = struct {
    id: PreSharedKeyId,
    index: u16,
    count: u16,

    pub fn encodedLen(self: PskLabel) usize {
        return self.id.encodedLen() + 4;
    }
    pub fn encode(self: PskLabel, w: *codec.Writer) codec.Error!void {
        try self.id.encode(w);
        try w.writeU16(self.index);
        try w.writeU16(self.count);
    }
};

/// RFC 9420 §8.4's `psk_secret` chain (Figure 24):
///
/// ```text
/// psk_extracted_[i] = KDF.Extract(0, psk_[i])
/// psk_input_[i]     = ExpandWithLabel(psk_extracted_[i], "derived psk",
///                                     PSKLabel, KDF.Nh)
/// psk_secret_[0]    = 0
/// psk_secret_[i]    = KDF.Extract(psk_input_[i-1], psk_secret_[i-1])
/// ```
///
/// **The second Extract's argument order is the one genuinely ambiguous
/// point in §8.** The prose above reads `Extract(psk_input, psk_secret)` —
/// salt first, per the KDF convention — while Figure 24 draws
/// `psk_secret_[i-1]` entering from the TOP, which §8's own figure legend
/// says is the salt position. The two readings disagree. This
/// implementation follows the PROSE (`salt = psk_input_[i-1]`, `ikm =
/// psk_secret_[i-1]`), and `psk_secret.json` confirms it byte-exact for
/// chains of 1 through 10 PSKs — see `kat_keyschedule_test.zig`.
///
/// Returns `zeroSecret(S)` for an empty list, which is not a special case
/// but simply `psk_secret_[0]` (§8.4: "if there are no PreSharedKey
/// proposals in a given Commit, then the resulting psk_secret is
/// psk_secret_[0], the all-zero vector").
pub fn pskSecret(comptime S: type, allocator: std.mem.Allocator, psks: []const PreSharedKey(S)) Error![S.Nh]u8 {
    const count = std.math.cast(u16, psks.len) orelse return error.TooManyPsks;
    var acc = zeroSecret(S);
    const zero = zeroSecret(S);

    for (psks, 0..) |psk, i| {
        const extracted = S.Hkdf.extract(&zero, &psk.secret);

        const psk_label: PskLabel = .{ .id = psk.id, .index = @intCast(i), .count = count };
        const label_buf = try allocator.alloc(u8, psk_label.encodedLen());
        defer allocator.free(label_buf);
        var w = codec.Writer.init(label_buf);
        try psk_label.encode(&w);
        const encoded_label = w.finish();

        var psk_input: [S.Nh]u8 = undefined;
        try expandWithContext(S, allocator, extracted, "derived psk", encoded_label, &psk_input);

        acc = S.Hkdf.extract(&psk_input, &acc);
        std.crypto.secureZero(u8, &psk_input);
    }
    return acc;
}

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;
const TestSuite = suite.default;

test "GroupContext: encodes RFC 9420 §8.1's field order, and round-trips" {
    const gid = [_]u8{0xaa} ** 4;
    const th = [_]u8{0xbb} ** 32;
    const cth = [_]u8{0xcc} ** 32;
    const gc: GroupContext = .{
        .cipher_suite = TestSuite.id,
        .group_id = &gid,
        .epoch = 7,
        .tree_hash = &th,
        .confirmed_transcript_hash = &cth,
    };

    const enc = try gc.encodeAlloc(testing.allocator);
    defer testing.allocator.free(enc);

    // version(2) suite(2) | 04 gid | epoch(8) | 20 th | 20 cth | 00 ext
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x00, 0x01, 0x04 }, enc[0..5]);
    try testing.expectEqualSlices(u8, &gid, enc[5..9]);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 7 }, enc[9..17]);
    try testing.expectEqual(@as(u8, 0x20), enc[17]);
    try testing.expectEqual(@as(u8, 0x00), enc[enc.len - 1]); // empty extensions

    var r = codec.Reader.init(enc);
    const back = try GroupContext.decode(testing.allocator, &r);
    defer back.deinit(testing.allocator);
    try testing.expect(r.atEnd());
    try testing.expectEqual(gc.epoch, back.epoch);
    try testing.expectEqual(gc.cipher_suite, back.cipher_suite);
    try testing.expectEqualSlices(u8, gc.group_id, back.group_id);
    try testing.expectEqualSlices(u8, gc.tree_hash, back.tree_hash);
    try testing.expectEqualSlices(u8, gc.confirmed_transcript_hash, back.confirmed_transcript_hash);
    try testing.expectEqual(@as(usize, 0), back.extensions.len);
}

test "GroupContext: a multi-kilobyte extension list still derives (the fixed 512-byte scratch cannot)" {
    const big = [_]u8{0x5a} ** 3000;
    const exts = [_]tree.Extension{.{ .extension_type = 0xf00d, .extension_data = &big }};
    const th = [_]u8{0xbb} ** 32;
    const gc: GroupContext = .{
        .cipher_suite = TestSuite.id,
        .group_id = "g",
        .epoch = 1,
        .tree_hash = &th,
        .confirmed_transcript_hash = &th,
        .extensions = &exts,
    };
    const enc = try gc.encodeAlloc(testing.allocator);
    defer testing.allocator.free(enc);
    try testing.expect(enc.len > 3000);

    // The point of the allocator on `joinerSecret`: this succeeds.
    const js = try joinerSecret(TestSuite, testing.allocator, zeroSecret(TestSuite), zeroSecret(TestSuite), enc);
    // ...where the fixed-scratch entry point would not.
    var direct: [TestSuite.Nh]u8 = undefined;
    try testing.expectError(
        error.LabelTooLong,
        crypto.ExpandWithLabel(TestSuite, zeroSecret(TestSuite), label_joiner, enc, &direct),
    );
    const zero = zeroSecret(TestSuite);
    try testing.expect(!std.mem.eql(u8, &js, &zero));
}

test "deriveEpoch: matches the step-by-step derivation, and every secret is distinct" {
    const init_prev = [_]u8{0x01} ** TestSuite.Nh;
    const commit = [_]u8{0x02} ** TestSuite.Nh;
    const psk = [_]u8{0x03} ** TestSuite.Nh;
    const th = [_]u8{0x04} ** 32;
    const gc: GroupContext = .{
        .cipher_suite = TestSuite.id,
        .group_id = "group",
        .epoch = 3,
        .tree_hash = &th,
        .confirmed_transcript_hash = &th,
    };
    const enc = try gc.encodeAlloc(testing.allocator);
    defer testing.allocator.free(enc);

    var got = try deriveEpoch(TestSuite, testing.allocator, init_prev, commit, psk, enc);

    const joiner = try joinerSecret(TestSuite, testing.allocator, init_prev, commit, enc);
    try testing.expectEqualSlices(u8, &joiner, &got.joiner_secret);
    const welcome = try welcomeSecret(TestSuite, joiner, psk);
    try testing.expectEqualSlices(u8, &welcome, &got.welcome_secret);
    const epoch = try epochSecret(TestSuite, testing.allocator, joiner, psk, enc);
    try testing.expectEqualSlices(u8, &epoch, &got.epoch_secret);
    const next_init = try crypto.DeriveSecret(TestSuite, got.epoch_secret, label_init);
    try testing.expectEqualSlices(u8, &next_init, &got.init_secret);

    // Distinct labels must give distinct secrets — catches a copy-paste of
    // the wrong label into a Table 4 row, which no round-trip test would.
    const all = [_][TestSuite.Nh]u8{
        got.joiner_secret,      got.welcome_secret,      got.epoch_secret,
        got.sender_data_secret, got.encryption_secret,   got.exporter_secret,
        got.external_secret,    got.confirmation_key,    got.membership_key,
        got.resumption_psk,     got.epoch_authenticator, got.init_secret,
    };
    for (all, 0..) |a, i| for (all[i + 1 ..]) |b| {
        try testing.expect(!std.mem.eql(u8, &a, &b));
    };

    got.wipe();
    const zero = zeroSecret(TestSuite);
    try testing.expectEqualSlices(u8, &zero, &got.epoch_secret);
}

test "extractInitCommit/memberSecret: salt and IKM are not interchangeable" {
    const a = [_]u8{0x11} ** TestSuite.Nh;
    const b = [_]u8{0x22} ** TestSuite.Nh;
    // If these were equal, Figure 22's salt/IKM convention would be
    // unfalsifiable and the KAT could not catch an inverted Extract.
    const ab = extractInitCommit(TestSuite, a, b);
    const ba = extractInitCommit(TestSuite, b, a);
    try testing.expect(!std.mem.eql(u8, &ab, &ba));
    const m_ab = memberSecret(TestSuite, a, b);
    const m_ba = memberSecret(TestSuite, b, a);
    try testing.expect(!std.mem.eql(u8, &m_ab, &m_ba));
}

test "pskSecret: empty list is psk_secret_[0], and order/count/nonce all change the result" {
    const empty = try pskSecret(TestSuite, testing.allocator, &.{});
    const zero = zeroSecret(TestSuite);
    try testing.expectEqualSlices(u8, &zero, &empty);

    const nonce_a = [_]u8{0xa0} ** TestSuite.Nh;
    const nonce_b = [_]u8{0xb0} ** TestSuite.Nh;
    const k0: PreSharedKey(TestSuite) = .{
        .id = .{ .id = .{ .external = "id-0" }, .psk_nonce = &nonce_a },
        .secret = [_]u8{0x10} ** TestSuite.Nh,
    };
    const k1: PreSharedKey(TestSuite) = .{
        .id = .{ .id = .{ .external = "id-1" }, .psk_nonce = &nonce_b },
        .secret = [_]u8{0x20} ** TestSuite.Nh,
    };

    const forward = try pskSecret(TestSuite, testing.allocator, &.{ k0, k1 });
    const reversed = try pskSecret(TestSuite, testing.allocator, &.{ k1, k0 });
    // PSKLabel.index binds each PSK to its position (§8.4).
    try testing.expect(!std.mem.eql(u8, &forward, &reversed));

    // PSKLabel.count binds the whole list length.
    const alone = try pskSecret(TestSuite, testing.allocator, &.{k0});
    try testing.expect(!std.mem.eql(u8, &alone, &forward));

    // A fresh psk_nonce changes the input even for an identical PSK.
    var k0_renonced = k0;
    k0_renonced.id.psk_nonce = &nonce_b;
    const renonced = try pskSecret(TestSuite, testing.allocator, &.{k0_renonced});
    try testing.expect(!std.mem.eql(u8, &alone, &renonced));
}

test "PreSharedKeyId: both select arms round-trip; an unknown psktype is rejected" {
    const nonce = [_]u8{0x77} ** TestSuite.Nh;
    const ext: PreSharedKeyId = .{ .id = .{ .external = "app-psk" }, .psk_nonce = &nonce };
    const res: PreSharedKeyId = .{
        .id = .{ .resumption = .{ .usage = .branch, .psk_group_id = "other-group", .psk_epoch = 42 } },
        .psk_nonce = &nonce,
    };

    for ([_]PreSharedKeyId{ ext, res }) |id| {
        var buf: [256]u8 = undefined;
        var w = codec.Writer.init(&buf);
        try id.encode(&w);
        const enc = w.finish();
        try testing.expectEqual(id.encodedLen(), enc.len);

        var r = codec.Reader.init(enc);
        const back = try PreSharedKeyId.decode(&r);
        try testing.expect(r.atEnd());
        try testing.expectEqual(id.pskType(), back.pskType());
        try testing.expectEqualSlices(u8, id.psk_nonce, back.psk_nonce);
    }

    // psktype = reserved(0): §8.4's select has no arm, so the remaining
    // bytes are unparseable — a decode failure, not a validation one.
    var r = codec.Reader.init(&[_]u8{ 0x00, 0x00 });
    try testing.expectError(error.Malformed, PreSharedKeyId.decode(&r));
}

test "confirmation/membership tags: verify accepts, one flipped bit and a short tag are rejected" {
    const key = [_]u8{0x5c} ** TestSuite.Nh;
    const cth = [_]u8{0x99} ** 32;

    var tag = confirmationTag(TestSuite, key, &cth);
    try verifyConfirmationTag(TestSuite, key, &cth, &tag);
    tag[0] ^= 0x01;
    try testing.expectError(error.MacMismatch, verifyConfirmationTag(TestSuite, key, &cth, &tag));
    tag[0] ^= 0x01;
    try testing.expectError(error.MacMismatch, verifyConfirmationTag(TestSuite, key, &cth, tag[0 .. TestSuite.Nm - 1]));

    // The two MACs use different keys from Table 4, so an
    // AuthenticatedContentTBM tag never collides with a transcript tag.
    const other_key = try crypto.DeriveSecret(TestSuite, key, label_membership);
    const mtag = membershipTag(TestSuite, key, &cth);
    try verifyMembershipTag(TestSuite, key, &cth, &mtag);
    try testing.expectEqualSlices(u8, &tag, &mtag); // same key+data => same MAC, by construction
    try testing.expectError(
        error.MacMismatch,
        verifyMembershipTag(TestSuite, other_key, &cth, &mtag),
    );
}

test "mlsExporter: label and context are both bound, and the length is honoured" {
    const es = [_]u8{0x6e} ** TestSuite.Nh;
    var out_a: [48]u8 = undefined;
    var out_b: [48]u8 = undefined;
    try mlsExporter(TestSuite, es, "label", "context", &out_a);
    try mlsExporter(TestSuite, es, "label", "different context", &out_b);
    try testing.expect(!std.mem.eql(u8, &out_a, &out_b));
    try mlsExporter(TestSuite, es, "other label", "context", &out_b);
    try testing.expect(!std.mem.eql(u8, &out_a, &out_b));

    var short: [16]u8 = undefined;
    try mlsExporter(TestSuite, es, "label", "context", &short);
    try testing.expect(!std.mem.eql(u8, short[0..16], out_a[0..16])); // Length is in the KDFLabel
}

test "externalKeyPair: deterministic in external_secret, and a distinct secret gives a distinct key" {
    const a = [_]u8{0x31} ** TestSuite.Nh;
    const b = [_]u8{0x32} ** TestSuite.Nh;
    const ka1 = externalKeyPair(TestSuite, a);
    const ka2 = externalKeyPair(TestSuite, a);
    const kb = externalKeyPair(TestSuite, b);
    try testing.expectEqualSlices(u8, &ka1.public_key, &ka2.public_key);
    try testing.expect(!std.mem.eql(u8, &ka1.public_key, &kb.public_key));
}
