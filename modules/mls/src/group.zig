// SPDX-License-Identifier: MIT
//! mls.group — Part 7, the group state machine: the object that turns
//! Parts 1-6's codecs and derivations into a client that can FOLLOW a
//! group. RFC 9420 §12.2 (proposal-list validation), §12.3 (applying a
//! proposal list) and §12.4.2 (processing a Commit), plus the state those
//! three steps read and write.
//!
//! **What this file is for.** Everything below it is a function: give it
//! bytes and keys, get bytes and keys back. A `Commit` is different in kind
//! — it is the one message whose meaning is "the group is now different",
//! and processing one correctly means running eleven ordered steps over
//! state that six other files each own a slice of. `Group(S)` is where that
//! state stops being the caller's problem. Concretely: after `fromWelcome`,
//! `processCommit` on the epoch's Commit bytes is the whole of what a
//! passive client does, and `epochAuthenticator()` afterwards is the value
//! every other member of that group also holds.
//!
//! **The order in §12.4.2 is the specification, not a suggestion.** Three
//! places in it are easy to get wrong in ways that still produce
//! well-formed 32-byte secrets:
//!
//!   1. The Commit's signature and `membership_tag` are verified against
//!      the OLD `GroupContext` (the epoch the sender was in), while the key
//!      schedule consumes the NEW one.
//!   2. The `UpdatePath`'s HPKE ciphertexts are opened under a
//!      **provisional** `GroupContext` that is neither: new `epoch`, new
//!      `tree_hash` (after the proposals AND after merging the UpdatePath),
//!      but the OLD `confirmed_transcript_hash`, because the transcript
//!      cannot yet include the Commit being processed. RFC 9420 §12.4.2
//!      spells this out in its "Construct a provisional GroupContext
//!      object" bullet; using the final context there is the single most
//!      plausible-looking way to derive an epoch nobody else derived.
//!   3. Proposals are applied in §12.3's fixed order — GroupContextExtensions,
//!      Update, Remove, Add, PSK — which is NOT the order they appear in the
//!      Commit. Applying Adds before Removes puts new members in the wrong
//!      leaves, and every subsequent tree hash diverges.
//!
//! `processCommit` is written as one function following the RFC's bullet
//! order, with each step commented by its bullet, because splitting it up
//! is exactly how the order drifts.
//!
//! **What this object deliberately does NOT own.**
//!
//!   * **Creating** Commits or proposals. This is the receiving half only.
//!     A committer additionally needs to generate an `UpdatePath` (the
//!     sender half of §7.5, which `treekem.zig` does not implement either),
//!     and to produce a `Welcome` for the members it adds. `fromWelcome`
//!     plus `processCommit` is a complete passive client and a complete
//!     *follower*; it is not a complete *client*.
//!   * **Application messages and the secret tree.** `secrettree.zig` owns
//!     §9's ratchets, but this object does not drive them: a Commit changes
//!     `encryption_secret`, and re-keying the secret tree per epoch is a
//!     separate concern with its own generation/deletion policy. Handshake
//!     messages sent as `PrivateMessage` are therefore NOT accepted here —
//!     see `error.PrivateHandshakeNotSupported`, which is a scope boundary
//!     stated as a named refusal rather than a silent gap.
//!   * **§7.3 LeafNode validation and §10.1 KeyPackage validation** (Part
//!     3, still not built). `processCommit` checks the leaf properties
//!     §12.4.2 names EXPLICITLY in its own bullets — `leaf_node_source ==
//!     commit`, the committer's encryption key actually changing, no
//!     UpdatePath public key already present in the tree — and the
//!     signature on every `LeafNode` it installs. It does not check
//!     lifetimes, credential acceptability, or capability/extension
//!     support.
//!   * **Atomicity.** A Commit that fails a check after the tree has been
//!     mutated leaves the `Group` unusable, and it says so: the object is
//!     marked poisoned and every later call returns
//!     `error.GroupPoisoned`. Real rollback means processing into a copy of
//!     the tree, which is a memory-model change, not a bug fix — noted in
//!     `SPEC.md`'s Backlog rather than half-done here.
//!
//! **Memory model: one arena for retained state, the caller's allocator for
//! scratch.** This module's decoders alias their input buffers (see
//! `tree.zig`'s convention: "aliased bytes must outlive the tree"), and a
//! group's ratchet tree accumulates leaves aliasing a DIFFERENT buffer per
//! epoch — the Welcome's `GroupInfo`, then each Commit's `UpdatePath`, then
//! each Add proposal's `KeyPackage`. Deep-copying every `LeafNode` would
//! mean a second, parallel implementation of `tree.zig`'s whole decode
//! layer. So `Group` owns an arena, copies each message it retains state
//! from into it, and decodes from that copy; group state is retained
//! wholesale and dropped wholesale by `deinit`, which is also how MLS
//! itself treats it. Verification scratch (transcript inputs, TBS buffers,
//! resolutions) uses `gpa` and is freed immediately.
//!
//! Model: RFC 9420 §12.2, §12.3, §12.4.2, and the receiving half of
//! §12.4.3.1. Anchored end-to-end against the official
//! `mlswg/mls-implementations` `passive-client-*.json` vectors, which
//! replay recorded sessions Commit by Commit and compare the
//! `epoch_authenticator` at every step — see `kat_passive_test.zig` and
//! `NOTICE`.

const std = @import("std");
const codec = @import("codec.zig");
const content = @import("content.zig");
const crypto = @import("crypto.zig");
const framing = @import("framing.zig");
const keyschedule = @import("keyschedule.zig");
const suite = @import("suite.zig");
const transcript = @import("transcript.zig");
const tree = @import("tree.zig");
const treehash = @import("treehash.zig");
const treekem = @import("treekem.zig");
const treemath = @import("treemath.zig");
const welcome_mod = @import("welcome.zig");

pub const Error = error{
    /// A previous `processCommit` failed after mutating the tree. See this
    /// file's doc comment on atomicity.
    GroupPoisoned,
    /// The message was a `PrivateMessage`. Encrypted handshake messages
    /// need the §9 secret tree driven per epoch, which this object does not
    /// own — a scope boundary, not a decode failure.
    PrivateHandshakeNotSupported,
    /// `FramedContent.epoch` did not equal the group's current epoch
    /// (§12.4.2's first bullet).
    WrongEpoch,
    /// The message was not a Commit (or, for a proposal, not a Proposal).
    WrongContentType,
    /// The `Sender` was of a type this path does not accept.
    UnexpectedSenderType,
    /// A leaf index named by a sender, a Remove, or an Update does not name
    /// a non-blank leaf in the current tree.
    UnknownMember,
    /// A `ProposalOrRef.reference` did not match any supplied proposal.
    ProposalNotFound,
    /// §12.2: the committed proposal list broke one of that section's rules.
    InvalidProposalList,
    /// §12.4.2: `path` was absent although the proposal list requires it
    /// (it contains an Update or a Remove, or it is empty).
    PathRequired,
    /// §12.4.2: an `UpdatePath` bullet failed — wrong `leaf_node_source`,
    /// the committer's encryption key did not change, or a public key in
    /// the UpdatePath already appears in the tree.
    InvalidUpdatePath,
    /// A `PreSharedKeyID` in the Commit could not be resolved to key
    /// material (§12.4.2: "Verify that all PreSharedKey proposals ... are
    /// available").
    PskNotAvailable,
    /// The joiner's own `KeyPackage` does not match any leaf of the tree
    /// the `GroupInfo` carries.
    OwnLeafNotFound,
    /// A private key handed to `fromWelcome` does not match the public key
    /// in the leaf it was supposed to belong to.
    PrivateKeyMismatch,
    /// The `GroupInfo` carried no `ratchet_tree` extension and no tree was
    /// supplied out of band.
    RatchetTreeUnavailable,
} || tree.Error || keyschedule.Error || transcript.Error || std.mem.Allocator.Error ||
    std.crypto.errors.Error || error{ Malformed, EndOfStream };

/// One application-provided external PSK: RFC 9420 §8.4's `psk_id` and the
/// key material it names. `Group` resolves `PreSharedKeyID.external` against
/// a list of these.
pub const ExternalPsk = struct {
    psk_id: []const u8,
    psk: []const u8,
};

/// RFC 9420 §12.2's rules that the spec defers to "the application". They
/// are policy, not protocol, so they are switchable — but they default ON,
/// because the failure they prevent (a group silently containing two leaves
/// for the same client) is not detectable later.
pub const Policy = struct {
    /// §12.2: reject a proposal list with "multiple Add proposals that
    /// contain KeyPackages that represent the same client according to the
    /// application (for example, identical signature keys)". Implemented as
    /// the RFC's own parenthetical: signature-key equality.
    reject_duplicate_add_signature_keys: bool = true,
    /// §12.2: reject "an Add proposal with a KeyPackage that represents a
    /// client already in the group ... unless there is a Remove proposal in
    /// the list removing the matching client". Same signature-key reading.
    reject_add_of_existing_signature_key: bool = true,
};

pub fn Group(comptime S: type) type {
    return struct {
        const Self = @This();

        /// Scratch allocator, also the owner of `arena`.
        gpa: std.mem.Allocator,
        /// Retained, wire-aliased group state — see this file's doc comment.
        /// Heap-allocated so `arena.allocator()` stays valid when a `Group`
        /// value is moved (returned from `fromWelcome`, stored in a struct).
        arena: *std.heap.ArenaAllocator,

        /// Set once a `processCommit` has failed after mutating the tree.
        poisoned: bool = false,

        policy: Policy = .{},

        // ── §8.1 GroupContext, held field by field ──
        group_id: []const u8,
        epoch: u64,
        tree_hash: [S.Hash.digest_length]u8,
        confirmed_transcript_hash: [S.Hash.digest_length]u8,
        extensions: []const tree.Extension,

        /// §8.2's other hash — not in the GroupContext, but part of the
        /// state a member must carry between epochs.
        interim_transcript_hash: [S.Hash.digest_length]u8,

        /// The group's public ratchet tree. Allocated from `arena`.
        ratchet_tree: tree.RatchetTree,

        /// Every §8 secret for the current epoch.
        secrets: keyschedule.EpochSecrets(S),

        // ── this member's private state ──
        my_leaf_index: u32,
        my_encryption_priv: [S.Kem.Nsk]u8,
        /// Path secrets this member holds for nodes on its own direct path
        /// (§7.4). Grows as Commits hand down path secrets, and is pruned
        /// against the tree after every Commit — see `prunePathSecrets`.
        my_path_secrets: std.ArrayList(treekem.PathSecretEntry),

        /// `resumption_psk` per epoch lived through, for §8.4 resumption
        /// PSKs — key material a Commit can name by epoch rather than by
        /// value, and which therefore has to be remembered rather than
        /// asked of the application. Bounded by the session length, like
        /// the arena.
        resumption_history: std.ArrayList(ResumptionEntry),

        /// One remembered epoch's `resumption_psk`. A NAMED type because
        /// two declarations mention it (the field above and
        /// `resolvePsksFromIds`' parameter), and two anonymous struct
        /// literals are two DIFFERENT types in Zig even when spelled
        /// identically.
        pub const ResumptionEntry = struct { epoch: u64, secret: [S.Nh]u8 };

        pub fn deinit(self: *Self) void {
            self.arena.deinit();
            self.gpa.destroy(self.arena);
            self.* = undefined;
        }

        /// The §8.1 `GroupContext` for the CURRENT epoch, as a view over
        /// this object's own fields (no allocation; the slices alias
        /// `self`, so it must not outlive the next `processCommit`).
        pub fn groupContext(self: *const Self) keyschedule.GroupContext {
            return .{
                .cipher_suite = S.id,
                .group_id = self.group_id,
                .epoch = self.epoch,
                .tree_hash = &self.tree_hash,
                .confirmed_transcript_hash = &self.confirmed_transcript_hash,
                .extensions = self.extensions,
            };
        }

        /// The encoded current `GroupContext` — what §6.1's signature/MAC
        /// inputs and §8's derivations actually consume. Caller frees.
        pub fn groupContextAlloc(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
            return self.groupContext().encodeAlloc(allocator);
        }

        /// RFC 9420 §8 Table 4's `epoch_authenticator`. This is the value
        /// the `passive-client-*.json` vectors compare at every step, and
        /// the one an application shows a user as a "safety number" for the
        /// group as a whole.
        pub fn epochAuthenticator(self: *const Self) [S.Nh]u8 {
            return self.secrets.epoch_authenticator;
        }

        /// The number of leaves the tree currently spans (blank included).
        pub fn treeSize(self: *const Self) usize {
            return self.ratchet_tree.nLeaves();
        }

        fn check(self: *const Self) !void {
            if (self.poisoned) return error.GroupPoisoned;
        }

        // ── §12.4.3.1: entering a group from a Welcome ────────────────────

        /// Everything `fromWelcome` needs. All byte slices are borrowed for
        /// the duration of the call only — whatever the group retains is
        /// copied into its own arena.
        pub const WelcomeParams = struct {
            /// The whole `MLSMessage(Welcome)` as received.
            welcome_msg: []const u8,
            /// This client's own whole `MLSMessage(KeyPackage)` — the one
            /// the committer added. Used both to compute the
            /// `KeyPackageRef` that selects our `EncryptedGroupSecrets`
            /// slot and to find our leaf in the tree.
            key_package_msg: []const u8,
            /// Private half of that KeyPackage's `init_key`.
            init_priv: [S.Kem.Nsk]u8,
            /// Private half of that KeyPackage's LeafNode `encryption_key`.
            encryption_priv: [S.Kem.Nsk]u8,
            /// §12.4.3.3's out-of-band tree: the encoded `optional<Node>
            /// ratchet_tree<V>` vector. `null` means the tree must come
            /// from the `GroupInfo`'s `ratchet_tree` extension.
            ratchet_tree: ?[]const u8 = null,
            /// External PSKs the application holds, for the `GroupSecrets`'
            /// PSK list.
            external_psks: []const ExternalPsk = &.{},
            policy: Policy = .{},
        };

        /// RFC 9420 §12.4.3.1's receiving procedure, run to completion and
        /// landed in a usable group state.
        ///
        /// **Why this re-sequences `welcome.join` rather than calling it.**
        /// `welcome.join` takes the signer's public key as a parameter,
        /// because Part 6 had no way to resolve a leaf index to a key. But
        /// the signer index is INSIDE the encrypted `GroupInfo`, and so is
        /// the tree that resolves it — so a caller with only a Welcome in
        /// hand cannot supply that parameter without decrypting first.
        /// Part 7 can: it owns the tree. This runs the same steps in the
        /// same order using the same public building blocks
        /// (`welcome.decryptGroupSecrets`/`welcomeKeyNonce`/
        /// `decryptGroupInfo`/`verifyTreeHash`,
        /// `keyschedule.deriveEpochFromJoiner`/`verifyConfirmationTag`,
        /// `transcript.interimTranscriptHash`), and additionally does the
        /// three things §12.4.3.1 lists that Part 6 explicitly left to the
        /// caller: verify the tree hash, verify the parent-hash chain, and
        /// find this client's own leaf.
        pub fn fromWelcome(gpa: std.mem.Allocator, params: WelcomeParams) !Self {
            const arena_ptr = try gpa.create(std.heap.ArenaAllocator);
            errdefer gpa.destroy(arena_ptr);
            arena_ptr.* = .init(gpa);
            errdefer arena_ptr.deinit();
            const arena = arena_ptr.allocator();

            // ── our own KeyPackage: the ref that selects our slot, and the
            // LeafNode we will look for in the tree.
            var kp_reader = codec.Reader.init(params.key_package_msg);
            const kp_msg = try framing.MLSMessage.decode(gpa, &kp_reader);
            defer kp_msg.deinit(gpa);
            if (!kp_reader.atEnd()) return error.Malformed;
            if (kp_msg != .key_package) return error.Malformed;
            const my_kp = kp_msg.key_package;
            if (my_kp.cipher_suite != S.id) return error.CipherSuiteMismatch;

            const kp_ref = blk: {
                const bytes = try my_kp.encodeAlloc(gpa);
                defer gpa.free(bytes);
                break :blk try crypto.make_keypackage_ref(S, bytes);
            };
            const my_leaf_encoded = try leafNodeEncodeAlloc(gpa, my_kp.leaf_node);
            defer gpa.free(my_leaf_encoded);

            // ── the Welcome. Its GroupInfo and (usually) the tree are
            // retained, so decode from an arena-owned copy of the bytes.
            const welcome_copy = try arena.dupe(u8, params.welcome_msg);
            var w_reader = codec.Reader.init(welcome_copy);
            const w_msg = try framing.MLSMessage.decode(arena, &w_reader);
            if (!w_reader.atEnd()) return error.Malformed;
            if (w_msg != .welcome) return error.Malformed;
            const w = w_msg.welcome;
            if (w.cipher_suite != S.id) return error.CipherSuiteMismatch;

            const slot = w.findSecret(&kp_ref) orelse return error.NoMatchingKeyPackage;

            const init_kp = try S.Kem.KeyPair.generateDeterministic(params.init_priv);
            if (!std.mem.eql(u8, my_kp.init_key, &init_kp.public_key)) return error.PrivateKeyMismatch;

            const gs_bytes = try welcome_mod.decryptGroupSecrets(
                S,
                arena,
                init_kp,
                w.encrypted_group_info,
                slot.encrypted_group_secrets,
            );
            var gs_reader = codec.Reader.init(gs_bytes);
            const group_secrets = try welcome_mod.GroupSecrets.decode(arena, &gs_reader);
            if (!gs_reader.atEnd()) return error.Malformed;
            if (group_secrets.joiner_secret.len != S.Nh) return error.WrongSecretLength;

            // §12.4.3.1: the PSKs named in GroupSecrets, resolved in the
            // order they appear — §8.4's chain is position-dependent.
            const psks = try resolvePsksFromIds(gpa, group_secrets.psks, params.external_psks, &.{});
            defer gpa.free(psks);
            const psk_secret = try keyschedule.pskSecret(S, gpa, psks);

            var joiner: [S.Nh]u8 = undefined;
            @memcpy(&joiner, group_secrets.joiner_secret);
            const welcome_secret = try keyschedule.welcomeSecret(S, joiner, psk_secret);

            const gi_bytes = try welcome_mod.decryptGroupInfo(S, arena, welcome_secret, w.encrypted_group_info);
            var gi_reader = codec.Reader.init(gi_bytes);
            const group_info = try welcome_mod.GroupInfo.decode(arena, &gi_reader);
            if (!gi_reader.atEnd()) return error.Malformed;
            if (group_info.group_context.cipher_suite != S.id) return error.CipherSuiteMismatch;

            // ── §12.4.3.3: the tree, from the extension or from out of band.
            var rt: tree.RatchetTree = blk: {
                if (params.ratchet_tree) |ext_bytes| {
                    const copy = try arena.dupe(u8, ext_bytes);
                    var r = codec.Reader.init(copy);
                    const t = try tree.RatchetTree.decode(arena, &r);
                    if (!r.atEnd()) return error.Malformed;
                    break :blk t;
                }
                break :blk group_info.ratchetTree(arena) catch |e| switch (e) {
                    error.ExtensionNotFound => return error.RatchetTreeUnavailable,
                    else => return e,
                };
            };

            // §12.4.3.1's tree-integrity block, which Part 6 left to the
            // caller: the tree really is the one the signed GroupContext
            // names, and its parent-hash chain is intact.
            try welcome_mod.verifyTreeHash(S, gpa, &rt, group_info.group_context);
            try treekem.validateParentHashes(S, gpa, &rt);

            // Only now can the GroupInfo signature be checked: the signer
            // index means nothing without the tree.
            const signer_key = try leafSignatureKey(&rt, group_info.signer);
            try group_info.verifySignature(S, gpa, signer_key);

            // ── §8: the epoch, entered at joiner_secret.
            const gc_bytes = group_info.raw.?.group_context;
            const secrets = try keyschedule.deriveEpochFromJoiner(S, gpa, joiner, psk_secret, gc_bytes);
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

            // ── our own leaf, and the private keys that must match it.
            const my_index = try findOwnLeaf(gpa, &rt, my_leaf_encoded);
            const enc_kp = try S.Kem.KeyPair.generateDeterministic(params.encryption_priv);
            {
                const leaf = (rt.nodes[my_index * 2].?).leaf;
                if (!std.mem.eql(u8, leaf.encryption_key, &enc_kp.public_key)) return error.PrivateKeyMismatch;
            }

            var path_secrets: std.ArrayList(treekem.PathSecretEntry) = .empty;
            // §12.4.3.1: "the path secret for the lowest node contained in
            // the direct paths of both the committer and the new member" —
            // so it belongs at the common ancestor of us and the signer,
            // and the chain above it is derived from there.
            if (group_secrets.path_secret) |ps| {
                if (ps.len != S.Nh) return error.WrongSecretLength;
                const start = try commonAncestor(&rt, my_index, group_info.signer);
                try derivePathSecretsUp(S, arena, &rt, my_index, start, ps, &path_secrets);
            }

            var self: Self = .{
                .gpa = gpa,
                .arena = arena_ptr,
                .policy = params.policy,
                .group_id = group_info.group_context.group_id,
                .epoch = group_info.group_context.epoch,
                .tree_hash = undefined,
                .confirmed_transcript_hash = undefined,
                .extensions = group_info.group_context.extensions,
                .interim_transcript_hash = interim,
                .ratchet_tree = rt,
                .secrets = secrets,
                .my_leaf_index = @intCast(my_index),
                .my_encryption_priv = params.encryption_priv,
                .my_path_secrets = path_secrets,
                .resumption_history = .empty,
            };
            if (group_info.group_context.tree_hash.len != S.Hash.digest_length) return error.Malformed;
            if (group_info.group_context.confirmed_transcript_hash.len != S.Hash.digest_length) return error.Malformed;
            @memcpy(&self.tree_hash, group_info.group_context.tree_hash);
            @memcpy(&self.confirmed_transcript_hash, group_info.group_context.confirmed_transcript_hash);
            try self.resumption_history.append(arena, .{ .epoch = self.epoch, .secret = secrets.resumption_psk });

            // The re-encoded GroupContext must equal the bytes the key
            // schedule just consumed. If it does not, every later epoch
            // this object derives (which uses the re-encoded form) silently
            // diverges from this one.
            {
                const re = try self.groupContextAlloc(gpa);
                defer gpa.free(re);
                if (!std.mem.eql(u8, gc_bytes, re)) return error.Malformed;
            }
            return self;
        }

        // ── §12.4.2: processing a Commit ──────────────────────────────────

        /// The inputs one epoch transition consumes.
        pub const CommitParams = struct {
            /// The whole `MLSMessage` carrying the Commit.
            commit_msg: []const u8,
            /// Every proposal `MLSMessage` seen during the current epoch,
            /// so `ProposalOrRef.reference` entries can be resolved.
            /// Proposals the Commit does not reference are ignored.
            proposal_msgs: []const []const u8 = &.{},
            /// External PSKs the application holds.
            external_psks: []const ExternalPsk = &.{},
        };

        /// RFC 9420 §12.4.2, bullet by bullet. On success the group has
        /// advanced one epoch; on failure see this file's note on
        /// atomicity.
        pub fn processCommit(self: *Self, params: CommitParams) !void {
            try self.check();
            const arena = self.arena.allocator();
            const gpa = self.gpa;

            // The Commit's UpdatePath contributes a LeafNode the tree keeps,
            // so the tree must alias a buffer the group owns.
            const msg_copy = try arena.dupe(u8, params.commit_msg);
            var reader = codec.Reader.init(msg_copy);
            const msg = try framing.MLSMessage.decode(arena, &reader);
            if (!reader.atEnd()) return error.Malformed;
            const pm = switch (msg) {
                .public_message => |m| m,
                .private_message => return error.PrivateHandshakeNotSupported,
                else => return error.WrongContentType,
            };

            const old_gc = try self.groupContextAlloc(gpa);
            defer gpa.free(old_gc);

            // Bullet 1: the epoch must match.
            if (pm.content.epoch != self.epoch) return error.WrongEpoch;
            if (pm.content.contentType() != .commit) return error.WrongContentType;

            // Bullets 2-3: unprotect with the CURRENT epoch's keys, then
            // check the signature — both against the OLD GroupContext.
            const committer: u32 = switch (pm.content.sender) {
                .member => |i| i,
                else => return error.UnexpectedSenderType,
            };
            const committer_key = try leafSignatureKey(&self.ratchet_tree, committer);
            try framing.verifyMembershipTag(S, gpa, self.secrets.membership_key, pm, old_gc);
            const ac = pm.authenticatedContent();
            try framing.verifyFramedContent(S, gpa, committer_key, ac, old_gc);

            const commit = switch (pm.content.body) {
                .commit => |c| c,
                else => return error.WrongContentType,
            };

            // Bullet 4: resolve every ProposalOrRef, then §12.2-validate the
            // resulting list. Resolution needs the proposal messages, which
            // may themselves contribute LeafNodes (an Add's KeyPackage), so
            // they are copied into the arena too.
            const resolved = try self.resolveProposals(arena, gpa, commit.proposals, params.proposal_msgs, old_gc);
            defer gpa.free(resolved);
            try self.validateProposalList(gpa, resolved, committer);

            // From here on the tree is mutated; any failure poisons.
            self.poisoned = true;

            // Bullet 6 (§12.3): apply the proposals, in §12.3's order.
            var new_extensions = self.extensions;
            for (resolved) |rp| {
                if (rp.proposal == .group_context_extensions) {
                    new_extensions = rp.proposal.group_context_extensions;
                }
            }
            for (resolved) |rp| switch (rp.proposal) {
                .update => |leaf| {
                    const sender = rp.sender orelse return error.InvalidProposalList;
                    try verifyLeafSignature(S, gpa, leaf, .update, self.group_id, sender);
                    const owned = try dupLeafNode(arena, leaf);
                    try self.ratchet_tree.updateLeaf(sender, owned);
                },
                else => {},
            };
            for (resolved) |rp| switch (rp.proposal) {
                .remove => |idx| {
                    if (idx * 2 >= self.ratchet_tree.nodes.len) return error.UnknownMember;
                    try self.ratchet_tree.removeLeaf(idx);
                },
                else => {},
            };
            // RFC 9420 §7.5: members added by THIS Commit must be excluded
            // from the resolutions the UpdatePath is encrypted to — they
            // receive their state from the Welcome, not from this path. So
            // their leaf indices are collected here and handed to
            // `applyUpdatePath`/`processUpdatePath` below. Getting this
            // wrong is not a subtle key divergence: the ciphertext count
            // simply does not match and the Commit cannot be processed.
            var added_leaves: std.ArrayList(u32) = .empty;
            defer added_leaves.deinit(gpa);
            for (resolved) |rp| switch (rp.proposal) {
                .add => |kp| {
                    try verifyLeafSignature(S, gpa, kp.leaf_node, .key_package, null, null);
                    const owned = try dupLeafNode(arena, kp.leaf_node);
                    // §12.1.1's placement, unchanged: the leftmost blank
                    // leaf, extending the tree to the right if there is
                    // none. Because §12.3 applies Removes first, this may
                    // legitimately reuse a leaf vacated by this same
                    // Commit — and it does so in the recorded sessions.
                    const at = try self.ratchet_tree.addLeaf(owned);
                    try added_leaves.append(gpa, @intCast(at));
                },
                else => {},
            };
            // Bullet 5 + §12.3's PSK step: every PreSharedKey proposal must
            // resolve, in the order the proposals appear.
            const psks = blk: {
                var ids: std.ArrayList(keyschedule.PreSharedKeyId) = .empty;
                defer ids.deinit(gpa);
                for (resolved) |rp| {
                    if (rp.proposal == .psk) try ids.append(gpa, rp.proposal.psk);
                }
                break :blk try self.resolvePsks(gpa, ids.items, params.external_psks);
            };
            defer gpa.free(psks);
            const psk_secret = try keyschedule.pskSecret(S, gpa, psks);

            // Bullet 7: path presence is mandatory for a proposal list that
            // is empty or that contains an Update or a Remove.
            var needs_path = resolved.len == 0;
            for (resolved) |rp| switch (rp.proposal) {
                .update, .remove => needs_path = true,
                else => {},
            };
            if (needs_path and commit.path == null) return error.PathRequired;

            // Bullet 8: validate and apply the path.
            var commit_secret = keyschedule.zeroSecret(S);
            var derived: []const treekem.PathSecretEntry = &.{};
            if (commit.path) |path| {
                // §7.3 via §12.4.2: source MUST be `commit`.
                if (path.leaf_node.leaf_node_source != .commit) return error.InvalidUpdatePath;
                try verifyLeafSignature(S, gpa, path.leaf_node, .commit, self.group_id, committer);

                // The committer's encryption key must actually change —
                // read BEFORE the merge replaces the leaf.
                {
                    const cur = self.ratchet_tree.nodes[committer * 2] orelse return error.UnknownMember;
                    if (std.mem.eql(u8, cur.leaf.encryption_key, path.leaf_node.encryption_key))
                        return error.InvalidUpdatePath;
                }
                // No public key in the UpdatePath may already appear in the
                // tree (a committer replaying another node's key would make
                // the path secrets decryptable by its owner).
                try rejectReusedPathKeys(&self.ratchet_tree, path);

                try treekem.applyUpdatePath(arena, &self.ratchet_tree, committer, path, added_leaves.items);

                // The PROVISIONAL GroupContext: new epoch, new tree hash,
                // OLD confirmed_transcript_hash. See this file's doc
                // comment — this is the step that is easy to get wrong and
                // impossible to notice without a vector.
                const merged_tree_hash = try treehash.rootHash(S, gpa, &self.ratchet_tree);
                const provisional: keyschedule.GroupContext = .{
                    .cipher_suite = S.id,
                    .group_id = self.group_id,
                    .epoch = self.epoch + 1,
                    .tree_hash = &merged_tree_hash,
                    .confirmed_transcript_hash = &self.confirmed_transcript_hash,
                    .extensions = new_extensions,
                };
                const provisional_bytes = try provisional.encodeAlloc(gpa);
                defer gpa.free(provisional_bytes);

                // A Commit that removed us leaves nothing to decrypt with;
                // §12.4.2's closing note says such a Commit is still valid.
                const processed = try treekem.processUpdatePath(
                    S,
                    arena,
                    &self.ratchet_tree,
                    .{
                        .leaf_index = self.my_leaf_index,
                        .encryption_priv = &self.my_encryption_priv,
                        .known_path_secrets = self.my_path_secrets.items,
                    },
                    committer,
                    path,
                    provisional_bytes,
                    added_leaves.items,
                );
                if (processed.commit_secret.len != S.Nh) return error.WrongSecretLength;
                @memcpy(&commit_secret, processed.commit_secret);
                derived = processed.derived_path_secrets;
            }

            // Bullet 9: advance both transcript hashes over this Commit.
            const hashes = try transcript.advance(S, gpa, &self.interim_transcript_hash, ac);

            // …and build the FINAL GroupContext, which differs from the
            // provisional one in exactly one field.
            const new_tree_hash = try treehash.rootHash(S, gpa, &self.ratchet_tree);
            const new_gc: keyschedule.GroupContext = .{
                .cipher_suite = S.id,
                .group_id = self.group_id,
                .epoch = self.epoch + 1,
                .tree_hash = &new_tree_hash,
                .confirmed_transcript_hash = &hashes.confirmed,
                .extensions = new_extensions,
            };
            const new_gc_bytes = try new_gc.encodeAlloc(gpa);
            defer gpa.free(new_gc_bytes);

            // Bullets 10-11: the key schedule.
            const secrets = try keyschedule.deriveEpoch(
                S,
                gpa,
                self.secrets.init_secret,
                commit_secret,
                psk_secret,
                new_gc_bytes,
            );

            // Bullet 12: the confirmation tag proves the committer derived
            // the same epoch. Everything above this line is unauthenticated
            // arithmetic; this is what makes it binding.
            try keyschedule.verifyConfirmationTag(
                S,
                secrets.confirmation_key,
                &hashes.confirmed,
                ac.auth.confirmation_tag orelse return error.MissingConfirmationTag,
            );

            // Bullet 13: adopt.
            self.epoch += 1;
            self.tree_hash = new_tree_hash;
            self.confirmed_transcript_hash = hashes.confirmed;
            self.interim_transcript_hash = hashes.interim;
            self.extensions = new_extensions;
            self.secrets = secrets;
            try self.adoptPathSecrets(arena, derived);
            try self.resumption_history.append(arena, .{ .epoch = self.epoch, .secret = secrets.resumption_psk });
            self.poisoned = false;
        }

        // ── proposal resolution and §12.2 validation ──────────────────────

        const Resolved = struct {
            proposal: content.Proposal,
            /// The leaf that SENT this proposal — `null` for one the Commit
            /// carried inline (whose sender is the committer). An Update
            /// applies to its sender's leaf, so this is not cosmetic.
            sender: ?u32,
            /// True when the Commit named it by reference.
            by_reference: bool,
        };

        fn resolveProposals(
            self: *Self,
            arena: std.mem.Allocator,
            gpa: std.mem.Allocator,
            refs: []const content.ProposalOrRef,
            proposal_msgs: []const []const u8,
            old_gc: []const u8,
        ) ![]Resolved {
            // Decode and authenticate every candidate proposal ONCE, then
            // index them by their §5.2 ProposalRef.
            const Candidate = struct {
                ref: [S.Hash.digest_length]u8,
                proposal: content.Proposal,
                sender: u32,
            };
            var candidates: std.ArrayList(Candidate) = .empty;
            defer candidates.deinit(gpa);

            for (proposal_msgs) |bytes| {
                const copy = try arena.dupe(u8, bytes);
                var r = codec.Reader.init(copy);
                const m = try framing.MLSMessage.decode(arena, &r);
                if (!r.atEnd()) return error.Malformed;
                const p = switch (m) {
                    .public_message => |x| x,
                    .private_message => return error.PrivateHandshakeNotSupported,
                    else => return error.WrongContentType,
                };
                if (p.content.contentType() != .proposal) return error.WrongContentType;
                if (p.content.epoch != self.epoch) return error.WrongEpoch;
                const sender: u32 = switch (p.content.sender) {
                    .member => |i| i,
                    else => return error.UnexpectedSenderType,
                };
                // A proposal is authenticated content in its own right;
                // §12.2's "contains an individual proposal that is invalid"
                // starts here.
                const key = try leafSignatureKey(&self.ratchet_tree, sender);
                try framing.verifyMembershipTag(S, gpa, self.secrets.membership_key, p, old_gc);
                const pac = p.authenticatedContent();
                try framing.verifyFramedContent(S, gpa, key, pac, old_gc);
                try candidates.append(gpa, .{
                    .ref = try framing.proposalRef(S, gpa, pac),
                    .proposal = switch (p.content.body) {
                        .proposal => |x| x,
                        else => return error.WrongContentType,
                    },
                    .sender = sender,
                });
            }

            const out = try gpa.alloc(Resolved, refs.len);
            errdefer gpa.free(out);
            for (refs, out) |ref, *slot| {
                switch (ref) {
                    .proposal => |p| slot.* = .{ .proposal = p, .sender = null, .by_reference = false },
                    .reference => |r| {
                        const found = for (candidates.items) |c| {
                            if (std.mem.eql(u8, r, &c.ref)) break c;
                        } else return error.ProposalNotFound;
                        slot.* = .{ .proposal = found.proposal, .sender = found.sender, .by_reference = true };
                    },
                }
            }
            return out;
        }

        /// RFC 9420 §12.2's rules for a REGULAR (non-external) Commit.
        fn validateProposalList(self: *const Self, gpa: std.mem.Allocator, list: []const Resolved, committer: u32) !void {
            var n_gce: usize = 0;
            var n_reinit: usize = 0;
            var touched: std.ArrayList(u32) = .empty; // leaves hit by Update/Remove
            defer touched.deinit(gpa);
            var psk_ids: std.ArrayList([]const u8) = .empty;
            defer {
                for (psk_ids.items) |b| gpa.free(b);
                psk_ids.deinit(gpa);
            }
            var add_keys: std.ArrayList([]const u8) = .empty;
            defer add_keys.deinit(gpa);
            var removed: std.ArrayList(u32) = .empty;
            defer removed.deinit(gpa);

            for (list) |rp| switch (rp.proposal) {
                // "It contains an ExternalInit proposal."
                .external_init => return error.InvalidProposalList,
                .group_context_extensions => n_gce += 1,
                .reinit => n_reinit += 1,
                .update => {
                    // "It contains an Update proposal generated by the
                    // committer." An inline Update has no sender of its own,
                    // so it IS the committer's.
                    const sender = rp.sender orelse return error.InvalidProposalList;
                    if (sender == committer) return error.InvalidProposalList;
                    try appendUnique(gpa, &touched, sender);
                },
                .remove => |idx| {
                    // "It contains a Remove proposal that removes the
                    // committer."
                    if (idx == committer) return error.InvalidProposalList;
                    try appendUnique(gpa, &touched, idx);
                    try removed.append(gpa, idx);
                },
                .psk => |id| {
                    // "multiple PreSharedKey proposals that reference the
                    // same PreSharedKeyID" — compared by ENCODED bytes so a
                    // future arm cannot be silently skipped.
                    const enc = try gpa.alloc(u8, id.encodedLen());
                    errdefer gpa.free(enc);
                    var w = codec.Writer.init(enc);
                    try id.encode(&w);
                    for (psk_ids.items) |seen| {
                        if (std.mem.eql(u8, seen, enc)) {
                            gpa.free(enc);
                            return error.InvalidProposalList;
                        }
                    }
                    try psk_ids.append(gpa, enc);
                },
                .add => |kp| try add_keys.append(gpa, kp.leaf_node.signature_key),
            };

            // "multiple Update and/or Remove proposals that apply to the
            // same leaf" — `appendUnique` reports the collision.
            if (n_gce > 1) return error.InvalidProposalList;
            // "a ReInit proposal together with any other proposal"
            if (n_reinit > 0 and list.len > 1) return error.InvalidProposalList;

            if (self.policy.reject_duplicate_add_signature_keys) {
                for (add_keys.items, 0..) |a, i| {
                    for (add_keys.items[i + 1 ..]) |b| {
                        if (std.mem.eql(u8, a, b)) return error.InvalidProposalList;
                    }
                }
            }
            if (self.policy.reject_add_of_existing_signature_key) {
                for (add_keys.items) |a| {
                    var leaf: u32 = 0;
                    while (leaf * 2 < self.ratchet_tree.nodes.len) : (leaf += 1) {
                        const node = self.ratchet_tree.nodes[leaf * 2] orelse continue;
                        if (!std.mem.eql(u8, node.leaf.signature_key, a)) continue;
                        // …"unless there is a Remove proposal in the list
                        // removing the matching client".
                        for (removed.items) |r| {
                            if (r == leaf) break;
                        } else return error.InvalidProposalList;
                    }
                }
            }
        }

        fn appendUnique(gpa: std.mem.Allocator, list: *std.ArrayList(u32), v: u32) !void {
            for (list.items) |x| if (x == v) return error.InvalidProposalList;
            try list.append(gpa, v);
        }

        // ── PSK resolution ────────────────────────────────────────────────

        fn resolvePsks(
            self: *const Self,
            gpa: std.mem.Allocator,
            ids: []const keyschedule.PreSharedKeyId,
            external: []const ExternalPsk,
        ) ![]keyschedule.PreSharedKey(S) {
            return resolvePsksFromIds(gpa, ids, external, self.resumption_history.items);
        }

        fn resolvePsksFromIds(
            gpa: std.mem.Allocator,
            ids: []const keyschedule.PreSharedKeyId,
            external: []const ExternalPsk,
            history: []const ResumptionEntry,
        ) ![]keyschedule.PreSharedKey(S) {
            const out = try gpa.alloc(keyschedule.PreSharedKey(S), ids.len);
            errdefer gpa.free(out);
            for (ids, out) |id, *slot| {
                // Borrowed, not copied: §8.4 puts no width constraint on a
                // PSK (it is `KDF.Extract` IKM), so there is no fixed-size
                // buffer to copy into. The slices point into the caller's
                // `external` list or into `history`, both of which outlive
                // the `pskSecret` call these feed.
                const secret: []const u8 = switch (id.id) {
                    .external => |psk_id| for (external) |e| {
                        if (std.mem.eql(u8, e.psk_id, psk_id)) break e.psk;
                    } else return error.PskNotAvailable,
                    .resumption => |r| for (history, 0..) |h, i| {
                        if (h.epoch == r.psk_epoch) break history[i].secret[0..];
                    } else return error.PskNotAvailable,
                };
                slot.* = .{ .id = id, .secret = secret };
            }
            return out;
        }

        // ── private-state bookkeeping ─────────────────────────────────────

        /// Install the path secrets this Commit handed down, then drop every
        /// stored secret that the new tree no longer agrees with.
        ///
        /// The pruning rule is self-validating rather than positional: a
        /// stored `path_secret` is kept only if the node it names still
        /// holds the public key that secret derives (§7.4's `node_secret =
        /// DeriveSecret(path_secret, "node")`, then `KEM.DeriveKeyPair`).
        /// Blanking, replacement by another member's Commit, and tree
        /// truncation are then all handled by the same check, with no
        /// index arithmetic to get wrong.
        fn adoptPathSecrets(self: *Self, arena: std.mem.Allocator, derived: []const treekem.PathSecretEntry) !void {
            for (derived) |e| {
                // Replace in place if we already hold this node.
                for (self.my_path_secrets.items) |*existing| {
                    if (existing.node == e.node) {
                        existing.path_secret = e.path_secret;
                        break;
                    }
                } else try self.my_path_secrets.append(arena, e);
            }
            var i: usize = 0;
            while (i < self.my_path_secrets.items.len) {
                const e = self.my_path_secrets.items[i];
                if (self.pathSecretStillValid(e)) {
                    i += 1;
                } else {
                    _ = self.my_path_secrets.swapRemove(i);
                }
            }
        }

        fn pathSecretStillValid(self: *const Self, e: treekem.PathSecretEntry) bool {
            if (e.node >= self.ratchet_tree.nodes.len) return false;
            if (e.path_secret.len != S.Nh) return false;
            const node = self.ratchet_tree.nodes[e.node] orelse return false;
            const pub_key = switch (node) {
                .parent => |p| p.encryption_key,
                .leaf => |l| l.encryption_key,
            };
            const node_secret = crypto.DeriveSecret(S, e.path_secret[0..S.Nh].*, "node") catch return false;
            const kp = S.Kem.deriveKeyPair(&node_secret);
            return std.mem.eql(u8, pub_key, &kp.public_key);
        }
    };
}

// ── free functions shared by the two entry points ─────────────────────────

/// The signature key of a leaf, by leaf index — the lookup §6.1's signature
/// check and §12.4.3's `GroupInfo.signer` both need and neither can do on
/// its own.
fn leafSignatureKey(t: *const tree.RatchetTree, leaf_index: u32) !std.crypto.sign.Ed25519.PublicKey {
    const idx = @as(usize, leaf_index) * 2;
    if (idx >= t.nodes.len) return error.UnknownMember;
    const node = t.nodes[idx] orelse return error.UnknownMember;
    const leaf = switch (node) {
        .leaf => |l| l,
        .parent => return error.Malformed,
    };
    if (leaf.signature_key.len != 32) return error.WrongKeyLength;
    return std.crypto.sign.Ed25519.PublicKey.fromBytes(leaf.signature_key[0..32].*);
}

/// RFC 9420 §7.3's `LeafNodeTBS` signature check, with the `group_id`/
/// `leaf_index` binding that `update`/`commit`-sourced leaves carry and
/// `key_package`-sourced ones do not.
fn verifyLeafSignature(
    comptime S: type,
    gpa: std.mem.Allocator,
    leaf: tree.LeafNode,
    expect_source: tree.LeafNodeSource,
    group_id: ?[]const u8,
    leaf_index: ?u32,
) !void {
    if (leaf.leaf_node_source != expect_source) return error.Malformed;
    // `LeafNodeTBS` covers `group_id`/`leaf_index` only for `update`- and
    // `commit`-sourced leaves (RFC 9420 §7.2); for a `key_package` leaf the
    // two arguments are ignored, which is why they are optional here and
    // why passing the wrong ones for a KeyPackage cannot mask a bad
    // signature.
    try leaf.verifySignature(S, gpa, group_id orelse "", leaf_index orelse 0);
}

/// `tree.LeafNode` has `encodedLen`/`encode` but no allocating helper of
/// its own; `findOwnLeaf` needs one to compare leaves by their wire bytes.
fn leafNodeEncodeAlloc(allocator: std.mem.Allocator, leaf: tree.LeafNode) ![]u8 {
    const buf = try allocator.alloc(u8, leaf.encodedLen());
    errdefer allocator.free(buf);
    var w = codec.Writer.init(buf);
    try leaf.encode(&w);
    std.debug.assert(w.finish().len == buf.len);
    return buf;
}

/// §12.4.2: "Verify that none of the public keys in the UpdatePath appear in
/// any node of the new ratchet tree." Checked against the tree as it stands
/// AFTER the proposals and BEFORE the merge — afterwards the UpdatePath's
/// own keys are in it by construction and the check would always fail.
fn rejectReusedPathKeys(t: *const tree.RatchetTree, path: treekem.UpdatePath) !void {
    for (t.nodes) |maybe| {
        const node = maybe orelse continue;
        const key = switch (node) {
            .leaf => |l| l.encryption_key,
            .parent => |p| p.encryption_key,
        };
        if (std.mem.eql(u8, key, path.leaf_node.encryption_key)) return error.InvalidUpdatePath;
        for (path.nodes) |n| {
            if (std.mem.eql(u8, key, n.encryption_key)) return error.InvalidUpdatePath;
        }
    }
}

/// The lowest node that is an ancestor of both leaves — §12.4.3.1's "the
/// lowest node contained in the direct paths of both the committer and the
/// new member", which is where a `GroupSecrets.path_secret` belongs.
fn commonAncestor(t: *const tree.RatchetTree, a: usize, b: usize) !usize {
    const n = t.nLeaves();
    var buf_a: [treemath.max_path_len]usize = undefined;
    var buf_b: [treemath.max_path_len]usize = undefined;
    const pa = try treemath.direct_path(a * 2, n, &buf_a);
    const pb = try treemath.direct_path(b * 2, n, &buf_b);
    for (pa) |x| {
        for (pb) |y| if (x == y) return x;
    }
    return error.Malformed;
}

/// §7.4's chain: given `path_secret` at `start` (a node on `leaf`'s direct
/// path), derive the secret for every node from `start` up to the root and
/// record them all — the joiner's private state after a Welcome.
fn derivePathSecretsUp(
    comptime S: type,
    arena: std.mem.Allocator,
    t: *const tree.RatchetTree,
    leaf: usize,
    start: usize,
    path_secret: []const u8,
    out: *std.ArrayList(treekem.PathSecretEntry),
) !void {
    var buf: [treemath.max_path_len]usize = undefined;
    const dp = try treemath.direct_path(leaf * 2, t.nLeaves(), &buf);
    var secret: [S.Nh]u8 = undefined;
    @memcpy(&secret, path_secret);
    var seen_start = false;
    for (dp) |node| {
        if (!seen_start) {
            if (node != start) continue;
            seen_start = true;
        } else {
            secret = try crypto.DeriveSecret(S, secret, "path");
        }
        try out.append(arena, .{ .node = node, .path_secret = try arena.dupe(u8, &secret) });
    }
    if (!seen_start) return error.Malformed;
}

/// The joiner's own leaf: §12.4.3.1's "identify the leaf in the tree whose
/// LeafNode is identical to the one in the KeyPackage". Compared by ENCODED
/// bytes — a field-by-field comparison would have to be extended every time
/// `LeafNode` grows a field, and would silently match on the day it is not.
fn findOwnLeaf(gpa: std.mem.Allocator, t: *const tree.RatchetTree, want_encoded: []const u8) !usize {
    var leaf: usize = 0;
    while (leaf * 2 < t.nodes.len) : (leaf += 1) {
        const node = t.nodes[leaf * 2] orelse continue;
        const l = switch (node) {
            .leaf => |x| x,
            .parent => continue,
        };
        const bytes = try leafNodeEncodeAlloc(gpa, l);
        defer gpa.free(bytes);
        if (std.mem.eql(u8, bytes, want_encoded)) return leaf;
    }
    return error.OwnLeafNotFound;
}

/// Re-decode a `LeafNode` through `arena` so the tree owns its lists. The
/// byte fields still alias whatever buffer the caller decoded from, which
/// is why `processCommit` copies every message it retains into the arena
/// first.
fn dupLeafNode(arena: std.mem.Allocator, leaf: tree.LeafNode) !tree.LeafNode {
    var out = leaf;
    out.extensions = try arena.dupe(tree.Extension, leaf.extensions);
    out.capabilities = .{
        .versions = try arena.dupe(u16, leaf.capabilities.versions),
        .cipher_suites = try arena.dupe(u16, leaf.capabilities.cipher_suites),
        .extensions = try arena.dupe(u16, leaf.capabilities.extensions),
        .proposals = try arena.dupe(u16, leaf.capabilities.proposals),
        .credentials = try arena.dupe(u16, leaf.capabilities.credentials),
    };
    out.credential = switch (leaf.credential) {
        // `basic` is a bare byte slice aliasing the arena copy already —
        // only `x509`'s LIST is an allocation `tree.Credential.deinit`
        // would free.
        .basic => |b| .{ .basic = b },
        .x509 => |certs| .{ .x509 = try arena.dupe([]const u8, certs) },
    };
    return out;
}

// ── tests ─────────────────────────────────────────────────────────────
//
// The real anchor for this file is `kat_passive_test.zig`, which replays
// recorded sessions from the official vectors. These are the unit-level
// checks for the pieces that file cannot isolate.

const testing = std.testing;
const TestSuite = suite.default;

test "commonAncestor: the lowest node on both direct paths, and it is symmetric" {
    var nodes: [15]?tree.Node = @splat(null);
    const t: tree.RatchetTree = .{ .allocator = testing.allocator, .nodes = &nodes };
    // 8 leaves: leaves 0 and 1 meet at node 1; 0 and 2 at node 3; 0 and 4
    // at the root, node 7.
    try testing.expectEqual(@as(usize, 1), try commonAncestor(&t, 0, 1));
    try testing.expectEqual(@as(usize, 3), try commonAncestor(&t, 0, 2));
    try testing.expectEqual(@as(usize, 7), try commonAncestor(&t, 0, 4));
    try testing.expectEqual(try commonAncestor(&t, 4, 0), try commonAncestor(&t, 0, 4));
}

test "Group(default): every public declaration type-checks" {
    // `Group` is a generic type constructor, so Zig analyses its bodies
    // only where they are REFERENCED. Without this the whole state machine
    // could be dead code and the suite would still pass — referencing each
    // declaration forces semantic analysis of all of it.
    const G = Group(TestSuite);
    inline for (@typeInfo(G).@"struct".decls) |d| _ = &@field(G, d.name);
}

test "Policy: both application-defined §12.2 rules default to ON" {
    const p: Policy = .{};
    try testing.expect(p.reject_duplicate_add_signature_keys);
    try testing.expect(p.reject_add_of_existing_signature_key);
}
