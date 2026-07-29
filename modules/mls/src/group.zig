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
    /// §7.3: a `LeafNode` broke one of the rules this object owns (see the
    /// "the §7.3 rules this object CAN own" section) — today, an extension
    /// its own `capabilities` do not list.
    LeafNodeInvalid,
    /// §7.3/§12.4.3.1: two nodes of the ratchet tree carry the same
    /// `encryption_key`, or two leaves the same `signature_key`.
    DuplicateKeyInTree,
    /// `createCommit`: the caller asked for a Commit that adds a member
    /// whose `KeyPackage` names a different cipher suite or protocol
    /// version than the group's.
    KeyPackageMismatch,
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
    /// §7.3: "Verify that the extensions in the LeafNode are supported by
    /// checking that the ID for each extension in the extensions field is
    /// listed in the capabilities.extensions field of the LeafNode." One of
    /// the two §7.3 rules that need nothing but the leaf itself — see this
    /// file's doc comment on where the §7.3/§10.1 boundary falls.
    check_leaf_extensions_supported: bool = true,
    /// §7.3: "Verify that the following fields are unique among the members
    /// of the group: signature_key, encryption_key", plus §12.4.3.1's
    /// "Verify that the encryption key in the parent node does not appear in
    /// any other node of the tree". Checked over the WHOLE tree after every
    /// epoch transition, which is the only place the property is even
    /// expressible. The other §7.3 rules are not here — see this file's doc
    /// comment.
    check_key_uniqueness: bool = true,
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
        /// How much of `confirmed_transcript_hash` is live. `digest_length`
        /// everywhere except epoch 0, where RFC 9420 §8.2 defines
        /// `confirmed_transcript_hash_[0]` as the ZERO-LENGTH octet string
        /// — not a zero-filled digest. A fixed-width field cannot express
        /// that difference, and it is not cosmetic: the value is encoded
        /// into the `GroupContext` as an `opaque<V>`, so a group created
        /// with 32 zero bytes here derives a completely different epoch 0
        /// from one created per the RFC.
        confirmed_len: usize = S.Hash.digest_length,
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

        /// Private keys for Update proposals THIS member has published but
        /// that no Commit has applied yet (§12.1: a proposal "should be
        /// cached ... [to] be retrieved ... in a later Commit message", and
        /// it may never be committed at all).
        ///
        /// **Why the group has to hold these.** §12.3 applies an Update
        /// BEFORE the Commit's `UpdatePath` is decrypted, so by the time
        /// `processUpdatePath` runs, this member's leaf in the tree already
        /// carries the Update's NEW `encryption_key` — and the committer
        /// sealed a ciphertext to exactly that key. A member still holding
        /// its old private key cannot open it, and the failure is a bare
        /// AEAD rejection several layers down with nothing pointing at the
        /// cause. Matching by public key rather than by `ProposalRef` means
        /// it works whether the Update was committed by value or by
        /// reference, and whether or not this member is the committer.
        pending_updates: std.ArrayList(PendingUpdate),

        pub const PendingUpdate = struct {
            /// Arena-owned; compared against the leaf the Commit installs.
            encryption_key: []const u8,
            encryption_priv: [S.Kem.Nsk]u8,
        };

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
                .confirmed_transcript_hash = self.confirmed_transcript_hash[0..self.confirmed_len],
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

        // ── §11: creating a group ─────────────────────────────────────────

        /// Everything `create` needs. Byte slices are borrowed for the
        /// duration of the call; whatever the group retains is copied into
        /// its own arena.
        pub const CreateParams = struct {
            /// Source of the one random value §11 calls for. See `create`'s
            /// doc comment for exactly which value it is and why.
            io: std.Io,
            /// §11: "Group ID: A value set by the creator." §11 recommends a
            /// fresh random value of size KDF.Nh; picking it is the
            /// application's, because uniqueness is scoped to the Delivery
            /// Service, not to this object.
            group_id: []const u8,
            /// This client's own whole `MLSMessage(KeyPackage)`. Its
            /// `leaf_node` becomes the group's single leaf (§11: "a leaf
            /// node containing an HPKE public key and credential for the
            /// creator"), which is also what makes the creator's leaf indis-
            /// tinguishable from any other member's.
            key_package_msg: []const u8,
            /// Private half of that KeyPackage's LeafNode `encryption_key`.
            encryption_priv: [S.Kem.Nsk]u8,
            /// §8.1 GroupContext extensions for epoch 0 (§11: "Extensions:
            /// Any values of the creator's choosing").
            extensions: []const tree.Extension = &.{},
            policy: Policy = .{},
        };

        /// RFC 9420 §11's group-creation procedure: a one-member group at
        /// epoch 0, with a fully initialized key schedule and transcript
        /// hashes, ready to have `createCommit` called on it.
        ///
        /// **Where the randomness goes, and the one deviation from §11's
        /// literal text.** §11 lists "Epoch secret: A fresh random value of
        /// size KDF.Nh". This draws a fresh random `init_secret_[-1]`
        /// instead and runs §8's normal chain over it with a zero
        /// `commit_secret` and a zero `psk_secret`. The resulting
        /// `epoch_secret` is `ExpandWithLabel` of an Extract of a uniformly
        /// random value — uniformly random and unknown to anyone else,
        /// exactly what §11 asks for. What it additionally gets is a DEFINED
        /// `joiner_secret` and `welcome_secret`: §8 derives both above
        /// `epoch_secret`, so a literally-random `epoch_secret` leaves them
        /// undefined, and `EpochSecrets(S)` would have two fields nothing
        /// could fill. Nothing outside this object can tell the difference —
        /// epoch 0 has one member, and every later epoch is reached through
        /// a Commit.
        ///
        /// §8.2's `confirmed_transcript_hash_[0]` is the ZERO-LENGTH string,
        /// not a zero-filled digest; see the `confirmed_len` field.
        pub fn create(gpa: std.mem.Allocator, params: CreateParams) !Self {
            const arena_ptr = try gpa.create(std.heap.ArenaAllocator);
            errdefer gpa.destroy(arena_ptr);
            arena_ptr.* = .init(gpa);
            errdefer arena_ptr.deinit();
            const arena = arena_ptr.allocator();

            // The tree keeps this leaf, so decode it from an arena-owned copy.
            const kp_copy = try arena.dupe(u8, params.key_package_msg);
            var kp_reader = codec.Reader.init(kp_copy);
            const kp_msg = try framing.MLSMessage.decode(arena, &kp_reader);
            if (!kp_reader.atEnd()) return error.Malformed;
            if (kp_msg != .key_package) return error.Malformed;
            const my_kp = kp_msg.key_package;
            if (my_kp.cipher_suite != S.id) return error.CipherSuiteMismatch;
            // §10: a KeyPackage is self-signed, and so is the LeafNode
            // inside it. Both are checked, because a group whose own
            // creator's leaf does not verify is one every joiner rejects.
            try my_kp.verifySignature(S, gpa);
            try verifyLeafSignature(S, gpa, my_kp.leaf_node, .key_package, null, null);

            const enc_kp = try S.Kem.KeyPair.generateDeterministic(params.encryption_priv);
            if (!std.mem.eql(u8, my_kp.leaf_node.encryption_key, &enc_kp.public_key)) return error.PrivateKeyMismatch;

            const nodes = try arena.alloc(?tree.Node, 1);
            nodes[0] = .{ .leaf = my_kp.leaf_node };
            var rt: tree.RatchetTree = .{ .allocator = arena, .nodes = nodes };

            const tree_hash = try treehash.rootHash(S, gpa, &rt);
            const gc: keyschedule.GroupContext = .{
                .cipher_suite = S.id,
                .group_id = try arena.dupe(u8, params.group_id),
                .epoch = 0,
                .tree_hash = &tree_hash,
                .confirmed_transcript_hash = transcript.empty_transcript_hash,
                .extensions = params.extensions,
            };
            const gc_bytes = try gc.encodeAlloc(gpa);
            defer gpa.free(gc_bytes);

            var init_secret: [S.Nh]u8 = undefined;
            params.io.random(&init_secret);
            const secrets = try keyschedule.deriveEpoch(
                S,
                gpa,
                init_secret,
                keyschedule.zeroSecret(S),
                keyschedule.zeroSecret(S),
                gc_bytes,
            );
            init_secret = @splat(0);

            // §11: "Compute a confirmation_tag over the empty
            // confirmed_transcript_hash ... Compute the updated
            // interim_transcript_hash".
            const tag = keyschedule.confirmationTag(S, secrets.confirmation_key, transcript.empty_transcript_hash);
            const interim = try transcript.interimTranscriptHash(S, transcript.empty_transcript_hash, &tag);

            var self: Self = .{
                .gpa = gpa,
                .arena = arena_ptr,
                .policy = params.policy,
                .group_id = gc.group_id,
                .epoch = 0,
                .tree_hash = tree_hash,
                .confirmed_transcript_hash = @splat(0),
                .confirmed_len = 0,
                .extensions = params.extensions,
                .interim_transcript_hash = interim,
                .ratchet_tree = rt,
                .secrets = secrets,
                .my_leaf_index = 0,
                .my_encryption_priv = params.encryption_priv,
                .my_path_secrets = .empty,
                .resumption_history = .empty,
                .pending_updates = .empty,
            };
            // `extensions` is the caller's, and its `extension_data` slices
            // point at caller memory the group outlives — so this is a DEEP
            // copy, not a `dupe` of the list alone.
            self.extensions = try dupExtensions(arena, params.extensions);
            try self.resumption_history.append(arena, .{ .epoch = 0, .secret = secrets.resumption_psk });

            // Same self-check `fromWelcome` runs: a re-encoded GroupContext
            // must equal the bytes the key schedule just consumed, or every
            // later epoch silently diverges from this one.
            {
                const re = try self.groupContextAlloc(gpa);
                defer gpa.free(re);
                if (!std.mem.eql(u8, gc_bytes, re)) return error.Malformed;
            }
            return self;
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
                .pending_updates = .empty,
            };
            if (group_info.group_context.tree_hash.len != S.Hash.digest_length) return error.Malformed;
            // §8.2 allows exactly two widths here: a digest, or the
            // zero-length string of epoch 0 (a `GroupInfo` for a group that
            // has not been committed to yet — publishable for an external
            // join, per §11's closing paragraph).
            const conf = group_info.group_context.confirmed_transcript_hash;
            if (conf.len != S.Hash.digest_length and conf.len != 0) return error.Malformed;
            self.confirmed_len = conf.len;
            @memcpy(&self.tree_hash, group_info.group_context.tree_hash);
            @memcpy(self.confirmed_transcript_hash[0..conf.len], conf);
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

            // Bullets 5-6 (§12.3): apply the proposals, in §12.3's order,
            // and resolve the PSKs they name.
            var applied = try self.applyProposals(arena, gpa, resolved, params.external_psks);
            defer applied.deinit(gpa);
            const new_extensions = applied.extensions;
            const psk_secret = applied.psk_secret;

            // Bullet 7: path presence.
            if (applied.needs_path and commit.path == null) return error.PathRequired;

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

                try treekem.applyUpdatePath(arena, &self.ratchet_tree, committer, path);

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
                    .confirmed_transcript_hash = self.confirmed_transcript_hash[0..self.confirmed_len],
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
                    applied.added_leaves,
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

            // §12.2's closing rule: "After processing the Commit the ratchet
            // tree is invalid ... if it contains any leaf node that is
            // invalid according to Section 7.3." The per-leaf half ran as
            // each leaf was installed; this is the half that only the
            // finished tree can answer.
            try self.checkKeyUniqueness();

            // Bullet 13: adopt.
            self.epoch += 1;
            self.tree_hash = new_tree_hash;
            self.confirmed_transcript_hash = hashes.confirmed;
            self.interim_transcript_hash = hashes.interim;
            self.extensions = new_extensions;
            self.secrets = secrets;
            // Pending Updates are epoch-scoped: §12.1 binds a proposal to
            // the epoch it was sent in, so any that this Commit did not
            // apply can never be applied and their private keys are dead.
            self.pending_updates.clearRetainingCapacity();
            try self.adoptPathSecrets(arena, derived);
            try self.resumption_history.append(arena, .{ .epoch = self.epoch, .secret = secrets.resumption_psk });
            self.poisoned = false;
        }

        // ── §12.1: creating a proposal ────────────────────────────────────

        /// Everything `createProposal` needs beyond the proposal itself.
        pub const ProposeParams = struct {
            /// This member's signing key — `Group` holds no private
            /// signature key. That is deliberate: a signature key outlives
            /// any one group (a client uses it across all of them), so its
            /// storage and its lifetime are the application's, and this
            /// object borrows it per call rather than keeping a copy alive
            /// for the length of a session.
            signature_key_pair: S.Sig.KeyPair,
            proposal: content.Proposal,
            authenticated_data: []const u8 = &.{},
        };

        /// RFC 9420 §12.1: frame a `Proposal` as a signed, MAC'd
        /// `PublicMessage` from this member, in this epoch. Returns the
        /// whole `MLSMessage` wire bytes (caller frees).
        ///
        /// The group is NOT advanced and nothing is applied: §12.1 says a
        /// received proposal "should be cached in such a way that it can be
        /// retrieved by hash (as a ProposalOrRef object) in a later Commit
        /// message", and it is the Commit that changes the group. Keep the
        /// returned bytes; they are what a later `createCommit`'s
        /// `.by_reference` arm and a receiver's `CommitParams.proposal_msgs`
        /// both take.
        pub fn createProposal(self: *const Self, allocator: std.mem.Allocator, params: ProposeParams) ![]u8 {
            try self.check();
            const gpa = self.gpa;
            const gc = try self.groupContextAlloc(gpa);
            defer gpa.free(gc);

            const fc: framing.FramedContent = .{
                .group_id = self.group_id,
                .epoch = self.epoch,
                .sender = .{ .member = self.my_leaf_index },
                .authenticated_data = params.authenticated_data,
                .body = .{ .proposal = params.proposal },
            };
            const sig = try framing.signFramedContent(S, gpa, params.signature_key_pair, .mls_public_message, fc, gc);
            const sig_bytes = sig.toBytes();
            const auth: framing.FramedContentAuthData = .{ .signature = &sig_bytes };
            const mtag = try framing.membershipTag(S, gpa, self.secrets.membership_key, fc, auth, gc);
            const msg: framing.MLSMessage = .{
                .public_message = .{ .content = fc, .auth = auth, .membership_tag = &mtag },
            };
            return msg.encodeAlloc(allocator);
        }

        /// What `updateLeaf` needs to build the `LeafNode` an Update
        /// proposal (§12.1.2) carries.
        pub const UpdateLeafParams = struct {
            signature_key_pair: S.Sig.KeyPair,
            /// The FRESH ratchet-tree key pair this member is rotating to.
            /// §7.3: an Update's `encryption_key` MUST differ from the one
            /// it replaces, and that is checked here rather than left to
            /// the receiver, since a sender that gets it wrong has
            /// published a proposal nobody can commit. The PRIVATE half is
            /// retained (see `pending_updates`), because the member needs
            /// it the moment some Commit applies this Update — which may
            /// be a Commit made by somebody else.
            encryption_key_pair: S.Kem.KeyPair,
        };

        /// RFC 9420 §12.1.2 + §7.2: build and sign the `LeafNode` for an
        /// Update proposal from this member. `leaf_node_source = update`, so
        /// the `LeafNodeTBS` binds `group_id` and this member's leaf index —
        /// which is precisely why this is a method on the group and not a
        /// free constructor.
        ///
        /// The credential, capabilities and extensions are carried over from
        /// this member's current leaf unchanged (the identity content is not
        /// what an Update rotates). Every allocation is made in the group's
        /// own arena, so the returned leaf stays valid for as long as the
        /// group does and needs no `deinit`.
        pub fn updateLeaf(self: *Self, params: UpdateLeafParams) !tree.LeafNode {
            try self.check();
            const arena = self.arena.allocator();
            const current = try self.ownLeaf();
            const new_pub = params.encryption_key_pair.public_key;
            if (std.mem.eql(u8, current.encryption_key, &new_pub)) return error.LeafNodeInvalid;

            var leaf = try dupLeafNode(arena, current);
            leaf.encryption_key = try arena.dupe(u8, &new_pub);
            leaf.leaf_node_source = .update;
            leaf.lifetime = null;
            leaf.parent_hash = null;
            leaf.signature = &.{};
            const sig = try leaf.sign(S, arena, params.signature_key_pair, self.group_id, self.my_leaf_index);
            leaf.signature = try arena.dupe(u8, &sig.toBytes());
            try self.checkLeafSelfConsistent(leaf);
            try self.pending_updates.append(arena, .{
                .encryption_key = leaf.encryption_key,
                .encryption_priv = params.encryption_key_pair.secret_key,
            });
            return leaf;
        }

        fn ownLeaf(self: *const Self) !tree.LeafNode {
            const node = self.ratchet_tree.nodes[self.my_leaf_index * 2] orelse return error.UnknownMember;
            return switch (node) {
                .leaf => |l| l,
                .parent => error.Malformed,
            };
        }

        // ── §12.4.1: creating a Commit ────────────────────────────────────

        /// How one proposal enters a Commit (RFC 9420 §12.4: "Commits that
        /// refer to new Proposals from the committer can be included by
        /// value. Commits for previously sent proposals from anyone
        /// (including the committer) can be sent by reference").
        pub const CommitSource = union(enum) {
            /// A proposal the committer introduces inline. Its bytes are
            /// copied into the group's arena before anything reads them, so
            /// the caller may free them as soon as `createCommit` returns.
            by_value: content.Proposal,
            /// The whole `MLSMessage` of a proposal received during the
            /// current epoch — what `createProposal` returned on the sender's
            /// side. It is re-authenticated here (§12.2 requires the
            /// committer to validate, not just the receivers) and named in
            /// the Commit by its §5.2 `ProposalRef`.
            by_reference: []const u8,
        };

        pub const CreateCommitParams = struct {
            /// Draws §7.4's `path_secret[0]`, the fresh leaf key pair, and
            /// the HPKE ephemerals for every ciphertext.
            io: std.Io,
            signature_key_pair: S.Sig.KeyPair,
            /// The proposal list, IN THE ORDER it will appear in the Commit.
            /// The order is the committer's to choose and it is observable:
            /// §12.1.1 places Adds at successive blank leaves "in the order
            /// they appear in the list", and §8.4's PSK chain is
            /// position-dependent. §12.3's APPLICATION order is fixed and
            /// unrelated — see `applyProposals`.
            proposals: []const CommitSource = &.{},
            external_psks: []const ExternalPsk = &.{},
            authenticated_data: []const u8 = &.{},
            /// §12.4: "The path field MAY be omitted if (a) it covers at
            /// least one proposal and (b) none of the proposals covered by
            /// the Commit are of 'path required' types." Default `false`,
            /// i.e. always populate — that is §12.4's own default ("By
            /// default, the path field of a Commit MUST be populated"), and
            /// it is the setting that provides post-compromise security for
            /// the committer. Setting it `true` asks for the path to be
            /// omitted WHEN ALLOWED; when the list requires one it is
            /// populated regardless.
            omit_path_when_allowed: bool = false,
            /// §12.4.3.3: carry the whole ratchet tree in the `GroupInfo`.
            /// Required unless the application has an out-of-band way to
            /// give joiners the tree, because a `Welcome` without it is
            /// unusable on its own.
            include_ratchet_tree: bool = true,
            /// §12.4.3.2: publish `external_pub` in the `GroupInfo`, which
            /// is what makes that `GroupInfo` usable for an external join.
            include_external_pub: bool = false,
            /// Further `GroupInfo` extensions (§12.4.3: "additional data
            /// that might be useful to new joiners"). Borrowed for the call.
            group_info_extensions: []const tree.Extension = &.{},
        };

        /// The three messages one Commit produces. All three are allocated
        /// from the allocator passed to `createCommit`.
        pub const Created = struct {
            /// `MLSMessage(PublicMessage)` carrying the Commit — send to
            /// every existing member.
            commit: []u8,
            /// `MLSMessage(Welcome)` covering every member this Commit
            /// added, or `null` when it added none. §12.4.3.1 lets a
            /// committer split new members across several Welcomes; this
            /// produces exactly one, which satisfies that section's only
            /// MUST ("the set of Welcome messages produced in this step MUST
            /// cover every new member added in the Commit").
            welcome: ?[]u8,
            /// `MLSMessage(GroupInfo)` for the NEW epoch, unencrypted —
            /// §17.2's `mls_group_info` wire format, what a Delivery Service
            /// caches to enable external joins (§12.4.3.2). The same
            /// `GroupInfo` the `Welcome` carries encrypted.
            group_info: []u8,

            pub fn deinit(self: Created, allocator: std.mem.Allocator) void {
                allocator.free(self.commit);
                if (self.welcome) |w| allocator.free(w);
                allocator.free(self.group_info);
            }
        };

        /// RFC 9420 §12.4.1, bullet by bullet — the sender's mirror of
        /// `processCommit`, and the last thing standing between this module
        /// and a two-way client.
        ///
        /// On success the group has advanced one epoch: a committer applies
        /// its own Commit, and the whole point is that it lands in the state
        /// its receivers will land in. On failure the object is poisoned,
        /// exactly as `processCommit` documents.
        ///
        /// **Three orderings inside are load-bearing, and two of them are
        /// the same ones §12.4.2 gets wrong-able:**
        ///
        ///   1. The `FramedContent` is signed under the OLD `GroupContext`,
        ///      while the key schedule consumes the NEW one.
        ///   2. The `UpdatePath` ciphertexts are sealed under the
        ///      PROVISIONAL context — new epoch, new tree hash, OLD
        ///      confirmed transcript hash — which is why generating a path
        ///      is two calls (`treekem.stageUpdatePath` then
        ///      `sealUpdatePath`) and not one: the tree hash the context
        ///      needs does not exist until the tree has been updated.
        ///   3. The `confirmation_tag` is computed AFTER the signature,
        ///      because the confirmed transcript hash covers the signature;
        ///      and the `membership_tag` is computed after BOTH, because
        ///      §6.2's `AuthenticatedContentTBM` covers the whole
        ///      `FramedContentAuthData` including the tag.
        pub fn createCommit(self: *Self, allocator: std.mem.Allocator, params: CreateCommitParams) !Created {
            try self.check();
            const arena = self.arena.allocator();
            const gpa = self.gpa;

            const old_gc = try self.groupContextAlloc(gpa);
            defer gpa.free(old_gc);

            // ── §12.4.1 bullets 1-2: the proposal list, resolved into the
            // arena, authenticated, and §12.2-validated BEFORE anything is
            // touched.
            const por = try gpa.alloc(content.ProposalOrRef, params.proposals.len);
            defer gpa.free(por);
            const resolved = try gpa.alloc(Resolved, params.proposals.len);
            defer gpa.free(resolved);
            for (params.proposals, por, resolved) |src, *ref_slot, *res_slot| switch (src) {
                .by_value => |p| {
                    const owned = try arenaCopyProposal(arena, p);
                    ref_slot.* = .{ .proposal = owned };
                    res_slot.* = .{ .proposal = owned, .sender = null, .by_reference = false };
                },
                .by_reference => |bytes| {
                    const c = try self.authenticateProposalMessage(arena, gpa, bytes, old_gc);
                    ref_slot.* = .{ .reference = try arena.dupe(u8, &c.ref) };
                    res_slot.* = .{ .proposal = c.proposal, .sender = c.sender, .by_reference = true };
                },
            };
            try self.validateProposalList(gpa, resolved, self.my_leaf_index);
            for (resolved) |rp| {
                if (rp.proposal == .add) {
                    const kp = rp.proposal.add;
                    if (kp.cipher_suite != S.id or kp.version != .mls10) return error.KeyPackageMismatch;
                    try kp.verifySignature(S, gpa);
                }
            }

            // From here on the tree is mutated; any failure poisons.
            self.poisoned = true;

            // ── §12.4.1 bullet 3 (§12.3): apply the proposals.
            var applied = try self.applyProposals(arena, gpa, resolved, params.external_psks);
            defer applied.deinit(gpa);

            // ── §12.4.1 bullets 4-5: the path.
            //
            // The committer's leaf content is duplicated into the arena
            // FIRST: `stageUpdatePath` blanks the sender's slot before it
            // builds the replacement, which frees the list containers the
            // old leaf owned — reading them afterwards would be a
            // use-after-free the DebugAllocator catches only if a test
            // happens to look at them.
            const base_leaf = try dupLeafNode(arena, try self.ownLeaf());

            var commit: content.Commit = .{ .proposals = por, .path = null };
            var commit_secret = keyschedule.zeroSecret(S);
            var staged: ?treekem.Staged(S) = null;
            var new_leaf_priv = self.my_encryption_priv;

            const want_path = applied.needs_path or !params.omit_path_when_allowed;
            if (want_path) {
                var path_secret_0: [S.Nh]u8 = undefined;
                params.io.random(&path_secret_0);
                const leaf_kp = S.Kem.generateKeyPair(params.io);

                const st = try treekem.stageUpdatePath(S, arena, &self.ratchet_tree, self.my_leaf_index, .{
                    .group_id = self.group_id,
                    .signature_key_pair = params.signature_key_pair,
                    .leaf_key_pair = leaf_kp,
                    .path_secret_0 = path_secret_0,
                    .signature_key = base_leaf.signature_key,
                    .credential = base_leaf.credential,
                    .capabilities = base_leaf.capabilities,
                    .extensions = base_leaf.extensions,
                });
                path_secret_0 = @splat(0);
                staged = st;
                commit_secret = st.commit_secret;
                new_leaf_priv = leaf_kp.secret_key;

                // The PROVISIONAL GroupContext — new epoch, new tree hash
                // (AFTER the proposals and AFTER the merge), OLD confirmed
                // transcript hash. Identical to the one `processCommit`
                // rebuilds; if the two ever disagreed, every receiver would
                // fail to open the ciphertexts sealed here.
                const merged_tree_hash = try treehash.rootHash(S, gpa, &self.ratchet_tree);
                const provisional: keyschedule.GroupContext = .{
                    .cipher_suite = S.id,
                    .group_id = self.group_id,
                    .epoch = self.epoch + 1,
                    .tree_hash = &merged_tree_hash,
                    .confirmed_transcript_hash = self.confirmed_transcript_hash[0..self.confirmed_len],
                    .extensions = applied.extensions,
                };
                const provisional_bytes = try provisional.encodeAlloc(gpa);
                defer gpa.free(provisional_bytes);

                commit.path = try treekem.sealUpdatePath(
                    S,
                    gpa,
                    params.io,
                    &self.ratchet_tree,
                    st,
                    provisional_bytes,
                    applied.added_leaves,
                );
            }
            defer if (commit.path) |p| p.deinitSealed(gpa);

            // ── §12.4.1: the FramedContent, signed under the OLD context.
            const fc: framing.FramedContent = .{
                .group_id = self.group_id,
                .epoch = self.epoch,
                .sender = .{ .member = self.my_leaf_index },
                .authenticated_data = params.authenticated_data,
                .body = .{ .commit = commit },
            };
            const sig = try framing.signFramedContent(S, gpa, params.signature_key_pair, .mls_public_message, fc, old_gc);
            const sig_bytes = sig.toBytes();

            // §8.2's confirmed hash covers `wire_format || content ||
            // signature` and NOT the confirmation tag — which is what makes
            // this order possible at all: the tag is derived from a key
            // schedule that consumes a GroupContext containing this hash.
            var ac: framing.AuthenticatedContent = .{
                .wire_format = .mls_public_message,
                .content = fc,
                .auth = .{ .signature = &sig_bytes, .confirmation_tag = null },
            };
            const confirmed = try transcript.confirmedTranscriptHash(S, gpa, &self.interim_transcript_hash, ac);

            const new_tree_hash = try treehash.rootHash(S, gpa, &self.ratchet_tree);
            const new_gc: keyschedule.GroupContext = .{
                .cipher_suite = S.id,
                .group_id = self.group_id,
                .epoch = self.epoch + 1,
                .tree_hash = &new_tree_hash,
                .confirmed_transcript_hash = &confirmed,
                .extensions = applied.extensions,
            };
            const new_gc_bytes = try new_gc.encodeAlloc(gpa);
            defer gpa.free(new_gc_bytes);

            const secrets = try keyschedule.deriveEpoch(
                S,
                gpa,
                self.secrets.init_secret,
                commit_secret,
                applied.psk_secret,
                new_gc_bytes,
            );
            const tag = keyschedule.confirmationTag(S, secrets.confirmation_key, &confirmed);
            ac.auth.confirmation_tag = &tag;
            const interim = try transcript.interimTranscriptHash(S, &confirmed, &tag);

            // ── §12.4.1: "Protect the AuthenticatedContent object using keys
            // from the old epoch ... compute the membership_tag value using
            // the membership_key."
            //
            // Built here rather than through `framing.protectPublic` for one
            // reason: `protectPublic` signs the content itself, and the
            // signature that went into the transcript above must be the
            // signature that goes on the wire. Ed25519 is deterministic so
            // the two would agree today, but "the transcript covers the
            // bytes we sent" should not rest on that.
            const mtag = try framing.membershipTag(S, gpa, self.secrets.membership_key, fc, ac.auth, old_gc);
            const commit_msg: framing.MLSMessage = .{
                .public_message = .{ .content = fc, .auth = ac.auth, .membership_tag = &mtag },
            };
            const commit_bytes = try commit_msg.encodeAlloc(allocator);
            errdefer allocator.free(commit_bytes);

            // ── §12.4.1: "Construct a GroupInfo reflecting the new state."
            var gi_exts: std.ArrayList(tree.Extension) = .empty;
            defer gi_exts.deinit(gpa);
            var tree_ext_bytes: ?[]u8 = null;
            defer if (tree_ext_bytes) |b| gpa.free(b);
            if (params.include_ratchet_tree) {
                tree_ext_bytes = try self.ratchet_tree.encode(gpa);
                try gi_exts.append(gpa, .{
                    .extension_type = welcome_mod.extension_type_ratchet_tree,
                    .extension_data = tree_ext_bytes.?,
                });
            }
            var ext_pub_buf: [1 + S.Kem.Npk]u8 = undefined;
            if (params.include_external_pub) {
                // §12.4.3.2's `ExternalPub` is a struct with one
                // `HPKEPublicKey` field, i.e. an `opaque<V>` — so the
                // extension body is length-prefixed, not a bare key.
                const ext_kp = keyschedule.externalKeyPair(S, secrets.external_secret);
                var w = codec.Writer.init(&ext_pub_buf);
                try w.writeVector(&ext_kp.public_key);
                try gi_exts.append(gpa, .{
                    .extension_type = welcome_mod.extension_type_external_pub,
                    .extension_data = w.finish(),
                });
            }
            try gi_exts.appendSlice(gpa, params.group_info_extensions);

            var gi: welcome_mod.GroupInfo = .{
                .group_context = new_gc,
                .extensions = gi_exts.items,
                .confirmation_tag = &tag,
                .signer = self.my_leaf_index,
                .signature = &.{},
            };
            const gi_sig = try gi.sign(S, gpa, params.signature_key_pair);
            const gi_sig_bytes = gi_sig.toBytes();
            gi.signature = &gi_sig_bytes;
            const gi_msg: framing.MLSMessage = .{ .group_info = gi };
            const group_info_bytes = try gi_msg.encodeAlloc(allocator);
            errdefer allocator.free(group_info_bytes);

            // ── §12.4.1: "For each new member in the group ..." — the
            // Welcome.
            const welcome_bytes = if (applied.added.len == 0) null else try self.buildWelcome(
                allocator,
                params.io,
                gi,
                secrets,
                applied,
                staged,
            );
            errdefer if (welcome_bytes) |w| allocator.free(w);

            try self.checkKeyUniqueness();

            // ── adopt. Same list as `processCommit`'s last bullet, plus the
            // two pieces only a committer holds: its new leaf private key
            // and a path secret for EVERY node of its filtered direct path
            // (a receiver only learns the ones at or above its overlap).
            var derived: []treekem.PathSecretEntry = &.{};
            if (staged) |st| {
                derived = try arena.alloc(treekem.PathSecretEntry, st.nodes.len);
                for (st.nodes, derived) |n, *slot| {
                    slot.* = .{ .node = n.node, .path_secret = try arena.dupe(u8, &n.path_secret) };
                }
            }
            self.epoch += 1;
            self.tree_hash = new_tree_hash;
            self.confirmed_transcript_hash = confirmed;
            self.confirmed_len = S.Hash.digest_length;
            self.interim_transcript_hash = interim;
            self.extensions = applied.extensions;
            self.secrets = secrets;
            self.my_encryption_priv = new_leaf_priv;
            // Pending Updates are epoch-scoped: §12.1 binds a proposal to
            // the epoch it was sent in, so any that this Commit did not
            // apply can never be applied and their private keys are dead.
            self.pending_updates.clearRetainingCapacity();
            try self.adoptPathSecrets(arena, derived);
            try self.resumption_history.append(arena, .{ .epoch = self.epoch, .secret = secrets.resumption_psk });
            self.poisoned = false;

            return .{ .commit = commit_bytes, .welcome = welcome_bytes, .group_info = group_info_bytes };
        }

        /// RFC 9420 §12.4.3.1's SEND direction: one `Welcome` covering every
        /// member the Commit added.
        ///
        /// The `GroupInfo` is encrypted once under the new epoch's
        /// `welcome_secret`; the `joiner_secret` is then encrypted per
        /// member under HPKE to that member's `KeyPackage.init_key`, with
        /// the whole `encrypted_group_info` as the `EncryptWithLabel`
        /// context — the binding that stops a Delivery Service from pairing
        /// one member's secrets with a different group's info.
        fn buildWelcome(
            self: *Self,
            allocator: std.mem.Allocator,
            io: std.Io,
            group_info: welcome_mod.GroupInfo,
            secrets: keyschedule.EpochSecrets(S),
            applied: Applied,
            staged: ?treekem.Staged(S),
        ) ![]u8 {
            const gpa = self.gpa;

            const gi_bytes = try group_info.encodeAlloc(gpa);
            defer gpa.free(gi_bytes);
            const egi = try welcome_mod.encryptGroupInfo(S, gpa, secrets.welcome_secret, gi_bytes);
            defer gpa.free(egi);

            const slots = try gpa.alloc(welcome_mod.EncryptedGroupSecrets, applied.added.len);
            defer {
                for (slots) |s| {
                    gpa.free(s.new_member);
                    gpa.free(s.encrypted_group_secrets.kem_output);
                    gpa.free(s.encrypted_group_secrets.ciphertext);
                }
                gpa.free(slots);
            }
            var built: usize = 0;
            errdefer {
                // Only the slots actually filled may be freed by the block
                // above; shrink the view so a mid-loop failure does not free
                // uninitialized pointers.
                for (slots[built..]) |*s| s.* = .{
                    .new_member = &.{},
                    .encrypted_group_secrets = .{ .kem_output = &.{}, .ciphertext = &.{} },
                };
            }

            for (applied.added, slots) |member, *slot| {
                // §12.4.1: "Identify the lowest common ancestor in the tree
                // of the new member's leaf node and the member sending the
                // Commit ... Compute the path secret corresponding to the
                // common ancestor node." See `Staged.pathSecretFor` for why
                // it is the lowest node OF THE PATH covering that leaf.
                const ps: ?[S.Nh]u8 = if (staged) |st| st.pathSecretFor(member.leaf_index) else null;
                const gs: welcome_mod.GroupSecrets = .{
                    .joiner_secret = &secrets.joiner_secret,
                    .path_secret = if (ps) |*p| p else null,
                    .psks = applied.psk_ids,
                };
                const gs_bytes = try gs.encodeAlloc(gpa);
                defer gpa.free(gs_bytes);

                const kp_bytes = try member.key_package.encodeAlloc(gpa);
                defer gpa.free(kp_bytes);
                const ref = try crypto.make_keypackage_ref(S, kp_bytes);
                if (member.key_package.init_key.len != S.Kem.Npk) return error.WrongKeyLength;
                const init_key: S.Kem.PublicKey = member.key_package.init_key[0..S.Kem.Npk].*;

                const ct = try welcome_mod.encryptGroupSecrets(S, gpa, io, init_key, egi, gs_bytes);
                slot.* = .{ .new_member = try gpa.dupe(u8, &ref), .encrypted_group_secrets = ct };
                built += 1;
            }

            const msg: framing.MLSMessage = .{ .welcome = .{
                .cipher_suite = S.id,
                .secrets = slots,
                .encrypted_group_info = egi,
            } };
            return msg.encodeAlloc(allocator);
        }

        /// Re-encode a caller-built `Proposal` into the group's arena and
        /// decode it back, so every byte it carries — a `KeyPackage`'s keys,
        /// an Update's `LeafNode`, a `PreSharedKeyID`'s nonce — aliases
        /// memory the group owns. Without this an inline `Add` would put a
        /// `LeafNode` into the ratchet tree whose bytes are the caller's,
        /// and the tree outlives the call by design.
        fn arenaCopyProposal(arena: std.mem.Allocator, p: content.Proposal) !content.Proposal {
            const bytes = try p.encodeAlloc(arena);
            var r = codec.Reader.init(bytes);
            const back = try content.Proposal.decode(arena, &r);
            if (!r.atEnd()) return error.Malformed;
            return back;
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

        /// One authenticated proposal message: what §5.2's `ProposalRef`
        /// names it by, the body, and the leaf that sent it.
        const Candidate = struct {
            ref: [S.Hash.digest_length]u8,
            proposal: content.Proposal,
            sender: u32,
        };

        /// Decode ONE proposal `MLSMessage` into the arena and run every
        /// check §12.2's "It contains an individual proposal that is
        /// invalid" implies for the enclosing message: right content type,
        /// right epoch, a `member` sender that names a real leaf, a valid
        /// `membership_tag` and a valid signature — all against the CURRENT
        /// epoch's `GroupContext`.
        ///
        /// Shared by both directions on purpose. A committer must run the
        /// same checks a receiver will (§12.2 opens with "A group member
        /// creating a Commit **and** a group member processing a Commit MUST
        /// verify..."), and the by-reference `ProposalRef` it puts in the
        /// Commit has to be computed over exactly the bytes the receiver
        /// will hash.
        fn authenticateProposalMessage(
            self: *const Self,
            arena: std.mem.Allocator,
            gpa: std.mem.Allocator,
            bytes: []const u8,
            old_gc: []const u8,
        ) !Candidate {
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
            const key = try leafSignatureKey(&self.ratchet_tree, sender);
            try framing.verifyMembershipTag(S, gpa, self.secrets.membership_key, p, old_gc);
            const pac = p.authenticatedContent();
            try framing.verifyFramedContent(S, gpa, key, pac, old_gc);
            return .{
                .ref = try framing.proposalRef(S, gpa, pac),
                .proposal = switch (p.content.body) {
                    .proposal => |x| x,
                    else => return error.WrongContentType,
                },
                .sender = sender,
            };
        }

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
            var candidates: std.ArrayList(Candidate) = .empty;
            defer candidates.deinit(gpa);
            for (proposal_msgs) |bytes| {
                try candidates.append(gpa, try self.authenticateProposalMessage(arena, gpa, bytes, old_gc));
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

        // ── §12.3: applying a proposal list ───────────────────────────────

        /// One member this Commit adds: where it landed and the KeyPackage
        /// that put it there (the committer needs the latter to address a
        /// `Welcome` to it; a receiver ignores it).
        pub const AddedMember = struct {
            leaf_index: u32,
            key_package: @import("keypackage.zig").KeyPackage,
        };

        /// What applying a proposal list produced. `added`/`added_leaves`/
        /// `psk_ids` are `gpa` allocations freed by `deinit`; everything
        /// else is a view.
        pub const Applied = struct {
            /// The GroupContext extensions for the NEW epoch — the old ones
            /// unless a `GroupContextExtensions` proposal replaced them
            /// wholesale (§12.1.7).
            extensions: []const tree.Extension,
            added: []AddedMember,
            /// The same leaf indices as `added`, in the shape §7.5's
            /// excluded set is passed in.
            added_leaves: []u32,
            /// Every `PreSharedKeyID` named, in proposal order — §8.4's
            /// chain is position-dependent, and a `Welcome` has to repeat
            /// the same list.
            psk_ids: []keyschedule.PreSharedKeyId,
            psk_secret: [S.Nh]u8,
            /// §12.4's `pathRequired` (see `applyProposals`).
            needs_path: bool,

            pub fn deinit(self: *Applied, gpa: std.mem.Allocator) void {
                gpa.free(self.added);
                gpa.free(self.added_leaves);
                gpa.free(self.psk_ids);
                self.* = undefined;
            }
        };

        /// RFC 9420 §12.3, in the RFC's fixed order — GroupContextExtensions,
        /// Update, Remove, Add, PSK — which is NOT the order the proposals
        /// appear in. MUTATES the tree.
        ///
        /// Shared by `processCommit` and `createCommit` because §12.3 is
        /// stated once for both ("When creating or processing a Commit, a
        /// client applies a list of proposals..."), and because the whole
        /// value of a committer applying the list itself is that it lands in
        /// the state its receivers will land in. Two copies of this ordering
        /// would be two chances to drift.
        fn applyProposals(
            self: *Self,
            arena: std.mem.Allocator,
            gpa: std.mem.Allocator,
            resolved: []const Resolved,
            external_psks: []const ExternalPsk,
        ) !Applied {
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
                    try self.checkLeafSelfConsistent(leaf);
                    // If this is OUR Update, adopt its private key now —
                    // see `pending_updates` for why it has to happen here
                    // and not after the Commit.
                    if (sender == self.my_leaf_index) {
                        for (self.pending_updates.items) |p| {
                            if (std.mem.eql(u8, p.encryption_key, leaf.encryption_key)) {
                                self.my_encryption_priv = p.encryption_priv;
                                break;
                            }
                        }
                    }
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
            // from the RESOLUTIONS the UpdatePath is encrypted to — they
            // receive their state from the Welcome, not from this path. So
            // their leaf indices are collected here and handed to
            // `processUpdatePath`/`sealUpdatePath`. Getting this wrong is
            // not a subtle key divergence: the ciphertext count simply does
            // not match and the Commit cannot be processed. It does NOT
            // narrow the §4.1.2 filtered direct path — see
            // `treekem.filteredDirectPath` for why that distinction is
            // load-bearing rather than pedantic.
            var added: std.ArrayList(AddedMember) = .empty;
            errdefer added.deinit(gpa);
            for (resolved) |rp| switch (rp.proposal) {
                .add => |kp| {
                    try verifyLeafSignature(S, gpa, kp.leaf_node, .key_package, null, null);
                    try self.checkLeafSelfConsistent(kp.leaf_node);
                    const owned = try dupLeafNode(arena, kp.leaf_node);
                    // §12.1.1's placement: the leftmost blank leaf,
                    // extending the tree to the right if there is none.
                    // Because §12.3 applies Removes first, this may
                    // legitimately reuse a leaf vacated by this same
                    // Commit — and it does so in the recorded sessions.
                    const at = try self.ratchet_tree.addLeaf(owned);
                    try added.append(gpa, .{ .leaf_index = @intCast(at), .key_package = kp });
                },
                else => {},
            };
            const added_slice = try added.toOwnedSlice(gpa);
            errdefer gpa.free(added_slice);
            const added_leaves = try gpa.alloc(u32, added_slice.len);
            errdefer gpa.free(added_leaves);
            for (added_slice, added_leaves) |m, *slot| slot.* = m.leaf_index;

            // §12.3's PSK step + §12.4.2's "Verify that all PreSharedKey
            // proposals ... are available", in the order the proposals
            // appear.
            var ids: std.ArrayList(keyschedule.PreSharedKeyId) = .empty;
            errdefer ids.deinit(gpa);
            for (resolved) |rp| {
                if (rp.proposal == .psk) try ids.append(gpa, rp.proposal.psk);
            }
            const psk_ids = try ids.toOwnedSlice(gpa);
            errdefer gpa.free(psk_ids);
            const psks = try self.resolvePsks(gpa, psk_ids, external_psks);
            defer gpa.free(psks);
            const psk_secret = try keyschedule.pskSecret(S, gpa, psks);

            // §12.4's `pathRequired` pseudocode, verbatim:
            //
            //     pathRequiredTypes = [update, remove, external_init,
            //                          group_context_extensions]
            //     if len(commit.proposals) == 0 || pathRequired:
            //         assert(commit.path != null)
            //
            // NOTE this is BROADER than §12.4.2's own bullet, which names
            // only "any Update or Remove proposals, or if it's empty". The
            // two sections of the RFC disagree; §12.4 is the one that
            // defines the "Path Required" column of §17.4's registry and
            // the one that states the rule as executable logic, so it is
            // the one followed here — and it is the safe direction to
            // disagree in for a SENDER, which is what this addition is for.
            // See `SPEC.md`'s Part 8 note.
            var needs_path = resolved.len == 0;
            for (resolved) |rp| switch (rp.proposal) {
                .update, .remove, .external_init, .group_context_extensions => needs_path = true,
                else => {},
            };

            return .{
                .extensions = new_extensions,
                .added = added_slice,
                .added_leaves = added_leaves,
                .psk_ids = psk_ids,
                .psk_secret = psk_secret,
                .needs_path = needs_path,
            };
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

        // ── the §7.3 rules this object CAN own ────────────────────────────
        //
        // §7.3's list splits cleanly in two, and the split is where this
        // module's boundary is drawn rather than at "§7.3 is Part 3's".
        //
        // NEEDS SOMETHING THIS MODULE DOES NOT HAVE, and so stays the
        // caller's (Part 3):
        //   * "the credential in the LeafNode is valid, as described in
        //     §5.3.1" — §5.3.1 is an Authentication Service, i.e. an
        //     application;
        //   * the `lifetime` window — needs a clock, and this module reads
        //     none (`meta.platform = .any`, no I/O anywhere in it);
        //   * `required_capabilities` compatibility and "the credential type
        //     is supported by all members" — policy over an extension
        //     registry the application owns.
        //
        // NEEDS ONLY THE LEAF AND THE TREE, and so is here:
        //   * `leaf_node_source` matching the context it arrived in —
        //     already enforced by `verifyLeafSignature`;
        //   * every extension in `extensions` listed in
        //     `capabilities.extensions`;
        //   * `signature_key`/`encryption_key` unique across the group.
        //
        // The second group is not optional bookkeeping: §12.2's closing rule
        // makes a Commit INVALID if "after processing the Commit the ratchet
        // tree is invalid, in particular, if it contains any leaf node that
        // is invalid according to §7.3", so a committer that skips it emits
        // Commits its receivers must reject. Both are `Policy` switches
        // defaulting ON.

        /// The §7.3 rules that read the leaf alone.
        fn checkLeafSelfConsistent(self: *const Self, leaf: tree.LeafNode) !void {
            if (!self.policy.check_leaf_extensions_supported) return;
            for (leaf.extensions) |ext| {
                if (std.mem.indexOfScalar(u16, leaf.capabilities.extensions, ext.extension_type) == null)
                    return error.LeafNodeInvalid;
            }
        }

        /// The §7.3 rule that reads the whole tree, plus §12.4.3.1's
        /// parent-node half of it. Run once per epoch transition, after the
        /// tree has reached its final shape — it is a property of the tree,
        /// not of any one leaf, and no earlier point can see it.
        fn checkKeyUniqueness(self: *const Self) !void {
            if (!self.policy.check_key_uniqueness) return;
            const nodes = self.ratchet_tree.nodes;
            for (nodes, 0..) |maybe_a, i| {
                const a = maybe_a orelse continue;
                const a_enc = switch (a) {
                    .leaf => |l| l.encryption_key,
                    .parent => |p| p.encryption_key,
                };
                for (nodes[i + 1 ..]) |maybe_b| {
                    const b = maybe_b orelse continue;
                    const b_enc = switch (b) {
                        .leaf => |l| l.encryption_key,
                        .parent => |p| p.encryption_key,
                    };
                    if (std.mem.eql(u8, a_enc, b_enc)) return error.DuplicateKeyInTree;
                    switch (a) {
                        .leaf => |la| switch (b) {
                            .leaf => |lb| if (std.mem.eql(u8, la.signature_key, lb.signature_key))
                                return error.DuplicateKeyInTree,
                            .parent => {},
                        },
                        .parent => {},
                    }
                }
            }
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

/// §7.4's chain, walked from the joiner's end: given the `path_secret` the
/// committer sent, derive the secret for every node from there up to the
/// root and record them all — the joiner's private state after a Welcome
/// (§12.4.3.1: "For each parent of the common ancestor, up to the root of
/// the tree, derive a new path secret").
///
/// **The chain follows the committer's FILTERED direct path, so blank nodes
/// are skipped rather than consuming a derivation step.** Above the common
/// ancestor the joiner's direct path and the committer's are the same nodes,
/// and the committer's Commit blanked that whole path and re-filled exactly
/// its filtered direct path — so on the resulting tree "in the committer's
/// filtered direct path" and "non-blank" coincide (RFC 9420 §7.9.1 relies on
/// the same identity). Deriving one step per UNFILTERED node instead is off
/// by one step for every node above a filtered-out one, which yields secrets
/// that match no key in the tree. That is not loud: `prunePathSecrets`
/// validates each stored secret against the node's public key and simply
/// drops the ones that do not match, so the damage shows up much later as a
/// Commit this member cannot decrypt.
///
/// `start` is the common ancestor (§12.4.3.1). It may itself be blank —
/// exactly when its whole copath subtree was blank and the §4.1.2 filter
/// dropped it — in which case the secret belongs to the first non-blank
/// node above it, which is what a committer following
/// `treekem.Staged.pathSecretFor` sends.
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
    var placed = false;
    for (dp) |node| {
        if (!seen_start) {
            if (node != start) continue;
            seen_start = true;
        }
        if (t.nodes[node] == null) continue; // filtered out by the committer
        if (placed) secret = try crypto.DeriveSecret(S, secret, "path");
        placed = true;
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

/// A DEEP copy of an extension list: the vector and every
/// `extension_data`. `arena.dupe(tree.Extension, ...)` copies the list
/// alone and leaves each `extension_data` pointing at the source, which is
/// exactly the aliasing bug this module's decode convention makes easy —
/// so the only place a caller's extensions enter retained group state uses
/// this instead.
fn dupExtensions(arena: std.mem.Allocator, exts: []const tree.Extension) ![]const tree.Extension {
    const out = try arena.alloc(tree.Extension, exts.len);
    for (exts, out) |src, *slot| {
        slot.* = .{
            .extension_type = src.extension_type,
            .extension_data = try arena.dupe(u8, src.extension_data),
        };
    }
    return out;
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

test "Policy: the two §7.3 rules this object owns default to ON" {
    const p: Policy = .{};
    try testing.expect(p.check_leaf_extensions_supported);
    try testing.expect(p.check_key_uniqueness);
}

// ── Part 8: creation, driven end to end against this module's own
// receive path ───────────────────────────────────────────────────────────
//
// **What these prove and what they do not.** Every assertion below is a
// ROUND TRIP: this module's `createCommit`/`buildWelcome` produce bytes and
// this module's `processCommit`/`fromWelcome` consume them. Nothing here is
// anchored against another implementation, and saying otherwise would be
// dishonest — an encoder agreeing with its own decoder proves consistency,
// not conformance.
//
// What makes them worth more than that, stated precisely:
//
//   * the CONSUMING half is externally anchored. `processCommit` and
//     `fromWelcome` are the code the three `passive-client-*.json` recorded
//     sessions drive Commit by Commit against another implementation's
//     `epoch_authenticator`, including a 200-Commit session. A commit this
//     module creates has to satisfy every check that code performs;
//   * the values compared are DERIVED, not transported. `epoch_authenticator`
//     is `DeriveSecret(epoch_secret, "authentication")`, and `epoch_secret`
//     depends on the tree hash, the whole transcript and the previous
//     epoch's `init_secret`. Two members agreeing on it means they agree on
//     every one of those;
//   * `kat_commit_test.zig` closes the remaining gap in the other
//     direction: it seeds a generation from a RECORDED vector's own path
//     secret and compares the derived public keys, the `commit_secret` and
//     the committer leaf's `parent_hash` byte-for-byte against that
//     vector — and creates Commits from group states restored out of the
//     recorded sessions.

const keypackage_mod = @import("keypackage.zig");

/// One test participant: its three key pairs and the `MLSMessage(KeyPackage)`
/// that publishes their public halves. Deterministic in `seed` so a failure
/// reproduces exactly.
const TestClient = struct {
    sig: TestSuite.Sig.KeyPair,
    init_priv: [TestSuite.Kem.Nsk]u8,
    enc_priv: [TestSuite.Kem.Nsk]u8,
    kp_msg: []u8,
    kp: keypackage_mod.KeyPackage,

    fn init(arena: std.mem.Allocator, name: []const u8, seed: u8) !TestClient {
        const sig = try TestSuite.Sig.KeyPair.generateDeterministic(@splat(seed));
        const init_kp = try TestSuite.Kem.KeyPair.generateDeterministic(@splat(seed +% 64));
        const enc_kp = try TestSuite.Kem.KeyPair.generateDeterministic(@splat(seed +% 128));
        const kp = try keypackage_mod.create(TestSuite, arena, .{
            .signature_key_pair = sig,
            .init_key = init_kp.public_key,
            .encryption_key = enc_kp.public_key,
            .credential = .{ .basic = name },
            .capabilities = .{
                .versions = &.{1},
                .cipher_suites = &.{1},
                .extensions = &.{},
                .proposals = &.{},
                .credentials = &.{1},
            },
            .lifetime = .{ .not_before = 0, .not_after = std.math.maxInt(u64) },
        });
        const msg: framing.MLSMessage = .{ .key_package = kp };
        return .{
            .sig = sig,
            .init_priv = init_kp.secret_key,
            .enc_priv = enc_kp.secret_key,
            .kp_msg = try msg.encodeAlloc(arena),
            .kp = kp,
        };
    }

    fn join(self: TestClient, gpa: std.mem.Allocator, welcome_msg: []const u8, psks: []const ExternalPsk) !Group(TestSuite) {
        return Group(TestSuite).fromWelcome(gpa, .{
            .welcome_msg = welcome_msg,
            .key_package_msg = self.kp_msg,
            .init_priv = self.init_priv,
            .encryption_priv = self.enc_priv,
            .external_psks = psks,
        });
    }
};

fn expectSameEpoch(a: *const Group(TestSuite), b: *const Group(TestSuite)) !void {
    try testing.expectEqual(a.epoch, b.epoch);
    try testing.expectEqualSlices(u8, &a.tree_hash, &b.tree_hash);
    try testing.expectEqualSlices(u8, &a.confirmed_transcript_hash, &b.confirmed_transcript_hash);
    try testing.expectEqualSlices(u8, &a.epochAuthenticator(), &b.epochAuthenticator());
}

test "§11: create() lands a one-member group at epoch 0 with §8.2's ZERO-LENGTH confirmed transcript hash" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const alice = try TestClient.init(arena.allocator(), "alice", 1);
    var g = try Group(TestSuite).create(testing.allocator, .{
        .io = threaded.io(),
        .group_id = "the-group",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer g.deinit();

    try testing.expectEqual(@as(u64, 0), g.epoch);
    try testing.expectEqual(@as(usize, 1), g.treeSize());
    // §8.2: `confirmed_transcript_hash_[0]` is the ZERO-LENGTH octet
    // string. A 32-byte zero-filled digest here would encode differently
    // and derive a different epoch 0 — the whole reason `confirmed_len`
    // exists.
    try testing.expectEqual(@as(usize, 0), g.confirmed_len);
    try testing.expectEqual(@as(usize, 0), g.groupContext().confirmed_transcript_hash.len);

    // §11's "fresh random value": two groups created with the same
    // KeyPackage and the same group_id must NOT share an epoch.
    var g2 = try Group(TestSuite).create(testing.allocator, .{
        .io = threaded.io(),
        .group_id = "the-group",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer g2.deinit();
    try testing.expect(!std.mem.eql(u8, &g.epochAuthenticator(), &g2.epochAuthenticator()));
    // ... while everything PUBLIC about them is identical, which is what
    // makes the secret the only thing separating them.
    try testing.expectEqualSlices(u8, &g.tree_hash, &g2.tree_hash);
}

test "§12.4.1: create a group, add a member by value, and the Welcome lands the joiner in the committer's epoch" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 1);
    const bob = try TestClient.init(aa, "bob", 2);

    var a = try Group(TestSuite).create(testing.allocator, .{
        .io = io,
        .group_id = "the-group",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    const created = try a.createCommit(testing.allocator, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .add = bob.kp } }},
    });
    defer created.deinit(testing.allocator);
    try testing.expect(created.welcome != null);
    try testing.expectEqual(@as(u64, 1), a.epoch);
    try testing.expectEqual(@as(usize, 2), a.treeSize());

    var b = try bob.join(testing.allocator, created.welcome.?, &.{});
    defer b.deinit();
    try expectSameEpoch(&a, &b);

    // §7.5's exclusion, observed from the sender's side, in the shape the
    // first Commit of every group's life takes: the committer's ONLY
    // copath child is the leaf this very Commit added. The node stays in
    // the §4.1.2 filtered direct path (that filter knows nothing about
    // Adds — see `treekem.filteredDirectPath`) and gets a fresh key, but
    // the resolution it would encrypt to is empty once the new member is
    // excluded, so the `UpdatePathNode` carries ZERO ciphertexts.
    {
        var r = codec.Reader.init(created.commit);
        const msg = try framing.MLSMessage.decode(aa, &r);
        const path = msg.public_message.content.body.commit.path.?;
        try testing.expectEqual(@as(usize, 1), path.nodes.len);
        try testing.expectEqual(@as(usize, 0), path.nodes[0].encrypted_path_secret.len);
        // ... and because the node is non-blank, the committer's leaf
        // carries a real parent hash rather than the zero-length string.
        try testing.expectEqual(@as(usize, TestSuite.Hash.digest_length), path.leaf_node.parent_hash.?.len);
    }
    // The new member is properly MERGED at that node: §12.4.3.1 hands it
    // the path secret for the lowest node of both direct paths, which is
    // exactly the node above. A reading that dropped the node from the
    // path would leave it blank and give the joiner nothing.
    try testing.expect(b.my_path_secrets.items.len > 0);
    try testing.expect(a.ratchet_tree.nodes[1] != null);
}

test "§12.4.1: a three-member group runs Commits in both directions, with proposals by value and by reference" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 1);
    const bob = try TestClient.init(aa, "bob", 2);
    const carol = try TestClient.init(aa, "carol", 3);
    const dave = try TestClient.init(aa, "dave", 4);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "three",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    // epoch 1: alice adds bob.
    var b = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .add = bob.kp } }},
        });
        defer c.deinit(gpa);
        break :blk try bob.join(gpa, c.welcome.?, &.{});
    };
    defer b.deinit();
    try expectSameEpoch(&a, &b);

    // epoch 2: BOB commits — the first Commit this group has seen from
    // anyone but its creator, and the first with a non-empty UpdatePath.
    // Alice must follow it.
    {
        const c = try b.createCommit(gpa, .{ .io = io, .signature_key_pair = bob.sig });
        defer c.deinit(gpa);
        try a.processCommit(.{ .commit_msg = c.commit });
        try expectSameEpoch(&a, &b);
        try testing.expect(c.welcome == null);
    }

    // epoch 3: alice adds carol AND dave in one Commit, so §12.1.1's
    // placement order and §7.5's exclusion of BOTH new leaves are
    // exercised at once.
    var c_grp: Group(TestSuite) = undefined;
    var d_grp: Group(TestSuite) = undefined;
    {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{
                .{ .by_value = .{ .add = carol.kp } },
                .{ .by_value = .{ .add = dave.kp } },
            },
        });
        defer c.deinit(gpa);
        try b.processCommit(.{ .commit_msg = c.commit });
        c_grp = try carol.join(gpa, c.welcome.?, &.{});
        d_grp = try dave.join(gpa, c.welcome.?, &.{});
    }
    defer c_grp.deinit();
    defer d_grp.deinit();
    try testing.expectEqual(@as(usize, 4), a.treeSize());
    try expectSameEpoch(&a, &b);
    try expectSameEpoch(&a, &c_grp);
    try expectSameEpoch(&a, &d_grp);

    // epoch 4: carol proposes an Update; dave commits it BY REFERENCE.
    // This is the only shape in which an Update is legal at all (§12.2
    // rejects an Update generated by the committer), so it is the only way
    // to reach `applyProposals`' Update arm from the creation side.
    {
        const new_enc = try TestSuite.Kem.KeyPair.generateDeterministic(@splat(0x33));
        const leaf = try c_grp.updateLeaf(.{ .signature_key_pair = carol.sig, .encryption_key_pair = new_enc });
        const prop = try c_grp.createProposal(gpa, .{
            .signature_key_pair = carol.sig,
            .proposal = .{ .update = leaf },
        });
        defer gpa.free(prop);

        const c = try d_grp.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = dave.sig,
            .proposals = &.{.{ .by_reference = prop }},
        });
        defer c.deinit(gpa);
        for ([_]*Group(TestSuite){ &a, &b, &c_grp }) |g| {
            try g.processCommit(.{ .commit_msg = c.commit, .proposal_msgs = &.{prop} });
        }
        // Carol adopted her own new leaf key inside `processCommit` — §12.3
        // applies the Update before the UpdatePath is decrypted, and dave
        // sealed a ciphertext to that new key, so without
        // `pending_updates` she would fail to open it. (She does not fail
        // visibly here BECAUSE that works; before it existed this exact
        // step was a bare AEAD rejection inside `processUpdatePath`.)
        try testing.expectEqualSlices(u8, &new_enc.secret_key, &c_grp.my_encryption_priv);
        try expectSameEpoch(&a, &b);
        try expectSameEpoch(&a, &c_grp);
        try expectSameEpoch(&a, &d_grp);
    }

    // epoch 5: bob removes alice by value. The removed member processes
    // the Commit too — §12.4.2's closing note makes that valid, and it is
    // the path where `processUpdatePath` has nothing it can decrypt.
    {
        const c = try b.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = bob.sig,
            .proposals = &.{.{ .by_value = .{ .remove = 0 } }},
        });
        defer c.deinit(gpa);
        for ([_]*Group(TestSuite){ &c_grp, &d_grp }) |g| {
            try g.processCommit(.{ .commit_msg = c.commit });
        }
        try expectSameEpoch(&b, &c_grp);
        try expectSameEpoch(&b, &d_grp);
        try testing.expectEqual(@as(u64, 5), b.epoch);
    }
}

test "§7.5: adding a member into the committer's OWN sibling leaf keeps that node in the path with an empty ciphertext vector, and the result is §7.9.2-valid" {
    // The shape that settles what §7.5's same-Commit-Add exclusion narrows
    // — the resolution only, or the filtered direct path as well. Here the
    // committer's immediate copath child is the leaf this Commit adds, so
    // the two readings differ: dropping the node from the path leaves it
    // BLANK, which puts the new member's leaf into the resolution of that
    // blank node and breaks §7.9.2's third criterion (`P.unmerged_leaves ∩
    // subtree(C) == resolution(C) \ {D}` — the merge empties
    // `unmerged_leaves`, so the left side is empty while the right side
    // holds the new member). Keeping it, per the RFC's own wording, leaves
    // it non-blank and the criterion holds.
    //
    // The teeth are at the end: the new member JOINS, and `fromWelcome`
    // runs `validateParentHashes` over the resulting tree. Under the other
    // reading that call returns `error.Malformed`.
    //
    // Reaching this needs at least four leaves (so something survives
    // ABOVE the node in question) with the committer's sibling leaf blank,
    // which is why the scenario removes a member before adding one.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 41);
    const bob = try TestClient.init(aa, "bob", 42);
    const carol = try TestClient.init(aa, "carol", 43);
    const dave = try TestClient.init(aa, "dave", 44);
    const erin = try TestClient.init(aa, "erin", 45);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "sibling",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    var b = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .add = bob.kp } }},
        });
        defer c.deinit(gpa);
        break :blk try bob.join(gpa, c.welcome.?, &.{});
    };
    defer b.deinit();

    var cg: Group(TestSuite) = undefined;
    var dg: Group(TestSuite) = undefined;
    {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{
                .{ .by_value = .{ .add = carol.kp } },
                .{ .by_value = .{ .add = dave.kp } },
            },
        });
        defer c.deinit(gpa);
        try b.processCommit(.{ .commit_msg = c.commit });
        cg = try carol.join(gpa, c.welcome.?, &.{});
        dg = try dave.join(gpa, c.welcome.?, &.{});
    }
    defer cg.deinit();
    defer dg.deinit();
    try testing.expectEqual(@as(usize, 4), a.treeSize());

    // Vacate leaf 1 — the committer's own sibling.
    {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .remove = 1 } }},
        });
        defer c.deinit(gpa);
        try cg.processCommit(.{ .commit_msg = c.commit });
        try dg.processCommit(.{ .commit_msg = c.commit });
        try expectSameEpoch(&a, &cg);
    }
    try testing.expect(a.ratchet_tree.nodes[2] == null); // leaf 1 is blank

    // ... and refill it in the same Commit that updates the path.
    const c = try a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .add = erin.kp } }},
    });
    defer c.deinit(gpa);
    {
        var r = codec.Reader.init(c.commit);
        const msg = try framing.MLSMessage.decode(aa, &r);
        const path = msg.public_message.content.body.commit.path.?;
        // Node 1 (alice's parent) and node 3 (the root) are BOTH in the
        // §4.1.2 filtered direct path — node 1 because its copath child,
        // erin's freshly filled leaf, resolves non-empty. But erin is
        // excluded from what node 1 encrypts to, so that node carries zero
        // ciphertexts while the root carries the rest.
        try testing.expectEqual(@as(usize, 2), path.nodes.len);
        try testing.expectEqual(@as(usize, 0), path.nodes[0].encrypted_path_secret.len);
        try testing.expect(path.nodes[1].encrypted_path_secret.len > 0);
        try testing.expectEqual(@as(usize, TestSuite.Hash.digest_length), path.leaf_node.parent_hash.?.len);
    }
    try testing.expect(a.ratchet_tree.nodes[1] != null); // non-blank after the merge

    try cg.processCommit(.{ .commit_msg = c.commit });
    try dg.processCommit(.{ .commit_msg = c.commit });
    var eg = try erin.join(gpa, c.welcome.?, &.{});
    defer eg.deinit();
    try expectSameEpoch(&a, &cg);
    try expectSameEpoch(&a, &dg);
    try expectSameEpoch(&a, &eg);
    // Erin landed in the vacated leaf, i.e. the case really was the one
    // this test is named for.
    try testing.expectEqual(@as(u32, 1), eg.my_leaf_index);
}

test "§12.4.3.1: a joiner's path secrets follow the committer's FILTERED direct path, skipping the nodes it left blank" {
    // §12.4.3.1: "For each parent of the common ancestor, up to the root of
    // the tree, derive a new path secret ... The private key MUST be the
    // private key that corresponds to the public key in the node." The
    // chain is §7.4's, which runs along the committer's FILTERED direct
    // path — so a node the §4.1.2 filter dropped (its whole copath subtree
    // is blank) consumes NO derivation step. Walking the joiner's plain
    // direct path instead is off by one step above every such node, and the
    // failure is silent: `adoptPathSecrets` drops secrets that do not match
    // the node's public key, so the joiner just quietly ends up holding
    // fewer of them.
    //
    // The shape needed: a blank subtree on the committer's copath BELOW a
    // surviving node. Three members are removed to create one.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 51);
    const members = [_]TestClient{
        try TestClient.init(aa, "bob", 52),
        try TestClient.init(aa, "carol", 53),
        try TestClient.init(aa, "dave", 54),
        try TestClient.init(aa, "erin", 55),
    };
    const frank = try TestClient.init(aa, "frank", 56);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "filtered",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    var erin_group: Group(TestSuite) = undefined;
    {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{
                .{ .by_value = .{ .add = members[0].kp } },
                .{ .by_value = .{ .add = members[1].kp } },
                .{ .by_value = .{ .add = members[2].kp } },
                .{ .by_value = .{ .add = members[3].kp } },
            },
        });
        defer c.deinit(gpa);
        erin_group = try members[3].join(gpa, c.welcome.?, &.{});
    }
    defer erin_group.deinit();
    try testing.expectEqual(@as(usize, 8), a.treeSize());
    try testing.expectEqual(@as(u32, 4), erin_group.my_leaf_index);

    // Vacate leaves 1, 2 and 3 — leaves 2 and 3 together are the whole
    // subtree under node 5, which is the copath child of node 3 on alice's
    // direct path.
    {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{
                .{ .by_value = .{ .remove = 1 } },
                .{ .by_value = .{ .remove = 2 } },
                .{ .by_value = .{ .remove = 3 } },
            },
        });
        defer c.deinit(gpa);
        try erin_group.processCommit(.{ .commit_msg = c.commit });
        try expectSameEpoch(&a, &erin_group);
    }
    try testing.expectEqual(@as(usize, 8), a.treeSize()); // no truncation: leaf 4 is live
    try testing.expect(a.ratchet_tree.nodes[5] == null); // the blank subtree's root

    // Add frank into leaf 1. Alice's filtered direct path is now
    // node 1 (copath child = frank's leaf) and node 7 (copath child covers
    // erin) — node 3 drops out, because everything under node 5 is blank.
    const c = try a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .add = frank.kp } }},
    });
    defer c.deinit(gpa);
    {
        var r = codec.Reader.init(c.commit);
        const msg = try framing.MLSMessage.decode(aa, &r);
        try testing.expectEqual(@as(usize, 2), msg.public_message.content.body.commit.path.?.nodes.len);
    }
    try testing.expect(a.ratchet_tree.nodes[3] == null); // dropped, hence blank
    try erin_group.processCommit(.{ .commit_msg = c.commit });

    var fg = try frank.join(gpa, c.welcome.?, &.{});
    defer fg.deinit();
    try testing.expectEqual(@as(u32, 1), fg.my_leaf_index);
    try expectSameEpoch(&a, &fg);
    try expectSameEpoch(&a, &erin_group);

    // The point of the test: frank's direct path is nodes 1, 3 and 7; node
    // 3 is blank, so he must hold exactly the OTHER two — the same secrets
    // alice generated for them. One derivation step too many and the node-7
    // secret matches nothing and is silently dropped.
    try testing.expectEqual(@as(usize, 2), fg.my_path_secrets.items.len);
    var has_1 = false;
    var has_7 = false;
    for (fg.my_path_secrets.items) |e| {
        if (e.node == 1) has_1 = true;
        if (e.node == 7) has_7 = true;
    }
    try testing.expect(has_1);
    try testing.expect(has_7);
}

test "§12.4.1: a PreSharedKey proposal reaches the Welcome, and a joiner without the PSK cannot enter" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 5);
    const bob = try TestClient.init(aa, "bob", 6);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "psk-group",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    const psks = [_]ExternalPsk{.{ .psk_id = "shared-id", .psk = "the pre-shared key material" }};
    const psk_id: keyschedule.PreSharedKeyId = .{
        .id = .{ .external = "shared-id" },
        .psk_nonce = &[_]u8{0x5a} ** TestSuite.Nh,
    };

    const c = try a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{
            .{ .by_value = .{ .add = bob.kp } },
            .{ .by_value = .{ .psk = psk_id } },
        },
        .external_psks = &psks,
    });
    defer c.deinit(gpa);

    var b = try bob.join(gpa, c.welcome.?, &psks);
    defer b.deinit();
    try expectSameEpoch(&a, &b);

    // §12.4.3.1: "If a PreSharedKeyID is part of the GroupSecrets and the
    // client is not in possession of the corresponding PSK, return an
    // error." Without the PSK the joiner cannot even derive
    // `welcome_secret`, so it fails at the group-info AEAD rather than at
    // the confirmation tag.
    try testing.expectError(error.PskNotAvailable, bob.join(gpa, c.welcome.?, &.{}));
}

test "§12.4: the path is populated by default and omitted only when both §12.4 conditions hold" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 7);
    const bob = try TestClient.init(aa, "bob", 8);
    const carol = try TestClient.init(aa, "carol", 9);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "path-group",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    var b = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .add = bob.kp } }},
        });
        defer c.deinit(gpa);
        break :blk try bob.join(gpa, c.welcome.?, &.{});
    };
    defer b.deinit();

    // An Add-only Commit is §12.4's "partial" Commit: `add` is not a
    // path-required type, so with `omit_path_when_allowed` the path really
    // is absent — and every member must still follow it.
    const c = try a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .add = carol.kp } }},
        .omit_path_when_allowed = true,
    });
    defer c.deinit(gpa);
    {
        var r = codec.Reader.init(c.commit);
        const msg = try framing.MLSMessage.decode(aa, &r);
        try testing.expect(msg.public_message.content.body.commit.path == null);
    }
    try b.processCommit(.{ .commit_msg = c.commit });
    var cg = try carol.join(gpa, c.welcome.?, &.{});
    defer cg.deinit();
    try expectSameEpoch(&a, &b);
    try expectSameEpoch(&a, &cg);

    // ... but an EMPTY proposal list forces one even when asked to omit
    // (§12.4's `len(commit.proposals) == 0 || pathRequired`).
    const empty = try a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .omit_path_when_allowed = true,
    });
    defer empty.deinit(gpa);
    {
        var r = codec.Reader.init(empty.commit);
        const msg = try framing.MLSMessage.decode(aa, &r);
        try testing.expect(msg.public_message.content.body.commit.path != null);
    }
}

test "§12.4.3.2: include_external_pub publishes an ExternalPub extension the GroupInfo reader can parse" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 11);
    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "ext-pub",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    const c = try a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .include_external_pub = true,
    });
    defer c.deinit(gpa);

    var r = codec.Reader.init(c.group_info);
    const gi_msg = try framing.MLSMessage.decode(aa, &r);
    try testing.expect(r.atEnd());
    const gi = gi_msg.group_info;
    // The GroupInfo is signed by the committer's leaf, and the tree it
    // carries is the one whose hash the signed GroupContext names.
    const signer_key = try leafSignatureKey(&a.ratchet_tree, gi.signer);
    try gi.verifySignature(TestSuite, gpa, signer_key);
    var rt = try gi.ratchetTree(aa);
    try welcome_mod.verifyTreeHash(TestSuite, gpa, &rt, gi.group_context);

    // §8: `external_pub` is `KEM.DeriveKeyPair(external_secret)`, so a
    // member can recompute it — that is what makes it verifiable at all.
    const published = (try gi.externalPub()).?;
    const expected = keyschedule.externalKeyPair(TestSuite, a.secrets.external_secret);
    try testing.expectEqualSlices(u8, &expected.public_key, published);
}

test "§12.2: createCommit refuses the proposal lists a receiver would reject" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 13);
    const bob = try TestClient.init(aa, "bob", 14);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "reject",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();

    // "It contains a Remove proposal that removes the committer."
    try testing.expectError(error.InvalidProposalList, a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .remove = 0 } }},
    }));
    // "It contains multiple Add proposals that contain KeyPackages that
    // represent the same client" — `Policy`'s signature-key reading.
    try testing.expectError(error.InvalidProposalList, a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{
            .{ .by_value = .{ .add = bob.kp } },
            .{ .by_value = .{ .add = bob.kp } },
        },
    }));
    // "It contains an ExternalInit proposal" (a regular Commit's list).
    try testing.expectError(error.InvalidProposalList, a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .external_init = &[_]u8{0xaa} ** 32 } }},
    }));
    // All three refusals happened BEFORE the tree was touched, so the
    // group is still usable — the poison flag is set only once mutation
    // begins.
    try testing.expectEqual(@as(u64, 0), a.epoch);
    const ok = try a.createCommit(gpa, .{ .io = io, .signature_key_pair = alice.sig });
    defer ok.deinit(gpa);
    try testing.expectEqual(@as(u64, 1), a.epoch);
}

test "§12.4.1: a tampered Commit is rejected by the receiver, so the round trip has teeth" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const alice = try TestClient.init(aa, "alice", 21);
    const bob = try TestClient.init(aa, "bob", 22);

    var a = try Group(TestSuite).create(gpa, .{
        .io = io,
        .group_id = "teeth",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = alice.enc_priv,
    });
    defer a.deinit();
    var b = blk: {
        const c = try a.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = alice.sig,
            .proposals = &.{.{ .by_value = .{ .add = bob.kp } }},
        });
        defer c.deinit(gpa);
        break :blk try bob.join(gpa, c.welcome.?, &.{});
    };
    defer b.deinit();

    const c = try a.createCommit(gpa, .{ .io = io, .signature_key_pair = alice.sig });
    defer c.deinit(gpa);

    // Flip one byte in the MIDDLE of the Commit — inside the UpdatePath's
    // ciphertexts, past the header. A receiver must not advance.
    const bad = try gpa.dupe(u8, c.commit);
    defer gpa.free(bad);
    bad[bad.len / 2] ^= 0x01;
    try testing.expectError(error.MacMismatch, b.processCommit(.{ .commit_msg = bad }));
    // The failure came from the membership tag, i.e. §12.4.2's second
    // bullet, before anything was applied — but the object is poisoned
    // only if the tree was already touched, and it was not.
    try testing.expectEqual(@as(u64, 1), b.epoch);
    try b.processCommit(.{ .commit_msg = c.commit });
    try expectSameEpoch(&a, &b);

    // And a Welcome whose ciphertext is corrupted must not produce a
    // member at all.
    const c2 = try a.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = alice.sig,
        .proposals = &.{.{ .by_value = .{ .add = (try TestClient.init(aa, "carol", 23)).kp } }},
    });
    defer c2.deinit(gpa);
    const bad_welcome = try gpa.dupe(u8, c2.welcome.?);
    defer gpa.free(bad_welcome);
    bad_welcome[bad_welcome.len - 8] ^= 0x01;
    const carol = try TestClient.init(aa, "carol", 23);
    try testing.expectError(error.DecryptionFailed, carol.join(gpa, bad_welcome, &.{}));
}
